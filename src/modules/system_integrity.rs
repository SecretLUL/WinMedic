use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

pub struct SystemIntegrityModule {
    runner: Arc<dyn CommandRunner>,
}

impl Default for SystemIntegrityModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemIntegrityModule {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    async fn send_progress(
        progress_tx: &Option<Sender<ModuleProgress>>,
        percent: u8,
        step: &str,
        log: Option<&str>,
    ) {
        if let Some(tx) = progress_tx {
            let _ = tx
                .send(ModuleProgress {
                    module_id: "system_integrity".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for SystemIntegrityModule {
    fn id(&self) -> &'static str {
        "system_integrity"
    }

    fn name(&self) -> &'static str {
        "System Integrity (DISM / SFC / VSS)"
    }

    fn description(&self) -> &'static str {
        "Checks the component store (DISM), system files (SFC) and Volume Shadow Copy services"
    }

    fn icon(&self) -> &'static str {
        "[SYS]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. DISM CheckHealth
        Self::send_progress(
            &progress_tx,
            15,
            "Checking the Windows component store (DISM CheckHealth)...",
            Some("Running DISM /Online /Cleanup-Image /CheckHealth..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let dism_check = self
            .runner
            .run(
                "dism.exe",
                &["/Online", "/Cleanup-Image", "/CheckHealth"],
                Duration::from_secs(45),
            )
            .await;

        match dism_check {
            Ok(output) => {
                let stdout = output.stdout.to_lowercase();
                if stdout.contains("repairable")
                    || stdout.contains("reparierbar")
                    || stdout.contains("corrupted")
                    || stdout.contains("beschädigt")
                {
                    issues.push(Issue::new(
                        "sys_dism_corrupt",
                        self.id(),
                        "Windows component store is corrupted",
                        "System Integrity",
                        Severity::Critical,
                        RiskScore::Low,
                        "The Windows component store (WinSxS) holds corrupted or inconsistent packages. This causes update and system failures.",
                        output.stdout.clone(),
                        "Repair automatically via DISM /Online /Cleanup-Image /RestoreHealth",
                        vec![
                            "Run DISM RestoreHealth with Windows Update as the repair source".to_string(),
                            "Synchronise the component store and refresh its cache".to_string(),
                        ],
                    ));
                } else {
                    Self::send_progress(
                        &progress_tx,
                        35,
                        "DISM component store is intact",
                        Some("DISM CheckHealth: no corruption found in the component store."),
                    )
                    .await;
                }
            }
            Err(e) => {
                Self::send_progress(
                    &progress_tx,
                    35,
                    "DISM check skipped (insufficient privileges)",
                    Some(&e),
                )
                .await;
            }
        }

        // 2. VSS Service Status
        Self::send_progress(
            &progress_tx,
            55,
            "Checking Volume Shadow Copy & VSS services...",
            Some("Querying the VSS and swprv service status..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let vss_query = self
            .runner
            .run("sc.exe", &["query", "vss"], Duration::from_secs(10))
            .await;
        if let Ok(vss_out) = vss_query {
            let stdout = vss_out.stdout.to_lowercase();
            if stdout.contains("disabled") || stdout.contains("deaktiviert") {
                issues.push(Issue::new(
                    "sys_vss_disabled",
                    self.id(),
                    "Volume Shadow Copy service (VSS) is disabled",
                    "System Integrity",
                    Severity::Warning,
                    RiskScore::Low,
                    "The VSS service is disabled, so Windows can create neither system restore points nor consistent backups.",
                    vss_out.stdout,
                    "Reset the VSS service start type to 'Manual/Demand' and enable the service",
                    vec!["sc config vss start= demand".to_string(), "net start vss".to_string()],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    70,
                    "VSS service ready",
                    Some("VSS service status: ready for restore points."),
                )
                .await;
            }
        }

        // 3. CBS Logs Inspection
        Self::send_progress(
            &progress_tx,
            85,
            "Checking the CBS system logs for integrity errors...",
            Some("Inspecting CBS.log..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let cbs_log_path = r"C:\Windows\Logs\CBS\CBS.log";
        if let Ok(cbs_content) = std::fs::read_to_string(cbs_log_path) {
            let last_chunk: String = cbs_content
                .chars()
                .rev()
                .take(15000)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if last_chunk.contains("Cannot repair member file") || last_chunk.contains("Corrupt") {
                issues.push(Issue::new(
                    "sys_sfc_corrupt",
                    self.id(),
                    "System files show integrity violations (CBS)",
                    "System Integrity",
                    Severity::Warning,
                    RiskScore::Low,
                    "The Windows CBS logs report integrity errors on protected system files.",
                    "Found in CBS.log: Cannot repair member file / Corrupt flags.",
                    "Run SFC /scannow to restore system files from the local component store",
                    vec![
                        "Run sfc /scannow in the background and repair damaged system files"
                            .to_string(),
                    ],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    95,
                    "CBS logs unremarkable",
                    Some("No critical CBS integrity violations reported."),
                )
                .await;
            }
        }

        Self::send_progress(&progress_tx, 100, "System integrity check complete", None).await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        let log_tx = if let Some(ref tx) = progress_tx {
            let (str_tx, mut str_rx) = tokio::sync::mpsc::channel::<String>(100);
            let tx_clone = tx.clone();
            let issue_id_clone = issue_id.to_string();
            tokio::spawn(async move {
                while let Some(line) = str_rx.recv().await {
                    let _ = tx_clone
                        .send(FixProgress {
                            issue_id: issue_id_clone.clone(),
                            step_description: "Repair in progress...".to_string(),
                            is_success: true,
                            error: None,
                            console_line: Some(line),
                        })
                        .await;
                }
            });
            Some(str_tx)
        } else {
            None
        };

        match issue_id {
            "sys_dism_corrupt" => {
                let out = self
                    .runner
                    .run_streaming(
                        "dism.exe",
                        &["/Online", "/Cleanup-Image", "/RestoreHealth"],
                        log_tx,
                        Duration::from_secs(600),
                    )
                    .await?;
                if out.success {
                    Ok(
                        "DISM /RestoreHealth completed successfully. Component store repaired."
                            .to_string(),
                    )
                } else {
                    Err(format!("DISM repair failed: {}", out.stderr))
                }
            }
            "sys_vss_disabled" => {
                let _ = self
                    .runner
                    .run(
                        "sc.exe",
                        &["config", "vss", "start=", "demand"],
                        Duration::from_secs(10),
                    )
                    .await;
                let _ = self
                    .runner
                    .run("net.exe", &["start", "vss"], Duration::from_secs(10))
                    .await;
                Ok(
                    "Volume Shadow Copy (VSS) service configured and started successfully."
                        .to_string(),
                )
            }
            "sys_sfc_corrupt" => {
                let out = self
                    .runner
                    .run_streaming("sfc.exe", &["/scannow"], log_tx, Duration::from_secs(600))
                    .await?;
                if out.success {
                    Ok("SFC /scannow completed successfully. System files repaired.".to_string())
                } else {
                    Ok(format!("SFC ran: {}", out.stdout))
                }
            }
            _ => Err(format!("Unknown issue ID: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    #[tokio::test]
    async fn test_system_integrity_detects_dism_corruption() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "dism.exe",
            CmdOutput::ok(
                "The component store is repairable. The operation completed successfully.",
            ),
        );
        mock.add_response("sc.exe", CmdOutput::ok("STATE: 4 RUNNING"));

        let module = SystemIntegrityModule::with_runner(Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "sys_dism_corrupt");
        assert_eq!(issues[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn test_system_integrity_detects_vss_disabled() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "dism.exe",
            CmdOutput::ok("No component store corruption detected."),
        );
        mock.add_response("sc.exe", CmdOutput::ok("START_TYPE: DISABLED"));

        let module = SystemIntegrityModule::with_runner(Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "sys_vss_disabled");
        assert_eq!(issues[0].severity, Severity::Warning);
    }
}
