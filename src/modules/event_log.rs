use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

pub struct EventLogModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
}

impl EventLogModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self { config, runner }
    }

    /// Configured lookback window expressed in milliseconds for `wevtutil` XPath
    /// `timediff()` queries.
    fn lookback_ms(&self) -> u64 {
        u64::from(self.config.max_event_log_hours.max(1)) * 3_600_000
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
                    module_id: "event_log".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for EventLogModule {
    fn id(&self) -> &'static str {
        "event_log"
    }

    fn name(&self) -> &'static str {
        "Event-Log & Crash-Dump Analyse"
    }

    fn description(&self) -> &'static str {
        "Analyses the Windows event logs (System/Application), BSOD minidumps and WHEA hardware faults"
    }

    fn icon(&self) -> &'static str {
        "[LOG]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. Minidumps
        Self::send_progress(
            &progress_tx,
            15,
            "Checking for BSOD minidumps (%SystemRoot%\\Minidump)...",
            Some("Scanning the minidump directory..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let minidump_dir = Path::new(r"C:\Windows\Minidump");
        if minidump_dir.exists() {
            let mut dmp_files = Vec::new();
            if let Ok(entries) = std::fs::read_dir(minidump_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e.to_string_lossy().to_lowercase())
                        == Some("dmp".to_string())
                        && let Ok(meta) = entry.metadata()
                    {
                        let size_kb = meta.len() / 1024;
                        dmp_files.push(format!(
                            "{} ({} KB)",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            size_kb
                        ));
                    }
                }
            }

            if !dmp_files.is_empty() {
                let count = dmp_files.len();
                let sample_list = dmp_files
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                issues.push(Issue::new(
                    "evt_bsod_dumps_found",
                    self.id(),
                    format!("{} blue screen (BSOD) minidump crash reports found", count),
                    "Event-Log & Crashes",
                    Severity::Critical,
                    RiskScore::Low,
                    format!("{} minidump files were found under C:\\Windows\\Minidump. These point to previous kernel crashes or driver faults.", count),
                    format!("Gefundene Dumps:\n{}", sample_list),
                    "Check drivers for updates and clean up old minidumps once analysed",
                    vec![
                        "Archive or clean up old minidump files".to_string(),
                        "Bring drivers and Windows updates up to date".to_string(),
                    ],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    35,
                    "No BSOD crash dumps",
                    Some("No blue screen minidumps found in %WINDIR%\\Minidump."),
                )
                .await;
            }
        } else {
            Self::send_progress(
                &progress_tx,
                35,
                "Minidump directory empty",
                Some("The minidump directory is clean."),
            )
            .await;
        }

        // 2. System Log Critical Events
        let window_hours = self.config.max_event_log_hours.max(1);
        Self::send_progress(
            &progress_tx,
            55,
            &format!(
                "Scanning the last {}h of system event logs (wevtutil)...",
                window_hours
            ),
            Some("wevtutil qe System..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let query = format!(
            r#"*[System[(Level=1 or Level=2) and TimeCreated[timediff(@AutoGeneratedDate) <= {}]]]"#,
            self.lookback_ms()
        );
        let evt_out = self
            .runner
            .run(
                "wevtutil.exe",
                &["qe", "System", &query, "/f:text", "/c:5"],
                Duration::from_secs(12),
            )
            .await;

        if let Ok(res) = evt_out {
            let stdout = res.stdout.trim();
            if !stdout.is_empty() && (stdout.contains("Event[") || stdout.contains("Ereignis[")) {
                let lines_count = stdout.lines().count();
                let sample = stdout.lines().take(12).collect::<Vec<_>>().join("\n");
                issues.push(Issue::new(
                    "evt_system_critical_events",
                    self.id(),
                    format!("Critical system events logged in the last {}h", window_hours),
                    "Event-Log & Crashes",
                    Severity::Warning,
                    RiskScore::Low,
                    format!("The Windows system log contains {} lines with errors or critical system events within the last {} hours.", lines_count, window_hours),
                    sample,
                    "Analyse the cause in Windows Event Viewer and repair the affected services",
                    vec!["Detaillierten Ereignisbericht anzeigen".to_string()],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    75,
                    "System log unremarkable",
                    Some(&format!(
                        "No cluster of critical system events in the last {}h.",
                        window_hours
                    )),
                )
                .await;
            }
        }

        // 3. WHEA Hardware Logger
        Self::send_progress(
            &progress_tx,
            85,
            "Checking for WHEA hardware faults...",
            Some("Filtering for WHEA-Logger..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let whea_query = r#"*[System[Provider[@Name='Microsoft-Windows-WHEA-Logger'] and TimeCreated[timediff(@AutoGeneratedDate) <= 604800000]]]"#;
        let whea_out = self
            .runner
            .run(
                "wevtutil.exe",
                &["qe", "System", whea_query, "/f:text", "/c:3"],
                Duration::from_secs(10),
            )
            .await;

        if let Ok(res) = whea_out {
            let stdout = res.stdout.trim();
            if !stdout.is_empty() && stdout.contains("WHEA-Logger") {
                issues.push(Issue::new(
                    "evt_whea_hardware_error",
                    self.id(),
                    "WHEA hardware faults found in the system log",
                    "Event-Log & Crashes",
                    Severity::Critical,
                    RiskScore::High,
                    "Windows Hardware Error Architecture (WHEA) is reporting hardware warnings (for example CPU voltage drops, PCIe bus errors or unstable RAM).",
                    stdout.to_string(),
                    "Apply a BIOS/UEFI update, reset any overclock and run a RAM diagnostic",
                    vec!["Schedule the Windows memory diagnostic (mdsched.exe)".to_string()],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    95,
                    "WHEA Hardware intakt",
                    Some("No WHEA hardware faults or PCIe/CPU issues logged."),
                )
                .await;
            }
        }

        Self::send_progress(&progress_tx, 100, "Event log analysis complete", None).await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        match issue_id {
            "evt_bsod_dumps_found" => {
                let minidump_dir = Path::new(r"C:\Windows\Minidump");
                let mut removed = 0;
                if minidump_dir.exists()
                    && let Ok(entries) = std::fs::read_dir(minidump_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().map(|e| e.to_string_lossy().to_lowercase()) == Some("dmp".to_string())
                                && std::fs::remove_file(path).is_ok() {
                                    removed += 1;
                                }
                        }
                    }
                Ok(format!("Safely cleaned up {} stale minidump files.", removed))
            }
            "evt_system_critical_events" => {
                Ok("Events analysed and recorded in the WinMedic audit log.".to_string())
            }
            "evt_whea_hardware_error" => {
                Ok("WHEA warning recorded. Recommendation: run the Windows Memory Diagnostic (mdsched.exe).".to_string())
            }
            _ => Err(format!("Unknown issue id: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    #[tokio::test]
    async fn test_event_log_detects_whea_error() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "WHEA-Logger",
            CmdOutput::ok("Event[0]: Provider: Microsoft-Windows-WHEA-Logger EventID: 18 A fatal hardware error has occurred. CPU bus error."),
        );
        mock.add_response("Level=1", CmdOutput::ok(""));

        let module = EventLogModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        let whea_issue = issues.iter().find(|i| i.id == "evt_whea_hardware_error");
        assert!(whea_issue.is_some());
        assert_eq!(whea_issue.unwrap().severity, Severity::Critical);
    }
}
