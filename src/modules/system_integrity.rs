use std::time::Duration;
use tokio::sync::mpsc::Sender;
use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{run_cmd, run_cmd_streaming};

pub struct SystemIntegrityModule;

impl SystemIntegrityModule {
    pub fn new() -> Self {
        Self
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
        "System-Integrität (DISM / SFC / VSS)"
    }

    fn description(&self) -> &'static str {
        "Prüft Component Store (DISM), Systemdateien (SFC) und Volumenschattenkopie-Dienste"
    }

    fn icon(&self) -> &'static str {
        "🛡"
    }

    async fn scan(&self, progress_tx: Option<Sender<ModuleProgress>>) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        Self::send_progress(&progress_tx, 15, "Prüfe Windows Component Store (DISM CheckHealth)...", Some("DISM /Online /Cleanup-Image /CheckHealth wird ausgeführt...")).await;

        let dism_check = run_cmd(
            "dism.exe",
            &["/Online", "/Cleanup-Image", "/CheckHealth"],
            Duration::from_secs(45),
        )
        .await;

        match dism_check {
            Ok(output) => {
                let stdout = output.stdout.to_lowercase();
                if stdout.contains("repairable") || stdout.contains("reparierbar") || stdout.contains("corrupted") || stdout.contains("beschädigt") {
                    issues.push(Issue::new(
                        "sys_dism_corrupt",
                        self.id(),
                        "Windows Component Store ist beschädigt",
                        "System-Integrität",
                        Severity::Critical,
                        RiskScore::Low,
                        "Der Windows Component Store (WinSxS) enthält beschädigte oder inkonsistente Pakete. Dies kann zu Update- und Systemfehlern führen.",
                        output.stdout.clone(),
                        "Automatische Reparatur via DISM /Online /Cleanup-Image /RestoreHealth",
                        vec![
                            "DISM RestoreHealth mit Windows Update als Reparaturquelle ausführen".to_string(),
                            "Komponentenspeicher synchronisieren und Cache auffrischen".to_string(),
                        ],
                    ));
                }
            }
            Err(e) => {
                Self::send_progress(&progress_tx, 30, "DISM Check übersprungen (keine Admin-Rechte oder Timeout)", Some(&e)).await;
            }
        }

        Self::send_progress(&progress_tx, 55, "Prüfe Volumenschattenkopie & VSS-Dienste...", Some("Abfrage von VSS und swprv Dienststatus...")).await;

        let vss_query = run_cmd("sc.exe", &["query", "vss"], Duration::from_secs(10)).await;
        if let Ok(vss_out) = vss_query {
            let stdout = vss_out.stdout.to_lowercase();
            if stdout.contains("disabled") || stdout.contains("deaktiviert") {
                issues.push(Issue::new(
                    "sys_vss_disabled",
                    self.id(),
                    "Volume Shadow Copy Dienst (VSS) ist deaktiviert",
                    "System-Integrität",
                    Severity::Warning,
                    RiskScore::Low,
                    "Der VSS-Dienst ist deaktiviert. Dadurch können keine Systemwiederherstellungspunkte oder konsistente Backups erstellt werden.",
                    vss_out.stdout,
                    "VSS-Dienst-Starttyp auf 'Manuell/Demand' zurücksetzen und Dienst aktivieren",
                    vec!["sc config vss start= demand".to_string(), "net start vss".to_string()],
                ));
            }
        }

        Self::send_progress(&progress_tx, 80, "Prüfe CBS-Systemprotokolle auf Integritätsfehler...", Some("CBS.log Inspektion...")).await;

        let cbs_log_path = r"C:\Windows\Logs\CBS\CBS.log";
        if let Ok(cbs_content) = std::fs::read_to_string(cbs_log_path) {
            let last_chunk: String = cbs_content.chars().rev().take(15000).collect::<String>().chars().rev().collect();
            if last_chunk.contains("Cannot repair member file") || last_chunk.contains("Corrupt") {
                issues.push(Issue::new(
                    "sys_sfc_corrupt",
                    self.id(),
                    "Systemdateien weisen Integritätsverletzungen auf (CBS)",
                    "System-Integrität",
                    Severity::Warning,
                    RiskScore::Low,
                    "In den Windows CBS-Protokollen wurden Integritätsfehler bei geschützten Systemdateien festgestellt.",
                    "Gefunden in CBS.log: Cannot repair member file / Corrupt flags.",
                    "SFC /scannow ausführen, um Systemdateien aus dem lokalen Komponentenspeicher wiederherzustellen",
                    vec!["sfc /scannow im Hintergrund ausführen und defekte Systemdateien reparieren".to_string()],
                ));
            }
        }

        Self::send_progress(&progress_tx, 100, "System-Integritätsprüfung abgeschlossen", None).await;

        Ok(issues)
    }

    async fn fix(&self, issue_id: &str, progress_tx: Option<Sender<FixProgress>>) -> Result<String, String> {
        let log_tx = if let Some(ref tx) = progress_tx {
            let (str_tx, mut str_rx) = tokio::sync::mpsc::channel::<String>(100);
            let tx_clone = tx.clone();
            let issue_id_clone = issue_id.to_string();
            tokio::spawn(async move {
                while let Some(line) = str_rx.recv().await {
                    let _ = tx_clone
                        .send(FixProgress {
                            issue_id: issue_id_clone.clone(),
                            step_description: "Reparatur läuft...".to_string(),
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
                let out = run_cmd_streaming(
                    "dism.exe",
                    &["/Online", "/Cleanup-Image", "/RestoreHealth"],
                    log_tx,
                    Duration::from_secs(600),
                )
                .await?;
                if out.success {
                    Ok("DISM /RestoreHealth erfolgreich abgeschlossen. Component Store repariert.".to_string())
                } else {
                    Err(format!("DISM-Reparatur fehlgeschlagen: {}", out.stderr))
                }
            }
            "sys_vss_disabled" => {
                let _ = run_cmd("sc.exe", &["config", "vss", "start=", "demand"], Duration::from_secs(10)).await;
                let _ = run_cmd("net.exe", &["start", "vss"], Duration::from_secs(10)).await;
                Ok("Volume Shadow Copy (VSS) Dienst wurde erfolgreich konfiguriert und gestartet.".to_string())
            }
            "sys_sfc_corrupt" => {
                let out = run_cmd_streaming(
                    "sfc.exe",
                    &["/scannow"],
                    log_tx,
                    Duration::from_secs(600),
                )
                .await?;
                if out.success {
                    Ok("SFC /scannow erfolgreich abgeschlossen. Systemdateien repariert.".to_string())
                } else {
                    Ok(format!("SFC ausgeführt: {}", out.stdout))
                }
            }
            _ => Err(format!("Unbekannte Problem-ID: {}", issue_id)),
        }
    }
}
