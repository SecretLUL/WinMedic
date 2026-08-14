use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;
use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::run_cmd;

pub struct WindowsUpdatesModule;

impl WindowsUpdatesModule {
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
                    module_id: "windows_updates".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for WindowsUpdatesModule {
    fn id(&self) -> &'static str {
        "windows_updates"
    }

    fn name(&self) -> &'static str {
        "Windows Update & Dienste"
    }

    fn description(&self) -> &'static str {
        "Prüft Update-Caches (SoftwareDistribution/Catroot2), Dienste (BITS, wuauserv) und Update-Blockaden"
    }

    fn icon(&self) -> &'static str {
        "🔄"
    }

    async fn scan(&self, progress_tx: Option<Sender<ModuleProgress>>) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        Self::send_progress(&progress_tx, 15, "Prüfe Windows Update Dienste (wuauserv, bits, cryptsvc)...", Some("Dienststatus abfragen...")).await;

        let services = [
            ("wuauserv", "Windows Update Dienst"),
            ("bits", "Background Intelligent Transfer Service (BITS)"),
            ("cryptsvc", "Kryptografiedienste"),
        ];

        for (svc, svc_name) in services {
            let out = run_cmd("sc.exe", &["query", svc], Duration::from_secs(8)).await;
            if let Ok(res) = out {
                let stdout = res.stdout.to_lowercase();
                if stdout.contains("disabled") || stdout.contains("deaktiviert") {
                    issues.push(Issue::new(
                        format!("wu_svc_disabled_{}", svc),
                        self.id(),
                        format!("Dienst '{}' ist deaktiviert", svc_name),
                        "Windows Update & Dienste",
                        Severity::Critical,
                        RiskScore::Medium,
                        format!("Der Systemdienst '{}' ({}) ist deaktiviert. Ohne diesen Dienst können keine Windows-Sicherheitsupdates installiert werden.", svc_name, svc),
                        res.stdout,
                        format!("Dienst '{}' auf Starttyp 'Manuell/Demand' zurücksetzen", svc),
                        vec![
                            format!("sc config {} start= demand", svc),
                            format!("net start {}", svc),
                        ],
                    ));
                }
            }
        }

        Self::send_progress(&progress_tx, 50, "Prüfe SoftwareDistribution Cache-Integrität...", Some("Prüfe C:\\Windows\\SoftwareDistribution\\Download...")).await;

        let soft_dist = Path::new(r"C:\Windows\SoftwareDistribution\Download");
        if soft_dist.exists() {
            let mut total_size_mb: u64 = 0;
            let mut file_count = 0;
            if let Ok(entries) = std::fs::read_dir(soft_dist) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_file() {
                            total_size_mb += meta.len() / (1024 * 1024);
                            file_count += 1;
                        }
                    }
                }
            }

            if total_size_mb > 5000 {
                issues.push(Issue::new(
                    "wu_cache_bloat",
                    self.id(),
                    format!("Windows Update Download-Cache überfüllt ({} MB)", total_size_mb),
                    "Windows Update & Dienste",
                    Severity::Warning,
                    RiskScore::Low,
                    format!("Im Ordner 'SoftwareDistribution\\Download' liegen {} temporäre Update-Dateien mit insgesamt {} MB, die nicht mehr benötigt werden oder verwaist sind.", file_count, total_size_mb),
                    format!("Dateien: {}, Gesamtgröße: {} MB", file_count, total_size_mb),
                    "SoftwareDistribution-Download-Ordner sicher bereinigen",
                    vec![
                        "Windows Update Dienste vorübergehend anhalten".to_string(),
                        "Temporären Download-Cache leeren".to_string(),
                        "Dienste sauber neu starten".to_string(),
                    ],
                ));
            }
        }

        Self::send_progress(&progress_tx, 80, "Prüfe auf ausstehende System-Neustarts (Pending Reboot)...", Some("Registry RebootPending prüfen...")).await;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let pending_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        ];

        for p_key in pending_keys {
            if hklm.open_subkey_with_flags(p_key, KEY_READ).is_ok() {
                issues.push(Issue::new(
                    "wu_reboot_pending",
                    self.id(),
                    "Ausstehender System-Neustart durch Updates (Reboot Pending)",
                    "Windows Update & Dienste",
                    Severity::Info,
                    RiskScore::Low,
                    "Windows signalisiert einen ausstehenden Neustart durch ein zuvor installiertes Update oder Treiberpaket. Manche Updates können erst nach einem Neustart fortgesetzt werden.",
                    format!("Gefunden in Registry: HKLM\\{}", p_key),
                    "Windows nach den Reparaturen neu starten, um Installationen abzuschließen",
                    vec!["Reboot-Hinweis im Reparaturbericht vermerken".to_string()],
                ));
                break;
            }
        }

        Self::send_progress(&progress_tx, 100, "Windows Update Diagnose abgeschlossen", None).await;

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
                            step_description: "Update-Reparatur läuft...".to_string(),
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

        if issue_id.starts_with("wu_svc_disabled_") {
            let svc = issue_id.trim_start_matches("wu_svc_disabled_");
            let _ = run_cmd("sc.exe", &["config", svc, "start=", "demand"], Duration::from_secs(10)).await;
            let _ = run_cmd("net.exe", &["start", svc], Duration::from_secs(10)).await;
            return Ok(format!("Dienst '{}' wurde auf Starttyp 'Manuell' gesetzt und gestartet.", svc));
        }

        match issue_id {
            "wu_cache_bloat" => {
                if let Some(ref tx) = log_tx {
                    let _ = tx.send("Stoppe Windows Update Dienste...".to_string()).await;
                }
                let _ = run_cmd("net.exe", &["stop", "wuauserv"], Duration::from_secs(15)).await;
                let _ = run_cmd("net.exe", &["stop", "bits"], Duration::from_secs(15)).await;
                let _ = run_cmd("net.exe", &["stop", "cryptsvc"], Duration::from_secs(15)).await;

                if let Some(ref tx) = log_tx {
                    let _ = tx.send("Bereinige SoftwareDistribution\\Download Cache...".to_string()).await;
                }
                let download_path = Path::new(r"C:\Windows\SoftwareDistribution\Download");
                if download_path.exists() {
                    if let Ok(entries) = std::fs::read_dir(download_path) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_file() {
                                let _ = std::fs::remove_file(path);
                            } else if path.is_dir() {
                                let _ = std::fs::remove_dir_all(path);
                            }
                        }
                    }
                }

                if let Some(ref tx) = log_tx {
                    let _ = tx.send("Starte Windows Update Dienste wieder...".to_string()).await;
                }
                let _ = run_cmd("net.exe", &["start", "wuauserv"], Duration::from_secs(15)).await;
                let _ = run_cmd("net.exe", &["start", "bits"], Duration::from_secs(15)).await;
                let _ = run_cmd("net.exe", &["start", "cryptsvc"], Duration::from_secs(15)).await;

                Ok("SoftwareDistribution Download-Cache erfolgreich bereinigt und Dienste neu gestartet.".to_string())
            }
            "wu_reboot_pending" => {
                Ok("Ausstehender Neustart vermerkt. Bitte führen Sie nach Abschluss einen System-Neustart durch.".to_string())
            }
            _ => Err(format!("Unbekannte Problem-ID: {}", issue_id)),
        }
    }
}
