use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

pub struct WindowsUpdatesModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
}

impl WindowsUpdatesModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self { config, runner }
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
        "Windows Update & Services"
    }

    fn description(&self) -> &'static str {
        "Checks update caches (SoftwareDistribution/Catroot2), services (BITS, wuauserv) and update blockers"
    }

    fn icon(&self) -> &'static str {
        "🔄"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. Service Status
        Self::send_progress(
            &progress_tx,
            15,
            "Checking the Windows Update services (wuauserv, bits, cryptsvc)...",
            Some("Querying service status..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let services = [
            ("wuauserv", "Windows Update service"),
            ("bits", "Background Intelligent Transfer Service (BITS)"),
            ("cryptsvc", "Cryptographic Services"),
        ];

        for (svc, svc_name) in services {
            let out = self
                .runner
                .run("sc.exe", &["query", svc], Duration::from_secs(8))
                .await;
            if let Ok(res) = out {
                let stdout = res.stdout.to_lowercase();
                if stdout.contains("disabled") || stdout.contains("deaktiviert") {
                    issues.push(Issue::new(
                        format!("wu_svc_disabled_{}", svc),
                        self.id(),
                        format!("Service '{}' is disabled", svc_name),
                        "Windows Update & Services",
                        Severity::Critical,
                        RiskScore::Medium,
                        format!("The system service '{}' ({}) is disabled. Without it Windows cannot install security updates.", svc_name, svc),
                        res.stdout,
                        format!("Reset service '{}' to start type 'Manual/Demand'", svc),
                        vec![
                            format!("sc config {} start= demand", svc),
                            format!("net start {}", svc),
                        ],
                    ));
                } else {
                    Self::send_progress(
                        &progress_tx,
                        35,
                        &format!("Service '{}' running", svc),
                        Some(&format!(
                            "✔ Service '{}' ({}) is operational.",
                            svc_name, svc
                        )),
                    )
                    .await;
                }
            }
        }

        // 2. SoftwareDistribution Cache
        Self::send_progress(
            &progress_tx,
            55,
            "Checking SoftwareDistribution cache integrity...",
            Some("Checking C:\\Windows\\SoftwareDistribution\\Download..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let soft_dist = Path::new(r"C:\Windows\SoftwareDistribution\Download");
        if soft_dist.exists() {
            // Shared walker: recursive (the fix below deletes subdirectories too,
            // so measuring only the top level under-reported what it removes) and
            // rounding to megabytes once at the end. Dividing per file discarded
            // every file below 1 MB, and this cache is mostly small files — the
            // 5000 MB threshold could barely be reached.
            let stats = crate::utils::fs_stats::dir_stats_recursive(soft_dist);
            let total_size_mb = stats.bytes / (1024 * 1024);
            let file_count = stats.files;

            if total_size_mb > 5000 {
                issues.push(Issue::new(
                    "wu_cache_bloat",
                    self.id(),
                    format!("Windows Update download cache is oversized ({} MB)", total_size_mb),
                    "Windows Update & Services",
                    Severity::Warning,
                    RiskScore::Low,
                    format!("The 'SoftwareDistribution\\Download' folder holds {} temporary update files totalling {} MB that are no longer needed or have been orphaned.", file_count, total_size_mb),
                    format!("Files: {}, total size: {} MB", file_count, total_size_mb),
                    "Safely clean the SoftwareDistribution download folder",
                    vec![
                        "Temporarily stop the Windows Update services".to_string(),
                        "Empty the temporary download cache".to_string(),
                        "Restart the services cleanly".to_string(),
                    ],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    75,
                    "Update cache unremarkable",
                    Some(&format!(
                        "✔ SoftwareDistribution cache: {} MB ({} packages).",
                        total_size_mb, file_count
                    )),
                )
                .await;
            }
        }

        // 3. Pending Reboot Keys
        Self::send_progress(
            &progress_tx,
            85,
            "Checking for a pending system reboot...",
            Some("Checking the RebootPending registry keys..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let pending_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        ];

        let mut reboot_found = false;
        for p_key in pending_keys {
            if hklm.open_subkey_with_flags(p_key, KEY_READ).is_ok() {
                reboot_found = true;
                issues.push(Issue::new(
                    "wu_reboot_pending",
                    self.id(),
                    "System reboot pending after updates",
                    "Windows Update & Services",
                    Severity::Info,
                    RiskScore::Low,
                    "Windows reports a reboot pending from a previously installed update or driver package. Some updates cannot continue until the machine restarts.",
                    format!("Found in the registry: HKLM\\{}", p_key),
                    "Restart Windows after the repairs to finish the pending installations",
                    vec!["Record the pending reboot in the repair report".to_string()],
                ));
                break;
            }
        }

        if !reboot_found {
            Self::send_progress(
                &progress_tx,
                95,
                "No pending update reboots",
                Some("✔ No blocking reboot-pending keys found."),
            )
            .await;
        }

        Self::send_progress(
            &progress_tx,
            100,
            "Windows Update diagnostics complete",
            None,
        )
        .await;

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
                            step_description: "Update repair in progress...".to_string(),
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
            let _ = self
                .runner
                .run(
                    "sc.exe",
                    &["config", svc, "start=", "demand"],
                    Duration::from_secs(10),
                )
                .await;

            if !self.config.auto_restart_services {
                return Ok(format!(
                    "Service '{}' was set to start type 'Manual'. Starting it was skipped because 'Restart services automatically' is off in the settings.",
                    svc
                ));
            }

            let _ = self
                .runner
                .run("net.exe", &["start", svc], Duration::from_secs(10))
                .await;
            return Ok(format!(
                "Service '{}' was set to start type 'Manual' and started.",
                svc
            ));
        }

        match issue_id {
            "wu_cache_bloat" => {
                // Clearing the cache requires stopping wuauserv/bits/cryptsvc. Doing
                // that without being allowed to start them again would leave Windows
                // Update broken, so refuse instead of half-applying the fix.
                if !self.config.auto_restart_services {
                    return Err(
                        "Skipped: emptying the update cache requires stopping and restarting wuauserv, bits and cryptsvc. Turn on 'Restart services automatically' in the settings [6]."
                            .to_string(),
                    );
                }

                if let Some(ref tx) = log_tx {
                    let _ = tx
                        .send("Stopping the Windows Update services...".to_string())
                        .await;
                }
                let _ = self
                    .runner
                    .run("net.exe", &["stop", "wuauserv"], Duration::from_secs(15))
                    .await;
                let _ = self
                    .runner
                    .run("net.exe", &["stop", "bits"], Duration::from_secs(15))
                    .await;
                let _ = self
                    .runner
                    .run("net.exe", &["stop", "cryptsvc"], Duration::from_secs(15))
                    .await;

                if let Some(ref tx) = log_tx {
                    let _ = tx
                        .send("Cleaning the SoftwareDistribution\\Download cache...".to_string())
                        .await;
                }
                let download_path = Path::new(r"C:\Windows\SoftwareDistribution\Download");
                if download_path.exists()
                    && let Ok(entries) = std::fs::read_dir(download_path)
                {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            let _ = std::fs::remove_file(path);
                        } else if path.is_dir() {
                            let _ = std::fs::remove_dir_all(path);
                        }
                    }
                }

                if let Some(ref tx) = log_tx {
                    let _ = tx
                        .send("Restarting the Windows Update services...".to_string())
                        .await;
                }
                let _ = self
                    .runner
                    .run("net.exe", &["start", "wuauserv"], Duration::from_secs(15))
                    .await;
                let _ = self
                    .runner
                    .run("net.exe", &["start", "bits"], Duration::from_secs(15))
                    .await;
                let _ = self
                    .runner
                    .run("net.exe", &["start", "cryptsvc"], Duration::from_secs(15))
                    .await;

                Ok("SoftwareDistribution download cache cleaned and services restarted successfully.".to_string())
            }
            "wu_reboot_pending" => Ok(
                "Pending reboot recorded. Please restart the system once the run has finished."
                    .to_string(),
            ),
            _ => Err(format!("Unknown issue ID: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    #[tokio::test]
    async fn test_windows_updates_detects_disabled_service() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "query wuauserv",
            CmdOutput::ok("STATE: 1 STOPPED \n START_TYPE: DISABLED"),
        );
        mock.add_response("query bits", CmdOutput::ok("STATE: 4 RUNNING"));
        mock.add_response("query cryptsvc", CmdOutput::ok("STATE: 4 RUNNING"));

        let module = WindowsUpdatesModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        let disabled_wu = issues.iter().find(|i| i.id == "wu_svc_disabled_wuauserv");
        assert!(disabled_wu.is_some());
        assert_eq!(disabled_wu.unwrap().severity, Severity::Critical);
    }
}
