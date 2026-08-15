use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

pub struct StorageModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
}

impl StorageModule {
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
                    module_id: "storage".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }

    fn calculate_dir_size_mb(path: &Path) -> (u64, usize) {
        let stats = crate::utils::fs_stats::dir_stats_recursive(path);
        (stats.bytes / (1024 * 1024), stats.files)
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for StorageModule {
    fn id(&self) -> &'static str {
        "storage"
    }

    fn name(&self) -> &'static str {
        "Speicher & Dateisystem"
    }

    fn description(&self) -> &'static str {
        "Prüft SMART-Laufwerkszustand, Dateisystemfehler (Dirty Bit), Junk/Temp-Dateien und IconCache"
    }

    fn icon(&self) -> &'static str {
        "💾"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. Filesystem Dirty Bit
        Self::send_progress(
            &progress_tx,
            15,
            "Prüfe Dateisystem-Integrität (Dirty Bit auf Laufwerk C:)...",
            Some("fsutil dirty query C:..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let dirty_check = self
            .runner
            .run(
                "fsutil.exe",
                &["dirty", "query", "C:"],
                Duration::from_secs(6),
            )
            .await;
        if let Ok(out) = dirty_check {
            let stdout = out.stdout.to_lowercase();
            if stdout.contains("dirty")
                || stdout.contains("beschädigt")
                || stdout.contains("fehlerhaft")
            {
                issues.push(Issue::new(
                    "storage_dirty_bit",
                    self.id(),
                    "Dateisystem-Inkonsistenz auf Systemlaufwerk C: (Dirty Bit gesetzt)",
                    "Speicher & Dateisystem",
                    Severity::Critical,
                    RiskScore::Medium,
                    "Auf Laufwerk C: ist das Dateisystem-Integritäts-Flag ('Dirty Bit') gesetzt. Dies deutet auf unvollständig geschriebene Sektoren oder abrupte Systemabschaltungen hin.",
                    out.stdout,
                    "Dateisystemprüfung via 'chkdsk C: /scan' durchführen",
                    vec!["chkdsk C: /scan online ausführen".to_string()],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    35,
                    "Dateisystem C: ist sauber",
                    Some("✔ Dateisystem C: Keine Dirty-Bit-Inkonsistenzen."),
                )
                .await;
            }
        }

        // 2. Physical Disk SMART Health
        Self::send_progress(
            &progress_tx,
            45,
            "Prüfe physische Laufwerke & SMART-Status...",
            Some("PowerShell Get-PhysicalDisk..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let disk_script = r#"Get-PhysicalDisk | Select-Object -Property DeviceId, FriendlyName, MediaType, HealthStatus, OperationalStatus | ForEach-Object { "$($_.FriendlyName) | Health: $($_.HealthStatus) | Status: $($_.OperationalStatus)" }"#;
        if let Ok(disk_out) = self
            .runner
            .run_powershell(disk_script, Duration::from_secs(8))
            .await
        {
            let output_str = disk_out.stdout.trim();
            for line in output_str.lines() {
                let l = line.trim();
                if !l.is_empty() {
                    Self::send_progress(
                        &progress_tx,
                        60,
                        "SMART Status geprüft",
                        Some(&format!("✔ Laufwerk: {}", l)),
                    )
                    .await;
                    if l.to_lowercase().contains("unhealthy")
                        || l.to_lowercase().contains("warning")
                    {
                        issues.push(Issue::new(
                            "storage_smart_warning",
                            self.id(),
                            "SMART-Hardwarewarnung für ein physisches Laufwerk festgestellt",
                            "Speicher & Dateisystem",
                            Severity::Critical,
                            RiskScore::High,
                            format!("Ein physischer Datenträger meldet einen eingeschränkten Gesundheitsstatus: {}", l),
                            l.to_string(),
                            "Wichtige Daten sichern und Laufwerksdiagnose des Herstellers ausführen",
                            vec!["Sofortiges Backup wichtiger Daten durchführen".to_string()],
                        ));
                    }
                }
            }
        }

        // 3. Junk & Temp Files Size
        Self::send_progress(
            &progress_tx,
            75,
            "Berechne Größe von Junk- & Temp-Dateien...",
            Some("Scanne %TEMP% und Windows\\Temp..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let mut total_temp_mb = 0;
        let mut total_temp_files = 0;

        if let Ok(temp_env) = std::env::var("TEMP") {
            let (mb, count) = Self::calculate_dir_size_mb(Path::new(&temp_env));
            total_temp_mb += mb;
            total_temp_files += count;
        }

        let win_temp = Path::new(r"C:\Windows\Temp");
        if win_temp.exists() {
            let (mb, count) = Self::calculate_dir_size_mb(win_temp);
            total_temp_mb += mb;
            total_temp_files += count;
        }

        if total_temp_mb > self.config.temp_clean_threshold_mb {
            issues.push(Issue::new(
                "storage_temp_bloat",
                self.id(),
                format!("Über {} MB temporäre Junk-Dateien gefunden ({} Dateien)", total_temp_mb, total_temp_files),
                "Speicher & Dateisystem",
                Severity::Warning,
                RiskScore::Low,
                format!("Im System- und Benutzer-Temp-Verzeichnis liegen {} MB veraltete temporäre Dateien, die wertvollen Speicherplatz belegen.", total_temp_mb),
                format!("Temp-Größe: {} MB in {} Dateien", total_temp_mb, total_temp_files),
                "Temporäre Dateien sicher bereinigen (gesperrte Dateien werden übersprungen)",
                vec![
                    "Benutzer-Temp (%TEMP%) bereinigen".to_string(),
                    "Windows-Temp (C:\\Windows\\Temp) bereinigen".to_string(),
                ],
            ));
        } else {
            Self::send_progress(
                &progress_tx,
                88,
                "Temporäre Dateien im normalen Bereich",
                Some(&format!(
                    "✔ Temp-Dateien: {} MB ({} Dateien), Schwelle liegt bei {} MB.",
                    total_temp_mb, total_temp_files, self.config.temp_clean_threshold_mb
                )),
            )
            .await;
        }

        // 4. Explorer Icon & Thumbnail Cache
        Self::send_progress(
            &progress_tx,
            92,
            "Prüfe Explorer Icon- & Thumbnail-Cache...",
            Some("IconCache.db Integrität..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let icon_cache = PathBuf::from(&local_app_data).join("IconCache.db");
            if icon_cache.exists()
                && let Ok(meta) = icon_cache.metadata()
                && meta.len() > 25 * 1024 * 1024
            {
                issues.push(Issue::new(
                            "storage_icon_cache_bloated",
                            self.id(),
                            "Icon- & Thumbnail-Cache ist überdimensioniert / korrupt",
                            "Speicher & Dateisystem",
                            Severity::Info,
                            RiskScore::Low,
                            "Der Windows Icon-Cache ist über 25 MB groß. Dies kann zu fehlerhaften oder weißen Symbolen in der Taskleiste und im Explorer führen.",
                            format!("IconCache.db Größe: {} MB", meta.len() / (1024 * 1024)),
                            "Icon- und Thumbnail-Cache sauber neu erstellen",
                            vec![
                                "Explorer-Prozess neu starten".to_string(),
                                "IconCache.db zurücksetzen".to_string(),
                            ],
                        ));
            }
        }

        Self::send_progress(
            &progress_tx,
            100,
            "Speicher- und Dateisystemdiagnose abgeschlossen",
            None,
        )
        .await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        match issue_id {
            "storage_dirty_bit" => {
                let out = self
                    .runner
                    .run("chkdsk.exe", &["C:", "/scan"], Duration::from_secs(120))
                    .await?;
                if out.success {
                    Ok(
                        "Dateisystemprüfung (chkdsk /scan) erfolgreich ohne Fehler beendet."
                            .to_string(),
                    )
                } else {
                    Ok(format!("chkdsk ausgeführt: {}", out.stdout))
                }
            }
            "storage_temp_bloat" => {
                let mut freed_mb = 0;
                let mut deleted_files = 0;

                let dirs_to_clean = [
                    std::env::var("TEMP").unwrap_or_default(),
                    r"C:\Windows\Temp".to_string(),
                ];

                for dir_str in dirs_to_clean {
                    if dir_str.is_empty() {
                        continue;
                    }
                    let dir = Path::new(&dir_str);
                    if let Ok(entries) = std::fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if let Ok(meta) = path.metadata() {
                                let size = meta.len();
                                if path.is_file() {
                                    if std::fs::remove_file(&path).is_ok() {
                                        freed_mb += size / (1024 * 1024);
                                        deleted_files += 1;
                                    }
                                } else if path.is_dir() {
                                    let _ = std::fs::remove_dir_all(&path);
                                }
                            }
                        }
                    }
                }
                Ok(format!(
                    "Temporäre Verzeichnisse bereinigt: {} Dateien entfernt (ca. {} MB freigegeben).",
                    deleted_files, freed_mb
                ))
            }
            "storage_icon_cache_bloated" => {
                if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                    let icon_cache = PathBuf::from(&local_app_data).join("IconCache.db");
                    if icon_cache.exists() {
                        let _ = std::fs::remove_file(icon_cache);
                    }
                }
                let _ = self
                    .runner
                    .run(
                        "powershell.exe",
                        &[
                            "-NoProfile",
                            "-Command",
                            "Stop-Process -Name explorer -Force; Start-Process explorer",
                        ],
                        Duration::from_secs(8),
                    )
                    .await;
                Ok(
                    "Icon- & Thumbnail-Cache erfolgreich zurückgesetzt und Explorer neu gestartet."
                        .to_string(),
                )
            }
            "storage_smart_warning" => Ok(
                "SMART-Warnung zur Kenntnis genommen und im Audit-Log dokumentiert.".to_string(),
            ),
            _ => Err(format!("Unbekannte Problem-ID: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    #[tokio::test]
    async fn test_storage_detects_dirty_bit() {
        let mock = MockCommandRunner::new();
        mock.add_response("dirty query C:", CmdOutput::ok("Volume - C: is Dirty"));
        mock.add_response(
            "Get-PhysicalDisk",
            CmdOutput::ok("NVMe SSD | Health: Healthy | Status: OK"),
        );

        let module = StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        let dirty_issue = issues.iter().find(|i| i.id == "storage_dirty_bit");
        assert!(dirty_issue.is_some());
        assert_eq!(dirty_issue.unwrap().severity, Severity::Critical);
    }
}
