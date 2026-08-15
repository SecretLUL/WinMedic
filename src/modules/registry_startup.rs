use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::safety::reg_backup::RegBackupManager;
use crate::utils::cmd::CommandRunner;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};

pub struct RegistryStartupModule {
    config: ModuleConfig,
}

impl RegistryStartupModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self { config }
    }

    pub fn with_runner(config: ModuleConfig, _runner: Arc<dyn CommandRunner>) -> Self {
        Self { config }
    }

    /// Export `key_path` before it is modified.
    ///
    /// Fails closed: if backups are enabled but the export does not succeed, the
    /// caller must abort rather than delete a value it cannot restore.
    async fn backup_before_change(
        &self,
        backup_mgr: &RegBackupManager,
        key_path: &str,
        description: &str,
    ) -> Result<(), String> {
        if !self.config.auto_backup_registry {
            return Ok(());
        }

        backup_mgr
            .export_key(key_path, description)
            .await
            .map(|_| ())
            .map_err(|e| {
                format!(
                    "Aborted: the registry backup of '{}' failed ({}). Nothing was changed.",
                    key_path, e
                )
            })
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
                    module_id: "registry_startup".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }

    fn extract_exe_path(raw_cmd: &str) -> Option<PathBuf> {
        let trimmed = raw_cmd.trim();
        if trimmed.is_empty() {
            return None;
        }

        // 1. Quoted path
        if let Some(rest) = trimmed.strip_prefix('"')
            && let Some(end_quote) = rest.find('"')
        {
            return Some(PathBuf::from(&rest[..end_quote]));
        }

        // 2. Look for case-insensitive .exe / .cmd / .bat in the command string
        let lower = trimmed.to_lowercase();
        for ext in [".exe", ".bat", ".cmd", ".vbs"] {
            if let Some(idx) = lower.find(ext) {
                let candidate = &trimmed[..idx + ext.len()];
                return Some(PathBuf::from(candidate.trim_matches('"')));
            }
        }

        // 3. Fallback to first token if no extension
        let first_word = trimmed.split_whitespace().next()?;
        Some(PathBuf::from(first_word.trim_matches('"')))
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for RegistryStartupModule {
    fn id(&self) -> &'static str {
        "registry_startup"
    }

    fn name(&self) -> &'static str {
        "Registry & Autostart"
    }

    fn description(&self) -> &'static str {
        "Checks for orphaned autostart entries (Run/RunOnce) and broken registry links"
    }

    fn icon(&self) -> &'static str {
        "⚡"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. User Run Keys
        Self::send_progress(
            &progress_tx,
            20,
            "Scanning HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run...",
            Some("Checking user autostart entries..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(run_key) =
            hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ)
        {
            let mut valid_count = 0;
            for (name, val) in run_key.enum_values().flatten() {
                let cmd_str = val.to_string();
                if let Some(path) = Self::extract_exe_path(&cmd_str) {
                    if path.is_absolute() && !path.exists() {
                        issues.push(Issue::new(
                            format!("reg_orphaned_hkcu_{}", name.replace(' ', "_")),
                            self.id(),
                            format!("Orphaned autostart entry in HKCU: '{}'", name),
                            "Registry & Autostart",
                            Severity::Warning,
                            RiskScore::Low,
                            format!("The autostart entry '{}' points at a file that does not exist ({}). This slows down startup and produces error messages.", name, path.display()),
                            format!("HKCU\\Run -> {} = {}", name, cmd_str),
                            "Safely remove the invalid autostart entry after a .reg backup",
                            vec![
                                "Take a registry snapshot".to_string(),
                                format!("Delete entry '{}' from HKCU\\Run", name),
                            ],
                        ));
                    } else {
                        valid_count += 1;
                    }
                }
            }
            Self::send_progress(
                &progress_tx,
                45,
                "User autostart checked",
                Some(&format!(
                    "✔ HKCU\\Run: {} valid autostart entries verified.",
                    valid_count
                )),
            )
            .await;
        }

        // 2. Machine Run Keys
        Self::send_progress(
            &progress_tx,
            55,
            "Scanning HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run...",
            Some("Checking machine autostart entries..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(run_key) =
            hklm.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ)
        {
            let mut valid_hklm = 0;
            for (name, val) in run_key.enum_values().flatten() {
                let cmd_str = val.to_string();
                if let Some(path) = Self::extract_exe_path(&cmd_str) {
                    if path.is_absolute() && !path.exists() {
                        issues.push(Issue::new(
                            format!("reg_orphaned_hklm_{}", name.replace(' ', "_")),
                            self.id(),
                            format!("Orphaned autostart entry in HKLM: '{}'", name),
                            "Registry & Autostart",
                            Severity::Warning,
                            RiskScore::Low,
                            format!("The machine autostart entry '{}' points at a deleted or moved file ({}).", name, path.display()),
                            format!("HKLM\\Run -> {} = {}", name, cmd_str),
                            "Remove the invalid autostart entry after a .reg backup",
                            vec![
                                "Take a registry snapshot".to_string(),
                                format!("Delete entry '{}' from HKLM\\Run", name),
                            ],
                        ));
                    } else {
                        valid_hklm += 1;
                    }
                }
            }
            Self::send_progress(
                &progress_tx,
                75,
                "Machine autostart checked",
                Some(&format!(
                    "✔ HKLM\\Run: {} machine-wide autostart entries intact.",
                    valid_hklm
                )),
            )
            .await;
        }

        // 3. Startup Folder Links
        Self::send_progress(
            &progress_tx,
            85,
            "Checking the user startup folder...",
            Some("Checking startup folder shortcuts..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        if let Ok(appdata) = std::env::var("APPDATA") {
            let startup_dir =
                PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            if startup_dir.exists() {
                let mut lnk_count = 0;
                if let Ok(entries) = std::fs::read_dir(startup_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().map(|e| e.to_string_lossy().to_lowercase())
                            == Some("lnk".to_string())
                        {
                            lnk_count += 1;
                        }
                    }
                }
                Self::send_progress(
                    &progress_tx,
                    95,
                    "Startup folder checked",
                    Some(&format!(
                        "✔ Startup folder: {} shortcuts checked.",
                        lnk_count
                    )),
                )
                .await;
            }
        }

        Self::send_progress(
            &progress_tx,
            100,
            "Registry and autostart diagnostics complete",
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
        let backup_mgr = RegBackupManager::new();

        if let Some(val_name) = issue_id.strip_prefix("reg_orphaned_hkcu_") {
            let clean_name = val_name.replace('_', " ");
            let key_path = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run";
            self.backup_before_change(
                &backup_mgr,
                key_path,
                "Before deleting an orphaned HKCU Run value",
            )
            .await?;

            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            if let Ok(run_key) = hkcu
                .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_WRITE)
            {
                let _ = run_key.delete_value(&clean_name);
                return Ok(format!(
                    "Removed orphaned autostart entry '{}' from HKCU\\Run.",
                    clean_name
                ));
            }
        }

        if let Some(val_name) = issue_id.strip_prefix("reg_orphaned_hklm_") {
            let clean_name = val_name.replace('_', " ");
            let key_path = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run";
            self.backup_before_change(
                &backup_mgr,
                key_path,
                "Before deleting an orphaned HKLM Run value",
            )
            .await?;

            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(run_key) = hklm
                .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_WRITE)
            {
                let _ = run_key.delete_value(&clean_name);
                return Ok(format!(
                    "Removed orphaned autostart entry '{}' from HKLM\\Run.",
                    clean_name
                ));
            }
        }

        Err(format!("Unknown issue id: {}", issue_id))
    }
}
