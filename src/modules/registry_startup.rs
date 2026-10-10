use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::safety::reg_backup::RegBackupManager;
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::registry::{self, RegValue};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

/// The two Run keys, each with the prefix of its findings' ids.
const RUN_KEYS: [(&str, &str); 2] = [
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "reg_orphaned_hkcu_",
    ),
    (
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        "reg_orphaned_hklm_",
    ),
];

/// The id of the finding for the Run value `name` under the key with
/// `prefix`: `reg_orphaned_hkcu_my_tool` for "My Tool".
///
/// Only an id: the repair reads the key again and deletes the value by its
/// real name. Turning the id back into a name made every `_` a space, so a
/// value named `My_Tool` was never deleted, or another one was.
fn issue_id(prefix: &str, name: &str) -> String {
    let slug: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{prefix}{slug}")
}

/// What `GetDriveTypeW` reports for the root of a drive letter. A function,
/// so that a test can pick the drives.
pub type DriveTypeSource = Arc<dyn Fn(char) -> u32 + Send + Sync>;

/// `GetDriveTypeW`: a disk of this PC. A network drive is 4, a removable
/// one 2, and a letter nothing is mounted at 1.
pub const DRIVE_FIXED: u32 = 3;

/// `GetDriveTypeW` of `X:\`. It reads the drive table without touching the
/// drive, so a share that does not answer cannot stall the scan.
pub(crate) fn real_drive_type() -> DriveTypeSource {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    Arc::new(|letter| {
        let root: Vec<u16> = format!("{letter}:\\")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        unsafe { GetDriveTypeW(root.as_ptr()) }
    })
}

/// Whether `path` names a file by the letter of a fixed drive of this PC
/// (`C:\...`, `\\?\C:\...`). A share, `\\?\UNC\...` and `\\.\...` are
/// not drive letters, and a mapped, removable or absent drive is no fixed
/// one: only on a fixed drive does a missing file prove a program is gone.
pub(crate) fn on_fixed_drive(path: &Path, drive_type: &dyn Fn(char) -> u32) -> bool {
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return false;
    };
    let (Prefix::Disk(letter) | Prefix::VerbatimDisk(letter)) = prefix.kind() else {
        return false;
    };
    drive_type(char::from(letter).to_ascii_uppercase()) == DRIVE_FIXED
}

/// The file a Run value starts, if it names one by an absolute path on a
/// fixed drive of this PC and that file is not there.
///
/// Only there is a missing file proof that the program is gone. WinMedic
/// runs elevated, and the drive letters the user mapped belong to the
/// unelevated session, so a program on a mapped drive looked missing; so did
/// one on a USB disk that is unplugged now. A share (`\\server\share`) may
/// just not answer.
fn missing_target(value: &RegValue, drive_type: &dyn Fn(char) -> u32) -> Option<PathBuf> {
    // `reg` prints the unnamed default value as "(Default)" in the display
    // language; deleting a value of that name would hit the wrong one.
    if value.name.starts_with('(') && value.name.ends_with(')') {
        return None;
    }
    let path = RegistryStartupModule::extract_exe_path(&value.data)?;
    (path.is_absolute() && on_fixed_drive(&path, drive_type) && !path.exists()).then_some(path)
}

pub struct RegistryStartupModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
    drive_type: DriveTypeSource,
    backup_dir: PathBuf,
}

impl RegistryStartupModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            config,
            runner,
            drive_type: real_drive_type(),
            backup_dir: RegBackupManager::new().backup_dir().to_path_buf(),
        }
    }

    /// For tests: drives other than the machine's own.
    pub fn with_drive_type(mut self, drive_type: DriveTypeSource) -> Self {
        self.drive_type = drive_type;
        self
    }

    /// Export `key_path` before it is modified.
    ///
    /// Fails closed: if backups are enabled but the export does not succeed, the
    /// caller must abort rather than delete a value it cannot restore.
    async fn backup_before_change(&self, key_path: &str, description: &str) -> Result<(), String> {
        if !self.config.auto_backup_registry {
            return Ok(());
        }

        RegBackupManager::with_dir(self.backup_dir.clone())
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

    /// The values of the Run key `key`; none when it does not exist.
    async fn run_values(&self, key: &str) -> Result<Vec<RegValue>, String> {
        let keys = registry::query(&*self.runner, key, false)
            .await?
            .unwrap_or_default();
        Ok(keys.into_iter().flat_map(|k| k.values).collect())
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

        // 2. Look for case-insensitive .exe / .cmd / .bat in the command string.
        // Lowering only ASCII keeps every byte position, so an index found in
        // `lower` is valid in `trimmed` too. `to_lowercase` changes the byte
        // length of some letters (U+0130, U+212A) and moved the cut.
        let lower = trimmed.to_ascii_lowercase();
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

    /// Delete every Run value under `key` whose finding is `issue_id` and
    /// whose file is still missing, then read the key back.
    async fn remove_orphans(
        &self,
        key: &str,
        prefix: &str,
        issue_id: &str,
    ) -> Result<String, String> {
        let names: Vec<String> = self
            .run_values(key)
            .await?
            .into_iter()
            .filter(|v| {
                self::issue_id(prefix, &v.name) == issue_id
                    && missing_target(v, &*self.drive_type).is_some()
            })
            .map(|v| v.name)
            .collect();
        if names.is_empty() {
            return Ok("The autostart entry is already gone.".to_string());
        }

        self.backup_before_change(key, "Before deleting an orphaned Run value")
            .await?;
        for name in &names {
            let out = self
                .runner
                .run(
                    "reg.exe",
                    &["delete", key, "/v", name, "/f"],
                    Duration::from_secs(10),
                )
                .await?;
            if !out.success {
                return Err(format!(
                    "The autostart entry '{name}' could not be deleted (reg delete exit code {:?}): {}",
                    out.exit_code,
                    out.stderr.trim()
                ));
            }
        }

        let left: Vec<String> = self
            .run_values(key)
            .await?
            .into_iter()
            .map(|v| v.name)
            .filter(|n| names.contains(n))
            .collect();
        if left.is_empty() {
            Ok(format!(
                "Removed the autostart entry '{}' from {key}.",
                names.join("', '")
            ))
        } else {
            Err(format!(
                "The autostart entry '{}' is still in {key} after deleting it.",
                left.join("', '")
            ))
        }
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
        "Checks the Run keys for autostart entries whose program is gone"
    }

    fn icon(&self) -> &'static str {
        "[REG]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues: Vec<Issue> = Vec::new();

        for (step, (key, prefix)) in RUN_KEYS.iter().enumerate() {
            Self::send_progress(
                &progress_tx,
                20 + 40 * step as u8,
                &format!("Scanning {key}..."),
                Some("Checking autostart entries..."),
            )
            .await;

            let values = match self.run_values(key).await {
                Ok(values) => values,
                Err(err) => {
                    Self::send_progress(
                        &progress_tx,
                        40 + 40 * step as u8,
                        "Not readable",
                        Some(&err),
                    )
                    .await;
                    continue;
                }
            };
            let mut valid = 0;
            for value in &values {
                let Some(path) = missing_target(value, &*self.drive_type) else {
                    valid += 1;
                    continue;
                };
                let id = issue_id(prefix, &value.name);
                // "My Tool" and "My_Tool" share an id; the repair removes both.
                if issues.iter().any(|i| i.id == id) {
                    continue;
                }
                issues.push(Issue::new(
                    id,
                    self.id(),
                    format!("Autostart entry without its program: '{}'", value.name),
                    "Registry & Autostart",
                    Severity::Warning,
                    RiskScore::Low,
                    format!(
                        "The autostart entry '{}' starts a file that does not exist ({}), usually left by a program that was uninstalled.",
                        value.name,
                        path.display()
                    ),
                    format!("{key}\n{} = {}", value.name, value.data),
                    "Remove the autostart entry after a .reg backup",
                    vec![
                        "Take a registry snapshot".to_string(),
                        format!("Delete '{}' from {key}", value.name),
                    ],
                ));
            }
            Self::send_progress(
                &progress_tx,
                40 + 40 * step as u8,
                "Autostart entries checked",
                Some(&format!("{key}: {valid} entries intact.")),
            )
            .await;
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
        for (key, prefix) in RUN_KEYS {
            if issue_id.starts_with(prefix) {
                return self.remove_orphans(key, prefix, issue_id).await;
            }
        }
        Err(format!("Unknown issue id: {}", issue_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    /// `reg query` of the HKLM Run key on a German Windows 11, as captured.
    fn real_run_key() -> String {
        crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/reg_query_run_hklm.bin"
        ))
    }

    /// The same key with one more value, whose program is gone.
    fn run_key_with(name: &str) -> String {
        format!(
            "{}\r\n    {name}    REG_SZ    \"C:\\WinMedic-no-such-dir\\tool.exe\" --tray\r\n",
            real_run_key().trim_end()
        )
    }

    /// The same key with these values added, each `(name, data)` as REG_SZ.
    fn run_key_plus(values: &[(&str, &str)]) -> String {
        let mut text = real_run_key().trim_end().to_string();
        for (name, data) in values {
            text.push_str(&format!("\r\n    {name}    REG_SZ    {data}"));
        }
        text + "\r\n"
    }

    /// What `GetDriveTypeW` reports for the other kinds of drive.
    const DRIVE_NO_ROOT_DIR: u32 = 1;
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_REMOTE: u32 = 4;

    /// The drives the tests' PC has, whatever the machine running them has:
    /// C: is its disk, E: a USB stick, Z: a mapped share, and no other
    /// letter is in use.
    fn drives(letter: char) -> u32 {
        match letter {
            'C' => DRIVE_FIXED,
            'E' => DRIVE_REMOVABLE,
            'Z' => DRIVE_REMOTE,
            _ => DRIVE_NO_ROOT_DIR,
        }
    }

    fn module(mock: &MockCommandRunner) -> RegistryStartupModule {
        let config = ModuleConfig {
            auto_backup_registry: false,
            ..ModuleConfig::default()
        };
        RegistryStartupModule::with_runner(config, Arc::new(mock.clone()))
            .with_drive_type(Arc::new(drives))
    }

    #[tokio::test]
    async fn an_entry_whose_program_is_gone_is_found() {
        let mock = MockCommandRunner::new();
        mock.add_response("HKLM", CmdOutput::ok(run_key_with("My_Old Tool")));
        mock.add_response("HKCU", CmdOutput::with_output(1, "", "not found"));
        let issues = module(&mock).scan(None).await.unwrap();

        let issue = issues
            .iter()
            .find(|i| i.id == "reg_orphaned_hklm_my_old_tool")
            .expect("the program is gone");
        assert!(issue.title.contains("'My_Old Tool'"));
        assert!(
            !issues.iter().any(|i| i.id.contains("securityhealth")),
            "%windir% is not an absolute path to judge"
        );
    }

    // Elevated, WinMedic does not see the drives the user mapped; a USB disk
    // may be unplugged, a share may not answer. None of them proves that a
    // program is gone. None of these paths exists on any machine, so each
    // was a finding before.
    #[tokio::test]
    async fn only_a_program_missing_from_a_fixed_drive_is_judged() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "HKLM",
            CmdOutput::ok(run_key_plus(&[
                (
                    "Mapped Tool",
                    r#""Z:\WinMedic-no-such-dir\tool.exe" --tray"#,
                ),
                ("Stick Tool", r"E:\WinMedic-no-such-dir\tool.exe"),
                ("Unplugged Disk", r"Y:\WinMedic-no-such-dir\tool.exe /min"),
                ("Share Tool", r#""\\winmedic.invalid\share\tool.exe""#),
                ("Verbatim Share", r"\\?\UNC\winmedic.invalid\share\tool.exe"),
                ("Verbatim Gone", r"\\?\C:\WinMedic-no-such-dir\tool.exe"),
                ("Lower Case Gone", r"c:\WinMedic-no-such-dir\tool.exe"),
            ])),
        );
        mock.add_response("HKCU", CmdOutput::with_output(1, "", "not found"));
        let issues = module(&mock).scan(None).await.unwrap();
        let ids: Vec<&str> = issues.iter().map(|i| i.id.as_str()).collect();

        for left_alone in [
            "reg_orphaned_hklm_mapped_tool",
            "reg_orphaned_hklm_stick_tool",
            "reg_orphaned_hklm_unplugged_disk",
            "reg_orphaned_hklm_share_tool",
            "reg_orphaned_hklm_verbatim_share",
        ] {
            assert!(!ids.contains(&left_alone), "{left_alone}: {ids:?}");
        }
        // On the fixed drive a missing file still is one.
        assert!(ids.contains(&"reg_orphaned_hklm_verbatim_gone"), "{ids:?}");
        assert!(
            ids.contains(&"reg_orphaned_hklm_lower_case_gone"),
            "{ids:?}"
        );
    }

    #[tokio::test]
    async fn the_repair_leaves_an_entry_on_a_mapped_drive_alone() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "reg.exe query",
            CmdOutput::ok(run_key_plus(&[(
                "Mapped Tool",
                r#""Z:\WinMedic-no-such-dir\tool.exe" --tray"#,
            )])),
        );
        mock.add_response("reg.exe delete", CmdOutput::ok(""));
        let _ = module(&mock)
            .fix("reg_orphaned_hklm_mapped_tool", None)
            .await;
        assert!(
            !mock.executed().iter().any(|c| c.contains("delete")),
            "{:?}",
            mock.executed()
        );
    }

    #[tokio::test]
    async fn the_repair_deletes_the_value_by_its_real_name() {
        let mock = MockCommandRunner::new();
        mock.add_response("reg.exe query", CmdOutput::ok(run_key_with("My_Old Tool")));
        mock.add_response("reg.exe delete", CmdOutput::ok(""));
        mock.add_response_after(
            "reg.exe delete",
            "reg.exe query",
            CmdOutput::ok(real_run_key()),
        );

        let msg = module(&mock)
            .fix("reg_orphaned_hklm_my_old_tool", None)
            .await
            .unwrap();
        assert!(msg.contains("'My_Old Tool'"), "{msg}");
        assert!(mock.executed().contains(
            &r"reg.exe delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v My_Old Tool /f"
                .to_string()
        ));
    }

    #[tokio::test]
    async fn a_refused_delete_is_a_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response("reg.exe query", CmdOutput::ok(run_key_with("Tool")));
        mock.add_response(
            "reg.exe delete",
            CmdOutput::with_output(1, "", "Zugriff verweigert"),
        );
        let err = module(&mock)
            .fix("reg_orphaned_hklm_tool", None)
            .await
            .unwrap_err();
        assert!(err.contains("Zugriff verweigert"), "{err}");
    }

    #[tokio::test]
    async fn a_value_that_stays_is_a_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response("reg.exe query", CmdOutput::ok(run_key_with("Tool")));
        mock.add_response("reg.exe delete", CmdOutput::ok(""));
        let err = module(&mock)
            .fix("reg_orphaned_hklm_tool", None)
            .await
            .unwrap_err();
        assert!(err.contains("still in"), "{err}");
    }

    #[tokio::test]
    async fn an_entry_that_is_gone_already_is_not_deleted_again() {
        let mock = MockCommandRunner::new();
        mock.add_response("reg.exe query", CmdOutput::ok(real_run_key()));
        let msg = module(&mock)
            .fix("reg_orphaned_hklm_tool", None)
            .await
            .unwrap();
        assert!(msg.contains("already gone"), "{msg}");
        assert!(!mock.executed().iter().any(|c| c.contains("delete")));
    }

    #[test]
    fn the_default_value_is_never_judged() {
        let value = RegValue {
            name: "(Standard)".to_string(),
            kind: "REG_SZ".to_string(),
            data: r"C:\WinMedic-no-such-dir\tool.exe".to_string(),
        };
        assert_eq!(missing_target(&value, &drives), None);
    }

    // Some letters change their length in UTF-8 when lowercased: U+0130 grows
    // from 2 bytes to 3, U+212B and U+212A shrink from 3 to 2 and 1.
    #[test]
    fn an_unquoted_path_with_a_dotted_capital_i_stops_at_its_extension() {
        assert_eq!(
            RegistryStartupModule::extract_exe_path("C:\\Users\\\u{130}lkay\\tool.exe /background"),
            Some(PathBuf::from("C:\\Users\\\u{130}lkay\\tool.exe"))
        );
    }

    #[test]
    fn an_unquoted_path_with_a_dotted_capital_i_and_no_arguments_does_not_panic() {
        assert_eq!(
            RegistryStartupModule::extract_exe_path("C:\\Users\\\u{130}lkay\\tool.exe"),
            Some(PathBuf::from("C:\\Users\\\u{130}lkay\\tool.exe"))
        );
    }

    #[test]
    fn an_unquoted_path_with_angstrom_and_kelvin_signs_stops_at_its_extension() {
        assert_eq!(
            RegistryStartupModule::extract_exe_path(
                "C:\\Program Files\\\u{212B}\u{212A}\\tool.exe --min"
            ),
            Some(PathBuf::from(
                "C:\\Program Files\\\u{212B}\u{212A}\\tool.exe"
            ))
        );
    }
}
