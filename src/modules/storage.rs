use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::admin::is_admin;
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::debug_log::DebugTrace;
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
        "Storage & File System"
    }

    fn description(&self) -> &'static str {
        "Checks SMART drive health, file system errors (dirty bit), junk/temp files and the icon cache"
    }

    fn icon(&self) -> &'static str {
        "[DSK]"
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
            "Checking file system integrity (dirty bit on drive C:)...",
            Some("fsutil dirty query C:..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let dbg = DebugTrace::scan(self.id(), progress_tx.clone(), self.config.verbose_logging);

        let dirty_check = dbg
            .run(
                &self.runner,
                "fsutil.exe",
                &["dirty", "query", "C:"],
                Duration::from_secs(6),
            )
            .await;
        if let Ok(out) = dirty_check
            && out.success
        {
            let verdict = volume_is_dirty(&out.stdout);
            dbg.kv("dirty bit", if verdict { "set" } else { "clear" })
                .await;
            if verdict {
                issues.push(Issue::new(
                    "storage_dirty_bit",
                    self.id(),
                    "File system inconsistency on system drive C: (dirty bit set)",
                    "Storage & File System",
                    Severity::Critical,
                    RiskScore::Medium,
                    "Drive C: has the file system integrity flag ('dirty bit') set. That points to incompletely written sectors or abrupt shutdowns.",
                    out.stdout,
                    "Run a file system check via 'chkdsk C: /scan'",
                    vec!["Run chkdsk C: /scan online".to_string()],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    35,
                    "File system C: is clean",
                    Some("File system C: no dirty-bit inconsistencies."),
                )
                .await;
            }
        } else {
            // fsutil needs elevation to read the dirty bit. A refused query says
            // nothing about the volume, and treating its error text as a verdict
            // is how a healthy disk ends up scheduled for chkdsk.
            dbg.warn("fsutil could not read the dirty bit - the volume state is unknown, not bad")
                .await;
        }

        // 2. Physical Disk SMART Health
        Self::send_progress(
            &progress_tx,
            45,
            "Checking physical drives & SMART status...",
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
                        "SMART status checked",
                        Some(&format!("Drive: {}", l)),
                    )
                    .await;
                    if l.to_lowercase().contains("unhealthy")
                        || l.to_lowercase().contains("warning")
                    {
                        issues.push(Issue::new(
                            "storage_smart_warning",
                            self.id(),
                            "SMART hardware warning reported for a physical drive",
                            "Storage & File System",
                            Severity::Critical,
                            RiskScore::High,
                            format!("A physical disk reports a degraded health status: {}", l),
                            l.to_string(),
                            "Back up important data and run the vendor's drive diagnostics",
                            vec!["Back up important data immediately".to_string()],
                        ));
                    }
                }
            }
        }

        // 3. Junk & Temp Files Size
        Self::send_progress(
            &progress_tx,
            75,
            "Measuring junk & temp file size...",
            Some("Scanning %TEMP% and Windows\\Temp..."),
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
                format!("Found {} MB of temporary junk files ({} files)", total_temp_mb, total_temp_files),
                "Storage & File System",
                Severity::Warning,
                RiskScore::Low,
                format!("The system and user temp directories hold {} MB of stale temporary files taking up disk space.", total_temp_mb),
                format!("Temp size: {} MB across {} files", total_temp_mb, total_temp_files),
                "Safely clean temporary files (locked files are skipped)",
                vec![
                    "Clean the user temp directory (%TEMP%)".to_string(),
                    "Clean the Windows temp directory (C:\\Windows\\Temp)".to_string(),
                ],
            ));
        } else {
            Self::send_progress(
                &progress_tx,
                88,
                "Temporary files within the normal range",
                Some(&format!(
                    "Temp files: {} MB ({} files), threshold is {} MB.",
                    total_temp_mb, total_temp_files, self.config.temp_clean_threshold_mb
                )),
            )
            .await;
        }

        // 4. Explorer Icon & Thumbnail Cache
        Self::send_progress(
            &progress_tx,
            92,
            "Checking the Explorer icon & thumbnail cache...",
            Some("IconCache.db integrity..."),
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
                            "Icon & thumbnail cache is oversized / corrupt",
                            "Storage & File System",
                            Severity::Info,
                            RiskScore::Low,
                            "The Windows icon cache exceeds 25 MB. That causes broken or blank icons in the taskbar and in Explorer.",
                            format!("IconCache.db size: {} MB", meta.len() / (1024 * 1024)),
                            "Rebuild the icon and thumbnail cache cleanly",
                            vec![
                                "Restart the Explorer process".to_string(),
                                "Reset IconCache.db".to_string(),
                            ],
                        ));
            }
        }

        Self::send_progress(
            &progress_tx,
            100,
            "Storage and file system diagnostics complete",
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
        let dbg = DebugTrace::fix(issue_id, progress_tx, self.config.verbose_logging);

        match issue_id {
            "storage_dirty_bit" => {
                dbg.section("preflight for chkdsk").await;
                dbg.kv("elevated", if is_admin() { "yes" } else { "no" })
                    .await;
                for candidate in chkdsk_candidates() {
                    dbg.path("chkdsk image", &candidate).await;
                }
                dbg.kv("target volume", "C:").await;
                dbg.kv("mode", "/scan (online, no dismount, no repair)")
                    .await;

                let out = dbg
                    .run(
                        &self.runner,
                        "chkdsk.exe",
                        &["C:", "/scan"],
                        Duration::from_secs(120),
                    )
                    .await
                    .map_err(|err| {
                        // A spawn failure is not chkdsk's verdict on the volume:
                        // the tool never ran, so say so in the message that ends
                        // up in the audit log and the issue list, where the
                        // verbose console is not available.
                        format!(
                            "chkdsk could not be started, the volume was not checked. {}",
                            err
                        )
                    })?;

                match out.exit_code {
                    Some(0) => {
                        Ok("File system check (chkdsk /scan) finished without errors.".to_string())
                    }
                    Some(code) => {
                        dbg.hint(chkdsk_exit_meaning(code)).await;
                        Ok(format!(
                            "chkdsk /scan finished with exit code {} ({}).",
                            code,
                            chkdsk_exit_meaning(code)
                        ))
                    }
                    None => Ok("chkdsk /scan ended without reporting an exit code.".to_string()),
                }
            }
            "storage_temp_bloat" => {
                let mut freed_mb = 0;
                let mut deleted_files = 0;
                let mut locked = 0;

                let dirs_to_clean = [
                    std::env::var("TEMP").unwrap_or_default(),
                    r"C:\Windows\Temp".to_string(),
                ];

                dbg.section("sweeping temp directories").await;
                for dir_str in dirs_to_clean {
                    if dir_str.is_empty() {
                        dbg.warn("TEMP is not set for this process - skipping that directory")
                            .await;
                        continue;
                    }
                    let dir = Path::new(&dir_str);
                    dbg.path("directory", dir).await;
                    match std::fs::read_dir(dir) {
                        Ok(entries) => {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if let Ok(meta) = path.metadata() {
                                    let size = meta.len();
                                    if path.is_file() {
                                        match std::fs::remove_file(&path) {
                                            Ok(()) => {
                                                freed_mb += size / (1024 * 1024);
                                                deleted_files += 1;
                                            }
                                            Err(err) => {
                                                locked += 1;
                                                dbg.warn(format!(
                                                    "locked: {} ({})",
                                                    path.display(),
                                                    err
                                                ))
                                                .await;
                                            }
                                        }
                                    } else if path.is_dir() {
                                        let _ = std::fs::remove_dir_all(&path);
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            dbg.warn(format!("cannot list {}: {}", dir.display(), err))
                                .await;
                        }
                    }
                }
                dbg.kv(
                    "result",
                    format!("{} deleted, {} locked", deleted_files, locked),
                )
                .await;
                Ok(format!(
                    "Temporary directories cleaned: {} files removed (about {} MB freed).",
                    deleted_files, freed_mb
                ))
            }
            "storage_icon_cache_bloated" => {
                dbg.section("resetting the icon cache").await;
                if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                    let icon_cache = PathBuf::from(&local_app_data).join("IconCache.db");
                    dbg.path("IconCache.db", &icon_cache).await;
                    if icon_cache.exists()
                        && let Err(err) = std::fs::remove_file(&icon_cache)
                    {
                        dbg.warn(format!("could not delete IconCache.db: {}", err))
                            .await;
                    }
                } else {
                    dbg.warn("LOCALAPPDATA is not set - the icon cache path is unknown")
                        .await;
                }
                let _ = dbg
                    .run(
                        &self.runner,
                        "powershell.exe",
                        &[
                            "-NoProfile",
                            "-Command",
                            "Stop-Process -Name explorer -Force; Start-Process explorer",
                        ],
                        Duration::from_secs(8),
                    )
                    .await;
                Ok("Icon & thumbnail cache reset and Explorer restarted successfully.".to_string())
            }
            "storage_smart_warning" => {
                dbg.hint(
                    "a SMART warning is hardware wear - WinMedic records it, only a drive replacement clears it",
                )
                .await;
                Ok("SMART warning acknowledged and recorded in the audit log.".to_string())
            }
            _ => Err(format!("Unknown issue ID: {}", issue_id)),
        }
    }
}

/// Decide whether `fsutil dirty query` reported a volume as dirty.
///
/// The catch is negation. A clean volume answers `Volume - C: is NOT Dirty`, and
/// in German `Volume - C: ist NICHT fehlerhaft.` — both contain the very word
/// that marks a *dirty* volume. Matching the keyword alone therefore reports
/// every healthy disk as damaged, which then schedules a chkdsk run that was
/// never needed.
///
/// So the negation decides: a line carrying the keyword counts as dirty only
/// when no negation precedes it.
///
/// Only the verdict line is considered — every localisation of it names the
/// volume (`Volume - C: ...`), while usage text and error messages do not. A
/// locale that words it differently therefore yields a missed dirty bit rather
/// than a healthy disk sent to chkdsk, which is the safer way to be wrong.
pub fn volume_is_dirty(output: &str) -> bool {
    const DIRTY_WORDS: [&str; 4] = ["dirty", "fehlerhaft", "beschädigt", "beschaedigt"];
    const NEGATIONS: [&str; 3] = ["not", "nicht", "kein"];

    output.to_lowercase().lines().any(|line| {
        let Some(keyword_at) = DIRTY_WORDS.iter().filter_map(|w| line.find(w)).min() else {
            return false;
        };
        // Everything that decides the verdict stands in front of the keyword:
        // the volume being named (`Volume - C: is ...`), and the negation if
        // there is one. Reading only that part keeps `Usage: fsutil dirty ...
        // <volume path>` out, and stops a stray "not" further along the line
        // from flipping a genuinely dirty verdict.
        let before = &line[..keyword_at];
        let words: Vec<&str> = before.split(|c: char| !c.is_alphanumeric()).collect();
        words.contains(&"volume") && !words.iter().any(|w| NEGATIONS.contains(w))
    })
}

/// Where `chkdsk.exe` is expected to live, in resolution order.
///
/// Logged before the call so a spawn failure can be told apart from a missing
/// image without a second run.
fn chkdsk_candidates() -> Vec<PathBuf> {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    vec![
        PathBuf::from(&sys_root).join("System32").join("chkdsk.exe"),
        PathBuf::from(&sys_root).join("SysWOW64").join("chkdsk.exe"),
    ]
}

/// Translate a chkdsk exit code into the sentence the log should show.
fn chkdsk_exit_meaning(code: i32) -> &'static str {
    match code {
        0 => "no errors found",
        1 => "errors were found and fixed",
        2 => "cleanup was performed, or a full scan is still needed",
        3 => "errors were found but could not be fixed online - schedule an offline check",
        _ => "unexpected exit code, see the output above",
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

    /// The regression that started this: on a German system `fsutil` answers
    /// "ist NICHT fehlerhaft" for a healthy volume, the old substring match saw
    /// "fehlerhaft" and reported a critical file system fault on every clean
    /// disk — then sent chkdsk after it.
    #[test]
    fn a_negated_verdict_is_not_a_dirty_volume() {
        for clean in [
            "Volume - C: ist NICHT fehlerhaft.",
            "Volume - C: is NOT Dirty",
            "Volume - C: ist nicht beschädigt.",
            "Volume - C: ist nicht beschaedigt.",
        ] {
            assert!(!volume_is_dirty(clean), "false alarm on: {}", clean);
        }
    }

    #[test]
    fn an_actually_dirty_volume_is_still_detected() {
        for dirty in [
            "Volume - C: is Dirty",
            "Volume - C: ist fehlerhaft.",
            "Volume - C: ist beschädigt.",
        ] {
            assert!(volume_is_dirty(dirty), "missed: {}", dirty);
        }
    }

    /// Anything that is not the verdict line must be ignored — the usage text
    /// alone mentions "dirty" often enough to trip a naive match.
    #[test]
    fn output_without_a_verdict_is_not_dirty() {
        for other in [
            "",
            "Fehler 5: Zugriff verweigert",
            "Usage: fsutil dirty {query | set} <volume path>",
            "---- DIRTY Meaning: the dirty bit is set",
        ] {
            assert!(!volume_is_dirty(other), "false alarm on: {}", other);
        }
    }

    /// A refused `fsutil` call carries no verdict, so it must not raise the
    /// issue — an unelevated run used to be enough to schedule a chkdsk.
    #[tokio::test]
    async fn a_clean_volume_raises_no_issue_in_either_language() {
        for output in [
            "Volume - C: ist NICHT fehlerhaft.",
            "Volume - C: is NOT Dirty",
        ] {
            let mock = MockCommandRunner::new();
            mock.add_response("dirty query C:", CmdOutput::ok(output));
            mock.add_response("Get-PhysicalDisk", CmdOutput::ok("SSD | Health: Healthy"));

            let module = StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock));
            let issues = module.scan(None).await.unwrap();

            assert!(
                !issues.iter().any(|i| i.id == "storage_dirty_bit"),
                "'{}' was read as a fault",
                output
            );
        }
    }

    #[tokio::test]
    async fn a_refused_dirty_query_raises_no_issue() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "dirty query C:",
            CmdOutput::failed(1, "Fehler 5: Zugriff verweigert"),
        );
        mock.add_response("Get-PhysicalDisk", CmdOutput::ok("SSD | Health: Healthy"));

        let module = StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        assert!(!issues.iter().any(|i| i.id == "storage_dirty_bit"));
    }

    /// Windows refusing to *start* chkdsk says nothing about the volume, and the
    /// old message ("Failed to spawn command ...") read as though the check had
    /// run and come back unhappy.
    #[tokio::test]
    async fn a_chkdsk_that_never_started_says_the_volume_was_not_checked() {
        // A mock with no configured response fails the call the same way a
        // refused CreateProcess does: an error instead of an exit code.
        let module =
            StorageModule::with_runner(ModuleConfig::default(), Arc::new(MockCommandRunner::new()));

        let err = module.fix("storage_dirty_bit", None).await.unwrap_err();
        assert!(
            err.contains("could not be started") && err.contains("not checked"),
            "unhelpful message: {}",
            err
        );
    }

    /// Exit code 3 means chkdsk found damage it could not repair online. Folding
    /// that into a bare "chkdsk ran" hid the one outcome that needs a reboot.
    #[tokio::test]
    async fn an_unrepairable_volume_is_named_in_the_result() {
        let mock = MockCommandRunner::new();
        mock.add_response("chkdsk.exe", CmdOutput::failed(3, ""));

        let module = StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let msg = module.fix("storage_dirty_bit", None).await.unwrap();

        assert!(msg.contains("exit code 3"), "{}", msg);
        assert!(msg.contains("offline check"), "{}", msg);
    }

    #[test]
    fn every_chkdsk_exit_code_has_a_sentence() {
        for code in 0..=3 {
            assert!(!chkdsk_exit_meaning(code).is_empty());
        }
        assert!(chkdsk_exit_meaning(99).contains("unexpected"));
    }

    /// The verbose trace has to reach the console rather than being dropped on
    /// the floor, and it must stay silent when the setting is off.
    #[tokio::test]
    async fn the_chkdsk_preflight_is_traced_only_in_verbose_mode() {
        use crate::utils::debug_log::parse_debug_line;

        for verbose in [false, true] {
            let mock = MockCommandRunner::new();
            mock.add_response("chkdsk.exe", CmdOutput::ok(""));
            let config = ModuleConfig {
                verbose_logging: verbose,
                ..ModuleConfig::default()
            };
            let module = StorageModule::with_runner(config, Arc::new(mock));

            let (tx, mut rx) = tokio::sync::mpsc::channel::<FixProgress>(256);
            let _ = module.fix("storage_dirty_bit", Some(tx)).await;

            let mut traces = Vec::new();
            while let Ok(progress) = rx.try_recv() {
                if let Some(line) = progress.console_line
                    && parse_debug_line(&line).is_some()
                {
                    traces.push(line);
                }
            }

            if verbose {
                let joined = traces.join("\n");
                assert!(joined.contains("chkdsk.exe C: /scan"), "{}", joined);
                assert!(joined.contains("elevated"), "{}", joined);
            } else {
                assert!(
                    traces.is_empty(),
                    "traces leaked with verbose off: {:?}",
                    traces
                );
            }
        }
    }
}
