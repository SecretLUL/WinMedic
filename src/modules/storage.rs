use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::system_cleaner::{
    CleanStats, clean_path_contents, cleanup_result, format_bytes,
};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner, ps_single_quoted};
use crate::utils::debug_log::DebugTrace;
use crate::utils::event_xml::{EventRecord, read_events, system_log_query};
use crate::utils::fs_stats::{dir_stats_recursive, measure_dirs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

pub struct StorageModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
    /// `%TEMP%` and `%SystemRoot%\Temp`.
    temp_dirs: Vec<PathBuf>,
    /// `%LOCALAPPDATA%\Microsoft\Windows\Explorer`, where the icon cache is.
    explorer_dir: Option<PathBuf>,
}

/// The icon cache files Explorer keeps: `iconcache_16.db`,
/// `iconcache_256.db`, ... A few dozen MB is normal.
const ICON_CACHE_PATTERN: &str = "iconcache_*.db";
/// Above this the icon cache is not just large but broken.
const ICON_CACHE_LIMIT_BYTES: u64 = 256 * 1024 * 1024;

fn is_icon_cache_file(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("iconcache_") && name.ends_with(".db")
}

/// The storage errors Windows logs when a disk, its cable or its controller
/// fails, as warnings or errors: a bad block (disk 7), a paging error (disk
/// 51), a retried I/O (disk 153), file system corruption (Ntfs 55), a reset
/// controller (stornvme and storahci 129). Without `Level<=3` Ntfs' "healthy"
/// events would come along. Named errors only: a generic check of the
/// System log fires on every PC.
const STORAGE_ERRORS: &str = "((Provider[@Name='disk'] and (EventID=7 or EventID=51 or EventID=153)) or (Provider[@Name='Ntfs'] and EventID=55) or ((Provider[@Name='stornvme'] or Provider[@Name='storahci']) and EventID=129)) and Level<=3";
/// How far back storage errors are looked for.
const STORAGE_ERROR_DAYS: u64 = 30;

/// The storage error events of the last [`STORAGE_ERROR_DAYS`], newest first.
pub fn storage_errors_query() -> Vec<String> {
    system_log_query(STORAGE_ERRORS, STORAGE_ERROR_DAYS * 24 * 3_600_000, 20)
}

/// What a storage error event says, and whether it means data is being lost.
fn storage_error_kind(event: &EventRecord) -> Option<(&'static str, bool)> {
    Some(match (event.provider.as_str(), event.event_id) {
        ("disk", 7) => ("bad block", true),
        ("disk", 51) => ("error while paging", true),
        ("disk", 153) => ("read or write had to be retried", false),
        ("Ntfs", 55) => ("file system structure damaged", true),
        ("stornvme" | "storahci", 129) => ("controller stopped answering and was reset", false),
        _ => return None,
    })
}

/// The finding for storage errors in the event log, or `None` without any.
/// Advice: nothing WinMedic runs repairs a failing disk.
pub fn storage_errors_finding(module_id: &str, events: &[EventRecord]) -> Option<Issue> {
    let errors: Vec<(&EventRecord, &'static str, bool)> = events
        .iter()
        .filter_map(|e| storage_error_kind(e).map(|(kind, loses)| (e, kind, loses)))
        .collect();
    if errors.is_empty() {
        return None;
    }
    let data_lost = errors.iter().any(|(_, _, loses)| *loses);
    let details = errors
        .iter()
        .map(|(event, kind, _)| {
            // The device, e.g. `\Device\Harddisk1\DR1`, is the first value of
            // these events; they have no field names.
            let device = event
                .data
                .first()
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            format!("{}  {kind}  {device}", event.summary())
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    Some(
        Issue::new(
            "storage_disk_errors",
            module_id,
            format!(
                "Windows logged {} storage error(s) in the last {STORAGE_ERROR_DAYS} days",
                errors.len()
            ),
            "Storage & File System",
            if data_lost {
                Severity::Critical
            } else {
                Severity::Warning
            },
            RiskScore::Low,
            "A disk, its cable or its controller reported errors. That causes hangs and damaged files, and reinstalling Windows does not help. Back up what matters first, while the disk still reads.",
            details,
            "Back up your files now, then check the disk and its cable",
            vec![
                "Back up your important files now".to_string(),
                "Check the cable and connector of the disk (SATA) or reseat the SSD (M.2)".to_string(),
                "Test the disk with its maker's tool (e.g. Samsung Magician, WD Dashboard, SeaTools)".to_string(),
            ],
        )
        .with_advice_only(),
    )
}

impl StorageModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        let temp_dirs = [
            std::env::var_os("TEMP").map(PathBuf::from),
            std::env::var_os("SystemRoot").map(|root| PathBuf::from(root).join("Temp")),
        ]
        .into_iter()
        .flatten()
        .collect();
        let explorer_dir = std::env::var_os("LOCALAPPDATA")
            .map(|local| PathBuf::from(local).join(r"Microsoft\Windows\Explorer"));
        Self::with_paths(config, runner, temp_dirs, explorer_dir)
    }

    /// Build a module that measures and deletes under explicit folders: a
    /// test that cleans `%TEMP%` would empty the temp folder of whoever runs
    /// it.
    pub fn with_paths(
        config: ModuleConfig,
        runner: Arc<dyn CommandRunner>,
        temp_dirs: Vec<PathBuf>,
        explorer_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            config,
            runner,
            temp_dirs,
            explorer_dir,
        }
    }

    /// The icon cache files and their size together.
    fn icon_cache(&self) -> (usize, u64) {
        let Some(dir) = &self.explorer_dir else {
            return (0, 0);
        };
        std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| is_icon_cache_file(&e.file_name().to_string_lossy()))
                    .filter_map(|e| e.metadata().ok())
                    .filter(|m| m.is_file())
                    .fold((0, 0), |(count, bytes), m| (count + 1, bytes + m.len()))
            })
            .unwrap_or((0, 0))
    }

    /// Stops Explorer, deletes the icon cache while nothing holds it (Windows
    /// starts Explorer again by itself within seconds, so it tries for a
    /// while), starts Explorer if it is not back, and prints `freed|left`.
    fn icon_cache_script(dir: &Path) -> String {
        format!(
            "$dir = {}; $freed = 0; Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; for ($i = 0; $i -lt 20; $i++) {{ $files = @(Get-ChildItem -LiteralPath $dir -Filter '{ICON_CACHE_PATTERN}' -File -ErrorAction SilentlyContinue); if ($files.Count -eq 0) {{ break }}; foreach ($f in $files) {{ $len = $f.Length; try {{ Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $freed += $len }} catch {{ }} }}; Start-Sleep -Milliseconds 250 }}; $left = @(Get-ChildItem -LiteralPath $dir -Filter '{ICON_CACHE_PATTERN}' -File -ErrorAction SilentlyContinue).Count; if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {{ Start-Process explorer }}; '{{0}}|{{1}}' -f $freed, $left",
            ps_single_quoted(&dir.to_string_lossy())
        )
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
        "Checks SMART drive health, disk and controller errors Windows logged, file system errors (dirty bit), junk/temp files and the icon cache"
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
            Some("Reading the dirty bit of C: (WMI, then fsutil)..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let dbg = DebugTrace::scan(self.id(), progress_tx.clone(), self.config.verbose_logging);

        if let Some((verdict, evidence)) = self.dirty_bit(&dbg).await {
            dbg.kv("dirty bit", if verdict { "set" } else { "clear" })
                .await;
            if verdict {
                // chkdsk /scan checks and fixes what it can while Windows
                // runs; the flag itself is cleared by the check Windows makes
                // before it starts, which the flag schedules.
                issues.push(
                    Issue::new(
                        "storage_dirty_bit",
                        self.id(),
                        "File system inconsistency on system drive C: (dirty bit set)",
                        "Storage & File System",
                        Severity::Critical,
                        RiskScore::Medium,
                        "Drive C: has the file system integrity flag ('dirty bit') set. That points to incompletely written sectors or abrupt shutdowns.",
                        evidence,
                        "Check the drive with 'chkdsk C: /scan', then restart so Windows checks it before it starts",
                        vec![
                            "Run chkdsk C: /scan online".to_string(),
                            "Restart Windows".to_string(),
                        ],
                    )
                    .with_requires_reboot(true),
                );
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
            // Both need elevation to read the dirty bit. A refused query says
            // nothing about the volume, and treating its error text as a verdict
            // is how a healthy disk ends up scheduled for chkdsk.
            dbg.warn(
                "neither WMI nor fsutil could read the dirty bit - the volume state is unknown, not bad",
            )
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
                        issues.push(
                            Issue::new(
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
                            )
                            .with_advice_only(),
                        );
                    }
                }
            }
        }

        // Storage errors Windows logged
        let query = storage_errors_query();
        let query: Vec<&str> = query.iter().map(String::as_str).collect();
        match read_events(
            self.runner
                .run("wevtutil.exe", &query, Duration::from_secs(15))
                .await,
        ) {
            Ok(events) => match storage_errors_finding(self.id(), &events) {
                Some(issue) => issues.push(issue),
                None => {
                    Self::send_progress(
                        &progress_tx,
                        70,
                        "No storage errors logged",
                        Some(&format!(
                            "No disk, NTFS or controller error in the last {STORAGE_ERROR_DAYS} days."
                        )),
                    )
                    .await;
                }
            },
            Err(err) => {
                Self::send_progress(&progress_tx, 70, "Storage errors not checked", Some(&err))
                    .await;
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

        // Walked on a blocking thread, so that cancelling the scan does not wait
        // for the walk to finish.
        let temp = measure_dirs(self.temp_dirs.clone(), dir_stats_recursive).await;
        let (temp_bytes, temp_files) = (temp.bytes, temp.files);
        let temp_size = format_bytes(temp_bytes);

        if temp_bytes > self.config.temp_clean_threshold_mb * 1024 * 1024 {
            issues.push(
                Issue::new(
                    "storage_temp_bloat",
                    self.id(),
                    format!("Found {temp_size} of temporary files ({temp_files} files)"),
                    "Storage & File System",
                    Severity::Warning,
                    RiskScore::Low,
                    format!(
                        "The temp folders hold {temp_size} of temporary files taking up disk space."
                    ),
                    format!(
                        "Temp size: {temp_size} across {temp_files} files\n{}",
                        self.temp_dirs
                            .iter()
                            .map(|d| d.display().to_string())
                            .collect::<Vec<_>>()
                            .join("\n")
                    ),
                    "Clean the temporary files (files in use are skipped)",
                    self.temp_dirs
                        .iter()
                        .map(|d| format!("Clean {}", d.display()))
                        .collect(),
                )
                .with_reclaimable_bytes(temp_bytes),
            );
        } else {
            Self::send_progress(
                &progress_tx,
                88,
                "Temporary files within the normal range",
                Some(&format!(
                    "Temp files: {temp_size} ({temp_files} files), threshold is {} MB.",
                    self.config.temp_clean_threshold_mb
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

        // `%LOCALAPPDATA%\IconCache.db`, which this used to measure, is the
        // cache of Windows 7; since Windows 8 it stays a few KB.
        let (icon_files, icon_bytes) = self.icon_cache();
        if icon_bytes > ICON_CACHE_LIMIT_BYTES {
            let mut issue = Issue::new(
                "storage_icon_cache_bloated",
                self.id(),
                format!("The icon cache has grown to {}", format_bytes(icon_bytes)),
                "Storage & File System",
                Severity::Info,
                RiskScore::Low,
                "A few dozen MB is normal for the icon cache; this much usually means it is damaged, which shows as blank or wrong icons. Rebuilding it restarts Explorer: the taskbar disappears for a few seconds.",
                format!(
                    "{} in {} {ICON_CACHE_PATTERN} files",
                    format_bytes(icon_bytes),
                    icon_files
                ),
                "Rebuild the icon cache (restarts Explorer)",
                vec![
                    "Stop Explorer".to_string(),
                    format!("Delete {ICON_CACHE_PATTERN}"),
                    "Start Explorer again".to_string(),
                ],
            );
            issue.is_selected = false;
            issues.push(issue);
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
                        crate::modules::SERVICING_TIMEOUT,
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

                // 3 means errors chkdsk cannot fix while Windows runs; any
                // other code is no verdict. Only 0 to 2 are a check that ran.
                let found = match out.exit_code {
                    Some(code @ 0..=2) => chkdsk_exit_meaning(code),
                    Some(code) => {
                        dbg.hint(chkdsk_exit_meaning(code)).await;
                        return Err(format!(
                            "chkdsk /scan finished with exit code {code}: {}. Restart Windows: it checks the drive before it starts.",
                            chkdsk_exit_meaning(code)
                        ));
                    }
                    None => {
                        return Err(
                            "chkdsk /scan ended without an exit code; the drive was not checked."
                                .to_string(),
                        );
                    }
                };
                match self.dirty_bit(&dbg).await {
                    Some((false, _)) => Ok(format!("chkdsk /scan: {found}. The flag is cleared.")),
                    _ => Ok(format!(
                        "chkdsk /scan: {found}. Restart Windows: it checks the drive before it starts and clears the flag."
                    )),
                }
            }
            // Counted in bytes, file by file, through the sweep the cleaner
            // uses. In whole MB per file, everything below 1 MB counted as
            // nothing and the message named a fraction of what was freed.
            "storage_temp_bloat" => {
                dbg.section("sweeping temp directories").await;
                let mut total = CleanStats::default();
                for dir in &self.temp_dirs {
                    dbg.path("directory", dir).await;
                    let dir = dir.clone();
                    let stats = tokio::task::spawn_blocking(move || clean_path_contents(&dir))
                        .await
                        .map_err(|e| format!("The temp sweep stopped: {e}"))?;
                    total.freed_bytes += stats.freed_bytes;
                    total.deleted_files += stats.deleted_files;
                    total.skipped_locked += stats.skipped_locked;
                    total.locked_bytes += stats.locked_bytes;
                }
                cleanup_result("Temporary files cleaned", total)
            }
            // Explorer holds the cache open, so it is stopped first; deleting
            // before that, as this used to, deleted nothing.
            "storage_icon_cache_bloated" => {
                dbg.section("rebuilding the icon cache").await;
                let Some(dir) = &self.explorer_dir else {
                    return Err(
                        "LOCALAPPDATA is not set, so the icon cache cannot be found.".to_string(),
                    );
                };
                dbg.path("icon cache", dir).await;
                let out = dbg
                    .run_powershell(
                        &self.runner,
                        &Self::icon_cache_script(dir),
                        Duration::from_secs(30),
                    )
                    .await?;
                let counts = out
                    .stdout
                    .lines()
                    .rev()
                    .find_map(|line| line.trim().split_once('|'))
                    .and_then(|(freed, left)| {
                        Some((freed.parse::<u64>().ok()?, left.parse::<usize>().ok()?))
                    });
                match counts {
                    Some((freed, 0)) => Ok(format!(
                        "Icon cache rebuilt: {} deleted, Explorer restarted.",
                        format_bytes(freed)
                    )),
                    Some((_, left)) => Err(format!(
                        "{left} icon cache file(s) stayed in use and were not deleted. Sign out and in again, then try once more."
                    )),
                    None => Err(format!(
                        "The icon cache could not be rebuilt (exit code {:?}): {}",
                        out.exit_code,
                        out.stderr.trim()
                    )),
                }
            }
            // A SMART warning is hardware wear and advice only: only a drive
            // replacement clears it, so a repair run never asks.
            _ => Err(format!("Unknown issue ID: {}", issue_id)),
        }
    }
}

impl StorageModule {
    /// Whether C:'s dirty bit is set, and what said so; `None` when neither
    /// WMI nor fsutil would tell.
    ///
    /// WMI first: `DirtyBitSet` is a boolean, the same on every Windows.
    /// fsutil answers in a sentence in the display language, which only the
    /// English and German wordings below can read; it stays as the fallback
    /// for a machine whose WMI does not answer.
    async fn dirty_bit(&self, dbg: &DebugTrace) -> Option<(bool, String)> {
        let wmi_verdict = dbg
            .run_powershell(&self.runner, DIRTY_BIT_SCRIPT, Duration::from_secs(10))
            .await
            .ok()
            .filter(|out| out.success)
            .and_then(|out| parse_dirty_bit_set(&out.stdout));
        match wmi_verdict {
            Some(dirty) => Some((
                dirty,
                format!(
                    "Win32_Volume C: DirtyBitSet = {}",
                    if dirty { "True" } else { "False" }
                ),
            )),
            None => match dbg
                .run(
                    &self.runner,
                    "fsutil.exe",
                    &["dirty", "query", "C:"],
                    Duration::from_secs(6),
                )
                .await
            {
                Ok(out) if out.success => Some((volume_is_dirty(&out.stdout), out.stdout)),
                _ => None,
            },
        }
    }
}

/// Asks WMI for the system drive's dirty bit. Prints `True` or `False`, or
/// nothing when WMI does not know — which it does not without elevation.
const DIRTY_BIT_SCRIPT: &str = "Get-CimInstance -ClassName Win32_Volume -Filter \"DriveLetter='C:'\" | ForEach-Object { $_.DirtyBitSet }";

/// The verdict in [`DIRTY_BIT_SCRIPT`]'s output, if it gave one.
pub fn parse_dirty_bit_set(output: &str) -> Option<bool> {
    match output.trim() {
        "True" => Some(true),
        "False" => Some(false),
        _ => None,
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

    /// Constructed in the shape of real classic events; see
    /// tests/fixtures/README.md.
    const STORAGE_ERRORS_XML: &str =
        include_str!("../../tests/fixtures/events/storage_errors_constructed.xml");

    fn storage_errors() -> Vec<EventRecord> {
        crate::utils::event_xml::parse_events(STORAGE_ERRORS_XML)
    }

    #[test]
    fn named_storage_errors_are_listed_with_their_device() {
        let issue = storage_errors_finding("storage", &storage_errors()).unwrap();
        assert!(
            issue.title.contains("4 storage error(s)"),
            "{}",
            issue.title
        );
        assert_eq!(issue.severity, Severity::Critical);
        assert!(issue.advice_only);
        let details = &issue.technical_details;
        assert!(
            details.contains("disk  Event 7  bad block  \\Device\\Harddisk1\\DR1"),
            "{details}"
        );
        assert!(
            details.contains("controller stopped answering"),
            "{details}"
        );
        assert!(details.contains("Ntfs  Event 55  file system structure damaged  D:"));
    }

    #[test]
    fn retries_and_resets_alone_are_a_warning() {
        let events: Vec<EventRecord> = storage_errors()
            .into_iter()
            .filter(|e| matches!(e.event_id, 129 | 153))
            .collect();
        let issue = storage_errors_finding("storage", &events).unwrap();
        assert_eq!(issue.severity, Severity::Warning);
    }

    #[test]
    fn no_storage_error_is_no_finding() {
        assert!(storage_errors_finding("storage", &[]).is_none());
        // Anything else the query might return is not named here.
        let other = crate::utils::event_xml::parse_events(include_str!(
            "../../tests/fixtures/events/system_errors.xml"
        ));
        assert!(storage_errors_finding("storage", &other).is_none());
    }

    #[tokio::test]
    async fn the_scan_asks_for_named_storage_errors_only() {
        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil.exe", CmdOutput::ok(STORAGE_ERRORS_XML));
        let issues = StorageModule::with_paths(
            ModuleConfig::default(),
            Arc::new(mock.clone()),
            Vec::new(),
            None,
        )
        .scan(None)
        .await
        .unwrap();
        assert!(issues.iter().any(|i| i.id == "storage_disk_errors"));
        let query = mock
            .executed()
            .into_iter()
            .find(|c| c.starts_with("wevtutil.exe"))
            .unwrap();
        assert!(query.contains("and Level<=3"), "{query}");
        assert!(
            query.contains("timediff(@SystemTime) <= 2592000000"),
            "{query}"
        );
    }

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

    #[tokio::test]
    async fn wmi_decides_the_dirty_bit_without_asking_fsutil() {
        for (answer, dirty) in [("True\r\n", true), ("False\r\n", false)] {
            let mock = MockCommandRunner::new();
            mock.add_response("DirtyBitSet", CmdOutput::ok(answer));
            mock.add_response("Get-PhysicalDisk", CmdOutput::ok("SSD | Health: Healthy"));

            let module =
                StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
            let issues = module.scan(None).await.unwrap();

            assert_eq!(
                issues.iter().any(|i| i.id == "storage_dirty_bit"),
                dirty,
                "WMI said {answer:?}"
            );
            assert!(
                !mock.executed().iter().any(|c| c.contains("fsutil")),
                "a WMI verdict needs no fsutil sentence to interpret"
            );
        }
    }

    #[tokio::test]
    async fn without_a_wmi_verdict_fsutil_is_asked() {
        let mock = MockCommandRunner::new();
        // Unelevated, WMI leaves DirtyBitSet empty.
        mock.add_response("DirtyBitSet", CmdOutput::ok("\r\n"));
        mock.add_response("dirty query C:", CmdOutput::ok("Volume - C: is Dirty"));
        mock.add_response("Get-PhysicalDisk", CmdOutput::ok("SSD | Health: Healthy"));

        let module = StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let issues = module.scan(None).await.unwrap();
        assert!(issues.iter().any(|i| i.id == "storage_dirty_bit"));
    }

    #[test]
    fn only_a_boolean_is_a_wmi_verdict() {
        assert_eq!(parse_dirty_bit_set("True\r\n"), Some(true));
        assert_eq!(parse_dirty_bit_set("False"), Some(false));
        assert_eq!(parse_dirty_bit_set(""), None);
        assert_eq!(parse_dirty_bit_set("Zugriff verweigert"), None);
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
    /// It is no repair either: the finding stays.
    #[tokio::test]
    async fn an_unrepairable_volume_is_named_in_the_result() {
        let mock = MockCommandRunner::new();
        mock.add_response("chkdsk.exe", CmdOutput::failed(3, ""));

        let module = StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let msg = module.fix("storage_dirty_bit", None).await.unwrap_err();

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
            } else {
                assert!(
                    traces.is_empty(),
                    "traces leaked with verbose off: {:?}",
                    traces
                );
            }
        }
    }

    /// A folder under the temp directory, removed when dropped.
    struct Sandbox(PathBuf);

    impl Sandbox {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("winmedic_storage_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sandboxed(
        temp: &Sandbox,
        explorer: Option<&Sandbox>,
        mock: &MockCommandRunner,
    ) -> StorageModule {
        let config = ModuleConfig {
            temp_clean_threshold_mb: 0,
            ..ModuleConfig::default()
        };
        StorageModule::with_paths(
            config,
            Arc::new(mock.clone()),
            vec![temp.0.clone()],
            explorer.map(|e| e.0.clone()),
        )
    }

    /// Three files of 100 KB each: every one of them counted as 0 MB before.
    #[tokio::test]
    async fn small_temp_files_count_in_what_is_freed() {
        let temp = Sandbox::new("temp_small");
        for name in ["a.tmp", "b.tmp", "c.tmp"] {
            std::fs::write(temp.0.join(name), vec![0u8; 100 * 1024]).unwrap();
        }
        let mock = MockCommandRunner::with_default_success();
        let module = sandboxed(&temp, None, &mock);

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "storage_temp_bloat")
            .unwrap();
        assert_eq!(issue.reclaimable_bytes, Some(300 * 1024));

        let msg = module.fix("storage_temp_bloat", None).await.unwrap();
        assert!(msg.contains("3 files deleted (300.0 KB freed"), "{msg}");
        assert_eq!(std::fs::read_dir(&temp.0).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn the_icon_cache_is_measured_where_explorer_keeps_it() {
        let temp = Sandbox::new("icon_temp");
        let explorer = Sandbox::new("icon_explorer");
        let big = std::fs::File::create(explorer.0.join("iconcache_256.db")).unwrap();
        big.set_len(ICON_CACHE_LIMIT_BYTES + 1).unwrap();
        drop(big);
        std::fs::write(explorer.0.join("thumbcache_256.db"), b"not the icon cache").unwrap();
        let mock = MockCommandRunner::with_default_success();

        let issues = sandboxed(&temp, Some(&explorer), &mock)
            .scan(None)
            .await
            .unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "storage_icon_cache_bloated")
            .expect("256 MB of icon cache");
        assert!(
            issue
                .technical_details
                .contains("in 1 iconcache_*.db files")
        );
        assert!(!issue.is_selected, "it restarts Explorer");
    }

    #[tokio::test]
    async fn a_normal_icon_cache_is_not_a_finding() {
        let temp = Sandbox::new("icon_small_temp");
        let explorer = Sandbox::new("icon_small_explorer");
        std::fs::write(explorer.0.join("iconcache_32.db"), vec![0u8; 4096]).unwrap();
        let mock = MockCommandRunner::with_default_success();
        let issues = sandboxed(&temp, Some(&explorer), &mock)
            .scan(None)
            .await
            .unwrap();
        assert!(!issues.iter().any(|i| i.id == "storage_icon_cache_bloated"));
    }

    #[tokio::test]
    async fn the_icon_cache_repair_reads_what_it_deleted() {
        let temp = Sandbox::new("icon_fix_temp");
        let explorer = Sandbox::new("icon_fix_explorer");
        let mock = MockCommandRunner::new();
        mock.add_response("iconcache_", CmdOutput::ok("80000000|0\r\n"));
        let module = sandboxed(&temp, Some(&explorer), &mock);
        let msg = module
            .fix("storage_icon_cache_bloated", None)
            .await
            .unwrap();
        assert!(msg.contains("76.3 MB deleted"), "{msg}");

        let mock = MockCommandRunner::new();
        mock.add_response("iconcache_", CmdOutput::ok("0|2\r\n"));
        let module = sandboxed(&temp, Some(&explorer), &mock);
        let err = module
            .fix("storage_icon_cache_bloated", None)
            .await
            .unwrap_err();
        assert!(err.contains("2 icon cache file(s) stayed in use"), "{err}");
    }

    #[tokio::test]
    async fn the_icon_cache_script_parses() {
        let script = StorageModule::icon_cache_script(Path::new(r"C:\Users\x\Explorer"));
        assert_eq!(crate::utils::cmd::powershell_parse_errors(&script).await, 0);
    }

    #[tokio::test]
    async fn a_check_that_ran_reads_the_flag_again() {
        let mock = MockCommandRunner::new();
        mock.add_response("chkdsk.exe", CmdOutput::ok(""));
        mock.add_response("DirtyBitSet", CmdOutput::ok("True"));
        let module = StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let msg = module.fix("storage_dirty_bit", None).await.unwrap();
        assert!(msg.contains("Restart Windows"), "{msg}");

        let mock = MockCommandRunner::new();
        mock.add_response("chkdsk.exe", CmdOutput::ok(""));
        mock.add_response("DirtyBitSet", CmdOutput::ok("False"));
        let module = StorageModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let msg = module.fix("storage_dirty_bit", None).await.unwrap();
        assert!(msg.contains("The flag is cleared"), "{msg}");
    }
}
