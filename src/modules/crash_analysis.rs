use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::crash_timeline::{self, Change};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::debug_log::DebugTrace;
use crate::utils::event_xml::{
    EventRecord, event_query, parse_events, read_events, system_log_query,
};
use chrono::{DateTime, Local, Utc};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

const DEFAULT_DUMP_DIR: &str = r"C:\Windows\Minidump";
/// Kernel dump payloads above this size are treated as full/memory dumps; only
/// the header is parsed for them because scanning megabytes of raw memory for
/// driver names would dominate the scan time.
const DRIVER_SCAN_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Above this many accumulated dump files the triage suggests cleaning up.
const STALE_DUMP_THRESHOLD: usize = 5;

/// Parsed kernel minidump header information.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MinidumpInfo {
    pub bugcheck_code: u32,
    pub bugcheck_params: [u64; 4],
    /// Best-effort faulting driver (e.g. `nvlddmkm.sys`), if a known
    /// third-party driver name is embedded in the dump.
    pub faulting_driver: Option<String>,
    /// All `.sys` module names found in the dump payload.
    pub drivers_seen: Vec<String>,
}

/// A crash instance reconstructed from a dump file or a BugCheck event.
#[derive(Debug, Clone)]
struct CrashInstance {
    bugcheck_code: u32,
    when: Option<String>,
    source_file: String,
}

/// Parsed System-log crash event (BugCheck 1001 / Kernel-Power 41).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrashEventRecord {
    pub event_id: u32,
    pub bugcheck_code: Option<u32>,
    /// When it was logged, local time, `%Y-%m-%d %H:%M` like the dump times.
    pub when: Option<String>,
    /// The file name of the dump a bugcheck event points at, so the same
    /// crash is not counted once from the dump and again from the event.
    pub dump_file: Option<String>,
    pub raw_snippet: String,
}

const KERNEL_POWER_PROVIDER: &str = "Microsoft-Windows-Kernel-Power";

/// Who logs Event 1001 for a bugcheck. Current Windows logs it as
/// WER-SystemErrorReporting; the event source that Event Viewer shows, and
/// older systems used as the provider, is "BugCheck". A query for "BugCheck"
/// alone returns nothing on Windows 10/11, so the event half of the crash
/// correlation never saw a single bugcheck there.
const BUGCHECK_PROVIDERS: [&str; 2] = ["Microsoft-Windows-WER-SystemErrorReporting", "BugCheck"];

/// Bugchecks (1001) and unexpected shutdowns (Kernel-Power 41).
fn crash_filter() -> String {
    format!(
        "(Provider[@Name='{}' or @Name='{}' or @Name='{}']) and (EventID=1001 or EventID=41)",
        BUGCHECK_PROVIDERS[0], BUGCHECK_PROVIDERS[1], KERNEL_POWER_PROVIDER,
    )
}

/// The oldest event in the System log: how far back it reaches.
const OLDEST_SYSTEM_EVENT: [&str; 5] = ["qe", "System", "/c:1", "/rd:false", "/f:xml"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BugcheckCategory {
    Memory,
    VideoDriver,
    Storage,
    System,
    Driver,
}

pub struct BugcheckInfo {
    pub code: u32,
    pub name: &'static str,
    pub summary: &'static str,
    pub category: BugcheckCategory,
}

pub struct CrashAnalysisModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
    dump_dir: PathBuf,
}

impl CrashAnalysisModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            config,
            runner,
            dump_dir: PathBuf::from(DEFAULT_DUMP_DIR),
        }
    }

    /// Test seam: like [`Self::with_runner`] but reading dumps from a custom
    /// directory so tests never touch the real `C:\Windows\Minidump`.
    pub fn with_runner_and_dump_dir(
        config: ModuleConfig,
        runner: Arc<dyn CommandRunner>,
        dump_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            config,
            runner,
            dump_dir: dump_dir.into(),
        }
    }

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
                    module_id: "crash_analysis".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }

    /// Reads every `*.dmp` in `dump_dir`, parses headers and returns crash
    /// instances plus the total file count (for the stale-dump heuristic).
    fn collect_dump_crashes(&self) -> (Vec<CrashInstance>, usize) {
        let mut crashes = Vec::new();
        let mut total_files = 0usize;

        let entries = match std::fs::read_dir(&self.dump_dir) {
            Ok(entries) => entries,
            Err(_) => {
                // No admin rights or no crashes at all - not an error, the
                // event-log correlation still works.
                return (crashes, total_files);
            }
        };

        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("dmp"))
            })
            .collect();
        files.sort();

        for path in files {
            total_files += 1;
            let modified = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .map(|t| {
                    DateTime::<Local>::from(t)
                        .format("%Y-%m-%d %H:%M")
                        .to_string()
                });
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown.dmp")
                .to_string();

            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let Some(info) = parse_minidump_header(&bytes) else {
                continue;
            };

            crashes.push(CrashInstance {
                bugcheck_code: info.bugcheck_code,
                when: modified,
                source_file: file_name,
            });
        }

        (crashes, total_files)
    }

    /// The events a `wevtutil` query returns, or `None` when it failed.
    async fn events(&self, dbg: &DebugTrace, query: Vec<String>) -> Option<Vec<EventRecord>> {
        let query: Vec<&str> = query.iter().map(String::as_str).collect();
        let out = dbg
            .run(
                &self.runner,
                "wevtutil.exe",
                &query,
                Duration::from_secs(20),
            )
            .await;
        match read_events(out) {
            Ok(events) => Some(events),
            Err(err) => {
                dbg.warn(format!("What-changed query failed: {err}")).await;
                None
            }
        }
    }

    /// The first crash of the last [`crash_timeline::SERIES_DAYS`] days and
    /// what changed in the week before it; `None` when the logs show nothing.
    async fn what_changed(&self, dbg: &DebugTrace) -> Option<(DateTime<Utc>, Vec<Change>)> {
        let series_ms = crash_timeline::SERIES_DAYS as u64 * 86_400_000;
        let first = self
            .events(dbg, system_log_query(&crash_filter(), series_ms, 500))
            .await?
            .iter()
            .filter_map(crash_timeline::logged_at)
            .min()?;
        let from = crash_timeline::week_before(first);
        let to = crash_timeline::xpath_time(first);
        let week = format!(
            "TimeCreated[@SystemTime>='{}' and @SystemTime<='{to}']",
            crash_timeline::xpath_time(from)
        );
        let until = format!("TimeCreated[@SystemTime<='{to}']");

        let mut changes = Vec::new();
        let updates = format!(
            "Provider[@Name='{}'] and EventID=19 and {week}",
            crash_timeline::WU_PROVIDER
        );
        if let Some(events) = self.events(dbg, event_query("System", &updates, 500)).await {
            changes.extend(crash_timeline::updates(&events));
        }
        // A driver is new at its first install, which only a log that began
        // before the week can tell.
        let log_start = self
            .events(dbg, OLDEST_SYSTEM_EVENT.map(str::to_string).to_vec())
            .await
            .and_then(|events| events.first().and_then(crash_timeline::logged_at));
        let services = format!(
            "Provider[@Name='{}'] and EventID=7045 and {until}",
            crash_timeline::SCM_PROVIDER
        );
        if log_start.is_some_and(|start| start < from)
            && let Some(events) = self
                .events(dbg, event_query("System", &services, 5000))
                .await
        {
            changes.extend(crash_timeline::new_drivers(&events));
        }
        let programs = format!(
            "Provider[@Name='{}'] and EventID=1033 and {until}",
            crash_timeline::MSI_PROVIDER
        );
        if let Some(events) = self
            .events(dbg, event_query("Application", &programs, 5000))
            .await
        {
            changes.extend(crash_timeline::new_programs(&events));
        }

        let changes = crash_timeline::before(first, changes);
        (!changes.is_empty()).then_some((first, changes))
    }

    fn count_user_mode_dumps(&self) -> usize {
        let Some(local) = std::env::var_os("LOCALAPPDATA") else {
            return 0;
        };
        let dir = Path::new(&local).join("CrashDumps");
        std::fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| {
                        e.path()
                            .extension()
                            .and_then(|x| x.to_str())
                            .is_some_and(|x| x.eq_ignore_ascii_case("dmp"))
                    })
                    .count()
            })
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for CrashAnalysisModule {
    fn id(&self) -> &'static str {
        "crash_analysis"
    }

    fn name(&self) -> &'static str {
        "Crash Dump & BSOD Analyzer"
    }

    fn description(&self) -> &'static str {
        "Parses kernel minidumps and BugCheck events to identify stop codes, faulting drivers and crash frequency"
    }

    fn icon(&self) -> &'static str {
        "[DMP]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();
        let dbg = DebugTrace::scan(self.id(), progress_tx.clone(), self.config.verbose_logging);
        let window_hours = self.config.max_event_log_hours.max(1);

        // Step 1: read minidump files
        Self::send_progress(
            &progress_tx,
            15,
            &format!("Reading kernel minidumps from {}...", DEFAULT_DUMP_DIR),
            Some("Parsing dump headers for stop codes and drivers..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        dbg.section("Minidump Directory").await;
        dbg.kv("dump_dir", DEFAULT_DUMP_DIR).await;
        dbg.kv("lookback_hours", window_hours.to_string()).await;

        let (dump_crashes, total_dump_files) = self.collect_dump_crashes();
        let user_dump_count = self.count_user_mode_dumps();
        dbg.kv("kernel_dumps", total_dump_files.to_string()).await;
        dbg.kv("user_mode_dumps", user_dump_count.to_string()).await;

        // Step 2: correlate System event log (BugCheck 1001, Kernel-Power 41)
        Self::send_progress(
            &progress_tx,
            50,
            "Correlating BugCheck (1001) & Kernel-Power (41) events...",
            Some("Querying System log via wevtutil..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let query = system_log_query(&crash_filter(), self.lookback_ms(), 200);
        let query: Vec<&str> = query.iter().map(String::as_str).collect();

        let evt_out = dbg
            .run(
                &self.runner,
                "wevtutil.exe",
                &query,
                Duration::from_secs(15),
            )
            .await;

        let events = match read_events(evt_out) {
            Ok(events) => crash_events(events),
            Err(err) => {
                dbg.warn(format!("Failed to query crash event logs: {}", err))
                    .await;
                return Err(err);
            }
        };
        let bugcheck_events: Vec<&CrashEventRecord> = events
            .iter()
            .filter(|e| e.event_id == 1001 && e.bugcheck_code.is_some())
            .collect();
        let kernel_power_41: usize = events.iter().filter(|e| e.event_id == 41).count();
        dbg.kv("bugcheck_events", bugcheck_events.len().to_string())
            .await;
        dbg.kv("kernel_power_41", kernel_power_41.to_string()).await;

        // Merge dump + event crash instances. A bugcheck usually leaves both a
        // dump and an Event 1001 naming that dump; it is one crash.
        let mut crashes: Vec<CrashInstance> = dump_crashes;
        for e in &bugcheck_events {
            let already_counted = e.dump_file.as_deref().is_some_and(|dump| {
                crashes
                    .iter()
                    .any(|c| c.source_file.eq_ignore_ascii_case(dump))
            });
            if already_counted {
                continue;
            }
            crashes.push(CrashInstance {
                bugcheck_code: e.bugcheck_code.unwrap_or(0),
                when: e.when.clone(),
                source_file: "Event 1001".to_string(),
            });
        }

        if crashes.is_empty() && kernel_power_41 == 0 {
            Self::send_progress(
                &progress_tx,
                90,
                "No BSOD or unexpected-shutdown records found",
                Some("System is crash-free within the analysis window."),
            )
            .await;
            Self::send_progress(&progress_tx, 100, "Crash analysis complete", None).await;
            return Ok(issues);
        }

        // Step 3: classify crashes
        Self::send_progress(
            &progress_tx,
            80,
            "Classifying stop codes, faulting drivers & crash frequency...",
            Some("Mapping bugcheck codes to root-cause categories..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        // Driver attribution: prefer the faulting driver parsed from each dump,
        // fall back to the video stack for TDR stop codes.
        let mut per_driver: BTreeMap<String, Vec<&CrashInstance>> = BTreeMap::new();
        let memory_codes = [0x1A, 0x50, 0x2E, 0x77, 0xC2, 0x19];
        let video_codes = [0x116, 0x117];

        // We need owned copies of driver names for map keys; the dump payload
        // scan already produced them per crash, so re-derive via the dump files
        // referenced by each instance.
        let mut driver_by_source: BTreeMap<String, String> = BTreeMap::new();
        for path in dump_dir_dmp_files(&self.dump_dir) {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown.dmp")
                .to_string();
            if let Ok(bytes) = std::fs::read(&path)
                && let Some(info) = parse_minidump_header(&bytes)
                && let Some(driver) = info.faulting_driver
            {
                driver_by_source.insert(file_name, driver);
            }
        }

        let mut memory_crashes = Vec::new();
        let mut video_crashes = Vec::new();
        let mut generic_crashes = Vec::new();

        for crash in &crashes {
            if video_codes.contains(&crash.bugcheck_code) {
                video_crashes.push(crash);
            } else if memory_codes.contains(&crash.bugcheck_code) {
                memory_crashes.push(crash);
            } else if let Some(driver) = driver_by_source.get(&crash.source_file) {
                per_driver.entry(driver.clone()).or_default().push(crash);
            } else {
                generic_crashes.push(crash);
            }
        }

        // 1. Faulting driver identified (e.g. nvlddmkm.sys)
        for (driver, instances) in &per_driver {
            let count = instances.len();
            let severity = if count >= 2 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            let stop_codes: BTreeSet<String> = instances
                .iter()
                .map(|c| format!("0x{:08X}", c.bugcheck_code))
                .collect();
            let dates: Vec<&str> = instances.iter().filter_map(|c| c.when.as_deref()).collect();
            let component = describe_driver_component(driver);

            issues.push(Issue::new(
                "crash_driver_fault",
                self.id(),
                format!("BSOD caused by driver {} ({} crash(es))", driver, count),
                "Hardware & Stability",
                severity,
                RiskScore::Medium,
                format!(
                    "Crash dumps directly implicate the {} driver {}. Repeated stop codes of this class typically follow a driver update gone wrong, a vendor-package conflict (e.g. GeForce/Adrenalin clean-install leftovers) or failing hardware behind the driver.",
                    component, driver
                ),
                format!(
                    "Faulting driver: {}\nStop code(s): {}\nCrashes: {}\nMost recent: {}\nDump files: {}",
                    driver,
                    stop_codes.into_iter().collect::<Vec<_>>().join(", "),
                    count,
                    dates.last().copied().unwrap_or("unknown"),
                    instances.iter().map(|c| c.source_file.as_str()).take(4).collect::<Vec<_>>().join(", "),
                ),
                "Roll back or clean-reinstall the implicated driver (DDU + latest vendor package)",
                vec![
                    format!("Open Device Manager and roll back the {} driver", driver),
                    format!(
                        "Perform a clean reinstall of the {} driver with DDU, then install the latest stable vendor package",
                        component
                    ),
                    "Verify the crash frequency drops in the days after the swap".to_string(),
                ],
            ));
        }

        // 2. GPU / TDR crashes
        if !video_crashes.is_empty() {
            let count = video_crashes.len();
            let video_driver = video_crashes
                .iter()
                .find_map(|c| driver_by_source.get(&c.source_file).cloned())
                .or_else(|| per_driver.keys().next().cloned())
                .unwrap_or_else(|| "unknown".to_string());
            issues.push(Issue::new(
                "crash_video_tdr",
                self.id(),
                format!("GPU driver timeout / TDR crash(es) ({} events)", count),
                "Hardware & Stability",
                Severity::Critical,
                RiskScore::Medium,
                "VIDEO_TDR_FAILURE / VIDEO_TDR_TIMEOUT_DETECTED stop codes: the GPU stopped responding and the display driver was reset. Typical causes are an unstable GPU driver, aggressive factory overclock, overheating or an undersized PSU under load spikes.",
                format!(
                    "Stop code(s): 0x116 / 0x117\nCrashes: {}\nImplicated display driver: {}\nDump files: {}",
                    count,
                    video_driver,
                    video_crashes.iter().map(|c| c.source_file.as_str()).take(4).collect::<Vec<_>>().join(", "),
                ),
                "Clean-reinstall the GPU driver and check GPU thermals",
                vec![
                    "Clean-reinstall the GPU driver (DDU, then latest stable vendor package)".to_string(),
                    "Check GPU temperatures under load and improve case airflow if needed".to_string(),
                    "If crashes persist, test with a known-stable driver branch or reduce core clock offsets".to_string(),
                ],
            ));
        }

        // 3. Memory-class stop codes without a clear driver
        if !memory_crashes.is_empty() {
            let count = memory_crashes.len();
            issues.push(Issue::new(
                "crash_memory_bugcheck",
                self.id(),
                format!("Memory-related BSOD stop code(s) ({} crashes)", count),
                "Hardware & Stability",
                Severity::Critical,
                RiskScore::Medium,
                "MEMORY_MANAGEMENT / PAGE_FAULT_IN_NONPAGED_AREA class stop codes point to defective or unstable RAM (XMP/EXPO timing instability, failing DIMM) or corrupted page tables.",
                format!(
                    "Crashes: {}\nDump files: {}",
                    count,
                    memory_crashes.iter().map(|c| c.source_file.as_str()).take(4).collect::<Vec<_>>().join(", "),
                ),
                "Schedule Windows Memory Diagnostic (mdsched.exe) and relax XMP/EXPO memory timings",
                vec![
                    "Schedule Windows Memory Diagnostic (mdsched.exe) for the next reboot".to_string(),
                    "Lower XMP/EXPO memory frequency or increase DRAM voltage in BIOS".to_string(),
                    "If errors persist, test DIMMs individually to isolate the failing module".to_string(),
                ],
            ));
        }

        // 4. Remaining crashes without driver attribution
        if !generic_crashes.is_empty() {
            let count = generic_crashes.len();
            let severity = if count >= 3 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            let code_counts: BTreeMap<String, usize> = generic_crashes
                .iter()
                .map(|c| (format!("0x{:08X}", c.bugcheck_code), ()))
                .fold(BTreeMap::new(), |mut acc, (code, ())| {
                    *acc.entry(code).or_insert(0) += 1;
                    acc
                });
            let details = code_counts
                .iter()
                .map(|(code, cnt)| {
                    let info = bugcheck_info(
                        u32::from_str_radix(code.trim_start_matches("0x"), 16).unwrap_or(0),
                    );
                    match info {
                        Some(i) => format!("{} x{} ({})", code, cnt, i.name),
                        None => format!("{} x{}", code, cnt),
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");

            issues.push(Issue::new(
                "crash_bugcheck_history",
                self.id(),
                format!("Recurring BSOD history ({} crashes)", count),
                "Hardware & Stability",
                severity,
                RiskScore::Low,
                "Bugchecks were recorded whose stop codes do not isolate a single driver or memory subsystem. Driver conflicts after Windows/driver updates are the most common root cause of this pattern.",
                format!("Stop code distribution:\n{}", details),
                "Review recently updated drivers and run system file verification (sfc /scannow)",
                vec![
                    "Review drivers updated shortly before the first crash and roll suspect updates back".to_string(),
                    "Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'".to_string(),
                ],
            ).with_advice_only());
        }

        // 5. Kernel-Power 41 events beyond explainable bugchecks
        let bugcheck_total = crashes.len();
        if kernel_power_41 > bugcheck_total {
            let unexplained = kernel_power_41 - bugcheck_total;
            issues.push(Issue::new(
                "crash_unexpected_shutdown",
                self.id(),
                format!(
                    "{} unexpected shutdown(s) without a bugcheck",
                    unexplained
                ),
                "Hardware & Stability",
                Severity::Warning,
                RiskScore::Low,
                "Kernel-Power Event 41 was logged without a corresponding crash dump: the system lost power or froze hard before Windows could write a bugcheck. This points to PSU instability, overheating with emergency shutdown, a stuck system image or a held power button.",
                format!(
                    "Kernel-Power 41 events: {}\nBugcheck-backed crashes: {}\nUnexplained: {}",
                    kernel_power_41, bugcheck_total, unexplained
                ),
                "Check PSU capacity/cabling, CPU & GPU thermals and Windows reliability history",
                vec![
                    "Check CPU/GPU temperatures under load and clean dust from fans/radiators".to_string(),
                    "Verify the PSU is sized for peak system load and cables are fully seated".to_string(),
                    "Review Event Viewer reliability history around the shutdown timestamps".to_string(),
                ],
            ).with_advice_only());
        }

        // 6. What changed before the crashes began
        Self::send_progress(
            &progress_tx,
            90,
            "Looking at what changed before the first crash...",
            None,
        )
        .await;
        if let Some((first, changes)) = self.what_changed(&dbg).await {
            issues.push(crash_timeline::finding(self.id(), first, &changes));
        }

        // 7. Dump accumulation
        if total_dump_files > STALE_DUMP_THRESHOLD || user_dump_count > 10 {
            issues.push(Issue::new(
                "crash_stale_dumps",
                self.id(),
                format!(
                    "{} crash dump(s) accumulated on disk",
                    total_dump_files + user_dump_count
                ),
                "System Cleanup",
                Severity::Info,
                RiskScore::Low,
                "A large number of crash dumps has accumulated. Each kernel minidump is up to a few megabytes; once analysed they can be safely deleted to reclaim disk space.",
                format!(
                    "Kernel minidumps in {}: {}\nUser-mode dumps in %LOCALAPPDATA%\\CrashDumps: {}",
                    DEFAULT_DUMP_DIR, total_dump_files, user_dump_count
                ),
                "Delete analysed crash dump files",
                vec!["Remove outdated minidump and user-mode crash dump files".to_string()],
            ));
        }

        Self::send_progress(&progress_tx, 100, "Crash analysis complete", None).await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        let dbg = DebugTrace::fix(self.id(), progress_tx.clone(), self.config.verbose_logging);
        match issue_id {
            "crash_driver_fault" | "crash_video_tdr" => {
                if let Some(ref tx) = progress_tx {
                    let _ = tx
                        .send(FixProgress {
                            issue_id: issue_id.to_string(),
                            step_description: "Opening Device Manager for driver rollback..."
                                .to_string(),
                            is_success: true,
                            error: None,
                            console_line: Some("cmd.exe /c start devmgmt.msc".to_string()),
                        })
                        .await;
                }

                let open_res = dbg
                    .run(
                        &self.runner,
                        "cmd.exe",
                        &["/c", "start", "", "devmgmt.msc"],
                        Duration::from_secs(10),
                    )
                    .await;

                match open_res {
                    Ok(out) if out.success => Ok(
                        "Device Manager opened. Roll back or clean-reinstall the implicated driver as outlined in the fix steps."
                            .to_string(),
                    ),
                    _ => Err(
                        "Device Manager could not be opened. Open it yourself (devmgmt.msc), roll back the implicated display/driver, then clean-reinstall the latest vendor package (DDU recommended)."
                            .to_string(),
                    ),
                }
            }
            "crash_memory_bugcheck" => {
                if let Some(ref tx) = progress_tx {
                    let _ = tx
                        .send(FixProgress {
                            issue_id: issue_id.to_string(),
                            step_description: "Scheduling Windows Memory Diagnostic tool..."
                                .to_string(),
                            is_success: true,
                            error: None,
                            console_line: Some("mdsched.exe".to_string()),
                        })
                        .await;
                }

                let sched_res = self
                    .runner
                    .run("mdsched.exe", &[], Duration::from_secs(5))
                    .await;

                match sched_res {
                    Ok(out) if out.success => Ok(
                        "Windows Memory Diagnostic (mdsched.exe) launched. The memory test runs during the next reboot; also check XMP/EXPO settings in BIOS."
                            .to_string(),
                    ),
                    _ => Err(
                        "Windows Memory Diagnostic (mdsched.exe) could not be started. Start it from the Start menu, and check XMP/EXPO settings in BIOS."
                            .to_string(),
                    ),
                }
            }
            "crash_stale_dumps" => {
                if let Some(ref tx) = progress_tx {
                    let _ = tx
                        .send(FixProgress {
                            issue_id: issue_id.to_string(),
                            step_description: "Deleting analysed crash dump files...".to_string(),
                            is_success: true,
                            error: None,
                            console_line: Some(format!(
                                "powershell.exe Remove-Item '{}\\*.dmp'",
                                DEFAULT_DUMP_DIR
                            )),
                        })
                        .await;
                }

                let remove_cmd = format!(
                    "Remove-Item -Path '{}\\*.dmp' -Force -ErrorAction SilentlyContinue",
                    DEFAULT_DUMP_DIR
                );
                let res = dbg
                    .run(
                        &self.runner,
                        "powershell.exe",
                        &["-NoProfile", "-Command", &remove_cmd],
                        Duration::from_secs(30),
                    )
                    .await;

                let user_dir_cmd = "Remove-Item -Path (Join-Path $env:LOCALAPPDATA 'CrashDumps\\*.dmp') -Force -ErrorAction SilentlyContinue";
                let _ = dbg
                    .run(
                        &self.runner,
                        "powershell.exe",
                        &["-NoProfile", "-Command", user_dir_cmd],
                        Duration::from_secs(30),
                    )
                    .await;

                match res {
                    Ok(out) if out.success => Ok("Analysed crash dump files deleted.".to_string()),
                    _ => Ok(
                        "Crash dump cleanup ran; individual unreadable files may remain."
                            .to_string(),
                    ),
                }
            }
            // The unexpected-shutdown and bugcheck-history findings are
            // advice: a repair run never asks.
            _ => Err(format!("Unknown crash analysis issue id: {}", issue_id)),
        }
    }
}

fn dump_dir_dmp_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("dmp"))
        })
        .collect();
    files.sort();
    files
}

/// Parses the kernel dump header (`PAGEDUMP` / `PAGEDU64` signatures) to
/// extract the bugcheck code, its four parameters and embedded driver names.
///
/// Header layout (documented `DUMP_HEADER` / `DUMP_HEADER64`):
/// 32-bit: signature `PAGE`+`DUMP`, BugCheckCode at 0x28, params (u32) at 0x2C.
/// 64-bit: signature `PAGE`+`DU64`, BugCheckCode at 0x38, params (u64) at 0x40.
pub fn parse_minidump_header(bytes: &[u8]) -> Option<MinidumpInfo> {
    if bytes.len() < 8 || &bytes[0..4] != b"PAGE" {
        return None;
    }

    let mut info = MinidumpInfo::default();
    let (code_off, param_off, param_u64): (usize, usize, bool) = match &bytes[4..8] {
        b"DU64" => (0x38, 0x40, true),
        b"DUMP" => (0x28, 0x2C, false),
        _ => return None,
    };

    let read_le = |off: usize, len: usize| -> Option<u64> {
        if off + len > bytes.len() {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[..len].copy_from_slice(&bytes[off..off + len]);
        Some(u64::from_le_bytes(buf))
    };

    info.bugcheck_code = read_le(code_off, 4)? as u32;
    for (i, slot) in info.bugcheck_params.iter_mut().enumerate() {
        *slot = if param_u64 {
            read_le(param_off + i * 8, 8)?
        } else {
            read_le(param_off + i * 4, 4)?
        };
    }

    if bytes.len() <= DRIVER_SCAN_MAX_BYTES {
        let drivers = extract_driver_names(bytes);
        info.faulting_driver = pick_faulting_driver(&drivers);
        info.drivers_seen = drivers;
    }

    Some(info)
}

/// Collects `.sys` module names embedded in the dump payload, both as ASCII
/// and as UTF-16LE (the format the kernel module list uses).
pub fn extract_driver_names(bytes: &[u8]) -> Vec<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();

    // ASCII runs
    let mut current = String::new();
    for &b in bytes {
        if b.is_ascii_graphic() {
            current.push(b as char);
        } else {
            flush_driver_token(&current, &mut found);
            current.clear();
        }
    }
    flush_driver_token(&current, &mut found);

    // UTF-16LE runs. Manual stepping instead of chunks_exact(2): the exact
    // API differs between toolchain versions and index pairs sidestep that.
    let mut current = String::new();
    let pairs = bytes.len() / 2 * 2;
    for i in (0..pairs).step_by(2) {
        let unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let c = u32::from(unit);
        if (0x20..=0x7E).contains(&c) {
            current.push(char::from_u32(c).unwrap_or('?'));
        } else {
            flush_driver_token(&current, &mut found);
            current.clear();
        }
    }
    flush_driver_token(&current, &mut found);

    found.into_iter().collect()
}

fn flush_driver_token(token: &str, out: &mut BTreeSet<String>) {
    if token.len() >= 6 && token.len() <= 48 && token.to_ascii_lowercase().ends_with(".sys") {
        out.insert(token.to_ascii_lowercase());
    }
}

/// Drivers with a strong track record of causing BSODs; if one of these is
/// embedded in the dump we name it as the faulting module.
const KNOWN_TROUBLE_DRIVERS: &[&str] = &[
    "nvlddmkm.sys",
    "nvlddmkm",
    "amdkmdag.sys",
    "amdkmdap.sys",
    "atikmdag.sys",
    "atikmpag.sys",
    "igdkmd64.sys",
    "igdkmd32.sys",
    "nvme.sys",
    "storahci.sys",
    "stornvme.sys",
    "rt640x64.sys",
    "rt640x86.sys",
    "e1d.sys",
    "e1g6032e.sys",
    "netwtw06.sys",
    "netwtw04.sys",
    "athw8x.sys",
    "athwnx.sys",
    "bcmwl63a.sys",
    "wdiwifi.sys",
    "dxgkrnl.sys",
    "dxgmms2.sys",
    "tcpip.sys",
    "ntfs.sys",
    "fltmgr.sys",
    "aswndsys.sys",
    "aswsp.sys",
];

fn pick_faulting_driver(drivers: &[String]) -> Option<String> {
    for known in KNOWN_TROUBLE_DRIVERS {
        if let Some(hit) = drivers.iter().find(|d| d == known || d.ends_with(known)) {
            return Some(hit.clone());
        }
    }
    None
}

fn describe_driver_component(driver: &str) -> &'static str {
    let d = driver.to_ascii_lowercase();
    if d.starts_with("nvlddmkm") {
        "NVIDIA display"
    } else if d.starts_with("amd") || d.starts_with("atik") {
        "AMD display"
    } else if d.starts_with("igdkmd") {
        "Intel graphics"
    } else if d.contains("nvme")
        || d.contains("storahci")
        || d.contains("stornvme")
        || d.contains("ntfs")
    {
        "storage"
    } else if d.contains("rt640")
        || d.starts_with("e1")
        || d.contains("netwtw")
        || d.contains("athw")
        || d.contains("wifi")
    {
        "network"
    } else if d.contains("dxg") {
        "DirectX graphics kernel"
    } else {
        "kernel"
    }
}

/// Human-readable information for the most common bugcheck codes.
pub fn bugcheck_info(code: u32) -> Option<BugcheckInfo> {
    let info = match code {
        0x03 => (
            "INVALID_AFFINITY_SET",
            "Illegal processor affinity was requested",
            BugcheckCategory::System,
        ),
        0x0A => (
            "IRQL_NOT_LESS_OR_EQUAL",
            "A kernel-mode driver accessed paged memory at an invalid IRQL",
            BugcheckCategory::Driver,
        ),
        0x1A => (
            "MEMORY_MANAGEMENT",
            "Severe memory management failure, typically defective RAM or corrupted page tables",
            BugcheckCategory::Memory,
        ),
        0x18 => (
            "REFERENCE_BY_POINTER",
            "Reference-counting inconsistency on a kernel object",
            BugcheckCategory::System,
        ),
        0x19 => (
            "BAD_POOL_HEADER",
            "Corrupted kernel pool header, often caused by a buggy driver or RAM",
            BugcheckCategory::Memory,
        ),
        0x1E => (
            "KMODE_EXCEPTION_NOT_HANDLED",
            "An unhandled exception occurred in kernel mode",
            BugcheckCategory::Driver,
        ),
        0x24 => (
            "NTFS_FILE_SYSTEM",
            "NTFS volume corruption or a faulty storage stack",
            BugcheckCategory::Storage,
        ),
        0x2E => (
            "DATA_BUS_ERROR",
            "Parity error on the system bus, typically failing RAM or motherboard",
            BugcheckCategory::Memory,
        ),
        0x3B => (
            "SYSTEM_SERVICE_EXCEPTION",
            "An exception occurred while executing a system service",
            BugcheckCategory::Driver,
        ),
        0x44 => (
            "MULTIPLE_IRP_COMPLETE_REQUESTS",
            "A driver completed the same I/O request packet twice",
            BugcheckCategory::Driver,
        ),
        0x50 => (
            "PAGE_FAULT_IN_NONPAGED_AREA",
            "Invalid memory reference in non-paged RAM, classically a RAM or driver fault",
            BugcheckCategory::Memory,
        ),
        0x77 => (
            "KERNEL_STACK_INPAGE_ERROR",
            "A kernel stack page could not be read from disk, often a failing drive",
            BugcheckCategory::Storage,
        ),
        0x7A => (
            "KERNEL_DATA_INPAGE_ERROR",
            "Kernel data could not be paged in from disk - drive or controller fault",
            BugcheckCategory::Storage,
        ),
        0x7F => (
            "UNEXPECTED_KERNEL_MODE_TRAP",
            "CPU trap in kernel mode, often hardware (RAM/CPU) or overclock instability",
            BugcheckCategory::Memory,
        ),
        0x9F => (
            "DRIVER_POWER_STATE_FAILURE",
            "A driver stalled during a power transition (sleep/resume)",
            BugcheckCategory::Driver,
        ),
        0xA0 => (
            "INTERNAL_POWER_ERROR",
            "Power policy failure, commonly GPU power management on laptops",
            BugcheckCategory::VideoDriver,
        ),
        0xC2 => (
            "BAD_POOL_CALLER",
            "A driver made an invalid pool request, often RAM or driver corruption",
            BugcheckCategory::Memory,
        ),
        0xC4 => (
            "DRIVER_VERIFIER_DETECTED_VIOLATION",
            "Driver Verifier caught a driver breaking kernel rules",
            BugcheckCategory::Driver,
        ),
        0xC5 => (
            "DRIVER_CORRUPTED_EXPOOL",
            "A driver corrupted the executive pool",
            BugcheckCategory::Driver,
        ),
        0xC9 => (
            "DRIVER_VERIFIER_IOMANAGER_VIOLATION",
            "Driver Verifier caught an I/O manager violation",
            BugcheckCategory::Driver,
        ),
        0xD1 => (
            "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
            "A driver accessed invalid memory at too high an IRQL",
            BugcheckCategory::Driver,
        ),
        0xEA => (
            "THREAD_STUCK_IN_DEVICE_DRIVER",
            "A display driver thread stopped responding, GPU/driver fault",
            BugcheckCategory::VideoDriver,
        ),
        0xF5 => (
            "FLTMGR_FILE_SYSTEM",
            "Filter Manager filesystem corruption",
            BugcheckCategory::Storage,
        ),
        0xFC => (
            "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
            "Code execution from non-executable memory, usually a buggy driver",
            BugcheckCategory::Driver,
        ),
        0x109 => (
            "CRITICAL_STRUCTURE_CORRUPTION",
            "Kernel code/data was modified, often by buggy drivers or malware",
            BugcheckCategory::System,
        ),
        0x116 => (
            "VIDEO_TDR_FAILURE",
            "The display driver failed to reset in time (Timeout Detection & Recovery)",
            BugcheckCategory::VideoDriver,
        ),
        0x117 => (
            "VIDEO_TDR_TIMEOUT_DETECTED",
            "The GPU stopped responding and the driver recovered or bugchecked",
            BugcheckCategory::VideoDriver,
        ),
        0x124 => (
            "WHEA_UNCORRECTABLE_ERROR",
            "Fatal hardware error reported by the CPU/platform (WHEA)",
            BugcheckCategory::System,
        ),
        0x133 => (
            "DPC_WATCHDOG_VIOLATION",
            "A deferred procedure call ran too long, typically storage/GPU drivers or SSD firmware",
            BugcheckCategory::Driver,
        ),
        0x139 => (
            "KERNEL_SECURITY_CHECK_FAILURE",
            "Kernel stack buffer overrun or security check failed, often driver or RAM related",
            BugcheckCategory::System,
        ),
        0x13A => (
            "KERNEL_MODE_HEAP_CORRUPTION",
            "Kernel heap corruption, commonly driver or RAM faults",
            BugcheckCategory::Memory,
        ),
        0x154 => (
            "UNEXPECTED_STORE_EXCEPTION",
            "Memory compression store error, frequently a failing SSD or RAM",
            BugcheckCategory::Storage,
        ),
        0x15F => (
            "CONNECTED_STANDBY_WATCHDOG_TIMEOUT",
            "Modern Standby watchdog expired during a sleep transition",
            BugcheckCategory::Driver,
        ),
        0x1000007E => (
            "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
            "A system thread raised an unhandled exception",
            BugcheckCategory::Driver,
        ),
        0x100000D1 => (
            "DRIVER_IRQL_NOT_LESS_OR_EQUAL_M",
            "DRIVER_IRQL_NOT_LESS_OR_EQUAL with modified parameters",
            BugcheckCategory::Driver,
        ),
        _ => return None,
    };
    Some(BugcheckInfo {
        code,
        name: info.0,
        summary: info.1,
        category: info.2,
    })
}

/// Parses `wevtutil /f:xml` System-log output into crash event records
/// (bugcheck Event 1001 with its stop code, Kernel-Power Event 41).
pub fn parse_crash_events(raw_output: &str) -> Vec<CrashEventRecord> {
    crash_events(parse_events(raw_output))
}

/// The bugcheck and Kernel-Power 41 events among `events`.
pub fn crash_events(events: Vec<EventRecord>) -> Vec<CrashEventRecord> {
    events
        .into_iter()
        .filter_map(|event| {
            let (bugcheck_code, dump_file) = if event.provider == KERNEL_POWER_PROVIDER {
                // Kernel-Power also logs events other than 41.
                if event.event_id != 41 {
                    return None;
                }
                // Decimal, and 0 when the machine went down without one.
                let code = event
                    .data("BugcheckCode")
                    .and_then(|code| code.trim().parse::<u32>().ok())
                    .filter(|&code| code != 0);
                (code, None)
            } else if BUGCHECK_PROVIDERS.contains(&event.provider.as_str()) {
                if event.event_id != 1001 {
                    return None;
                }
                // param1: "0x0000009f (0x..., 0x..., 0x..., 0x...)",
                // param2: the dump Windows wrote for it.
                let code = event.data("param1").and_then(extract_hex_code);
                let dump = event.data("param2").and_then(|path| {
                    Path::new(path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(str::to_string)
                });
                (code, dump)
            } else {
                return None;
            };
            let when = event.time_created.as_deref().and_then(|time| {
                DateTime::parse_from_rfc3339(time)
                    .ok()
                    .map(|t| t.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string())
            });
            Some(CrashEventRecord {
                event_id: event.event_id,
                bugcheck_code,
                when,
                dump_file,
                raw_snippet: event.summary(),
            })
        })
        .collect()
}

/// Extracts the first `0x........` (8 hex digits) stop code on a line.
fn extract_hex_code(line: &str) -> Option<u32> {
    let line = line.trim();
    let lower = line.to_lowercase();
    let mut search_from = 0usize;
    while let Some(pos) = lower[search_from..].find("0x") {
        let start = search_from + pos + 2;
        let hex: String = lower[start..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .take(8)
            .collect();
        if hex.len() == 8 {
            return u32::from_str_radix(&hex, 16).ok();
        }
        search_from = start;
        if search_from >= lower.len() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::{CodePage, decode_output_in};

    fn empty_event_response(mock: &MockCommandRunner) {
        mock.add_response("wevtutil.exe", CmdOutput::ok(""));
    }

    // Captured on a German Windows 11 whose crashes began on 26 July; see
    // tests/fixtures/README.md.
    const JULY_CRASHES: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_crashes_july.bin");
    const JULY_UPDATES: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_wu_installed_19_de.bin");
    const JULY_SERVICES: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_service_installed_7045.bin");
    const JULY_PROGRAMS: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_msi_installed_1033.bin");
    const OLDEST_EVENT: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_system_oldest_event.bin");

    /// The capture machine's logs, its System log beginning at `log_start`.
    fn july(log_start: &[u8]) -> MockCommandRunner {
        let ansi = |bytes| CmdOutput::ok(decode_output_in(bytes, CodePage::Ansi));
        let mock = MockCommandRunner::new();
        mock.add_response("EventID=19 and", ansi(JULY_UPDATES));
        mock.add_response("EventID=7045", ansi(JULY_SERVICES));
        mock.add_response("EventID=1033", ansi(JULY_PROGRAMS));
        mock.add_response("/rd:false", ansi(log_start));
        mock.add_response("EventID=41", ansi(JULY_CRASHES));
        mock
    }

    async fn what_changed(tag: &str, mock: MockCommandRunner) -> Option<Issue> {
        let dir = temp_dump_dir(tag);
        let module = CrashAnalysisModule::with_runner_and_dump_dir(
            ModuleConfig::default(),
            Arc::new(mock),
            &dir,
        );
        let issues = module.scan(None).await.expect("scan failed");
        let _ = std::fs::remove_dir_all(&dir);
        issues.into_iter().find(|i| i.id == "crash_what_changed")
    }

    #[tokio::test]
    async fn the_week_before_the_first_crash_is_laid_out() {
        let issue = what_changed("timeline_week", july(OLDEST_EVENT))
            .await
            .expect("changes before 26 July");
        assert!(issue.advice_only && !issue.is_selected);
        let details = &issue.technical_details;
        assert!(details.contains("New driver: BEDaisy ("), "{details}");
        assert!(
            details.contains("Windows update: Sicherheitsupdate für Microsoft Visual C++ 2010"),
            "{details}"
        );
        assert!(!details.contains("KB2267602"), "{details}");
        assert!(!details.contains("MagicianSataModeReader"), "{details}");
        assert!(
            issue
                .fix_steps
                .iter()
                .any(|step| step.starts_with("Uninstall an update")),
            "{:?}",
            issue.fix_steps
        );
    }

    /// A System log that begins inside the week cannot tell a new driver
    /// from one registered again, so it names none.
    #[tokio::test]
    async fn a_short_log_names_no_driver_new() {
        let issue = what_changed("timeline_short_log", july(JULY_CRASHES))
            .await
            .expect("updates and programs are still changes");
        assert!(
            !issue.technical_details.contains("New driver"),
            "{}",
            issue.technical_details
        );
    }

    #[tokio::test]
    async fn no_crash_no_timeline() {
        let mock = MockCommandRunner::new();
        empty_event_response(&mock);
        assert_eq!(what_changed("timeline_no_crash", mock).await, None);
    }

    /// Builds a synthetic 64-bit kernel dump with the given bugcheck code and
    /// an optional embedded ASCII driver name.
    fn synth_dump64(code: u32, extra: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x60];
        bytes[0..8].copy_from_slice(b"PAGEDU64");
        bytes[0x38..0x3C].copy_from_slice(&code.to_le_bytes());
        bytes[0x40..0x48].copy_from_slice(&0x1111111111111111u64.to_le_bytes());
        bytes[0x48..0x50].copy_from_slice(&0x2222222222222222u64.to_le_bytes());
        bytes[0x50..0x58].copy_from_slice(&0x3333333333333333u64.to_le_bytes());
        bytes[0x58..0x60].copy_from_slice(&0x4444444444444444u64.to_le_bytes());
        bytes.extend_from_slice(b"\x00\x00");
        bytes.extend_from_slice(extra);
        bytes
    }

    fn temp_dump_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("winmedic_dmp_test_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("failed to create temp dump dir");
        dir
    }

    fn write_dump(dir: &Path, name: &str, bytes: &[u8]) {
        std::fs::write(dir.join(name), bytes).expect("failed to write dump");
    }

    #[test]
    fn test_parse_header_pagedu64() {
        let bytes = synth_dump64(0x116, b"");
        let info = parse_minidump_header(&bytes).expect("header should parse");
        assert_eq!(info.bugcheck_code, 0x116);
        assert_eq!(info.bugcheck_params[0], 0x1111111111111111);
        assert_eq!(info.bugcheck_params[3], 0x4444444444444444);
    }

    #[test]
    fn test_parse_header_pagedump_32bit() {
        let mut bytes = vec![0u8; 0x40];
        bytes[0..8].copy_from_slice(b"PAGEDUMP");
        bytes[0x28..0x2C].copy_from_slice(&0x1Au32.to_le_bytes());
        bytes[0x2C..0x30].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let info = parse_minidump_header(&bytes).expect("header should parse");
        assert_eq!(info.bugcheck_code, 0x1A);
        assert_eq!(info.bugcheck_params[0], 0xDEADBEEF);
    }

    #[test]
    fn test_parse_header_rejects_garbage() {
        assert!(parse_minidump_header(b"MDMP junk data here").is_none());
        assert!(parse_minidump_header(b"").is_none());
        assert!(parse_minidump_header(b"PAGEXXXX").is_none());
    }

    #[test]
    fn test_extract_driver_names_ascii_and_utf16() {
        let payload = b"\x00\x00nvlddmkm.sys\x00\x00ntoskrnl.exe\x00rt640x64.sys".to_vec();
        let mut utf16 = Vec::new();
        for c in "amdkmdag.sys".chars() {
            utf16.extend_from_slice(&(c as u16).to_le_bytes());
        }
        let mut bytes = payload;
        bytes.push(0);
        if bytes.len() % 2 == 1 {
            bytes.push(0); // keep the UTF-16LE run 2-byte aligned
        }
        bytes.extend_from_slice(&utf16);

        let drivers = extract_driver_names(&bytes);
        assert!(drivers.contains(&"nvlddmkm.sys".to_string()));
        assert!(drivers.contains(&"rt640x64.sys".to_string()));
        // Unaligned UTF-16LE runs can absorb a stray preceding byte; the
        // suffix must match so driver attribution still works.
        assert!(drivers.iter().any(|d| d.ends_with("amdkmdag.sys")));
        assert!(!drivers.iter().any(|d| d.ends_with(".exe")));

        let faulting = pick_faulting_driver(&drivers);
        assert_eq!(faulting.as_deref(), Some("nvlddmkm.sys"));
    }

    #[test]
    fn test_bugcheck_info_known_and_unknown() {
        let mm = bugcheck_info(0x1A).expect("0x1A must be known");
        assert_eq!(mm.name, "MEMORY_MANAGEMENT");
        assert_eq!(mm.category, BugcheckCategory::Memory);

        let tdr = bugcheck_info(0x116).expect("0x116 must be known");
        assert_eq!(tdr.category, BugcheckCategory::VideoDriver);

        assert!(bugcheck_info(0xDEADBEEF).is_none());
    }

    // Real events from a German Windows 11; see tests/fixtures/README.md.
    const WER_BUGCHECK: &str = include_str!("../../tests/fixtures/events/wer_bugcheck_1001.xml");
    const KERNEL_POWER_41: &str = include_str!("../../tests/fixtures/events/kernel_power_41.xml");
    const SYSTEM_ERRORS: &str = include_str!("../../tests/fixtures/events/system_errors.xml");

    /// A minimal event in the shape `wevtutil /f:xml` prints.
    fn event_xml(provider: &str, id: u32, data: &[(&str, &str)]) -> String {
        let data: String = data
            .iter()
            .map(|(name, value)| format!("<Data Name='{name}'>{value}</Data>"))
            .collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{provider}'/><EventID>{id}</EventID><Level>2</Level><TimeCreated SystemTime='2026-08-20T10:15:30.0000000Z'/></System><EventData>{data}</EventData></Event>"
        )
    }

    #[test]
    fn test_parse_real_bugcheck_event() {
        let events = parse_crash_events(WER_BUGCHECK);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 1001);
        assert_eq!(events[0].bugcheck_code, Some(0x9F));
        assert_eq!(events[0].dump_file.as_deref(), Some("072726-7843-01.dmp"));
        assert!(events[0].when.is_some());
    }

    #[test]
    fn test_parse_bugcheck_event_from_the_legacy_provider() {
        let xml = event_xml(
            "BugCheck",
            1001,
            &[(
                "param1",
                "0x000000d1 (0x0000000000000000, 0x0000000000000002)",
            )],
        );
        let events = parse_crash_events(&xml);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].bugcheck_code, Some(0xD1));
        assert_eq!(events[0].dump_file, None);
    }

    #[test]
    fn test_parse_real_kernel_power_41_events() {
        let events = parse_crash_events(KERNEL_POWER_41);
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.event_id == 41));
        // BugcheckCode 0: the machine went down without a bugcheck.
        assert!(events.iter().all(|e| e.bugcheck_code.is_none()));
    }

    #[test]
    fn test_kernel_power_41_carries_a_decimal_bugcheck_code() {
        let xml = event_xml(KERNEL_POWER_PROVIDER, 41, &[("BugcheckCode", "159")]);
        assert_eq!(parse_crash_events(&xml)[0].bugcheck_code, Some(0x9F));
    }

    #[test]
    fn test_parse_events_ignores_unrelated_logs() {
        assert!(parse_crash_events(SYSTEM_ERRORS).is_empty());
        let other_kernel_power = event_xml(KERNEL_POWER_PROVIDER, 109, &[]);
        assert!(parse_crash_events(&other_kernel_power).is_empty());
    }

    #[test]
    fn test_the_query_asks_for_the_provider_windows_actually_uses() {
        // Found on a real machine: a 0x9F bugcheck logged by
        // WER-SystemErrorReporting, invisible to a query for 'BugCheck'.
        assert!(BUGCHECK_PROVIDERS.contains(&"Microsoft-Windows-WER-SystemErrorReporting"));
    }

    #[tokio::test]
    async fn test_scan_detects_driver_fault_from_dump() {
        let dir = temp_dump_dir("drv");
        write_dump(
            &dir,
            "dump01.dmp",
            &synth_dump64(0xD1, b"\x00nvlddmkm.sys\x00"),
        );
        write_dump(
            &dir,
            "dump02.dmp",
            &synth_dump64(0xD1, b"\x00nvlddmkm.sys\x00"),
        );

        let mock = MockCommandRunner::new();
        empty_event_response(&mock);

        let module = CrashAnalysisModule::with_runner_and_dump_dir(
            ModuleConfig::default(),
            Arc::new(mock),
            &dir,
        );
        let issues = module.scan(None).await.expect("scan failed");

        let driver_issue = issues
            .iter()
            .find(|i| i.id == "crash_driver_fault")
            .expect("driver issue");
        assert_eq!(driver_issue.severity, Severity::Critical); // 2 crashes escalate
        assert!(driver_issue.title.contains("nvlddmkm.sys"));
        assert!(driver_issue.technical_details.contains("0x000000D1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_scan_detects_memory_bugcheck_from_event() {
        let dir = temp_dump_dir("mem");
        let mock = MockCommandRunner::new();
        mock.add_response(
            "wevtutil.exe",
            CmdOutput::ok(event_xml(
                "Microsoft-Windows-WER-SystemErrorReporting",
                1001,
                &[("param1", "0x00000050 (0xfffff80233000000)")],
            )),
        );

        let module = CrashAnalysisModule::with_runner_and_dump_dir(
            ModuleConfig::default(),
            Arc::new(mock),
            &dir,
        );
        let issues = module.scan(None).await.expect("scan failed");

        let mem = issues
            .iter()
            .find(|i| i.id == "crash_memory_bugcheck")
            .expect("memory issue");
        assert_eq!(mem.severity, Severity::Critical);
        assert!(mem.technical_details.contains("Event 1001"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_scan_detects_video_tdr() {
        let dir = temp_dump_dir("tdr");
        write_dump(
            &dir,
            "dump01.dmp",
            &synth_dump64(0x116, b"\x00dxgkrnl.sys\x00"),
        );

        let mock = MockCommandRunner::new();
        empty_event_response(&mock);

        let module = CrashAnalysisModule::with_runner_and_dump_dir(
            ModuleConfig::default(),
            Arc::new(mock),
            &dir,
        );
        let issues = module.scan(None).await.expect("scan failed");

        let tdr = issues
            .iter()
            .find(|i| i.id == "crash_video_tdr")
            .expect("tdr issue");
        assert_eq!(tdr.severity, Severity::Critical);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_scan_detects_unexpected_shutdown() {
        let dir = temp_dump_dir("kp41");
        let mock = MockCommandRunner::new();
        mock.add_response(
            "wevtutil.exe",
            CmdOutput::ok(event_xml(
                KERNEL_POWER_PROVIDER,
                41,
                &[("BugcheckCode", "0")],
            )),
        );

        let module = CrashAnalysisModule::with_runner_and_dump_dir(
            ModuleConfig::default(),
            Arc::new(mock),
            &dir,
        );
        let issues = module.scan(None).await.expect("scan failed");

        let kp = issues
            .iter()
            .find(|i| i.id == "crash_unexpected_shutdown")
            .expect("unexpected shutdown issue");
        assert_eq!(kp.severity, Severity::Warning);
        assert!(kp.technical_details.contains("Unexplained: 1"));
        assert!(
            kp.advice_only,
            "a lost power supply is not repaired in software"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_a_crash_with_dump_and_event_is_counted_once() {
        // The real event names 072726-7843-01.dmp; the same dump sits in the
        // dump directory. One crash, not two.
        let dir = temp_dump_dir("dedup");
        write_dump(&dir, "072726-7843-01.dmp", &synth_dump64(0x9F, b""));

        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil.exe", CmdOutput::ok(WER_BUGCHECK));

        let module = CrashAnalysisModule::with_runner_and_dump_dir(
            ModuleConfig::default(),
            Arc::new(mock),
            &dir,
        );
        let issues = module.scan(None).await.expect("scan failed");

        let history = issues
            .iter()
            .find(|i| i.id == "crash_bugcheck_history")
            .expect("bugcheck history");
        assert!(history.advice_only);
        assert!(
            history.technical_details.contains("0x0000009F x1"),
            "the event's crash is the dump's crash: {}",
            history.technical_details
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_scan_clean_when_no_crashes() {
        let dir = temp_dump_dir("clean");
        let mock = MockCommandRunner::new();
        empty_event_response(&mock);

        let module = CrashAnalysisModule::with_runner_and_dump_dir(
            ModuleConfig::default(),
            Arc::new(mock),
            &dir,
        );
        let issues = module.scan(None).await.expect("scan failed");
        assert!(issues.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_scan_flags_stale_dump_accumulation() {
        let dir = temp_dump_dir("stale");
        for i in 0..6 {
            write_dump(&dir, &format!("dump{i}.dmp"), &synth_dump64(0xD1, b""));
        }

        let mock = MockCommandRunner::new();
        empty_event_response(&mock);

        let module = CrashAnalysisModule::with_runner_and_dump_dir(
            ModuleConfig::default(),
            Arc::new(mock),
            &dir,
        );
        let issues = module.scan(None).await.expect("scan failed");

        let stale = issues
            .iter()
            .find(|i| i.id == "crash_stale_dumps")
            .expect("stale issue");
        assert_eq!(stale.severity, Severity::Info);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_fix_driver_fault_opens_device_manager() {
        let mock = MockCommandRunner::new();
        mock.add_response("cmd.exe", CmdOutput::ok(""));

        let module =
            CrashAnalysisModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let res = module.fix("crash_driver_fault", None).await;

        assert!(res.is_ok());
        let exec = mock.executed();
        assert!(
            exec.iter()
                .any(|c| c.contains("cmd.exe") && c.contains("devmgmt.msc"))
        );
    }

    #[tokio::test]
    async fn test_fix_memory_bugcheck_runs_mdsched() {
        let mock = MockCommandRunner::new();
        mock.add_response("mdsched.exe", CmdOutput::ok(""));

        let module =
            CrashAnalysisModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let res = module.fix("crash_memory_bugcheck", None).await;

        assert!(res.is_ok());
        let exec = mock.executed();
        assert!(exec.iter().any(|c| c.contains("mdsched.exe")));
    }

    #[tokio::test]
    async fn test_fix_stale_dumps_runs_powershell_remove() {
        let mock = MockCommandRunner::new();
        mock.add_response("powershell.exe", CmdOutput::ok(""));

        let module =
            CrashAnalysisModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let res = module.fix("crash_stale_dumps", None).await;

        assert!(res.is_ok());
        let exec = mock.executed();
        assert!(
            exec.iter()
                .any(|c| c.contains("Remove-Item") && c.contains("Minidump"))
        );
    }

    #[tokio::test]
    async fn advice_findings_have_no_repair_that_could_claim_success() {
        let mock = MockCommandRunner::new();
        let module = CrashAnalysisModule::with_runner(ModuleConfig::default(), Arc::new(mock));

        for id in ["crash_unexpected_shutdown", "crash_bugcheck_history"] {
            assert!(module.fix(id, None).await.is_err(), "{id}");
        }
    }

    #[tokio::test]
    async fn test_fix_unknown_id_returns_error() {
        let mock = MockCommandRunner::new();
        let module = CrashAnalysisModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let res = module.fix("nonexistent_id", None).await;

        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Unknown crash analysis issue id"));
    }
}
