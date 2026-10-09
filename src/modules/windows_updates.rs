use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::crash_timeline::{DEFENDER_SIGNATURES, STORE_SERVICE, WU_PROVIDER, logged_at};
use crate::modules::system_cleaner::{clean_path_contents, cleanup_result, format_bytes};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::event_xml::{EventRecord, read_events, system_log_query};
use crate::utils::fs_stats::{dir_stats_recursive, measure_dirs};
use crate::utils::service::{
    self, SERVICE_DISABLED, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STOPPED, StartAgain,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

pub struct WindowsUpdatesModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
    /// `%SystemRoot%\SoftwareDistribution\Download`.
    download_dir: PathBuf,
    /// `%SystemRoot%\SoftwareDistribution` and `%SystemRoot%\System32\catroot2`,
    /// which the component reset renames.
    component_dirs: [PathBuf; 2],
}

/// The services that hold the update download cache open, in the order they
/// are stopped.
const CACHE_SERVICES: [&str; 3] = ["wuauserv", "bits", "cryptsvc"];

/// [`CACHE_SERVICES`] in reverse: the order they are started again.
const CACHE_SERVICES_REVERSED: [&str; 3] =
    [CACHE_SERVICES[2], CACHE_SERVICES[1], CACHE_SERVICES[0]];

/// The finding for restart work Windows has queued. Only the restart settles
/// it, so it is advice, and the window offers the restart.
pub const REBOOT_PENDING: &str = "wu_reboot_pending";

/// Where Component Based Servicing parks the work a restart has to finish.
const CBS_REBOOT_PENDING_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending";

/// Windows Update's own restart flag.
const WU_REBOOT_REQUIRED_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";

/// Holds `PendingFileRenameOperations`, the queue the Session Manager runs
/// before anything else starts at boot.
const SESSION_MANAGER_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager";

/// What the registry says about a restart Windows is still waiting for.
///
/// Collected apart from the verdict so [`pending_reboot_reason`] can be tested
/// against every combination without a registry to write into.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RebootSignals {
    /// Entries (values plus subkeys) under the CBS `RebootPending` key, or
    /// `None` when the key does not exist at all.
    pub cbs_pending_entries: Option<u32>,
    /// Whether Windows Update's `RebootRequired` key exists.
    pub wu_reboot_required: bool,
    /// Non-empty entries queued in `PendingFileRenameOperations`.
    pub pending_file_renames: usize,
}

/// Why a restart is outstanding, or `None` when nothing actually is.
///
/// The subtlety is the CBS key. Windows creates
/// `Component Based Servicing\RebootPending` while it services the machine and
/// files the work underneath it; the restart consumes that work and clears the
/// entries, but the key itself is routinely left behind — empty and permanent.
/// Treating its bare existence as evidence, which is what every "is a reboot
/// pending" snippet on the internet does, reports a restart that no restart can
/// ever clear: the user reboots, scans again, and WinMedic says the same thing.
/// So the key counts only when it still holds something.
///
/// The other two signals are cleared properly by the boot that acts on them and
/// are read as they stand.
pub fn pending_reboot_reason(signals: &RebootSignals) -> Option<String> {
    let mut evidence = Vec::new();

    if let Some(entries) = signals.cbs_pending_entries
        && entries > 0
    {
        evidence.push(format!(
            "HKLM\\{} holds {} queued entr{}",
            CBS_REBOOT_PENDING_KEY,
            entries,
            if entries == 1 { "y" } else { "ies" }
        ));
    }

    if signals.wu_reboot_required {
        evidence.push(format!("HKLM\\{} exists", WU_REBOOT_REQUIRED_KEY));
    }

    if signals.pending_file_renames > 0 {
        evidence.push(format!(
            "PendingFileRenameOperations lists {} entr{} to be executed at the next boot",
            signals.pending_file_renames,
            if signals.pending_file_renames == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }

    (!evidence.is_empty()).then(|| evidence.join(" | "))
}

/// Read the three restart signals out of the registry.
fn read_reboot_signals() -> RebootSignals {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let cbs_pending_entries = hklm
        .open_subkey_with_flags(CBS_REBOOT_PENDING_KEY, KEY_READ)
        .ok()
        .map(|key| match key.query_info() {
            Ok(info) => info.sub_keys + info.values,
            // The key opened but refuses to be counted. That is evidence of
            // something rather than of nothing, so treat it as pending.
            Err(_) => 1,
        });

    let wu_reboot_required = hklm
        .open_subkey_with_flags(WU_REBOOT_REQUIRED_KEY, KEY_READ)
        .is_ok();

    // The value is a REG_MULTI_SZ of source/destination pairs, and a stale one
    // can sit there holding nothing but empty strings — those queue no work.
    let pending_file_renames = hklm
        .open_subkey_with_flags(SESSION_MANAGER_KEY, KEY_READ)
        .ok()
        .and_then(|key| {
            key.get_value::<Vec<String>, _>("PendingFileRenameOperations")
                .ok()
        })
        .map(|ops| ops.iter().filter(|op| !op.trim().is_empty()).count())
        .unwrap_or(0);

    RebootSignals {
        cbs_pending_entries,
        wu_reboot_required,
        pending_file_renames,
    }
}

/// The finding for a restart Windows is waiting for. Advice: WinMedic has
/// nothing to run for it. As a repair it only wrote a line into the report,
/// and the window then counted it as a repair waiting for the restart.
pub fn reboot_pending_finding(module_id: &str, evidence: &str) -> Issue {
    Issue::new(
        REBOOT_PENDING,
        module_id,
        "System reboot pending after updates",
        "Windows Update & Services",
        Severity::Info,
        RiskScore::Low,
        "Windows reports a reboot pending from a previously installed update or driver package. Some updates cannot continue until the machine restarts.",
        format!("Found in the registry: {}", evidence),
        "Restart Windows after the repairs to finish the pending installations",
        Vec::new(),
    )
    .with_advice_only()
}

/// How far back failed installs are looked for.
const FAILED_UPDATE_DAYS: u64 = 30;
/// An update that failed once may just have been interrupted.
const MIN_FAILURES: usize = 2;

/// The events of Windows Update installing (19) or failing to install (20)
/// something within the last [`FAILED_UPDATE_DAYS`].
pub fn install_events_query() -> Vec<String> {
    system_log_query(
        &format!("Provider[@Name='{WU_PROVIDER}'] and (EventID=19 or EventID=20)"),
        FAILED_UPDATE_DAYS * 24 * 3_600_000,
        500,
    )
}

/// An update Windows Update failed to install again and again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedUpdate {
    pub title: String,
    /// The newest failure's `errorCode`, e.g. `0x800f081f`.
    pub error_code: String,
    pub failures: usize,
}

/// Updates that failed at least [`MIN_FAILURES`] times since the last update
/// that did install.
///
/// Store apps (their own service, several a day) and Defender's signatures
/// (retried within hours) are left out, as in the crash timeline. An install
/// that works again clears the older failures: a failed monthly update is
/// replaced by the next month's, whose install is the proof that Windows
/// Update works, so a failure before it would never go away.
pub fn failing_updates(events: &[EventRecord]) -> Vec<FailedUpdate> {
    let relevant: Vec<&EventRecord> = events
        .iter()
        .filter(|e| e.provider == WU_PROVIDER && matches!(e.event_id, 19 | 20))
        .filter(|e| {
            e.data("serviceGuid")
                .is_none_or(|service| !service.eq_ignore_ascii_case(STORE_SERVICE))
        })
        .filter(|e| {
            e.data("updateTitle")
                .is_none_or(|title| !title.contains(DEFENDER_SIGNATURES))
        })
        .collect();
    let last_install = relevant
        .iter()
        .filter(|e| e.event_id == 19)
        .filter_map(|e| logged_at(e))
        .max();

    // Newest first, as wevtutil lists them, so the first failure of an
    // update seen is its newest.
    let mut failed: Vec<(String, FailedUpdate, chrono::DateTime<chrono::Utc>)> = Vec::new();
    for event in relevant.iter().filter(|e| e.event_id == 20) {
        let Some(when) = logged_at(event) else {
            continue;
        };
        if last_install.is_some_and(|installed| when <= installed) {
            continue;
        }
        let title = event.data("updateTitle").unwrap_or("").to_string();
        let key = event
            .data("updateGuid")
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| title.clone());
        match failed.iter_mut().find(|(known, _, _)| *known == key) {
            Some((_, update, newest)) => {
                update.failures += 1;
                if when > *newest {
                    *newest = when;
                    update.error_code = event.data("errorCode").unwrap_or("").to_string();
                }
            }
            None => failed.push((
                key,
                FailedUpdate {
                    title,
                    error_code: event.data("errorCode").unwrap_or("").to_string(),
                    failures: 1,
                },
                when,
            )),
        }
    }
    failed
        .into_iter()
        .map(|(_, update, _)| update)
        .filter(|update| update.failures >= MIN_FAILURES)
        .collect()
}

/// What an update's error code points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureCause {
    /// Damaged component store: DISM repairs it.
    ComponentStore,
    DiskFull,
    /// The update servers could not be reached: proxy, hosts file, DNS.
    Connection,
    /// The secure connection failed, which a wrong clock causes.
    Clock,
    /// A service Windows Update needs is disabled.
    ServiceDisabled,
    /// Nothing more specific: reset Windows Update's components.
    Other,
}

impl FailureCause {
    /// The cause behind an `errorCode` as event 20 writes it.
    pub fn of(error_code: &str) -> Self {
        match error_code.trim().to_ascii_lowercase().as_str() {
            // CBS_E_SOURCE_MISSING, CBS_E_STORE_CORRUPTION,
            // ERROR_SXS_COMPONENT_STORE_CORRUPT, ERROR_FILE_CORRUPT,
            // ERROR_INVALID_DATA
            "0x800f081f" | "0x800f0831" | "0x80073712" | "0x80070570" | "0x8007000d" => {
                Self::ComponentStore
            }
            // ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL
            "0x80070070" | "0x80070027" => Self::DiskFull,
            // WinHTTP timeouts and refused connections, names that do not
            // resolve, HTTP 503, a failed download of the repair source
            "0x80072ee2" | "0x80072efd" | "0x80072efe" | "0x80072ee7" | "0x8024402c"
            | "0x8024401c" | "0x80244022" | "0x8024402f" | "0x80240438" | "0x800f0906" => {
                Self::Connection
            }
            // ERROR_INTERNET_SECURE_FAILURE
            "0x80072f8f" => Self::Clock,
            // ERROR_SERVICE_DISABLED
            "0x80070422" => Self::ServiceDisabled,
            _ => Self::Other,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::ComponentStore => "wu_failed_component_store",
            Self::DiskFull => "wu_failed_disk_full",
            Self::Connection => "wu_failed_connection",
            Self::Clock => "wu_failed_clock",
            Self::ServiceDisabled => "wu_failed_service",
            Self::Other => UPDATE_RESET,
        }
    }

    /// Why the updates fail, and where WinMedic repairs that.
    fn advice(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::ComponentStore => (
                "Windows' component store, which every update is installed from, is damaged. DISM repairs it; System Integrity offers that repair when its check finds the damage.",
                &[
                    "DISM /Online /Cleanup-Image /RestoreHealth",
                    "Run Windows Update again",
                ],
            ),
            Self::DiskFull => (
                "The drive ran out of space while the update was installed.",
                &[
                    "Free space on C: (System & Cache Cleaner)",
                    "Run Windows Update again",
                ],
            ),
            Self::Connection => (
                "Windows Update could not reach Microsoft's servers. The usual causes are what the Network and Tweaks checks look for: a proxy nothing answers at, hosts entries that block the update servers, DNS.",
                &[
                    "Repair what the Network & DNS and Tweaks & Policies checks find",
                    "Run Windows Update again",
                ],
            ),
            Self::Clock => (
                "The secure connection to the update servers failed, which a wrong clock causes.",
                &[
                    "Set the clock right (Clock & Restart)",
                    "Run Windows Update again",
                ],
            ),
            Self::ServiceDisabled => (
                "A service Windows Update needs is disabled.",
                &[
                    "Set the disabled services back (Windows Update & Services, Tweaks & Policies)",
                    "Run Windows Update again",
                ],
            ),
            Self::Other => ("", &[]),
        }
    }
}

/// The finding for updates whose error code names no more specific cause.
pub const UPDATE_RESET: &str = "wu_update_reset";

fn failed_list(updates: &[&FailedUpdate]) -> String {
    updates
        .iter()
        .map(|u| format!("{} - {} ({} failures)", u.title, u.error_code, u.failures))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One finding per cause, listing the updates behind it.
pub fn failed_update_findings(module_id: &str, failed: &[FailedUpdate]) -> Vec<Issue> {
    let mut causes: Vec<FailureCause> = failed
        .iter()
        .map(|u| FailureCause::of(&u.error_code))
        .collect();
    causes.sort_unstable();
    causes.dedup();
    causes
        .into_iter()
        .map(|cause| {
            let updates: Vec<&FailedUpdate> = failed
                .iter()
                .filter(|u| FailureCause::of(&u.error_code) == cause)
                .collect();
            let title = match updates.as_slice() {
                [one] => format!("'{}' keeps failing to install", one.title),
                many => format!("{} updates keep failing to install", many.len()),
            };
            if cause == FailureCause::Other {
                let mut issue = Issue::new(
                    UPDATE_RESET,
                    module_id,
                    title,
                    "Windows Update & Services",
                    Severity::Warning,
                    RiskScore::Medium,
                    "Windows Update tried again and again and failed each time. Resetting its components makes it start over with a fresh download folder and signature catalog. The update history in Settings is empty afterwards; the installed updates stay.",
                    failed_list(&updates),
                    "Reset Windows Update's components",
                    vec![
                        "Stop wuauserv, bits and cryptsvc".to_string(),
                        r"Rename %SystemRoot%\SoftwareDistribution and %SystemRoot%\System32\catroot2".to_string(),
                        "Start the services again".to_string(),
                    ],
                );
                // The history is gone afterwards: the user's call.
                issue.is_selected = false;
                return issue;
            }
            let (why, steps) = cause.advice();
            Issue::new(
                cause.id(),
                module_id,
                title,
                "Windows Update & Services",
                Severity::Warning,
                RiskScore::Low,
                format!("Windows Update tried again and again and failed each time. {why}"),
                failed_list(&updates),
                steps[0],
                steps.iter().map(|s| s.to_string()).collect(),
            )
            .with_advice_only()
        })
        .collect()
}

impl WindowsUpdatesModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let root = PathBuf::from(root);
        Self {
            config,
            runner,
            download_dir: root.join(r"SoftwareDistribution\Download"),
            component_dirs: [
                root.join("SoftwareDistribution"),
                root.join(r"System32\catroot2"),
            ],
        }
    }

    /// For tests: rename these folders instead of the real ones.
    pub fn with_component_dirs(mut self, dirs: [PathBuf; 2]) -> Self {
        self.component_dirs = dirs;
        self
    }

    /// For tests: empty this folder instead of the real download cache.
    pub fn with_download_dir(mut self, dir: PathBuf) -> Self {
        self.download_dir = dir;
        self
    }

    /// Stop [`CACHE_SERVICES`] and check each one stopped. The guard starts
    /// them again if the caller does not get to; `untouched` says what was
    /// left alone when one does not stop.
    async fn stop_services(&self, untouched: &str) -> Result<StartAgain, String> {
        let guard = StartAgain::new(self.runner.clone(), &CACHE_SERVICES_REVERSED);
        for svc in CACHE_SERVICES {
            let _ = self
                .runner
                .run("net.exe", &["stop", svc], Duration::from_secs(60))
                .await;
            let state = service::state(&*self.runner, svc).await?;
            if state != Some(SERVICE_STOPPED) {
                return Err(format!(
                    "'{svc}' did not stop (state {state:?}), so {untouched}. The services are being started again."
                ));
            }
        }
        Ok(guard)
    }

    /// Start the services again; the ones that did not, with their state.
    async fn start_services(&self, mut guard: StartAgain) -> Result<Vec<String>, String> {
        let mut not_running = Vec::new();
        for svc in CACHE_SERVICES_REVERSED {
            let _ = self
                .runner
                .run("net.exe", &["start", svc], Duration::from_secs(60))
                .await;
            let state = service::state(&*self.runner, svc).await?;
            if !matches!(state, Some(SERVICE_RUNNING | SERVICE_START_PENDING)) {
                not_running.push(format!("{svc} (state {state:?})"));
            }
        }
        guard.disarm();
        Ok(not_running)
    }

    /// Reset Windows Update's components the way Microsoft describes it: stop
    /// the services, rename `SoftwareDistribution` and `catroot2`, start the
    /// services. Windows creates both folders anew. A folder that is not
    /// there is skipped; when the second rename fails, the first is undone.
    async fn reset_components(&self, log_tx: Option<&Sender<String>>) -> Result<String, String> {
        let say = |line: String| async move {
            if let Some(tx) = log_tx {
                let _ = tx.send(line).await;
            }
        };
        say("Stopping the Windows Update services...".to_string()).await;
        let guard = self.stop_services("nothing was renamed").await?;

        let suffix = format!("winmedic-{}", chrono::Local::now().format("%Y%m%d-%H%M%S"));
        let mut renamed: Vec<(PathBuf, PathBuf)> = Vec::new();
        for dir in &self.component_dirs {
            if !dir.exists() {
                continue;
            }
            let mut name = dir.file_name().unwrap_or_default().to_os_string();
            name.push(format!(".{suffix}"));
            let to = dir.with_file_name(name);
            say(format!("Renaming {} to {}...", dir.display(), to.display())).await;
            if let Err(e) = std::fs::rename(dir, &to) {
                let undone = renamed
                    .iter()
                    .rev()
                    .all(|(from, to)| std::fs::rename(to, from).is_ok());
                return Err(format!(
                    "{} could not be renamed ({e}); a service or another program still uses it. {} The services are being started again.",
                    dir.display(),
                    if undone {
                        "Nothing was changed."
                    } else {
                        "The folder renamed before it could not be renamed back either."
                    }
                ));
            }
            renamed.push((dir.clone(), to));
        }

        say("Starting the Windows Update services again...".to_string()).await;
        let not_running = self.start_services(guard).await?;
        let moved = renamed
            .iter()
            .map(|(from, to)| format!("{} -> {}", from.display(), to.display()))
            .collect::<Vec<_>>()
            .join(", ");
        if !not_running.is_empty() {
            return Err(format!(
                "The components were reset ({moved}), but these services did not start again: {}. Restart Windows to start them.",
                not_running.join(", ")
            ));
        }
        Ok(format!(
            "Windows Update's components were reset ({moved}) and its services run. Run Windows Update now; the next scan shows whether the update installs. The update history in Settings starts empty."
        ))
    }

    /// Stop the services, empty the cache and start them again, checking
    /// each step. A service that does not stop leaves the cache alone.
    async fn clean_update_cache(&self, log_tx: Option<&Sender<String>>) -> Result<String, String> {
        let say = |line: &str| {
            let line = line.to_string();
            async move {
                if let Some(tx) = log_tx {
                    let _ = tx.send(line).await;
                }
            }
        };

        say("Stopping the Windows Update services...").await;
        let guard = self.stop_services("the cache was left alone").await?;

        say("Emptying SoftwareDistribution\\Download...").await;
        let dir = self.download_dir.clone();
        let stats = tokio::task::spawn_blocking(move || clean_path_contents(&dir))
            .await
            .map_err(|e| format!("The cache sweep stopped: {e}"))?;

        say("Starting the Windows Update services again...").await;
        let not_running = self.start_services(guard).await?;
        if !not_running.is_empty() {
            return Err(format!(
                "The cache was emptied ({} freed), but these services did not start again: {}. Restart Windows to start them.",
                format_bytes(stats.freed_bytes),
                not_running.join(", ")
            ));
        }
        cleanup_result(
            "Update download cache emptied, services started again",
            stats,
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
        "Checks update caches (SoftwareDistribution/Catroot2), services (BITS, wuauserv), update blockers and updates that keep failing"
    }

    fn icon(&self) -> &'static str {
        "[UPD]"
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
            match service::start_type(&*self.runner, svc).await {
                Ok(Some(SERVICE_DISABLED)) => {
                    issues.push(Issue::new(
                        format!("wu_svc_disabled_{}", svc),
                        self.id(),
                        format!("Service '{}' is disabled", svc_name),
                        "Windows Update & Services",
                        Severity::Critical,
                        RiskScore::Medium,
                        format!("The system service '{}' ({}) is disabled. Without it Windows cannot install security updates.", svc_name, svc),
                        format!("sc qc {}: START_TYPE 4 (DISABLED)", svc),
                        format!("Reset service '{}' to start type 'Manual/Demand'", svc),
                        vec![
                            format!("sc config {} start= demand", svc),
                            format!("net start {}", svc),
                        ],
                    ));
                }
                Ok(Some(_)) => {
                    Self::send_progress(
                        &progress_tx,
                        35,
                        &format!("Service '{}' enabled", svc),
                        Some(&format!(
                            "Service '{}' ({}) is not disabled.",
                            svc_name, svc
                        )),
                    )
                    .await;
                }
                Ok(None) | Err(_) => {
                    Self::send_progress(
                        &progress_tx,
                        35,
                        &format!("Service '{}' not checked", svc),
                        Some(&format!(
                            "sc qc {} reported no start type; the service was not checked.",
                            svc
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
            Some("Checking SoftwareDistribution\\Download..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let soft_dist = self.download_dir.as_path();
        if soft_dist.exists() {
            // Shared walker: recursive (the fix below deletes subdirectories too,
            // so measuring only the top level under-reported what it removes) and
            // rounding to megabytes once at the end. Dividing per file discarded
            // every file below 1 MB, and this cache is mostly small files — the
            // 5000 MB threshold could barely be reached.
            let stats = measure_dirs(vec![soft_dist.to_path_buf()], dir_stats_recursive).await;
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
                )
                .with_reclaimable_bytes(stats.bytes));
            } else {
                Self::send_progress(
                    &progress_tx,
                    75,
                    "Update cache unremarkable",
                    Some(&format!(
                        "SoftwareDistribution cache: {} MB ({} packages).",
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

        let signals = read_reboot_signals();
        match pending_reboot_reason(&signals) {
            Some(evidence) => issues.push(reboot_pending_finding(self.id(), &evidence)),
            None => {
                Self::send_progress(
                    &progress_tx,
                    95,
                    "No pending update reboots",
                    Some(if signals.cbs_pending_entries == Some(0) {
                        "No queued restart work found. The empty CBS RebootPending key is a leftover Windows never removes and does not count."
                    } else {
                        "No queued restart work found."
                    }),
                )
                .await;
            }
        }

        // 4. Updates that keep failing
        Self::send_progress(
            &progress_tx,
            95,
            "Checking for updates that keep failing...",
            Some("Reading Windows Update's install events (19 and 20)..."),
        )
        .await;
        let query = install_events_query();
        let query: Vec<&str> = query.iter().map(String::as_str).collect();
        match read_events(
            self.runner
                .run("wevtutil.exe", &query, Duration::from_secs(15))
                .await,
        ) {
            Ok(events) => {
                let failed = failing_updates(&events);
                if failed.is_empty() {
                    Self::send_progress(
                        &progress_tx,
                        98,
                        "No update keeps failing",
                        Some(&format!(
                            "No update failed twice since the last install in the last {FAILED_UPDATE_DAYS} days (Store apps and Defender signatures not counted)."
                        )),
                    )
                    .await;
                }
                issues.extend(failed_update_findings(self.id(), &failed));
            }
            Err(err) => {
                Self::send_progress(&progress_tx, 98, "Failed updates not checked", Some(&err))
                    .await;
            }
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
            let config = self
                .runner
                .run(
                    "sc.exe",
                    &["config", svc, "start=", "demand"],
                    Duration::from_secs(10),
                )
                .await?;
            if !config.success {
                return Err(format!(
                    "sc config {} failed: {}",
                    svc,
                    config.stdout.trim()
                ));
            }
            // Read back: a group policy can pin a service to disabled, and
            // Windows then accepts the change without keeping it.
            if service::start_type(&*self.runner, svc).await? == Some(SERVICE_DISABLED) {
                return Err(format!(
                    "Windows accepted the change but '{}' is still disabled - a group policy may enforce it",
                    svc
                ));
            }

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
            // Read back, as the cache repair does: net start's own verdict is
            // a translated sentence. The start type is repaired either way, so
            // a service that stays stopped is reported, not failed.
            return Ok(match service::state(&*self.runner, svc).await {
                Ok(Some(SERVICE_RUNNING | SERVICE_START_PENDING)) => {
                    format!("Service '{svc}' was set to start type 'Manual' and started.")
                }
                Ok(state) => format!(
                    "Service '{svc}' was set to start type 'Manual', but it did not start ({}). Windows starts a Manual service when something needs it.",
                    match state {
                        Some(SERVICE_STOPPED) => "it is stopped".to_string(),
                        Some(other) => format!("state {other}"),
                        None => "its state is unknown".to_string(),
                    }
                ),
                Err(e) => format!(
                    "Service '{svc}' was set to start type 'Manual'; whether it started could not be checked: {e}"
                ),
            });
        }

        match issue_id {
            "wu_cache_bloat" => {
                // Clearing the cache requires stopping wuauserv/bits/cryptsvc. Doing
                // that without being allowed to start them again would leave Windows
                // Update broken, so refuse instead of half-applying the fix.
                if !self.config.auto_restart_services {
                    return Err(
                        "Skipped: emptying the update cache requires stopping and restarting wuauserv, bits and cryptsvc. Turn on 'Restart services automatically' in the settings."
                            .to_string(),
                    );
                }
                self.clean_update_cache(log_tx.as_ref()).await
            }
            UPDATE_RESET => {
                if !self.config.auto_restart_services {
                    return Err(
                        "Skipped: the reset requires stopping and restarting wuauserv, bits and cryptsvc. Turn on 'Restart services automatically' in the settings."
                            .to_string(),
                    );
                }
                self.reset_components(log_tx.as_ref()).await
            }
            _ => Err(format!("Unknown issue ID: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    use crate::utils::service::test_support::{sc_qc_output, sc_query_output};

    #[tokio::test]
    async fn test_windows_updates_detects_disabled_service() {
        let mock = MockCommandRunner::new();
        mock.add_response("qc wuauserv", CmdOutput::ok(sc_qc_output("wuauserv", 4)));
        mock.add_response("qc bits", CmdOutput::ok(sc_qc_output("bits", 2)));
        mock.add_response("qc cryptsvc", CmdOutput::ok(sc_qc_output("cryptsvc", 2)));

        let module = WindowsUpdatesModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        let disabled_wu = issues.iter().find(|i| i.id == "wu_svc_disabled_wuauserv");
        assert!(disabled_wu.is_some());
        assert_eq!(disabled_wu.unwrap().severity, Severity::Critical);
        assert!(!issues.iter().any(|i| i.id == "wu_svc_disabled_bits"));
    }

    /// A disabled service set back to Manual: what `sc query` says after
    /// `net start` decides whether the message may say it started.
    fn disabled_service_repair(state_after_start: u32) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "config wuauserv",
            CmdOutput::ok("[SC] ChangeServiceConfig ERFOLG"),
        );
        mock.add_response("qc wuauserv", CmdOutput::ok(sc_qc_output("wuauserv", 3)));
        mock.add_response("net.exe start wuauserv", CmdOutput::ok(""));
        mock.add_response(
            "query wuauserv",
            CmdOutput::ok(sc_query_output("wuauserv", state_after_start)),
        );
        mock
    }

    #[tokio::test]
    async fn a_service_set_back_to_manual_is_called_started_only_when_it_runs() {
        let module = WindowsUpdatesModule::with_runner(
            ModuleConfig::default(),
            Arc::new(disabled_service_repair(SERVICE_RUNNING)),
        );
        let msg = module.fix("wu_svc_disabled_wuauserv", None).await.unwrap();
        assert!(msg.ends_with("and started."), "{msg}");

        let module = WindowsUpdatesModule::with_runner(
            ModuleConfig::default(),
            Arc::new(disabled_service_repair(SERVICE_STOPPED)),
        );
        let msg = module.fix("wu_svc_disabled_wuauserv", None).await.unwrap();
        assert!(msg.contains("did not start (it is stopped)"), "{msg}");
        assert!(!msg.contains("and started"), "{msg}");
    }

    #[tokio::test]
    async fn a_service_disable_that_windows_does_not_keep_is_a_failed_repair() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "config wuauserv",
            CmdOutput::ok("[SC] ChangeServiceConfig ERFOLG"),
        );
        // Read back after the change: still 4, as a group policy would keep it.
        mock.add_response("qc wuauserv", CmdOutput::ok(sc_qc_output("wuauserv", 4)));

        let module = WindowsUpdatesModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let err = module
            .fix("wu_svc_disabled_wuauserv", None)
            .await
            .unwrap_err();
        assert!(err.contains("still disabled"), "{err}");
    }

    /// The false positive this detection was rewritten for. Windows leaves the
    /// CBS `RebootPending` key behind after the very restart that emptied it,
    /// so testing for the key's existence reports a pending reboot that no
    /// reboot can ever clear: the user restarts, scans again, and WinMedic says
    /// the same thing.
    #[test]
    fn an_empty_cbs_reboot_pending_key_is_not_a_pending_reboot() {
        let signals = RebootSignals {
            cbs_pending_entries: Some(0),
            ..Default::default()
        };
        assert_eq!(pending_reboot_reason(&signals), None);
    }

    #[test]
    fn a_cbs_key_still_holding_work_is_a_pending_reboot() {
        let signals = RebootSignals {
            cbs_pending_entries: Some(2),
            ..Default::default()
        };
        let reason = pending_reboot_reason(&signals).expect("2 queued entries are evidence");
        assert!(reason.contains("2 queued entries"), "{}", reason);
    }

    #[test]
    fn windows_update_and_queued_renames_are_both_reported() {
        let signals = RebootSignals {
            cbs_pending_entries: None,
            wu_reboot_required: true,
            pending_file_renames: 1,
        };
        let reason = pending_reboot_reason(&signals).expect("either signal is enough on its own");
        assert!(reason.contains("RebootRequired"), "{}", reason);
        assert!(reason.contains("1 entry"), "{}", reason);
    }

    #[test]
    fn a_machine_with_nothing_queued_reports_nothing() {
        assert_eq!(pending_reboot_reason(&RebootSignals::default()), None);
    }

    /// Windows' own pending restart is advice: nothing to tick, no steps to
    /// run, only what to do.
    #[test]
    fn a_pending_restart_is_advice() {
        let issue = reboot_pending_finding("windows_updates", "evidence");
        assert!(issue.advice_only && !issue.is_selected && !issue.will_repair());
        assert!(issue.fix_steps.is_empty());
        assert!(issue.recommended_fix.starts_with("Restart Windows"));
    }

    /// A repair run neither runs it nor counts it.
    #[tokio::test]
    async fn a_repair_run_does_not_count_the_pending_restart() {
        use crate::engine::runner::{DiagnosticEngine, RepairEvent, RepairOptions};

        let module = WindowsUpdatesModule::with_runner(
            ModuleConfig::default(),
            Arc::new(MockCommandRunner::new()),
        );
        let engine = DiagnosticEngine::with_modules(vec![Arc::new(module)]);
        let mut issues = vec![reboot_pending_finding("windows_updates", "evidence")];
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let options = RepairOptions {
            create_vss: false,
            dry_run: false,
            verbose_logging: false,
        };

        let counted = engine
            .run_repairs(
                &mut issues,
                options,
                tx,
                tokio_util::sync::CancellationToken::new(),
            )
            .await;

        assert_eq!(counted, (0, 0));
        assert!(!issues[0].is_fixed && !issues[0].is_reboot_pending);
        while let Ok(event) = rx.try_recv() {
            assert!(
                !matches!(event, RepairEvent::FixStarted { .. }),
                "{event:?}"
            );
        }
    }

    /// Reading the live registry must work on any machine and say something
    /// consistent; which signals it finds is the machine's business.
    #[test]
    fn reading_the_registry_agrees_with_the_verdict() {
        let signals = read_reboot_signals();
        let expected = signals.cbs_pending_entries.is_some_and(|n| n > 0)
            || signals.wu_reboot_required
            || signals.pending_file_renames > 0;
        assert_eq!(pending_reboot_reason(&signals).is_some(), expected);
    }

    /// A download cache in a temp folder with one 200 KB file.
    struct Cache(PathBuf);

    impl Cache {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("winmedic_wu_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("sub")).unwrap();
            std::fs::write(dir.join("sub").join("update.cab"), vec![0u8; 200 * 1024]).unwrap();
            Self(dir)
        }
    }

    impl Drop for Cache {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `sc query` answers `before` for every service until a `net start`
    /// ran, then `after`.
    fn services(before: u32, after: u32) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("net.exe", CmdOutput::ok(""));
        for svc in CACHE_SERVICES {
            mock.add_response(
                format!("query {svc}"),
                CmdOutput::ok(sc_query_output(svc, before)),
            );
            mock.add_response_after(
                "net.exe start",
                format!("query {svc}"),
                CmdOutput::ok(sc_query_output(svc, after)),
            );
        }
        mock
    }

    fn module(mock: &MockCommandRunner, cache: &Cache) -> WindowsUpdatesModule {
        WindowsUpdatesModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()))
            .with_download_dir(cache.0.clone())
    }

    #[tokio::test]
    async fn the_cache_is_emptied_between_a_checked_stop_and_start() {
        let cache = Cache::new("clean");
        let mock = services(SERVICE_STOPPED, SERVICE_RUNNING);
        let msg = module(&mock, &cache)
            .fix("wu_cache_bloat", None)
            .await
            .unwrap();
        assert!(msg.contains("200.0 KB freed"), "{msg}");
        assert_eq!(std::fs::read_dir(&cache.0).unwrap().count(), 0);
        let starts = mock
            .executed()
            .iter()
            .filter(|c| c.starts_with("net.exe start"))
            .count();
        assert_eq!(starts, 3);
    }

    #[tokio::test]
    async fn a_service_that_does_not_stop_leaves_the_cache_and_is_started_again() {
        let cache = Cache::new("no_stop");
        let mock = services(SERVICE_RUNNING, SERVICE_RUNNING);
        let err = module(&mock, &cache)
            .fix("wu_cache_bloat", None)
            .await
            .unwrap_err();
        assert!(err.contains("'wuauserv' did not stop"), "{err}");
        assert!(cache.0.join("sub").join("update.cab").exists());
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let started: Vec<String> = mock
            .executed()
            .into_iter()
            .filter(|c| c.starts_with("net.exe start"))
            .collect();
        assert_eq!(
            started,
            [
                "net.exe start cryptsvc",
                "net.exe start bits",
                "net.exe start wuauserv"
            ]
        );
    }

    // Captured on a German Windows 11; see tests/fixtures/README.md.
    const FAILED_STORE: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_wu_failed_20_store.bin");
    const INSTALLED: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_wu_installed_19_de.bin");

    /// Windows Update's own service, next to the Store's.
    const WU_SERVICE: &str = "{9482f4b4-e343-43b6-b170-9a65bc822c77}";

    fn text(bytes: &[u8]) -> String {
        crate::utils::decode::decode_output_in(bytes, crate::utils::decode::CodePage::Ansi)
    }

    /// The four captured failures as Windows Update failing one update: its
    /// service instead of the Store's, one `updateGuid`, the newest failure
    /// with `newest_code`.
    fn one_update_failing(newest_code: &str) -> String {
        let mut xml = text(FAILED_STORE).replace(STORE_SERVICE, WU_SERVICE);
        for guid in [
            "{8d2eb37a-ec42-47cd-bd49-0df3df4bbe34}",
            "{01e84f1c-8841-476e-8113-879c8e7a2ca7}",
            "{5ef639d5-48dd-4a53-86a6-c73766c99346}",
        ] {
            xml = xml.replace(guid, "{a71d945c-a477-45f6-8f5d-3b4daab59c9d}");
        }
        xml.replacen("0x80073d02", newest_code, 1)
    }

    fn parse(xml: &str) -> Vec<EventRecord> {
        crate::utils::event_xml::parse_events(xml)
    }

    #[test]
    fn store_apps_failing_are_not_counted() {
        // The capture machine: three Store apps failed with 0x80073d02.
        assert_eq!(parse(&text(FAILED_STORE)).len(), 4);
        assert!(failing_updates(&parse(&text(FAILED_STORE))).is_empty());
    }

    #[test]
    fn an_update_that_fails_again_and_again_is_found() {
        let failed = failing_updates(&parse(&one_update_failing("0x800f081f")));
        assert_eq!(
            failed,
            [FailedUpdate {
                title: "9MWPM2CQNLHN-Microsoft.GamingServices".to_string(),
                error_code: "0x800f081f".to_string(),
                failures: 4,
            }]
        );
        // July's installs came before, so they change nothing.
        let mut events = parse(&text(INSTALLED));
        events.extend(parse(&one_update_failing("0x800f081f")));
        assert_eq!(failing_updates(&events).len(), 1);
    }

    #[test]
    fn an_install_after_the_failures_clears_them() {
        // The Visual C++ update, the one install in the capture that counts.
        let later = text(INSTALLED).replacen(
            "2026-07-26T16:06:15.2191749Z",
            "2026-09-01T10:00:00.0000000Z",
            1,
        );
        let mut events = parse(&one_update_failing("0x800f081f"));
        events.extend(parse(&later));
        assert!(failing_updates(&events).is_empty());
    }

    #[test]
    fn one_failure_is_not_enough() {
        let xml = one_update_failing("0x800f081f");
        let first = &xml[..xml.find("</Event>").unwrap() + "</Event>".len()];
        assert!(failing_updates(&parse(first)).is_empty());
    }

    #[test]
    fn the_error_code_names_the_repair() {
        assert_eq!(FailureCause::of("0x800F081F"), FailureCause::ComponentStore);
        assert_eq!(FailureCause::of("0x80070070"), FailureCause::DiskFull);
        assert_eq!(FailureCause::of("0x8024402c"), FailureCause::Connection);
        assert_eq!(FailureCause::of("0x80072f8f"), FailureCause::Clock);
        assert_eq!(
            FailureCause::of("0x80070422"),
            FailureCause::ServiceDisabled
        );
        assert_eq!(FailureCause::of("0x80073d02"), FailureCause::Other);

        let failed = failing_updates(&parse(&one_update_failing("0x800f081f")));
        let issues = failed_update_findings("windows_updates", &failed);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "wu_failed_component_store");
        assert!(issues[0].advice_only);
        assert!(issues[0].fix_steps[0].contains("RestoreHealth"));
        assert!(
            issues[0]
                .technical_details
                .contains("0x800f081f (4 failures)")
        );
    }

    #[test]
    fn an_unknown_code_offers_the_reset_unticked() {
        let failed = failing_updates(&parse(&one_update_failing("0x80246007")));
        let issues = failed_update_findings("windows_updates", &failed);
        assert_eq!(issues[0].id, UPDATE_RESET);
        assert!(issues[0].is_repairable());
        assert!(!issues[0].is_selected, "the update history is lost");
        assert_eq!(issues[0].risk_score, RiskScore::Medium);
    }

    #[tokio::test]
    async fn the_scan_reads_the_install_events() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "wevtutil.exe",
            CmdOutput::ok(one_update_failing("0x80246007")),
        );
        mock.add_response("sc.exe", CmdOutput::ok(sc_qc_output("x", 3)));
        let issues =
            WindowsUpdatesModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()))
                .with_download_dir(std::env::temp_dir().join("winmedic_wu_no_such_cache"))
                .scan(None)
                .await
                .unwrap();
        assert!(issues.iter().any(|i| i.id == UPDATE_RESET), "{issues:?}");
        let query = mock
            .executed()
            .into_iter()
            .find(|c| c.starts_with("wevtutil.exe"))
            .unwrap();
        assert!(
            query.contains("(EventID=19 or EventID=20)")
                && query.contains("timediff(@SystemTime) <= 2592000000"),
            "{query}"
        );
    }

    /// `SoftwareDistribution` and `catroot2` in a temp folder.
    fn component_dirs(cache: &Cache) -> [PathBuf; 2] {
        let dirs = [
            cache.0.join("SoftwareDistribution"),
            cache.0.join("catroot2"),
        ];
        for dir in &dirs {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("DataStore.edb"), b"x").unwrap();
        }
        dirs
    }

    #[tokio::test]
    async fn the_reset_renames_both_folders_between_a_checked_stop_and_start() {
        let cache = Cache::new("reset");
        let dirs = component_dirs(&cache);
        let mock = services(SERVICE_STOPPED, SERVICE_RUNNING);
        let msg = module(&mock, &cache)
            .with_component_dirs(dirs.clone())
            .fix(UPDATE_RESET, None)
            .await
            .unwrap();
        assert!(msg.contains("components were reset"), "{msg}");
        for dir in &dirs {
            assert!(!dir.exists(), "{} was renamed", dir.display());
        }
        let renamed: Vec<String> = std::fs::read_dir(&cache.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".winmedic-"))
            .collect();
        assert_eq!(renamed.len(), 2, "{renamed:?}");
    }

    #[tokio::test]
    async fn a_service_that_does_not_stop_leaves_the_folders() {
        let cache = Cache::new("reset_no_stop");
        let dirs = component_dirs(&cache);
        let mock = services(SERVICE_RUNNING, SERVICE_RUNNING);
        let err = module(&mock, &cache)
            .with_component_dirs(dirs.clone())
            .fix(UPDATE_RESET, None)
            .await
            .unwrap_err();
        assert!(err.contains("nothing was renamed"), "{err}");
        assert!(dirs.iter().all(|d| d.exists()));
    }

    #[tokio::test]
    async fn services_that_do_not_come_back_are_a_failure() {
        let cache = Cache::new("no_start");
        let mock = services(SERVICE_STOPPED, SERVICE_STOPPED);
        let err = module(&mock, &cache)
            .fix("wu_cache_bloat", None)
            .await
            .unwrap_err();
        assert!(err.contains("did not start again: cryptsvc"), "{err}");
    }
}
