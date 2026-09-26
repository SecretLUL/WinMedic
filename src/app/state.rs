//! The [`App`] struct itself: construction, log buffers and report
//! export. Behaviour that belongs to a specific feature lives in the sibling
//! modules listed in [`crate::app`].

use super::{BackgroundEvent, ScanState, TAB_COUNT, TAB_HOME, TAB_SETTINGS, push_bounded_log};
use crate::config::AppConfig;
use crate::engine::issue::{Issue, Severity};
use crate::engine::reporter::DiagnosticReporter;
use crate::engine::runner::{DiagnosticEngine, RepairEvent, ScanEvent};
use crate::modules::ModuleStatus;
use crate::modules::windows_updates::REBOOT_PENDING;
use crate::safety::audit::{AuditEntry, AuditLogger};
use crate::safety::reg_backup::{BackupRecord, RegBackupManager};
use crate::utils::admin::is_admin;
use crate::utils::cmd::SystemCommandRunner;
use crate::utils::updater::{self, UpdateInfo};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

use super::confirm::{ConfirmRequest, SystemActions};

/// One module's dashboard row: id, name, icon and status.
type ModuleStatusRow = (String, String, String, ModuleStatus);

/// One diagnostic module's live state during a scan.
///
/// The engine runs every module in parallel, so "what is happening right now"
/// is a question with seven simultaneous answers. The scanner used to keep one
/// shared step line for all of them, which meant it showed whichever module
/// reported last — and a module sitting on a slow DISM call reported nothing at
/// all, so it silently lost the line to its faster neighbours and looked wedged
/// at 10%. Every module now carries its own answer.
#[derive(Debug, Clone)]
pub struct ModuleScanProgress {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub percent: u8,
    /// Set once the module has finished, successfully or not.
    pub is_done: bool,
    /// Why the module failed, when it did.
    pub failure: Option<String>,
    /// What the module last reported it was doing.
    pub step: String,
    /// When [`Self::step`] last *changed*. A step that takes two minutes has
    /// nothing else to show for itself, so how long it has been running is the
    /// difference between "working" and "hung".
    pub step_since: Option<Instant>,
}

impl ModuleScanProgress {
    pub(super) fn new(id: String, name: String, icon: String) -> Self {
        Self {
            id,
            name,
            icon,
            percent: 0,
            is_done: false,
            failure: None,
            step: String::new(),
            step_since: None,
        }
    }

    /// Record what the module is doing now, restamping the clock only when the
    /// step actually changed — a module repeating itself has not made progress,
    /// and resetting the timer for it would hide exactly the stall worth seeing.
    pub(super) fn set_step(&mut self, step: &str) {
        if self.step != step {
            self.step = step.to_string();
            self.step_since = Some(Instant::now());
        }
    }

    pub(super) fn reset(&mut self) {
        self.percent = 0;
        self.is_done = false;
        self.failure = None;
        self.step = String::new();
        self.step_since = None;
    }

    /// How long the current step has been running, while it still is.
    pub fn step_elapsed(&self) -> Option<Duration> {
        if self.is_done {
            return None;
        }
        self.step_since.map(|since| since.elapsed())
    }
}

/// Which of the two lists on the Settings tab currently owns `↑`/`↓`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SafetyFocus {
    /// The configuration list. What the tab opens on.
    #[default]
    Settings,
    /// The registry backup list, so `↑`/`↓` picks the target of `[U]`.
    Backups,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingInput {
    pub setting_index: usize,
    pub setting_name: String,
    pub unit: String,
    pub min_value: u64,
    pub max_value: u64,
    pub buffer: String,
    pub error_msg: Option<String>,
}

pub struct App {
    pub active_tab: usize,
    pub is_admin: bool,
    pub config: AppConfig,

    // Diagnostic & Engine
    pub engine: Arc<DiagnosticEngine>,
    pub issues: Vec<Issue>,
    pub selected_issue_index: usize,
    pub health_score: u8,

    // Issue Filtering & Search
    pub severity_filter: Option<Severity>,
    pub module_filter: Option<String>,
    pub search_query: String,
    /// A one-shot request from the `/` binding: put the caret in the triage
    /// search box.
    ///
    /// The terminal front end had to capture every keystroke itself and append
    /// it to [`Self::search_query`]. A window has a real text field bound to
    /// that same string, so the only thing `/` still has to do is say where the
    /// keyboard should go. The front end clears the flag as it honours it.
    pub focus_search: bool,
    pub selected_filtered_index: usize,

    // Live Scanner State
    pub is_scanning: bool,
    pub scan_overall_progress: u8,
    /// When the running scan started. Cleared once it ends, so the readout
    /// stops rather than counting up forever under "DIAGNOSTICS COMPLETE".
    pub scan_started_at: Option<Instant>,
    /// How long the last completed scan took.
    pub scan_duration: Option<Duration>,
    /// Exact timestamp when the last scan was performed.
    pub last_scan_timestamp: Option<String>,
    pub module_progress_list: Vec<ModuleScanProgress>,
    pub module_statuses: Vec<(String, String, String, ModuleStatus)>,
    pub scan_log_messages: VecDeque<String>,

    // Live Repair State
    pub is_fixing: bool,
    /// Simulate repairs instead of executing them.
    pub dry_run: bool,
    pub current_fix_title: String,
    /// When the running step of the repair run began: the restore point,
    /// then each repair. DISM runs for many minutes with nothing else to show,
    /// so how long it has been at it is what tells working from hung.
    pub repair_step_since: Option<Instant>,
    /// How far the running step's tool says it got, when it says.
    pub repair_step_percent: Option<f32>,
    pub fixed_count: usize,
    pub failed_count: usize,
    pub total_to_fix: usize,
    pub vss_status: String,
    pub repair_console_lines: VecDeque<String>,

    // Safety: audit log, registry backups, VSS restore points
    pub audit_logger: AuditLogger,
    pub reg_backup_mgr: RegBackupManager,
    pub audit_entries: Vec<AuditEntry>,
    pub backup_records: Vec<BackupRecord>,
    pub vss_restore_points: Vec<String>,
    pub selected_backup_index: usize,
    pub restore_points_loading: bool,
    pub(super) restore_points_requested: bool,
    pub is_restoring: bool,

    // Settings
    pub selected_setting_index: usize,
    pub setting_input: Option<SettingInput>,
    /// Which list on the Settings tab the arrow keys drive.
    pub safety_focus: SafetyFocus,

    // UI state
    pub status_message: Option<String>,
    pub show_help: bool,
    pub pending_confirm: Option<ConfirmRequest>,
    pub available_update: Option<UpdateInfo>,
    /// True from the moment the user accepts an update until the download has
    /// either been installed or given up on.
    pub is_updating: bool,
    /// The installed update to restart into, once no scan, repair or restore
    /// is running.
    pub restart_into: Option<std::path::PathBuf>,
    /// What this app is allowed to do to the machine it runs on: browser
    /// windows, UAC prompts, restore points.
    ///
    /// Inert unless the caller opts in through
    /// [`App::enable_real_system_actions`], which only the desktop front end
    /// does — see [`SystemActions`].
    pub system_actions: SystemActions,
    pub should_quit: bool,

    // Internal async event channels
    pub scan_event_rx: Option<Receiver<ScanEvent>>,
    pub repair_event_rx: Option<Receiver<RepairEvent>>,
    /// Cancels whichever scan or repair run is currently active.
    pub(super) cancel_token: Option<CancellationToken>,
    pub(super) bg_tx: UnboundedSender<BackgroundEvent>,
    pub(super) bg_rx: UnboundedReceiver<BackgroundEvent>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let admin_flag = is_admin();
        let (config, config_status) = AppConfig::load_reporting();
        let system_actions = SystemActions::default();
        let audit_logger = AuditLogger::inert();
        let engine = Arc::new(
            DiagnosticEngine::new(&config)
                .with_restore_points(system_actions.restore_point)
                .with_audit_log(audit_logger.clone()),
        );
        let reg_backup_mgr = RegBackupManager::new();
        let audit_entries = audit_logger.get_history();
        let backup_records = reg_backup_mgr.list_backups();
        let (bg_tx, bg_rx) = tokio::sync::mpsc::unbounded_channel();

        let (module_progress_list, default_module_statuses) = Self::module_lists(&engine);
        let (
            saved_issues,
            saved_health,
            module_statuses,
            saved_duration,
            saved_timestamp,
            init_msg,
        ) = if let Some(mut saved) = ScanState::load() {
            let current_boot = sysinfo::System::boot_time();
            let rebooted = saved.boot_time_secs.is_some_and(|b| current_boot > b);
            if rebooted {
                settle_after_restart(&mut saved.issues);
            }
            let health = DiagnosticEngine::calculate_health_score(&saved.issues);
            let open_count = saved.issues.iter().filter(|i| !i.is_fixed).count();
            let msg = format!(
                "WinMedic initialised. Loaded previous scan from {} ({} open issues, health: {}/100).",
                saved.timestamp, open_count, health
            );

            let reconciled_statuses =
                Self::reconcile_module_statuses(&default_module_statuses, &saved.module_statuses);

            (
                saved.issues,
                health,
                reconciled_statuses,
                saved.scan_duration_secs.map(Duration::from_secs),
                Some(saved.timestamp),
                msg,
            )
        } else {
            (
                Vec::new(),
                100,
                default_module_statuses,
                None,
                None,
                "WinMedic initialised. Ready to diagnose.".to_string(),
            )
        };

        Self {
            active_tab: TAB_HOME,
            is_admin: admin_flag,
            config,
            engine,
            issues: saved_issues,
            selected_issue_index: 0,
            health_score: saved_health,
            severity_filter: None,
            module_filter: None,
            search_query: String::new(),
            focus_search: false,
            selected_filtered_index: 0,
            is_scanning: false,
            scan_overall_progress: 0,
            scan_started_at: None,
            scan_duration: saved_duration,
            last_scan_timestamp: saved_timestamp,
            module_progress_list,
            module_statuses,
            scan_log_messages: VecDeque::from([init_msg]),
            is_fixing: false,
            dry_run: false,
            current_fix_title: String::new(),
            repair_step_since: None,
            repair_step_percent: None,
            fixed_count: 0,
            failed_count: 0,
            total_to_fix: 0,
            vss_status: "Ready".to_string(),
            repair_console_lines: VecDeque::from([String::from("Repair centre ready.")]),
            audit_logger,
            reg_backup_mgr,
            audit_entries,
            backup_records,
            vss_restore_points: Vec::new(),
            selected_backup_index: 0,
            restore_points_loading: false,
            restore_points_requested: false,
            is_restoring: false,
            selected_setting_index: 0,
            setting_input: None,
            safety_focus: SafetyFocus::default(),
            // A corrupt config file is the one startup condition worth
            // interrupting the user's first glance for: their saved settings
            // are not in effect and the defaults silently re-enable things
            // they may have deliberately switched off.
            status_message: Some(
                config_status
                    .warning()
                    .unwrap_or_else(|| "Ready".to_string()),
            ),
            show_help: false,
            pending_confirm: if !admin_flag {
                Some(ConfirmRequest::Elevate)
            } else {
                None
            },
            available_update: None,
            is_updating: false,
            restart_into: None,
            system_actions,
            should_quit: false,
            scan_event_rx: None,
            repair_event_rx: None,
            cancel_token: None,
            bg_tx,
            bg_rx,
        }
    }

    /// Hand this app the real machine.
    ///
    /// [`App::new`] builds an app that cannot touch it: confirming a dialog
    /// opens no browser and raises no UAC prompt, a repair run asks Windows
    /// for no restore point, and nothing is written to the audit log. That
    /// default is what keeps `cargo test` — which builds dozens of `App`s —
    /// off the developer's own desktop. The desktop front end is the one
    /// caller that wants the real thing, so it is the one caller that opts in.
    ///
    /// The engine is rebuilt because it reads
    /// [`SystemActions::restore_point`] and the audit log at construction
    /// time.
    pub fn enable_real_system_actions(&mut self) {
        self.system_actions = SystemActions::real();
        self.audit_logger = AuditLogger::real();
        self.rebuild_engine();
    }

    /// Rebuild the engine from the current config, system actions and audit
    /// log.
    pub(super) fn rebuild_engine(&mut self) {
        self.engine = Arc::new(
            DiagnosticEngine::new(&self.config)
                .with_restore_points(self.system_actions.restore_point)
                .with_audit_log(self.audit_logger.clone()),
        );
    }

    /// Kick off the background GitHub release check.
    ///
    /// Deliberately *not* part of [`App::new`]: constructing an `App` must stay
    /// free of network I/O so the test suite — which builds dozens of them
    /// inside `#[tokio::test]` — never reaches out to api.github.com. The
    /// desktop front end calls this once, right after construction.
    pub fn start_update_check(&mut self) {
        if !self.config.check_for_updates {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let tx = self.bg_tx.clone();
        handle.spawn(async move {
            let runner = SystemCommandRunner::new();
            let update_info = updater::check_for_update(
                &runner,
                env!("CARGO_PKG_VERSION"),
                Duration::from_secs(5),
            )
            .await;
            let _ = tx.send(BackgroundEvent::UpdateChecked(update_info));
        });
    }

    /// Repair the scheduled task and the Run entry for the settings that are on.
    ///
    /// Like [`App::start_update_check`], not part of [`App::new`]: the desktop
    /// front end calls it once, after handing the app the real machine.
    pub fn reconcile_background_integration(&mut self) {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        if let Err(e) = (self.system_actions.reconcile_background)(&self.config, &exe) {
            let problem = format!("Background scan / autostart could not be repaired: {e}");
            self.status_message = Some(match self.status_message.take() {
                Some(existing) if existing != "Ready" => format!("{existing} {problem}"),
                _ => problem,
            });
        }
    }

    /// Whether any repaired issue currently requires a system restart.
    pub fn has_pending_reboot(&self) -> bool {
        self.issues.iter().any(|i| i.is_reboot_pending)
    }

    /// Whether Windows waits for a restart: a repair needs one, or the scan
    /// found restart work Windows queued itself.
    pub fn restart_pending(&self) -> bool {
        self.issues.iter().any(waits_for_restart)
    }

    /// Open the restart confirmation dialog if there are issues pending a reboot.
    pub fn show_reboot_notice(&mut self) {
        if self.pending_confirm.is_some() || self.is_fixing || self.is_scanning {
            return;
        }
        let reboot_issues: Vec<String> = self
            .issues
            .iter()
            .filter(|i| waits_for_restart(i))
            .map(|i| i.title.clone())
            .collect();
        if !reboot_issues.is_empty() {
            self.pending_confirm = Some(ConfirmRequest::RestartRequired {
                issues: reboot_issues,
            });
        }
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn module_lists(
        engine: &DiagnosticEngine,
    ) -> (
        Vec<ModuleScanProgress>,
        Vec<(String, String, String, ModuleStatus)>,
    ) {
        let mut progress = Vec::new();
        let mut statuses = Vec::new();
        for m in engine.modules() {
            progress.push(ModuleScanProgress::new(
                m.id().to_string(),
                m.name().to_string(),
                m.icon().to_string(),
            ));
            statuses.push((
                m.id().to_string(),
                m.name().to_string(),
                m.icon().to_string(),
                ModuleStatus::Idle,
            ));
        }
        (progress, statuses)
    }

    /// Saved module statuses laid over the current engine's module list, so a
    /// module added since the save still appears.
    fn reconcile_module_statuses(
        defaults: &[ModuleStatusRow],
        saved: &[ModuleStatusRow],
    ) -> Vec<ModuleStatusRow> {
        defaults
            .iter()
            .map(|(id, name, icon, default)| {
                let status = saved
                    .iter()
                    .find(|(saved_id, ..)| saved_id == id)
                    .map_or(default, |(.., status)| status);
                (id.clone(), name.clone(), icon.clone(), status.clone())
            })
            .collect()
    }

    /// How long the scan has been running, or how long the last one took.
    pub fn scan_elapsed(&self) -> Option<Duration> {
        match self.scan_started_at {
            Some(start) => Some(start.elapsed()),
            None => self.scan_duration,
        }
    }

    /// How long the running repair step has been at it.
    pub fn repair_step_elapsed(&self) -> Option<Duration> {
        self.repair_step_since
            .filter(|_| self.is_fixing)
            .map(|since| since.elapsed())
    }

    /// About how long the running repair step still needs: the time it took
    /// to get as far as its tool says, stretched to the rest of the way.
    /// `None` while the tool has said nothing, or too little to go on.
    pub fn repair_step_remaining(&self) -> Option<Duration> {
        time_left(self.repair_step_elapsed()?, self.repair_step_percent?)
    }

    /// How much of the repair run is done, counting the part of the running
    /// step its tool reports. The bar moves while DISM works instead of
    /// standing still for ten minutes.
    pub fn repair_fraction(&self) -> f32 {
        let done = (self.fixed_count + self.failed_count) as f32;
        let step = self.repair_step_percent.unwrap_or(0.0) / 100.0;
        ((done + step) / self.total_to_fix.max(1) as f32).clamp(0.0, 1.0)
    }

    /// True while a scan or a repair run is in flight.
    pub fn is_busy(&self) -> bool {
        self.is_scanning || self.is_fixing
    }

    /// Advance to the next tab in cyclic order (BIOS-style right navigation).
    pub fn next_tab(&mut self) {
        self.active_tab = (self.active_tab + 1) % TAB_COUNT;
        self.on_tab_entered();
    }

    /// Go back to the previous tab in cyclic order (BIOS-style left navigation).
    pub fn prev_tab(&mut self) {
        self.active_tab = if self.active_tab == 0 {
            TAB_COUNT - 1
        } else {
            self.active_tab - 1
        };
        self.on_tab_entered();
    }

    /// Jump straight to a tab, as the number keys do.
    ///
    /// Out-of-range indices are ignored rather than clamped: silently landing on
    /// a neighbouring tab would be a worse answer than not moving at all.
    pub fn goto_tab(&mut self, index: usize) {
        if index >= TAB_COUNT {
            return;
        }
        self.active_tab = index;
        self.on_tab_entered();
    }

    /// Per-tab work that has to happen however the tab was reached.
    ///
    /// Only the Settings tab needs it: its audit log and backup list
    /// are read off disk, and both go stale the moment a repair run writes to
    /// them. Routing every entry point through here is what stops `[Tab]` and
    /// `→` from showing a different list than `[5]` does.
    fn on_tab_entered(&mut self) {
        if self.active_tab == TAB_SETTINGS {
            self.load_safety_data();
        }
    }

    // ------------------------------------------------------------ log buffers

    pub fn push_scan_log(&mut self, msg: impl Into<String>) {
        push_bounded_log(&mut self.scan_log_messages, msg);
    }

    pub fn push_repair_log(&mut self, line: impl Into<String>) {
        push_bounded_log(&mut self.repair_console_lines, line);
    }

    /// Export the current scan/repair report as an HTML file in the reports directory.
    pub fn export_report(&mut self) -> Result<std::path::PathBuf, String> {
        let base = dirs::data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        let report_dir = base.join("WinMedic").join("reports");
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("winmedic_report_{}.html", timestamp);
        let path = report_dir.join(filename);

        let health = DiagnosticEngine::calculate_health_score(&self.issues);
        self.audit_entries = self.audit_logger.get_history();

        DiagnosticReporter::save_report(&path, &self.issues, health, &self.audit_entries)
            .map(|_| path)
            .map_err(|e| format!("Export failed: {}", e))
    }

    /// Persist the latest scan results, health score, and module statuses to disk.
    pub fn save_scan_state(&self) {
        // Guarded by the same seam as the browser and the UAC prompt: an `App`
        // that was never handed the real machine does not write to it.
        if !self.system_actions.persist_scan_state {
            return;
        }
        // Stamped with the scan's time, not the save's. A tick in triage is not
        // a new scan, and [`Self::poll_external_scan_updates`] tells a scan from
        // another process apart by exactly this timestamp. Nothing scanned,
        // nothing to save — and nothing to overwrite a helper's results with.
        let Some(timestamp) = self.last_scan_timestamp.clone() else {
            return;
        };
        let mut state = ScanState::new(
            self.health_score,
            self.issues.clone(),
            self.module_statuses.clone(),
            self.scan_duration.map(|d| d.as_secs()),
        );
        state.timestamp = timestamp;
        let _ = state.save();
    }

    /// Check if an external background scan (e.g. from WinMedicHelper) saved newer results.
    pub fn poll_external_scan_updates(&mut self) {
        if self.is_busy() || !self.system_actions.persist_scan_state {
            return;
        }
        let Some(mut saved) = ScanState::load() else {
            return;
        };
        if self.last_scan_timestamp.as_deref() == Some(saved.timestamp.as_str()) {
            return;
        }

        // A fresh scan knows nothing of the decisions made against the last
        // one: which findings the user unticked, which repairs wait on a
        // restart, which failed and why. Carry them over for findings that are
        // still reported, or the next [F] repairs what was deliberately left
        // out. No reboot can have happened in between — it would have ended
        // this process — so a pending restart is still pending.
        for issue in &mut saved.issues {
            let Some(known) = self.issues.iter().find(|i| i.id == issue.id) else {
                continue;
            };
            if known.is_reboot_pending {
                issue.is_reboot_pending = true;
                issue.is_selected = false;
            } else {
                issue.is_selected = known.is_selected && !issue.advice_only;
            }
            if issue.fix_error.is_none() {
                issue.fix_error = known.fix_error.clone();
            }
        }

        let (_, default_statuses) = Self::module_lists(&self.engine);
        self.module_statuses =
            Self::reconcile_module_statuses(&default_statuses, &saved.module_statuses);
        self.health_score = DiagnosticEngine::calculate_health_score(&saved.issues);
        self.issues = saved.issues;
        self.scan_duration = saved.scan_duration_secs.map(Duration::from_secs);
        self.clamp_filtered_selection();

        let message = format!(
            "Loaded background scan from {} (health: {}/100).",
            saved.timestamp, self.health_score
        );
        self.last_scan_timestamp = Some(saved.timestamp);
        self.push_scan_log(message.clone());
        self.status_message = Some(message);
    }
}

/// What is left of a step that got to `percent` in `elapsed`, if it keeps its
/// pace. Below one percent there is no pace to speak of, and more than two
/// hours is past the point where WinMedic stops the tool anyway.
fn time_left(elapsed: Duration, percent: f32) -> Option<Duration> {
    if percent >= 100.0 {
        return Some(Duration::ZERO);
    }
    if percent < 1.0 {
        return None;
    }
    let percent = f64::from(percent);
    let left = elapsed.as_secs_f64() * (100.0 - percent) / percent;
    (left <= 2.0 * 60.0 * 60.0).then(|| Duration::from_secs_f64(left.round()))
}

/// Whether `issue` is settled by restarting Windows: a repair that needs the
/// restart to finish, or Windows' own queued restart work. A restart settles
/// both; if Windows queued more, the next scan finds it again.
fn waits_for_restart(issue: &Issue) -> bool {
    issue.is_reboot_pending || (issue.id == REBOOT_PENDING && !issue.is_fixed)
}

/// Windows has restarted since the saved scan: what waited for it is done.
fn settle_after_restart(issues: &mut [Issue]) {
    for issue in issues.iter_mut().filter(|i| waits_for_restart(i)) {
        issue.is_reboot_pending = false;
        issue.is_fixed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::MAX_LOG_LINES;
    use crate::engine::issue::RiskScore;

    fn finding(id: &str) -> Issue {
        Issue::new(
            id,
            "windows_updates",
            id,
            "Windows Update & Services",
            Severity::Info,
            RiskScore::Low,
            "",
            "",
            "",
            vec![],
        )
    }

    /// A repair waiting for the restart and the restart Windows queued itself
    /// both keep the restart pending; nothing else does.
    #[test]
    fn a_restart_is_pending_for_repairs_and_for_windows() {
        let mut app = App::new();
        app.issues = vec![finding("dns")];
        assert!(!app.restart_pending());

        app.issues.push(finding(REBOOT_PENDING));
        assert!(app.restart_pending(), "Windows' own restart work");

        app.issues = vec![finding("chkdsk")];
        app.issues[0].is_reboot_pending = true;
        assert!(app.restart_pending(), "a repair waiting for it");
    }

    /// A restart settles what waited for it, and nothing else.
    #[test]
    fn a_restart_settles_what_waited_for_it() {
        let mut issues = vec![finding("chkdsk"), finding(REBOOT_PENDING), finding("dns")];
        issues[0].is_reboot_pending = true;

        settle_after_restart(&mut issues);

        assert!(issues[0].is_fixed && !issues[0].is_reboot_pending);
        assert!(issues[1].is_fixed);
        assert!(!issues[2].is_fixed, "a finding a restart does not touch");
        assert!(!issues.iter().any(waits_for_restart));
    }

    #[test]
    fn the_time_left_follows_the_pace_so_far() {
        let minutes = |m: u64| Duration::from_secs(m * 60);
        assert_eq!(time_left(minutes(3), 30.0), Some(minutes(7)));
        assert_eq!(time_left(minutes(4), 80.0), Some(minutes(1)));
        assert_eq!(time_left(minutes(9), 100.0), Some(Duration::ZERO));
    }

    #[test]
    fn too_little_progress_gives_no_estimate() {
        let minutes = |m: u64| Duration::from_secs(m * 60);
        assert_eq!(time_left(minutes(2), 0.5), None);
        assert_eq!(time_left(minutes(30), 10.0), None, "4h30m is no estimate");
    }

    #[test]
    fn test_app_export_report() {
        let mut app = App::new();
        let res = app.export_report();
        assert!(res.is_ok());
        let path = res.unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("WinMedic Diagnostic Report"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_scan_log_evicts_its_oldest_lines_once_it_is_full() {
        let mut app = App::new();
        app.scan_log_messages.clear();

        // Push 2100 messages (exceeding MAX_LOG_LINES = 2000)
        for i in 0..2100 {
            app.push_scan_log(format!("Log line {}", i));
        }

        assert_eq!(app.scan_log_messages.len(), MAX_LOG_LINES);
        // The first 100 messages should have been evicted; line 100 should be the oldest
        assert_eq!(
            app.scan_log_messages.front(),
            Some(&"Log line 100".to_string())
        );
        assert_eq!(
            app.scan_log_messages.back(),
            Some(&"Log line 2099".to_string())
        );
    }

    #[test]
    fn test_tab_navigation_wrapping() {
        let mut app = App::new();
        app.active_tab = 0;

        app.prev_tab();
        assert_eq!(app.active_tab, TAB_COUNT - 1);

        app.next_tab();
        assert_eq!(app.active_tab, 0);

        app.next_tab();
        assert_eq!(app.active_tab, 1);
    }

    #[test]
    fn test_app_persists_and_restores_scan_state() {
        let tmp =
            std::env::temp_dir().join(format!("winmedic_state_test_{}.json", std::process::id()));
        let mut app = App::new();
        app.issues = vec![Issue::new(
            "iss_1",
            "storage",
            "Low Disk Space",
            "Storage",
            Severity::Warning,
            RiskScore::Low,
            "Temp files are taking up too much space",
            "5 GB in temp directory",
            "Clean temp files",
            vec!["Delete temp files".to_string()],
        )];
        app.health_score = 85;

        let state = ScanState::new(
            app.health_score,
            app.issues.clone(),
            app.module_statuses.clone(),
            Some(5),
        );
        state.save_to(&tmp).unwrap();

        let loaded = ScanState::load_from(&tmp).expect("should load scan state");
        assert_eq!(loaded.health_score, 85);
        assert_eq!(loaded.issues.len(), 1);
        assert_eq!(loaded.issues[0].title, "Low Disk Space");
        assert_eq!(loaded.scan_duration_secs, Some(5));

        let _ = std::fs::remove_file(tmp);
    }
}
