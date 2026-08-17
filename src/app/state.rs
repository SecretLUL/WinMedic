//! The [`App`] struct itself: construction, telemetry, log buffers and report
//! export. Behaviour that belongs to a specific feature lives in the sibling
//! modules listed in [`crate::app`].

use super::{
    BackgroundEvent, TAB_COUNT, TAB_DASHBOARD, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS,
    push_bounded_log,
};
use crate::config::AppConfig;
use crate::engine::issue::{Issue, Severity};
use crate::engine::reporter::DiagnosticReporter;
use crate::engine::runner::{DiagnosticEngine, RepairEvent, ScanEvent};
use crate::modules::ModuleStatus;
use crate::safety::audit::{AuditEntry, AuditLogger};
use crate::safety::reg_backup::{BackupRecord, RegBackupManager};
use crate::utils::admin::is_admin;
use crate::utils::cmd::SystemCommandRunner;
use crate::utils::hardware::{SystemTelemetry, TelemetryCollector};
use crate::utils::updater::{self, UpdateInfo};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

use super::confirm::{ConfirmRequest, SystemActions};

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

/// Which of the two lists on the Settings & Safety tab currently owns `↑`/`↓`.
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

    // Telemetry
    pub telemetry_collector: TelemetryCollector,
    pub telemetry: Option<SystemTelemetry>,

    // Diagnostic & Engine
    pub engine: Arc<DiagnosticEngine>,
    pub issues: Vec<Issue>,
    pub selected_issue_index: usize,
    pub health_score: u8,

    // Issue Filtering & Search
    pub severity_filter: Option<Severity>,
    pub module_filter: Option<String>,
    pub search_query: String,
    pub is_searching: bool,
    pub selected_filtered_index: usize,

    // Live Scanner State
    pub is_scanning: bool,
    pub scan_overall_progress: u8,
    /// When the running scan started. Cleared once it ends, so the readout
    /// stops rather than counting up forever under "DIAGNOSTICS COMPLETE".
    pub scan_started_at: Option<Instant>,
    /// How long the last completed scan took.
    pub scan_duration: Option<Duration>,
    pub module_progress_list: Vec<ModuleScanProgress>,
    pub module_statuses: Vec<(String, String, String, ModuleStatus)>,
    pub scan_log_messages: VecDeque<String>,
    pub scan_log_scroll: usize,

    // Live Repair State
    pub is_fixing: bool,
    /// Simulate repairs instead of executing them.
    pub dry_run: bool,
    pub current_fix_title: String,
    pub fixed_count: usize,
    pub failed_count: usize,
    pub total_to_fix: usize,
    pub vss_status: String,
    pub repair_console_lines: VecDeque<String>,
    pub repair_log_scroll: usize,

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
    /// Which list on the Settings & Safety tab the arrow keys drive.
    pub safety_focus: SafetyFocus,

    // UI state
    pub status_message: Option<String>,
    pub show_help: bool,
    pub pending_confirm: Option<ConfirmRequest>,
    pub available_update: Option<UpdateInfo>,
    /// What this app is allowed to do to the machine it runs on: browser
    /// windows, UAC prompts, restore points.
    ///
    /// Inert unless the caller opts in through
    /// [`App::enable_real_system_actions`], which only the TUI entry point
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
        let mut telemetry_collector = TelemetryCollector::new();
        let telemetry = Some(telemetry_collector.refresh());
        let admin_flag = is_admin();
        let (config, config_status) = AppConfig::load_reporting();
        let system_actions = SystemActions::default();
        let engine = Arc::new(
            DiagnosticEngine::new(&config).with_restore_points(system_actions.restore_point),
        );
        let audit_logger = AuditLogger::new();
        let reg_backup_mgr = RegBackupManager::new();
        let audit_entries = audit_logger.get_history();
        let backup_records = reg_backup_mgr.list_backups();
        let (bg_tx, bg_rx) = tokio::sync::mpsc::unbounded_channel();

        let (module_progress_list, module_statuses) = Self::module_lists(&engine);

        Self {
            active_tab: TAB_DASHBOARD,
            is_admin: admin_flag,
            config,
            telemetry_collector,
            telemetry,
            engine,
            issues: Vec::new(),
            selected_issue_index: 0,
            health_score: 100,
            severity_filter: None,
            module_filter: None,
            search_query: String::new(),
            is_searching: false,
            selected_filtered_index: 0,
            is_scanning: false,
            scan_overall_progress: 0,
            scan_started_at: None,
            scan_duration: None,
            module_progress_list,
            module_statuses,
            scan_log_messages: VecDeque::from([String::from(
                "WinMedic initialised. Ready to diagnose.",
            )]),
            scan_log_scroll: 0,
            is_fixing: false,
            dry_run: false,
            current_fix_title: String::new(),
            fixed_count: 0,
            failed_count: 0,
            total_to_fix: 0,
            vss_status: "Ready".to_string(),
            repair_console_lines: VecDeque::from([String::from("Repair centre ready.")]),
            repair_log_scroll: 0,
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
    /// opens no browser and raises no UAC prompt, and a repair run asks Windows
    /// for no restore point. That default is what keeps `cargo test` — which
    /// builds dozens of `App`s — off the developer's own desktop. The TUI entry
    /// point is the one caller that wants the real thing, so it is the one
    /// caller that opts in.
    ///
    /// The engine is rebuilt because it reads
    /// [`SystemActions::restore_point`] at construction time.
    pub fn enable_real_system_actions(&mut self) {
        self.system_actions = SystemActions::real();
        self.rebuild_engine();
    }

    /// Rebuild the engine from the current config and system actions.
    pub(super) fn rebuild_engine(&mut self) {
        self.engine = Arc::new(
            DiagnosticEngine::new(&self.config)
                .with_restore_points(self.system_actions.restore_point),
        );
    }

    /// Kick off the background GitHub release check.
    ///
    /// Deliberately *not* part of [`App::new`]: constructing an `App` must stay
    /// free of network I/O so the test suite — which builds dozens of them
    /// inside `#[tokio::test]` — never reaches out to api.github.com. The TUI
    /// entry point calls this once, right after construction.
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

    pub fn refresh_telemetry(&mut self) {
        self.telemetry = Some(self.telemetry_collector.refresh());
    }

    /// How long the scan has been running, or how long the last one took.
    pub fn scan_elapsed(&self) -> Option<Duration> {
        match self.scan_started_at {
            Some(start) => Some(start.elapsed()),
            None => self.scan_duration,
        }
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
    /// Only the Settings & Safety tab needs it: its audit log and backup list
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

    pub fn scroll_log_up(&mut self, amount: usize) {
        match self.active_tab {
            TAB_SCANNER => {
                let max_scroll = self.scan_log_messages.len().saturating_sub(1);
                self.scan_log_scroll = (self.scan_log_scroll + amount).min(max_scroll);
            }
            TAB_REPAIR => {
                let max_scroll = self.repair_console_lines.len().saturating_sub(1);
                self.repair_log_scroll = (self.repair_log_scroll + amount).min(max_scroll);
            }
            _ => {}
        }
    }

    pub fn scroll_log_down(&mut self, amount: usize) {
        match self.active_tab {
            TAB_SCANNER => {
                self.scan_log_scroll = self.scan_log_scroll.saturating_sub(amount);
            }
            TAB_REPAIR => {
                self.repair_log_scroll = self.repair_log_scroll.saturating_sub(amount);
            }
            _ => {}
        }
    }

    pub fn scroll_log_top(&mut self) {
        match self.active_tab {
            TAB_SCANNER => {
                self.scan_log_scroll = self.scan_log_messages.len().saturating_sub(1);
            }
            TAB_REPAIR => {
                self.repair_log_scroll = self.repair_console_lines.len().saturating_sub(1);
            }
            _ => {}
        }
    }

    pub fn scroll_log_bottom(&mut self) {
        match self.active_tab {
            TAB_SCANNER => {
                self.scan_log_scroll = 0;
            }
            TAB_REPAIR => {
                self.repair_log_scroll = 0;
            }
            _ => {}
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::MAX_LOG_LINES;

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
    fn test_app_log_ring_buffer_and_scrolling() {
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

        // Test scrolling
        app.active_tab = TAB_SCANNER;
        assert_eq!(app.scan_log_scroll, 0);

        app.scroll_log_up(15);
        assert_eq!(app.scan_log_scroll, 15);

        app.scroll_log_down(5);
        assert_eq!(app.scan_log_scroll, 10);

        app.scroll_log_top();
        assert_eq!(app.scan_log_scroll, MAX_LOG_LINES - 1);

        app.scroll_log_bottom();
        assert_eq!(app.scan_log_scroll, 0);
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
}
