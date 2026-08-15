//! The [`App`] struct itself: construction, telemetry, log buffers and report
//! export. Behaviour that belongs to a specific feature lives in the sibling
//! modules listed in [`crate::app`].

use super::{BackgroundEvent, TAB_DASHBOARD, TAB_REPAIR, TAB_SCANNER, push_bounded_log};
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
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

use super::confirm::ConfirmRequest;

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
    pub scan_active_module_name: String,
    pub scan_current_step_text: String,
    pub module_progress_list: Vec<(String, String, String, u8, bool)>, // (id, name, icon, percent, is_done)
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

    // Backups & History
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

    // UI state
    pub status_message: Option<String>,
    pub show_help: bool,
    pub pending_confirm: Option<ConfirmRequest>,
    pub available_update: Option<UpdateInfo>,
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
        let engine = Arc::new(DiagnosticEngine::new(&config));
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
            scan_active_module_name: "Bereit".to_string(),
            scan_current_step_text: "Kein Scan aktiv".to_string(),
            module_progress_list,
            module_statuses,
            scan_log_messages: VecDeque::from([String::from(
                "WinMedic initialisiert. Bereit für Diagnose.",
            )]),
            scan_log_scroll: 0,
            is_fixing: false,
            dry_run: false,
            current_fix_title: String::new(),
            fixed_count: 0,
            failed_count: 0,
            total_to_fix: 0,
            vss_status: "Bereit".to_string(),
            repair_console_lines: VecDeque::from([String::from("Reparatur-Center bereit.")]),
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
            // A corrupt config file is the one startup condition worth
            // interrupting the user's first glance for: their saved settings
            // are not in effect and the defaults silently re-enable things
            // they may have deliberately switched off.
            status_message: Some(
                config_status
                    .warning()
                    .unwrap_or_else(|| "Bereit".to_string()),
            ),
            show_help: false,
            pending_confirm: if !admin_flag {
                Some(ConfirmRequest::Elevate)
            } else {
                None
            },
            available_update: None,
            should_quit: false,
            scan_event_rx: None,
            repair_event_rx: None,
            cancel_token: None,
            bg_tx,
            bg_rx,
        }
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
        Vec<(String, String, String, u8, bool)>,
        Vec<(String, String, String, ModuleStatus)>,
    ) {
        let mut progress = Vec::new();
        let mut statuses = Vec::new();
        for m in engine.modules() {
            progress.push((
                m.id().to_string(),
                m.name().to_string(),
                m.icon().to_string(),
                0u8,
                false,
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

    /// True while a scan or a repair run is in flight.
    pub fn is_busy(&self) -> bool {
        self.is_scanning || self.is_fixing
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
            .map_err(|e| format!("Export fehlgeschlagen: {}", e))
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
        assert!(content.contains("WinMedic Diagnosebericht"));
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
}
