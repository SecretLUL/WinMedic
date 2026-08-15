use crate::config::AppConfig;
use crate::engine::issue::{Issue, Severity};
use crate::engine::reporter::DiagnosticReporter;
use crate::engine::runner::{DiagnosticEngine, RepairEvent, RepairOptions, ScanEvent};
use crate::modules::ModuleStatus;
use crate::safety::audit::{AuditEntry, AuditLogger};
use crate::safety::reg_backup::{BackupRecord, RegBackupManager};
use crate::safety::restore_point::list_restore_points;
use crate::utils::admin::{is_admin, relaunch_as_admin};
use crate::utils::cmd::SystemCommandRunner;
use crate::utils::hardware::{SystemTelemetry, TelemetryCollector};
use crate::utils::updater::{self, UpdateInfo};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender, channel};
use tokio_util::sync::CancellationToken;

/// Maximum number of log lines kept in memory for scan and repair terminal buffers.
pub const MAX_LOG_LINES: usize = 2000;

/// Number of tabs in the main navigation.
pub const TAB_COUNT: usize = 6;

pub const TAB_DASHBOARD: usize = 0;
pub const TAB_SCANNER: usize = 1;
pub const TAB_TRIAGE: usize = 2;
pub const TAB_REPAIR: usize = 3;
pub const TAB_HISTORY: usize = 4;
pub const TAB_SETTINGS: usize = 5;

/// Results of short-lived background tasks that are not part of a scan or a
/// repair run (restore point lookups, registry rollbacks, update checks).
#[derive(Debug, Clone)]
pub enum BackgroundEvent {
    RestorePointsLoaded(Vec<String>),
    RollbackFinished { success: bool, message: String },
    UpdateChecked(Option<UpdateInfo>),
}

/// An action that needs an explicit yes before it touches the system.
#[derive(Debug, Clone)]
pub enum ConfirmRequest {
    Rollback {
        description: String,
        key_path: String,
        file_path: String,
    },
    Elevate,
    UpdateAvailable {
        current_version: String,
        latest_version: String,
        release_url: String,
    },
}

impl ConfirmRequest {
    pub fn title(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "REGISTRY-SICHERUNG WIEDERHERSTELLEN?",
            ConfirmRequest::Elevate => "ADMINISTRATORRECHTE ERFORDERLICH",
            ConfirmRequest::UpdateAvailable { .. } => "NEUES WINMEDIC UPDATE VERFÜGBAR",
        }
    }

    pub fn confirm_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Wiederherstellen",
            ConfirmRequest::Elevate => "Jetzt als Admin neu starten",
            ConfirmRequest::UpdateAvailable { .. } => "Release-Seite im Browser öffnen",
        }
    }

    pub fn dismiss_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Abbrechen",
            ConfirmRequest::Elevate => "Ohne Admin fortfahren",
            ConfirmRequest::UpdateAvailable { .. } => "Später erinnern",
        }
    }

    pub fn body(&self) -> Vec<String> {
        match self {
            ConfirmRequest::Rollback {
                description,
                key_path,
                file_path,
            } => vec![
                "Die folgende Registry-Sicherung wird per 'reg import' zurückgespielt.".to_string(),
                "Bestehende Werte unter diesem Schlüssel werden dabei überschrieben.".to_string(),
                String::new(),
                format!("Sicherung:  {}", description),
                format!("Schlüssel:  {}", key_path),
                format!("Datei:      {}", file_path),
            ],
            ConfirmRequest::Elevate => vec![
                "WinMedic wurde ohne Administratorrechte ausgeführt.".to_string(),
                "Vollständige Diagnose- und Reparaturfunktionen (Systemdateien via SFC/DISM,"
                    .to_string(),
                "Dienste und Registry) erfordern erhöhte Administratorrechte.".to_string(),
                String::new(),
                "Möchten Sie WinMedic jetzt mit Administratorrechten (UAC) neu starten?"
                    .to_string(),
            ],
            ConfirmRequest::UpdateAvailable {
                current_version,
                latest_version,
                release_url,
            } => vec![
                "Eine neue Version von WinMedic ist auf GitHub verfügbar!".to_string(),
                String::new(),
                format!(
                    "Installierte Version:  v{}",
                    current_version.trim_start_matches(['v', 'V'])
                ),
                format!(
                    "Neueste Version:       v{}",
                    latest_version.trim_start_matches(['v', 'V'])
                ),
                String::new(),
                format!("URL: {}", release_url),
                String::new(),
                "Möchten Sie die GitHub Release-Seite im Standardbrowser öffnen?".to_string(),
            ],
        }
    }
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
    restore_points_requested: bool,
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
    cancel_token: Option<CancellationToken>,
    bg_tx: UnboundedSender<BackgroundEvent>,
    bg_rx: UnboundedReceiver<BackgroundEvent>,
}

fn push_bounded_log(buffer: &mut VecDeque<String>, line: impl Into<String>) {
    if buffer.len() >= MAX_LOG_LINES {
        buffer.pop_front();
    }
    buffer.push_back(line.into());
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
        let config = AppConfig::load();
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
            status_message: Some("Bereit".to_string()),
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
    fn module_lists(
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

    pub fn start_scan(&mut self) {
        if self.is_busy() {
            return;
        }

        self.is_scanning = true;
        self.scan_overall_progress = 0;
        self.active_tab = TAB_SCANNER;
        self.issues.clear();
        self.selected_issue_index = 0;
        self.selected_filtered_index = 0;
        self.scan_log_scroll = 0;
        self.scan_log_messages.clear();
        self.push_scan_log("Starte vollständigen System-Health-Scan...");

        for item in &mut self.module_progress_list {
            item.3 = 0;
            item.4 = false;
        }
        for item in &mut self.module_statuses {
            item.3 = ModuleStatus::Scanning;
        }

        let (tx, rx) = channel::<ScanEvent>(100);
        self.scan_event_rx = Some(rx);

        let cancel = CancellationToken::new();
        self.cancel_token = Some(cancel.clone());

        let engine_clone = self.engine.clone();
        tokio::spawn(async move {
            engine_clone.run_scan(tx, cancel).await;
        });

        self.status_message = Some("Diagnose-Scan läuft... [Esc] bricht ab".to_string());
    }

    pub fn start_repairs(&mut self) {
        if self.is_busy() {
            return;
        }

        if !self.is_admin && !self.dry_run {
            self.pending_confirm = Some(ConfirmRequest::Elevate);
            self.status_message =
                Some("Administratorrechte erforderlich für Reparaturen.".to_string());
            return;
        }

        let selected_count = self
            .issues
            .iter()
            .filter(|i| i.is_selected && !i.is_fixed)
            .count();
        if selected_count == 0 {
            self.status_message =
                Some("Keine offenen Probleme zur Reparatur ausgewählt.".to_string());
            return;
        }

        self.is_fixing = true;
        self.active_tab = TAB_REPAIR;
        self.fixed_count = 0;
        self.failed_count = 0;
        self.total_to_fix = selected_count;
        self.repair_log_scroll = 0;
        self.vss_status = if self.dry_run {
            "Simulation".to_string()
        } else {
            "Initialisiere...".to_string()
        };
        self.repair_console_lines.clear();
        self.push_repair_log(if self.dry_run {
            format!(
                "SIMULATION: Zeige geplante Schritte für {} Probleme. Es wird nichts verändert.",
                selected_count
            )
        } else {
            format!(
                "Starte Reparatur von {} ausgewählten Problemen...",
                selected_count
            )
        });

        let (tx, rx) = channel::<RepairEvent>(100);
        self.repair_event_rx = Some(rx);

        let cancel = CancellationToken::new();
        self.cancel_token = Some(cancel.clone());

        let mut issues_clone = self.issues.clone();
        let engine_clone = self.engine.clone();
        let options = RepairOptions::from_config(&self.config, self.dry_run);

        tokio::spawn(async move {
            engine_clone
                .run_repairs(&mut issues_clone, options, tx, cancel)
                .await;
        });

        self.status_message = Some(if self.dry_run {
            "Simulation läuft... [Esc] bricht ab".to_string()
        } else {
            "Reparaturen werden ausgeführt... [Esc] bricht ab".to_string()
        });
    }

    /// Signal the running scan or repair to stop at the next safe point.
    ///
    /// Returns false when there was nothing to cancel.
    pub fn cancel_current_operation(&mut self) -> bool {
        let Some(token) = self.cancel_token.as_ref() else {
            return false;
        };
        if token.is_cancelled() {
            return true;
        }

        token.cancel();
        let target = if self.is_scanning {
            "Scan"
        } else {
            "Reparatur"
        };
        self.status_message = Some(format!("{} wird abgebrochen...", target));
        let line = format!("⏹ Abbruch angefordert – laufender {} wird beendet.", target);
        if self.is_scanning {
            self.push_scan_log(line);
        } else {
            self.push_repair_log(line);
        }
        true
    }

    /// Toggle simulation mode. Not allowed while a run is in progress.
    pub fn toggle_dry_run(&mut self) {
        if self.is_busy() {
            self.status_message = Some(
                "Simulationsmodus kann während eines Laufs nicht geändert werden.".to_string(),
            );
            return;
        }
        self.dry_run = !self.dry_run;
        self.status_message = Some(if self.dry_run {
            "Simulationsmodus AN – [F] zeigt nur die geplanten Schritte.".to_string()
        } else {
            "Simulationsmodus AUS – [F] führt Reparaturen wirklich aus.".to_string()
        });
    }

    pub fn process_background_events(&mut self) {
        self.process_scan_events();
        self.process_repair_events();
        self.process_bg_events();
    }

    fn process_scan_events(&mut self) {
        let mut scan_ended = false;
        if let Some(ref mut rx) = self.scan_event_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    ScanEvent::ModuleStarted(mod_id) => {
                        self.scan_active_module_name = mod_id.clone();
                        self.scan_current_step_text = "Initialisiere Prüfung...".to_string();
                        if let Some(pos) =
                            self.module_progress_list.iter().position(|m| m.0 == mod_id)
                        {
                            self.scan_active_module_name = self.module_progress_list[pos].1.clone();
                        }
                    }
                    ScanEvent::ModuleProgressUpdate(prog) => {
                        self.scan_current_step_text = prog.current_step.clone();
                        if let Some(pos) = self
                            .module_progress_list
                            .iter()
                            .position(|m| m.0 == prog.module_id)
                        {
                            self.module_progress_list[pos].3 = prog.progress_percent;
                            self.scan_active_module_name = self.module_progress_list[pos].1.clone();
                        }
                        if let Some(msg) = prog.log_message {
                            push_bounded_log(&mut self.scan_log_messages, msg);
                        }
                        let total_mods = self.module_progress_list.len().max(1);
                        let sum_progress: usize =
                            self.module_progress_list.iter().map(|m| m.3 as usize).sum();
                        self.scan_overall_progress = (sum_progress / total_mods) as u8;
                    }
                    ScanEvent::ModuleFinished { module_id, issues } => {
                        if let Some(pos) = self
                            .module_progress_list
                            .iter()
                            .position(|m| m.0 == module_id)
                        {
                            self.module_progress_list[pos].3 = 100;
                            self.module_progress_list[pos].4 = true;
                        }
                        if let Some(pos) =
                            self.module_statuses.iter().position(|m| m.0 == module_id)
                        {
                            let crit = issues
                                .iter()
                                .filter(|i| i.severity == Severity::Critical)
                                .count();
                            let warn = issues
                                .iter()
                                .filter(|i| i.severity == Severity::Warning)
                                .count();
                            if crit > 0 {
                                self.module_statuses[pos].3 = ModuleStatus::Critical(crit);
                            } else if warn > 0 {
                                self.module_statuses[pos].3 = ModuleStatus::Warning(warn);
                            } else {
                                self.module_statuses[pos].3 = ModuleStatus::Passed;
                            }
                        }
                        self.issues.extend(issues);
                        push_bounded_log(
                            &mut self.scan_log_messages,
                            format!("Modul '{}' abgeschlossen.", module_id),
                        );
                    }
                    ScanEvent::ModuleFailed { module_id, error } => {
                        if let Some(pos) =
                            self.module_statuses.iter().position(|m| m.0 == module_id)
                        {
                            self.module_statuses[pos].3 = ModuleStatus::Failed(error.clone());
                        }
                        push_bounded_log(
                            &mut self.scan_log_messages,
                            format!("Fehler in Modul '{}': {}", module_id, error),
                        );
                    }
                    ScanEvent::ScanCancelled {
                        completed_modules,
                        total_modules,
                    } => {
                        self.is_scanning = false;
                        scan_ended = true;
                        self.health_score = DiagnosticEngine::calculate_health_score(&self.issues);
                        for item in &mut self.module_statuses {
                            if item.3 == ModuleStatus::Scanning {
                                item.3 = ModuleStatus::Idle;
                            }
                        }
                        let msg = format!(
                            "Scan abgebrochen nach {}/{} Modulen ({} Teilergebnisse behalten).",
                            completed_modules,
                            total_modules,
                            self.issues.len()
                        );
                        push_bounded_log(&mut self.scan_log_messages, format!("⏹ {}", msg));
                        self.status_message = Some(msg);
                    }
                    ScanEvent::ScanCompleted {
                        total_issues,
                        health_score,
                    } => {
                        self.health_score = health_score;
                        self.scan_overall_progress = 100;
                        self.is_scanning = false;
                        scan_ended = true;
                        self.status_message = Some(format!(
                            "Scan abgeschlossen: {} Probleme gefunden (Health: {}/100)",
                            total_issues, health_score
                        ));
                    }
                }
            }
        }
        if scan_ended {
            self.scan_event_rx = None;
            self.cancel_token = None;
            self.audit_entries = self.audit_logger.get_history();
        }
    }

    fn process_repair_events(&mut self) {
        let mut repair_ended = false;
        if let Some(ref mut rx) = self.repair_event_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    RepairEvent::DryRunStarted { issue_count } => {
                        self.vss_status = "Simulation (kein VSS)".to_string();
                        push_bounded_log(
                            &mut self.repair_console_lines,
                            format!(
                                "Simuliere {} Reparatur(en) – kein Wiederherstellungspunkt nötig.",
                                issue_count
                            ),
                        );
                    }
                    RepairEvent::VssStarted => {
                        self.vss_status = "Erstelle Restore Point...".to_string();
                        push_bounded_log(
                            &mut self.repair_console_lines,
                            "Erstelle Windows Systemwiederherstellungspunkt (VSS)...",
                        );
                    }
                    RepairEvent::VssCompleted { success, message } => {
                        self.vss_status = if success {
                            "Erstellt (OK)".to_string()
                        } else {
                            "Hinweis".to_string()
                        };
                        push_bounded_log(
                            &mut self.repair_console_lines,
                            format!("VSS: {}", message),
                        );
                    }
                    RepairEvent::FixStarted { issue_id: _, title } => {
                        self.current_fix_title = title.clone();
                        push_bounded_log(
                            &mut self.repair_console_lines,
                            if self.dry_run {
                                format!("Simuliere: {}", title)
                            } else {
                                format!("Repariere: {}", title)
                            },
                        );
                    }
                    RepairEvent::FixOutput { issue_id: _, line } => {
                        push_bounded_log(&mut self.repair_console_lines, line);
                    }
                    RepairEvent::FixFinished {
                        issue_id,
                        success,
                        message,
                    } => {
                        // A simulation must never flip an issue to "fixed".
                        if !self.dry_run
                            && let Some(issue) = self.issues.iter_mut().find(|i| i.id == issue_id)
                        {
                            issue.is_fixed = success;
                            if !success {
                                issue.fix_error = Some(message.clone());
                            }
                        }
                        if success {
                            self.fixed_count += 1;
                            push_bounded_log(
                                &mut self.repair_console_lines,
                                format!("✔ {}", message),
                            );
                        } else {
                            self.failed_count += 1;
                            push_bounded_log(
                                &mut self.repair_console_lines,
                                format!("✖ Fehler: {}", message),
                            );
                        }
                    }
                    RepairEvent::RepairsCancelled {
                        fixed_count,
                        failed_count,
                        remaining,
                    } => {
                        self.is_fixing = false;
                        repair_ended = true;
                        self.fixed_count = fixed_count;
                        self.failed_count = failed_count;
                        self.health_score = DiagnosticEngine::calculate_health_score(&self.issues);
                        let msg = format!(
                            "Reparatur abgebrochen: {} erledigt, {} fehlgeschlagen, {} nicht mehr ausgeführt.",
                            fixed_count, failed_count, remaining
                        );
                        push_bounded_log(&mut self.repair_console_lines, format!("⏹ {}", msg));
                        self.status_message = Some(msg);
                    }
                    RepairEvent::AllRepairsCompleted {
                        fixed_count,
                        failed_count,
                    } => {
                        self.is_fixing = false;
                        repair_ended = true;
                        self.fixed_count = fixed_count;
                        self.failed_count = failed_count;
                        self.health_score = DiagnosticEngine::calculate_health_score(&self.issues);
                        self.status_message = Some(if self.dry_run {
                            format!(
                                "Simulation fertig: {} Reparatur(en) geplant, nichts verändert.",
                                fixed_count
                            )
                        } else {
                            format!(
                                "Reparatur fertig: {} behoben, {} fehlgeschlagen",
                                fixed_count, failed_count
                            )
                        });
                    }
                }
            }
        }
        if repair_ended {
            self.repair_event_rx = None;
            self.cancel_token = None;
            self.audit_entries = self.audit_logger.get_history();
            self.backup_records = self.reg_backup_mgr.list_backups();
            self.clamp_backup_selection();
        }
    }

    fn process_bg_events(&mut self) {
        while let Ok(event) = self.bg_rx.try_recv() {
            match event {
                BackgroundEvent::RestorePointsLoaded(points) => {
                    self.restore_points_loading = false;
                    self.status_message = Some(if points.is_empty() {
                        "Keine Windows-Wiederherstellungspunkte gefunden.".to_string()
                    } else {
                        format!("{} Wiederherstellungspunkte geladen.", points.len())
                    });
                    self.vss_restore_points = points;
                }
                BackgroundEvent::RollbackFinished { success, message } => {
                    self.is_restoring = false;
                    self.status_message = Some(message.clone());
                    self.audit_logger.log(
                        "RESTORE",
                        "reg_backup",
                        "Registry-Rollback",
                        if success { "SUCCESS" } else { "FAILED" },
                        &message,
                    );
                    self.audit_entries = self.audit_logger.get_history();
                }
                BackgroundEvent::UpdateChecked(Some(info)) => {
                    // The check lands at an arbitrary point in the session, so it
                    // never raises the modal by itself. A confirmation dialog
                    // swallows every keystroke and maps `j`/Enter — this app's own
                    // list-navigation keys — onto "open a browser", which would
                    // fire whatever the user happened to press next. Park the
                    // notice and let them open it deliberately with [U].
                    self.status_message = Some(format!(
                        "Update verfügbar: v{} (aktuell: v{}) – [U] für Details",
                        info.latest_version.trim_start_matches(['v', 'V']),
                        info.current_version.trim_start_matches(['v', 'V'])
                    ));
                    self.available_update = Some(info);
                }
                BackgroundEvent::UpdateChecked(None) => {}
            }
        }
    }

    pub fn filtered_issue_indices(&self) -> Vec<usize> {
        self.issues
            .iter()
            .enumerate()
            .filter(|(_idx, issue)| {
                // Severity filter
                if let Some(sev) = self.severity_filter
                    && issue.severity != sev
                {
                    return false;
                }
                // Module filter
                if let Some(ref mod_id) = self.module_filter
                    && &issue.module_id != mod_id
                {
                    return false;
                }
                // Search query
                if !self.search_query.is_empty() {
                    let q = self.search_query.to_lowercase();
                    let matches_title = issue.title.to_lowercase().contains(&q);
                    let matches_desc = issue.description.to_lowercase().contains(&q);
                    let matches_cat = issue.category.to_lowercase().contains(&q);
                    let matches_mod = issue.module_id.to_lowercase().contains(&q);
                    let matches_tech = issue.technical_details.to_lowercase().contains(&q);
                    if !matches_title
                        && !matches_desc
                        && !matches_cat
                        && !matches_mod
                        && !matches_tech
                    {
                        return false;
                    }
                }
                true
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    pub fn clamp_filtered_selection(&mut self) {
        let count = self.filtered_issue_indices().len();
        if count == 0 {
            self.selected_filtered_index = 0;
        } else if self.selected_filtered_index >= count {
            self.selected_filtered_index = count - 1;
        }
    }

    pub fn toggle_selected_issue(&mut self) {
        let indices = self.filtered_issue_indices();
        if let Some(&orig_idx) = indices.get(self.selected_filtered_index)
            && let Some(issue) = self.issues.get_mut(orig_idx)
            && !issue.is_fixed
        {
            issue.is_selected = !issue.is_selected;
        }
    }

    pub fn select_all_issues(&mut self) {
        let indices = self.filtered_issue_indices();
        for &orig_idx in &indices {
            if let Some(issue) = self.issues.get_mut(orig_idx)
                && !issue.is_fixed
            {
                issue.is_selected = true;
            }
        }
    }

    pub fn deselect_all_issues(&mut self) {
        let indices = self.filtered_issue_indices();
        for &orig_idx in &indices {
            if let Some(issue) = self.issues.get_mut(orig_idx) {
                issue.is_selected = false;
            }
        }
    }

    pub fn next_issue(&mut self) {
        let indices = self.filtered_issue_indices();
        if !indices.is_empty() {
            self.selected_filtered_index = (self.selected_filtered_index + 1) % indices.len();
        }
    }

    pub fn prev_issue(&mut self) {
        let indices = self.filtered_issue_indices();
        if !indices.is_empty() {
            if self.selected_filtered_index == 0 {
                self.selected_filtered_index = indices.len() - 1;
            } else {
                self.selected_filtered_index -= 1;
            }
        }
    }

    pub fn toggle_severity_filter(&mut self, sev: Severity) {
        if self.severity_filter == Some(sev) {
            self.severity_filter = None;
        } else {
            self.severity_filter = Some(sev);
        }
        self.clamp_filtered_selection();
    }

    pub fn cycle_module_filter(&mut self) {
        let mut module_ids: Vec<String> = self
            .engine
            .modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect();
        module_ids.dedup();

        if module_ids.is_empty() {
            self.module_filter = None;
            return;
        }

        self.module_filter = match &self.module_filter {
            None => Some(module_ids[0].clone()),
            Some(current) => {
                if let Some(pos) = module_ids.iter().position(|m| m == current) {
                    if pos + 1 < module_ids.len() {
                        Some(module_ids[pos + 1].clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };
        self.clamp_filtered_selection();
    }

    pub fn clear_filters(&mut self) {
        self.severity_filter = None;
        self.module_filter = None;
        self.search_query.clear();
        self.is_searching = false;
        self.clamp_filtered_selection();
    }

    pub fn has_active_filters(&self) -> bool {
        self.severity_filter.is_some()
            || self.module_filter.is_some()
            || !self.search_query.is_empty()
    }

    // ---------------------------------------------------------------- history

    pub fn load_history_data(&mut self) {
        self.audit_entries = self.audit_logger.get_history();
        self.backup_records = self.reg_backup_mgr.list_backups();
        self.clamp_backup_selection();

        // Querying VSS costs a PowerShell round trip, so only do it the first
        // time the tab is opened. [R] forces a refresh afterwards.
        if !self.restore_points_requested {
            self.refresh_restore_points();
        }
    }

    pub fn refresh_restore_points(&mut self) {
        if self.restore_points_loading {
            return;
        }
        self.restore_points_requested = true;
        self.restore_points_loading = true;
        let tx = self.bg_tx.clone();
        tokio::spawn(async move {
            let points = list_restore_points().await;
            let _ = tx.send(BackgroundEvent::RestorePointsLoaded(points));
        });
    }

    fn clamp_backup_selection(&mut self) {
        if self.backup_records.is_empty() {
            self.selected_backup_index = 0;
        } else if self.selected_backup_index >= self.backup_records.len() {
            self.selected_backup_index = self.backup_records.len() - 1;
        }
    }

    /// Backup records newest first — the order the history tab renders them in.
    pub fn backups_newest_first(&self) -> Vec<&BackupRecord> {
        self.backup_records.iter().rev().collect()
    }

    pub fn next_backup(&mut self) {
        if !self.backup_records.is_empty() {
            self.selected_backup_index =
                (self.selected_backup_index + 1) % self.backup_records.len();
        }
    }

    pub fn prev_backup(&mut self) {
        if !self.backup_records.is_empty() {
            if self.selected_backup_index == 0 {
                self.selected_backup_index = self.backup_records.len() - 1;
            } else {
                self.selected_backup_index -= 1;
            }
        }
    }

    /// Ask for confirmation before importing the selected `.reg` backup.
    pub fn request_rollback(&mut self) {
        if self.is_busy() || self.is_restoring {
            self.status_message =
                Some("Rollback nicht möglich, während ein anderer Vorgang läuft.".to_string());
            return;
        }

        let ordered = self.backups_newest_first();
        let Some(record) = ordered.get(self.selected_backup_index) else {
            self.status_message = Some(
                "Keine Registry-Sicherung vorhanden. Sicherungen entstehen bei Registry-Fixes."
                    .to_string(),
            );
            return;
        };

        self.pending_confirm = Some(ConfirmRequest::Rollback {
            description: record.description.clone(),
            key_path: record.key_path.clone(),
            file_path: record.file_path.clone(),
        });
    }

    pub fn dismiss_confirm(&mut self) {
        if let Some(request) = self.pending_confirm.take() {
            match request {
                ConfirmRequest::Rollback { .. } => {
                    self.status_message =
                        Some("Abgebrochen – es wurde nichts verändert.".to_string());
                }
                ConfirmRequest::Elevate => {
                    self.status_message = Some(
                        "Eingeschränkter Modus: Reparaturen ohne Administratorrechte können fehlschlagen."
                            .to_string(),
                    );
                }
                ConfirmRequest::UpdateAvailable { .. } => {
                    // "Später erinnern" — the notice stays parked in
                    // `available_update` so [U] can bring it back.
                    self.status_message =
                        Some("Update-Hinweis geschlossen – [U] öffnet ihn erneut.".to_string());
                }
            }
        }
    }

    /// Open the parked update notice as a confirmation dialog.
    ///
    /// This is the only path that raises the update modal, so it can never
    /// intercept a keystroke the user meant for something else.
    pub fn show_update_notice(&mut self) {
        if self.pending_confirm.is_some() {
            return;
        }
        let Some(info) = self.available_update.clone() else {
            return;
        };
        self.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
            current_version: info.current_version,
            latest_version: info.latest_version,
            release_url: info.release_url,
        });
    }

    /// Execute whatever action the confirmation dialog was asking about.
    pub fn confirm_pending_action(&mut self) {
        let Some(request) = self.pending_confirm.take() else {
            return;
        };

        match request {
            ConfirmRequest::Rollback {
                description,
                file_path,
                ..
            } => {
                self.is_restoring = true;
                self.status_message = Some(format!("Stelle '{}' wieder her...", description));

                let tx = self.bg_tx.clone();
                let mgr = RegBackupManager::new();
                tokio::spawn(async move {
                    let (success, message) = match mgr.restore_key(&file_path).await {
                        Ok(msg) => (true, msg),
                        Err(err) => (false, format!("Rollback fehlgeschlagen: {}", err)),
                    };
                    let _ = tx.send(BackgroundEvent::RollbackFinished { success, message });
                });
            }
            ConfirmRequest::Elevate => {
                if let Err(e) = relaunch_as_admin() {
                    self.status_message = Some(format!("Elevierung fehlgeschlagen: {}", e));
                } else {
                    self.should_quit = true;
                }
            }
            ConfirmRequest::UpdateAvailable { release_url, .. } => {
                if let Err(e) = updater::launch_browser(&release_url) {
                    self.status_message = Some(format!("Browser-Start fehlgeschlagen: {}", e));
                } else {
                    self.status_message =
                        Some("GitHub Release-Seite im Browser geöffnet.".to_string());
                }
                // The user has acted on it; stop offering it under [U].
                self.available_update = None;
            }
        }
    }

    // --------------------------------------------------------------- settings

    pub fn next_setting(&mut self) {
        self.selected_setting_index = (self.selected_setting_index + 1) % AppConfig::SETTING_COUNT;
    }

    pub fn prev_setting(&mut self) {
        if self.selected_setting_index == 0 {
            self.selected_setting_index = AppConfig::SETTING_COUNT - 1;
        } else {
            self.selected_setting_index -= 1;
        }
    }

    pub fn toggle_current_setting(&mut self) {
        if self.config.toggle_setting(self.selected_setting_index) {
            self.apply_config_change();
        }
    }

    pub fn adjust_current_setting(&mut self, increase: bool) {
        if self
            .config
            .adjust_setting(self.selected_setting_index, increase)
        {
            self.apply_config_change();
        }
    }

    /// Persist the config and rebuild the engine so modules pick up new
    /// thresholds on the next scan.
    fn apply_config_change(&mut self) {
        match self.config.save() {
            Ok(()) => {
                self.status_message = Some(format!(
                    "Einstellung gespeichert: {}",
                    AppConfig::config_path().display()
                ));
            }
            Err(e) => {
                self.status_message = Some(format!(
                    "Einstellung konnte nicht gespeichert werden: {}",
                    e
                ));
            }
        }

        if self.is_busy() {
            return;
        }

        self.engine = Arc::new(DiagnosticEngine::new(&self.config));
        let (progress, statuses) = Self::module_lists(&self.engine);
        self.module_progress_list = progress;
        // Findings from the last scan stay on screen; only reset the per-module
        // badges once there is nothing left to explain them.
        if self.issues.is_empty() {
            self.module_statuses = statuses;
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

    #[test]
    fn test_confirm_request_elevate() {
        let req = ConfirmRequest::Elevate;
        assert_eq!(req.title(), "ADMINISTRATORRECHTE ERFORDERLICH");
        assert_eq!(req.confirm_label(), "Jetzt als Admin neu starten");
        assert_eq!(req.dismiss_label(), "Ohne Admin fortfahren");
        assert!(!req.body().is_empty());
    }

    #[test]
    fn test_confirm_request_rollback() {
        let req = ConfirmRequest::Rollback {
            description: "Test Backup".to_string(),
            key_path: "HKCU\\Test".to_string(),
            file_path: "C:\\test.reg".to_string(),
        };
        assert_eq!(req.title(), "REGISTRY-SICHERUNG WIEDERHERSTELLEN?");
        assert_eq!(req.confirm_label(), "Wiederherstellen");
        assert_eq!(req.dismiss_label(), "Abbrechen");
        assert!(!req.body().is_empty());
    }

    #[test]
    fn test_confirm_request_update_available() {
        let req = ConfirmRequest::UpdateAvailable {
            current_version: "0.1.0".to_string(),
            latest_version: "v0.2.0".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        };
        assert_eq!(req.title(), "NEUES WINMEDIC UPDATE VERFÜGBAR");
        assert_eq!(req.confirm_label(), "Release-Seite im Browser öffnen");
        assert_eq!(req.dismiss_label(), "Später erinnern");
        let body = req.body().join("\n");
        assert!(body.contains("v0.1.0"));
        assert!(body.contains("v0.2.0"));
        assert!(body.contains("https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"));
    }

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
    fn test_app_filter_and_search() {
        let mut app = App::new();
        app.issues = vec![
            Issue::new(
                "sfc_1",
                "system_integrity",
                "CBS log corrupt",
                "System",
                Severity::Critical,
                crate::engine::issue::RiskScore::Low,
                "SFC corrupt",
                "details",
                "fix",
                vec![],
            ),
            Issue::new(
                "temp_1",
                "storage",
                "Temp bloat files",
                "Storage",
                Severity::Warning,
                crate::engine::issue::RiskScore::Low,
                "Temp bloat",
                "details",
                "fix",
                vec![],
            ),
            Issue::new(
                "net_1",
                "network",
                "DNS cache full",
                "Network",
                Severity::Info,
                crate::engine::issue::RiskScore::Low,
                "DNS flush",
                "details",
                "fix",
                vec![],
            ),
        ];

        // Initially all 3 are returned
        assert_eq!(app.filtered_issue_indices(), vec![0, 1, 2]);

        // Filter by Critical
        app.toggle_severity_filter(Severity::Critical);
        assert_eq!(app.filtered_issue_indices(), vec![0]);

        // Toggle again to reset severity filter
        app.toggle_severity_filter(Severity::Critical);
        assert_eq!(app.filtered_issue_indices(), vec![0, 1, 2]);

        // Filter by module
        app.module_filter = Some("storage".to_string());
        assert_eq!(app.filtered_issue_indices(), vec![1]);

        // Search text
        app.clear_filters();
        app.search_query = "DNS".to_string();
        assert_eq!(app.filtered_issue_indices(), vec![2]);

        app.clear_filters();
        assert_eq!(app.filtered_issue_indices(), vec![0, 1, 2]);
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
