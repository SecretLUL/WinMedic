use crate::config::AppConfig;
use crate::engine::issue::{Issue, Severity};
use crate::engine::reporter::DiagnosticReporter;
use crate::engine::runner::{DiagnosticEngine, RepairEvent, RepairOptions, ScanEvent};
use crate::modules::ModuleStatus;
use crate::safety::audit::{AuditEntry, AuditLogger};
use crate::safety::reg_backup::{BackupRecord, RegBackupManager};
use crate::safety::restore_point::list_restore_points;
use crate::utils::admin::{is_admin, relaunch_as_admin};
use crate::utils::hardware::{SystemTelemetry, TelemetryCollector};
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender, channel};
use tokio_util::sync::CancellationToken;

/// Number of tabs in the main navigation.
pub const TAB_COUNT: usize = 6;

pub const TAB_DASHBOARD: usize = 0;
pub const TAB_SCANNER: usize = 1;
pub const TAB_TRIAGE: usize = 2;
pub const TAB_REPAIR: usize = 3;
pub const TAB_HISTORY: usize = 4;
pub const TAB_SETTINGS: usize = 5;

/// Results of short-lived background tasks that are not part of a scan or a
/// repair run (restore point lookups, registry rollbacks).
#[derive(Debug, Clone)]
pub enum BackgroundEvent {
    RestorePointsLoaded(Vec<String>),
    RollbackFinished { success: bool, message: String },
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
}

impl ConfirmRequest {
    pub fn title(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "REGISTRY-SICHERUNG WIEDERHERSTELLEN?",
            ConfirmRequest::Elevate => "ADMINISTRATORRECHTE ERFORDERLICH",
        }
    }

    pub fn confirm_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Wiederherstellen",
            ConfirmRequest::Elevate => "Jetzt als Admin neu starten",
        }
    }

    pub fn dismiss_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Abbrechen",
            ConfirmRequest::Elevate => "Ohne Admin fortfahren",
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

    // Live Scanner State
    pub is_scanning: bool,
    pub scan_overall_progress: u8,
    pub scan_active_module_name: String,
    pub scan_current_step_text: String,
    pub module_progress_list: Vec<(String, String, String, u8, bool)>, // (id, name, icon, percent, is_done)
    pub module_statuses: Vec<(String, String, String, ModuleStatus)>,
    pub scan_log_messages: Vec<String>,

    // Live Repair State
    pub is_fixing: bool,
    /// Simulate repairs instead of executing them.
    pub dry_run: bool,
    pub current_fix_title: String,
    pub fixed_count: usize,
    pub failed_count: usize,
    pub total_to_fix: usize,
    pub vss_status: String,
    pub repair_console_lines: Vec<String>,

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
    pub should_quit: bool,

    // Internal async event channels
    pub scan_event_rx: Option<Receiver<ScanEvent>>,
    pub repair_event_rx: Option<Receiver<RepairEvent>>,
    /// Cancels whichever scan or repair run is currently active.
    cancel_token: Option<CancellationToken>,
    bg_tx: UnboundedSender<BackgroundEvent>,
    bg_rx: UnboundedReceiver<BackgroundEvent>,
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
            is_scanning: false,
            scan_overall_progress: 0,
            scan_active_module_name: "Bereit".to_string(),
            scan_current_step_text: "Kein Scan aktiv".to_string(),
            module_progress_list,
            module_statuses,
            scan_log_messages: vec!["WinMedic initialisiert. Bereit für Diagnose.".to_string()],
            is_fixing: false,
            dry_run: false,
            current_fix_title: String::new(),
            fixed_count: 0,
            failed_count: 0,
            total_to_fix: 0,
            vss_status: "Bereit".to_string(),
            repair_console_lines: vec!["Reparatur-Center bereit.".to_string()],
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
            should_quit: false,
            scan_event_rx: None,
            repair_event_rx: None,
            cancel_token: None,
            bg_tx,
            bg_rx,
        }
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

    pub fn start_scan(&mut self) {
        if self.is_busy() {
            return;
        }

        self.is_scanning = true;
        self.scan_overall_progress = 0;
        self.active_tab = TAB_SCANNER;
        self.issues.clear();
        self.selected_issue_index = 0;
        self.scan_log_messages.clear();
        self.scan_log_messages
            .push("Starte vollständigen System-Health-Scan...".to_string());

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
        self.vss_status = if self.dry_run {
            "Simulation".to_string()
        } else {
            "Initialisiere...".to_string()
        };
        self.repair_console_lines.clear();
        self.repair_console_lines.push(if self.dry_run {
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
            self.scan_log_messages.push(line);
        } else {
            self.repair_console_lines.push(line);
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
                            self.scan_log_messages.push(msg);
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
                        self.scan_log_messages
                            .push(format!("Modul '{}' abgeschlossen.", module_id));
                    }
                    ScanEvent::ModuleFailed { module_id, error } => {
                        if let Some(pos) =
                            self.module_statuses.iter().position(|m| m.0 == module_id)
                        {
                            self.module_statuses[pos].3 = ModuleStatus::Failed(error.clone());
                        }
                        self.scan_log_messages
                            .push(format!("Fehler in Modul '{}': {}", module_id, error));
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
                        self.scan_log_messages.push(format!("⏹ {}", msg));
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
                        self.repair_console_lines.push(format!(
                            "Simuliere {} Reparatur(en) – kein Wiederherstellungspunkt nötig.",
                            issue_count
                        ));
                    }
                    RepairEvent::VssStarted => {
                        self.vss_status = "Erstelle Restore Point...".to_string();
                        self.repair_console_lines.push(
                            "Erstelle Windows Systemwiederherstellungspunkt (VSS)...".to_string(),
                        );
                    }
                    RepairEvent::VssCompleted { success, message } => {
                        self.vss_status = if success {
                            "Erstellt (OK)".to_string()
                        } else {
                            "Hinweis".to_string()
                        };
                        self.repair_console_lines.push(format!("VSS: {}", message));
                    }
                    RepairEvent::FixStarted { issue_id: _, title } => {
                        self.current_fix_title = title.clone();
                        self.repair_console_lines.push(if self.dry_run {
                            format!("Simuliere: {}", title)
                        } else {
                            format!("Repariere: {}", title)
                        });
                    }
                    RepairEvent::FixOutput { issue_id: _, line } => {
                        self.repair_console_lines.push(line);
                    }
                    RepairEvent::FixFinished {
                        issue_id,
                        success,
                        message,
                    } => {
                        // A simulation must never flip an issue to "fixed".
                        if !self.dry_run {
                            if let Some(issue) = self.issues.iter_mut().find(|i| i.id == issue_id) {
                                issue.is_fixed = success;
                                if !success {
                                    issue.fix_error = Some(message.clone());
                                }
                            }
                        }
                        if success {
                            self.fixed_count += 1;
                            self.repair_console_lines.push(format!("✔ {}", message));
                        } else {
                            self.failed_count += 1;
                            self.repair_console_lines
                                .push(format!("✖ Fehler: {}", message));
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
                        self.repair_console_lines.push(format!("⏹ {}", msg));
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
            }
        }
    }

    pub fn toggle_selected_issue(&mut self) {
        if let Some(issue) = self.issues.get_mut(self.selected_issue_index) {
            issue.is_selected = !issue.is_selected;
        }
    }

    pub fn select_all_issues(&mut self) {
        for issue in &mut self.issues {
            issue.is_selected = true;
        }
    }

    pub fn deselect_all_issues(&mut self) {
        for issue in &mut self.issues {
            issue.is_selected = false;
        }
    }

    pub fn next_issue(&mut self) {
        if !self.issues.is_empty() {
            self.selected_issue_index = (self.selected_issue_index + 1) % self.issues.len();
        }
    }

    pub fn prev_issue(&mut self) {
        if !self.issues.is_empty() {
            if self.selected_issue_index == 0 {
                self.selected_issue_index = self.issues.len() - 1;
            } else {
                self.selected_issue_index -= 1;
            }
        }
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
            }
        }
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
}
