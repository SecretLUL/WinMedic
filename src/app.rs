use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver};
use crate::config::AppConfig;
use crate::engine::issue::{Issue, Severity};
use crate::engine::runner::{DiagnosticEngine, RepairEvent, ScanEvent};
use crate::modules::ModuleStatus;
use crate::safety::audit::{AuditEntry, AuditLogger};
use crate::safety::reg_backup::{BackupRecord, RegBackupManager};
use crate::utils::admin::is_admin;
use crate::utils::hardware::{SystemTelemetry, TelemetryCollector};

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

    // UI state
    pub status_message: Option<String>,
    pub show_help: bool,
    pub should_quit: bool,

    // Internal async event channels
    pub scan_event_rx: Option<Receiver<ScanEvent>>,
    pub repair_event_rx: Option<Receiver<RepairEvent>>,
}

impl App {
    pub fn new() -> Self {
        let mut telemetry_collector = TelemetryCollector::new();
        let telemetry = Some(telemetry_collector.refresh());
        let admin_flag = is_admin();
        let engine = Arc::new(DiagnosticEngine::new());
        let audit_logger = AuditLogger::new();
        let reg_backup_mgr = RegBackupManager::new();
        let audit_entries = audit_logger.get_history();
        let backup_records = reg_backup_mgr.list_backups();

        let mut module_progress_list = Vec::new();
        let mut module_statuses = Vec::new();

        for m in engine.modules() {
            module_progress_list.push((
                m.id().to_string(),
                m.name().to_string(),
                m.icon().to_string(),
                0u8,
                false,
            ));
            module_statuses.push((
                m.id().to_string(),
                m.name().to_string(),
                m.icon().to_string(),
                ModuleStatus::Idle,
            ));
        }

        Self {
            active_tab: 0,
            is_admin: admin_flag,
            config: AppConfig::load(),
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
            status_message: Some("Bereit".to_string()),
            show_help: false,
            should_quit: false,
            scan_event_rx: None,
            repair_event_rx: None,
        }
    }

    pub fn refresh_telemetry(&mut self) {
        self.telemetry = Some(self.telemetry_collector.refresh());
    }

    pub fn start_scan(&mut self) {
        if self.is_scanning || self.is_fixing {
            return;
        }

        self.is_scanning = true;
        self.scan_overall_progress = 0;
        self.active_tab = 1; // Switch to Scanner Tab
        self.issues.clear();
        self.selected_issue_index = 0;
        self.scan_log_messages.clear();
        self.scan_log_messages.push("Starte vollständigen System-Health-Scan...".to_string());

        for item in &mut self.module_progress_list {
            item.3 = 0;
            item.4 = false;
        }
        for item in &mut self.module_statuses {
            item.3 = ModuleStatus::Scanning;
        }

        let (tx, rx) = channel::<ScanEvent>(100);
        self.scan_event_rx = Some(rx);

        let engine_clone = self.engine.clone();
        tokio::spawn(async move {
            engine_clone.run_scan(tx).await;
        });

        self.status_message = Some("Diagnose-Scan läuft...".to_string());
    }

    pub fn start_repairs(&mut self) {
        if self.is_fixing || self.is_scanning {
            return;
        }

        let selected_count = self.issues.iter().filter(|i| i.is_selected && !i.is_fixed).count();
        if selected_count == 0 {
            self.status_message = Some("Keine offenen Probleme zur Reparatur ausgewählt.".to_string());
            return;
        }

        self.is_fixing = true;
        self.active_tab = 3; // Switch to Repair Center Tab
        self.fixed_count = 0;
        self.failed_count = 0;
        self.total_to_fix = selected_count;
        self.vss_status = "Initialisiere...".to_string();
        self.repair_console_lines.clear();
        self.repair_console_lines.push(format!("Starte Reparatur von {} ausgewählten Problemen...", selected_count));

        let (tx, rx) = channel::<RepairEvent>(100);
        self.repair_event_rx = Some(rx);

        let mut issues_clone = self.issues.clone();
        let engine_clone = self.engine.clone();
        let create_vss = self.config.create_vss_before_repair;

        tokio::spawn(async move {
            engine_clone.run_repairs(&mut issues_clone, create_vss, tx).await;
        });

        self.status_message = Some("Reparaturen werden ausgeführt...".to_string());
    }

    pub fn process_background_events(&mut self) {
        // 1. Process Scan Events
        let mut finished_scan = false;
        if let Some(ref mut rx) = self.scan_event_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    ScanEvent::ModuleStarted(mod_id) => {
                        self.scan_active_module_name = mod_id.clone();
                        self.scan_current_step_text = "Initialisiere Prüfung...".to_string();
                        if let Some(pos) = self.module_progress_list.iter().position(|m| m.0 == mod_id) {
                            self.scan_active_module_name = self.module_progress_list[pos].1.clone();
                        }
                    }
                    ScanEvent::ModuleProgressUpdate(prog) => {
                        self.scan_current_step_text = prog.current_step.clone();
                        if let Some(pos) = self.module_progress_list.iter().position(|m| m.0 == prog.module_id) {
                            self.module_progress_list[pos].3 = prog.progress_percent;
                        }
                        if let Some(msg) = prog.log_message {
                            self.scan_log_messages.push(msg);
                        }
                        let total_mods = self.module_progress_list.len().max(1);
                        let sum_progress: usize = self.module_progress_list.iter().map(|m| m.3 as usize).sum();
                        self.scan_overall_progress = (sum_progress / total_mods) as u8;
                    }
                    ScanEvent::ModuleFinished { module_id, issues } => {
                        if let Some(pos) = self.module_progress_list.iter().position(|m| m.0 == module_id) {
                            self.module_progress_list[pos].3 = 100;
                            self.module_progress_list[pos].4 = true;
                        }
                        if let Some(pos) = self.module_statuses.iter().position(|m| m.0 == module_id) {
                            let crit = issues.iter().filter(|i| i.severity == Severity::Critical).count();
                            let warn = issues.iter().filter(|i| i.severity == Severity::Warning).count();
                            if crit > 0 {
                                self.module_statuses[pos].3 = ModuleStatus::Critical(crit);
                            } else if warn > 0 {
                                self.module_statuses[pos].3 = ModuleStatus::Warning(warn);
                            } else {
                                self.module_statuses[pos].3 = ModuleStatus::Passed;
                            }
                        }
                        self.issues.extend(issues);
                        self.scan_log_messages.push(format!("Modul '{}' abgeschlossen.", module_id));
                    }
                    ScanEvent::ModuleFailed { module_id, error } => {
                        if let Some(pos) = self.module_statuses.iter().position(|m| m.0 == module_id) {
                            self.module_statuses[pos].3 = ModuleStatus::Failed(error.clone());
                        }
                        self.scan_log_messages.push(format!("Fehler in Modul '{}': {}", module_id, error));
                    }
                    ScanEvent::ScanCompleted { total_issues, health_score } => {
                        self.health_score = health_score;
                        self.scan_overall_progress = 100;
                        self.is_scanning = false;
                        finished_scan = true;
                        self.status_message = Some(format!("Scan abgeschlossen: {} Probleme gefunden (Health: {}/100)", total_issues, health_score));
                    }
                }
            }
        }
        if finished_scan {
            self.scan_event_rx = None;
            self.audit_entries = self.audit_logger.get_history();
        }

        // 2. Process Repair Events
        let mut finished_repair = false;
        if let Some(ref mut rx) = self.repair_event_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    RepairEvent::VssStarted => {
                        self.vss_status = "Erstelle Restore Point...".to_string();
                        self.repair_console_lines.push("Erstelle Windows Systemwiederherstellungspunkt (VSS)...".to_string());
                    }
                    RepairEvent::VssCompleted { success, message } => {
                        self.vss_status = if success { "Erstellt (OK)".to_string() } else { "Hinweis".to_string() };
                        self.repair_console_lines.push(format!("VSS: {}", message));
                    }
                    RepairEvent::FixStarted { issue_id: _, title } => {
                        self.current_fix_title = title.clone();
                        self.repair_console_lines.push(format!("Repariere: {}", title));
                    }
                    RepairEvent::FixOutput { issue_id: _, line } => {
                        self.repair_console_lines.push(line);
                    }
                    RepairEvent::FixFinished { issue_id, success, message } => {
                        if let Some(issue) = self.issues.iter_mut().find(|i| i.id == issue_id) {
                            issue.is_fixed = success;
                            if !success {
                                issue.fix_error = Some(message.clone());
                            }
                        }
                        if success {
                            self.fixed_count += 1;
                            self.repair_console_lines.push(format!("✔ Erfolgreich: {}", message));
                        } else {
                            self.failed_count += 1;
                            self.repair_console_lines.push(format!("✖ Fehler: {}", message));
                        }
                    }
                    RepairEvent::AllRepairsCompleted { fixed_count, failed_count } => {
                        self.is_fixing = false;
                        finished_repair = true;
                        self.fixed_count = fixed_count;
                        self.failed_count = failed_count;
                        self.health_score = DiagnosticEngine::calculate_health_score(&self.issues);
                        self.status_message = Some(format!("Reparatur fertig: {} behoben, {} fehlgeschlagen", fixed_count, failed_count));
                    }
                }
            }
        }
        if finished_repair {
            self.repair_event_rx = None;
            self.audit_entries = self.audit_logger.get_history();
            self.backup_records = self.reg_backup_mgr.list_backups();
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

    pub fn load_history_data(&mut self) {
        self.audit_entries = self.audit_logger.get_history();
        self.backup_records = self.reg_backup_mgr.list_backups();
    }
}
