//! Draining the scan, repair and background channels into application state.
//!
//! Called once per frame from the TUI loop. Everything here is non-blocking:
//! `try_recv` until empty, never awaiting, so a slow producer cannot stall
//! rendering.

use super::state::App;
use super::{BackgroundEvent, push_bounded_log};
use crate::engine::issue::Severity;
use crate::engine::runner::{DiagnosticEngine, RepairEvent, ScanEvent};
use crate::modules::ModuleStatus;

impl App {
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
}
