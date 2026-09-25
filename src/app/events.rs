//! Draining the scan, repair and background channels into application state.
//!
//! Called once per frame from the front end, out of `eframe::App::logic` —
//! which runs even while the window is hidden, so a scan does not appear to
//! stall when it is minimised. Everything here is non-blocking: `try_recv`
//! until empty, never awaiting, so a slow producer cannot stall rendering.

use super::ConfirmRequest;
use super::state::{App, ModuleScanProgress};
use super::{BackgroundEvent, push_bounded_log};
use crate::engine::runner::{DiagnosticEngine, RepairEvent, ScanEvent};
use crate::modules::ModuleStatus;
use crate::utils::progress::percent;
use std::time::Instant;

impl App {
    pub fn process_background_events(&mut self) {
        self.process_scan_events();
        self.process_repair_events();
        self.process_bg_events();
        self.restart_into_update_when_idle();
    }

    fn module_progress_mut(&mut self, module_id: &str) -> Option<&mut ModuleScanProgress> {
        self.module_progress_list
            .iter_mut()
            .find(|m| m.id == module_id)
    }

    /// The overall bar is the mean of the per-module bars.
    ///
    /// Modules run concurrently, so there is no single "current" module whose
    /// progress could stand in for the run — averaging is what makes the bar
    /// keep moving while one module is stuck on a slow external command.
    fn recalculate_scan_progress(&mut self) {
        let total = self.module_progress_list.len().max(1);
        let sum: usize = self
            .module_progress_list
            .iter()
            .map(|m| m.percent as usize)
            .sum();
        self.scan_overall_progress = (sum / total) as u8;
    }

    fn process_scan_events(&mut self) {
        // Drained into a batch first so that handling an event can reach the
        // rest of `App` — holding the receiver borrowed across the match would
        // pin all of `self` for the duration.
        let mut batch = Vec::new();
        if let Some(ref mut rx) = self.scan_event_rx {
            while let Ok(event) = rx.try_recv() {
                batch.push(event);
            }
        }

        let mut scan_ended = false;
        for event in batch {
            match event {
                ScanEvent::ModuleStarted(mod_id) => {
                    if let Some(module) = self.module_progress_mut(&mod_id) {
                        module.set_step("Starting up...");
                    }
                }
                ScanEvent::ModuleProgressUpdate(prog) => {
                    if let Some(module) = self.module_progress_mut(&prog.module_id) {
                        module.percent = prog.progress_percent;
                        module.set_step(&prog.current_step);
                    }
                    if let Some(msg) = prog.log_message {
                        push_bounded_log(&mut self.scan_log_messages, msg);
                    }
                    self.recalculate_scan_progress();
                }
                ScanEvent::ModuleFinished { module_id, issues } => {
                    if let Some(module) = self.module_progress_mut(&module_id) {
                        module.percent = 100;
                        module.is_done = true;
                        module.set_step(&format!(
                            "Finished - {}",
                            match issues.len() {
                                0 => "nothing to report".to_string(),
                                1 => "1 finding".to_string(),
                                n => format!("{} findings", n),
                            }
                        ));
                    }
                    if let Some(pos) = self.module_statuses.iter().position(|m| m.0 == module_id) {
                        self.module_statuses[pos].3 = ModuleStatus::from_findings(&issues);
                    }
                    self.issues.extend(issues);
                    self.recalculate_scan_progress();
                    push_bounded_log(
                        &mut self.scan_log_messages,
                        format!("Module '{}' finished.", module_id),
                    );
                }
                ScanEvent::ModuleFailed { module_id, error } => {
                    // A module that gave up is no longer making progress.
                    // Leaving its row mid-bar left it spinning for the rest
                    // of the scan as though it were still working.
                    if let Some(module) = self.module_progress_mut(&module_id) {
                        module.percent = 100;
                        module.is_done = true;
                        module.failure = Some(error.clone());
                        module.set_step(&format!("Failed - {}", error));
                    }
                    if let Some(pos) = self.module_statuses.iter().position(|m| m.0 == module_id) {
                        self.module_statuses[pos].3 = ModuleStatus::Failed(error.clone());
                    }
                    self.recalculate_scan_progress();
                    push_bounded_log(
                        &mut self.scan_log_messages,
                        format!("Error in module '{}': {}", module_id, error),
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
                    // Nothing is running any more, so nothing should still
                    // be animating a step it will never complete.
                    for module in &mut self.module_progress_list {
                        if !module.is_done {
                            module.is_done = true;
                            module.set_step("Cancelled");
                        }
                    }
                    let msg = format!(
                        "Scan cancelled after {}/{} modules ({} partial findings kept).",
                        completed_modules,
                        total_modules,
                        self.issues.len()
                    );
                    push_bounded_log(&mut self.scan_log_messages, format!("[STOP] {}", msg));
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
                        "Scan finished: {} issues found (health: {}/100)",
                        total_issues, health_score
                    ));
                }
            }
        }
        if scan_ended {
            // Freeze the clock. Left running, "DIAGNOSTICS COMPLETE" would go
            // on counting up for as long as the app stayed open.
            self.scan_duration = self.scan_started_at.map(|start| start.elapsed());
            self.last_scan_timestamp =
                Some(chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
            self.scan_started_at = None;
            self.scan_event_rx = None;
            self.cancel_token = None;
            self.audit_entries = self.audit_logger.get_history();
            self.save_scan_state();
        }
    }

    /// A step of the repair run begins; its clock and percentage start over.
    fn start_repair_step(&mut self, title: &str) {
        self.current_fix_title = title.to_string();
        self.repair_step_since = Some(Instant::now());
        self.repair_step_percent = None;
    }

    fn end_repair_step(&mut self) {
        self.repair_step_since = None;
        self.repair_step_percent = None;
    }

    /// DISM and SFC redraw their progress on one line, and so does the log:
    /// the step's newest percentage replaces the one before it rather than
    /// adding a line for every tenth of a percent.
    fn push_fix_output(&mut self, line: String) {
        if let Some(step_percent) = percent(&line) {
            let redraw = self.repair_step_percent.is_some()
                && self
                    .repair_console_lines
                    .back()
                    .is_some_and(|last| percent(last).is_some());
            self.repair_step_percent = Some(step_percent);
            if redraw && let Some(last) = self.repair_console_lines.back_mut() {
                *last = line;
                return;
            }
        }
        push_bounded_log(&mut self.repair_console_lines, line);
    }

    fn process_repair_events(&mut self) {
        let mut repair_ended = false;
        // Taken out while it drains, so that handling an event can reach the
        // rest of `App`; see `process_scan_events`.
        if let Some(mut rx) = self.repair_event_rx.take() {
            while let Ok(event) = rx.try_recv() {
                match event {
                    RepairEvent::DryRunStarted { issue_count } => {
                        self.vss_status = "Simulation (no VSS)".to_string();
                        push_bounded_log(
                            &mut self.repair_console_lines,
                            format!(
                                "Simulating {} repair(s) - no restore point needed.",
                                issue_count
                            ),
                        );
                    }
                    RepairEvent::VssStarted => {
                        self.start_repair_step("Creating a restore point");
                        self.vss_status = "Creating restore point...".to_string();
                        push_bounded_log(
                            &mut self.repair_console_lines,
                            "Creating a Windows System Restore point (VSS)...",
                        );
                    }
                    RepairEvent::VssCompleted { success, message } => {
                        self.vss_status = if success {
                            "Created (OK)".to_string()
                        } else {
                            "Notice".to_string()
                        };
                        push_bounded_log(
                            &mut self.repair_console_lines,
                            format!("VSS: {}", message),
                        );
                    }
                    RepairEvent::FixStarted { issue_id: _, title } => {
                        self.start_repair_step(&title);
                        push_bounded_log(
                            &mut self.repair_console_lines,
                            if self.dry_run {
                                format!("Simulating: {}", title)
                            } else {
                                format!("Repairing: {}", title)
                            },
                        );
                    }
                    RepairEvent::FixOutput { issue_id: _, line } => {
                        self.push_fix_output(line);
                    }
                    RepairEvent::FixFinished {
                        issue_id,
                        success,
                        message,
                    } => {
                        self.end_repair_step();
                        // A simulation must never flip an issue to "fixed".
                        if !self.dry_run
                            && let Some(issue) = self.issues.iter_mut().find(|i| i.id == issue_id)
                        {
                            if success {
                                if issue.requires_reboot {
                                    issue.is_reboot_pending = true;
                                    issue.is_fixed = false;
                                    issue.is_selected = false;
                                } else {
                                    issue.is_fixed = true;
                                    issue.is_reboot_pending = false;
                                }
                                issue.fix_error = None;
                            } else {
                                issue.is_fixed = false;
                                issue.is_reboot_pending = false;
                                issue.fix_error = Some(message.clone());
                            }
                        }
                        if success {
                            self.fixed_count += 1;
                            push_bounded_log(
                                &mut self.repair_console_lines,
                                format!("[OK] {}", message),
                            );
                        } else {
                            self.failed_count += 1;
                            push_bounded_log(
                                &mut self.repair_console_lines,
                                format!("[X] Error: {}", message),
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
                            "Repairs cancelled: {} done, {} failed, {} never attempted.",
                            fixed_count, failed_count, remaining
                        );
                        push_bounded_log(&mut self.repair_console_lines, format!("[STOP] {}", msg));
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
                                "Simulation finished: {} repair(s) planned, nothing changed.",
                                fixed_count
                            )
                        } else {
                            format!(
                                "Repairs finished: {} fixed, {} failed",
                                fixed_count, failed_count
                            )
                        });

                        if !self.dry_run {
                            let reboot_issues: Vec<String> = self
                                .issues
                                .iter()
                                .filter(|i| i.is_reboot_pending)
                                .map(|i| i.title.clone())
                                .collect();
                            if !reboot_issues.is_empty() {
                                self.pending_confirm = Some(ConfirmRequest::RestartRequired {
                                    issues: reboot_issues,
                                });
                            }
                        }
                    }
                }
            }
            self.repair_event_rx = Some(rx);
        }
        if repair_ended {
            self.current_fix_title.clear();
            self.end_repair_step();
            self.repair_event_rx = None;
            self.cancel_token = None;
            self.audit_entries = self.audit_logger.get_history();
            self.backup_records = self.reg_backup_mgr.list_backups();
            self.clamp_backup_selection();
            self.save_scan_state();
        }
    }

    fn process_bg_events(&mut self) {
        while let Ok(event) = self.bg_rx.try_recv() {
            match event {
                BackgroundEvent::RestorePointsLoaded(points) => {
                    self.restore_points_loading = false;
                    self.status_message = Some(if points.is_empty() {
                        "No Windows restore points found.".to_string()
                    } else {
                        format!("{} restore points loaded.", points.len())
                    });
                    self.vss_restore_points = points;
                }
                BackgroundEvent::RollbackFinished { success, message } => {
                    self.is_restoring = false;
                    self.status_message = Some(message.clone());
                    self.audit_logger.log(
                        "RESTORE",
                        "reg_backup",
                        "Registry rollback",
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
                        "Update available: v{} (current: v{}) - [U] for details",
                        info.latest_version.trim_start_matches(['v', 'V']),
                        info.current_version.trim_start_matches(['v', 'V'])
                    ));
                    self.available_update = Some(info);
                }
                BackgroundEvent::UpdateChecked(None) => {}
                BackgroundEvent::UpdateInstallStep(step) => {
                    // A step that arrives after the run finished would overwrite
                    // the outcome the user is reading.
                    if self.is_updating {
                        self.status_message = Some(step);
                    }
                }
                BackgroundEvent::UpdateInstallFinished {
                    version,
                    release_url,
                    result,
                } => {
                    self.is_updating = false;
                    let version = version.trim_start_matches(['v', 'V']).to_string();

                    match result {
                        Ok(installed) => {
                            self.audit_logger.log(
                                "UPDATE",
                                "self_update",
                                &format!("Installed WinMedic v{}", version),
                                "SUCCESS",
                                &format!(
                                    "sha256={} | {} | replaced binary parked at {}",
                                    installed.sha256,
                                    installed.signature.summary(),
                                    installed.retired.display()
                                ),
                            );
                            self.available_update = None;
                            let installed_as = match installed.installed.file_name() {
                                Some(name) if installed.installed != installed.replaced => {
                                    format!(" as {}", name.to_string_lossy())
                                }
                                _ => String::new(),
                            };
                            // A run in flight keeps the window open until it
                            // ends; see `restart_into_update_when_idle`.
                            let restart = if self.is_busy() || self.is_restoring {
                                "WinMedic restarts when the current run is finished."
                            } else {
                                "Restarting..."
                            };
                            let mut message = format!(
                                "WinMedic v{version} installed and SHA256-verified{installed_as}. {restart}"
                            );
                            if installed.installed != installed.replaced {
                                // The task and the Run entry still name the
                                // file that is now gone.
                                if let Err(e) = (self.system_actions.reconcile_background)(
                                    &self.config,
                                    &installed.installed,
                                ) {
                                    message.push_str(&format!(
                                        " Background scan / autostart still point at the old file: {e}"
                                    ));
                                }
                            }
                            self.status_message = Some(message);
                            self.restart_into = Some(installed.installed);
                        }
                        Err(err) => {
                            self.audit_logger.log(
                                "UPDATE",
                                "self_update",
                                &format!("Did not install WinMedic v{}", version),
                                err.kind(),
                                &err.reason(),
                            );
                            self.fall_back_to_browser(&release_url, &err.reason());
                        }
                    }
                    self.audit_entries = self.audit_logger.get_history();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::ModuleProgress;
    use crate::safety::audit::AuditLogger;
    use crate::utils::self_update::{InstalledUpdate, SignatureStatus, UpdateFailure};
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::sync::mpsc::channel;

    /// An app with a scan in flight, and the sender feeding it.
    fn scanning_app() -> (App, tokio::sync::mpsc::Sender<ScanEvent>) {
        let mut app = App::new();
        let (tx, rx) = channel::<ScanEvent>(64);
        app.scan_event_rx = Some(rx);
        app.is_scanning = true;
        app.scan_started_at = Some(std::time::Instant::now());
        (app, tx)
    }

    fn progress(module_id: &str, percent: u8, step: &str) -> ScanEvent {
        ScanEvent::ModuleProgressUpdate(ModuleProgress {
            module_id: module_id.to_string(),
            progress_percent: percent,
            current_step: step.to_string(),
            log_message: None,
        })
    }

    fn find<'a>(app: &'a App, id: &str) -> &'a ModuleScanProgress {
        app.module_progress_list
            .iter()
            .find(|m| m.id == id)
            .expect("module is registered")
    }

    /// Every module keeps its own step, rather than all of them sharing one
    /// line that showed whichever module reported most recently.
    #[tokio::test]
    async fn each_module_reports_its_own_step() {
        let (mut app, tx) = scanning_app();

        tx.send(progress(
            "system_cleaner",
            10,
            "Analysing the WinSxS store...",
        ))
        .await
        .unwrap();
        tx.send(progress("network", 20, "Testing DNS name resolution..."))
            .await
            .unwrap();
        app.process_background_events();

        assert_eq!(
            find(&app, "system_cleaner").step,
            "Analysing the WinSxS store..."
        );
        assert_eq!(find(&app, "network").step, "Testing DNS name resolution...");
    }

    /// The clock on a step measures the step, not the last event to arrive.
    ///
    /// Modules re-send their current step as they emit log lines; restamping on
    /// every one of those would reset the timer of the very step slow enough to
    /// need it.
    #[tokio::test]
    async fn repeating_a_step_does_not_restart_its_clock() {
        let (mut app, tx) = scanning_app();

        tx.send(progress("system_cleaner", 10, "Analysing..."))
            .await
            .unwrap();
        app.process_background_events();
        let first = find(&app, "system_cleaner").step_since.expect("stamped");

        tx.send(progress("system_cleaner", 10, "Analysing..."))
            .await
            .unwrap();
        app.process_background_events();
        assert_eq!(find(&app, "system_cleaner").step_since, Some(first));

        tx.send(progress("system_cleaner", 22, "Checking the WUDO cache..."))
            .await
            .unwrap();
        app.process_background_events();
        assert!(
            find(&app, "system_cleaner").step_since > Some(first),
            "a genuinely new step does restart it"
        );
    }

    /// A module that gave up has stopped working and must stop looking busy.
    #[tokio::test]
    async fn a_failed_module_is_marked_finished() {
        let (mut app, tx) = scanning_app();

        tx.send(progress("event_log", 15, "Checking for BSOD minidumps..."))
            .await
            .unwrap();
        tx.send(ScanEvent::ModuleFailed {
            module_id: "event_log".to_string(),
            error: "access denied".to_string(),
        })
        .await
        .unwrap();
        app.process_background_events();

        let module = find(&app, "event_log");
        assert!(module.is_done, "it will not report again");
        assert_eq!(module.failure.as_deref(), Some("access denied"));
        assert_eq!(module.step_elapsed(), None, "and its clock has stopped");
    }

    /// The overall bar is the mean of the module bars, so it keeps moving even
    /// while one module sits on a slow external command.
    #[tokio::test]
    async fn overall_progress_averages_the_modules() {
        let (mut app, tx) = scanning_app();
        let total = app.module_progress_list.len();

        tx.send(progress("system_cleaner", 10, "Analysing..."))
            .await
            .unwrap();
        tx.send(progress("network", 80, "Checking Winsock..."))
            .await
            .unwrap();
        app.process_background_events();

        assert_eq!(app.scan_overall_progress as usize, 90 / total);
    }

    // ------------------------------------------------------ in-place updates

    /// An app whose audit log writes to a scratch directory instead of the
    /// developer's own `%APPDATA%\\WinMedic\\logs`.
    fn app_with_scratch_audit_log() -> (App, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "winmedic_events_audit_{}_{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut app = App::new();
        app.audit_logger = AuditLogger::with_dir_and_size(dir.clone(), 5 * 1024 * 1024);
        app.is_updating = true;
        (app, dir)
    }

    fn installed_update() -> InstalledUpdate {
        InstalledUpdate {
            installed: PathBuf::from(r"C:\Tools\winmedic.exe"),
            replaced: PathBuf::from(r"C:\Tools\winmedic.exe"),
            retired: PathBuf::from(r"C:\Tools\winmedic.exe.old-v0.2.0"),
            sha256: "a".repeat(64),
            signature: SignatureStatus::Unsigned,
        }
    }

    /// The process still running is the *old* build, so the new one is started
    /// and this one closes: after "Download and restart" the user is running
    /// the version they just installed.
    #[tokio::test]
    async fn an_installed_update_clears_the_notice_and_restarts_into_it() {
        static STARTED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

        let (mut app, dir) = app_with_scratch_audit_log();
        app.available_update = None;
        app.system_actions.start_installed_update = |exe| {
            *STARTED.lock().unwrap() = Some(exe.to_path_buf());
            Ok(())
        };

        app.bg_tx
            .send(BackgroundEvent::UpdateInstallFinished {
                version: "v0.2.0".to_string(),
                release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
                    .to_string(),
                result: Ok(installed_update()),
            })
            .unwrap();
        app.process_background_events();

        assert!(!app.is_updating);
        assert!(app.available_update.is_none());
        let message = app.status_message.clone().unwrap();
        assert!(message.contains("v0.2.0"), "{}", message);
        assert!(message.contains("SHA256-verified"), "{}", message);
        assert_eq!(
            STARTED.lock().unwrap().as_deref(),
            Some(std::path::Path::new(r"C:\Tools\winmedic.exe"))
        );
        assert!(app.should_quit);

        // Replacing the binary is exactly the kind of change this tool records.
        let entry = app
            .audit_entries
            .iter()
            .find(|e| e.action_type == "UPDATE")
            .expect("the install was not written to the audit log");
        assert_eq!(entry.status, "SUCCESS");
        assert!(entry.details.contains(&"a".repeat(64)));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A file that took the new release's name says so, the task and the Run
    /// entry follow it, and the restart starts it under that name.
    #[tokio::test]
    async fn a_renamed_install_names_the_new_file_and_moves_the_background_entries() {
        static RETARGETED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
        static STARTED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

        let (mut app, dir) = app_with_scratch_audit_log();
        app.system_actions.reconcile_background = |_, exe| {
            *RETARGETED.lock().unwrap() = Some(exe.to_path_buf());
            Ok(())
        };
        app.system_actions.start_installed_update = |exe| {
            *STARTED.lock().unwrap() = Some(exe.to_path_buf());
            Ok(())
        };
        let mut installed = installed_update();
        installed.replaced = PathBuf::from(r"C:\Tools\winmedic-v0.1.0.exe");
        installed.installed = PathBuf::from(r"C:\Tools\winmedic-v0.2.0.exe");

        app.bg_tx
            .send(BackgroundEvent::UpdateInstallFinished {
                version: "v0.2.0".to_string(),
                release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
                    .to_string(),
                result: Ok(installed),
            })
            .unwrap();
        app.process_background_events();

        let message = app.status_message.clone().unwrap();
        assert!(message.contains("as winmedic-v0.2.0.exe"), "{message}");
        assert_eq!(
            RETARGETED.lock().unwrap().as_deref(),
            Some(std::path::Path::new(r"C:\Tools\winmedic-v0.2.0.exe"))
        );
        assert_eq!(
            STARTED.lock().unwrap().as_deref(),
            Some(std::path::Path::new(r"C:\Tools\winmedic-v0.2.0.exe"))
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Closing the window under a repair run would leave the repair half done,
    /// so the restart waits for the run to end.
    #[tokio::test]
    async fn a_run_in_flight_holds_the_restart_until_it_ends() {
        let (mut app, dir) = app_with_scratch_audit_log();
        app.is_fixing = true;

        app.bg_tx
            .send(BackgroundEvent::UpdateInstallFinished {
                version: "v0.2.0".to_string(),
                release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
                    .to_string(),
                result: Ok(installed_update()),
            })
            .unwrap();
        app.process_background_events();

        assert!(!app.should_quit, "the restart cut the repair run short");
        let message = app.status_message.clone().unwrap();
        assert!(
            message.contains("when the current run is finished"),
            "{message}"
        );

        app.is_fixing = false;
        app.process_background_events();
        assert!(app.should_quit);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// An update that is installed but cannot be started leaves the window
    /// open and says how to get to the new version.
    #[tokio::test]
    async fn a_restart_that_cannot_start_the_update_stays_open_and_says_so() {
        let (mut app, dir) = app_with_scratch_audit_log();
        app.system_actions.start_installed_update = |_| Err("access denied".to_string());

        app.bg_tx
            .send(BackgroundEvent::UpdateInstallFinished {
                version: "v0.2.0".to_string(),
                release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
                    .to_string(),
                result: Ok(installed_update()),
            })
            .unwrap();
        app.process_background_events();

        assert!(!app.should_quit);
        assert!(app.restart_into.is_none(), "it would retry every frame");
        let message = app.status_message.clone().unwrap();
        assert!(message.contains("access denied"), "{message}");
        assert!(message.contains("Restart WinMedic"), "{message}");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The issue's fourth prerequisite, as a test: any failure ends with the
    /// user in front of the manual download and told why.
    #[tokio::test]
    async fn a_failed_install_falls_back_to_the_release_page_with_the_reason() {
        let (mut app, dir) = app_with_scratch_audit_log();

        app.bg_tx
            .send(BackgroundEvent::UpdateInstallFinished {
                version: "v0.2.0".to_string(),
                release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
                    .to_string(),
                result: Err(UpdateFailure::Verification(
                    "SHA256 mismatch - the release publishes abc, the download hashes to def"
                        .to_string(),
                )),
            })
            .unwrap();
        app.process_background_events();

        assert!(!app.is_updating);
        let message = app.status_message.clone().unwrap();
        assert!(message.contains("SHA256 mismatch"), "{}", message);
        assert!(message.contains("release page"), "{}", message);

        let entry = app
            .audit_entries
            .iter()
            .find(|e| e.action_type == "UPDATE")
            .expect("the refusal was not written to the audit log");
        assert_eq!(entry.status, "VERIFICATION");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A step queued just before the run ended must not overwrite the outcome
    /// the user is now reading.
    #[tokio::test]
    async fn a_late_progress_step_does_not_overwrite_the_outcome() {
        let (mut app, dir) = app_with_scratch_audit_log();

        app.bg_tx
            .send(BackgroundEvent::UpdateInstallStep(
                "Verifying the SHA256 checksum...".to_string(),
            ))
            .unwrap();
        app.process_background_events();
        assert_eq!(
            app.status_message.as_deref(),
            Some("Verifying the SHA256 checksum...")
        );

        app.bg_tx
            .send(BackgroundEvent::UpdateInstallFinished {
                version: "v0.2.0".to_string(),
                release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
                    .to_string(),
                result: Ok(installed_update()),
            })
            .unwrap();
        app.bg_tx
            .send(BackgroundEvent::UpdateInstallStep(
                "Installing the new binary...".to_string(),
            ))
            .unwrap();
        app.process_background_events();

        assert!(
            app.status_message
                .as_deref()
                .is_some_and(|m| m.contains("Restart")),
            "{:?}",
            app.status_message
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// "DIAGNOSTICS COMPLETE - 4:17 elapsed" has to stay at 4:17.
    #[tokio::test]
    async fn the_elapsed_clock_stops_when_the_scan_does() {
        let (mut app, tx) = scanning_app();
        app.scan_started_at = Some(std::time::Instant::now() - Duration::from_secs(90));

        tx.send(ScanEvent::ScanCompleted {
            total_issues: 0,
            health_score: 100,
        })
        .await
        .unwrap();
        app.process_background_events();

        let frozen = app.scan_elapsed().expect("the run was timed");
        assert!(frozen >= Duration::from_secs(90));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(app.scan_elapsed(), Some(frozen), "and it stays put");
    }

    /// An app repairing `total` findings, and the sender feeding it.
    fn repairing_app(total: usize) -> (App, tokio::sync::mpsc::Sender<RepairEvent>) {
        let mut app = App::new();
        let (tx, rx) = channel::<RepairEvent>(64);
        app.repair_event_rx = Some(rx);
        app.is_fixing = true;
        app.total_to_fix = total;
        (app, tx)
    }

    fn output(line: &str) -> RepairEvent {
        RepairEvent::FixOutput {
            issue_id: "sys_dism_corrupt".to_string(),
            line: line.to_string(),
        }
    }

    /// DISM's bar reaches the step, the progress bar and the log, where it
    /// takes one line however often it is redrawn.
    #[tokio::test]
    async fn a_step_follows_its_tools_percentage() {
        let (mut app, tx) = repairing_app(4);
        app.repair_console_lines.clear();
        tx.send(RepairEvent::FixStarted {
            issue_id: "sys_dism_corrupt".to_string(),
            title: "Windows component store is corrupted".to_string(),
        })
        .await
        .unwrap();
        for line in [
            "Image Version: 10.0.26200.9457",
            "[=   10.0%   ]",
            "[==  50.0%   ]",
        ] {
            tx.send(output(line)).await.unwrap();
        }
        app.process_background_events();

        assert_eq!(
            app.current_fix_title,
            "Windows component store is corrupted"
        );
        assert_eq!(app.repair_step_percent, Some(50.0));
        assert!(app.repair_step_elapsed().is_some());
        assert_eq!(app.repair_fraction(), 0.5 / 4.0);
        assert_eq!(
            Vec::from(app.repair_console_lines.clone()),
            [
                "Repairing: Windows component store is corrupted",
                "Image Version: 10.0.26200.9457",
                "[==  50.0%   ]",
            ]
        );

        tx.send(RepairEvent::FixFinished {
            issue_id: "sys_dism_corrupt".to_string(),
            success: true,
            message: "done".to_string(),
        })
        .await
        .unwrap();
        app.process_background_events();
        assert_eq!(app.repair_step_percent, None);
        assert_eq!(app.repair_step_elapsed(), None);
        assert_eq!(app.repair_fraction(), 1.0 / 4.0);
    }

    /// The next step's first bar is a line of its own, not a redraw of the
    /// last step's.
    #[tokio::test]
    async fn a_new_step_starts_its_own_progress_line() {
        let (mut app, tx) = repairing_app(2);
        app.repair_console_lines.clear();
        for title in ["first", "second"] {
            tx.send(RepairEvent::FixStarted {
                issue_id: title.to_string(),
                title: title.to_string(),
            })
            .await
            .unwrap();
            tx.send(output("[==========100.0%==========]"))
                .await
                .unwrap();
        }
        app.process_background_events();

        let bars = app
            .repair_console_lines
            .iter()
            .filter(|l| l.contains("100.0%"))
            .count();
        assert_eq!(bars, 2);
    }

    #[tokio::test]
    async fn repairs_requiring_reboot_trigger_restart_confirmation() {
        let mut app = App::new();
        app.issues.clear();
        let issue = crate::engine::issue::Issue::new(
            "wu_reboot_pending",
            "windows_updates",
            "System reboot pending after updates",
            "Windows Update & Services",
            crate::engine::issue::Severity::Info,
            crate::engine::issue::RiskScore::Low,
            "Description",
            "Details",
            "Fix",
            vec!["Step 1".to_string()],
        )
        .with_requires_reboot(true);

        app.issues.push(issue);
        let (tx, rx) = channel::<RepairEvent>(10);
        app.repair_event_rx = Some(rx);
        app.is_fixing = true;

        tx.send(RepairEvent::FixFinished {
            issue_id: "wu_reboot_pending".to_string(),
            success: true,
            message: "Pending reboot recorded.".to_string(),
        })
        .await
        .unwrap();

        tx.send(RepairEvent::AllRepairsCompleted {
            fixed_count: 1,
            failed_count: 0,
        })
        .await
        .unwrap();

        app.process_background_events();

        assert!(!app.is_fixing);
        assert!(app.issues[0].is_reboot_pending);
        assert!(!app.issues[0].is_fixed);
        assert!(app.has_pending_reboot());
        match app.pending_confirm {
            Some(ConfirmRequest::RestartRequired { ref issues }) => {
                assert_eq!(issues.len(), 1);
                assert_eq!(issues[0], "System reboot pending after updates");
            }
            other => panic!("expected RestartRequired confirm request, got {:?}", other),
        }
    }
}
