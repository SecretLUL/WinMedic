//! Draining the scan, repair and background channels into application state.
//!
//! Called once per frame from the TUI loop. Everything here is non-blocking:
//! `try_recv` until empty, never awaiting, so a slow producer cannot stall
//! rendering.

use super::ConfirmRequest;
use super::state::{App, ModuleScanProgress};
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
            self.scan_started_at = None;
            self.scan_event_rx = None;
            self.cancel_token = None;
            self.audit_entries = self.audit_logger.get_history();
            self.save_scan_state();
        }
    }

    fn process_repair_events(&mut self) {
        let mut repair_ended = false;
        if let Some(ref mut rx) = self.repair_event_rx {
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
                        self.current_fix_title = title.clone();
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
        }
        if repair_ended {
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
                            // Deliberately explicit about the restart: the
                            // process still running is the old build, and a
                            // "done" that let someone believe otherwise would be
                            // a lie about which code is executing.
                            self.status_message = Some(format!(
                                "WinMedic v{} installed and SHA256-verified. Restart WinMedic to run it.",
                                version
                            ));
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
            retired: PathBuf::from(r"C:\Tools\winmedic.exe.old-v0.2.0"),
            sha256: "a".repeat(64),
            signature: SignatureStatus::Unsigned,
        }
    }

    /// The process still running is the *old* build — the new one only starts
    /// existing at the next launch. Saying "updated" and stopping there would be
    /// a claim about which code is executing that is simply not true.
    #[tokio::test]
    async fn an_installed_update_clears_the_notice_and_asks_for_a_restart() {
        let (mut app, dir) = app_with_scratch_audit_log();
        app.available_update = None;

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
        assert!(message.contains("Restart"), "{}", message);

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
