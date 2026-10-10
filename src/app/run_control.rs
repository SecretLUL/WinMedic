//! Starting, cancelling and simulating scans and repair runs.

use super::TAB_HOME;
use super::state::{App, repair_waits_for_restart};
use crate::engine::runner::{RepairEvent, RepairOptions, ScanEvent};
use crate::modules::ModuleStatus;
use std::time::Instant;
use tokio::sync::mpsc::channel;
use tokio_util::sync::CancellationToken;

impl App {
    pub fn start_scan(&mut self) {
        if self.is_busy() {
            return;
        }

        self.is_scanning = true;
        self.scan_overall_progress = 0;
        self.scan_started_at = Some(Instant::now());
        self.active_tab = TAB_HOME;
        // What was decided against the findings on screen carries over to
        // the new scan's, see `carry_over`. A repair that waits for the
        // restart stays: no restart can have happened while this process
        // ran, and the scan may no longer report it.
        self.last_findings = self
            .issues
            .iter()
            .chain(&self.archived_issues)
            .cloned()
            .collect();
        self.issues.retain(repair_waits_for_restart);
        self.archived_issues.retain(repair_waits_for_restart);
        self.selected_issue_index = 0;
        self.selected_filtered_index = 0;
        self.scan_log_messages.clear();
        self.push_scan_log("Starting a full system health scan...");

        for item in &mut self.module_progress_list {
            item.reset();
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

        self.status_message = Some("Diagnostic scan running... [Esc] cancels".to_string());
    }

    pub fn start_repairs(&mut self) {
        self.start_repairs_with(self.config.create_vss_before_repair);
    }

    /// Repair the same selection again, without the restore point Windows
    /// would not create; the user said yes to that.
    pub fn start_repairs_without_restore_point(&mut self) {
        self.start_repairs_with(false);
    }

    fn start_repairs_with(&mut self, create_vss: bool) {
        if self.is_busy() {
            return;
        }

        let selected_count = self.issues.iter().filter(|i| i.will_repair()).count();
        if selected_count == 0 {
            self.status_message = Some("No open issues selected for repair.".to_string());
            return;
        }

        self.is_fixing = true;
        self.active_tab = TAB_HOME;
        self.fixed_count = 0;
        self.failed_count = 0;
        self.total_to_fix = selected_count;
        self.vss_status = if self.dry_run {
            "Simulation".to_string()
        } else if !create_vss {
            "Skipped".to_string()
        } else {
            "Initialising...".to_string()
        };
        self.repair_console_lines.clear();
        self.push_repair_log(if self.dry_run {
            format!(
                "SIMULATION: showing the planned steps for {} issues. Nothing will be changed.",
                selected_count
            )
        } else {
            format!("Starting repairs for {} selected issues...", selected_count)
        });

        let (tx, rx) = channel::<RepairEvent>(100);
        self.repair_event_rx = Some(rx);

        let cancel = CancellationToken::new();
        self.cancel_token = Some(cancel.clone());

        let mut issues_clone = self.issues.clone();
        let engine_clone = self.engine.clone();
        let options = RepairOptions {
            create_vss,
            ..RepairOptions::from_config(&self.config, self.dry_run)
        };

        tokio::spawn(async move {
            engine_clone
                .run_repairs(&mut issues_clone, options, tx, cancel)
                .await;
        });

        self.status_message = Some(if self.dry_run {
            "Simulation running... [Esc] cancels".to_string()
        } else {
            "Running repairs... [Esc] cancels".to_string()
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
        let target = if self.is_scanning { "Scan" } else { "Repair" };
        self.status_message = Some(format!("Cancelling the {}...", target.to_lowercase()));
        let line = format!(
            "[STOP] Cancellation requested - stopping the running {}.",
            target.to_lowercase()
        );
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
            self.status_message =
                Some("Simulation mode cannot be changed while a run is in progress.".to_string());
            return;
        }
        self.dry_run = !self.dry_run;
        self.status_message = Some(if self.dry_run {
            "Simulation mode ON - [F] only shows the planned steps.".to_string()
        } else {
            "Simulation mode OFF - [F] really executes repairs.".to_string()
        });
    }
}
