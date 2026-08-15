//! Starting, cancelling and simulating scans and repair runs.

use super::state::App;
use super::{TAB_REPAIR, TAB_SCANNER};
use crate::engine::runner::{RepairEvent, RepairOptions, ScanEvent};
use crate::modules::ModuleStatus;
use tokio::sync::mpsc::channel;
use tokio_util::sync::CancellationToken;

use super::confirm::ConfirmRequest;

impl App {
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
}
