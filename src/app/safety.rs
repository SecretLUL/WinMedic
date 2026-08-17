//! Backups, restore points and rollback requests — the safety half of the
//! "Settings & Safety" tab.

use super::BackgroundEvent;
use super::confirm::ConfirmRequest;
use super::state::{App, SafetyFocus};
use crate::safety::reg_backup::BackupRecord;
use crate::safety::restore_point::list_restore_points;

impl App {
    /// Refresh the audit log and backup list shown on the Settings & Safety tab.
    ///
    /// Called whenever that tab is opened, from any direction — the direct `[5]`
    /// jump, `[Tab]`, or the `←`/`→` arrows.
    pub fn load_safety_data(&mut self) {
        self.audit_entries = self.audit_logger.get_history();
        self.backup_records = self.reg_backup_mgr.list_backups();
        self.clamp_backup_selection();

        // Querying VSS costs a PowerShell round trip, so only do it the first
        // time the tab is opened. [R] forces a refresh afterwards.
        if !self.restore_points_requested {
            self.refresh_restore_points();
        }
    }

    /// Move the `↑`/`↓` keys between the settings list and the backup list.
    ///
    /// Both panes live on the same tab and both want the arrow keys, so one of
    /// them has to hold focus. `[B]` is the toggle.
    pub fn toggle_safety_focus(&mut self) {
        self.safety_focus = match self.safety_focus {
            SafetyFocus::Settings => SafetyFocus::Backups,
            SafetyFocus::Backups => SafetyFocus::Settings,
        };
    }

    /// True while the backup list owns the arrow keys.
    pub fn backups_focused(&self) -> bool {
        self.safety_focus == SafetyFocus::Backups
    }

    pub fn refresh_restore_points(&mut self) {
        if self.restore_points_loading {
            return;
        }
        // Merging this tab into Settings means every `[Tab]` and `→` that lands
        // on tab 5 now reaches this, including from the synchronous key-dispatch
        // tests. `tokio::spawn` panics outside a runtime, so ask rather than
        // assume — same reasoning as `App::start_update_check`.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        self.restore_points_requested = true;
        self.restore_points_loading = true;
        let tx = self.bg_tx.clone();
        handle.spawn(async move {
            let points = list_restore_points().await;
            let _ = tx.send(BackgroundEvent::RestorePointsLoaded(points));
        });
    }

    pub(super) fn clamp_backup_selection(&mut self) {
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
                Some("A rollback cannot start while another operation is running.".to_string());
            return;
        }

        let ordered = self.backups_newest_first();
        let Some(record) = ordered.get(self.selected_backup_index) else {
            self.status_message = Some(
                "No registry backup available. Backups are created by registry fixes.".to_string(),
            );
            return;
        };

        self.pending_confirm = Some(ConfirmRequest::Rollback {
            description: record.description.clone(),
            key_path: record.key_path.clone(),
            file_path: record.file_path.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> BackupRecord {
        BackupRecord {
            id: id.to_string(),
            timestamp: "2026-01-01 12:00:00".to_string(),
            description: format!("backup {}", id),
            key_path: format!("HKCU\\Test\\{}", id),
            file_path: format!("C:\\backups\\{}.reg", id),
        }
    }

    #[test]
    fn backup_navigation_wraps_and_reads_newest_first() {
        let mut app = App::new();
        app.backup_records = vec![record("a"), record("b"), record("c")];

        // Records are stored oldest first but presented newest first.
        assert_eq!(app.backups_newest_first()[0].id, "c");

        assert_eq!(app.selected_backup_index, 0);
        app.prev_backup();
        assert_eq!(app.selected_backup_index, 2);
        app.next_backup();
        assert_eq!(app.selected_backup_index, 0);
    }

    #[test]
    fn backup_navigation_on_an_empty_list_does_not_panic() {
        let mut app = App::new();
        app.backup_records.clear();
        app.next_backup();
        app.prev_backup();
        assert_eq!(app.selected_backup_index, 0);
    }

    #[test]
    fn selection_is_clamped_when_the_record_list_shrinks() {
        let mut app = App::new();
        app.backup_records = vec![record("a"), record("b"), record("c")];
        app.selected_backup_index = 2;

        app.backup_records.truncate(1);
        app.clamp_backup_selection();
        assert_eq!(app.selected_backup_index, 0);
    }

    #[test]
    fn rollback_without_any_backup_explains_itself_instead_of_confirming() {
        let mut app = App::new();
        app.backup_records.clear();
        app.pending_confirm = None;

        app.request_rollback();

        assert!(app.pending_confirm.is_none(), "nothing to confirm");
        assert!(
            app.status_message
                .is_some_and(|m| m.contains("No registry backup"))
        );
    }

    #[test]
    fn rollback_targets_the_record_the_list_is_showing() {
        let mut app = App::new();
        app.backup_records = vec![record("a"), record("b"), record("c")];
        app.pending_confirm = None;
        // Index 0 of the rendered list is the *newest* record.
        app.selected_backup_index = 0;

        app.request_rollback();

        match app.pending_confirm {
            Some(ConfirmRequest::Rollback { ref key_path, .. }) => {
                assert!(
                    key_path.ends_with('c'),
                    "expected the newest, got {key_path}"
                );
            }
            _ => panic!("expected a rollback confirmation"),
        }
    }

    #[test]
    fn focus_toggles_between_the_settings_list_and_the_backup_list() {
        let mut app = App::new();
        assert!(
            !app.backups_focused(),
            "the settings list starts with the arrow keys"
        );

        app.toggle_safety_focus();
        assert!(app.backups_focused());

        app.toggle_safety_focus();
        assert!(!app.backups_focused());
    }

    #[test]
    fn rollback_is_refused_while_another_operation_runs() {
        let mut app = App::new();
        app.backup_records = vec![record("a")];
        app.pending_confirm = None;
        app.is_scanning = true;

        app.request_rollback();

        assert!(
            app.pending_confirm.is_none(),
            "a rollback must not start mid-scan"
        );
    }
}
