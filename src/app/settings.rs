//! Settings tab navigation and persistence.

use super::state::App;
use crate::config::AppConfig;
use crate::engine::runner::DiagnosticEngine;
use std::sync::Arc;

impl App {
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
                    "Setting saved: {}",
                    AppConfig::config_path().display()
                ));
            }
            Err(e) => {
                self.status_message = Some(format!("Setting could not be saved: {}", e));
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_navigation_wraps_in_both_directions() {
        let mut app = App::new();
        app.selected_setting_index = 0;

        app.prev_setting();
        assert_eq!(app.selected_setting_index, AppConfig::SETTING_COUNT - 1);

        app.next_setting();
        assert_eq!(app.selected_setting_index, 0);
    }

    #[test]
    fn every_reachable_index_has_a_label() {
        let mut app = App::new();
        for _ in 0..AppConfig::SETTING_COUNT * 2 {
            assert!(
                app.config.setting_row(app.selected_setting_index).is_some(),
                "index {} has no label",
                app.selected_setting_index
            );
            app.next_setting();
        }
    }
}
