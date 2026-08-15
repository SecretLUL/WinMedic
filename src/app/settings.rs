use super::state::{App, SettingInput};
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
        let changed = match self.selected_setting_index {
            4 | 5 => self
                .config
                .adjust_setting(self.selected_setting_index, true),
            _ => self.config.toggle_setting(self.selected_setting_index),
        };
        if changed {
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

    /// Open a numeric input modal for threshold settings, or toggle boolean settings.
    pub fn open_setting_input(&mut self) {
        match self.selected_setting_index {
            4 => {
                self.setting_input = Some(SettingInput {
                    setting_index: 4,
                    setting_name: "Temp file threshold".to_string(),
                    unit: "MB".to_string(),
                    min_value: 0,
                    max_value: 1_000_000,
                    buffer: self.config.temp_clean_threshold_mb.to_string(),
                    error_msg: None,
                });
            }
            5 => {
                self.setting_input = Some(SettingInput {
                    setting_index: 5,
                    setting_name: "Event log analysis window".to_string(),
                    unit: "Hours (h)".to_string(),
                    min_value: 1,
                    max_value: 8760,
                    buffer: self.config.max_event_log_hours.to_string(),
                    error_msg: None,
                });
            }
            _ => {
                self.toggle_current_setting();
            }
        }
    }

    /// Validate and apply the value in the active setting input modal.
    pub fn submit_setting_input(&mut self) -> bool {
        let Some(input) = self.setting_input.as_mut() else {
            return false;
        };

        let trimmed = input.buffer.trim();
        if trimmed.is_empty() {
            input.error_msg = Some("Value cannot be empty.".to_string());
            return false;
        }

        let Ok(val) = trimmed.parse::<u64>() else {
            input.error_msg = Some("Please enter a valid positive whole number.".to_string());
            return false;
        };

        if val < input.min_value || val > input.max_value {
            input.error_msg = Some(format!(
                "Value must be between {} and {}.",
                input.min_value, input.max_value
            ));
            return false;
        }

        let idx = input.setting_index;
        match idx {
            4 => {
                self.config.temp_clean_threshold_mb = val;
            }
            5 => {
                self.config.max_event_log_hours = val as u32;
            }
            _ => {}
        }

        self.setting_input = None;
        self.apply_config_change();
        true
    }

    /// Close the active setting input modal without applying changes.
    pub fn cancel_setting_input(&mut self) {
        self.setting_input = None;
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

    #[test]
    fn open_setting_input_opens_dialog_for_numeric_settings() {
        let mut app = App::new();
        app.config.temp_clean_threshold_mb = 500;
        app.config.max_event_log_hours = 24;

        app.selected_setting_index = 4;
        app.open_setting_input();

        assert!(app.setting_input.is_some());
        let input = app.setting_input.as_ref().unwrap();
        assert_eq!(input.setting_index, 4);
        assert_eq!(input.setting_name, "Temp file threshold");
        assert_eq!(input.buffer, "500");

        app.selected_setting_index = 5;
        app.open_setting_input();
        let input5 = app.setting_input.as_ref().unwrap();
        assert_eq!(input5.setting_index, 5);
        assert_eq!(input5.setting_name, "Event log analysis window");
        assert_eq!(input5.buffer, "24");
    }

    #[test]
    fn submit_setting_input_validates_and_updates_config() {
        let mut app = App::new();
        app.selected_setting_index = 4;
        app.open_setting_input();

        // Valid edit
        if let Some(input) = app.setting_input.as_mut() {
            input.buffer = "750".to_string();
        }
        assert!(app.submit_setting_input());
        assert!(app.setting_input.is_none());
        assert_eq!(app.config.temp_clean_threshold_mb, 750);

        // Invalid edit: empty
        app.selected_setting_index = 4;
        app.open_setting_input();
        if let Some(input) = app.setting_input.as_mut() {
            input.buffer = "".to_string();
        }
        assert!(!app.submit_setting_input());
        assert!(app.setting_input.is_some());
        assert!(app.setting_input.as_ref().unwrap().error_msg.is_some());

        // Cancel dialog
        app.cancel_setting_input();
        assert!(app.setting_input.is_none());
    }
}
