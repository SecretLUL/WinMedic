use super::state::{App, SettingInput};
use crate::config::AppConfig;
use crate::utils::background_task::helper_schedule;

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
            4 | 5 | 8 => self
                .config
                .adjust_setting(self.selected_setting_index, true),
            _ => self.config.toggle_setting(self.selected_setting_index),
        };
        if changed {
            self.apply_config_change(self.selected_setting_index);
        }
    }

    pub fn adjust_current_setting(&mut self, increase: bool) {
        if self
            .config
            .adjust_setting(self.selected_setting_index, increase)
        {
            self.apply_config_change(self.selected_setting_index);
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
            8 => {
                self.setting_input = Some(SettingInput {
                    setting_index: 8,
                    setting_name: "WinMedicHelper scan frequency".to_string(),
                    unit: "Hours (h)".to_string(),
                    min_value: 1,
                    max_value: 720,
                    buffer: self.config.helper_frequency_hours.to_string(),
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

        if input.setting_index == 8 && helper_schedule(val as u32).is_none() {
            input.error_msg = Some(
                "Task Scheduler repeats every 1-23 hours or every whole number of days (24, 48, 72 ...)."
                    .to_string(),
            );
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
            8 => {
                self.config.helper_frequency_hours = val as u32;
            }
            _ => {}
        }

        self.setting_input = None;
        self.apply_config_change(idx);
        true
    }

    /// Close the active setting input modal without applying changes.
    pub fn cancel_setting_input(&mut self) {
        self.setting_input = None;
    }

    /// Switch between Easy and Advanced mode — F7, as in a BIOS setup screen
    /// — and remember the choice for the next start.
    ///
    /// Only what the Scan & Repair page draws changes. The findings, their
    /// ticks and the filters stay as they are, so switching back and forth
    /// loses nothing.
    pub fn toggle_advanced_mode(&mut self) {
        self.config.advanced_mode = !self.config.advanced_mode;
        let mode = if self.config.advanced_mode {
            "Advanced mode: every finding with its details, the filters and the logs"
        } else {
            "Easy mode: only what needs doing"
        };
        let unsaved = if self.system_actions.persist_config {
            self.config.save().err()
        } else {
            None
        };
        self.status_message = Some(match unsaved {
            None => format!("{mode}. F7 switches back."),
            Some(e) => format!("{mode}. The choice could not be saved: {e}"),
        });
    }

    /// Persist the config, bring Windows in line with the setting at `index`,
    /// and rebuild the engine so modules pick up new thresholds on the next
    /// scan.
    fn apply_config_change(&mut self, index: usize) {
        let mut message = if !self.system_actions.persist_config {
            "Setting changed.".to_string()
        } else {
            match self.config.save() {
                Ok(()) => format!("Setting saved: {}", AppConfig::config_path().display()),
                Err(e) => format!("Setting could not be saved: {}", e),
            }
        };

        // Only the setting that changed is synced. Re-registering the task on
        // every change blocked the window on schtasks and, with no /ST, restarted
        // the helper's schedule each time.
        let synced = match index {
            7 => (self.system_actions.sync_helper_task)(
                self.config.helper_enabled,
                self.config.helper_frequency_hours,
            ),
            8 if self.config.helper_enabled => {
                (self.system_actions.sync_helper_task)(true, self.config.helper_frequency_hours)
            }
            9 => (self.system_actions.sync_autostart)(self.config.autostart),
            _ => Ok(()),
        };
        if let Err(e) = synced {
            message = format!("{message} - but Windows was not updated: {e}");
        }
        self.status_message = Some(message);

        if self.is_busy() {
            return;
        }

        self.rebuild_engine();
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
    fn the_mode_switch_flips_and_says_so_without_touching_the_findings() {
        let mut app = App::new();
        app.config.advanced_mode = false;
        let tab = app.active_tab;

        app.toggle_advanced_mode();
        assert!(app.config.advanced_mode);
        assert!(
            app.status_message
                .as_deref()
                .is_some_and(|m| m.starts_with("Advanced mode"))
        );

        app.toggle_advanced_mode();
        assert!(!app.config.advanced_mode);
        assert!(
            app.status_message
                .as_deref()
                .is_some_and(|m| m.starts_with("Easy mode"))
        );
        assert_eq!(app.active_tab, tab, "switching modes is not navigation");
    }

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
        app.config.temp_clean_threshold_mb = 500;
        app.config.helper_frequency_hours = 24;
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

        // Test helper frequency setting (index 8)
        app.selected_setting_index = 8;
        app.open_setting_input();
        assert!(app.setting_input.is_some());
        let input8 = app.setting_input.as_ref().unwrap();
        assert_eq!(input8.setting_index, 8);
        assert_eq!(input8.setting_name, "WinMedicHelper scan frequency");
        assert_eq!(input8.buffer, "24");

        // In range, but Task Scheduler has no way to repeat every 30 h.
        if let Some(input) = app.setting_input.as_mut() {
            input.buffer = "30".to_string();
        }
        assert!(!app.submit_setting_input());
        assert!(app.setting_input.as_ref().unwrap().error_msg.is_some());

        if let Some(input) = app.setting_input.as_mut() {
            input.buffer = "48".to_string();
        }
        assert!(app.submit_setting_input());
        assert_eq!(app.config.helper_frequency_hours, 48);
    }
}
