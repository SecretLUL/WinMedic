use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persistent user configuration.
///
/// Every field is `#[serde(default)]` so that config files written by older or
/// newer WinMedic versions still load instead of silently falling back to the
/// complete default set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// Restart Windows services automatically when a fix requires stopping them.
    /// When disabled, fixes that would leave a service stopped refuse to run.
    pub auto_restart_services: bool,
    /// Create a VSS system restore point before applying any repair.
    pub create_vss_before_repair: bool,
    /// Export affected registry keys to a `.reg` file before modifying them.
    /// When disabled, registry fixes run without a safety net.
    pub auto_backup_registry: bool,
    /// Report temp/junk files as an issue once they exceed this many megabytes.
    pub temp_clean_threshold_mb: u64,
    /// How far back the event log module looks for critical events.
    pub max_event_log_hours: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_restart_services: true,
            create_vss_before_repair: true,
            auto_backup_registry: true,
            temp_clean_threshold_mb: 500,
            max_event_log_hours: 24,
        }
    }
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("WinMedic").join("config.json")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if let Ok(data) = std::fs::read_to_string(path) {
            if let Ok(cfg) = serde_json::from_str(&data) {
                return cfg;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }

    /// Number of editable settings exposed in the settings tab.
    pub const SETTING_COUNT: usize = 5;

    /// Human readable label, current value and explanation for setting `index`.
    pub fn setting_row(&self, index: usize) -> Option<(&'static str, String, &'static str)> {
        let on_off = |b: bool| {
            if b {
                "AN".to_string()
            } else {
                "AUS".to_string()
            }
        };
        match index {
            0 => Some((
                "VSS-Wiederherstellungspunkt vor Reparatur",
                on_off(self.create_vss_before_repair),
                "Legt vor jedem Reparaturlauf einen Windows-Systemwiederherstellungspunkt an.",
            )),
            1 => Some((
                "Registry vor Änderung sichern",
                on_off(self.auto_backup_registry),
                "Exportiert betroffene Schlüssel als .reg-Datei. Ist dies AUS, laufen Registry-Fixes ohne Sicherung.",
            )),
            2 => Some((
                "Dienste automatisch neu starten",
                on_off(self.auto_restart_services),
                "Erlaubt Fixes, Windows-Dienste anzuhalten und neu zu starten. Ist dies AUS, werden solche Fixes übersprungen.",
            )),
            3 => Some((
                "Schwelle für Temp-Dateien",
                format!("{} MB", self.temp_clean_threshold_mb),
                "Ab dieser Gesamtgröße werden temporäre Dateien als Problem gemeldet. [←/→] ±100 MB.",
            )),
            4 => Some((
                "Zeitfenster für Event-Log-Analyse",
                format!("{} h", self.max_event_log_hours),
                "Wie weit das Ereignisprotokoll nach kritischen Events durchsucht wird. [←/→] ±6 h.",
            )),
            _ => None,
        }
    }

    /// Toggle the boolean setting at `index`. Returns true if anything changed.
    pub fn toggle_setting(&mut self, index: usize) -> bool {
        match index {
            0 => self.create_vss_before_repair = !self.create_vss_before_repair,
            1 => self.auto_backup_registry = !self.auto_backup_registry,
            2 => self.auto_restart_services = !self.auto_restart_services,
            _ => return false,
        }
        true
    }

    /// Increase (`delta > 0`) or decrease the numeric setting at `index`.
    /// Returns true if anything changed.
    pub fn adjust_setting(&mut self, index: usize, increase: bool) -> bool {
        match index {
            3 => {
                let new = if increase {
                    (self.temp_clean_threshold_mb + 100).min(100_000)
                } else {
                    self.temp_clean_threshold_mb.saturating_sub(100).max(100)
                };
                let changed = new != self.temp_clean_threshold_mb;
                self.temp_clean_threshold_mb = new;
                changed
            }
            4 => {
                let new = if increase {
                    (self.max_event_log_hours + 6).min(720)
                } else {
                    self.max_event_log_hours.saturating_sub(6).max(1)
                };
                let changed = new != self.max_event_log_hours;
                self.max_event_log_hours = new;
                changed
            }
            _ => self.toggle_setting(index),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = AppConfig::default();
        assert!(cfg.create_vss_before_repair);
        assert!(cfg.auto_restart_services);
        assert!(cfg.auto_backup_registry);
        assert_eq!(cfg.max_event_log_hours, 24);
        assert_eq!(cfg.temp_clean_threshold_mb, 500);
    }

    #[test]
    fn test_partial_config_keeps_defaults() {
        // A config file written by an older version must still load.
        let cfg: AppConfig = serde_json::from_str(r#"{"temp_clean_threshold_mb": 1234}"#).unwrap();
        assert_eq!(cfg.temp_clean_threshold_mb, 1234);
        assert_eq!(cfg.max_event_log_hours, 24);
        assert!(cfg.create_vss_before_repair);
    }

    #[test]
    fn test_config_roundtrip() {
        let mut cfg = AppConfig::default();
        cfg.toggle_setting(0);
        cfg.adjust_setting(3, true);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
        assert!(!restored.create_vss_before_repair);
        assert_eq!(restored.temp_clean_threshold_mb, 600);
    }

    #[test]
    fn test_every_setting_index_is_described() {
        let cfg = AppConfig::default();
        for i in 0..AppConfig::SETTING_COUNT {
            assert!(cfg.setting_row(i).is_some(), "setting {} has no label", i);
        }
        assert!(cfg.setting_row(AppConfig::SETTING_COUNT).is_none());
    }

    #[test]
    fn test_numeric_settings_have_floors() {
        let mut cfg = AppConfig::default();
        for _ in 0..50 {
            cfg.adjust_setting(3, false);
            cfg.adjust_setting(4, false);
        }
        assert_eq!(cfg.temp_clean_threshold_mb, 100);
        assert_eq!(cfg.max_event_log_hours, 1);
    }
}
