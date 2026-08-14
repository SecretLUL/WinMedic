use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub auto_restart_services: bool,
    pub create_vss_before_repair: bool,
    pub temp_clean_threshold_mb: u64,
    pub max_event_log_hours: u32,
    pub auto_backup_registry: bool,
    pub dark_mode: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_restart_services: true,
            create_vss_before_repair: true,
            temp_clean_threshold_mb: 500,
            max_event_log_hours: 24,
            auto_backup_registry: true,
            dark_mode: true,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = AppConfig::default();
        assert!(cfg.create_vss_before_repair);
        assert!(cfg.auto_restart_services);
        assert_eq!(cfg.max_event_log_hours, 24);
        assert_eq!(cfg.temp_clean_threshold_mb, 500);
    }
}
