use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub create_vss_before_repair: bool,
    pub auto_restart_services: bool,
    pub max_event_log_hours: u32,
    pub temp_clean_threshold_mb: u64,
    pub telemetry_refresh_secs: u64,
    pub enable_audit_log: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            create_vss_before_repair: true,
            auto_restart_services: true,
            max_event_log_hours: 24,
            temp_clean_threshold_mb: 500,
            telemetry_refresh_secs: 1,
            enable_audit_log: true,
        }
    }
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("WinMedic").join("config.json")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if let Ok(content) = std::fs::read_to_string(&path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            let def = Self::default();
            let _ = def.save();
            def
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())?;
        Ok(())
    }
}
