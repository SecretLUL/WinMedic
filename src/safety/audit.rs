use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action_type: String, // "SCAN", "FIX", "BACKUP", "RESTORE"
    pub module_id: String,
    pub title: String,
    pub status: String, // "SUCCESS", "FAILED", "WARNING", "INFO"
    pub details: String,
}

pub struct AuditLogger {
    log_dir: PathBuf,
}

impl AuditLogger {
    pub fn new() -> Self {
        let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        let log_dir = base.join("WinMedic").join("logs");
        let _ = std::fs::create_dir_all(&log_dir);
        Self { log_dir }
    }

    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    pub fn log(
        &self,
        action_type: &str,
        module_id: &str,
        title: &str,
        status: &str,
        details: &str,
    ) {
        let entry = AuditEntry {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            action_type: action_type.to_string(),
            module_id: module_id.to_string(),
            title: title.to_string(),
            status: status.to_string(),
            details: details.to_string(),
        };

        // Append to human-readable audit.log
        let log_file = self.log_dir.join("audit.log");
        let line = format!(
            "[{}] [{}] [{}] {} -> {} | {}\n",
            entry.timestamp,
            entry.action_type,
            entry.module_id,
            entry.title,
            entry.status,
            entry.details
        );

        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
        {
            use std::io::Write;
            let _ = f.write_all(line.as_bytes());
        }

        // Also append to JSON history
        let history_file = self.log_dir.join("history.json");
        let mut entries = self.get_history();
        entries.push(entry);
        if let Ok(json) = serde_json::to_string_pretty(&entries) {
            let _ = std::fs::write(history_file, json);
        }
    }

    pub fn get_history(&self) -> Vec<AuditEntry> {
        let history_file = self.log_dir.join("history.json");
        if let Ok(content) = std::fs::read_to_string(history_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    pub fn get_raw_log(&self) -> String {
        let log_file = self.log_dir.join("audit.log");
        std::fs::read_to_string(log_file).unwrap_or_default()
    }
}
