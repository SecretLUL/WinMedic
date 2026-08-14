use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Default maximum size in bytes before rotating log files (5 MB).
pub const MAX_LOG_FILE_BYTES: u64 = 5 * 1024 * 1024;
/// Maximum number of rotated log backup files to keep.
pub const MAX_ROTATED_FILES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action_type: String, // "SCAN", "FIX", "BACKUP", "RESTORE", "DRYRUN"
    pub module_id: String,
    pub title: String,
    pub status: String, // "SUCCESS", "FAILED", "WARNING", "INFO"
    pub details: String,
}

pub struct AuditLogger {
    log_dir: PathBuf,
    max_file_size: u64,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self::with_dir_and_size(
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("WinMedic")
                .join("logs"),
            MAX_LOG_FILE_BYTES,
        )
    }

    pub fn with_dir_and_size(log_dir: PathBuf, max_file_size: u64) -> Self {
        let _ = std::fs::create_dir_all(&log_dir);
        let logger = Self {
            log_dir,
            max_file_size,
        };
        logger.migrate_legacy_json_if_needed();
        logger
    }

    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// Rotate files if the base file exceeds `max_file_size`.
    /// e.g. for "history.jsonl":
    /// history.4.jsonl -> history.5.jsonl
    /// history.3.jsonl -> history.4.jsonl
    /// ...
    /// history.jsonl -> history.1.jsonl
    fn rotate_if_needed(&self, filename: &str, ext: &str) {
        let base_path = self.log_dir.join(format!("{}.{}", filename, ext));
        if let Ok(metadata) = std::fs::metadata(&base_path) {
            if metadata.len() >= self.max_file_size {
                // Delete the oldest rotated file if it exceeds the max backup count
                let oldest = self
                    .log_dir
                    .join(format!("{}.{}.{}", filename, MAX_ROTATED_FILES, ext));
                if oldest.exists() {
                    let _ = std::fs::remove_file(oldest);
                }

                // Shift existing rotated files downwards
                for i in (1..MAX_ROTATED_FILES).rev() {
                    let src = self.log_dir.join(format!("{}.{}.{}", filename, i, ext));
                    let dst = self.log_dir.join(format!("{}.{}.{}", filename, i + 1, ext));
                    if src.exists() {
                        let _ = std::fs::rename(src, dst);
                    }
                }

                // Rename current active log file to .1
                let first_backup = self.log_dir.join(format!("{}.1.{}", filename, ext));
                let _ = std::fs::rename(&base_path, first_backup);
            }
        }
    }

    /// Append an entry in O(1) time to append-only JSONL and formatted text log.
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

        // 1. Text log (audit.log)
        self.rotate_if_needed("audit", "log");
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

        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_file) {
            let _ = f.write_all(line.as_bytes());
        }

        // 2. Append-only JSONL log (history.jsonl)
        self.rotate_if_needed("history", "jsonl");
        let history_file = self.log_dir.join("history.jsonl");
        if let Ok(json_line) = serde_json::to_string(&entry) {
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(history_file)
            {
                let _ = writeln!(f, "{}", json_line);
            }
        }
    }

    /// Read history from JSONL log files in chronological order.
    pub fn get_history(&self) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        let history_file = self.log_dir.join("history.jsonl");

        if let Ok(file) = File::open(&history_file) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
                        entries.push(entry);
                    }
                }
            }
        }

        entries
    }

    /// Migrate legacy history.json to history.jsonl if present.
    fn migrate_legacy_json_if_needed(&self) {
        let legacy_file = self.log_dir.join("history.json");
        let jsonl_file = self.log_dir.join("history.jsonl");

        if legacy_file.exists() && !jsonl_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&legacy_file) {
                if let Ok(legacy_entries) = serde_json::from_str::<Vec<AuditEntry>>(&content) {
                    if let Ok(mut f) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&jsonl_file)
                    {
                        for entry in legacy_entries {
                            if let Ok(line) = serde_json::to_string(&entry) {
                                let _ = writeln!(f, "{}", line);
                            }
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(legacy_file);
        }
    }

    pub fn get_raw_log(&self) -> String {
        let log_file = self.log_dir.join("audit.log");
        std::fs::read_to_string(log_file).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_logger_creation() {
        let logger = AuditLogger::new();
        assert!(logger.log_dir().exists());
    }

    #[test]
    fn test_audit_logger_append_and_read_jsonl() {
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_append");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES);
        logger.log(
            "SCAN",
            "system_integrity",
            "SFC Scan",
            "SUCCESS",
            "All clean",
        );
        logger.log("FIX", "storage", "Temp Cleanup", "SUCCESS", "Freed 500MB");

        let history = logger.get_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].module_id, "system_integrity");
        assert_eq!(history[1].module_id, "storage");

        let raw = logger.get_raw_log();
        assert!(raw.contains("SFC Scan"));
        assert!(raw.contains("Temp Cleanup"));

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_audit_logger_rotation() {
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_rotation");
        let _ = std::fs::remove_dir_all(&temp_dir);

        // Low threshold to force rotation quickly (e.g. 150 bytes)
        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), 150);

        for i in 0..10 {
            logger.log(
                "FIX",
                "test_mod",
                &format!("Fix #{}", i),
                "SUCCESS",
                "Details for rotation test",
            );
        }

        // Verify rotated file was created
        let rotated_file = temp_dir.join("history.1.jsonl");
        assert!(rotated_file.exists());

        let active_file = temp_dir.join("history.jsonl");
        assert!(active_file.exists());

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_audit_logger_legacy_migration() {
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_migration");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);

        // Create legacy history.json
        let legacy_file = temp_dir.join("history.json");
        let sample = vec![AuditEntry {
            timestamp: "2026-01-01 12:00:00".to_string(),
            action_type: "SCAN".to_string(),
            module_id: "legacy_module".to_string(),
            title: "Legacy Title".to_string(),
            status: "SUCCESS".to_string(),
            details: "Legacy Details".to_string(),
        }];
        std::fs::write(&legacy_file, serde_json::to_string(&sample).unwrap()).unwrap();

        // Logger should migrate on init
        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES);
        assert!(!legacy_file.exists());
        assert!(temp_dir.join("history.jsonl").exists());

        let history = logger.get_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].module_id, "legacy_module");

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
