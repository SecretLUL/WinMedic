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

/// Where the record of every scan, repair, simulation and rollback goes.
///
/// [`Default`] is the inert logger, like the other seams in
/// [`crate::app::SystemActions`]: `cargo test` builds dozens of engines and
/// apps, and every scan and repair they run used to land in the developer's
/// own `%APPDATA%\WinMedic\logs\audit.log`. Only the entry points that work
/// on the real machine pass [`AuditLogger::real`].
///
/// Building a logger touches no file. The folder is created by the first
/// entry, so a logger that is built and never written to leaves nothing
/// behind.
#[derive(Debug, Clone)]
pub struct AuditLogger {
    /// `None` for the inert logger, which records nothing and has no history.
    log_dir: Option<PathBuf>,
    max_file_size: u64,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::inert()
    }
}

impl AuditLogger {
    /// The log in `%APPDATA%\WinMedic\logs`.
    pub fn real() -> Self {
        Self::with_dir_and_size(Self::real_dir(), MAX_LOG_FILE_BYTES)
    }

    /// Records nothing and has no history. The default.
    pub fn inert() -> Self {
        Self {
            log_dir: None,
            max_file_size: MAX_LOG_FILE_BYTES,
        }
    }

    pub fn with_dir_and_size(log_dir: PathBuf, max_file_size: u64) -> Self {
        Self {
            log_dir: Some(log_dir),
            max_file_size,
        }
    }

    fn real_dir() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("WinMedic")
            .join("logs")
    }

    /// Whether entries are written anywhere at all.
    pub fn is_live(&self) -> bool {
        self.log_dir.is_some()
    }

    /// The folder the log is written to; `None` for the inert logger.
    pub fn log_dir(&self) -> Option<&Path> {
        self.log_dir.as_deref()
    }

    /// Rotate files if the base file exceeds `max_file_size`.
    /// e.g. for "history.jsonl":
    /// history.4.jsonl -> history.5.jsonl
    /// history.3.jsonl -> history.4.jsonl
    /// ...
    /// history.jsonl -> history.1.jsonl
    fn rotate_if_needed(&self, dir: &Path, filename: &str, ext: &str) {
        let base_path = dir.join(format!("{}.{}", filename, ext));
        if let Ok(metadata) = std::fs::metadata(&base_path)
            && metadata.len() >= self.max_file_size
        {
            // Delete the oldest rotated file if it exceeds the max backup count
            let oldest = dir.join(format!("{}.{}.{}", filename, MAX_ROTATED_FILES, ext));
            if oldest.exists() {
                let _ = std::fs::remove_file(oldest);
            }

            // Shift existing rotated files downwards
            for i in (1..MAX_ROTATED_FILES).rev() {
                let src = dir.join(format!("{}.{}.{}", filename, i, ext));
                let dst = dir.join(format!("{}.{}.{}", filename, i + 1, ext));
                if src.exists() {
                    let _ = std::fs::rename(src, dst);
                }
            }

            // Rename current active log file to .1
            let first_backup = dir.join(format!("{}.1.{}", filename, ext));
            let _ = std::fs::rename(&base_path, first_backup);
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
        let Some(dir) = self.log_dir.as_deref() else {
            return;
        };
        let _ = std::fs::create_dir_all(dir);
        Self::migrate_legacy_json_if_needed(dir);

        let entry = AuditEntry {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            action_type: action_type.to_string(),
            module_id: module_id.to_string(),
            title: title.to_string(),
            status: status.to_string(),
            details: details.to_string(),
        };

        // 1. Text log (audit.log)
        self.rotate_if_needed(dir, "audit", "log");
        let log_file = dir.join("audit.log");
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
        self.rotate_if_needed(dir, "history", "jsonl");
        let history_file = dir.join("history.jsonl");
        if let Ok(json_line) = serde_json::to_string(&entry)
            && let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(history_file)
        {
            let _ = writeln!(f, "{}", json_line);
        }
    }

    /// Read history from JSONL log files in chronological order.
    pub fn get_history(&self) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        let Some(dir) = self.log_dir.as_deref() else {
            return entries;
        };
        Self::migrate_legacy_json_if_needed(dir);
        let history_file = dir.join("history.jsonl");

        if let Ok(file) = File::open(&history_file) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed)
                {
                    entries.push(entry);
                }
            }
        }

        entries
    }

    /// Migrate legacy history.json to history.jsonl if present.
    fn migrate_legacy_json_if_needed(dir: &Path) {
        let legacy_file = dir.join("history.json");
        let jsonl_file = dir.join("history.jsonl");

        if legacy_file.exists() && !jsonl_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&legacy_file)
                && let Ok(legacy_entries) = serde_json::from_str::<Vec<AuditEntry>>(&content)
                && let Ok(mut f) = OpenOptions::new()
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
            let _ = std::fs::remove_file(legacy_file);
        }
    }

    pub fn get_raw_log(&self) -> String {
        self.log_dir
            .as_deref()
            .and_then(|dir| std::fs::read_to_string(dir.join("audit.log")).ok())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_logger_records_nothing() {
        let logger = AuditLogger::default();
        logger.log("FIX", "storage", "Temp Cleanup", "SUCCESS", "Freed 500MB");

        assert!(!logger.is_live());
        assert!(logger.log_dir().is_none());
        assert!(logger.get_history().is_empty());
        assert!(logger.get_raw_log().is_empty());
    }

    /// Built, not written to: nothing on disk changes. The folder appears
    /// with the first entry.
    #[test]
    fn building_a_logger_touches_no_file() {
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_lazy_dir");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES);
        assert!(!temp_dir.exists());

        logger.log("SCAN", "network", "Network", "SUCCESS", "");
        assert!(temp_dir.join("audit.log").exists());

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn the_real_log_lives_in_appdata() {
        // Built, not written to: building touches no file.
        let logger = AuditLogger::real();

        assert!(logger.is_live());
        assert!(
            logger
                .log_dir()
                .unwrap()
                .ends_with(Path::new("WinMedic").join("logs"))
        );
    }

    /// No test may write the developer's own audit log. Every scan and
    /// repair a test ran used to end up in `%APPDATA%\WinMedic\logs`, among
    /// the entries of the real runs the log exists for.
    #[test]
    fn no_test_in_the_tree_writes_the_real_audit_log() {
        let offenders =
            crate::utils::test_guard::integration_test_lines_mentioning("AuditLogger::real(");

        assert!(
            offenders.is_empty(),
            "these tests would write the audit log of the machine running the suite; \
             use AuditLogger::with_dir_and_size with a temp directory instead: {:?}",
            offenders
        );
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

        // Logger should migrate on the first read
        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES);
        let history = logger.get_history();
        assert!(!legacy_file.exists());
        assert!(temp_dir.join("history.jsonl").exists());

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].module_id, "legacy_module");

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
