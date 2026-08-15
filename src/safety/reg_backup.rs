use crate::utils::cmd::run_cmd;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// File name of the backup index inside [`RegBackupManager::backup_dir`].
pub const INDEX_FILE_NAME: &str = "index.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecord {
    pub id: String,
    pub timestamp: String,
    pub description: String,
    pub key_path: String,
    pub file_path: String,
}

pub struct RegBackupManager {
    backup_dir: PathBuf,
}

impl Default for RegBackupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RegBackupManager {
    pub fn new() -> Self {
        let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        Self::with_dir(base.join("WinMedic").join("backups"))
    }

    /// Construct a manager rooted at an explicit directory.
    ///
    /// This is the seam the index tests use so they operate on a sandbox instead
    /// of the real `%APPDATA%\WinMedic\backups`.
    pub fn with_dir(backup_dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&backup_dir);
        Self { backup_dir }
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    fn index_path(&self) -> PathBuf {
        self.backup_dir.join(INDEX_FILE_NAME)
    }

    /// Export a Windows Registry Key into a standard .reg backup file before modification
    pub async fn export_key(
        &self,
        key_path: &str,
        description: &str,
    ) -> Result<BackupRecord, String> {
        let timestamp_slug = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let safe_key = key_path.replace(['\\', '/'], "_");
        let file_name = format!("reg_{}_{}.reg", timestamp_slug, safe_key);
        let file_path = self.backup_dir.join(file_name);

        let output = run_cmd(
            "reg",
            &["export", key_path, &file_path.to_string_lossy(), "/y"],
            Duration::from_secs(15),
        )
        .await?;

        if !output.success {
            return Err(format!(
                "Registry export failed: {} ({})",
                output.stderr, output.stdout
            ));
        }

        let record = BackupRecord {
            id: timestamp_slug,
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            description: description.to_string(),
            key_path: key_path.to_string(),
            file_path: file_path.to_string_lossy().to_string(),
        };

        // A backup that never reaches the index is invisible to the rollback UI,
        // so callers must treat it as a failed export. The message names the
        // .reg file that *was* written so the user is not left stranded.
        self.save_record_index(&record).map_err(|e| {
            format!(
                "Backup file '{}' was written but could not be recorded in the index: {}. \
                 It can still be restored manually with `reg import`.",
                file_path.display(),
                e
            )
        })?;

        Ok(record)
    }

    /// Import / restore a .reg file
    pub async fn restore_key(&self, file_path: &str) -> Result<String, String> {
        let output = run_cmd("reg", &["import", file_path], Duration::from_secs(15)).await?;

        if output.success {
            Ok(format!("Successfully restored registry from {}", file_path))
        } else {
            Err(format!(
                "Registry import failed: {} ({})",
                output.stderr, output.stdout
            ))
        }
    }

    /// Read the backup index, distinguishing "no backups yet" from "the index is
    /// there but unreadable".
    ///
    /// That distinction is the whole point: collapsing both cases into an empty
    /// list is what previously let a single malformed byte erase every recorded
    /// backup on the next write.
    pub fn load_index(&self) -> Result<Vec<BackupRecord>, String> {
        let path = self.index_path();
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("could not read {}: {}", path.display(), e)),
        };

        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_str(&content)
            .map_err(|e| format!("{} is malformed: {}", INDEX_FILE_NAME, e))
    }

    /// All recorded backups, or an empty list if the index cannot be read.
    ///
    /// Intended for read-only display. Never build a new index from this — use
    /// [`Self::load_index`], which reports corruption instead of hiding it.
    pub fn list_backups(&self) -> Vec<BackupRecord> {
        self.load_index().unwrap_or_default()
    }

    /// Move an unreadable index aside so a rebuild cannot destroy it.
    ///
    /// Returns the path the old index was preserved at.
    fn quarantine_index(&self) -> Result<PathBuf, String> {
        let stamp = Local::now().format("%Y%m%d_%H%M%S");
        let mut dest = self
            .backup_dir
            .join(format!("{}.corrupt-{}", INDEX_FILE_NAME, stamp));

        // Two failures inside the same second must not overwrite each other.
        let mut counter = 1;
        while dest.exists() {
            dest = self
                .backup_dir
                .join(format!("{}.corrupt-{}-{}", INDEX_FILE_NAME, stamp, counter));
            counter += 1;
        }

        std::fs::rename(self.index_path(), &dest).map_err(|e| {
            format!(
                "could not move the unreadable index to {}: {}",
                dest.display(),
                e
            )
        })?;

        Ok(dest)
    }

    /// Append `record` to the index.
    ///
    /// If the existing index cannot be parsed it is quarantined rather than
    /// overwritten, and only then is a fresh index started. If quarantining
    /// fails, this returns an error and leaves the old file untouched.
    fn save_record_index(&self, record: &BackupRecord) -> Result<(), String> {
        let mut list = match self.load_index() {
            Ok(list) => list,
            Err(read_err) => {
                let preserved = self.quarantine_index()?;
                // Not fatal: the old entries survive on disk under `preserved`,
                // and the caller still gets a working index going forward.
                eprintln!(
                    "WinMedic: {} — previous index preserved at {}",
                    read_err,
                    preserved.display()
                );
                Vec::new()
            }
        };

        list.push(record.clone());

        let json = serde_json::to_string_pretty(&list)
            .map_err(|e| format!("could not serialize the backup index: {}", e))?;

        self.write_index_atomically(&json)
    }

    /// Write the index via a temp file + rename, so an interrupted write leaves
    /// the previous index intact instead of a half-written one.
    fn write_index_atomically(&self, json: &str) -> Result<(), String> {
        let tmp_path = self.backup_dir.join(format!("{}.tmp", INDEX_FILE_NAME));

        std::fs::write(&tmp_path, json)
            .map_err(|e| format!("could not write {}: {}", tmp_path.display(), e))?;

        // `std::fs::rename` replaces the destination on both Unix and Windows.
        std::fs::rename(&tmp_path, self.index_path()).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            format!("could not replace {}: {}", INDEX_FILE_NAME, e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal scoped temp directory; the crate has no dev-dependency on `tempfile`.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = format!(
                "winmedic_regbackup_{}_{}_{:?}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn record(id: &str) -> BackupRecord {
        BackupRecord {
            id: id.to_string(),
            timestamp: "2026-01-01 12:00:00".to_string(),
            description: format!("backup {}", id),
            key_path: r"HKCU\Software\Test".to_string(),
            file_path: format!(r"C:\backups\reg_{}.reg", id),
        }
    }

    #[test]
    fn missing_index_reads_as_empty_not_as_error() {
        let dir = TempDir::new("missing");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        assert_eq!(mgr.load_index().unwrap(), Vec::new());
        assert!(mgr.list_backups().is_empty());
    }

    #[test]
    fn empty_index_file_reads_as_empty() {
        let dir = TempDir::new("empty");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        std::fs::write(mgr.index_path(), "   \n").unwrap();

        assert_eq!(mgr.load_index().unwrap(), Vec::new());
    }

    #[test]
    fn records_accumulate_across_writes() {
        let dir = TempDir::new("accumulate");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        mgr.save_record_index(&record("a")).unwrap();
        mgr.save_record_index(&record("b")).unwrap();
        mgr.save_record_index(&record("c")).unwrap();

        let ids: Vec<String> = mgr.list_backups().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn corrupt_index_is_reported_instead_of_silently_emptied() {
        let dir = TempDir::new("corrupt_read");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        std::fs::write(mgr.index_path(), "{not valid json").unwrap();

        // The old behaviour was `unwrap_or_default()`, which made this look like
        // "no backups exist" and set up the next write to erase the file.
        assert!(mgr.load_index().is_err());
    }

    #[test]
    fn corrupt_index_is_preserved_not_overwritten() {
        let dir = TempDir::new("corrupt_write");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        let original = r#"[{"id":"old","truncated":"#;
        std::fs::write(mgr.index_path(), original).unwrap();

        mgr.save_record_index(&record("new")).unwrap();

        // The new entry is recorded...
        let ids: Vec<String> = mgr.list_backups().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, vec!["new"]);

        // ...and the unreadable original still exists verbatim, so nothing the
        // user had is lost.
        let quarantined: Vec<PathBuf> = std::fs::read_dir(&dir.path)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(".corrupt-"))
            })
            .collect();

        assert_eq!(
            quarantined.len(),
            1,
            "expected exactly one quarantined index"
        );
        assert_eq!(std::fs::read_to_string(&quarantined[0]).unwrap(), original);
    }

    #[test]
    fn quarantine_does_not_clobber_an_earlier_quarantine() {
        let dir = TempDir::new("double_corrupt");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        std::fs::write(mgr.index_path(), "first corruption").unwrap();
        mgr.save_record_index(&record("one")).unwrap();

        std::fs::write(mgr.index_path(), "second corruption").unwrap();
        mgr.save_record_index(&record("two")).unwrap();

        let mut preserved: Vec<String> = std::fs::read_dir(&dir.path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .collect();
        preserved.sort();

        assert_eq!(preserved, vec!["first corruption", "second corruption"]);
    }

    #[test]
    fn no_temp_file_is_left_behind_after_a_successful_write() {
        let dir = TempDir::new("no_temp");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        mgr.save_record_index(&record("a")).unwrap();

        let tmp = dir.path.join(format!("{}.tmp", INDEX_FILE_NAME));
        assert!(!tmp.exists(), "atomic write left its temp file behind");
    }

    #[test]
    fn index_survives_a_manager_being_reconstructed() {
        let dir = TempDir::new("reopen");

        RegBackupManager::with_dir(dir.path.clone())
            .save_record_index(&record("persisted"))
            .unwrap();

        let reopened = RegBackupManager::with_dir(dir.path.clone());
        let ids: Vec<String> = reopened.list_backups().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, vec!["persisted"]);
    }
}
