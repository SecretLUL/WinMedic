use crate::utils::cmd::run_cmd;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl RegBackupManager {
    pub fn new() -> Self {
        let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        let backup_dir = base.join("WinMedic").join("backups");
        let _ = std::fs::create_dir_all(&backup_dir);
        Self { backup_dir }
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// Export a Windows Registry Key into a standard .reg backup file before modification
    pub async fn export_key(
        &self,
        key_path: &str,
        description: &str,
    ) -> Result<BackupRecord, String> {
        let timestamp_slug = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let safe_key = key_path.replace('\\', "_").replace('/', "_");
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

        self.save_record_index(&record);
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

    /// List all backup records
    pub fn list_backups(&self) -> Vec<BackupRecord> {
        let index_path = self.backup_dir.join("index.json");
        if let Ok(content) = std::fs::read_to_string(index_path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    fn save_record_index(&self, record: &BackupRecord) {
        let mut list = self.list_backups();
        list.push(record.clone());
        let index_path = self.backup_dir.join("index.json");
        if let Ok(json) = serde_json::to_string_pretty(&list) {
            let _ = std::fs::write(index_path, json);
        }
    }
}
