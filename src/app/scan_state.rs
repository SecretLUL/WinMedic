//! Persistence for the latest scan state across app restarts.
//!
//! Stores the diagnosed issues, module statuses, health index and timestamp
//! in `%APPDATA%\WinMedic\last_scan.json`.

use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::engine::issue::Issue;
use crate::modules::ModuleStatus;
use crate::modules::windows_updates::REBOOT_PENDING;

pub const SCAN_STATE_FILE_NAME: &str = "last_scan.json";

/// Raised whenever an older file would be read wrongly. 1: findings say
/// whether they are advice; before that, advice read as a repairable finding
/// and a repair run failed on it.
const FORMAT: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanState {
    /// A file from before [`FORMAT`] reads as 0 and is not loaded: the next
    /// scan replaces it.
    #[serde(default)]
    pub format: u32,
    pub timestamp: String,
    pub health_score: u8,
    pub issues: Vec<Issue>,
    pub module_statuses: Vec<(String, String, String, ModuleStatus)>,
    #[serde(default)]
    pub scan_duration_secs: Option<u64>,
    #[serde(default)]
    pub boot_time_secs: Option<u64>,
    /// Windows' boot counter when the scan was saved, see [`current_boot_id`].
    #[serde(default)]
    pub boot_id: Option<u32>,
}

/// Windows' boot counter, one more on every start: `BootId` under
/// `PrefetchParameters`, readable without Administrator rights.
///
/// The boot time `sysinfo` reports is "now minus uptime", cut to seconds, so
/// a clock correction, a wake from sleep or a second's rounding moved it, and
/// restarts that were still due counted as done.
pub fn current_boot_id() -> Option<u32> {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
        )
        .and_then(|key| key.get_value("BootId"))
        .ok()
}

/// How far a file without a boot counter lets the boot time drift before it
/// counts as a restart.
const BOOT_TIME_TOLERANCE_SECS: u64 = 10 * 60;

/// Whether Windows has started again since `saved` was written.
pub fn restarted_since(saved: &ScanState, boot_id: Option<u32>, boot_time_secs: u64) -> bool {
    match (saved.boot_id, boot_id) {
        (Some(then), Some(now)) => then != now,
        _ => saved
            .boot_time_secs
            .is_some_and(|then| boot_time_secs > then + BOOT_TIME_TOLERANCE_SECS),
    }
}

impl ScanState {
    pub fn new(
        health_score: u8,
        issues: Vec<Issue>,
        module_statuses: Vec<(String, String, String, ModuleStatus)>,
        scan_duration_secs: Option<u64>,
    ) -> Self {
        Self {
            format: FORMAT,
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            health_score,
            issues,
            module_statuses,
            scan_duration_secs,
            boot_time_secs: Some(sysinfo::System::boot_time()),
            boot_id: current_boot_id(),
        }
    }

    pub fn file_path() -> PathBuf {
        let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("WinMedic").join(SCAN_STATE_FILE_NAME)
    }

    pub fn load() -> Option<Self> {
        Self::load_from(&Self::file_path())
    }

    pub fn load_from(path: &Path) -> Option<Self> {
        let data = std::fs::read_to_string(path).ok()?;
        let mut state: Self = serde_json::from_str(&data)
            .ok()
            .filter(|state: &Self| state.format == FORMAT)?;
        // Up to 0.8.0 the restart Windows waits for was a repair. It is advice
        // now, and its repair is gone: a ticked one would fail.
        for issue in state.issues.iter_mut().filter(|i| i.id == REBOOT_PENDING) {
            issue.advice_only = true;
            issue.is_selected = false;
        }
        Some(state)
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        Self::save_to(self, &Self::file_path())
    }

    /// Write atomically, through a temp file renamed over the target.
    ///
    /// The window and the WinMedicHelper task both write this file, and the
    /// window re-reads it every second. A plain write let either of them read,
    /// or leave behind, half a file.
    pub fn save_to(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Per process, so the two writers never share a temp file.
        let tmp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::issue::{RiskScore, Severity};

    #[test]
    fn test_scan_state_serialization_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "winmedic_scan_state_test_{}.json",
            std::process::id()
        ));
        let issue = Issue::new(
            "test_iss",
            "storage",
            "Corrupted volume",
            "Storage",
            Severity::Critical,
            RiskScore::High,
            "Desc",
            "Details",
            "Fix",
            vec!["Step 1".to_string()],
        );
        let statuses = vec![(
            "storage".to_string(),
            "Storage".to_string(),
            "[DSK]".to_string(),
            ModuleStatus::Critical(1),
        )];

        let state = ScanState::new(75, vec![issue], statuses, Some(12));
        state.save_to(&tmp).unwrap();

        let loaded = ScanState::load_from(&tmp).expect("should load saved scan state");
        assert_eq!(loaded.health_score, 75);
        assert_eq!(loaded.issues.len(), 1);
        assert_eq!(loaded.issues[0].id, "test_iss");
        assert_eq!(loaded.module_statuses.len(), 1);
        assert_eq!(loaded.scan_duration_secs, Some(12));

        let _ = std::fs::remove_file(&tmp);
    }

    /// A v0.5.0 file has no format and no advice flags; loading it would
    /// offer advice for repair.
    #[test]
    fn a_file_from_an_older_format_is_not_loaded() {
        let tmp = std::env::temp_dir().join(format!(
            "winmedic_scan_state_old_{}.json",
            std::process::id()
        ));
        let mut state = ScanState::new(90, Vec::new(), Vec::new(), None);
        let current = serde_json::to_value(&state).unwrap();
        assert_eq!(current["format"], FORMAT);

        state.format = 0;
        let mut old = serde_json::to_value(&state).unwrap();
        old.as_object_mut().unwrap().remove("format");
        std::fs::write(&tmp, old.to_string()).unwrap();

        assert!(ScanState::load_from(&tmp).is_none());
        let _ = std::fs::remove_file(&tmp);
    }

    /// A scan saved by 0.8.0 offered Windows' pending restart as a repair:
    /// ticked, or "repaired" and waiting for the restart. It loads as advice,
    /// and one that waits keeps waiting.
    #[test]
    fn a_pending_restart_saved_as_a_repair_loads_as_advice() {
        let tmp = std::env::temp_dir().join(format!(
            "winmedic_scan_state_reboot_{}.json",
            std::process::id()
        ));
        let mut ticked = crate::modules::windows_updates::reboot_pending_finding("w", "e");
        ticked.advice_only = false;
        ticked.is_selected = true;
        let mut waiting = ticked.clone();
        waiting.is_selected = false;
        waiting.is_reboot_pending = true;

        for (saved, waits) in [(ticked, false), (waiting, true)] {
            ScanState::new(90, vec![saved], Vec::new(), None)
                .save_to(&tmp)
                .unwrap();
            let loaded = ScanState::load_from(&tmp).unwrap().issues.remove(0);
            assert!(loaded.advice_only && !loaded.will_repair());
            assert_eq!(loaded.is_reboot_pending, waits);
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn this_machine_has_a_boot_counter() {
        assert!(current_boot_id().is_some_and(|id| id > 0));
    }

    fn saved(boot_id: Option<u32>, boot_time_secs: Option<u64>) -> ScanState {
        ScanState {
            boot_id,
            boot_time_secs,
            ..ScanState::new(100, Vec::new(), Vec::new(), None)
        }
    }

    #[test]
    fn the_boot_counter_decides_whether_windows_restarted() {
        let boot = 1_790_000_000;
        assert!(!restarted_since(
            &saved(Some(835), Some(boot)),
            Some(835),
            boot + 3
        ));
        assert!(restarted_since(
            &saved(Some(835), Some(boot)),
            Some(836),
            boot
        ));
    }

    /// A file saved before the counter was, compared by boot time: a clock
    /// correction or a wake from sleep moves that by seconds, not a restart.
    #[test]
    fn without_a_counter_the_boot_time_may_drift() {
        let boot = 1_790_000_000;
        let old = saved(None, Some(boot));
        assert!(!restarted_since(&old, Some(836), boot + 1));
        assert!(!restarted_since(&old, None, boot + 90));
        assert!(restarted_since(&old, None, boot + 3600));
        assert!(!restarted_since(&saved(None, None), Some(1), boot));
    }
}
