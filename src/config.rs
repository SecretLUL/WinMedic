use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// File name of the config file inside the WinMedic config directory.
pub const CONFIG_FILE_NAME: &str = "config.json";

/// What [`AppConfig::load_from`] found on disk.
///
/// The distinction between [`Self::Missing`] and [`Self::Corrupt`] is the point
/// of this type. Collapsing both into "use the defaults" is what previously let
/// a truncated write silently re-enable settings the user had deliberately
/// turned off, with nothing shown to say it had happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigStatus {
    /// No config file yet — the normal first run. Defaults apply, silently.
    Missing,
    /// Read and parsed from disk.
    Loaded,
    /// A file was there but could not be used. Defaults apply, and the
    /// unreadable file was preserved at `quarantined` unless moving it aside
    /// failed too.
    Corrupt {
        error: String,
        quarantined: Option<PathBuf>,
    },
}

impl ConfigStatus {
    /// Message worth putting in front of the user, if any.
    ///
    /// `Missing` and `Loaded` are both unremarkable, so neither produces one.
    pub fn warning(&self) -> Option<String> {
        match self {
            Self::Missing | Self::Loaded => None,
            Self::Corrupt {
                error,
                quarantined: Some(path),
            } => Some(format!(
                "Settings could not be read ({}). Defaults are in effect; \
                 the previous file was preserved at {}.",
                error,
                path.display()
            )),
            Self::Corrupt {
                error,
                quarantined: None,
            } => Some(format!(
                "Settings could not be read ({}) and the file could not be \
                 moved aside. Defaults are in effect and saving will overwrite it.",
                error
            )),
        }
    }

    pub fn is_corrupt(&self) -> bool {
        matches!(self, Self::Corrupt { .. })
    }
}

/// Move an unusable config file aside, returning where it was preserved.
///
/// Mirrors what `safety::reg_backup` does with a malformed backup index: the
/// file is renamed rather than deleted, so whatever the user had in there is
/// still recoverable by hand.
fn quarantine(path: &Path) -> Result<PathBuf, std::io::Error> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| CONFIG_FILE_NAME.to_string());
    let stamp = Local::now().format("%Y%m%d_%H%M%S");

    let mut dest = dir.join(format!("{}.corrupt-{}", file_name, stamp));
    // Two failures inside the same second must not overwrite each other.
    let mut counter = 1;
    while dest.exists() {
        dest = dir.join(format!("{}.corrupt-{}-{}", file_name, stamp, counter));
        counter += 1;
    }

    std::fs::rename(path, &dest)?;
    Ok(dest)
}

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
    /// Check for newer WinMedic releases on GitHub upon startup.
    pub check_for_updates: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_restart_services: true,
            create_vss_before_repair: true,
            auto_backup_registry: true,
            temp_clean_threshold_mb: 500,
            max_event_log_hours: 24,
            check_for_updates: true,
        }
    }
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("WinMedic").join(CONFIG_FILE_NAME)
    }

    /// Load the config, discarding any information about how it went.
    ///
    /// Prefer [`Self::load_reporting`] anywhere the result can be shown to the
    /// user — this variant cannot tell a first run apart from a corrupt file.
    pub fn load() -> Self {
        Self::load_reporting().0
    }

    /// Load the config from the standard location, reporting what happened.
    pub fn load_reporting() -> (Self, ConfigStatus) {
        Self::load_from(&Self::config_path())
    }

    /// Load the config from an explicit path.
    ///
    /// This is the seam the tests use so they operate on a sandbox rather than
    /// the real `%APPDATA%\WinMedic\config.json`.
    ///
    /// An unusable file is moved aside before the caller gets a chance to save
    /// over it, so a hand edit with one missing brace costs the user their
    /// settings for this session but never the file itself.
    pub fn load_from(path: &Path) -> (Self, ConfigStatus) {
        let data = match std::fs::read_to_string(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (Self::default(), ConfigStatus::Missing);
            }
            Err(e) => {
                let error = format!("could not read {}: {}", path.display(), e);
                let quarantined = quarantine(path).ok();
                return (
                    Self::default(),
                    ConfigStatus::Corrupt { error, quarantined },
                );
            }
        };

        match serde_json::from_str(&data) {
            Ok(cfg) => (cfg, ConfigStatus::Loaded),
            Err(e) => {
                let error = format!("{} is malformed: {}", CONFIG_FILE_NAME, e);
                let quarantined = quarantine(path).ok();
                (
                    Self::default(),
                    ConfigStatus::Corrupt { error, quarantined },
                )
            }
        }
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        self.save_to(&Self::config_path())
    }

    /// Persist the config to an explicit path, atomically.
    ///
    /// The write goes to a temp file that is then renamed over the target, so
    /// an interrupted save leaves the previous config intact rather than a
    /// half-written file that fails to parse on the next start.
    pub fn save_to(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;

        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;

        // `std::fs::rename` replaces the destination on both Unix and Windows.
        std::fs::rename(&tmp_path, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })
    }

    /// Number of editable settings exposed in the settings tab.
    pub const SETTING_COUNT: usize = 6;

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
                "Automatisch nach Updates suchen",
                on_off(self.check_for_updates),
                "Prüft beim Programmstart im Hintergrund auf neue WinMedic-Releases auf GitHub.",
            )),
            4 => Some((
                "Schwelle für Temp-Dateien",
                format!("{} MB", self.temp_clean_threshold_mb),
                "Ab dieser Gesamtgröße werden temporäre Dateien als Problem gemeldet. [←/→] ±100 MB.",
            )),
            5 => Some((
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
            3 => self.check_for_updates = !self.check_for_updates,
            _ => return false,
        }
        true
    }

    /// Increase (`delta > 0`) or decrease the numeric setting at `index`.
    /// Returns true if anything changed.
    pub fn adjust_setting(&mut self, index: usize, increase: bool) -> bool {
        match index {
            4 => {
                let new = if increase {
                    (self.temp_clean_threshold_mb + 100).min(100_000)
                } else {
                    self.temp_clean_threshold_mb.saturating_sub(100).max(100)
                };
                let changed = new != self.temp_clean_threshold_mb;
                self.temp_clean_threshold_mb = new;
                changed
            }
            5 => {
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

    /// Minimal scoped temp directory; the crate has no dev-dependency on `tempfile`.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = format!(
                "winmedic_config_{}_{}_{:?}",
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

        fn config(&self) -> PathBuf {
            self.path.join(CONFIG_FILE_NAME)
        }

        /// Files the quarantine routine left behind.
        fn corrupt_copies(&self) -> Vec<PathBuf> {
            let mut found: Vec<PathBuf> = std::fs::read_dir(&self.path)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.contains(".corrupt-"))
                })
                .collect();
            found.sort();
            found
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn missing_file_is_not_reported_as_corrupt() {
        let dir = TempDir::new("missing");
        let (cfg, status) = AppConfig::load_from(&dir.config());

        // A first run must stay silent — there is nothing wrong with it.
        assert_eq!(status, ConfigStatus::Missing);
        assert!(!status.is_corrupt());
        assert_eq!(status.warning(), None);
        assert_eq!(cfg, AppConfig::default());
        assert!(dir.corrupt_copies().is_empty());
    }

    #[test]
    fn saved_config_round_trips_through_disk() {
        let dir = TempDir::new("roundtrip");
        let mut cfg = AppConfig::default();
        cfg.toggle_setting(0); // create_vss_before_repair -> false
        cfg.adjust_setting(4, true); // threshold -> 600

        cfg.save_to(&dir.config()).unwrap();
        let (loaded, status) = AppConfig::load_from(&dir.config());

        assert_eq!(status, ConfigStatus::Loaded);
        assert_eq!(status.warning(), None);
        assert_eq!(loaded, cfg);
        assert!(!loaded.create_vss_before_repair);
    }

    #[test]
    fn malformed_file_is_reported_and_preserved() {
        let dir = TempDir::new("malformed");
        // A hand edit that dropped a brace — indistinguishable from "no file"
        // under the old load(), which is exactly the bug.
        std::fs::write(dir.config(), r#"{"create_vss_before_repair": false"#).unwrap();

        let (cfg, status) = AppConfig::load_from(&dir.config());

        assert!(status.is_corrupt());
        assert!(status.warning().is_some());
        // Defaults apply, which means the setting the user turned *off* is back
        // on — precisely why this has to be visible rather than silent.
        assert_eq!(cfg, AppConfig::default());
        assert!(cfg.create_vss_before_repair);

        // The original bytes still exist under a quarantined name.
        let preserved = dir.corrupt_copies();
        assert_eq!(preserved.len(), 1, "expected exactly one quarantined file");
        assert!(
            std::fs::read_to_string(&preserved[0])
                .unwrap()
                .contains("create_vss_before_repair")
        );
        // And the unusable file is gone from the live path, so the next save
        // writes a clean config rather than appending to wreckage.
        assert!(!dir.config().exists());
    }

    #[test]
    fn truncated_file_is_treated_as_corrupt() {
        let dir = TempDir::new("truncated");
        // What a crash mid-write leaves behind.
        std::fs::write(dir.config(), "").unwrap();

        let (cfg, status) = AppConfig::load_from(&dir.config());

        assert!(status.is_corrupt());
        assert_eq!(cfg, AppConfig::default());
        assert_eq!(dir.corrupt_copies().len(), 1);
    }

    #[test]
    fn quarantine_does_not_clobber_an_earlier_quarantine() {
        let dir = TempDir::new("twice");

        std::fs::write(dir.config(), "first broken").unwrap();
        let (_, first) = AppConfig::load_from(&dir.config());
        assert!(first.is_corrupt());

        std::fs::write(dir.config(), "second broken").unwrap();
        let (_, second) = AppConfig::load_from(&dir.config());
        assert!(second.is_corrupt());

        // Both failures happen inside the same second, so the collision
        // counter is what keeps the first one from being overwritten.
        let preserved = dir.corrupt_copies();
        assert_eq!(preserved.len(), 2);
        let contents: Vec<String> = preserved
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();
        assert!(contents.contains(&"first broken".to_string()));
        assert!(contents.contains(&"second broken".to_string()));
    }

    #[test]
    fn save_leaves_no_temp_file_behind() {
        let dir = TempDir::new("atomic");
        AppConfig::default().save_to(&dir.config()).unwrap();

        let leftovers: Vec<PathBuf> = std::fs::read_dir(&dir.path)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp file left behind: {:?}",
            leftovers
        );
    }

    #[test]
    fn save_replaces_an_existing_config_without_a_partial_window() {
        let dir = TempDir::new("replace");
        std::fs::write(dir.config(), r#"{"temp_clean_threshold_mb": 999}"#).unwrap();

        let cfg = AppConfig {
            temp_clean_threshold_mb: 4242,
            ..Default::default()
        };
        cfg.save_to(&dir.config()).unwrap();

        let (loaded, status) = AppConfig::load_from(&dir.config());
        assert_eq!(status, ConfigStatus::Loaded);
        assert_eq!(loaded.temp_clean_threshold_mb, 4242);
    }

    #[test]
    fn partial_json_still_loads_cleanly() {
        // Distinct from corruption: a config written by an older version is
        // valid JSON with fields missing, and must not be quarantined.
        let dir = TempDir::new("partial");
        std::fs::write(dir.config(), r#"{"max_event_log_hours": 48}"#).unwrap();

        let (cfg, status) = AppConfig::load_from(&dir.config());
        assert_eq!(status, ConfigStatus::Loaded);
        assert_eq!(cfg.max_event_log_hours, 48);
        assert_eq!(cfg.temp_clean_threshold_mb, 500);
        assert!(dir.corrupt_copies().is_empty());
    }

    #[test]
    fn test_default_config() {
        let cfg = AppConfig::default();
        assert!(cfg.create_vss_before_repair);
        assert!(cfg.auto_restart_services);
        assert!(cfg.auto_backup_registry);
        assert!(cfg.check_for_updates);
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
        assert!(cfg.check_for_updates);
    }

    #[test]
    fn test_config_roundtrip() {
        let mut cfg = AppConfig::default();
        cfg.toggle_setting(0);
        cfg.toggle_setting(3);
        cfg.adjust_setting(4, true);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
        assert!(!restored.create_vss_before_repair);
        assert!(!restored.check_for_updates);
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
            cfg.adjust_setting(4, false);
            cfg.adjust_setting(5, false);
        }
        assert_eq!(cfg.temp_clean_threshold_mb, 100);
        assert_eq!(cfg.max_event_log_hours, 1);
    }

    #[test]
    fn test_toggle_update_setting() {
        let mut cfg = AppConfig::default();
        assert!(cfg.check_for_updates);
        assert!(cfg.toggle_setting(3));
        assert!(!cfg.check_for_updates);
        assert!(cfg.toggle_setting(3));
        assert!(cfg.check_for_updates);
        assert!(!cfg.toggle_setting(99));
    }
}
