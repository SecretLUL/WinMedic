use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Default maximum size in bytes before rotating log files (5 MB).
pub const MAX_LOG_FILE_BYTES: u64 = 5 * 1024 * 1024;
/// How many entries "Recent activity" shows.
pub const RECENT_ENTRIES: usize = 10;
/// How much of the history's end is read first. An entry is about 225 bytes
/// on the development PC (17,232 in 3.9 MB), so this holds some 290.
const FIRST_WINDOW_BYTES: u64 = 64 * 1024;
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
            // The active file moves aside first, and nothing else happens
            // unless that worked. It was renamed last, with every result
            // ignored: while a program held the file open (a viewer that
            // follows it), each entry deleted the oldest generation, shifted
            // the others and then failed to move the active file, which was
            // still over the limit. After five entries all five generations
            // were gone and the file went on growing.
            //
            // One left over from a rotation that was cut off is finished
            // now instead of being written over.
            let aside = dir.join(format!("{}.0.{}", filename, ext));
            if !aside.exists() && std::fs::rename(&base_path, &aside).is_err() {
                return;
            }

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

            // What was the active log file becomes .1
            let first_backup = dir.join(format!("{}.1.{}", filename, ext));
            let _ = std::fs::rename(&aside, first_backup);
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
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(history_file)
        {
            append_entry(&mut f, &entry);
        }
    }

    /// The end of the history, oldest first: at least the last
    /// [`RECENT_ENTRIES`], when the file holds that many.
    ///
    /// For the window's "Recent activity". [`Self::get_history`] was read
    /// there, at the end of every scan and repair and whenever Settings
    /// opened: the whole file, up to 5 MB, parsed on the UI thread and every
    /// entry kept, to show ten (#281).
    pub fn recent_history(&self) -> Vec<AuditEntry> {
        self.history_end(|entries| entries.len() >= RECENT_ENTRIES)
    }

    /// The end of the history that reaches back to `since` (`%Y-%m-%d
    /// %H:%M:%S`, the log's own format), oldest first, for a report of what
    /// one run did. It starts with an entry older than `since` unless the
    /// file holds none: the caller picks its own.
    pub fn history_since(&self, since: &str) -> Vec<AuditEntry> {
        self.history_end(|entries| {
            entries
                .first()
                .is_some_and(|oldest| oldest.timestamp.as_str() < since)
        })
    }

    /// The entries at the end of the active file, oldest first: read from a
    /// window at its end that grows until `enough` says so or it is the
    /// whole file.
    fn history_end(&self, enough: impl Fn(&[AuditEntry]) -> bool) -> Vec<AuditEntry> {
        let Some(dir) = self.log_dir.as_deref() else {
            return Vec::new();
        };
        Self::migrate_legacy_json_if_needed(dir);
        let history_file = dir.join("history.jsonl");
        let mut window = FIRST_WINDOW_BYTES;
        loop {
            let mut entries = Vec::new();
            let whole_file = read_end(&history_file, window, &mut entries);
            if whole_file || enough(&entries) {
                return entries;
            }
            window = window.saturating_mul(4);
        }
    }

    /// Read all of the active history file, in chronological order. What the
    /// window shows and a report carries comes from
    /// [`Self::recent_history`] and [`Self::history_since`], which read its
    /// end only.
    ///
    /// Each line is read as a stream of entries: up to 0.8.0, two writers
    /// appending at the same moment could glue their entries onto one line
    /// (see `append_entry`), and reading one entry per line skipped it whole.
    /// A damaged entry costs the rest of its line.
    pub fn get_history(&self) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        let Some(dir) = self.log_dir.as_deref() else {
            return entries;
        };
        Self::migrate_legacy_json_if_needed(dir);
        let history_file = dir.join("history.jsonl");

        read_entries(&history_file, None, &mut entries);
        entries
    }

    /// Every entry on a line that holds `needle`, from the rotated files and
    /// the active one, oldest first.
    ///
    /// For a module that asks what WinMedic itself did weeks ago, which
    /// [`Self::get_history`] cannot answer: it reads the active file only,
    /// and all of it. Here a line that cannot match is not parsed, so six
    /// files of 5 MB cost a search and little else. A line that holds
    /// several entries (see [`Self::get_history`]) gives all of them: the
    /// caller still looks at each entry.
    pub fn history_mentioning(&self, needle: &str) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        let Some(dir) = self.log_dir.as_deref() else {
            return entries;
        };
        // `history.0.jsonl` is the active file of a rotation that was cut
        // off: newer than every numbered one.
        let rotated = (0..=MAX_ROTATED_FILES)
            .rev()
            .map(|generation| dir.join(format!("history.{generation}.jsonl")));
        for file in rotated.chain([dir.join("history.jsonl")]) {
            read_entries(&file, Some(needle), &mut entries);
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
                for entry in &legacy_entries {
                    append_entry(&mut f, entry);
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

/// Add the entries of the JSONL file `path` to `entries`, in the file's
/// order; with a `needle`, only those on a line that holds it. A file that
/// is not there adds nothing.
fn read_entries(path: &Path, needle: Option<&str>, entries: &mut Vec<AuditEntry>) {
    if let Ok(file) = File::open(path) {
        entries_from(BufReader::new(file), needle, entries);
    }
}

/// Add the entries in the last `window` bytes of the JSONL file `path` to
/// `entries`, in the file's order. Whether that was the whole file: also
/// said of a file that is not there or cannot be read, which has no more to
/// give.
///
/// A window that starts inside the file starts inside a line, so what comes
/// before the first line break is left out.
fn read_end(path: &Path, window: u64, entries: &mut Vec<AuditEntry>) -> bool {
    let Ok(mut file) = File::open(path) else {
        return true;
    };
    let Ok(len) = file.metadata().map(|meta| meta.len()) else {
        return true;
    };
    let start = len.saturating_sub(window);
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return true;
    }
    let mut reader = BufReader::new(file);
    if start > 0 && reader.read_until(b'\n', &mut Vec::new()).is_err() {
        return true;
    }
    entries_from(reader, None, entries);
    start == 0
}

/// Add the entries `reader` gives to `entries`; with a `needle`, only those
/// on a line that holds it.
fn entries_from(mut reader: impl BufRead, needle: Option<&str>, entries: &mut Vec<AuditEntry>) {
    let mut line = Vec::new();
    // Line by line as bytes: `lines()` gives an error for a line that is not
    // UTF-8, such as a write a power cut tore in the middle of a character,
    // and the loop ended there. Every later entry was written and never
    // shown or exported, until the file rotated.
    while reader
        .read_until(b'\n', &mut line)
        .is_ok_and(|read| read > 0)
    {
        let text = String::from_utf8_lossy(&line);
        if needle.is_none_or(|needle| text.contains(needle)) {
            entries.extend(
                serde_json::Deserializer::from_str(&text)
                    .into_iter::<AuditEntry>()
                    .map_while(Result::ok),
            );
        }
        drop(text);
        line.clear();
    }
}

/// Append `entry` and its line break with one write. As two writes, another
/// writer's entry could land in between: both on one line, an empty line
/// after them.
fn append_entry(file: &mut File, entry: &AuditEntry) {
    if let Ok(mut line) = serde_json::to_string(entry) {
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
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

    /// The doc comment promises that a damaged entry costs the rest of its
    /// line. A line that is not UTF-8 cost every entry after it.
    #[test]
    fn a_line_torn_inside_a_character_hides_no_later_entry() {
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_torn_line");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES);

        logger.log("SCAN", "network", "Before", "SUCCESS", "");
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(temp_dir.join("history.jsonl"))
                .unwrap();
            // "ä" is C3 A4; the write ended after the first byte.
            file.write_all(b"{\"timestamp\":\"2026-11-12 10:00:00\",\"title\":\"Ger\xC3\n")
                .unwrap();
        }
        logger.log("SCAN", "network", "After", "SUCCESS", "");

        let titles: Vec<String> = logger.get_history().into_iter().map(|e| e.title).collect();
        assert_eq!(titles, ["Before", "After"]);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    /// A history of `count` entries, one a second from 10:00:00 on, each
    /// about 1 KB: the first window holds some sixty of them.
    fn long_history(name: &str, count: u32) -> (PathBuf, AuditLogger) {
        let temp_dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let mut file = File::create(temp_dir.join("history.jsonl")).unwrap();
        let start = chrono::NaiveDate::from_ymd_opt(2026, 11, 13)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        for n in 0..count {
            append_entry(
                &mut file,
                &AuditEntry {
                    timestamp: (start + chrono::TimeDelta::seconds(n.into()))
                        .format("%Y-%m-%d %H:%M:%S")
                        .to_string(),
                    action_type: "SCAN".to_string(),
                    module_id: "network".to_string(),
                    title: format!("Entry {n}"),
                    status: "SUCCESS".to_string(),
                    details: "ä".repeat(450),
                },
            );
        }
        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES);
        (temp_dir, logger)
    }

    /// The window shows ten entries and read the whole file for them, up to
    /// 5 MB at the end of every scan and repair (#281).
    #[test]
    fn recent_activity_reads_only_the_end_of_the_history() {
        let (temp_dir, logger) = long_history("winmedic_audit_test_recent", 1000);
        let all = logger.get_history();
        assert_eq!(all.len(), 1000);
        assert!(
            std::fs::metadata(temp_dir.join("history.jsonl"))
                .unwrap()
                .len()
                > 900_000
        );

        let recent = logger.recent_history();
        // The end of the file, whole entries in the file's order, and far
        // from all of it. The window starts inside a line of two-byte
        // characters: that line is left out, not read as an entry.
        assert!(
            (RECENT_ENTRIES..100).contains(&recent.len()),
            "{}",
            recent.len()
        );
        assert_eq!(recent[..], all[all.len() - recent.len()..]);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    /// A file shorter than the window is read whole, and one with fewer
    /// entries than the window shows gives what it has.
    #[test]
    fn a_short_history_is_read_whole() {
        let (temp_dir, logger) = long_history("winmedic_audit_test_short", 3);
        assert_eq!(logger.recent_history(), logger.get_history());
        assert_eq!(logger.history_since("2026-11-13 00:00:00").len(), 3);
        assert_eq!(logger.recent_history().len(), 3);

        let _ = std::fs::remove_dir_all(&temp_dir);
        assert!(logger.recent_history().is_empty());
        assert!(logger.history_since("2026-11-13 00:00:00").is_empty());
    }

    /// A report carries what its run did, however much that was: the end
    /// that is read grows until it reaches back before the run.
    #[test]
    fn a_report_gets_every_entry_since_its_run_started() {
        let (temp_dir, logger) = long_history("winmedic_audit_test_since", 1000);
        let all = logger.get_history();
        // Entry 850 is some 140 KB from the end: outside the first window of
        // 64 KB, inside the second of 256 KB.
        let since = all[850].timestamp.clone();

        let read = logger.history_since(&since);
        assert!(read.len() < all.len(), "{}", read.len());
        assert!(read[0].timestamp < since, "{}", read[0].timestamp);
        let of_the_run: Vec<&AuditEntry> = read.iter().filter(|e| e.timestamp >= since).collect();
        assert_eq!(of_the_run.len(), 150);
        assert_eq!(of_the_run[0].title, "Entry 850");

        // A run that started before the first entry gets the whole file.
        assert_eq!(logger.history_since("2026-01-01 00:00:00"), all);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    /// While another program holds the log open, it cannot be renamed. Each
    /// entry then deleted one old generation.
    #[cfg(windows)]
    #[test]
    fn a_log_that_cannot_be_moved_costs_no_old_generation() {
        use std::os::windows::fs::OpenOptionsExt;
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_held_log");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), 64);

        logger.log(
            "SCAN",
            "network",
            "First",
            "SUCCESS",
            "long enough to pass 64 bytes",
        );
        for generation in 1..=MAX_ROTATED_FILES {
            for (name, ext) in [("history", "jsonl"), ("audit", "log")] {
                std::fs::write(temp_dir.join(format!("{name}.{generation}.{ext}")), "old").unwrap();
            }
        }
        // FILE_SHARE_READ | FILE_SHARE_WRITE, and not FILE_SHARE_DELETE,
        // which a rename needs: what a viewer that follows the file does.
        let held: Vec<File> = ["history.jsonl", "audit.log"]
            .iter()
            .map(|name| {
                OpenOptions::new()
                    .read(true)
                    .share_mode(0x3)
                    .open(temp_dir.join(name))
                    .unwrap()
            })
            .collect();

        for _ in 0..MAX_ROTATED_FILES + 1 {
            logger.log("SCAN", "network", "More", "SUCCESS", "");
        }
        for generation in 1..=MAX_ROTATED_FILES {
            for (name, ext) in [("history", "jsonl"), ("audit", "log")] {
                let old = temp_dir.join(format!("{name}.{generation}.{ext}"));
                assert_eq!(
                    std::fs::read_to_string(&old).ok().as_deref(),
                    Some("old"),
                    "{}",
                    old.display()
                );
            }
        }
        // The entries were still written, to the file that could not move.
        assert_eq!(logger.get_history().len(), MAX_ROTATED_FILES + 2);

        // Let go, the next entry rotates as it always did.
        drop(held);
        logger.log("SCAN", "network", "Rotates", "SUCCESS", "");
        assert!(
            std::fs::read_to_string(temp_dir.join("history.1.jsonl"))
                .unwrap()
                .contains("First")
        );
        assert!(!temp_dir.join("history.0.jsonl").exists());

        let _ = std::fs::remove_dir_all(temp_dir);
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

    /// Writers appending at the same moment, as the window and the scheduled
    /// background scan can: every entry stays on a line of its own.
    #[test]
    fn writers_at_the_same_moment_keep_one_entry_per_line() {
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_writers");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES);

        std::thread::scope(|s| {
            for writer in 0..8 {
                let logger = &logger;
                s.spawn(move || {
                    for entry in 0..100 {
                        let title = format!("Writer {writer}, entry {entry}");
                        logger.log("SCAN", "test_mod", &title, "SUCCESS", "");
                    }
                });
            }
        });

        let text = std::fs::read_to_string(temp_dir.join("history.jsonl")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 800);
        for line in lines {
            assert!(
                serde_json::from_str::<AuditEntry>(line).is_ok(),
                "not one entry: {line}"
            );
        }

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    /// The first 24 lines of the development PC's history.jsonl, written on
    /// 14 August 2026 by tests running side by side: 25 entries, five lines
    /// with two to four of them glued together, eight empty lines. One entry
    /// per line read 11 of them.
    const GLUED_LINES: &[u8] = include_bytes!("../../tests/fixtures/files/history_glued_lines.bin");

    #[test]
    fn entries_glued_onto_one_line_are_all_read() {
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_glued");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::fs::write(temp_dir.join("history.jsonl"), GLUED_LINES).unwrap();

        let history =
            AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES).get_history();

        assert_eq!(history.len(), 25);
        // The first glued line, in the order it was written.
        assert_eq!(history[4].module_id, "storage");
        assert_eq!(history[5].module_id, "system_integrity");
        assert_eq!(history[5].title, "System-Integrität (DISM / SFC / VSS)");
        // The last line holds four.
        let last = history.last().unwrap();
        assert_eq!(
            (last.module_id.as_str(), last.timestamp.as_str()),
            ("windows_updates", "2026-08-14 17:06:39")
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    /// A damaged entry costs the rest of its line, not the entries after it.
    #[test]
    fn a_damaged_entry_costs_only_the_rest_of_its_line() {
        let temp_dir = std::env::temp_dir().join("winmedic_audit_test_damaged");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let text = String::from_utf8(GLUED_LINES.to_vec()).unwrap();
        let first = text.lines().next().unwrap();
        let damaged = format!("{first}{{\"timestamp\":\"2026-08-14\n{first}\n");
        std::fs::write(temp_dir.join("history.jsonl"), damaged).unwrap();

        let history =
            AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES).get_history();

        assert_eq!(history.len(), 2);

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

    /// A question about what WinMedic did long ago reaches the rotated
    /// files, oldest first, and parses only the lines that can answer it.
    #[test]
    fn history_mentioning_reads_every_generation_oldest_first() {
        let temp_dir =
            std::env::temp_dir().join(format!("winmedic_audit_mention_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let line = |details: &str| {
            let mut line = serde_json::to_string(&AuditEntry {
                timestamp: "2026-08-22 00:11:46".to_string(),
                action_type: "FIX".to_string(),
                module_id: "scheduled_tasks".to_string(),
                title: "t".to_string(),
                status: "SUCCESS".to_string(),
                details: details.to_string(),
            })
            .unwrap();
            line.push('\n');
            line
        };
        let write = |name: &str, text: String| std::fs::write(temp_dir.join(name), text).unwrap();
        write(
            &format!("history.{MAX_ROTATED_FILES}.jsonl"),
            line("needle oldest") + "not json but with a needle\n",
        );
        write("history.2.jsonl", line("other") + &line("needle second"));
        // A rotation that was cut off left the active file here.
        write("history.0.jsonl", line("needle aside"));
        write("history.jsonl", line("needle newest") + &line("other"));

        let logger = AuditLogger::with_dir_and_size(temp_dir.clone(), MAX_LOG_FILE_BYTES);
        let found: Vec<String> = logger
            .history_mentioning("needle")
            .into_iter()
            .map(|entry| entry.details)
            .collect();
        assert_eq!(
            found,
            [
                "needle oldest",
                "needle second",
                "needle aside",
                "needle newest"
            ]
        );
        // The window's history still reads the active file, all of it.
        assert_eq!(logger.get_history().len(), 2);
        assert!(AuditLogger::inert().history_mentioning("needle").is_empty());

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
