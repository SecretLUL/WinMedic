//! Windows features whose installation Windows rolled back, from the ends
//! of CBS.log and the CbsPersist logs before it.
//!
//! A feature that needs a restart is finished by "advanced installers" while
//! Windows starts. When one of them fails, servicing rolls the whole
//! installation back, restarts once more, and the feature is simply off:
//! Windows Sandbox on the development PC, twice on 2026-10-08, with nothing
//! but 0x800f0922 to show for it. Which installer failed, and with what, is
//! in the CBS logs only, in English on every system.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// How much of the end of each CBS log is read first. The advanced
/// installers run while Windows starts, and on the development PC the run
/// that failed and the one that installed were each within half a megabyte
/// of the end of their log - the second after the Container Installer had
/// logged 40 MB.
pub const TAIL_BYTES: u64 = 8 * 1024 * 1024;

/// An advanced installer, and the service it waits for.
pub struct FeatureInstaller {
    /// Its GUID as CBS logs it, in lower case.
    pub guid: &'static str,
    /// What it installs, for the finding.
    pub features: &'static str,
    pub service: &'static str,
}

pub const INSTALLERS: &[FeatureInstaller] = &[
    // containerai.dll, which loads cmclient.dll, the Container Manager's
    // client. On the development PC it failed creating the container base
    // layer with 0x800706D9 (EPT_S_NOT_REGISTERED: nothing listened at the
    // Container Manager's endpoint) while CmService could not start (events
    // 7001 at the same starts), and went through once CmService ran.
    FeatureInstaller {
        guid: "{9edf0f01-ef44-4c87-ac5a-8aad730137ab}",
        features: "Windows Sandbox or another container feature",
        service: "CmService",
    },
];

/// The table's entry for the installer with `guid`.
pub fn installer(guid: &str) -> Option<&'static FeatureInstaller> {
    INSTALLERS
        .iter()
        .find(|entry| entry.guid.eq_ignore_ascii_case(guid))
}

/// An installation Windows rolled back because an advanced installer
/// failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollback {
    /// The installer as the log names it: `Container Installer`.
    pub installer: String,
    /// `{9edf0f01-…}`, in lower case.
    pub guid: String,
    /// What it failed with, as the log writes it:
    /// `HRESULT_FROM_WIN32(1753)`.
    pub hresult: String,
    /// When: `2026-10-08 21:19:36`.
    pub at: String,
    /// What it was installing:
    /// `Microsoft-Windows-Containers-DisposableClientVM 10.0.26100.9549`.
    pub components: Vec<String>,
}

const FAILED_ITEM: &str = "Failed execution of queue item Installer: ";

/// The installer failure on `line`, if it is one that is not ignored.
fn failure(line: &str) -> Option<Rollback> {
    let (head, rest) = line.split_once(FAILED_ITEM)?;
    // "Failure will not be ignored: A rollback will be initiated ..."
    if rest.contains("Failure will be ignored") {
        return None;
    }
    let (installer, rest) = rest.split_once(" ({")?;
    let (guid, rest) = rest.split_once("}) with HRESULT ")?;
    let hresult = rest.split_whitespace().next()?.trim_end_matches('.');
    Some(Rollback {
        installer: installer.trim().to_string(),
        guid: format!("{{{}}}", guid.to_ascii_lowercase()),
        hresult: hresult.to_string(),
        at: head.split(',').next()?.trim().to_string(),
        components: Vec::new(),
    })
}

/// `Microsoft-Windows-Containers-DisposableClientVM 10.0.26100.9549` from
/// the component in a `CSIPERF:AIDONE` line; `None` for `(null)`.
fn component(text: &str) -> Option<String> {
    let (name, rest) = text.split_once(", version ")?;
    let version = rest.split(',').next()?.trim();
    Some(format!("{} {version}", name.trim()))
}

/// The rollbacks in `log` - CBS log text, oldest first - that no later
/// servicing run made good, the newest of each installer.
///
/// A rollback is an installer's `Failed execution of queue item Installer:
/// <name> ({guid}) with HRESULT <hr>` and, after it, the queue's `Failed to
/// process advanced operation queue ... CBS_E_INSTALLERS_FAILED`. A later
/// run makes it good when the same installer completes in it (its
/// `CSIPERF:AIDONE` line, then `Completion status: S_OK`) and the run ends
/// `Processing complete. [HRESULT = 0x00000000 - S_OK]`. The run that rolls
/// back runs the installer too, uninstalling, and ends with
/// CBS_E_INSTALLERS_FAILED, so it does not count.
pub fn unresolved_rollbacks(log: &str) -> Vec<Rollback> {
    let mut reader = RollbackReader::default();
    for line in log.lines() {
        reader.line(line);
    }
    reader.rollbacks()
}

/// [`unresolved_rollbacks`], fed a line at a time, for logs too large to
/// hold at once.
#[derive(Debug, Default)]
pub struct RollbackReader {
    rolled_back: Vec<Rollback>,
    // The run being read: failures waiting for the queue's verdict, the
    // installers that completed, the components each worked on, and the
    // installer whose completion status comes next.
    failed: Vec<Rollback>,
    completed: Vec<String>,
    worked_on: Vec<(String, String)>,
    finishing: Option<String>,
}

impl RollbackReader {
    pub fn line(&mut self, line: &str) {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.trim_start().strip_prefix("CSIPERF:AIDONE;") {
            // `{guid};<component, version ..., arch ...>;<n>us`, the
            // component `(null)` for an installer's run as a whole.
            let Some((guid, rest)) = rest.split_once(';') else {
                return;
            };
            let guid = guid.to_ascii_lowercase();
            if let Some(component) = rest.rsplit_once(';').and_then(|(c, _)| component(c))
                && !self.worked_on.contains(&(guid.clone(), component.clone()))
            {
                self.worked_on.push((guid.clone(), component));
            }
            self.finishing = Some(guid);
        } else if let Some(status) = line.trim_start().strip_prefix("Completion status:") {
            if let Some(guid) = self.finishing.take()
                && status.trim() == "S_OK"
                && !self.completed.contains(&guid)
            {
                self.completed.push(guid);
            }
        } else if let Some(mut failure) = failure(line) {
            self.completed.retain(|guid| *guid != failure.guid);
            failure.components = self
                .worked_on
                .iter()
                .filter(|(guid, _)| *guid == failure.guid)
                .map(|(_, component)| component.clone())
                .collect();
            self.failed.push(failure);
        } else if line.contains("Failed to process advanced operation queue")
            && line.contains("CBS_E_INSTALLERS_FAILED")
        {
            for failure in self.failed.drain(..) {
                self.rolled_back
                    .retain(|earlier| earlier.guid != failure.guid);
                self.rolled_back.push(failure);
            }
        } else if line.contains("Processing complete.") && line.contains("[HRESULT = ") {
            if line.contains("[HRESULT = 0x00000000 - S_OK]") {
                let completed = &self.completed;
                self.rolled_back
                    .retain(|rollback| !completed.contains(&rollback.guid));
            }
            self.failed.clear();
            self.completed.clear();
            self.worked_on.clear();
            self.finishing = None;
        }
    }

    /// The rollbacks no later run made good, the newest of each installer.
    pub fn rollbacks(self) -> Vec<Rollback> {
        self.rolled_back
    }
}

/// The rollbacks in `logs`, oldest first, that no later installation made
/// good.
///
/// The last `tail_bytes` of each log are read first: that is where a start's
/// installers are logged. A rollback found there is then checked against
/// the logs as a whole, read a line at a time, since the installation that
/// made it good can lie further back in a newer log than the part read. A
/// rollback only further back than the ends is older than what they hold,
/// and is left alone.
pub fn rollbacks_in(logs: &[PathBuf], tail_bytes: u64) -> Vec<Rollback> {
    let ends: Vec<String> = logs
        .iter()
        .filter_map(|log| tail(log, tail_bytes))
        .collect();
    let found = unresolved_rollbacks(&ends.join("\n"));
    if found.is_empty() {
        return found;
    }
    let mut whole = RollbackReader::default();
    for log in logs {
        let Ok(file) = std::fs::File::open(log) else {
            continue;
        };
        for line in BufReader::new(file).split(b'\n').map_while(Result::ok) {
            whole.line(&String::from_utf8_lossy(&line));
        }
    }
    let whole = whole.rollbacks();
    found
        .into_iter()
        .filter(|rollback| {
            whole
                .iter()
                .any(|still| still.guid == rollback.guid && still.at == rollback.at)
        })
        .collect()
}

/// The end of `path`, from the first whole line in it.
fn tail(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(max_bytes)))
        .ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Some(if len > max_bytes {
        text.split_once('\n')
            .map_or_else(String::new, |(_, rest)| rest.to_string())
    } else {
        text
    })
}

/// The logs to read for `cbs_log`: the `CbsPersist_<time>.log` files beside
/// it, oldest first - their names sort by the time - then CBS.log itself.
/// The `.cab` archives of older ones are left alone.
pub fn cbs_logs(cbs_log: &Path) -> Vec<PathBuf> {
    let mut persisted: Vec<PathBuf> = cbs_log
        .parent()
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| {
                            let name = name.to_ascii_lowercase();
                            name.starts_with("cbspersist_") && name.ends_with(".log")
                        })
                })
                .collect()
        })
        .unwrap_or_default();
    persisted.sort();
    persisted.push(cbs_log.to_path_buf());
    persisted
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cut from the development PC's CBS logs: the Container Installer
    // failing at the start at 20:50 and the start that rolled it back
    // (CbsPersist_20261008190827.log), the same at 21:14
    // (CbsPersist_20261008192300.log), and the start at 23:01 that installed
    // Windows Sandbox (CbsPersist_20261008212907.log). See
    // tests/fixtures/README.md.
    const ROLLED_BACK: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_container_installer_rolled_back.bin");
    const ROLLED_BACK_AGAIN: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_container_installer_rolled_back_again.bin");
    const INSTALLED: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_container_installer_installed.bin");

    fn text(logs: &[&[u8]]) -> String {
        logs.iter()
            .map(|log| String::from_utf8_lossy(log))
            .collect()
    }

    const CONTAINER_INSTALLER: &str = "{9edf0f01-ef44-4c87-ac5a-8aad730137ab}";

    #[test]
    fn a_rolled_back_installation_is_found_with_its_installer() {
        let rollbacks = unresolved_rollbacks(&text(&[ROLLED_BACK]));
        assert_eq!(
            rollbacks,
            [Rollback {
                installer: "Container Installer".to_string(),
                guid: CONTAINER_INSTALLER.to_string(),
                hresult: "HRESULT_FROM_WIN32(1753)".to_string(),
                at: "2026-10-08 20:55:05".to_string(),
                components: vec![
                    "Microsoft-Windows-Containers-DisposableClientVM 10.0.26100.9549".to_string(),
                    "Microsoft-Windows-Professional-Config 10.0.26100.9550".to_string(),
                ],
            }]
        );
        assert_eq!(
            installer(&rollbacks[0].guid).map(|entry| entry.service),
            Some("CmService")
        );
    }

    /// Two rollbacks of the same installer are one, the newer.
    #[test]
    fn the_newest_rollback_of_an_installer_stands() {
        let rollbacks = unresolved_rollbacks(&text(&[ROLLED_BACK, ROLLED_BACK_AGAIN]));
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].at, "2026-10-08 21:19:36");
    }

    /// The development PC today: the installation at 23:01 went through.
    #[test]
    fn a_later_installation_makes_it_good() {
        let logs = text(&[ROLLED_BACK, ROLLED_BACK_AGAIN, INSTALLED]);
        assert!(unresolved_rollbacks(&logs).is_empty());
        // Read the other way round, the installation is older than the
        // rollbacks and makes nothing good.
        let reversed = text(&[INSTALLED, ROLLED_BACK]);
        assert_eq!(unresolved_rollbacks(&reversed).len(), 1);
    }

    /// The start that rolls back runs the installer too, uninstalling, with
    /// S_OK - and ends with CBS_E_INSTALLERS_FAILED.
    #[test]
    fn the_rollback_itself_is_no_installation() {
        let log = text(&[ROLLED_BACK]);
        let rollback_start = log
            .rfind("Startup: Processing advanced operation queue")
            .unwrap();
        assert!(log[rollback_start..].contains("operation flags Uninstall"));
        assert!(log[rollback_start..].contains("Completion status: S_OK"));
        assert_eq!(unresolved_rollbacks(&log).len(), 1);
    }

    /// Without the queue's CBS_E_INSTALLERS_FAILED a failed installer
    /// rolled nothing back.
    #[test]
    fn an_installer_failure_without_a_rollback_is_none() {
        let log = text(&[ROLLED_BACK])
            .lines()
            .filter(|line| !line.contains("CBS_E_INSTALLERS_FAILED"))
            .collect::<Vec<_>>()
            .join("\r\n");
        assert!(unresolved_rollbacks(&log).is_empty());
        let ignored =
            text(&[ROLLED_BACK]).replace("Failure will not be ignored", "Failure will be ignored");
        assert!(unresolved_rollbacks(&ignored).is_empty());
        assert!(unresolved_rollbacks("").is_empty());
    }

    /// Another installer in the same place: found, but not in the table.
    #[test]
    fn an_installer_the_table_does_not_know_is_still_found() {
        let log = text(&[ROLLED_BACK])
            .replace(
                CONTAINER_INSTALLER,
                "{00000000-1111-2222-3333-444444444444}",
            )
            .replace("Container Installer", "Other Installer");
        let rollbacks = unresolved_rollbacks(&log);
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].installer, "Other Installer");
        assert!(installer(&rollbacks[0].guid).is_none());
    }

    /// A folder of logs, removed when the test ends.
    struct Logs(PathBuf);

    impl Logs {
        fn new(tag: &str, logs: &[(&str, Vec<u8>)]) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("winmedic_rollback_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            for (name, bytes) in logs {
                std::fs::write(dir.join(name), bytes).unwrap();
            }
            Self(dir)
        }

        fn paths(&self, names: &[&str]) -> Vec<PathBuf> {
            names.iter().map(|name| self.0.join(name)).collect()
        }
    }

    impl Drop for Logs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Lines of other servicing, `count` of them.
    fn filler(count: usize) -> Vec<u8> {
        "2026-10-08 23:30:00, Info                  CBS    Exec: other servicing\r\n"
            .repeat(count)
            .into_bytes()
    }

    #[test]
    fn only_the_end_of_a_log_is_read_and_from_a_whole_line() {
        let mut log = ROLLED_BACK.to_vec();
        log.extend(filler(100));
        let logs = Logs::new("tail", &[("CbsPersist_1.log", log)]);
        let path = &logs.paths(&["CbsPersist_1.log"])[0];
        let whole = tail(path, 1 << 20).unwrap();
        assert_eq!(unresolved_rollbacks(&whole).len(), 1);
        let end = tail(path, filler(100).len() as u64 + 10).unwrap();
        assert!(end.starts_with("2026-10-08 23:30:00"), "{end:.80}");
        assert!(unresolved_rollbacks(&end).is_empty());
    }

    /// The rollbacks found in the ends of the logs, confirmed in the whole.
    #[test]
    fn a_rollback_at_the_end_is_reported() {
        let logs = Logs::new(
            "found",
            &[
                ("CbsPersist_1.log", ROLLED_BACK.to_vec()),
                ("CbsPersist_2.log", ROLLED_BACK_AGAIN.to_vec()),
            ],
        );
        let found = rollbacks_in(
            &logs.paths(&["CbsPersist_1.log", "CbsPersist_2.log"]),
            1 << 20,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].at, "2026-10-08 21:19:36");
    }

    /// The installation that made it good lies further back in the newer
    /// log than the part read first: it still counts.
    #[test]
    fn a_later_installation_beyond_the_end_read_still_counts() {
        let mut installed = INSTALLED.to_vec();
        installed.extend(filler(200));
        let logs = Logs::new(
            "beyond",
            &[
                ("CbsPersist_1.log", ROLLED_BACK.to_vec()),
                ("CbsPersist_2.log", installed),
            ],
        );
        let paths = logs.paths(&["CbsPersist_1.log", "CbsPersist_2.log"]);
        let ends: Vec<String> = paths.iter().filter_map(|p| tail(p, 8192)).collect();
        assert_eq!(
            unresolved_rollbacks(&ends.join("\n")).len(),
            1,
            "the ends alone miss the installation"
        );
        assert!(rollbacks_in(&paths, 8192).is_empty());
    }

    /// A rollback further back than the ends of the logs is older than what
    /// they hold, and is left alone.
    #[test]
    fn a_rollback_further_back_is_left_alone() {
        let mut log = ROLLED_BACK.to_vec();
        log.extend(filler(200));
        let logs = Logs::new("older", &[("CbsPersist_1.log", log)]);
        assert!(rollbacks_in(&logs.paths(&["CbsPersist_1.log"]), 8192).is_empty());
        assert!(rollbacks_in(&logs.paths(&["missing.log"]), 8192).is_empty());
    }

    #[test]
    fn the_logs_are_read_oldest_first_and_cbs_log_last() {
        let dir = std::env::temp_dir().join(format!("winmedic_cbs_logs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in [
            "CbsPersist_20261008212907.log",
            "CbsPersist_20261005120129.log",
            "CbsPersist_20261005062713.cab",
            "CBS.log",
            "FilterList.log",
        ] {
            std::fs::write(dir.join(name), b"").unwrap();
        }
        let names: Vec<String> = cbs_logs(&dir.join("CBS.log"))
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            names,
            [
                "CbsPersist_20261005120129.log",
                "CbsPersist_20261008212907.log",
                "CBS.log"
            ]
        );
    }
}
