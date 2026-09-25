//! What changed on the PC in the week before its crashes began.
//!
//! Crashes that start out of nowhere mostly start after something changed: an
//! update, a new driver, a new program. Windows logs all three, so the week
//! before the first crash can be laid out next to it. No log says which change
//! is to blame; the list is where to start.
//!
//! What decides is read from fields that are the same in every display
//! language: event ids, GUIDs, paths, a status number. Update titles and
//! program names are shown as Windows wrote them.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::utils::event_xml::EventRecord;
use chrono::{DateTime, Local, TimeDelta, Utc};

/// How far back the first crash of a series is looked for.
pub const SERIES_DAYS: i64 = 30;
/// How long before the first crash a change is listed.
pub const WEEK_DAYS: i64 = 7;
/// Listed at most: the ones closest to the crash.
const MAX_CHANGES: usize = 10;

pub const WU_PROVIDER: &str = "Microsoft-Windows-WindowsUpdateClient";
pub const SCM_PROVIDER: &str = "Service Control Manager";
pub const MSI_PROVIDER: &str = "MsiInstaller";

/// The Microsoft Store's update service: app updates, several a day.
const STORE_SERVICE: &str = "{855e8a7c-ecb4-4ca3-b045-1dfa50104289}";
/// Microsoft Defender's signature update, several a day.
const DEFENDER_SIGNATURES: &str = "KB2267602";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeKind {
    Update,
    Driver,
    Program,
}

impl ChangeKind {
    fn label(self) -> &'static str {
        match self {
            ChangeKind::Update => "Windows update",
            ChangeKind::Driver => "New driver",
            ChangeKind::Program => "Program installed",
        }
    }

    /// How to undo a change of this kind.
    pub fn undo(self) -> &'static str {
        match self {
            ChangeKind::Update => {
                "Uninstall an update: Settings -> Windows Update -> Update history -> Uninstall updates"
            }
            ChangeKind::Driver => {
                "Remove a new driver with the program that brought it: Settings -> Apps -> Installed apps"
            }
            ChangeKind::Program => "Uninstall a program: Settings -> Apps -> Installed apps",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub when: DateTime<Utc>,
    pub kind: ChangeKind,
    pub what: String,
}

impl Change {
    /// `25 Jul 23:59  New driver: BEDaisy (C:\...\BEDaisy.sys)`, local time.
    pub fn line(&self) -> String {
        format!(
            "{}  {}: {}",
            self.when.with_timezone(&Local).format("%d %b %H:%M"),
            self.kind.label(),
            self.what
        )
    }
}

/// When an event was logged.
pub fn logged_at(event: &EventRecord) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(event.time_created.as_deref()?)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// `2026-07-19T20:02:01.025Z`, the form an event log time filter compares.
pub fn xpath_time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Where the week before `first_crash` starts.
pub fn week_before(first_crash: DateTime<Utc>) -> DateTime<Utc> {
    first_crash - TimeDelta::days(WEEK_DAYS)
}

/// Updates Windows Update installed (event 19), without the Store's apps and
/// Defender's signatures.
pub fn updates(events: &[EventRecord]) -> Vec<Change> {
    events
        .iter()
        .filter(|e| e.provider == WU_PROVIDER && e.event_id == 19)
        .filter(|e| {
            e.data("serviceGuid")
                .is_none_or(|service| !service.eq_ignore_ascii_case(STORE_SERVICE))
        })
        .filter_map(|e| {
            let title = e.data("updateTitle")?;
            if title.contains(DEFENDER_SIGNATURES) {
                return None;
            }
            Some(Change {
                when: logged_at(e)?,
                kind: ChangeKind::Update,
                what: title.to_string(),
            })
        })
        .collect()
}

/// Kernel drivers (a service whose image is a `.sys` file, event 7045), each
/// at its first install.
///
/// Tools that load a driver while they run register it again on every start,
/// so only the first event of a service is a change. `events` has to reach
/// back further than the week for that to be known.
pub fn new_drivers(events: &[EventRecord]) -> Vec<Change> {
    let mut drivers: Vec<(String, Change)> = Vec::new();
    for event in events
        .iter()
        .filter(|e| e.provider == SCM_PROVIDER && e.event_id == 7045)
    {
        let (Some(name), Some(image), Some(when)) = (
            event.data("ServiceName"),
            event.data("ImagePath"),
            logged_at(event),
        ) else {
            continue;
        };
        if !image
            .trim_matches('"')
            .to_ascii_lowercase()
            .ends_with(".sys")
        {
            continue;
        }
        let change = Change {
            when,
            kind: ChangeKind::Driver,
            what: format!("{name} ({})", image.trim_matches('"')),
        };
        match drivers
            .iter_mut()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
        {
            Some((_, first)) if first.when <= when => {}
            Some((_, first)) => *first = change,
            None => drivers.push((name.to_string(), change)),
        }
    }
    drivers.into_iter().map(|(_, change)| change).collect()
}

/// Programs Windows Installer installed (event 1033 with status 0), each
/// name and version at its first install. Its fields have no names: product,
/// version, language, status, manufacturer.
pub fn new_programs(events: &[EventRecord]) -> Vec<Change> {
    let mut programs: Vec<Change> = Vec::new();
    for event in events
        .iter()
        .filter(|e| e.provider == MSI_PROVIDER && e.event_id == 1033)
    {
        let field = |at: usize| event.data.get(at).map(|(_, value)| value.as_str());
        let (Some(name), Some(version), Some("0"), Some(when)) =
            (field(0), field(1), field(3), logged_at(event))
        else {
            continue;
        };
        // "Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219"
        // carries its version already, and a double space.
        let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
        let what = if name.contains(version) {
            name
        } else {
            format!("{name} {version}")
        };
        match programs.iter_mut().find(|known| known.what == what) {
            Some(first) if first.when <= when => {}
            Some(first) => first.when = when,
            None => programs.push(Change {
                when,
                kind: ChangeKind::Program,
                what,
            }),
        }
    }
    programs
}

/// The finding that lays the week out. Advice: which change to undo is the
/// user's call.
pub fn finding(module_id: &str, first_crash: DateTime<Utc>, changes: &[Change]) -> Issue {
    let mut kinds: Vec<ChangeKind> = changes.iter().map(|c| c.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let first = first_crash.with_timezone(&Local).format("%d %b %Y, %H:%M");
    Issue::new(
        "crash_what_changed",
        module_id,
        format!(
            "{} change(s) in the week before the crashes began",
            changes.len()
        ),
        "Hardware & Stability",
        Severity::Info,
        RiskScore::Low,
        format!(
            "The first crash of the last {SERIES_DAYS} days was on {first}. In the week before it, Windows installed what the details list. Crashes that start after a change often come from it; undoing the change is the quickest test."
        ),
        format!(
            "First crash: {first}\n{}",
            changes
                .iter()
                .map(Change::line)
                .collect::<Vec<_>>()
                .join("\n")
        ),
        "Undo the change that fits best and see whether the crashes stop",
        kinds.into_iter().map(|k| k.undo().to_string()).collect(),
    )
    .with_advice_only()
}

/// The changes in the week before `first_crash`, oldest first; the ten
/// closest to it when there are more.
pub fn before(first_crash: DateTime<Utc>, mut changes: Vec<Change>) -> Vec<Change> {
    let from = week_before(first_crash);
    changes.retain(|c| c.when >= from && c.when <= first_crash);
    changes.sort_by_key(|c| c.when);
    let excess = changes.len().saturating_sub(MAX_CHANGES);
    changes.drain(..excess);
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::decode::{CodePage, decode_output_in};
    use crate::utils::event_xml::parse_events;

    // Captured on a German Windows 11; see tests/fixtures/README.md.
    const WU: &[u8] = include_bytes!("../../tests/fixtures/events/wevtutil_wu_installed_19_de.bin");
    const SERVICES: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_service_installed_7045.bin");
    const MSI: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_msi_installed_1033.bin");
    const CRASHES: &[u8] = include_bytes!("../../tests/fixtures/events/wevtutil_crashes_july.bin");

    fn events(bytes: &[u8]) -> Vec<EventRecord> {
        parse_events(&decode_output_in(bytes, CodePage::Ansi))
    }

    fn at(time: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(time)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// The first crash in the captured log: 26 July, 22:02 local time.
    fn first_crash() -> DateTime<Utc> {
        events(CRASHES).iter().filter_map(logged_at).min().unwrap()
    }

    #[test]
    fn the_first_crash_is_the_earliest_event() {
        assert_eq!(first_crash(), at("2026-07-26T20:02:01.0258131Z"));
    }

    #[test]
    fn store_apps_and_defender_signatures_are_not_changes() {
        let updates = updates(&events(WU));
        assert_eq!(updates.len(), 1, "{updates:?}");
        assert_eq!(
            updates[0].what,
            "Sicherheitsupdate für Microsoft Visual C++ 2010 Service Pack 1 Redistributable Package (KB2565063)"
        );
    }

    #[test]
    fn a_driver_counts_at_its_first_install_only() {
        let drivers = new_drivers(&events(SERVICES));
        let names: Vec<&str> = drivers
            .iter()
            .map(|d| d.what.split(' ').next().unwrap())
            .collect();
        // Services that run an .exe are not drivers.
        assert!(!names.contains(&"Docker"), "{names:?}");
        let bedaisy = drivers
            .iter()
            .find(|d| d.what.starts_with("BEDaisy "))
            .unwrap();
        assert_eq!(
            bedaisy.what,
            r"BEDaisy (C:\Program Files (x86)\Common Files\BattlEye\BEDaisy.sys)"
        );
        // Registered again on the 26th, first installed on the 25th.
        assert!(bedaisy.when < at("2026-07-26T00:00:00Z"), "{bedaisy:?}");
        let magician = drivers
            .iter()
            .find(|d| d.what.starts_with("MagicianSataModeReader "))
            .unwrap();
        assert!(magician.when < week_before(first_crash()), "{magician:?}");
    }

    #[test]
    fn a_program_counts_at_its_first_install_only() {
        let programs = new_programs(&events(MSI));
        let names: Vec<&str> = programs.iter().map(|p| p.what.as_str()).collect();
        assert!(names.contains(&"Paint.NET 5.1.12"), "{names:?}");
        assert!(
            names.contains(&"Microsoft Visual C++ 2010 x64 Redistributable - 10.0.40219"),
            "{names:?}"
        );
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "{names:?}");
    }

    #[test]
    fn the_week_before_the_first_crash_is_laid_out() {
        let mut changes = updates(&events(WU));
        changes.extend(new_drivers(&events(SERVICES)));
        changes.extend(new_programs(&events(MSI)));
        let week = before(first_crash(), changes);

        assert!(week.len() <= MAX_CHANGES);
        assert!(week.windows(2).all(|pair| pair[0].when <= pair[1].when));
        assert!(week.iter().all(|c| c.when >= week_before(first_crash())));
        assert!(
            week.iter()
                .any(|c| c.kind == ChangeKind::Driver && c.what.starts_with("BEDaisy ")),
            "{week:#?}"
        );
        assert!(
            !week
                .iter()
                .any(|c| c.what.starts_with("MagicianSataModeReader ")),
            "{week:#?}"
        );
        // The last change before the crash: the Visual C++ update that
        // afternoon.
        assert_eq!(week.last().unwrap().kind, ChangeKind::Update, "{week:#?}");
    }

    #[test]
    fn only_the_changes_closest_to_the_crash_are_kept() {
        let crash = at("2026-07-26T20:00:00Z");
        let changes: Vec<Change> = (0..15)
            .map(|hour| Change {
                when: crash - TimeDelta::hours(hour),
                kind: ChangeKind::Program,
                what: format!("program {hour}"),
            })
            .collect();
        let kept = before(crash, changes);
        assert_eq!(kept.len(), MAX_CHANGES);
        assert_eq!(kept.first().unwrap().what, "program 9");
        assert_eq!(kept.last().unwrap().what, "program 0");
    }
}
