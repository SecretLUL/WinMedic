//! What changed on the PC in the week before its crashes began.
//!
//! Crashes that start out of nowhere mostly start after something changed: an
//! update, a new driver, a new program. Windows logs all three, so the week
//! before the first crash can be laid out next to it. No log says which change
//! is to blame; the list is where to start. A restore point from before the
//! first crash takes back all of them at once, and what no log names.
//!
//! What decides is read from fields that are the same in every display
//! language: event ids, GUIDs, paths, a status number. Update titles and
//! program names are shown as Windows wrote them.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::safety::restore_point::RestorePoint;
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
pub const STORE_SERVICE: &str = "{855e8a7c-ecb4-4ca3-b045-1dfa50104289}";
/// Microsoft Defender's signature update, several a day.
pub const DEFENDER_SIGNATURES: &str = "KB2267602";

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

/// Crash events closer together than this are one crash: a bugcheck logs its
/// event 1001 and a Kernel-Power 41 at the same start.
const SAME_CRASH_MINUTES: i64 = 15;
/// A series takes at least this many crashes. One unexpected shutdown, a
/// power cut say, starts none.
pub const MIN_SERIES: usize = 2;

/// The first crash of a series among the times crash events were logged, or
/// `None` when they make fewer than [`MIN_SERIES`] crashes.
pub fn first_of_series(mut logged: Vec<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    logged.sort_unstable();
    let crashes = logged
        .windows(2)
        .filter(|pair| pair[1] - pair[0] > TimeDelta::minutes(SAME_CRASH_MINUTES))
        .count()
        + usize::from(!logged.is_empty());
    (crashes >= MIN_SERIES).then(|| logged[0])
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

/// The restore point the timeline names: the newest one made before the
/// first crash. System Restore to it takes back every change since, the
/// listed ones and those no log names. With no change listed, only a point
/// from the week before the first crash is named: an older one would take
/// back weeks of changes nothing points at.
pub fn point_before(
    first_crash: DateTime<Utc>,
    points: Vec<RestorePoint>,
    changes: &[Change],
) -> Option<RestorePoint> {
    let from = changes.is_empty().then(|| week_before(first_crash));
    points
        .into_iter()
        .filter(|p| {
            p.created
                .is_some_and(|t| t < first_crash && from.is_none_or(|from| t >= from))
        })
        .max_by_key(|p| (p.created, p.sequence))
}

/// The finding that lays the week out, and names the restore point from
/// before it. Advice: which change to undo, and whether to go back to the
/// point, is the user's call.
pub fn finding(
    module_id: &str,
    first_crash: DateTime<Utc>,
    changes: &[Change],
    point: Option<&RestorePoint>,
) -> Issue {
    let mut kinds: Vec<ChangeKind> = changes.iter().map(|c| c.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let first = first_crash.with_timezone(&Local).format("%d %b %Y, %H:%M");
    let (title, mut description, fix) = if changes.is_empty() {
        (
            "A restore point from before the crashes began".to_string(),
            format!(
                "The first crash of the last {SERIES_DAYS} days was on {first}. The event logs name no change in the week before it."
            ),
            "Go back to the restore point and see whether the crashes stop",
        )
    } else {
        (
            format!(
                "{} change(s) in the week before the crashes began",
                changes.len()
            ),
            format!(
                "The first crash of the last {SERIES_DAYS} days was on {first}. In the week before it, Windows installed what the details list. Crashes that start after a change often come from it; undoing the change is the quickest test."
            ),
            "Undo the change that fits best and see whether the crashes stop",
        )
    };
    let mut details = vec![format!("First crash: {first}")];
    let mut steps: Vec<String> = kinds.into_iter().map(|k| k.undo().to_string()).collect();
    if let Some(point) = point {
        let when = point.time_in(&Local);
        // Microsoft: System Restore reverts system files, registry settings
        // and installed programs, without affecting personal files.
        description.push_str(&format!(
            " A restore point from {when} is older than the first crash. System Restore to it removes the programs, drivers and updates installed since, listed or not, and keeps personal files."
        ));
        details.push(format!(
            "Restore point before it: {when}  {}",
            point.description
        ));
        steps.push(format!(
            "Go back to before the crashes: System Restore (rstrui.exe) -> choose the point of {when}, \"{}\"",
            point.description
        ));
    }
    details.extend(changes.iter().map(Change::line));
    Issue::new(
        "crash_what_changed",
        module_id,
        title,
        "Hardware & Stability",
        Severity::Info,
        RiskScore::Low,
        description,
        details.join("\n"),
        fix,
        steps,
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
        let logged = events(CRASHES).iter().filter_map(logged_at).collect();
        assert_eq!(first_of_series(logged), Some(first_crash()));
    }

    #[test]
    fn one_crash_is_no_series() {
        assert_eq!(first_of_series(Vec::new()), None);
        let crash = at("2026-09-26T00:43:10Z");
        assert_eq!(first_of_series(vec![crash]), None);
        // Event 1001 and Kernel-Power 41 of the same start.
        let same = crash + TimeDelta::seconds(40);
        assert_eq!(first_of_series(vec![same, crash]), None);
        let next_day = crash + TimeDelta::days(1);
        assert_eq!(first_of_series(vec![next_day, same, crash]), Some(crash));
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

    // The restore points of the development PC, 249 to 255 on 8 and 9
    // October; see tests/fixtures/README.md.
    const POINTS: &str = include_str!("../../tests/fixtures/console/powershell_restore_points.txt");

    fn points() -> Vec<RestorePoint> {
        crate::safety::restore_point::parse_restore_points(POINTS)
    }

    /// How the finding shows a time, in this machine's zone.
    fn local(time: &str) -> String {
        at(time)
            .with_timezone(&Local)
            .format("%d %b %Y, %H:%M")
            .to_string()
    }

    fn a_change_before(crash: DateTime<Utc>) -> Vec<Change> {
        vec![Change {
            when: crash - TimeDelta::hours(30),
            kind: ChangeKind::Program,
            what: "Paint.NET 5.1.12".to_string(),
        }]
    }

    /// A series that began between point 253 (11:33 UTC) and 254 (15:38
    /// UTC) names 253, with its time converted from the WMI date.
    #[test]
    fn the_newest_point_before_the_first_crash_is_named() {
        let crash = at("2026-10-09T14:02:01Z");
        let changes = a_change_before(crash);
        let point = point_before(crash, points(), &changes).expect("point 253");
        assert_eq!(point.sequence, 253);

        let issue = finding("crash_analysis", crash, &changes, Some(&point));
        let when = local("2026-10-09T11:33:42.770309Z");
        assert!(issue.advice_only && !issue.is_selected);
        assert_eq!(
            issue.title,
            "1 change(s) in the week before the crashes began"
        );
        let details = &issue.technical_details;
        assert!(
            details.contains(&format!(
                "Restore point before it: {when}  WinMedic Auto-Restore Point (before repairs)"
            )),
            "{details}"
        );
        assert!(
            details.contains("Program installed: Paint.NET 5.1.12"),
            "{details}"
        );
        assert!(!details.contains("20261009113342"), "{details}");
        assert!(issue.description.contains("keeps personal files"));
        assert_eq!(
            issue.fix_steps,
            [
                ChangeKind::Program.undo().to_string(),
                format!(
                    "Go back to before the crashes: System Restore (rstrui.exe) -> choose the point of {when}, \"WinMedic Auto-Restore Point (before repairs)\""
                ),
            ]
        );
    }

    /// Every point is younger than the first crash: none is named, and the
    /// finding is the one without a point.
    #[test]
    fn no_point_before_the_first_crash_names_none() {
        let crash = at("2026-10-08T12:00:00Z");
        let changes = a_change_before(crash);
        assert_eq!(point_before(crash, points(), &changes), None);
        assert_eq!(point_before(crash, Vec::new(), &changes), None);

        let issue = finding("crash_analysis", crash, &changes, None);
        assert!(!issue.technical_details.contains("Restore point"));
        assert!(!issue.description.contains("restore point"));
        assert_eq!(issue.fix_steps, [ChangeKind::Program.undo().to_string()]);
    }

    /// With no change listed, a point from the week before the first crash
    /// is still worth naming; an older one is not.
    #[test]
    fn without_changes_only_a_point_from_the_week_before_is_named() {
        let crash = at("2026-10-09T14:02:01Z");
        let point = point_before(crash, points(), &[]).expect("point 253");
        assert_eq!(point.sequence, 253);
        let issue = finding("crash_analysis", crash, &[], Some(&point));
        assert_eq!(issue.title, "A restore point from before the crashes began");
        assert!(issue.advice_only && !issue.is_selected);
        assert_eq!(issue.fix_steps.len(), 1);
        assert!(issue.fix_steps[0].contains("System Restore (rstrui.exe)"));

        // Point 255 is eleven days older than this crash.
        let later = at("2026-10-20T08:00:00Z");
        assert_eq!(point_before(later, points(), &[]), None);
        let named = point_before(later, points(), &a_change_before(later));
        assert_eq!(named.map(|p| p.sequence), Some(255));
    }

    /// A point whose time is no WMI date has no place in the order.
    #[test]
    fn a_point_without_a_time_is_never_named() {
        let mut all = points();
        all.extend(RestorePoint::parse("256 | Manual point | not a date"));
        assert_eq!(all.len(), 8);
        let crash = at("2026-10-20T08:00:00Z");
        let named = point_before(crash, all, &a_change_before(crash));
        assert_eq!(named.map(|p| p.sequence), Some(255));
    }
}
