//! WinMedic's own crashes, which the window offers to send, and the report
//! it sends (#236).
//!
//! A panic leaves a crash log (`utils::crash_log`). A crash no hook sees, such
//! as the abort that ended 0.10.0 during the WinSxS step, leaves only what
//! Windows logs for it: Application Error 1000 in the Application log. At its
//! next start the window offers the newest of them, once. Nothing leaves the
//! PC without a click, and what leaves is shown first, with the user and the
//! computer it names replaced: the report becomes a public GitHub issue.

use crate::utils::event_xml::{EventRecord, event_query};
use chrono::{DateTime, Utc};

/// Where a report goes: the bug report form of WinMedic's repository.
pub const ISSUE_URL_PREFIX: &str = "https://github.com/SecretLUL/WinMedic/issues/new?";

/// Windows may hand on no more than 2083 characters of a URL
/// (INTERNET_MAX_URL_LENGTH), and a longer one can arrive cut. What does not
/// fit goes to the clipboard instead.
pub const MAX_URL_LEN: usize = 2000;

/// How far back Windows' record of a crash is read.
const LOOKBACK_DAYS: u64 = 30;

/// WinMedic's crashes as Windows logged them, among every program's, newest
/// first. `wevtutil` cannot filter on the start of a name, and the release is
/// downloaded as `winmedic-v0.12.0.exe`: [`from_event`] picks them out.
pub fn own_crashes_query() -> Vec<String> {
    event_query(
        "Application",
        &format!(
            "Provider[@Name='Application Error'] and EventID=1000 and TimeCreated[timediff(@SystemTime) <= {}]",
            LOOKBACK_DAYS * 86_400_000
        ),
        300,
    )
}

/// A crash of WinMedic, as a report tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash {
    pub when: DateTime<Utc>,
    /// One line: the panic's message, or the exception and where it struck.
    pub summary: String,
    pub version: String,
    /// The Windows build the crash log names; a crash Windows logged names
    /// none.
    pub windows: Option<String>,
    /// How WinMedic was started, as the crash log names it.
    pub mode: Option<String>,
    /// The crash log as it was written or, for a crash Windows logged, in the
    /// same layout, so that `scripts/resolve-crash-log.ps1` reads both.
    pub log: String,
}

impl Crash {
    /// A crash log as `crash_log::Report::render` wrote it.
    pub fn from_crash_log(text: &str) -> Option<Self> {
        let version = text
            .lines()
            .next()?
            .strip_prefix("WinMedic ")?
            .strip_suffix(" panicked")?
            .to_string();
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::to_string)
        };
        let when = DateTime::parse_from_str(&field("Time: ")?, "%Y-%m-%d %H:%M:%S %:z")
            .ok()?
            .with_timezone(&Utc);
        let summary = text
            .lines()
            .skip_while(|line| *line != "Message:")
            .nth(1)
            .map(|line| line.trim().to_string())
            .unwrap_or_default();
        Some(Self {
            when,
            summary,
            version,
            windows: field("Windows: "),
            mode: field("Mode: "),
            log: text.to_string(),
        })
    }

    /// A crash Windows logged as Application Error 1000, if the program was
    /// WinMedic.
    pub fn from_event(event: &EventRecord) -> Option<Self> {
        let app = event.data("AppName")?;
        let name = app.to_ascii_lowercase();
        if !(name.starts_with("winmedic") && name.ends_with(".exe")) {
            return None;
        }
        let when = DateTime::parse_from_rfc3339(event.time_created.as_deref()?)
            .ok()?
            .with_timezone(&Utc);
        let version = event.data("AppVersion").unwrap_or_default().to_string();
        let exception = event.data("ExceptionCode").unwrap_or_default();
        let module = event.data("ModuleName").unwrap_or_default();
        let frame = match event
            .data("FaultingOffset")
            .and_then(|offset| u64::from_str_radix(offset, 16).ok())
        {
            Some(offset) => format!("{module}+{offset:#x}"),
            None => module.to_string(),
        };
        let log = format!(
            "WinMedic {version} stopped\n\
             Time: {}\n\
             Program: {app}\n\
             Exception: {exception}\n\
             \n\
             Stack (return addresses; scripts/resolve-crash-log.ps1 and the release's PDB resolve them):\n\
             \x20 {frame}\n",
            when.format("%Y-%m-%d %H:%M:%S UTC"),
        );
        Some(Self {
            when,
            summary: format!("Exception {exception} in {frame}"),
            version,
            windows: None,
            mode: None,
            log,
        })
    }
}

/// The crashes after `seen_until`, newest first: crash logs, and what Windows
/// logged.
pub fn crashes_since(
    crash_logs: &[String],
    events: &[EventRecord],
    seen_until: DateTime<Utc>,
) -> Vec<Crash> {
    let mut crashes: Vec<Crash> = crash_logs
        .iter()
        .filter_map(|text| Crash::from_crash_log(text))
        .chain(events.iter().filter_map(Crash::from_event))
        .filter(|crash| crash.when > seen_until)
        .collect();
    crashes.sort_by_key(|crash| std::cmp::Reverse(crash.when));
    crashes
}

/// What names this PC and its user in a report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// `C:\Users\<name>`.
    pub profile: String,
    pub user: String,
    pub computer: String,
}

impl Identity {
    /// The signed-in user's, from the environment.
    pub fn of_this_pc() -> Self {
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        Self {
            profile: var("USERPROFILE"),
            user: var("USERNAME"),
            computer: var("COMPUTERNAME"),
        }
    }

    /// `text` with the profile folder, the user name and the computer name
    /// replaced. A name counts only as a whole word, so that a user called
    /// "Win" leaves "Windows" alone.
    pub fn scrub(&self, text: &str) -> String {
        let mut text = replace_ignoring_case(text, &self.profile, "%USERPROFILE%", false);
        text = replace_ignoring_case(&text, &self.computer, "<computer>", true);
        replace_ignoring_case(&text, &self.user, "<user>", true)
    }
}

fn replace_ignoring_case(text: &str, needle: &str, with: &str, whole_word: bool) -> String {
    if needle.is_empty() {
        return text.to_string();
    }
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    let lower = text.to_lowercase();
    let needle = needle.to_lowercase();
    // Lowercasing can change byte lengths outside ASCII; then the positions
    // would not line up, and the text is scrubbed as it is.
    if lower.len() != text.len() {
        return text.replace(&needle, with);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = 0;
    let mut from = 0;
    while let Some(found) = lower[from..].find(&needle) {
        let start = from + found;
        let end = start + needle.len();
        let alone = !whole_word
            || (!word(text[..start].chars().last()) && !word(text[end..].chars().next()));
        if alone {
            out.push_str(&text[rest..start]);
            out.push_str(with);
            rest = end;
        }
        from = end;
    }
    out.push_str(&text[rest..]);
    out
}

/// The bug report form, filled in for `crash`, and what the user has to paste
/// into it because it did not fit into the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueDraft {
    pub url: String,
    /// The crash log, for the clipboard, when the URL could not carry it.
    pub to_paste: Option<String>,
}

/// What a report says, already scrubbed: the title, and the text of each field
/// of `bug_report.yml` it fills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub title: String,
    pub fields: Vec<(&'static str, String)>,
    /// The crash log, for the form's "Anything else".
    pub log: String,
}

impl Report {
    pub fn of(crash: &Crash, identity: &Identity, windows_now: &str) -> Self {
        let summary = identity.scrub(&crash.summary);
        let mode = match crash.mode.as_deref() {
            Some("window") => "Desktop window (GUI)",
            Some("--auto-fix") => "Headless with repairs (--auto-fix)",
            Some("--dry-run") => "Simulation (--dry-run, or the simulation switch in the window)",
            Some("--scan") | Some("helper") => "Headless (--scan)",
            _ => "",
        };
        let mut fields = vec![
            (
                "what-happened",
                format!("WinMedic ran into an error of its own: {summary}"),
            ),
            (
                "reproduce",
                "Not known. WinMedic wrote the crash log below.".to_string(),
            ),
            ("version", format!("WinMedic {}", crash.version)),
            (
                "windows-build",
                identity.scrub(crash.windows.as_deref().unwrap_or(windows_now)),
            ),
        ];
        if !mode.is_empty() {
            fields.push(("mode", mode.to_string()));
        }
        Self {
            title: format!("Crash: {}", truncate(&summary, 80)),
            fields,
            log: identity.scrub(&crash.log),
        }
    }

    /// The text the window shows before anything is sent: everything the
    /// issue will say.
    pub fn preview(&self) -> String {
        let mut text = format!("Title: {}\n\n", self.title);
        for (field, value) in &self.fields {
            text.push_str(&format!("{}: {value}\n", label(field)));
        }
        text.push_str("\nAnything else:\n");
        text.push_str(&self.log);
        text
    }

    /// The form's URL, with the crash log in "Anything else" when it fits,
    /// and otherwise left for the clipboard.
    pub fn draft(&self) -> IssueDraft {
        let fenced = format!("```text\n{}```", self.log);
        let with_log = self.url(&fenced);
        if with_log.len() <= MAX_URL_LEN {
            return IssueDraft {
                url: with_log,
                to_paste: None,
            };
        }
        IssueDraft {
            url: self.url("The crash log is on the clipboard: paste it here."),
            to_paste: Some(fenced),
        }
    }

    /// No `labels=`: GitHub takes it only from someone allowed to label
    /// issues, and the form adds `bug` itself.
    fn url(&self, extra: &str) -> String {
        let mut url = format!(
            "{ISSUE_URL_PREFIX}template=bug_report.yml&title={}",
            encode(&self.title)
        );
        for (field, value) in &self.fields {
            url.push('&');
            url.push_str(field);
            url.push('=');
            url.push_str(&encode(value));
        }
        url.push_str("&extra=");
        url.push_str(&encode(extra));
        url
    }
}

/// The label `bug_report.yml` gives a field.
fn label(field: &str) -> &str {
    match field {
        "what-happened" => "What happened",
        "reproduce" => "Steps to reproduce",
        "version" => "WinMedic version",
        "windows-build" => "Windows version and build",
        "mode" => "How was it running?",
        other => other,
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let cut: String = text.chars().take(max_chars - 1).collect();
    format!("{cut}…")
}

/// Percent-encoding for a query value: everything but the unreserved
/// characters of RFC 3986.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Whether [`launch_issue_form`] would open `url`: WinMedic's bug report form
/// and nothing else, with a query of encoded values only.
///
/// `validate_release_url` cannot serve here: it refuses `&` and `%`, which
/// every filled-in form needs.
pub fn validate_issue_url(url: &str) -> Result<(), String> {
    let Some(query) = url.strip_prefix(ISSUE_URL_PREFIX) else {
        return Err(format!(
            "URL rejected (only {ISSUE_URL_PREFIX}... is allowed): {url}"
        ));
    };
    if url.len() > MAX_URL_LEN {
        return Err(format!(
            "URL rejected: {} characters, more than {MAX_URL_LEN}",
            url.len()
        ));
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || "-_.~%&=".contains(c);
    if !query.chars().all(allowed) {
        return Err(format!("URL rejected: unexpected characters in {url}"));
    }
    Ok(())
}

/// Open the bug report form in the default browser.
///
/// The URL is checked by [`validate_issue_url`] first and then handed to
/// `explorer.exe`, as `updater::launch_browser` does: no command interpreter
/// reads it, so the `&` between its fields separates nothing but fields.
///
/// Tests check [`validate_issue_url`] instead: this opens a real browser.
pub fn launch_issue_form(url: &str) -> Result<(), String> {
    validate_issue_url(url)?;

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        Command::new(crate::utils::cmd::system_program("explorer.exe")?)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("Could not open the default browser: {e}"))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::crash_log::Report as Written;
    use crate::utils::decode::decode_output;
    use crate::utils::event_xml::parse_events;
    use chrono::{FixedOffset, TimeZone};

    /// The capture of WinMedic's own crash query in Windows Sandbox, right
    /// after a winmedic.exe that only aborts; see tests/fixtures/README.md.
    const OWN_CRASH: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_app_error_1000_winmedic.bin");
    /// Other programs' crashes, which the query also returns.
    const OTHERS: &[u8] = include_bytes!("../../tests/fixtures/events/wevtutil_app_error_1000.bin");

    fn written() -> String {
        Written {
            time: FixedOffset::east_opt(2 * 3600)
                .unwrap()
                .with_ymd_and_hms(2026, 10, 13, 0, 11, 49)
                .unwrap(),
            version: "0.11.0".to_string(),
            windows: "Windows 11 Pro 25H2, build 26200.9550".to_string(),
            mode: "window".to_string(),
            thread: "tokio-rt-worker".to_string(),
            running: Some(
                r#"repair 'temp_files' of storage, at "Deleting C:\Users\AMMAR-PC\AppData\Local\Temp\x""#
                    .to_string(),
            ),
            location: r"src\modules\storage.rs:120:9".to_string(),
            message: "the count the repair read".to_string(),
            stack: vec!["winmedic-v0.11.0.exe+0x38772".to_string()],
        }
        .render()
    }

    fn identity() -> Identity {
        Identity {
            profile: r"C:\Users\AMMAR-PC".to_string(),
            user: "AMMAR-PC".to_string(),
            computer: "DESKTOP-416752K".to_string(),
        }
    }

    #[test]
    fn the_query_is_the_one_the_fixture_was_captured_with() {
        assert_eq!(
            own_crashes_query(),
            [
                "qe",
                "Application",
                "/q:*[System[Provider[@Name='Application Error'] and EventID=1000 and TimeCreated[timediff(@SystemTime) <= 2592000000]]]",
                "/f:xml",
                "/c:300",
                "/rd:true",
            ]
        );
    }

    #[test]
    fn a_crash_windows_logged_reads_like_a_crash_log() {
        let events = parse_events(&decode_output(OWN_CRASH));
        let crash = Crash::from_event(&events[0]).unwrap();
        assert_eq!(
            crash.when,
            Utc.with_ymd_and_hms(2026, 10, 12, 22, 24, 26).unwrap()
                + chrono::Duration::nanoseconds(464_814_900)
        );
        assert_eq!(crash.summary, "Exception c0000409 in winmedic.exe+0x1035");
        assert_eq!(crash.version, "0.0.0.0");
        assert!(
            crash.log.contains("\n  winmedic.exe+0x1035\n"),
            "{}",
            crash.log
        );
    }

    #[test]
    fn other_programs_crashes_are_not_winmedics() {
        let events = parse_events(&decode_output(OTHERS));
        assert!(!events.is_empty());
        assert!(
            events
                .iter()
                .all(|event| Crash::from_event(event).is_none())
        );
    }

    #[test]
    fn a_crash_log_names_its_time_version_and_message() {
        let crash = Crash::from_crash_log(&written()).unwrap();
        assert_eq!(
            crash.when,
            Utc.with_ymd_and_hms(2026, 10, 12, 22, 11, 49).unwrap()
        );
        assert_eq!(crash.version, "0.11.0");
        assert_eq!(crash.summary, "the count the repair read");
        assert_eq!(crash.mode.as_deref(), Some("window"));
        assert!(Crash::from_crash_log("not a crash log").is_none());
    }

    #[test]
    fn only_crashes_after_the_last_offer_come_newest_first() {
        let mut events = parse_events(&decode_output(OWN_CRASH));
        events.extend(parse_events(&decode_output(OTHERS)));
        let logs = [written()];

        let all = crashes_since(&logs, &events, DateTime::<Utc>::MIN_UTC);
        let summaries: Vec<&str> = all.iter().map(|c| c.summary.as_str()).collect();
        assert_eq!(
            summaries,
            [
                "Exception c0000409 in winmedic.exe+0x1035",
                "the count the repair read"
            ]
        );

        let after_the_log = Utc.with_ymd_and_hms(2026, 10, 12, 22, 20, 0).unwrap();
        assert_eq!(crashes_since(&logs, &events, after_the_log).len(), 1);
        let after_both = Utc.with_ymd_and_hms(2026, 10, 12, 23, 0, 0).unwrap();
        assert!(crashes_since(&logs, &events, after_both).is_empty());
    }

    #[test]
    fn the_user_and_the_pc_are_replaced_and_windows_is_not() {
        let scrubbed = identity().scrub(
            r"C:\Users\AMMAR-PC\AppData\Local\Temp\x, c:\users\ammar-pc\Downloads, AMMAR-PC on DESKTOP-416752K, Windows",
        );
        assert_eq!(
            scrubbed,
            r"%USERPROFILE%\AppData\Local\Temp\x, %USERPROFILE%\Downloads, <user> on <computer>, Windows"
        );

        let short = Identity {
            user: "Win".to_string(),
            ..Identity::default()
        };
        assert_eq!(short.scrub("Win runs Windows"), "<user> runs Windows");
    }

    #[test]
    fn a_report_fills_the_bug_report_form() {
        let crash = Crash::from_crash_log(&written()).unwrap();
        let report = Report::of(&crash, &identity(), "unused");

        assert_eq!(report.title, "Crash: the count the repair read");
        assert!(report.log.contains(r"%USERPROFILE%\AppData\Local\Temp\x"));
        assert!(!report.preview().contains("AMMAR-PC"));
        let field = |id: &str| {
            report
                .fields
                .iter()
                .find(|(name, _)| *name == id)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(field("version"), Some("WinMedic 0.11.0"));
        assert_eq!(
            field("windows-build"),
            Some("Windows 11 Pro 25H2, build 26200.9550")
        );
        assert_eq!(field("mode"), Some("Desktop window (GUI)"));

        let draft = report.draft();
        assert_eq!(draft.to_paste, None, "{}", draft.url.len());
        assert!(draft.url.starts_with(
            "https://github.com/SecretLUL/WinMedic/issues/new?template=bug_report.yml&title=Crash%3A%20the%20count"
        ));
        assert!(
            draft
                .url
                .contains("&extra=%60%60%60text%0AWinMedic%200.11.0%20panicked")
        );
        assert_eq!(validate_issue_url(&draft.url), Ok(()));
    }

    /// The ids, labels and dropdown options a report fills in are the ones
    /// the form has: GitHub drops a value whose field or option it does not
    /// know.
    #[test]
    fn a_report_fills_the_fields_the_form_has() {
        let form =
            include_str!("../../.github/ISSUE_TEMPLATE/bug_report.yml").replace("\r\n", "\n");
        for id in [
            "what-happened",
            "reproduce",
            "version",
            "windows-build",
            "mode",
            "extra",
        ] {
            let label = label(id);
            assert!(form.contains(&format!("id: {id}\n")), "{id}");
            if id != "extra" {
                assert!(
                    form.contains(&format!(
                        "id: {id}\n    attributes:\n      label: {label}\n"
                    )),
                    "{id}: {label}"
                );
            }
        }
        for mode in ["window", "--scan", "--auto-fix", "--dry-run", "helper"] {
            let crash = Crash {
                mode: Some(mode.to_string()),
                ..Crash::from_crash_log(&written()).unwrap()
            };
            let report = Report::of(&crash, &identity(), "unused");
            let (_, option) = report.fields.iter().find(|(id, _)| *id == "mode").unwrap();
            assert!(form.contains(&format!("        - {option}\n")), "{option}");
        }
    }

    #[test]
    fn the_preview_names_each_field_as_the_form_does() {
        let crash = Crash::from_crash_log(&written()).unwrap();
        let preview = Report::of(&crash, &identity(), "unused").preview();
        assert!(
            preview.starts_with(
                "Title: Crash: the count the repair read\n\n\
             What happened: WinMedic ran into an error of its own: the count the repair read\n\
             Steps to reproduce: Not known. WinMedic wrote the crash log below.\n\
             WinMedic version: WinMedic 0.11.0\n\
             Windows version and build: Windows 11 Pro 25H2, build 26200.9550\n\
             How was it running?: Desktop window (GUI)\n\
             \n\
             Anything else:\n\
             WinMedic 0.11.0 panicked\n"
            ),
            "{preview}"
        );
    }

    #[test]
    fn a_crash_windows_logged_takes_this_windows_and_no_mode() {
        let events = parse_events(&decode_output(OWN_CRASH));
        let crash = Crash::from_event(&events[0]).unwrap();
        let report = Report::of(&crash, &identity(), "Windows 11 Pro 25H2, build 26200.9550");
        assert!(report.fields.iter().all(|(name, _)| *name != "mode"));
        assert!(report.fields.contains(&(
            "windows-build",
            "Windows 11 Pro 25H2, build 26200.9550".to_string()
        )));
    }

    #[test]
    fn a_log_too_long_for_the_url_goes_to_the_clipboard() {
        let mut crash = Crash::from_crash_log(&written()).unwrap();
        crash.log.push_str(&"  winmedic.exe+0x1a2b3c\n".repeat(200));
        let draft = Report::of(&crash, &identity(), "unused").draft();

        let pasted = draft.to_paste.unwrap();
        assert!(pasted.starts_with("```text\nWinMedic 0.11.0 panicked\n"));
        assert!(draft.url.len() <= MAX_URL_LEN);
        assert!(
            draft
                .url
                .contains("&extra=The%20crash%20log%20is%20on%20the%20clipboard")
        );
        assert_eq!(validate_issue_url(&draft.url), Ok(()));
    }

    #[test]
    fn only_winmedics_bug_report_form_is_opened() {
        for url in [
            "https://github.com/SecretLUL/WinMedic/releases/tag/v0.11.0",
            "https://github.com/SecretLUL/WinMedic/issues/new?title=a b",
            "https://github.com/SecretLUL/WinMedic/issues/new?title=a\"&cmd",
            "https://github.com/someone/else/issues/new?title=x",
            "http://github.com/SecretLUL/WinMedic/issues/new?title=x",
        ] {
            assert!(validate_issue_url(url).is_err(), "{url}");
        }
        let long = format!("{ISSUE_URL_PREFIX}title={}", "a".repeat(MAX_URL_LEN));
        assert!(validate_issue_url(&long).is_err());
    }
}
