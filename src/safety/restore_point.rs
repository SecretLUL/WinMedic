use crate::utils::cmd::{ps_single_quoted, run_powershell};
use chrono::{DateTime, FixedOffset, Local, NaiveDate, TimeZone, Utc};
use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Marker prefix the checkpoint script prints so the Rust side never has to
/// match on Windows' localized status text.
const RESULT_MARKER: &str = "WINMEDIC_RP:";

/// What actually happened when a restore point was requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestorePointOutcome {
    /// A new restore point exists that did not exist before.
    Created,
    /// No new restore point appeared although older ones exist. By default
    /// Windows allows only one per 24 hours (`SystemRestorePointCreationFrequency`,
    /// 1440 minutes); the script lifts that for its own checkpoint, so this is
    /// Windows declining for another reason.
    Throttled,
    /// The checkpoint call did not fail, but the restore point list could not be
    /// read back, so creation could not be confirmed. Usually missing rights.
    Unverified,
    /// The checkpoint call itself failed.
    Failed(String),
    /// Windows was never asked. Only an engine built without the real
    /// [`RestorePointService`] reports this — see [`RestorePointService::inert`].
    NotRequested,
}

impl RestorePointOutcome {
    /// Only a confirmed new restore point counts as protection.
    pub fn is_protected(&self) -> bool {
        matches!(self, Self::Created)
    }

    pub fn message(&self) -> String {
        match self {
            Self::Created => "A VSS restore point was created.".to_string(),
            Self::NotRequested => "No restore point was requested: this engine was built \
                 without access to Windows System Restore."
                .to_string(),
            Self::Throttled => "Windows did not create a new restore point, although WinMedic \
                 lifted the once-a-day limit for it. A recent point exists, but it does \
                 not capture the state immediately before this repair."
                .to_string(),
            Self::Unverified => "The restore point could not be confirmed: the list of restore \
                 points was unreadable (missing Administrator privileges?). Whether \
                 a point exists is unknown."
                .to_string(),
            Self::Failed(err) => {
                format!("Restore point failed: {}", err)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RestorePointResult {
    pub success: bool,
    pub outcome: RestorePointOutcome,
    pub description: String,
    pub message: String,
}

impl RestorePointResult {
    fn from_outcome(description: &str, outcome: RestorePointOutcome) -> Self {
        Self {
            success: outcome.is_protected(),
            message: outcome.message(),
            outcome,
            description: description.to_string(),
        }
    }
}

/// Map the script's marker line onto an outcome.
pub fn parse_checkpoint_output(output: &str) -> RestorePointOutcome {
    let marker = output
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(RESULT_MARKER));

    match marker {
        Some("CREATED") => RestorePointOutcome::Created,
        Some("THROTTLED") => RestorePointOutcome::Throttled,
        Some("UNVERIFIED") => RestorePointOutcome::Unverified,
        Some(rest) => {
            let detail = rest.strip_prefix("ERROR:").unwrap_or(rest).trim();
            let detail = if detail.is_empty() {
                "unknown error".to_string()
            } else {
                detail.to_string()
            };
            RestorePointOutcome::Failed(detail)
        }
        // No marker at all means the script did not run to completion.
        None => {
            let tail = output.trim();
            let detail = if tail.is_empty() {
                "PowerShell produced no output".to_string()
            } else {
                tail.lines().next_back().unwrap_or(tail).trim().to_string()
            };
            RestorePointOutcome::Failed(detail)
        }
    }
}

fn checkpoint_script(description: &str) -> String {
    format!(
        r#"
        function Get-MaxSeq {{
            try {{
                $points = Get-ComputerRestorePoint
                if ($null -eq $points) {{ return -1 }}
                $max = ($points | Measure-Object -Maximum -Property SequenceNumber).Maximum
                if ($null -eq $max) {{ return -1 }}
                return [int]$max
            }} catch {{ return -1 }}
        }}

        try {{
            $before = Get-MaxSeq
            # Turns System Protection on for the system drive if it is off.
            Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
            # Windows creates at most one restore point a day and skips the rest
            # silently. A frequency of 0 lifts that, as Microsoft documents for
            # CreateRestorePoint; the old value is put back afterwards.
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
            $name = 'SystemRestorePointCreationFrequency'
            $old = (Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue).$name
            New-ItemProperty -Path $key -Name $name -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
            try {{
                # Windows reports the rate limit as a *warning*, not an error, so
                # -ErrorAction cannot catch it and the call still "succeeds". The
                # only reliable check is whether a new sequence number appeared.
                Checkpoint-Computer -Description {} -RestorePointType 'MODIFY_SETTINGS' -WarningAction SilentlyContinue
            }} finally {{
                if ($null -eq $old) {{
                    Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
                }} else {{
                    New-ItemProperty -Path $key -Name $name -Value $old -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
                }}
            }}
            $after = Get-MaxSeq
            if ($after -gt $before) {{
                "{}CREATED"
            }} elseif ($before -ge 0) {{
                "{}THROTTLED"
            }} else {{
                "{}UNVERIFIED"
            }}
        }} catch {{
            "{}ERROR:" + $_.Exception.Message
        }}
        "#,
        ps_single_quoted(description),
        RESULT_MARKER,
        RESULT_MARKER,
        RESULT_MARKER,
        RESULT_MARKER
    )
}

/// Create a Windows System Restore Point (VSS Checkpoint).
///
/// Verifies that a restore point was really added instead of trusting the exit
/// status, because Windows silently declines to create one if another was made
/// within the last 24 hours.
///
/// Deliberately private: the only way to reach it is through
/// [`RestorePointService::real`], so a caller cannot create a restore point on
/// the machine running the code without saying so out loud.
async fn create_system_restore_point(description: &str) -> RestorePointResult {
    let script = checkpoint_script(description);

    match run_powershell(&script, Duration::from_secs(180)).await {
        Ok(out) => {
            let combined = format!("{}\n{}", out.stdout, out.stderr);
            RestorePointResult::from_outcome(description, parse_checkpoint_output(&combined))
        }
        Err(e) => RestorePointResult::from_outcome(
            description,
            RestorePointOutcome::Failed(format!("PowerShell could not be run: {}", e)),
        ),
    }
}

/// A boxed future, so the service below can stay a plain function pointer and
/// therefore stay `Copy` — the engine and the app pass it around by value.
type RestorePointFuture = Pin<Box<dyn Future<Output = RestorePointResult> + Send>>;

/// Where a repair run's pre-repair restore point comes from.
///
/// The one thing `run_repairs` does to the machine before any module gets a
/// turn is ask Windows for a checkpoint, and `Checkpoint-Computer` is not
/// something a test run should ever trigger on the developer's own PC. So this
/// follows the same shape as the `CommandRunner`, `CleanerPaths` and
/// `SystemActions` seams: [`Default`] is the *inert* implementation, and the
/// real one is installed explicitly by the entry points via
/// [`RestorePointService::real`].
#[derive(Debug, Clone, Copy)]
pub struct RestorePointService {
    checkpoint: fn(String) -> RestorePointFuture,
    /// Whether `checkpoint` really talks to Windows.
    ///
    /// Carried as data so a guard test can assert that an engine is inert
    /// *without* invoking it — invoking it is exactly what such a test must
    /// never do.
    live: bool,
}

impl RestorePointService {
    /// The real thing: runs `Checkpoint-Computer` on this machine.
    pub fn real() -> Self {
        fn checkpoint(description: String) -> RestorePointFuture {
            Box::pin(async move { create_system_restore_point(&description).await })
        }
        Self {
            checkpoint,
            live: true,
        }
    }

    /// Reports [`RestorePointOutcome::NotRequested`] without touching Windows.
    /// The default.
    pub fn inert() -> Self {
        fn checkpoint(description: String) -> RestorePointFuture {
            Box::pin(std::future::ready(RestorePointResult::from_outcome(
                &description,
                RestorePointOutcome::NotRequested,
            )))
        }
        Self {
            checkpoint,
            live: false,
        }
    }

    /// Reports [`RestorePointOutcome::Throttled`] without touching Windows:
    /// a request Windows answered without a new point.
    #[cfg(test)]
    pub(crate) fn declined() -> Self {
        fn checkpoint(description: String) -> RestorePointFuture {
            Box::pin(std::future::ready(RestorePointResult::from_outcome(
                &description,
                RestorePointOutcome::Throttled,
            )))
        }
        Self {
            checkpoint,
            live: false,
        }
    }

    /// Whether [`Self::create`] reaches the real Windows System Restore.
    pub fn is_live(&self) -> bool {
        self.live
    }

    pub async fn create(&self, description: &str) -> RestorePointResult {
        (self.checkpoint)(description.to_string()).await
    }
}

impl Default for RestorePointService {
    fn default() -> Self {
        Self::inert()
    }
}

/// Lists the restore points one per line, `<SequenceNumber> | <Description>
/// | <CreationTime>`. `CreationTime` is a WMI date string, and interpolated it
/// stays one (`20261009201051.313055-000`); Rust converts it, see
/// [`parse_wmi_datetime`]. Needs Administrator. Settings and the crash
/// timeline both read it.
pub const LIST_SCRIPT: &str = r#"
        Get-ComputerRestorePoint | Select-Object -Property SequenceNumber, Description, CreationTime | ForEach-Object {
            "$($_.SequenceNumber) | $($_.Description) | $($_.CreationTime)"
        }
    "#;

/// How a restore point's time is shown: `09 Oct 2026, 22:10`.
const TIME_FORMAT: &str = "%d %b %Y, %H:%M";

/// A WMI date, `yyyymmddHHMMSS.mmmmmmsUUU`: the time where it was taken,
/// then the sign and the minutes that zone is ahead of UTC (`-000` is UTC,
/// `+120` two hours ahead). `None` for anything else, such as the asterisks
/// WMI writes for fields it leaves out.
pub fn parse_wmi_datetime(text: &str) -> Option<DateTime<Utc>> {
    let text = text.trim();
    if text.len() != 25 || !text.is_ascii() || &text[14..15] != "." {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<u32> {
        let digits = &text[from..to];
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    };
    let local = NaiveDate::from_ymd_opt(number(0, 4)? as i32, number(4, 6)?, number(6, 8)?)?
        .and_hms_micro_opt(
            number(8, 10)?,
            number(10, 12)?,
            number(12, 14)?,
            number(15, 21)?,
        )?;
    let minutes = number(22, 25)? as i32;
    let ahead = match &text[21..22] {
        "+" => minutes,
        "-" => -minutes,
        _ => return None,
    };
    FixedOffset::east_opt(ahead * 60)?
        .from_local_datetime(&local)
        .single()
        .map(|t| t.with_timezone(&Utc))
}

/// One line of [`LIST_SCRIPT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePoint {
    pub sequence: u32,
    pub description: String,
    /// `None` when `CreationTime` was no WMI date.
    pub created: Option<DateTime<Utc>>,
    /// `CreationTime` as Windows wrote it.
    creation_time: String,
}

impl RestorePoint {
    /// `None` for a line that is not `<number> | <description> | <time>`. A
    /// description may itself contain ` | `, so the number is split off the
    /// front and the time off the back.
    pub fn parse(line: &str) -> Option<Self> {
        let (sequence, rest) = line.trim().split_once(" | ")?;
        let (description, creation_time) = rest.rsplit_once(" | ")?;
        Some(Self {
            sequence: sequence.trim().parse().ok()?,
            description: description.trim().to_string(),
            created: parse_wmi_datetime(creation_time),
            creation_time: creation_time.trim().to_string(),
        })
    }

    /// When it was created, in `zone`; as Windows wrote it when that was no
    /// WMI date.
    pub fn time_in<Tz: TimeZone>(&self, zone: &Tz) -> String
    where
        Tz::Offset: Display,
    {
        match self.created {
            Some(created) => created.with_timezone(zone).format(TIME_FORMAT).to_string(),
            None => self.creation_time.clone(),
        }
    }

    /// `255 | WinMedic Auto-Restore Point (before repairs) | 09 Oct 2026, 22:10`.
    pub fn line_in<Tz: TimeZone>(&self, zone: &Tz) -> String
    where
        Tz::Offset: Display,
    {
        format!(
            "{} | {} | {}",
            self.sequence,
            self.description,
            self.time_in(zone)
        )
    }
}

/// The restore points in [`LIST_SCRIPT`]'s output; lines that are none are
/// left out.
pub fn parse_restore_points(stdout: &str) -> Vec<RestorePoint> {
    stdout.lines().filter_map(RestorePoint::parse).collect()
}

/// What Settings lists for [`LIST_SCRIPT`]'s output: each point with its time
/// in local time. A line that does not parse is shown as it came, rather than
/// not at all.
pub fn settings_lines(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            RestorePoint::parse(line).map_or_else(|| line.to_string(), |p| p.line_in(&Local))
        })
        .collect()
}

/// Query existing Windows restore points, as Settings lists them.
pub async fn list_restore_points() -> Vec<String> {
    match run_powershell(LIST_SCRIPT, Duration::from_secs(30)).await {
        Ok(out) => settings_lines(&out.stdout),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_created() {
        let out = parse_checkpoint_output("noise\nWINMEDIC_RP:CREATED\n");
        assert_eq!(out, RestorePointOutcome::Created);
        assert!(out.is_protected());
    }

    #[test]
    fn parses_throttled_as_unprotected() {
        let out = parse_checkpoint_output("WINMEDIC_RP:THROTTLED");
        assert_eq!(out, RestorePointOutcome::Throttled);
        // The whole point of this change: a throttled run is not protected.
        assert!(!out.is_protected());
        assert!(out.message().contains("once-a-day limit"));
    }

    #[test]
    fn parses_unverified() {
        let out = parse_checkpoint_output("WINMEDIC_RP:UNVERIFIED");
        assert_eq!(out, RestorePointOutcome::Unverified);
        assert!(!out.is_protected());
    }

    #[test]
    fn parses_error_with_detail() {
        let out = parse_checkpoint_output("WINMEDIC_RP:ERROR:Access is denied");
        assert_eq!(
            out,
            RestorePointOutcome::Failed("Access is denied".to_string())
        );
        assert!(out.message().contains("Access is denied"));
    }

    #[test]
    fn missing_marker_is_a_failure_not_a_success() {
        // A localized success banner without our marker must never read as success.
        let out = parse_checkpoint_output("Der Vorgang wurde erfolgreich beendet.");
        assert!(matches!(out, RestorePointOutcome::Failed(_)));
        assert!(!out.is_protected());
    }

    #[test]
    fn empty_output_is_a_failure() {
        assert!(matches!(
            parse_checkpoint_output("   \n  "),
            RestorePointOutcome::Failed(_)
        ));
    }

    #[test]
    fn last_marker_wins() {
        // Enable-ComputerRestore chatter before the real verdict must not shadow it.
        let out = parse_checkpoint_output("WINMEDIC_RP:UNVERIFIED\nWINMEDIC_RP:CREATED");
        assert_eq!(out, RestorePointOutcome::Created);
    }

    #[test]
    fn description_is_escaped_into_the_script() {
        let script = checkpoint_script("WinMedic O'Brien $(whoami) `hostname`");
        // Single quotes are doubled, so the injected text stays one literal string.
        assert!(script.contains("'WinMedic O''Brien $(whoami) `hostname`'"));
        // And the string never terminates early, which is what would let the
        // rest execute as code.
        assert!(!script.contains("O'Brien"));
    }

    /// The once-a-day limit is lifted for WinMedic's own checkpoint only, and
    /// whatever was set before comes back whether the checkpoint works or not.
    #[test]
    fn the_daily_limit_is_lifted_for_the_checkpoint_and_put_back() {
        let script = checkpoint_script("WinMedic Auto-Restore Point (before repairs)");
        let lift = script
            .find("-Name $name -Value 0")
            .expect("the frequency is set to 0");
        let checkpoint = script.find("Checkpoint-Computer").unwrap();
        let finally = script.find("} finally {").expect("restored in a finally");
        assert!(lift < checkpoint && checkpoint < finally);
        assert!(script.contains("Remove-ItemProperty -Path $key -Name $name"));
        assert!(script.contains("-Name $name -Value $old -PropertyType DWord"));
        assert!(script.contains("SystemRestorePointCreationFrequency"));
    }

    /// System Protection is switched on for the drive Windows is on, which is
    /// not always C:.
    #[test]
    fn protection_is_switched_on_for_the_system_drive() {
        let script = checkpoint_script("x");
        assert!(script.contains(r#"Enable-ComputerRestore -Drive "$env:SystemDrive\""#));
        assert!(!script.contains("'C:\\'"));
    }

    #[tokio::test]
    async fn the_checkpoint_script_parses() {
        let script = checkpoint_script("WinMedic O'Brien \u{2019}s point");
        assert_eq!(
            crate::utils::cmd::powershell_parse_errors(&script).await,
            0,
            "{script}"
        );
    }

    #[test]
    fn plain_description_survives_unchanged() {
        let script = checkpoint_script("WinMedic Auto-Restore Point (before repairs)");
        assert!(script.contains("'WinMedic Auto-Restore Point (before repairs)'"));
    }

    /// The default service must not reach Windows, and must say so honestly
    /// rather than reporting a protection that does not exist.
    #[tokio::test]
    async fn the_default_service_creates_nothing() {
        let service = RestorePointService::default();
        assert!(!service.is_live());

        let res = service
            .create("WinMedic Auto-Restore Point (before repairs)")
            .await;
        assert!(!res.success);
        assert_eq!(res.outcome, RestorePointOutcome::NotRequested);
        assert_eq!(
            res.description,
            "WinMedic Auto-Restore Point (before repairs)"
        );
    }

    #[test]
    fn the_real_service_is_marked_live() {
        // Marked, not called: calling it would create a restore point on
        // whichever machine runs the suite.
        assert!(RestorePointService::real().is_live());
    }

    /// No test may build a live [`RestorePointService`]. `Checkpoint-Computer`
    /// takes up to a minute, needs elevation, and — when it does succeed —
    /// leaves a real restore point on the machine that ran `cargo test`.
    #[test]
    fn no_test_in_the_tree_creates_a_restore_point() {
        let offenders = crate::utils::test_guard::integration_test_lines_mentioning(
            "RestorePointService::real",
        );

        assert!(
            offenders.is_empty(),
            "these tests would run Checkpoint-Computer on the test machine; leave the engine's \
             inert default in place and assert on the VssStarted/VssCompleted events instead: {:?}",
            offenders
        );
    }

    #[test]
    fn result_carries_outcome_and_description() {
        let res =
            RestorePointResult::from_outcome("Before repairs", RestorePointOutcome::Throttled);
        assert!(!res.success);
        assert_eq!(res.outcome, RestorePointOutcome::Throttled);
        assert_eq!(res.description, "Before repairs");
        assert!(!res.message.is_empty());
    }

    /// What [`LIST_SCRIPT`] printed, elevated, on the development PC; see
    /// tests/fixtures/README.md.
    const CAPTURED_POINTS: &str =
        include_str!("../../tests/fixtures/console/powershell_restore_points.txt");

    fn utc(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn the_captured_points_parse_with_their_times_in_utc() {
        let points = parse_restore_points(CAPTURED_POINTS);
        let sequences: Vec<u32> = points.iter().map(|p| p.sequence).collect();
        assert_eq!(sequences, [249, 250, 251, 252, 253, 254, 255]);
        assert_eq!(points[1].description, "Windows Modules Installer");
        assert_eq!(
            points[6].description,
            "WinMedic Auto-Restore Point (before repairs)"
        );
        // `-000`: the times are UTC.
        assert_eq!(points[6].created, Some(utc("2026-10-09T20:10:51.313055Z")));
        assert_eq!(points[0].created, Some(utc("2026-10-08T17:15:52.483597Z")));
    }

    /// 20261009201051 UTC was 22:10:51 on the PC the list was captured on,
    /// two hours ahead of UTC in October.
    #[test]
    fn settings_shows_the_time_where_the_pc_is() {
        let point = RestorePoint::parse(CAPTURED_POINTS.lines().last().unwrap()).unwrap();
        let berlin = FixedOffset::east_opt(2 * 3600).unwrap();
        assert_eq!(
            point.line_in(&berlin),
            "255 | WinMedic Auto-Restore Point (before repairs) | 09 Oct 2026, 22:10"
        );
        assert_eq!(point.time_in(&Utc), "09 Oct 2026, 20:10");
    }

    /// Settings lists every captured point, and none as a WMI date string.
    #[test]
    fn settings_lists_no_wmi_date() {
        let lines = settings_lines(CAPTURED_POINTS);
        assert_eq!(lines.len(), 7, "{lines:?}");
        for (line, point) in lines.iter().zip(parse_restore_points(CAPTURED_POINTS)) {
            assert_eq!(*line, point.line_in(&Local));
            assert!(
                !line.contains("-000") && !line.contains(".483597"),
                "{line}"
            );
        }
    }

    /// The offset is minutes ahead of UTC, with a sign: the issue's example
    /// was taken two hours ahead of UTC.
    #[test]
    fn the_offset_is_signed_minutes() {
        assert_eq!(
            parse_wmi_datetime("20261009221311.500000+120"),
            Some(utc("2026-10-09T20:13:11.5Z"))
        );
        assert_eq!(
            parse_wmi_datetime("20261009221311.500000-300"),
            Some(utc("2026-10-10T03:13:11.5Z"))
        );
        assert_eq!(
            parse_wmi_datetime("20261009221311.500000+330"),
            Some(utc("2026-10-09T16:43:11.5Z"))
        );
    }

    #[test]
    fn what_is_no_wmi_date_is_none() {
        for text in [
            "",
            "09.10.2026 22:13:11",
            "20261009221311.500000",
            "20261309221311.500000-000",
            "20261009221311.500000*000",
            "2026100922131*.******+***",
            "20261009221311,500000-000",
            "20261009221311.5000ä-000",
        ] {
            assert_eq!(parse_wmi_datetime(text), None, "{text}");
        }
    }

    /// A description of its own may contain ` | `.
    #[test]
    fn a_bar_in_the_description_stays_in_it() {
        let point = RestorePoint::parse("256 | Before A | B | 20261009201051.313055-000").unwrap();
        assert_eq!(point.sequence, 256);
        assert_eq!(point.description, "Before A | B");
        assert_eq!(point.created, Some(utc("2026-10-09T20:10:51.313055Z")));
    }

    /// A time that is no WMI date is shown as Windows wrote it, and a line
    /// that is no point at all as it came: neither vanishes.
    #[test]
    fn what_does_not_parse_is_shown_raw() {
        let point = RestorePoint::parse("256 | Manual point | not a date").unwrap();
        assert_eq!(point.created, None);
        assert_eq!(point.line_in(&Utc), "256 | Manual point | not a date");

        let lines = settings_lines("256 | Manual point | not a date\r\n\r\nsomething else\r\n");
        assert_eq!(lines, ["256 | Manual point | not a date", "something else"]);
        assert!(
            parse_restore_points("something else\nx | y | 20261009201051.313055-000").is_empty()
        );
    }
}
