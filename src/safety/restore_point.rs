use crate::utils::cmd::{ps_single_quoted, run_powershell};
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
    /// Windows refused because one was already created recently. By default it
    /// allows only one restore point per 24 hours
    /// (`SystemRestorePointCreationFrequency`, 1440 minutes).
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
            Self::Throttled => "Windows did not create a new restore point: one was already \
                 created within the last 24 hours (the Windows default throttle). \
                 A recent point therefore exists, but it does not capture the state \
                 immediately before this repair."
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
            Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
            # Windows reports the 24h rate limit as a *warning*, not an error, so
            # -ErrorAction cannot catch it and the call still "succeeds". The only
            # reliable check is whether a new sequence number actually appeared.
            Checkpoint-Computer -Description {} -RestorePointType 'MODIFY_SETTINGS' -WarningAction SilentlyContinue
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

/// Query existing Windows restore points
pub async fn list_restore_points() -> Vec<String> {
    let script = r#"
        Get-ComputerRestorePoint | Select-Object -Property SequenceNumber, Description, CreationTime | ForEach-Object {
            "$($_.SequenceNumber) | $($_.Description) | $($_.CreationTime)"
        }
    "#;

    match run_powershell(script, Duration::from_secs(30)).await {
        Ok(out) => out
            .stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
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
        assert!(out.message().contains("24 hours"));
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
}
