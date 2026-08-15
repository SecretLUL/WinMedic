use crate::utils::cmd::run_powershell;
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
}

impl RestorePointOutcome {
    /// Only a confirmed new restore point counts as protection.
    pub fn is_protected(&self) -> bool {
        matches!(self, Self::Created)
    }

    pub fn message(&self) -> String {
        match self {
            Self::Created => "VSS-Wiederherstellungspunkt wurde erstellt.".to_string(),
            Self::Throttled => "Windows hat keinen neuen Wiederherstellungspunkt angelegt: \
                 Es wurde bereits einer innerhalb der letzten 24 Stunden erstellt \
                 (Windows-Standarddrosselung). Ein aktueller Punkt existiert also, \
                 er bildet aber nicht den Stand unmittelbar vor dieser Reparatur ab."
                .to_string(),
            Self::Unverified => "Wiederherstellungspunkt konnte nicht bestätigt werden: \
                 Die Liste der Wiederherstellungspunkte war nicht lesbar \
                 (fehlen Administratorrechte?). Es ist unklar, ob ein Punkt existiert."
                .to_string(),
            Self::Failed(err) => {
                format!("Wiederherstellungspunkt fehlgeschlagen: {}", err)
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

/// Escape a value for embedding in a PowerShell single-quoted string, where the
/// only metacharacter is `'` itself. Single-quoted strings do not interpolate,
/// so `$(...)`, backticks and `$vars` are inert inside them.
fn escape_ps_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
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
                "unbekannter Fehler".to_string()
            } else {
                detail.to_string()
            };
            RestorePointOutcome::Failed(detail)
        }
        // No marker at all means the script did not run to completion.
        None => {
            let tail = output.trim();
            let detail = if tail.is_empty() {
                "PowerShell lieferte keine Ausgabe".to_string()
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
            Checkpoint-Computer -Description '{}' -RestorePointType 'MODIFY_SETTINGS' -WarningAction SilentlyContinue
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
        escape_ps_single_quoted(description),
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
pub async fn create_system_restore_point(description: &str) -> RestorePointResult {
    let script = checkpoint_script(description);

    match run_powershell(&script, Duration::from_secs(60)).await {
        Ok(out) => {
            let combined = format!("{}\n{}", out.stdout, out.stderr);
            RestorePointResult::from_outcome(description, parse_checkpoint_output(&combined))
        }
        Err(e) => RestorePointResult::from_outcome(
            description,
            RestorePointOutcome::Failed(format!("PowerShell nicht ausführbar: {}", e)),
        ),
    }
}

/// Query existing Windows restore points
pub async fn list_restore_points() -> Vec<String> {
    let script = r#"
        Get-ComputerRestorePoint | Select-Object -Property SequenceNumber, Description, CreationTime | ForEach-Object {
            "$($_.SequenceNumber) | $($_.Description) | $($_.CreationTime)"
        }
    "#;

    match run_powershell(script, Duration::from_secs(15)).await {
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
        assert!(out.message().contains("24 Stunden"));
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
        let script = checkpoint_script("WinMedic Auto-Restore Point (Vor Reparatur)");
        assert!(script.contains("'WinMedic Auto-Restore Point (Vor Reparatur)'"));
    }

    #[test]
    fn result_carries_outcome_and_description() {
        let res = RestorePointResult::from_outcome("Vor Reparatur", RestorePointOutcome::Throttled);
        assert!(!res.success);
        assert_eq!(res.outcome, RestorePointOutcome::Throttled);
        assert_eq!(res.description, "Vor Reparatur");
        assert!(!res.message.is_empty());
    }
}
