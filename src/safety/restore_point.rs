use crate::utils::cmd::run_powershell;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RestorePointResult {
    pub success: bool,
    pub description: String,
    pub message: String,
}

/// Create a Windows System Restore Point (VSS Checkpoint)
pub async fn create_system_restore_point(description: &str) -> RestorePointResult {
    let script = format!(
        r#"
        try {{
            Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
            Checkpoint-Computer -Description "{}" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            "SUCCESS: Restore point created successfully."
        }} catch {{
            "ERROR: " + $_.Exception.Message
        }}
        "#,
        description
    );

    match run_powershell(&script, Duration::from_secs(45)).await {
        Ok(out) => {
            let combined = format!("{}\n{}", out.stdout, out.stderr);
            if combined.contains("SUCCESS") {
                RestorePointResult {
                    success: true,
                    description: description.to_string(),
                    message: "VSS System Restore Point created successfully.".to_string(),
                }
            } else {
                RestorePointResult {
                    success: false,
                    description: description.to_string(),
                    message: format!("Restore point creation note: {}", combined.trim()),
                }
            }
        }
        Err(e) => RestorePointResult {
            success: false,
            description: description.to_string(),
            message: format!("Failed to invoke PowerShell for restore point: {}", e),
        },
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
