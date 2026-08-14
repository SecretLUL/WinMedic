use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Execute a system command with timeout and return the complete output.
pub async fn run_cmd(
    program: &str,
    args: &[&str],
    timeout_duration: Duration,
) -> Result<CmdOutput, String> {
    let mut cmd = TokioCommand::new(program);
    cmd.args(args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn command '{}': {}", program, e))?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let stdout_handle = tokio::spawn(async move {
        let mut out = Vec::new();
        if let Some(mut s) = stdout {
            let _ = s.read_to_end(&mut out).await;
        }
        out
    });

    let stderr_handle = tokio::spawn(async move {
        let mut err = Vec::new();
        if let Some(mut s) = stderr {
            let _ = s.read_to_end(&mut err).await;
        }
        err
    });

    let status_res = timeout(timeout_duration, child.wait()).await;
    match status_res {
        Ok(Ok(status)) => {
            let stdout_bytes = stdout_handle.await.unwrap_or_default();
            let stderr_bytes = stderr_handle.await.unwrap_or_default();
            let stdout_str = String::from_utf8_lossy(&stdout_bytes).to_string();
            let stderr_str = String::from_utf8_lossy(&stderr_bytes).to_string();
            Ok(CmdOutput {
                success: status.success(),
                exit_code: status.code(),
                stdout: stdout_str,
                stderr: stderr_str,
            })
        }
        Ok(Err(e)) => Err(format!("Command execution error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Err(format!(
                "Command '{}' timed out after {:?}",
                program, timeout_duration
            ))
        }
    }
}

/// Execute a command and stream each output line to a Tokio channel in real-time.
pub async fn run_cmd_streaming(
    program: &str,
    args: &[&str],
    log_tx: Option<Sender<String>>,
    timeout_duration: Duration,
) -> Result<CmdOutput, String> {
    let mut cmd = TokioCommand::new(program);
    cmd.args(args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn command '{}': {}", program, e))?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let mut stdout_lines = Vec::new();
    let mut stderr_lines = Vec::new();

    let stdout_tx = log_tx.clone();
    let stdout_handle = tokio::spawn(async move {
        if let Some(stdout) = stdout {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if let Some(ref tx) = stdout_tx {
                    let _ = tx.send(line.clone()).await;
                }
                stdout_lines.push(line);
            }
        }
        stdout_lines
    });

    let stderr_tx = log_tx;
    let stderr_handle = tokio::spawn(async move {
        if let Some(stderr) = stderr {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if let Some(ref tx) = stderr_tx {
                    let _ = tx.send(format!("[STDERR] {}", line)).await;
                }
                stderr_lines.push(line);
            }
        }
        stderr_lines
    });

    let wait_result = timeout(timeout_duration, child.wait()).await;

    let (stdout_out, stderr_out) = tokio::join!(stdout_handle, stderr_handle);
    let stdout_combined = stdout_out.unwrap_or_default().join("\n");
    let stderr_combined = stderr_out.unwrap_or_default().join("\n");

    match wait_result {
        Ok(Ok(status)) => Ok(CmdOutput {
            success: status.success(),
            exit_code: status.code(),
            stdout: stdout_combined,
            stderr: stderr_combined,
        }),
        Ok(Err(e)) => Err(format!("Command error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Err(format!(
                "Command '{}' timed out after {:?}",
                program, timeout_duration
            ))
        }
    }
}

/// Run a PowerShell command safely and return output.
pub async fn run_powershell(command_str: &str, timeout_dur: Duration) -> Result<CmdOutput, String> {
    run_cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", command_str],
        timeout_dur,
    )
    .await
}
