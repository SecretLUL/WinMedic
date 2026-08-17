//! Structured verbose tracing for scans and repairs.
//!
//! A repair that fails is only actionable if the log says *what ran*, *what came
//! back* and *what that means*. The plain progress lines deliberately stay short
//! and human-readable, so everything diagnostic goes through [`DebugTrace`],
//! which writes into the same console buffer but with a marker the UI can pick
//! out and colour separately.
//!
//! Every line looks like this:
//!
//! ```text
//! [DBG 09:30:48.123] EXEC chkdsk.exe C: /scan
//! [DBG 09:30:48.140] WARN spawn refused by the OS: os error 5
//! [DBG 09:30:48.140] HINT ACCESS_DENIED - the image never started
//! ```
//!
//! Tracing is off unless the user turns on "Enable verbose / debug logs" in the
//! settings tab, and a disabled [`DebugTrace`] does no formatting work at all —
//! the `enabled` check happens before any `format!`.

use crate::modules::{FixProgress, ModuleProgress};
use crate::utils::cmd::{CmdOutput, CommandRunner, describe_os_error};
use chrono::Local;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;

/// Opening marker of every verbose line, used by the UI to recognise them.
pub const DEBUG_MARKER: &str = "[DBG ";

/// Number of leading output lines echoed into the trace per command.
const MAX_ECHOED_STDOUT_LINES: usize = 8;
/// Number of error-stream lines echoed into the trace per command.
const MAX_ECHOED_STDERR_LINES: usize = 12;

/// The kind of a verbose line. Rendered as a fixed-width tag so the log stays
/// in columns, and mapped to its own colour by the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugTag {
    /// A step inside a repair or check.
    Step,
    /// A command about to be executed.
    Exec,
    /// The result of a command.
    Exit,
    /// A value read from the system (path, size, registry value, ...).
    Data,
    /// Something went wrong, or looks wrong.
    Warn,
    /// An interpretation of the failure: what it usually means.
    Hint,
    /// A duration measurement.
    Time,
}

impl DebugTag {
    /// Fixed-width label written into the log line.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Step => "STEP",
            Self::Exec => "EXEC",
            Self::Exit => "EXIT",
            Self::Data => "DATA",
            Self::Warn => "WARN",
            Self::Hint => "HINT",
            Self::Time => "TIME",
        }
    }

    /// Parse a tag back out of a rendered line.
    pub fn from_label(label: &str) -> Option<Self> {
        Some(match label {
            "STEP" => Self::Step,
            "EXEC" => Self::Exec,
            "EXIT" => Self::Exit,
            "DATA" => Self::Data,
            "WARN" => Self::Warn,
            "HINT" => Self::Hint,
            "TIME" => Self::Time,
            _ => return None,
        })
    }
}

/// A rendered verbose line, split into its parts for styling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDebugLine<'a> {
    /// `[DBG 09:30:48.123]`, including the brackets.
    pub stamp: &'a str,
    pub tag: DebugTag,
    pub message: &'a str,
}

/// Split a console line into its verbose parts, or `None` for a normal line.
///
/// The UI uses this to colour traces differently from repair output, so it has
/// to reject anything that merely *looks* like a trace — a command that printed
/// `[DBG ...]` itself, for instance, must keep flowing through the normal path.
pub fn parse_debug_line(line: &str) -> Option<ParsedDebugLine<'_>> {
    let rest = line.strip_prefix(DEBUG_MARKER)?;
    let close = rest.find(']')?;
    let stamp = &line[..DEBUG_MARKER.len() + close + 1];
    let after = rest[close + 1..].strip_prefix(' ')?;
    let (label, message) = after.split_at(after.len().min(4));
    let tag = DebugTag::from_label(label)?;
    Some(ParsedDebugLine {
        stamp,
        tag,
        message: message.trim_start(),
    })
}

/// Render one verbose line, timestamp and all.
///
/// Public because the repair engine writes into a different channel than the
/// modules do but has to produce lines the UI recognises just the same.
pub fn render_debug_line(tag: DebugTag, message: &str) -> String {
    format!(
        "{}{}] {} {}",
        DEBUG_MARKER,
        Local::now().format("%H:%M:%S%.3f"),
        tag.label(),
        message
    )
}

/// Render a `key = value` fact, aligned into a column.
pub fn render_debug_kv(key: &str, value: &str) -> String {
    render_debug_line(DebugTag::Data, &format!("{:<22} {}", key, value))
}

/// Where the rendered lines are sent.
enum DebugSink {
    Fix {
        issue_id: String,
        tx: Sender<FixProgress>,
    },
    Scan {
        module_id: String,
        tx: Sender<ModuleProgress>,
    },
    /// Verbose mode off, or nobody listening.
    Discard,
}

/// Emitter for verbose diagnostic lines.
///
/// Cheap to create and to pass around; when tracing is off every method returns
/// immediately without allocating.
pub struct DebugTrace {
    sink: DebugSink,
    enabled: bool,
}

impl DebugTrace {
    /// Trace attached to a running repair.
    pub fn fix(issue_id: &str, tx: Option<Sender<FixProgress>>, enabled: bool) -> Self {
        match tx {
            Some(tx) if enabled => Self {
                sink: DebugSink::Fix {
                    issue_id: issue_id.to_string(),
                    tx,
                },
                enabled: true,
            },
            _ => Self::disabled(),
        }
    }

    /// Trace attached to a running module scan.
    pub fn scan(module_id: &str, tx: Option<Sender<ModuleProgress>>, enabled: bool) -> Self {
        match tx {
            Some(tx) if enabled => Self {
                sink: DebugSink::Scan {
                    module_id: module_id.to_string(),
                    tx,
                },
                enabled: true,
            },
            _ => Self::disabled(),
        }
    }

    /// A trace that swallows everything.
    pub fn disabled() -> Self {
        Self {
            sink: DebugSink::Discard,
            enabled: false,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Render and dispatch one line.
    async fn emit(&self, tag: DebugTag, message: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        let line = render_debug_line(tag, message.as_ref());
        match &self.sink {
            DebugSink::Fix { issue_id, tx } => {
                let _ = tx
                    .send(FixProgress {
                        issue_id: issue_id.clone(),
                        step_description: String::new(),
                        is_success: tag != DebugTag::Warn,
                        error: None,
                        console_line: Some(line),
                    })
                    .await;
            }
            DebugSink::Scan { module_id, tx } => {
                let _ = tx
                    .send(ModuleProgress {
                        module_id: module_id.clone(),
                        progress_percent: 0,
                        current_step: String::new(),
                        log_message: Some(line),
                    })
                    .await;
            }
            DebugSink::Discard => {}
        }
    }

    pub async fn step(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Step, message).await;
    }

    pub async fn data(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Data, message).await;
    }

    pub async fn warn(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Warn, message).await;
    }

    pub async fn hint(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Hint, message).await;
    }

    pub async fn time(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Time, message).await;
    }

    /// A `key = value` fact about the system, aligned into a column.
    pub async fn kv(&self, key: &str, value: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        self.emit(DebugTag::Data, format!("{:<22} {}", key, value.as_ref()))
            .await;
    }

    /// Report a filesystem path with everything the log needs to judge it.
    pub async fn path(&self, label: &str, path: &std::path::Path) {
        if !self.enabled {
            return;
        }
        let state = match std::fs::metadata(path) {
            Ok(meta) if meta.is_dir() => "directory".to_string(),
            Ok(meta) => format!("file, {} B", meta.len()),
            Err(err) => format!("unavailable: {}", err),
        };
        self.kv(label, format!("{} ({})", path.display(), state))
            .await;
    }

    /// A named divider that groups the lines that follow it.
    pub async fn section(&self, title: &str) {
        if !self.enabled {
            return;
        }
        self.emit(DebugTag::Step, format!("--- {} ---", title))
            .await;
    }

    /// Run a command and trace the call, the result and any failure reason.
    ///
    /// The returned value is exactly what the runner produced; tracing never
    /// changes the outcome of a repair.
    pub async fn run(
        &self,
        runner: &Arc<dyn CommandRunner>,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CmdOutput, String> {
        if self.enabled {
            self.emit(
                DebugTag::Exec,
                format!("{} {}", program, args.join(" ")).trim_end(),
            )
            .await;
            self.kv("timeout", format!("{:?}", timeout)).await;
        }

        let started = Instant::now();
        let result = runner.run(program, args, timeout).await;
        self.trace_outcome(program, started, &result).await;
        result
    }

    /// Run a PowerShell script and trace the script itself alongside the result.
    pub async fn run_powershell(
        &self,
        runner: &Arc<dyn CommandRunner>,
        script: &str,
        timeout: Duration,
    ) -> Result<CmdOutput, String> {
        if self.enabled {
            self.emit(
                DebugTag::Exec,
                "powershell -NoProfile -NonInteractive -Command",
            )
            .await;
            for line in script.lines().filter(|l| !l.trim().is_empty()) {
                self.data(format!("  | {}", line.trim_end())).await;
            }
            self.kv("timeout", format!("{:?}", timeout)).await;
        }

        let started = Instant::now();
        let result = runner.run_powershell(script, timeout).await;
        self.trace_outcome("powershell", started, &result).await;
        result
    }

    /// Report how a command ended: exit code, duration and its output streams.
    async fn trace_outcome(
        &self,
        program: &str,
        started: Instant,
        result: &Result<CmdOutput, String>,
    ) {
        if !self.enabled {
            return;
        }
        let elapsed = started.elapsed();

        match result {
            Ok(out) => {
                self.emit(
                    DebugTag::Exit,
                    format!(
                        "code {} ({}) after {:.2?} | stdout {} B, stderr {} B",
                        out.exit_code
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "none".to_string()),
                        if out.success { "success" } else { "failure" },
                        elapsed,
                        out.stdout.len(),
                        out.stderr.len()
                    ),
                )
                .await;

                self.echo_stream(DebugTag::Data, "out", &out.stdout, MAX_ECHOED_STDOUT_LINES)
                    .await;
                self.echo_stream(DebugTag::Warn, "err", &out.stderr, MAX_ECHOED_STDERR_LINES)
                    .await;

                if !out.success && out.stdout.trim().is_empty() && out.stderr.trim().is_empty() {
                    self.hint(format!(
                        "'{}' failed without writing a single byte of output - the reason was suppressed, not absent (PowerShell does this with -ErrorAction SilentlyContinue).",
                        program
                    ))
                    .await;
                }
            }
            Err(err) => {
                self.warn(format!("could not run '{}': {}", program, err))
                    .await;
                self.time(format!("gave up after {:.2?}", elapsed)).await;
                if let Some(code) = extract_os_error_code(err)
                    && let Some(desc) = describe_os_error(code)
                {
                    // The command layer already appends the meaning to the
                    // message it hands back, so repeating it here would print
                    // the same sentence twice in a row.
                    if !err.contains(desc.name) {
                        self.hint(format!("{} - {}", desc.name, desc.meaning)).await;
                    }
                    for cause in desc.likely_causes {
                        self.hint(format!("  possible cause: {}", cause)).await;
                    }
                }
            }
        }
    }

    /// Echo the first `limit` non-empty lines of an output stream.
    async fn echo_stream(&self, tag: DebugTag, label: &str, stream: &str, limit: usize) {
        let lines: Vec<&str> = stream
            .lines()
            .map(str::trim_end)
            .filter(|l| !l.is_empty())
            .collect();
        for line in lines.iter().take(limit) {
            self.emit(tag, format!("{}| {}", label, line)).await;
        }
        if lines.len() > limit {
            self.emit(
                tag,
                format!(
                    "{}| ... {} more line(s) omitted",
                    label,
                    lines.len() - limit
                ),
            )
            .await;
        }
    }
}

/// Pull the numeric code out of an `std::io::Error` rendered into a message.
///
/// The command layer hands failures back as strings, so the code has to be
/// recovered from the `(os error N)` suffix Rust appends.
pub fn extract_os_error_code(message: &str) -> Option<i32> {
    let start = message.rfind("(os error ")? + "(os error ".len();
    let rest = &message[start..];
    let end = rest.find(')')?;
    rest[..end].trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_rendered_debug_line() {
        let parsed = parse_debug_line("[DBG 09:30:48.123] EXEC chkdsk.exe C: /scan").unwrap();
        assert_eq!(parsed.stamp, "[DBG 09:30:48.123]");
        assert_eq!(parsed.tag, DebugTag::Exec);
        assert_eq!(parsed.message, "chkdsk.exe C: /scan");
    }

    #[test]
    fn rejects_lines_that_are_not_traces() {
        // Ordinary repair output, including output that merely mentions a tag.
        for line in [
            "Repairing: Recycle Bin",
            "[OK] Package cache cleaned",
            "[DBG] EXEC something",
            "[DBG 09:30:48.123] NOPE unknown tag",
            "[DBG 09:30:48.123]",
        ] {
            assert!(parse_debug_line(line).is_none(), "wrongly parsed: {}", line);
        }
    }

    #[tokio::test]
    async fn a_disabled_trace_sends_nothing() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<FixProgress>(16);
        let trace = DebugTrace::fix("some_issue", Some(tx), false);

        assert!(!trace.is_enabled());
        trace.step("ignored").await;
        trace.warn("ignored").await;
        trace.kv("key", "value").await;

        assert!(rx.try_recv().is_err(), "a disabled trace must stay silent");
    }

    #[tokio::test]
    async fn an_enabled_trace_renders_parseable_lines() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<FixProgress>(16);
        let trace = DebugTrace::fix("sys_clean_recycle_bin", Some(tx), true);

        trace.warn("it broke").await;

        let progress = rx.try_recv().unwrap();
        assert_eq!(progress.issue_id, "sys_clean_recycle_bin");
        let line = progress.console_line.unwrap();
        let parsed = parse_debug_line(&line).unwrap();
        assert_eq!(parsed.tag, DebugTag::Warn);
        assert_eq!(parsed.message, "it broke");
    }

    #[test]
    fn recovers_the_os_error_code_from_a_message() {
        assert_eq!(
            extract_os_error_code(
                "Failed to spawn command 'chkdsk.exe': Access denied (os error 5)"
            ),
            Some(5)
        );
        assert_eq!(extract_os_error_code("timed out after 120s"), None);
        assert_eq!(extract_os_error_code("(os error not-a-number)"), None);
    }
}
