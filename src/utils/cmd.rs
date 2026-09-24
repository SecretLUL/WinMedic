use crate::utils::decode::{LineDecoder, decode_output};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            success: true,
            exit_code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    pub fn failed(exit_code: i32, stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            exit_code: Some(exit_code),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    pub fn with_output(
        exit_code: i32,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Self {
        Self {
            success: exit_code == 0,
            exit_code: Some(exit_code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
}

/// Abstract runner for executing system commands, enabling deterministic unit testing
/// of diagnostic detection and repair parsing logic without real system execution.
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout_duration: Duration,
    ) -> Result<CmdOutput, String>;

    async fn run_streaming(
        &self,
        program: &str,
        args: &[&str],
        log_tx: Option<Sender<String>>,
        timeout_duration: Duration,
    ) -> Result<CmdOutput, String>;

    async fn run_powershell(
        &self,
        command_str: &str,
        timeout_duration: Duration,
    ) -> Result<CmdOutput, String> {
        let script = powershell_script(command_str);
        self.run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            timeout_duration,
        )
        .await
    }

    /// [`Self::run_powershell`] for a script that only reads: a timeout is
    /// retried once.
    ///
    /// At scan start every module asks WMI something at the same moment, and
    /// on a busy machine (seen on CI runners) the first query of a module
    /// sometimes stalls past its timeout while the same query answers at
    /// once a little later. A second timeout is reported as before.
    async fn query_powershell(
        &self,
        command_str: &str,
        timeout_duration: Duration,
    ) -> Result<CmdOutput, String> {
        match self.run_powershell(command_str, timeout_duration).await {
            Err(err) if is_timeout(&err) => self
                .run_powershell(command_str, timeout_duration)
                .await
                .map_err(|again| format!("{again} (on the second attempt too)")),
            result => result,
        }
    }
}

/// The error [`run_cmd`] and [`run_cmd_streaming`] return when a command did
/// not finish in time.
fn timed_out(program: &str, timeout_duration: Duration) -> String {
    format!("Command '{program}' timed out after {timeout_duration:?}")
}

/// Whether an error from a [`CommandRunner`] is a timeout.
pub fn is_timeout(err: &str) -> bool {
    err.starts_with("Command '") && err.contains("' timed out after ")
}

/// How many PowerShell processes the real runner starts at once.
///
/// Every module of a scan starts at the same time, and most ask PowerShell
/// and WMI something first: a dozen processes loading CIM together. Capping
/// them costs a couple of seconds on a fast PC and keeps WMI from being
/// swamped on a slow one. Waiting for a slot does not count against a
/// command's timeout.
const POWERSHELL_SLOTS: usize = 4;

fn powershell_slots() -> &'static tokio::sync::Semaphore {
    static SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(POWERSHELL_SLOTS))
}

/// Prefix a script with the switch that makes PowerShell write UTF-8.
///
/// Left alone, PowerShell writes into a pipe in the OEM code page, which cannot
/// hold every character a device name, a path or a task description may carry.
/// UTF-8 can, and [`crate::utils::decode`] takes UTF-8 as it is. No byte order
/// mark: the output would otherwise start with one.
pub fn powershell_script(command_str: &str) -> String {
    format!(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); {}",
        command_str
    )
}

/// Production runner executing actual OS processes via tokio::process::Command.
#[derive(Debug, Default, Clone)]
pub struct SystemCommandRunner;

impl SystemCommandRunner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl CommandRunner for SystemCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout_duration: Duration,
    ) -> Result<CmdOutput, String> {
        run_cmd(program, args, timeout_duration).await
    }

    async fn run_streaming(
        &self,
        program: &str,
        args: &[&str],
        log_tx: Option<Sender<String>>,
        timeout_duration: Duration,
    ) -> Result<CmdOutput, String> {
        run_cmd_streaming(program, args, log_tx, timeout_duration).await
    }

    async fn run_powershell(
        &self,
        command_str: &str,
        timeout_duration: Duration,
    ) -> Result<CmdOutput, String> {
        let _slot = powershell_slots()
            .acquire()
            .await
            .map_err(|e| format!("PowerShell could not be started: {e}"))?;
        let script = powershell_script(command_str);
        run_cmd(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            timeout_duration,
        )
        .await
    }
}

/// Mock runner allowing tests to inject canned command outputs and verify executed commands.
#[derive(Default, Clone)]
pub struct MockCommandRunner {
    responses: Arc<Mutex<Vec<(String, CmdOutput)>>>,
    default_response: Arc<Mutex<Option<CmdOutput>>>,
    executed_commands: Arc<Mutex<Vec<String>>>,
}

impl MockCommandRunner {
    pub fn new() -> Self {
        Self {
            responses: Arc::new(Mutex::new(Vec::new())),
            default_response: Arc::new(Mutex::new(None)),
            executed_commands: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_default_success() -> Self {
        Self {
            responses: Arc::new(Mutex::new(Vec::new())),
            default_response: Arc::new(Mutex::new(Some(CmdOutput::ok("")))),
            executed_commands: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a mock response for commands matching `match_substring`.
    pub fn add_response(&self, match_substring: impl Into<String>, output: CmdOutput) {
        self.responses
            .lock()
            .unwrap()
            .push((match_substring.into(), output));
    }

    /// Retrieve all executed command strings.
    pub fn executed(&self) -> Vec<String> {
        self.executed_commands.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl CommandRunner for MockCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        _timeout_duration: Duration,
    ) -> Result<CmdOutput, String> {
        let full_cmd = format!("{} {}", program, args.join(" "));
        self.executed_commands
            .lock()
            .unwrap()
            .push(full_cmd.clone());

        let responses = self.responses.lock().unwrap();
        for (pattern, output) in responses.iter() {
            if full_cmd.contains(pattern) || program.contains(pattern) {
                return Ok(output.clone());
            }
        }

        let def = self.default_response.lock().unwrap();
        if let Some(ref default_out) = *def {
            return Ok(default_out.clone());
        }

        Err(format!(
            "No mock response configured for command: '{}'",
            full_cmd
        ))
    }

    async fn run_streaming(
        &self,
        program: &str,
        args: &[&str],
        log_tx: Option<Sender<String>>,
        timeout_duration: Duration,
    ) -> Result<CmdOutput, String> {
        let res = self.run(program, args, timeout_duration).await?;
        if let Some(ref tx) = log_tx {
            for line in res.stdout.lines() {
                let _ = tx.send(line.to_string()).await;
            }
            for line in res.stderr.lines() {
                let _ = tx.send(format!("[STDERR] {}", line)).await;
            }
        }
        Ok(res)
    }
}

/// What a process-creation error code means, in the terms the log needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsErrorDescription {
    /// The Windows symbolic name, e.g. `ACCESS_DENIED`.
    pub name: &'static str,
    /// What the code says about the attempt itself.
    pub meaning: &'static str,
    /// The explanations worth checking first, most likely one first.
    pub likely_causes: &'static [&'static str],
}

/// Explain a Windows error code returned while starting a process.
///
/// `CreateProcess` failing is categorically different from the tool running and
/// reporting a problem: nothing executed, so no exit code and no output exist to
/// look at. Without this the log shows only a number, and "os error 5" reads as
/// "chkdsk said access denied" when it actually means "chkdsk never started".
pub fn describe_os_error(code: i32) -> Option<OsErrorDescription> {
    let desc = match code {
        2 => OsErrorDescription {
            name: "FILE_NOT_FOUND",
            meaning: "the executable was not found under that name",
            likely_causes: &[
                "the tool is not installed, or not on PATH for this process",
                "a 32-bit build looking into System32, which WOW64 redirects to SysWOW64",
            ],
        },
        3 => OsErrorDescription {
            name: "PATH_NOT_FOUND",
            meaning: "a directory in the given path does not exist",
            likely_causes: &["a stale or mistyped directory in the command path"],
        },
        5 => OsErrorDescription {
            name: "ACCESS_DENIED",
            meaning: "Windows refused to create the process; the program never started, so this is not the tool's own output",
            likely_causes: &[
                "a kernel-mode security driver (anti-cheat, antivirus, EDR) blocking that image name",
                "an execution policy: AppLocker, Software Restriction Policies or WDAC",
                "the file's ACL not granting execute permission to this account",
            ],
        },
        216 => OsErrorDescription {
            name: "EXE_MACHINE_TYPE_MISMATCH",
            meaning: "the image was built for a different processor architecture",
            likely_causes: &["an x86/x64/ARM64 mismatch between WinMedic and the tool"],
        },
        577 => OsErrorDescription {
            name: "INVALID_IMAGE_HASH",
            meaning: "code integrity rejected the image signature",
            likely_causes: &[
                "a modified or corrupted system file",
                "a code integrity policy demanding a signature the file does not carry",
            ],
        },
        740 => OsErrorDescription {
            name: "ELEVATION_REQUIRED",
            meaning: "the tool demands Administrator rights and WinMedic is not elevated",
            likely_causes: &["WinMedic was started without elevation; restart it with '--elevate'"],
        },
        1260 => OsErrorDescription {
            name: "ACCESS_DISABLED_BY_POLICY",
            meaning: "a group policy forbids running this program",
            likely_causes: &["a Software Restriction Policy or AppLocker rule set by the domain"],
        },
        _ => return None,
    };
    Some(desc)
}

/// Render a spawn failure with the explanation attached.
///
/// Keeps Rust's own message intact — including the `(os error N)` suffix that
/// [`crate::utils::debug_log::extract_os_error_code`] reads back out — and adds
/// what that number means for the repair the user just watched fail.
fn describe_spawn_failure(program: &str, err: &std::io::Error) -> String {
    let base = format!("Failed to spawn command '{}': {}", program, err);
    match err.raw_os_error().and_then(describe_os_error) {
        Some(desc) => format!("{} [{}: {}]", base, desc.name, desc.meaning),
        None => base,
    }
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
    // Dropping the future (e.g. when the user cancels a running scan) must take
    // the child process with it, otherwise a DISM or chkdsk run keeps going.
    cmd.kill_on_drop(true);

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| describe_spawn_failure(program, &e))?;

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
            Ok(CmdOutput {
                success: status.success(),
                exit_code: status.code(),
                stdout: decode_output(&stdout_bytes),
                stderr: decode_output(&stderr_bytes),
            })
        }
        Ok(Err(e)) => Err(format!("Command execution error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Err(timed_out(program, timeout_duration))
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
    // Dropping the future (e.g. when the user cancels a running scan) must take
    // the child process with it, otherwise a DISM or chkdsk run keeps going.
    cmd.kill_on_drop(true);

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| describe_spawn_failure(program, &e))?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let mut stdout_lines = Vec::new();
    let mut stderr_lines = Vec::new();

    let stdout_tx = log_tx.clone();
    let stdout_handle = tokio::spawn(async move {
        if let Some(stdout) = stdout {
            forward_lines(stdout, stdout_tx, "", &mut stdout_lines).await;
        }
        stdout_lines
    });

    let stderr_tx = log_tx;
    let stderr_handle = tokio::spawn(async move {
        if let Some(stderr) = stderr {
            forward_lines(stderr, stderr_tx, "[STDERR] ", &mut stderr_lines).await;
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
            Err(timed_out(program, timeout_duration))
        }
    }
}

/// Read `pipe` to the end, decoding it line by line, and hand each line to the
/// log channel as it arrives.
///
/// Reads raw bytes rather than `lines()`: that reader stops at the first line
/// that is not UTF-8, and German DISM or SFC output has one within the first
/// few lines — everything after it, the verdict included, was lost.
async fn forward_lines(
    mut pipe: impl tokio::io::AsyncRead + Unpin,
    tx: Option<Sender<String>>,
    prefix: &str,
    lines: &mut Vec<String>,
) {
    let mut decoder = LineDecoder::new();
    let mut buf = [0u8; 4096];
    loop {
        let read = match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        for line in decoder.push(&buf[..read]) {
            if let Some(ref tx) = tx {
                let _ = tx.send(format!("{prefix}{line}")).await;
            }
            lines.push(line);
        }
    }
    if let Some(line) = decoder.finish() {
        if let Some(ref tx) = tx {
            let _ = tx.send(format!("{prefix}{line}")).await;
        }
        lines.push(line);
    }
}

/// Run a PowerShell command safely and return output.
pub async fn run_powershell(command_str: &str, timeout_dur: Duration) -> Result<CmdOutput, String> {
    let script = powershell_script(command_str);
    run_cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        timeout_dur,
    )
    .await
}

/// Quote a runtime value for embedding in a PowerShell script.
///
/// This is the **one supported way** to put a value WinMedic did not write
/// itself — a path, a service name, a device id, a restore point description,
/// anything read back from the system, a config file or the network — into a
/// script handed to [`run_powershell`]. Interpolating such a value directly
/// lets it end the surrounding string and continue as code, in a process that
/// is very often running as Administrator.
///
/// The returned string *includes* its quotes, so a caller cannot forget them:
///
/// ```
/// use winmedic::utils::cmd::ps_single_quoted;
///
/// let name = "My Service";
/// let script = format!("Get-Service -Name {}", ps_single_quoted(name));
/// assert_eq!(script, "Get-Service -Name 'My Service'");
/// ```
///
/// PowerShell performs no interpolation inside single-quoted strings, so
/// `$var`, `$(...)`, `@(...)` and backtick escapes are all inert there. That
/// leaves `'` as the only metacharacter, and it is escaped by doubling it —
/// which is why this needs no allow-list and cannot be defeated by an encoding
/// the caller did not anticipate.
///
/// This protects a *value*. It does not make an arbitrary script safe: command
/// names, parameter names and script structure must always be literals in the
/// source, never assembled from external input.
pub fn ps_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_command_runner() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "dism.exe",
            CmdOutput::ok("The component store is repairable."),
        );
        mock.add_response("sfc.exe", CmdOutput::failed(1, "Corrupted files"));

        let out1 = mock
            .run(
                "dism.exe",
                &["/Online", "/Cleanup-Image", "/CheckHealth"],
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert!(out1.success);
        assert_eq!(out1.stdout, "The component store is repairable.");

        let out2 = mock
            .run("sfc.exe", &["/verifyonly"], Duration::from_secs(5))
            .await
            .unwrap();
        assert!(!out2.success);
        assert_eq!(out2.stderr, "Corrupted files");

        let executed = mock.executed();
        assert_eq!(executed.len(), 2);
        assert!(executed[0].contains("dism.exe"));
        assert!(executed[1].contains("sfc.exe"));
    }

    /// Answers each call with the next of `answers` and counts the calls.
    struct Scripted {
        answers: Mutex<Vec<Result<CmdOutput, String>>>,
        calls: Mutex<usize>,
    }

    impl Scripted {
        fn new(answers: Vec<Result<CmdOutput, String>>) -> Self {
            Self {
                answers: Mutex::new(answers),
                calls: Mutex::new(0),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for Scripted {
        async fn run(&self, _: &str, _: &[&str], _: Duration) -> Result<CmdOutput, String> {
            *self.calls.lock().unwrap() += 1;
            self.answers.lock().unwrap().remove(0)
        }

        async fn run_streaming(
            &self,
            program: &str,
            args: &[&str],
            _: Option<Sender<String>>,
            timeout: Duration,
        ) -> Result<CmdOutput, String> {
            self.run(program, args, timeout).await
        }
    }

    const QUERY_TIMEOUT: Duration = Duration::from_secs(20);

    #[tokio::test]
    async fn a_query_that_timed_out_is_asked_once_more() {
        let runner = Scripted::new(vec![
            Err(timed_out("powershell", QUERY_TIMEOUT)),
            Ok(CmdOutput::ok("True|17179869184")),
        ]);
        let out = runner.query_powershell("q", QUERY_TIMEOUT).await.unwrap();
        assert_eq!(out.stdout, "True|17179869184");
        assert_eq!(runner.calls(), 2);
    }

    #[tokio::test]
    async fn a_second_timeout_is_reported() {
        let runner = Scripted::new(vec![
            Err(timed_out("powershell", QUERY_TIMEOUT)),
            Err(timed_out("powershell", QUERY_TIMEOUT)),
        ]);
        let err = runner
            .query_powershell("q", QUERY_TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            "Command 'powershell' timed out after 20s (on the second attempt too)"
        );
        assert_eq!(runner.calls(), 2);
    }

    #[tokio::test]
    async fn only_a_timeout_is_retried() {
        let runner = Scripted::new(vec![Err("Command execution error: denied".to_string())]);
        assert!(runner.query_powershell("q", QUERY_TIMEOUT).await.is_err());
        assert_eq!(runner.calls(), 1);
        assert!(!is_timeout("Command execution error: denied"));
        assert!(is_timeout(&timed_out("wevtutil.exe", QUERY_TIMEOUT)));
    }

    /// The whole point of the table is that a failed repair explains itself, so
    /// an entry without a usable explanation is worse than no entry.
    #[test]
    fn every_known_os_error_carries_a_usable_explanation() {
        for code in [2, 3, 5, 216, 577, 740, 1260] {
            let desc = describe_os_error(code).unwrap_or_else(|| panic!("missing: {}", code));
            assert!(!desc.name.is_empty());
            assert!(!desc.meaning.is_empty());
            assert!(!desc.likely_causes.is_empty(), "no causes for {}", code);
        }
        assert_eq!(describe_os_error(0), None);
        assert_eq!(describe_os_error(123456), None);
    }

    /// The message keeps Rust's `(os error N)` suffix, because that is what the
    /// verbose log parses back out to look the code up again.
    #[test]
    fn a_spawn_failure_keeps_its_code_and_gains_an_explanation() {
        let err = std::io::Error::from_raw_os_error(5);
        let message = describe_spawn_failure("chkdsk.exe", &err);

        assert!(message.starts_with("Failed to spawn command 'chkdsk.exe':"));
        assert!(message.contains("(os error 5)"));
        assert!(message.contains("ACCESS_DENIED"));
        assert!(message.contains("never started"));
    }

    /// An unmapped code must still produce the plain message rather than a
    /// half-finished sentence with an empty explanation attached.
    #[test]
    fn an_unknown_spawn_failure_is_left_as_the_os_reported_it() {
        let err = std::io::Error::from_raw_os_error(1450);
        let message = describe_spawn_failure("dism.exe", &err);

        assert!(message.starts_with("Failed to spawn command 'dism.exe':"));
        assert!(!message.contains('['));
    }

    #[test]
    fn ps_quoting_wraps_a_plain_value() {
        assert_eq!(ps_single_quoted("Spooler"), "'Spooler'");
        assert_eq!(ps_single_quoted(""), "''");
        assert_eq!(
            ps_single_quoted(r"C:\Program Files\App"),
            r"'C:\Program Files\App'"
        );
    }

    #[test]
    fn ps_quoting_neutralises_a_quote_break_out() {
        // The classic escape: close the string, run something, reopen it.
        let hostile = "x'; Remove-Item -Recurse -Force C:\\Windows; '";
        let quoted = ps_single_quoted(hostile);

        // Every embedded quote is doubled, so the literal never terminates
        // early and the payload stays data.
        assert_eq!(quoted, "'x''; Remove-Item -Recurse -Force C:\\Windows; '''");
        // A well-formed single-quoted literal has an even number of quote
        // characters; an early termination would make it odd.
        assert_eq!(quoted.matches('\'').count() % 2, 0);
    }

    #[test]
    fn ps_quoting_leaves_interpolation_syntax_inert() {
        // `'` is the only metacharacter inside a single-quoted string, so
        // everything below must survive byte for byte rather than being
        // mangled — and, once quoted, is data rather than code to PowerShell.
        for payload in [
            "$(whoami)",
            "$env:USERNAME",
            "`n`r`t",
            "@(Get-Process)",
            "; shutdown /r /t 0",
            "| Out-File C:\\pwned.txt",
            "&{Get-Content C:\\secret}",
            "%TEMP%",
            "\u{202e}gnp.exe",
        ] {
            let quoted = ps_single_quoted(payload);
            assert_eq!(quoted, format!("'{}'", payload), "mangled: {}", payload);
            assert_eq!(quoted.matches('\'').count(), 2, "unbalanced: {}", payload);
        }
    }

    #[test]
    fn ps_quoting_handles_interpolation_that_also_contains_quotes() {
        // The interesting case: a payload combining both a subexpression and
        // the one character that could end the literal early.
        let quoted = ps_single_quoted("$(Invoke-Expression 'calc')");
        assert_eq!(quoted, "'$(Invoke-Expression ''calc'')'");
        // The subexpression is preserved as text...
        assert!(quoted.contains("$(Invoke-Expression"));
        // ...and no lone quote survives to terminate the literal.
        assert_eq!(quoted.matches('\'').count() % 2, 0);
    }

    #[test]
    fn ps_quoting_survives_a_round_trip_through_the_helper() {
        // Quoting an already-quoted value must stay balanced rather than
        // producing a literal that ends in the middle.
        let once = ps_single_quoted("O'Brien");
        let twice = ps_single_quoted(&once);
        assert_eq!(once, "'O''Brien'");
        assert_eq!(twice, "'''O''''Brien'''");
        assert_eq!(twice.matches('\'').count() % 2, 0);
    }
}
