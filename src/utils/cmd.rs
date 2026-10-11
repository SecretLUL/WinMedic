use crate::utils::decode::{CodePage, LineDecoder, decode_output_in};
use crate::utils::job::Job;
use crate::utils::pnp::PnpDevice;
use std::io::{PipeReader, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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

    /// Every device connected now, with the problem code Device Manager
    /// shows. Only the real runner asks Windows; any other knows no devices
    /// unless a test gives it some.
    async fn connected_devices(&self) -> Result<Vec<PnpDevice>, String> {
        Ok(Vec::new())
    }

    /// Waits until the PowerShell calls asked for so far have finished, for a
    /// command that keeps the disk busy for minutes.
    ///
    /// Started next to them, `DISM /AnalyzeComponentStore` made other
    /// modules' PowerShell calls time out twice over on CI runners: it reads
    /// the component store in small pieces, and the disk's latency went from
    /// 3 ms to 52 ms on average while CPU stayed at a few percent. Only the
    /// real runner waits.
    async fn after_pending_powershell(&self) {}

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

/// Waits until all `count` slots are free at once. The semaphore is fair: this
/// queues behind the calls that asked before it, and the ones that ask later
/// wait only for the moment it holds every slot.
async fn after_every_slot(slots: &tokio::sync::Semaphore, count: usize) {
    let _ = slots.acquire_many(count as u32).await;
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

    async fn after_pending_powershell(&self) {
        after_every_slot(powershell_slots(), POWERSHELL_SLOTS).await;
    }

    async fn connected_devices(&self) -> Result<Vec<PnpDevice>, String> {
        tokio::task::spawn_blocking(crate::utils::pnp::connected_devices)
            .await
            .map_err(|e| format!("The device list could not be read: {e}"))?
    }
}

/// Mock runner allowing tests to inject canned command outputs and verify executed commands.
#[derive(Default, Clone)]
pub struct MockCommandRunner {
    responses: Arc<Mutex<Vec<(String, CmdOutput)>>>,
    /// `(trigger, match_substring, output)`, see [`Self::add_response_after`].
    responses_after: Arc<Mutex<Vec<(String, String, CmdOutput)>>>,
    default_response: Arc<Mutex<Option<CmdOutput>>>,
    executed_commands: Arc<Mutex<Vec<String>>>,
    devices: Arc<Mutex<Vec<PnpDevice>>>,
    devices_after: Arc<Mutex<Vec<DevicesAfter>>>,
    written_files: Arc<Mutex<Vec<WrittenFile>>>,
}

/// `(trigger, devices)`, see [`MockCommandRunner::set_devices_after`].
type DevicesAfter = (String, Vec<PnpDevice>);

/// `(match_substring, argument, bytes)`, see
/// [`MockCommandRunner::add_written_file`].
type WrittenFile = (String, usize, Vec<u8>);

impl MockCommandRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default_success() -> Self {
        let mock = Self::default();
        *mock.default_response.lock().unwrap() = Some(CmdOutput::ok(""));
        mock
    }

    /// Register a mock response for commands matching `match_substring`.
    pub fn add_response(&self, match_substring: impl Into<String>, output: CmdOutput) {
        self.responses
            .lock()
            .unwrap()
            .push((match_substring.into(), output));
    }

    /// Like [`Self::add_response`], but only once a command matching
    /// `trigger` has run - the state a repair leaves behind, which is what
    /// its read-back has to see. Takes precedence over `add_response`.
    pub fn add_response_after(
        &self,
        trigger: impl Into<String>,
        match_substring: impl Into<String>,
        output: CmdOutput,
    ) {
        self.responses_after
            .lock()
            .unwrap()
            .push((trigger.into(), match_substring.into(), output));
    }

    /// What [`Self::executed`] lists where a module waited in
    /// [`CommandRunner::after_pending_powershell`].
    pub const WAITED_FOR_POWERSHELL: &'static str = "(waited for the pending PowerShell calls)";

    /// Retrieve all executed command strings.
    pub fn executed(&self) -> Vec<String> {
        self.executed_commands.lock().unwrap().clone()
    }

    /// The devices [`CommandRunner::connected_devices`] answers with.
    pub fn set_devices(&self, devices: Vec<PnpDevice>) {
        *self.devices.lock().unwrap() = devices;
    }

    /// Like [`Self::set_devices`], but only once a command matching `trigger`
    /// has run. Takes precedence over `set_devices`.
    pub fn set_devices_after(&self, trigger: impl Into<String>, devices: Vec<PnpDevice>) {
        self.devices_after
            .lock()
            .unwrap()
            .push((trigger.into(), devices));
    }

    /// For a command that writes a file, such as `reg export`: whenever a
    /// command matching `match_substring` runs, `bytes` are written to the
    /// file its argument number `argument` names. What it answers is set
    /// with [`Self::add_response`] as for any other command.
    pub fn add_written_file(
        &self,
        match_substring: impl Into<String>,
        argument: usize,
        bytes: impl Into<Vec<u8>>,
    ) {
        self.written_files
            .lock()
            .unwrap()
            .push((match_substring.into(), argument, bytes.into()));
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
        let matches = |pattern: &str| full_cmd.contains(pattern) || program.contains(pattern);

        let mut executed = self.executed_commands.lock().unwrap();
        let after = self
            .responses_after
            .lock()
            .unwrap()
            .iter()
            .find(|(trigger, pattern, _)| {
                matches(pattern) && executed.iter().any(|done| done.contains(trigger.as_str()))
            })
            .map(|(_, _, output)| output.clone());
        executed.push(full_cmd.clone());
        drop(executed);
        for (pattern, argument, bytes) in self.written_files.lock().unwrap().iter() {
            if let Some(path) = args.get(*argument).filter(|_| matches(pattern)) {
                std::fs::write(path, bytes).map_err(|e| format!("{path}: {e}"))?;
            }
        }
        if let Some(output) = after {
            return Ok(output);
        }

        let responses = self.responses.lock().unwrap();
        for (pattern, output) in responses.iter() {
            if matches(pattern) {
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

    async fn after_pending_powershell(&self) {
        self.executed_commands
            .lock()
            .unwrap()
            .push(Self::WAITED_FOR_POWERSHELL.to_string());
    }

    async fn connected_devices(&self) -> Result<Vec<PnpDevice>, String> {
        let executed = self.executed_commands.lock().unwrap();
        let after = self
            .devices_after
            .lock()
            .unwrap()
            .iter()
            .find(|(trigger, _)| executed.iter().any(|done| done.contains(trigger.as_str())))
            .map(|(_, devices)| devices.clone());
        Ok(after.unwrap_or_else(|| self.devices.lock().unwrap().clone()))
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
            likely_causes: &["WinMedic was started without Administrator rights"],
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

/// The full path of a Windows tool WinMedic starts by name, such as
/// `reg.exe`, `powershell` or `explorer.exe`. A name with a folder in it is
/// taken as it is.
///
/// Given a bare name, Rust looks in the folder of the running executable
/// before System32, and winmedic.exe usually sits in Downloads or in WinGet's
/// package folder under %LOCALAPPDATA%, both writable without Administrator
/// rights: a `reg.exe` put next to it would run in the elevated WinMedic
/// process. So every tool is started from the Windows folders, as Windows
/// reports them, never as the environment (`%SystemRoot%`, `PATH`) says.
pub fn system_program(program: &str) -> Result<PathBuf, String> {
    if program.contains(['\\', '/']) {
        return Ok(PathBuf::from(program));
    }
    let file = if Path::new(program).extension().is_some() {
        program.to_string()
    } else {
        format!("{program}.exe")
    };
    let folder = |dir: Option<&'static Path>| {
        dir.ok_or_else(|| {
            format!("'{program}' was not started: Windows did not say where its system folder is")
        })
    };
    Ok(match file.to_ascii_lowercase().as_str() {
        "powershell.exe" => folder(system_dir())?.join(r"WindowsPowerShell\v1.0\powershell.exe"),
        "winmgmt.exe" => folder(system_dir())?.join(r"wbem\winmgmt.exe"),
        "explorer.exe" => folder(windows_dir())?.join(file),
        _ => folder(system_dir())?.join(file),
    })
}

/// System32, from `GetSystemDirectoryW`.
fn system_dir() -> Option<&'static Path> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    #[cfg(windows)]
    let dir = DIR.get_or_init(|| {
        windows_folder(windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW)
    });
    #[cfg(not(windows))]
    let dir = DIR.get_or_init(|| None);
    dir.as_deref()
}

/// The Windows folder, from `GetSystemWindowsDirectoryW`, which unlike
/// `GetWindowsDirectoryW` is the shared one on a terminal server too.
fn windows_dir() -> Option<&'static Path> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    #[cfg(windows)]
    let dir = DIR.get_or_init(|| {
        windows_folder(windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW)
    });
    #[cfg(not(windows))]
    let dir = DIR.get_or_init(|| None);
    dir.as_deref()
}

/// Ask one of the `Get...DirectoryW` functions for its folder. They return
/// the length without the terminating null, or the size needed with it when
/// the buffer was too small, or 0 on failure.
#[cfg(windows)]
fn windows_folder(get: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;

    let mut buffer = vec![0u16; 260];
    loop {
        let len = unsafe { get(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if len == 0 {
            return None;
        }
        if len < buffer.len() {
            buffer.truncate(len);
            return Some(PathBuf::from(std::ffi::OsString::from_wide(&buffer)));
        }
        buffer.resize(len, 0);
    }
}

/// How long the output readers get to finish once the process has exited.
///
/// They end when the pipes close, and a process the command started can hold
/// them open after the command itself has ended: waiting for the readers
/// without a limit then waited for that process, however long it ran. The
/// command's own output is in the pipe by the time it exits, so reading the
/// rest takes milliseconds; whatever arrived by the limit is kept.
const PIPE_DRAIN_LIMIT: Duration = Duration::from_secs(10);

/// Wait up to `limit` ([`PIPE_DRAIN_LIMIT`]) for both readers. A reader that
/// is still reading then goes on in the background until its pipe closes;
/// the caller takes what it has collected so far.
async fn drain_readers<T>(
    stdout: tokio::task::JoinHandle<T>,
    stderr: tokio::task::JoinHandle<T>,
    limit: Duration,
) {
    let (stop_stdout, stop_stderr) = (stdout.abort_handle(), stderr.abort_handle());
    let both = async {
        let _ = tokio::join!(stdout, stderr);
    };
    if timeout(limit, both).await.is_err() {
        stop_stdout.abort();
        stop_stderr.abort();
    }
}

/// A pipe for one of a command's outputs: the end this process reads, and the
/// end for the command to write to.
///
/// Not `Stdio::piped()`. tokio reads that on Windows with blocking reads on
/// the handle the standard library opens for overlapped I/O. Such a read
/// waits for the handle to be signalled, and when that wait ends with the
/// read still pending, the standard library ends the whole process: "fatal
/// runtime error: I/O error: operation failed to complete synchronously".
/// 0.10.0 ended so in the middle of the scan, while DISM analysed the
/// component store and wrote nothing (two minidumps of 2026-10-10). Both ends
/// of a pipe from `std::io::pipe` are synchronous: a read waits in the kernel
/// until it is done, and that abort cannot be reached.
fn output_pipe() -> Result<(PipeReader, Stdio), String> {
    let (reader, writer) =
        std::io::pipe().map_err(|e| format!("The command's output could not be piped: {e}"))?;
    Ok((reader, writer.into()))
}

/// A command started by [`start`], and the ends of its output pipes.
struct Started {
    child: tokio::process::Child,
    stdout: PipeReader,
    stderr: PipeReader,
    /// The job the command runs in, `None` when Windows gave it none.
    job: Option<Job>,
}

/// Start `program` without a window, its input empty and its output in two
/// pipes of [`output_pipe`], in a [`Job`] of its own.
fn start(program: &str, args: &[&str]) -> Result<Started, String> {
    let mut cmd = TokioCommand::new(system_program(program)?);
    cmd.args(args);
    // No command reads its input. Inherited, a command run from the command
    // line would read the terminal.
    cmd.stdin(Stdio::null());
    let (stdout, stdout_end) = output_pipe()?;
    let (stderr, stderr_end) = output_pipe()?;
    cmd.stdout(stdout_end);
    cmd.stderr(stderr_end);
    // Dropping the future (e.g. when the user cancels a running scan) must take
    // the child process with it, otherwise a DISM or chkdsk run keeps going.
    // When WinMedic ends without dropping it, the job takes it.
    cmd.kill_on_drop(true);
    // Without one the command runs as every command did before #223.
    let job = Job::new().ok();

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let suspended = if job.is_some() {
            crate::utils::job::CREATE_SUSPENDED
        } else {
            0
        };
        cmd.creation_flags(CREATE_NO_WINDOW | suspended);
    }

    let child = cmd
        .spawn()
        .map_err(|e| describe_spawn_failure(program, &e))?;
    // `cmd` still holds this process's copies of the ends the command writes
    // to, and an output does not end while one of them is open: every read
    // would wait out PIPE_DRAIN_LIMIT.
    drop(cmd);
    #[cfg(windows)]
    let job = match (job, child.raw_handle()) {
        (Some(job), Some(process)) => {
            // SAFETY: the child's handle, which lives as long as `child`.
            let process = unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(process) };
            match job.adopt(process) {
                Ok(adopted) => adopted.then_some(job),
                // Dropped, the suspended process is ended.
                Err(e) => return Err(format!("'{program}' was started but could not run: {e}")),
            }
        }
        _ => None,
    };
    Ok(Started {
        child,
        stdout,
        stderr,
        job,
    })
}

/// For a command that has ended by itself: what it left running, if anything,
/// runs on (the icon cache repair starts Explorer so), once its job is closed.
fn ended(job: &Option<Job>) {
    if let Some(job) = job {
        let _ = job.let_go();
    }
}

/// Read `pipe` to the end into `out`, a piece at a time, so that what has
/// arrived is kept when nobody waits for the rest. Blocks: for a blocking
/// thread.
fn read_into(mut pipe: PipeReader, out: &Mutex<Vec<u8>>) {
    let mut buf = [0u8; 4096];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if let Ok(mut out) = out.lock() {
                    out.extend_from_slice(&buf[..read]);
                }
            }
        }
    }
}

/// What a reader collected, taken out of its shared buffer.
fn take_collected<T: Default>(collected: &Mutex<T>) -> T {
    collected
        .lock()
        .map(|mut collected| std::mem::take(&mut *collected))
        .unwrap_or_default()
}

/// Execute a system command with timeout and return the complete output.
pub async fn run_cmd(
    program: &str,
    args: &[&str],
    timeout_duration: Duration,
) -> Result<CmdOutput, String> {
    let Started {
        mut child,
        stdout,
        stderr,
        job,
    } = start(program, args)?;

    let stdout_bytes = Arc::new(Mutex::new(Vec::new()));
    let stderr_bytes = Arc::new(Mutex::new(Vec::new()));
    let stdout_handle = {
        let sink = stdout_bytes.clone();
        tokio::task::spawn_blocking(move || read_into(stdout, &sink))
    };
    let stderr_handle = {
        let sink = stderr_bytes.clone();
        tokio::task::spawn_blocking(move || read_into(stderr, &sink))
    };

    let status_res = timeout(timeout_duration, child.wait()).await;
    match status_res {
        Ok(Ok(status)) => {
            ended(&job);
            drain_readers(stdout_handle, stderr_handle, PIPE_DRAIN_LIMIT).await;
            Ok(CmdOutput {
                success: status.success(),
                exit_code: status.code(),
                stdout: decode_output_in(&take_collected(&stdout_bytes), CodePage::of(program)),
                stderr: decode_output_in(&take_collected(&stderr_bytes), CodePage::of(program)),
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
    let Started {
        mut child,
        stdout,
        stderr,
        job,
    } = start(program, args)?;

    let stdout_lines = Arc::new(Mutex::new(Vec::new()));
    let stderr_lines = Arc::new(Mutex::new(Vec::new()));
    let stdout_handle = {
        let (tx, sink) = (log_tx.clone(), stdout_lines.clone());
        tokio::task::spawn_blocking(move || {
            forward_lines(stdout, |line| send(&tx, line), "", &sink)
        })
    };
    let stderr_handle = {
        let (tx, sink) = (log_tx, stderr_lines.clone());
        tokio::task::spawn_blocking(move || {
            forward_lines(stderr, |line| send(&tx, line), "[STDERR] ", &sink)
        })
    };

    // The readers end when the pipes close, which is when the process has
    // ended. Waiting for them before killing a process that ran out of time
    // waited for it to finish after all: a DISM run past its limit went on to
    // the end and was then reported as timed out, whatever it had achieved.
    // They are not waited for at all then, in case something the process
    // started still holds its pipes; a read goes on until they close.
    let status = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => return Err(format!("Command error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            return Err(timed_out(program, timeout_duration));
        }
    };

    ended(&job);
    drain_readers(stdout_handle, stderr_handle, PIPE_DRAIN_LIMIT).await;
    Ok(CmdOutput {
        success: status.success(),
        exit_code: status.code(),
        stdout: take_collected(&stdout_lines).join("\n"),
        stderr: take_collected(&stderr_lines).join("\n"),
    })
}

/// Read `pipe` to the end, decoding it line by line, and hand each line to
/// `send` as it arrives. Blocks: for a blocking thread.
///
/// Reads raw bytes rather than `lines()`: that reader stops at the first line
/// that is not UTF-8, and German DISM or SFC output has one within the first
/// few lines — everything after it, the verdict included, was lost.
///
/// A progress bar the tool is still redrawing goes to `send` as well, each
/// time it changes; only finished lines become the command's output.
fn forward_lines(
    mut pipe: impl Read,
    mut send: impl FnMut(String),
    prefix: &str,
    lines: &Mutex<Vec<String>>,
) {
    let mut decoder = LineDecoder::new();
    let mut buf = [0u8; 4096];
    let mut sent_progress = None;
    loop {
        let read = match pipe.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        for line in decoder.push(&buf[..read]) {
            send(format!("{prefix}{line}"));
            keep(lines, line);
            sent_progress = None;
        }
        let progress = decoder.progress();
        if progress.is_some() && progress != sent_progress {
            if let Some(text) = &progress {
                send(format!("{prefix}{text}"));
            }
            sent_progress = progress;
        }
    }
    if let Some(line) = decoder.finish() {
        send(format!("{prefix}{line}"));
        keep(lines, line);
    }
}

/// Hand a line to the log channel, if there is one. On a reader's blocking
/// thread, which waits here while the channel is full.
fn send(tx: &Option<Sender<String>>, line: String) {
    if let Some(tx) = tx {
        let _ = tx.blocking_send(line);
    }
}

/// Add a finished line to the command's output.
fn keep(lines: &Mutex<Vec<String>>, line: String) {
    if let Ok(mut lines) = lines.lock() {
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
/// leaves the single quote as the only metacharacter, and it is escaped by
/// doubling it — which is why this needs no allow-list.
///
/// PowerShell knows five single quotes, not one: besides `'` it ends a
/// single-quoted string at `‘`, `’`, `‚` and `‛` as well (see
/// [`is_ps_single_quote`]). A task called "Bob’s Backup", with the apostrophe
/// Word and most keyboards on phones type, closed the literal early. All five
/// are doubled, as PowerShell's own
/// `CodeGeneration.EscapeSingleQuotedStringContent` does.
///
/// This protects a *value*. It does not make an arbitrary script safe: command
/// names, parameter names and script structure must always be literals in the
/// source, never assembled from external input.
pub fn ps_single_quoted(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if is_ps_single_quote(c) {
            quoted.push(c);
        }
        quoted.push(c);
    }
    quoted.push('\'');
    quoted
}

/// Whether PowerShell's tokenizer treats `c` as a single quote: the ASCII
/// apostrophe and the four typographic ones (`CharExtensions.IsSingleQuote`).
pub fn is_ps_single_quote(c: char) -> bool {
    matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}')
}

/// How many syntax errors PowerShell's parser finds in `script`, which it
/// only parses, never runs. For the tests of scripts that change the
/// machine and so cannot be run by a test.
#[cfg(test)]
pub(crate) async fn powershell_parse_errors(script: &str) -> usize {
    let check = format!(
        "$errors = $null; [void][System.Management.Automation.Language.Parser]::ParseInput({}, [ref]$null, [ref]$errors); $errors.Count",
        ps_single_quoted(script)
    );
    let out = run_powershell(&check, Duration::from_secs(60))
        .await
        .expect("PowerShell starts");
    out.stdout.trim().parse().expect("a count")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    #[tokio::test]
    async fn the_parse_check_finds_a_broken_script() {
        assert_eq!(powershell_parse_errors("Get-Date; '{0}' -f 1").await, 0);
        assert!(powershell_parse_errors("foreach ($x in @(1) { $x").await > 0);
    }

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

    #[tokio::test]
    async fn the_mock_answers_a_read_back_with_the_repaired_state() {
        let mock = MockCommandRunner::new();
        mock.add_response("query", CmdOutput::ok("broken"));
        mock.add_response("repair", CmdOutput::ok("done"));
        mock.add_response_after("repair", "query", CmdOutput::ok("healthy"));
        let run = |args: &'static [&'static str]| {
            let mock = mock.clone();
            async move {
                mock.run("tool.exe", args, Duration::from_secs(1))
                    .await
                    .unwrap()
                    .stdout
            }
        };

        assert_eq!(run(&["query"]).await, "broken");
        assert_eq!(run(&["repair"]).await, "done");
        assert_eq!(run(&["query"]).await, "healthy");
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

    /// SFC's progress reaches the log while its one progress line is still
    /// being written, and only the finished line becomes its output.
    #[test]
    fn sfc_progress_is_forwarded_before_its_line_ends() {
        let captured: &[u8] =
            include_bytes!("../../tests/fixtures/console/sfc_verifyonly_progress_de.bin");
        let mut forwarded = Vec::new();
        let lines = Mutex::new(Vec::new());
        forward_lines(captured, |line| forwarded.push(line), "", &lines);
        let lines = lines.into_inner().unwrap();

        let done = forwarded
            .iter()
            .position(|l| l == "Überprüfung 100 % abgeschlossen.")
            .expect("the finished line is forwarded");
        assert!(done >= 3, "progress before the end: {forwarded:?}");
        assert_eq!(lines.iter().filter(|l| l.contains('%')).count(), 1);
    }

    /// ping writes a line a second for half a minute, so its pipe stays open
    /// long past the limit. Loopback only, no window.
    #[tokio::test]
    async fn a_streamed_command_is_stopped_when_its_time_is_up() {
        let started = std::time::Instant::now();
        let result = run_cmd_streaming(
            "ping.exe",
            &["-n", "30", "127.0.0.1"],
            None,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err_and(|err| is_timeout(&err)));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "returned after {:?}",
            started.elapsed()
        );
    }

    /// cmd ends at once, but the ping it starts inherits the pipes and holds
    /// them for twenty seconds. Loopback only, no window.
    #[tokio::test]
    async fn a_process_left_holding_the_pipes_does_not_hold_up_the_command() {
        let started = std::time::Instant::now();
        let out = run_cmd(
            "cmd.exe",
            &["/c", "echo verdict& start /b ping -n 20 127.0.0.1 >nul"],
            Duration::from_secs(60),
        )
        .await
        .expect("cmd starts");
        assert_eq!(out.stdout.trim(), "verdict");
        assert!(
            started.elapsed() < PIPE_DRAIN_LIMIT + Duration::from_secs(7),
            "returned after {:?}",
            started.elapsed()
        );
    }

    /// A reader whose pipe stays open is not waited for past the limit, and
    /// what it read until then is kept. It reads on a blocking thread, as the
    /// real ones do, and cannot be stopped there.
    #[tokio::test]
    async fn a_reader_held_open_is_left_behind_with_what_it_read() {
        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink = collected.clone();
        let (release, held_open) = std::sync::mpsc::channel::<()>();
        let held = tokio::task::spawn_blocking(move || {
            sink.lock().unwrap().extend_from_slice(b"verdict");
            let _ = held_open.recv();
        });
        let finished = tokio::task::spawn_blocking(|| {});

        let started = std::time::Instant::now();
        drain_readers(held, finished, Duration::from_millis(200)).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(take_collected(&collected), b"verdict");
        release.send(()).expect("the reader is still there");
    }

    /// A command's output ends with the command. Were this process to keep
    /// its copies of the ends the command writes to, every read would wait
    /// out PIPE_DRAIN_LIMIT. No window.
    #[test]
    fn a_command_is_read_to_its_end_as_soon_as_it_ends() {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let started = std::time::Instant::now();
        let out = runtime.block_on(run_cmd(
            "cmd.exe",
            &["/c", "echo verdict& echo trouble 1>&2"],
            Duration::from_secs(30),
        ));
        // A dropped runtime waits for its blocking threads, and a reader of a
        // pipe that never ends would hold up the test instead of failing it.
        runtime.shutdown_background();
        let out = out.expect("cmd starts");
        assert_eq!(out.stdout.trim(), "verdict");
        assert_eq!(out.stderr.trim(), "trouble");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "returned after {:?}",
            started.elapsed()
        );
    }

    /// Each line a streamed command writes reaches the log, sent from the
    /// thread that read it, and becomes its output. No window.
    #[tokio::test]
    async fn a_streamed_command_hands_its_lines_to_the_log() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
        let out = run_cmd_streaming(
            "cmd.exe",
            &["/c", "echo one& echo two& (echo trouble) 1>&2"],
            Some(tx),
            Duration::from_secs(30),
        )
        .await
        .expect("cmd starts");
        let mut logged = Vec::new();
        while let Ok(line) = rx.try_recv() {
            logged.push(line);
        }
        logged.sort();
        assert_eq!(logged, ["[STDERR] trouble", "one", "two"]);
        assert_eq!(out.stdout, "one\ntwo");
        assert_eq!(out.stderr, "trouble");
    }

    /// Turns the test binary into [`starts_a_ping_and_waits`] and names the
    /// file it writes the ping's process id to.
    const PING_REPORT: &str = "WINMEDIC_PING_REPORT";

    /// A handle to process `pid`, to wait for it and to end it.
    fn open_process(pid: u32) -> OwnedHandle {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };
        // SAFETY: takes plain values; the handle it returns is owned below.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, 0, pid) };
        assert!(
            !handle.is_null(),
            "process {pid}: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: a handle just opened, owned by nothing else.
        unsafe { OwnedHandle::from_raw_handle(handle) }
    }

    /// Whether `process` has ended or ends within `limit`.
    fn ends_within(process: &OwnedHandle, limit: Duration) -> bool {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: waits on a live handle of this process.
        let waited =
            unsafe { WaitForSingleObject(process.as_raw_handle(), limit.as_millis() as u32) };
        waited == WAIT_OBJECT_0
    }

    /// Ends `process`, for a test that leaves one behind when it fails.
    fn end(process: &OwnedHandle) {
        // SAFETY: ends a process this test started, through a live handle.
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(process.as_raw_handle(), 1)
        };
    }

    /// A command ends with WinMedic, however WinMedic ends. Ended by an abort
    /// (a release build panics so) or in Task Manager, WinMedic drops
    /// nothing, and the DISM runs of the scans 0.10.0 crashed in ran on for
    /// hours (#223). The test binary starts itself as
    /// [`starts_a_ping_and_waits`], which starts a ping as WinMedic starts a
    /// command, and ends it with `TerminateProcess`, as Task Manager does.
    /// Loopback only, no window.
    #[test]
    fn a_command_ends_with_the_process_that_started_it() {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let report = std::env::temp_dir().join(format!("winmedic_ping_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&report);
        // libtest names a test by its path inside the crate.
        let (_, module) = module_path!().split_once("::").expect("a crate path");
        let mut waiter =
            std::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args([
                    "--exact",
                    &format!("{module}::starts_a_ping_and_waits"),
                    "--ignored",
                    "--test-threads=1",
                    "-q",
                ])
                .env(PING_REPORT, &report)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .expect("the test binary starts");

        let asked = std::time::Instant::now();
        let pid = loop {
            let named = std::fs::read_to_string(&report).ok();
            if let Some(pid) = named.and_then(|pid| pid.trim().parse::<u32>().ok()) {
                break pid;
            }
            if asked.elapsed() > Duration::from_secs(60) {
                let _ = waiter.kill();
                panic!("the ping was not started");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let _ = std::fs::remove_file(&report);
        let ping = open_process(pid);

        waiter.kill().expect("the test binary is ended");
        let _ = waiter.wait();

        let ended = ends_within(&ping, Duration::from_secs(10));
        if !ended {
            end(&ping);
        }
        assert!(ended, "the ping outlived the process that started it");
    }

    /// The child half of [`a_command_ends_with_the_process_that_started_it`]:
    /// starts a ping as WinMedic starts a command, names it and waits to be
    /// ended. Does nothing unless that test started it.
    #[test]
    #[ignore = "started by a_command_ends_with_the_process_that_started_it"]
    fn starts_a_ping_and_waits() {
        let Some(report) = std::env::var_os(PING_REPORT).map(PathBuf::from) else {
            return;
        };
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let _runtime = runtime.enter();
        let started = start("ping.exe", &["-n", "60", "127.0.0.1"]).expect("ping starts");
        let pid = started.child.id().expect("the ping runs");
        // Named in one step: the test reads the file while it waits.
        let named = report.with_extension("tmp");
        std::fs::write(&named, pid.to_string()).expect("the report is written");
        std::fs::rename(&named, &report).expect("the report is named");
        std::thread::sleep(Duration::from_secs(60));
        drop(started);
    }

    /// Where PowerShell writes the process id of the ping it starts.
    fn ping_report(test: &str, streamed: bool) -> PathBuf {
        std::env::temp_dir().join(format!(
            "winmedic_{test}_{}_{streamed}.txt",
            std::process::id()
        ))
    }

    /// PowerShell starts a ping that runs `seconds`, writes its process id to
    /// `report` and waits `then` seconds before it ends.
    fn ping_script(report: &Path, seconds: u32, then: u32) -> String {
        format!(
            "(Start-Process ping.exe -ArgumentList '-n {seconds} 127.0.0.1' -NoNewWindow -PassThru).Id | Set-Content -LiteralPath {}; Start-Sleep -Seconds {then}",
            ps_single_quoted(&report.to_string_lossy())
        )
    }

    /// `script` in PowerShell, through [`run_cmd`] or [`run_cmd_streaming`].
    fn powershell_through(
        streamed: bool,
        script: String,
        limit: Duration,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<CmdOutput, String>>>> {
        Box::pin(async move {
            let args = ["-NoProfile", "-NonInteractive", "-Command", &script];
            if streamed {
                run_cmd_streaming("powershell", &args, None, limit).await
            } else {
                run_cmd("powershell", &args, limit).await
            }
        })
    }

    /// The process `report` names, opened while it runs, once PowerShell has
    /// written the file.
    async fn process_named_in(report: &Path) -> OwnedHandle {
        let asked = std::time::Instant::now();
        loop {
            let named = std::fs::read_to_string(report).ok();
            if let Some(pid) = named.and_then(|pid| pid.trim().parse().ok()) {
                let _ = std::fs::remove_file(report);
                return open_process(pid);
            }
            assert!(
                asked.elapsed() < Duration::from_secs(60),
                "PowerShell named no ping"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// What a command that has ended by itself left running runs on: the icon
    /// cache repair starts Explorer again so. The ping holds the pipes, so
    /// each run waits out PIPE_DRAIN_LIMIT. Loopback only, no window.
    #[tokio::test]
    async fn what_a_command_left_running_runs_on() {
        let left_running = |streamed| async move {
            let report = ping_report("left_running", streamed);
            let run = powershell_through(
                streamed,
                ping_script(&report, 30, 0),
                Duration::from_secs(60),
            );
            tokio::join!(run, process_named_in(&report))
        };
        let (plain, streamed) = tokio::join!(left_running(false), left_running(true));
        // Windows ends the processes of a closed job a moment after the close.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let ran_on = [&plain.1, &streamed.1].map(|ping| !ends_within(ping, Duration::ZERO));
        end(&plain.1);
        end(&streamed.1);
        assert!(plain.0.is_ok_and(|out| out.success), "PowerShell ran");
        assert!(streamed.0.is_ok_and(|out| out.success), "PowerShell ran");
        assert_eq!(ran_on, [true, true], "plain and streamed: the ping ran on");
    }

    /// A command dropped while it runs, as a cancelled scan drops it, ends with
    /// what it started: here a ping, for DISM its DismHost. One that runs out
    /// of time ends the same way. Loopback only, no window.
    #[tokio::test]
    async fn a_cancelled_command_ends_with_what_it_started() {
        let cancelled = |streamed| async move {
            let report = ping_report("cancelled", streamed);
            let mut run = powershell_through(
                streamed,
                ping_script(&report, 60, 60),
                Duration::from_secs(90),
            );
            let ping = tokio::select! {
                ping = process_named_in(&report) => ping,
                out = &mut run => panic!("PowerShell ended first: {out:?}"),
            };
            drop(run);
            ping
        };
        let (plain, streamed) = tokio::join!(cancelled(false), cancelled(true));
        let ended = [&plain, &streamed].map(|ping| ends_within(ping, Duration::from_secs(10)));
        end(&plain);
        end(&streamed);
        assert_eq!(
            ended,
            [true, true],
            "plain and streamed: the ping ended with the command"
        );
    }

    /// Whether the kernel opened `handle` for synchronous I/O.
    fn is_synchronous(handle: std::os::windows::io::RawHandle) -> bool {
        #[link(name = "ntdll", kind = "raw-dylib")]
        unsafe extern "system" {
            fn NtQueryInformationFile(
                file: *mut std::ffi::c_void,
                io_status: *mut [usize; 2],
                information: *mut std::ffi::c_void,
                length: u32,
                class: i32,
            ) -> i32;
        }
        const FILE_MODE_INFORMATION: i32 = 16;
        const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
        const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;

        let mut io_status = [0usize; 2];
        let mut mode = 0u32;
        // SAFETY: queries a live handle of this process into locals of the
        // sizes passed.
        let status = unsafe {
            NtQueryInformationFile(
                handle.cast(),
                &mut io_status,
                (&raw mut mode).cast(),
                size_of::<u32>() as u32,
                FILE_MODE_INFORMATION,
            )
        };
        assert!(status >= 0, "NtQueryInformationFile: {status:#x}");
        mode & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0
    }

    /// 0.10.0 ended itself during the scan, with "fatal runtime error: I/O
    /// error: operation failed to complete synchronously" (two minidumps of
    /// 2026-10-10). It read DISM's output through the overlapped handle that
    /// `Stdio::piped()` leaves this process, and the wait for one read ended
    /// before the read. A command's output now comes through a pipe that is
    /// synchronous at this end, where a read waits in the kernel until it is
    /// done. cmd ends at once; no window.
    #[test]
    fn a_commands_output_is_read_through_a_synchronous_handle() {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let (reader, _writer) = output_pipe().expect("a pipe");
        assert!(is_synchronous(reader.as_raw_handle()));

        // What 0.10.0 read through.
        let mut child = std::process::Command::new(system_program("cmd.exe").unwrap())
            .args(["/c", "exit"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .expect("cmd starts");
        let piped = child.stdout.take().expect("a piped output");
        assert!(!is_synchronous(piped.as_raw_handle()));
        child.wait().expect("cmd ends");
    }

    #[test]
    fn system_tools_are_started_by_their_full_path() {
        let system32 = system_dir().expect("Windows names its system folder");
        assert!(system32.is_absolute());
        assert_eq!(system_program("reg.exe").unwrap(), system32.join("reg.exe"));
        assert_eq!(system_program("reg").unwrap(), system32.join("reg.exe"));
        assert_eq!(
            system_program("powershell").unwrap(),
            system32.join(r"WindowsPowerShell\v1.0\powershell.exe")
        );
        assert_eq!(
            system_program("WINMGMT.EXE").unwrap(),
            system32.join(r"wbem\winmgmt.exe")
        );
        let windows = windows_dir().expect("Windows names its own folder");
        assert_eq!(
            system_program("explorer.exe").unwrap(),
            windows.join("explorer.exe")
        );
        // A path is the caller's choice: the updater starts the new winmedic.exe.
        assert_eq!(
            system_program(r"C:\Tools\winmedic.exe").unwrap(),
            PathBuf::from(r"C:\Tools\winmedic.exe")
        );
    }

    /// The tools that live outside System32 itself are where this Windows
    /// keeps them. Only looks, starts nothing.
    #[test]
    fn the_tools_are_where_they_are_started_from() {
        for tool in [
            "powershell",
            "winmgmt.exe",
            "explorer.exe",
            "reg.exe",
            "sc.exe",
        ] {
            let path = system_program(tool).unwrap();
            assert!(path.is_file(), "{tool}: no {}", path.display());
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

    #[tokio::test]
    async fn a_heavy_command_waits_for_the_powershell_calls_before_it() {
        let slots = tokio::sync::Semaphore::new(4);
        let running = slots.acquire().await.unwrap();
        let heavy = after_every_slot(&slots, 4);
        tokio::pin!(heavy);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut heavy)
                .await
                .is_err(),
            "it waits while a call runs"
        );
        assert!(
            slots.try_acquire().is_err(),
            "a call asked for after it waits behind it"
        );
        drop(running);
        tokio::time::timeout(Duration::from_secs(5), heavy)
            .await
            .expect("it goes once the call has ended");
        assert_eq!(slots.available_permits(), 4, "and keeps no slot");
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

    /// Reads a single-quoted literal off the front of `script` the way
    /// PowerShell's tokenizer does (`Tokenizer.ScanStringLiteral`): any of the
    /// five quotes opens and closes it, and two of them in a row stand for the
    /// second one. Returns the value and what follows the literal.
    fn scan_ps_literal(script: &str) -> Option<(String, &str)> {
        let mut chars = script.char_indices().peekable();
        let (_, open) = chars.next()?;
        if !is_ps_single_quote(open) {
            return None;
        }
        let mut value = String::new();
        while let Some((at, c)) = chars.next() {
            if is_ps_single_quote(c) {
                match chars.peek() {
                    Some(&(_, next)) if is_ps_single_quote(next) => {
                        value.push(next);
                        chars.next();
                        continue;
                    }
                    _ => return Some((value, &script[at + c.len_utf8()..])),
                }
            }
            value.push(c);
        }
        None
    }

    #[test]
    fn ps_quoting_doubles_every_quote_powershell_knows() {
        for quote in ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
            let value = format!("Bob{quote}s Backup{quote}; Remove-Item C:\\x; {quote}");
            let quoted = ps_single_quoted(&value);
            assert_eq!(
                quoted,
                format!(
                    "'Bob{quote}{quote}s Backup{quote}{quote}; Remove-Item C:\\x; {quote}{quote}'"
                ),
                "U+{:04X}",
                quote as u32
            );
            assert_eq!(
                scan_ps_literal(&quoted),
                Some((value.clone(), "")),
                "the literal must end exactly where the quoting ends (U+{:04X})",
                quote as u32
            );
        }
    }

    #[test]
    fn a_typographic_apostrophe_no_longer_ends_the_literal() {
        // What the old helper made of it: the literal closed after "Bob".
        let old = format!("'{}'", "Bob\u{2019}s Backup".replace('\'', "''"));
        assert_eq!(
            scan_ps_literal(&old),
            Some(("Bob".to_string(), "s Backup'"))
        );

        let quoted = ps_single_quoted("Bob\u{2019}s Backup");
        assert_eq!(
            scan_ps_literal(&quoted),
            Some(("Bob\u{2019}s Backup".to_string(), ""))
        );
        assert!(!is_ps_single_quote('"'));
        assert!(!is_ps_single_quote('`'));
    }

    /// PowerShell itself reads every quoted value back unchanged, whichever
    /// quotes it holds.
    #[tokio::test]
    async fn powershell_reads_a_quoted_value_back_unchanged() {
        let value = "Bob's \u{2018}Backup\u{2019} \u{201A}x\u{201B} $(Get-Date) `n";
        let script = format!("[Console]::Out.Write({})", ps_single_quoted(value));
        let out = run_powershell(&script, Duration::from_secs(60))
            .await
            .expect("PowerShell starts");
        assert_eq!(out.stdout, value);
        assert_eq!(powershell_parse_errors(&script).await, 0);
    }
}
