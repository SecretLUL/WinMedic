//! The crash log WinMedic leaves behind when it panics (#224).
//!
//! The window gives its console back as it starts and sets the standard
//! handles to null (`utils::console`), so what Rust prints on the way out of a
//! panic reaches nobody. The hook here first writes down what happened, next
//! to the audit log: the version and the Windows build, what WinMedic was
//! doing, the message and where it was raised, and the stack.
//!
//! Only `main` installs the hook. A test that did would write into the real
//! log folder whenever another test provokes a panic, so what the hook writes
//! is put together by [`Report`], which the tests build from plain values.

use chrono::{DateTime, FixedOffset};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// How many crash logs are kept: writing a sixth deletes the oldest.
pub const KEEP: usize = 5;

/// `crash-20261012-224107-1234-1.log`: the time, the process, and which of
/// its panics. The names sort by time.
const FILE_PREFIX: &str = "crash-";
const FILE_SUFFIX: &str = ".log";

/// The panics of this process so far. Two can come within a second, as a
/// repair's and then the window's did in a test of the release build, and the
/// second log must not take the first one's name.
static PANICS: AtomicU32 = AtomicU32::new(0);

/// Room to spare: a panicking check's stack in the release build is under
/// twenty frames deep.
const MAX_FRAMES: usize = 128;

tokio::task_local! {
    static RUNNING: Running;
}

/// The check or repair a task runs, and the step it last reported: what a
/// crash log names as running. The engine sets it around each check and
/// repair.
#[derive(Clone, Debug)]
pub struct Running {
    what: Arc<str>,
    step: Arc<Mutex<String>>,
}

impl Running {
    pub fn new(what: impl Into<String>) -> Self {
        Self {
            what: what.into().into(),
            step: Arc::default(),
        }
    }

    /// Note the step a progress report names.
    pub fn set_step(&self, step: &str) {
        if let Ok(mut current) = self.step.lock() {
            current.clear();
            current.push_str(step);
        }
    }

    /// Run `future` as this check or repair.
    pub async fn scope<F: Future>(self, future: F) -> F::Output {
        RUNNING.scope(self, future).await
    }

    /// Only tries the lock: a panic raised while a step is noted must not
    /// wait for itself.
    fn describe(&self) -> String {
        match self.step.try_lock() {
            Ok(step) if !step.is_empty() => format!("{}, at \"{}\"", self.what, step),
            _ => self.what.to_string(),
        }
    }
}

/// What the task that panicked was running, when the engine named it.
pub fn running_now() -> Option<String> {
    RUNNING.try_with(Running::describe).ok()
}

/// What a crash log says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub time: DateTime<FixedOffset>,
    pub version: String,
    pub windows: String,
    /// How WinMedic was started: window, --scan, --auto-fix, --dry-run,
    /// helper or --uninstall.
    pub mode: String,
    pub thread: String,
    pub running: Option<String>,
    pub location: String,
    pub message: String,
    /// Each return address as the module it lies in and the offset into it.
    pub stack: Vec<String>,
}

impl Report {
    /// The file's text: one field to a line, then the message and the stack,
    /// each indented below its heading, since a message can span lines.
    pub fn render(&self) -> String {
        let mut text = format!(
            "WinMedic {} panicked\n\
             Time: {}\n\
             Windows: {}\n\
             Mode: {}\n\
             Thread: {}\n\
             Running: {}\n\
             Location: {}\n\
             \n\
             Message:\n",
            self.version,
            self.time.format("%Y-%m-%d %H:%M:%S %:z"),
            self.windows,
            self.mode,
            self.thread,
            self.running
                .as_deref()
                .unwrap_or("nothing the engine named"),
            self.location,
        );
        for line in self.message.lines() {
            text.push_str("  ");
            text.push_str(line);
            text.push('\n');
        }
        text.push_str(
            "\nStack (return addresses; scripts/resolve-crash-log.ps1 and the release's PDB resolve them):\n",
        );
        for frame in &self.stack {
            text.push_str("  ");
            text.push_str(frame);
            text.push('\n');
        }
        text
    }

    fn file_name(&self, id: &str) -> String {
        format!(
            "{FILE_PREFIX}{}-{id}{FILE_SUFFIX}",
            self.time.format("%Y%m%d-%H%M%S")
        )
    }
}

/// Have every panic leave a crash log in `dir` before Rust's own hook prints
/// it. `mode` says how WinMedic was started.
///
/// The Windows build is read now rather than in the hook, which should do as
/// little as it can while the process is in trouble.
pub fn install(dir: PathBuf, mode: &'static str) {
    let windows = windows_build();
    let rust_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let report = Report {
            time: chrono::Local::now().fixed_offset(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            windows: windows.clone(),
            mode: mode.to_string(),
            thread: std::thread::current()
                .name()
                .unwrap_or("unnamed")
                .to_string(),
            running: running_now(),
            location: info.location().map(ToString::to_string).unwrap_or_default(),
            message: info
                .payload_as_str()
                .unwrap_or("(the panic carries no text)")
                .to_string(),
            stack: stack(),
        };
        let panic = PANICS.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = write(&dir, &report, &format!("{}-{panic}", std::process::id()));
        rust_hook(info);
    }));
}

/// Write `report` into `dir` and keep the newest [`KEEP`] crash logs there.
/// `id` tells apart the logs of one second.
pub fn write(dir: &Path, report: &Report, id: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(report.file_name(id));
    std::fs::write(&path, report.render())?;
    let logs = crash_logs(dir);
    for old in &logs[..logs.len().saturating_sub(KEEP)] {
        let _ = std::fs::remove_file(old);
    }
    Ok(path)
}

/// The crash logs in `dir`, oldest first.
pub fn crash_logs(dir: &Path) -> Vec<PathBuf> {
    let mut logs: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(FILE_PREFIX) && name.ends_with(FILE_SUFFIX))
        })
        .collect();
    logs.sort();
    logs
}

/// The Windows build as the bug report form asks for it, such as "Windows 11
/// Pro 25H2, build 26200.9550".
pub fn windows_build() -> String {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    else {
        return "unknown".to_string();
    };
    let text = |name: &str| key.get_value::<String, _>(name).unwrap_or_default();
    // DisplayVersion came with 20H2; ReleaseId names the versions before it.
    let release = Some(text("DisplayVersion"))
        .filter(|release| !release.is_empty())
        .unwrap_or_else(|| text("ReleaseId"));
    describe_windows(
        &text("ProductName"),
        &release,
        &text("CurrentBuild"),
        key.get_value::<u32, _>("UBR").ok(),
    )
}

/// ProductName still says "Windows 10" on Windows 11 ("Windows 10 Pro" on the
/// development PC, 25H2): only the build tells them apart, and Windows 11
/// starts at 22000.
fn describe_windows(product: &str, release: &str, build: &str, revision: Option<u32>) -> String {
    let mut text = match build.parse::<u32>() {
        Ok(number) if number >= 22000 => product.replacen("Windows 10", "Windows 11", 1),
        _ => product.to_string(),
    };
    if !release.is_empty() {
        text.push(' ');
        text.push_str(release);
    }
    if !build.is_empty() {
        text.push_str(", build ");
        text.push_str(build);
        if let Some(revision) = revision {
            text.push_str(&format!(".{revision}"));
        }
    }
    text
}

/// The return addresses on the stack, each as the module it lies in and the
/// offset into it.
///
/// The release ships without its PDB, so no symbol name is to be had on the
/// user's PC, while an offset into winmedic.exe is the same on every PC; the
/// release workflow keeps the PDB that resolves it. File names only: the path
/// to winmedic.exe can name the user.
#[cfg(windows)]
fn stack() -> Vec<String> {
    use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;

    let mut addresses = [std::ptr::null_mut(); MAX_FRAMES];
    // SAFETY: the buffer holds MAX_FRAMES pointers, as many as are asked for,
    // and no hash is wanted.
    let captured = unsafe {
        RtlCaptureStackBackTrace(
            0,
            MAX_FRAMES as u32,
            addresses.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    addresses[..usize::from(captured)]
        .iter()
        .map(|&address| frame(address))
        .collect()
}

#[cfg(not(windows))]
fn stack() -> Vec<String> {
    Vec::new()
}

#[cfg(windows)]
fn frame(address: *mut std::ffi::c_void) -> String {
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        GetModuleFileNameW, GetModuleHandleExW,
    };

    let mut module = std::ptr::null_mut();
    // SAFETY: with FROM_ADDRESS the second argument is read as an address
    // inside a module, not as a name, and UNCHANGED_REFCOUNT takes no
    // reference that would have to be released.
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            address as *const u16,
            &mut module,
        )
    } != 0;
    if !found {
        return format!("{address:p}");
    }
    let mut path = [0u16; 1024];
    // SAFETY: the pointer and the length describe the same array; the call
    // writes at most that many characters and returns how many it wrote.
    let len = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
    let path = String::from_utf16_lossy(&path[..len.min(path.len())]);
    let name = path.rsplit('\\').next().unwrap_or_default();
    format!("{name}+{:#x}", address as usize - module as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn report() -> Report {
        Report {
            time: FixedOffset::east_opt(2 * 3600)
                .unwrap()
                .with_ymd_and_hms(2026, 10, 12, 22, 41, 7)
                .unwrap(),
            version: "0.11.0".to_string(),
            windows: "Windows 11 Pro 25H2, build 26200.9550".to_string(),
            mode: "window".to_string(),
            thread: "tokio-runtime-worker".to_string(),
            running: Some("check 'storage', at \"Scanning %TEMP%\"".to_string()),
            location: r"src\modules\storage.rs:120:9".to_string(),
            message: "assertion failed\n  left: 1\n right: 2".to_string(),
            stack: vec![
                "winmedic.exe+0x1a2b3c".to_string(),
                "ntdll.dll+0x2c1f4".to_string(),
            ],
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("winmedic_crash_log_{name}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_report_reads_one_field_to_a_line() {
        assert_eq!(
            report().render(),
            "WinMedic 0.11.0 panicked\n\
             Time: 2026-10-12 22:41:07 +02:00\n\
             Windows: Windows 11 Pro 25H2, build 26200.9550\n\
             Mode: window\n\
             Thread: tokio-runtime-worker\n\
             Running: check 'storage', at \"Scanning %TEMP%\"\n\
             Location: src\\modules\\storage.rs:120:9\n\
             \n\
             Message:\n\
             \x20 assertion failed\n\
             \x20   left: 1\n\
             \x20  right: 2\n\
             \n\
             Stack (return addresses; scripts/resolve-crash-log.ps1 and the release's PDB resolve them):\n\
             \x20 winmedic.exe+0x1a2b3c\n\
             \x20 ntdll.dll+0x2c1f4\n"
        );
    }

    #[test]
    fn a_panic_outside_the_engine_names_nothing() {
        let text = Report {
            running: None,
            ..report()
        }
        .render();
        assert!(text.contains("\nRunning: nothing the engine named\n"));
    }

    #[test]
    fn the_newest_five_crash_logs_are_kept() {
        let dir = TempDir::new("keep");
        let base = report();
        for second in 0..7 {
            let report = Report {
                time: base.time + chrono::Duration::seconds(second),
                ..base.clone()
            };
            write(&dir.0, &report, "4242-1").unwrap();
        }
        // Not a crash log: left alone.
        std::fs::write(dir.0.join("audit.log"), "x").unwrap();

        let names: Vec<String> = crash_logs(&dir.0)
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "crash-20261012-224109-4242-1.log",
                "crash-20261012-224110-4242-1.log",
                "crash-20261012-224111-4242-1.log",
                "crash-20261012-224112-4242-1.log",
                "crash-20261012-224113-4242-1.log",
            ]
        );
        assert!(dir.0.join("audit.log").exists());
        assert_eq!(
            std::fs::read_to_string(dir.0.join("crash-20261012-224113-4242-1.log")).unwrap(),
            Report {
                time: base.time + chrono::Duration::seconds(6),
                ..base
            }
            .render()
        );
    }

    /// The repair's and the window's panic of the release test came within
    /// one second; the first log was lost while the name had only the time
    /// and the process.
    #[test]
    fn two_panics_of_one_second_leave_two_logs() {
        let dir = TempDir::new("same_second");
        write(&dir.0, &report(), "4242-1").unwrap();
        write(&dir.0, &report(), "4242-2").unwrap();
        assert_eq!(crash_logs(&dir.0).len(), 2);
    }

    #[test]
    fn windows_11_is_told_from_windows_10_by_its_build() {
        // The values of the development PC.
        assert_eq!(
            describe_windows("Windows 10 Pro", "25H2", "26200", Some(9550)),
            "Windows 11 Pro 25H2, build 26200.9550"
        );
        assert_eq!(
            describe_windows("Windows 10 Pro", "22H2", "19045", Some(6456)),
            "Windows 10 Pro 22H2, build 19045.6456"
        );
        assert_eq!(
            describe_windows("Windows Server 2025 Datacenter", "24H2", "26100", None),
            "Windows Server 2025 Datacenter 24H2, build 26100"
        );
    }

    #[test]
    fn the_windows_build_is_read_from_the_registry() {
        let build = windows_build();
        assert!(build.starts_with("Windows"), "{build}");
        assert!(build.contains(", build "), "{build}");
    }

    #[tokio::test]
    async fn a_task_names_what_it_runs_and_its_last_step() {
        assert_eq!(running_now(), None);

        let running = Running::new("check 'storage'");
        let steps = running.clone();
        let named = running
            .scope(async move {
                let before = running_now();
                steps.set_step("Scanning %TEMP%");
                (before, running_now())
            })
            .await;
        assert_eq!(
            named,
            (
                Some("check 'storage'".to_string()),
                Some("check 'storage', at \"Scanning %TEMP%\"".to_string())
            )
        );
        assert_eq!(running_now(), None);
    }

    #[cfg(windows)]
    #[test]
    fn the_stack_names_modules_by_file_name_and_offset() {
        let stack = stack();
        let exe = std::env::current_exe().unwrap();
        let exe = exe.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            stack
                .iter()
                .any(|frame| frame.starts_with(&format!("{exe}+0x"))),
            "{stack:?}"
        );
        assert!(stack.iter().all(|frame| !frame.contains('\\')), "{stack:?}");
    }
}
