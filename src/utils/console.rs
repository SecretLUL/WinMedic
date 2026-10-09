//! Handing the console back when WinMedic starts as a desktop application.
//!
//! WinMedic is a single binary linked into the *console* subsystem, and that is
//! deliberate. The alternative — `#![windows_subsystem = "windows"]` — buys a
//! GUI that never flashes a console window, and pays for it by breaking every
//! headless guarantee the CLI help makes: a Windows-subsystem process does not
//! hold the shell, so `winmedic --json > report.json` returns before the file
//! is finished and the documented exit codes arrive after whatever ran next.
//! The release workflow depends on it too, capturing `winmedic.exe --version`
//! into a variable it compares against the tag.
//!
//! So the console stays and the GUI gives it back on the way up. The cost is a
//! console window visible for as long as it takes to reach `main`: a flicker
//! when WinMedic is launched from the desktop, and nothing at all when it is
//! launched from a shell — because then it was never ours to give back.

/// Release the console, but only when this process is the one that owns it.
///
/// Ownership is the whole question. A process started from Explorer gets a
/// console to itself, so closing it removes a window the user never asked for.
/// A process started from `cmd.exe`, PowerShell or Windows Terminal *shares*
/// the shell's console — freeing that one detaches WinMedic from the terminal
/// it was typed into and leaves the user at a prompt that prints nothing.
///
/// `GetConsoleProcessList` answers it directly: it reports how many processes
/// are attached to this console, and one means us and nobody else.
///
/// Freeing an owned console closes the three standard handles, but
/// `GetStdHandle` goes on returning their numbers, and Windows hands those
/// numbers out again. A child started with inherited stdio then got whatever
/// held them: "Restart now" failed with os error 50 on an ETW registration, or
/// with os error 6 on a free slot. So they are set to null, which Rust's
/// `Command` passes on as "no handle" and its `print!` treats as nowhere.
///
/// Returns whether the console was actually released.
#[cfg(windows)]
pub fn release_console_if_owned() -> bool {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::System::Console::{
        FreeConsole, GetConsoleProcessList, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        SetStdHandle,
    };

    // Two slots are enough to tell "exactly one" from "more than one": the call
    // reports the number of attached processes even when the buffer is too
    // small to list them all, and their identities are of no interest here.
    let mut attached = [0u32; 2];

    // SAFETY: the pointer and the length describe the same live array, which is
    // what the call contracts for. It writes at most `len` process ids and
    // returns the count — zero when there is no console attached at all.
    let count = unsafe { GetConsoleProcessList(attached.as_mut_ptr(), attached.len() as u32) };

    if count != 1 {
        return false;
    }

    // SAFETY: takes no arguments, and this process is attached to a console.
    if unsafe { FreeConsole() } == FALSE {
        return false;
    }
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: stores a value and dereferences nothing. Not closed first:
        // where FreeConsole closed them, their numbers may belong to
        // something else by now.
        unsafe { SetStdHandle(which, std::ptr::null_mut()) };
    }
    true
}

#[cfg(not(windows))]
pub fn release_console_if_owned() -> bool {
    false
}

/// Tell the user something went wrong when there is no console to print it to.
///
/// Once [`release_console_if_owned`] has run, `eprintln!` writes into nothing:
/// a window that fails to open would leave the user who double-clicked the exe
/// looking at a desktop where nothing happened. A message box needs no console
/// and no working graphics driver.
#[cfg(windows)]
pub fn show_error_dialog(title: &str, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (title, text) = (wide(title), wide(text));
    // SAFETY: both pointers are to NUL-terminated UTF-16 buffers that outlive
    // the call; a null owner window is allowed.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(not(windows))]
pub fn show_error_dialog(title: &str, text: &str) {
    eprintln!("{title}: {text}");
}

#[cfg(all(test, windows))]
mod tests {
    use super::release_console_if_owned;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess,
        PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
    };

    /// Turns the test binary into [`console_probe`] and names the file it
    /// writes what it found to.
    const PROBE_REPORT: &str = "WINMEDIC_CONSOLE_PROBE_REPORT";

    /// WinMedic started from Explorer owns its console. Giving it back closed
    /// the three standard handles, `GetStdHandle` went on returning their
    /// numbers, and Windows hands those numbers out again: a child started
    /// with inherited stdio got whatever held them. "Restart now" failed with
    /// os error 50 because one of them was an ETW registration.
    ///
    /// Only a process whose standard handles are its console's shows it, and
    /// `Command` cannot start one: it always passes standard handles
    /// (`STARTF_USESTDHANDLES`). So the test binary starts itself with
    /// `CreateProcessW`, in a console without a window, as [`console_probe`].
    #[test]
    fn a_released_console_leaves_no_stale_std_handles() {
        let report =
            std::env::temp_dir().join(format!("winmedic_console_probe_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&report);

        let exit_code = run_probe(&report);

        let found = std::fs::read_to_string(&report).unwrap_or_default();
        let _ = std::fs::remove_file(&report);
        assert_eq!(
            found.lines().collect::<Vec<_>>(),
            [
                "released: true",
                "stdin: 0x0",
                "stdout: 0x0",
                "stderr: 0x0",
                "ping: exit code 0",
            ],
            "the probe exited with {exit_code:?}"
        );
        // libtest printed its result after the probe, into null handles.
        assert_eq!(exit_code, Some(0));
    }

    /// The child half of [`a_released_console_leaves_no_stale_std_handles`];
    /// does nothing unless that test started it.
    #[test]
    #[ignore = "started by a_released_console_leaves_no_stale_std_handles"]
    fn console_probe() {
        let Some(report) = std::env::var_os(PROBE_REPORT) else {
            return;
        };
        let released = release_console_if_owned();
        // SAFETY: takes a constant and returns a value; nothing is dereferenced.
        let [stdin, stdout, stderr] = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
            .map(|which| unsafe { GetStdHandle(which) } as usize);
        // Inherited stdio, what `spawn` and `status` default to.
        let ping = std::process::Command::new(
            crate::utils::cmd::system_program("ping.exe").expect("System32"),
        )
        .args(["127.0.0.1", "-n", "1"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
        let ping = match ping {
            Ok(status) => match status.code() {
                Some(code) => format!("exit code {code}"),
                None => "no exit code".to_string(),
            },
            Err(e) => format!("not started: {e}"),
        };
        std::fs::write(
            report,
            format!(
                "released: {released}\nstdin: {stdin:#x}\nstdout: {stdout:#x}\nstderr: {stderr:#x}\nping: {ping}\n"
            ),
        )
        .expect("the report is written");
    }

    /// Start this test binary as [`console_probe`], in a console of its own
    /// without a window, and return its exit code.
    fn run_probe(report: &Path) -> Option<u32> {
        let exe = std::env::current_exe().expect("the test binary");
        // libtest names a test by its path inside the crate.
        let (_, module) = module_path!().split_once("::").expect("a crate path");
        let mut command_line: Vec<u16> = format!(
            "\"{}\" --exact {module}::console_probe --ignored --test-threads=1 -q",
            exe.display()
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();

        // In the child's block only: `set_var` would change it for every
        // test running in this process.
        let mut variables: Vec<(OsString, OsString)> = std::env::vars_os()
            .chain([(PROBE_REPORT.into(), report.into())])
            .collect();
        variables.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
        let mut environment: Vec<u16> = Vec::new();
        for (name, value) in &variables {
            environment.extend(name.encode_wide());
            environment.push(u16::from(b'='));
            environment.extend(value.encode_wide());
            environment.push(0);
        }
        environment.push(0);

        // No STARTF_USESTDHANDLES: the child's standard handles are its
        // console's, as for a start from Explorer.
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: the command line is a writable, NUL-terminated UTF-16
        // buffer and the environment a UTF-16 block ending in two NULs, as
        // CREATE_UNICODE_ENVIRONMENT says; both outlive the call, and the
        // structures are initialised and live for it.
        let started = unsafe {
            CreateProcessW(
                std::ptr::null(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                FALSE,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                std::ptr::null(),
                &startup,
                &mut process,
            )
        };
        assert_ne!(started, FALSE, "{}", std::io::Error::last_os_error());

        let mut exit_code = None;
        // SAFETY: both handles came from CreateProcessW above and are closed
        // once, here.
        unsafe {
            if WaitForSingleObject(process.hProcess, 60_000) == WAIT_OBJECT_0 {
                let mut code = 0;
                if GetExitCodeProcess(process.hProcess, &mut code) != FALSE {
                    exit_code = Some(code);
                }
            } else {
                TerminateProcess(process.hProcess, 1);
            }
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        exit_code
    }
}
