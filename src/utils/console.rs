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
/// Returns whether the console was actually released.
#[cfg(windows)]
pub fn release_console_if_owned() -> bool {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};

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
    unsafe { FreeConsole() != FALSE }
}

#[cfg(not(windows))]
pub fn release_console_if_owned() -> bool {
    false
}
