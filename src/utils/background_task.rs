//! Registering WinMedic with Windows: the WinMedicHelper scheduled task, and
//! removing the "Start with Windows" Run entry older versions wrote.

use crate::config::AppConfig;
use std::path::Path;

pub const HELPER_TASK_NAME: &str = "WinMedicHelper";
/// The Run value older versions wrote for "Start with Windows".
pub const LEGACY_AUTOSTART_NAME: &str = "WinMedic";

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The helper task's name for the signed-in account.
///
/// Tasks in the root folder are machine-wide while settings are per user, so
/// one shared name let two accounts overwrite and delete each other's task.
pub fn helper_task_name() -> String {
    let account = format!(
        "{}-{}",
        std::env::var("USERDOMAIN").unwrap_or_default(),
        std::env::var("USERNAME").unwrap_or_default()
    );
    let account: String = account
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{HELPER_TASK_NAME}-{account}")
}

/// The `/SC` schedule and `/MO` modifier for a helper frequency, if schtasks
/// has one.
///
/// `HOURLY` accepts 1-23 and `DAILY` whole days, so an interval such as 30 h
/// has no spelling at all.
pub fn helper_schedule(frequency_hours: u32) -> Option<(&'static str, u32)> {
    match frequency_hours {
        1..=23 => Some(("hourly", frequency_hours)),
        hours if hours % 24 == 0 && (24..=8760).contains(&hours) => Some(("daily", hours / 24)),
        _ => None,
    }
}

/// The command line the task runs.
///
/// WinMedic is a console-subsystem binary, so started directly the task would
/// open a console window on the user's desktop on every run. `conhost
/// --headless` hosts that console without one.
#[cfg(windows)]
fn helper_command(exe: &Path) -> String {
    format!(
        r#"%SystemRoot%\System32\conhost.exe --headless "{}" --helper"#,
        exe.display()
    )
}

#[cfg(windows)]
fn current_exe() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("Failed to determine executable path: {e}"))
}

#[cfg(windows)]
fn schtasks(args: &[&str]) -> Result<std::process::Output, String> {
    use std::os::windows::process::CommandExt;

    std::process::Command::new(crate::utils::cmd::system_program("schtasks.exe")?)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute schtasks: {e}"))
}

#[cfg(windows)]
fn check(output: std::process::Output, what: &str) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        let err = crate::utils::decode::decode_output(&output.stderr);
        Err(format!("{what}: {}", err.trim()))
    }
}

/// The registered task's XML definition, or `None` when there is no task.
#[cfg(windows)]
fn query_helper_task(name: &str) -> Option<String> {
    let output = schtasks(&["/query", "/tn", name, "/xml"]).ok()?;
    output
        .status
        .success()
        .then(|| crate::utils::decode::decode_output(&output.stdout))
}

/// What keeps WinMedic from letting the helper task start `exe`, if anything.
///
/// The task starts WinMedic with the highest rights, on a schedule and without
/// a UAC prompt. Whoever can change winmedic.exe, or a folder on its path,
/// decides what runs there as Administrator: the signed-in account itself
/// when it sits in Downloads or in WinGet's per-user package folder, and any
/// program that account runs. So the task is only registered for a file that
/// only administrators can change, as under Program Files.
pub fn helper_location_problem(exe: &Path) -> Option<String> {
    crate::utils::acl::admin_only_problem(exe).map(|problem| {
        format!(
            "{problem}, and the scheduled task would start winmedic.exe from there with the highest rights, without asking. \
             Move winmedic.exe to a folder only administrators can change, such as C:\\Program Files\\WinMedic, \
             or install it with winget install SecretLUL.WinMedic --scope machine, then turn the background scan on again."
        )
    })
}

/// Create or replace the helper task so that it runs `exe`.
#[cfg(windows)]
fn register_helper_task(exe: &Path, frequency_hours: u32) -> Result<(), String> {
    if let Some(problem) = helper_location_problem(exe) {
        return Err(problem);
    }
    let (schedule, modifier) = helper_schedule(frequency_hours).ok_or_else(|| {
        format!(
            "Task Scheduler cannot repeat every {frequency_hours} h: use 1-23 hours or whole days"
        )
    })?;
    let output = schtasks(&[
        "/create",
        "/tn",
        &helper_task_name(),
        "/tr",
        &helper_command(exe),
        "/sc",
        schedule,
        "/mo",
        &modifier.to_string(),
        // Without `/rl` a task runs with limited rights, and Windows refuses
        // to start WinMedic, whose manifest demands Administrator rights.
        "/rl",
        "highest",
        "/f",
    ])?;
    check(output, "Could not create the scheduled task")
}

/// Delete the helper task, if there is one.
#[cfg(windows)]
fn delete_helper_task() -> Result<(), String> {
    let name = helper_task_name();
    if query_helper_task(&name).is_some() {
        // Only a task that exists is deleted, so a failure here is a real
        // one (access denied, say) rather than "there was nothing to delete".
        check(
            schtasks(&["/delete", "/tn", &name, "/f"])?,
            "Could not delete the scheduled task",
        )
    } else {
        Ok(())
    }
}

pub fn sync_helper_task(enabled: bool, frequency_hours: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        if enabled {
            register_helper_task(&current_exe()?, frequency_hours)
        } else {
            delete_helper_task()
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (enabled, frequency_hours);
        Ok(())
    }
}

/// Whether the helper task exists and runs `exe`.
#[cfg(windows)]
fn helper_task_is_current(exe: &Path) -> bool {
    query_helper_task(&helper_task_name()).is_some_and(|xml| task_runs(&xml, exe))
}

/// Whether the task `xml` describes, as `schtasks /query /xml` prints it,
/// starts `exe` with the highest rights.
fn task_runs(xml: &str, exe: &Path) -> bool {
    let exe = exe.display().to_string();
    // The path is text in the XML, where `&` reads `&amp;`: compared as it
    // was, a path with one never matched, and the task was registered again,
    // its schedule restarted, on every start of the window.
    let xml = crate::utils::event_xml::unescape(xml).to_lowercase();
    // A task an older WinMedic registered with limited rights cannot start
    // this one, so it is registered again with the highest.
    if !xml.contains("<runlevel>highestavailable</runlevel>") {
        return false;
    }
    // schtasks writes the XML in the console code page, so a path outside ASCII
    // cannot be compared byte for byte. Such a task is taken as current rather
    // than re-created, and its schedule restarted, on every launch.
    !exe.is_ascii() || xml.contains(&exe.to_lowercase())
}

/// Whether a Run value is the "Start with Windows" entry an older WinMedic
/// wrote: `"<path to winmedic>" --autostart`.
fn is_legacy_autostart(command: &str) -> bool {
    command.trim_end().ends_with("--autostart")
}

/// Delete the Run entry older versions wrote for "Start with Windows", and
/// say whether there was one.
///
/// Windows does not start a program that demands Administrator rights from a
/// Run entry, so the entry could only fail at every sign-in. A value of the
/// same name that does not start WinMedic is somebody else's and stays.
pub fn remove_legacy_autostart() -> Result<bool, String> {
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};

        let Ok(key) =
            RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE)
        else {
            return Ok(false);
        };
        let ours = key
            .get_value::<String, _>(LEGACY_AUTOSTART_NAME)
            .is_ok_and(|command| is_legacy_autostart(&command));
        if !ours {
            return Ok(false);
        }
        key.delete_value(LEGACY_AUTOSTART_NAME)
            .map(|()| true)
            .map_err(|e| format!("Failed to remove the old \"Start with Windows\" entry: {e}"))
    }

    #[cfg(not(windows))]
    Ok(false)
}

/// Point the task at `exe` when its setting is on, and remove the Run entry
/// older versions wrote for "Start with Windows".
///
/// Run when the window opens, for the running executable, and right after an
/// update that renamed the file, for the new one. The task remembers the
/// executable that was running when the setting last changed, and a
/// hand-downloaded release carries the version in its file name.
///
/// The task is only repaired, never removed: with a corrupt config every
/// setting reads as off, and that must not delete what the user set up. A task
/// left behind is inert anyway, because `--helper` checks the setting. The one
/// exception is a task for a winmedic.exe that someone besides the
/// administrators can change, which an older version registered: it would
/// start whatever is put in its place with the highest rights.
pub fn reconcile(config: &AppConfig, exe: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let mut problems = Vec::new();
        if config.helper_enabled {
            if let Some(problem) = helper_location_problem(exe) {
                match delete_helper_task() {
                    Ok(()) => problems.push(format!("The background scan is off: {problem}")),
                    Err(e) => problems.push(format!(
                        "{e}. Delete the task {} in Task Scheduler: {problem}",
                        helper_task_name()
                    )),
                }
            } else if !helper_task_is_current(exe) {
                problems.extend(register_helper_task(exe, config.helper_frequency_hours).err());
            }
        }
        problems.extend(remove_legacy_autostart().err());
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (config, exe);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_intervals_schtasks_can_express_are_scheduled() {
        assert_eq!(helper_schedule(1), Some(("hourly", 1)));
        assert_eq!(helper_schedule(23), Some(("hourly", 23)));
        assert_eq!(helper_schedule(24), Some(("daily", 1)));
        assert_eq!(helper_schedule(48), Some(("daily", 2)));
        assert_eq!(helper_schedule(720), Some(("daily", 30)));
        assert_eq!(helper_schedule(0), None);
        assert_eq!(helper_schedule(30), None, "HOURLY stops at 23");
    }

    #[test]
    fn the_task_name_is_per_account_and_valid() {
        let name = helper_task_name();
        assert!(name.starts_with(HELPER_TASK_NAME));
        assert!(!name.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|']));
    }

    #[test]
    fn a_path_with_an_ampersand_is_found_in_the_task() {
        let xml = r#"<Task><Principals><Principal id="Author"><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions Context="Author"><Exec><Command>%SystemRoot%\System32\conhost.exe</Command><Arguments>--headless "C:\Program Files\Tom &amp; Jerry\winmedic.exe" --helper</Arguments></Exec></Actions></Task>"#;
        assert!(task_runs(
            xml,
            Path::new(r"C:\Program Files\Tom & Jerry\winmedic.exe")
        ));
        assert!(!task_runs(
            xml,
            Path::new(r"C:\Program Files\WinMedic\winmedic.exe")
        ));
        let limited = xml.replace("HighestAvailable", "LeastPrivilege");
        assert!(!task_runs(
            &limited,
            Path::new(r"C:\Program Files\Tom & Jerry\winmedic.exe")
        ));
    }

    /// What 0.5.0 to 0.6.0 wrote is removed; another program's value under
    /// the same name is not.
    #[test]
    fn only_the_entry_winmedic_wrote_is_removed() {
        assert!(is_legacy_autostart(
            r#""C:\Tools\winmedic.exe" --autostart"#
        ));
        assert!(is_legacy_autostart(
            r#""C:\Users\Some User\AppData\Local\Microsoft\WinGet\Links\winmedic.exe" --autostart"#
        ));
        assert!(!is_legacy_autostart(r#""C:\Tools\winmedic.exe""#));
        assert!(!is_legacy_autostart(
            r#""C:\Program Files\Other\app.exe" /min"#
        ));
    }
}
