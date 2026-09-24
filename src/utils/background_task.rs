//! Registering WinMedic with Windows: the WinMedicHelper scheduled task and the
//! "Start with Windows" Run entry.

use crate::config::AppConfig;

pub const HELPER_TASK_NAME: &str = "WinMedicHelper";
pub const AUTOSTART_KEY_NAME: &str = "WinMedic";

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The helper task's name for the signed-in account.
///
/// Tasks in the root folder are machine-wide while the Run entry is per user,
/// so one shared name let two accounts overwrite and delete each other's task.
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
fn helper_command(exe: &std::path::Path) -> String {
    format!(
        r#"%SystemRoot%\System32\conhost.exe --headless "{}" --helper"#,
        exe.display()
    )
}

#[cfg(windows)]
fn autostart_command(exe: &std::path::Path) -> String {
    format!("\"{}\" --autostart", exe.display())
}

#[cfg(windows)]
fn current_exe() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("Failed to determine executable path: {e}"))
}

#[cfg(windows)]
fn schtasks(args: &[&str]) -> Result<std::process::Output, String> {
    use std::os::windows::process::CommandExt;

    std::process::Command::new("schtasks.exe")
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

pub fn sync_helper_task(enabled: bool, frequency_hours: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        let name = helper_task_name();
        if enabled {
            let (schedule, modifier) = helper_schedule(frequency_hours).ok_or_else(|| {
                format!(
                    "Task Scheduler cannot repeat every {frequency_hours} h: use 1-23 hours or whole days"
                )
            })?;
            let exe_path = current_exe()?;
            let output = schtasks(&[
                "/create",
                "/tn",
                &name,
                "/tr",
                &helper_command(&exe_path),
                "/sc",
                schedule,
                "/mo",
                &modifier.to_string(),
                "/f",
            ])?;
            check(output, "Could not create the scheduled task")
        } else if query_helper_task(&name).is_some() {
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

    #[cfg(not(windows))]
    {
        let _ = (enabled, frequency_hours);
        Ok(())
    }
}

/// Whether the helper task exists and runs this executable.
#[cfg(windows)]
fn helper_task_is_current() -> bool {
    let Some(xml) = query_helper_task(&helper_task_name()) else {
        return false;
    };
    let Ok(exe) = std::env::current_exe() else {
        return true;
    };
    let exe = exe.display().to_string();
    // schtasks writes the XML in the console code page, so a path outside ASCII
    // cannot be compared byte for byte. Such a task is taken as current rather
    // than re-created, and its schedule restarted, on every launch.
    !exe.is_ascii() || xml.to_lowercase().contains(&exe.to_lowercase())
}

pub fn sync_autostart(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        if enabled {
            let exe_path = current_exe()?;
            let (key, _) = hkcu
                .create_subkey(RUN_KEY)
                .map_err(|e| format!("Failed to open Run registry key: {e}"))?;
            key.set_value(AUTOSTART_KEY_NAME, &autostart_command(&exe_path))
                .map_err(|e| format!("Failed to write autostart registry entry: {e}"))?;
        } else if let Ok(key) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_WRITE) {
            match key.delete_value(AUTOSTART_KEY_NAME) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!(
                        "Failed to remove the autostart registry entry: {e}"
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = enabled;
        Ok(())
    }
}

/// Whether the Run entry exists and starts this executable.
#[cfg(windows)]
fn autostart_is_current() -> bool {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};

    let Ok(exe) = std::env::current_exe() else {
        return true;
    };
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(RUN_KEY, KEY_READ)
        .and_then(|key| key.get_value::<String, _>(AUTOSTART_KEY_NAME))
        .is_ok_and(|value| value.eq_ignore_ascii_case(&autostart_command(&exe)))
}

/// Repair the task and the Run entry for the settings that are on.
///
/// Run once when the window opens. Both remember the executable that was
/// running when the setting last changed, and releases carry the version in the
/// file name, so the next download would leave them pointing at a file that is
/// gone — which WinMedic's own startup check then reports, and removes.
///
/// It only repairs, never removes: with a corrupt config every setting reads as
/// off, and that must not delete what the user set up. An entry left behind is
/// inert anyway, because `--helper` and `--autostart` both check the setting.
pub fn reconcile(config: &AppConfig) -> Result<(), String> {
    #[cfg(windows)]
    {
        let mut problems = Vec::new();
        if config.helper_enabled && !helper_task_is_current() {
            problems.extend(sync_helper_task(true, config.helper_frequency_hours).err());
        }
        if config.autostart && !autostart_is_current() {
            problems.extend(sync_autostart(true).err());
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    #[cfg(not(windows))]
    {
        let _ = config;
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
}
