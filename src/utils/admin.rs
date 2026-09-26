use std::process::Command;

use crate::utils::cmd::ps_single_quoted;

/// Check whether the current process has Windows Administrator privileges.
///
/// Uses the Win32 `CheckTokenMembership` API with the well-known Administrators
/// SID (`S-1-5-32-544`). This avoids spawning external processes (`net session`
/// or `whoami`), is non-blocking, instant (~microsecond), and reliable across all
/// Windows language / domain configurations.
#[cfg(windows)]
pub fn is_admin() -> bool {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, SECURITY_NT_AUTHORITY,
        SID_IDENTIFIER_AUTHORITY,
    };
    use windows_sys::core::BOOL;

    const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x00000020;
    const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x00000220;

    unsafe {
        let nt_authority: SID_IDENTIFIER_AUTHORITY = SECURITY_NT_AUTHORITY;
        let mut admin_group: *mut core::ffi::c_void = core::ptr::null_mut();

        // S-1-5-32-544 (Builtin Administrators Group)
        if AllocateAndInitializeSid(
            &nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admin_group,
        ) == FALSE
        {
            return false;
        }

        let mut is_member: BOOL = FALSE;
        let success = CheckTokenMembership(core::ptr::null_mut(), admin_group, &mut is_member);
        FreeSid(admin_group);

        success != FALSE && is_member != FALSE
    }
}

#[cfg(not(windows))]
pub fn is_admin() -> bool {
    false
}

/// The SID of the account this process runs as, e.g. `S-1-5-21-...-1001`:
/// the name of its folder in every `$Recycle.Bin`.
pub fn current_user_sid() -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = core::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            return None;
        }
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, core::ptr::null_mut(), 0, &mut needed);
        // u64 keeps the buffer aligned for the pointer TOKEN_USER starts with.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == FALSE {
            return None;
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut text: *mut u16 = core::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == FALSE {
            return None;
        }
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let sid = String::from_utf16_lossy(core::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Some(sid)
    }
}

/// Build the `Start-Process` script that relaunches `exe` elevated with `args`.
///
/// `-ArgumentList` is omitted entirely when there are no arguments: the
/// parameter rejects an empty string, so passing `-ArgumentList ''` aborts the
/// relaunch with a binding error instead of elevating.
///
/// Each argument becomes its own element of a PowerShell array rather than one
/// space-joined string, so an argument that itself contains a space — a
/// `--output` path, say — arrives as a single argument instead of being split.
/// Both the path and the arguments go through [`ps_single_quoted`], which is
/// what keeps a value containing `'` from ending the literal and running as
/// code in a process that is about to be elevated.
fn build_relaunch_script(exe: &str, args: &[String]) -> String {
    let file_path = ps_single_quoted(exe);

    if args.is_empty() {
        format!("Start-Process -FilePath {file_path} -Verb RunAs")
    } else {
        let list = args
            .iter()
            .map(|a| ps_single_quoted(a))
            .collect::<Vec<_>>()
            .join(",");
        format!("Start-Process -FilePath {file_path} -ArgumentList {list} -Verb RunAs")
    }
}

/// Request UAC elevation by relaunching the current executable with 'runas'
pub fn relaunch_as_admin() -> std::io::Result<()> {
    let current_exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let script = build_relaunch_script(&current_exe.display().to_string(), &args);

    Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .spawn()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_admin_does_not_panic() {
        // Must execute cleanly without error or panic
        let _ = is_admin();
    }

    /// `-ArgumentList ''` is a binding error, not an empty argument list, so
    /// relaunching without arguments must not emit the parameter at all.
    #[test]
    fn relaunch_without_args_omits_argument_list() {
        let script = build_relaunch_script(r"C:\Tools\winmedic.exe", &[]);

        assert_eq!(
            script,
            r"Start-Process -FilePath 'C:\Tools\winmedic.exe' -Verb RunAs"
        );
        assert!(!script.contains("-ArgumentList"));
    }

    #[test]
    fn relaunch_quotes_each_argument_separately() {
        let args = vec!["--auto-fix".to_string(), "--output".to_string()];
        let script = build_relaunch_script(r"C:\Tools\winmedic.exe", &args);

        assert_eq!(
            script,
            r"Start-Process -FilePath 'C:\Tools\winmedic.exe' -ArgumentList '--auto-fix','--output' -Verb RunAs"
        );
    }

    /// An argument containing a space is one argument, not two. Joining the
    /// list into a single string would hand the relaunched process a split
    /// path.
    #[test]
    fn relaunch_keeps_an_argument_with_spaces_intact() {
        let args = vec![
            "--output".to_string(),
            r"C:\Users\Some User\report.html".to_string(),
        ];
        let script = build_relaunch_script(r"C:\Tools\winmedic.exe", &args);

        assert!(script.contains(r"'--output','C:\Users\Some User\report.html'"));
    }

    /// A Windows profile directory may contain an apostrophe. Unescaped, it
    /// ends the single-quoted literal and the rest of the path runs as code —
    /// in the one call in the tree that is deliberately elevating.
    #[test]
    fn relaunch_escapes_apostrophes_in_the_exe_path() {
        let script = build_relaunch_script(r"C:\Users\O'Brien\winmedic.exe", &[]);

        assert_eq!(
            script,
            r"Start-Process -FilePath 'C:\Users\O''Brien\winmedic.exe' -Verb RunAs"
        );
    }

    #[test]
    fn relaunch_escapes_apostrophes_in_arguments() {
        let args = vec!["--output".to_string(), r"C:\O'Brien\out.html".to_string()];
        let script = build_relaunch_script(r"C:\Tools\winmedic.exe", &args);

        assert!(script.contains(r"'--output','C:\O''Brien\out.html'"));
    }

    #[test]
    fn the_current_account_has_a_sid() {
        let sid = current_user_sid().expect("the process token names its user");
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }
}
