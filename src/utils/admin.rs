use std::process::Command;

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

/// Request UAC elevation by relaunching the current executable with 'runas'
pub fn relaunch_as_admin() -> std::io::Result<()> {
    let current_exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_str = args.join(" ");

    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs",
                current_exe.display(),
                args_str
            ),
        ])
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
}
