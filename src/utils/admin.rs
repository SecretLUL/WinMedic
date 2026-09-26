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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_admin_does_not_panic() {
        // Must execute cleanly without error or panic
        let _ = is_admin();
    }

    #[test]
    fn the_current_account_has_a_sid() {
        let sid = current_user_sid().expect("the process token names its user");
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }
}
