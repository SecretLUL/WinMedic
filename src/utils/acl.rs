//! Who besides the administrators can change a file, a folder or a registry
//! key.
//!
//! WinMedic runs elevated, and in a few places it acts on something that a
//! standard account could have put there or swapped: the program the
//! background task starts with the highest rights, the folder registry
//! backups are written into, and the key that records each backup. These
//! must be changeable by Administrators, SYSTEM and TrustedInstaller only,
//! like everything under Program Files, or acting on them hands their rights
//! to whoever can change them.

use std::path::{Path, PathBuf};

/// What a path component or a registry key is, which decides the rights that
/// let someone change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// The file itself: whoever can write it, or remove it so that another
    /// file takes its place, decides what it holds.
    File,
    /// A folder on the way to it: whoever can remove or rename it, or an
    /// entry in it, can put a folder of their own in its place.
    Folder,
    /// The drive's root. Everyone signed in may create folders in `C:\`,
    /// which replaces nothing that is there.
    Root,
    /// A folder WinMedic writes files into: whoever can add an entry to it
    /// can also put one in place before WinMedic writes there.
    Store,
    /// A registry key: whoever can set a value in it, add a key below it or
    /// remove it decides what WinMedic reads from it.
    Key,
}

/// An account, as its string SID and, for messages, its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub sid: String,
    pub name: String,
}

/// One entry of a permission list that allows something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub account: Account,
    /// The rights it allows.
    pub mask: u32,
    /// Whether it only passes on to what is created inside: such an entry
    /// gives nothing on the folder itself.
    pub inherit_only: bool,
}

const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
/// On a folder: `FILE_ADD_FILE`.
const FILE_WRITE_DATA: u32 = 0x0002;
/// On a folder: `FILE_ADD_SUBDIRECTORY`.
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_DELETE_CHILD: u32 = 0x0040;
const KEY_SET_VALUE: u32 = 0x0002;
const KEY_CREATE_SUB_KEY: u32 = 0x0004;
const KEY_CREATE_LINK: u32 = 0x0020;

/// The rights that let someone change what `part` is: rewrite the file,
/// remove or rename it or a folder on its path so that another takes its
/// place, or rewrite its permissions to allow either.
fn change_rights(part: Part) -> u32 {
    let anything = WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    match part {
        Part::File => anything | DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE,
        Part::Folder => anything | DELETE | FILE_DELETE_CHILD,
        Part::Root => anything | FILE_DELETE_CHILD,
        Part::Store => {
            anything
                | DELETE
                | FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_DELETE_CHILD
                | GENERIC_WRITE
        }
        Part::Key => {
            anything | DELETE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | GENERIC_WRITE
        }
    }
}

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// CREATOR OWNER, CREATOR GROUP and OWNER RIGHTS: placeholders that no
/// account signs in as. OWNER RIGHTS stands for the owner, who is checked on
/// their own.
const PLACEHOLDERS: [&str; 3] = ["S-1-3-0", "S-1-3-1", "S-1-3-4"];

fn is_trusted(sid: &str) -> bool {
    matches!(sid, SYSTEM | ADMINISTRATORS | TRUSTED_INSTALLER) || PLACEHOLDERS.contains(&sid)
}

/// Who, besides Administrators, SYSTEM and TrustedInstaller, can change a
/// `part` that `owner` owns and `grants` give rights to; `grants` is `None`
/// for a missing permission list, which lets everyone do anything. The owner
/// counts, since an owner can always rewrite the permissions.
pub fn who_else_can_change(
    part: Part,
    owner: &Account,
    grants: Option<&[Grant]>,
) -> Option<String> {
    if !is_trusted(&owner.sid) {
        return Some(owner.name.clone());
    }
    let Some(grants) = grants else {
        return Some("Everyone".to_string());
    };
    grants
        .iter()
        .find(|grant| {
            !grant.inherit_only
                && grant.mask & change_rights(part) != 0
                && !is_trusted(&grant.account.sid)
        })
        .map(|grant| grant.account.name.clone())
}

/// `path` and every folder above it, with what each one is; the drive's root
/// comes last.
fn path_chain(path: &Path) -> Vec<(PathBuf, Part)> {
    let mut chain = vec![(path.to_path_buf(), Part::File)];
    let mut folder = path.parent();
    while let Some(dir) = folder {
        folder = dir.parent();
        let part = if folder.is_some() {
            Part::Folder
        } else {
            Part::Root
        };
        chain.push((dir.to_path_buf(), part));
    }
    chain
}

/// `path` without the `\\?\` that `canonicalize` puts in front, for messages
/// and for the functions that do not take it.
pub(crate) fn plain(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{unc}"))
    } else if let Some(local) = text.strip_prefix(r"\\?\") {
        PathBuf::from(local)
    } else {
        path.to_path_buf()
    }
}

/// What keeps the file at `path` from being changeable by administrators
/// only: who else can change it or a folder above it, or that it is not on a
/// fixed drive of this PC. `None` when nothing does.
///
/// `path` is checked as written and as it resolves, past links and
/// junctions, since Windows follows them when it opens the file.
pub fn admin_only_problem(path: &Path) -> Option<String> {
    let mut ways = vec![path.to_path_buf()];
    if let Ok(resolved) = std::fs::canonicalize(path) {
        ways.push(plain(&resolved));
    }
    for way in &ways {
        let chain = path_chain(way);
        if let Some((root, _)) = chain.last()
            && !on_fixed_drive(root)
        {
            return Some(format!(
                "{} is not on a fixed drive of this PC",
                way.display()
            ));
        }
        for (item, part) in &chain {
            let found = match permissions(item) {
                Ok((owner, grants)) => who_else_can_change(*part, &owner, grants.as_deref()),
                Err(e) => {
                    return Some(format!(
                        "the permissions of {} could not be read ({e})",
                        item.display()
                    ));
                }
            };
            if let Some(who) = found {
                return Some(format!("{who} can change {}", item.display()));
            }
        }
    }
    None
}

/// Create `dir`, and the folders missing above it, owned by Administrators
/// and changeable by Administrators and SYSTEM only. A folder that is there
/// already is left as it is: someone else may have made it, so the caller
/// checks it.
pub fn create_admin_only_dir(dir: &Path) -> Result<(), String> {
    let mut missing = Vec::new();
    let mut at = Some(dir);
    while let Some(folder) = at.filter(|folder| !folder.exists()) {
        missing.push(folder);
        at = folder.parent();
    }
    for folder in missing.into_iter().rev() {
        create_admin_only(folder)
            .map_err(|e| format!("{} could not be created: {e}", folder.display()))?;
    }
    Ok(())
}

/// Who besides Administrators, SYSTEM and TrustedInstaller can change the
/// file or folder `file` is open on, a `part` of the file system; `None` when
/// nobody can.
///
/// Read through the handle, so it is about what WinMedic holds, not whatever
/// a path names by the time it is looked up.
#[cfg(windows)]
pub fn who_else_can_change_file(
    file: &std::fs::File,
    part: Part,
) -> Result<Option<String>, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;

    who_else_can_change_object(file.as_raw_handle(), SE_FILE_OBJECT, part)
}

/// [`who_else_can_change_file`] for the registry key `key`.
#[cfg(windows)]
pub fn who_else_can_change_key(key: &winreg::RegKey) -> Result<Option<String>, String> {
    use windows_sys::Win32::Security::Authorization::SE_REGISTRY_KEY;

    who_else_can_change_object(key.raw_handle(), SE_REGISTRY_KEY, Part::Key)
}

/// Who besides Administrators, SYSTEM and TrustedInstaller can change the
/// `object` that `handle`, an open handle, is open on.
#[cfg(windows)]
fn who_else_can_change_object(
    handle: windows_sys::Win32::Foundation::HANDLE,
    object: windows_sys::Win32::Security::Authorization::SE_OBJECT_TYPE,
    part: Part,
) -> Result<Option<String>, String> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            object,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32).to_string());
    }
    let read = unsafe { read_descriptor(owner, dacl) };
    unsafe { LocalFree(descriptor) };
    let (owner, grants) = read.ok_or("the permission list is not readable")?;
    Ok(who_else_can_change(part, &owner, grants.as_deref()))
}

/// Whether the drive whose root is `root` is a fixed drive of this PC.
#[cfg(windows)]
fn on_fixed_drive(root: &Path) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    const DRIVE_FIXED: u32 = 3;

    let mut root = plain(root).into_os_string();
    if !root.to_string_lossy().ends_with('\\') {
        root.push("\\");
    }
    unsafe { GetDriveTypeW(wide(root.as_os_str()).as_ptr()) == DRIVE_FIXED }
}

#[cfg(not(windows))]
fn on_fixed_drive(_root: &Path) -> bool {
    false
}

#[cfg(windows)]
fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    text.encode_wide().chain(Some(0)).collect()
}

/// The owner of `path` and the entries of its permission list that allow
/// something; `None` for a missing list.
#[cfg(windows)]
fn permissions(path: &Path) -> Result<(Account, Option<Vec<Grant>>), String> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    let name = wide(path.as_os_str());
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32).to_string());
    }
    let result = unsafe { read_descriptor(owner, dacl) };
    unsafe { LocalFree(descriptor) };
    result.ok_or_else(|| "the permission list is not readable".to_string())
}

/// The account `owner` and the entries of the permission list `dacl` that
/// allow something, `None` for a missing list; both from a security
/// descriptor that is still allocated.
#[cfg(windows)]
unsafe fn read_descriptor(
    owner: windows_sys::Win32::Security::PSID,
    dacl: *mut windows_sys::Win32::Security::ACL,
) -> Option<(Account, Option<Vec<Grant>>)> {
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, GetAce, INHERIT_ONLY_ACE, PSID,
    };

    // ACCESS_ALLOWED_CALLBACK_ACE starts like ACCESS_ALLOWED_ACE; the object
    // variants are for directory objects, not files.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;

    let owner = account(owner)?;
    if dacl.is_null() {
        return Some((owner, None));
    }
    let mut grants = Vec::new();
    for index in 0..u32::from(unsafe { (*dacl).AceCount }) {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return None;
        }
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        if !matches!(
            header.AceType,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        ) {
            continue;
        }
        let allowed = ace as *const ACCESS_ALLOWED_ACE;
        let sid = unsafe { std::ptr::addr_of!((*allowed).SidStart) } as PSID;
        grants.push(Grant {
            account: account(sid)?,
            mask: unsafe { (*allowed).Mask },
            inherit_only: u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0,
        });
    }
    Some((owner, Some(grants)))
}

#[cfg(not(windows))]
fn permissions(_path: &Path) -> Result<(Account, Option<Vec<Grant>>), String> {
    Err("permissions are only read on Windows".to_string())
}

/// The account behind `sid`: its string SID, and `DOMAIN\name` where Windows
/// knows one.
#[cfg(windows)]
fn account(sid: windows_sys::Win32::Security::PSID) -> Option<Account> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{LookupAccountSidW, SID_NAME_USE};

    let text_of = |buffer: &[u16]| {
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..len])
    };

    let mut string_sid: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut string_sid) } == 0 {
        return None;
    }
    let len = (0..)
        .take_while(|&i| unsafe { *string_sid.add(i) } != 0)
        .count();
    let sid_text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(string_sid, len) });
    unsafe { LocalFree(string_sid.cast()) };

    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
    let mut kind: SID_NAME_USE = 0;
    let found = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    } != 0;
    let name = match (found, text_of(&domain), text_of(&name)) {
        (true, domain, name) if !domain.is_empty() => format!(r"{domain}\{name}"),
        (true, _, name) if !name.is_empty() => name,
        _ => sid_text.clone(),
    };
    Some(Account {
        sid: sid_text,
        name,
    })
}

/// `sddl` as security attributes for `create`, freed after it ran.
#[cfg(windows)]
fn with_attributes<T>(
    sddl: &str,
    create: impl FnOnce(&windows_sys::Win32::Security::SECURITY_ATTRIBUTES) -> std::io::Result<T>,
) -> std::io::Result<T> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let sddl = wide(std::ffi::OsStr::new(sddl));
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let result = create(&SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    });
    unsafe { LocalFree(descriptor) };
    result
}

/// Create one folder owned by Administrators, whose permissions let only
/// SYSTEM and Administrators in, inherited by everything created inside, and
/// not inherited from above.
#[cfg(windows)]
fn create_admin_only(folder: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    // An owner can always rewrite the permissions, so it is set too: the
    // account that runs WinMedic must not become it.
    const ADMINS_AND_SYSTEM_ONLY: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    with_attributes(ADMINS_AND_SYSTEM_ONLY, |attributes| {
        if unsafe { CreateDirectoryW(wide(folder.as_os_str()).as_ptr(), attributes) } != 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        // Made in the meantime, by WinMedic or by someone else: the caller
        // checks which.
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(err)
        }
    })
}

#[cfg(not(windows))]
fn create_admin_only(folder: &Path) -> std::io::Result<()> {
    std::fs::create_dir(folder)
}

/// Open `HKEY_LOCAL_MACHINE\<path>`, creating it, if it is missing, owned by
/// Administrators and with permissions that let only SYSTEM and
/// Administrators in, inherited by the keys below and not from above. A key
/// that is there already keeps its own permissions; the caller checks them.
#[cfg(windows)]
pub fn create_admin_only_key(path: &str) -> std::io::Result<winreg::RegKey> {
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, REG_OPTION_NON_VOLATILE, RegCreateKeyExW,
    };

    const ADMINS_AND_SYSTEM_ONLY: &str = "O:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)";

    with_attributes(ADMINS_AND_SYSTEM_ONLY, |attributes| {
        let mut key = std::ptr::null_mut();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(std::ffi::OsStr::new(path)).as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                attributes,
                &mut key,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            // Closed when it is dropped, as any key `RegKey` opened itself.
            Ok(winreg::RegKey::predef(key))
        } else {
            Err(std::io::Error::from_raw_os_error(status as i32))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(sid: &str, name: &str) -> Account {
        Account {
            sid: sid.to_string(),
            name: name.to_string(),
        }
    }

    fn grant(sid: &str, name: &str, mask: u32) -> Grant {
        Grant {
            account: named(sid, name),
            mask,
            inherit_only: false,
        }
    }

    const USER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
    const USERS: &str = "S-1-5-32-545";
    const AUTHENTICATED_USERS: &str = "S-1-5-11";
    /// Full control, Modify and Read & execute, as icacls prints F, M and RX.
    const FULL: u32 = 0x001F_01FF;
    const MODIFY: u32 = 0x0013_01BF;
    const READ_EXECUTE: u32 = 0x0012_00A9;

    fn program_files() -> (Account, Vec<Grant>) {
        (
            named(TRUSTED_INSTALLER, r"NT SERVICE\TrustedInstaller"),
            vec![
                grant(TRUSTED_INSTALLER, r"NT SERVICE\TrustedInstaller", FULL),
                grant(SYSTEM, r"NT AUTHORITY\SYSTEM", MODIFY),
                grant(ADMINISTRATORS, r"BUILTIN\Administrators", MODIFY),
                grant(USERS, r"BUILTIN\Users", READ_EXECUTE),
                Grant {
                    inherit_only: true,
                    ..grant("S-1-3-0", "CREATOR OWNER", GENERIC_ALL)
                },
            ],
        )
    }

    #[test]
    fn program_files_is_changeable_by_administrators_only() {
        let (owner, grants) = program_files();
        for part in [Part::File, Part::Folder, Part::Root] {
            assert_eq!(who_else_can_change(part, &owner, Some(&grants)), None);
        }
    }

    #[test]
    fn a_file_the_user_owns_is_changeable_by_the_user() {
        let owner = named(USER, r"PC\Bob");
        let grants = vec![grant(USER, r"PC\Bob", FULL)];
        assert_eq!(
            who_else_can_change(Part::File, &owner, Some(&grants)).as_deref(),
            Some(r"PC\Bob")
        );
    }

    #[test]
    fn a_file_users_may_modify_is_changeable_by_them() {
        let (owner, mut grants) = program_files();
        grants.push(grant(USERS, r"BUILTIN\Users", MODIFY));
        assert_eq!(
            who_else_can_change(Part::File, &owner, Some(&grants)).as_deref(),
            Some(r"BUILTIN\Users")
        );
    }

    #[test]
    fn a_missing_permission_list_lets_everyone_change_it() {
        let (owner, _) = program_files();
        assert_eq!(
            who_else_can_change(Part::File, &owner, None).as_deref(),
            Some("Everyone")
        );
    }

    /// C:\ProgramData lets Users create files and folders in it, but not
    /// remove or rename what is there, so a folder an administrator made in
    /// it stays theirs.
    #[test]
    fn creating_in_a_folder_replaces_nothing_but_removing_does() {
        let (owner, mut grants) = program_files();
        // icacls: BUILTIN\Users:(CI)(WD,AD,WEA,WA)
        grants.push(grant(USERS, r"BUILTIN\Users", 0x0116));
        assert_eq!(
            who_else_can_change(Part::Folder, &owner, Some(&grants)),
            None
        );

        grants.push(grant(USERS, r"BUILTIN\Users", FILE_DELETE_CHILD));
        assert!(who_else_can_change(Part::Folder, &owner, Some(&grants)).is_some());
    }

    /// C:\ lets everyone signed in create folders (AD) and passes Modify on
    /// to what they create; neither changes a folder that is there.
    #[test]
    fn the_root_of_c_lets_nobody_replace_what_is_in_it() {
        let owner = named(SYSTEM, r"NT AUTHORITY\SYSTEM");
        let grants = vec![
            grant(ADMINISTRATORS, r"BUILTIN\Administrators", FULL),
            grant(SYSTEM, r"NT AUTHORITY\SYSTEM", FULL),
            grant(USERS, r"BUILTIN\Users", READ_EXECUTE),
            grant(
                AUTHENTICATED_USERS,
                r"NT AUTHORITY\Authenticated Users",
                0x0004,
            ),
            Grant {
                inherit_only: true,
                ..grant(
                    AUTHENTICATED_USERS,
                    r"NT AUTHORITY\Authenticated Users",
                    MODIFY,
                )
            },
        ];
        assert_eq!(who_else_can_change(Part::Root, &owner, Some(&grants)), None);
    }

    /// What C:\ProgramData lets Users do, create files and folders, replaces
    /// nothing on the way to a file, but in the folder WinMedic writes into
    /// it lets them put a file in place first.
    #[test]
    fn a_folder_others_may_add_files_to_is_no_place_to_write() {
        let (owner, mut grants) = program_files();
        // icacls: BUILTIN\Users:(CI)(WD,AD,WEA,WA)
        grants.push(grant(USERS, r"BUILTIN\Users", 0x0116));
        assert_eq!(
            who_else_can_change(Part::Folder, &owner, Some(&grants)),
            None
        );
        assert_eq!(
            who_else_can_change(Part::Store, &owner, Some(&grants)).as_deref(),
            Some(r"BUILTIN\Users")
        );
    }

    /// HKLM\SOFTWARE lets Users read its keys, which changes nothing; setting
    /// a value does.
    #[test]
    fn a_key_others_can_set_values_in_is_changeable_by_them() {
        const KEY_READ: u32 = 0x0002_0019;
        const KEY_ALL_ACCESS: u32 = 0x000F_003F;
        let owner = named(ADMINISTRATORS, r"BUILTIN\Administrators");
        let mut grants = vec![
            grant(SYSTEM, r"NT AUTHORITY\SYSTEM", KEY_ALL_ACCESS),
            grant(ADMINISTRATORS, r"BUILTIN\Administrators", KEY_ALL_ACCESS),
            grant(USERS, r"BUILTIN\Users", KEY_READ),
        ];
        assert_eq!(who_else_can_change(Part::Key, &owner, Some(&grants)), None);

        grants.push(grant(USERS, r"BUILTIN\Users", KEY_SET_VALUE));
        assert_eq!(
            who_else_can_change(Part::Key, &owner, Some(&grants)).as_deref(),
            Some(r"BUILTIN\Users")
        );
    }

    #[test]
    fn rewriting_the_permissions_counts_as_changing() {
        let (owner, mut grants) = program_files();
        grants.push(grant(USER, r"PC\Bob", WRITE_DAC));
        assert!(who_else_can_change(Part::Folder, &owner, Some(&grants)).is_some());
        assert!(who_else_can_change(Part::Root, &owner, Some(&grants)).is_some());
    }

    #[test]
    fn the_chain_runs_from_the_file_to_the_root() {
        let chain = path_chain(Path::new(r"C:\Program Files\WinMedic\winmedic.exe"));
        let parts: Vec<(String, Part)> = chain
            .into_iter()
            .map(|(path, part)| (path.display().to_string(), part))
            .collect();
        assert_eq!(
            parts,
            vec![
                (
                    r"C:\Program Files\WinMedic\winmedic.exe".to_string(),
                    Part::File
                ),
                (r"C:\Program Files\WinMedic".to_string(), Part::Folder),
                (r"C:\Program Files".to_string(), Part::Folder),
                (r"C:\".to_string(), Part::Root),
            ]
        );
        assert_eq!(
            plain(Path::new(r"\\?\C:\Program Files")),
            PathBuf::from(r"C:\Program Files")
        );
        assert_eq!(
            plain(Path::new(r"\\?\UNC\server\share\x.exe")),
            PathBuf::from(r"\\server\share\x.exe")
        );
    }

    /// A file in the temp folder belongs to the account running the tests,
    /// whoever that is. Only reads permissions.
    #[test]
    fn a_file_in_the_temp_folder_is_not_changeable_by_administrators_only() {
        let file = std::env::temp_dir().join(format!("winmedic_acl_{}.exe", std::process::id()));
        std::fs::write(&file, b"MZ").unwrap();
        let problem = admin_only_problem(&file);
        let _ = std::fs::remove_file(&file);
        assert!(problem.is_some());
    }
}
