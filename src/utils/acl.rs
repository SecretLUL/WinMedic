//! Who besides the administrators can change a file or a folder.
//!
//! WinMedic runs elevated, and in a few places it acts on a file that a
//! standard account could have put there or swapped: the program the
//! background task starts with the highest rights, and the registry backups a
//! rollback imports. Such a file must be changeable by Administrators, SYSTEM
//! and TrustedInstaller only, like everything under Program Files, or acting
//! on it hands their rights to whoever can change it.

use std::path::{Path, PathBuf};

/// What a path component is, which decides the rights that let someone change it.
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
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_DELETE_CHILD: u32 = 0x0040;

/// The rights that let someone change what `part` is: rewrite the file,
/// remove or rename it or a folder on its path so that another takes its
/// place, or rewrite its permissions to allow either.
fn change_rights(part: Part) -> u32 {
    let anything = WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    match part {
        Part::File => anything | DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE,
        Part::Folder => anything | DELETE | FILE_DELETE_CHILD,
        Part::Root => anything | FILE_DELETE_CHILD,
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
fn plain(path: &Path) -> PathBuf {
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
/// and changeable by Administrators and SYSTEM only; then check that nobody
/// else can change `dir` or a folder above it, since a folder of that name
/// may have been there already, made by someone else.
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
    match admin_only_problem(dir) {
        None => Ok(()),
        Some(problem) => Err(problem),
    }
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
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, INHERIT_ONLY_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    // ACCESS_ALLOWED_CALLBACK_ACE starts like ACCESS_ALLOWED_ACE; the object
    // variants are for directory objects, not files.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;

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

    let read = || -> Option<(Account, Option<Vec<Grant>>)> {
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
    };
    let result = read();
    unsafe { LocalFree(descriptor) };
    result.ok_or_else(|| "the permission list is not readable".to_string())
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

/// Make Administrators the owner of `path`.
///
/// A new file belongs to the default owner of the program that wrote it:
/// Administrators for a program elevated under UAC, but it can be the
/// account itself, for instance with UAC switched off. An owner can always
/// rewrite the permissions, so [`admin_only_problem`] counts such a file as
/// changeable by that account.
#[cfg(windows)]
pub fn hand_to_administrators(path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSID};

    let mut administrators: PSID = std::ptr::null_mut();
    if unsafe {
        ConvertStringSidToSidW(
            wide(std::ffi::OsStr::new(ADMINISTRATORS)).as_ptr(),
            &mut administrators,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide(path.as_os_str()).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            administrators,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    unsafe { LocalFree(administrators) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(status as i32).to_string())
    }
}

#[cfg(not(windows))]
pub fn hand_to_administrators(_path: &Path) -> Result<(), String> {
    Err("owners are only set on Windows".to_string())
}

/// Create one folder owned by Administrators, whose permissions let only
/// SYSTEM and Administrators in, inherited by everything created inside, and
/// not inherited from above.
#[cfg(windows)]
fn create_admin_only(folder: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    // The owner, for the reason given at `hand_to_administrators`.
    const ADMINS_AND_SYSTEM_ONLY: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    let sddl = wide(std::ffi::OsStr::new(ADMINS_AND_SYSTEM_ONLY));
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
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let created = unsafe { CreateDirectoryW(wide(folder.as_os_str()).as_ptr(), &attributes) } != 0;
    let result = if created {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        // Made in the meantime, by WinMedic or by someone else: the check
        // that follows tells which.
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(err)
        }
    };
    unsafe { LocalFree(descriptor) };
    result
}

#[cfg(not(windows))]
fn create_admin_only(folder: &Path) -> std::io::Result<()> {
    std::fs::create_dir(folder)
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
