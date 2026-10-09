//! Registry backups a rollback can trust.
//!
//! Before a repair changes a registry key, `reg export` writes the key to a
//! `.reg` file in `%ProgramData%\WinMedic\backups`, and a rollback runs
//! `reg import` on that file with Administrator rights. So a rollback must
//! import exactly the bytes WinMedic exported, and only for the key it backed
//! up.
//!
//! Each backup is anchored in `HKLM\SOFTWARE\WinMedic\Backups`, which only
//! Administrators and SYSTEM can change: one key per file, holding the key
//! that was backed up and the SHA-256 of the file. The file is held open from
//! the moment it is read until `reg import` is done with it, so it cannot
//! change in between. The folders above the backup folder may belong to
//! anyone: they decide whether a backup is still there, not whether it is
//! genuine.

use crate::utils::acl::{self, Part};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::registry::{self, RegValue};
use chrono::{DateTime, Local};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::time::Duration;
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

/// The first line of every file `reg export` writes.
const REG_EXPORT_SIGNATURE: &str = "Windows Registry Editor Version 5.00";

/// The key below `HKEY_LOCAL_MACHINE` that holds the anchors;
/// `--uninstall --purge` deletes it.
pub const MACHINE_KEY: &str = r"SOFTWARE\WinMedic";

/// The key, below [`MACHINE_KEY`] or at the top of a test's hive, with one
/// key per backup, named like its file.
const ANCHORS: &str = "Backups";

/// The registry hive file that stands in for [`MACHINE_KEY`] in any folder
/// other than the real one.
const HIVE_FILE: &str = "anchors.dat";

/// Where the registry backups are kept: `%ProgramData%\WinMedic\backups`,
/// a folder WinMedic creates so that only Administrators and SYSTEM can
/// change it.
///
/// Older versions kept them in `%APPDATA%`, which every program the user runs
/// can write to. Nothing anchors those, so they are neither listed nor
/// imported.
pub fn default_backup_dir() -> PathBuf {
    program_data().join("WinMedic").join("backups")
}

/// `C:\ProgramData`, wherever this Windows keeps it. Asked from Windows rather
/// than read from `%ProgramData%`, which each account can set for itself.
#[cfg(windows)]
fn program_data() -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    let mut path: *mut u16 = std::ptr::null_mut();
    let status =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut path) };
    let found = (status >= 0 && !path.is_null()).then(|| {
        let len = (0..).take_while(|&i| unsafe { *path.add(i) } != 0).count();
        PathBuf::from(std::ffi::OsString::from_wide(unsafe {
            std::slice::from_raw_parts(path, len)
        }))
    });
    // Freed even after a failure, as the documentation asks.
    unsafe { CoTaskMemFree(path as *const std::ffi::c_void) };
    found.unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

#[cfg(not(windows))]
fn program_data() -> PathBuf {
    PathBuf::from(r"C:\ProgramData")
}

/// A backup, as its anchor records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRecord {
    /// The name of the file, which is also the name of its anchor.
    pub id: String,
    pub timestamp: String,
    pub description: String,
    pub key_path: String,
    pub file_path: String,
}

/// A backup's anchor: its record, and the SHA-256 of the file as WinMedic
/// wrote it.
struct Anchor {
    record: BackupRecord,
    sha256: String,
}

impl Anchor {
    /// The anchor `key` of the backup `id` in the folder `dir`.
    fn read(key: &RegKey, id: &str, dir: &Path) -> std::io::Result<Self> {
        Ok(Self {
            sha256: key.get_value("Sha256")?,
            record: BackupRecord {
                id: id.to_string(),
                timestamp: key.get_value("Time")?,
                description: key.get_value("Description")?,
                key_path: key.get_value("Key")?,
                file_path: dir.join(id).to_string_lossy().into_owned(),
            },
        })
    }
}

pub struct RegBackupManager {
    backup_dir: PathBuf,
    /// The hive file that holds the anchors of a folder other than the real
    /// one; `None` for the real folder, whose anchors are in
    /// `HKLM\SOFTWARE\WinMedic`.
    hive: Option<PathBuf>,
    /// Whether the folder, each new file and each anchor count only while
    /// nobody but Administrators and SYSTEM can change them. True for the
    /// real folder; a test's folder belongs to the account running it.
    checked: bool,
}

impl Default for RegBackupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RegBackupManager {
    pub fn new() -> Self {
        Self::with_dir(default_backup_dir())
    }

    /// Construct a manager rooted at an explicit directory.
    ///
    /// This is the seam tests use so they operate on a sandbox instead of the
    /// real `%ProgramData%\WinMedic\backups` and `HKLM\SOFTWARE\WinMedic`: any
    /// other folder keeps its anchors in a hive file of its own. Modules pass
    /// the real folder on as they got it from [`Self::new`].
    ///
    /// Building one touches nothing; the folder is created by the first
    /// backup. Modules build a manager to learn where backups go, so every
    /// test that built one created the real folder.
    pub fn with_dir(backup_dir: PathBuf) -> Self {
        let real = backup_dir == default_backup_dir();
        Self {
            hive: (!real).then(|| backup_dir.join(HIVE_FILE)),
            checked: real,
            backup_dir,
        }
    }

    /// For tests: a folder whose permissions, and those of its anchors, are
    /// checked like the real ones'.
    #[cfg(test)]
    fn checked_at(backup_dir: PathBuf) -> Self {
        Self {
            checked: true,
            ..Self::with_dir(backup_dir)
        }
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// The backup folder, created if it is missing, opened so that nobody can
    /// rename or remove it or a folder above it while the handle is open; and
    /// the path Windows resolves it to.
    ///
    /// Only a folder that nobody but Administrators and SYSTEM can change is
    /// written into: whoever can add or replace a file in it could swap a
    /// backup before WinMedic hashes it. One that someone else made is not
    /// taken over, since links of theirs may be in it and handles of theirs
    /// may still be open.
    fn open_folder_to_write(&self) -> Result<(File, PathBuf), String> {
        let unusable = |why: String| {
            format!(
                "The backup folder {} cannot be used: {why}",
                self.backup_dir.display()
            )
        };
        let created = if self.checked {
            acl::create_admin_only_dir(&self.backup_dir)
        } else {
            std::fs::create_dir_all(&self.backup_dir).map_err(|e| e.to_string())
        };
        created.map_err(unusable)?;
        let (folder, real) = open_held(&self.backup_dir, true).map_err(unusable)?;
        if self.checked
            && let Some(who) = acl::who_else_can_change_file(&folder, Part::Store)
                .map_err(|e| unusable(format!("its permissions could not be read ({e})")))?
        {
            return Err(unusable(format!(
                "{who} can change it; delete that folder, then repair again"
            )));
        }
        Ok((folder, real))
    }

    /// Export a Windows Registry Key into a standard .reg backup file before modification
    pub async fn export_key(
        &self,
        key_path: &str,
        description: &str,
    ) -> Result<BackupRecord, String> {
        self.export_key_with(&SystemCommandRunner::new(), key_path, description)
            .await
    }

    /// [`Self::export_key`] through `runner`, so a module's tests can answer
    /// `reg export` instead of running it.
    pub async fn export_key_with(
        &self,
        runner: &dyn CommandRunner,
        key_path: &str,
        description: &str,
    ) -> Result<BackupRecord, String> {
        let now = Local::now();
        let safe_key = key_path.replace(['\\', '/'], "_");
        let name = format!("reg_{}_{safe_key}.reg", now.format("%Y%m%d_%H%M%S"));
        // Held until the file is anchored, so the folder stays where it is.
        let (_folder, real) = self.open_folder_to_write()?;
        let file = real.join(&name);

        let output = runner
            .run(
                "reg.exe",
                &["export", key_path, &file.to_string_lossy(), "/y"],
                Duration::from_secs(15),
            )
            .await?;

        if !output.success {
            return Err(format!(
                "Registry export failed: {} ({})",
                output.stderr, output.stdout
            ));
        }
        self.keep(&real, name, key_path, description, now)
    }

    /// Back up one `REG_DWORD` value of `key_path` into a `.reg` file that
    /// holds that value alone.
    ///
    /// Some values sit in keys far too large to export:
    /// `SvcHostSplitThresholdInKB` is directly in
    /// `HKLM\SYSTEM\CurrentControlSet\Control`, and importing that whole key
    /// would turn back every other change made in it since. The file is
    /// written the way `reg export` writes one - UTF-16 with a byte order
    /// mark, the signature line, the key, the value - so a rollback imports
    /// it like any other backup, and it sets this value and nothing else.
    pub async fn export_value_with(
        &self,
        runner: &dyn CommandRunner,
        key_path: &str,
        value_name: &str,
        description: &str,
    ) -> Result<BackupRecord, String> {
        let value = registry::query_value(runner, key_path, value_name)
            .await?
            .ok_or_else(|| format!("{key_path}\\{value_name} does not exist"))?;
        let export = value_export(key_path, &value)?;

        let now = Local::now();
        let safe_key = key_path.replace(['\\', '/'], "_");
        let safe_value = value_name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
        let name = format!(
            "reg_{}_{safe_key}_{safe_value}.reg",
            now.format("%Y%m%d_%H%M%S")
        );
        let (_folder, real) = self.open_folder_to_write()?;
        let file = real.join(&name);
        if let Err(e) = std::fs::write(&file, export) {
            // A partial file is not a backup.
            let _ = std::fs::remove_file(&file);
            return Err(format!("{} could not be written: {e}", file.display()));
        }
        self.keep(&real, name, key_path, description, now)
    }

    /// Anchor the backup `name` that was just written into the folder `real`,
    /// or remove it.
    fn keep(
        &self,
        real: &Path,
        name: String,
        key_path: &str,
        description: &str,
        now: DateTime<Local>,
    ) -> Result<BackupRecord, String> {
        let file = real.join(&name);
        let kept = self.read_written(&file).and_then(|bytes| {
            let record = BackupRecord {
                file_path: self.backup_dir.join(&name).to_string_lossy().into_owned(),
                id: name,
                timestamp: now.format("%Y-%m-%d %H:%M:%S").to_string(),
                description: description.to_string(),
                key_path: key_path.to_string(),
            };
            self.anchor(&record, &sha256(&bytes)).map(|()| record)
        });
        if kept.is_err() {
            let _ = std::fs::remove_file(&file);
        }
        kept.map_err(|why| format!("The backup was not kept: {why}"))
    }

    /// What the file just written at `path` holds, read through a handle that
    /// keeps everyone from changing it meanwhile. In the real folder nobody
    /// but Administrators and SYSTEM may be able to change it, or it could
    /// have changed before it was opened.
    fn read_written(&self, path: &Path) -> Result<Vec<u8>, String> {
        let (file, bytes) = read_held(path)?;
        if self.checked
            && let Some(who) = acl::who_else_can_change_file(&file, Part::File).map_err(|e| {
                format!(
                    "the permissions of {} could not be read ({e})",
                    path.display()
                )
            })?
        {
            return Err(format!("{who} can change {}", path.display()));
        }
        Ok(bytes)
    }

    /// The key that holds the anchors, created if it is missing.
    fn create_anchors(&self) -> std::io::Result<RegKey> {
        let root = match &self.hive {
            Some(hive) => RegKey::load_app_key(hive, false)?,
            // A test that got here would change the anchors of the PC it runs on.
            None if cfg!(test) => return Err(std::io::Error::other("tests never write to HKLM")),
            None => acl::create_admin_only_key(MACHINE_KEY)?,
        };
        root.create_subkey(ANCHORS).map(|(key, _)| key)
    }

    /// The key that holds the anchors; `None` while there is none.
    fn open_anchors(&self) -> std::io::Result<Option<RegKey>> {
        let root = match &self.hive {
            Some(hive) if !hive.exists() => return Ok(None),
            Some(hive) => RegKey::load_app_key(hive, false),
            // A test that got here would read the anchors of the PC it runs on.
            None if cfg!(test) => return Ok(None),
            None => RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(MACHINE_KEY),
        };
        match root.and_then(|root| root.open_subkey(ANCHORS)) {
            Ok(key) => Ok(Some(key)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Where the anchors are, for messages.
    fn anchors_name(&self) -> String {
        match &self.hive {
            Some(hive) => format!(r"{}\{ANCHORS}", hive.display()),
            None => format!(r"HKLM\{MACHINE_KEY}\{ANCHORS}"),
        }
    }

    /// Why the anchor `key` is not to be trusted: someone besides
    /// Administrators and SYSTEM can change it. Only asked of the real
    /// anchors.
    fn untrusted(&self, key: &RegKey) -> Option<String> {
        if !self.checked {
            return None;
        }
        match acl::who_else_can_change_key(key) {
            Ok(None) => None,
            Ok(Some(who)) => Some(format!(
                "{who} can change its anchor in {}",
                self.anchors_name()
            )),
            Err(e) => Some(format!(
                "the permissions of its anchor in {} could not be read ({e})",
                self.anchors_name()
            )),
        }
    }

    /// Record `record` and the SHA-256 of its file where only Administrators
    /// and SYSTEM can change them.
    fn anchor(&self, record: &BackupRecord, sha256: &str) -> Result<(), String> {
        let failed = |e: std::io::Error| {
            format!(
                "its anchor in {} could not be written ({e})",
                self.anchors_name()
            )
        };
        let anchors = self.create_anchors().map_err(failed)?;
        let (key, _) = anchors.create_subkey(&record.id).map_err(failed)?;
        let written = match self.untrusted(&key) {
            Some(why) => Err(why),
            None => [
                ("Key", record.key_path.as_str()),
                ("Sha256", sha256),
                ("Time", record.timestamp.as_str()),
                ("Description", record.description.as_str()),
            ]
            .iter()
            .try_for_each(|(name, value)| key.set_value(name, value))
            .map_err(failed),
        };
        if written.is_err() {
            drop(key);
            let _ = anchors.delete_subkey(&record.id);
        }
        written
    }

    /// The anchor of the backup `id`. The real one counts only while nobody
    /// but Administrators and SYSTEM can change it.
    fn anchor_of(&self, id: &str) -> Result<Anchor, String> {
        let missing = || format!("it has no anchor in {}", self.anchors_name());
        let unreadable =
            |e: std::io::Error| format!("{} could not be read ({e})", self.anchors_name());
        let anchors = self
            .open_anchors()
            .map_err(unreadable)?
            .ok_or_else(missing)?;
        let key = anchors.open_subkey(id).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => missing(),
            _ => unreadable(e),
        })?;
        if let Some(why) = self.untrusted(&key) {
            return Err(why);
        }
        Anchor::read(&key, id, &self.backup_dir)
            .map_err(|e| format!("its anchor in {} is incomplete ({e})", self.anchors_name()))
    }

    /// Import / restore a .reg file from the backup folder.
    pub async fn restore_key(&self, file_path: &str) -> Result<String, String> {
        self.restore_key_with(&SystemCommandRunner::new(), file_path)
            .await
    }

    /// [`Self::restore_key`] through `runner`.
    ///
    /// `reg import` writes whatever the file says with WinMedic's
    /// Administrator rights. So the file is imported only when it is in the
    /// backup folder, its anchor is there and trusted, it hashes to what the
    /// anchor recorded, and it holds nothing but the anchored key and the
    /// keys below it. It is held open until `reg import` is done, so it
    /// cannot change after it was checked.
    pub async fn restore_key_with(
        &self,
        runner: &dyn CommandRunner,
        file_path: &str,
    ) -> Result<String, String> {
        let refused = |why: String| format!("{file_path} was not imported: {why}.");
        let path = Path::new(file_path);
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|_| path.parent() == Some(self.backup_dir.as_path()))
            .ok_or_else(|| refused(format!("it is not in {}", self.backup_dir.display())))?;
        let anchor = self.anchor_of(id).map_err(refused)?;
        let (_folder, real) = open_held(&self.backup_dir, true).map_err(refused)?;
        let file = real.join(id);
        let (_held, bytes) = read_held(&file).map_err(refused)?;
        if sha256(&bytes) != anchor.sha256 {
            return Err(refused(
                "it is not the file WinMedic wrote, its content has changed since".to_string(),
            ));
        }
        check_contents(&bytes, &anchor.record.key_path).map_err(refused)?;

        let output = runner
            .run(
                "reg.exe",
                &["import", &file.to_string_lossy()],
                Duration::from_secs(15),
            )
            .await?;

        if output.success {
            Ok(format!("Successfully restored registry from {}", file_path))
        } else {
            Err(format!(
                "Registry import failed: {} ({})",
                output.stderr, output.stdout
            ))
        }
    }

    /// Every anchored backup, oldest first; none if the anchors cannot be
    /// read.
    ///
    /// For display: a rollback reads the anchor again and checks it.
    pub fn list_backups(&self) -> Vec<BackupRecord> {
        let Ok(Some(anchors)) = self.open_anchors() else {
            return Vec::new();
        };
        let mut records: Vec<BackupRecord> = anchors
            .enum_keys()
            .flatten()
            .filter_map(|id| {
                let key = anchors.open_subkey(&id).ok()?;
                Anchor::read(&key, &id, &self.backup_dir).ok()
            })
            .map(|anchor| anchor.record)
            .collect();
        records.sort_by(|a, b| (&a.timestamp, &a.id).cmp(&(&b.timestamp, &b.id)));
        records
    }

    /// Write `bytes` into the backup folder as `name`, for a copy that
    /// WinMedic never reads back, such as the hosts file's. Its path is
    /// named like a backup's, from the folder as this manager was given it.
    pub fn save_copy(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
        let (_folder, real) = self.open_folder_to_write()?;
        let path = real.join(name);
        std::fs::write(&path, bytes).map_err(|e| {
            // A partial copy is not a backup.
            let _ = std::fs::remove_file(&path);
            format!("{} could not be written ({e})", path.display())
        })?;
        Ok(self.backup_dir.join(name))
    }
}

/// Delete `HKLM\SOFTWARE\WinMedic` with every anchor in it, for
/// `--uninstall --purge`; whether it was there.
pub fn delete_machine_anchors() -> Result<bool, String> {
    match RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey_all(MACHINE_KEY) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

/// `bytes` hashed with SHA-256, in lower-case hex.
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `path`, opened so that nobody can write, rename or delete it until the
/// handle is dropped, nor rename or remove a folder above it; and the path
/// Windows resolves it to. A folder stays open for files to be created and
/// deleted in it. `path` itself must not be a link: it is not followed.
fn open_held(path: &Path, folder: bool) -> Result<(File, PathBuf), String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let (share, flags) = if folder {
        (
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        )
    } else {
        (FILE_SHARE_READ, FILE_FLAG_OPEN_REPARSE_POINT)
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(share)
        .custom_flags(flags)
        .open(path)
        .map_err(|e| format!("{} could not be opened ({e})", path.display()))?;
    let attributes = file
        .metadata()
        .map_err(|e| format!("{} could not be read ({e})", path.display()))?
        .file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{} is a link", path.display()));
    }
    let real = final_path(&file)
        .map_err(|e| format!("the path of {} could not be read ({e})", path.display()))?;
    Ok((file, real))
}

/// The path of the file or folder `file` is open on, with every link on the
/// way resolved, without the `\\?\` in front.
fn final_path(file: &File) -> std::io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    let mut buffer = vec![0u16; 512];
    loop {
        // Flags 0: the normalized name, with a drive letter.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                0,
            )
        } as usize;
        match len {
            0 => return Err(std::io::Error::last_os_error()),
            len if len < buffer.len() => {
                buffer.truncate(len);
                let path = PathBuf::from(std::ffi::OsString::from_wide(&buffer));
                return Ok(acl::plain(&path));
            }
            // Too small: `len` is the size it needs, its NUL included.
            len => buffer.resize(len, 0),
        }
    }
}

/// The file at `path`, held as [`open_held`] holds it, and what it holds. It
/// must be at `path` itself, not reached through a link.
fn read_held(path: &Path) -> Result<(File, Vec<u8>), String> {
    let (mut file, real) = open_held(path, false)?;
    let same = real
        .to_string_lossy()
        .eq_ignore_ascii_case(&path.to_string_lossy());
    if !same {
        return Err(format!("{} leads to {}", path.display(), real.display()));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("{} could not be read ({e})", path.display()))?;
    Ok((file, bytes))
}

/// Why `reg import` of `bytes` would write more than the key `key_path` and
/// the keys below it, or import something other than what `reg export`
/// wrote.
///
/// `reg export` writes UTF-16 with a byte order mark, the line
/// [`REG_EXPORT_SIGNATURE`], and then each key as a `[HKEY_...\path]` line
/// followed by its values. A value goes to the key of the last such line, so
/// the key lines decide what an import writes to. A `[-...]` line deletes a
/// key; `reg export` never writes one.
fn check_contents(bytes: &[u8], key_path: &str) -> Result<(), String> {
    let text = bytes
        .strip_prefix(b"\xFF\xFE")
        .filter(|body| body.len() % 2 == 0)
        .and_then(|body| {
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&pair| u16::from_le_bytes(pair))
                .collect();
            String::from_utf16(&units).ok()
        })
        .ok_or("it is not the UTF-16 text `reg export` writes")?;
    if text.contains('\0') {
        return Err("it contains a NUL character".to_string());
    }
    let key = key_name(key_path);
    if !key.contains('\\') {
        return Err(format!("its record names a whole root key, {key_path}"));
    }
    let below = format!("{key}\\");

    // Split at either, so that a line ended by a lone CR or LF counts too.
    let mut lines = text
        .split(['\r', '\n'])
        .filter(|line| !line.trim().is_empty());
    if lines.next() != Some(REG_EXPORT_SIGNATURE) {
        return Err(format!("it does not start with \"{REG_EXPORT_SIGNATURE}\""));
    }
    let mut in_key = false;
    for line in lines {
        let Some(header) = line.trim_start().strip_prefix('[') else {
            if !in_key {
                return Err(format!("\"{line}\" comes before the first key"));
            }
            continue;
        };
        let name = header
            .trim_end()
            .strip_suffix(']')
            .ok_or_else(|| format!("\"{line}\" is not a key"))?;
        if let Some(deleted) = name.strip_prefix('-') {
            return Err(format!("it deletes the key {deleted}"));
        }
        let named = key_name(name);
        if named != key && !named.starts_with(&below) {
            return Err(format!(
                "it writes to {name}, which is neither {key_path} nor a key below it"
            ));
        }
        in_key = true;
    }
    Ok(())
}

/// What `reg export` would write for `key_path` if `value` were all it held:
/// UTF-16 with a byte order mark, the signature, the key and the value.
/// Only for `REG_DWORD`, the one kind a repair backs up on its own.
fn value_export(key_path: &str, value: &RegValue) -> Result<Vec<u8>, String> {
    let number = (value.kind == "REG_DWORD")
        .then(|| value.number())
        .flatten()
        .and_then(|number| u32::try_from(number).ok())
        .ok_or_else(|| {
            format!(
                "{} is {} {}, not a number a REG_DWORD holds",
                value.name, value.kind, value.data
            )
        })?;
    let key = registry::expand_hive(key_path.trim_end_matches('\\'));
    let name = value.name.replace('\\', r"\\").replace('"', "\\\"");
    let text =
        format!("{REG_EXPORT_SIGNATURE}\r\n\r\n[{key}]\r\n\"{name}\"=dword:{number:08x}\r\n\r\n");
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    Ok(bytes)
}

/// `path` with its root key spelt out, without a trailing backslash and in
/// lower case: the form in which two names of one key are equal.
fn key_name(path: &str) -> String {
    let path = path.trim_end_matches('\\');
    let (root, rest) = match path.split_once('\\') {
        Some((root, rest)) => (root, Some(rest)),
        None => (path, None),
    };
    let root = match root.to_ascii_uppercase().as_str() {
        "HKLM" => "HKEY_LOCAL_MACHINE",
        "HKCU" => "HKEY_CURRENT_USER",
        "HKCR" => "HKEY_CLASSES_ROOT",
        "HKU" => "HKEY_USERS",
        "HKCC" => "HKEY_CURRENT_CONFIG",
        _ => root,
    };
    match rest {
        Some(rest) => format!("{root}\\{rest}"),
        None => root.to_string(),
    }
    .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use std::sync::Mutex;

    /// Minimal scoped temp directory; the crate has no dev-dependency on `tempfile`.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = format!(
                "winmedic_regbackup_{}_{}_{:?}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// The Fast Startup key as `reg export` wrote it on Windows 11.
    const POWER_EXPORT: &[u8] =
        include_bytes!("../../tests/fixtures/files/reg_export_session_manager_power.bin");
    const POWER_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power";

    fn text_of(export: &[u8]) -> String {
        let units: Vec<u16> = export[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect();
        String::from_utf16(&units).unwrap()
    }

    /// `text` encoded the way `reg export` writes it.
    fn utf16(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        bytes
    }

    /// The export of the Fast Startup key with `extra` after its last value.
    fn power_export_and(extra: &str) -> Vec<u8> {
        utf16(&format!("{}{extra}", text_of(POWER_EXPORT)))
    }

    #[test]
    fn an_export_of_the_key_and_the_keys_below_it_is_importable() {
        for key in [
            POWER_KEY,
            r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Power\",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
        ] {
            assert_eq!(check_contents(POWER_EXPORT, key), Ok(()), "{key}");
        }
        let below = power_export_and(
            "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\\PowerSettings]\r\n\"x\"=dword:00000001\r\n\r\n",
        );
        assert_eq!(check_contents(&below, POWER_KEY), Ok(()));
    }

    #[test]
    fn an_export_that_writes_to_another_key_is_not_importable() {
        let run_key = power_export_and(
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n\"x\"=\"C:\\\\x.exe\"\r\n\r\n",
        );
        let refused = check_contents(&run_key, POWER_KEY).unwrap_err();
        assert!(
            refused.contains(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            "{refused}"
        );

        let other = [
            // A key whose name only starts like the backed-up one.
            power_export_and(
                "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PowerX]\r\n",
            ),
            // The key itself, deleted.
            power_export_and(
                "[-HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power]\r\n",
            ),
            // A key line after a lone CR, or indented.
            utf16(&format!(
                "{}\r[HKEY_LOCAL_MACHINE\\SOFTWARE\\X]\r\n",
                text_of(POWER_EXPORT).trim_end()
            )),
            power_export_and("  [HKEY_LOCAL_MACHINE\\SOFTWARE\\X]\r\n"),
            // The same key under another of its names.
            utf16(&text_of(POWER_EXPORT).replace("CurrentControlSet", "ControlSet001")),
        ];
        for export in other {
            assert!(
                check_contents(&export, POWER_KEY).is_err(),
                "{}",
                text_of(&export)
                    .lines()
                    .filter(|line| line.contains('['))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
    }

    #[test]
    fn only_what_reg_export_writes_is_importable() {
        let text = text_of(POWER_EXPORT);
        let not_exports = [
            // UTF-8 without a byte order mark, and UTF-16 cut in a character.
            text.as_bytes().to_vec(),
            POWER_EXPORT[..POWER_EXPORT.len() - 1].to_vec(),
            // Another first line.
            utf16(&text.replacen(REG_EXPORT_SIGNATURE, "", 1)),
            utf16(&text.replacen(REG_EXPORT_SIGNATURE, "REGEDIT4", 1)),
            // A value before the first key, and a NUL character.
            utf16(&text.replacen("\r\n\r\n[", "\r\n\r\n\"x\"=dword:00000001\r\n[", 1)),
            utf16(&text.replacen("\"AcPolicy\"", "\"Ac\0Policy\"", 1)),
        ];
        for export in not_exports {
            assert!(check_contents(&export, POWER_KEY).is_err());
        }
        // A record that names a whole root key allows nothing.
        assert!(check_contents(POWER_EXPORT, "HKLM").is_err());
    }

    /// `reg export` writing `export` to the file it names, and `reg import`.
    fn reg(export: &[u8]) -> MockCommandRunner {
        let runner = MockCommandRunner::new();
        runner.add_written_file("reg.exe export", 2, export);
        runner.add_response("reg.exe export", CmdOutput::ok(""));
        runner.add_response("reg.exe import", CmdOutput::ok(""));
        runner
    }

    fn imported(runner: &MockCommandRunner) -> bool {
        runner
            .executed()
            .iter()
            .any(|c| c.starts_with("reg.exe import"))
    }

    /// Where Windows has `path`, which is what `reg import` is given.
    fn resolved(path: &str) -> String {
        acl::plain(&std::fs::canonicalize(path).unwrap())
            .to_string_lossy()
            .into_owned()
    }

    #[tokio::test]
    async fn a_backup_is_anchored_listed_and_imported() {
        let dir = TempDir::new("anchored");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = reg(POWER_EXPORT);

        let record = mgr
            .export_key_with(&runner, POWER_KEY, "Before turning Fast Startup off")
            .await
            .unwrap();
        assert_eq!(record.key_path, POWER_KEY);
        assert_eq!(std::fs::read(&record.file_path).unwrap(), POWER_EXPORT);
        // Read from the anchors, as the next start of the window reads them.
        assert_eq!(
            RegBackupManager::with_dir(dir.path.clone()).list_backups(),
            std::slice::from_ref(&record)
        );

        mgr.restore_key_with(&runner, &record.file_path)
            .await
            .unwrap();
        assert_eq!(
            runner.executed().last(),
            Some(&format!("reg.exe import {}", resolved(&record.file_path)))
        );
    }

    #[tokio::test]
    async fn a_backup_reg_export_did_not_write_is_not_kept() {
        let dir = TempDir::new("not_written");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let refused = mgr
            .export_key_with(
                &MockCommandRunner::with_default_success(),
                POWER_KEY,
                "test",
            )
            .await
            .unwrap_err();
        assert!(refused.starts_with("The backup was not kept"), "{refused}");
        assert!(mgr.list_backups().is_empty());
    }

    #[tokio::test]
    async fn a_backup_whose_content_changed_is_not_imported() {
        let dir = TempDir::new("changed");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = reg(POWER_EXPORT);
        let record = mgr
            .export_key_with(&runner, POWER_KEY, "Before turning Fast Startup off")
            .await
            .unwrap();

        // Fast Startup on again: still that key alone, which the content
        // check lets through.
        let changed = utf16(&text_of(POWER_EXPORT).replace(
            "\"HiberbootEnabled\"=dword:00000000",
            "\"HiberbootEnabled\"=dword:00000001",
        ));
        assert_eq!(check_contents(&changed, POWER_KEY), Ok(()));
        std::fs::write(&record.file_path, changed).unwrap();

        let refused = mgr
            .restore_key_with(&runner, &record.file_path)
            .await
            .unwrap_err();
        assert!(refused.contains("content has changed"), "{refused}");
        assert!(!imported(&runner));
    }

    #[tokio::test]
    async fn a_backup_without_an_anchor_is_not_imported() {
        let dir = TempDir::new("unanchored");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = reg(POWER_EXPORT);

        // A good export WinMedic did not write.
        let stray = dir.path.join("reg_20261009_120000_stray.reg");
        std::fs::write(&stray, POWER_EXPORT).unwrap();
        let refused = mgr
            .restore_key_with(&runner, &stray.to_string_lossy())
            .await
            .unwrap_err();
        assert!(refused.contains("has no anchor"), "{refused}");

        // One it wrote, whose anchor is gone.
        let record = mgr
            .export_key_with(&runner, POWER_KEY, "test")
            .await
            .unwrap();
        mgr.create_anchors()
            .unwrap()
            .delete_subkey(&record.id)
            .unwrap();
        let refused = mgr
            .restore_key_with(&runner, &record.file_path)
            .await
            .unwrap_err();
        assert!(refused.contains("has no anchor"), "{refused}");
        assert!(mgr.list_backups().is_empty());
        assert!(!imported(&runner));
    }

    /// The content check reads the key from the anchor, not from the file.
    #[tokio::test]
    async fn a_backup_may_only_write_the_key_its_anchor_names() {
        let dir = TempDir::new("other_key");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = reg(POWER_EXPORT);
        let record = mgr
            .export_key_with(
                &runner,
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                "test",
            )
            .await
            .unwrap();

        let refused = mgr
            .restore_key_with(&runner, &record.file_path)
            .await
            .unwrap_err();
        assert!(
            refused.contains("Session Manager\\Power, which is neither"),
            "{refused}"
        );
        assert!(!imported(&runner));
    }

    /// What `reg export` writes for a value whose data holds a line break and
    /// a key line: anchored as written, and still not imported.
    #[tokio::test]
    async fn the_content_check_still_guards_an_anchored_backup() {
        let dir = TempDir::new("injected");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = reg(&power_export_and(
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\X]\r\n\"x\"=dword:00000001\r\n",
        ));
        let record = mgr
            .export_key_with(&runner, POWER_KEY, "test")
            .await
            .unwrap();

        let refused = mgr
            .restore_key_with(&runner, &record.file_path)
            .await
            .unwrap_err();
        assert!(
            refused.contains(r"HKEY_LOCAL_MACHINE\SOFTWARE\X"),
            "{refused}"
        );
        assert!(!imported(&runner));
    }

    #[tokio::test]
    async fn only_a_file_in_the_backup_folder_is_imported() {
        let dir = TempDir::new("elsewhere");
        let mgr = RegBackupManager::with_dir(dir.path.join("backups"));
        let runner = reg(POWER_EXPORT);
        let record = mgr
            .export_key_with(&runner, POWER_KEY, "test")
            .await
            .unwrap();

        // The same file under the same name, beside the folder.
        let beside = dir.path.join(&record.id);
        std::fs::copy(&record.file_path, &beside).unwrap();
        let sneaky = dir.path.join("backups").join("..").join(&record.id);
        for path in [&beside, &sneaky] {
            let refused = mgr
                .restore_key_with(&runner, &path.to_string_lossy())
                .await
                .unwrap_err();
            assert!(refused.contains("it is not in"), "{refused}");
        }
        assert!(!imported(&runner));
    }

    /// `reg.exe` that writes `export` like `reg export`, and that, while it
    /// runs, tries what someone else could do to the file and its folder.
    /// What worked is kept in `worked`.
    struct Meddling {
        export: Vec<u8>,
        worked: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl CommandRunner for Meddling {
        async fn run(&self, _: &str, args: &[&str], _: Duration) -> Result<CmdOutput, String> {
            let (file, attempts): (&Path, &[&str]) = match args {
                ["export", _, file, ..] => {
                    std::fs::write(file, &self.export).unwrap();
                    // Nothing holds the new file yet; the folder is held.
                    (Path::new(file), &["rename the folder"])
                }
                ["import", file] => (
                    Path::new(file),
                    &["write", "delete", "rename", "rename the folder"],
                ),
                _ => return Err(format!("not reg export or import: {args:?}")),
            };
            let folder = file.parent().unwrap();
            for attempt in attempts {
                let result = match *attempt {
                    "write" => std::fs::OpenOptions::new().write(true).open(file).map(drop),
                    "delete" => std::fs::remove_file(file),
                    "rename" => std::fs::rename(file, file.with_extension("moved")),
                    _ => std::fs::rename(folder, folder.with_extension("moved")),
                };
                if result.is_ok() {
                    self.worked
                        .lock()
                        .unwrap()
                        .push(format!("{attempt} during {}", args[0]));
                }
            }
            Ok(CmdOutput::ok(""))
        }

        async fn run_streaming(
            &self,
            program: &str,
            args: &[&str],
            _: Option<tokio::sync::mpsc::Sender<String>>,
            timeout: Duration,
        ) -> Result<CmdOutput, String> {
            self.run(program, args, timeout).await
        }
    }

    #[tokio::test]
    async fn the_backup_and_its_folder_stay_put_while_reg_runs() {
        let dir = TempDir::new("held");
        let mgr = RegBackupManager::with_dir(dir.path.join("backups"));
        let meddling = Meddling {
            export: POWER_EXPORT.to_vec(),
            worked: Mutex::new(Vec::new()),
        };

        let record = mgr
            .export_key_with(&meddling, POWER_KEY, "test")
            .await
            .unwrap();
        mgr.restore_key_with(&meddling, &record.file_path)
            .await
            .unwrap();

        assert_eq!(meddling.worked.lock().unwrap().as_slice(), &[] as &[String]);
        assert_eq!(std::fs::read(&record.file_path).unwrap(), POWER_EXPORT);
    }

    /// `C:\` and the temp folder let the account running the tests do
    /// anything, so the checks the real folder gets turn this one down:
    /// nothing is written into it.
    #[tokio::test]
    async fn a_folder_others_can_change_is_not_written_into() {
        let dir = TempDir::new("checked");
        let mgr = RegBackupManager::checked_at(dir.path.clone());
        let runner = reg(POWER_EXPORT);

        let refused = mgr
            .export_key_with(&runner, POWER_KEY, "test")
            .await
            .unwrap_err();
        assert!(refused.contains("cannot be used"), "{refused}");
        assert!(refused.contains("delete that folder"), "{refused}");
        assert!(mgr.save_copy("hosts_20261009_120000.bak", b"x").is_err());
        assert!(runner.executed().is_empty());
        assert_eq!(std::fs::read_dir(&dir.path).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_backup_folder_that_is_a_link_is_not_used() {
        use std::os::windows::process::CommandExt;

        let dir = TempDir::new("junction");
        let target = dir.path.join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path.join("backups");
        let made =
            std::process::Command::new(crate::utils::cmd::system_program("cmd.exe").unwrap())
                .args(["/c", "mklink", "/J"])
                .arg(&link)
                .arg(&target)
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
                .output()
                .unwrap();
        assert!(made.status.success(), "{made:?}");

        let mgr = RegBackupManager::with_dir(link.clone());
        let runner = reg(POWER_EXPORT);
        let refused = mgr
            .export_key_with(&runner, POWER_KEY, "test")
            .await
            .unwrap_err();
        assert!(refused.contains("is a link"), "{refused}");
        assert!(runner.executed().is_empty());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        // The junction itself, not what it points at.
        std::fs::remove_dir(&link).unwrap();
    }

    /// Every key in a hive file lets Everyone change it, so the checks the
    /// real anchors get turn this one down.
    #[tokio::test]
    async fn an_anchor_others_can_change_is_not_trusted() {
        let dir = TempDir::new("anchor_rights");
        let runner = reg(POWER_EXPORT);
        let record = RegBackupManager::with_dir(dir.path.clone())
            .export_key_with(&runner, POWER_KEY, "test")
            .await
            .unwrap();
        let mgr = RegBackupManager::checked_at(dir.path.clone());

        let refused = mgr
            .restore_key_with(&runner, &record.file_path)
            .await
            .unwrap_err();
        assert!(refused.contains("can change its anchor"), "{refused}");
        assert!(!imported(&runner));
    }

    #[test]
    fn backups_are_listed_oldest_first() {
        let dir = TempDir::new("order");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let record = |id: &str, timestamp: &str| BackupRecord {
            id: id.to_string(),
            timestamp: timestamp.to_string(),
            description: format!("backup {id}"),
            key_path: POWER_KEY.to_string(),
            file_path: dir.path.join(id).to_string_lossy().into_owned(),
        };
        let records = [
            record("reg_b.reg", "2026-10-09 08:00:00"),
            record("reg_c.reg", "2026-10-08 12:00:00"),
            record("reg_a.reg", "2026-10-09 08:00:00"),
        ];
        for record in &records {
            mgr.anchor(record, &sha256(POWER_EXPORT)).unwrap();
        }

        let ids: Vec<String> = mgr.list_backups().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, ["reg_c.reg", "reg_a.reg", "reg_b.reg"]);
    }

    #[test]
    fn only_the_real_folder_is_checked_and_anchored_in_hklm() {
        let real = default_backup_dir();
        assert!(real.is_absolute(), "{}", real.display());
        assert!(real.ends_with(r"WinMedic\backups"), "{}", real.display());
        let mgr = RegBackupManager::new();
        assert!(mgr.checked);
        assert_eq!(mgr.hive, None);

        let test = RegBackupManager::with_dir(std::env::temp_dir());
        assert!(!test.checked);
        assert_eq!(test.hive, Some(std::env::temp_dir().join(HIVE_FILE)));
    }

    #[test]
    fn a_test_cannot_reach_the_real_anchors() {
        let mgr = RegBackupManager::new();
        assert!(mgr.create_anchors().is_err());
        assert!(mgr.open_anchors().unwrap().is_none());
    }

    #[test]
    fn building_a_manager_creates_no_folder() {
        let dir = std::env::temp_dir().join(format!(
            "winmedic_regbackup_not_created_{}",
            std::process::id()
        ));
        let mgr = RegBackupManager::with_dir(dir.join("backups"));
        assert!(mgr.list_backups().is_empty());
        assert!(!dir.exists());
    }

    /// `reg query` of the Fast Startup key on Windows 11, the key the export
    /// above was taken of.
    const POWER_QUERY: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_session_manager_power.bin");

    #[test]
    fn a_value_is_written_as_reg_export_writes_it() {
        let export = text_of(POWER_EXPORT);
        let keys = registry::parse_reg_query(&crate::utils::decode::decode_output(POWER_QUERY));
        // Values both captures agree on; the boot times changed in between.
        for name in [
            "HBFlagsSwitch",
            "HiberbootEnabled",
            "SleepStudyDeviceAccountingLevel",
            "WatchdogResumeTimeout",
            "WatchdogSleepTimeout",
            "TotalResumeTime",
        ] {
            let value = registry::find(&keys, POWER_KEY, name).unwrap();
            let written = text_of(&value_export(POWER_KEY, value).unwrap());
            let mut lines = written.lines().filter(|line| !line.is_empty());
            assert_eq!(lines.next(), Some(REG_EXPORT_SIGNATURE));
            for line in lines {
                assert!(export.lines().any(|real| real == line), "{name}: {line}");
            }
        }
    }

    /// `reg query ... /v SvcHostSplitThresholdInKB` on Windows 11, with the
    /// value a tuning tool had left on 2026-10-08: 32 GB.
    fn split_threshold_query() -> String {
        crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/reg_query_svchost_split_threshold.bin"
        ))
        .replace("0x380000", "0x2000000")
    }

    const CONTROL_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control";

    #[tokio::test]
    async fn a_value_backup_holds_that_value_alone_and_is_imported() {
        let dir = TempDir::new("value");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = MockCommandRunner::new();
        runner.add_response(
            "query HKLM\\SYSTEM\\CurrentControlSet\\Control /v SvcHostSplitThresholdInKB",
            CmdOutput::ok(split_threshold_query()),
        );
        runner.add_response("reg.exe import", CmdOutput::ok(""));

        let record = mgr
            .export_value_with(
                &runner,
                CONTROL_KEY,
                "SvcHostSplitThresholdInKB",
                "Before resetting SvcHostSplitThresholdInKB",
            )
            .await
            .unwrap();
        let bytes = std::fs::read(&record.file_path).unwrap();
        assert_eq!(
            text_of(&bytes),
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control]\r\n\"SvcHostSplitThresholdInKB\"=dword:02000000\r\n\r\n"
        );
        assert_eq!(record.key_path, CONTROL_KEY);
        assert_eq!(mgr.list_backups(), std::slice::from_ref(&record));

        mgr.restore_key_with(&runner, &record.file_path)
            .await
            .unwrap();
        assert!(
            runner
                .executed()
                .contains(&format!("reg.exe import {}", resolved(&record.file_path)))
        );
    }

    #[tokio::test]
    async fn no_value_backup_is_kept_when_there_is_nothing_to_keep() {
        let dir = TempDir::new("value_refused");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = MockCommandRunner::new();
        runner.add_response(
            "/v Missing",
            CmdOutput::with_output(1, "\r\n\r\n", "FEHLER"),
        );
        runner.add_response(
            "/v Text",
            CmdOutput::ok(
                "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\r\n    Text    REG_SZ    x\r\n\r\n",
            ),
        );

        for name in ["Missing", "Text", "Unanswered"] {
            let refused = mgr
                .export_value_with(&runner, CONTROL_KEY, name, "test")
                .await
                .unwrap_err();
            assert!(refused.contains(name), "{refused}");
        }
        assert!(mgr.list_backups().is_empty());
        assert_eq!(std::fs::read_dir(&dir.path).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_value_backup_into_a_folder_others_can_change_is_not_kept() {
        let dir = TempDir::new("value_checked");
        let mgr = RegBackupManager::checked_at(dir.path.clone());
        let runner = MockCommandRunner::new();
        runner.add_response(
            "/v SvcHostSplitThresholdInKB",
            CmdOutput::ok(split_threshold_query()),
        );
        let refused = mgr
            .export_value_with(&runner, CONTROL_KEY, "SvcHostSplitThresholdInKB", "test")
            .await
            .unwrap_err();
        assert!(refused.contains("cannot be used"), "{refused}");
        assert_eq!(std::fs::read_dir(&dir.path).unwrap().count(), 0);
    }
}
