use crate::utils::acl;
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::registry::{self, RegValue};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// File name of the backup index inside [`RegBackupManager::backup_dir`].
pub const INDEX_FILE_NAME: &str = "index.json";

/// The first line of every file `reg export` writes.
const REG_EXPORT_SIGNATURE: &str = "Windows Registry Editor Version 5.00";

/// Where the registry backups are kept: `%ProgramData%\WinMedic\backups`.
///
/// A rollback imports them with Administrator rights, so they live where
/// WinMedic can make sure that only Administrators and SYSTEM can change
/// them. Older versions kept them in `%APPDATA%`, which every program the
/// user runs can write to.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecord {
    pub id: String,
    pub timestamp: String,
    pub description: String,
    pub key_path: String,
    pub file_path: String,
}

pub struct RegBackupManager {
    backup_dir: PathBuf,
    /// Whether the folder is kept changeable by Administrators and SYSTEM
    /// only, and a backup is imported only when it still is. True for
    /// [`default_backup_dir`]; a folder a test hands in is used as it is.
    protected: bool,
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
    /// This is the seam the index tests use so they operate on a sandbox instead
    /// of the real `%ProgramData%\WinMedic\backups`. Only that real folder is
    /// protected (see [`Self::ensure_backup_dir`]); modules pass it on as
    /// they got it from [`Self::new`].
    ///
    /// Building one touches nothing; the folder is created by the first
    /// backup. Modules build a manager to learn where backups go, so every
    /// test that built one created the real folder.
    pub fn with_dir(backup_dir: PathBuf) -> Self {
        let protected = backup_dir == default_backup_dir();
        Self {
            backup_dir,
            protected,
        }
    }

    /// For tests: a folder treated like the real one, whose permissions are
    /// set and checked.
    #[cfg(test)]
    fn protected_at(backup_dir: PathBuf) -> Self {
        Self {
            backup_dir,
            protected: true,
        }
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    fn index_path(&self) -> PathBuf {
        self.backup_dir.join(INDEX_FILE_NAME)
    }

    /// Create the backup folder if it is missing.
    ///
    /// The real one is created owned by Administrators and changeable by
    /// Administrators and SYSTEM only, and checked: someone else may have
    /// made a folder of that name first, and then it is not used.
    pub fn ensure_backup_dir(&self) -> Result<(), String> {
        let ready = if self.protected {
            acl::create_admin_only_dir(&self.backup_dir)
        } else {
            std::fs::create_dir_all(&self.backup_dir).map_err(|e| e.to_string())
        };
        ready.map_err(|e| {
            format!(
                "The backup folder {} cannot be used: {e}",
                self.backup_dir.display()
            )
        })
    }

    /// In the real folder: hand `path` to Administrators and check that
    /// nobody else can change it, since a rollback trusts it.
    fn protect(&self, path: &Path) -> Result<(), String> {
        if !self.protected {
            return Ok(());
        }
        // A failure shows in the check that follows.
        let _ = acl::hand_to_administrators(path);
        match acl::admin_only_problem(path) {
            None => Ok(()),
            Some(problem) => Err(problem),
        }
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
        let timestamp_slug = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let safe_key = key_path.replace(['\\', '/'], "_");
        let file_name = format!("reg_{}_{}.reg", timestamp_slug, safe_key);
        let file_path = self.backup_dir.join(file_name);
        self.ensure_backup_dir()?;

        let output = runner
            .run(
                "reg.exe",
                &["export", key_path, &file_path.to_string_lossy(), "/y"],
                Duration::from_secs(15),
            )
            .await?;

        if !output.success {
            return Err(format!(
                "Registry export failed: {} ({})",
                output.stderr, output.stdout
            ));
        }
        self.keep(file_path, timestamp_slug, key_path, description)
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

        let timestamp_slug = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let safe_key = key_path.replace(['\\', '/'], "_");
        let safe_value = value_name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
        let file_name = format!("reg_{timestamp_slug}_{safe_key}_{safe_value}.reg");
        let file_path = self.backup_dir.join(file_name);
        self.ensure_backup_dir()?;
        if let Err(e) = std::fs::write(&file_path, export) {
            // A partial file is not a backup.
            let _ = std::fs::remove_file(&file_path);
            return Err(format!("{} could not be written: {e}", file_path.display()));
        }
        self.keep(file_path, timestamp_slug, key_path, description)
    }

    /// A backup file just written to `file_path`: protected in the real
    /// folder and recorded in the index.
    fn keep(
        &self,
        file_path: PathBuf,
        timestamp_slug: String,
        key_path: &str,
        description: &str,
    ) -> Result<BackupRecord, String> {
        if let Err(problem) = self.protect(&file_path) {
            let _ = std::fs::remove_file(&file_path);
            return Err(format!(
                "The backup was not kept: {problem}, so a rollback would not import it."
            ));
        }

        let record = BackupRecord {
            id: timestamp_slug,
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            description: description.to_string(),
            key_path: key_path.to_string(),
            file_path: file_path.to_string_lossy().to_string(),
        };

        // A backup that never reaches the index is invisible to the rollback UI,
        // so callers must treat it as a failed export. The message names the
        // .reg file that *was* written so the user is not left stranded.
        self.save_record_index(&record).map_err(|e| {
            format!(
                "Backup file '{}' was written but could not be recorded in the index: {}. \
                 It can still be restored manually with `reg import`.",
                file_path.display(),
                e
            )
        })?;

        Ok(record)
    }

    /// `file_path` if it is a `.reg` file directly in the backup folder.
    ///
    /// The path comes from `index.json`, and `reg import` of whatever it
    /// names runs with WinMedic's rights.
    pub fn backup_file(&self, file_path: &str) -> Result<PathBuf, String> {
        let file = Path::new(file_path);
        let is_reg = file
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("reg"));
        let inside = match (
            file.parent().map(std::fs::canonicalize),
            std::fs::canonicalize(&self.backup_dir),
        ) {
            (Some(Ok(parent)), Ok(dir)) => parent == dir,
            _ => false,
        };
        if is_reg && inside && file.is_file() {
            Ok(file.to_path_buf())
        } else {
            Err(format!(
                "{} is not a registry backup in {}; nothing was imported.",
                file.display(),
                self.backup_dir.display()
            ))
        }
    }

    /// Import / restore a .reg file from the backup folder.
    pub async fn restore_key(&self, file_path: &str) -> Result<String, String> {
        self.restore_key_with(&SystemCommandRunner::new(), file_path)
            .await
    }

    /// [`Self::restore_key`] through `runner`.
    ///
    /// `reg import` writes whatever the file says with WinMedic's
    /// Administrator rights. So the file must be recorded in the index; in
    /// the real folder, it and the index must be changeable by Administrators
    /// and SYSTEM only; and it must hold nothing but the key its record names
    /// and the keys below it.
    pub async fn restore_key_with(
        &self,
        runner: &dyn CommandRunner,
        file_path: &str,
    ) -> Result<String, String> {
        let file = self.backup_file(file_path)?;
        let refused = |why: String| format!("{} was not imported: {why}.", file.display());
        let record = self
            .load_index()
            .map_err(refused)?
            .into_iter()
            .find(|record| record.file_path == file_path)
            .ok_or_else(|| refused("the backup index has no record of it".to_string()))?;
        if self.protected {
            for path in [file.clone(), self.index_path()] {
                if let Some(problem) = acl::admin_only_problem(&path) {
                    return Err(refused(problem));
                }
            }
        }
        let bytes =
            std::fs::read(&file).map_err(|e| refused(format!("it could not be read ({e})")))?;
        check_contents(&bytes, &record.key_path).map_err(refused)?;

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

    /// Read the backup index, distinguishing "no backups yet" from "the index is
    /// there but unreadable".
    ///
    /// That distinction is the whole point: collapsing both cases into an empty
    /// list is what previously let a single malformed byte erase every recorded
    /// backup on the next write.
    pub fn load_index(&self) -> Result<Vec<BackupRecord>, String> {
        let path = self.index_path();
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("could not read {}: {}", path.display(), e)),
        };

        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_str(&content)
            .map_err(|e| format!("{} is malformed: {}", INDEX_FILE_NAME, e))
    }

    /// All recorded backups, or an empty list if the index cannot be read.
    ///
    /// Intended for read-only display. Never build a new index from this — use
    /// [`Self::load_index`], which reports corruption instead of hiding it.
    pub fn list_backups(&self) -> Vec<BackupRecord> {
        self.load_index().unwrap_or_default()
    }

    /// Move an unreadable index aside so a rebuild cannot destroy it.
    ///
    /// Returns the path the old index was preserved at.
    fn quarantine_index(&self) -> Result<PathBuf, String> {
        let stamp = Local::now().format("%Y%m%d_%H%M%S");
        let mut dest = self
            .backup_dir
            .join(format!("{}.corrupt-{}", INDEX_FILE_NAME, stamp));

        // Two failures inside the same second must not overwrite each other.
        let mut counter = 1;
        while dest.exists() {
            dest = self
                .backup_dir
                .join(format!("{}.corrupt-{}-{}", INDEX_FILE_NAME, stamp, counter));
            counter += 1;
        }

        std::fs::rename(self.index_path(), &dest).map_err(|e| {
            format!(
                "could not move the unreadable index to {}: {}",
                dest.display(),
                e
            )
        })?;

        Ok(dest)
    }

    /// Append `record` to the index.
    ///
    /// If the existing index cannot be parsed it is quarantined rather than
    /// overwritten, and only then is a fresh index started. If quarantining
    /// fails, this returns an error and leaves the old file untouched.
    fn save_record_index(&self, record: &BackupRecord) -> Result<(), String> {
        let mut list = match self.load_index() {
            Ok(list) => list,
            Err(read_err) => {
                let preserved = self.quarantine_index()?;
                // Not fatal: the old entries survive on disk under `preserved`,
                // and the caller still gets a working index going forward.
                eprintln!(
                    "WinMedic: {} — previous index preserved at {}",
                    read_err,
                    preserved.display()
                );
                Vec::new()
            }
        };

        list.push(record.clone());

        let json = serde_json::to_string_pretty(&list)
            .map_err(|e| format!("could not serialize the backup index: {}", e))?;

        self.write_index_atomically(&json)
    }

    /// Write the index via a temp file + rename, so an interrupted write leaves
    /// the previous index intact instead of a half-written one.
    fn write_index_atomically(&self, json: &str) -> Result<(), String> {
        self.ensure_backup_dir()?;
        let tmp_path = self.backup_dir.join(format!("{}.tmp", INDEX_FILE_NAME));

        std::fs::write(&tmp_path, json)
            .map_err(|e| format!("could not write {}: {}", tmp_path.display(), e))?;
        // A rollback trusts the record's key, so the index is protected like
        // the backups.
        if let Err(problem) = self.protect(&tmp_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(problem);
        }

        // `std::fs::rename` replaces the destination on both Unix and Windows.
        std::fs::rename(&tmp_path, self.index_path()).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            format!("could not replace {}: {}", INDEX_FILE_NAME, e)
        })
    }
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
    use crate::utils::cmd::MockCommandRunner;

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

    fn record(id: &str) -> BackupRecord {
        BackupRecord {
            id: id.to_string(),
            timestamp: "2026-01-01 12:00:00".to_string(),
            description: format!("backup {}", id),
            key_path: r"HKCU\Software\Test".to_string(),
            file_path: format!(r"C:\backups\reg_{}.reg", id),
        }
    }

    #[test]
    fn only_a_reg_file_in_the_backup_folder_is_restored() {
        let dir = TempDir::new("restorable");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let backup = dir.path.join("reg_20260926_x.reg");
        std::fs::write(&backup, "Windows Registry Editor Version 5.00").unwrap();
        assert!(mgr.backup_file(&backup.to_string_lossy()).is_ok());

        let outside =
            std::env::temp_dir().join(format!("winmedic_outside_{}.reg", std::process::id()));
        std::fs::write(&outside, "x").unwrap();
        let not_reg = dir.path.join("payload.cmd");
        std::fs::write(&not_reg, "x").unwrap();
        let sneaky = dir.path.join("..").join(outside.file_name().unwrap());
        for path in [&outside, &not_reg, &sneaky, &dir.path.join("missing.reg")] {
            assert!(
                mgr.backup_file(&path.to_string_lossy()).is_err(),
                "{}",
                path.display()
            );
        }
        let _ = std::fs::remove_file(&outside);
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

    /// Write `export` into `mgr`'s folder as a backup of the Fast Startup key
    /// and record it; its path.
    fn recorded_backup(mgr: &RegBackupManager, export: &[u8]) -> String {
        let file = mgr.backup_dir().join("reg_20261008_120000_power.reg");
        std::fs::write(&file, export).unwrap();
        let file_path = file.to_string_lossy().to_string();
        mgr.save_record_index(&BackupRecord {
            id: "20261008_120000".to_string(),
            timestamp: "2026-10-08 12:00:00".to_string(),
            description: "Before turning Fast Startup off".to_string(),
            key_path: POWER_KEY.to_string(),
            file_path: file_path.clone(),
        })
        .unwrap();
        file_path
    }

    #[tokio::test]
    async fn a_recorded_backup_of_its_own_key_is_imported() {
        let dir = TempDir::new("import");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let file = recorded_backup(&mgr, POWER_EXPORT);
        let runner = MockCommandRunner::with_default_success();

        assert!(mgr.restore_key_with(&runner, &file).await.is_ok());
        assert_eq!(runner.executed(), vec![format!("reg.exe import {file}")]);
    }

    #[tokio::test]
    async fn a_backup_that_fails_a_check_is_not_imported() {
        let dir = TempDir::new("refused");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = MockCommandRunner::with_default_success();
        let file = recorded_backup(
            &mgr,
            &power_export_and("[HKEY_LOCAL_MACHINE\\SOFTWARE\\X]\r\n\"x\"=dword:00000001\r\n"),
        );

        // A good export, but not the one the index records.
        let stray = dir.path.join("reg_stray.reg");
        std::fs::write(&stray, POWER_EXPORT).unwrap();
        let refused = mgr
            .restore_key_with(&runner, &stray.to_string_lossy())
            .await
            .unwrap_err();
        assert!(refused.contains("no record"), "{refused}");

        let refused = mgr.restore_key_with(&runner, &file).await.unwrap_err();
        assert!(refused.contains("was not imported"), "{refused}");

        assert!(runner.executed().is_empty());
    }

    /// The real folder's checks, on a temp folder the account running the
    /// tests can change: nothing in it is imported, and no backup is written
    /// into it.
    #[tokio::test]
    async fn a_protected_folder_others_can_change_is_not_used() {
        let dir = TempDir::new("protected");
        let file = recorded_backup(&RegBackupManager::with_dir(dir.path.clone()), POWER_EXPORT);
        let mgr = RegBackupManager::protected_at(dir.path.clone());
        let runner = MockCommandRunner::with_default_success();

        let refused = mgr.restore_key_with(&runner, &file).await.unwrap_err();
        assert!(refused.contains("was not imported"), "{refused}");
        let refused = mgr
            .export_key_with(&runner, POWER_KEY, "Before turning Fast Startup off")
            .await
            .unwrap_err();
        assert!(refused.contains("cannot be used"), "{refused}");
        assert!(runner.executed().is_empty());
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
            crate::utils::cmd::CmdOutput::ok(split_threshold_query()),
        );
        runner.add_response("reg.exe import", crate::utils::cmd::CmdOutput::ok(""));

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
                .contains(&format!("reg.exe import {}", record.file_path))
        );
    }

    #[tokio::test]
    async fn no_value_backup_is_kept_when_there_is_nothing_to_keep() {
        let dir = TempDir::new("value_refused");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        let runner = MockCommandRunner::new();
        runner.add_response(
            "/v Missing",
            crate::utils::cmd::CmdOutput::with_output(1, "\r\n\r\n", "FEHLER"),
        );
        runner.add_response(
            "/v Text",
            crate::utils::cmd::CmdOutput::ok(
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
        let dir = TempDir::new("value_protected");
        let mgr = RegBackupManager::protected_at(dir.path.clone());
        let runner = MockCommandRunner::new();
        runner.add_response(
            "/v SvcHostSplitThresholdInKB",
            crate::utils::cmd::CmdOutput::ok(split_threshold_query()),
        );
        let refused = mgr
            .export_value_with(&runner, CONTROL_KEY, "SvcHostSplitThresholdInKB", "test")
            .await
            .unwrap_err();
        assert!(refused.contains("cannot be used"), "{refused}");
        assert_eq!(std::fs::read_dir(&dir.path).unwrap().count(), 0);
    }

    #[test]
    fn only_the_real_folder_is_protected() {
        let real = default_backup_dir();
        assert!(real.is_absolute(), "{}", real.display());
        assert!(real.ends_with(r"WinMedic\backups"), "{}", real.display());
        assert!(RegBackupManager::new().protected);
        assert!(!RegBackupManager::with_dir(std::env::temp_dir()).protected);
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

    #[test]
    fn missing_index_reads_as_empty_not_as_error() {
        let dir = TempDir::new("missing");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        assert_eq!(mgr.load_index().unwrap(), Vec::new());
        assert!(mgr.list_backups().is_empty());
    }

    #[test]
    fn empty_index_file_reads_as_empty() {
        let dir = TempDir::new("empty");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        std::fs::write(mgr.index_path(), "   \n").unwrap();

        assert_eq!(mgr.load_index().unwrap(), Vec::new());
    }

    #[test]
    fn records_accumulate_across_writes() {
        let dir = TempDir::new("accumulate");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        mgr.save_record_index(&record("a")).unwrap();
        mgr.save_record_index(&record("b")).unwrap();
        mgr.save_record_index(&record("c")).unwrap();

        let ids: Vec<String> = mgr.list_backups().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn corrupt_index_is_reported_instead_of_silently_emptied() {
        let dir = TempDir::new("corrupt_read");
        let mgr = RegBackupManager::with_dir(dir.path.clone());
        std::fs::write(mgr.index_path(), "{not valid json").unwrap();

        // The old behaviour was `unwrap_or_default()`, which made this look like
        // "no backups exist" and set up the next write to erase the file.
        assert!(mgr.load_index().is_err());
    }

    #[test]
    fn corrupt_index_is_preserved_not_overwritten() {
        let dir = TempDir::new("corrupt_write");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        let original = r#"[{"id":"old","truncated":"#;
        std::fs::write(mgr.index_path(), original).unwrap();

        mgr.save_record_index(&record("new")).unwrap();

        // The new entry is recorded...
        let ids: Vec<String> = mgr.list_backups().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, vec!["new"]);

        // ...and the unreadable original still exists verbatim, so nothing the
        // user had is lost.
        let quarantined: Vec<PathBuf> = std::fs::read_dir(&dir.path)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(".corrupt-"))
            })
            .collect();

        assert_eq!(
            quarantined.len(),
            1,
            "expected exactly one quarantined index"
        );
        assert_eq!(std::fs::read_to_string(&quarantined[0]).unwrap(), original);
    }

    #[test]
    fn quarantine_does_not_clobber_an_earlier_quarantine() {
        let dir = TempDir::new("double_corrupt");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        std::fs::write(mgr.index_path(), "first corruption").unwrap();
        mgr.save_record_index(&record("one")).unwrap();

        std::fs::write(mgr.index_path(), "second corruption").unwrap();
        mgr.save_record_index(&record("two")).unwrap();

        let mut preserved: Vec<String> = std::fs::read_dir(&dir.path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .collect();
        preserved.sort();

        assert_eq!(preserved, vec!["first corruption", "second corruption"]);
    }

    #[test]
    fn no_temp_file_is_left_behind_after_a_successful_write() {
        let dir = TempDir::new("no_temp");
        let mgr = RegBackupManager::with_dir(dir.path.clone());

        mgr.save_record_index(&record("a")).unwrap();

        let tmp = dir.path.join(format!("{}.tmp", INDEX_FILE_NAME));
        assert!(!tmp.exists(), "atomic write left its temp file behind");
    }

    #[test]
    fn index_survives_a_manager_being_reconstructed() {
        let dir = TempDir::new("reopen");

        RegBackupManager::with_dir(dir.path.clone())
            .save_record_index(&record("persisted"))
            .unwrap();

        let reopened = RegBackupManager::with_dir(dir.path.clone());
        let ids: Vec<String> = reopened.list_backups().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, vec!["persisted"]);
    }
}
