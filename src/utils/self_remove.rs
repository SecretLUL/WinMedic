//! Taking WinMedic off this PC in one step, from its own window.
//!
//! WinMedic is one file without an installer, so nothing else removes it.
//! *Settings -> Remove WinMedic from this PC* does, and leaves nothing to do
//! by hand afterwards:
//!
//! 1. The click only notes the wish ([`request`]) and closes the window, so
//!    the window ends the way it always does: eframe saves its position, and
//!    services a cancelled repair left stopped are started again.
//! 2. `main` then calls [`remove_this_installation`]. It deletes the
//!    background scan task, the two folders WinMedic keeps and its registry
//!    key, in this process: with Rust's own `remove_dir_all`, which does not
//!    follow a link out of the folder, and with an error it can show.
//! 3. A running program cannot delete its own file. So the last step is
//!    handed to a hidden PowerShell ([`Removal::cleanup_script`]) that waits
//!    for this process to end and then deletes winmedic.exe. For a WinGet
//!    install it first has WinGet take its own entry out.
//!
//! What stays is Windows' own: the restore points, and what was repaired.

use crate::config::AppConfig;
use crate::safety::reg_backup;
use crate::utils::background_task;
use crate::utils::cmd::{powershell_module_path, ps_single_quoted, system_dir, system_program};
use crate::utils::self_update::update_leftovers;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The name of every folder WinMedic keeps for itself. A folder under any
/// other name is never deleted here, wherever a path came from.
const OWN_FOLDER: &str = "WinMedic";

/// How long the last step waits for this process to end. `main` returns
/// right after starting it; this is for a process that hangs on its way out.
const WAIT_SECONDS: u32 = 150;

/// How often, half a second apart, the last step tries to delete a file
/// that something still holds, such as a virus scanner looking at it.
const DELETE_TRIES: u32 = 20;

static REQUESTED: AtomicBool = AtomicBool::new(false);

/// Note that the user confirmed the removal. The window then closes, and
/// `main` does the rest once it has.
pub fn request() {
    REQUESTED.store(true, Ordering::SeqCst);
}

/// Whether [`request`] was called in this process.
pub fn requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// WinGet's own record of this installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WingetInstall {
    /// `winget.exe` of the account WinMedic runs as.
    pub winget_exe: PathBuf,
    /// What WinGet calls the installation: the name of its package folder
    /// and of its key under `Uninstall`.
    pub product_code: String,
}

/// Everything one removal deletes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// The process whose end the last step waits for: this one.
    pub pid: u32,
    /// winmedic.exe, the file a WinGet link to it points at, and what
    /// updates left beside them.
    pub files: Vec<PathBuf>,
    /// `%APPDATA%\WinMedic` and `%ProgramData%\WinMedic`.
    pub folders: Vec<PathBuf>,
    /// The folder winmedic.exe is in, when it is one made for it, such as
    /// the `C:\Program Files\WinMedic` the background scan asks for. It
    /// goes once it is empty; anything else in it keeps it.
    pub program_folders: Vec<PathBuf>,
    pub winget: Option<WingetInstall>,
}

impl Removal {
    /// What removing the running WinMedic deletes.
    pub fn of_this_pc() -> Result<Self, String> {
        let exe = std::env::current_exe()
            .map_err(|e| format!("could not work out where winmedic.exe is: {e}"))?;
        let folders = [
            AppConfig::config_path().parent().map(Path::to_path_buf),
            dirs::data_dir().map(|dir| dir.join(OWN_FOLDER)),
            reg_backup::default_backup_dir()
                .parent()
                .map(Path::to_path_buf),
        ];
        Self::of(
            &exe,
            folders.into_iter().flatten().collect(),
            std::process::id(),
            winget_exe(),
        )
    }

    /// A removal of `exe` and `folders`, refused when a path is not plainly
    /// WinMedic's own.
    pub fn of(
        exe: &Path,
        folders: Vec<PathBuf>,
        pid: u32,
        winget_exe: Option<PathBuf>,
    ) -> Result<Self, String> {
        // Started through WinGet's link, the running file is the link; the
        // program is where it points.
        let target = std::fs::canonicalize(exe)
            .map(|path| without_verbatim_prefix(&path))
            .unwrap_or_else(|_| exe.to_path_buf());

        let mut files = Vec::new();
        let mut program_folders = Vec::new();
        for file in [exe, target.as_path()] {
            if let Some(folder) = file.parent().filter(|folder| is_own_folder(folder)) {
                push_once(&mut program_folders, folder.to_path_buf());
            }
            for path in std::iter::once(file.to_path_buf()).chain(update_leftovers(file)) {
                if !path.is_absolute() || path.to_str().is_none() {
                    return Err(format!(
                        "refusing to delete {}: not a full path",
                        path.display()
                    ));
                }
                push_once(&mut files, path);
            }
        }

        let mut own = Vec::new();
        for folder in folders {
            if !is_own_folder(&folder) {
                return Err(format!(
                    "refusing to delete {}: it is not a folder of WinMedic",
                    folder.display()
                ));
            }
            push_once(&mut own, folder);
        }

        let winget = winget_exe.and_then(|winget_exe| {
            Some(WingetInstall {
                product_code: winget_product_code(&target)?,
                winget_exe,
            })
        });

        Ok(Self {
            pid,
            files,
            folders: own,
            program_folders,
            winget,
        })
    }

    /// Delete the folders, with everything in them.
    ///
    /// `remove_dir_all` removes a link it meets, not what the link points
    /// at: `%APPDATA%\WinMedic` can be written by every program of the
    /// user, and this runs as Administrator.
    pub fn delete_folders(&self) -> Result<(), String> {
        for folder in &self.folders {
            if !is_own_folder(folder) {
                return Err(format!(
                    "refusing to delete {}: it is not a folder of WinMedic",
                    folder.display()
                ));
            }
            match std::fs::remove_dir_all(folder) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("could not delete {}: {e}", folder.display())),
            }
        }
        Ok(())
    }

    /// The PowerShell script of the last step: wait for this process, have
    /// WinGet remove its entry, delete the files.
    ///
    /// Every path is a single-quoted literal. Errors are silent, because
    /// nobody is left to read them: a file that cannot be deleted stays.
    pub fn cleanup_script(&self) -> String {
        let mut script = String::from("$ErrorActionPreference = 'SilentlyContinue'; ");
        let _ = write!(
            script,
            "Wait-Process -Id {} -Timeout {WAIT_SECONDS}; ",
            self.pid
        );
        if let Some(winget) = &self.winget {
            // `--force`: an update WinMedic installed itself changed the
            // file WinGet remembers, and WinGet refuses to remove a
            // changed file without it.
            let _ = write!(
                script,
                "& {} uninstall --product-code {} --force --silent --disable-interactivity | Out-Null; ",
                ps_single_quoted(&winget.winget_exe.to_string_lossy()),
                ps_single_quoted(&winget.product_code),
            );
        }
        let files: Vec<String> = self
            .files
            .iter()
            .map(|file| ps_single_quoted(&file.to_string_lossy()))
            .collect();
        let _ = write!(
            script,
            "$files = @({}); \
             foreach ($try in 1..{DELETE_TRIES}) {{ \
             $left = $false; \
             foreach ($file in $files) {{ \
             Remove-Item -LiteralPath $file -Force; \
             if (Test-Path -LiteralPath $file) {{ $left = $true }} }}; \
             if (-not $left) {{ break }}; \
             Start-Sleep -Milliseconds 500 }}",
            files.join(", ")
        );
        // Not recursive: .NET refuses a folder that still holds something,
        // and whatever that is, it is not WinMedic's to delete.
        for folder in &self.program_folders {
            let _ = write!(
                script,
                "; try {{ [System.IO.Directory]::Delete({}) }} catch {{ }}",
                ps_single_quoted(&folder.to_string_lossy())
            );
        }
        script
    }

    /// Start the last step. It outlives this process: nothing waits for it,
    /// and it is in no job of WinMedic's.
    ///
    /// Hidden, as every command WinMedic starts, and from the Windows
    /// folder, so it does not keep a folder open that is about to go.
    pub fn start_cleanup(&self) -> Result<(), String> {
        use std::process::Stdio;

        let powershell = system_program("powershell.exe")?;
        let mut cmd = std::process::Command::new(&powershell);
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &self.cleanup_script(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        if let Some(modules) = powershell_module_path(&powershell) {
            cmd.env("PSModulePath", modules);
        }
        if let Some(dir) = system_dir() {
            cmd.current_dir(dir);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        cmd.spawn()
            .map(|_| ())
            .map_err(|e| format!("could not start the step that deletes winmedic.exe: {e}"))
    }
}

/// Remove the running WinMedic from this PC. Called by `main` once the
/// window has closed; the process has to end right after it.
///
/// The order is the one a failure does least harm in: nothing is deleted
/// before every path has been checked, and winmedic.exe goes last, so a
/// removal that stopped halfway can be started again from the window.
pub fn remove_this_installation() -> Result<(), String> {
    let removal = Removal::of_this_pc()?;
    // A background scan in flight holds winmedic.exe open.
    background_task::end_running_helper();
    background_task::sync_helper_task(false, 0)?;
    background_task::remove_legacy_autostart()?;
    removal.delete_folders()?;
    reg_backup::delete_machine_anchors()
        .map_err(|e| format!(r"could not delete HKLM\{}: {e}", reg_backup::MACHINE_KEY))?;
    removal.start_cleanup()
}

/// Whether `path` is a folder WinMedic keeps for itself: a full path whose
/// last part is `WinMedic`, inside another folder.
///
/// The folders come from where Windows says `%APPDATA%` and `%ProgramData%`
/// are. Should that ever answer with something else, the parent or a
/// relative path, deleting it with everything in it is not an option.
pub fn is_own_folder(path: &Path) -> bool {
    path.is_absolute()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(OWN_FOLDER))
        && path
            .parent()
            .is_some_and(|parent| parent.file_name().is_some())
}

/// What WinGet calls the installation `exe` belongs to: the folder below
/// `...\WinGet\Packages`, which is also the name of its key under
/// `Uninstall` and what `winget uninstall --product-code` takes. `None` for
/// a file anywhere else.
pub fn winget_product_code(exe: &Path) -> Option<String> {
    let parts: Vec<String> = exe
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    let packages = parts.windows(2).position(|pair| {
        pair[0].eq_ignore_ascii_case("WinGet") && pair[1].eq_ignore_ascii_case("Packages")
    })?;
    // The file itself is below the package folder, never the folder.
    let code = parts
        .get(packages + 2)
        .filter(|_| parts.len() > packages + 3)?;
    let plain = !code.is_empty()
        && code.len() <= 200
        && code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    plain.then(|| code.clone())
}

/// `winget.exe` of the account WinMedic runs as, when it has one.
///
/// By its full path, not through `PATH`. The folder belongs to the user,
/// like the WinGet package folder winmedic.exe itself then runs from: who
/// can change one can change the other.
fn winget_exe() -> Option<PathBuf> {
    let exe = dirs::data_local_dir()?
        .join("Microsoft")
        .join("WindowsApps")
        .join("winget.exe");
    // An app execution alias: `exists` cannot open it, its entry is there.
    std::fs::symlink_metadata(&exe).ok().map(|_| exe)
}

/// `C:\x` for the `\\?\C:\x` that `canonicalize` answers with. PowerShell's
/// `-LiteralPath` and WinGet take the plain form.
fn without_verbatim_prefix(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.starts_with("UNC\\") => PathBuf::from(format!(r"\\{}", &rest[4..])),
        Some(rest) => PathBuf::from(rest),
        None => path.to_path_buf(),
    }
}

/// Add `path` unless it is there already, compared the way Windows does.
fn push_once(paths: &mut Vec<PathBuf>, path: PathBuf) {
    let known = paths.iter().any(|known| {
        known
            .to_string_lossy()
            .eq_ignore_ascii_case(&path.to_string_lossy())
    });
    if !known {
        paths.push(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder of its own under the temp folder, gone when the test ends.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "winmedic_selfremove_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            let path = self.path.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, name).expect("failed to write temp file");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    // -------------------------------------------------------------- folders

    #[test]
    fn only_a_folder_named_winmedic_inside_another_is_its_own() {
        assert!(is_own_folder(Path::new(
            r"C:\Users\User\AppData\Roaming\WinMedic"
        )));
        assert!(is_own_folder(Path::new(r"C:\ProgramData\winmedic")));

        // What a wrong answer about %APPDATA% would hand over.
        assert!(!is_own_folder(Path::new(r"C:\Users\User\AppData\Roaming")));
        assert!(!is_own_folder(Path::new(r"C:\ProgramData")));
        assert!(!is_own_folder(Path::new(r"C:\")));
        // `dirs` falls back to "." when Windows names no folder.
        assert!(!is_own_folder(Path::new(r".\WinMedic")));
        assert!(!is_own_folder(Path::new("WinMedic")));
        // Directly on a drive is nowhere WinMedic keeps anything.
        assert!(!is_own_folder(Path::new(r"C:\WinMedic")));
        assert!(!is_own_folder(Path::new(
            r"C:\Users\User\AppData\Roaming\WinMedic\logs"
        )));
    }

    #[test]
    fn a_removal_refuses_a_folder_that_is_not_winmedics() {
        let dir = TempDir::new("refuse");
        let exe = dir.file("winmedic.exe");
        let other = dir.path.join("Documents");
        std::fs::create_dir_all(&other).unwrap();

        let err = Removal::of(&exe, vec![other.clone()], 1, None).unwrap_err();
        assert!(err.contains("not a folder of WinMedic"), "{err}");
        assert!(other.exists());

        // Built by hand around the check, it is refused again at the
        // deletion itself.
        let forced = Removal {
            pid: 1,
            files: vec![],
            folders: vec![other.clone()],
            program_folders: vec![],
            winget: None,
        };
        assert!(forced.delete_folders().is_err());
        assert!(
            other.exists(),
            "a folder that is not WinMedic's was deleted"
        );
    }

    #[test]
    fn the_folders_go_with_everything_in_them_and_a_missing_one_is_fine() {
        let dir = TempDir::new("folders");
        let exe = dir.file("winmedic.exe");
        dir.file(r"Roaming\WinMedic\config.json");
        dir.file(r"Roaming\WinMedic\logs\audit.log");
        dir.file(r"Roaming\WinMedic\data\app.ron");
        dir.file(r"Roaming\keep.txt");
        let roaming = dir.path.join(r"Roaming\WinMedic");
        let never_created = dir.path.join(r"ProgramData\WinMedic");

        let removal = Removal::of(&exe, vec![roaming.clone(), never_created], 1, None).unwrap();
        removal.delete_folders().unwrap();

        assert!(!roaming.exists());
        assert!(dir.path.join(r"Roaming\keep.txt").exists());
        assert!(exe.exists(), "the folders' step deleted the program");
    }

    /// `%APPDATA%\WinMedic` can be written by any program of the user. A
    /// junction put there must go as a junction, not take its target along.
    #[cfg(windows)]
    #[test]
    fn a_junction_in_the_folder_is_removed_without_what_it_points_at() {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let dir = TempDir::new("junction");
        let exe = dir.file("winmedic.exe");
        let precious = dir.file(r"elsewhere\precious.txt");
        dir.file(r"Roaming\WinMedic\config.json");
        let own = dir.path.join(r"Roaming\WinMedic");
        let junction = own.join("planted");

        let made = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(precious.parent().unwrap())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .expect("cmd.exe did not start");
        assert!(
            made.status.success() && junction.join("precious.txt").exists(),
            "no junction to test with: {}",
            String::from_utf8_lossy(&made.stderr)
        );

        Removal::of(&exe, vec![own.clone()], 1, None)
            .unwrap()
            .delete_folders()
            .unwrap();

        assert!(!own.exists());
        assert!(precious.exists(), "the deletion followed the junction");
    }

    // ---------------------------------------------------------------- files

    #[test]
    fn the_program_goes_with_what_updates_left_beside_it() {
        let dir = TempDir::new("files");
        let exe = dir.file("winmedic.exe");
        let retired = dir.file("winmedic.exe.old-v0.15.0");
        let staged = dir.file("winmedic.exe.new-v0.16.0");
        dir.file("winmedic-v0.3.0.exe");
        dir.file("notes.txt");

        let removal = Removal::of(&exe, vec![], 7, None).unwrap();

        // Under the temp folder's long name, whatever name it was given by.
        let same = |a: &Path, b: &Path| {
            std::fs::canonicalize(a).unwrap() == std::fs::canonicalize(b).unwrap()
        };
        for expected in [&exe, &retired, &staged] {
            assert!(
                removal.files.iter().any(|file| same(file, expected)),
                "{} is not deleted: {:?}",
                expected.display(),
                removal.files
            );
        }
        // An older release kept beside it is a program of its own, and the
        // user's files are the user's.
        assert!(
            !removal.files.iter().any(|file| {
                let name = file.file_name().unwrap().to_string_lossy().into_owned();
                name == "winmedic-v0.3.0.exe" || name == "notes.txt"
            }),
            "{:?}",
            removal.files
        );
        assert_eq!(removal.pid, 7);
    }

    /// `C:\Program Files\WinMedic` was made for WinMedic; Downloads was not.
    #[test]
    fn only_a_folder_made_for_winmedic_goes_with_the_program() {
        let dir = TempDir::new("programfolder");
        let own = dir.file(r"Program Files\WinMedic\winmedic.exe");
        let downloaded = dir.file(r"Downloads\winmedic.exe");

        let in_own = Removal::of(&own, vec![], 1, None).unwrap();
        assert_eq!(in_own.program_folders.len(), 1, "{in_own:?}");
        assert!(in_own.program_folders[0].ends_with(r"Program Files\WinMedic"));

        let in_downloads = Removal::of(&downloaded, vec![], 1, None).unwrap();
        assert!(in_downloads.program_folders.is_empty(), "{in_downloads:?}");
        assert!(!in_downloads.cleanup_script().contains("Directory"));
    }

    #[test]
    fn a_program_without_a_full_path_is_refused() {
        let err = Removal::of(Path::new("winmedic.exe"), vec![], 1, None).unwrap_err();
        assert!(err.contains("not a full path"), "{err}");
    }

    // --------------------------------------------------------------- WinGet

    /// What WinGet wrote for a portable package on a real PC: the key's
    /// name, the folder's name and the product code are one and the same.
    #[test]
    fn the_product_code_is_the_name_winget_registered_the_package_under() {
        let captured = String::from_utf8_lossy(include_bytes!(
            "../../tests/fixtures/console/reg_query_winget_portable_arp.bin"
        ));
        let value = |name: &str| {
            captured
                .lines()
                .find_map(|line| line.trim().strip_prefix(name))
                .and_then(|rest| rest.trim().strip_prefix("REG_SZ"))
                .map(|rest| rest.trim().to_string())
                .unwrap_or_else(|| panic!("the capture has no {name}"))
        };
        let key_name = captured
            .lines()
            .find(|line| line.starts_with("HKEY_CURRENT_USER"))
            .and_then(|line| line.trim().rsplit('\\').next())
            .expect("the capture names no key")
            .to_string();
        let exe = Path::new(&value("InstallLocation")).join("ninja.exe");

        let code = winget_product_code(&exe).expect("no product code for a WinGet package");

        assert_eq!(code, key_name);
        assert_eq!(
            value("UninstallString"),
            format!("winget uninstall --product-code {code}")
        );
    }

    #[test]
    fn only_a_file_in_wingets_package_folder_has_a_product_code() {
        let code = "SecretLUL.WinMedic_Microsoft.Winget.Source_8wekyb3d8bbwe";
        let packages = r"C:\Users\User\AppData\Local\Microsoft\WinGet\Packages";

        assert_eq!(
            winget_product_code(Path::new(&format!(r"{packages}\{code}\winmedic.exe"))).as_deref(),
            Some(code)
        );
        // An archive package keeps its program further down.
        assert_eq!(
            winget_product_code(Path::new(&format!(r"{packages}\{code}\bin\winmedic.exe")))
                .as_deref(),
            Some(code)
        );
        assert_eq!(
            winget_product_code(Path::new(r"C:\Users\User\Downloads\winmedic-v0.16.0.exe")),
            None
        );
        // WinGet's link is not the package.
        assert_eq!(
            winget_product_code(Path::new(
                r"C:\Users\User\AppData\Local\Microsoft\WinGet\Links\winmedic.exe"
            )),
            None
        );
        // A file put straight into the package folder has no package.
        assert_eq!(
            winget_product_code(Path::new(&format!(r"{packages}\winmedic.exe"))),
            None
        );
        // Nothing but a plain name reaches a command line.
        assert_eq!(
            winget_product_code(Path::new(&format!(r"{packages}\a' ; calc\winmedic.exe"))),
            None
        );
    }

    #[test]
    fn winget_is_asked_only_for_an_installation_of_its_own() {
        let dir = TempDir::new("winget");
        let code = "SecretLUL.WinMedic_Microsoft.Winget.Source_8wekyb3d8bbwe";
        let own = dir.file(&format!(r"WinGet\Packages\{code}\winmedic.exe"));
        let downloaded = dir.file(r"Downloads\winmedic.exe");
        let winget = dir.path.join("winget.exe");

        let from_winget = Removal::of(&own, vec![], 1, Some(winget.clone())).unwrap();
        assert_eq!(
            from_winget.winget.as_ref().map(|w| w.product_code.as_str()),
            Some(code)
        );
        assert!(from_winget.cleanup_script().contains(&format!(
            "uninstall --product-code '{code}' --force --silent --disable-interactivity"
        )));

        let by_hand = Removal::of(&downloaded, vec![], 1, Some(winget)).unwrap();
        assert_eq!(by_hand.winget, None);
        assert!(!by_hand.cleanup_script().contains("uninstall"));

        // Without a winget.exe there is nobody to ask.
        let no_winget = Removal::of(&own, vec![], 1, None).unwrap();
        assert_eq!(no_winget.winget, None);
    }

    // --------------------------------------------------------------- script

    #[test]
    fn the_script_waits_for_this_process_and_quotes_every_path() {
        let removal = Removal {
            pid: 4242,
            files: vec![
                PathBuf::from(r"C:\Users\O'Brien\Downloads\winmedic.exe"),
                PathBuf::from(r"C:\Users\O'Brien\Downloads\winmedic.exe.old-v0.15.0"),
            ],
            folders: vec![],
            program_folders: vec![PathBuf::from(r"C:\Program Files\WinMedic")],
            winget: None,
        };

        let script = removal.cleanup_script();

        assert!(
            script.starts_with(
                "$ErrorActionPreference = 'SilentlyContinue'; Wait-Process -Id 4242 -Timeout 150; "
            ),
            "{script}"
        );
        // The apostrophe doubled, or it would end the literal.
        assert!(
            script.contains(
                r"$files = @('C:\Users\O''Brien\Downloads\winmedic.exe', 'C:\Users\O''Brien\Downloads\winmedic.exe.old-v0.15.0');"
            ),
            "{script}"
        );
        assert!(
            script.contains("Remove-Item -LiteralPath $file -Force"),
            "{script}"
        );
        // Rust quotes the argument for PowerShell; a double quote in it
        // would end that.
        assert!(!script.contains('"'), "{script}");
        // The folders are not this step's: PowerShell 5.1 follows links.
        assert!(!script.contains("-Recurse"), "{script}");
        // The program's own folder goes last, and only when it is empty.
        assert!(
            script.ends_with(
                r"; try { [System.IO.Directory]::Delete('C:\Program Files\WinMedic') } catch { }"
            ),
            "{script}"
        );
    }

    /// The real last step, against files in the temp folder: they are still
    /// there while the process it waits for runs, and gone after it ended.
    #[cfg(windows)]
    #[test]
    fn the_last_step_deletes_the_files_once_the_process_has_ended() {
        use std::os::windows::process::CommandExt;
        use std::process::Stdio;
        use std::time::{Duration, Instant};
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let dir = TempDir::new("laststep");
        let exe = dir.file(r"emptied\WinMedic\winmedic.exe");
        let retired = dir.file(r"emptied\WinMedic\winmedic.exe.old-v0.15.0");
        let bystander = dir.file(r"emptied\notes.txt");

        // Stands in for WinMedic: runs for about four seconds, harmlessly.
        let mut waited_for = std::process::Command::new("ping.exe")
            .args(["-n", "5", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .expect("ping.exe did not start");

        let removal = Removal::of(&exe, vec![], waited_for.id(), None).unwrap();
        removal.start_cleanup().unwrap();

        // PowerShell needs a moment to start; the files outlast it.
        std::thread::sleep(Duration::from_millis(1500));
        if waited_for.try_wait().unwrap().is_none() {
            assert!(exe.exists(), "deleted while the process still ran");
        }

        let deadline = Instant::now() + Duration::from_secs(60);
        while (exe.exists() || retired.exists()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        let ended = waited_for.try_wait().unwrap().is_some();
        let _ = waited_for.kill();
        let _ = waited_for.wait();

        assert!(!exe.exists(), "the program is still there");
        assert!(!retired.exists(), "the replaced program is still there");
        assert!(ended, "the files went before the process had ended");
        assert!(bystander.exists(), "a file that is not WinMedic's went too");
        // The folder made for WinMedic is empty now, and goes as well.
        let folder = exe.parent().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while folder.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!folder.exists(), "the emptied program folder stayed");
    }

    /// A folder named WinMedic that holds something else keeps it, and
    /// stays.
    #[cfg(windows)]
    #[test]
    fn a_program_folder_with_something_else_in_it_stays() {
        use std::time::{Duration, Instant};

        let dir = TempDir::new("keptfolder");
        let exe = dir.file(r"WinMedic\winmedic.exe");
        let kept = dir.file(r"WinMedic\my-notes.txt");

        // A process id nothing runs under: there is nothing to wait for.
        let removal = Removal::of(&exe, vec![], u32::MAX - 1, None).unwrap();
        assert_eq!(removal.program_folders.len(), 1);
        removal.start_cleanup().unwrap();

        let deadline = Instant::now() + Duration::from_secs(60);
        while exe.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(!exe.exists(), "the program is still there");
        // Long enough for the step after the files to have run.
        std::thread::sleep(Duration::from_secs(2));
        assert!(kept.exists(), "a file that is not WinMedic's was deleted");
    }

    /// No test may remove the real WinMedic: its folders hold the
    /// developer's settings, logs and registry backups, and "the program"
    /// would be the test binary. Everything worth asserting is reachable
    /// through [`Removal::of`] with folders under the temp folder.
    #[test]
    fn no_test_in_the_tree_removes_the_real_winmedic() {
        let mut offenders = Vec::new();
        for needle in [
            "remove_this_installation(",
            "Removal::of_this_pc(",
            "self_remove::request(",
        ] {
            offenders.extend(crate::utils::test_guard::integration_test_lines_mentioning(
                needle,
            ));
        }

        assert!(
            offenders.is_empty(),
            "these tests would delete WinMedic's real folders and registry key: {offenders:?}"
        );
    }

    #[test]
    fn nothing_is_requested_until_someone_asks() {
        // No test calls `request`: it would stay set for every test after.
        assert!(!requested());
    }
}
