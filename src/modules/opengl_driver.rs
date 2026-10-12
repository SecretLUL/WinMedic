//! A graphics card whose OpenGL driver Windows cannot find.
//!
//! A graphics driver registers its OpenGL driver in the card's driver key,
//! `OpenGLDriverName` for 64-bit programs and `OpenGLDriverNameWow` for 32-bit
//! ones, and Windows' `opengl32.dll` loads the file named there. When that
//! file is gone, an OpenGL program gets Windows' own OpenGL 1.1, which draws
//! in software, and most do not start: Minecraft stops at its first OpenGL
//! call. Direct3D goes on working, and Device Manager reports nothing.
//!
//! That is how it was found. After the graphics card's driver, Windows Update
//! installed an old driver for the processor's graphics, and the OpenGL
//! entries of both were pointed into another package of the driver store,
//! which does not hold those files.
//!
//! An entry is judged only in the form current drivers write it: one path into
//! the driver store, `<SystemRoot>\System32\DriverStore\FileRepository\<package>\...`,
//! which 32-bit programs reach without redirection too. A bare file name
//! (loaded from System32), a path anywhere else, a variable, a virtual
//! machine's `HostDriverStore`, several strings, and a path `reg query` may
//! not have printed whole (a `?`, a character outside ASCII) are left alone:
//! rather no finding than a made-up one.
//!
//! What it is pointed back at is the file of the same name in the folder the
//! same card loads its Direct3D driver from, the first path of
//! `UserModeDriverName` (`UserModeDriverNameWow` for 32 bits): the card's own
//! driver package, which is there as long as Direct3D works. A captured AMD
//! card has both drivers side by side, each name once in its package. Nothing
//! is searched for; where that file is not, the finding is advice.
//!
//! `OpenGLVendorName`, which AMD's drivers add, names files of a further
//! package that Windows does not load itself. It is not checked.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::devices::slug;
use crate::safety::reg_backup::RegBackupManager;
use crate::utils::cmd::CommandRunner;
use crate::utils::pnp::PnpDevice;
use crate::utils::registry::{self, RegKeyValues, RegValue};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The findings' id prefix; the card's instance ID follows.
pub const ID_PREFIX: &str = "dev_opengl_";

/// The setup class of display adapters, the first part of their driver keys.
const DISPLAY_CLASS: &str = "{4d36e968-e325-11ce-bfc1-08002be10318}";

/// Where the driver keys are.
const CLASS_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Class";

/// Each OpenGL entry, and the Direct3D entry for the same programs.
const ENTRIES: [(&str, &str); 2] = [
    ("OpenGLDriverName", "UserModeDriverName"),
    ("OpenGLDriverNameWow", "UserModeDriverNameWow"),
];

/// The graphics cards among `devices` that work: those whose driver key is
/// one of the display adapters' class. A card that reports a problem is the
/// devices check's, which restarts it.
pub fn graphics_cards(devices: &[PnpDevice]) -> impl Iterator<Item = &PnpDevice> {
    devices.iter().filter(|device| {
        device.problem == 0
            && device
                .driver
                .split_once('\\')
                .is_some_and(|(class, number)| {
                    class.eq_ignore_ascii_case(DISPLAY_CLASS)
                        && number.len() == 4
                        && number.bytes().all(|b| b.is_ascii_digit())
                })
    })
}

/// The id of the finding about `card`.
pub fn issue_id(card: &PnpDevice) -> String {
    format!("{ID_PREFIX}{}", slug(&card.instance_id))
}

/// The driver key of `card`, as `reg` takes it.
fn driver_key(card: &PnpDevice) -> String {
    format!(r"{CLASS_KEY}\{}", card.driver)
}

/// The driver store: as the registry spells it, and where its files are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverStore {
    /// `C:\Windows\System32\DriverStore\FileRepository`, compared without
    /// regard to case, as Windows compares paths.
    pub registered: String,
    /// Where a file under it is looked for: that same folder, but in tests.
    pub on_disk: PathBuf,
}

impl DriverStore {
    /// This Windows' driver store.
    pub fn of_this_windows() -> Self {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let registered = format!(r"{root}\System32\DriverStore\FileRepository");
        Self {
            on_disk: PathBuf::from(&registered),
            registered,
        }
    }

    /// Where `path`, as the registry holds it, is on disk, if it is a path
    /// this check judges: a file in a package of the driver store, printed
    /// whole.
    fn on_disk(&self, path: &str) -> Option<PathBuf> {
        // `reg query` joins the strings of a multi-string with `\0`, so a
        // path with it (a folder `0409`) cannot be told from two strings.
        if !path.is_ascii() || path.contains(['?', '/', '%', '\0']) || path.contains(r"\0") {
            return None;
        }
        let below = path
            .get(..self.registered.len())
            .filter(|root| root.eq_ignore_ascii_case(&self.registered))
            .and_then(|_| path.get(self.registered.len()..))?
            .strip_prefix('\\')?;
        let parts: Vec<&str> = below.split('\\').collect();
        // The package, then the file, perhaps in folders of the package.
        let whole = parts.len() >= 2
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part.trim() == *part
                    && !part.ends_with('.')
                    && !part.contains(':')
            });
        whole.then(|| {
            parts
                .iter()
                .fold(self.on_disk.clone(), |path, part| path.join(part))
        })
    }

    /// Whether `path` is a file in the driver store.
    fn is_file(&self, path: &str) -> bool {
        self.on_disk(path).is_some_and(|file| file.is_file())
    }

    /// Whether `path` is in the driver store and nothing is there. A path
    /// whose state cannot be told is not.
    fn is_gone(&self, path: &str) -> bool {
        self.on_disk(path)
            .is_some_and(|file| matches!(file.try_exists(), Ok(false)))
    }
}

/// An OpenGL entry that names a file that is not there.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Broken {
    /// `OpenGLDriverName` or `OpenGLDriverNameWow`.
    name: &'static str,
    /// `REG_MULTI_SZ` or `REG_SZ`, which the repair writes again.
    kind: String,
    path: String,
    /// The file of the same name beside the card's Direct3D driver.
    replacement: Option<String>,
}

/// The values of `key` itself, or why they could not be read.
async fn read_key(runner: &dyn CommandRunner, key: &str) -> Result<RegKeyValues, String> {
    let wanted = registry::expand_hive(key);
    registry::query(runner, key, false)
        .await?
        .and_then(|keys| {
            keys.into_iter()
                .find(|found| found.key.eq_ignore_ascii_case(&wanted))
        })
        .ok_or_else(|| format!("{key} could not be read"))
}

/// A string or a multi-string, the forms an entry takes.
fn text(value: &RegValue) -> Option<&RegValue> {
    matches!(value.kind.as_str(), "REG_SZ" | "REG_MULTI_SZ").then_some(value)
}

/// The OpenGL entries among `values` that name a file in the driver store
/// that is not there.
fn broken_entries(store: &DriverStore, values: &RegKeyValues) -> Vec<Broken> {
    ENTRIES
        .into_iter()
        .filter_map(|(name, direct3d)| {
            let value = values.value(name).and_then(text)?;
            if !store.is_gone(&value.data) {
                return None;
            }
            Some(Broken {
                name,
                kind: value.kind.clone(),
                path: value.data.clone(),
                replacement: values
                    .value(direct3d)
                    .and_then(text)
                    .and_then(|direct3d| beside(store, &direct3d.data, &value.data)),
            })
        })
        .collect()
}

/// The file named like `path` in the folder of the first file `direct3d`
/// names, if both are files in the driver store.
fn beside(store: &DriverStore, direct3d: &str, path: &str) -> Option<String> {
    // A `\0` inside the first path (a folder `0409`) cuts it short, and what
    // is left of it is no file.
    let first = direct3d.split(r"\0").next()?;
    let (folder, _) = first.rsplit_once('\\')?;
    let (_, name) = path.rsplit_once('\\')?;
    let replacement = format!(r"{folder}\{name}");
    (store.is_file(first) && store.is_file(&replacement)).then_some(replacement)
}

/// Who made the card's driver, after its key.
fn provider(values: &RegKeyValues) -> String {
    values
        .value("ProviderName")
        .map(|value| value.data.trim())
        .filter(|name| !name.is_empty())
        .unwrap_or("the graphics card's maker")
        .to_string()
}

/// The finding about `card` when one of its OpenGL entries names a file that
/// is not there, or why its driver key could not be read.
pub async fn finding(
    runner: &dyn CommandRunner,
    store: &DriverStore,
    card: &PnpDevice,
    module_id: &str,
    backing_up: bool,
) -> Result<Option<Issue>, String> {
    let key = driver_key(card);
    let values = read_key(runner, &key).await?;
    let broken = broken_entries(store, &values);
    if broken.is_empty() {
        return Ok(None);
    }

    let value = |name| values.value(name).map_or("?", |v| v.data.as_str());
    let mut details = format!(
        "Graphics card: {}\nInstance ID: {}\nDriver: {} {} ({})\nDriver key: {key}",
        if card.name.is_empty() {
            "(no name)"
        } else {
            &card.name
        },
        card.instance_id,
        value("ProviderName"),
        value("DriverVersion"),
        value("InfPath")
    );
    for entry in &broken {
        details.push_str(&format!(
            "\n{} ({}): {} - does not exist\n  {}",
            entry.name,
            entry.kind,
            entry.path,
            match &entry.replacement {
                Some(file) => format!("Beside its Direct3D driver: {file}"),
                None => "Not beside its Direct3D driver either".to_string(),
            }
        ));
    }
    let issue = |recommendation: String, steps| {
        Issue::new(
            issue_id(card),
            module_id,
            format!("Windows cannot find the OpenGL driver of {}", card.label()),
            "Devices & Drivers",
            Severity::Warning,
            RiskScore::High,
            "Games and programs that draw with OpenGL, Minecraft among them, get only Windows' own OpenGL 1.1, which draws in software, and most of them do not start. Direct3D goes on working, and Device Manager shows nothing wrong. A driver Windows Update installs for a second graphics adapter, often an older one, can leave a card like this.",
            details.clone(),
            recommendation,
            steps,
        )
    };

    let provider = provider(&values);
    let replacements: Option<Vec<&str>> = broken
        .iter()
        .map(|entry| entry.replacement.as_deref())
        .collect();
    let Some(replacements) = replacements else {
        return Ok(Some(
            issue(
                format!("Install the graphics driver from {provider} again"),
                vec![format!(
                    "Download the current driver for {} from the website of {provider} and install it: that registers its OpenGL driver again.",
                    card.label()
                )],
            )
            .with_advice_only(),
        ));
    };

    let mut steps = Vec::new();
    if backing_up {
        for entry in &broken {
            steps.push(format!(
                "Back up {} of {key} to the registry backups",
                entry.name
            ));
        }
    }
    for (entry, replacement) in broken.iter().zip(&replacements) {
        steps.push(format!(
            "reg add \"{key}\" /v {} /t {} /d \"{replacement}\" /f",
            entry.name, entry.kind
        ));
    }
    steps.push("Read the entries back and check that the files are there".to_string());
    steps.push("Restart Windows".to_string());
    let mut issue = issue(
        "Point the OpenGL entries back at the card's own driver files, then restart Windows"
            .to_string(),
        steps,
    )
    // Whether Windows takes the new entry before it restarts is not known.
    .with_requires_reboot(true);
    issue.is_selected = false;
    Ok(Some(issue))
}

/// Point the OpenGL entries of the card `issue_id` names at the files beside
/// its Direct3D driver: after backing each up into `backups`, when that is
/// given, and reading each back.
///
/// Everything is found again first. A card that is gone, or whose entries
/// name files that are there by now, is left as it is.
pub async fn repair(
    runner: &dyn CommandRunner,
    store: &DriverStore,
    issue_id: &str,
    backups: Option<&Path>,
) -> Result<String, String> {
    let devices = runner.connected_devices().await?;
    let Some(card) = graphics_cards(&devices).find(|card| self::issue_id(card) == issue_id) else {
        return Ok(
            "The graphics card is no longer connected, or Device Manager reports a problem for it now - nothing was changed."
                .to_string(),
        );
    };
    let label = card.label();
    let key = driver_key(card);
    let values = read_key(runner, &key)
        .await
        .map_err(|e| format!("{e}. Nothing was changed."))?;
    let broken = broken_entries(store, &values);
    if broken.is_empty() {
        return Ok(format!(
            "The OpenGL entries of {label} name files that are there by now - nothing was changed."
        ));
    }
    let mut changes = Vec::new();
    for entry in &broken {
        let Some(replacement) = entry.replacement.as_deref() else {
            return Err(format!(
                "{} of {label} names {}, which does not exist, and the folder of its Direct3D driver has no file of that name either. Install the graphics driver from {} again. Nothing was changed.",
                entry.name,
                entry.path,
                provider(&values)
            ));
        };
        changes.push((entry, replacement));
    }

    if let Some(dir) = backups {
        let backup = RegBackupManager::with_dir(dir.to_path_buf());
        for (entry, _) in &changes {
            backup
                .export_value_with(
                    runner,
                    &key,
                    entry.name,
                    &format!(
                        "Before pointing {} of {label} at its own driver files",
                        entry.name
                    ),
                )
                .await
                .map_err(|e| {
                    format!(
                        "Aborted: the registry backup of {key}\\{} failed ({e}). Nothing was changed.",
                        entry.name
                    )
                })?;
        }
    }

    let mut set: Vec<&str> = Vec::new();
    for (entry, replacement) in &changes {
        let added = runner
            .run(
                "reg.exe",
                &[
                    "add",
                    &key,
                    "/v",
                    entry.name,
                    "/t",
                    &entry.kind,
                    "/d",
                    replacement,
                    "/f",
                ],
                Duration::from_secs(10),
            )
            .await;
        let failed = match added {
            Ok(out) if out.success => None,
            Ok(out) => Some(format!(
                "exit code {:?}: {}",
                out.exit_code,
                out.stderr.trim()
            )),
            Err(e) => Some(e),
        };
        if let Some(why) = failed {
            return Err(format!(
                "Could not set {key}\\{} ({why}). {}",
                entry.name,
                if set.is_empty() {
                    "Nothing was changed.".to_string()
                } else {
                    format!("{} is set already.", set.join(" and "))
                }
            ));
        }
        set.push(entry.name);
    }

    for (entry, replacement) in &changes {
        let now = registry::query_value(runner, &key, entry.name)
            .await
            .map_err(|e| {
                format!(
                    "{key}\\{} was set but could not be read back: {e}",
                    entry.name
                )
            })?;
        match now {
            Some(value) if value.kind == entry.kind && value.data == *replacement => {
                if !store.is_file(replacement) {
                    return Err(format!(
                        "{key}\\{} names {replacement} now, but that file is gone.",
                        entry.name
                    ));
                }
            }
            other => {
                return Err(format!(
                    "{key}\\{} was set to {replacement} but reads {}.",
                    entry.name,
                    other.map_or("nothing".to_string(), |value| format!(
                        "{} {}",
                        value.kind, value.data
                    ))
                ));
            }
        }
    }

    let named: Vec<String> = changes
        .iter()
        .map(|(entry, replacement)| format!("{} {replacement}", entry.name))
        .collect();
    Ok(format!(
        "The OpenGL entries of {label} name its own driver files again: {}. Restart Windows, then start the OpenGL programs again.{}",
        named.join(", "),
        if backups.is_some() {
            " The old entries are in the registry backups."
        } else {
            ""
        }
    ))
}

/// The development PC's graphics card, its driver key as `reg` printed it,
/// and a driver store to go with it, for this module's tests and the devices
/// check's.
#[cfg(test)]
pub(crate) mod test_support {
    use super::DriverStore;
    use crate::safety::reg_backup::test_support::{DISPLAY_EXPORT, DISPLAY_KEY, with_path};
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;
    use crate::utils::pnp::PnpDevice;
    use std::path::PathBuf;

    /// `reg query` of the card's driver key on Windows 11, and of its two
    /// OpenGL entries on their own.
    const KEY_QUERY: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_display_driver_key.bin");
    pub const ICD_QUERY: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_display_opengl_driver_name.bin");
    pub const ICD_WOW_QUERY: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_display_opengl_driver_name_wow.bin");

    pub const KEY: &str = DISPLAY_KEY;
    pub const STORE: &str = r"C:\WINDOWS\System32\DriverStore\FileRepository";
    /// The folder of the card's driver package that holds its drivers.
    const OWN: &str = r"u0203304.inf_amd64_a6e5a337568ce3f0\B026373";
    /// AMD's OpenGL package, which `OpenGLVendorName` names.
    const OPENGL_PACKAGE: &str = "amdogl.inf_amd64_0c58af8f08364541";
    /// The OpenGL drivers, 64-bit and 32-bit.
    pub const ICD: &str = "atig6pxx.dll";
    pub const ICD_WOW: &str = "atiglpxx.dll";

    /// `name` in the card's own folder, as the registry holds it.
    pub fn own(name: &str) -> String {
        format!(r"{STORE}\{OWN}\{name}")
    }

    /// `name` in AMD's OpenGL package, which does not hold it.
    pub fn in_opengl_package(name: &str) -> String {
        format!(r"{STORE}\{OPENGL_PACKAGE}\{name}")
    }

    /// The card as SetupAPI lists it.
    pub fn card() -> PnpDevice {
        PnpDevice {
            problem: 0,
            class: "Display".to_string(),
            instance_id: r"PCI\VEN_1002&DEV_747E&SUBSYS_24141458&REV_FF\6&3AF519&0&00000009"
                .to_string(),
            name: "AMD Radeon RX 7700 XT".to_string(),
            service: "amduw23g-203304-e29338d6".to_string(),
            driver: r"{4d36e968-e325-11ce-bfc1-08002be10318}\0000".to_string(),
        }
    }

    /// `text`, captured, with the entries naming the drivers `away` pointed
    /// into AMD's OpenGL package, as on the PC the check was written for:
    /// **constructed**.
    pub fn pointed_away(text: &str, away: &[&str]) -> String {
        away.iter().fold(text.to_string(), |text, name| {
            assert!(text.matches(&own(name)).count() <= 1, "{name}");
            text.replace(&own(name), &in_opengl_package(name))
        })
    }

    /// The key as `reg query` printed it, the drivers `away` pointed away.
    pub fn key_query(away: &[&str]) -> String {
        pointed_away(&decode_output(KEY_QUERY), away)
    }

    /// The PC with the card, `reg query` answering for its key with the
    /// drivers `away` pointed away.
    pub fn pc(away: &[&str]) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.set_devices(vec![card()]);
        answer_for_the_key(&mock, away);
        mock
    }

    /// `reg query` of the key and of its two entries. `/v OpenGLDriverName`
    /// is part of `/v OpenGLDriverNameWow`, and the key of both, so the
    /// longer ones come first.
    pub fn answer_for_the_key(mock: &MockCommandRunner, away: &[&str]) {
        mock.add_response(
            format!("query {KEY} /v OpenGLDriverNameWow"),
            CmdOutput::ok(pointed_away(&decode_output(ICD_WOW_QUERY), away)),
        );
        mock.add_response(
            format!("query {KEY} /v OpenGLDriverName"),
            CmdOutput::ok(pointed_away(&decode_output(ICD_QUERY), away)),
        );
        mock.add_response(format!("query {KEY}"), CmdOutput::ok(key_query(away)));
    }

    /// `reg export` of the key as it is with the drivers `away` pointed away.
    pub fn export(away: &[&str]) -> Vec<u8> {
        let mut export = DISPLAY_EXPORT.to_vec();
        for (name, value) in [(ICD, "OpenGLDriverName"), (ICD_WOW, "OpenGLDriverNameWow")] {
            if away.contains(&name) {
                export = with_path(&export, value, &in_opengl_package(name));
            }
        }
        export
    }

    /// A temporary folder with a driver store in it, holding the files the
    /// captured key names in the card's own folder, and AMD's OpenGL package
    /// with its own file only. Registry backups go into it too.
    pub struct Store {
        pub dir: PathBuf,
    }

    impl Store {
        pub fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "winmedic_opengl_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let store = Self { dir };
            for name in [ICD, ICD_WOW, "atidx9loader64.dll", "atidx9loader32.dll"] {
                store.add(&format!(r"{OWN}\{name}"));
            }
            store.add(&format!(r"{OPENGL_PACKAGE}\atio6axx.dll"));
            store
        }

        /// `file`, a path below the driver store, on disk.
        fn file(&self, file: &str) -> PathBuf {
            file.split('\\')
                .fold(self.dir.join("FileRepository"), |path, part| {
                    path.join(part)
                })
        }

        pub fn add(&self, file: &str) {
            let path = self.file(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"").unwrap();
        }

        /// Takes `name` out of the card's own folder.
        pub fn remove_own(&self, name: &str) {
            std::fs::remove_file(self.file(&format!(r"{OWN}\{name}"))).unwrap();
        }

        pub fn store(&self) -> DriverStore {
            DriverStore {
                registered: STORE.to_string(),
                on_disk: self.dir.join("FileRepository"),
            }
        }

        pub fn backups(&self) -> PathBuf {
            self.dir.join("backups")
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::safety::reg_backup::test_support::{hex7_lines, text_of};
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;

    async fn found(mock: &MockCommandRunner, store: &Store, backing_up: bool) -> Option<Issue> {
        finding(mock, &store.store(), &card(), "devices", backing_up)
            .await
            .unwrap()
    }

    #[test]
    fn only_graphics_cards_that_work_are_checked() {
        let device = |problem, driver: &str| PnpDevice {
            problem,
            driver: driver.to_string(),
            ..card()
        };
        let devices = [
            card(),
            device(0, r"{4D36E968-E325-11CE-BFC1-08002BE10318}\0001"),
            // A card that reports a problem, a network adapter, a device
            // without a driver, and keys that are not a driver key.
            device(43, r"{4d36e968-e325-11ce-bfc1-08002be10318}\0002"),
            device(0, r"{4d36e972-e325-11ce-bfc1-08002be10318}\0003"),
            device(0, ""),
            device(0, r"{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD"),
            device(0, r"{4d36e968-e325-11ce-bfc1-08002be10318}\00x0"),
        ];
        let checked: Vec<&str> = graphics_cards(&devices)
            .map(|card| card.driver.as_str())
            .collect();
        assert_eq!(
            checked,
            [
                r"{4d36e968-e325-11ce-bfc1-08002be10318}\0000",
                r"{4D36E968-E325-11CE-BFC1-08002BE10318}\0001"
            ]
        );
    }

    #[test]
    fn only_one_path_into_the_driver_store_is_judged() {
        let store = Store::new("judged");
        let store = store.store();
        assert!(store.on_disk(&own(ICD)).is_some());
        // Windows compares paths without regard to case.
        assert!(
            store
                .on_disk(&own(ICD).replace(STORE, &STORE.to_lowercase()))
                .is_some()
        );
        let in_store = |below: &str| format!(r"{STORE}\{below}");
        for path in [
            String::new(),
            "atig6pxx.dll".to_string(),
            r"%SystemRoot%\System32\DriverStore\FileRepository\x\atig6pxx.dll".to_string(),
            r"C:\Program Files\AMD\atig6pxx.dll".to_string(),
            r"C:\WINDOWS\System32\HostDriverStore\FileRepository\x\atig6pxx.dll".to_string(),
            STORE.to_string(),
            in_store("atig6pxx.dll"),
            in_store(r"x\\atig6pxx.dll"),
            in_store(r"x\..\..\atig6pxx.dll"),
            in_store(r"x\B026373 \atig6pxx.dll"),
            in_store(r"x/B026373\atig6pxx.dll"),
            in_store(r"x\atig6pxx.dll:stream"),
            // Two strings, and what `reg query` could not print.
            format!(r"{}\0{}", own(ICD), own(ICD_WOW)),
            own(r"0409\atig6pxx.dll"),
            in_store(r"x\B0?6373\atig6pxx.dll"),
            in_store(r"x\Treiber\atig6pxx.dll").replace("Treiber", "Tréiber"),
        ] {
            assert_eq!(store.on_disk(&path), None, "{path}");
        }
    }

    #[tokio::test]
    async fn the_captured_card_is_in_order() {
        let store = Store::new("captured");
        assert_eq!(found(&pc(&[]), &store, true).await, None);
    }

    /// The state the check was written for: both entries pointed into AMD's
    /// OpenGL package, the drivers beside the Direct3D driver.
    #[tokio::test]
    async fn entries_pointed_into_another_package_are_found_with_the_files_to_point_at() {
        let store = Store::new("found");
        let issue = found(&pc(&[ICD, ICD_WOW]), &store, true).await.unwrap();

        assert_eq!(
            issue.id,
            "dev_opengl_pci_ven_1002_dev_747e_subsys_24141458_rev_ff_6_3af519_0_00000009"
        );
        assert_eq!(
            issue.title,
            "Windows cannot find the OpenGL driver of 'AMD Radeon RX 7700 XT'"
        );
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.risk_score, RiskScore::High);
        assert!(issue.requires_reboot && !issue.is_selected && !issue.advice_only);
        for expected in [
            "Driver: Advanced Micro Devices, Inc. 32.0.31041.1004 (oem2.inf)".to_string(),
            format!(
                "OpenGLDriverName (REG_MULTI_SZ): {} - does not exist\n  Beside its Direct3D driver: {}",
                in_opengl_package(ICD),
                own(ICD)
            ),
            format!(
                "OpenGLDriverNameWow (REG_MULTI_SZ): {} - does not exist\n  Beside its Direct3D driver: {}",
                in_opengl_package(ICD_WOW),
                own(ICD_WOW)
            ),
        ] {
            assert!(
                issue.technical_details.contains(&expected),
                "{}",
                issue.technical_details
            );
        }
        assert_eq!(
            issue.fix_steps,
            [
                format!("Back up OpenGLDriverName of {KEY} to the registry backups"),
                format!("Back up OpenGLDriverNameWow of {KEY} to the registry backups"),
                format!(
                    "reg add \"{KEY}\" /v OpenGLDriverName /t REG_MULTI_SZ /d \"{}\" /f",
                    own(ICD)
                ),
                format!(
                    "reg add \"{KEY}\" /v OpenGLDriverNameWow /t REG_MULTI_SZ /d \"{}\" /f",
                    own(ICD_WOW)
                ),
                "Read the entries back and check that the files are there".to_string(),
                "Restart Windows".to_string(),
            ]
        );

        let without_backups = found(&pc(&[ICD, ICD_WOW]), &store, false).await.unwrap();
        assert!(without_backups.fix_steps[0].starts_with("reg add"));
    }

    #[tokio::test]
    async fn only_the_entry_whose_file_is_gone_is_named() {
        let store = Store::new("one");
        let issue = found(&pc(&[ICD_WOW]), &store, true).await.unwrap();
        assert!(
            issue
                .technical_details
                .contains("OpenGLDriverNameWow (REG_MULTI_SZ)")
        );
        assert!(
            !issue
                .technical_details
                .contains("OpenGLDriverName (REG_MULTI_SZ)")
        );
        assert_eq!(issue.fix_steps.len(), 4, "{:?}", issue.fix_steps);
    }

    #[tokio::test]
    async fn without_the_file_beside_the_direct3d_driver_it_is_advice() {
        let store = Store::new("advice");
        store.remove_own(ICD);
        let issue = found(&pc(&[ICD, ICD_WOW]), &store, true).await.unwrap();
        assert!(issue.advice_only && !issue.is_selected);
        assert_eq!(
            issue.recommended_fix,
            "Install the graphics driver from Advanced Micro Devices, Inc. again"
        );
        assert!(
            issue
                .technical_details
                .contains("Not beside its Direct3D driver either"),
            "{}",
            issue.technical_details
        );
    }

    /// The file is gone, but the entry is not one this check judges.
    #[tokio::test]
    async fn an_entry_that_is_not_judged_raises_nothing() {
        let store = Store::new("unjudged");
        let mock = MockCommandRunner::new();
        mock.add_response(
            format!("query {KEY}"),
            CmdOutput::ok(key_query(&[]).replace(&own(ICD), "atig6pxx.dll")),
        );
        store.remove_own(ICD);
        assert_eq!(found(&mock, &store, true).await, None);
    }

    #[tokio::test]
    async fn a_key_that_cannot_be_read_is_an_error() {
        let store = Store::new("unread");
        let refused = MockCommandRunner::new();
        refused.add_response(
            format!("query {KEY}"),
            CmdOutput::with_output(1, "", "FEHLER: Zugriff verweigert"),
        );
        for mock in [refused, MockCommandRunner::new()] {
            assert!(
                finding(&mock, &store.store(), &card(), "devices", true)
                    .await
                    .is_err()
            );
        }
    }

    /// The PC with both entries pointed away, which takes `reg export` and
    /// `reg add` and afterwards reads the entries as captured; `first` are
    /// answers that come before those.
    fn repairable(first: &[(&str, CmdOutput)]) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.set_devices(vec![card()]);
        for (pattern, answer) in first {
            mock.add_response(*pattern, answer.clone());
        }
        mock.add_response_after(
            "/v OpenGLDriverNameWow /t",
            format!("query {KEY} /v OpenGLDriverNameWow"),
            CmdOutput::ok(decode_output(ICD_WOW_QUERY)),
        );
        mock.add_response_after(
            "/v OpenGLDriverName /t",
            format!("query {KEY} /v OpenGLDriverName"),
            CmdOutput::ok(decode_output(ICD_QUERY)),
        );
        answer_for_the_key(&mock, &[ICD, ICD_WOW]);
        mock.add_written_file("reg.exe export", 2, export(&[ICD, ICD_WOW]));
        mock.add_response("reg.exe export", CmdOutput::ok(""));
        mock.add_response("reg.exe add", CmdOutput::ok(""));
        mock
    }

    fn reg_calls(mock: &MockCommandRunner) -> Vec<String> {
        mock.executed()
            .into_iter()
            .filter(|c| c.starts_with("reg.exe"))
            .collect()
    }

    #[tokio::test]
    async fn the_entries_are_backed_up_pointed_back_and_read_back() {
        let store = Store::new("repair");
        let mock = repairable(&[]);
        let done = repair(
            &mock,
            &store.store(),
            &issue_id(&card()),
            Some(&store.backups()),
        )
        .await
        .unwrap();
        assert!(
            done.contains(&format!("OpenGLDriverName {}", own(ICD))),
            "{done}"
        );
        assert!(done.contains("Restart Windows") && done.contains("registry backups"));

        let calls = reg_calls(&mock);
        let added: Vec<&String> = calls
            .iter()
            .filter(|c| c.starts_with("reg.exe add"))
            .collect();
        assert_eq!(
            added,
            [
                &format!(
                    "reg.exe add {KEY} /v OpenGLDriverName /t REG_MULTI_SZ /d {} /f",
                    own(ICD)
                ),
                &format!(
                    "reg.exe add {KEY} /v OpenGLDriverNameWow /t REG_MULTI_SZ /d {} /f",
                    own(ICD_WOW)
                ),
            ]
        );
        let first_add = calls
            .iter()
            .position(|c| c.starts_with("reg.exe add"))
            .unwrap();
        let exports = |calls: &[String]| {
            calls
                .iter()
                .filter(|c| c.starts_with("reg.exe export"))
                .count()
        };
        assert_eq!(
            exports(&calls[..first_add]),
            2,
            "backed up first: {calls:?}"
        );
        assert_eq!(exports(&calls[first_add..]), 0);
        for name in ["OpenGLDriverName", "OpenGLDriverNameWow"] {
            let read_back = format!("reg.exe query {KEY} /v {name}");
            assert!(calls[first_add..].contains(&read_back), "{calls:?}");
        }

        // Each backup holds the entry as it was, written as reg export wrote it.
        let backups = RegBackupManager::with_dir(store.backups()).list_backups();
        assert_eq!(backups.len(), 2);
        let held: Vec<String> = backups
            .iter()
            .map(|record| text_of(&std::fs::read(&record.file_path).unwrap()))
            .collect();
        for (name, value) in [(ICD, "OpenGLDriverName"), (ICD_WOW, "OpenGLDriverNameWow")] {
            let lines = hex7_lines(&format!("\"{value}\"=hex(7):"), &in_opengl_package(name));
            assert_eq!(held.iter().filter(|text| text.contains(&lines)).count(), 1);
        }
        assert!(backups.iter().all(|record| record.key_path == KEY));
    }

    #[tokio::test]
    async fn without_backups_the_entries_are_set_straight_away() {
        let store = Store::new("no_backup");
        let mock = repairable(&[]);
        let done = repair(&mock, &store.store(), &issue_id(&card()), None)
            .await
            .unwrap();
        assert!(!done.contains("backup"), "{done}");
        let calls = reg_calls(&mock);
        assert!(!calls.iter().any(|c| c.starts_with("reg.exe export")));
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("reg.exe add"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn a_failed_backup_changes_nothing() {
        let store = Store::new("backup_failed");
        let mock = repairable(&[(
            "reg.exe export",
            CmdOutput::with_output(1, "", "FEHLER: Zugriff verweigert"),
        )]);
        let error = repair(
            &mock,
            &store.store(),
            &issue_id(&card()),
            Some(&store.backups()),
        )
        .await
        .unwrap_err();
        assert!(error.starts_with("Aborted") && error.ends_with("Nothing was changed."));
        assert!(
            !reg_calls(&mock)
                .iter()
                .any(|c| c.starts_with("reg.exe add"))
        );
    }

    #[tokio::test]
    async fn a_refused_entry_says_what_is_set_already() {
        let store = Store::new("refused");
        let mock = repairable(&[(
            "/v OpenGLDriverNameWow /t",
            CmdOutput::with_output(1, "", "FEHLER: Zugriff verweigert"),
        )]);
        let error = repair(&mock, &store.store(), &issue_id(&card()), None)
            .await
            .unwrap_err();
        assert!(
            error.contains(&format!("Could not set {KEY}\\OpenGLDriverNameWow")),
            "{error}"
        );
        assert!(
            error.ends_with("OpenGLDriverName is set already."),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_entry_that_reads_back_unchanged_is_an_error() {
        let store = Store::new("unchanged");
        let mock = pc(&[ICD, ICD_WOW]);
        mock.add_response("reg.exe add", CmdOutput::ok(""));
        let error = repair(&mock, &store.store(), &issue_id(&card()), None)
            .await
            .unwrap_err();
        assert!(
            error.contains(&format!(
                "was set to {} but reads REG_MULTI_SZ {}",
                own(ICD),
                in_opengl_package(ICD)
            )),
            "{error}"
        );
    }

    #[tokio::test]
    async fn what_is_in_order_by_now_is_left_alone() {
        let store = Store::new("in_order");
        let id = issue_id(&card());
        let healthy = pc(&[]);
        let gone = pc(&[ICD, ICD_WOW]);
        gone.set_devices(Vec::new());
        for mock in [healthy, gone] {
            let done = repair(&mock, &store.store(), &id, Some(&store.backups()))
                .await
                .unwrap();
            assert!(done.contains("nothing was changed"), "{done}");
            assert!(
                !reg_calls(&mock)
                    .iter()
                    .any(|c| !c.starts_with("reg.exe query"))
            );
        }
    }

    #[tokio::test]
    async fn without_the_file_beside_the_direct3d_driver_nothing_is_changed() {
        let store = Store::new("no_replacement");
        store.remove_own(ICD);
        let mock = repairable(&[]);
        let error = repair(
            &mock,
            &store.store(),
            &issue_id(&card()),
            Some(&store.backups()),
        )
        .await
        .unwrap_err();
        assert!(
            error.ends_with(
                "Install the graphics driver from Advanced Micro Devices, Inc. again. Nothing was changed."
            ),
            "{error}"
        );
        assert!(
            reg_calls(&mock)
                .iter()
                .all(|c| c.starts_with("reg.exe query"))
        );
    }
}
