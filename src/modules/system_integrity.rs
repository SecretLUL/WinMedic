use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::feature_rollback::{self, Rollback};
use crate::modules::install_media::{self, Media};
use crate::modules::service_chain;
use crate::modules::tweaks::device_name;
use crate::modules::{
    DiagnosticModule, FixProgress, ModuleProgress, SERVICING_TIMEOUT, console_lines,
};
use crate::utils::cmd::{CmdOutput, CommandRunner, SystemCommandRunner};
use crate::utils::service::{self, SERVICE_DISABLED, SERVICE_RUNNING};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

/// `/English` pins DISM's output language. Its verdict is a sentence in the
/// display language otherwise, and the German one ("Der Komponentenspeicher
/// kann repariert werden.") matched none of the words this check looked for,
/// so a damaged store was reported as intact on every German machine.
const DISM_CHECK_HEALTH_ARGS: &[&str] = &["/English", "/Online", "/Cleanup-Image", "/CheckHealth"];
const DISM_RESTORE_HEALTH_ARGS: &[&str] =
    &["/English", "/Online", "/Cleanup-Image", "/RestoreHealth"];

/// How long mounting the ISOs and listing their images may take.
const MEDIA_TIMEOUT: Duration = Duration::from_secs(300);

/// DISM's exit code as it prints it: an HRESULT in hex, a Windows error
/// number in decimal.
fn dism_code(code: i32) -> String {
    if code < 0 {
        format!("0x{:08X}", code as u32)
    } else {
        code.to_string()
    }
}

/// Why a DISM run failed: its error code and the message it printed after
/// `Error: <code>`.
fn dism_failure(out: &CmdOutput) -> String {
    let Some(code) = out.exit_code else {
        return "DISM was terminated".to_string();
    };
    let message = out
        .stdout
        .lines()
        .map(str::trim)
        .skip_while(|line| !line.starts_with("Error:"))
        .skip(1)
        .find(|line| !line.is_empty());
    match message {
        Some(message) => format!("error {}: {message}", dism_code(code)),
        None => format!("error {}", dism_code(code)),
    }
}

/// How much of the end of CBS.log to read. The log grows to hundreds of
/// megabytes; the last SFC or DISM run is all that matters, and its summary
/// sits at the very end.
const CBS_TAIL_BYTES: u64 = 64 * 1024;

/// How much of the end of CBS.log is searched for DISM's last report. Its list
/// of damaged files comes before the summary and runs to a hundred kilobytes
/// for a few hundred files.
const STORE_REPORT_TAIL_BYTES: u64 = 8 * 1024 * 1024;

/// What the last DISM scan or repair reported about the component store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreReport {
    pub detected: u32,
    pub repaired: u32,
    /// Damaged payloads left unrepaired that are backup copies: the reverse
    /// differentials in a component's `r` folder, which let Windows go back
    /// to an older version of a file.
    pub missing_backups: u32,
    /// Everything else it listed as damaged and left unrepaired.
    pub other_unrepaired: u32,
    /// Servicing marked the store corrupt after the report, when an update
    /// failed on a damaged component: damage the report does not know.
    pub marked_corrupt_since: bool,
}

/// What CBS logs when servicing finds a damaged component outside a DISM
/// scan: "Mark store corruption flag because of package: ...".
const MARKED_CORRUPT: &str = "Mark store corruption flag";

impl StoreReport {
    /// Whether all DISM left unrepaired are backup copies.
    ///
    /// On Windows 11 24H2 and later, `DISM /RestoreHealth` repairs file flags
    /// and marks files as having a backup copy it never writes; the next scan
    /// reports those copies missing, and no source holds them. On the
    /// development PC a repair that ended "2049 repaired" set the flag on 328
    /// files, and the scan after it listed exactly those 328 as missing in
    /// their component's `r` folder. The files Windows runs are intact, so
    /// this is no damage to repair.
    pub fn only_backups_left(&self) -> bool {
        self.detected > self.repaired
            && !self.marked_corrupt_since
            && self.other_unrepaired == 0
            && self.missing_backups == self.detected - self.repaired
    }
}

/// The last report of a DISM scan or repair in `log`: from "Checking System
/// Update Readiness." to its summary, one `(p)` line per damaged item. CBS
/// writes it in English on every system.
pub fn last_store_report(log: &str) -> Option<StoreReport> {
    let report = &log[log.rfind("Checking System Update Readiness.")?..];
    let counted =
        |line: &str, label: &str| -> Option<u32> { line.split_once(label)?.1.trim().parse().ok() };
    let (mut detected, mut repaired) = (None, None);
    let (mut missing_backups, mut other_unrepaired) = (0, 0);
    let mut after_summary = "";
    for line in report.lines() {
        if let Some(count) = counted(line, "Total Detected Corruption:") {
            detected = Some(count);
        } else if let Some(count) = counted(line, "Total Repaired Corruption:") {
            repaired = Some(count);
            let summary_at = line.as_ptr() as usize - report.as_ptr() as usize;
            after_summary = &report[summary_at + line.len()..];
            break;
        } else if let Some((_, item)) = line.split_once("(p)\t") {
            // `CSI Payload Corrupt\t(n)\t\t\t<component>\r\<file>`, or with
            // `(w)\t(Fixed)` once repaired.
            let fields: Vec<&str> = item.split('\t').collect();
            if fields.contains(&"(Fixed)") {
                continue;
            }
            let backup = fields[0] == "CSI Payload Corrupt"
                && fields
                    .last()
                    .and_then(|path| path.trim().split_once('\\'))
                    .is_some_and(|(_, in_component)| in_component.starts_with("r\\"));
            if backup {
                missing_backups += 1;
            } else {
                other_unrepaired += 1;
            }
        }
    }
    Some(StoreReport {
        detected: detected?,
        repaired: repaired?,
        missing_backups,
        other_unrepaired,
        marked_corrupt_since: after_summary.contains(MARKED_CORRUPT),
    })
}

/// What the user reads when all DISM left are backup copies.
fn only_backups_missing(count: u32) -> String {
    format!(
        "Windows itself is intact. DISM still lists {count} backup copies inside the component store as missing; Windows 11 24H2 and later leaves these behind, and they need no repair."
    )
}

/// What `DISM /CheckHealth` said about the component store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentStoreHealth {
    Healthy,
    Repairable,
    NotRepairable,
    /// DISM did not run to a verdict; the reason is for the log.
    Unknown(String),
}

impl ComponentStoreHealth {
    pub fn from_dism(output: &CmdOutput) -> Self {
        if !output.success {
            return Self::Unknown(match output.exit_code {
                Some(740) => "DISM needs Administrator rights".to_string(),
                Some(code) => format!("DISM exited with code {code}"),
                None => "DISM was terminated".to_string(),
            });
        }
        let text = output.stdout.to_lowercase();
        // The English sentences come from DISM's own resources. The German
        // ones stay for a DISM that ignores /English; they are the same
        // resources' de-DE versions.
        let says = |phrases: &[&str]| phrases.iter().any(|p| text.contains(p));
        if says(&[
            "the component store cannot be repaired",
            "der komponentenspeicher kann nicht repariert werden",
        ]) {
            Self::NotRepairable
        } else if says(&[
            "the component store is repairable",
            "der komponentenspeicher kann repariert werden",
        ]) {
            Self::Repairable
        } else if says(&[
            "no component store corruption detected",
            "es wurde keine komponentenspeicherbeschädigung erkannt",
        ]) {
            Self::Healthy
        } else {
            Self::Unknown("DISM reported no health verdict".to_string())
        }
    }
}

/// Whether the end of CBS.log records corruption the last run left unrepaired,
/// with the lines that say so.
///
/// Matching the bare word "Corrupt" fired on DISM's own summary, whose
/// "Total Detected Corruption: 0" says the opposite — so every DISM run,
/// WinMedic's own repair included, made the next scan report damaged system
/// files. Only statements of an unrepaired file count here: SFC giving up on
/// one, a driver file SFC found damaged and did not put back, or a DISM
/// summary that detected more than it repaired.
pub fn cbs_unrepaired_corruption(tail: &str) -> Option<String> {
    unrepaired_evidence(tail, true)
}

/// [`cbs_unrepaired_corruption`], with DISM's summary left out unless
/// `dism_summary` - for when that summary counts only backup copies.
fn unrepaired_evidence(tail: &str, dism_summary: bool) -> Option<String> {
    const SFC_GAVE_UP: [&str; 2] = [
        "Cannot repair member file",
        "Could not reproject corrupted file",
    ];
    let mut evidence: Vec<String> = tail
        .lines()
        .filter(|line| SFC_GAVE_UP.iter().any(|marker| line.contains(marker)))
        .take(3)
        .map(|line| line.trim().to_string())
        .collect();

    let damaged: Vec<String> = pnp_files(tail)
        .into_iter()
        .filter_map(|(path, damaged)| damaged.then_some(path))
        .collect();
    evidence.extend(
        damaged
            .iter()
            .take(3)
            .map(|path| format!("Damaged and not repaired: {path}")),
    );
    if damaged.len() > 3 {
        evidence.push(format!("... and {} more", damaged.len() - 3));
    }

    let count_after = |label: &str, text: &str| -> Option<(usize, u32)> {
        let at = text.rfind(label)?;
        let value = text[at + label.len()..]
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()?;
        Some((at, value))
    };
    if let Some((at, detected)) =
        count_after("Total Detected Corruption:", tail).filter(|_| dism_summary)
    {
        let repaired = count_after("Total Repaired Corruption:", &tail[at..])
            .map(|(_, repaired)| repaired)
            .unwrap_or(0);
        if detected > repaired {
            evidence.push(format!(
                "DISM summary: {detected} corruption(s) detected, {repaired} repaired"
            ));
        }
    }

    (!evidence.is_empty()).then(|| evidence.join("\n"))
}

/// Every driver file SFC wrote about in `log`, and whether the last thing it
/// said was that the file is damaged.
///
/// On Windows 11 SFC logs a damaged driver file as `DEPLOY [Pnp] Corrupt
/// file: <path>` and, once it has put the original back, as `... Repaired
/// file: <path>`; `/verifyonly` writes only the first. Neither is an `[SR]`
/// line, which is all SFC wrote about files before.
fn pnp_files(log: &str) -> Vec<(String, bool)> {
    const CORRUPT: &str = "[Pnp] Corrupt file: ";
    const REPAIRED: &str = "[Pnp] Repaired file: ";
    let mut files: Vec<(String, bool)> = Vec::new();
    for line in log.lines() {
        let (path, damaged) = if let Some((_, path)) = line.split_once(CORRUPT) {
            (path.trim(), true)
        } else if let Some((_, path)) = line.split_once(REPAIRED) {
            (path.trim(), false)
        } else {
            continue;
        };
        match files
            .iter_mut()
            .find(|(known, _)| known.eq_ignore_ascii_case(path))
        {
            Some(file) => file.1 = damaged,
            None => files.push((path.to_string(), damaged)),
        }
    }
    files
}

/// What an `sfc /scannow` run did, from the lines it added to CBS.log.
///
/// SFC exits 0 whether it found nothing, repaired everything or gave up on a
/// file, and says which in the display language. CBS.log says it in English
/// on every system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfcOutcome {
    /// Nothing damaged is left. `repaired` holds the files SFC put back, as
    /// far as it names them.
    Intact { repaired: Vec<String> },
    /// SFC could not repair everything; the lines that say what.
    Unrepaired(String),
    /// SFC checked nothing: it wrote no `[SR]` line.
    NotRun,
}

pub fn sfc_outcome(run_log: &str) -> SfcOutcome {
    if !run_log.contains("[SR] ") {
        return SfcOutcome::NotRun;
    }
    if let Some(evidence) = cbs_unrepaired_corruption(run_log) {
        return SfcOutcome::Unrepaired(evidence);
    }
    SfcOutcome::Intact {
        repaired: pnp_files(run_log)
            .into_iter()
            .map(|(path, _)| path)
            .collect(),
    }
}

/// What SFC printed after its progress bar, or all of it when it had none:
/// the paragraph that says why it checked nothing, in the display language.
fn sfc_message(stdout: &str) -> String {
    let lines: Vec<&str> = stdout.lines().map(str::trim).collect();
    let after_progress = lines
        .iter()
        .rposition(|line| line.contains('%'))
        .map_or(0, |at| at + 1);
    lines[after_progress..]
        .iter()
        .skip_while(|line| line.is_empty())
        .take_while(|line| !line.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ")
}

/// What was added to `path` after it was `from` bytes long. CBS archives a
/// full log and starts a new one, so a file that got shorter is read whole.
fn read_since(path: &Path, from: u64) -> std::io::Result<String> {
    let len = std::fs::metadata(path)?.len();
    let from = if len >= from { from } else { 0 };
    read_tail(path, len - from)
}

fn read_tail(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(max_bytes)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

fn default_cbs_log() -> PathBuf {
    system_root().join(r"Logs\CBS\CBS.log")
}

fn default_reagent_xml() -> PathBuf {
    system_root().join(r"System32\Recovery\ReAgent.xml")
}

/// Whether ReAgent.xml says the recovery environment is enabled.
///
/// `reagentc /info` says so too, but only elevated and only in the display
/// language. The file it reads is neither: `<InstallState state="1"/>` means
/// enabled on every Windows, unelevated or not.
pub fn winre_enabled(reagent_xml: &str) -> Option<bool> {
    let tag = &reagent_xml[reagent_xml.find("<InstallState")?..];
    let tag = &tag[..tag.find('>')?];
    let value = tag.split("state=").nth(1)?.trim_start_matches(['"', '\'']);
    match value.chars().next()? {
        '1' => Some(true),
        '0' => Some(false),
        _ => None,
    }
}

/// Asks WMI for the classes WinMedic's own checks read, one line per class.
///
/// A functional test rather than `winmgmt /verifyrepository`, which needs
/// elevation and answers in the display language. A repository that verifies
/// fine can still fail queries, and failing queries are what break things.
const WMI_PROBE_SCRIPT: &str = "foreach ($class in 'Win32_OperatingSystem', 'Win32_ComputerSystem', 'Win32_Volume') { try { $null = Get-CimInstance -ClassName $class -ErrorAction Stop; \"OK $class\" } catch { \"FAIL $class $($_.Exception.Message)\" } }";

/// The failed classes in [`WMI_PROBE_SCRIPT`]'s output, or `None` when it
/// printed no verdict at all - PowerShell itself failing is not WMI failing.
pub fn wmi_failures(output: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("OK ") || l.starts_with("FAIL "))
        .collect();
    if lines.is_empty() {
        return None;
    }
    Some(
        lines
            .into_iter()
            .filter_map(|l| l.strip_prefix("FAIL ").map(str::to_string))
            .collect(),
    )
}

/// Unmounts the ISOs a repair mounted. Dropped before [`Self::now`] ran, when
/// the repair is cancelled, it unmounts them on the runtime, because a
/// destructor cannot wait.
struct Dismount {
    runner: Arc<dyn CommandRunner>,
    isos: Vec<String>,
}

impl Dismount {
    async fn now(mut self) {
        let isos = std::mem::take(&mut self.isos);
        if !isos.is_empty() {
            let _ = self
                .runner
                .run_powershell(
                    &install_media::dismount_script(&isos),
                    Duration::from_secs(60),
                )
                .await;
        }
    }
}

impl Drop for Dismount {
    fn drop(&mut self) {
        let isos = std::mem::take(&mut self.isos);
        if isos.is_empty() {
            return;
        }
        let runner = self.runner.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = runner
                    .run_powershell(
                        &install_media::dismount_script(&isos),
                        Duration::from_secs(60),
                    )
                    .await;
            });
        }
    }
}

/// Every app package of this user as `status|full name|install location`.
/// `Status` is an enum name (`Ok`, `Modified`, `Tampered`, `LicenseIssue`,
/// `PackageOffline` and more, several joined with `, `), the same in every
/// language. Start, Settings and the Store are such packages; a broken one
/// does not open.
const APPX_PACKAGES_SCRIPT: &str = "Get-AppxPackage -ErrorAction Stop | ForEach-Object { '{0}|{1}|{2}' -f $_.Status, $_.PackageFullName, $_.InstallLocation }";

/// The finding for damaged app packages.
pub const APPX_BROKEN: &str = "sys_appx_broken";

/// The finding for app packages on a drive that is not there.
pub const APPX_OFFLINE: &str = "sys_appx_offline";

/// The package or its data is on a drive that is not there, such as an
/// unplugged external disk (`PackageStatus`: "the package is offline and
/// cannot be used"). Registering it again from its folder fails; connecting
/// the drive is what helps.
const OFFLINE_STATUS: [&str; 2] = ["PackageOffline", "DataOffline"];

/// A Store install or update is working on the package ("the package is
/// being serviced"); it passes on its own.
const PASSING_STATUS: [&str; 2] = ["DeploymentInProgress", "Servicing"];

/// One line of [`APPX_PACKAGES_SCRIPT`]'s output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppxPackage {
    pub status: String,
    pub full_name: String,
    pub install_location: String,
}

impl AppxPackage {
    /// `Microsoft.WindowsStore` out of its full name.
    pub fn name(&self) -> &str {
        self.full_name.split('_').next().unwrap_or(&self.full_name)
    }

    /// Whether one of the names in its `Status` is among `names`. A
    /// combination of flags prints as `Modified, NeedsRemediation`.
    fn status_among(&self, names: &[&str]) -> bool {
        self.status.split(',').any(|status| {
            names
                .iter()
                .any(|name| status.trim().eq_ignore_ascii_case(name))
        })
    }

    /// Whether it or its data is on a drive that is not there.
    pub fn offline(&self) -> bool {
        self.status_among(&OFFLINE_STATUS)
    }

    /// Whether Windows reports it damaged: `Modified`, `Tampered`,
    /// `NeedsRemediation`, `DependencyIssue`, `LicenseIssue` or any other
    /// status but `Ok`, unless it is offline or only being serviced.
    pub fn damaged(&self) -> bool {
        !self.offline()
            && self.status.split(',').map(str::trim).any(|status| {
                !status.eq_ignore_ascii_case("Ok")
                    && !PASSING_STATUS
                        .iter()
                        .any(|name| status.eq_ignore_ascii_case(name))
            })
    }

    /// The drive that is not there, `E:`: the one its folder is on, when it
    /// is `PackageOffline` and the folder starts with a drive letter. With
    /// only `DataOffline` it is the data's drive, which the folder does not
    /// tell.
    fn missing_drive(&self) -> Option<&str> {
        if !self.status_among(&["PackageOffline"]) {
            return None;
        }
        let drive = self.install_location.get(..2)?;
        (drive.ends_with(':') && drive.starts_with(|c: char| c.is_ascii_alphabetic()))
            .then_some(drive)
    }
}

pub fn parse_appx_packages(output: &str) -> Vec<AppxPackage> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim().splitn(3, '|');
            Some(AppxPackage {
                status: fields.next()?.to_string(),
                full_name: fields.next()?.to_string(),
                install_location: fields.next()?.to_string(),
            })
        })
        .collect()
}

/// The damaged packages, which can be registered again from their folder.
pub fn broken_packages(packages: Vec<AppxPackage>) -> Vec<AppxPackage> {
    packages
        .into_iter()
        .filter(|p| p.damaged() && !p.install_location.is_empty())
        .collect()
}

/// The packages on a drive that is not there, with the folder they are in.
pub fn offline_packages(packages: &[AppxPackage]) -> Vec<AppxPackage> {
    packages
        .iter()
        .filter(|p| p.offline() && !p.install_location.is_empty())
        .cloned()
        .collect()
}

/// Registers the package in `install_location` again for this user.
fn reregister_script(install_location: &str) -> String {
    format!(
        "Add-AppxPackage -DisableDevelopmentMode -Register {} -ErrorAction Stop",
        crate::utils::cmd::ps_single_quoted(&format!(r"{install_location}\AppxManifest.xml"))
    )
}

pub struct SystemIntegrityModule {
    runner: Arc<dyn CommandRunner>,
    cbs_log: PathBuf,
    reagent_xml: PathBuf,
    /// Where a Windows ISO to repair from is looked for.
    downloads: Option<PathBuf>,
    /// The setting "Restart services automatically".
    restart_services: bool,
}

impl Default for SystemIntegrityModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemIntegrityModule {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self::with_runner_and_cbs_log(runner, default_cbs_log())
    }

    /// For tests: read `cbs_log` instead of the machine's own CBS.log.
    pub fn with_runner_and_cbs_log(runner: Arc<dyn CommandRunner>, cbs_log: PathBuf) -> Self {
        Self {
            runner,
            cbs_log,
            reagent_xml: default_reagent_xml(),
            downloads: dirs::download_dir(),
            restart_services: true,
        }
    }

    /// Whether a repair may start a service: the setting "Restart services
    /// automatically".
    pub fn restarting_services(mut self, allowed: bool) -> Self {
        self.restart_services = allowed;
        self
    }

    /// For tests: read `path` instead of the machine's own ReAgent.xml.
    pub fn with_reagent_xml(mut self, path: PathBuf) -> Self {
        self.reagent_xml = path;
        self
    }

    /// For tests: look for ISOs in `folder` instead of the user's Downloads.
    pub fn with_downloads(mut self, folder: Option<PathBuf>) -> Self {
        self.downloads = folder;
        self
    }

    async fn app_packages(&self) -> Result<Vec<AppxPackage>, String> {
        let out = self
            .runner
            .query_powershell(APPX_PACKAGES_SCRIPT, Duration::from_secs(60))
            .await?;
        if !out.success {
            return Err(format!(
                "Get-AppxPackage failed (exit code {:?}): {}",
                out.exit_code,
                out.stderr.lines().next().unwrap_or("").trim()
            ));
        }
        Ok(parse_appx_packages(&out.stdout))
    }

    /// Register every damaged package again, then read the statuses back.
    async fn reregister_packages(&self) -> Result<String, String> {
        let broken = broken_packages(self.app_packages().await?);
        if broken.is_empty() {
            return Ok("Every app package is intact.".to_string());
        }
        let mut refused = Vec::new();
        for package in &broken {
            let out = self
                .runner
                .run_powershell(
                    &reregister_script(&package.install_location),
                    Duration::from_secs(120),
                )
                .await?;
            if !out.success {
                refused.push(format!(
                    "{}: {}",
                    package.name(),
                    out.stderr.lines().next().unwrap_or("").trim()
                ));
            }
        }
        let still: Vec<AppxPackage> = broken_packages(self.app_packages().await?)
            .into_iter()
            .filter(|p| broken.iter().any(|b| b.full_name == p.full_name))
            .collect();
        if still.is_empty() {
            return Ok(format!(
                "Registered {} app package(s) again; Windows reports them intact: {}.",
                broken.len(),
                broken
                    .iter()
                    .map(|p| p.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Err(format!(
            "Still damaged after registering them again: {}. Reinstall them from the Microsoft Store.{}",
            still
                .iter()
                .map(|p| format!("{} ({})", p.name(), p.status))
                .collect::<Vec<_>>()
                .join(", "),
            if refused.is_empty() {
                String::new()
            } else {
                format!(" Add-AppxPackage said: {}", refused.join("; "))
            }
        ))
    }

    /// The advice for app packages on a drive that is not there. Registering
    /// them again from a folder Windows cannot reach fails, so the finding is
    /// advice: connecting the drive clears it.
    fn offline_packages_issue(&self, offline: &[AppxPackage]) -> Issue {
        let mut drives: Vec<&str> = offline
            .iter()
            .filter_map(AppxPackage::missing_drive)
            .collect();
        drives.sort_unstable();
        drives.dedup();
        let recommendation = if offline.iter().any(|p| p.missing_drive().is_none()) {
            "Connect the drive these apps are on again".to_string()
        } else if drives.len() == 1 {
            format!("Connect drive {} again", drives[0])
        } else {
            format!("Connect drives {} again", drives.join(", "))
        };
        Issue::new(
            APPX_OFFLINE,
            self.id(),
            format!("{} app(s) are on a drive that is not connected", offline.len()),
            "System Integrity",
            Severity::Info,
            RiskScore::Low,
            "Windows reports app packages whose files or data are on a drive that is not there, such as an unplugged external disk. They work again once that drive is connected.",
            offline
                .iter()
                .map(|p| format!("{} ({}): {}", p.name(), p.status, p.install_location))
                .collect::<Vec<_>>()
                .join("\n"),
            recommendation,
            offline
                .iter()
                .map(|p| match p.missing_drive() {
                    Some(drive) => format!("Connect drive {drive}, which holds {}", p.name()),
                    None => format!("Connect the drive that holds the data of {}", p.name()),
                })
                .collect(),
        )
        .with_advice_only()
    }

    /// The feature installations Windows rolled back that no later one
    /// made good, from the ends of the CBS logs.
    /// Off the runtime: confirming a rollback reads the logs whole.
    async fn feature_rollbacks(&self) -> Vec<Rollback> {
        let logs = feature_rollback::cbs_logs(&self.cbs_log);
        tokio::task::spawn_blocking(move || {
            feature_rollback::rollbacks_in(&logs, feature_rollback::TAIL_BYTES)
        })
        .await
        .unwrap_or_default()
    }

    /// Why the service an installer waits for does not run: the cause, the
    /// recommendation, its steps, and lines for the technical details.
    async fn why_not_running(&self, service: &str) -> (String, String, Vec<String>, Vec<String>) {
        let devices = self.runner.connected_devices().await.unwrap_or_default();
        let chains = service_chain::chains_from_service(&*self.runner, &devices, service)
            .await
            .unwrap_or_default();
        if let Some(chain) = chains.first() {
            let name = device_name(&chain.device);
            let sentences: Vec<String> = chains
                .iter()
                .map(|chain| chain.sentence(&device_name(&chain.device)))
                .collect();
            return (
                format!("The installer waits for {service}. {}", sentences.join(" ")),
                format!("Repair '{name}' first, restart Windows, then install the feature again"),
                vec![format!(
                    "Repair '{name}' with its finding under Tweaks & Policies or Devices & Drivers, then restart Windows"
                )],
                chains.iter().map(service_chain::Chain::details).collect(),
            );
        }
        match service::state(&*self.runner, service).await {
            Ok(Some(SERVICE_RUNNING)) => (
                format!(
                    "The installer waits for {service}, which runs now, so installing the feature again should go through."
                ),
                "Install the feature again".to_string(),
                Vec::new(),
                Vec::new(),
            ),
            _ => (
                format!("The installer waits for {service}, which is not running."),
                format!("Find out why {service} does not start, then install the feature again"),
                vec![format!(
                    "Event Viewer -> Windows Logs -> System: the Service Control Manager's events about {service}"
                )],
                Vec::new(),
            ),
        }
    }

    /// The finding for a rolled-back installation. Advice: what the
    /// installer waited for is repaired where it is reported, and only the
    /// user can start the installation again.
    async fn rollback_issue(&self, rollback: &Rollback) -> Issue {
        let entry = feature_rollback::installer(&rollback.guid);
        let what = entry.map_or("a Windows feature", |entry| entry.features);
        let mut details = vec![
            format!(
                "CBS: Failed execution of queue item Installer: {} ({}) with HRESULT {}, then CBS_E_INSTALLERS_FAILED (0x800f0922)",
                rollback.installer, rollback.guid, rollback.hresult
            ),
            format!("At: {}", rollback.at),
        ];
        if !rollback.components.is_empty() {
            details.push(format!("Components: {}", rollback.components.join(", ")));
        }
        let (cause, recommendation, mut steps) = match entry {
            Some(entry) => {
                details.push(format!("Waits for: {}", entry.service));
                let (cause, recommendation, steps, chains) =
                    self.why_not_running(entry.service).await;
                details.extend(chains);
                (cause, recommendation, steps)
            }
            None => (
                "WinMedic does not know what this installer waits for.".to_string(),
                "Install the feature again; if it is rolled back again, look up the installer's error"
                    .to_string(),
                Vec::new(),
            ),
        };
        steps.push(
            "Install the feature again: Settings -> System -> Optional features -> More Windows features"
                .to_string(),
        );
        let id: String = rollback
            .guid
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .map(|c| if c == '-' { '_' } else { c })
            .collect();
        Issue::new(
            format!("sys_feature_rolled_back_{id}"),
            self.id(),
            format!("Installing {what} was rolled back"),
            "System Integrity",
            Severity::Warning,
            RiskScore::Low,
            format!(
                "On {} Windows rolled back installing {what}: its {} failed with {}. {cause}",
                rollback.at, rollback.installer, rollback.hresult
            ),
            details.join("\n"),
            recommendation,
            steps,
        )
        .with_advice_only()
    }

    fn cbs_log_len(&self) -> u64 {
        std::fs::metadata(&self.cbs_log).map_or(0, |m| m.len())
    }

    /// How many backup copies DISM left unrepaired, if that is all its run
    /// left: from the report the run added to CBS.log after `before` bytes.
    fn only_backups_left_since(&self, before: u64) -> Option<u32> {
        let report = last_store_report(&read_since(&self.cbs_log, before).ok()?)?;
        report.only_backups_left().then_some(report.missing_backups)
    }

    /// `DISM /RestoreHealth` from Windows installation media, for when
    /// Windows Update could not deliver the files: an ISO in Downloads,
    /// mounted for the run, or media that is mounted or inserted already.
    async fn restore_health_from_media(
        &self,
        first_run: &CmdOutput,
        log_tx: Option<Sender<String>>,
    ) -> Result<String, String> {
        if let Some(tx) = &log_tx {
            let _ = tx
                .send(format!(
                    "Windows Update could not deliver the files ({}). Looking for a Windows ISO in Downloads and on inserted media...",
                    dism_failure(first_run)
                ))
                .await;
        }
        let isos = self
            .downloads
            .as_deref()
            .map(install_media::isos_in)
            .unwrap_or_default();
        // Which ISOs are mounted already: when the search runs out of time
        // it never says which ones it mounted, and those stayed mounted.
        let attached_before = if isos.is_empty() {
            Vec::new()
        } else {
            match self
                .runner
                .run_powershell(&install_media::attached_script(&isos), MEDIA_TIMEOUT)
                .await
            {
                Ok(out) => install_media::attached(&out.stdout),
                // Unknown: unmount nothing the search does not name.
                Err(_) => isos.iter().map(|p| p.display().to_string()).collect(),
            }
        };
        let mut mounted = Dismount {
            runner: self.runner.clone(),
            isos: isos
                .iter()
                .map(|p| p.display().to_string())
                .filter(|iso| !attached_before.contains(iso))
                .collect(),
        };
        let found = match self
            .runner
            .run_powershell(&install_media::find_script(&isos), MEDIA_TIMEOUT)
            .await
        {
            Ok(found) => found,
            Err(err) => {
                mounted.now().await;
                return Err(err);
            }
        };
        let media = Media::parse(&found.stdout);
        mounted.isos = media.mounted.clone();
        if let Some(tx) = &log_tx {
            for failure in &media.failed {
                let _ = tx.send(format!("Not usable: {failure}")).await;
            }
        }

        let result = self.repair_from(&media, first_run, log_tx).await;
        mounted.now().await;
        result
    }

    async fn repair_from(
        &self,
        media: &Media,
        first_run: &CmdOutput,
        log_tx: Option<Sender<String>>,
    ) -> Result<String, String> {
        let (iso, page) = media.windows.as_ref().map_or(
            (
                "a Windows ISO of this PC's edition".to_string(),
                "windows11",
            ),
            |w| (w.iso_to_get(), w.download_page()),
        );
        let download = format!(
            "Save {iso} from microsoft.com/software-download/{page} in your Downloads folder, then run this repair again."
        );
        let Some(image) = media.best() else {
            let found = if media.images.is_empty() {
                String::new()
            } else {
                " The Windows installation media found holds no image of this PC's edition."
                    .to_string()
            };
            return Err(format!(
                "Windows Update could not deliver the files DISM needs (error {}).{found} {download}",
                dism_code(first_run.exit_code.unwrap_or_default())
            ));
        };

        let origin = media.origin(image);
        if let Some(tx) = &log_tx {
            let _ = tx
                .send(format!(
                    "Repairing from {origin}: image {} ({}, {}, {})",
                    image.index, image.edition, image.version, image.languages
                ))
                .await;
        }
        let source = image.dism_source();
        let mut args = DISM_RESTORE_HEALTH_ARGS.to_vec();
        args.extend([source.as_str(), "/LimitAccess"]);
        let before = self.cbs_log_len();
        let out = self
            .runner
            .run_streaming("dism.exe", &args, log_tx, SERVICING_TIMEOUT)
            .await?;
        if out.success {
            Ok(format!(
                "DISM repaired the component store from {origin}; Windows Update could not deliver the files."
            ))
        } else if install_media::source_missing(&out) {
            match self.only_backups_left_since(before) {
                Some(count) => Ok(format!(
                    "DISM repaired what it could from {origin}. {}",
                    only_backups_missing(count)
                )),
                // The ISO is of the right edition, so what it lacks is the
                // version: the damage is in files of updates newer than the
                // ISO, or of older ones later updates replaced. A repair
                // install puts in the ISO's whole store, and Windows Update
                // follows up.
                None => Err(format!(
                    "{origin} does not hold the damaged files' versions either. A repair install from it replaces them and keeps apps and files: open {origin} and run setup.exe."
                )),
            }
        } else {
            Err(format!(
                "DISM could not repair from {origin}: {}",
                dism_failure(&out)
            ))
        }
    }

    fn winre_state(&self) -> Option<bool> {
        let bytes = std::fs::read(&self.reagent_xml).ok()?;
        winre_enabled(&String::from_utf8_lossy(&bytes))
    }

    async fn send_progress(
        progress_tx: &Option<Sender<ModuleProgress>>,
        percent: u8,
        step: &str,
        log: Option<&str>,
    ) {
        if let Some(tx) = progress_tx {
            let _ = tx
                .send(ModuleProgress {
                    module_id: "system_integrity".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for SystemIntegrityModule {
    fn id(&self) -> &'static str {
        "system_integrity"
    }

    fn name(&self) -> &'static str {
        "System Integrity (DISM / SFC / VSS)"
    }

    fn description(&self) -> &'static str {
        "Checks the component store (DISM), system files (SFC), Volume Shadow Copy, the recovery environment, WMI and the app packages of Start, Settings and the Store"
    }

    fn icon(&self) -> &'static str {
        "[SYS]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. DISM CheckHealth
        Self::send_progress(
            &progress_tx,
            15,
            "Checking the component store (DISM CheckHealth, ~45s)...",
            Some("Running DISM /Online /Cleanup-Image /CheckHealth..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let dism_check = self
            .runner
            .run("dism.exe", DISM_CHECK_HEALTH_ARGS, Duration::from_secs(45))
            .await;
        // CheckHealth only repeats what the last scan or repair found, and
        // that one's report says what it was.
        let missing_backups = read_tail(&self.cbs_log, STORE_REPORT_TAIL_BYTES)
            .ok()
            .and_then(|tail| last_store_report(&tail))
            .filter(StoreReport::only_backups_left)
            .map(|report| report.missing_backups);

        match dism_check {
            Ok(output) => match ComponentStoreHealth::from_dism(&output) {
                ComponentStoreHealth::Repairable if missing_backups.is_some() => {
                    Self::send_progress(
                        &progress_tx,
                        35,
                        "DISM component store is intact",
                        Some(&format!(
                            "DISM CheckHealth: repairable, but its last report lists only missing backup copies. {}",
                            only_backups_missing(missing_backups.unwrap_or_default())
                        )),
                    )
                    .await;
                }
                ComponentStoreHealth::Repairable => {
                    issues.push(Issue::new(
                        "sys_dism_corrupt",
                        self.id(),
                        "Windows component store is corrupted",
                        "System Integrity",
                        Severity::Critical,
                        RiskScore::Low,
                        "The Windows component store (WinSxS) holds corrupted or inconsistent packages. This causes update and system failures.",
                        output.stdout.clone(),
                        "Repair automatically via DISM /Online /Cleanup-Image /RestoreHealth",
                        vec![
                            "Run DISM RestoreHealth with Windows Update as the repair source".to_string(),
                            "If Windows Update cannot deliver the files: repair from a Windows ISO in Downloads, or from an inserted installation USB stick or DVD".to_string(),
                        ],
                    ));
                }
                ComponentStoreHealth::NotRepairable => {
                    // RestoreHealth cannot fix a store DISM itself calls
                    // unrepairable, so offering it would be a repair that is
                    // bound to fail. What does work keeps apps and files.
                    issues.push(Issue::new(
                        "sys_dism_unrepairable",
                        self.id(),
                        "Windows component store cannot be repaired",
                        "System Integrity",
                        Severity::Critical,
                        RiskScore::High,
                        "DISM reports that the component store is damaged beyond what it can repair. Updates and feature changes will keep failing. A repair install of Windows replaces the system files while keeping installed apps and personal files.",
                        output.stdout.clone(),
                        "Run a Windows repair install that keeps apps and files",
                        vec![
                            "Windows 11: Settings > System > Recovery > 'Fix problems using Windows Update'".to_string(),
                            "Otherwise: mount a Windows ISO of the same edition and run setup.exe, choosing 'Keep personal files and apps'".to_string(),
                        ],
                    ).with_advice_only());
                }
                ComponentStoreHealth::Healthy => {
                    Self::send_progress(
                        &progress_tx,
                        35,
                        "DISM component store is intact",
                        Some("DISM CheckHealth: no corruption found in the component store."),
                    )
                    .await;
                }
                ComponentStoreHealth::Unknown(reason) => {
                    // Not "intact": nothing was checked, and saying otherwise
                    // is how an unelevated scan used to pass a damaged store.
                    Self::send_progress(
                        &progress_tx,
                        35,
                        "DISM check skipped",
                        Some(&format!("DISM CheckHealth gave no verdict: {reason}")),
                    )
                    .await;
                }
            },
            Err(e) => {
                Self::send_progress(
                    &progress_tx,
                    35,
                    "DISM check skipped (insufficient privileges)",
                    Some(&e),
                )
                .await;
            }
        }

        // 2. VSS Service Status
        Self::send_progress(
            &progress_tx,
            55,
            "Checking Volume Shadow Copy & VSS services...",
            Some("Querying the VSS and swprv service status..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        match service::start_type(&*self.runner, "vss").await {
            Ok(Some(SERVICE_DISABLED)) => {
                issues.push(Issue::new(
                    "sys_vss_disabled",
                    self.id(),
                    "Volume Shadow Copy service (VSS) is disabled",
                    "System Integrity",
                    Severity::Warning,
                    RiskScore::Low,
                    "The VSS service is disabled, so Windows can create neither system restore points nor consistent backups.",
                    "sc qc vss: START_TYPE 4 (DISABLED)",
                    "Reset the VSS service start type to 'Manual/Demand' and enable the service",
                    vec!["sc config vss start= demand".to_string(), "net start vss".to_string()],
                ));
            }
            Ok(Some(_)) => {
                Self::send_progress(
                    &progress_tx,
                    70,
                    "VSS service ready",
                    Some("VSS service status: ready for restore points."),
                )
                .await;
            }
            Ok(None) | Err(_) => {
                Self::send_progress(
                    &progress_tx,
                    70,
                    "VSS service state unknown",
                    Some("sc qc vss reported no start type; the VSS check was skipped."),
                )
                .await;
            }
        }

        // 3. CBS Logs Inspection
        Self::send_progress(
            &progress_tx,
            85,
            "Checking the CBS system logs for integrity errors...",
            Some("Inspecting CBS.log..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        if let Ok(tail) = read_tail(&self.cbs_log, CBS_TAIL_BYTES) {
            if let Some(evidence) = unrepaired_evidence(&tail, missing_backups.is_none()) {
                issues.push(Issue::new(
                    "sys_sfc_corrupt",
                    self.id(),
                    "System files show integrity violations (CBS)",
                    "System Integrity",
                    Severity::Warning,
                    RiskScore::Low,
                    "The Windows CBS logs report integrity errors on protected system files.",
                    format!("Found in CBS.log:\n{evidence}"),
                    "Run SFC /scannow to restore system files from the local component store",
                    vec![
                        "Run sfc /scannow in the background and repair damaged system files"
                            .to_string(),
                    ],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    95,
                    "CBS logs unremarkable",
                    Some("No critical CBS integrity violations reported."),
                )
                .await;
            }
        }

        // 4. Feature installations Windows rolled back
        Self::send_progress(
            &progress_tx,
            96,
            "Checking for feature installations Windows rolled back...",
            Some("CBS.log and CbsPersist logs: failed advanced installers"),
        )
        .await;
        for rollback in self.feature_rollbacks().await {
            issues.push(self.rollback_issue(&rollback).await);
        }

        // 5. Windows Recovery Environment
        match self.winre_state() {
            Some(false) => issues.push(Issue::new(
                "sys_winre_disabled",
                self.id(),
                "The Windows Recovery Environment is switched off",
                "System Integrity",
                Severity::Warning,
                RiskScore::Medium,
                "When Windows no longer starts, the recovery environment is what offers Startup Repair, Safe Mode, System Restore and resetting the PC. With it switched off, a PC that fails to boot leaves only a reinstall from a USB stick.",
                format!("{}: InstallState 0", self.reagent_xml.display()),
                "Switch the recovery environment back on (reagentc /enable)",
                vec!["reagentc /enable".to_string()],
            )),
            Some(true) => {
                Self::send_progress(
                    &progress_tx,
                    92,
                    "Recovery environment enabled",
                    Some("The Windows Recovery Environment is enabled."),
                )
                .await;
            }
            None => {
                Self::send_progress(
                    &progress_tx,
                    92,
                    "Recovery environment not checked",
                    Some("ReAgent.xml could not be read; the recovery environment was not checked."),
                )
                .await;
            }
        }

        // 5. WMI
        Self::send_progress(
            &progress_tx,
            95,
            "Checking that WMI answers...",
            Some("Querying the WMI classes WinMedic itself relies on..."),
        )
        .await;
        if let Ok(out) = self
            .runner
            .query_powershell(WMI_PROBE_SCRIPT, Duration::from_secs(30))
            .await
        {
            match wmi_failures(&out.stdout) {
                Some(failures) if !failures.is_empty() => issues.push(Issue::new(
                    "sys_wmi_broken",
                    self.id(),
                    "WMI does not answer",
                    "System Integrity",
                    Severity::Critical,
                    RiskScore::Medium,
                    "Windows Management Instrumentation fails basic queries. System information, device and driver tools, many installers and several of WinMedic's own checks depend on it. If the Tweaks & Policies check reports the WMI service disabled, repair that first.",
                    failures.join("\n"),
                    "Salvage the WMI repository (winmgmt /salvagerepository)",
                    vec!["winmgmt /salvagerepository".to_string()],
                )),
                Some(_) => {
                    Self::send_progress(
                        &progress_tx,
                        98,
                        "WMI answers",
                        Some("Every probed WMI class answered."),
                    )
                    .await;
                }
                None => {}
            }
        }

        Self::send_progress(
            &progress_tx,
            99,
            "Checking the app packages...",
            Some("Get-AppxPackage: Start, Settings, the Store and every other app"),
        )
        .await;
        match self.app_packages().await {
            Ok(packages) => {
                let offline = offline_packages(&packages);
                if !offline.is_empty() {
                    issues.push(self.offline_packages_issue(&offline));
                }
                let broken = broken_packages(packages);
                if !broken.is_empty() {
                    issues.push(Issue::new(
                        APPX_BROKEN,
                        self.id(),
                        format!("{} app package(s) are damaged", broken.len()),
                        "System Integrity",
                        Severity::Warning,
                        RiskScore::Low,
                        "Windows reports app packages that are not intact. When one of them is Start, Settings or the Store, it does not open. Registering the package again from its folder usually repairs it.",
                        broken
                            .iter()
                            .map(|p| format!("{} ({}): {}", p.name(), p.status, p.install_location))
                            .collect::<Vec<_>>()
                            .join("\n"),
                        "Register the packages again (Add-AppxPackage -Register)",
                        broken
                            .iter()
                            .map(|p| {
                                format!(
                                    "Add-AppxPackage -DisableDevelopmentMode -Register \"{}\\AppxManifest.xml\"",
                                    p.install_location
                                )
                            })
                            .collect(),
                    ));
                }
            }
            Err(err) => {
                Self::send_progress(&progress_tx, 99, "App packages not checked", Some(&err)).await;
            }
        }

        Self::send_progress(&progress_tx, 100, "System integrity check complete", None).await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        let log_tx = console_lines(issue_id, progress_tx.as_ref());

        match issue_id {
            "sys_dism_corrupt" => {
                let before = self.cbs_log_len();
                let out = self
                    .runner
                    .run_streaming(
                        "dism.exe",
                        DISM_RESTORE_HEALTH_ARGS,
                        log_tx.clone(),
                        SERVICING_TIMEOUT,
                    )
                    .await?;
                if out.success {
                    Ok(
                        "DISM /RestoreHealth completed successfully. Component store repaired."
                            .to_string(),
                    )
                } else if install_media::source_missing(&out) {
                    // No source holds backup copies DISM never wrote, so an
                    // ISO is not looked for then.
                    match self.only_backups_left_since(before) {
                        Some(count) => Ok(only_backups_missing(count)),
                        None => self.restore_health_from_media(&out, log_tx).await,
                    }
                } else {
                    Err(format!("DISM repair failed with {}", dism_failure(&out)))
                }
            }
            "sys_vss_disabled" => {
                let config = self
                    .runner
                    .run(
                        "sc.exe",
                        &["config", "vss", "start=", "demand"],
                        Duration::from_secs(10),
                    )
                    .await?;
                if !config.success {
                    return Err(format!("sc config vss failed: {}", config.stdout.trim()));
                }
                // VSS is a demand-start service: it only has to be startable,
                // so a start that fails because it is already running is fine.
                if self.restart_services {
                    let _ = self
                        .runner
                        .run("net.exe", &["start", "vss"], Duration::from_secs(10))
                        .await;
                }
                match service::start_type(&*self.runner, "vss").await? {
                    Some(SERVICE_DISABLED) => Err(
                        "Windows accepted the change but VSS is still disabled - a group policy may enforce it"
                            .to_string(),
                    ),
                    _ if !self.restart_services => Ok(
                        "Volume Shadow Copy (VSS) service set to start on demand. Starting it was skipped because 'Restart services automatically' is off in the settings."
                            .to_string(),
                    ),
                    _ => Ok("Volume Shadow Copy (VSS) service set to start on demand.".to_string()),
                }
            }
            "sys_winre_disabled" => {
                let out = self
                    .runner
                    .run("reagentc.exe", &["/enable"], Duration::from_secs(120))
                    .await?;
                if self.winre_state() == Some(true) {
                    return Ok("The Windows Recovery Environment is enabled again.".to_string());
                }
                Err(format!(
                    "reagentc /enable did not enable it (exit code {:?}): {}. Its image, Winre.wim, is usually missing then; a repair install of Windows puts it back.",
                    out.exit_code,
                    out.stdout
                        .lines()
                        .map(str::trim)
                        .find(|l| !l.is_empty())
                        .unwrap_or("")
                ))
            }
            "sys_wmi_broken" => {
                let _ = self
                    .runner
                    .run(
                        "winmgmt.exe",
                        &["/salvagerepository"],
                        Duration::from_secs(300),
                    )
                    .await?;
                let probe = self
                    .runner
                    .query_powershell(WMI_PROBE_SCRIPT, Duration::from_secs(30))
                    .await?;
                match wmi_failures(&probe.stdout) {
                    Some(failures) if failures.is_empty() => {
                        Ok("WMI answers again after salvaging its repository.".to_string())
                    }
                    _ => Err(
                        "WMI still fails after salvaging its repository. 'winmgmt /resetrepository' rebuilds it from scratch but drops every third-party WMI registration; a repair install of Windows is the safer next step."
                            .to_string(),
                    ),
                }
            }
            "sys_sfc_corrupt" => {
                let before = std::fs::metadata(&self.cbs_log).map_or(0, |m| m.len());
                let out = self
                    .runner
                    .run_streaming("sfc.exe", &["/scannow"], log_tx, SERVICING_TIMEOUT)
                    .await?;
                let run_log = read_since(&self.cbs_log, before).unwrap_or_default();
                match sfc_outcome(&run_log) {
                    SfcOutcome::Intact { repaired } if repaired.is_empty() => Ok(
                        "SFC checked every protected system file and left none damaged."
                            .to_string(),
                    ),
                    SfcOutcome::Intact { repaired } => Ok(format!(
                        "SFC repaired {} damaged system file(s): {}.",
                        repaired.len(),
                        repaired
                            .iter()
                            .map(|path| path.rsplit('\\').next().unwrap_or(path))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                    SfcOutcome::Unrepaired(evidence) => Err(format!(
                        "SFC could not repair every damaged file. Repair the component store first (DISM /RestoreHealth), then run SFC again.\n{evidence}"
                    )),
                    SfcOutcome::NotRun => Err(format!(
                        "SFC checked no files (exit code {:?}): {}",
                        out.exit_code,
                        sfc_message(&out.stdout)
                    )),
                }
            }
            APPX_BROKEN => self.reregister_packages().await,
            _ => Err(format!("Unknown issue ID: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;
    use crate::utils::service::test_support::sc_qc_output;

    // DISM's verdicts, word for word from its en-US resources
    // (CbsProvider.dll.mui), framed the way DISM prints them.
    fn dism_says(verdict: &str) -> CmdOutput {
        CmdOutput::ok(format!(
            "\r\nDeployment Image Servicing and Management tool\r\nVersion: 10.0.26100.1\r\n\r\nImage Version: 10.0.26100.4652\r\n\r\n{verdict}\r\nThe operation completed successfully.\r\n"
        ))
    }
    const HEALTHY: &str = "No component store corruption detected.";
    const REPAIRABLE: &str = "The component store is repairable.";
    const NOT_REPAIRABLE: &str = "The component store cannot be repaired.";

    /// A real, elevated DISM run, progress bar and all, says the same
    /// sentence the resources above do.
    #[test]
    fn the_verdict_of_a_captured_dism_run_is_read() {
        let captured = decode_output(include_bytes!(
            "../../tests/fixtures/console/dism_scanhealth_progress.bin"
        ));
        assert_eq!(
            ComponentStoreHealth::from_dism(&CmdOutput::ok(captured)),
            ComponentStoreHealth::Repairable
        );
    }

    /// A module that reads no CBS.log, so the machine running the tests does
    /// not decide what they see.
    fn module_with(mock: MockCommandRunner) -> SystemIntegrityModule {
        SystemIntegrityModule::with_runner_and_cbs_log(
            Arc::new(mock),
            std::env::temp_dir().join("winmedic-test-no-such-cbs.log"),
        )
        .with_reagent_xml(std::env::temp_dir().join("winmedic-test-no-such-ReAgent.xml"))
        .with_downloads(None)
    }

    // DISM /RestoreHealth from the German 25H2 ISO on the development PC,
    // whose damage was in component versions the ISO does not carry: exit
    // -2146498283, "Error: 0x800f0915". See tests/fixtures/README.md.
    const DISM_REPAIR_CONTENT_MISSING: &[u8] = include_bytes!(
        "../../tests/fixtures/console/dism_restorehealth_repair_content_missing.bin"
    );
    // What the media search printed for that ISO, which it mounted, and for
    // the same ISO mounted already.
    const MEDIA_MOUNTED_IT: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_install_media_mount.bin");
    const MEDIA_MOUNTED_ALREADY: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_install_media_mounted.bin");
    const ISO: &str = r"C:\Users\user\Downloads\Win11_25H2_German_x64_v2.iso";

    /// DISM's answer when it found the repair content nowhere.
    fn repair_content_missing() -> CmdOutput {
        CmdOutput::with_output(-2146498283, decode_output(DISM_REPAIR_CONTENT_MISSING), "")
    }

    /// Windows Update cannot deliver the files; the media search answers
    /// `media`, and DISM run from it answers `from_media`.
    fn update_cannot_deliver(media: &str, from_media: CmdOutput) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("Dismount-DiskImage", CmdOutput::ok(""));
        mock.add_response("Get-WindowsImage", CmdOutput::ok(media));
        mock.add_response_after("Get-WindowsImage", "dism.exe", from_media);
        mock.add_response("dism.exe", repair_content_missing());
        mock
    }

    #[test]
    fn dism_says_why_it_failed_after_its_error_code() {
        assert_eq!(
            dism_failure(&repair_content_missing()),
            "error 0x800F0915: The repair content could not be found anywhere."
        );
        let not_a_wim = CmdOutput::with_output(
            11,
            decode_output(include_bytes!(
                "../../tests/fixtures/console/dism_get_wiminfo_not_a_wim.bin"
            )),
            "",
        );
        assert_eq!(
            dism_failure(&not_a_wim),
            "error 11: An attempt was made to load a program with an incorrect format."
        );
    }

    #[tokio::test]
    async fn a_store_windows_update_cannot_repair_is_repaired_from_an_iso() {
        let mock = update_cannot_deliver(&decode_output(MEDIA_MOUNTED_IT), CmdOutput::ok(""));
        let msg = module_with(mock.clone())
            .fix("sys_dism_corrupt", None)
            .await
            .unwrap();
        assert_eq!(
            msg,
            "DISM repaired the component store from Win11_25H2_German_x64_v2.iso; Windows Update could not deliver the files."
        );
        let ran = mock.executed();
        let from_iso = ran
            .iter()
            .find(|c| c.contains("/Source:"))
            .expect("DISM ran from the ISO");
        assert!(
            from_iso.ends_with(r"/RestoreHealth /Source:wim:D:\sources\install.wim:5 /LimitAccess"),
            "{from_iso}"
        );
        let dismount = ran.last().unwrap();
        assert!(
            dismount.contains("Dismount-DiskImage") && dismount.contains(ISO),
            "{dismount}"
        );
    }

    #[tokio::test]
    async fn an_iso_the_user_mounted_stays_mounted() {
        let mock = update_cannot_deliver(&decode_output(MEDIA_MOUNTED_ALREADY), CmdOutput::ok(""));
        module_with(mock.clone())
            .fix("sys_dism_corrupt", None)
            .await
            .unwrap();
        assert!(!mock.executed().iter().any(|c| c.contains("Dismount")));
    }

    #[tokio::test]
    async fn without_an_iso_the_repair_says_where_to_get_one() {
        let this_pc = decode_output(MEDIA_MOUNTED_IT)
            .lines()
            .next()
            .unwrap()
            .to_string();
        let mock = update_cannot_deliver(&this_pc, CmdOutput::ok(""));
        let err = module_with(mock.clone())
            .fix("sys_dism_corrupt", None)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            "Windows Update could not deliver the files DISM needs (error 0x800F0915). Save the current Windows 11 ISO from microsoft.com/software-download/windows11 in your Downloads folder, then run this repair again."
        );
        assert!(!mock.executed().iter().any(|c| c.contains("/Source:")));
        assert!(
            !mock.executed().iter().any(|c| c.contains("Dismount")),
            "nothing was mounted"
        );
    }

    /// What happened on the development PC.
    #[tokio::test]
    async fn an_iso_without_the_damaged_versions_points_to_a_repair_install() {
        let mock =
            update_cannot_deliver(&decode_output(MEDIA_MOUNTED_IT), repair_content_missing());
        let err = module_with(mock.clone())
            .fix("sys_dism_corrupt", None)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            "Win11_25H2_German_x64_v2.iso does not hold the damaged files' versions either. A repair install from it replaces them and keeps apps and files: open Win11_25H2_German_x64_v2.iso and run setup.exe."
        );
        assert!(
            mock.executed()
                .last()
                .unwrap()
                .contains("Dismount-DiskImage")
        );
    }

    #[tokio::test]
    async fn only_a_missing_source_sends_dism_to_the_iso() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "dism.exe",
            CmdOutput::with_output(
                740,
                decode_output(include_bytes!(
                    "../../tests/fixtures/console/dism_elevation_required_english.bin"
                )),
                "",
            ),
        );
        let err = module_with(mock.clone())
            .fix("sys_dism_corrupt", None)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            "DISM repair failed with error 740: Elevated permissions are required to run DISM."
        );
        assert_eq!(mock.executed().len(), 1);
    }

    // The reports of the scan at 11:01 and of the ISO repair at 21:56 on the
    // development PC, cut from its CBS.log: 328 backup copies missing, all
    // of them files the repair in the morning had flagged, and nothing else.
    const CBS_SCAN_BACKUPS_MISSING: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_scanhealth_backups_missing.bin");
    const CBS_REPAIR_BACKUPS_MISSING: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_restorehealth_backups_missing.bin");

    /// `report` with one missing backup copy turned into a missing file of
    /// the component itself. Constructed: no PC here showed that.
    fn with_real_damage(report: &[u8]) -> String {
        text(report).replacen(
            r"3d9125d57cc0da9e\r\WMIC.exe",
            r"3d9125d57cc0da9e\WMIC.exe",
            1,
        )
    }

    #[test]
    fn a_report_of_only_missing_backups_is_recognised() {
        for report in [CBS_SCAN_BACKUPS_MISSING, CBS_REPAIR_BACKUPS_MISSING] {
            let report = last_store_report(&text(report)).unwrap();
            assert_eq!(
                report,
                StoreReport {
                    detected: 328,
                    repaired: 0,
                    missing_backups: 328,
                    other_unrepaired: 0,
                    marked_corrupt_since: false,
                }
            );
            assert!(report.only_backups_left());
        }

        let damaged = last_store_report(&with_real_damage(CBS_SCAN_BACKUPS_MISSING)).unwrap();
        assert_eq!(
            (damaged.missing_backups, damaged.other_unrepaired),
            (327, 1)
        );
        assert!(!damaged.only_backups_left());

        let all_repaired = text(CBS_SCAN_BACKUPS_MISSING).replace(
            "Total Repaired Corruption:\t0",
            "Total Repaired Corruption:\t328",
        );
        assert!(
            !last_store_report(&all_repaired)
                .unwrap()
                .only_backups_left()
        );
    }

    /// An update that failed on a damaged component after the report: the
    /// old report can no longer vouch for the store.
    #[test]
    fn damage_servicing_found_after_the_report_counts() {
        let later = format!(
            "{}2026-09-27 09:12:40, Info                  CBS    {MARKED_CORRUPT} because of package: Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9999.1.3\r\n",
            text(CBS_SCAN_BACKUPS_MISSING)
        );
        let report = last_store_report(&later).unwrap();
        assert!(report.marked_corrupt_since);
        assert!(!report.only_backups_left());
    }

    #[test]
    fn only_the_last_report_counts() {
        let log = with_real_damage(CBS_SCAN_BACKUPS_MISSING) + &text(CBS_REPAIR_BACKUPS_MISSING);
        assert!(last_store_report(&log).unwrap().only_backups_left());
        assert_eq!(last_store_report("no DISM run in here"), None);
    }

    fn cbs_file(name: &str, content: &[u8]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("winmedic-cbs-{name}-{}.log", std::process::id()));
        std::fs::write(&path, content).unwrap();
        path
    }

    /// A scan while DISM calls the store repairable and CBS.log holds `cbs`.
    async fn scan_repairable_with(name: &str, cbs: &[u8]) -> Vec<String> {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(REPAIRABLE));
        healthy_vss(&mock);
        let path = cbs_file(name, cbs);
        let issues = SystemIntegrityModule::with_runner_and_cbs_log(Arc::new(mock), path.clone())
            .with_reagent_xml(std::env::temp_dir().join("winmedic-test-no-such-ReAgent.xml"))
            .with_downloads(None)
            .scan(None)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&path);
        issues.into_iter().map(|issue| issue.id).collect()
    }

    /// What the development PC showed: no repair clears it, so offering one
    /// made a loop.
    #[tokio::test]
    async fn a_store_that_misses_only_backups_is_not_damaged() {
        let found = scan_repairable_with("scan-backups", CBS_REPAIR_BACKUPS_MISSING).await;
        assert!(found.is_empty(), "{found:?}");
    }

    #[tokio::test]
    async fn damage_next_to_missing_backups_is_reported() {
        let found = scan_repairable_with(
            "scan-damage",
            with_real_damage(CBS_REPAIR_BACKUPS_MISSING).as_bytes(),
        )
        .await;
        assert_eq!(found, vec!["sys_dism_corrupt", "sys_sfc_corrupt"]);
    }

    /// Stands in for DISM and the media search: each DISM run adds the next
    /// report to the CBS.log the module reads and answers with its output.
    /// Every command is recorded in `others`, which answers all but DISM.
    struct Servicing {
        cbs_log: PathBuf,
        dism_runs: std::sync::Mutex<Vec<(Vec<u8>, CmdOutput)>>,
        others: MockCommandRunner,
    }

    #[async_trait::async_trait]
    impl CommandRunner for Servicing {
        async fn run(
            &self,
            program: &str,
            args: &[&str],
            timeout: Duration,
        ) -> Result<CmdOutput, String> {
            self.others.run(program, args, timeout).await
        }

        async fn run_streaming(
            &self,
            program: &str,
            args: &[&str],
            _: Option<Sender<String>>,
            timeout: Duration,
        ) -> Result<CmdOutput, String> {
            use std::io::Write;
            assert_eq!(program, "dism.exe");
            let _ = self.others.run(program, args, timeout).await;
            let (report, out) = self.dism_runs.lock().unwrap().remove(0);
            std::fs::OpenOptions::new()
                .append(true)
                .open(&self.cbs_log)
                .and_then(|mut log| log.write_all(&report))
                .unwrap();
            Ok(out)
        }
    }

    async fn repair_with(
        name: &str,
        dism_runs: Vec<(Vec<u8>, CmdOutput)>,
        others: MockCommandRunner,
    ) -> Result<String, String> {
        let path = cbs_file(name, b"");
        let servicing = Servicing {
            cbs_log: path.clone(),
            dism_runs: std::sync::Mutex::new(dism_runs),
            others,
        };
        let result =
            SystemIntegrityModule::with_runner_and_cbs_log(Arc::new(servicing), path.clone())
                .with_reagent_xml(std::env::temp_dir().join("winmedic-test-no-such-ReAgent.xml"))
                .with_downloads(None)
                .fix("sys_dism_corrupt", None)
                .await;
        let _ = std::fs::remove_file(&path);
        result
    }

    #[tokio::test]
    async fn a_repair_that_leaves_only_backups_is_done() {
        let others = MockCommandRunner::with_default_success();
        let msg = repair_with(
            "dism-only-backups",
            vec![(
                CBS_REPAIR_BACKUPS_MISSING.to_vec(),
                repair_content_missing(),
            )],
            others.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            msg,
            "Windows itself is intact. DISM still lists 328 backup copies inside the component store as missing; Windows 11 24H2 and later leaves these behind, and they need no repair."
        );
        assert!(
            !others
                .executed()
                .iter()
                .any(|c| c.contains("Get-WindowsImage")),
            "no ISO holds them, so none is looked for"
        );
    }

    #[tokio::test]
    async fn an_iso_repair_that_leaves_only_backups_is_done() {
        let others = MockCommandRunner::with_default_success();
        others.add_response(
            "Get-WindowsImage",
            CmdOutput::ok(decode_output(MEDIA_MOUNTED_IT)),
        );
        let msg = repair_with(
            "dism-iso-backups",
            vec![
                (
                    with_real_damage(CBS_REPAIR_BACKUPS_MISSING).into_bytes(),
                    repair_content_missing(),
                ),
                (
                    CBS_REPAIR_BACKUPS_MISSING.to_vec(),
                    repair_content_missing(),
                ),
            ],
            others.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            msg,
            format!(
                "DISM repaired what it could from Win11_25H2_German_x64_v2.iso. {}",
                only_backups_missing(328)
            )
        );
        assert!(
            others
                .executed()
                .last()
                .unwrap()
                .contains("Dismount-DiskImage")
        );
    }

    /// The ReAgent.xml of a real Windows 11 with the recovery environment on.
    const REAGENT_ENABLED: &str = include_str!("../../tests/fixtures/files/reagent_enabled.xml");

    fn reagent_file(name: &str, content: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "winmedic-reagent-{}-{}.xml",
            name,
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn the_recovery_state_is_read_from_reagent_xml() {
        assert_eq!(winre_enabled(REAGENT_ENABLED), Some(true));
        let disabled =
            REAGENT_ENABLED.replace("<InstallState state=\"1\"/>", "<InstallState state=\"0\"/>");
        assert_eq!(winre_enabled(&disabled), Some(false));
        assert_eq!(winre_enabled("<WindowsRE/>"), None);
    }

    #[tokio::test]
    async fn a_disabled_recovery_environment_is_reported() {
        let path = reagent_file(
            "scan",
            &REAGENT_ENABLED.replace("<InstallState state=\"1\"/>", "<InstallState state=\"0\"/>"),
        );
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        healthy_vss(&mock);
        let issues = module_with(mock)
            .with_reagent_xml(path.clone())
            .scan(None)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].id, "sys_winre_disabled");
    }

    #[tokio::test]
    async fn enabling_the_recovery_environment_is_read_back() {
        let still_off = reagent_file("off", "<WindowsRE><InstallState state=\"0\"/></WindowsRE>");
        let mock = MockCommandRunner::new();
        mock.add_response(
            "reagentc.exe",
            CmdOutput::with_output(
                2,
                "REAGENTC.EXE: Das Windows RE-Abbild wurde nicht gefunden.",
                "",
            ),
        );
        let err = module_with(mock.clone())
            .with_reagent_xml(still_off.clone())
            .fix("sys_winre_disabled", None)
            .await
            .unwrap_err();
        assert!(err.contains("Winre.wim"), "{err}");

        std::fs::write(&still_off, REAGENT_ENABLED).unwrap();
        let ok = module_with(mock)
            .with_reagent_xml(still_off.clone())
            .fix("sys_winre_disabled", None)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&still_off);
        assert!(ok.contains("enabled again"));
    }

    #[test]
    fn wmi_failures_are_read_per_class() {
        assert_eq!(
            wmi_failures(
                "OK Win32_OperatingSystem\r\nOK Win32_ComputerSystem\r\nOK Win32_Volume\r\n"
            ),
            Some(vec![])
        );
        assert_eq!(
            wmi_failures("OK Win32_OperatingSystem\r\nFAIL Win32_Volume Ungültige Klasse \r\n"),
            Some(vec!["Win32_Volume Ungültige Klasse".to_string()])
        );
        // PowerShell failing to run at all is not a verdict on WMI.
        assert_eq!(
            wmi_failures("Das System kann die Datei nicht finden."),
            None
        );
    }

    #[tokio::test]
    async fn failing_wmi_queries_are_a_finding() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        healthy_vss(&mock);
        mock.add_response(
            "Get-CimInstance",
            CmdOutput::ok("FAIL Win32_OperatingSystem Invalid class\r\nFAIL Win32_ComputerSystem Invalid class\r\nOK Win32_Volume\r\n"),
        );
        let issues = module_with(mock).scan(None).await.unwrap();
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].id, "sys_wmi_broken");
        assert!(
            issues[0]
                .technical_details
                .contains("Win32_OperatingSystem")
        );
    }

    fn healthy_vss(mock: &MockCommandRunner) {
        mock.add_response("qc vss", CmdOutput::ok(sc_qc_output("vss", 3)));
    }

    #[tokio::test]
    async fn test_system_integrity_detects_dism_corruption() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(REPAIRABLE));
        healthy_vss(&mock);

        let issues = module_with(mock).scan(None).await.unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "sys_dism_corrupt");
        assert_eq!(issues[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn dism_is_asked_in_english() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        healthy_vss(&mock);

        let issues = module_with(mock.clone()).scan(None).await.unwrap();

        assert!(issues.is_empty());
        let dism = mock
            .executed()
            .into_iter()
            .find(|c| c.contains("dism.exe"))
            .expect("DISM ran");
        assert!(dism.contains("/English"), "{dism}");
    }

    #[tokio::test]
    async fn an_unrepairable_store_is_not_offered_restorehealth() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(NOT_REPAIRABLE));
        healthy_vss(&mock);

        let issues = module_with(mock).scan(None).await.unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "sys_dism_unrepairable");
        assert_eq!(issues[0].risk_score, RiskScore::High);
        assert!(issues[0].advice_only, "only a repair install clears it");
    }

    #[tokio::test]
    async fn an_unelevated_dism_is_no_verdict_at_all() {
        // Captured: German DISM refusing to run without elevation, exit 740.
        let refused = CmdOutput::with_output(
            740,
            decode_output(include_bytes!(
                "../../tests/fixtures/console/dism_elevation_required_de.bin"
            )),
            "",
        );
        assert!(matches!(
            ComponentStoreHealth::from_dism(&refused),
            ComponentStoreHealth::Unknown(reason) if reason.contains("Administrator")
        ));

        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", refused);
        healthy_vss(&mock);
        assert!(module_with(mock).scan(None).await.unwrap().is_empty());
    }

    #[test]
    fn the_german_verdicts_are_read_if_dism_ignores_english() {
        // These are the de-DE resource strings. The old check looked for
        // "reparierbar" and "beschädigt" and matched neither.
        let de = |text: &str| ComponentStoreHealth::from_dism(&CmdOutput::ok(text));
        assert_eq!(
            de("Der Komponentenspeicher kann repariert werden."),
            ComponentStoreHealth::Repairable
        );
        assert_eq!(
            de("Der Komponentenspeicher kann nicht repariert werden."),
            ComponentStoreHealth::NotRepairable
        );
        assert_eq!(
            de("Es wurde keine Komponentenspeicherbeschädigung erkannt."),
            ComponentStoreHealth::Healthy
        );
    }

    #[tokio::test]
    async fn test_system_integrity_detects_vss_disabled() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        mock.add_response("qc vss", CmdOutput::ok(sc_qc_output("vss", 4)));

        let issues = module_with(mock).scan(None).await.unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "sys_vss_disabled");
        assert_eq!(issues[0].severity, Severity::Warning);
    }

    #[tokio::test]
    async fn a_vss_repair_windows_does_not_keep_fails() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "config vss",
            CmdOutput::ok("[SC] ChangeServiceConfig ERFOLG"),
        );
        mock.add_response("net.exe", CmdOutput::ok(""));
        mock.add_response("qc vss", CmdOutput::ok(sc_qc_output("vss", 4)));

        let err = module_with(mock)
            .fix("sys_vss_disabled", None)
            .await
            .unwrap_err();
        assert!(err.contains("still disabled"), "{err}");
    }

    #[tokio::test]
    async fn vss_is_not_started_when_services_may_not_be() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "config vss",
            CmdOutput::ok("[SC] ChangeServiceConfig ERFOLG"),
        );
        mock.add_response("qc vss", CmdOutput::ok(sc_qc_output("vss", 3)));

        let msg = module_with(mock.clone())
            .restarting_services(false)
            .fix("sys_vss_disabled", None)
            .await
            .unwrap();
        assert!(msg.contains("Starting it was skipped"), "{msg}");
        assert!(!mock.executed().iter().any(|c| c.starts_with("net.exe")));
    }

    fn cbs_line(text: &str) -> String {
        format!("2026-09-01 10:00:00, Info                  CBS    {text}\r\n")
    }

    fn dism_summary(detected: u32, repaired: u32) -> String {
        [
            "Summary:".to_string(),
            "Operation: Detect and Repair ".to_string(),
            "Operation result: 0x0".to_string(),
            "Last Successful Step: Entire operation completes.".to_string(),
            format!("Total Detected Corruption:\t{detected}"),
            "\tCBS Manifest Corruption:\t0".to_string(),
            format!("\tCSI Payload Corruption:\t{detected}"),
            format!("Total Repaired Corruption:\t{repaired}"),
            format!("\tCSI Payload Repaired:\t{repaired}"),
        ]
        .iter()
        .map(|l| cbs_line(l))
        .collect()
    }

    #[test]
    fn a_clean_dism_summary_is_not_corruption() {
        // "Total Detected Corruption: 0" contains "Corrupt"; the old check
        // raised a finding on it after every DISM run, its own repair included.
        assert_eq!(cbs_unrepaired_corruption(&dism_summary(0, 0)), None);
        assert_eq!(cbs_unrepaired_corruption(&dism_summary(3, 3)), None);
    }

    #[test]
    fn corruption_left_unrepaired_is_reported() {
        let evidence = cbs_unrepaired_corruption(&dism_summary(2, 1)).expect("1 left over");
        assert!(
            evidence.contains("2 corruption(s) detected, 1 repaired"),
            "{evidence}"
        );

        let sfc = cbs_line(
            "[SR] Cannot repair member file [l:10]\"winload.efi\" of Microsoft-Windows-BootEnvironment-OSLoader",
        );
        let evidence = cbs_unrepaired_corruption(&sfc).expect("SFC gave up on a file");
        assert!(evidence.contains("winload.efi"));
    }

    #[test]
    fn only_the_latest_dism_summary_counts() {
        let log = format!("{}{}", dism_summary(2, 0), dism_summary(2, 2));
        assert_eq!(cbs_unrepaired_corruption(&log), None);
    }

    #[tokio::test]
    async fn the_cbs_log_is_read_from_its_tail() {
        let path = std::env::temp_dir().join(format!("winmedic-cbs-{}.log", std::process::id()));
        // Old damage far above the tail, then a clean run at the end.
        let mut log = cbs_line("[SR] Cannot repair member file [l:4]\"old.dll\"");
        log.push_str(&"x".repeat(CBS_TAIL_BYTES as usize * 2));
        log.push('\n');
        log.push_str(&dism_summary(0, 0));
        std::fs::write(&path, log).unwrap();

        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        healthy_vss(&mock);
        let module = SystemIntegrityModule::with_runner_and_cbs_log(Arc::new(mock), path.clone());
        let issues = module.scan(None).await.unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(!issues.iter().any(|i| i.id == "sys_sfc_corrupt"));
    }

    // What single SFC runs added to CBS.log on the capture machine, which
    // had three damaged Bluetooth drivers; see tests/fixtures/README.md.
    const CBS_SFC_FOUND_DAMAGE: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_sfc_verifyonly_found_damage.bin");
    const CBS_SFC_REPAIRED: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_sfc_scannow_repaired.bin");
    const CBS_SFC_CLEAN: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_sfc_verifyonly_clean.bin");
    const SFC_REPAIRED: &[u8] =
        include_bytes!("../../tests/fixtures/console/sfc_scannow_repaired_de.bin");
    const SFC_FOUND_DAMAGE: &[u8] =
        include_bytes!("../../tests/fixtures/console/sfc_verifyonly_progress_de.bin");
    const SFC_NOT_ELEVATED: &[u8] =
        include_bytes!("../../tests/fixtures/console/sfc_elevation_required_de.bin");

    const BLUETOOTH: [&str; 3] = [
        r"C:\WINDOWS\System32\drivers\BthA2dp.sys",
        r"C:\WINDOWS\System32\drivers\BthHfEnum.sys",
        r"C:\WINDOWS\System32\drivers\bthmodem.sys",
    ];

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn an_sfc_run_is_judged_by_what_it_logged() {
        assert_eq!(
            sfc_outcome(&text(CBS_SFC_REPAIRED)),
            SfcOutcome::Intact {
                repaired: BLUETOOTH.map(str::to_string).to_vec()
            }
        );
        assert_eq!(
            sfc_outcome(&text(CBS_SFC_CLEAN)),
            SfcOutcome::Intact { repaired: vec![] }
        );
        let SfcOutcome::Unrepaired(evidence) = sfc_outcome(&text(CBS_SFC_FOUND_DAMAGE)) else {
            panic!("the verify run left three files damaged");
        };
        for file in BLUETOOTH {
            assert!(
                evidence.contains(&format!("Damaged and not repaired: {file}")),
                "{evidence}"
            );
        }
        assert_eq!(sfc_outcome(""), SfcOutcome::NotRun);
    }

    #[test]
    fn a_driver_file_is_judged_by_the_last_run_that_named_it() {
        let repaired_later = text(CBS_SFC_FOUND_DAMAGE) + &text(CBS_SFC_REPAIRED);
        assert_eq!(cbs_unrepaired_corruption(&repaired_later), None);
        let damaged_again = text(CBS_SFC_REPAIRED) + &text(CBS_SFC_FOUND_DAMAGE);
        assert!(cbs_unrepaired_corruption(&damaged_again).is_some());
    }

    #[test]
    fn sfcs_message_is_the_paragraph_after_its_progress() {
        assert!(
            sfc_message(&decode_output(SFC_REPAIRED)).starts_with(
                "Der Windows-Ressourcenschutz hat beschädigte Dateien gefunden und erfolgreich repariert. "
            )
        );
        assert_eq!(
            sfc_message(&decode_output(SFC_NOT_ELEVATED)),
            "Sie müssen als Administrator angemeldet sein und eine Konsolensitzung ausführen, um das SFC-Hilfsprogramm verwenden zu können."
        );
    }

    #[test]
    fn a_cbs_log_archived_during_the_run_is_read_whole() {
        let path =
            std::env::temp_dir().join(format!("winmedic-cbs-since-{}.log", std::process::id()));
        std::fs::write(&path, "new log\n").unwrap();
        let grown = read_since(&path, 4).unwrap();
        let archived = read_since(&path, 1_000_000).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(grown, "log\n");
        assert_eq!(archived, "new log\n");
    }

    #[tokio::test]
    async fn a_driver_file_sfc_found_damaged_is_a_finding() {
        let path =
            std::env::temp_dir().join(format!("winmedic-cbs-damaged-{}.log", std::process::id()));
        std::fs::write(&path, CBS_SFC_FOUND_DAMAGE).unwrap();
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        healthy_vss(&mock);
        let module = SystemIntegrityModule::with_runner_and_cbs_log(Arc::new(mock), path.clone());
        let issues = module.scan(None).await.unwrap();
        let _ = std::fs::remove_file(&path);

        let issue = issues.iter().find(|i| i.id == "sys_sfc_corrupt").unwrap();
        assert!(
            issue.technical_details.contains(BLUETOOTH[0]),
            "{}",
            issue.technical_details
        );
    }

    /// Stands in for `sfc /scannow`: prints `stdout` and adds `run_log` to
    /// the CBS.log the module reads, as a real run does.
    struct Sfc {
        cbs_log: PathBuf,
        run_log: Vec<u8>,
        stdout: String,
    }

    #[async_trait::async_trait]
    impl CommandRunner for Sfc {
        async fn run(
            &self,
            program: &str,
            args: &[&str],
            _: Duration,
        ) -> Result<CmdOutput, String> {
            Err(format!("not expected: {program} {args:?}"))
        }

        async fn run_streaming(
            &self,
            program: &str,
            args: &[&str],
            _: Option<Sender<String>>,
            _: Duration,
        ) -> Result<CmdOutput, String> {
            use std::io::Write;
            assert_eq!((program, args), ("sfc.exe", &["/scannow"][..]));
            std::fs::OpenOptions::new()
                .append(true)
                .open(&self.cbs_log)
                .and_then(|mut log| log.write_all(&self.run_log))
                .unwrap();
            Ok(CmdOutput::ok(self.stdout.clone()))
        }
    }

    /// The SFC repair on a CBS.log that already holds `earlier`, while SFC
    /// prints `stdout` and logs `run_log`.
    async fn repair_with_sfc(
        name: &str,
        earlier: &[u8],
        run_log: &[u8],
        stdout: &[u8],
    ) -> Result<String, String> {
        let path =
            std::env::temp_dir().join(format!("winmedic-cbs-{name}-{}.log", std::process::id()));
        std::fs::write(&path, earlier).unwrap();
        let sfc = Sfc {
            cbs_log: path.clone(),
            run_log: run_log.to_vec(),
            stdout: decode_output(stdout),
        };
        let module = SystemIntegrityModule::with_runner_and_cbs_log(Arc::new(sfc), path.clone());
        let result = module.fix("sys_sfc_corrupt", None).await;
        let _ = std::fs::remove_file(&path);
        result
    }

    /// The damage the earlier verify run found is still in the log; only
    /// what this run added counts.
    #[tokio::test]
    async fn an_sfc_repair_names_the_files_it_put_back() {
        let msg = repair_with_sfc(
            "repaired",
            CBS_SFC_FOUND_DAMAGE,
            CBS_SFC_REPAIRED,
            SFC_REPAIRED,
        )
        .await
        .unwrap();
        assert_eq!(
            msg,
            "SFC repaired 3 damaged system file(s): BthA2dp.sys, BthHfEnum.sys, bthmodem.sys."
        );
    }

    #[tokio::test]
    async fn an_sfc_run_with_nothing_to_repair_says_so() {
        let msg = repair_with_sfc("clean", b"", CBS_SFC_CLEAN, b"")
            .await
            .unwrap();
        assert_eq!(
            msg,
            "SFC checked every protected system file and left none damaged."
        );
    }

    /// Exit 0 either way; the old repair called this "System files
    /// repaired".
    #[tokio::test]
    async fn an_sfc_run_that_leaves_damage_is_a_failure() {
        let err = repair_with_sfc("damage", b"", CBS_SFC_FOUND_DAMAGE, SFC_FOUND_DAMAGE)
            .await
            .unwrap_err();
        assert!(
            err.starts_with("SFC could not repair every damaged file."),
            "{err}"
        );
        assert!(err.contains(BLUETOOTH[0]), "{err}");
    }

    #[tokio::test]
    async fn an_sfc_run_that_checked_nothing_says_why() {
        let err = repair_with_sfc("refused", CBS_SFC_CLEAN, b"", SFC_NOT_ELEVATED)
            .await
            .unwrap_err();
        assert!(err.starts_with("SFC checked no files"), "{err}");
        assert!(
            err.contains("Sie müssen als Administrator angemeldet sein"),
            "{err}"
        );
    }

    /// A Downloads folder with one (empty) ISO in it, removed when dropped.
    struct Downloads(PathBuf);

    impl Downloads {
        fn with_iso(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("winmedic_iso_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("Win11.iso"), b"").unwrap();
            Self(dir)
        }

        fn iso(&self) -> String {
            self.0.join("Win11.iso").display().to_string()
        }
    }

    impl Drop for Downloads {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Windows Update cannot deliver, the ISO is mounted already or not
    /// (`attached`), and the media search never answers: no response is set
    /// for it, which the mock reports as an error, like a timeout.
    async fn search_fails(downloads: &Downloads, attached: &str) -> Vec<String> {
        let mock = MockCommandRunner::new();
        mock.add_response("Dismount-DiskImage", CmdOutput::ok(""));
        mock.add_response("\"ATTACHED`t", CmdOutput::ok(attached));
        mock.add_response("dism.exe", repair_content_missing());
        let result = module_with(mock.clone())
            .with_downloads(Some(downloads.0.clone()))
            .fix("sys_dism_corrupt", None)
            .await;
        assert!(result.is_err());
        mock.executed()
    }

    #[tokio::test]
    async fn an_iso_mounted_by_a_search_that_timed_out_is_unmounted() {
        let downloads = Downloads::with_iso("timeout");
        let ran = search_fails(&downloads, "").await;
        let dismount = ran.last().unwrap();
        assert!(
            dismount.contains("Dismount-DiskImage") && dismount.contains(&downloads.iso()),
            "{ran:?}"
        );
    }

    #[tokio::test]
    async fn an_iso_mounted_before_stays_mounted_when_the_search_fails() {
        let downloads = Downloads::with_iso("user_mounted");
        let ran = search_fails(&downloads, &format!("ATTACHED\t{}\r\n", downloads.iso())).await;
        assert!(!ran.iter().any(|c| c.contains("Dismount")), "{ran:?}");
    }

    #[test]
    fn the_mounted_isos_are_read() {
        assert_eq!(
            install_media::attached("ATTACHED\tC:\\a.iso\r\nnoise\r\n"),
            [r"C:\a.iso"]
        );
    }

    #[tokio::test]
    async fn the_attached_script_parses() {
        let script = install_media::attached_script(&[PathBuf::from(r"C:\a b.iso")]);
        assert_eq!(crate::utils::cmd::powershell_parse_errors(&script).await, 0);
    }

    /// Every app package of the capture machine's user, all `Ok`.
    fn real_packages() -> String {
        crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/powershell_appx_packages.bin"
        ))
    }

    /// The same with Start's package damaged.
    fn start_menu_damaged() -> String {
        real_packages().replace(
            "Ok|Microsoft.Windows.StartMenuExperienceHost_",
            "Modified|Microsoft.Windows.StartMenuExperienceHost_",
        )
    }

    const START: &str =
        r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy";

    #[test]
    fn the_captured_packages_are_intact() {
        let packages = parse_appx_packages(&real_packages());
        assert_eq!(packages.len(), 163);
        assert!(packages.iter().all(|p| p.status == "Ok"));
        assert!(broken_packages(packages).is_empty());
    }

    #[test]
    fn a_damaged_package_is_named_with_its_folder() {
        let broken = broken_packages(parse_appx_packages(&start_menu_damaged()));
        assert_eq!(broken.len(), 1);
        assert_eq!(
            broken[0].name(),
            "Microsoft.Windows.StartMenuExperienceHost"
        );
        assert_eq!(broken[0].status, "Modified");
        assert_eq!(broken[0].install_location, START);
    }

    #[tokio::test]
    async fn a_damaged_package_is_a_finding() {
        let mock = MockCommandRunner::with_default_success();
        mock.add_response("Get-AppxPackage", CmdOutput::ok(start_menu_damaged()));
        let issues = module_with(mock).scan(None).await.unwrap();
        let issue = issues.iter().find(|i| i.id == APPX_BROKEN).unwrap();
        assert!(issue.is_selected);
        assert!(
            issue
                .technical_details
                .contains("StartMenuExperienceHost (Modified)")
        );
    }

    /// The captured list with Xbox's package `status`, and on drive E: as an
    /// app moved to another drive is. Constructed: every captured package is
    /// `Ok` and on C:; only the status and the drive letter are changed.
    fn xbox_app(status: &str) -> String {
        real_packages().replace(
            r"Ok|Microsoft.GamingApp_2608.1001.17.0_x64__8wekyb3d8bbwe|C:\",
            &format!(r"{status}|Microsoft.GamingApp_2608.1001.17.0_x64__8wekyb3d8bbwe|E:\"),
        )
    }

    /// Registering it again from a folder on an unplugged disk fails, and
    /// the finding came back on every scan: advice to connect the drive.
    #[tokio::test]
    async fn an_app_on_an_unplugged_drive_is_advice() {
        let packages = parse_appx_packages(&xbox_app("PackageOffline"));
        assert!(broken_packages(packages.clone()).is_empty());
        assert_eq!(offline_packages(&packages).len(), 1);

        let mock = MockCommandRunner::with_default_success();
        mock.add_response("Get-AppxPackage", CmdOutput::ok(xbox_app("PackageOffline")));
        let issues = module_with(mock.clone()).scan(None).await.unwrap();
        assert!(!issues.iter().any(|i| i.id == APPX_BROKEN), "{issues:?}");
        let issue = issues.iter().find(|i| i.id == APPX_OFFLINE).unwrap();
        assert!(issue.advice_only && !issue.is_selected);
        assert_eq!(issue.recommended_fix, "Connect drive E: again");
        assert!(
            issue
                .technical_details
                .contains(r"Microsoft.GamingApp (PackageOffline): E:\Program Files\WindowsApps\"),
            "{}",
            issue.technical_details
        );

        // Nor does the repair of damaged packages try it.
        let msg = module_with(mock.clone())
            .fix(APPX_BROKEN, None)
            .await
            .unwrap();
        assert_eq!(msg, "Every app package is intact.");
        assert!(
            !mock
                .executed()
                .iter()
                .any(|c| c.contains("Add-AppxPackage"))
        );
    }

    /// Only the data is offline: the folder does not tell which drive.
    #[test]
    fn an_app_whose_data_is_offline_names_no_drive() {
        let offline = offline_packages(&parse_appx_packages(&xbox_app("DataOffline")));
        assert_eq!(offline.len(), 1);
        assert_eq!(offline[0].missing_drive(), None);
    }

    /// A Store install or update passes on its own; damage stays damage,
    /// also among several flags.
    #[test]
    fn statuses_are_read_by_their_names() {
        for passing in [
            "DeploymentInProgress",
            "Servicing",
            "DeploymentInProgress, Servicing",
        ] {
            assert!(
                broken_packages(parse_appx_packages(&xbox_app(passing))).is_empty(),
                "{passing}"
            );
        }
        for damaged in [
            "Modified",
            "Tampered",
            "NeedsRemediation",
            "DependencyIssue",
            "LicenseIssue",
            "Servicing, NeedsRemediation",
        ] {
            assert_eq!(
                broken_packages(parse_appx_packages(&xbox_app(damaged))).len(),
                1,
                "{damaged}"
            );
        }
        let both = parse_appx_packages(&xbox_app("Modified, PackageOffline"));
        assert!(broken_packages(both.clone()).is_empty());
        assert_eq!(offline_packages(&both).len(), 1);
    }

    /// The package list answers `before` until a package was registered.
    fn reregister_mock(add: CmdOutput, after: String) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("Get-AppxPackage", CmdOutput::ok(start_menu_damaged()));
        mock.add_response("Add-AppxPackage", add);
        mock.add_response_after("Add-AppxPackage", "Get-AppxPackage", CmdOutput::ok(after));
        mock
    }

    #[tokio::test]
    async fn a_registered_package_is_read_back() {
        let mock = reregister_mock(CmdOutput::ok(""), real_packages());
        let msg = module_with(mock.clone())
            .fix(APPX_BROKEN, None)
            .await
            .unwrap();
        assert!(msg.contains("StartMenuExperienceHost"), "{msg}");
        let add = mock
            .executed()
            .into_iter()
            .find(|c| c.contains("Add-AppxPackage"))
            .unwrap();
        assert!(
            add.contains(&format!(r"-Register '{START}\AppxManifest.xml'")),
            "{add}"
        );
    }

    #[tokio::test]
    async fn a_package_that_stays_damaged_is_a_failure() {
        let mock = reregister_mock(
            CmdOutput::with_output(1, "", "Fehler bei der Bereitstellung. HRESULT: 0x80073CF6"),
            start_menu_damaged(),
        );
        let err = module_with(mock).fix(APPX_BROKEN, None).await.unwrap_err();
        assert!(
            err.contains("Microsoft Store") && err.contains("0x80073CF6"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_app_package_scripts_parse() {
        for script in [
            APPX_PACKAGES_SCRIPT.to_string(),
            reregister_script(r"C:\A'B"),
        ] {
            assert_eq!(crate::utils::cmd::powershell_parse_errors(&script).await, 0);
        }
    }

    // Cut from the development PC's CBS logs of 2026-10-08: the Container
    // Installer failing and the start that rolled it back, at 20:50 and at
    // 21:14, and the start at 23:01 that installed Windows Sandbox. See
    // tests/fixtures/README.md.
    const CBS_ROLLED_BACK: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_container_installer_rolled_back.bin");
    const CBS_ROLLED_BACK_AGAIN: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_container_installer_rolled_back_again.bin");
    const CBS_INSTALLED: &[u8] =
        include_bytes!("../../tests/fixtures/files/cbs_container_installer_installed.bin");

    const ROLLED_BACK_ID: &str = "sys_feature_rolled_back_9edf0f01_ef44_4c87_ac5a_8aad730137ab";

    /// A folder like `C:\Windows\Logs\CBS` with these logs and an empty
    /// CBS.log, removed when the test ends.
    struct CbsFolder(PathBuf);

    impl CbsFolder {
        fn new(tag: &str, logs: &[(&str, &[u8])]) -> Self {
            let dir =
                std::env::temp_dir().join(format!("winmedic_cbs_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            for (name, bytes) in logs {
                std::fs::write(dir.join(name), bytes).unwrap();
            }
            std::fs::write(dir.join("CBS.log"), b"").unwrap();
            Self(dir)
        }

        fn module(&self, mock: MockCommandRunner) -> SystemIntegrityModule {
            SystemIntegrityModule::with_runner_and_cbs_log(Arc::new(mock), self.0.join("CBS.log"))
                .with_reagent_xml(std::env::temp_dir().join("winmedic-test-no-such-ReAgent.xml"))
                .with_downloads(None)
        }
    }

    impl Drop for CbsFolder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The development PC's logs on the evening of 2026-10-08: two
    /// rollbacks, and with `installed` the installation that followed.
    fn dev_pc_cbs(tag: &str, installed: bool) -> CbsFolder {
        let mut logs: Vec<(&str, &[u8])> = vec![
            ("CbsPersist_20261008190827.log", CBS_ROLLED_BACK),
            ("CbsPersist_20261008192300.log", CBS_ROLLED_BACK_AGAIN),
        ];
        if installed {
            logs.push(("CbsPersist_20261008212907.log", CBS_INSTALLED));
        }
        CbsFolder::new(tag, &logs)
    }

    fn hypervisor_service(problem: u32) -> crate::utils::pnp::PnpDevice {
        crate::utils::pnp::PnpDevice {
            problem,
            class: "System".to_string(),
            instance_id: r"ROOT\HVSERVICE\0000".to_string(),
            name: "Microsoft-Hypervisor-Dienst".to_string(),
            service: "hvservice".to_string(),
        }
    }

    async fn rollback_findings(folder: &CbsFolder, mock: MockCommandRunner) -> Vec<Issue> {
        mock.add_response("dism.exe", dism_says(HEALTHY));
        healthy_vss(&mock);
        folder
            .module(mock)
            .scan(None)
            .await
            .unwrap()
            .into_iter()
            .filter(|issue| issue.id.starts_with("sys_feature_rolled_back_"))
            .collect()
    }

    /// The evening of 2026-10-08 before the fix: Windows Sandbox rolled
    /// back, CmService not starting because HvHost stopped with 31, the
    /// device behind it disabled.
    #[tokio::test]
    async fn a_rolled_back_installation_names_what_the_installer_waited_for() {
        let folder = dev_pc_cbs("rolled_back", false);
        let mock = crate::modules::service_chain::test_support::dev_pc_services(31);
        mock.set_devices(vec![hypervisor_service(22)]);
        let found = rollback_findings(&folder, mock).await;
        assert_eq!(found.len(), 1, "{found:?}");
        let issue = &found[0];
        assert_eq!(issue.id, ROLLED_BACK_ID);
        assert_eq!(
            issue.title,
            "Installing Windows Sandbox or another container feature was rolled back"
        );
        assert_eq!(
            issue.description,
            "On 2026-10-08 21:19:36 Windows rolled back installing Windows Sandbox or another container feature: its Container Installer failed with HRESULT_FROM_WIN32(1753). The installer waits for CmService. Container-Manager-Dienst (CmService) cannot start: HV-Hostdienst (HvHost) failed (exit code 31) because the device 'Microsoft Hypervisor Service' is disabled."
        );
        assert!(issue.advice_only && !issue.is_selected);
        assert_eq!(
            issue.recommended_fix,
            "Repair 'Microsoft Hypervisor Service' first, restart Windows, then install the feature again"
        );
        for line in [
            "Components: Microsoft-Windows-Containers-DisposableClientVM 10.0.26100.9549, Microsoft-Windows-Professional-Config 10.0.26100.9550",
            "Waits for: CmService",
            r"Service chain: CmService (exit code 1068) -> HvHost (exit code 31) -> driver hvservice -> device ROOT\HVSERVICE\0000 (problem code 22)",
        ] {
            assert!(
                issue.technical_details.contains(line),
                "{}",
                issue.technical_details
            );
        }
    }

    /// The development PC today: Windows Sandbox installed at 23:01.
    #[tokio::test]
    async fn a_later_installation_of_the_same_feature_is_no_finding() {
        let folder = dev_pc_cbs("installed", true);
        let found = rollback_findings(&folder, MockCommandRunner::new()).await;
        assert!(found.is_empty(), "{found:?}");
    }

    /// The device works again but the feature was not installed since: the
    /// rollback stands, and the advice is to install again.
    #[tokio::test]
    async fn a_rollback_whose_service_runs_now_says_to_install_again() {
        let folder = dev_pc_cbs("runs_now", false);
        let mock = crate::modules::service_chain::test_support::listing(&[(
            "CmService",
            "Container-Manager-Dienst",
            4,
            0,
        )]);
        mock.add_response(
            "query CmService",
            CmdOutput::ok(crate::utils::service::test_support::sc_query_output(
                "CmService",
                4,
            )),
        );
        mock.set_devices(vec![hypervisor_service(0)]);
        let found = rollback_findings(&folder, mock).await;
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0]
                .description
                .ends_with("The installer waits for CmService, which runs now, so installing the feature again should go through."),
            "{}",
            found[0].description
        );
        assert_eq!(found[0].recommended_fix, "Install the feature again");
    }

    /// An installer the table does not know: the rollback is reported,
    /// without a guess at what it waited for.
    #[tokio::test]
    async fn a_rollback_of_another_installer_is_reported_without_a_cause() {
        let other = String::from_utf8_lossy(CBS_ROLLED_BACK)
            .replace(
                "{9edf0f01-ef44-4c87-ac5a-8aad730137ab}",
                "{00000000-1111-2222-3333-444444444444}",
            )
            .replace("Container Installer", "Other Installer");
        let folder = CbsFolder::new(
            "other",
            &[("CbsPersist_20261008190827.log", other.as_bytes())],
        );
        let found = rollback_findings(&folder, MockCommandRunner::new()).await;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found[0].title,
            "Installing a Windows feature was rolled back"
        );
        assert!(
            found[0].description.contains(
                "its Other Installer failed with HRESULT_FROM_WIN32(1753). WinMedic does not know"
            ),
            "{}",
            found[0].description
        );
    }
}
