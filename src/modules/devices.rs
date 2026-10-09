//! Devices Windows reports a problem for: stopped, or without a driver.
//!
//! This is the yellow warning sign in Device Manager, which few people ever
//! open. A USB port, the sound or the webcam that stopped working usually
//! shows up there with a problem code, and restarting the device - what
//! unplugging it and plugging it back in does - often brings it back.
//!
//! Only problem codes and device instance IDs decide, which are the same in
//! every display language; the device's name is for showing only. They come
//! from the device manager itself, see [`crate::utils::pnp`].

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::tweaks::{WU_POLICY_KEY, drivers_excluded_from_updates};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::pnp::PnpDevice;
use crate::utils::registry;
use crate::utils::service::{
    self, SERVICE_AUTO_START, SERVICE_DISABLED, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STOPPED, StartAgain,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

const CURRENT_VERSION_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
/// The build that brought `pnputil /restart-device` and `/scan-devices`.
const PNPUTIL_REPAIR_BUILD: u32 = 19041;
/// What to do where pnputil cannot.
const OLD_PNPUTIL: &str = "This Windows cannot restart devices from the command line (that needs Windows 10 2004 or later). In Device Manager, right-click the device and choose Disable device, then Enable device, or Scan for hardware changes.";

/// `CM_PROB_FAILED_INSTALL`: Windows found the device but has no driver for it.
const NO_DRIVER: u32 = 28;

pub type Device = PnpDevice;

impl Device {
    /// `'Brio 500'`, or `an unknown device (ACPI\AMDI0204)` for one without
    /// a name - the part of the instance ID that names the hardware, which is
    /// what to search for.
    pub fn label(&self) -> String {
        if self.name.trim().is_empty() {
            let hardware = self
                .instance_id
                .rsplit_once('\\')
                .map_or(self.instance_id.as_str(), |(hardware, _)| hardware);
            format!("an unknown device ({hardware})")
        } else {
            format!("'{}'", self.name.trim())
        }
    }

    /// The id of the finding about this device, or `None` when its problem
    /// is not a fault. It carries the remedy, so a repair never acts on a
    /// device whose problem has changed since the scan.
    pub fn finding_id(&self) -> Option<String> {
        let prefix = match remedy(self.problem) {
            Remedy::None => return None,
            Remedy::FindDriver => NO_DRIVER_ID,
            Remedy::Restart => FAILED_ID,
            Remedy::Advice => CANNOT_START_ID,
        };
        let slug: String = self
            .instance_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        Some(format!("{prefix}{slug}"))
    }

    fn details(&self) -> String {
        format!(
            "Device: {}\nInstance ID: {}\nSetup class: {}\nProblem code: {} ({})",
            if self.name.is_empty() {
                "(no name)"
            } else {
                &self.name
            },
            self.instance_id,
            if self.class.is_empty() {
                "(none)"
            } else {
                &self.class
            },
            self.problem,
            meaning(self.problem)
        )
    }
}

const NO_DRIVER_ID: &str = "dev_no_driver_";
const FAILED_ID: &str = "dev_failed_";
const CANNOT_START_ID: &str = "dev_cannot_start_";
const DRIVERS_EXCLUDED_ID: &str = "dev_wu_drivers_excluded";

/// Where the policy is switched off, after the ADMX and ADML in
/// `C:\Windows\PolicyDefinitions`.
const POLICY_OFF: &str = "If nobody set it on purpose: gpedit.msc -> Computer Configuration -> Administrative Templates -> Windows Components -> Windows Update -> Manage updates offered from Windows Update -> Do not include drivers with Windows Updates -> Not configured. Then look under Settings -> Windows Update -> Advanced options -> Optional updates.";

/// What WinMedic can do about a problem code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    /// Not a fault: switched off on purpose, unplugged, or on its way out.
    None,
    /// Look for hardware changes, which installs a driver Windows has by now.
    FindDriver,
    /// Restart the device.
    Restart,
    /// Restarting the device cannot help; see [`advice`].
    Advice,
}

pub fn remedy(problem: u32) -> Remedy {
    match problem {
        // 0 no problem, 21 being removed, 22 disabled, 29 disabled by the
        // firmware, 45 not connected, 46 Windows shutting down, 47 prepared
        // for safe removal, 53 reserved for the kernel debugger.
        0 | 21 | 22 | 29 | 45 | 46 | 47 | 53 => Remedy::None,
        NO_DRIVER => Remedy::FindDriver,
        14 | 32 | 38 | 48 | 52 => Remedy::Advice,
        _ => Remedy::Restart,
    }
}

/// What to do about a problem a device restart cannot clear: the
/// recommendation and its steps.
fn advice(problem: u32) -> (&'static str, &'static str) {
    match problem {
        14 | 38 => ("Restart Windows", RESTART_WINDOWS),
        32 => (
            "Reinstall its driver, which switches its service back on - a tweak tool may have switched it off",
            REINSTALL_DRIVER,
        ),
        _ => (
            "Install a current driver from the device's manufacturer",
            REINSTALL_DRIVER,
        ),
    }
}

const RESTART_WINDOWS: &str = "Restart Windows: Start -> Power -> Restart.";
const REINSTALL_DRIVER: &str = "Update or reinstall its driver: Device Manager -> right-click the device -> Update driver, or Uninstall device and restart Windows.";

/// What a problem code means, after the Device Manager error code list.
pub fn meaning(problem: u32) -> &'static str {
    match problem {
        3 => "its driver may be damaged, or Windows is low on memory",
        10 => "it cannot start",
        14 => "it needs Windows to restart",
        18 => "its driver needs to be reinstalled",
        19 => "its settings in the registry are damaged",
        24 => "it is not working properly or lacks a driver",
        NO_DRIVER => "no driver is installed for it",
        31 => "Windows cannot load its driver",
        32 => "its driver's service is switched off",
        37 => "its driver failed to start",
        38 => "an old copy of its driver is still in memory",
        39 => "its driver is damaged or missing",
        43 => "it reported a problem and was stopped",
        44 => "a program or service shut it down",
        48 => "its driver is blocked because it is known to cause problems",
        52 => "its driver is not signed",
        _ => "it is not working",
    }
}

/// The print spooler's service name.
const SPOOLER: &str = "spooler";
/// A print job waiting this long is stuck, not printing.
const STUCK_JOB_AGE: Duration = Duration::from_secs(60 * 60);
/// The finding for a stuck print queue.
pub const PRINT_QUEUE_STUCK: &str = "dev_print_queue_stuck";

/// Print jobs in `dir` (`.SPL` and `.SHD` files) older than
/// [`STUCK_JOB_AGE`], or why the folder could not be read. It needs
/// Administrator rights.
pub fn stuck_print_jobs(dir: &Path) -> Result<usize, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("{} could not be read: {e}", dir.display()))?;
    Ok(entries
        .flatten()
        .filter(|entry| {
            entry.metadata().is_ok_and(|meta| {
                meta.is_file()
                    && meta
                        .modified()
                        .ok()
                        .and_then(|at| at.elapsed().ok())
                        .is_some_and(|age| age >= STUCK_JOB_AGE)
            })
        })
        .count())
}

/// The files left in `dir`.
fn files_in(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.metadata().is_ok_and(|m| m.is_file()))
                .count()
        })
        .unwrap_or(0)
}

pub struct DevicesModule {
    runner: Arc<dyn CommandRunner>,
    /// `%SystemRoot%\System32\spool\PRINTERS`, where waiting print jobs are.
    spool_dir: PathBuf,
    /// The setting "Restart services automatically".
    restart_services: bool,
}

impl Default for DevicesModule {
    fn default() -> Self {
        Self::new()
    }
}

impl DevicesModule {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        Self {
            runner,
            spool_dir: PathBuf::from(root).join(r"System32\spool\PRINTERS"),
            restart_services: true,
        }
    }

    /// Whether a repair may stop a service and start it again: the setting
    /// "Restart services automatically".
    pub fn restarting_services(mut self, allowed: bool) -> Self {
        self.restart_services = allowed;
        self
    }

    /// For tests: the print jobs are in this folder.
    pub fn with_spool_dir(mut self, dir: PathBuf) -> Self {
        self.spool_dir = dir;
        self
    }

    /// The finding for a print queue that is stuck: jobs waiting for over an
    /// hour, or a spooler that should run and does not. `None` when printing
    /// is fine, the spooler is switched off on purpose, or `sc` did not say.
    async fn print_queue_finding(&self) -> Option<Issue> {
        let start_type = service::start_type(&*self.runner, SPOOLER).await.ok()??;
        if start_type == SERVICE_DISABLED {
            // Switched off on purpose, often against PrintNightmare.
            return None;
        }
        let state = service::state(&*self.runner, SPOOLER).await.ok()??;
        let stuck = stuck_print_jobs(&self.spool_dir).unwrap_or(0);
        let stopped = start_type == SERVICE_AUTO_START && state == SERVICE_STOPPED;
        if stuck == 0 && !stopped {
            return None;
        }
        let title = if stuck > 0 {
            format!("{stuck} print job(s) stuck for more than an hour")
        } else {
            "The print spooler is not running".to_string()
        };
        Some(Issue::new(
            PRINT_QUEUE_STUCK,
            self.id(),
            title,
            "Devices & Drivers",
            Severity::Warning,
            RiskScore::Low,
            "Nothing prints while the queue is stuck: a damaged print job blocks every job behind it, or stops the print spooler whenever it starts. Clearing the queue deletes every waiting job; print them again afterwards.",
            format!(
                "sc qc spooler: START_TYPE {start_type}\nsc query spooler: STATE {state}\n{}: {stuck} job file(s) older than an hour",
                self.spool_dir.display()
            ),
            "Clear the print queue and restart the print spooler",
            vec![
                "net stop spooler".to_string(),
                format!("Delete the files in {}", self.spool_dir.display()),
                "net start spooler".to_string(),
            ],
        ))
    }

    /// Stop the spooler and check it stopped, delete the waiting jobs, start
    /// it again, then check it runs and the folder is empty. Until that second
    /// start, a cancelled or failing repair starts the spooler again itself.
    async fn clear_print_queue(&self) -> Result<String, String> {
        if !self.restart_services {
            return Err(
                "Skipped: clearing the print queue stops the print spooler and starts it again. Turn on 'Restart services automatically' in the settings."
                    .to_string(),
            );
        }
        // Armed before the stop, so that a cancel, or a failed state check,
        // between stopping and starting does not leave the spooler stopped.
        let mut start_again = StartAgain::new(self.runner.clone(), &[SPOOLER]);
        let _ = self
            .runner
            .run("net.exe", &["stop", SPOOLER], Duration::from_secs(60))
            .await;
        let state = service::state(&*self.runner, SPOOLER).await?;
        if state != Some(SERVICE_STOPPED) {
            return Err(format!(
                "The print spooler did not stop (state {state:?}), so no print job was deleted."
            ));
        }
        let mut deleted = 0;
        if let Ok(entries) = std::fs::read_dir(&self.spool_dir) {
            for entry in entries.flatten() {
                if entry.metadata().is_ok_and(|m| m.is_file())
                    && std::fs::remove_file(entry.path()).is_ok()
                {
                    deleted += 1;
                }
            }
        }
        let _ = self
            .runner
            .run("net.exe", &["start", SPOOLER], Duration::from_secs(60))
            .await;
        start_again.disarm();
        let state = service::state(&*self.runner, SPOOLER).await?;
        let left = files_in(&self.spool_dir);
        if !matches!(state, Some(SERVICE_RUNNING | SERVICE_START_PENDING)) {
            return Err(format!(
                "{deleted} print job file(s) deleted, but the print spooler did not start again (state {state:?}). Restart Windows; if it stops again, a printer driver is the likely cause."
            ));
        }
        if left > 0 {
            return Err(format!(
                "The print spooler runs again, but {left} file(s) in {} could not be deleted.",
                self.spool_dir.display()
            ));
        }
        Ok(format!(
            "The print queue was cleared ({deleted} file(s)) and the print spooler runs again. Print the documents again."
        ))
    }

    /// The connected devices that report a problem.
    async fn problem_devices(&self) -> Result<Vec<Device>, String> {
        let mut devices = self.runner.connected_devices().await?;
        devices.retain(|d| d.problem != 0);
        Ok(devices)
    }

    /// The device a finding is about, if it still has the problem the finding
    /// was raised for.
    async fn device_for(&self, issue_id: &str) -> Result<Option<Device>, String> {
        Ok(self
            .problem_devices()
            .await?
            .into_iter()
            .find(|d| d.finding_id().as_deref() == Some(issue_id)))
    }

    /// The device again after a repair, or `None` when it is gone.
    async fn read_back(&self, device: &Device) -> Result<Option<Device>, String> {
        Ok(self
            .runner
            .connected_devices()
            .await?
            .into_iter()
            .find(|d| d.instance_id.eq_ignore_ascii_case(&device.instance_id)))
    }

    /// Whether this Windows' pnputil has `/restart-device` and
    /// `/scan-devices`: Windows 10 2004 (build 19041) and later. Unknown
    /// counts as yes, as it did before.
    async fn pnputil_can_repair(&self) -> bool {
        let Ok(out) = self
            .runner
            .run(
                "reg.exe",
                &["query", CURRENT_VERSION_KEY, "/v", "CurrentBuild"],
                Duration::from_secs(10),
            )
            .await
        else {
            return true;
        };
        let keys = registry::parse_reg_query(&out.stdout);
        registry::find(&keys, CURRENT_VERSION_KEY, "CurrentBuild")
            .and_then(|value| value.data.trim().parse::<u32>().ok())
            .is_none_or(|build| build >= PNPUTIL_REPAIR_BUILD)
    }

    /// `pnputil /restart-device`, then the problem code again.
    ///
    /// pnputil says nothing: refused with "access denied" it still exits 0,
    /// and it reports a successful restart for a device that goes on
    /// failing. Only the device's state afterwards counts.
    async fn restart(&self, issue_id: &str) -> Result<String, String> {
        let Some(device) = self.device_for(issue_id).await? else {
            return Ok(
                "The device works again or is no longer connected - nothing to restart."
                    .to_string(),
            );
        };
        if !self.pnputil_can_repair().await {
            return Err(OLD_PNPUTIL.to_string());
        }
        let _ = self
            .runner
            .run(
                "pnputil.exe",
                &["/restart-device", &device.instance_id],
                Duration::from_secs(120),
            )
            .await;

        let label = capitalised(&device.label());
        match self.read_back(&device).await? {
            None => Ok(format!("{label} was restarted and is no longer connected.")),
            Some(after) if after.problem == 0 => {
                Ok(format!("{label} was restarted and works again."))
            }
            Some(after) => Err(format!(
                "{label} was restarted but still reports problem code {}: {}. Restart Windows; if the problem stays, update or reinstall its driver: Device Manager -> right-click the device -> Update driver, or Uninstall device.",
                after.problem,
                meaning(after.problem)
            )),
        }
    }

    /// `pnputil /scan-devices` - Device Manager's "Scan for hardware
    /// changes" - then the problem code again.
    async fn find_driver(&self, issue_id: &str) -> Result<String, String> {
        let Some(device) = self.device_for(issue_id).await? else {
            return Ok("The device has a driver by now or is no longer connected.".to_string());
        };
        if !self.pnputil_can_repair().await {
            return Err(OLD_PNPUTIL.to_string());
        }
        let _ = self
            .runner
            .run("pnputil.exe", &["/scan-devices"], Duration::from_secs(180))
            .await;

        let label = device.label();
        match self.read_back(&device).await? {
            None => Ok(format!("{} is no longer connected.", capitalised(&label))),
            Some(after) if after.problem == 0 => Ok(format!(
                "Windows found a driver for {label} and installed it."
            )),
            Some(after) if after.problem == NO_DRIVER => Err(format!(
                "Windows looked again and has no driver for {label}. Look under Settings -> Windows Update -> Advanced options -> Optional updates -> Driver updates, or get the driver from the manufacturer's website."
            )),
            Some(after) => Err(format!(
                "Windows installed a driver for {label}, but the device now reports problem code {}: {}. {REINSTALL_DRIVER}",
                after.problem,
                meaning(after.problem)
            )),
        }
    }

    fn finding(&self, device: &Device) -> Option<Issue> {
        let id = device.finding_id()?;
        let label = capitalised(&device.label());
        let meaning = capitalised(meaning(device.problem));
        let issue = match remedy(device.problem) {
            Remedy::None => return None,
            Remedy::FindDriver => {
                let mut issue = Issue::new(
                    id,
                    self.id(),
                    format!("{label} has no driver"),
                    "Devices & Drivers",
                    Severity::Info,
                    RiskScore::Low,
                    "Windows found this device but has no driver for it, so it does nothing. Often that is an extra function nobody misses; when something is missing, this is why.",
                    device.details(),
                    "Scan for hardware changes, which installs a driver Windows has by now",
                    vec![
                        "Run pnputil /scan-devices (Device Manager: Scan for hardware changes)"
                            .to_string(),
                        "Check that the device now has a driver".to_string(),
                    ],
                );
                // Windows looked for a driver when the device arrived; looking
                // again only helps when one has turned up since.
                issue.is_selected = false;
                issue
            }
            Remedy::Restart => Issue::new(
                id,
                self.id(),
                format!("{label} has stopped working"),
                "Devices & Drivers",
                Severity::Warning,
                RiskScore::Low,
                format!(
                    "{meaning}. Whatever the device does - sound, network, a USB port, the camera - is missing until it runs again. Restarting the device, like unplugging it and plugging it back in, often brings it back."
                ),
                device.details(),
                "Restart the device and check that it works",
                vec![
                    format!("Run pnputil /restart-device \"{}\"", device.instance_id),
                    "Check that the device no longer reports a problem".to_string(),
                ],
            ),
            Remedy::Advice => {
                let (recommendation, step) = advice(device.problem);
                Issue::new(
                    id,
                    self.id(),
                    format!("{label} cannot start"),
                    "Devices & Drivers",
                    Severity::Warning,
                    RiskScore::Low,
                    format!("{meaning}, so the device does not work."),
                    device.details(),
                    recommendation,
                    vec![step.to_string()],
                )
                .with_advice_only()
            }
        };
        Some(issue)
    }

    /// Whether a policy keeps drivers out of Windows Update. A key that
    /// cannot be read counts as no policy: the findings about the devices
    /// stand without the hint.
    async fn drivers_excluded(&self) -> bool {
        match registry::query(&*self.runner, WU_POLICY_KEY, true).await {
            Ok(Some(keys)) => drivers_excluded_from_updates(&keys),
            _ => false,
        }
    }

    /// Advice for devices without a driver while a policy keeps drivers out
    /// of Windows Update, which is where Windows would get one.
    fn drivers_excluded_finding(&self, without_driver: &[&Device]) -> Issue {
        let devices = match without_driver.len() {
            1 => "the device that has none".to_string(),
            n => format!("the {n} devices that have none"),
        };
        let labels: Vec<String> = without_driver.iter().map(|d| d.label()).collect();
        Issue::new(
            DRIVERS_EXCLUDED_ID,
            self.id(),
            "Windows Update is not allowed to deliver drivers",
            "Devices & Drivers",
            Severity::Info,
            RiskScore::Low,
            format!(
                "A policy keeps drivers out of Windows Update, so it cannot bring a driver for {devices} either."
            ),
            format!(
                "Policy: Do not include drivers with Windows Updates\nValue: {WU_POLICY_KEY}\\ExcludeWUDriversInQualityUpdate = 1\nWithout a driver: {}",
                labels.join(", ")
            ),
            "Get the driver from the device's manufacturer, or switch the policy off",
            vec![
                "Get the driver from the manufacturer's website".to_string(),
                POLICY_OFF.to_string(),
            ],
        )
        .with_advice_only()
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
                    module_id: "devices".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(str::to_string),
                })
                .await;
        }
    }
}

/// `an unknown device` -> `An unknown device`; a quoted name stays as it is.
fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

#[async_trait::async_trait]
impl DiagnosticModule for DevicesModule {
    fn id(&self) -> &'static str {
        "devices"
    }

    fn name(&self) -> &'static str {
        "Devices & Drivers"
    }

    fn description(&self) -> &'static str {
        "Finds devices that stopped working or have no driver, the warning signs in Device Manager, and restarts them; clears a stuck print queue"
    }

    fn icon(&self) -> &'static str {
        "[DEV]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        Self::send_progress(
            &progress_tx,
            10,
            "Asking Windows for devices with a problem...",
            Some("Device Manager's problem codes (SetupAPI, CfgMgr32)"),
        )
        .await;
        let devices = self.problem_devices().await?;
        let mut issues: Vec<Issue> = devices.iter().filter_map(|d| self.finding(d)).collect();
        // Older pnputil does not know the switches: its "repair" failed and
        // the message blamed the device.
        if !issues.is_empty() && !self.pnputil_can_repair().await {
            issues = issues
                .into_iter()
                .map(|issue| {
                    let mut issue = issue.with_advice_only();
                    issue.fix_steps = vec![OLD_PNPUTIL.to_string()];
                    issue
                })
                .collect();
        }

        let summary = format!(
            "{} device(s) with a problem code, {} of them worth a finding",
            devices.len(),
            issues.len()
        );

        // Only asked when it can matter: while every device has a driver, a
        // policy that keeps drivers out of Windows Update costs nothing.
        let without_driver: Vec<&Device> = devices
            .iter()
            .filter(|d| remedy(d.problem) == Remedy::FindDriver)
            .collect();
        if !without_driver.is_empty() && self.drivers_excluded().await {
            issues.push(self.drivers_excluded_finding(&without_driver));
        }

        Self::send_progress(
            &progress_tx,
            80,
            "Checking the print queue...",
            Some("sc qc / sc query spooler, print jobs older than an hour"),
        )
        .await;
        issues.extend(self.print_queue_finding().await);
        Self::send_progress(&progress_tx, 100, "Device check complete", Some(&summary)).await;
        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        // A device that cannot start is advice: a repair run never asks.
        if issue_id.starts_with(FAILED_ID) {
            self.restart(issue_id).await
        } else if issue_id.starts_with(NO_DRIVER_ID) {
            self.find_driver(issue_id).await
        } else if issue_id == PRINT_QUEUE_STUCK {
            self.clear_print_queue().await
        } else {
            Err(format!("Unknown device issue id: {issue_id}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;

    // pnputil's answers, captured on a German Windows 11; see
    // tests/fixtures/README.md.
    const RESTART_DENIED: &[u8] =
        include_bytes!("../../tests/fixtures/console/pnputil_restart_device_denied_de.bin");
    const RESTARTED: &[u8] = include_bytes!(
        "../../tests/fixtures/console/pnputil_restart_device_no_driver_elevated_de.bin"
    );
    const SCAN_DENIED: &[u8] =
        include_bytes!("../../tests/fixtures/console/pnputil_scan_devices_denied_de.bin");
    const SCANNED: &[u8] =
        include_bytes!("../../tests/fixtures/console/pnputil_scan_devices_elevated_de.bin");

    const BRIO: &str = r"USB\VID_046D&PID_0943&MI_05\9&B24F85A&0&0005";
    const AMD: &str = r"ACPI\AMDI0204\2&DABA3FF&0";

    fn device(problem: u32, class: &str, instance_id: &str, name: &str) -> Device {
        Device {
            problem,
            class: class.to_string(),
            instance_id: instance_id.to_string(),
            name: name.to_string(),
            service: String::new(),
        }
    }

    /// The development PC's devices with a problem, as Device Manager listed
    /// them on 2026-09-25 - three disabled, two without a driver - and one
    /// that works.
    fn dev_pc() -> Vec<Device> {
        vec![
            device(
                0,
                "System",
                r"ACPI\PNP0000\4&1D401FB5&0",
                "Programmierbarer Interruptcontroller",
            ),
            device(
                22,
                "System",
                r"ACPI\PNP0103\2&DABA3FF&0",
                "Hochpräzisionsereigniszeitgeber",
            ),
            device(
                22,
                "System",
                r"ROOT\HVSERVICE\0000",
                "Microsoft-Hypervisor-Dienst",
            ),
            device(28, "", BRIO, "Brio 500"),
            device(
                22,
                "System",
                r"ROOT\NDISVIRTUALBUS\0000",
                "Enumerator für virtuelle NDIS-Netzwerkadapter",
            ),
            device(28, "", AMD, ""),
        ]
    }

    fn brio(code: u32) -> Device {
        device(code, "Image", BRIO, "Brio 500")
    }

    /// The development PC with the Brio's interface reporting `code`.
    fn brio_reporting(code: u32) -> Vec<Device> {
        dev_pc()
            .into_iter()
            .map(|d| if d.instance_id == BRIO { brio(code) } else { d })
            .collect()
    }

    /// The id of the finding about the Brio while it reports `code`.
    fn brio_id(code: u32) -> String {
        brio(code).finding_id().unwrap()
    }

    /// What was asked of pnputil, without the build lookup before it.
    fn pnputil_calls(mock: &MockCommandRunner) -> Vec<String> {
        mock.executed()
            .into_iter()
            .filter(|c| c.starts_with("pnputil"))
            .collect()
    }

    fn module(mock: &MockCommandRunner) -> DevicesModule {
        DevicesModule::with_runner(Arc::new(mock.clone()))
    }

    async fn scan(devices: Vec<Device>) -> Vec<Issue> {
        let mock = MockCommandRunner::new();
        mock.set_devices(devices);
        module(&mock).scan(None).await.unwrap()
    }

    #[test]
    fn a_device_without_a_name_is_named_by_its_hardware() {
        assert_eq!(brio(28).label(), "'Brio 500'");
        assert_eq!(
            device(28, "", AMD, "").label(),
            r"an unknown device (ACPI\AMDI0204)"
        );
    }

    #[test]
    fn only_real_faults_get_a_remedy() {
        for code in [0, 21, 22, 29, 45, 46, 47, 53] {
            assert_eq!(remedy(code), Remedy::None, "code {code}");
            assert_eq!(brio(code).finding_id(), None, "code {code}");
        }
        assert_eq!(remedy(28), Remedy::FindDriver);
        for code in [14, 32, 38, 48, 52] {
            assert_eq!(remedy(code), Remedy::Advice, "code {code}");
        }
        for code in [10, 31, 39, 43] {
            assert_eq!(remedy(code), Remedy::Restart, "code {code}");
        }
    }

    #[test]
    fn the_finding_id_names_the_device_and_the_remedy() {
        assert_eq!(
            brio_id(43),
            "dev_failed_usb_vid_046d_pid_0943_mi_05_9_b24f85a_0_0005"
        );
        assert!(brio_id(28).starts_with("dev_no_driver_usb_vid_046d"));
        assert!(brio_id(52).starts_with("dev_cannot_start_usb_vid_046d"));
    }

    #[tokio::test]
    async fn disabled_devices_are_left_alone_and_missing_drivers_are_information() {
        let issues = scan(dev_pc()).await;

        // The three disabled devices are not findings; the two without a
        // driver are, unticked.
        assert_eq!(issues.len(), 2, "{issues:?}");
        for issue in &issues {
            assert!(issue.id.starts_with(NO_DRIVER_ID), "{}", issue.id);
            assert_eq!(issue.severity, Severity::Info);
            assert!(!issue.is_selected);
        }
        assert_eq!(issues[0].title, "'Brio 500' has no driver");
        assert_eq!(
            issues[1].title,
            r"An unknown device (ACPI\AMDI0204) has no driver"
        );
    }

    /// The development PC's WindowsUpdate policy key, captured with
    /// `reg query ... /s`: drivers are kept out of Windows Update.
    const WU_POLICY: &[u8] = include_bytes!("../../tests/fixtures/console/reg_query_wu_policy.bin");

    async fn scan_with_policy(
        devices: Vec<Device>,
        policy: CmdOutput,
    ) -> (Vec<Issue>, Vec<String>) {
        let mock = MockCommandRunner::new();
        mock.set_devices(devices);
        mock.add_response(
            r"reg.exe query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            policy,
        );
        let issues = module(&mock).scan(None).await.unwrap();
        (issues, mock.executed())
    }

    /// The development PC: two devices without a driver, and a policy that
    /// keeps Windows Update from bringing one.
    #[tokio::test]
    async fn a_policy_that_keeps_drivers_out_of_windows_update_is_named() {
        let (issues, _) = scan_with_policy(dev_pc(), CmdOutput::ok(decode_output(WU_POLICY))).await;

        assert_eq!(issues.len(), 3, "{issues:?}");
        let hint = issues
            .iter()
            .find(|i| i.id == DRIVERS_EXCLUDED_ID)
            .expect("no hint about the policy");
        assert!(hint.advice_only && !hint.is_selected);
        assert_eq!(hint.severity, Severity::Info);
        assert!(
            hint.description.contains("the 2 devices that have none"),
            "{}",
            hint.description
        );
        assert!(
            hint.technical_details.contains("'Brio 500'"),
            "{}",
            hint.technical_details
        );
        assert!(
            hint.technical_details.contains(r"ACPI\AMDI0204"),
            "{}",
            hint.technical_details
        );
    }

    #[tokio::test]
    async fn without_the_policy_there_is_no_hint() {
        let off = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\r\n    ExcludeWUDriversInQualityUpdate    REG_DWORD    0x0\r\n\r\n";
        for policy in [
            CmdOutput::ok(off),
            // No WindowsUpdate policy key at all.
            CmdOutput::failed(1, ""),
        ] {
            let (issues, _) = scan_with_policy(dev_pc(), policy).await;
            assert_eq!(issues.len(), 2, "{issues:?}");
            assert!(issues.iter().all(|i| i.id.starts_with(NO_DRIVER_ID)));
        }
    }

    /// Every device has a driver: the policy costs nothing and is not asked.
    #[tokio::test]
    async fn the_policy_is_only_read_when_a_device_has_no_driver() {
        let (issues, executed) =
            scan_with_policy(brio_reporting(43), CmdOutput::ok(decode_output(WU_POLICY))).await;
        let with_driver: Vec<Device> = dev_pc().into_iter().filter(|d| d.problem != 28).collect();
        let (none, executed_none) =
            scan_with_policy(with_driver, CmdOutput::ok(decode_output(WU_POLICY))).await;

        // The AMD device still has no driver while the Brio reports 43.
        assert!(issues.iter().any(|i| i.id == DRIVERS_EXCLUDED_ID));
        assert!(executed.iter().any(|c| c.starts_with("reg.exe")));
        assert!(none.is_empty(), "{none:?}");
        assert!(
            !executed_none.iter().any(|c| c.starts_with("reg.exe")),
            "{executed_none:?}"
        );
    }

    #[tokio::test]
    async fn a_stopped_device_is_a_warning_with_a_restart() {
        let issues = scan(brio_reporting(43)).await;
        let issue = issues.iter().find(|i| i.id == brio_id(43)).unwrap();
        assert_eq!(issue.title, "'Brio 500' has stopped working");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.is_selected && !issue.advice_only);
        assert!(
            issue
                .description
                .starts_with("It reported a problem and was stopped. "),
            "{}",
            issue.description
        );
    }

    #[tokio::test]
    async fn a_blocked_driver_is_advice() {
        let issues = scan(brio_reporting(52)).await;
        let issue = issues.iter().find(|i| i.id == brio_id(52)).unwrap();
        assert!(issue.advice_only && !issue.is_selected);
        assert_eq!(issue.title, "'Brio 500' cannot start");
        assert_eq!(
            issue.description,
            "Its driver is not signed, so the device does not work."
        );
    }

    #[tokio::test]
    async fn a_device_waiting_for_windows_to_restart_says_so() {
        let issues = scan(brio_reporting(14)).await;
        let issue = issues.iter().find(|i| i.id == brio_id(14)).unwrap();
        assert!(issue.advice_only);
        assert_eq!(issue.recommended_fix, "Restart Windows");
    }

    /// A machine whose Brio fails with code 43 until pnputil ran, printing
    /// `pnputil` with exit 0 as it does either way, and then lists `after`.
    fn restart_mock(pnputil: &[u8], after: Vec<Device>) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.set_devices(brio_reporting(43));
        mock.add_response(
            "pnputil.exe /restart-device",
            CmdOutput::ok(decode_output(pnputil)),
        );
        mock.set_devices_after("/restart-device", after);
        mock
    }

    #[tokio::test]
    async fn a_restarted_device_is_read_back() {
        let mock = restart_mock(RESTARTED, brio_reporting(0));
        let msg = module(&mock).fix(&brio_id(43), None).await.unwrap();
        assert_eq!(msg, "'Brio 500' was restarted and works again.");
        assert_eq!(
            pnputil_calls(&mock),
            vec![format!("pnputil.exe /restart-device {BRIO}")]
        );
    }

    /// Elevated, pnputil reported "Das Gerät wurde erfolgreich neu gestartet"
    /// for the Brio's interface, which went on reporting code 28; refused, it
    /// exits 0 as well. Neither is believed.
    #[tokio::test]
    async fn pnputil_is_not_believed() {
        for pnputil in [RESTARTED, RESTART_DENIED] {
            let mock = restart_mock(pnputil, brio_reporting(43));
            let err = module(&mock).fix(&brio_id(43), None).await.unwrap_err();
            assert!(
                err.starts_with("'Brio 500' was restarted but still reports problem code 43"),
                "{err}"
            );
        }
    }

    #[tokio::test]
    async fn a_device_that_is_gone_is_not_a_failure() {
        let unplugged = dev_pc()
            .into_iter()
            .filter(|d| d.instance_id != BRIO)
            .collect();
        let mock = restart_mock(RESTARTED, unplugged);
        let msg = module(&mock).fix(&brio_id(43), None).await.unwrap();
        assert!(msg.contains("no longer connected"), "{msg}");
    }

    #[tokio::test]
    async fn a_device_whose_problem_changed_is_not_restarted() {
        for devices in [Vec::new(), brio_reporting(22)] {
            let mock = MockCommandRunner::new();
            mock.set_devices(devices);
            let msg = module(&mock).fix(&brio_id(43), None).await.unwrap();
            assert!(msg.contains("nothing to restart"), "{msg}");
            assert!(mock.executed().is_empty());
        }
    }

    #[tokio::test]
    async fn a_device_that_cannot_start_is_never_restarted() {
        let mock = MockCommandRunner::new();
        mock.set_devices(brio_reporting(52));
        let err = module(&mock).fix(&brio_id(52), None).await.unwrap_err();
        assert!(err.starts_with("Unknown device issue id"), "{err}");
        assert!(mock.executed().is_empty());
    }

    /// The development PC, whose scan for hardware changes prints `pnputil`
    /// and then lists `after`.
    fn scan_devices_mock(pnputil: CmdOutput, after: Vec<Device>) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.set_devices(dev_pc());
        mock.add_response("pnputil.exe /scan-devices", pnputil);
        mock.set_devices_after("/scan-devices", after);
        mock
    }

    fn scanned() -> CmdOutput {
        CmdOutput::ok(decode_output(SCANNED))
    }

    #[tokio::test]
    async fn a_driver_found_by_a_scan_is_read_back() {
        let mock = scan_devices_mock(scanned(), brio_reporting(0));
        let msg = module(&mock).fix(&brio_id(28), None).await.unwrap();
        assert_eq!(
            msg,
            "Windows found a driver for 'Brio 500' and installed it."
        );
        assert_eq!(pnputil_calls(&mock), vec!["pnputil.exe /scan-devices"]);
    }

    /// What happened on the development PC: the scan finished at once with
    /// exit 0 and both devices still had no driver.
    #[tokio::test]
    async fn still_no_driver_says_where_to_get_one() {
        let amd = device(28, "", AMD, "");
        let mock = scan_devices_mock(scanned(), dev_pc());
        let err = module(&mock)
            .fix(&amd.finding_id().unwrap(), None)
            .await
            .unwrap_err();
        assert!(
            err.starts_with(
                r"Windows looked again and has no driver for an unknown device (ACPI\AMDI0204)."
            ),
            "{err}"
        );
        assert!(err.contains("Optional updates"), "{err}");
    }

    #[tokio::test]
    async fn a_refused_scan_leaves_the_finding_open() {
        let refused = CmdOutput::with_output(5, decode_output(SCAN_DENIED), "");
        let mock = scan_devices_mock(refused, dev_pc());
        assert!(module(&mock).fix(&brio_id(28), None).await.is_err());
    }

    /// `reg query ... /v CurrentBuild` as captured (26200), or with `build`.
    fn current_build(build: &str) -> CmdOutput {
        CmdOutput::ok(
            decode_output(include_bytes!(
                "../../tests/fixtures/console/reg_query_current_build.bin"
            ))
            .replace("26200", build),
        )
    }

    #[tokio::test]
    async fn before_windows_10_2004_devices_are_advice() {
        let mock = MockCommandRunner::new();
        mock.set_devices(brio_reporting(28));
        mock.add_response("CurrentBuild", current_build("18363"));
        let issues = module(&mock).scan(None).await.unwrap();
        let issue = issues.iter().find(|i| i.id == brio_id(28)).unwrap();
        assert!(issue.advice_only, "pnputil there has no /scan-devices");
        assert!(issue.fix_steps[0].contains("Device Manager"));

        let err = module(&mock).fix(&brio_id(28), None).await.unwrap_err();
        assert!(err.contains("Windows 10 2004"), "{err}");
        assert!(!mock.executed().iter().any(|c| c.contains("pnputil")));
    }

    #[tokio::test]
    async fn this_windows_repairs_devices_with_pnputil() {
        let mock = MockCommandRunner::new();
        mock.set_devices(brio_reporting(28));
        mock.add_response("CurrentBuild", current_build("26200"));
        let issues = module(&mock).scan(None).await.unwrap();
        let issue = issues.iter().find(|i| i.id == brio_id(28)).unwrap();
        assert!(!issue.advice_only);
    }

    // `sc` about the print spooler, captured on a German Windows 11: it
    // starts automatically and runs.
    const QC_SPOOLER: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_spooler.bin");
    const QUERY_SPOOLER: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_query_spooler.bin");

    fn spooler_state(state: &str) -> CmdOutput {
        CmdOutput::ok(decode_output(QUERY_SPOOLER).replace("4  RUNNING", state))
    }

    /// A spool folder in the temp directory, removed when the test ends.
    struct Spool(PathBuf);

    impl Spool {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("winmedic_spool_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        /// A print job written `hours` ago.
        fn job(&self, name: &str, hours: u64) -> &Self {
            let path = self.0.join(name);
            std::fs::write(&path, b"job").unwrap();
            let when = std::time::SystemTime::now() - Duration::from_secs(hours * 3600);
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(when)
                .unwrap();
            self
        }
    }

    impl Drop for Spool {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn scan_spooler(qc: String, query: CmdOutput, spool: &Spool) -> Vec<Issue> {
        let mock = MockCommandRunner::new();
        mock.add_response("qc spooler", CmdOutput::ok(qc));
        mock.add_response("query spooler", query);
        module(&mock)
            .with_spool_dir(spool.0.clone())
            .scan(None)
            .await
            .unwrap()
    }

    #[test]
    fn only_old_print_jobs_are_stuck() {
        let spool = Spool::new("age");
        spool.job("00012.SPL", 0).job("00012.SHD", 0);
        assert_eq!(stuck_print_jobs(&spool.0), Ok(0));
        spool.job("00011.SPL", 2).job("00011.SHD", 2);
        assert_eq!(stuck_print_jobs(&spool.0), Ok(2));
        assert!(stuck_print_jobs(&spool.0.join("missing")).is_err());
    }

    #[tokio::test]
    async fn print_jobs_waiting_for_hours_are_a_finding() {
        let spool = Spool::new("stuck");
        spool.job("00011.SPL", 3).job("00011.SHD", 3);
        let issues = scan_spooler(
            decode_output(QC_SPOOLER),
            spooler_state("4  RUNNING"),
            &spool,
        )
        .await;
        let issue = issues.iter().find(|i| i.id == PRINT_QUEUE_STUCK).unwrap();
        assert_eq!(issue.title, "2 print job(s) stuck for more than an hour");
        assert!(issue.is_selected);
    }

    #[tokio::test]
    async fn a_stopped_spooler_that_should_run_is_a_finding() {
        let spool = Spool::new("stopped");
        let issues = scan_spooler(
            decode_output(QC_SPOOLER),
            spooler_state("1  STOPPED"),
            &spool,
        )
        .await;
        let issue = issues.iter().find(|i| i.id == PRINT_QUEUE_STUCK).unwrap();
        assert_eq!(issue.title, "The print spooler is not running");
    }

    #[tokio::test]
    async fn a_working_or_switched_off_spooler_is_left_alone() {
        let spool = Spool::new("fine");
        spool.job("00012.SPL", 0);
        let issues = scan_spooler(
            decode_output(QC_SPOOLER),
            spooler_state("4  RUNNING"),
            &spool,
        )
        .await;
        assert!(issues.is_empty(), "{issues:?}");

        // Switched off on purpose: old jobs or not, printing is not wanted.
        spool.job("00011.SPL", 5);
        let disabled = decode_output(QC_SPOOLER).replace("2   AUTO_START", "4   DISABLED");
        let issues = scan_spooler(disabled, spooler_state("1  STOPPED"), &spool).await;
        assert!(issues.is_empty(), "{issues:?}");
    }

    /// The spooler answers `before` until `net start` ran, then running.
    fn spooler_repair(before: &str) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("net.exe", CmdOutput::ok(""));
        mock.add_response("query spooler", spooler_state(before));
        mock.add_response_after(
            "net.exe start",
            "query spooler",
            spooler_state("4  RUNNING"),
        );
        mock
    }

    #[tokio::test]
    async fn the_queue_is_cleared_between_a_checked_stop_and_start() {
        let spool = Spool::new("clear");
        spool
            .job("00011.SPL", 3)
            .job("00011.SHD", 3)
            .job("00012.SPL", 0);
        let mock = spooler_repair("1  STOPPED");
        let msg = module(&mock)
            .with_spool_dir(spool.0.clone())
            .fix(PRINT_QUEUE_STUCK, None)
            .await
            .unwrap();
        assert!(msg.contains("3 file(s)"), "{msg}");
        assert_eq!(files_in(&spool.0), 0);
        // The success path starts the spooler once. The guard must not add a
        // second start.
        settle().await;
        let net: Vec<String> = mock
            .executed()
            .into_iter()
            .filter(|c| c.starts_with("net.exe"))
            .collect();
        assert_eq!(net, ["net.exe stop spooler", "net.exe start spooler"]);
    }

    #[tokio::test]
    async fn a_spooler_that_does_not_stop_keeps_the_jobs_and_is_started_again() {
        let spool = Spool::new("nostop");
        spool.job("00011.SPL", 3);
        let mock = spooler_repair("4  RUNNING");
        let err = module(&mock)
            .with_spool_dir(spool.0.clone())
            .fix(PRINT_QUEUE_STUCK, None)
            .await
            .unwrap_err();
        assert!(err.contains("did not stop"), "{err}");
        assert_eq!(files_in(&spool.0), 1);
        settle().await;
        assert_eq!(spooler_starts(&mock), 1, "{:?}", mock.executed());
    }

    #[tokio::test]
    async fn the_print_queue_is_left_alone_when_services_may_not_be_restarted() {
        let spool = Spool::new("norestart");
        spool.job("00011.SPL", 3);
        let mock = spooler_repair("1  STOPPED");
        let err = module(&mock)
            .with_spool_dir(spool.0.clone())
            .restarting_services(false)
            .fix(PRINT_QUEUE_STUCK, None)
            .await
            .unwrap_err();
        assert!(err.starts_with("Skipped:"), "{err}");
        assert!(mock.executed().is_empty(), "{:?}", mock.executed());
        assert_eq!(files_in(&spool.0), 1);
    }

    /// Lets the restart that a dropped repair spawns on the runtime run.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// How often `net start spooler` ran.
    fn spooler_starts(mock: &MockCommandRunner) -> usize {
        mock.executed()
            .iter()
            .filter(|c| c.as_str() == "net.exe start spooler")
            .count()
    }

    /// Answers like its mock, except that the spooler's state query after the
    /// stop never returns: the repair waits there until it is dropped, as it
    /// is when the user cancels.
    struct StuckAfterStop(MockCommandRunner);

    #[async_trait::async_trait]
    impl CommandRunner for StuckAfterStop {
        async fn run(
            &self,
            program: &str,
            args: &[&str],
            timeout: Duration,
        ) -> Result<CmdOutput, String> {
            let stopped = self
                .0
                .executed()
                .iter()
                .any(|c| c == "net.exe stop spooler");
            if stopped && args.first() == Some(&"query") {
                std::future::pending::<()>().await;
            }
            self.0.run(program, args, timeout).await
        }

        async fn run_streaming(
            &self,
            program: &str,
            args: &[&str],
            log_tx: Option<Sender<String>>,
            timeout: Duration,
        ) -> Result<CmdOutput, String> {
            self.0.run_streaming(program, args, log_tx, timeout).await
        }
    }

    /// A `sc query` that fails after the stop: the state check returns early,
    /// and the spooler is still started again.
    #[tokio::test]
    async fn a_spooler_whose_state_cannot_be_read_after_the_stop_is_started_again() {
        let spool = Spool::new("unreadable");
        spool.job("00011.SPL", 3);
        // No answer for `sc query`, so the runner fails.
        let mock = MockCommandRunner::new();
        mock.add_response("net.exe", CmdOutput::ok(""));
        let result = module(&mock)
            .with_spool_dir(spool.0.clone())
            .fix(PRINT_QUEUE_STUCK, None)
            .await;
        assert!(result.is_err());
        settle().await;
        assert_eq!(spooler_starts(&mock), 1, "{:?}", mock.executed());
        assert_eq!(files_in(&spool.0), 1);
    }

    /// The user cancels while the repair waits between the stop and the start.
    #[tokio::test]
    async fn a_repair_cancelled_while_the_spooler_is_stopped_starts_it_again() {
        let spool = Spool::new("cancelled");
        spool.job("00011.SPL", 3);
        let mock = spooler_repair("1  STOPPED");
        let repairs = DevicesModule::with_runner(Arc::new(StuckAfterStop(mock.clone())))
            .with_spool_dir(spool.0.clone());
        // Dropped while it waits for the state after the stop, as a cancel drops it.
        let finished = tokio::time::timeout(
            Duration::from_millis(20),
            repairs.fix(PRINT_QUEUE_STUCK, None),
        )
        .await;
        assert!(finished.is_err(), "the state query was answered");
        settle().await;
        assert_eq!(spooler_starts(&mock), 1, "{:?}", mock.executed());
        assert_eq!(files_in(&spool.0), 1);
    }
}
