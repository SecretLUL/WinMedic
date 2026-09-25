//! Devices Windows reports a problem for: stopped, or without a driver.
//!
//! This is the yellow warning sign in Device Manager, which few people ever
//! open. A USB port, the sound or the webcam that stopped working usually
//! shows up there with a problem code, and restarting the device - what
//! unplugging it and plugging it back in does - often brings it back.
//!
//! Only numbers and device instance IDs are read, which are the same in every
//! display language; the device's name is for showing only.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner, ps_single_quoted};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

/// Every present device with a problem code, one line each: code, setup
/// class, instance ID, name, separated by tabs - a character no instance ID
/// can hold. `Win32_PnPEntity` lists only devices that are connected.
const PROBLEM_DEVICES_SCRIPT: &str = "Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' | ForEach-Object { @($_.ConfigManagerErrorCode, $_.PNPClass, $_.PNPDeviceID, $_.Name) -join [char]9 }";

/// The same line for one device, whatever its state; nothing when it is no
/// longer connected.
fn device_script(instance_id: &str) -> String {
    format!(
        "Get-CimInstance -ClassName Win32_PnPEntity | Where-Object PNPDeviceID -eq {} | ForEach-Object {{ @($_.ConfigManagerErrorCode, $_.PNPClass, $_.PNPDeviceID, $_.Name) -join [char]9 }}",
        ps_single_quoted(instance_id)
    )
}

/// `CM_PROB_FAILED_INSTALL`: Windows found the device but has no driver for it.
const NO_DRIVER: u32 = 28;

/// One line of [`PROBLEM_DEVICES_SCRIPT`]'s output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub problem: u32,
    /// Empty for a device without a driver: the driver brings the class.
    pub class: String,
    pub instance_id: String,
    /// Empty for some devices without a driver.
    pub name: String,
}

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

/// The devices in [`PROBLEM_DEVICES_SCRIPT`]'s output.
pub fn parse_devices(output: &str) -> Vec<Device> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim_end_matches('\r').splitn(4, '\t');
            let problem = fields.next()?.trim().parse().ok()?;
            let class = fields.next()?.to_string();
            let instance_id = fields.next()?.to_string();
            let name = fields.next().unwrap_or_default().to_string();
            (!instance_id.is_empty()).then_some(Device {
                problem,
                class,
                instance_id,
                name,
            })
        })
        .collect()
}

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

pub struct DevicesModule {
    runner: Arc<dyn CommandRunner>,
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
        Self { runner }
    }

    async fn query(&self, script: &str) -> Result<Vec<Device>, String> {
        let out = self
            .runner
            .query_powershell(script, Duration::from_secs(30))
            .await?;
        if !out.success {
            return Err(format!(
                "the device query failed (exit code {:?}): {}",
                out.exit_code,
                out.stderr.trim()
            ));
        }
        Ok(parse_devices(&out.stdout))
    }

    /// The device a finding is about, if it still has the problem the finding
    /// was raised for.
    async fn device_for(&self, issue_id: &str) -> Result<Option<Device>, String> {
        Ok(self
            .query(PROBLEM_DEVICES_SCRIPT)
            .await?
            .into_iter()
            .find(|d| d.finding_id().as_deref() == Some(issue_id)))
    }

    /// The device again after a repair, or `None` when it is gone.
    async fn read_back(&self, device: &Device) -> Result<Option<Device>, String> {
        Ok(self
            .query(&device_script(&device.instance_id))
            .await?
            .into_iter()
            .next())
    }

    /// `pnputil /restart-device`, then the problem code again.
    ///
    /// pnputil's exit code says nothing: refused with "access denied", it
    /// still exits 0. Only the device's state afterwards does.
    async fn restart(&self, issue_id: &str) -> Result<String, String> {
        let Some(device) = self.device_for(issue_id).await? else {
            return Ok(
                "The device works again or is no longer connected - nothing to restart."
                    .to_string(),
            );
        };
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
        "Finds devices that stopped working or have no driver, the warning signs in Device Manager, and restarts them"
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
            Some("Win32_PnPEntity, ConfigManagerErrorCode"),
        )
        .await;
        let devices = self.query(PROBLEM_DEVICES_SCRIPT).await?;
        let issues: Vec<Issue> = devices.iter().filter_map(|d| self.finding(d)).collect();

        let summary = format!(
            "{} device(s) with a problem code, {} of them worth a finding",
            devices.len(),
            issues.len()
        );
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

    // Captured on a German Windows 11; see tests/fixtures/README.md.
    const PROBLEM_DEVICES: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_pnp_problem_devices.bin");
    const RESTART_DENIED: &[u8] =
        include_bytes!("../../tests/fixtures/console/pnputil_restart_device_denied_de.bin");
    const SCAN_DENIED: &[u8] =
        include_bytes!("../../tests/fixtures/console/pnputil_scan_devices_denied_de.bin");

    const BRIO: &str = r"USB\VID_046D&PID_0943&MI_05\9&B24F85A&0&0005";
    const AMD: &str = r"ACPI\AMDI0204\2&DABA3FF&0";

    fn captured() -> String {
        decode_output(PROBLEM_DEVICES)
    }

    /// The captured list with the Brio's interface reporting `code` instead
    /// of lacking a driver.
    fn brio_reporting(code: u32) -> String {
        captured().replace("28\t\tUSB\\", &format!("{code}\tImage\tUSB\\"))
    }

    fn brio(code: u32) -> Device {
        Device {
            problem: code,
            class: "Image".to_string(),
            instance_id: BRIO.to_string(),
            name: "Brio 500".to_string(),
        }
    }

    fn brio_line(code: u32) -> String {
        format!("{code}\tImage\t{BRIO}\tBrio 500\r\n")
    }

    /// The id of the finding about the Brio while it reports `code`.
    fn brio_id(code: u32) -> String {
        brio(code).finding_id().unwrap()
    }

    fn module(mock: &MockCommandRunner) -> DevicesModule {
        DevicesModule::with_runner(Arc::new(mock.clone()))
    }

    async fn scan(listing: String) -> Vec<Issue> {
        let mock = MockCommandRunner::new();
        mock.add_response("Win32_PnPEntity", CmdOutput::ok(listing));
        module(&mock).scan(None).await.unwrap()
    }

    #[test]
    fn the_captured_devices_parse() {
        let devices = parse_devices(&captured());
        assert_eq!(devices.len(), 5);
        assert_eq!(devices[0].problem, 22);
        // Written as UTF-8 by PowerShell.
        assert_eq!(devices[0].name, "Hochpräzisionsereigniszeitgeber");
        assert_eq!(
            devices[2],
            Device {
                class: String::new(),
                ..brio(28)
            }
        );
        assert_eq!(devices[4].instance_id, AMD);
        assert_eq!(devices[4].name, "");
    }

    #[test]
    fn a_device_without_a_name_is_named_by_its_hardware() {
        let devices = parse_devices(&captured());
        assert_eq!(devices[2].label(), "'Brio 500'");
        assert_eq!(devices[4].label(), r"an unknown device (ACPI\AMDI0204)");
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
        let issues = scan(captured()).await;

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

    #[tokio::test]
    async fn a_failed_query_fails_the_module() {
        let mock = MockCommandRunner::new();
        mock.add_response("Win32_PnPEntity", CmdOutput::failed(1, "Invalid class"));
        let err = module(&mock).scan(None).await.unwrap_err();
        assert!(err.contains("Invalid class"), "{err}");
    }

    /// A machine whose Brio fails with code 43 until pnputil ran, and then
    /// reads `after` for the device on its own.
    fn restart_mock(after: CmdOutput) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "ConfigManagerErrorCode <> 0",
            CmdOutput::ok(brio_reporting(43)),
        );
        // Exit 0 although it was refused, as captured.
        mock.add_response(
            "pnputil.exe /restart-device",
            CmdOutput::ok(decode_output(RESTART_DENIED)),
        );
        mock.add_response_after("/restart-device", "Where-Object PNPDeviceID", after);
        mock
    }

    #[tokio::test]
    async fn a_restarted_device_is_read_back() {
        let mock = restart_mock(CmdOutput::ok(brio_line(0)));
        let msg = module(&mock).fix(&brio_id(43), None).await.unwrap();
        assert_eq!(msg, "'Brio 500' was restarted and works again.");
        assert!(
            mock.executed()
                .contains(&format!("pnputil.exe /restart-device {BRIO}"))
        );
        // The read-back names the device as a quoted value.
        assert!(
            mock.executed()
                .iter()
                .any(|c| c.contains(&format!("Where-Object PNPDeviceID -eq '{BRIO}'")))
        );
    }

    #[tokio::test]
    async fn pnputils_exit_code_is_not_believed() {
        let mock = restart_mock(CmdOutput::ok(brio_line(43)));
        let err = module(&mock).fix(&brio_id(43), None).await.unwrap_err();
        assert!(
            err.starts_with("'Brio 500' was restarted but still reports problem code 43"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_device_that_is_gone_is_not_a_failure() {
        let mock = restart_mock(CmdOutput::ok(""));
        let msg = module(&mock).fix(&brio_id(43), None).await.unwrap();
        assert!(msg.contains("no longer connected"), "{msg}");
    }

    #[tokio::test]
    async fn a_device_whose_problem_changed_is_not_restarted() {
        for listing in [String::new(), brio_reporting(22)] {
            let mock = MockCommandRunner::new();
            mock.add_response("Win32_PnPEntity", CmdOutput::ok(listing));
            let msg = module(&mock).fix(&brio_id(43), None).await.unwrap();
            assert!(msg.contains("nothing to restart"), "{msg}");
            assert!(!mock.executed().iter().any(|c| c.contains("pnputil")));
        }
    }

    #[tokio::test]
    async fn a_device_that_cannot_start_is_never_restarted() {
        let mock = MockCommandRunner::new();
        mock.add_response("Win32_PnPEntity", CmdOutput::ok(brio_reporting(52)));
        let err = module(&mock).fix(&brio_id(52), None).await.unwrap_err();
        assert!(err.starts_with("Unknown device issue id"), "{err}");
        assert!(mock.executed().is_empty());
    }

    fn scan_devices_mock(after: CmdOutput) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("ConfigManagerErrorCode <> 0", CmdOutput::ok(captured()));
        mock.add_response(
            "pnputil.exe /scan-devices",
            CmdOutput::with_output(5, decode_output(SCAN_DENIED), ""),
        );
        mock.add_response_after("/scan-devices", "Where-Object PNPDeviceID", after);
        mock
    }

    #[tokio::test]
    async fn a_driver_found_by_a_scan_is_read_back() {
        let mock = scan_devices_mock(CmdOutput::ok(brio_line(0)));
        let msg = module(&mock).fix(&brio_id(28), None).await.unwrap();
        assert_eq!(
            msg,
            "Windows found a driver for 'Brio 500' and installed it."
        );
        assert!(
            mock.executed()
                .contains(&"pnputil.exe /scan-devices".to_string())
        );
    }

    #[tokio::test]
    async fn still_no_driver_says_where_to_get_one() {
        let amd = parse_devices(&captured()).remove(4);
        let mock = scan_devices_mock(CmdOutput::ok(format!("28\t\t{AMD}\t\r\n")));
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
}
