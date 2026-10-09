//! Reading a service's start type through `sc qc`.
//!
//! `sc query` reports whether a service is running, never how it starts, so a
//! check that looked for "disabled" in its output could not fire: a disabled
//! Windows Update or VSS service went unreported on every machine. `sc qc`
//! does report the start type, and as a number — its field names are the same
//! in every display language and the number is the value Windows stores, so
//! nothing here depends on the language.

use crate::utils::cmd::CommandRunner;
use std::sync::Arc;
use std::time::Duration;

/// `START_TYPE` 2: Windows starts the service at boot.
pub const SERVICE_AUTO_START: u32 = 2;
/// `START_TYPE` 4: the service cannot be started, not even on demand.
pub const SERVICE_DISABLED: u32 = 4;

/// The `START_TYPE` number in `sc qc` output.
pub fn parse_start_type(sc_qc_output: &str) -> Option<u32> {
    sc_qc_output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "START_TYPE" {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

/// `STATE` numbers `sc query` prints, the same in every language.
pub const SERVICE_STOPPED: u32 = 1;
pub const SERVICE_START_PENDING: u32 = 2;
pub const SERVICE_RUNNING: u32 = 4;

/// The `STATE` number in `sc query` output.
pub fn parse_state(sc_query_output: &str) -> Option<u32> {
    sc_query_output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "STATE" {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

/// `TYPE` numbers `sc qc` prints, in hex: a kernel driver and a file system
/// driver. Win32 services have 0x10 and up.
pub const SERVICE_KERNEL_DRIVER: u32 = 0x1;
pub const SERVICE_FILE_SYSTEM_DRIVER: u32 = 0x2;

/// `WIN32_EXIT_CODE` 1077: not started since Windows started.
pub const ERROR_SERVICE_NEVER_STARTED: u32 = 1077;
/// `WIN32_EXIT_CODE` 1068: a service it depends on did not start. Windows
/// sets it whether it started the service at boot or someone did by hand
/// (seen in Windows Sandbox).
pub const ERROR_SERVICE_DEPENDENCY_FAIL: u32 = 1068;

/// What `sc qc` says about a service, its display name in the display
/// language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    pub service_type: u32,
    pub display_name: String,
    /// The services it depends on (`DependOnService`); groups, which `sc`
    /// prints with a `+`, are left out.
    pub dependencies: Vec<String>,
}

impl ServiceConfig {
    pub fn is_driver(&self) -> bool {
        matches!(
            self.service_type,
            SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER
        )
    }
}

/// The fields of `sc` output: `KEY : value`, and the lines that continue a
/// list as ` : value` under it, with an empty key.
fn fields(output: &str) -> impl Iterator<Item = (&str, &str)> {
    output.lines().filter_map(|line| {
        let (key, value) = line.split_once(':')?;
        Some((key.trim(), value.trim()))
    })
}

/// The configuration in `sc qc` output, or `None` when it holds none (the
/// service is not installed, or `sc` was refused).
pub fn parse_config(sc_qc_output: &str) -> Option<ServiceConfig> {
    let mut service_type = None;
    let mut display_name = String::new();
    let mut dependencies = Vec::new();
    let mut in_dependencies = false;
    for (key, value) in fields(sc_qc_output) {
        in_dependencies = match key {
            "DEPENDENCIES" => true,
            "" => in_dependencies,
            _ => false,
        };
        match key {
            "TYPE" => {
                service_type = value
                    .split_whitespace()
                    .next()
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok());
            }
            "DISPLAY_NAME" => display_name = value.to_string(),
            _ if in_dependencies && !value.is_empty() && !value.starts_with('+') => {
                dependencies.push(value.to_string());
            }
            _ => {}
        }
    }
    Some(ServiceConfig {
        service_type: service_type?,
        display_name,
        dependencies,
    })
}

/// A service as `sc query type= service state= all` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub name: String,
    pub display_name: String,
    pub state: u32,
    pub exit_code: u32,
}

/// Every service in `sc query` output, which lists one or many.
pub fn parse_status_list(sc_query_output: &str) -> Vec<ServiceStatus> {
    let number = |value: &str| value.split_whitespace().next()?.parse().ok();
    let mut services: Vec<ServiceStatus> = Vec::new();
    for (key, value) in fields(sc_query_output) {
        if key == "SERVICE_NAME" {
            services.push(ServiceStatus {
                name: value.to_string(),
                display_name: String::new(),
                state: 0,
                exit_code: 0,
            });
            continue;
        }
        let Some(service) = services.last_mut() else {
            continue;
        };
        match key {
            "DISPLAY_NAME" => service.display_name = value.to_string(),
            "STATE" => service.state = number(value).unwrap_or(0),
            "WIN32_EXIT_CODE" => service.exit_code = number(value).unwrap_or(0),
            _ => {}
        }
    }
    services
}

/// Whether the service runs, is stopped, ..., or `None` when `sc query` did
/// not say. `net start` and `net stop` report in the display language, and
/// `net stop` of a service that is not running fails with exit code 2.
pub async fn state(runner: &dyn CommandRunner, service: &str) -> Result<Option<u32>, String> {
    let out = runner
        .run("sc.exe", &["query", service], Duration::from_secs(8))
        .await?;
    Ok(parse_state(&out.stdout))
}

/// The service's start type, or `None` when `sc qc` did not report one (no
/// such service, access denied).
pub async fn start_type(runner: &dyn CommandRunner, service: &str) -> Result<Option<u32>, String> {
    let out = runner
        .run("sc.exe", &["qc", service], Duration::from_secs(8))
        .await?;
    Ok(parse_start_type(&out.stdout))
}

/// Starts `services`, in the order given, when dropped while still armed: a
/// repair that is cancelled, or fails, between stopping a service and starting
/// it again must not leave it stopped. Through the runner, on the runtime,
/// because a destructor cannot wait. Armed by [`Self::new`]; [`Self::disarm`]
/// once the caller has started them itself.
pub struct StartAgain {
    runner: Arc<dyn CommandRunner>,
    services: &'static [&'static str],
    armed: bool,
}

impl StartAgain {
    /// Armed: dropping the guard runs `net start` for each of `services`.
    pub fn new(runner: Arc<dyn CommandRunner>, services: &'static [&'static str]) -> Self {
        Self {
            runner,
            services,
            armed: true,
        }
    }

    /// The caller has started the services, so dropping the guard does nothing.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartAgain {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let runner = self.runner.clone();
        let services = self.services;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for svc in services {
                    let _ = runner
                        .run("net.exe", &["start", svc], Duration::from_secs(30))
                        .await;
                }
            });
        }
    }
}

/// Real `sc qc` output for other modules' tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::utils::decode::decode_output;

    /// What `sc qc <service>` prints on a German Windows 11 for a service with
    /// this start type — the captured output of a disabled service, renamed and
    /// with its start type swapped.
    pub fn sc_qc_output(service: &str, start_type: u32) -> String {
        let name = match start_type {
            2 => "AUTO_START",
            3 => "DEMAND_START",
            4 => "DISABLED",
            _ => "BOOT_START",
        };
        decode_output(include_bytes!(
            "../../tests/fixtures/console/sc_qc_disabled.bin"
        ))
        .replace("AppVClient", service)
        .replace("4   DISABLED", &format!("{start_type}   {name}"))
    }

    /// A list as `sc query type= service state= all` prints it, of
    /// `(name, display name, state, exit code)`: for each, the captured
    /// entry of a stopped service (WinMedicChainA, Windows Sandbox) or of a
    /// running one (RpcSs), renamed and with its exit code swapped.
    pub fn sc_query_list(services: &[(&str, &str, u32, u32)]) -> String {
        let list = decode_output(include_bytes!(
            "../../tests/fixtures/console/sc_query_service_list.bin"
        ));
        let entry = |name: &str| {
            let start = list.find(&format!("SERVICE_NAME: {name}\r\n")).unwrap();
            let end = list[start..]
                .find("\r\n\r\n")
                .map_or(list.len(), |at| start + at + 4);
            list[start..end].to_string()
        };
        services
            .iter()
            .map(|&(name, display, state, exit_code)| {
                let (template, (old_name, old_display)) = if state == super::SERVICE_RUNNING {
                    (entry("RpcSs"), ("RpcSs", "Remoteprozeduraufruf (RPC)"))
                } else {
                    (
                        entry("WinMedicChainA"),
                        ("WinMedicChainA", "WinMedic Chain A"),
                    )
                };
                template
                    .replace(
                        &format!("SERVICE_NAME: {old_name}\r\n"),
                        &format!("SERVICE_NAME: {name}\r\n"),
                    )
                    .replace(
                        &format!("DISPLAY_NAME: {old_display}\r\n"),
                        &format!("DISPLAY_NAME: {display}\r\n"),
                    )
                    .replace("1068  (0x42c)", &format!("{exit_code}  ({exit_code:#x})"))
            })
            .collect()
    }

    /// What `sc query <service>` prints for a service in this state: the
    /// captured output of a stopped service, renamed and with its state
    /// swapped.
    pub fn sc_query_output(service: &str, state: u32) -> String {
        let name = match state {
            1 => "STOPPED",
            2 => "START_PENDING",
            _ => "RUNNING",
        };
        decode_output(include_bytes!(
            "../../tests/fixtures/console/sc_query_disabled_service.bin"
        ))
        .replace("AppVClient", service)
        .replace("1  STOPPED", &format!("{state}  {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::decode::decode_output;

    // Captured on a German Windows 11. `sc` keeps its field names in English
    // there, and the start type is a number either way.
    const QC_DISABLED: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_disabled.bin");
    const QC_DEMAND: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_demand.bin");
    const QUERY_OF_DISABLED: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_query_disabled_service.bin");

    #[test]
    fn reads_the_start_type_from_sc_qc() {
        assert_eq!(
            parse_start_type(&decode_output(QC_DISABLED)),
            Some(SERVICE_DISABLED)
        );
        assert_eq!(parse_start_type(&decode_output(QC_DEMAND)), Some(3));
    }

    #[test]
    fn sc_query_never_says_how_a_service_starts() {
        // The same disabled service, asked with `sc query`: only its state.
        // This is why the old checks never found a disabled service.
        let text = decode_output(QUERY_OF_DISABLED);
        assert!(text.contains("STOPPED"));
        assert!(!text.to_lowercase().contains("disabled"));
        assert_eq!(parse_start_type(&text), None);
    }

    #[test]
    fn reads_the_state_from_sc_query() {
        assert_eq!(
            parse_state(&decode_output(QUERY_OF_DISABLED)),
            Some(SERVICE_STOPPED)
        );
        assert_eq!(parse_state(&decode_output(QC_DEMAND)), None);
    }

    // `sc qc` on the development PC, 2026-10-09: CmService and HvHost as
    // Windows sets them up, the driver HvHost depends on, a file system
    // driver that depends on a group, and a service that does not exist.
    const QC_CMSERVICE: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_cmservice.bin");
    const QC_HVHOST: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_hvhost.bin");
    const QC_HVSERVICE: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_hvservice.bin");
    const QC_GROUP: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_qc_group_dependency.bin");
    const QC_MISSING: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_qc_not_installed_de.bin");

    #[test]
    fn reads_dependencies_over_several_lines() {
        let cm = parse_config(&decode_output(QC_CMSERVICE)).unwrap();
        assert_eq!(cm.dependencies, ["rpcss", "vmcompute", "hvhost"]);
        assert_eq!(cm.service_type, 0x20);
        assert_eq!(cm.display_name, "Container-Manager-Dienst");
        assert!(!cm.is_driver());

        let hv = parse_config(&decode_output(QC_HVHOST)).unwrap();
        assert_eq!(hv.dependencies, ["hvservice"]);
    }

    #[test]
    fn a_driver_has_type_1_or_2_and_groups_are_not_services() {
        let driver = parse_config(&decode_output(QC_HVSERVICE)).unwrap();
        assert!(driver.is_driver());
        assert!(driver.dependencies.is_empty());

        let file_system = parse_config(&decode_output(QC_GROUP)).unwrap();
        assert_eq!(file_system.service_type, SERVICE_FILE_SYSTEM_DRIVER);
        assert!(file_system.is_driver());
        assert!(file_system.dependencies.is_empty(), "+SCSI CDROM Class");
    }

    #[test]
    fn a_service_that_does_not_exist_has_no_configuration() {
        assert_eq!(parse_config(&decode_output(QC_MISSING)), None);
        assert_eq!(parse_config(""), None);
    }

    /// `sc query type= service state= all` in Windows Sandbox, with two test
    /// services: WinMedicChainA starts automatically and depends on
    /// WinMedicChainB, whose program does not exist.
    const SERVICE_LIST: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_query_service_list.bin");

    #[test]
    fn reads_every_service_in_a_list() {
        let services = parse_status_list(&decode_output(SERVICE_LIST));
        assert_eq!(services.len(), 268);
        let a = services
            .iter()
            .find(|s| s.name == "WinMedicChainA")
            .unwrap();
        assert_eq!(
            (a.state, a.exit_code),
            (SERVICE_STOPPED, ERROR_SERVICE_DEPENDENCY_FAIL)
        );
        assert_eq!(a.display_name, "WinMedic Chain A");
        // A service whose program is missing never ran: no exit code.
        let b = services
            .iter()
            .find(|s| s.name == "WinMedicChainB")
            .unwrap();
        assert_eq!((b.state, b.exit_code), (SERVICE_STOPPED, 0));
        let alg = services.iter().find(|s| s.name == "ALG").unwrap();
        assert_eq!(alg.exit_code, ERROR_SERVICE_NEVER_STARTED);
        assert!(services.iter().all(|s| s.state != 0), "every state read");
    }

    #[test]
    fn reads_one_service() {
        let one = parse_status_list(&decode_output(QUERY_OF_DISABLED));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name, "AppVClient");
        assert_eq!(one[0].state, SERVICE_STOPPED);
    }

    #[test]
    fn output_without_a_start_type_yields_none() {
        assert_eq!(parse_start_type(""), None);
        assert_eq!(
            parse_start_type(
                "[SC] OpenService FEHLER 1060:\n\nDer angegebene Dienst ist nicht installiert."
            ),
            None
        );
    }
}
