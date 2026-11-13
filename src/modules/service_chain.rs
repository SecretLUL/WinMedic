//! Why a service cannot start: the services it depends on, followed down to
//! the drivers, and the devices bound to those drivers.
//!
//! On the development PC the Container Manager Service did not start
//! because the HV Host Service it depends on stopped with error 31, and
//! HvHost stopped because the device its driver serves was disabled. Each
//! symptom was in a different place - a service error, an event, Device
//! Manager - and the chain linking them took hours to find.
//!
//! Only what the service configuration says counts (`DependOnService`, as
//! `sc qc` prints it), never the text of an event, and devices are judged by
//! their problem code.
//!
//! A chain also ends at a driver that is switched off (`START_TYPE` 4) and
//! not loaded, when the service above it stopped with 1068: see
//! [`DriverOff`].

use crate::modules::devices::meaning;
use crate::utils::cmd::CommandRunner;
use crate::utils::pnp::PnpDevice;
use crate::utils::service::{
    self, ERROR_SERVICE_DEPENDENCY_FAIL, ERROR_SERVICE_NEVER_STARTED, SERVICE_DISABLED,
    SERVICE_RUNNING, SERVICE_STOPPED, ServiceConfig, ServiceStatus,
};
use std::collections::HashMap;
use std::time::Duration;

/// How many services deep a chain is followed. The longest one Windows sets
/// up for itself here is three (CmService, HvHost, the hvservice driver).
const MAX_DEPTH: usize = 6;

/// `CM_PROB_DISABLED`.
const DEVICE_DISABLED: u32 = 22;

/// A service in a chain and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    pub display_name: String,
    pub exit_code: u32,
}

impl Link {
    fn from_status(status: &ServiceStatus) -> Self {
        Self {
            name: status.name.clone(),
            display_name: status.display_name.clone(),
            exit_code: status.exit_code,
        }
    }

    /// `HV-Hostdienst (HvHost)`: the name the user knows, in the display
    /// language, and the one that is the same everywhere.
    fn label(&self) -> String {
        if self.display_name.is_empty() || self.display_name.eq_ignore_ascii_case(&self.name) {
            self.name.clone()
        } else {
            format!("{} ({})", self.display_name, self.name)
        }
    }
}

/// A service that cannot start, the services between it and a driver, and
/// the device of that driver whose problem is the cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// From the service that cannot start down to the one that depends on
    /// the driver.
    pub services: Vec<Link>,
    pub driver: String,
    pub device: PnpDevice,
}

impl Chain {
    /// `Container-Manager-Dienst (CmService) cannot start: HV-Hostdienst
    /// (HvHost) failed (exit code 31) because the device 'Microsoft
    /// Hypervisor Service' is disabled.`, with `device_name` for the device.
    pub fn sentence(&self, device_name: &str) -> String {
        let problem = match self.device.problem {
            DEVICE_DISABLED => "is disabled".to_string(),
            code => format!("reports problem code {code}: {}", meaning(code)),
        };
        format!(
            "{} because the device '{device_name}' {problem}.",
            how_they_ended(&self.services)
        )
    }

    /// The service the chain starts with.
    pub fn head(&self) -> &Link {
        &self.services[0]
    }

    /// The chain for technical details: each service with its exit code,
    /// the driver and the device.
    pub fn details(&self) -> String {
        format!(
            "Service chain: {} -> driver {} -> device {} (problem code {})",
            with_exit_codes(&self.services),
            self.driver,
            self.device.instance_id,
            self.device.problem
        )
    }
}

/// `A cannot start: B failed (exit code 31)`: the services of a chain, each
/// with how it ended.
fn how_they_ended(services: &[Link]) -> String {
    services
        .iter()
        .map(|link| match link.exit_code {
            ERROR_SERVICE_DEPENDENCY_FAIL => format!("{} cannot start", link.label()),
            ERROR_SERVICE_NEVER_STARTED => format!("{} did not start", link.label()),
            0 => format!("{} is stopped", link.label()),
            code => format!("{} failed (exit code {code})", link.label()),
        })
        .collect::<Vec<_>>()
        .join(": ")
}

/// `A (exit code 1068) -> B (exit code 31)`, for technical details.
fn with_exit_codes(services: &[Link]) -> String {
    services
        .iter()
        .map(|link| format!("{} (exit code {})", link.name, link.exit_code))
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// A service that cannot start because a driver it depends on is switched
/// off, with the services between them (#141).
///
/// Windows ships drivers switched off (`cdfs` in Windows Sandbox, seven on
/// the development PC), so a switched-off driver alone says nothing. It ends
/// a chain only when all of this holds:
/// - its `START_TYPE` is 4, a number in every display language,
/// - it is not loaded: a driver switched off while it runs stays loaded
///   until Windows restarts, and its dependents start,
/// - the service that depends on it stopped with 1068, "the dependency
///   service or group failed to start", which is what Windows leaves on a
///   service after such a start (seen in Windows Sandbox, 26100.9974, on
///   2026-11-13; a service that was never asked to start shows 1077),
/// - no device of the driver reports a problem: that device is the cause
///   then, and has a [`Chain`] of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverOff {
    /// From the service that cannot start down to the one that depends on
    /// the driver.
    pub services: Vec<Link>,
    /// The driver's service name, `cdfs`.
    pub driver: String,
    /// `CD/DVD File System Reader`; empty when `sc` printed none.
    pub display_name: String,
}

impl DriverOff {
    /// The service the chain starts with.
    pub fn head(&self) -> &Link {
        &self.services[0]
    }

    /// `CD/DVD File System Reader (cdfs)`, or the service name alone.
    pub fn driver_label(&self) -> String {
        if self.display_name.is_empty() || self.display_name.eq_ignore_ascii_case(&self.driver) {
            self.driver.clone()
        } else {
            format!("{} ({})", self.display_name, self.driver)
        }
    }

    /// `Windows-Zeitgeber (W32Time) cannot start because the driver 'CD/DVD
    /// File System Reader (cdfs)' is switched off.`
    pub fn sentence(&self) -> String {
        format!(
            "{} because the driver '{}' is switched off.",
            how_they_ended(&self.services),
            self.driver_label()
        )
    }

    /// The chain for technical details: each service with its exit code,
    /// and the driver with its start type.
    pub fn details(&self) -> String {
        format!(
            "Service chain: {} -> driver {} (START_TYPE {SERVICE_DISABLED}, switched off; not loaded)",
            with_exit_codes(&self.services),
            self.driver
        )
    }
}

/// What explains the services that stopped with an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Failing {
    /// The chains that end at a device with a problem.
    pub chains: Vec<Chain>,
    /// The chains that end at a driver that is switched off.
    pub drivers_off: Vec<DriverOff>,
}

/// The services Windows lists, by state, and each one's configuration once
/// it has been asked for.
struct Walker<'a> {
    runner: &'a dyn CommandRunner,
    statuses: &'a [ServiceStatus],
    devices: &'a [PnpDevice],
    configs: HashMap<String, Option<ServiceConfig>>,
}

impl Walker<'_> {
    fn status(&self, name: &str) -> Option<&ServiceStatus> {
        self.statuses
            .iter()
            .find(|status| status.name.eq_ignore_ascii_case(name))
    }

    /// `sc qc` of `name`, asked once. `None` for a service that does not
    /// exist or that `sc` may not read: a chain through it is not followed.
    async fn config(&mut self, name: &str) -> Option<ServiceConfig> {
        let key = name.to_ascii_lowercase();
        if let Some(known) = self.configs.get(&key) {
            return known.clone();
        }
        let config = self
            .runner
            .run("sc.exe", &["qc", name], Duration::from_secs(8))
            .await
            .ok()
            .and_then(|out| service::parse_config(&out.stdout));
        self.configs.insert(key, config.clone());
        config
    }

    /// Whether the driver `name` is not loaded, as `sc query` says. A driver
    /// `sc` does not answer for is not known to be stopped.
    async fn stopped(&self, name: &str) -> bool {
        service::state(self.runner, name).await == Ok(Some(SERVICE_STOPPED))
    }

    /// Every chain from `start` down to a driver whose device has a problem,
    /// or that is switched off: added to `found`.
    async fn chains_from(&mut self, start: Link, found: &mut Failing) {
        let mut pending = vec![vec![start]];
        while let Some(path) = pending.pop() {
            let current = &path[path.len() - 1].name;
            let Some(config) = self.config(current).await else {
                continue;
            };
            for dependency in config.dependencies {
                if path
                    .iter()
                    .any(|link| link.name.eq_ignore_ascii_case(&dependency))
                {
                    // A cycle.
                    continue;
                }
                match self.status(&dependency) {
                    // A service that runs is not why its dependents stopped.
                    Some(status) if status.state == SERVICE_RUNNING => continue,
                    Some(status) => {
                        if path.len() < MAX_DEPTH {
                            let mut longer = path.clone();
                            longer.push(Link::from_status(status));
                            pending.push(longer);
                        }
                        continue;
                    }
                    // Not in the list of Win32 services: a driver, or none.
                    None => {}
                }
                let Some(driver) = self.config(&dependency).await else {
                    continue;
                };
                if !driver.is_driver() {
                    continue;
                }
                let mut a_device_explains_it = false;
                for device in self.devices.iter().filter(|device| {
                    device.problem != 0 && device.service.eq_ignore_ascii_case(&dependency)
                }) {
                    a_device_explains_it = true;
                    found.chains.push(Chain {
                        services: path.clone(),
                        driver: dependency.clone(),
                        device: device.clone(),
                    });
                }
                // See `DriverOff` for why each of these is asked.
                if !a_device_explains_it
                    && driver.start_type == Some(SERVICE_DISABLED)
                    && path[path.len() - 1].exit_code == ERROR_SERVICE_DEPENDENCY_FAIL
                    && self.stopped(&dependency).await
                {
                    found.drivers_off.push(DriverOff {
                        services: path.clone(),
                        driver: dependency.clone(),
                        display_name: driver.display_name.clone(),
                    });
                }
            }
        }
    }
}

/// `sc query` of every Win32 service.
async fn service_statuses(runner: &dyn CommandRunner) -> Result<Vec<ServiceStatus>, String> {
    let out = runner
        .run(
            "sc.exe",
            &["query", "type=", "service", "state=", "all"],
            Duration::from_secs(30),
        )
        .await?;
    let statuses = service::parse_status_list(&out.stdout);
    if !out.success || statuses.is_empty() {
        return Err(format!(
            "sc query listed no services (exit code {:?})",
            out.exit_code
        ));
    }
    Ok(statuses)
}

/// The chains to a device with a problem among [`failing`]'s. Without such
/// a device nothing is asked at all.
pub async fn failing_chains(
    runner: &dyn CommandRunner,
    devices: &[PnpDevice],
) -> Result<Vec<Chain>, String> {
    if !devices.iter().any(|device| device.problem != 0) {
        return Ok(Vec::new());
    }
    Ok(failing(runner, devices).await?.chains)
}

/// Every chain that explains a service which stopped with an error: stopped,
/// with an exit code other than 0 and 1077 ("never started"). A chain that
/// is the end of a longer one is left out, so CmService's chain through
/// HvHost stands for HvHost's own.
pub async fn failing(runner: &dyn CommandRunner, devices: &[PnpDevice]) -> Result<Failing, String> {
    let statuses = service_statuses(runner).await?;
    let mut walker = Walker {
        runner,
        statuses: &statuses,
        devices,
        configs: HashMap::new(),
    };
    let mut found = Failing::default();
    for status in statuses.iter().filter(|status| {
        status.state == SERVICE_STOPPED
            && !matches!(status.exit_code, 0 | ERROR_SERVICE_NEVER_STARTED)
    }) {
        walker
            .chains_from(Link::from_status(status), &mut found)
            .await;
    }
    Ok(Failing {
        chains: without_tails(found.chains),
        drivers_off: without_driver_tails(found.drivers_off),
    })
}

/// The chains from the service `name`, whatever its exit code: for a service
/// something else waits for. Empty while it runs.
pub async fn chains_from_service(
    runner: &dyn CommandRunner,
    devices: &[PnpDevice],
    name: &str,
) -> Result<Vec<Chain>, String> {
    let statuses = service_statuses(runner).await?;
    let Some(status) = statuses
        .iter()
        .find(|status| status.name.eq_ignore_ascii_case(name))
    else {
        return Ok(Vec::new());
    };
    if status.state == SERVICE_RUNNING {
        return Ok(Vec::new());
    }
    let mut walker = Walker {
        runner,
        statuses: &statuses,
        devices,
        configs: HashMap::new(),
    };
    let mut found = Failing::default();
    walker
        .chains_from(Link::from_status(status), &mut found)
        .await;
    Ok(without_tails(found.chains))
}

/// `chains` without those whose services are the end of another chain's to
/// the same device.
fn without_tails(chains: Vec<Chain>) -> Vec<Chain> {
    let is_tail = |chain: &Chain, of: &Chain| {
        of.services.len() > chain.services.len()
            && of.device.instance_id == chain.device.instance_id
            && of.services[of.services.len() - chain.services.len()..] == chain.services[..]
    };
    let mut kept: Vec<Chain> = chains
        .iter()
        .filter(|chain| !chains.iter().any(|other| is_tail(chain, other)))
        .cloned()
        .collect();
    kept.dedup();
    kept
}

/// [`without_tails`] for the chains that end at a switched-off driver.
fn without_driver_tails(chains: Vec<DriverOff>) -> Vec<DriverOff> {
    let is_tail = |chain: &DriverOff, of: &DriverOff| {
        of.services.len() > chain.services.len()
            && of.driver.eq_ignore_ascii_case(&chain.driver)
            && of.services[of.services.len() - chain.services.len()..] == chain.services[..]
    };
    let mut kept: Vec<DriverOff> = chains
        .iter()
        .filter(|chain| !chains.iter().any(|other| is_tail(chain, other)))
        .cloned()
        .collect();
    kept.dedup();
    kept
}

/// Captured `sc` output of the services in the development PC's chain, for
/// the tests of the modules that report it.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;
    use crate::utils::service::test_support::sc_query_list;

    // `sc qc` on the development PC, 2026-10-09, as Windows sets these up:
    // CmService depends on rpcss, vmcompute and hvhost, HvHost on the
    // driver hvservice, vmcompute on rpcss and three drivers.
    pub const QC_CMSERVICE: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_qc_cmservice.bin");
    pub const QC_HVHOST: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_hvhost.bin");
    pub const QC_HVSERVICE: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_qc_hvservice.bin");
    pub const QC_VMCOMPUTE: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_qc_vmcompute.bin");
    pub const QC_MISSING: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_qc_not_installed_de.bin");

    // Windows Sandbox (26100.9974, German) on 2026-11-13, for #141: W32Time
    // made to depend on the driver cdfs, which Windows ships switched off
    // there, and asked to start. `sc start` failed with 1068.
    const QC_DRIVER_OFF: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_qc_driver_disabled.bin");
    const QUERY_DRIVER_OFF: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_query_driver_disabled.bin");
    const QC_WAITS_FOR_DRIVER: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_qc_depends_on_disabled_driver.bin");
    pub const QUERY_WAITS_FOR_DRIVER: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_query_depends_on_disabled_driver.bin");

    /// `sc qc cdfs` there: a file system driver, `START_TYPE` 4.
    pub fn qc_driver_off() -> String {
        decode_output(QC_DRIVER_OFF)
    }

    /// `sc query cdfs` there: stopped.
    pub fn query_driver_off() -> String {
        decode_output(QUERY_DRIVER_OFF)
    }

    /// The sandbox's services as far as the chain goes: W32Time stopped
    /// with `exit_code` (1068 after the failed start, 1077 before it) and
    /// depending on cdfs, for which `sc` prints `qc_cdfs` and `query_cdfs`.
    pub fn waits_for_driver(
        exit_code: u32,
        qc_cdfs: String,
        query_cdfs: String,
    ) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "query type= service",
            CmdOutput::ok(sc_query_list(&[(
                "W32Time",
                "Windows-Zeitgeber",
                1,
                exit_code,
            )])),
        );
        mock.add_response(
            "qc W32Time",
            CmdOutput::ok(decode_output(QC_WAITS_FOR_DRIVER)),
        );
        mock.add_response("qc cdfs", CmdOutput::ok(qc_cdfs));
        mock.add_response("query cdfs", CmdOutput::ok(query_cdfs));
        mock
    }

    /// The sandbox as captured: W32Time waits for the switched-off cdfs.
    pub fn waits_for_a_switched_off_driver() -> MockCommandRunner {
        waits_for_driver(1068, qc_driver_off(), query_driver_off())
    }

    /// The captured `sc qc` of HvHost as `name`, depending on `on`.
    pub fn depends_on(name: &str, on: &[&str]) -> CmdOutput {
        CmdOutput::ok(decode_output(QC_HVHOST).replace("HvHost", name).replace(
            "DEPENDENCIES       : hvservice",
            &format!(
                "DEPENDENCIES       : {}",
                on.join("\r\n                           : ")
            ),
        ))
    }

    /// `services` as `sc query` lists them, with the captured `sc qc` of
    /// CmService, HvHost, vmcompute and their drivers.
    pub fn listing(services: &[(&str, &str, u32, u32)]) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "query type= service",
            CmdOutput::ok(sc_query_list(services)),
        );
        mock.add_response("qc CmService", CmdOutput::ok(decode_output(QC_CMSERVICE)));
        for name in ["HvHost", "hvhost"] {
            mock.add_response(
                format!("qc {name}"),
                CmdOutput::ok(decode_output(QC_HVHOST)),
            );
        }
        mock.add_response("qc vmcompute", CmdOutput::ok(decode_output(QC_VMCOMPUTE)));
        mock.add_response("qc hvservice", CmdOutput::ok(decode_output(QC_HVSERVICE)));
        // vmcompute's drivers: the captured `sc qc` of a driver, renamed.
        for name in ["wcifs", "hvsocketcontrol", "condrv"] {
            mock.add_response(
                format!("qc {name}"),
                CmdOutput::ok(decode_output(QC_HVSERVICE).replace("hvservice", name)),
            );
        }
        mock
    }

    /// The services as they were on the development PC on 2026-10-08:
    /// CmService could not start because HvHost stopped with `hvhost_exit`.
    pub fn dev_pc_services(hvhost_exit: u32) -> MockCommandRunner {
        listing(&[
            ("ALG", "Gatewaydienst auf Anwendungsebene", 1, 1077),
            ("CmService", "Container-Manager-Dienst", 1, 1068),
            ("HvHost", "HV-Hostdienst", 1, hvhost_exit),
            ("RpcSs", "Remoteprozeduraufruf (RPC)", 4, 0),
            ("vmcompute", "Hyper-V-Hostserverdienst", 1, 1077),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;
    use crate::utils::service::test_support::sc_query_list;

    const HVSERVICE: &str = r"ROOT\HVSERVICE\0000";

    fn device(problem: u32, instance_id: &str, service: &str) -> PnpDevice {
        PnpDevice {
            problem,
            class: "System".to_string(),
            instance_id: instance_id.to_string(),
            name: String::new(),
            service: service.to_string(),
            driver: String::new(),
        }
    }

    /// The development PC's devices with a problem, the Microsoft
    /// Hypervisor Service reporting `hvservice`.
    fn devices(hvservice: u32) -> Vec<PnpDevice> {
        vec![
            device(22, r"ACPI\PNP0103\2&DABA3FF&0", ""),
            device(hvservice, HVSERVICE, "hvservice"),
            device(22, r"ROOT\NDISVIRTUALBUS\0000", "NdisVirtualBus"),
            device(28, r"ACPI\AMDI0204\2&DABA3FF&0", ""),
        ]
    }

    #[tokio::test]
    async fn the_container_manager_waits_for_a_disabled_device() {
        let chains = failing_chains(&dev_pc_services(31), &devices(22))
            .await
            .unwrap();
        assert_eq!(chains.len(), 1, "{chains:?}");
        let chain = &chains[0];
        let names: Vec<&str> = chain.services.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["CmService", "HvHost"]);
        assert_eq!(chain.driver, "hvservice");
        assert_eq!(chain.device.instance_id, HVSERVICE);
        assert_eq!(
            chain.sentence("Microsoft Hypervisor Service"),
            "Container-Manager-Dienst (CmService) cannot start: HV-Hostdienst (HvHost) failed (exit code 31) because the device 'Microsoft Hypervisor Service' is disabled."
        );
    }

    /// While the services were grouped, HvHost failed with 298 instead:
    /// the same chain.
    #[tokio::test]
    async fn the_chain_holds_whatever_error_the_service_reports() {
        let chains = failing_chains(&dev_pc_services(298), &devices(22))
            .await
            .unwrap();
        assert_eq!(chains.len(), 1, "{chains:?}");
        assert!(
            chains[0]
                .sentence("x")
                .contains("HV-Hostdienst (HvHost) failed (exit code 298)")
        );
    }

    #[tokio::test]
    async fn a_device_that_works_explains_nothing() {
        let chains = failing_chains(&dev_pc_services(31), &devices(0))
            .await
            .unwrap();
        assert!(chains.is_empty(), "{chains:?}");
    }

    /// Without a device with a problem nothing is asked at all.
    #[tokio::test]
    async fn a_pc_whose_devices_work_is_not_asked_about_its_services() {
        let mock = MockCommandRunner::new();
        let healthy = vec![device(0, HVSERVICE, "hvservice")];
        assert_eq!(failing_chains(&mock, &healthy).await, Ok(Vec::new()));
        assert!(mock.executed().is_empty());
    }

    /// Services that never started or stopped without an error are no
    /// starting point, and a running HvHost ends the chain.
    #[tokio::test]
    async fn only_services_that_stopped_with_an_error_are_followed() {
        for (cm, hv) in [
            ((1, 1077), (1, 1077)),
            ((1, 0), (1, 0)),
            ((1, 1068), (4, 0)),
        ] {
            let mock = listing(&[
                ("CmService", "Container-Manager-Dienst", cm.0, cm.1),
                ("HvHost", "HV-Hostdienst", hv.0, hv.1),
            ]);
            let chains = failing_chains(&mock, &devices(22)).await.unwrap();
            assert!(chains.is_empty(), "{cm:?} {hv:?}: {chains:?}");
        }
    }

    /// A dependency that is not installed, one `sc` may not read, and two
    /// services that depend on each other end the search quietly.
    #[tokio::test]
    async fn missing_services_refusals_and_cycles_end_the_search() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "query type= service",
            CmdOutput::ok(sc_query_list(&[
                ("LoopA", "Loop A", 1, 1068),
                ("LoopB", "Loop B", 1, 1068),
            ])),
        );
        mock.add_response(
            "qc LoopA",
            depends_on("LoopA", &["LoopB", "gone", "refused"]),
        );
        mock.add_response("qc LoopB", depends_on("LoopB", &["LoopA"]));
        mock.add_response(
            "qc gone",
            CmdOutput::with_output(1060, decode_output(QC_MISSING), ""),
        );
        // `qc refused` has no answer: the runner fails.
        let chains = failing_chains(&mock, &devices(22)).await.unwrap();
        assert!(chains.is_empty(), "{chains:?}");
        let mut asked: Vec<String> = mock
            .executed()
            .into_iter()
            .filter(|c| c.contains(" qc "))
            .collect();
        asked.sort();
        assert_eq!(
            asked,
            [
                "sc.exe qc LoopA",
                "sc.exe qc LoopB",
                "sc.exe qc gone",
                "sc.exe qc refused"
            ],
            "each service is asked once"
        );
    }

    /// Ten services each waiting for the next, the last for the driver of
    /// the disabled device: the search goes `MAX_DEPTH` services deep.
    #[tokio::test]
    async fn the_search_depth_is_limited() {
        let names: Vec<String> = (0..10).map(|i| format!("Step{i}")).collect();
        let list: Vec<(&str, &str, u32, u32)> = names
            .iter()
            .map(|name| (name.as_str(), name.as_str(), 1, 1068))
            .collect();
        let mock = MockCommandRunner::new();
        mock.add_response("query type= service", CmdOutput::ok(sc_query_list(&list)));
        for (i, name) in names.iter().enumerate() {
            let next = names.get(i + 1).map_or("hvservice", String::as_str);
            mock.add_response(format!("qc {name}"), depends_on(name, &[next]));
        }
        mock.add_response("qc hvservice", CmdOutput::ok(decode_output(QC_HVSERVICE)));
        let chains = failing_chains(&mock, &devices(22)).await.unwrap();
        let heads: Vec<&str> = chains.iter().map(|c| c.head().name.as_str()).collect();
        // Step9 depends on the driver; Step4 is six services above it.
        assert_eq!(heads, ["Step4"], "{chains:?}");
        assert_eq!(chains[0].services.len(), MAX_DEPTH);
    }

    #[tokio::test]
    async fn a_refused_service_list_is_an_error() {
        let mock = MockCommandRunner::new();
        mock.add_response("query type= service", CmdOutput::failed(5, "FEHLER"));
        assert!(failing_chains(&mock, &devices(22)).await.is_err());
    }

    /// #141, as captured in Windows Sandbox: W32Time depends on the driver
    /// cdfs, which is switched off, and stopped with 1068 when it was asked
    /// to start.
    #[tokio::test]
    async fn a_service_waits_for_a_driver_that_is_switched_off() {
        // What Windows left on the service after the failed start.
        let after = service::parse_status_list(&decode_output(QUERY_WAITS_FOR_DRIVER));
        assert_eq!(after.len(), 1);
        assert_eq!(
            (after[0].state, after[0].exit_code),
            (SERVICE_STOPPED, ERROR_SERVICE_DEPENDENCY_FAIL)
        );
        let driver = service::parse_config(&qc_driver_off()).unwrap();
        assert!(driver.is_driver());
        assert_eq!(driver.start_type, Some(SERVICE_DISABLED));
        // Its dependency is a group, `+SCSI CDROM Class`: no service.
        assert!(driver.dependencies.is_empty());

        let mock = waits_for_a_switched_off_driver();
        let found = failing(&mock, &[]).await.unwrap();
        assert!(found.chains.is_empty());
        assert_eq!(found.drivers_off.len(), 1, "{found:?}");
        let off = &found.drivers_off[0];
        assert_eq!(off.head().name, "W32Time");
        assert_eq!(off.driver, "cdfs");
        assert_eq!(
            off.sentence(),
            "Windows-Zeitgeber (W32Time) cannot start because the driver 'CD/DVD File System Reader (cdfs)' is switched off."
        );
        assert_eq!(
            off.details(),
            "Service chain: W32Time (exit code 1068) -> driver cdfs (START_TYPE 4, switched off; not loaded)"
        );
        // The chains to devices are unchanged by it.
        assert!(
            failing_chains(&mock, &devices(22))
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Windows ships drivers switched off, so that alone ends no chain: the
    /// service has to have failed with 1068, and the driver has to be
    /// switched off and not loaded.
    #[tokio::test]
    async fn a_switched_off_driver_alone_explains_nothing() {
        let on_demand = qc_driver_off().replace("4   DISABLED", "3   DEMAND_START");
        assert_eq!(
            service::parse_config(&on_demand).unwrap().start_type,
            Some(3)
        );
        let loaded = query_driver_off().replace("1  STOPPED", "4  RUNNING");
        assert_eq!(service::parse_state(&loaded), Some(SERVICE_RUNNING));
        for (why, mock) in [
            (
                "never asked to start, as captured before the start: 1077",
                waits_for_driver(1077, qc_driver_off(), query_driver_off()),
            ),
            (
                "stopped with another error",
                waits_for_driver(31, qc_driver_off(), query_driver_off()),
            ),
            (
                "the driver starts on demand",
                waits_for_driver(1068, on_demand, query_driver_off()),
            ),
            (
                "the driver is loaded, switched off only for the next start",
                waits_for_driver(1068, qc_driver_off(), loaded),
            ),
            (
                "sc does not answer for the driver",
                waits_for_driver(1068, qc_driver_off(), String::new()),
            ),
        ] {
            let found = failing(&mock, &[]).await.unwrap();
            assert_eq!(found, Failing::default(), "{why}");
        }
    }

    /// A device of the driver that reports a problem is the cause, and has
    /// the chain; the driver's start type is not blamed next to it.
    #[tokio::test]
    async fn a_device_with_a_problem_comes_before_the_switched_off_driver() {
        let cd = vec![device(22, r"SCSI\CDROM\1", "cdfs")];
        let found = failing(&waits_for_a_switched_off_driver(), &cd)
            .await
            .unwrap();
        assert!(found.drivers_off.is_empty(), "{found:?}");
        assert_eq!(found.chains.len(), 1);
        assert_eq!(found.chains[0].driver, "cdfs");
    }

    /// Two services above the driver: one chain, from the top.
    #[tokio::test]
    async fn a_longer_chain_to_a_switched_off_driver_stands_for_its_end() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "query type= service",
            CmdOutput::ok(sc_query_list(&[
                ("Above", "Above", 1, 1068),
                ("W32Time", "Windows-Zeitgeber", 1, 1068),
            ])),
        );
        mock.add_response("qc Above", depends_on("Above", &["W32Time"]));
        let below = waits_for_a_switched_off_driver();
        for command in ["qc W32Time", "qc cdfs", "query cdfs"] {
            let args: Vec<&str> = command.split(' ').collect();
            let out = below
                .run("sc.exe", &args, Duration::from_secs(1))
                .await
                .unwrap();
            mock.add_response(command, out);
        }
        let found = failing(&mock, &[]).await.unwrap();
        assert_eq!(found.drivers_off.len(), 1, "{found:?}");
        let names: Vec<&str> = found.drivers_off[0]
            .services
            .iter()
            .map(|l| l.name.as_str())
            .collect();
        assert_eq!(names, ["Above", "W32Time"]);
    }

    /// What an installer waits for: the chains from that service, whatever
    /// its own exit code says.
    #[tokio::test]
    async fn the_chain_from_a_service_something_waits_for() {
        let chains = chains_from_service(&dev_pc_services(31), &devices(22), "cmservice")
            .await
            .unwrap();
        assert_eq!(chains.len(), 1, "{chains:?}");
        assert_eq!(chains[0].head().name, "CmService");

        let running = listing(&[("CmService", "Container-Manager-Dienst", 4, 0)]);
        for name in ["CmService", "NoSuchService"] {
            let none = chains_from_service(&running, &devices(22), name)
                .await
                .unwrap();
            assert!(none.is_empty(), "{name}");
        }
    }
}
