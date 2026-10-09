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

use crate::modules::devices::meaning;
use crate::utils::cmd::CommandRunner;
use crate::utils::pnp::PnpDevice;
use crate::utils::service::{
    self, ERROR_SERVICE_DEPENDENCY_FAIL, ERROR_SERVICE_NEVER_STARTED, SERVICE_RUNNING,
    SERVICE_STOPPED, ServiceConfig, ServiceStatus,
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
        let services: Vec<String> = self
            .services
            .iter()
            .map(|link| match link.exit_code {
                ERROR_SERVICE_DEPENDENCY_FAIL => format!("{} cannot start", link.label()),
                ERROR_SERVICE_NEVER_STARTED => format!("{} did not start", link.label()),
                0 => format!("{} is stopped", link.label()),
                code => format!("{} failed (exit code {code})", link.label()),
            })
            .collect();
        let problem = match self.device.problem {
            DEVICE_DISABLED => "is disabled".to_string(),
            code => format!("reports problem code {code}: {}", meaning(code)),
        };
        format!(
            "{} because the device '{device_name}' {problem}.",
            services.join(": ")
        )
    }

    /// The service the chain starts with.
    pub fn head(&self) -> &Link {
        &self.services[0]
    }

    /// The chain for technical details: each service with its exit code,
    /// the driver and the device.
    pub fn details(&self) -> String {
        let services: Vec<String> = self
            .services
            .iter()
            .map(|link| format!("{} (exit code {})", link.name, link.exit_code))
            .collect();
        format!(
            "Service chain: {} -> driver {} -> device {} (problem code {})",
            services.join(" -> "),
            self.driver,
            self.device.instance_id,
            self.device.problem
        )
    }
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

    /// Every chain from `start` down to a driver whose device has a problem.
    async fn chains_from(&mut self, start: Link) -> Vec<Chain> {
        let mut chains = Vec::new();
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
                for device in self.devices.iter().filter(|device| {
                    device.problem != 0 && device.service.eq_ignore_ascii_case(&dependency)
                }) {
                    chains.push(Chain {
                        services: path.clone(),
                        driver: dependency.clone(),
                        device: device.clone(),
                    });
                }
            }
        }
        chains
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

/// Every chain that explains a service which stopped with an error: stopped,
/// with an exit code other than 0 and 1077 ("never started"). A chain that
/// is the end of a longer one is left out, so CmService's chain through
/// HvHost stands for HvHost's own.
pub async fn failing_chains(
    runner: &dyn CommandRunner,
    devices: &[PnpDevice],
) -> Result<Vec<Chain>, String> {
    if !devices.iter().any(|device| device.problem != 0) {
        return Ok(Vec::new());
    }
    let statuses = service_statuses(runner).await?;
    let mut walker = Walker {
        runner,
        statuses: &statuses,
        devices,
        configs: HashMap::new(),
    };
    let mut chains = Vec::new();
    for status in statuses.iter().filter(|status| {
        status.state == SERVICE_STOPPED
            && !matches!(status.exit_code, 0 | ERROR_SERVICE_NEVER_STARTED)
    }) {
        chains.extend(walker.chains_from(Link::from_status(status)).await);
    }
    Ok(without_tails(chains))
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
    Ok(without_tails(
        walker.chains_from(Link::from_status(status)).await,
    ))
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
