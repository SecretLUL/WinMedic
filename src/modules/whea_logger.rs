use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::crash_timeline::logged_at;
use crate::modules::event_log::{
    last_passed_memory_test, memory_test_finding, schedule_memory_test,
};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::debug_log::DebugTrace;
use crate::utils::event_xml::{EventRecord, parse_events, read_events, system_log_query};
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

/// Parsed WHEA hardware event record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WheaEventRecord {
    pub event_id: u32,
    pub level: Option<String>,
    /// When it was logged.
    pub logged: Option<DateTime<Utc>>,
    pub error_source: Option<String>,
    pub error_type: Option<String>,
    pub apic_id: Option<u32>,
    pub mca_bank: Option<u32>,
    pub mci_stat: Option<String>,
    pub mci_addr: Option<String>,
    pub mci_misc: Option<String>,
    pub bus_dev_func: Option<String>,
    pub primary_device_name: Option<String>,
    pub raw_snippet: String,
}

pub struct WheaLoggerModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
}

impl WheaLoggerModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self { config, runner }
    }

    /// How many hours back the `wevtutil` query looks: the event log
    /// setting, but at least a week. WHEA faults are rare, and this is the
    /// only check that reads them.
    fn window_hours(&self) -> u32 {
        self.config.max_event_log_hours.max(MIN_WINDOW_HOURS)
    }

    fn lookback_ms(&self) -> u64 {
        u64::from(self.window_hours()) * 3_600_000
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
                    module_id: "whea_logger".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for WheaLoggerModule {
    fn id(&self) -> &'static str {
        "whea_logger"
    }

    fn name(&self) -> &'static str {
        "WHEA Hardware Error Logger"
    }

    fn description(&self) -> &'static str {
        "Monitors Windows Hardware Error Architecture (WHEA) events: CPU cache hierarchy, PCIe root ports, APIC IDs, and memory bus errors"
    }

    fn icon(&self) -> &'static str {
        "[WHEA]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();
        let dbg = DebugTrace::scan(self.id(), progress_tx.clone(), self.config.verbose_logging);

        // Step 1: Initialise WHEA Query
        let window_hours = self.window_hours();
        Self::send_progress(
            &progress_tx,
            15,
            &format!(
                "Scanning WHEA hardware errors over the last {}h...",
                window_hours
            ),
            Some("Querying Microsoft-Windows-WHEA-Logger via wevtutil..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let query = system_log_query(
            &format!("Provider[@Name='{WHEA_PROVIDER}']"),
            self.lookback_ms(),
            50,
        );
        let query: Vec<&str> = query.iter().map(String::as_str).collect();

        dbg.section("WHEA-Logger Query").await;
        dbg.kv("provider", WHEA_PROVIDER).await;
        dbg.kv("lookback_hours", window_hours.to_string()).await;

        let whea_out = dbg
            .run(
                &self.runner,
                "wevtutil.exe",
                &query,
                Duration::from_secs(15),
            )
            .await;

        // Step 2: Parse WHEA Events
        Self::send_progress(
            &progress_tx,
            50,
            "Analysing WHEA events & hardware fault localization...",
            Some("Parsing APIC-IDs, MCA Banks, and PCIe Root Port addresses..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        // A refused query is not a clean bill of health (see `read_events`).
        let parsed_events = match read_events(whea_out) {
            Ok(events) => whea_records(events),
            Err(err) => {
                dbg.warn(format!("Failed to query WHEA event logs: {}", err))
                    .await;
                return Err(err);
            }
        };
        dbg.kv("total_whea_events", parsed_events.len().to_string())
            .await;

        if parsed_events.is_empty() {
            Self::send_progress(
                &progress_tx,
                90,
                "WHEA hardware telemetry healthy",
                Some("No WHEA CPU, memory, or PCIe bus errors recorded."),
            )
            .await;
            Self::send_progress(&progress_tx, 100, "WHEA analysis complete", None).await;
            return Ok(issues);
        }

        // Step 3: Categorise and Triangulate Errors
        Self::send_progress(
            &progress_tx,
            80,
            "Classifying CPU, PCIe and memory faults...",
            Some("Triangulating core, bank and bus mappings..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        // A passed memory test answers the findings that offer one; it is
        // read only when there is such a finding.
        let memory_test = if parsed_events
            .iter()
            .any(|e| matches!(e.event_id, 18 | 19 | 47))
        {
            last_passed_memory_test(&*self.runner).await
        } else {
            None
        };

        // 1. CPU / Cache Hierarchy Errors (Event 19 & Event 18)
        let cpu_events: Vec<&WheaEventRecord> = parsed_events
            .iter()
            .filter(|e| e.event_id == 19 || e.event_id == 18)
            .collect();

        if !cpu_events.is_empty() {
            let has_fatal = cpu_events.iter().any(|e| e.event_id == 18);
            let count = cpu_events.len();

            let mut apic_ids = BTreeMap::new();
            let mut mca_banks = HashSet::new();
            let mut fault_addrs = HashSet::new();
            let mut mci_stats = HashSet::new();

            for e in &cpu_events {
                if let Some(apic) = e.apic_id {
                    *apic_ids.entry(apic).or_insert(0usize) += 1;
                }
                if let Some(bank) = e.mca_bank {
                    mca_banks.insert(bank);
                }
                if let Some(ref addr) = e.mci_addr
                    && addr != "0x0"
                    && addr != "0"
                {
                    fault_addrs.insert(addr.clone());
                }
                if let Some(ref stat) = e.mci_stat {
                    mci_stats.insert(stat.clone());
                }
            }

            let apic_summary = if !apic_ids.is_empty() {
                apic_ids
                    .iter()
                    .map(|(apic, cnt)| {
                        let core_est = apic / 2;
                        format!("APIC ID {} (Core ~#{}, {} events)", apic, core_est, cnt)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                "Unknown Core".to_string()
            };

            let banks_summary = if !mca_banks.is_empty() {
                let mut b_list: Vec<_> = mca_banks.into_iter().collect();
                b_list.sort_unstable();
                b_list
                    .into_iter()
                    .map(|b| format!("MCABank {}", b))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                "N/A".to_string()
            };

            let addrs_summary = if !fault_addrs.is_empty() {
                format!(
                    "Fault Addresses: {}",
                    fault_addrs
                        .into_iter()
                        .take(4)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                String::new()
            };

            let severity = if has_fatal || count >= 10 {
                Severity::Critical
            } else {
                Severity::Warning
            };

            let mut tech_lines = vec![
                format!(
                    "Detected {} WHEA CPU/Cache Hierarchy error events within {}h window.",
                    count, window_hours
                ),
                format!("Affected Hardware: {}", apic_summary),
                format!("MCA Banks: {}", banks_summary),
            ];
            if !addrs_summary.is_empty() {
                tech_lines.push(addrs_summary);
            }
            if !mci_stats.is_empty() {
                tech_lines.push(format!(
                    "MciStat Signature(s): {}",
                    mci_stats.into_iter().take(3).collect::<Vec<_>>().join(", ")
                ));
            }

            let sample_snippet = cpu_events
                .iter()
                .take(2)
                .map(|e| e.raw_snippet.as_str())
                .collect::<Vec<_>>()
                .join("\n---\n");

            issues.push(memory_test_finding(Issue::new(
                "whea_cpu_cache_error",
                self.id(),
                format!("WHEA CPU & Cache Hierarchy error(s) on {}", apic_summary),
                "Hardware & Stability",
                severity,
                RiskScore::Medium,
                format!(
                    "Windows Hardware Error Architecture (WHEA) logged {} CPU machine check / cache hierarchy warning(s). Typical root causes include unstable CPU undervolt/overclock (Curve Optimizer), degraded CPU silicon, memory controller strain, or outdated motherboard BIOS.",
                    count
                ),
                format!("{}\n\nEvent Log Excerpt:\n{}", tech_lines.join("\n"), sample_snippet),
                "Schedule Windows Memory Diagnostic (mdsched.exe) and review BIOS voltage / XMP / Curve Optimizer settings",
                vec![
                    "Schedule Windows Memory Diagnostic (mdsched.exe) for the next reboot".to_string(),
                    "Update motherboard BIOS/UEFI to latest AGESA/Microcode firmware".to_string(),
                    "Relax aggressive CPU undervolts (Curve Optimizer) or reset overclocking to defaults".to_string(),
                ],
            ), memory_test, cpu_events.iter().map(|e| e.logged)));
        }

        // 2. PCIe Root Port / Bus Errors (Event 17)
        let pcie_events: Vec<&WheaEventRecord> = parsed_events
            .iter()
            .filter(|e| e.event_id == 17 || e.bus_dev_func.is_some())
            .collect();

        if !pcie_events.is_empty() {
            let count = pcie_events.len();
            let mut devices = HashSet::new();
            let mut bdfs = HashSet::new();

            for e in &pcie_events {
                if let Some(ref dev) = e.primary_device_name {
                    devices.insert(dev.clone());
                }
                if let Some(ref bdf) = e.bus_dev_func {
                    bdfs.insert(bdf.clone());
                }
            }

            let bdf_str = if !bdfs.is_empty() {
                bdfs.into_iter().collect::<Vec<_>>().join(", ")
            } else {
                "PCIe Root Port".to_string()
            };

            let dev_str = if !devices.is_empty() {
                devices.into_iter().take(3).collect::<Vec<_>>().join("; ")
            } else {
                "Generic PCI Express Device".to_string()
            };

            let severity = if count >= 20 {
                Severity::Critical
            } else {
                Severity::Warning
            };

            let sample_snippet = pcie_events
                .iter()
                .take(2)
                .map(|e| e.raw_snippet.as_str())
                .collect::<Vec<_>>()
                .join("\n---\n");

            let mut issue = Issue::new(
                "whea_pcie_bus_error",
                self.id(),
                format!("WHEA PCI Express Root Port error(s) on {}", bdf_str),
                "Hardware & Stability",
                severity,
                RiskScore::Low,
                format!(
                    "{} corrected PCIe hardware error(s) logged by WHEA. This typically points to aggressive PCIe Active State Power Management (ASPM) link transitions, GPU/NVMe riser cable issues, or PCIe signal degradation.",
                    count
                ),
                format!(
                    "Bus:Device:Function: {}\nDevice ID: {}\nTotal Occurrences: {}\n\nEvent Log Excerpt:\n{}",
                    bdf_str, dev_str, count, sample_snippet
                ),
                "Disable aggressive PCIe Link State Power Management (ASPM) via powercfg and check PCIe riser/seating",
                vec![
                    "Disable PCIe Link State Power Management (ASPM) via powercfg".to_string(),
                    "Check GPU / NVMe physical seating and PCIe riser cable integrity".to_string(),
                    "Update motherboard chipset and NVMe / GPU driver firmware".to_string(),
                ],
            );

            // The events stay in the window for a week after ASPM is off.
            // With it off already the repair has nothing left to change, so
            // the finding is advice; offered again, it reported a repair that
            // changed nothing on every run. When powercfg cannot tell, the
            // repair stays on offer and reads the setting itself.
            match self.aspm_indices().await {
                Ok((0, 0)) => {
                    issue.description = format!(
                        "{count} corrected PCIe hardware error(s) logged by WHEA. PCIe Link State Power Management (ASPM) is already off on mains and battery. If it was switched off after these errors, see whether new ones are logged; if they keep coming, the device, its slot or riser cable, or its firmware is the likelier cause."
                    );
                    issue.technical_details = format!(
                        "ASPM: off on mains and battery\n{}",
                        issue.technical_details
                    );
                    issue.recommended_fix =
                        "Check the device's seating and riser cable, and update its firmware"
                            .to_string();
                    issue.fix_steps.remove(0);
                    issue = issue.with_advice_only();
                }
                Ok(_) => {}
                Err(err) => dbg.warn(format!("PCIe ASPM not read: {err}")).await,
            }
            issues.push(issue);
        }

        // 3. Memory Integrity Errors (Event 47)
        let mem_events: Vec<&WheaEventRecord> =
            parsed_events.iter().filter(|e| e.event_id == 47).collect();

        if !mem_events.is_empty() {
            let count = mem_events.len();
            let mut addrs = HashSet::new();

            for e in &mem_events {
                if let Some(ref addr) = e.mci_addr {
                    addrs.insert(addr.clone());
                }
            }

            let sample_snippet = mem_events
                .iter()
                .take(2)
                .map(|e| e.raw_snippet.as_str())
                .collect::<Vec<_>>()
                .join("\n---\n");

            issues.push(memory_test_finding(Issue::new(
                "whea_memory_error",
                self.id(),
                format!("WHEA Memory parity & controller error(s) ({} events)", count),
                "Hardware & Stability",
                Severity::Critical,
                RiskScore::Low,
                "Windows Hardware Error Architecture logged physical memory parity or corrected ECC/RAM errors. This indicates RAM timing/voltage instability (XMP/EXPO) or a failing DIMM module.",
                format!("Error count: {}\nAddresses: {}\n\n{}", count, addrs.into_iter().collect::<Vec<_>>().join(", "), sample_snippet),
                "Schedule Windows Memory Diagnostic (mdsched.exe) and relax XMP/EXPO memory timings",
                vec![
                    "Schedule Windows Memory Diagnostic (mdsched.exe) for the next reboot".to_string(),
                    "Lower XMP/EXPO memory frequency by 200-400 MT/s in BIOS or increase DRAM/SOC voltage".to_string(),
                ],
            ), memory_test, mem_events.iter().map(|e| e.logged)));
        }

        // 4. Fatal hardware errors (Event 1). In the provider's manifest event
        // 1 is the generic fatal error: its only data are `Length` and
        // `RawData`, the error record, so nothing in it names a component.
        // The specific events (18 for a processor, 47 for memory) are separate.
        // The id is older than this reading and kept, so earlier reports and
        // the history still match.
        let fatal_events: Vec<&WheaEventRecord> =
            parsed_events.iter().filter(|e| e.event_id == 1).collect();

        if !fatal_events.is_empty() {
            let count = fatal_events.len();
            let sample_snippet = fatal_events
                .iter()
                .take(2)
                .map(|e| e.raw_snippet.as_str())
                .collect::<Vec<_>>()
                .join("\n---\n");

            issues.push(Issue::new(
                "whea_storage_platform_error",
                self.id(),
                format!("WHEA fatal hardware error(s) ({} events)", count),
                "Hardware & Stability",
                Severity::Critical,
                RiskScore::Medium,
                "Windows logged a fatal hardware error. The event holds only the raw error record, so it does not say which component failed. It usually comes with a WHEA_UNCORRECTABLE_ERROR blue screen; unstable CPU or memory settings are a common cause, a failing component another.",
                format!("Total Events: {}\n\nEvent Log Excerpt:\n{}", count, sample_snippet),
                "Run the PC at BIOS defaults and see whether the error comes back",
                vec![
                    "Reset CPU and memory overclocking, undervolting and XMP/EXPO to the BIOS defaults".to_string(),
                    "Update the motherboard BIOS/UEFI".to_string(),
                    "Check CPU temperatures and the power supply under load".to_string(),
                ],
            ).with_advice_only());
        }

        Self::send_progress(&progress_tx, 100, "WHEA hardware diagnosis complete", None).await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        match issue_id {
            "whea_pcie_bus_error" => {
                if let Some(ref tx) = progress_tx {
                    let _ = tx
                        .send(FixProgress {
                            issue_id: issue_id.to_string(),
                            step_description:
                                "Switching PCIe Link State Power Management (ASPM) off..."
                                    .to_string(),
                            is_success: true,
                            error: None,
                            console_line: Some(format!("powercfg {}", ASPM_OFF_AC.join(" "))),
                        })
                        .await;
                }
                self.switch_aspm_off().await
            }
            "whea_cpu_cache_error" | "whea_memory_error" => {
                schedule_memory_test(&*self.runner).await
            }
            // The fatal-error finding is advice: a repair run never asks.
            _ => Err(format!("Unknown WHEA issue id: {}", issue_id)),
        }
    }
}

/// `powercfg` arguments that switch PCIe ASPM off on mains and on battery.
/// `ASPM` is the setting's alias; without it powercfg has three arguments
/// instead of four and exits with "Invalid parameters".
const ASPM_OFF_AC: [&str; 5] = [
    "/setacvalueindex",
    "SCHEME_CURRENT",
    "SUB_PCIEXPRESS",
    "ASPM",
    "0",
];
const ASPM_OFF_DC: [&str; 5] = [
    "/setdcvalueindex",
    "SCHEME_CURRENT",
    "SUB_PCIEXPRESS",
    "ASPM",
    "0",
];
const ASPM_QUERY: [&str; 4] = ["/query", "SCHEME_CURRENT", "SUB_PCIEXPRESS", "ASPM"];

/// The AC and DC index `powercfg /query` prints for one setting.
///
/// The labels are translated ("Index der aktuellen Wechselstromeinstellung");
/// the two indices are the only `0x` numbers of an option setting, AC first.
pub fn powercfg_indices(output: &str) -> Option<(u32, u32)> {
    let values: Vec<u32> = output
        .lines()
        .filter_map(|line| {
            let hex = line.trim().rsplit(' ').next()?.strip_prefix("0x")?;
            u32::from_str_radix(hex, 16).ok()
        })
        .collect();
    match values[..] {
        [.., ac, dc] => Some((ac, dc)),
        _ => None,
    }
}

impl WheaLoggerModule {
    async fn aspm_indices(&self) -> Result<(u32, u32), String> {
        let out = self
            .runner
            .run("powercfg.exe", &ASPM_QUERY, Duration::from_secs(10))
            .await?;
        if !out.success {
            return Err(format!(
                "powercfg /query failed (exit code {:?}): {}",
                out.exit_code,
                out.stderr.trim()
            ));
        }
        powercfg_indices(&out.stdout)
            .ok_or_else(|| "powercfg /query printed no ASPM setting".to_string())
    }

    /// Switch ASPM off, then read the setting back. The message names the
    /// values it had, so they can be set again.
    async fn switch_aspm_off(&self) -> Result<String, String> {
        let (ac, dc) = self.aspm_indices().await?;
        // Off since the scan: nothing to change is no repair, and counted as
        // one it was recorded as a success on every run.
        if (ac, dc) == (0, 0) {
            return Err(
                "PCIe Link State Power Management is already off on mains and battery; nothing was changed."
                    .to_string(),
            );
        }
        for args in [
            &ASPM_OFF_AC[..],
            &ASPM_OFF_DC[..],
            &["/setactive", "SCHEME_CURRENT"],
        ] {
            let out = self
                .runner
                .run("powercfg.exe", args, Duration::from_secs(10))
                .await?;
            if !out.success {
                return Err(format!(
                    "powercfg {} failed (exit code {:?}): {}",
                    args.join(" "),
                    out.exit_code,
                    [out.stdout.trim(), out.stderr.trim()].join(" ").trim()
                ));
            }
        }
        match self.aspm_indices().await? {
            (0, 0) => Ok(format!(
                "PCIe Link State Power Management is off; on battery that costs a little runtime. It was {ac} on mains and {dc} on battery: `powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM {ac}` and `/setdcvalueindex ... {dc}` put it back."
            )),
            (ac_now, dc_now) => Err(format!(
                "powercfg ran, but ASPM still reads {ac_now} on mains and {dc_now} on battery."
            )),
        }
    }
}

const WHEA_PROVIDER: &str = "Microsoft-Windows-WHEA-Logger";

/// A week, see [`WheaLoggerModule::window_hours`].
const MIN_WINDOW_HOURS: u32 = 7 * 24;

/// Parses `wevtutil /f:xml` output into `WheaEventRecord`s.
///
/// Everything is read from the event's named `EventData` fields. The text
/// rendering this used to parse labels them in the display language
/// ("Fehlerquelle", "Prozessor-APIC-ID"), which no parser can keep up with,
/// and its attempt at XML looked for `Name="..."` in double quotes while
/// `wevtutil` writes single ones, so that branch never matched either.
pub fn parse_whea_output(raw_output: &str) -> Vec<WheaEventRecord> {
    whea_records(parse_events(raw_output))
}

/// The WHEA-Logger events among `events`, as `WheaEventRecord`s.
pub fn whea_records(events: Vec<EventRecord>) -> Vec<WheaEventRecord> {
    events
        .into_iter()
        .filter(|event| event.provider == WHEA_PROVIDER)
        .map(|event| {
            let text = |name: &str| event.data(name).map(str::to_string);
            let number = |name: &str| event.data(name).and_then(parse_number);
            let bus_dev_func = match (
                event.data("Bus"),
                event.data("Device"),
                event.data("Function"),
            ) {
                (Some(bus), Some(device), Some(function)) => {
                    Some(format!("{bus}:{device}:{function}"))
                }
                _ => None,
            };
            let primary_device_name = text("PrimaryDeviceName").or_else(|| {
                let vendor = event.data("VendorID").and_then(parse_number)?;
                let device = event.data("DeviceID").and_then(parse_number)?;
                Some(format!(r"PCI\VEN_{vendor:04X}&DEV_{device:04X}"))
            });
            WheaEventRecord {
                event_id: event.event_id,
                level: event.level.map(|level| level_name(level).to_string()),
                logged: logged_at(&event),
                error_source: text("ErrorSource"),
                error_type: text("ErrorType"),
                apic_id: number("ApicId"),
                mca_bank: number("MCABank"),
                mci_stat: text("MciStat"),
                // Memory events (47) carry a physical address instead.
                mci_addr: text("MciAddr").or_else(|| text("PhysicalAddress")),
                mci_misc: text("MciMisc"),
                bus_dev_func,
                primary_device_name,
                raw_snippet: event.details(),
            }
        })
        .collect()
}

/// `0x1c` or `28`.
fn parse_number(value: &str) -> Option<u32> {
    let value = value.trim();
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => value.parse().ok(),
    }
}

fn level_name(level: u8) -> &'static str {
    match level {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        _ => "Verbose",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::event_log::test_support::memory_test_event;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    // Built in the exact shape wevtutil prints, with the EventData field names
    // WHEA-Logger uses; the machine the other fixtures come from has never
    // logged a WHEA event. See tests/fixtures/README.md.
    const WHEA_EVENTS: &str = include_str!("../../tests/fixtures/events/whea_constructed.xml");
    const SYSTEM_ERRORS: &str = include_str!("../../tests/fixtures/events/system_errors.xml");

    fn whea_event(id: u32, level: u8, data: &[(&str, &str)]) -> String {
        let data: String = data
            .iter()
            .map(|(name, value)| format!("<Data Name='{name}'>{value}</Data>"))
            .collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WHEA-Logger' Guid='{{c26c4f3c-3f66-4e99-8f8a-39405cfed220}}'/><EventID>{id}</EventID><Level>{level}</Level><TimeCreated SystemTime='2026-08-20T10:15:30.0000000Z'/></System><EventData>{data}</EventData></Event>"
        )
    }

    async fn scan_with(output: String) -> Vec<Issue> {
        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil.exe", CmdOutput::ok(output));
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        module.scan(None).await.expect("scan failed")
    }

    #[test]
    fn test_parse_whea_event_19_cache_hierarchy() {
        let events = parse_whea_output(WHEA_EVENTS);
        assert_eq!(events.len(), 4);
        let e = &events[0];
        assert_eq!(e.event_id, 19);
        assert_eq!(e.level.as_deref(), Some("Warning"));
        assert_eq!(e.error_source.as_deref(), Some("1"));
        assert_eq!(e.apic_id, Some(4));
        assert_eq!(e.mca_bank, Some(1));
        assert_eq!(e.mci_stat.as_deref(), Some("0x9020000f0120100e"));
        assert_eq!(e.mci_addr.as_deref(), Some("0x7fe1c0"));
        assert!(!e.raw_snippet.contains("RawData"));
    }

    #[test]
    fn test_parse_whea_event_17_pcie_root_port() {
        let events = parse_whea_output(WHEA_EVENTS);
        let e = events.iter().find(|e| e.event_id == 17).expect("event 17");
        assert_eq!(e.bus_dev_func.as_deref(), Some("0x0:0x1c:0x5"));
        assert_eq!(
            e.primary_device_name.as_deref(),
            Some(r"PCI\VEN_8086&DEV_A33D&SUBSYS_86941043&REV_F0")
        );
    }

    #[test]
    fn test_pcie_device_falls_back_to_vendor_and_device_ids() {
        let xml = whea_event(
            17,
            3,
            &[
                ("Bus", "0x2"),
                ("Device", "0x0"),
                ("Function", "0x0"),
                ("VendorID", "0x10ec"),
                ("DeviceID", "0x8168"),
            ],
        );
        let events = parse_whea_output(&xml);
        assert_eq!(
            events[0].primary_device_name.as_deref(),
            Some(r"PCI\VEN_10EC&DEV_8168")
        );
    }

    #[test]
    fn test_memory_event_reports_its_physical_address() {
        let events = parse_whea_output(WHEA_EVENTS);
        let e = events.iter().find(|e| e.event_id == 47).expect("event 47");
        assert_eq!(e.mci_addr.as_deref(), Some("0x1f7a3c000"));
    }

    #[test]
    fn test_parse_whea_xml_with_double_quotes_and_line_breaks() {
        let xml_sample = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-WHEA-Logger" />
    <EventID>19</EventID>
    <Level>3</Level>
  </System>
  <EventData>
    <Data Name="ApicId">6</Data>
    <Data Name="MCABank">5</Data>
    <Data Name="MciStat">0xbaa000000002010b</Data>
    <Data Name="MciAddr">0x80001000</Data>
  </EventData>
</Event>"#;

        let events = parse_whea_output(xml_sample);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_id, 19);
        assert_eq!(e.apic_id, Some(6));
        assert_eq!(e.mca_bank, Some(5));
        assert_eq!(e.mci_addr.as_deref(), Some("0x80001000"));
    }

    #[test]
    fn test_events_from_other_providers_are_ignored() {
        assert!(parse_whea_output(SYSTEM_ERRORS).is_empty());
        assert!(parse_whea_output("").is_empty());
    }

    #[tokio::test]
    async fn test_scan_detects_cpu_cache_hierarchy_issue() {
        let issues = scan_with(whea_event(
            19,
            3,
            &[
                ("ApicId", "8"),
                ("MCABank", "3"),
                ("MciStat", "0xbaa000000002010b"),
                ("MciAddr", "0x107e54280"),
            ],
        ))
        .await;

        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.id, "whea_cpu_cache_error");
        assert_eq!(issue.category, "Hardware & Stability");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.title.contains("APIC ID 8"));
        assert!(issue.technical_details.contains("MCABank 3"));
        assert!(issue.technical_details.contains("0x107e54280"));
    }

    #[tokio::test]
    async fn test_scan_detects_pcie_root_port_issue() {
        let issues = scan_with(pcie_event()).await;

        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.id, "whea_pcie_bus_error");
        assert_eq!(issue.category, "Hardware & Stability");
        assert!(issue.title.contains("0x0:0x1:0x1"));
        // powercfg did not answer: the repair stays on offer and reads
        // ASPM itself.
        assert!(issue.will_repair() && !issue.advice_only);
    }

    fn pcie_event() -> String {
        whea_event(
            17,
            3,
            &[
                ("Bus", "0x0"),
                ("Device", "0x1"),
                ("Function", "0x1"),
                ("PrimaryDeviceName", r"PCI\VEN_1022&amp;DEV_1453"),
            ],
        )
    }

    /// The module over a PCIe event and what `powercfg /query` prints for ASPM.
    fn pcie_module(aspm: String) -> (WheaLoggerModule, MockCommandRunner) {
        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil.exe", CmdOutput::ok(pcie_event()));
        mock.add_response("/query", CmdOutput::ok(aspm));
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        (module, mock)
    }

    /// The events stay for a week after ASPM was switched off. With it off,
    /// the finding is advice, and a repair that finds it off changed nothing
    /// and says so instead of reporting a success.
    #[tokio::test]
    async fn pcie_errors_with_aspm_already_off_are_advice() {
        let (module, mock) = pcie_module(aspm_off_query());

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "whea_pcie_bus_error")
            .expect("the errors are still reported");
        assert!(issue.advice_only && !issue.will_repair());
        assert!(
            issue.description.contains("already off"),
            "{}",
            issue.description
        );
        assert!(!issue.fix_steps.iter().any(|s| s.contains("ASPM")));

        let err = module.fix("whea_pcie_bus_error", None).await.unwrap_err();
        assert!(err.contains("nothing was changed"), "{err}");
        assert!(!mock.executed().iter().any(|c| c.contains("/set")));
    }

    #[tokio::test]
    async fn pcie_errors_with_aspm_on_offer_to_switch_it_off() {
        let (module, _) = pcie_module(real_aspm_query());

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "whea_pcie_bus_error")
            .unwrap();
        assert!(issue.will_repair() && !issue.advice_only);
        assert!(issue.fix_steps[0].contains("ASPM"));
    }

    #[tokio::test]
    async fn test_scan_of_mixed_events_raises_one_finding_per_subsystem() {
        let issues = scan_with(WHEA_EVENTS.to_string()).await;
        let ids: Vec<&str> = issues.iter().map(|i| i.id.as_str()).collect();
        assert!(ids.contains(&"whea_cpu_cache_error"), "{ids:?}");
        assert!(ids.contains(&"whea_pcie_bus_error"), "{ids:?}");
        assert!(ids.contains(&"whea_memory_error"), "{ids:?}");
        assert_eq!(issues.len(), 3);
    }

    #[tokio::test]
    async fn test_scan_clean_when_no_whea_events() {
        assert!(scan_with(String::new()).await.is_empty());
        // What wevtutil prints when it refuses a query: no event in it.
        assert!(
            scan_with("Falscher Parameter.".to_string())
                .await
                .is_empty()
        );
    }

    /// `powercfg /query SCHEME_CURRENT SUB_PCIEXPRESS ASPM` on a German
    /// Windows 11: 1 on mains, 2 on battery.
    fn real_aspm_query() -> String {
        crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/powercfg_query_aspm_de.bin"
        ))
    }

    /// The same after both were set to 0.
    fn aspm_off_query() -> String {
        real_aspm_query()
            .replace("0x00000001", "0x00000000")
            .replace("0x00000002", "0x00000000")
    }

    #[test]
    fn the_aspm_indices_are_read_whatever_the_labels_say() {
        assert_eq!(powercfg_indices(&real_aspm_query()), Some((1, 2)));
        assert_eq!(powercfg_indices(&aspm_off_query()), Some((0, 0)));
        assert_eq!(powercfg_indices(""), None);
    }

    fn aspm_mock(set: CmdOutput, after: String) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("/query", CmdOutput::ok(real_aspm_query()));
        mock.add_response("powercfg.exe /set", set);
        mock.add_response_after("/setactive", "/query", CmdOutput::ok(after));
        mock
    }

    #[tokio::test]
    async fn aspm_is_switched_off_and_read_back() {
        let mock = aspm_mock(CmdOutput::ok(""), aspm_off_query());
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let msg = module.fix("whea_pcie_bus_error", None).await.unwrap();
        assert!(msg.contains("It was 1 on mains and 2 on battery"), "{msg}");

        let exec = mock.executed();
        assert!(exec.contains(
            &"powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0".to_string()
        ));
        assert!(exec.contains(
            &"powercfg.exe /setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0".to_string()
        ));
    }

    /// What powercfg answered to the command without `ASPM` that used to
    /// count as a repair.
    #[tokio::test]
    async fn a_refused_powercfg_is_a_failure() {
        let refused = crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/powercfg_setacvalueindex_missing_setting_de.bin"
        ));
        let mock = aspm_mock(CmdOutput::with_output(1, "", refused), aspm_off_query());
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let err = module.fix("whea_pcie_bus_error", None).await.unwrap_err();
        assert!(err.contains("exit code Some(1)"), "{err}");
    }

    #[tokio::test]
    async fn aspm_that_stays_on_is_a_failure() {
        let mock = aspm_mock(CmdOutput::ok(""), real_aspm_query());
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let err = module.fix("whea_pcie_bus_error", None).await.unwrap_err();
        assert!(
            err.contains("still reads 1 on mains and 2 on battery"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_scan_detects_fatal_event_18_as_critical() {
        let issues = scan_with(whea_event(
            18,
            2,
            &[
                ("ApicId", "0"),
                ("MCABank", "22"),
                ("MciStat", "0xbaa000000002010b"),
                ("MciAddr", "0x0"),
                ("MciMisc", "0xd0130fff00000000"),
            ],
        ))
        .await;

        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.id, "whea_cpu_cache_error");
        assert_eq!(issue.severity, Severity::Critical);
        assert_eq!(issue.risk_score, RiskScore::High);
        assert!(issue.requires_reboot && !issue.is_selected);
        assert!(issue.title.contains("APIC ID 0"));
        assert!(issue.technical_details.contains("MCABank 22"));
    }

    #[tokio::test]
    async fn test_scan_detects_memory_event_47() {
        let issues = scan_with(whea_event(47, 3, &[("PhysicalAddress", "0x1f4c8000")])).await;

        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.id, "whea_memory_error");
        assert_eq!(issue.severity, Severity::Critical);
        assert!(issue.technical_details.contains("0x1f4c8000"));
    }

    /// WHEA events 19 and 47 of 2026-08-20 and a memory test logged at
    /// `test_logged`.
    async fn scan_with_memory_test(id: u32, test_logged: &str) -> Vec<Issue> {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "MemoryDiagnostics",
            CmdOutput::ok(memory_test_event(id, test_logged)),
        );
        let events = whea_event(19, 3, &[("ApicId", "8"), ("MCABank", "3")])
            + &whea_event(47, 3, &[("PhysicalAddress", "0x1f4c8000")]);
        mock.add_response("wevtutil.exe", CmdOutput::ok(events));
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        module.scan(None).await.expect("scan failed")
    }

    /// A WHEA event 47 and a later Windows Memory Diagnostic that found no
    /// errors: the test has been run, so it is not offered again. The BIOS
    /// steps stay, since the test misses faults that come and go.
    #[tokio::test]
    async fn a_memory_test_passed_after_the_errors_is_not_offered_again() {
        let issues = scan_with_memory_test(1201, "2026-09-20T06:12:03.0000000Z").await;
        for id in ["whea_memory_error", "whea_cpu_cache_error"] {
            let issue = issues.iter().find(|i| i.id == id).expect(id);
            assert!(issue.advice_only && !issue.will_repair(), "{id}");
            assert!(!issue.requires_reboot, "{id}");
            assert!(
                issue
                    .recommended_fix
                    .contains("Windows Memory Diagnostic found no errors on 2026-09-"),
                "{}",
                issue.recommended_fix
            );
            assert!(
                !issue
                    .fix_steps
                    .iter()
                    .any(|s| s.contains("Memory Diagnostic"))
            );
            assert!(issue.fix_steps.iter().any(|s| s.contains("BIOS")), "{id}");
        }
    }

    /// A test from before the errors, or one that found errors, answers
    /// nothing: the test is offered as before.
    #[tokio::test]
    async fn an_older_or_failed_memory_test_leaves_the_test_on_offer() {
        for (id, logged) in [
            (1201, "2026-08-01T06:12:03.0000000Z"),
            (1202, "2026-09-20T06:12:03.0000000Z"),
        ] {
            let issues = scan_with_memory_test(id, logged).await;
            let issue = issues.iter().find(|i| i.id == "whea_memory_error").unwrap();
            assert!(!issue.advice_only && issue.requires_reboot, "{id} {logged}");
            assert!(issue.fix_steps[0].contains("Memory Diagnostic"));
        }
    }

    /// Event 1 as the provider's manifest defines it: `Length` and
    /// `RawData` (the error record), in the shape of `whea_constructed.xml`,
    /// whose first event carries the same two fields. Nothing in it names a
    /// component, so the finding names none either.
    #[tokio::test]
    async fn event_1_is_a_fatal_error_of_an_unknown_component() {
        let issues = scan_with(whea_event(
            1,
            2,
            &[
                ("Length", "928"),
                (
                    "RawData",
                    "435045521002FFFFFFFF03000200000002000000A0030000",
                ),
            ],
        ))
        .await;

        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.id, "whea_storage_platform_error");
        assert_eq!(issue.severity, Severity::Critical);
        assert!(
            issue.title.contains("fatal hardware error"),
            "{}",
            issue.title
        );
        assert!(
            issue.advice_only,
            "a hardware fault is not repaired in software"
        );
        let text = format!(
            "{} {} {} {}",
            issue.title,
            issue.description,
            issue.recommended_fix,
            issue.fix_steps.join(" ")
        )
        .to_lowercase();
        for blamed in ["storage", "storport", "nvme", "ssd", "chkdsk"] {
            assert!(!text.contains(blamed), "{blamed}: {text}");
        }
    }

    #[tokio::test]
    async fn a_memory_test_that_did_not_start_is_not_a_repair() {
        let mock = MockCommandRunner::new();
        mock.add_response("bcdedit.exe", CmdOutput::failed(1, ""));
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock));

        let res = module.fix("whea_memory_error", None).await;
        assert!(res.unwrap_err().contains("could not be scheduled"));
    }

    #[tokio::test]
    async fn test_fix_unknown_id_returns_error() {
        let mock = MockCommandRunner::new();
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let res = module.fix("nonexistent_id", None).await;

        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Unknown WHEA issue id"));
    }
}
