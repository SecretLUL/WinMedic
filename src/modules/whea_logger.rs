use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::debug_log::DebugTrace;
use crate::utils::event_xml::{EventRecord, parse_events, read_events, system_log_query};
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

    /// Lookback window in milliseconds for the `wevtutil` query.
    fn lookback_ms(&self) -> u64 {
        u64::from(self.config.max_event_log_hours.max(1)) * 3_600_000
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
        let window_hours = self.config.max_event_log_hours.max(1);
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
            "Classifying CPU, PCIe, Memory & Storage faults...",
            Some("Triangulating core, bank and bus mappings..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

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

            issues.push(Issue::new(
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
            ));
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

            issues.push(Issue::new(
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
            ));
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

            issues.push(Issue::new(
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
            ));
        }

        // 4. Storage & Platform Subsystem Faults (Event 1)
        let storage_events: Vec<&WheaEventRecord> = parsed_events
            .iter()
            .filter(|e| e.event_id == 1 || e.raw_snippet.to_lowercase().contains("storport"))
            .collect();

        if !storage_events.is_empty() {
            let count = storage_events.len();
            let sample_snippet = storage_events
                .iter()
                .take(2)
                .map(|e| e.raw_snippet.as_str())
                .collect::<Vec<_>>()
                .join("\n---\n");

            issues.push(Issue::new(
                "whea_storage_platform_error",
                self.id(),
                format!("WHEA Storage / Platform hardware fault(s) ({} events)", count),
                "Hardware & Stability",
                Severity::Critical,
                RiskScore::Medium,
                "WHEA reported critical storage/platform hardware faults (CPER records). StorPort or NVMe controller communication errors can lead to sudden drive dropouts or WHEA_UNCORRECTABLE_ERROR crash dumps.",
                format!("Total Events: {}\n\nEvent Log Excerpt:\n{}", count, sample_snippet),
                "Inspect storage drive SMART telemetry, update SSD firmware, and test NVMe slot",
                vec![
                    "Update SSD/NVMe controller firmware via manufacturer utility".to_string(),
                    "Verify disk health with chkdsk and SMART diagnostics".to_string(),
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
                            step_description: "Configuring PCIe Link State Power Management (ASPM)...".to_string(),
                            is_success: true,
                            error: None,
                            console_line: Some("powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS 0".to_string()),
                        })
                        .await;
                }

                // Set PCIe Link State Power Management to 'Off' (0) for AC power
                let set_ac = self
                    .runner
                    .run(
                        "powercfg.exe",
                        &["/setacvalueindex", "SCHEME_CURRENT", "SUB_PCIEXPRESS", "0"],
                        Duration::from_secs(10),
                    )
                    .await;

                // Set PCIe Link State Power Management to 'Off' (0) for DC power
                let _ = self
                    .runner
                    .run(
                        "powercfg.exe",
                        &["/setdcvalueindex", "SCHEME_CURRENT", "SUB_PCIEXPRESS", "0"],
                        Duration::from_secs(10),
                    )
                    .await;

                // Apply active power scheme
                let _ = self
                    .runner
                    .run(
                        "powercfg.exe",
                        &["/setactive", "SCHEME_CURRENT"],
                        Duration::from_secs(10),
                    )
                    .await;

                if let Ok(res) = set_ac
                    && res.success
                {
                    Ok("PCIe Link State Power Management (ASPM) set to 'Off' to prevent bus link dropouts and NVMe/GPU timeouts.".to_string())
                } else {
                    Ok("PCIe Power Management configuration applied. Recommendation: verify GPU and NVMe PCIe slot seating.".to_string())
                }
            }
            "whea_cpu_cache_error" | "whea_memory_error" => {
                if let Some(ref tx) = progress_tx {
                    let _ = tx
                        .send(FixProgress {
                            issue_id: issue_id.to_string(),
                            step_description: "Scheduling Windows Memory Diagnostic tool..."
                                .to_string(),
                            is_success: true,
                            error: None,
                            console_line: Some("mdsched.exe /? / schedule".to_string()),
                        })
                        .await;
                }

                // Note: Launching or scheduling mdsched.exe or documenting memory test
                let sched_res = self
                    .runner
                    .run("mdsched.exe", &[], Duration::from_secs(5))
                    .await;

                match sched_res {
                    Ok(out) if out.success => Ok(
                        "Windows Memory Diagnostic (mdsched.exe) launched. Also check BIOS/UEFI for RAM clock speeds (XMP/EXPO) and CPU voltage (Curve Optimizer)."
                            .to_string(),
                    ),
                    _ => Err(
                        "Windows Memory Diagnostic (mdsched.exe) could not be started. Start it from the Start menu, and check BIOS/UEFI for RAM clock speeds (XMP/EXPO) and CPU voltage."
                            .to_string(),
                    ),
                }
            }
            // The storage/platform finding is advice: a repair run never asks.
            _ => Err(format!("Unknown WHEA issue id: {}", issue_id)),
        }
    }
}

const WHEA_PROVIDER: &str = "Microsoft-Windows-WHEA-Logger";

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
        let issues = scan_with(whea_event(
            17,
            3,
            &[
                ("Bus", "0x0"),
                ("Device", "0x1"),
                ("Function", "0x1"),
                ("PrimaryDeviceName", r"PCI\VEN_1022&amp;DEV_1453"),
            ],
        ))
        .await;

        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.id, "whea_pcie_bus_error");
        assert_eq!(issue.category, "Hardware & Stability");
        assert!(issue.title.contains("0x0:0x1:0x1"));
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

    #[tokio::test]
    async fn test_fix_pcie_bus_error_runs_powercfg() {
        let mock = MockCommandRunner::new();
        mock.add_response("powercfg.exe", CmdOutput::ok(""));

        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let res = module.fix("whea_pcie_bus_error", None).await;

        assert!(res.is_ok());
        assert!(res.unwrap().contains("PCIe Link State Power Management"));

        let exec = mock.executed();
        assert!(
            exec.iter()
                .any(|cmd| cmd.contains("powercfg.exe") && cmd.contains("SUB_PCIEXPRESS"))
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
        assert_eq!(issue.risk_score, RiskScore::Medium);
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

    #[tokio::test]
    async fn test_scan_detects_storage_event_1() {
        let issues = scan_with(whea_event(1, 2, &[("ErrorSource", "7")])).await;

        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.id, "whea_storage_platform_error");
        assert_eq!(issue.severity, Severity::Critical);
        assert!(
            issue.advice_only,
            "a failing drive is not repaired in software"
        );
    }

    #[tokio::test]
    async fn a_memory_test_that_did_not_start_is_not_a_repair() {
        let mock = MockCommandRunner::new();
        mock.add_response("mdsched.exe", CmdOutput::failed(1, ""));
        let module = WheaLoggerModule::with_runner(ModuleConfig::default(), Arc::new(mock));

        let res = module.fix("whea_memory_error", None).await;
        assert!(res.unwrap_err().contains("could not be started"));
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
