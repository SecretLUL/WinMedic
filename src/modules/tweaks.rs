//! Damage left behind by tweak, debloat and "privacy" tools.
//!
//! The commonest reason a Windows PC half-works without anything in it being
//! corrupt: a script switched off a service something else depends on, a
//! policy points Windows Update at a server that does not exist, or a hosts
//! entry sends the update endpoints to 0.0.0.0. None of it is visible from the
//! symptom — "the Store will not open", "updates fail with 0x8024..." — and
//! none of it is fixed by DISM or SFC, because nothing is broken: everything is
//! doing exactly what it was told.
//!
//! Every one of these was somebody's decision, so the policy and hosts findings
//! start unticked. Only the services whose loss breaks something basic — no
//! network, no sound, no updates — are ticked by default.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::devices::meaning;
use crate::modules::page_file::{RamSource, real_ram};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::safety::reg_backup::RegBackupManager;
use crate::utils::cmd::{CommandRunner, SystemCommandRunner, ps_single_quoted};
use crate::utils::pnp::PnpDevice;
use crate::utils::registry::{self, RegKeyValues};
use crate::utils::service::{self, SERVICE_DISABLED};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartMode {
    Auto,
    DelayedAuto,
    Demand,
}

impl StartMode {
    fn sc_arg(self) -> &'static str {
        match self {
            StartMode::Auto => "auto",
            StartMode::DelayedAuto => "delayed-auto",
            StartMode::Demand => "demand",
        }
    }

    fn label(self) -> &'static str {
        match self {
            StartMode::Auto => "Automatic",
            StartMode::DelayedAuto => "Automatic (Delayed Start)",
            StartMode::Demand => "Manual",
        }
    }
}

/// A service Windows needs, and what goes wrong without it.
struct CoreService {
    name: &'static str,
    display: &'static str,
    /// What the repair sets. Manual for every service Windows starts on
    /// demand or by trigger; its own default differs between builds, and
    /// Manual works on all of them.
    restore: StartMode,
    breaks: &'static str,
    severity: Severity,
    /// Commonly switched off on purpose, so the finding starts unticked.
    often_deliberate: bool,
}

/// wuauserv, bits and cryptsvc are checked by the Windows Update module and
/// vss by System Integrity, so they are not repeated here.
const CORE_SERVICES: &[CoreService] = &[
    CoreService {
        name: "Dhcp",
        display: "DHCP Client",
        restore: StartMode::Auto,
        breaks: "The PC asks the router for no IP address, so it has no network and no internet.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "Dnscache",
        display: "DNS Client",
        restore: StartMode::Auto,
        breaks: "Names no longer resolve reliably: websites, updates and sign-ins fail while the network itself works.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "nsi",
        display: "Network Store Interface Service",
        restore: StartMode::Auto,
        breaks: "Windows loses track of its network adapters; the network icon shows no connection.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "Wcmsvc",
        display: "Windows Connection Manager",
        restore: StartMode::Auto,
        breaks: "Wi-Fi networks cannot be joined and connections drop between networks.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "BFE",
        display: "Base Filtering Engine",
        restore: StartMode::Auto,
        breaks: "The firewall, IPsec and most VPN clients stop working.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "mpssvc",
        display: "Windows Defender Firewall",
        restore: StartMode::Auto,
        breaks: "The firewall is off, and Store apps that register firewall rules fail to install.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "EventLog",
        display: "Windows Event Log",
        restore: StartMode::Auto,
        breaks: "Crashes, update failures and driver faults leave no trace, and services that depend on the log do not start.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "Winmgmt",
        display: "Windows Management Instrumentation",
        restore: StartMode::Auto,
        breaks: "System information, many drivers' tools and several of WinMedic's own checks get no answers.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "AudioSrv",
        display: "Windows Audio",
        restore: StartMode::Auto,
        breaks: "There is no sound, and the volume icon shows a red cross.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "AudioEndpointBuilder",
        display: "Windows Audio Endpoint Builder",
        restore: StartMode::Auto,
        breaks: "Windows finds no playback or recording devices, so there is no sound.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "LanmanWorkstation",
        display: "Workstation",
        restore: StartMode::Auto,
        breaks: "Network shares, mapped drives and network printers are unreachable.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "UsoSvc",
        display: "Update Orchestrator Service",
        restore: StartMode::Demand,
        breaks: "Windows Update never scans, downloads or installs anything, without saying why.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "TrustedInstaller",
        display: "Windows Modules Installer",
        restore: StartMode::Demand,
        breaks: "Updates cannot install and SFC cannot repair system files.",
        severity: Severity::Critical,
        often_deliberate: false,
    },
    CoreService {
        name: "msiserver",
        display: "Windows Installer",
        restore: StartMode::Demand,
        breaks: "Every .msi setup fails, including installers of drivers and runtimes.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "AppXSvc",
        display: "AppX Deployment Service",
        restore: StartMode::Demand,
        breaks: "Store apps cannot install or update, and Settings, Start or the Store may not open.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "ClipSVC",
        display: "Client License Service",
        restore: StartMode::Demand,
        breaks: "Store apps refuse to start with a licence error.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "InstallService",
        display: "Microsoft Store Install Service",
        restore: StartMode::Demand,
        breaks: "Downloads from the Microsoft Store never start.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "wlidsvc",
        display: "Microsoft Account Sign-in Assistant",
        restore: StartMode::Demand,
        breaks: "Signing in with a Microsoft account fails in Windows, the Store and Office.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "TokenBroker",
        display: "Web Account Manager",
        restore: StartMode::Demand,
        breaks: "The Store, Office and other apps cannot sign in and keep asking for credentials.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "NlaSvc",
        display: "Network Location Awareness",
        restore: StartMode::Demand,
        breaks: "Windows reports 'No internet' on a working connection, and apps that trust that report stay offline.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "netprofm",
        display: "Network List Service",
        restore: StartMode::Demand,
        breaks: "The network icon and the network profile (public/private) stop working.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "W32Time",
        display: "Windows Time",
        restore: StartMode::Demand,
        breaks: "The clock drifts, and a clock that is off by minutes breaks HTTPS, sign-ins and updates.",
        severity: Severity::Warning,
        often_deliberate: false,
    },
    CoreService {
        name: "WSearch",
        display: "Windows Search",
        restore: StartMode::DelayedAuto,
        breaks: "Search in Start, Settings, Explorer and Outlook finds little or nothing.",
        severity: Severity::Info,
        often_deliberate: true,
    },
    CoreService {
        name: "DoSvc",
        display: "Delivery Optimization",
        restore: StartMode::Demand,
        breaks: "Windows Update and Store downloads can stall at 0 %.",
        severity: Severity::Info,
        often_deliberate: true,
    },
];

fn service_issue_id(name: &str) -> String {
    format!("tweak_svc_{}", name.to_ascii_lowercase())
}

/// `CM_PROB_DISABLED`: the device is disabled in Device Manager.
const DEVICE_DISABLED: u32 = 22;
/// `CM_PROB_NEED_RESTART`: the device starts after Windows restarts.
const NEEDS_RESTART: u32 = 14;

/// Where a device's settings are, `ConfigFlags` among them.
const ENUM_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Enum";

/// A Windows system device, and what goes wrong while it is disabled.
///
/// The Devices & Drivers check leaves every disabled device alone, which is
/// right for hardware someone switched off. These are parts of Windows
/// itself that tuning tools switch off.
struct CoreDevice {
    /// The device's hardware ID. Its instance ID starts with it:
    /// `ROOT\HVSERVICE\0000` for `ROOT\HVSERVICE`.
    hardware_id: &'static str,
    display: &'static str,
    /// What stops working while it is disabled. Only what has been observed
    /// or is documented; without that, a neutral sentence.
    breaks: &'static str,
    /// Disabling it is known to break something, so the finding is a ticked
    /// warning. Otherwise it is an unticked hint.
    known_fault: bool,
}

/// No fault is known to come from disabling the device.
const NO_KNOWN_FAULT: &str = "No fault is known to come from this; enable it if something has misbehaved since it was disabled.";

const CORE_DEVICES: &[CoreDevice] = &[
    // On the development PC a tuning tool had disabled it. HvHost then
    // stopped at every start with an error (31; 298 while the services were
    // grouped), CmService could not start, and installing Windows Sandbox
    // was rolled back twice (CBS_E_INSTALLERS_FAILED). Enabled again on
    // 2026-10-08, HvHost started at once and Windows Sandbox installed.
    CoreDevice {
        hardware_id: r"ROOT\HVSERVICE",
        display: "Microsoft Hypervisor Service",
        breaks: "Without it the HV Host Service stops with an error: Windows Sandbox and containers do not start, and installing Windows Sandbox is rolled back.",
        known_fault: true,
    },
    // Disabled by the same tuning tool; nothing was seen to break.
    CoreDevice {
        hardware_id: r"ROOT\NDISVIRTUALBUS",
        display: "NDIS Virtual Network Adapter Enumerator",
        breaks: NO_KNOWN_FAULT,
        known_fault: false,
    },
    // Disabled by the same tuning tool; nothing was seen to break.
    CoreDevice {
        hardware_id: r"ACPI\PNP0103",
        display: "High Precision Event Timer",
        breaks: NO_KNOWN_FAULT,
        known_fault: false,
    },
];

/// The entry for the device with `instance_id`: the one whose hardware ID it
/// starts with, followed by a backslash, in any case. SetupAPI reports
/// `ROOT\HVSERVICE\0000`, pnputil the same device as `ROOT\hvservice\0000`.
fn core_device(instance_id: &str) -> Option<&'static CoreDevice> {
    CORE_DEVICES.iter().find(|entry| {
        let len = entry.hardware_id.len();
        instance_id
            .get(..len)
            .is_some_and(|start| start.eq_ignore_ascii_case(entry.hardware_id))
            && instance_id[len..].starts_with('\\')
            && instance_id.len() > len + 1
    })
}

const DEVICE_ID_PREFIX: &str = "tweak_dev_";

fn device_issue_id(instance_id: &str) -> String {
    let slug: String = instance_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{DEVICE_ID_PREFIX}{slug}")
}

/// Device Manager's "Enable device" for one device, through PowerShell's
/// `Enable-PnpDevice`, which clears the device's disabled flag
/// (`ConfigFlags`) and starts it.
///
/// Not `pnputil /enable-device`: pnputil refuses a device that was already
/// disabled when Windows started. It reads the device's state from its
/// `DEVPKEY_Device_DevNodeStatus` property, which Windows does not report
/// for such a device, lists it as disconnected and fails with
/// `ERROR_DEVICE_NOT_CONNECTED` (1167). `Enable-PnpDevice` enabled the same
/// device without a restart - in Windows Sandbox, and on 2026-10-08 the
/// development PC's Microsoft Hypervisor Service.
fn enable_device_script(instance_id: &str) -> String {
    format!(
        "Enable-PnpDevice -InstanceId {} -Confirm:$false -ErrorAction Stop",
        ps_single_quoted(instance_id)
    )
}

/// Holds `SvcHostSplitThresholdInKB`.
const CONTROL_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control";
const SPLIT_THRESHOLD: &str = "SvcHostSplitThresholdInKB";
pub const SPLIT_THRESHOLD_ID: &str = "tweak_svchost_split_threshold";
/// 3.5 GB in KB, the value the repair writes. On PCs with more memory than
/// 3.5 GB Windows runs most services in a process of their own, and groups
/// them on PCs with less (Microsoft Learn, "Service host grouping in
/// Windows 10").
const DEFAULT_SPLIT_THRESHOLD_KB: u64 = 3_670_016;

/// Whether `threshold_kb` keeps Windows from splitting its services on a PC
/// whose memory Windows reports as `ram_bytes`: it gives each service a
/// process of its own only while it has more memory than that.
///
/// Measured against the memory Windows has (`GlobalMemoryStatusEx`), not
/// against what is installed. On the development PC the tuning tool had
/// set exactly the installed 32 GB, 33554432 KB, above the 33119136 KB
/// Windows has, and the services ran grouped.
pub fn keeps_services_grouped(threshold_kb: u64, ram_bytes: u64) -> bool {
    threshold_kb > ram_bytes / 1024
}

pub const WU_POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
const WU_AU_POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
const STORE_POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsStore";

/// A policy setting that stops part of Windows from working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyHit {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    /// `(key, value name)` of every value this finding is about; the repair
    /// deletes exactly these.
    pub values: Vec<(&'static str, &'static str)>,
}

fn is_on(keys: &[RegKeyValues], key: &str, name: &str) -> bool {
    registry::find(keys, key, name).and_then(|v| v.number()) == Some(1)
}

fn has_text(keys: &[RegKeyValues], key: &str, name: &str) -> bool {
    registry::find(keys, key, name).is_some_and(|v| !v.data.trim().is_empty())
}

/// Whether the policy "Do not include drivers with Windows Updates" is on,
/// among `wu` (the WindowsUpdate key).
///
/// Not a finding here: a company may keep drivers out of Windows Update on
/// purpose, and nothing is missing while every device has one. The devices
/// module names it when a device has no driver.
pub fn drivers_excluded_from_updates(wu: &[RegKeyValues]) -> bool {
    is_on(wu, WU_POLICY_KEY, "ExcludeWUDriversInQualityUpdate")
}

/// The harmful policies among `wu` (the WindowsUpdate key, read with `/s`)
/// and `store`.
pub fn policy_hits(wu: &[RegKeyValues], store: &[RegKeyValues]) -> Vec<PolicyHit> {
    let mut hits = Vec::new();

    if is_on(wu, WU_AU_POLICY_KEY, "UseWUServer") && has_text(wu, WU_POLICY_KEY, "WUServer") {
        let mut values = vec![
            (WU_POLICY_KEY, "WUServer"),
            (WU_AU_POLICY_KEY, "UseWUServer"),
        ];
        if registry::find(wu, WU_POLICY_KEY, "WUStatusServer").is_some() {
            values.push((WU_POLICY_KEY, "WUStatusServer"));
        }
        hits.push(PolicyHit {
            id: "tweak_policy_wsus",
            title: "Windows Update is pointed at a WSUS server",
            severity: Severity::Critical,
            description: "A policy sends Windows Update to a company update server (WSUS) instead of Microsoft. On a PC outside that company, updates, optional features and .NET installs fail because nobody answers.",
            values,
        });
    }

    let blocking: Vec<(&'static str, &'static str)> = [
        (WU_POLICY_KEY, "DisableWindowsUpdateAccess"),
        (WU_POLICY_KEY, "SetDisableUXWUAccess"),
        (
            WU_POLICY_KEY,
            "DoNotConnectToWindowsUpdateInternetLocations",
        ),
    ]
    .into_iter()
    .filter(|(key, name)| is_on(wu, key, name))
    .collect();
    if !blocking.is_empty() {
        hits.push(PolicyHit {
            id: "tweak_policy_wu_blocked",
            title: "Windows Update is blocked by policy",
            severity: Severity::Critical,
            description: "A policy hides or disables Windows Update. Security updates stop, and so do the repairs DISM downloads from Windows Update.",
            values: blocking,
        });
    }

    if is_on(wu, WU_AU_POLICY_KEY, "NoAutoUpdate") {
        hits.push(PolicyHit {
            id: "tweak_policy_no_auto_update",
            title: "Automatic updates are switched off by policy",
            severity: Severity::Warning,
            description: "A policy stops Windows from installing updates on its own. Security fixes arrive only when someone remembers to install them by hand.",
            values: vec![(WU_AU_POLICY_KEY, "NoAutoUpdate")],
        });
    }

    let store_off: Vec<(&'static str, &'static str)> = [
        (STORE_POLICY_KEY, "RemoveWindowsStore"),
        (STORE_POLICY_KEY, "DisableStoreApps"),
    ]
    .into_iter()
    .filter(|(key, name)| is_on(store, key, name))
    .collect();
    if !store_off.is_empty() {
        hits.push(PolicyHit {
            id: "tweak_policy_store_off",
            title: "The Microsoft Store is switched off by policy",
            severity: Severity::Warning,
            description: "A policy disables the Microsoft Store. Store apps cannot be installed or updated, and some built-in apps that update through the Store stop working.",
            values: store_off,
        });
    }

    hits
}

pub const DEFENDER_POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender";
const DEFENDER_RTP_POLICY_KEY: &str =
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
pub const DEFENDER_OFF: &str = "tweak_policy_defender_off";

/// The policy values debloat tools set to switch Microsoft Defender off,
/// among `defender` (its policy key, read with `/s`).
pub fn defender_policy_hit(defender: &[RegKeyValues]) -> Option<PolicyHit> {
    let values: Vec<(&'static str, &'static str)> = [
        (DEFENDER_POLICY_KEY, "DisableAntiSpyware"),
        (DEFENDER_POLICY_KEY, "DisableAntiVirus"),
        (DEFENDER_RTP_POLICY_KEY, "DisableRealtimeMonitoring"),
        (DEFENDER_RTP_POLICY_KEY, "DisableBehaviorMonitoring"),
        (DEFENDER_RTP_POLICY_KEY, "DisableOnAccessProtection"),
        (DEFENDER_RTP_POLICY_KEY, "DisableIOAVProtection"),
        (DEFENDER_RTP_POLICY_KEY, "DisableScanOnRealtimeEnable"),
    ]
    .into_iter()
    .filter(|(key, name)| is_on(defender, key, name))
    .collect();
    (!values.is_empty()).then_some(PolicyHit {
        id: DEFENDER_OFF,
        title: "Microsoft Defender is switched off by policy",
        severity: Severity::Critical,
        description: "A policy switches Microsoft Defender's protection off, and no other antivirus is active. Debloat tools set it; this PC is unprotected against malware.",
        values,
    })
}

/// Whether Defender's real-time protection runs (`MP|True`), and every
/// antivirus Windows Security knows as `AV|productState|instanceGuid|name`.
/// `True`, the state number and the GUID are the same in every language.
const DEFENDER_STATUS_SCRIPT: &str = "try { 'MP|{0}' -f (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { 'MP|FAILED|' + $_.FullyQualifiedErrorId }; Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { 'AV|{0}|{1}|{2}' -f $_.productState, $_.instanceGuid, $_.displayName }";

/// Microsoft Defender's `instanceGuid` in Windows Security.
const DEFENDER_GUID: &str = "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}";

/// What [`DEFENDER_STATUS_SCRIPT`] printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefenderStatus {
    /// Real-time protection on; `false` also when Defender does not answer.
    pub realtime_on: bool,
    /// Other antivirus products Windows Security reports switched on.
    pub other_antivirus: Vec<String>,
}

pub fn parse_defender_status(output: &str) -> DefenderStatus {
    let mut status = DefenderStatus::default();
    for line in output.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("MP|") {
            status.realtime_on = rest.eq_ignore_ascii_case("True");
        } else if let Some(rest) = line.strip_prefix("AV|") {
            let mut fields = rest.splitn(3, '|');
            let (Some(state), Some(guid), Some(name)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            // Bits 12-15 of productState: 1 is switched on.
            let on = state.parse::<u32>().is_ok_and(|s| (s >> 12) & 0xF == 1);
            if on && !guid.eq_ignore_ascii_case(DEFENDER_GUID) {
                status.other_antivirus.push(name.to_string());
            }
        }
    }
    status
}

/// Hosts entries that take a Windows endpoint out of reach.
///
/// Only endpoints Windows needs to work are listed: updates, the Store's
/// catalog, activation, sign-in, the connectivity probe behind "No
/// internet", and certificate revocation. Telemetry endpoints are not, however
/// often hosts files block them: that is a privacy choice that breaks nothing.
const WINDOWS_ENDPOINTS: &[&str] = &[
    "windowsupdate.com",
    "update.microsoft.com",
    "delivery.mp.microsoft.com",
    "download.microsoft.com",
    "displaycatalog.mp.microsoft.com",
    "licensing.mp.microsoft.com",
    "sls.microsoft.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "login.live.com",
    "login.microsoftonline.com",
];

/// Whether `host` is one Windows needs to reach.
pub fn is_needed_endpoint(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if WINDOWS_ENDPOINTS
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return true;
    }
    // Certificate revocation: ocsp.digicert.com, crl3.digicert.com, ... A
    // blocked responder makes signature checks wait for a timeout instead of
    // an answer, which is slow app starts and failing update verification.
    let Some((label, rest)) = host.split_once('.') else {
        return false;
    };
    rest.contains('.')
        && ["ocsp", "crl"].iter().any(|prefix| {
            label
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.chars().all(|c| c.is_ascii_digit()))
        })
}

/// One hosts line that maps at least one needed endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsBlock {
    /// Index of the line in the file.
    pub line: usize,
    pub address: String,
    /// The needed endpoints on it.
    pub hosts: Vec<String>,
    /// The other names on it, which the repair keeps.
    pub others: Vec<String>,
}

/// The lines of a hosts file that map a needed endpoint anywhere at all: to
/// 0.0.0.0, to 127.0.0.1, or to a fixed address that is out of date the moment
/// the CDN behind the name moves.
pub fn hosts_blocks(hosts: &str) -> Vec<HostsBlock> {
    hosts
        .lines()
        .enumerate()
        .filter_map(|(line, text)| block_on_line(line, text.as_bytes()))
        .collect()
}

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// The fields of one hosts line: the text before a `#`, split at ASCII
/// whitespace, without a byte order mark in front. Judging a line and
/// rewriting it both start from these, so they agree on where each name ends.
fn line_fields(line: &[u8]) -> Vec<&[u8]> {
    let mut text = line;
    while let Some(rest) = text.strip_prefix(UTF8_BOM) {
        text = rest;
    }
    let text = text.split(|&b| b == b'#').next().unwrap_or_default();
    text.split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .collect()
}

/// The block one line makes, if it maps a needed endpoint. Each name is
/// decoded on its own, leniently: a name with bytes that are not UTF-8 cannot
/// be a needed endpoint anyway.
fn block_on_line(line: usize, text: &[u8]) -> Option<HostsBlock> {
    let fields = line_fields(text);
    let (address, names) = fields.split_first()?;
    let (hosts, others): (Vec<String>, Vec<String>) = names
        .iter()
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .partition(|name| is_needed_endpoint(name));
    (!hosts.is_empty()).then_some(HostsBlock {
        line,
        address: String::from_utf8_lossy(address).into_owned(),
        hosts,
        others,
    })
}

/// `hosts`, the bytes of a hosts file, with every blocking line commented out
/// and nothing else changed. A blocking line becomes `# WinMedic unblocked:`
/// followed by its own text; the names on it that are not needed stay active on
/// a line of their own. Every other byte is copied as it was: the byte order
/// mark, Windows-1252 text, and each line's own terminator (CRLF, LF, or none
/// on a last line).
pub fn unblock_hosts(hosts: &[u8]) -> Vec<u8> {
    let (bom, body) = hosts.split_at(if hosts.starts_with(UTF8_BOM) {
        UTF8_BOM.len()
    } else {
        0
    });
    let file_newline: &[u8] = if body.windows(2).any(|pair| pair == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };

    let mut out = bom.to_vec();
    for (index, line) in body.split_inclusive(|&b| b == b'\n').enumerate() {
        let (text, eol) = split_eol(line);
        let Some(block) = block_on_line(index, text) else {
            out.extend_from_slice(line);
            continue;
        };
        out.extend_from_slice(b"# WinMedic unblocked: ");
        out.extend_from_slice(text.trim_ascii_end());
        if block.others.is_empty() {
            out.extend_from_slice(eol);
        } else {
            // A last line without a terminator still needs one before the names that stay.
            out.extend_from_slice(if eol.is_empty() { file_newline } else { eol });
            out.extend_from_slice(&active_remainder(text));
            out.extend_from_slice(eol);
        }
    }
    out
}

/// A line's text and its terminator: CRLF, LF, or nothing on a last line.
fn split_eol(line: &[u8]) -> (&[u8], &[u8]) {
    if let Some(text) = line.strip_suffix(b"\r\n") {
        (text, b"\r\n")
    } else if let Some(text) = line.strip_suffix(b"\n") {
        (text, b"\n")
    } else {
        (line, b"")
    }
}

/// The address and the names of a blocking line that are not needed, as the
/// bytes of the original line, joined by single spaces.
fn active_remainder(text: &[u8]) -> Vec<u8> {
    let mut fields = line_fields(text).into_iter();
    let mut out = fields.next().unwrap_or_default().to_vec();
    for field in fields.filter(|field| !is_needed_endpoint(&String::from_utf8_lossy(field))) {
        out.push(b' ');
        out.extend_from_slice(field);
    }
    out
}

/// Replaces the file at `path` with `bytes` in one step. The bytes are written
/// and synced to `path.winmedic-tmp` beside it, which is then renamed over
/// `path`. The rename either happens or it does not, so `path` is always either
/// the old file or the new one. A failure removes the temp file.
fn replace_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("winmedic-tmp");
    let written = write_synced(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

pub struct TweaksModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
    hosts_path: PathBuf,
    local_policy_path: PathBuf,
    backup_dir: PathBuf,
    /// How long Defender gets to switch its protection on after the policy
    /// is gone, before each of three looks.
    defender_wait: Duration,
    ram: RamSource,
}

fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

impl TweaksModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        let root = system_root();
        Self::with_paths(
            config,
            runner,
            root.join(r"System32\drivers\etc\hosts"),
            root.join(r"System32\GroupPolicy\Machine\Registry.pol"),
            RegBackupManager::new().backup_dir().to_path_buf(),
        )
    }

    /// For tests: a hosts file, a local policy file and a backup directory
    /// other than the machine's own.
    pub fn with_paths(
        config: ModuleConfig,
        runner: Arc<dyn CommandRunner>,
        hosts_path: PathBuf,
        local_policy_path: PathBuf,
        backup_dir: PathBuf,
    ) -> Self {
        Self {
            config,
            runner,
            hosts_path,
            local_policy_path,
            backup_dir,
            defender_wait: Duration::from_secs(5),
            ram: real_ram(),
        }
    }

    /// For tests: do not wait for Defender.
    pub fn with_defender_wait(mut self, wait: Duration) -> Self {
        self.defender_wait = wait;
        self
    }

    /// For tests: a PC with this much memory.
    pub fn with_ram(mut self, ram: RamSource) -> Self {
        self.ram = ram;
        self
    }

    /// Defender's protection and the other antivirus, or `None` when the
    /// query did not run.
    async fn defender_status(&self) -> Option<DefenderStatus> {
        let out = self
            .runner
            .query_powershell(DEFENDER_STATUS_SCRIPT, Duration::from_secs(30))
            .await
            .ok()?;
        out.stdout
            .contains("MP|")
            .then(|| parse_defender_status(&out.stdout))
    }

    /// Whether real-time protection came on, looking three times.
    async fn defender_came_on(&self) -> bool {
        for _ in 0..3 {
            tokio::time::sleep(self.defender_wait).await;
            if self.defender_status().await.is_some_and(|s| s.realtime_on) {
                return true;
            }
        }
        false
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
                    module_id: "tweaks".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }

    /// Whether the PC is joined to a domain, whose administrators set these
    /// policies on purpose. `None` when WMI did not say.
    async fn part_of_domain(&self) -> Option<bool> {
        let out = self
            .runner
            .query_powershell(
                "(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain",
                Duration::from_secs(10),
            )
            .await
            .ok()?;
        match out.stdout.trim() {
            "True" => Some(true),
            "False" => Some(false),
            _ => None,
        }
    }

    async fn current_policy_hits(&self) -> Result<Vec<PolicyHit>, String> {
        let wu = registry::query(&*self.runner, WU_POLICY_KEY, true)
            .await?
            .unwrap_or_default();
        let store = registry::query(&*self.runner, STORE_POLICY_KEY, false)
            .await?
            .unwrap_or_default();
        let defender = registry::query(&*self.runner, DEFENDER_POLICY_KEY, true)
            .await?
            .unwrap_or_default();
        let mut hits = policy_hits(&wu, &store);
        hits.extend(defender_policy_hit(&defender));
        Ok(hits)
    }

    /// Whether a value name appears in the local Group Policy file, which
    /// re-applies it on the next policy refresh however often it is deleted
    /// from the registry.
    fn set_by_local_policy(&self, name: &str) -> bool {
        let Ok(bytes) = std::fs::read(&self.local_policy_path) else {
            return false;
        };
        let wide: Vec<u8> = name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        bytes.windows(wide.len()).any(|window| window == wide)
    }

    async fn fix_policy(&self, issue_id: &str) -> Result<String, String> {
        let hit = self
            .current_policy_hits()
            .await?
            .into_iter()
            .find(|hit| hit.id == issue_id)
            .ok_or_else(|| "The policy is no longer set - nothing to change.".to_string())?;

        if let Some((_, name)) = hit
            .values
            .iter()
            .find(|(_, name)| self.set_by_local_policy(name))
        {
            return Err(format!(
                "'{name}' is set in the local Group Policy, which would put it back at the next policy refresh. Nothing was changed; change the setting in gpedit.msc instead."
            ));
        }

        if self.config.auto_backup_registry {
            let backup = RegBackupManager::with_dir(self.backup_dir.clone());
            let mut keys: Vec<&str> = hit.values.iter().map(|(key, _)| *key).collect();
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                backup
                    .export_key(key, &format!("Before removing the policy behind '{}'", hit.title))
                    .await
                    .map_err(|e| {
                        format!("Aborted: the registry backup of '{key}' failed ({e}). Nothing was changed.")
                    })?;
            }
        }

        for (key, name) in &hit.values {
            let out = self
                .runner
                .run(
                    "reg.exe",
                    &["delete", key, "/v", name, "/f"],
                    Duration::from_secs(10),
                )
                .await?;
            if !out.success {
                return Err(format!(
                    "Could not delete {key}\\{name}: {}",
                    out.stderr.trim()
                ));
            }
        }

        if self
            .current_policy_hits()
            .await?
            .iter()
            .any(|still| still.id == issue_id)
        {
            return Err(
                "The values were deleted but the policy is still in effect - something re-applies it."
                    .to_string(),
            );
        }
        if issue_id == DEFENDER_OFF && !self.defender_came_on().await {
            return Err(format!(
                "Removed {}, but Defender's real-time protection is still off. Switch it on under Windows Security -> Virus & threat protection, or restart Windows and scan again.",
                hit.values
                    .iter()
                    .map(|(_, name)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Ok(format!(
            "Removed {} policy value(s): {}.{}",
            hit.values.len(),
            hit.values
                .iter()
                .map(|(_, name)| *name)
                .collect::<Vec<_>>()
                .join(", "),
            if self.config.auto_backup_registry {
                " A registry backup was taken first."
            } else {
                ""
            }
        ))
    }

    async fn fix_service(&self, svc: &CoreService) -> Result<String, String> {
        let out = self
            .runner
            .run(
                "sc.exe",
                &["config", svc.name, "start=", svc.restore.sc_arg()],
                Duration::from_secs(10),
            )
            .await?;
        if !out.success {
            return Err(format!(
                "sc config {} failed: {}",
                svc.name,
                out.stdout.trim()
            ));
        }
        if service::start_type(&*self.runner, svc.name).await? == Some(SERVICE_DISABLED) {
            return Err(format!(
                "Windows accepted the change but '{}' is still disabled - a group policy may enforce it",
                svc.name
            ));
        }
        let set = format!(
            "'{}' is set to start {} again.",
            svc.display,
            svc.restore.label()
        );
        if svc.restore == StartMode::Demand {
            return Ok(set);
        }
        if !self.config.auto_restart_services {
            return Ok(format!(
                "{set} Starting it was skipped because 'Restart services automatically' is off in the settings; Windows starts it at the next start."
            ));
        }
        let _ = self
            .runner
            .run("net.exe", &["start", svc.name], Duration::from_secs(20))
            .await;
        Ok(set)
    }

    /// The finding for `device`, if it is a Windows system device that is
    /// disabled.
    fn device_issue(&self, device: &PnpDevice) -> Option<Issue> {
        if device.problem != DEVICE_DISABLED {
            return None;
        }
        let entry = core_device(&device.instance_id)?;
        let mut steps = Vec::new();
        if self.config.auto_backup_registry {
            steps.push(format!(
                "Back up ConfigFlags of {ENUM_KEY}\\{} to the registry backups",
                device.instance_id
            ));
        }
        steps.push(format!(
            "Run {} (Device Manager: Enable device)",
            enable_device_script(&device.instance_id)
        ));
        steps.push("Check that the device no longer reports a problem".to_string());
        let mut issue = Issue::new(
            device_issue_id(&device.instance_id),
            self.id(),
            format!("'{}' is disabled", entry.display),
            "Tweaks & Policies",
            if entry.known_fault {
                Severity::Warning
            } else {
                Severity::Info
            },
            RiskScore::Medium,
            format!(
                "This Windows device is disabled in Device Manager, which tuning tools do. {}",
                entry.breaks
            ),
            format!(
                "Device: {}\nInstance ID: {}\nProblem code: {} (disabled)",
                device.name, device.instance_id, device.problem
            ),
            format!("Enable '{}' again", entry.display),
            steps,
        );
        issue.is_selected = entry.known_fault;
        Some(issue)
    }

    /// Back up the device's `ConfigFlags`, enable it, and read its problem
    /// code again.
    async fn fix_device(&self, issue_id: &str) -> Result<String, String> {
        let devices = self.runner.connected_devices().await?;
        let Some((device, entry)) = devices.iter().find_map(|device| {
            let entry = core_device(&device.instance_id)?;
            (device_issue_id(&device.instance_id) == issue_id).then_some((device, entry))
        }) else {
            return Ok("The device is no longer connected - nothing to change.".to_string());
        };
        if device.problem != DEVICE_DISABLED {
            return Ok(format!(
                "'{}' is no longer disabled - nothing to change.",
                entry.display
            ));
        }

        let key = format!("{ENUM_KEY}\\{}", device.instance_id);
        if self.config.auto_backup_registry {
            RegBackupManager::with_dir(self.backup_dir.clone())
                .export_value_with(
                    &*self.runner,
                    &key,
                    "ConfigFlags",
                    &format!(
                        "Before enabling '{}'; restoring it disables the device again at the next restart",
                        entry.display
                    ),
                )
                .await
                .map_err(|e| {
                    format!("Aborted: the registry backup of {key} failed ({e}). Nothing was changed.")
                })?;
        }

        let out = self
            .runner
            .run_powershell(
                &enable_device_script(&device.instance_id),
                Duration::from_secs(60),
            )
            .await;
        let refusal = match &out {
            Ok(out) if !out.success => format!(" Enable-PnpDevice: {}", out.stderr.trim()),
            Err(e) => format!(" Enable-PnpDevice: {e}"),
            Ok(_) => String::new(),
        };

        let after = self
            .runner
            .connected_devices()
            .await?
            .into_iter()
            .find(|d| d.instance_id.eq_ignore_ascii_case(&device.instance_id));
        let name = entry.display;
        match after.map(|d| d.problem) {
            Some(0) => Ok(format!(
                "'{name}' is enabled again and works.{} To disable it again: Device Manager -> right-click it -> Disable device.",
                if self.config.auto_backup_registry {
                    " Its old setting is in the registry backups."
                } else {
                    ""
                }
            )),
            Some(DEVICE_DISABLED) => Err(format!(
                "Windows did not enable '{name}'; it is still disabled.{refusal}"
            )),
            Some(NEEDS_RESTART) => Err(format!(
                "'{name}' is enabled, but Windows starts it only after a restart. Restart Windows."
            )),
            Some(code) => Err(format!(
                "'{name}' is enabled but reports problem code {code}: {}.",
                meaning(code)
            )),
            None => Err(format!(
                "'{name}' is no longer listed after it was enabled.{refusal}"
            )),
        }
    }

    /// `SvcHostSplitThresholdInKB` in KB, or `None` when it is not set and
    /// Windows uses its own.
    async fn split_threshold(&self) -> Result<Option<u64>, String> {
        Ok(
            registry::query_value(&*self.runner, CONTROL_KEY, SPLIT_THRESHOLD)
                .await?
                .filter(|value| value.kind == "REG_DWORD")
                .and_then(|value| value.number()),
        )
    }

    fn split_threshold_issue(&self, threshold_kb: u64, ram_bytes: u64) -> Issue {
        let gb = |kb: u64| kb as f64 / (1024.0 * 1024.0);
        let mut steps = Vec::new();
        if self.config.auto_backup_registry {
            steps.push(format!(
                "Back up {SPLIT_THRESHOLD} ({CONTROL_KEY}) to the registry backups"
            ));
        }
        steps.push(format!(
            "reg add {CONTROL_KEY} /v {SPLIT_THRESHOLD} /t REG_DWORD /d {DEFAULT_SPLIT_THRESHOLD_KB} /f"
        ));
        steps.push("Read the value back".to_string());
        steps.push("Restart Windows".to_string());
        let mut issue = Issue::new(
            SPLIT_THRESHOLD_ID,
            self.id(),
            "Windows services share their processes",
            "Tweaks & Policies",
            Severity::Warning,
            RiskScore::High,
            format!(
                "{SPLIT_THRESHOLD} is {:.1} GB, more than the {:.1} GB of memory Windows has, so services run grouped in shared processes, as on PCs with under 3.5 GB. One failing service can then take others with it, and report the wrong error. Tuning tools set it.",
                gb(threshold_kb),
                gb(ram_bytes / 1024)
            ),
            format!(
                "{CONTROL_KEY}\\{SPLIT_THRESHOLD} = {threshold_kb} KB\nMemory Windows has: {} KB",
                ram_bytes / 1024
            ),
            "Set it back to 3.5 GB, Windows' default, and restart Windows",
            steps,
        )
        .with_requires_reboot(true);
        // Takes effect only after a restart.
        issue.is_selected = false;
        issue
    }

    /// Back the value up, set it back to 3.5 GB and read it back.
    async fn fix_split_threshold(&self) -> Result<String, String> {
        match self.split_threshold().await? {
            Some(kb) if keeps_services_grouped(kb, (self.ram)()) => {}
            _ => {
                return Ok(format!(
                    "{SPLIT_THRESHOLD} no longer keeps services together - nothing to change."
                ));
            }
        }
        if self.config.auto_backup_registry {
            RegBackupManager::with_dir(self.backup_dir.clone())
                .export_value_with(
                    &*self.runner,
                    CONTROL_KEY,
                    SPLIT_THRESHOLD,
                    &format!("Before setting {SPLIT_THRESHOLD} back to 3.5 GB"),
                )
                .await
                .map_err(|e| {
                    format!("Aborted: the registry backup failed ({e}). Nothing was changed.")
                })?;
        }
        let out = self
            .runner
            .run(
                "reg.exe",
                &[
                    "add",
                    CONTROL_KEY,
                    "/v",
                    SPLIT_THRESHOLD,
                    "/t",
                    "REG_DWORD",
                    "/d",
                    &DEFAULT_SPLIT_THRESHOLD_KB.to_string(),
                    "/f",
                ],
                Duration::from_secs(10),
            )
            .await?;
        if !out.success {
            return Err(format!(
                "Could not set {SPLIT_THRESHOLD} (exit code {:?}): {}",
                out.exit_code,
                out.stderr.trim()
            ));
        }
        match self.split_threshold().await? {
            Some(DEFAULT_SPLIT_THRESHOLD_KB) => Ok(format!(
                "{SPLIT_THRESHOLD} is back at 3.5 GB. Restart Windows so that services run in processes of their own again."
            )),
            other => Err(format!(
                "{SPLIT_THRESHOLD} was set to {DEFAULT_SPLIT_THRESHOLD_KB} but reads {}.",
                other.map_or("nothing".to_string(), |kb| kb.to_string())
            )),
        }
    }

    /// Backs the hosts file up, then replaces it with the unblocked bytes. The
    /// result is read back and checked; if the check fails, the backup is
    /// copied back over the hosts file.
    fn fix_hosts(&self) -> Result<String, String> {
        let original = std::fs::read(&self.hosts_path).map_err(|e| {
            format!(
                "Could not read {} ({e}). Nothing was changed.",
                self.hosts_path.display()
            )
        })?;
        let blocks = hosts_blocks(&String::from_utf8_lossy(&original));
        if blocks.is_empty() {
            return Ok("The hosts file no longer blocks any Windows endpoint.".to_string());
        }

        RegBackupManager::with_dir(self.backup_dir.clone())
            .ensure_backup_dir()
            .map_err(|e| format!("Aborted: {e}. Nothing was changed."))?;
        let backup = self.backup_dir.join(format!(
            "hosts_{}.bak",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        ));
        std::fs::copy(&self.hosts_path, &backup).map_err(|e| {
            // A partial copy is not a backup.
            let _ = std::fs::remove_file(&backup);
            format!("Aborted: the hosts file could not be backed up ({e}). Nothing was changed.")
        })?;

        let fixed = unblock_hosts(&original);
        if let Err(e) = replace_file(&self.hosts_path, &fixed) {
            return Err(format!(
                "Could not write {} ({e}); the hosts file was not changed. Antivirus software often protects it. The backup is {}.",
                self.hosts_path.display(),
                backup.display()
            ));
        }

        // The hosts file has been replaced: it must be exactly what was written and must block nothing.
        let problem = match std::fs::read(&self.hosts_path) {
            Err(e) => format!("The new hosts file could not be read back ({e})"),
            Ok(after) if after != fixed => "The new hosts file is not what was written".to_string(),
            Ok(after) if !hosts_blocks(&String::from_utf8_lossy(&after)).is_empty() => {
                "The hosts file was written but still blocks Windows endpoints".to_string()
            }
            Ok(_) => {
                let unblocked: Vec<String> = blocks.into_iter().flat_map(|b| b.hosts).collect();
                return Ok(format!(
                    "Unblocked {} in the hosts file; the old file is saved as {}.",
                    unblocked.join(", "),
                    backup.display()
                ));
            }
        };
        Err(
            match std::fs::read(&backup).and_then(|bytes| replace_file(&self.hosts_path, &bytes)) {
                Ok(()) => format!(
                    "{problem}, so the backup was copied back and the hosts file is as it was. The backup is {}.",
                    backup.display()
                ),
                Err(e) => format!(
                    "{problem}, and the backup could not be copied back ({e}). The hosts file has the new content; the original is in {}.",
                    backup.display()
                ),
            },
        )
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for TweaksModule {
    fn id(&self) -> &'static str {
        "tweaks"
    }

    fn name(&self) -> &'static str {
        "Tweaks & Policies"
    }

    fn description(&self) -> &'static str {
        "Finds what tweak and debloat tools leave behind: disabled core services and system devices, services kept in shared processes, update, Store and Defender policies, and hosts entries that block Windows"
    }

    fn icon(&self) -> &'static str {
        "[TWK]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. Services
        Self::send_progress(
            &progress_tx,
            10,
            "Checking core Windows services...",
            Some("Reading the start type of every service Windows depends on (sc qc)..."),
        )
        .await;
        let mut disabled = 0;
        for svc in CORE_SERVICES {
            if let Ok(Some(SERVICE_DISABLED)) = service::start_type(&*self.runner, svc.name).await {
                disabled += 1;
                let mut issue = Issue::new(
                    service_issue_id(svc.name),
                    self.id(),
                    format!("Service '{}' is disabled", svc.display),
                    "Tweaks & Policies",
                    svc.severity,
                    RiskScore::Medium,
                    format!(
                        "The service '{}' ({}) is disabled. {} Tweak and debloat tools switch it off; Windows never does.",
                        svc.display, svc.name, svc.breaks
                    ),
                    format!("sc qc {}: START_TYPE 4 (DISABLED)", svc.name),
                    format!("Set '{}' back to {}", svc.display, svc.restore.label()),
                    vec![format!(
                        "sc config {} start= {}",
                        svc.name,
                        svc.restore.sc_arg()
                    )],
                );
                issue.is_selected = !svc.often_deliberate;
                issues.push(issue);
            }
        }
        Self::send_progress(
            &progress_tx,
            35,
            "Core services checked",
            Some(&format!(
                "{} of {} core services disabled.",
                disabled,
                CORE_SERVICES.len()
            )),
        )
        .await;

        // 2. Windows system devices
        Self::send_progress(
            &progress_tx,
            40,
            "Checking Windows system devices...",
            Some("Device Manager's problem codes (SetupAPI, CfgMgr32)"),
        )
        .await;
        match self.runner.connected_devices().await {
            Ok(devices) => {
                let found: Vec<Issue> = devices
                    .iter()
                    .filter_map(|device| self.device_issue(device))
                    .collect();
                Self::send_progress(
                    &progress_tx,
                    45,
                    "Windows system devices checked",
                    Some(&format!(
                        "{} of {} Windows system devices disabled.",
                        found.len(),
                        CORE_DEVICES.len()
                    )),
                )
                .await;
                issues.extend(found);
            }
            Err(e) => {
                Self::send_progress(&progress_tx, 45, "System devices not checked", Some(&e)).await;
            }
        }
        match self.split_threshold().await {
            Ok(Some(kb)) => {
                let ram = (self.ram)();
                if keeps_services_grouped(kb, ram) {
                    issues.push(self.split_threshold_issue(kb, ram));
                }
            }
            // Not set: Windows uses its own.
            Ok(None) => {}
            Err(e) => {
                Self::send_progress(&progress_tx, 47, "Service grouping not checked", Some(&e))
                    .await;
            }
        }

        // 3. Policies
        Self::send_progress(
            &progress_tx,
            50,
            "Checking Windows Update and Store policies...",
            Some("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\..."),
        )
        .await;
        // Only a PC WMI calls standalone is judged: on a domain member these
        // policies are its administrators' to set, and a PC whose membership
        // could not be read may be one.
        let membership = self.part_of_domain().await;
        if membership != Some(false) {
            let why = if membership == Some(true) {
                "This PC is joined to a domain, whose administrators set these policies on purpose."
            } else {
                "WMI did not say whether this PC is joined to a domain, so its policies were not judged."
            };
            Self::send_progress(&progress_tx, 70, "Policies left alone", Some(why)).await;
        } else {
            match self.current_policy_hits().await {
                Ok(hits) => {
                    for hit in hits {
                        // Defender switched off by policy is only a fault
                        // while nothing else protects the PC.
                        if hit.id == DEFENDER_OFF {
                            match self.defender_status().await {
                                Some(status)
                                    if !status.realtime_on && status.other_antivirus.is_empty() => {
                                }
                                Some(status) => {
                                    let why = if status.realtime_on {
                                        "its real-time protection runs anyway".to_string()
                                    } else {
                                        format!(
                                            "{} protects this PC",
                                            status.other_antivirus.join(", ")
                                        )
                                    };
                                    Self::send_progress(
                                        &progress_tx,
                                        70,
                                        "Defender policy left alone",
                                        Some(&format!(
                                            "A policy switches Defender off, but {why}."
                                        )),
                                    )
                                    .await;
                                    continue;
                                }
                                None => continue,
                            }
                        }
                        let evidence = hit
                            .values
                            .iter()
                            .map(|(key, name)| format!("{key}\\{name}"))
                            .collect::<Vec<_>>()
                            .join("\n");
                        let mut issue = Issue::new(
                            hit.id,
                            self.id(),
                            hit.title,
                            "Tweaks & Policies",
                            hit.severity,
                            RiskScore::Medium,
                            format!(
                                "{} If this PC belongs to an organisation, ask its IT before changing it.",
                                hit.description
                            ),
                            evidence,
                            "Remove the policy values after a registry backup",
                            hit.values
                                .iter()
                                .map(|(key, name)| format!("reg delete \"{key}\" /v {name} /f"))
                                .collect(),
                        );
                        issue.is_selected = false;
                        issues.push(issue);
                    }
                }
                Err(e) => {
                    Self::send_progress(&progress_tx, 70, "Policies not checked", Some(&e)).await;
                }
            }
        }

        // 4. hosts
        Self::send_progress(
            &progress_tx,
            80,
            "Checking the hosts file...",
            Some(&format!("Reading {}...", self.hosts_path.display())),
        )
        .await;
        if let Ok(bytes) = std::fs::read(&self.hosts_path) {
            let blocks = hosts_blocks(&String::from_utf8_lossy(&bytes));
            if !blocks.is_empty() {
                let hosts: Vec<String> = blocks.iter().flat_map(|b| b.hosts.clone()).collect();
                let mut issue = Issue::new(
                    "tweak_hosts_blocks_windows",
                    self.id(),
                    format!("The hosts file blocks {} Windows endpoint(s)", hosts.len()),
                    "Tweaks & Policies",
                    Severity::Warning,
                    RiskScore::Medium,
                    "Entries in the hosts file send addresses Windows needs to a dead end: updates, the Store, activation, sign-in, the 'No internet' probe or certificate revocation checks. Privacy lists add them alongside telemetry addresses, whose blocking breaks nothing and is left alone.",
                    format!(
                        "{}:\n{}",
                        self.hosts_path.display(),
                        blocks
                            .iter()
                            .map(|b| format!("{} {}", b.address, b.hosts.join(" ")))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ),
                    "Comment out these entries after backing up the hosts file",
                    vec![
                        "Copy the hosts file to the WinMedic backup folder".to_string(),
                        format!("Comment out the entries for {}", hosts.join(", ")),
                        "ipconfig /flushdns".to_string(),
                    ],
                );
                issue.is_selected = false;
                issues.push(issue);
            }
        }

        Self::send_progress(&progress_tx, 100, "Tweak check complete", None).await;
        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        if let Some(svc) = CORE_SERVICES
            .iter()
            .find(|svc| service_issue_id(svc.name) == issue_id)
        {
            return self.fix_service(svc).await;
        }
        if issue_id.starts_with("tweak_policy_") {
            return self.fix_policy(issue_id).await;
        }
        if issue_id.starts_with(DEVICE_ID_PREFIX) {
            return self.fix_device(issue_id).await;
        }
        if issue_id == SPLIT_THRESHOLD_ID {
            return self.fix_split_threshold().await;
        }
        if issue_id == "tweak_hosts_blocks_windows" {
            let message = self.fix_hosts()?;
            let _ = self
                .runner
                .run("ipconfig.exe", &["/flushdns"], Duration::from_secs(8))
                .await;
            return Ok(message);
        }
        Err(format!("Unknown tweaks issue id: {issue_id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;
    use crate::utils::service::test_support::sc_qc_output;
    use std::path::Path;

    /// The hosts file of a real Windows 11 (its LAN address replaced).
    const HOSTS: &[u8] = include_bytes!("../../tests/fixtures/files/hosts_blocking_update.bin");

    /// `reg query` of the WindowsUpdate policy key on a real Windows 11.
    const WU_POLICY: &[u8] = include_bytes!("../../tests/fixtures/console/reg_query_wu_policy.bin");

    /// A folder under the temp directory, removed when the test ends. Seven
    /// of them were left behind by every run.
    struct Sandbox(PathBuf);

    impl std::ops::Deref for Sandbox {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sandbox(name: &str) -> Sandbox {
        let dir =
            std::env::temp_dir().join(format!("winmedic_tweaks_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox(dir)
    }

    fn module(mock: MockCommandRunner, dir: &Path, hosts: &[u8]) -> TweaksModule {
        std::fs::write(dir.join("hosts"), hosts).unwrap();
        let config = ModuleConfig {
            auto_backup_registry: false,
            ..ModuleConfig::default()
        };
        TweaksModule::with_paths(
            config,
            Arc::new(mock),
            dir.join("hosts"),
            dir.join("Registry.pol"),
            dir.join("backups"),
        )
    }

    /// Every service enabled, no policy, not in a domain.
    fn healthy(mock: &MockCommandRunner) {
        mock.add_response("PartOfDomain", CmdOutput::ok("False\r\n"));
        mock.add_response("reg.exe", CmdOutput::with_output(1, "", "FEHLER"));
        mock.add_response("sc.exe", CmdOutput::ok(sc_qc_output("x", 3)));
    }

    fn reg_output(lines: &str) -> CmdOutput {
        CmdOutput::ok(format!("\r\n{lines}\r\n\r\n"))
    }

    #[test]
    fn the_real_hosts_file_blocks_the_update_front_end_and_a_revocation_server() {
        let blocks = hosts_blocks(&decode_output(HOSTS));
        let hosts: Vec<&str> = blocks
            .iter()
            .flat_map(|b| b.hosts.iter().map(String::as_str))
            .collect();
        assert_eq!(
            hosts,
            ["ocsp.digicert.com", "fe3.delivery.mp.microsoft.com"]
        );
    }

    #[test]
    fn telemetry_blocks_are_a_choice_not_a_fault() {
        for host in [
            "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com",
            "watson.telemetry.microsoft.com",
            "browser.events.data.microsoft.com",
            "geo-prod.do.dsp.mp.microsoft.com",
            "activity.windows.com",
            "wpad.microsoft.com",
            "ocsp",
            "crlfoo.example.com",
        ] {
            assert!(!is_needed_endpoint(host), "{host}");
        }
        for host in [
            "download.windowsupdate.com",
            "sls.update.microsoft.com",
            "activation-v2.sls.microsoft.com",
            "www.msftconnecttest.com",
            "crl3.digicert.com",
            "LOGIN.LIVE.COM.",
        ] {
            assert!(is_needed_endpoint(host), "{host}");
        }
    }

    #[test]
    fn unblocking_keeps_bom_line_endings_and_other_names() {
        let original = "\u{feff}127.0.0.1 localhost\r\n0.0.0.0 fe3.delivery.mp.microsoft.com mine.example # x\r\n# comment\r\n";
        let fixed = unblock_hosts(original.as_bytes());
        assert_eq!(
            fixed,
            "\u{feff}127.0.0.1 localhost\r\n# WinMedic unblocked: 0.0.0.0 fe3.delivery.mp.microsoft.com mine.example # x\r\n0.0.0.0 mine.example\r\n# comment\r\n".as_bytes()
        );
        assert!(hosts_blocks(&String::from_utf8_lossy(&fixed)).is_empty());
    }

    #[test]
    fn unblocking_copies_every_byte_it_does_not_have_to_change() {
        // "für" with a Windows-1252 ü (0xFC), in a comment on a line that stays
        // and in one on the blocking line, next to CRLF and LF lines and with no
        // line ending at the end of the file.
        let original: &[u8] = b"# F\xFCr Updates\r\n0.0.0.0 fe3.delivery.mp.microsoft.com # f\xFCr Updates\r\n127.0.0.1 localhost\n0.0.0.0 vortex.data.microsoft.com";
        let expected: &[u8] = b"# F\xFCr Updates\r\n# WinMedic unblocked: 0.0.0.0 fe3.delivery.mp.microsoft.com # f\xFCr Updates\r\n127.0.0.1 localhost\n0.0.0.0 vortex.data.microsoft.com";
        assert_eq!(unblock_hosts(original), expected);
    }

    #[test]
    fn a_last_line_without_a_terminator_gets_the_file_newline_before_the_names_that_stay() {
        assert_eq!(
            unblock_hosts(b"127.0.0.1 localhost\r\n0.0.0.0 fe3.delivery.mp.microsoft.com mine.example"),
            b"127.0.0.1 localhost\r\n# WinMedic unblocked: 0.0.0.0 fe3.delivery.mp.microsoft.com mine.example\r\n0.0.0.0 mine.example"
        );
    }

    #[tokio::test]
    async fn a_healthy_pc_raises_nothing() {
        let dir = sandbox("healthy");
        let mock = MockCommandRunner::new();
        healthy(&mock);
        let issues = module(mock, &dir, b"127.0.0.1 localhost\r\n")
            .scan(None)
            .await
            .unwrap();
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[tokio::test]
    async fn a_disabled_core_service_is_found_and_ticked() {
        let dir = sandbox("svc");
        let mock = MockCommandRunner::new();
        mock.add_response("qc Dhcp", CmdOutput::ok(sc_qc_output("Dhcp", 4)));
        mock.add_response("qc WSearch", CmdOutput::ok(sc_qc_output("WSearch", 4)));
        healthy(&mock);
        let issues = module(mock, &dir, b"").scan(None).await.unwrap();

        let dhcp = issues.iter().find(|i| i.id == "tweak_svc_dhcp").unwrap();
        assert_eq!(dhcp.severity, Severity::Critical);
        assert!(dhcp.is_selected);
        let search = issues.iter().find(|i| i.id == "tweak_svc_wsearch").unwrap();
        assert!(!search.is_selected, "often switched off on purpose");
        assert_eq!(issues.len(), 2);
    }

    #[tokio::test]
    async fn a_service_repair_is_read_back() {
        let dir = sandbox("svcfix");
        let mock = MockCommandRunner::new();
        mock.add_response(
            "config Dhcp",
            CmdOutput::ok("[SC] ChangeServiceConfig ERFOLG"),
        );
        mock.add_response("qc Dhcp", CmdOutput::ok(sc_qc_output("Dhcp", 2)));
        mock.add_response("net.exe", CmdOutput::ok(""));
        let module = module(mock.clone(), &dir, b"");
        let msg = module.fix("tweak_svc_dhcp", None).await.unwrap();
        assert!(msg.contains("DHCP Client"), "{msg}");
        assert!(
            mock.executed()
                .iter()
                .any(|c| c == "sc.exe config Dhcp start= auto")
        );
    }

    #[tokio::test]
    async fn a_service_is_not_started_when_services_may_not_be_and_says_so() {
        let dir = sandbox("svcnostart");
        let mock = MockCommandRunner::new();
        mock.add_response(
            "config Dhcp",
            CmdOutput::ok("[SC] ChangeServiceConfig ERFOLG"),
        );
        mock.add_response("qc Dhcp", CmdOutput::ok(sc_qc_output("Dhcp", 2)));
        std::fs::write(dir.join("hosts"), b"").unwrap();
        let module = TweaksModule::with_paths(
            ModuleConfig {
                auto_backup_registry: false,
                auto_restart_services: false,
                ..ModuleConfig::default()
            },
            Arc::new(mock.clone()),
            dir.join("hosts"),
            dir.join("Registry.pol"),
            dir.join("backups"),
        );
        let msg = module.fix("tweak_svc_dhcp", None).await.unwrap();
        assert!(msg.contains("Starting it was skipped"), "{msg}");
        assert!(!mock.executed().iter().any(|c| c.starts_with("net.exe")));
    }

    #[test]
    fn policies_are_judged_by_value() {
        let wu = registry::parse_reg_query(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\r\n    WUServer    REG_SZ    http://wsus.example:8530\r\n    ExcludeWUDriversInQualityUpdate    REG_DWORD    0x1\r\n    SetDisableUXWUAccess    REG_DWORD    0x0\r\n\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\r\n    UseWUServer    REG_DWORD    0x1\r\n    NoAutoUpdate    REG_DWORD    0x1\r\n",
        );
        let hits = policy_hits(&wu, &[]);
        let ids: Vec<&str> = hits.iter().map(|h| h.id).collect();
        // SetDisableUXWUAccess is 0 and excluding drivers from updates is a
        // legitimate preference: neither is a finding.
        assert_eq!(ids, ["tweak_policy_wsus", "tweak_policy_no_auto_update"]);
    }

    #[test]
    fn a_wsus_address_without_use_wu_server_is_inert() {
        let wu = registry::parse_reg_query(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\r\n    WUServer    REG_SZ    http://wsus.example:8530\r\n",
        );
        assert!(policy_hits(&wu, &[]).is_empty());
    }

    #[test]
    fn the_real_wu_policy_key_raises_nothing() {
        // The capture machine excludes drivers from quality updates, nothing more.
        let wu = registry::parse_reg_query(&decode_output(WU_POLICY));
        assert!(policy_hits(&wu, &[]).is_empty());
        assert!(drivers_excluded_from_updates(&wu));
    }

    #[test]
    fn drivers_are_excluded_only_while_the_policy_is_on() {
        let key = |data: &str| {
            registry::parse_reg_query(&format!(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\r\n    ExcludeWUDriversInQualityUpdate    REG_DWORD    {data}\r\n"
            ))
        };
        assert!(drivers_excluded_from_updates(&key("0x1")));
        assert!(!drivers_excluded_from_updates(&key("0x0")));
        assert!(!drivers_excluded_from_updates(&[]));
    }

    /// A PC pointed at a WSUS server, with every service healthy and no
    /// Store policy; `domain` is what WMI says about membership, `None`
    /// when it does not answer.
    async fn wsus_scan(name: &str, domain: Option<&str>) -> Vec<Issue> {
        let dir = sandbox(name);
        let mock = MockCommandRunner::new();
        if let Some(answer) = domain {
            mock.add_response("PartOfDomain", CmdOutput::ok(format!("{answer}\r\n")));
        }
        mock.add_response(
            format!("query {WU_POLICY_KEY}"),
            reg_output(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\r\n    WUServer    REG_SZ    http://wsus.corp:8530\r\n\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\r\n    UseWUServer    REG_DWORD    0x1",
            ),
        );
        mock.add_response("reg.exe", CmdOutput::with_output(1, "", "FEHLER"));
        mock.add_response("sc.exe", CmdOutput::ok(sc_qc_output("x", 3)));
        module(mock, &dir, b"").scan(None).await.unwrap()
    }

    #[tokio::test]
    async fn a_standalone_pc_pointed_at_wsus_is_a_finding() {
        let issues = wsus_scan("domain_no", Some("False")).await;
        assert!(
            issues.iter().any(|i| i.id == "tweak_policy_wsus"),
            "{issues:?}"
        );
    }

    #[tokio::test]
    async fn policies_of_a_domain_are_left_alone() {
        let issues = wsus_scan("domain_yes", Some("True")).await;
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[tokio::test]
    async fn policies_are_left_alone_when_the_domain_is_unknown() {
        // This may be a company PC whose WSUS server the repair would
        // otherwise offer to delete.
        let issues = wsus_scan("domain_unknown", None).await;
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[tokio::test]
    async fn a_policy_from_local_group_policy_is_not_deleted() {
        let dir = sandbox("gpo");
        let mock = MockCommandRunner::new();
        mock.add_response(
            "query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
            reg_output(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\r\n    NoAutoUpdate    REG_DWORD    0x1",
            ),
        );
        mock.add_response("reg.exe", CmdOutput::with_output(1, "", "FEHLER"));
        let module = module(mock.clone(), &dir, b"");
        let pol: Vec<u8> = "PReg\u{1}[Software\\Policies;NoAutoUpdate]"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        std::fs::write(dir.join("Registry.pol"), pol).unwrap();

        let err = module
            .fix("tweak_policy_no_auto_update", None)
            .await
            .unwrap_err();
        assert!(err.contains("local Group Policy"), "{err}");
        assert!(!mock.executed().iter().any(|c| c.contains("delete")));
    }

    /// The captured policy key with automatic updates switched off by policy
    /// on top; `reg delete` answers `delete`.
    fn auto_updates_off(delete: CmdOutput) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            format!("query {WU_POLICY_KEY}"),
            CmdOutput::ok(format!(
                "{}HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\r\n    NoAutoUpdate    REG_DWORD    0x1\r\n\r\n",
                decode_output(WU_POLICY)
            )),
        );
        mock.add_response("reg.exe delete", delete);
        mock.add_response("reg.exe", CmdOutput::with_output(1, "", "FEHLER"));
        mock
    }

    #[tokio::test]
    async fn a_policy_repair_deletes_the_value_and_reads_back() {
        let dir = sandbox("policyfix");
        let mock = auto_updates_off(CmdOutput::ok(""));
        mock.add_response_after(
            "delete",
            format!("query {WU_POLICY_KEY}"),
            CmdOutput::ok(decode_output(WU_POLICY)),
        );
        let module = module(mock.clone(), &dir, b"");

        let msg = module
            .fix("tweak_policy_no_auto_update", None)
            .await
            .unwrap();
        assert!(msg.contains("NoAutoUpdate"), "{msg}");
        // Registry backups are off in these tests: none may be claimed.
        assert!(!msg.contains("backup"), "{msg}");
        assert!(mock.executed().contains(&format!(
            "reg.exe delete {WU_AU_POLICY_KEY} /v NoAutoUpdate /f"
        )));
    }

    #[tokio::test]
    async fn a_refused_policy_delete_is_a_failure() {
        let dir = sandbox("policydenied");
        let mock = auto_updates_off(CmdOutput::with_output(1, "", "FEHLER: Zugriff verweigert"));
        let err = module(mock, &dir, b"")
            .fix("tweak_policy_no_auto_update", None)
            .await
            .unwrap_err();
        assert!(err.contains("Zugriff verweigert"), "{err}");
    }

    #[tokio::test]
    async fn a_policy_that_is_still_set_after_the_delete_is_a_failure() {
        let dir = sandbox("policystays");
        let mock = auto_updates_off(CmdOutput::ok(""));
        let err = module(mock, &dir, b"")
            .fix("tweak_policy_no_auto_update", None)
            .await
            .unwrap_err();
        assert!(err.contains("still in effect"), "{err}");
    }

    #[tokio::test]
    async fn the_hosts_repair_backs_up_comments_out_and_reads_back() {
        let dir = sandbox("hostsfix");
        let mock = MockCommandRunner::with_default_success();
        let module = module(mock, &dir, HOSTS);

        let msg = module
            .fix("tweak_hosts_blocks_windows", None)
            .await
            .unwrap();
        assert!(msg.contains("fe3.delivery.mp.microsoft.com"), "{msg}");

        let after = std::fs::read(dir.join("hosts")).unwrap();
        assert!(
            after.starts_with(&[0xEF, 0xBB, 0xBF]),
            "byte order mark kept"
        );
        let after = String::from_utf8_lossy(&after);
        assert!(hosts_blocks(&after).is_empty());
        assert!(
            after.contains("0.0.0.0 vortex.data.microsoft.com"),
            "telemetry blocks stay"
        );
        let backups: Vec<_> = std::fs::read_dir(dir.join("backups")).unwrap().collect();
        assert_eq!(backups.len(), 1);
    }

    #[tokio::test]
    async fn the_hosts_repair_changes_only_the_blocking_lines_and_leaves_no_temp_file() {
        let dir = sandbox("hostsbytes");
        let original: &[u8] = b"# F\xFCr Updates\r\n0.0.0.0 fe3.delivery.mp.microsoft.com\r\n127.0.0.1 localhost\n# Telemetrie \xE4\xF6\xFC\r\n0.0.0.0 vortex.data.microsoft.com";
        let expected: &[u8] = b"# F\xFCr Updates\r\n# WinMedic unblocked: 0.0.0.0 fe3.delivery.mp.microsoft.com\r\n127.0.0.1 localhost\n# Telemetrie \xE4\xF6\xFC\r\n0.0.0.0 vortex.data.microsoft.com";
        let module = module(MockCommandRunner::with_default_success(), &dir, original);

        module
            .fix("tweak_hosts_blocks_windows", None)
            .await
            .unwrap();

        assert_eq!(std::fs::read(dir.join("hosts")).unwrap(), expected);
        assert!(!dir.join("hosts.winmedic-tmp").exists());
        let backups: Vec<PathBuf> = std::fs::read_dir(dir.join("backups"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read(&backups[0]).unwrap(), original);
    }

    #[tokio::test]
    async fn a_hosts_repair_that_cannot_write_says_the_file_is_unchanged() {
        let dir = sandbox("hostsnowrite");
        // The new file cannot be created while a folder has its name.
        std::fs::create_dir(dir.join("hosts.winmedic-tmp")).unwrap();
        let module = module(MockCommandRunner::with_default_success(), &dir, HOSTS);

        let err = module
            .fix("tweak_hosts_blocks_windows", None)
            .await
            .unwrap_err();

        assert!(err.contains("was not changed"), "{err}");
        assert!(
            err.contains(&dir.join("backups").display().to_string()),
            "{err}"
        );
        assert_eq!(std::fs::read(dir.join("hosts")).unwrap(), HOSTS);
    }

    #[tokio::test]
    async fn a_read_only_hosts_file_is_not_replaced_and_no_temp_file_is_left() {
        let dir = sandbox("hostsreadonly");
        let module = module(MockCommandRunner::with_default_success(), &dir, HOSTS);
        set_read_only(&dir.join("hosts"), true);

        let err = module
            .fix("tweak_hosts_blocks_windows", None)
            .await
            .unwrap_err();

        assert!(err.contains("was not changed"), "{err}");
        assert_eq!(std::fs::read(dir.join("hosts")).unwrap(), HOSTS);
        assert!(!dir.join("hosts.winmedic-tmp").exists());
        // A read-only file cannot be removed with the sandbox: clear the flags first.
        for entry in std::fs::read_dir(dir.join("backups")).unwrap() {
            set_read_only(&entry.unwrap().path(), false);
        }
        set_read_only(&dir.join("hosts"), false);
    }

    fn set_read_only(path: &Path, read_only: bool) {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(read_only);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    /// `reg query` of Defender's policy key on the capture machine: only an
    /// empty `Policy Manager` subkey.
    const DEFENDER_POLICY: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_defender_policy.bin");
    /// The Defender status query there: protection on, Defender the only
    /// antivirus.
    const DEFENDER_STATUS: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_defender_status.bin");

    /// The captured key with what debloat tools write on top.
    fn defender_switched_off() -> String {
        format!(
            "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\r\n    DisableAntiSpyware    REG_DWORD    0x1\r\n{}\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\r\n    DisableRealtimeMonitoring    REG_DWORD    0x1\r\n    DisableBehaviorMonitoring    REG_DWORD    0x0\r\n\r\n",
            decode_output(DEFENDER_POLICY).trim_end()
        )
    }

    /// The captured status with real-time protection off.
    fn defender_off_status() -> String {
        decode_output(DEFENDER_STATUS).replace("MP|True", "MP|False")
    }

    #[test]
    fn the_captured_defender_is_on_and_alone() {
        let status = parse_defender_status(&decode_output(DEFENDER_STATUS));
        assert_eq!(
            status,
            DefenderStatus {
                realtime_on: true,
                other_antivirus: Vec::new(),
            }
        );
        assert!(
            defender_policy_hit(&registry::parse_reg_query(&decode_output(DEFENDER_POLICY)))
                .is_none()
        );
    }

    #[test]
    fn another_antivirus_counts_only_while_it_is_on() {
        let status = parse_defender_status(&format!(
            "{}AV|266240|{{17AD7D40-BA12-9C46-7131-94903A54AD8B}}|Avast Antivirus\r\nAV|262144|{{00000000-0000-0000-0000-000000000001}}|Old Antivirus\r\n",
            defender_off_status()
        ));
        assert!(!status.realtime_on);
        assert_eq!(status.other_antivirus, ["Avast Antivirus"]);
        assert!(!parse_defender_status("MP|FAILED|HRESULT 0x800106ba").realtime_on);
    }

    #[test]
    fn only_values_that_switch_defender_off_are_named() {
        let hit =
            defender_policy_hit(&registry::parse_reg_query(&defender_switched_off())).unwrap();
        assert_eq!(hit.id, DEFENDER_OFF);
        assert_eq!(
            hit.values,
            [
                (DEFENDER_POLICY_KEY, "DisableAntiSpyware"),
                (DEFENDER_RTP_POLICY_KEY, "DisableRealtimeMonitoring"),
            ]
        );
    }

    /// Not in a domain, every service fine, Defender switched off by
    /// policy, the status query answering `status`.
    async fn defender_scan(name: &str, status: String) -> Vec<Issue> {
        let dir = sandbox(name);
        let mock = MockCommandRunner::new();
        mock.add_response("PartOfDomain", CmdOutput::ok("False\r\n"));
        mock.add_response(
            format!("query {DEFENDER_POLICY_KEY}"),
            CmdOutput::ok(defender_switched_off()),
        );
        mock.add_response("Get-MpComputerStatus", CmdOutput::ok(status));
        mock.add_response("reg.exe", CmdOutput::with_output(1, "", "FEHLER"));
        mock.add_response("sc.exe", CmdOutput::ok(sc_qc_output("x", 3)));
        module(mock, &dir, b"").scan(None).await.unwrap()
    }

    #[tokio::test]
    async fn defender_switched_off_with_nothing_else_is_a_finding() {
        let issues = defender_scan("defender_off", defender_off_status()).await;
        let issue = issues.iter().find(|i| i.id == DEFENDER_OFF).unwrap();
        assert_eq!(issue.severity, Severity::Critical);
        assert!(
            issue
                .technical_details
                .contains("DisableRealtimeMonitoring")
        );
    }

    #[tokio::test]
    async fn defender_policy_is_left_alone_while_something_protects() {
        // The policy is set, but real-time protection runs anyway: Tamper
        // Protection ignores such policies.
        let issues = defender_scan("defender_on", decode_output(DEFENDER_STATUS)).await;
        assert!(issues.is_empty(), "{issues:?}");
        let other = format!(
            "{}AV|266240|{{17AD7D40-BA12-9C46-7131-94903A54AD8B}}|Avast Antivirus\r\n",
            defender_off_status()
        );
        let issues = defender_scan("defender_other", other).await;
        assert!(issues.is_empty(), "{issues:?}");
    }

    /// Defender's policy is set until deleted; the status says `after` once
    /// it was.
    fn defender_repair(after: String) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            format!("query {DEFENDER_POLICY_KEY}"),
            CmdOutput::ok(defender_switched_off()),
        );
        mock.add_response_after(
            "delete",
            format!("query {DEFENDER_POLICY_KEY}"),
            CmdOutput::ok(decode_output(DEFENDER_POLICY)),
        );
        mock.add_response("Get-MpComputerStatus", CmdOutput::ok(defender_off_status()));
        mock.add_response_after("delete", "Get-MpComputerStatus", CmdOutput::ok(after));
        mock.add_response("reg.exe delete", CmdOutput::ok(""));
        mock.add_response("reg.exe", CmdOutput::with_output(1, "", "FEHLER"));
        mock
    }

    #[tokio::test]
    async fn defender_is_on_again_after_the_policy_is_gone() {
        let dir = sandbox("defender_fix");
        let mock = defender_repair(decode_output(DEFENDER_STATUS));
        let msg = module(mock.clone(), &dir, b"")
            .with_defender_wait(Duration::ZERO)
            .fix(DEFENDER_OFF, None)
            .await
            .unwrap();
        assert!(
            msg.contains("DisableAntiSpyware, DisableRealtimeMonitoring"),
            "{msg}"
        );
        let deletes: Vec<String> = mock
            .executed()
            .into_iter()
            .filter(|c| c.starts_with("reg.exe delete"))
            .collect();
        assert_eq!(deletes.len(), 2, "{deletes:?}");
    }

    #[tokio::test]
    async fn defender_that_stays_off_is_a_failure() {
        let dir = sandbox("defender_stays");
        let mock = defender_repair(defender_off_status());
        let err = module(mock, &dir, b"")
            .with_defender_wait(Duration::ZERO)
            .fix(DEFENDER_OFF, None)
            .await
            .unwrap_err();
        assert!(err.contains("still off"), "{err}");
    }

    #[tokio::test]
    async fn the_defender_script_parses() {
        assert_eq!(
            crate::utils::cmd::powershell_parse_errors(DEFENDER_STATUS_SCRIPT).await,
            0
        );
    }

    const HPET: &str = r"ACPI\PNP0103\2&DABA3FF&0";
    const HVSERVICE: &str = r"ROOT\HVSERVICE\0000";
    const NDIS_BUS: &str = r"ROOT\NDISVIRTUALBUS\0000";

    fn pnp(problem: u32, instance_id: &str, name: &str) -> PnpDevice {
        PnpDevice {
            problem,
            class: "System".to_string(),
            instance_id: instance_id.to_string(),
            name: name.to_string(),
        }
    }

    /// The development PC's devices with a problem as SetupAPI listed them
    /// on 2026-10-09 - HPET and the NDIS enumerator disabled, two devices
    /// without a driver - with the Microsoft Hypervisor Service reporting
    /// `hvservice`: 22 until it was enabled on 2026-10-08, 0 since.
    fn dev_pc(hvservice: u32) -> Vec<PnpDevice> {
        vec![
            pnp(22, HPET, "Hochpräzisionsereigniszeitgeber"),
            pnp(hvservice, HVSERVICE, "Microsoft-Hypervisor-Dienst"),
            pnp(
                28,
                r"USB\VID_046D&PID_0943&MI_05\9&B24F85A&0&0005",
                "Brio 500",
            ),
            pnp(
                22,
                NDIS_BUS,
                "Enumerator für virtuelle NDIS-Netzwerkadapter",
            ),
            pnp(28, r"ACPI\AMDI0204\2&DABA3FF&0", ""),
        ]
    }

    fn device_findings(issues: &[Issue]) -> Vec<&Issue> {
        issues
            .iter()
            .filter(|i| i.id.starts_with(DEVICE_ID_PREFIX))
            .collect()
    }

    #[test]
    fn instance_ids_match_a_hardware_id_in_any_case() {
        for id in [
            HVSERVICE,
            r"ROOT\hvservice\0000",
            HPET,
            r"acpi\pnp0103\0",
            NDIS_BUS,
            r"ROOT\NdisVirtualBus\0000",
        ] {
            assert!(core_device(id).is_some(), "{id}");
        }
        for id in [
            r"ROOT\HVSERVICEX\0000",
            r"ROOT\HVSERVICE",
            r"ROOT\HVSERVICE\",
            r"ACPI\PNP0103",
            r"ACPI\PNP01030\0",
            r"SWD\ROOT\HVSERVICE\0000",
            r"USB\VID_046D&PID_0943&MI_05\9&B24F85A&0&0005",
            "",
        ] {
            assert!(core_device(id).is_none(), "{id}");
        }
    }

    /// Every entry fires for its device while it is disabled, and for no
    /// other problem: a device that stopped or has no driver is the Devices
    /// & Drivers check's.
    #[test]
    fn every_entry_fires_only_while_its_device_is_disabled() {
        let dir = sandbox("device_entries");
        let module = module(MockCommandRunner::new(), &dir, b"");
        for entry in CORE_DEVICES {
            let id = format!("{}\\0000", entry.hardware_id);
            let issue = module.device_issue(&pnp(22, &id, "x")).unwrap();
            assert_eq!(issue.title, format!("'{}' is disabled", entry.display));
            assert_eq!(issue.is_selected, entry.known_fault, "{id}");
            for problem in [0, 10, 28, 45] {
                assert!(module.device_issue(&pnp(problem, &id, "x")).is_none());
            }
        }
    }

    /// Only an entry whose fault has been seen starts ticked; the others are
    /// hints that claim nothing.
    #[test]
    fn only_entries_with_a_known_fault_are_ticked_warnings() {
        for entry in CORE_DEVICES {
            assert_eq!(entry.known_fault, entry.breaks != NO_KNOWN_FAULT);
        }
        let known: Vec<&str> = CORE_DEVICES
            .iter()
            .filter(|entry| entry.known_fault)
            .map(|entry| entry.hardware_id)
            .collect();
        assert_eq!(known, [r"ROOT\HVSERVICE"]);
    }

    async fn scan_devices(devices: Vec<PnpDevice>) -> Vec<Issue> {
        let dir = sandbox("devices_scan");
        let mock = MockCommandRunner::new();
        healthy(&mock);
        mock.set_devices(devices);
        module(mock, &dir, b"").scan(None).await.unwrap()
    }

    #[tokio::test]
    async fn the_devices_a_tuning_tool_disabled_are_found() {
        let issues = scan_devices(dev_pc(22)).await;
        let found = device_findings(&issues);
        assert_eq!(found.len(), 3, "{found:?}");

        let hv = found
            .iter()
            .find(|i| i.id == device_issue_id(HVSERVICE))
            .unwrap();
        assert_eq!(hv.title, "'Microsoft Hypervisor Service' is disabled");
        assert_eq!(hv.severity, Severity::Warning);
        assert!(hv.is_selected && !hv.advice_only && !hv.requires_reboot);
        assert!(
            hv.description.contains("Windows Sandbox"),
            "{}",
            hv.description
        );
        assert!(hv.technical_details.contains(HVSERVICE));

        for id in [HPET, NDIS_BUS] {
            let hint = found.iter().find(|i| i.id == device_issue_id(id)).unwrap();
            assert_eq!(hint.severity, Severity::Info);
            assert!(!hint.is_selected, "{id}");
            assert!(hint.description.ends_with(NO_KNOWN_FAULT));
        }
    }

    /// The development PC today: the Hypervisor Service works again, HPET
    /// and the NDIS enumerator are still disabled.
    #[tokio::test]
    async fn an_enabled_device_is_not_a_finding() {
        let issues = scan_devices(dev_pc(0)).await;
        let ids: Vec<String> = device_findings(&issues)
            .iter()
            .map(|i| i.id.clone())
            .collect();
        assert_eq!(ids, [device_issue_id(HPET), device_issue_id(NDIS_BUS)]);
    }

    /// Devices & Drivers leaves every disabled device alone, so none of
    /// these is reported twice.
    #[tokio::test]
    async fn the_devices_check_does_not_report_them_too() {
        use crate::modules::devices::{DevicesModule, Remedy, remedy};
        assert_eq!(remedy(DEVICE_DISABLED), Remedy::None);
        let mock = MockCommandRunner::new();
        mock.set_devices(dev_pc(22));
        let issues = DevicesModule::with_runner(Arc::new(mock))
            .scan(None)
            .await
            .unwrap();
        for id in [HVSERVICE, HPET, NDIS_BUS] {
            assert!(
                !issues.iter().any(|i| i.technical_details.contains(id)),
                "{id}: {issues:?}"
            );
        }
    }

    #[test]
    fn the_dry_run_lists_the_backup_the_enable_and_the_check() {
        let dir = sandbox("device_steps");
        let hv = pnp(22, HVSERVICE, "Microsoft-Hypervisor-Dienst");
        let steps = module(MockCommandRunner::new(), &dir, b"")
            .device_issue(&hv)
            .unwrap()
            .fix_steps;
        assert_eq!(
            steps,
            [
                format!(
                    "Run Enable-PnpDevice -InstanceId '{HVSERVICE}' -Confirm:$false -ErrorAction Stop (Device Manager: Enable device)"
                ),
                "Check that the device no longer reports a problem".to_string(),
            ]
        );
        let steps = backing_up(MockCommandRunner::new(), &dir)
            .device_issue(&hv)
            .unwrap()
            .fix_steps;
        assert_eq!(
            steps[0],
            format!(
                r"Back up ConfigFlags of HKLM\SYSTEM\CurrentControlSet\Enum\{HVSERVICE} to the registry backups"
            )
        );
        assert_eq!(steps.len(), 3);
    }

    #[tokio::test]
    async fn the_enable_script_parses() {
        assert_eq!(
            crate::utils::cmd::powershell_parse_errors(&enable_device_script(HPET)).await,
            0
        );
    }

    /// `reg query ... /v ConfigFlags` of the development PC's HPET, disabled.
    const CONFIG_FLAGS_DISABLED: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_enum_configflags_disabled.bin");
    /// `Enable-PnpDevice` refusing a device it cannot find: exit 1 and a
    /// German message on stderr.
    const ENABLE_REFUSED: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_enable_pnpdevice_not_found_de.bin");
    /// `pnputil /enable-device` of a device disabled since Windows started:
    /// exit 1167, "Das Gerät ist nicht angeschlossen".
    const PNPUTIL_REFUSED: &[u8] = include_bytes!(
        "../../tests/fixtures/console/pnputil_enable_device_disabled_since_boot_de.bin"
    );

    /// The module with registry backups on, into `dir\backups`.
    fn backing_up(mock: MockCommandRunner, dir: &Path) -> TweaksModule {
        std::fs::write(dir.join("hosts"), b"").unwrap();
        TweaksModule::with_paths(
            ModuleConfig {
                auto_backup_registry: true,
                ..ModuleConfig::default()
            },
            Arc::new(mock),
            dir.join("hosts"),
            dir.join("Registry.pol"),
            dir.join("backups"),
        )
    }

    /// The development PC with HPET disabled until `Enable-PnpDevice` ran,
    /// which answers `enable` and leaves HPET reporting `after`.
    fn hpet_repair(enable: CmdOutput, after: u32) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.set_devices(dev_pc(0));
        mock.add_response(
            "/v ConfigFlags",
            CmdOutput::ok(decode_output(CONFIG_FLAGS_DISABLED)),
        );
        mock.add_response("Enable-PnpDevice", enable);
        let devices = dev_pc(0)
            .into_iter()
            .map(|d| {
                if d.instance_id == HPET {
                    pnp(after, HPET, &d.name)
                } else {
                    d
                }
            })
            .collect();
        mock.set_devices_after("Enable-PnpDevice", devices);
        mock
    }

    #[tokio::test]
    async fn a_disabled_device_is_backed_up_enabled_and_read_back() {
        let dir = sandbox("device_fix");
        let mock = hpet_repair(CmdOutput::ok(""), 0);
        let msg = backing_up(mock.clone(), &dir)
            .fix(&device_issue_id(HPET), None)
            .await
            .unwrap();
        assert!(
            msg.starts_with("'High Precision Event Timer' is enabled again and works."),
            "{msg}"
        );
        assert!(msg.contains("registry backups"), "{msg}");

        let executed = mock.executed();
        let at = |what: &str| executed.iter().position(|c| c.contains(what)).unwrap();
        assert!(
            at("/v ConfigFlags") < at("Enable-PnpDevice"),
            "{executed:?}"
        );
        assert!(executed[at("Enable-PnpDevice")].contains(&format!("-InstanceId '{HPET}'")));

        let backup = RegBackupManager::with_dir(dir.join("backups")).list_backups();
        assert_eq!(backup.len(), 1);
        assert_eq!(backup[0].key_path, format!(r"{ENUM_KEY}\{HPET}"));
        let bytes = std::fs::read(&backup[0].file_path).unwrap();
        let text = String::from_utf16(
            &bytes[2..]
                .chunks(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(text.contains("\"ConfigFlags\"=dword:00000001"), "{text}");
    }

    #[tokio::test]
    async fn a_refused_enable_leaves_the_finding_open() {
        let dir = sandbox("device_refused");
        let refused = CmdOutput::with_output(1, "", decode_output(ENABLE_REFUSED));
        let err = module(hpet_repair(refused, 22), &dir, b"")
            .fix(&device_issue_id(HPET), None)
            .await
            .unwrap_err();
        assert!(
            err.starts_with(
                "Windows did not enable 'High Precision Event Timer'; it is still disabled."
            ),
            "{err}"
        );
        assert!(
            err.contains("CmdletizationQuery_NotFound_DeviceID"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_device_that_starts_only_after_a_restart_says_so() {
        let dir = sandbox("device_restart");
        let err = module(hpet_repair(CmdOutput::ok(""), NEEDS_RESTART), &dir, b"")
            .fix(&device_issue_id(HPET), None)
            .await
            .unwrap_err();
        assert!(err.contains("Restart Windows"), "{err}");

        let err = module(hpet_repair(CmdOutput::ok(""), 10), &dir, b"")
            .fix(&device_issue_id(HPET), None)
            .await
            .unwrap_err();
        assert!(err.contains("problem code 10: it cannot start"), "{err}");
    }

    #[tokio::test]
    async fn without_a_backup_nothing_is_enabled() {
        let dir = sandbox("device_nobackup");
        let mock = MockCommandRunner::new();
        mock.set_devices(dev_pc(22));
        mock.add_response(
            "/v ConfigFlags",
            CmdOutput::with_output(1, "", "FEHLER: Zugriff verweigert"),
        );
        let err = backing_up(mock.clone(), &dir)
            .fix(&device_issue_id(HVSERVICE), None)
            .await
            .unwrap_err();
        assert!(err.starts_with("Aborted:"), "{err}");
        assert!(
            !mock
                .executed()
                .iter()
                .any(|c| c.contains("Enable-PnpDevice"))
        );
    }

    #[tokio::test]
    async fn a_device_enabled_since_the_scan_is_left_alone() {
        let dir = sandbox("device_gone");
        let mock = MockCommandRunner::new();
        mock.set_devices(dev_pc(0));
        let module = module(mock.clone(), &dir, b"");
        let msg = module.fix(&device_issue_id(HVSERVICE), None).await.unwrap();
        assert!(msg.contains("no longer disabled"), "{msg}");
        mock.set_devices(Vec::new());
        let msg = module.fix(&device_issue_id(HVSERVICE), None).await.unwrap();
        assert!(msg.contains("no longer connected"), "{msg}");
        assert!(mock.executed().is_empty(), "{:?}", mock.executed());
    }

    /// The memory Windows reported on the development PC on 2026-10-09
    /// (`TotalPhysicalMemory`): 33119136 KB of the 32 GB installed.
    const DEV_PC_RAM: u64 = 33_913_995_264;
    /// The value the tuning tool had left there: exactly the installed 32 GB.
    const TUNED_THRESHOLD: u64 = 33_554_432;

    #[test]
    fn services_stay_grouped_only_above_the_memory_windows_has() {
        assert!(keeps_services_grouped(TUNED_THRESHOLD, DEV_PC_RAM));
        assert!(!keeps_services_grouped(
            DEFAULT_SPLIT_THRESHOLD_KB,
            DEV_PC_RAM
        ));
        // Windows Sandbox has 0 there and 4 GB: every service on its own.
        assert!(!keeps_services_grouped(0, 4_293_857_280));
        assert!(!keeps_services_grouped(DEV_PC_RAM / 1024, DEV_PC_RAM));
    }

    /// `reg query` of the threshold as captured (3.5 GB), or with `kb`.
    fn split_threshold_output(kb: u64) -> CmdOutput {
        CmdOutput::ok(
            decode_output(include_bytes!(
                "../../tests/fixtures/console/reg_query_svchost_split_threshold.bin"
            ))
            .replace("0x380000", &format!("{kb:#x}")),
        )
    }

    async fn scan_split_threshold(answer: CmdOutput) -> Vec<Issue> {
        let dir = sandbox("split_scan");
        let mock = MockCommandRunner::new();
        mock.add_response("/v SvcHostSplitThresholdInKB", answer);
        healthy(&mock);
        module(mock, &dir, b"")
            .with_ram(Arc::new(|| DEV_PC_RAM))
            .scan(None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_threshold_above_the_memory_is_an_unticked_finding_that_needs_a_restart() {
        let issues = scan_split_threshold(split_threshold_output(TUNED_THRESHOLD)).await;
        assert_eq!(issues.len(), 1, "{issues:?}");
        let issue = &issues[0];
        assert_eq!(issue.id, SPLIT_THRESHOLD_ID);
        assert_eq!(issue.risk_score, RiskScore::High);
        assert!(issue.requires_reboot && !issue.is_selected);
        assert!(
            issue
                .description
                .starts_with("SvcHostSplitThresholdInKB is 32.0 GB, more than the 31.6 GB"),
            "{}",
            issue.description
        );
    }

    #[tokio::test]
    async fn the_default_threshold_or_none_is_not_a_finding() {
        for answer in [
            split_threshold_output(DEFAULT_SPLIT_THRESHOLD_KB),
            split_threshold_output(0),
            // Not set: the captured answer for a missing value.
            CmdOutput::with_output(1, "\r\n\r\n", "FEHLER"),
        ] {
            let issues = scan_split_threshold(answer).await;
            assert!(issues.is_empty(), "{issues:?}");
        }
    }

    const QUERY_THRESHOLD: &str =
        r"reg.exe query HKLM\SYSTEM\CurrentControlSet\Control /v SvcHostSplitThresholdInKB";

    /// Tuned until `reg add` ran, which answers `add`, then `after`.
    fn split_repair(add: CmdOutput, after: u64) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("reg.exe add", add);
        mock.add_response(QUERY_THRESHOLD, split_threshold_output(TUNED_THRESHOLD));
        mock.add_response_after(
            "reg.exe add",
            QUERY_THRESHOLD,
            split_threshold_output(after),
        );
        mock
    }

    #[tokio::test]
    async fn the_threshold_is_backed_up_reset_and_read_back() {
        let dir = sandbox("split_fix");
        let mock = split_repair(CmdOutput::ok(""), DEFAULT_SPLIT_THRESHOLD_KB);
        let msg = backing_up(mock.clone(), &dir)
            .with_ram(Arc::new(|| DEV_PC_RAM))
            .fix(SPLIT_THRESHOLD_ID, None)
            .await
            .unwrap();
        assert!(msg.contains("Restart Windows"), "{msg}");
        assert!(mock.executed().contains(&format!(
            r"reg.exe add {CONTROL_KEY} /v SvcHostSplitThresholdInKB /t REG_DWORD /d 3670016 /f"
        )));
        let backups = RegBackupManager::with_dir(dir.join("backups")).list_backups();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].key_path, CONTROL_KEY);
    }

    #[tokio::test]
    async fn a_threshold_that_does_not_change_is_a_failure() {
        let dir = sandbox("split_refused");
        let refused = CmdOutput::with_output(1, "", "FEHLER: Zugriff verweigert");
        let err = module(split_repair(refused, TUNED_THRESHOLD), &dir, b"")
            .with_ram(Arc::new(|| DEV_PC_RAM))
            .fix(SPLIT_THRESHOLD_ID, None)
            .await
            .unwrap_err();
        assert!(err.contains("Zugriff verweigert"), "{err}");

        let err = module(split_repair(CmdOutput::ok(""), TUNED_THRESHOLD), &dir, b"")
            .with_ram(Arc::new(|| DEV_PC_RAM))
            .fix(SPLIT_THRESHOLD_ID, None)
            .await
            .unwrap_err();
        assert!(err.contains("reads 33554432"), "{err}");
    }

    #[tokio::test]
    async fn a_threshold_reset_meanwhile_is_left_alone_and_a_failed_backup_changes_nothing() {
        let dir = sandbox("split_left");
        let mock = MockCommandRunner::new();
        mock.add_response(
            "/v SvcHostSplitThresholdInKB",
            split_threshold_output(DEFAULT_SPLIT_THRESHOLD_KB),
        );
        let msg = module(mock.clone(), &dir, b"")
            .with_ram(Arc::new(|| DEV_PC_RAM))
            .fix(SPLIT_THRESHOLD_ID, None)
            .await
            .unwrap();
        assert!(msg.contains("nothing to change"), "{msg}");

        // The backup reads the value again; this time nobody answers.
        let mock = MockCommandRunner::new();
        mock.add_response(
            "/v SvcHostSplitThresholdInKB",
            split_threshold_output(TUNED_THRESHOLD),
        );
        mock.add_response_after(
            "/v SvcHostSplitThresholdInKB",
            "/v SvcHostSplitThresholdInKB",
            CmdOutput::failed(1, "FEHLER"),
        );
        let err = backing_up(mock.clone(), &dir)
            .with_ram(Arc::new(|| DEV_PC_RAM))
            .fix(SPLIT_THRESHOLD_ID, None)
            .await
            .unwrap_err();
        assert!(err.starts_with("Aborted:"), "{err}");
        assert!(!mock.executed().iter().any(|c| c.contains("reg.exe add")));
    }

    /// pnputil refused the development PC's Microsoft Hypervisor Service on
    /// 2026-10-08, and in Windows Sandbox it refused the NDIS enumerator once
    /// it had been disabled across a restart. The repair does not ask it.
    #[tokio::test]
    async fn the_repair_does_not_rely_on_pnputil() {
        let refused = decode_output(PNPUTIL_REFUSED);
        assert!(refused.contains(r"ROOT\NdisVirtualBus\0000"), "{refused}");
        let dir = sandbox("device_pnputil");
        let mock = hpet_repair(CmdOutput::ok(""), 0);
        mock.add_response("pnputil.exe", CmdOutput::with_output(1167, refused, ""));
        module(mock.clone(), &dir, b"")
            .fix(&device_issue_id(HPET), None)
            .await
            .unwrap();
        assert!(!mock.executed().iter().any(|c| c.contains("pnputil")));
    }
}
