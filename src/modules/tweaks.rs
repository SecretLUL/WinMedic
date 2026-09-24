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
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::safety::reg_backup::RegBackupManager;
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::registry::{self, RegKeyValues};
use crate::utils::service::{self, SERVICE_DISABLED};
use std::path::PathBuf;
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

const WU_POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
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
        .filter_map(|(line, text)| {
            let text = text.trim_start_matches('\u{feff}');
            let content = text.split('#').next().unwrap_or("");
            let mut fields = content.split_whitespace();
            let address = fields.next()?.to_string();
            let (hosts, others): (Vec<String>, Vec<String>) = fields
                .map(str::to_string)
                .partition(|h| is_needed_endpoint(h));
            (!hosts.is_empty()).then_some(HostsBlock {
                line,
                address,
                hosts,
                others,
            })
        })
        .collect()
}

/// `hosts` with every blocking line commented out, keeping its byte order
/// mark, its line endings and every other name on the line.
pub fn unblock_hosts(hosts: &str) -> String {
    let blocks = hosts_blocks(hosts);
    let newline = if hosts.contains("\r\n") { "\r\n" } else { "\n" };
    let bom = if hosts.starts_with('\u{feff}') {
        "\u{feff}"
    } else {
        ""
    };
    let body = hosts.trim_start_matches('\u{feff}');
    let ends_with_newline = body.ends_with('\n');

    let mut lines: Vec<String> = Vec::new();
    for (index, line) in body.lines().enumerate() {
        match blocks.iter().find(|b| b.line == index) {
            Some(block) => {
                lines.push(format!("# WinMedic unblocked: {}", line.trim_end()));
                if !block.others.is_empty() {
                    lines.push(format!("{} {}", block.address, block.others.join(" ")));
                }
            }
            None => lines.push(line.to_string()),
        }
    }
    let mut out = format!("{bom}{}", lines.join(newline));
    if ends_with_newline {
        out.push_str(newline);
    }
    out
}

pub struct TweaksModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
    hosts_path: PathBuf,
    local_policy_path: PathBuf,
    backup_dir: PathBuf,
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
        }
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
        Ok(policy_hits(&wu, &store))
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
        Ok(format!(
            "Removed {} policy value(s): {}. A registry backup was taken first.",
            hit.values.len(),
            hit.values
                .iter()
                .map(|(_, name)| *name)
                .collect::<Vec<_>>()
                .join(", ")
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
        if svc.restore != StartMode::Demand && self.config.auto_restart_services {
            let _ = self
                .runner
                .run("net.exe", &["start", svc.name], Duration::from_secs(20))
                .await;
        }
        Ok(format!(
            "'{}' is set to start {} again.",
            svc.display,
            svc.restore.label()
        ))
    }

    fn fix_hosts(&self) -> Result<String, String> {
        let bytes = std::fs::read(&self.hosts_path)
            .map_err(|e| format!("Could not read {}: {e}", self.hosts_path.display()))?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let blocks = hosts_blocks(&text);
        if blocks.is_empty() {
            return Ok("The hosts file no longer blocks any Windows endpoint.".to_string());
        }

        std::fs::create_dir_all(&self.backup_dir).map_err(|e| e.to_string())?;
        let backup = self.backup_dir.join(format!(
            "hosts_{}.bak",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        ));
        std::fs::copy(&self.hosts_path, &backup).map_err(|e| {
            format!("Aborted: the hosts file could not be backed up ({e}). Nothing was changed.")
        })?;

        std::fs::write(&self.hosts_path, unblock_hosts(&text)).map_err(|e| {
            format!(
                "Could not write {} ({e}). Antivirus software often protects it; the original is unchanged.",
                self.hosts_path.display()
            )
        })?;

        let after = std::fs::read(&self.hosts_path).map_err(|e| e.to_string())?;
        if !hosts_blocks(&String::from_utf8_lossy(&after)).is_empty() {
            return Err(
                "The hosts file was written but still blocks Windows endpoints.".to_string(),
            );
        }
        let unblocked: Vec<String> = blocks.into_iter().flat_map(|b| b.hosts).collect();
        Ok(format!(
            "Unblocked {} in the hosts file; the old file is saved as {}.",
            unblocked.join(", "),
            backup.display()
        ))
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
        "Finds what tweak and debloat tools leave behind: disabled core services, update and Store policies, and hosts entries that block Windows"
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
            40,
            "Core services checked",
            Some(&format!(
                "{} of {} core services disabled.",
                disabled,
                CORE_SERVICES.len()
            )),
        )
        .await;

        // 2. Policies
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

        // 3. hosts
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

    fn sandbox(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("winmedic_tweaks_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
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
        let fixed = unblock_hosts(original);
        assert_eq!(
            fixed,
            "\u{feff}127.0.0.1 localhost\r\n# WinMedic unblocked: 0.0.0.0 fe3.delivery.mp.microsoft.com mine.example # x\r\n0.0.0.0 mine.example\r\n# comment\r\n"
        );
        assert!(hosts_blocks(&fixed).is_empty());
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
        let wu = registry::parse_reg_query(&decode_output(include_bytes!(
            "../../tests/fixtures/console/reg_query_wu_policy.bin"
        )));
        assert!(policy_hits(&wu, &[]).is_empty());
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
        let _ = std::fs::remove_dir_all(&dir);
    }
}
