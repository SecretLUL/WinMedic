//! Page file and virtual memory diagnostics.
//!
//! A page file the user sized deliberately is a legitimate configuration rather
//! than damage, and the changes that would correct one take effect only after a
//! restart. Both point the same way: every finding here is `RiskScore::High`
//! and deselected by default, so `--auto-fix` never rewrites virtual memory
//! settings unattended. The nearly-full-drive finding goes further and changes
//! nothing at all — which files to delete is not WinMedic's decision to make.
//!
//! The numbers come from CIM rather than from the registry. `Win32_PageFileUsage`
//! reports what the running system actually has, which is the only source that
//! distinguishes "no page file" from "a page file Windows is managing for you" —
//! a distinction the `PagingFiles` registry value cannot make.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::system_cleaner::format_bytes;
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner, ps_single_quoted};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

/// `AutomaticManagedPagefile|TotalPhysicalMemory` — a flag and a byte count.
const COMPUTER_SYSTEM_SCRIPT: &str = concat!(
    "Get-CimInstance -ClassName Win32_ComputerSystem | ForEach-Object { ",
    r#""$($_.AutomaticManagedPagefile)|$($_.TotalPhysicalMemory)" }"#,
);

/// The page files the running system actually has. Empty output means none.
const PAGE_FILE_USAGE_SCRIPT: &str = concat!(
    "Get-CimInstance -ClassName Win32_PageFileUsage | ForEach-Object { ",
    r#""$($_.Name)|$($_.AllocatedBaseSize)|$($_.CurrentUsage)|$($_.PeakUsage)" }"#,
);

/// Only page files with a *manually* set size appear here; a system-managed one
/// has no `Win32_PageFileSetting` instance at all.
const PAGE_FILE_SETTING_SCRIPT: &str = concat!(
    "Get-CimInstance -ClassName Win32_PageFileSetting | ForEach-Object { ",
    r#""$($_.Name)|$($_.InitialSize)|$($_.MaximumSize)" }"#,
);

/// Fixed local disks only (`DriveType=3`); a page file cannot live on a network
/// drive, and removable media is not a case worth reporting on.
const LOGICAL_DISK_SCRIPT: &str = concat!(
    "Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { ",
    r#""$($_.DeviceID)|$($_.Size)|$($_.FreeSpace)" }"#,
);

/// Below this, running without a page file reliably ends in out-of-memory
/// terminations rather than merely losing crash dumps.
const LOW_RAM_MB: u64 = 8192;

/// The floor for a manually sized page file, whatever the RAM size suggests.
const MIN_RECOMMENDED_PAGE_FILE_MB: u64 = 1024;

/// A volume this close to full cannot absorb a page file growing under load.
const CRITICAL_FREE_MB: u64 = 512;
const LOW_FREE_MB: u64 = 2048;
const LOW_FREE_PERCENT: f64 = 10.0;

/// Without the RAM size and the management flag nothing else can be judged, so
/// this is the one probe whose *failure* fails the module.
const CONFIG_UNREADABLE: &str = "The virtual memory configuration could not be read";

/// A query that ran and reported nothing is a different case from one that
/// failed, and neither may be reported as a clean bill of health.
const CONFIG_EMPTY: &str =
    "Win32_ComputerSystem returned no data — nothing was judged against an unknown RAM size.";

/// Stands in for a PowerShell failure that carried no stderr of its own.
const NO_DETAIL: &str = "PowerShell reported no detail";

/// Confirmation for the one repair that changes a machine-wide setting.
const ENABLED_MESSAGE: &str =
    "Automatic page file management enabled. Windows creates the page file on the next restart.";

fn mb_to_bytes(mb: u64) -> u64 {
    mb.saturating_mul(1024 * 1024)
}

/// Whether the machine leaves virtual memory to Windows, and how much RAM it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemoryFacts {
    automatic_managed: bool,
    ram_mb: u64,
}

/// An active page file, as the running system reports it. Sizes are megabytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PageFileUsage {
    name: String,
    allocated_mb: u64,
    current_mb: u64,
    peak_mb: u64,
}

/// A manually configured page file size. Sizes are megabytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PageFileSetting {
    name: String,
    initial_mb: u64,
    maximum_mb: u64,
}

/// A fixed local volume's capacity. Sizes are bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VolumeSpace {
    device_id: String,
    size_bytes: u64,
    free_bytes: u64,
}

pub struct PageFileModule {
    runner: Arc<dyn CommandRunner>,
}

impl Default for PageFileModule {
    fn default() -> Self {
        Self::new()
    }
}

impl PageFileModule {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
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
                    module_id: "page_file".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }

    /// The drive letter a `C:\pagefile.sys` style path lives on, lowercased.
    ///
    /// A path this module cannot attribute to a drive is skipped rather than
    /// guessed at, because the drive letter is what every later lookup and the
    /// repair command key on.
    fn drive_letter(path: &str) -> Option<char> {
        let mut chars = path.trim().chars();
        let letter = chars.next()?;
        if chars.next()? != ':' || !letter.is_ascii_alphabetic() {
            return None;
        }
        Some(letter.to_ascii_lowercase())
    }

    fn parse_memory_facts(stdout: &str) -> Option<MemoryFacts> {
        let line = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
        let (managed_raw, ram_raw) = line.split_once('|')?;

        Some(MemoryFacts {
            automatic_managed: managed_raw.trim().eq_ignore_ascii_case("true"),
            ram_mb: ram_raw.trim().parse::<u64>().unwrap_or(0) / (1024 * 1024),
        })
    }

    fn parse_usage(stdout: &str) -> Vec<PageFileUsage> {
        stdout
            .lines()
            .filter_map(|line| {
                let mut fields = line.trim().splitn(4, '|');
                let name = fields.next()?.trim().to_string();
                if name.is_empty() {
                    return None;
                }
                Some(PageFileUsage {
                    name,
                    allocated_mb: fields.next()?.trim().parse().unwrap_or(0),
                    current_mb: fields.next()?.trim().parse().unwrap_or(0),
                    peak_mb: fields.next()?.trim().parse().unwrap_or(0),
                })
            })
            .collect()
    }

    fn parse_settings(stdout: &str) -> Vec<PageFileSetting> {
        stdout
            .lines()
            .filter_map(|line| {
                let mut fields = line.trim().splitn(3, '|');
                let name = fields.next()?.trim().to_string();
                if name.is_empty() {
                    return None;
                }
                Some(PageFileSetting {
                    initial_mb: fields.next()?.trim().parse().unwrap_or(0),
                    maximum_mb: fields.next()?.trim().parse().unwrap_or(0),
                    name,
                })
            })
            .collect()
    }

    fn parse_volumes(stdout: &str) -> Vec<VolumeSpace> {
        stdout
            .lines()
            .filter_map(|line| {
                let mut fields = line.trim().splitn(3, '|');
                let device_id = fields.next()?.trim().to_string();
                if device_id.is_empty() {
                    return None;
                }
                let size_bytes = fields.next()?.trim().parse().unwrap_or(0);
                let free_bytes = fields.next()?.trim().parse().unwrap_or(0);
                // A volume reporting no capacity says nothing about free space.
                if size_bytes == 0 {
                    return None;
                }
                Some(VolumeSpace {
                    device_id,
                    size_bytes,
                    free_bytes,
                })
            })
            .collect()
    }

    /// The smallest maximum size worth having on a machine with `ram_mb` of RAM.
    ///
    /// An eighth of physical memory is the size Windows itself starts from for
    /// a system-managed file, with a floor so that a low-RAM machine does not
    /// end up with a maximum too small to hold anything.
    fn recommended_min_page_file_mb(ram_mb: u64) -> u64 {
        (ram_mb / 8).max(MIN_RECOMMENDED_PAGE_FILE_MB)
    }

    /// Run one probe and return its stdout.
    ///
    /// A query that *ran* and matched no instances is not an error — that is
    /// exactly how "this machine has no manually sized page file" looks. Only a
    /// query that could not be executed at all is reported as one, so the
    /// caller can tell the two apart instead of reading both as "nothing found".
    async fn probe(&self, script: &str) -> Result<String, String> {
        let out = self
            .runner
            .run_powershell(script, Duration::from_secs(20))
            .await?;

        if !out.success && out.stdout.trim().is_empty() {
            let detail = out.stderr.trim();
            let detail = if detail.is_empty() { NO_DETAIL } else { detail };
            return Err(detail.to_string());
        }
        Ok(out.stdout)
    }

    /// Hand a volume's page file back to Windows by clearing both sizes.
    ///
    /// `InitialSize = MaximumSize = 0` is how Win32_PageFileSetting spells
    /// "system managed". The drive letter is validated by the caller and still
    /// goes through [`ps_single_quoted`], because this runs elevated.
    async fn set_system_managed(&self, drive: char) -> Result<String, String> {
        let script = format!(
            "Get-CimInstance -ClassName Win32_PageFileSetting | Where-Object {{ $_.Name -like {} }} | ForEach-Object {{ Set-CimInstance -InputObject $_ -Property @{{InitialSize=0; MaximumSize=0}} -ErrorAction Stop }}",
            ps_single_quoted(&format!("{}:*", drive.to_ascii_uppercase()))
        );

        let out = self
            .runner
            .run_powershell(&script, Duration::from_secs(30))
            .await?;

        if out.success {
            return Ok(format!(
                "Page file on {}: handed back to Windows (system managed). The change takes effect after a restart.",
                drive.to_ascii_uppercase()
            ));
        }

        let detail = out.stderr.trim();
        let detail = if detail.is_empty() { NO_DETAIL } else { detail };
        Err(format!(
            "Could not reset the page file on {}: {}",
            drive.to_ascii_uppercase(),
            detail
        ))
    }

    /// Let Windows manage virtual memory across every volume again.
    async fn enable_automatic_management(&self) -> Result<String, String> {
        let script = "Get-CimInstance -ClassName Win32_ComputerSystem | ForEach-Object { Set-CimInstance -InputObject $_ -Property @{AutomaticManagedPagefile=$true} -ErrorAction Stop }";

        let out = self
            .runner
            .run_powershell(script, Duration::from_secs(30))
            .await?;

        if out.success {
            return Ok(ENABLED_MESSAGE.to_string());
        }

        let detail = out.stderr.trim();
        let detail = if detail.is_empty() {
            "PowerShell reported no detail — this change requires Administrator rights"
        } else {
            detail
        };
        Err(format!(
            "Could not enable automatic page file management: {}",
            detail
        ))
    }

    /// The drive letter encoded in an issue id, if it is a well-formed one.
    ///
    /// The suffix reaches [`Self::fix`] as text and ends up in a PowerShell
    /// command, so it is validated to a single ASCII letter before it is used
    /// rather than merely quoted.
    fn drive_from_issue_id(issue_id: &str, prefix: &str) -> Option<char> {
        let suffix = issue_id.strip_prefix(prefix)?;
        let mut chars = suffix.chars();
        let letter = chars.next()?;
        if chars.next().is_some() || !letter.is_ascii_alphabetic() {
            return None;
        }
        Some(letter)
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for PageFileModule {
    fn id(&self) -> &'static str {
        "page_file"
    }

    fn name(&self) -> &'static str {
        "Page File & Memory"
    }

    fn description(&self) -> &'static str {
        "Checks for a disabled page file, a page file on a nearly full drive and undersized fixed page file limits"
    }

    fn icon(&self) -> &'static str {
        "[MEM]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        Self::send_progress(
            &progress_tx,
            20,
            "Reading the virtual memory configuration...",
            Some("Get-CimInstance Win32_ComputerSystem..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let raw_facts = self
            .probe(COMPUTER_SYSTEM_SCRIPT)
            .await
            .map_err(|e| format!("{}: {}", CONFIG_UNREADABLE, e))?;

        let Some(facts) = Self::parse_memory_facts(&raw_facts) else {
            // Judging a page file against an unknown RAM size would be
            // guesswork, so the scan records why it stopped rather than
            // returning an empty result that reads as "everything is fine".
            Self::send_progress(
                &progress_tx,
                100,
                "Page file diagnostics skipped",
                Some(CONFIG_EMPTY),
            )
            .await;
            return Ok(Vec::new());
        };

        let management = if facts.automatic_managed {
            "automatic"
        } else {
            "manual"
        };
        let facts_line = format!(
            "{} RAM, page file management: {}",
            format_bytes(mb_to_bytes(facts.ram_mb)),
            management
        );
        Self::send_progress(
            &progress_tx,
            45,
            "Reading the active page files...",
            Some(&facts_line),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        // One unavailable class here costs its own check, not the whole module:
        // an unreadable disk inventory should not hide a disabled page file.
        let usage_probe = self.probe(PAGE_FILE_USAGE_SCRIPT).await;
        let raw_setting = self
            .probe(PAGE_FILE_SETTING_SCRIPT)
            .await
            .unwrap_or_default();
        let raw_disks = self.probe(LOGICAL_DISK_SCRIPT).await.unwrap_or_default();

        // Whether the query ran — a different question from whether it found
        // any page files, and the only one that separates "this machine has
        // none" from "this machine could not be asked".
        let usage_readable = usage_probe.is_ok();
        let raw_usage = usage_probe.unwrap_or_default();

        let usages = Self::parse_usage(&raw_usage);
        let settings = Self::parse_settings(&raw_setting);
        let volumes = Self::parse_volumes(&raw_disks);

        // 1. No page file at all, and Windows is not allowed to create one.
        //    With automatic management on, an empty usage list is a transient
        //    reading rather than a configuration fault, so it is not reported —
        //    and neither is one that comes from a query that never ran.
        if usage_readable && usages.is_empty() && !facts.automatic_managed {
            let low_ram = facts.ram_mb > 0 && facts.ram_mb < LOW_RAM_MB;
            let consequence = if low_ram {
                "At this RAM size, programs are terminated outright once physical memory runs out instead of being paged out."
            } else {
                "Memory-hungry programs are terminated outright once physical memory runs out instead of being paged out."
            };

            let mut issue = Issue::new(
                "pagefile_disabled",
                self.id(),
                "Page file disabled on every drive",
                "Page File & Memory",
                if low_ram {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                // Nothing takes effect before a restart.
                RiskScore::High,
                format!(
                    "This machine has {} of RAM and no page file, with automatic management switched off. {} Windows also cannot write a kernel crash dump without one, so the next blue screen leaves nothing to analyse.",
                    format_bytes(mb_to_bytes(facts.ram_mb)),
                    consequence
                ),
                format!(
                    "Win32_ComputerSystem.AutomaticManagedPagefile: False\nWin32_ComputerSystem.TotalPhysicalMemory: {} MB\nWin32_PageFileUsage instances: 0",
                    facts.ram_mb
                ),
                "Hand virtual memory back to Windows (automatic management); takes effect after a restart",
                vec![
                    "Set Win32_ComputerSystem.AutomaticManagedPagefile to $true".to_string(),
                    "Restart Windows so the page file is created".to_string(),
                ],
            );
            issue.is_selected = false;
            issues.push(issue);
        }

        Self::send_progress(
            &progress_tx,
            70,
            "Checking the volumes hosting a page file...",
            Some(&format!("{} active page file(s) found.", usages.len())),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        // 2. A page file on a volume with no room left to grow into.
        for usage in &usages {
            let Some(drive) = Self::drive_letter(&usage.name) else {
                continue;
            };
            let Some(volume) = volumes
                .iter()
                .find(|v| Self::drive_letter(&v.device_id) == Some(drive))
            else {
                continue;
            };

            let free_mb = volume.free_bytes / (1024 * 1024);
            let free_percent = (volume.free_bytes as f64 / volume.size_bytes as f64) * 100.0;
            let critical = free_mb < CRITICAL_FREE_MB;

            if !critical && free_mb >= LOW_FREE_MB && free_percent >= LOW_FREE_PERCENT {
                continue;
            }

            let mut issue = Issue::new(
                format!("pagefile_low_space_{}", drive),
                self.id(),
                format!(
                    "Page file on a nearly full drive ({}:)",
                    drive.to_ascii_uppercase()
                ),
                "Page File & Memory",
                if critical {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                // Advisory: freeing space or moving the page file is a decision
                // about the user's own data, so WinMedic does not make it.
                RiskScore::High,
                format!(
                    "The page file '{}' sits on a volume with only {} free ({:.1} %). A page file that cannot grow under load turns into out-of-memory errors, and its peak use has already reached {}.",
                    usage.name,
                    format_bytes(volume.free_bytes),
                    free_percent,
                    format_bytes(mb_to_bytes(usage.peak_mb))
                ),
                format!(
                    "Page file: {}\nAllocated: {} MB, current use: {} MB, peak use: {} MB\nVolume {}: {} of {} free ({:.1} %)",
                    usage.name,
                    usage.allocated_mb,
                    usage.current_mb,
                    usage.peak_mb,
                    volume.device_id,
                    format_bytes(volume.free_bytes),
                    format_bytes(volume.size_bytes),
                    free_percent
                ),
                "Free space on this volume, or move the page file to a roomier drive — WinMedic reports this rather than deciding which files to remove",
                vec![
                    format!(
                        "Free space on {}: (the System & Cache Cleaner module finds candidates)",
                        drive.to_ascii_uppercase()
                    ),
                    "Or move the page file: System Properties -> Advanced -> Performance -> Virtual memory".to_string(),
                ],
            );
            issue.is_selected = false;
            issues.push(issue);
        }

        // 3. A manually sized page file whose maximum is too small to be useful.
        let recommended_min = Self::recommended_min_page_file_mb(facts.ram_mb);
        for setting in &settings {
            let Some(drive) = Self::drive_letter(&setting.name) else {
                continue;
            };
            // Both sizes at zero is how a system-managed file is spelled.
            if setting.maximum_mb == 0 && setting.initial_mb == 0 {
                continue;
            }

            let inverted = setting.maximum_mb < setting.initial_mb;
            let too_small = setting.maximum_mb < recommended_min;
            if !inverted && !too_small {
                continue;
            }

            // An inverted range can still have a generous maximum, so it is not
            // the same finding as one that is merely too small.
            let (title, reason) = if inverted {
                (
                    format!(
                        "Invalid fixed page file range on {}:",
                        drive.to_ascii_uppercase()
                    ),
                    format!(
                        "its maximum ({} MB) is below its initial size ({} MB), which is not a usable range",
                        setting.maximum_mb, setting.initial_mb
                    ),
                )
            } else {
                (
                    format!(
                        "Undersized fixed page file limit on {}:",
                        drive.to_ascii_uppercase()
                    ),
                    format!(
                        "its maximum of {} MB is below the {} MB this machine's {} of RAM calls for",
                        setting.maximum_mb,
                        recommended_min,
                        format_bytes(mb_to_bytes(facts.ram_mb))
                    ),
                )
            };

            let mut issue = Issue::new(
                format!("pagefile_fixed_size_{}", drive),
                self.id(),
                title,
                "Page File & Memory",
                Severity::Warning,
                // Takes effect only after a restart.
                RiskScore::High,
                format!(
                    "The page file '{}' has a manually fixed size and {}. Under load Windows cannot grow it, so allocations fail even though the drive still has room.",
                    setting.name, reason
                ),
                format!(
                    "Win32_PageFileSetting: {}\nInitialSize: {} MB\nMaximumSize: {} MB\nRecommended minimum for {} MB of RAM: {} MB",
                    setting.name,
                    setting.initial_mb,
                    setting.maximum_mb,
                    facts.ram_mb,
                    recommended_min
                ),
                "Hand this volume's page file back to Windows (system managed); takes effect after a restart",
                vec![
                    format!(
                        "Set InitialSize and MaximumSize to 0 for the page file on {}:",
                        drive.to_ascii_uppercase()
                    ),
                    "Restart Windows so the new size applies".to_string(),
                ],
            );
            issue.is_selected = false;
            issues.push(issue);
        }

        Self::send_progress(
            &progress_tx,
            100,
            "Page file diagnostics complete",
            Some(&format!(
                "{} page file(s) and {} manual size setting(s) checked.",
                usages.len(),
                settings.len()
            )),
        )
        .await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        if issue_id == "pagefile_disabled" {
            return self.enable_automatic_management().await;
        }

        if let Some(drive) = Self::drive_from_issue_id(issue_id, "pagefile_fixed_size_") {
            return self.set_system_managed(drive).await;
        }

        if let Some(drive) = Self::drive_from_issue_id(issue_id, "pagefile_low_space_") {
            // Deliberately advisory. Freeing space means choosing which of the
            // user's files to remove, and moving the page file to another
            // volume is a decision about their disk layout — neither is
            // WinMedic's to make, so this reports rather than acts.
            return Ok(format!(
                "No change was made. Free space on {}:, or move the page file to another volume via System Properties -> Advanced -> Performance -> Virtual memory.",
                drive.to_ascii_uppercase()
            ));
        }

        Err(format!("Unknown issue id: {}", issue_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    /// Wire up the four probes a scan makes. Each script names a distinct CIM
    /// class, which is what the mock matches on.
    fn mock_system(
        computer_system: &str,
        usage: &str,
        setting: &str,
        logical_disk: &str,
    ) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("Win32_ComputerSystem", CmdOutput::ok(computer_system));
        mock.add_response("Win32_PageFileUsage", CmdOutput::ok(usage));
        mock.add_response("Win32_PageFileSetting", CmdOutput::ok(setting));
        mock.add_response("Win32_LogicalDisk", CmdOutput::ok(logical_disk));
        mock
    }

    /// 16 GB of RAM, automatic management on.
    const HEALTHY_SYSTEM: &str = "True|17179869184";
    /// A 500 GB volume with 250 GB free.
    const ROOMY_DISK: &str = "C:|536870912000|268435456000";

    #[test]
    fn a_drive_letter_is_only_read_from_a_well_formed_path() {
        assert_eq!(PageFileModule::drive_letter(r"C:\pagefile.sys"), Some('c'));
        assert_eq!(PageFileModule::drive_letter("D:"), Some('d'));
        assert_eq!(PageFileModule::drive_letter(r"\\server\share"), None);
        assert_eq!(PageFileModule::drive_letter("4:"), None);
        assert_eq!(PageFileModule::drive_letter(""), None);
    }

    #[test]
    fn ram_is_converted_from_bytes_and_the_flag_is_case_insensitive() {
        let facts = PageFileModule::parse_memory_facts("true|17179869184").unwrap();
        assert!(facts.automatic_managed);
        assert_eq!(facts.ram_mb, 16384);

        let facts = PageFileModule::parse_memory_facts("False|8589934592").unwrap();
        assert!(!facts.automatic_managed);
        assert_eq!(facts.ram_mb, 8192);

        assert!(PageFileModule::parse_memory_facts("").is_none());
        assert!(PageFileModule::parse_memory_facts("no-separator").is_none());
    }

    #[test]
    fn a_volume_without_a_capacity_is_dropped_rather_than_divided_by() {
        // Reporting 0 % free for a volume of unknown size would be a fabricated
        // number, and the percentage calculation would divide by zero.
        let volumes = PageFileModule::parse_volumes("C:|0|0\r\nD:|1000|400");
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].device_id, "D:");
        assert_eq!(volumes[0].free_bytes, 400);
    }

    #[test]
    fn the_recommended_minimum_never_drops_below_the_floor() {
        // An eighth of RAM once there is enough of it...
        assert_eq!(PageFileModule::recommended_min_page_file_mb(32768), 4096);
        // ...and the floor on a small machine, where RAM/8 would be tiny.
        assert_eq!(PageFileModule::recommended_min_page_file_mb(4096), 1024);
        assert_eq!(PageFileModule::recommended_min_page_file_mb(0), 1024);
    }

    #[tokio::test]
    async fn a_healthy_machine_produces_no_findings() {
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            HEALTHY_SYSTEM,
            r"C:\pagefile.sys|2048|512|900",
            "",
            ROOMY_DISK,
        )));

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_disabled_page_file_on_a_small_machine_is_critical() {
        // 4 GB of RAM, manual management, no page file anywhere.
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            "False|4294967296",
            "",
            "",
            ROOMY_DISK,
        )));

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "pagefile_disabled")
            .expect("a machine with no page file must be reported");

        assert_eq!(issue.severity, Severity::Critical);
        assert_eq!(issue.risk_score, RiskScore::High);
        assert!(!issue.is_selected, "a reboot-level change is never unattended");
        assert!(issue.fix_steps.iter().any(|s| s.contains("Restart")));
    }

    #[tokio::test]
    async fn an_absent_page_file_under_automatic_management_is_not_reported() {
        // Windows manages it; an empty usage list here is a transient reading,
        // not a configuration fault to act on.
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            HEALTHY_SYSTEM,
            "",
            "",
            ROOMY_DISK,
        )));

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_page_file_on_a_full_volume_is_reported_but_never_auto_fixed() {
        // 500 GB volume with 300 MB free.
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            HEALTHY_SYSTEM,
            r"C:\pagefile.sys|2048|1800|2040",
            "",
            "C:|536870912000|314572800",
        )));

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "pagefile_low_space_c")
            .expect("the full volume must be reported");

        assert_eq!(issue.severity, Severity::Critical);
        assert!(!issue.is_selected);

        // The repair is advisory by design: it must succeed without touching
        // anything, and say so.
        let mock = MockCommandRunner::new();
        let advisory = PageFileModule::with_runner(Arc::new(mock.clone()))
            .fix("pagefile_low_space_c", None)
            .await
            .unwrap();
        assert!(advisory.starts_with("No change was made."));
        assert!(mock.executed().is_empty(), "nothing may be executed");
    }

    #[tokio::test]
    async fn a_volume_with_room_to_spare_is_not_flagged() {
        // 1 TiB with 128 GiB free — 12.5 %, chosen as an exact binary fraction
        // so the comparison does not hinge on f64 rounding.
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            HEALTHY_SYSTEM,
            r"C:\pagefile.sys|2048|512|900",
            "",
            "C:|1099511627776|137438953472",
        )));

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_percentage_rule_fires_even_with_gigabytes_still_free() {
        // 1 TiB with 64 GiB free — 6.25 %. Far above the absolute floor, so
        // only the proportional threshold can catch this one.
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            HEALTHY_SYSTEM,
            r"C:\pagefile.sys|2048|512|900",
            "",
            "C:|1099511627776|68719476736",
        )));

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "pagefile_low_space_c")
            .expect("6.25 % free must be reported");

        assert_eq!(
            issue.severity,
            Severity::Warning,
            "64 GiB free is tight, not critical"
        );
    }

    #[tokio::test]
    async fn an_undersized_fixed_limit_is_reported() {
        // 16 GB of RAM wants at least 2048 MB; this file stops at 512.
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            HEALTHY_SYSTEM,
            r"C:\pagefile.sys|512|400|500",
            r"C:\pagefile.sys|512|512",
            ROOMY_DISK,
        )));

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "pagefile_fixed_size_c")
            .expect("the undersized limit must be reported");

        assert_eq!(issue.risk_score, RiskScore::High);
        assert!(!issue.is_selected);
        assert!(issue.technical_details.contains("Recommended minimum"));
    }

    #[tokio::test]
    async fn an_inverted_range_is_reported_even_when_the_maximum_is_generous() {
        // 8 GB maximum is plenty for 16 GB of RAM, but it is below the initial
        // size, so the range itself is unusable.
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            HEALTHY_SYSTEM,
            r"C:\pagefile.sys|8192|400|500",
            r"C:\pagefile.sys|16384|8192",
            ROOMY_DISK,
        )));

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "pagefile_fixed_size_c")
            .expect("an inverted range must be reported");

        assert!(issue.description.contains("below its initial size"));
        assert!(
            issue.title.contains("Invalid"),
            "a generous but inverted range is not an undersized one: {}",
            issue.title
        );
    }

    #[tokio::test]
    async fn a_system_managed_setting_is_left_alone() {
        // Both sizes at zero is exactly what "system managed" looks like here.
        let module = PageFileModule::with_runner(Arc::new(mock_system(
            HEALTHY_SYSTEM,
            r"C:\pagefile.sys|2048|512|900",
            r"C:\pagefile.sys|0|0",
            ROOMY_DISK,
        )));

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_fix_hands_the_named_volume_back_to_windows() {
        let mock = MockCommandRunner::with_default_success();
        let module = PageFileModule::with_runner(Arc::new(mock.clone()));

        let result = module.fix("pagefile_fixed_size_c", None).await.unwrap();
        assert!(result.contains("system managed"));

        let executed = mock.executed().join("\n");
        assert!(executed.contains("Win32_PageFileSetting"));
        assert!(executed.contains("'C:*'"));
        assert!(executed.contains("InitialSize=0; MaximumSize=0"));
    }

    #[tokio::test]
    async fn the_fix_re_enables_automatic_management() {
        let mock = MockCommandRunner::with_default_success();
        let module = PageFileModule::with_runner(Arc::new(mock.clone()));

        let result = module.fix("pagefile_disabled", None).await.unwrap();
        assert!(result.contains("Automatic page file management enabled"));
        assert!(
            mock.executed()
                .join("\n")
                .contains("AutomaticManagedPagefile=$true")
        );
    }

    #[tokio::test]
    async fn a_malformed_drive_suffix_is_refused_rather_than_interpolated() {
        let mock = MockCommandRunner::with_default_success();
        let module = PageFileModule::with_runner(Arc::new(mock.clone()));

        for hostile in [
            "pagefile_fixed_size_c:*'; Remove-Item C:\\Windows; '",
            "pagefile_fixed_size_cd",
            "pagefile_fixed_size_",
            "pagefile_fixed_size_4",
        ] {
            let err = module.fix(hostile, None).await.unwrap_err();
            assert!(err.contains("Unknown issue id"), "accepted: {}", hostile);
        }
        assert!(
            mock.executed().is_empty(),
            "a rejected id must reach no command"
        );
    }

    #[tokio::test]
    async fn a_failing_repair_is_reported_as_a_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "Win32_ComputerSystem",
            CmdOutput::failed(1, "Access denied."),
        );
        let module = PageFileModule::with_runner(Arc::new(mock));

        let err = module.fix("pagefile_disabled", None).await.unwrap_err();
        assert!(err.contains("Access denied."));
    }

    #[tokio::test]
    async fn a_configuration_query_that_fails_fails_the_module() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "Win32_ComputerSystem",
            CmdOutput::failed(1, "WMI repository is corrupt."),
        );
        let module = PageFileModule::with_runner(Arc::new(mock));

        let err = module.scan(None).await.unwrap_err();
        assert!(err.contains("could not be read"));
        assert!(err.contains("WMI repository is corrupt."));
    }

    #[tokio::test]
    async fn a_configuration_query_that_returns_nothing_judges_nothing() {
        // Distinct from the case above: the query ran. Without a RAM size
        // there is nothing to measure against, so the module reports no
        // findings rather than inventing them — and does not fail either.
        let mock = MockCommandRunner::new();
        mock.add_response("Win32_ComputerSystem", CmdOutput::ok(""));
        let module = PageFileModule::with_runner(Arc::new(mock));

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_page_file_list_is_not_read_as_having_no_page_file() {
        // Manual management plus an empty usage list is the disabled-page-file
        // finding — but only when the list was actually readable. Here the
        // query fails, so claiming there is no page file would be fabricated.
        let mock = MockCommandRunner::new();
        mock.add_response("Win32_ComputerSystem", CmdOutput::ok("False|4294967296"));
        mock.add_response(
            "Win32_PageFileUsage",
            CmdOutput::failed(1, "Class not available."),
        );
        mock.add_response("Win32_PageFileSetting", CmdOutput::ok(""));
        mock.add_response("Win32_LogicalDisk", CmdOutput::ok(ROOMY_DISK));
        let module = PageFileModule::with_runner(Arc::new(mock));

        let issues = module.scan(None).await.unwrap();
        assert!(
            !issues.iter().any(|i| i.id == "pagefile_disabled"),
            "a failed query must not become a finding"
        );
    }
}
