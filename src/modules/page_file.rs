//! Page file and virtual memory diagnostics.
//!
//! A page file the user sized deliberately is a legitimate configuration rather
//! than damage, and the changes that would correct one take effect only after a
//! restart. Both point the same way: every finding here is `RiskScore::High`
//! and deselected by default, so `--auto-fix` never rewrites virtual memory
//! settings unattended. The nearly-full-drive finding goes further and changes
//! nothing at all — which files to delete is not WinMedic's decision to make.
//!
//! What every finding is judged against needs no WMI: the page files Windows
//! creates come from the registry and the RAM size from Windows itself. The
//! old source, `Win32_ComputerSystem`, gathers dozens of properties, and on a
//! busy machine it twice took longer than 20 seconds — and busy machines are
//! what WinMedic is for. What the page files look like right now (their use, the
//! disks they live on) still comes from CIM, and each of those queries only
//! costs its own check when it fails.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::system_cleaner::format_bytes;
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner, ps_single_quoted};
use crate::utils::registry;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

/// Holds `PagingFiles`, the page files the Session Manager creates at boot:
/// one entry per file, `?:\pagefile.sys` for "Automatically manage paging file
/// size for all drives", and no entry at all when there is to be none.
const MEMORY_MANAGEMENT_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";

/// Physical memory in bytes. A function, so that a test can pick the machine.
pub type RamSource = Arc<dyn Fn() -> u64 + Send + Sync>;

/// `GlobalMemoryStatusEx`, the same number `Win32_ComputerSystem` reports as
/// `TotalPhysicalMemory`.
fn real_ram() -> RamSource {
    Arc::new(|| {
        let mut system = sysinfo::System::new();
        system.refresh_memory_specifics(sysinfo::MemoryRefreshKind::nothing().with_ram());
        system.total_memory()
    })
}

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

/// Without the configured page files the main finding cannot be judged, so
/// this is the one probe whose *failure* fails the module.
const CONFIG_UNREADABLE: &str = "The virtual memory configuration could not be read";

/// A missing value is a different case from an empty one, and neither may be
/// reported as a clean bill of health.
const CONFIG_MISSING: &str =
    "PagingFiles is not set - whether this PC has a page file was not judged.";

/// Stands in for a PowerShell failure that carried no stderr of its own.
const NO_DETAIL: &str = "PowerShell reported no detail";

/// Confirmation for the one repair that changes a machine-wide setting.
const ENABLED_MESSAGE: &str =
    "Automatic page file management enabled. Windows creates the page file on the next restart.";

fn mb_to_bytes(mb: u64) -> u64 {
    mb.saturating_mul(1024 * 1024)
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
    ram: RamSource,
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
        Self {
            runner,
            ram: real_ram(),
        }
    }

    /// For tests: a RAM size other than the machine's own.
    pub fn with_ram(mut self, ram: RamSource) -> Self {
        self.ram = ram;
        self
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

    /// The entries of a `REG_MULTI_SZ` as `reg query` prints it: joined by a
    /// literal `\0`, nothing at all for an empty list.
    fn multi_sz_entries(data: &str) -> Vec<String> {
        data.split(r"\0")
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// The page files Windows is set up to create, or `None` when the key or
    /// the value is missing and nothing can be said.
    async fn configured_page_files(&self) -> Result<Option<Vec<String>>, String> {
        let Some(keys) = registry::query(&*self.runner, MEMORY_MANAGEMENT_KEY, false).await? else {
            return Ok(None);
        };
        Ok(registry::find(&keys, MEMORY_MANAGEMENT_KEY, "PagingFiles")
            .map(|value| Self::multi_sz_entries(&value.data)))
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
            .query_powershell(script, Duration::from_secs(20))
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
            Some("reg query ...\\Session Manager\\Memory Management"),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let configured = self
            .configured_page_files()
            .await
            .map_err(|e| format!("{}: {}", CONFIG_UNREADABLE, e))?;
        let ram_mb = (self.ram)() / (1024 * 1024);

        let facts_line = match &configured {
            Some(files) if files.is_empty() => format!(
                "{} RAM, page files set up: none",
                format_bytes(mb_to_bytes(ram_mb))
            ),
            Some(files) => format!(
                "{} RAM, page files set up: {}",
                format_bytes(mb_to_bytes(ram_mb)),
                files.join(", ")
            ),
            None => CONFIG_MISSING.to_string(),
        };
        Self::send_progress(
            &progress_tx,
            45,
            "Reading the active page files...",
            Some(&facts_line),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        // One unavailable class here costs its own check, not the whole module:
        // an unreadable disk inventory should not hide an undersized limit.
        let raw_usage = self.probe(PAGE_FILE_USAGE_SCRIPT).await.unwrap_or_default();
        let raw_setting = self
            .probe(PAGE_FILE_SETTING_SCRIPT)
            .await
            .unwrap_or_default();
        let raw_disks = self.probe(LOGICAL_DISK_SCRIPT).await.unwrap_or_default();

        let usages = Self::parse_usage(&raw_usage);
        let settings = Self::parse_settings(&raw_setting);
        let volumes = Self::parse_volumes(&raw_disks);

        // 1. No page file set up on any drive, so Windows creates none at
        //    boot. A missing value says nothing either way and is not read as
        //    an empty one.
        if configured.as_ref().is_some_and(Vec::is_empty) {
            let low_ram = ram_mb > 0 && ram_mb < LOW_RAM_MB;
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
                    "This machine has {} of RAM and no page file set up on any drive, so Windows creates none. {} Windows also cannot write a kernel crash dump without one, so the next blue screen leaves nothing to analyse.",
                    format_bytes(mb_to_bytes(ram_mb)),
                    consequence
                ),
                format!(
                    "{}\nPagingFiles: (empty)\nPhysical memory: {} MB",
                    MEMORY_MANAGEMENT_KEY, ram_mb
                ),
                "Hand virtual memory back to Windows (automatic management); takes effect after a restart",
                vec![
                    "Set Win32_ComputerSystem.AutomaticManagedPagefile to $true".to_string(),
                    "Restart Windows so the page file is created".to_string(),
                ],
            )
            .with_requires_reboot(true);
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

            issues.push(Issue::new(
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
            ).with_advice_only());
        }

        // 3. A manually sized page file whose maximum is too small to be useful.
        let recommended_min = Self::recommended_min_page_file_mb(ram_mb);
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
                        format_bytes(mb_to_bytes(ram_mb))
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
                    ram_mb,
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
            )
            .with_requires_reboot(true);
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

        // The nearly-full-drive finding is advice: freeing space means choosing
        // which of the user's files to remove, and moving the page file is a
        // decision about their disk layout. A repair run never asks.
        Err(format!("Unknown issue id: {}", issue_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;

    // Captured on a German Windows 11; see tests/fixtures/README.md.
    const MEMORY_MANAGEMENT: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_memory_management.bin");

    const GIB: u64 = 1024 * 1024 * 1024;

    /// "Automatically manage paging file size for all drives", as captured.
    const AUTOMATIC: &str = r"?:\pagefile.sys";

    /// The captured Memory Management key with `PagingFiles` set to `data`.
    fn memory_management(data: &str) -> String {
        let line = format!("PagingFiles    REG_MULTI_SZ    {data}");
        decode_output(MEMORY_MANAGEMENT).replace(
            r"PagingFiles    REG_MULTI_SZ    ?:\pagefile.sys",
            line.trim_end(),
        )
    }

    /// Wire up the four probes a scan makes. The registry key and each CIM
    /// class have a distinct name, which is what the mock matches on.
    fn mock_system(
        paging_files: &str,
        usage: &str,
        setting: &str,
        logical_disk: &str,
    ) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "Memory Management",
            CmdOutput::ok(memory_management(paging_files)),
        );
        mock.add_response("Win32_PageFileUsage", CmdOutput::ok(usage));
        mock.add_response("Win32_PageFileSetting", CmdOutput::ok(setting));
        mock.add_response("Win32_LogicalDisk", CmdOutput::ok(logical_disk));
        mock
    }

    /// The module on a machine with `ram_gib` of RAM.
    fn module(mock: MockCommandRunner, ram_gib: u64) -> PageFileModule {
        PageFileModule::with_runner(Arc::new(mock)).with_ram(Arc::new(move || ram_gib * GIB))
    }

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
    fn the_configured_page_files_are_read_from_the_captured_key() {
        let keys = registry::parse_reg_query(&decode_output(MEMORY_MANAGEMENT));
        let value = registry::find(&keys, MEMORY_MANAGEMENT_KEY, "PagingFiles").unwrap();
        assert_eq!(value.kind, "REG_MULTI_SZ");
        assert_eq!(
            PageFileModule::multi_sz_entries(&value.data),
            vec![AUTOMATIC]
        );

        // `reg` joins the entries of a REG_MULTI_SZ with a literal `\0`.
        assert_eq!(
            PageFileModule::multi_sz_entries(r"C:\pagefile.sys 0 0\0D:\pagefile.sys 1024 4096"),
            vec![r"C:\pagefile.sys 0 0", r"D:\pagefile.sys 1024 4096"]
        );
        assert!(PageFileModule::multi_sz_entries("").is_empty());
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
        let module = module(
            mock_system(AUTOMATIC, r"C:\pagefile.sys|2048|512|900", "", ROOMY_DISK),
            16,
        );

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_disabled_page_file_on_a_small_machine_is_critical() {
        // 4 GB of RAM and no page file set up on any drive.
        let module = module(mock_system("", "", "", ROOMY_DISK), 4);

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "pagefile_disabled")
            .expect("a machine with no page file must be reported");

        assert_eq!(issue.severity, Severity::Critical);
        assert_eq!(issue.risk_score, RiskScore::High);
        assert!(
            !issue.is_selected,
            "a reboot-level change is never unattended"
        );
        assert!(issue.fix_steps.iter().any(|s| s.contains("Restart")));
    }

    #[tokio::test]
    async fn the_severity_follows_the_ram_size() {
        let issues = module(mock_system("", "", "", ROOMY_DISK), 32)
            .scan(None)
            .await
            .unwrap();
        let issue = issues.iter().find(|i| i.id == "pagefile_disabled").unwrap();
        assert_eq!(
            issue.severity,
            Severity::Warning,
            "32 GB of RAM go a long way"
        );
        assert!(issue.technical_details.contains("PagingFiles: (empty)"));
    }

    #[tokio::test]
    async fn an_absent_page_file_under_automatic_management_is_not_reported() {
        // Windows creates it at boot; an empty usage list here is a transient
        // reading, not a configuration fault to act on.
        let module = module(mock_system(AUTOMATIC, "", "", ROOMY_DISK), 16);

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_missing_value_is_not_read_as_an_empty_one() {
        // Without `PagingFiles` nothing says whether a page file is set up, so
        // claiming there is none would be fabricated.
        let without_value: String = decode_output(MEMORY_MANAGEMENT)
            .lines()
            .filter(|line| !line.contains("PagingFiles"))
            .map(|line| format!("{line}\r\n"))
            .collect();
        let mock = MockCommandRunner::new();
        mock.add_response("Memory Management", CmdOutput::ok(without_value));
        mock.add_response("Win32_PageFileUsage", CmdOutput::ok(""));
        mock.add_response("Win32_PageFileSetting", CmdOutput::ok(""));
        mock.add_response("Win32_LogicalDisk", CmdOutput::ok(ROOMY_DISK));

        let issues = module(mock, 4).scan(None).await.unwrap();
        assert!(!issues.iter().any(|i| i.id == "pagefile_disabled"));
    }

    #[tokio::test]
    async fn a_page_file_on_a_full_volume_is_reported_but_never_auto_fixed() {
        // 500 GB volume with 300 MB free.
        let module = module(
            mock_system(
                AUTOMATIC,
                r"C:\pagefile.sys|2048|1800|2040",
                "",
                "C:|536870912000|314572800",
            ),
            16,
        );

        let issues = module.scan(None).await.unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "pagefile_low_space_c")
            .expect("the full volume must be reported");

        assert_eq!(issue.severity, Severity::Critical);
        assert!(
            issue.advice_only,
            "which files to delete is not WinMedic's call"
        );
        assert!(!issue.is_selected);
    }

    #[tokio::test]
    async fn a_volume_with_room_to_spare_is_not_flagged() {
        // 1 TiB with 128 GiB free — 12.5 %, chosen as an exact binary fraction
        // so the comparison does not hinge on f64 rounding.
        let module = module(
            mock_system(
                AUTOMATIC,
                r"C:\pagefile.sys|2048|512|900",
                "",
                "C:|1099511627776|137438953472",
            ),
            16,
        );

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_percentage_rule_fires_even_with_gigabytes_still_free() {
        // 1 TiB with 64 GiB free — 6.25 %. Far above the absolute floor, so
        // only the proportional threshold can catch this one.
        let module = module(
            mock_system(
                AUTOMATIC,
                r"C:\pagefile.sys|2048|512|900",
                "",
                "C:|1099511627776|68719476736",
            ),
            16,
        );

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
        let module = module(
            mock_system(
                AUTOMATIC,
                r"C:\pagefile.sys|512|400|500",
                r"C:\pagefile.sys|512|512",
                ROOMY_DISK,
            ),
            16,
        );

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
        let module = module(
            mock_system(
                AUTOMATIC,
                r"C:\pagefile.sys|8192|400|500",
                r"C:\pagefile.sys|16384|8192",
                ROOMY_DISK,
            ),
            16,
        );

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
        let module = module(
            mock_system(
                AUTOMATIC,
                r"C:\pagefile.sys|2048|512|900",
                r"C:\pagefile.sys|0|0",
                ROOMY_DISK,
            ),
            16,
        );

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
        // `reg` could not be run at all: nothing is known about the page files.
        let mock = MockCommandRunner::new();
        mock.add_response("Win32_PageFileUsage", CmdOutput::ok(""));
        let err = module(mock, 16).scan(None).await.unwrap_err();
        assert!(err.contains("could not be read"), "{err}");
    }

    #[tokio::test]
    async fn a_missing_key_judges_nothing_and_fails_nothing() {
        // Distinct from the case above: `reg` ran and said the key does not
        // exist (exit code 1, translated text). The other checks still run.
        let mock = MockCommandRunner::new();
        mock.add_response(
            "Memory Management",
            CmdOutput::failed(
                1,
                "FEHLER: Der angegebene Registrierungsschlüssel bzw. Wert wurde nicht gefunden.",
            ),
        );
        mock.add_response(
            "Win32_PageFileUsage",
            CmdOutput::ok(r"C:\pagefile.sys|2048|1800|2040"),
        );
        mock.add_response("Win32_PageFileSetting", CmdOutput::ok(""));
        mock.add_response(
            "Win32_LogicalDisk",
            CmdOutput::ok("C:|536870912000|314572800"),
        );

        let issues = module(mock, 16).scan(None).await.unwrap();
        assert!(!issues.iter().any(|i| i.id == "pagefile_disabled"));
        assert!(issues.iter().any(|i| i.id == "pagefile_low_space_c"));
    }

    #[tokio::test]
    async fn the_page_file_check_asks_wmi_nothing_it_cannot_do_without() {
        // Every CIM query failing costs the checks that need it, never the
        // disabled-page-file finding and never the module.
        let mock = MockCommandRunner::new();
        mock.add_response("Memory Management", CmdOutput::ok(memory_management("")));
        for class in [
            "Win32_PageFileUsage",
            "Win32_PageFileSetting",
            "Win32_LogicalDisk",
        ] {
            mock.add_response(class, CmdOutput::failed(1, "Timeout"));
        }

        let issues = module(mock.clone(), 4).scan(None).await.unwrap();
        assert!(issues.iter().any(|i| i.id == "pagefile_disabled"));
        assert!(
            !mock
                .executed()
                .iter()
                .any(|c| c.contains("Win32_ComputerSystem")),
            "the scan must not depend on Win32_ComputerSystem"
        );
    }
}
