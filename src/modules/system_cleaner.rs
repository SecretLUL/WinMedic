use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::debug_log::DebugTrace;
use crate::utils::fs_stats::dir_stats_recursive;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

/// Directory statistics collected during scan.
///
/// Re-exported from [`crate::utils::fs_stats`], which owns the one directory
/// walker every module shares.
pub use crate::utils::fs_stats::DirStats;

/// Statistics on cleaned directory contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanStats {
    pub freed_bytes: u64,
    pub deleted_files: usize,
    pub skipped_locked: usize,
}

/// Parsed results from `dism.exe /Online /Cleanup-Image /AnalyzeComponentStore`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WinSxSAnalysis {
    pub cleanup_recommended: bool,
    pub reclaimable_packages: u32,
    pub reported_size: Option<String>,
    pub backups_size: Option<String>,
    pub cache_size: Option<String>,
}

/// Format bytes into human-readable strings (B, KB, MB, GB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Recursively calculate file count and total bytes in a directory.
///
/// Blocking: call it through [`SystemCleanerModule::scan_dirs`] from async code.
pub fn scan_path_recursive(path: &Path) -> DirStats {
    dir_stats_recursive(path)
}

/// Turn cleanup statistics into a repair result.
///
/// A sweep that removed nothing while every candidate was locked is *not* a
/// successful repair. Reporting `Ok` there makes the engine mark the issue
/// fixed, write a SUCCESS audit entry and lower the exit code, even though not
/// a single byte was freed — so that case becomes an error the user can act on.
pub fn cleanup_result(label: &str, stats: CleanStats) -> Result<String, String> {
    if stats.deleted_files == 0 && stats.skipped_locked > 0 {
        return Err(format!(
            "{} failed: none of the {} files could be removed (all locked). Close any running programs and try again.",
            label, stats.skipped_locked
        ));
    }
    Ok(format!(
        "{}: {} files deleted ({} freed, {} locked files skipped).",
        label,
        stats.deleted_files,
        format_bytes(stats.freed_bytes),
        stats.skipped_locked
    ))
}

/// Clean files and subdirectories within a path, safely skipping locked files.
pub fn clean_path_contents(path: &Path) -> CleanStats {
    let mut stats = CleanStats::default();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = p.symlink_metadata() {
                if meta.is_file() || meta.is_symlink() {
                    let len = meta.len();
                    if std::fs::remove_file(&p).is_ok() {
                        stats.freed_bytes += len;
                        stats.deleted_files += 1;
                    } else {
                        stats.skipped_locked += 1;
                    }
                } else if meta.is_dir() {
                    let sub = clean_path_contents(&p);
                    stats.freed_bytes += sub.freed_bytes;
                    stats.deleted_files += sub.deleted_files;
                    stats.skipped_locked += sub.skipped_locked;
                    let _ = std::fs::remove_dir(&p);
                }
            }
        }
    }
    stats
}

/// Scan a directory for log and diagnostic archive files (.log, .cab, .bak, .etl, .txt).
pub fn scan_log_dir_files(path: &Path) -> DirStats {
    let mut stats = DirStats::default();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = p.symlink_metadata() {
                if meta.is_file() {
                    let ext = p
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|s| s.to_ascii_lowercase())
                        .unwrap_or_default();
                    if matches!(ext.as_str(), "log" | "cab" | "bak" | "etl" | "txt") {
                        stats.bytes += meta.len();
                        stats.files += 1;
                    }
                } else if meta.is_dir() {
                    let sub = scan_log_dir_files(&p);
                    stats.bytes += sub.bytes;
                    stats.files += sub.files;
                }
            }
        }
    }
    stats
}

/// Clean log and diagnostic archive files in a directory, safely skipping locked active logs.
pub fn clean_log_dir_files(path: &Path) -> CleanStats {
    let mut stats = CleanStats::default();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = p.symlink_metadata() {
                if meta.is_file() {
                    let ext = p
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|s| s.to_ascii_lowercase())
                        .unwrap_or_default();
                    if matches!(ext.as_str(), "log" | "cab" | "bak" | "etl" | "txt") {
                        let len = meta.len();
                        if std::fs::remove_file(&p).is_ok() {
                            stats.freed_bytes += len;
                            stats.deleted_files += 1;
                        } else {
                            stats.skipped_locked += 1;
                        }
                    }
                } else if meta.is_dir() {
                    let sub = clean_log_dir_files(&p);
                    stats.freed_bytes += sub.freed_bytes;
                    stats.deleted_files += sub.deleted_files;
                    stats.skipped_locked += sub.skipped_locked;
                }
            }
        }
    }
    stats
}

/// Parse DISM `/AnalyzeComponentStore` output supporting English and German outputs.
pub fn parse_winsxs_analysis(output: &str) -> WinSxSAnalysis {
    let mut analysis = WinSxSAnalysis::default();

    for line in output.lines() {
        let lower = line.to_lowercase();
        let trimmed = lower.trim();

        if trimmed.contains("cleanup recommended")
            || trimmed.contains("bereinigung des komponentenspeichers empfohlen")
        {
            if let Some((_, val)) = line.split_once(':') {
                let v = val.trim().to_lowercase();
                if v == "yes" || v == "ja" || v == "true" || v == "1" {
                    analysis.cleanup_recommended = true;
                }
            }
        } else if trimmed.contains("reclaimable packages")
            || trimmed.contains("wiederverwendbaren pakete")
        {
            if let Some((_, val)) = line.split_once(':') {
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(num) = digits.parse::<u32>() {
                    analysis.reclaimable_packages = num;
                }
            }
        } else if trimmed.contains("explorer reported size") || trimmed.contains("laut explorer") {
            if let Some((_, val)) = line.split_once(':') {
                analysis.reported_size = Some(val.trim().to_string());
            }
        } else if trimmed.contains("backups and disabled features")
            || trimmed.contains("sicherungen und deaktivierte features")
        {
            if let Some((_, val)) = line.split_once(':') {
                analysis.backups_size = Some(val.trim().to_string());
            }
        } else if (trimmed.contains("cache and temporary data")
            || trimmed.contains("cache und temporäre daten"))
            && let Some((_, val)) = line.split_once(':')
        {
            analysis.cache_size = Some(val.trim().to_string());
        }
    }

    analysis
}

// System path discovery helper functions
pub fn get_system_root() -> PathBuf {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows"))
}

pub fn get_program_data() -> PathBuf {
    std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
}

pub fn get_local_app_data() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

pub fn get_app_data() -> PathBuf {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Default\AppData\Roaming"))
}

pub fn get_user_profile() -> PathBuf {
    std::env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Default"))
}

pub fn discover_delivery_optimization_dirs(sys_root: &Path) -> Vec<PathBuf> {
    vec![
        sys_root
            .join("SoftwareDistribution")
            .join("DeliveryOptimization"),
        sys_root
            .join("ServiceProfiles")
            .join("NetworkService")
            .join("AppData")
            .join("Local")
            .join("Microsoft")
            .join("Windows")
            .join("DeliveryOptimization")
            .join("Cache"),
    ]
}

pub fn discover_browser_cache_dirs(local_app_data: &Path, app_data: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Chrome
    let chrome_user_data = local_app_data
        .join("Google")
        .join("Chrome")
        .join("User Data");
    if chrome_user_data.exists()
        && let Ok(entries) = std::fs::read_dir(&chrome_user_data)
    {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy();
                if name == "Default" || name.starts_with("Profile ") {
                    dirs.push(p.join("Cache"));
                    dirs.push(p.join("Code Cache"));
                    dirs.push(p.join("GPUCache"));
                }
            }
        }
    }

    // Edge
    let edge_user_data = local_app_data
        .join("Microsoft")
        .join("Edge")
        .join("User Data");
    if edge_user_data.exists()
        && let Ok(entries) = std::fs::read_dir(&edge_user_data)
    {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy();
                if name == "Default" || name.starts_with("Profile ") {
                    dirs.push(p.join("Cache"));
                    dirs.push(p.join("Code Cache"));
                    dirs.push(p.join("GPUCache"));
                }
            }
        }
    }

    // Firefox
    let ff_roots = [
        local_app_data
            .join("Mozilla")
            .join("Firefox")
            .join("Profiles"),
        app_data.join("Mozilla").join("Firefox").join("Profiles"),
    ];
    for ff_root in &ff_roots {
        if ff_root.exists()
            && let Ok(entries) = std::fs::read_dir(ff_root)
        {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    dirs.push(p.join("cache2"));
                }
            }
        }
    }

    dirs
}

pub fn discover_setup_log_dirs(sys_root: &Path) -> Vec<PathBuf> {
    vec![
        sys_root.join("Panther"),
        sys_root.join("Logs").join("CBS"),
        sys_root.join("Logs").join("DISM"),
        sys_root.join("Logs").join("MoSetup"),
    ]
}

pub fn discover_wer_and_dump_dirs(local_app_data: &Path, prog_data: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // LocalAppData WER
    let local_wer = local_app_data.join("Microsoft").join("Windows").join("WER");
    dirs.push(local_wer.join("ReportArchive"));
    dirs.push(local_wer.join("ReportQueue"));
    dirs.push(local_wer.join("Temp"));
    dirs.push(local_wer.join("ERC"));

    // ProgramData WER
    let pd_wer = prog_data.join("Microsoft").join("Windows").join("WER");
    dirs.push(pd_wer.join("ReportArchive"));
    dirs.push(pd_wer.join("ReportQueue"));
    dirs.push(pd_wer.join("Temp"));
    dirs.push(pd_wer.join("ERC"));

    // CrashDumps
    dirs.push(local_app_data.join("CrashDumps"));

    dirs
}

pub fn discover_shader_and_cert_dirs(local_app_data: &Path, user_profile: &Path) -> Vec<PathBuf> {
    vec![
        local_app_data.join("D3DSCache"),
        local_app_data
            .join("Microsoft")
            .join("DirectX")
            .join("ShaderCache"),
        user_profile
            .join("AppData")
            .join("LocalLow")
            .join("Microsoft")
            .join("CryptnetUrlCache")
            .join("Content"),
        user_profile
            .join("AppData")
            .join("LocalLow")
            .join("Microsoft")
            .join("CryptnetUrlCache")
            .join("MetaData"),
    ]
}

pub fn discover_system_temp_dirs(sys_root: &Path) -> Vec<PathBuf> {
    vec![
        sys_root
            .join("System32")
            .join("config")
            .join("systemprofile")
            .join("AppData")
            .join("Local")
            .join("Temp"),
        sys_root.join("SystemTemp"),
    ]
}

pub fn discover_recycle_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for drive in b'C'..=b'Z' {
        let drive_str = format!("{}:\\$Recycle.Bin", drive as char);
        let path = PathBuf::from(drive_str);
        if path.exists() {
            dirs.push(path);
        }
    }
    dirs
}

/// The filesystem roots this module measures and deletes under.
///
/// This is the module's filesystem seam. Every path used by `scan` and `fix`
/// derives from one of these fields, so a test can point the whole module at a
/// temporary directory — without it, calling `fix("sys_clean_browser_cache")`
/// in a test permanently deletes the *test machine's* real browser caches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanerPaths {
    pub sys_root: PathBuf,
    pub prog_data: PathBuf,
    pub local_app_data: PathBuf,
    pub app_data: PathBuf,
    pub user_profile: PathBuf,
    pub recycle_bins: Vec<PathBuf>,
}

impl CleanerPaths {
    /// The real Windows locations, resolved from the environment.
    pub fn from_env() -> Self {
        Self {
            sys_root: get_system_root(),
            prog_data: get_program_data(),
            local_app_data: get_local_app_data(),
            app_data: get_app_data(),
            user_profile: get_user_profile(),
            recycle_bins: discover_recycle_bin_dirs(),
        }
    }

    /// Every root relocated under `base`, mirroring the real layout.
    ///
    /// Intended for tests and for anything else that must not touch the live
    /// system.
    pub fn rooted_at(base: &Path) -> Self {
        Self {
            sys_root: base.join("Windows"),
            prog_data: base.join("ProgramData"),
            local_app_data: base.join("AppData").join("Local"),
            app_data: base.join("AppData").join("Roaming"),
            user_profile: base.join("UserProfile"),
            recycle_bins: vec![base.join("$Recycle.Bin")],
        }
    }
}

impl Default for CleanerPaths {
    fn default() -> Self {
        Self::from_env()
    }
}

pub struct SystemCleanerModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
    paths: CleanerPaths,
}

impl SystemCleanerModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self::with_runner_and_paths(config, runner, CleanerPaths::from_env())
    }

    /// Build a module rooted at explicit paths instead of the live system.
    pub fn with_runner_and_paths(
        config: ModuleConfig,
        runner: Arc<dyn CommandRunner>,
        paths: CleanerPaths,
    ) -> Self {
        Self {
            config,
            runner,
            paths,
        }
    }

    /// Measure `dirs` on a blocking thread and return the combined totals.
    ///
    /// The walks below are synchronous `std::fs` recursion over locations that
    /// routinely hold hundreds of thousands of files. Run inline they would pin
    /// a Tokio worker for minutes, and — having no await point — would make the
    /// scan task un-abortable, so `[Esc]` could not cancel it.
    async fn scan_dirs(dirs: Vec<PathBuf>) -> DirStats {
        tokio::task::spawn_blocking(move || {
            let mut total = DirStats::default();
            for dir in &dirs {
                let stats = scan_path_recursive(dir);
                total.bytes += stats.bytes;
                total.files += stats.files;
            }
            total
        })
        .await
        .unwrap_or_default()
    }

    /// Like [`Self::scan_dirs`], but counting only log/diagnostic archive files.
    async fn scan_log_dirs(dirs: Vec<PathBuf>) -> DirStats {
        tokio::task::spawn_blocking(move || {
            let mut total = DirStats::default();
            for dir in &dirs {
                let stats = scan_log_dir_files(dir);
                total.bytes += stats.bytes;
                total.files += stats.files;
            }
            total
        })
        .await
        .unwrap_or_default()
    }

    /// Delete the contents of `dirs` on a blocking thread, reporting each one.
    ///
    /// A cleanup that frees nothing is the hardest kind of failure to read from
    /// a summary line: "0 files deleted" is the same number whether the
    /// directory was already empty, missing, or locked by a running service.
    /// Per-directory tracing is what tells those three apart. With tracing off
    /// this falls straight through to the batched sweep, which keeps the common
    /// case on one blocking task instead of one per directory.
    async fn clean_dirs_reporting(
        dirs: Vec<PathBuf>,
        sweep: fn(&Path) -> CleanStats,
        dbg: &DebugTrace,
    ) -> CleanStats {
        if !dbg.is_enabled() {
            return tokio::task::spawn_blocking(move || {
                let mut total = CleanStats::default();
                for dir in &dirs {
                    let stats = sweep(dir);
                    total.freed_bytes += stats.freed_bytes;
                    total.deleted_files += stats.deleted_files;
                    total.skipped_locked += stats.skipped_locked;
                }
                total
            })
            .await
            .unwrap_or_default();
        }

        let mut total = CleanStats::default();
        for dir in dirs {
            dbg.path("sweeping", &dir).await;
            if !dir.exists() {
                dbg.data("  -> nothing to do, the path does not exist on this machine")
                    .await;
                continue;
            }
            let target = dir.clone();
            let stats = tokio::task::spawn_blocking(move || sweep(&target))
                .await
                .unwrap_or_default();
            dbg.data(format!(
                "  -> {} deleted, {} freed, {} locked",
                stats.deleted_files,
                format_bytes(stats.freed_bytes),
                stats.skipped_locked
            ))
            .await;
            if stats.skipped_locked > 0 {
                // "1 locked" on its own gives the user nothing to act on. What
                // survived the sweep *is* what was locked, so listing the
                // remainder names the files without tracking them separately.
                for path in remaining_entries(&dir, 6) {
                    dbg.warn(format!("locked: {}", path)).await;
                }
                if stats.deleted_files == 0 {
                    dbg.hint("every candidate in this directory is held open by a running process")
                        .await;
                }
            }
            total.freed_bytes += stats.freed_bytes;
            total.deleted_files += stats.deleted_files;
            total.skipped_locked += stats.skipped_locked;
        }
        total
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
                    module_id: "system_cleaner".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for SystemCleanerModule {
    fn id(&self) -> &'static str {
        "system_cleaner"
    }

    fn name(&self) -> &'static str {
        "System & Cache Cleaner"
    }

    fn description(&self) -> &'static str {
        "Cleans WinSxS, Delivery Optimization, browser caches, setup logs, shader caches and temporary system data."
    }

    fn icon(&self) -> &'static str {
        "[CLR]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        if self.config.verbose_logging {
            Self::send_progress(
                &progress_tx,
                0,
                "Starting system cleaner sweep...",
                Some("[DEBUG] Initialising cleaner cache targets and path scanners..."),
            )
            .await;
        }

        // 1. WinSxS Component Store Deep Clean
        Self::send_progress(
            &progress_tx,
            10,
            "Analysing the WinSxS component store...",
            Some("dism.exe /Online /Cleanup-Image /AnalyzeComponentStore"),
        )
        .await;

        let dism_check = self
            .runner
            .run(
                "dism.exe",
                &["/Online", "/Cleanup-Image", "/AnalyzeComponentStore"],
                Duration::from_secs(120),
            )
            .await;

        // A non-zero exit still yields `Ok(CmdOutput { success: false, .. })`, and
        // DISM prints partial store figures to stdout before it errors out — so
        // the exit status has to gate the parse, or an aborted run (error 740,
        // "elevated permissions required") gets reported as real analysis.
        if let Some(out) = dism_check.ok().filter(|out| out.success) {
            let analysis = parse_winsxs_analysis(&out.stdout);
            if analysis.cleanup_recommended || analysis.reclaimable_packages > 0 {
                let title = if analysis.reclaimable_packages > 0 {
                    format!(
                        "WinSxS component store cleanup recommended ({} reclaimable packages)",
                        analysis.reclaimable_packages
                    )
                } else {
                    "WinSxS component store cleanup recommended".to_string()
                };

                let mut details = Vec::new();
                if let Some(size) = &analysis.reported_size {
                    details.push(format!("Explorer size: {}", size));
                }
                if let Some(backups) = &analysis.backups_size {
                    details.push(format!("Backups: {}", backups));
                }
                if let Some(cache) = &analysis.cache_size {
                    details.push(format!("Cache & temp: {}", cache));
                }
                details.push(format!(
                    "Reclaimable packages: {}",
                    analysis.reclaimable_packages
                ));
                let details_str = details.join(" | ");

                issues.push(Issue::new(
                    "sys_clean_winsxs",
                    self.id(),
                    title,
                    "System & Cache Cleaner",
                    Severity::Warning,
                    RiskScore::Medium,
                    "The Windows component store (WinSxS) holds superseded update packages and backup data that can safely be reclaimed.",
                    details_str,
                    "Clean the WinSxS component store via DISM (dism.exe /Online /Cleanup-Image /StartComponentCleanup)",
                    vec!["Run dism.exe /Online /Cleanup-Image /StartComponentCleanup (may take several minutes)".to_string()],
                ));
            }
        }

        // 2. Delivery Optimization (WUDO) Cache
        Self::send_progress(
            &progress_tx,
            22,
            "Checking the Delivery Optimization (WUDO) cache...",
            Some("Scanning the WUDO cache directories..."),
        )
        .await;

        let sys_root = self.paths.sys_root.clone();
        let wudo_dirs = discover_delivery_optimization_dirs(&sys_root);
        let wudo_stats = Self::scan_dirs(wudo_dirs).await;

        if wudo_stats.bytes > 0 || wudo_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_delivery_optimization",
                self.id(),
                format!(
                    "Delivery Optimization (WUDO) cache ({}, {} files)",
                    format_bytes(wudo_stats.bytes),
                    wudo_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Windows Update Delivery Optimization (WUDO) stores downloaded update fragments for peer-to-peer distribution on the local network.",
                format!(
                    "WUDO cache size: {} across {} files",
                    format_bytes(wudo_stats.bytes),
                    wudo_stats.files
                ),
                "Clean the WUDO cache files and run the cleanup cmdlet",
                vec![
                    "Empty the Delivery Optimization cache directories".to_string(),
                    "Run PowerShell Delete-DeliveryOptimizationCache -Force".to_string(),
                ],
            ));
        }

        // 3. Package Cache Audit
        Self::send_progress(
            &progress_tx,
            34,
            "Checking the installer package cache...",
            Some("Scanning %ProgramData%\\Package Cache..."),
        )
        .await;

        let prog_data = self.paths.prog_data.clone();
        let pkg_cache_dir = prog_data.join("Package Cache");
        let pkg_stats = Self::scan_dirs(vec![pkg_cache_dir]).await;

        if pkg_stats.bytes > 0 || pkg_stats.files > 0 {
            let mut pkg_issue = Issue::new(
                "sys_clean_package_cache",
                self.id(),
                format!(
                    "Installer package cache ({}, {} files)",
                    format_bytes(pkg_stats.bytes),
                    pkg_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Warning,
                // The fix empties the directory wholesale, including the payloads
                // of *installed* products — not a low-risk operation.
                RiskScore::High,
                "The package cache (%ProgramData%\\Package Cache) holds the install and update payloads (.msi, .cab, .exe) of Visual Studio, WiX, VC++ redistributables and .NET. WARNING: this cleanup removes the entire folder contents, not just orphaned packages.",
                format!(
                    "Package cache size: {} across {} files under %ProgramData%\\Package Cache",
                    format_bytes(pkg_stats.bytes),
                    pkg_stats.files
                ),
                "Empty the whole package cache — repairing, changing or uninstalling the affected products then requires the original installers",
                vec![
                    "Empty %ProgramData%\\Package Cache completely (locked files are skipped)".to_string(),
                    "Re-download the Visual Studio / VC++ redistributable installers afterwards if needed".to_string(),
                ],
            );
            // Not reversible by the VSS checkpoint, so it never runs unattended
            // under `--auto-fix`; the user has to select it deliberately.
            pkg_issue.is_selected = false;
            issues.push(pkg_issue);
        }

        // 4. Browser Caches
        Self::send_progress(
            &progress_tx,
            46,
            "Checking browser caches (Chrome, Edge, Firefox)...",
            Some("Scanning the Chrome, Edge and Firefox profiles..."),
        )
        .await;

        let local_app_data = self.paths.local_app_data.clone();
        let app_data = self.paths.app_data.clone();
        let browser_dirs = discover_browser_cache_dirs(&local_app_data, &app_data);
        let browser_stats = Self::scan_dirs(browser_dirs).await;

        if browser_stats.bytes > 0 || browser_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_browser_cache",
                self.id(),
                format!(
                    "Browser caches (Chrome, Edge, Firefox) ({}, {} files)",
                    format_bytes(browser_stats.bytes),
                    browser_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Browsers keep HTTP and script caches for faster load times. These caches can grow to several gigabytes.",
                format!(
                    "Total browser cache size: {} across {} files in the detected profiles",
                    format_bytes(browser_stats.bytes),
                    browser_stats.files
                ),
                "Clean browser caches (files held by active browser sessions are safely skipped)",
                vec!["Empty the Chrome / Edge / Firefox cache directories".to_string()],
            ));
        }

        // 5. Windows Setup & System Logs
        Self::send_progress(
            &progress_tx,
            58,
            "Checking Windows setup & system logs...",
            Some("Scanning the Panther, CBS, DISM and MoSetup logs..."),
        )
        .await;

        let setup_log_dirs = discover_setup_log_dirs(&sys_root);
        let setup_log_stats = Self::scan_log_dirs(setup_log_dirs).await;

        if setup_log_stats.bytes > 0 || setup_log_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_setup_logs",
                self.id(),
                format!(
                    "Windows setup & system logs ({}, {} files)",
                    format_bytes(setup_log_stats.bytes),
                    setup_log_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Windows setup (Panther/MoSetup), CBS and DISM servicing logs accumulate historical diagnostic reports.",
                format!(
                    "Setup and system logs: {} across {} files",
                    format_bytes(setup_log_stats.bytes),
                    setup_log_stats.files
                ),
                "Remove archived setup, CBS and DISM logs (active system logs are left alone)",
                vec!["Clean the Panther, CBS, DISM and MoSetup log directories".to_string()],
            ));
        }

        // 6. Error Reporting & Crash Dumps
        Self::send_progress(
            &progress_tx,
            70,
            "Checking Windows error reports & crash dumps...",
            Some("Scanning the WER archives and CrashDumps..."),
        )
        .await;

        let wer_dirs = discover_wer_and_dump_dirs(&local_app_data, &prog_data);
        let wer_stats = Self::scan_dirs(wer_dirs).await;

        if wer_stats.bytes > 0 || wer_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_error_reporting",
                self.id(),
                format!(
                    "Windows error reports & crash dumps ({}, {} files)",
                    format_bytes(wer_stats.bytes),
                    wer_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Windows Error Reporting (WER) and minidumps/CrashDumps store crash reports and memory images.",
                format!(
                    "Error reports & crash dumps: {} across {} files",
                    format_bytes(wer_stats.bytes),
                    wer_stats.files
                ),
                "Delete stored crash dumps and WER report archives",
                vec!["Empty WER ReportArchive, ReportQueue and %LOCALAPPDATA%\\CrashDumps".to_string()],
            ));
        }

        // 7. DirectX Shader & Certificate Caches
        Self::send_progress(
            &progress_tx,
            80,
            "Checking DirectX shader & certificate caches...",
            Some("Scanning D3DSCache, DirectX ShaderCache and CryptnetUrlCache..."),
        )
        .await;

        let user_profile = self.paths.user_profile.clone();
        let shader_dirs = discover_shader_and_cert_dirs(&local_app_data, &user_profile);
        let shader_stats = Self::scan_dirs(shader_dirs).await;

        if shader_stats.bytes > 0 || shader_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_shader_certs",
                self.id(),
                format!(
                    "DirectX shader & certificate caches ({}, {} files)",
                    format_bytes(shader_stats.bytes),
                    shader_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "DirectX shader caches and CryptnetUrlCache (CRL/OCSP certificate validation) store compiled shader bytecode and certificate metadata.",
                format!(
                    "Shader & certificate caches: {} across {} files",
                    format_bytes(shader_stats.bytes),
                    shader_stats.files
                ),
                "Empty stale shader builds and the CRL cache",
                vec!["Empty D3DSCache, DirectX ShaderCache and CryptnetUrlCache".to_string()],
            ));
        }

        // 8. Windows Recycle Bin
        Self::send_progress(
            &progress_tx,
            90,
            "Checking the Windows Recycle Bin...",
            Some("Scanning $Recycle.Bin on the system drives..."),
        )
        .await;

        let recycle_dirs = self.paths.recycle_bins.clone();
        let recycle_stats = Self::scan_dirs(recycle_dirs).await;

        if recycle_stats.bytes > 0 || recycle_stats.files > 0 {
            let mut recycle_issue = Issue::new(
                "sys_clean_recycle_bin",
                self.id(),
                format!(
                    "Windows Recycle Bin ({}, {} files)",
                    format_bytes(recycle_stats.bytes),
                    recycle_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                // Emptying the bin destroys user documents outright. The VSS
                // checkpoint taken before a repair run does not restore user
                // files, so there is no way back from this one.
                RiskScore::High,
                "The Windows Recycle Bin holds deleted files from every local partition. WARNING: emptying it is permanent — not even the system restore point brings these files back.",
                format!(
                    "Recycle Bin contents: {} across {} files on the detected drives",
                    format_bytes(recycle_stats.bytes),
                    recycle_stats.files
                ),
                "Permanently empty the Recycle Bin on every drive (irreversible)",
                vec!["Run PowerShell Clear-RecycleBin -Force".to_string()],
            );
            // Never runs unattended under `--auto-fix` / [A] auto-fix all: the
            // user has to tick this one themselves.
            recycle_issue.is_selected = false;
            issues.push(recycle_issue);
        }

        // 9. Extended System Temp Directories
        Self::send_progress(
            &progress_tx,
            95,
            "Checking the extended system temp directories...",
            Some("Scanning systemprofile Temp and SystemTemp..."),
        )
        .await;

        let system_temp_dirs = discover_system_temp_dirs(&sys_root);
        let system_temp_stats = Self::scan_dirs(system_temp_dirs).await;

        if system_temp_stats.bytes > 0 || system_temp_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_system_temp",
                self.id(),
                format!(
                    "Extended system temp directories ({}, {} files)",
                    format_bytes(system_temp_stats.bytes),
                    system_temp_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "System services (systemprofile) and the Windows SystemTemp directory accumulate temporary data from background services.",
                format!(
                    "Extended system temp directories: {} across {} files",
                    format_bytes(system_temp_stats.bytes),
                    system_temp_stats.files
                ),
                "Clean the extended system temp directories (locked files are skipped)",
                vec!["Clean systemprofile\\AppData\\Local\\Temp and SystemTemp".to_string()],
            ));
        }

        Self::send_progress(
            &progress_tx,
            100,
            "System and cache diagnostics complete",
            None,
        )
        .await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        let dbg = DebugTrace::fix(issue_id, progress_tx, self.config.verbose_logging);

        match issue_id {
            "sys_clean_winsxs" => {
                dbg.section("WinSxS component store cleanup").await;
                dbg.hint("DISM refuses to touch the component store without Administrator rights")
                    .await;
                let out = dbg
                    .run(
                        &self.runner,
                        "dism.exe",
                        &["/Online", "/Cleanup-Image", "/StartComponentCleanup"],
                        Duration::from_secs(300),
                    )
                    .await?;
                if out.success {
                    Ok("WinSxS component store cleaned successfully (StartComponentCleanup finished).".to_string())
                } else {
                    let err = if out.stderr.trim().is_empty() {
                        out.stdout
                    } else {
                        out.stderr
                    };
                    Err(format!("DISM error during StartComponentCleanup: {}", err))
                }
            }
            "sys_clean_delivery_optimization" => {
                // The cmdlet runs *first*: it asks the Delivery Optimization
                // service to release and flush its own cache. Sweeping the
                // directories while DoSvc still holds them open just piles every
                // file into `skipped_locked`.
                dbg.section("Delivery Optimization cache").await;
                let ps = dbg
                    .run_powershell(
                        &self.runner,
                        "Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue",
                        Duration::from_secs(30),
                    )
                    .await;
                let cmdlet_ok = matches!(&ps, Ok(out) if out.success);
                dbg.kv(
                    "cmdlet",
                    if cmdlet_ok {
                        "flushed the cache"
                    } else {
                        "did not flush - sweeping the directories instead"
                    },
                )
                .await;

                let wudo_dirs = discover_delivery_optimization_dirs(&self.paths.sys_root);
                let total_clean =
                    Self::clean_dirs_reporting(wudo_dirs, clean_path_contents, &dbg).await;

                // The cmdlet doing the work is a perfectly good outcome even
                // when the leftover sweep finds nothing, so it counts as success.
                if !cmdlet_ok {
                    return cleanup_result(
                        "Delivery Optimization (WUDO) cache cleaned",
                        total_clean,
                    );
                }
                Ok(format!(
                    "Delivery Optimization (WUDO) cache cleaned: cmdlet executed, {} further files deleted ({} freed, {} locked files skipped).",
                    total_clean.deleted_files,
                    format_bytes(total_clean.freed_bytes),
                    total_clean.skipped_locked
                ))
            }
            "sys_clean_package_cache" => {
                dbg.section("installer package cache").await;
                let pkg_cache_dir = self.paths.prog_data.join("Package Cache");
                let stats =
                    Self::clean_dirs_reporting(vec![pkg_cache_dir], clean_path_contents, &dbg)
                        .await;
                cleanup_result("Package cache cleaned", stats)
            }
            "sys_clean_browser_cache" => {
                dbg.section("browser caches").await;
                let browser_dirs =
                    discover_browser_cache_dirs(&self.paths.local_app_data, &self.paths.app_data);
                let total_clean =
                    Self::clean_dirs_reporting(browser_dirs, clean_path_contents, &dbg).await;
                cleanup_result("Browser caches cleaned", total_clean)
            }
            "sys_clean_setup_logs" => {
                dbg.section("Windows setup & system logs").await;
                let setup_log_dirs = discover_setup_log_dirs(&self.paths.sys_root);
                let total_clean =
                    Self::clean_dirs_reporting(setup_log_dirs, clean_log_dir_files, &dbg).await;
                cleanup_result("Windows setup & system logs cleaned", total_clean)
            }
            "sys_clean_error_reporting" => {
                dbg.section("error reports & crash dumps").await;
                let wer_dirs =
                    discover_wer_and_dump_dirs(&self.paths.local_app_data, &self.paths.prog_data);
                let total_clean =
                    Self::clean_dirs_reporting(wer_dirs, clean_path_contents, &dbg).await;
                cleanup_result("Windows error reports & crash dumps cleaned", total_clean)
            }
            "sys_clean_shader_certs" => {
                dbg.section("DirectX shader & certificate caches").await;
                let shader_dirs = discover_shader_and_cert_dirs(
                    &self.paths.local_app_data,
                    &self.paths.user_profile,
                );
                let total_clean =
                    Self::clean_dirs_reporting(shader_dirs, clean_path_contents, &dbg).await;
                cleanup_result("DirectX shader & certificate caches cleaned", total_clean)
            }
            "sys_clean_recycle_bin" => {
                dbg.section("emptying the Recycle Bin").await;
                dbg.hint(
                    "Clear-RecycleBin without -DriveLetter walks every drive PowerShell can see, mapped network drives included, and a single unusable drive fails the whole call",
                )
                .await;

                let out = dbg
                    .run_powershell(&self.runner, RECYCLE_BIN_SCRIPT, Duration::from_secs(60))
                    .await?;

                let report = RecycleBinReport::parse(&out.stdout);
                for (drive, outcome) in &report.drives {
                    match outcome {
                        Ok(()) => dbg.kv(&format!("drive {}:", drive), "emptied").await,
                        Err(msg) => {
                            dbg.warn(format!("drive {}: refused - {}", drive, msg))
                                .await
                        }
                    }
                }

                // The shell only ever sees entries whose `$R` payload still
                // exists. An orphaned `$I` index stub — a deleted file whose
                // data is already gone — is invisible to `Clear-RecycleBin`,
                // which then fails with "the system cannot find the file
                // specified", while the scan happily counts the stub and raises
                // the issue again on the next run. Sweeping the same
                // directories the scan measured is what breaks that loop.
                dbg.section("leftover entries on disk").await;
                dbg.kv(
                    "scope",
                    "every profile directory under the discovered $Recycle.Bin roots",
                )
                .await;
                let leftovers = Self::clean_dirs_reporting(
                    self.paths.recycle_bins.clone(),
                    clean_path_contents,
                    &dbg,
                )
                .await;

                report.into_result(leftovers, out.success, || failure_reason(&out))
            }
            "sys_clean_system_temp" => {
                dbg.section("extended system temp directories").await;
                let system_temp_dirs = discover_system_temp_dirs(&self.paths.sys_root);
                let total_clean =
                    Self::clean_dirs_reporting(system_temp_dirs, clean_path_contents, &dbg).await;
                cleanup_result("Extended system temp directories cleaned", total_clean)
            }
            _ => Err(format!("Unknown issue ID: {}", issue_id)),
        }
    }
}

/// Empty the Recycle Bin one drive at a time, naming each drive in the output.
///
/// `Clear-RecycleBin` without `-DriveLetter` walks every drive PowerShell can
/// see, and one drive it cannot handle — a mapped network share, a drive whose
/// bin was never created — fails the entire call. Combined with
/// `-ErrorAction SilentlyContinue` that produced the worst possible outcome:
/// the error text was discarded while PowerShell still exited non-zero, so the
/// repair failed with a blank reason and nothing to act on.
///
/// Catching per drive inside the script keeps each message, and stops one bad
/// drive from hiding the drives that were emptied.
const RECYCLE_BIN_SCRIPT: &str = r#"
$ErrorActionPreference = 'Continue'
foreach ($vol in Get-Volume) {
    if (-not $vol.DriveLetter) { continue }
    if ($vol.DriveType -ne 'Fixed') { continue }
    $letter = $vol.DriveLetter
    try {
        Clear-RecycleBin -DriveLetter $letter -Force -Confirm:$false -ErrorAction Stop
        Write-Output "DRIVE $letter OK"
    } catch {
        Write-Output "DRIVE $letter ERR $($_.Exception.Message -replace '\s+', ' ')"
    }
}
"#;

/// Per-drive outcome parsed out of [`RECYCLE_BIN_SCRIPT`]'s output.
#[derive(Debug, Default, PartialEq, Eq)]
struct RecycleBinReport {
    /// Drive letter and whether it could be emptied, in the script's order.
    drives: Vec<(String, Result<(), String>)>,
}

impl RecycleBinReport {
    fn parse(stdout: &str) -> Self {
        let mut drives = Vec::new();
        for line in stdout.lines() {
            let Some(rest) = line.trim().strip_prefix("DRIVE ") else {
                continue;
            };
            let mut parts = rest.splitn(3, ' ');
            let (Some(letter), Some(status)) = (parts.next(), parts.next()) else {
                continue;
            };
            let detail = parts.next().unwrap_or("").trim();
            let outcome = match status {
                "OK" => Ok(()),
                _ if detail.is_empty() => Err("no reason reported".to_string()),
                _ => Err(detail.to_string()),
            };
            drives.push((letter.to_string(), outcome));
        }
        Self { drives }
    }

    /// Turn the per-drive outcomes and the leftover sweep into one result.
    ///
    /// A drive that refused is worth reporting even when others succeeded, so a
    /// partial run stays a success with the refusals spelled out rather than
    /// silently claiming every drive was emptied. And a shell that refused
    /// everywhere is still a completed repair when the sweep removed the
    /// entries it choked on — otherwise the run reports failure over files that
    /// are, by then, gone.
    ///
    /// `shell_ok` and `shell_failure` describe the PowerShell run itself, for
    /// the case where it never produced a single per-drive line.
    fn into_result(
        self,
        leftovers: CleanStats,
        shell_ok: bool,
        shell_failure: impl FnOnce() -> String,
    ) -> Result<String, String> {
        let cleared: Vec<String> = self
            .drives
            .iter()
            .filter(|(_, outcome)| outcome.is_ok())
            .map(|(letter, _)| format!("{}:", letter))
            .collect();
        let refused: Vec<String> = self
            .drives
            .iter()
            .filter_map(|(letter, outcome)| {
                outcome
                    .as_ref()
                    .err()
                    .map(|msg| format!("{}: {}", letter, msg))
            })
            .collect();

        let swept = if leftovers.deleted_files > 0 {
            format!(
                " {} leftover entries removed from disk ({} freed).",
                leftovers.deleted_files,
                format_bytes(leftovers.freed_bytes)
            )
        } else {
            String::new()
        };

        if !cleared.is_empty() {
            return Ok(if refused.is_empty() {
                format!(
                    "Windows Recycle Bin emptied successfully on every drive ({}).{}",
                    cleared.join(", "),
                    swept
                )
            } else {
                format!(
                    "Windows Recycle Bin emptied on {} - refused on {}.{}",
                    cleared.join(", "),
                    refused.join("; "),
                    swept
                )
            });
        }

        // Nothing the shell would admit to clearing. The sweep decides.
        if leftovers.deleted_files > 0 {
            let reason = if refused.is_empty() {
                shell_failure()
            } else {
                refused.join("; ")
            };
            return Ok(format!(
                "Windows Recycle Bin: the shell cleared nothing ({}), but{}",
                reason,
                swept.trim_end_matches('.')
            ));
        }

        if refused.is_empty() && shell_ok {
            return Ok("Windows Recycle Bin emptied successfully on every drive.".to_string());
        }

        Err(format!(
            "Failed to empty the Recycle Bin: {}",
            if refused.is_empty() {
                shell_failure()
            } else {
                refused.join("; ")
            }
        ))
    }
}

/// What is still sitting in `dir` after a sweep, up to `limit` entries.
///
/// A sweep only counts how many files it could not remove. Since it removes
/// everything it can, whatever is left is exactly what was locked — so reading
/// the directory back names them without threading paths through `CleanStats`.
fn remaining_entries(dir: &Path, limit: usize) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(limit)
        .map(|entry| {
            let size = entry
                .metadata()
                .map(|m| format_bytes(m.len()))
                .unwrap_or_else(|_| "size unknown".to_string());
            format!("{} ({})", entry.path().display(), size)
        })
        .collect()
}

/// The most informative reason a command can give for having failed.
///
/// An empty string is a reason in itself and says so, rather than leaving the
/// user with a message that stops after the colon.
fn failure_reason(out: &crate::utils::cmd::CmdOutput) -> String {
    for stream in [out.stderr.trim(), out.stdout.trim()] {
        if !stream.is_empty() {
            return stream.to_string();
        }
    }
    format!(
        "the command exited with code {} without writing any reason - it was suppressed rather than absent",
        out.exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use std::fs::{File, create_dir_all};
    use std::io::Write;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("winmedic_test_{}_{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            create_dir_all(&path).unwrap();
            Self { path }
        }

        fn create_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
            let full_path = self.path.join(rel_path);
            if let Some(parent) = full_path.parent() {
                create_dir_all(parent).unwrap();
            }
            let mut file = File::create(&full_path).unwrap();
            file.write_all(content).unwrap();
            full_path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// A module whose every filesystem root lives inside `dir`.
    ///
    /// `scan` and `fix` delete for real, so no test may ever construct this
    /// module with [`CleanerPaths::from_env`] — that would point it at the test
    /// machine's own browser caches, WER archives and `C:\Windows\Panther`.
    fn sandboxed(dir: &TestDir, runner: Arc<dyn CommandRunner>) -> SystemCleanerModule {
        SystemCleanerModule::with_runner_and_paths(
            ModuleConfig::default(),
            runner,
            CleanerPaths::rooted_at(&dir.path),
        )
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(10 * 1024 * 1024), "10.0 MB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn test_parse_winsxs_english() {
        let sample = "\
Explorer Reported Size of Component Store : 8.12 GB
Actual Size of Component Store : 7.85 GB
    Shared with Windows : 4.50 GB
    Backups and Disabled Features : 2.50 GB
    Cache and Temporary Data : 0.85 GB
Date of Last Cleanup : 2026-08-10 14:00:00
Number of Reclaimable Packages : 3
Component Store Cleanup Recommended : Yes
The operation completed successfully.";

        let analysis = parse_winsxs_analysis(sample);
        assert!(analysis.cleanup_recommended);
        assert_eq!(analysis.reclaimable_packages, 3);
        assert_eq!(analysis.reported_size, Some("8.12 GB".to_string()));
        assert_eq!(analysis.backups_size, Some("2.50 GB".to_string()));
        assert_eq!(analysis.cache_size, Some("0.85 GB".to_string()));
    }

    #[test]
    fn test_parse_winsxs_german() {
        let sample = "\
Größe des Komponentenspeichers laut Explorer : 9.45 GB
Tatsächliche Größe des Komponentenspeichers : 8.90 GB
    Für Windows freigegeben : 5.10 GB
    Sicherungen und deaktivierte Features : 3.15 GB
    Cache und temporäre Daten : 0.65 GB
Datum der letzten Bereinigung : 2026-08-01 10:00:00
Anzahl der wiederverwendbaren Pakete : 5
Bereinigung des Komponentenspeichers empfohlen : Ja
Der Vorgang wurde erfolgreich beendet.";

        let analysis = parse_winsxs_analysis(sample);
        assert!(analysis.cleanup_recommended);
        assert_eq!(analysis.reclaimable_packages, 5);
        assert_eq!(analysis.reported_size, Some("9.45 GB".to_string()));
        assert_eq!(analysis.backups_size, Some("3.15 GB".to_string()));
        assert_eq!(analysis.cache_size, Some("0.65 GB".to_string()));
    }

    #[test]
    fn test_parse_winsxs_no_cleanup_needed() {
        let sample = "\
Explorer Reported Size of Component Store : 6.00 GB
Actual Size of Component Store : 5.80 GB
Number of Reclaimable Packages : 0
Component Store Cleanup Recommended : No
The operation completed successfully.";

        let analysis = parse_winsxs_analysis(sample);
        assert!(!analysis.cleanup_recommended);
        assert_eq!(analysis.reclaimable_packages, 0);
    }

    #[test]
    fn test_scan_and_clean_path_recursive() {
        let td = TestDir::new("scan_clean_test");
        td.create_file("file1.txt", b"hello world");
        td.create_file("sub/file2.txt", b"second file content");
        td.create_file("sub/deep/file3.txt", b"third file");

        let stats = scan_path_recursive(&td.path);
        assert_eq!(stats.files, 3);
        assert_eq!(stats.bytes, 11 + 19 + 10);

        let clean_res = clean_path_contents(&td.path);
        assert_eq!(clean_res.deleted_files, 3);
        assert_eq!(clean_res.freed_bytes, 11 + 19 + 10);
        assert_eq!(clean_res.skipped_locked, 0);

        let stats_after = scan_path_recursive(&td.path);
        assert_eq!(stats_after.files, 0);
        assert_eq!(stats_after.bytes, 0);
    }

    #[test]
    fn test_scan_and_clean_log_dir_files() {
        let td = TestDir::new("log_clean_test");
        td.create_file("setupact.log", b"log data 1");
        td.create_file("archive.cab", b"cab archive");
        td.create_file("important.doc", b"do not delete me");
        td.create_file("sub/CbsPersist_1.log", b"cbs log");
        td.create_file("sub/test.etl", b"etl trace");

        let stats = scan_log_dir_files(&td.path);
        assert_eq!(stats.files, 4); // .log, .cab, .log, .etl

        let clean_res = clean_log_dir_files(&td.path);
        assert_eq!(clean_res.deleted_files, 4);

        assert!(td.path.join("important.doc").exists());
        assert!(!td.path.join("setupact.log").exists());
    }

    #[test]
    fn test_browser_cache_discovery() {
        let td = TestDir::new("browser_discovery");
        let local_app_data = td.path.join("Local");
        let app_data = td.path.join("Roaming");

        // Mock Chrome structure
        td.create_file(
            "Local/Google/Chrome/User Data/Default/Cache/data_0",
            b"cache",
        );
        td.create_file(
            "Local/Google/Chrome/User Data/Profile 1/Code Cache/js/entry",
            b"code",
        );

        // Mock Edge structure
        td.create_file(
            "Local/Microsoft/Edge/User Data/Default/Cache/data_1",
            b"edge cache",
        );

        // Mock Firefox structure
        td.create_file(
            "Local/Mozilla/Firefox/Profiles/abc.default/cache2/entries/1",
            b"ff cache",
        );

        let dirs = discover_browser_cache_dirs(&local_app_data, &app_data);
        assert!(dirs.len() >= 4);

        let mut total_stats = DirStats::default();
        for dir in &dirs {
            let stats = scan_path_recursive(dir);
            total_stats.bytes += stats.bytes;
            total_stats.files += stats.files;
        }
        assert_eq!(total_stats.files, 4);
    }

    #[tokio::test]
    async fn test_winsxs_scan_and_fix() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "AnalyzeComponentStore",
            CmdOutput::ok(
                "Explorer Reported Size of Component Store : 8.12 GB\n\
                 Number of Reclaimable Packages : 2\n\
                 Component Store Cleanup Recommended : Yes\n",
            ),
        );
        mock.add_response(
            "StartComponentCleanup",
            CmdOutput::ok("The operation completed successfully."),
        );

        let td = TestDir::new("winsxs_scan_fix");
        let module = sandboxed(&td, Arc::new(mock.clone()));
        let issues = module.scan(None).await.unwrap();

        let winsxs = issues.iter().find(|i| i.id == "sys_clean_winsxs");
        assert!(winsxs.is_some());
        let issue = winsxs.unwrap();
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.title.contains("2 reclaimable packages"));

        let fix_res = module.fix("sys_clean_winsxs", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("StartComponentCleanup finished"));

        let executed = mock.executed();
        assert!(
            executed
                .iter()
                .any(|cmd| cmd.contains("AnalyzeComponentStore"))
        );
        assert!(
            executed
                .iter()
                .any(|cmd| cmd.contains("StartComponentCleanup"))
        );
    }

    #[tokio::test]
    async fn test_winsxs_scan_ignores_failed_dism_run() {
        // DISM prints partial store figures before erroring out; a non-zero exit
        // must not be parsed as a real analysis.
        let mock = MockCommandRunner::new();
        mock.add_response(
            "AnalyzeComponentStore",
            CmdOutput::with_output(
                740,
                "Number of Reclaimable Packages : 7\n\
                 Component Store Cleanup Recommended : Yes\n",
                "Error: 740 - elevated permissions required",
            ),
        );

        let td = TestDir::new("winsxs_failed_dism");
        let module = sandboxed(&td, Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        assert!(issues.iter().all(|i| i.id != "sys_clean_winsxs"));
    }

    #[tokio::test]
    async fn test_recycle_bin_fix() {
        let mock = MockCommandRunner::new();
        mock.add_response("Clear-RecycleBin", CmdOutput::ok(""));

        let td = TestDir::new("recycle_bin_fix");
        let module = sandboxed(&td, Arc::new(mock.clone()));
        let fix_res = module.fix("sys_clean_recycle_bin", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Windows Recycle Bin"));

        let executed = mock.executed();
        assert!(executed.iter().any(|cmd| cmd.contains("Clear-RecycleBin")));
    }

    /// The failure that started all of this: PowerShell exits non-zero while
    /// `-ErrorAction SilentlyContinue` has already thrown the reason away, and
    /// the repair reports "Failed to empty the Recycle Bin:" with nothing after
    /// the colon. Whatever else changes, the message must never end there again.
    #[tokio::test]
    async fn a_silent_recycle_bin_failure_still_reports_a_reason() {
        let mock = MockCommandRunner::new();
        mock.add_response("Clear-RecycleBin", CmdOutput::failed(1, ""));

        let td = TestDir::new("recycle_bin_silent_failure");
        let module = sandboxed(&td, Arc::new(mock));
        let err = module.fix("sys_clean_recycle_bin", None).await.unwrap_err();

        assert!(
            !err.trim_end().ends_with(':'),
            "message stops dead: {}",
            err
        );
        assert!(err.contains("exited with code 1"), "{}", err);
        assert!(err.contains("suppressed rather than absent"), "{}", err);
    }

    #[tokio::test]
    async fn a_refusing_drive_is_named_and_the_working_drives_still_count() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "Clear-RecycleBin",
            CmdOutput::ok("DRIVE C OK\r\nDRIVE D ERR Das Laufwerk wurde nicht gefunden.\r\n"),
        );

        let td = TestDir::new("recycle_bin_partial");
        let module = sandboxed(&td, Arc::new(mock));
        let msg = module.fix("sys_clean_recycle_bin", None).await.unwrap();

        assert!(msg.contains("C:"), "{}", msg);
        assert!(
            msg.contains("D: Das Laufwerk wurde nicht gefunden."),
            "{}",
            msg
        );
    }

    #[test]
    fn the_recycle_bin_report_reads_per_drive_lines() {
        let report = RecycleBinReport::parse(
            "some banner\nDRIVE C OK\nDRIVE D ERR access denied on D\nDRIVE E ERR\nnoise",
        );

        assert_eq!(
            report.drives,
            vec![
                ("C".to_string(), Ok(())),
                ("D".to_string(), Err("access denied on D".to_string())),
                ("E".to_string(), Err("no reason reported".to_string())),
            ]
        );
    }

    #[test]
    fn every_drive_refusing_with_nothing_swept_is_a_failed_repair() {
        let report = RecycleBinReport::parse("DRIVE C ERR bin is locked");
        let err = report
            .into_result(CleanStats::default(), false, || "unused".to_string())
            .unwrap_err();
        assert!(err.contains("C: bin is locked"), "{}", err);
    }

    /// The case from the field: `Clear-RecycleBin` cannot see orphaned `$I`
    /// index stubs and fails, but the sweep removes them. The files really are
    /// gone by then, so calling the repair failed would be a lie — and the scan
    /// would raise the same issue forever.
    #[test]
    fn a_sweep_that_cleared_the_leftovers_rescues_a_refusing_shell() {
        let report = RecycleBinReport::parse(
            "DRIVE C ERR Das System kann die angegebene Datei nicht finden",
        );
        let swept = CleanStats {
            freed_bytes: 2607,
            deleted_files: 16,
            skipped_locked: 0,
        };

        let msg = report
            .into_result(swept, false, || "unused".to_string())
            .expect("a completed sweep is a completed repair");
        assert!(msg.contains("16 leftover entries"), "{}", msg);
        assert!(
            msg.contains("nicht finden"),
            "the shell's own reason must survive: {}",
            msg
        );
    }

    #[test]
    fn output_without_drive_lines_yields_no_verdict() {
        assert!(RecycleBinReport::parse("").drives.is_empty());
        assert!(RecycleBinReport::parse("DRIVE\nDRIVE C").drives.is_empty());
    }

    #[tokio::test]
    async fn test_destructive_issues_are_not_auto_selected() {
        let mock = MockCommandRunner::new();
        let td = TestDir::new("auto_select_guard");
        // Both destructive locations get content so the issues are raised.
        td.create_file("$Recycle.Bin/S-1-5-21/deleted.docx", b"user document");
        td.create_file(
            "ProgramData/Package Cache/vs/setup.msi",
            b"installer payload",
        );

        let module = sandboxed(&td, Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        for id in ["sys_clean_recycle_bin", "sys_clean_package_cache"] {
            let issue = issues
                .iter()
                .find(|i| i.id == id)
                .unwrap_or_else(|| panic!("{} should have been detected", id));
            assert_eq!(
                issue.risk_score,
                RiskScore::High,
                "{} destroys data that no restore point brings back",
                id
            );
            assert!(
                !issue.is_selected,
                "{} must not be picked up by --auto-fix without the user asking",
                id
            );
        }

        // The reversible cache sweeps stay selected by default.
        for id in ["sys_clean_browser_cache", "sys_clean_setup_logs"] {
            if let Some(issue) = issues.iter().find(|i| i.id == id) {
                assert!(issue.is_selected);
            }
        }
    }

    #[tokio::test]
    async fn test_delivery_optimization_fix_runs_cmdlet_before_sweep() {
        let mock = MockCommandRunner::new();
        mock.add_response("Delete-DeliveryOptimizationCache", CmdOutput::ok(""));

        let td = TestDir::new("wudo_fix");
        td.create_file(
            "Windows/SoftwareDistribution/DeliveryOptimization/frag.dat",
            &[7u8; 512],
        );

        let module = sandboxed(&td, Arc::new(mock.clone()));
        let fix_res = module.fix("sys_clean_delivery_optimization", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Delivery Optimization"));

        // The service is asked to release its own cache before files are swept.
        let executed = mock.executed();
        assert!(
            executed
                .iter()
                .any(|cmd| cmd.contains("Delete-DeliveryOptimizationCache"))
        );
        assert!(
            !td.path
                .join("Windows/SoftwareDistribution/DeliveryOptimization/frag.dat")
                .exists()
        );
    }

    #[tokio::test]
    async fn test_package_cache_fix() {
        let mock = MockCommandRunner::new();
        let td = TestDir::new("pkg_cache_fix");
        let module = sandboxed(&td, Arc::new(mock));
        let fix_res = module.fix("sys_clean_package_cache", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Package cache cleaned"));
    }

    #[tokio::test]
    async fn test_browser_cache_fix() {
        let mock = MockCommandRunner::new();
        let td = TestDir::new("browser_cache_fix");
        let module = sandboxed(&td, Arc::new(mock));
        let fix_res = module.fix("sys_clean_browser_cache", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Browser caches cleaned"));
    }

    #[tokio::test]
    async fn test_setup_logs_fix() {
        let mock = MockCommandRunner::new();
        let td = TestDir::new("setup_logs_fix");
        let module = sandboxed(&td, Arc::new(mock));
        let fix_res = module.fix("sys_clean_setup_logs", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("setup & system logs cleaned"));
    }

    #[tokio::test]
    async fn test_error_reporting_fix() {
        let mock = MockCommandRunner::new();
        let td = TestDir::new("wer_fix");
        let module = sandboxed(&td, Arc::new(mock));
        let fix_res = module.fix("sys_clean_error_reporting", None).await;
        assert!(fix_res.is_ok());
        let msg = fix_res.unwrap();
        assert!(msg.contains("error reports & crash dumps cleaned"));
        // Every cleanup arm now reports the locked-file count.
        assert!(msg.contains("locked files skipped"));
    }

    #[tokio::test]
    async fn test_shader_certs_fix() {
        let mock = MockCommandRunner::new();
        let td = TestDir::new("shader_fix");
        let module = sandboxed(&td, Arc::new(mock));
        let fix_res = module.fix("sys_clean_shader_certs", None).await;
        assert!(fix_res.is_ok());
        let msg = fix_res.unwrap();
        assert!(msg.contains("DirectX shader & certificate caches cleaned"));
        assert!(msg.contains("locked files skipped"));
    }

    #[tokio::test]
    async fn test_system_temp_fix() {
        let mock = MockCommandRunner::new();
        let td = TestDir::new("system_temp_fix");
        let module = sandboxed(&td, Arc::new(mock));
        let fix_res = module.fix("sys_clean_system_temp", None).await;
        assert!(fix_res.is_ok());
        assert!(
            fix_res
                .unwrap()
                .contains("Extended system temp directories cleaned")
        );
    }

    #[test]
    fn test_cleanup_result_reports_total_lockout_as_failure() {
        // Nothing removed and everything locked is a failed repair, not a
        // success with a zero count.
        let all_locked = CleanStats {
            freed_bytes: 0,
            deleted_files: 0,
            skipped_locked: 12,
        };
        let res = cleanup_result("Browser caches cleaned", all_locked);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("12"));

        // Partial progress still counts as success.
        let partial = CleanStats {
            freed_bytes: 2048,
            deleted_files: 3,
            skipped_locked: 4,
        };
        let res = cleanup_result("Browser caches cleaned", partial);
        assert!(res.is_ok());
        let msg = res.unwrap();
        assert!(msg.contains("3 files deleted"));
        assert!(msg.contains("2.0 KB"));
        assert!(msg.contains("4 locked"));

        // An empty directory is a no-op success.
        assert!(cleanup_result("X", CleanStats::default()).is_ok());
    }

    #[test]
    fn test_cleaner_paths_rooted_at_stays_inside_base() {
        let base = Path::new(r"C:\sandbox");
        let paths = CleanerPaths::rooted_at(base);
        for p in [
            &paths.sys_root,
            &paths.prog_data,
            &paths.local_app_data,
            &paths.app_data,
            &paths.user_profile,
        ] {
            assert!(p.starts_with(base), "{:?} escaped the sandbox", p);
        }
        assert!(paths.recycle_bins.iter().all(|p| p.starts_with(base)));
    }

    #[tokio::test]
    async fn test_unknown_issue_fix_returns_error() {
        let mock = MockCommandRunner::new();
        let td = TestDir::new("unknown_fix");
        let module = sandboxed(&td, Arc::new(mock));
        let fix_res = module.fix("sys_clean_non_existent", None).await;
        assert!(fix_res.is_err());
        assert!(fix_res.unwrap_err().contains("Unknown issue ID"));
    }
}
