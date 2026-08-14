use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

/// Directory statistics collected during scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirStats {
    pub bytes: u64,
    pub files: usize,
}

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
pub fn scan_path_recursive(path: &Path) -> DirStats {
    let mut stats = DirStats::default();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = p.symlink_metadata() {
                if meta.is_file() || meta.is_symlink() {
                    stats.bytes += meta.len();
                    stats.files += 1;
                } else if meta.is_dir() {
                    let sub = scan_path_recursive(&p);
                    stats.bytes += sub.bytes;
                    stats.files += sub.files;
                }
            }
        }
    }
    stats
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
        } else if trimmed.contains("explorer reported size")
            || trimmed.contains("laut explorer")
        {
            if let Some((_, val)) = line.split_once(':') {
                analysis.reported_size = Some(val.trim().to_string());
            }
        } else if trimmed.contains("backups and disabled features")
            || trimmed.contains("sicherungen und deaktivierte features")
        {
            if let Some((_, val)) = line.split_once(':') {
                analysis.backups_size = Some(val.trim().to_string());
            }
        } else if trimmed.contains("cache and temporary data")
            || trimmed.contains("cache und temporäre daten")
        {
            if let Some((_, val)) = line.split_once(':') {
                analysis.cache_size = Some(val.trim().to_string());
            }
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
        sys_root.join("SoftwareDistribution").join("DeliveryOptimization"),
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
    let chrome_user_data = local_app_data.join("Google").join("Chrome").join("User Data");
    if chrome_user_data.exists() {
        if let Ok(entries) = std::fs::read_dir(&chrome_user_data) {
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
    }

    // Edge
    let edge_user_data = local_app_data.join("Microsoft").join("Edge").join("User Data");
    if edge_user_data.exists() {
        if let Ok(entries) = std::fs::read_dir(&edge_user_data) {
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
    }

    // Firefox
    let ff_roots = [
        local_app_data.join("Mozilla").join("Firefox").join("Profiles"),
        app_data.join("Mozilla").join("Firefox").join("Profiles"),
    ];
    for ff_root in &ff_roots {
        if ff_root.exists() {
            if let Ok(entries) = std::fs::read_dir(ff_root) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        dirs.push(p.join("cache2"));
                    }
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
        local_app_data.join("Microsoft").join("DirectX").join("ShaderCache"),
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

pub struct SystemCleanerModule {
    _config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
}

impl SystemCleanerModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            _config: config,
            runner,
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
        "Bereinigt WinSxS, Delivery Optimization, Browser-Caches, Setup-Logs, Shader-Caches und temporäre Systemdaten."
    }

    fn icon(&self) -> &'static str {
        "[CLR]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. WinSxS Component Store Deep Clean
        Self::send_progress(
            &progress_tx,
            10,
            "Analysiere WinSxS Komponentenspeicher...",
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

        if let Ok(out) = dism_check {
            let analysis = parse_winsxs_analysis(&out.stdout);
            if analysis.cleanup_recommended || analysis.reclaimable_packages > 0 {
                let title = if analysis.reclaimable_packages > 0 {
                    format!(
                        "WinSxS Komponenten-Store Bereinigung empfohlen ({} wiederverwendbare Pakete)",
                        analysis.reclaimable_packages
                    )
                } else {
                    "WinSxS Komponenten-Store Bereinigung empfohlen".to_string()
                };

                let mut details = Vec::new();
                if let Some(size) = &analysis.reported_size {
                    details.push(format!("Explorer-Größe: {}", size));
                }
                if let Some(backups) = &analysis.backups_size {
                    details.push(format!("Sicherungen: {}", backups));
                }
                if let Some(cache) = &analysis.cache_size {
                    details.push(format!("Cache & Temp: {}", cache));
                }
                details.push(format!(
                    "Wiederverwendbare Pakete: {}",
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
                    "Der Windows-Komponentenspeicher (WinSxS) enthält veraltete Update-Pakete und Sicherungsdaten, die sicher freigegeben werden können.",
                    details_str,
                    "WinSxS Komponentenspeicher via DISM bereinigen (dism.exe /Online /Cleanup-Image /StartComponentCleanup)",
                    vec!["dism.exe /Online /Cleanup-Image /StartComponentCleanup ausführen (kann einige Minuten dauern)".to_string()],
                ));
            }
        }

        // 2. Delivery Optimization (WUDO) Cache
        Self::send_progress(
            &progress_tx,
            22,
            "Prüfe Delivery Optimization (WUDO) Cache...",
            Some("Scanne WUDO Cache-Verzeichnisse..."),
        )
        .await;

        let sys_root = get_system_root();
        let wudo_dirs = discover_delivery_optimization_dirs(&sys_root);
        let mut wudo_stats = DirStats::default();
        for dir in &wudo_dirs {
            let stats = scan_path_recursive(dir);
            wudo_stats.bytes += stats.bytes;
            wudo_stats.files += stats.files;
        }

        if wudo_stats.bytes > 0 || wudo_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_delivery_optimization",
                self.id(),
                format!(
                    "Delivery Optimization (WUDO) Cache ({}, {} Dateien)",
                    format_bytes(wudo_stats.bytes),
                    wudo_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Windows Update Delivery Optimization (WUDO) speichert heruntergeladene Update-Fragmente für Peer-to-Peer-Verteilung im lokalen Netzwerk.",
                format!(
                    "WUDO Cache-Größe: {} in {} Dateien",
                    format_bytes(wudo_stats.bytes),
                    wudo_stats.files
                ),
                "WUDO Cache-Dateien bereinigen und Bereinigungs-Cmdlet ausführen",
                vec![
                    "Delivery Optimization Cache-Verzeichnisse leeren".to_string(),
                    "PowerShell Delete-DeliveryOptimizationCache -Force ausführen".to_string(),
                ],
            ));
        }

        // 3. Package Cache Audit
        Self::send_progress(
            &progress_tx,
            34,
            "Prüfe Installer Package Cache...",
            Some("Scanne %ProgramData%\\Package Cache..."),
        )
        .await;

        let prog_data = get_program_data();
        let pkg_cache_dir = prog_data.join("Package Cache");
        let pkg_stats = scan_path_recursive(&pkg_cache_dir);

        if pkg_stats.bytes > 0 || pkg_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_package_cache",
                self.id(),
                format!(
                    "Installer Package Cache ({}, {} Dateien)",
                    format_bytes(pkg_stats.bytes),
                    pkg_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Warning,
                RiskScore::Low,
                "Im Package Cache (%ProgramData%\\Package Cache) verbleiben oft alte Installations- und Update-Payloads (.msi, .cab, .exe) von Visual Studio, WiX und VC++ Redists.",
                format!(
                    "Package Cache Größe: {} in {} Dateien unter %ProgramData%\\Package Cache",
                    format_bytes(pkg_stats.bytes),
                    pkg_stats.files
                ),
                "Verwaiste Installer-Paket-Caches bereinigen (gesperrte Dateien werden übersprungen)",
                vec!["%ProgramData%\\Package Cache durchsuchen und alte Pakete entfernen".to_string()],
            ));
        }

        // 4. Browser Caches
        Self::send_progress(
            &progress_tx,
            46,
            "Prüfe Browser-Caches (Chrome, Edge, Firefox)...",
            Some("Scanne Chrome-, Edge- und Firefox-Profile..."),
        )
        .await;

        let local_app_data = get_local_app_data();
        let app_data = get_app_data();
        let browser_dirs = discover_browser_cache_dirs(&local_app_data, &app_data);
        let mut browser_stats = DirStats::default();
        for dir in &browser_dirs {
            let stats = scan_path_recursive(dir);
            browser_stats.bytes += stats.bytes;
            browser_stats.files += stats.files;
        }

        if browser_stats.bytes > 0 || browser_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_browser_cache",
                self.id(),
                format!(
                    "Browser-Caches (Chrome, Edge, Firefox) ({}, {} Dateien)",
                    format_bytes(browser_stats.bytes),
                    browser_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Browser speichern HTTP- und Script-Caches für schnellere Ladezeiten. Diese Caches können mehrere Gigabyte an Speicher belegen.",
                format!(
                    "Gesamtgröße Browser-Caches: {} in {} Dateien über erkannte Profile",
                    format_bytes(browser_stats.bytes),
                    browser_stats.files
                ),
                "Browser-Caches bereinigen (Dateien aktiver Browser-Sitzungen werden sicher übersprungen)",
                vec!["Chrome / Edge / Firefox Cache-Verzeichnisse leeren".to_string()],
            ));
        }

        // 5. Windows Setup & System Logs
        Self::send_progress(
            &progress_tx,
            58,
            "Prüfe Windows Setup- & System-Logs...",
            Some("Scanne Panther, CBS, DISM und MoSetup Logs..."),
        )
        .await;

        let setup_log_dirs = discover_setup_log_dirs(&sys_root);
        let mut setup_log_stats = DirStats::default();
        for dir in &setup_log_dirs {
            let stats = scan_log_dir_files(dir);
            setup_log_stats.bytes += stats.bytes;
            setup_log_stats.files += stats.files;
        }

        if setup_log_stats.bytes > 0 || setup_log_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_setup_logs",
                self.id(),
                format!(
                    "Windows Setup- & System-Logs ({}, {} Dateien)",
                    format_bytes(setup_log_stats.bytes),
                    setup_log_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Windows Setup- (Panther/MoSetup), CBS- und DISM-Wartungsprotokolle akkumulieren historische Diagnoseberichte.",
                format!(
                    "Setup- und System-Logs: {} in {} Dateien",
                    format_bytes(setup_log_stats.bytes),
                    setup_log_stats.files
                ),
                "Archivierte Setup-, CBS- und DISM-Logs entfernen (aktive Systemlogs werden geschont)",
                vec!["Panther, CBS, DISM und MoSetup Log-Verzeichnisse bereinigen".to_string()],
            ));
        }

        // 6. Error Reporting & Crash Dumps
        Self::send_progress(
            &progress_tx,
            70,
            "Prüfe Windows-Fehlerberichte & Crash-Dumps...",
            Some("Scanne WER-Archive und CrashDumps..."),
        )
        .await;

        let wer_dirs = discover_wer_and_dump_dirs(&local_app_data, &prog_data);
        let mut wer_stats = DirStats::default();
        for dir in &wer_dirs {
            let stats = scan_path_recursive(dir);
            wer_stats.bytes += stats.bytes;
            wer_stats.files += stats.files;
        }

        if wer_stats.bytes > 0 || wer_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_error_reporting",
                self.id(),
                format!(
                    "Windows-Fehlerberichte & Crash-Dumps ({}, {} Dateien)",
                    format_bytes(wer_stats.bytes),
                    wer_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Windows Error Reporting (WER) und Minidumps/CrashDumps speichern Absturzberichte und Speicherabbilder.",
                format!(
                    "Fehlerberichte & Crash-Dumps: {} in {} Dateien",
                    format_bytes(wer_stats.bytes),
                    wer_stats.files
                ),
                "Gespeicherte Absturzabbilder und WER-Berichtsarchive löschen",
                vec!["WER ReportArchive, ReportQueue und %LOCALAPPDATA%\\CrashDumps leeren".to_string()],
            ));
        }

        // 7. DirectX Shader & Certificate Caches
        Self::send_progress(
            &progress_tx,
            80,
            "Prüfe DirectX Shader & Zertifikats-Caches...",
            Some("Scanne D3DSCache, DirectX ShaderCache und CryptnetUrlCache..."),
        )
        .await;

        let user_profile = get_user_profile();
        let shader_dirs = discover_shader_and_cert_dirs(&local_app_data, &user_profile);
        let mut shader_stats = DirStats::default();
        for dir in &shader_dirs {
            let stats = scan_path_recursive(dir);
            shader_stats.bytes += stats.bytes;
            shader_stats.files += stats.files;
        }

        if shader_stats.bytes > 0 || shader_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_shader_certs",
                self.id(),
                format!(
                    "DirectX Shader & Zertifikats-Caches ({}, {} Dateien)",
                    format_bytes(shader_stats.bytes),
                    shader_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "DirectX Shader-Caches und CryptnetUrlCache (CRL/OCSP Zertifikatsvalidierung) speichern kompilierte Shader-Bytecodes und Zertifikatsmetadaten.",
                format!(
                    "Shader- & Zertifikats-Caches: {} in {} Dateien",
                    format_bytes(shader_stats.bytes),
                    shader_stats.files
                ),
                "Veraltete Shader-Kompilate und CRL-Cache leeren",
                vec!["D3DSCache, DirectX ShaderCache und CryptnetUrlCache leeren".to_string()],
            ));
        }

        // 8. Windows Recycle Bin
        Self::send_progress(
            &progress_tx,
            90,
            "Prüfe Windows Papierkorb...",
            Some("Scanne $Recycle.Bin auf Systemlaufwerken..."),
        )
        .await;

        let recycle_dirs = discover_recycle_bin_dirs();
        let mut recycle_stats = DirStats::default();
        for dir in &recycle_dirs {
            let stats = scan_path_recursive(dir);
            recycle_stats.bytes += stats.bytes;
            recycle_stats.files += stats.files;
        }

        if recycle_stats.bytes > 0 || recycle_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_recycle_bin",
                self.id(),
                format!(
                    "Windows Papierkorb ({}, {} Dateien)",
                    format_bytes(recycle_stats.bytes),
                    recycle_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Der Windows Papierkorb enthält gelöschte Dateien auf allen lokalen Partitionen.",
                format!(
                    "Papierkorb-Inhalt: {} in {} Dateien auf erkannten Laufwerken",
                    format_bytes(recycle_stats.bytes),
                    recycle_stats.files
                ),
                "Papierkorb über alle Laufwerke vollständig leeren",
                vec!["PowerShell Clear-RecycleBin -Force ausführen".to_string()],
            ));
        }

        // 9. Extended System Temp Directories
        Self::send_progress(
            &progress_tx,
            95,
            "Prüfe erweiterte System-Temp Verzeichnisse...",
            Some("Scanne systemprofile Temp und SystemTemp..."),
        )
        .await;

        let system_temp_dirs = discover_system_temp_dirs(&sys_root);
        let mut system_temp_stats = DirStats::default();
        for dir in &system_temp_dirs {
            let stats = scan_path_recursive(dir);
            system_temp_stats.bytes += stats.bytes;
            system_temp_stats.files += stats.files;
        }

        if system_temp_stats.bytes > 0 || system_temp_stats.files > 0 {
            issues.push(Issue::new(
                "sys_clean_system_temp",
                self.id(),
                format!(
                    "Erweiterte System-Temp Verzeichnisse ({}, {} Dateien)",
                    format_bytes(system_temp_stats.bytes),
                    system_temp_stats.files
                ),
                "System & Cache Cleaner",
                Severity::Info,
                RiskScore::Low,
                "Systemdienste (systemprofile) und das Windows SystemTemp-Verzeichnis akkumulieren temporäre Daten von Hintergrunddiensten.",
                format!(
                    "Erweiterte System-Temp Verzeichnisse: {} in {} Dateien",
                    format_bytes(system_temp_stats.bytes),
                    system_temp_stats.files
                ),
                "Erweiterte System-Temp Verzeichnisse bereinigen (gesperrte Dateien werden übersprungen)",
                vec!["systemprofile\\AppData\\Local\\Temp und SystemTemp bereinigen".to_string()],
            ));
        }

        Self::send_progress(
            &progress_tx,
            100,
            "System- und Cache-Diagnose abgeschlossen",
            None,
        )
        .await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        match issue_id {
            "sys_clean_winsxs" => {
                let out = self
                    .runner
                    .run(
                        "dism.exe",
                        &["/Online", "/Cleanup-Image", "/StartComponentCleanup"],
                        Duration::from_secs(300),
                    )
                    .await?;
                if out.success {
                    Ok("WinSxS Komponentenspeicher erfolgreich bereinigt (StartComponentCleanup abgeschlossen).".to_string())
                } else {
                    let err = if out.stderr.trim().is_empty() {
                        out.stdout
                    } else {
                        out.stderr
                    };
                    Err(format!("DISM-Fehler bei StartComponentCleanup: {}", err))
                }
            }
            "sys_clean_delivery_optimization" => {
                let sys_root = get_system_root();
                let wudo_dirs = discover_delivery_optimization_dirs(&sys_root);
                let mut total_clean = CleanStats::default();
                for dir in &wudo_dirs {
                    let stats = clean_path_contents(dir);
                    total_clean.freed_bytes += stats.freed_bytes;
                    total_clean.deleted_files += stats.deleted_files;
                    total_clean.skipped_locked += stats.skipped_locked;
                }

                let _ = self
                    .runner
                    .run_powershell(
                        "Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue",
                        Duration::from_secs(30),
                    )
                    .await;

                Ok(format!(
                    "Delivery Optimization (WUDO) Cache bereinigt: {} Dateien gelöscht (ca. {} freigegeben).",
                    total_clean.deleted_files,
                    format_bytes(total_clean.freed_bytes)
                ))
            }
            "sys_clean_package_cache" => {
                let prog_data = get_program_data();
                let pkg_cache_dir = prog_data.join("Package Cache");
                let stats = clean_path_contents(&pkg_cache_dir);

                Ok(format!(
                    "Package Cache bereinigt: {} Dateien gelöscht (ca. {} freigegeben, {} gesperrte Dateien übersprungen).",
                    stats.deleted_files,
                    format_bytes(stats.freed_bytes),
                    stats.skipped_locked
                ))
            }
            "sys_clean_browser_cache" => {
                let local_app_data = get_local_app_data();
                let app_data = get_app_data();
                let browser_dirs = discover_browser_cache_dirs(&local_app_data, &app_data);
                let mut total_clean = CleanStats::default();
                for dir in &browser_dirs {
                    let stats = clean_path_contents(dir);
                    total_clean.freed_bytes += stats.freed_bytes;
                    total_clean.deleted_files += stats.deleted_files;
                    total_clean.skipped_locked += stats.skipped_locked;
                }

                Ok(format!(
                    "Browser-Caches bereinigt: {} Dateien gelöscht ({} freigegeben, {} gesperrte Dateien übersprungen).",
                    total_clean.deleted_files,
                    format_bytes(total_clean.freed_bytes),
                    total_clean.skipped_locked
                ))
            }
            "sys_clean_setup_logs" => {
                let sys_root = get_system_root();
                let setup_log_dirs = discover_setup_log_dirs(&sys_root);
                let mut total_clean = CleanStats::default();
                for dir in &setup_log_dirs {
                    let stats = clean_log_dir_files(dir);
                    total_clean.freed_bytes += stats.freed_bytes;
                    total_clean.deleted_files += stats.deleted_files;
                    total_clean.skipped_locked += stats.skipped_locked;
                }

                Ok(format!(
                    "Windows Setup- & System-Logs bereinigt: {} Dateien gelöscht ({} freigegeben, {} gesperrte Dateien übersprungen).",
                    total_clean.deleted_files,
                    format_bytes(total_clean.freed_bytes),
                    total_clean.skipped_locked
                ))
            }
            "sys_clean_error_reporting" => {
                let local_app_data = get_local_app_data();
                let prog_data = get_program_data();
                let wer_dirs = discover_wer_and_dump_dirs(&local_app_data, &prog_data);
                let mut total_clean = CleanStats::default();
                for dir in &wer_dirs {
                    let stats = clean_path_contents(dir);
                    total_clean.freed_bytes += stats.freed_bytes;
                    total_clean.deleted_files += stats.deleted_files;
                    total_clean.skipped_locked += stats.skipped_locked;
                }

                Ok(format!(
                    "Windows-Fehlerberichte & Crash-Dumps bereinigt: {} Dateien gelöscht (ca. {} freigegeben).",
                    total_clean.deleted_files,
                    format_bytes(total_clean.freed_bytes)
                ))
            }
            "sys_clean_shader_certs" => {
                let local_app_data = get_local_app_data();
                let user_profile = get_user_profile();
                let shader_dirs = discover_shader_and_cert_dirs(&local_app_data, &user_profile);
                let mut total_clean = CleanStats::default();
                for dir in &shader_dirs {
                    let stats = clean_path_contents(dir);
                    total_clean.freed_bytes += stats.freed_bytes;
                    total_clean.deleted_files += stats.deleted_files;
                    total_clean.skipped_locked += stats.skipped_locked;
                }

                Ok(format!(
                    "DirectX Shader & Zertifikats-Caches bereinigt: {} Dateien gelöscht (ca. {} freigegeben).",
                    total_clean.deleted_files,
                    format_bytes(total_clean.freed_bytes)
                ))
            }
            "sys_clean_recycle_bin" => {
                let out = self
                    .runner
                    .run_powershell(
                        "Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
                        Duration::from_secs(30),
                    )
                    .await?;
                if out.success {
                    Ok("Windows Papierkorb auf allen Laufwerken erfolgreich geleert.".to_string())
                } else {
                    Err(format!("Fehler beim Leeren des Papierkorbs: {}", out.stderr))
                }
            }
            "sys_clean_system_temp" => {
                let sys_root = get_system_root();
                let system_temp_dirs = discover_system_temp_dirs(&sys_root);
                let mut total_clean = CleanStats::default();
                for dir in &system_temp_dirs {
                    let stats = clean_path_contents(dir);
                    total_clean.freed_bytes += stats.freed_bytes;
                    total_clean.deleted_files += stats.deleted_files;
                    total_clean.skipped_locked += stats.skipped_locked;
                }

                Ok(format!(
                    "Erweiterte System-Temp Verzeichnisse bereinigt: {} Dateien gelöscht (ca. {} freigegeben, {} gesperrte Dateien übersprungen).",
                    total_clean.deleted_files,
                    format_bytes(total_clean.freed_bytes),
                    total_clean.skipped_locked
                ))
            }
            _ => Err(format!("Unbekannte Problem-ID: {}", issue_id)),
        }
    }
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
            let path = std::env::temp_dir().join(format!("winmedic_test_{}_{}", name, std::process::id()));
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
        td.create_file("Local/Google/Chrome/User Data/Default/Cache/data_0", b"cache");
        td.create_file("Local/Google/Chrome/User Data/Profile 1/Code Cache/js/entry", b"code");

        // Mock Edge structure
        td.create_file("Local/Microsoft/Edge/User Data/Default/Cache/data_1", b"edge cache");

        // Mock Firefox structure
        td.create_file("Local/Mozilla/Firefox/Profiles/abc.default/cache2/entries/1", b"ff cache");

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

        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let issues = module.scan(None).await.unwrap();

        let winsxs = issues.iter().find(|i| i.id == "sys_clean_winsxs");
        assert!(winsxs.is_some());
        let issue = winsxs.unwrap();
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.title.contains("2 wiederverwendbare Pakete"));

        let fix_res = module.fix("sys_clean_winsxs", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("StartComponentCleanup abgeschlossen"));

        let executed = mock.executed();
        assert!(executed.iter().any(|cmd| cmd.contains("AnalyzeComponentStore")));
        assert!(executed.iter().any(|cmd| cmd.contains("StartComponentCleanup")));
    }

    #[tokio::test]
    async fn test_recycle_bin_fix() {
        let mock = MockCommandRunner::new();
        mock.add_response("Clear-RecycleBin", CmdOutput::ok(""));

        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let fix_res = module.fix("sys_clean_recycle_bin", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Windows Papierkorb"));

        let executed = mock.executed();
        assert!(executed.iter().any(|cmd| cmd.contains("Clear-RecycleBin")));
    }

    #[tokio::test]
    async fn test_delivery_optimization_fix() {
        let mock = MockCommandRunner::new();
        mock.add_response("Delete-DeliveryOptimizationCache", CmdOutput::ok(""));

        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock.clone()));
        let fix_res = module.fix("sys_clean_delivery_optimization", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Delivery Optimization"));
    }

    #[tokio::test]
    async fn test_package_cache_fix() {
        let mock = MockCommandRunner::new();
        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let fix_res = module.fix("sys_clean_package_cache", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Package Cache bereinigt"));
    }

    #[tokio::test]
    async fn test_browser_cache_fix() {
        let mock = MockCommandRunner::new();
        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let fix_res = module.fix("sys_clean_browser_cache", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Browser-Caches bereinigt"));
    }

    #[tokio::test]
    async fn test_setup_logs_fix() {
        let mock = MockCommandRunner::new();
        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let fix_res = module.fix("sys_clean_setup_logs", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Setup- & System-Logs bereinigt"));
    }

    #[tokio::test]
    async fn test_error_reporting_fix() {
        let mock = MockCommandRunner::new();
        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let fix_res = module.fix("sys_clean_error_reporting", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Fehlerberichte & Crash-Dumps bereinigt"));
    }

    #[tokio::test]
    async fn test_shader_certs_fix() {
        let mock = MockCommandRunner::new();
        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let fix_res = module.fix("sys_clean_shader_certs", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("DirectX Shader & Zertifikats-Caches bereinigt"));
    }

    #[tokio::test]
    async fn test_system_temp_fix() {
        let mock = MockCommandRunner::new();
        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let fix_res = module.fix("sys_clean_system_temp", None).await;
        assert!(fix_res.is_ok());
        assert!(fix_res.unwrap().contains("Erweiterte System-Temp Verzeichnisse bereinigt"));
    }

    #[tokio::test]
    async fn test_unknown_issue_fix_returns_error() {
        let mock = MockCommandRunner::new();
        let module = SystemCleanerModule::with_runner(ModuleConfig::default(), Arc::new(mock));
        let fix_res = module.fix("sys_clean_non_existent", None).await;
        assert!(fix_res.is_err());
        assert!(fix_res.unwrap_err().contains("Unbekannte Problem-ID"));
    }
}
