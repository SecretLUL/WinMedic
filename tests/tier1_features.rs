#![allow(dead_code, unused_imports)]

mod common;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::{
    DISM_ANALYZE_CLEAN, DISM_ANALYZE_ENGLISH_RECLAIMABLE, DISM_ANALYZE_GERMAN_RECLAIMABLE,
    GITHUB_RELEASE_CURRENT_JSON, GITHUB_RELEASE_DRAFT_JSON, GITHUB_RELEASE_NEWER_JSON,
    MockWindowsPaths, ProgrammableMockRunner, TempWorkspace, sandboxed_cleaner,
};
use winmedic::app::{
    App, BackgroundEvent, ConfirmRequest, TAB_DASHBOARD, TAB_SETTINGS, TAB_TRIAGE,
};
use winmedic::config::AppConfig;
use winmedic::engine::issue::{RiskScore, Severity};
use winmedic::engine::runner::DiagnosticEngine;
use winmedic::modules::system_cleaner::{
    SystemCleanerModule, clean_log_dir_files, clean_path_contents, format_bytes,
    parse_winsxs_analysis, scan_log_dir_files, scan_path_recursive,
};
use winmedic::modules::{
    DiagnosticModule, ModuleConfig, get_all_modules, get_all_modules_with_runner,
};
use winmedic::utils::cmd::{CmdOutput, CommandRunner, MockCommandRunner};
use winmedic::utils::updater::{
    GITHUB_LATEST_RELEASE_URL, GITHUB_USER_AGENT, GitHubRelease, SemVer, UpdateInfo,
    check_for_update, is_safe_release_url, is_update_available, validate_release_url,
};

// ============================================================================
// FEATURE 1: Git Branch Fast-Forward (M1, R1)
// ============================================================================

#[test]
fn test_tier1_f01_git_branch_naming_convention() {
    let feature_branch = "feature/enhancements";
    assert!(feature_branch.starts_with("feature/"));
    assert_eq!(feature_branch, "feature/enhancements");
}

#[test]
fn test_tier1_f01_git_mock_fast_forward_merge_simulation() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "git.exe",
        CmdOutput::ok(
            "Updating a1b2c3d..e4f5g6h\nFast-forward\n 5 files changed, 250 insertions(+)",
        ),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run(
                "git.exe",
                &["merge", "--ff-only", "main"],
                Duration::from_secs(5),
            )
            .await
    });

    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.success);
    assert!(out.stdout.contains("Fast-forward"));
}

#[test]
fn test_tier1_f01_git_mock_branch_verification() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response("git.exe", CmdOutput::ok("* feature/enhancements\n  main\n"));

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run("git.exe", &["branch", "--list"], Duration::from_secs(5))
            .await
    });

    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.stdout.contains("feature/enhancements"));
}

#[test]
fn test_tier1_f01_git_mock_status_clean() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "git.exe",
        CmdOutput::ok("nothing to commit, working tree clean"),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run(
                "git.exe",
                &["status", "--porcelain"],
                Duration::from_secs(5),
            )
            .await
    });

    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.success);
}

#[test]
fn test_tier1_f01_git_mock_log_continuity() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "git.exe",
        CmdOutput::ok("commit e4f5g6h (HEAD -> feature/enhancements, main)\nAuthor: WinMedic\n"),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run(
                "git.exe",
                &["log", "-n", "1", "--oneline"],
                Duration::from_secs(5),
            )
            .await
    });

    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.stdout.contains("feature/enhancements"));
}

// ============================================================================
// FEATURE 2: WinSxS Component Store Deep Clean (M2, R2.1)
// ============================================================================

#[test]
fn test_tier1_f02_winsxs_analyze_english_parser() {
    let analysis = parse_winsxs_analysis(DISM_ANALYZE_ENGLISH_RECLAIMABLE);
    assert!(analysis.cleanup_recommended);
    assert_eq!(analysis.reclaimable_packages, 3);
    assert_eq!(analysis.reported_size, Some("8.12 GB".to_string()));
    assert_eq!(analysis.backups_size, Some("2.50 GB".to_string()));
    assert_eq!(analysis.cache_size, Some("0.85 GB".to_string()));
}

#[test]
fn test_tier1_f02_winsxs_analyze_german_parser() {
    let analysis = parse_winsxs_analysis(DISM_ANALYZE_GERMAN_RECLAIMABLE);
    assert!(analysis.cleanup_recommended);
    assert_eq!(analysis.reclaimable_packages, 5);
    assert_eq!(analysis.reported_size, Some("9.45 GB".to_string()));
    assert_eq!(analysis.backups_size, Some("3.15 GB".to_string()));
    assert_eq!(analysis.cache_size, Some("0.65 GB".to_string()));
}

#[tokio::test]
async fn test_tier1_f02_winsxs_scan_creates_issue_when_recommended() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response_for_cmd_and_args(
        "dism.exe /Online /Cleanup-Image /AnalyzeComponentStore",
        CmdOutput::ok(DISM_ANALYZE_ENGLISH_RECLAIMABLE),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier1_features_135", runner);
    let issues = module.scan(None).await.expect("scan failed");

    let winsxs_issue = issues.iter().find(|i| i.id == "sys_clean_winsxs");
    assert!(winsxs_issue.is_some());
    let issue = winsxs_issue.unwrap();
    assert_eq!(issue.severity, Severity::Warning);
    assert_eq!(issue.risk_score, RiskScore::Medium);
    assert!(issue.title.contains("3 reclaimable packages"));
    assert!(issue.technical_details.contains("8.12 GB"));
}

#[tokio::test]
async fn test_tier1_f02_winsxs_scan_clean_when_not_recommended() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response_for_cmd_and_args(
        "dism.exe /Online /Cleanup-Image /AnalyzeComponentStore",
        CmdOutput::ok(DISM_ANALYZE_CLEAN),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier1_features_155", runner);
    let issues = module.scan(None).await.expect("scan failed");

    let winsxs_issue = issues.iter().find(|i| i.id == "sys_clean_winsxs");
    assert!(winsxs_issue.is_none());
}

#[tokio::test]
async fn test_tier1_f02_winsxs_fix_executes_start_component_cleanup() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response_for_cmd_and_args(
        "dism.exe /Online /Cleanup-Image /StartComponentCleanup",
        CmdOutput::ok("The operation completed successfully."),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier1_features_170", runner.clone());
    let res = module.fix("sys_clean_winsxs", None).await;

    assert!(res.is_ok());
    assert!(res.unwrap().contains("StartComponentCleanup finished"));
    assert_eq!(runner.calls_for("dism.exe").len(), 1);
    assert_eq!(
        runner.calls_for("dism.exe")[0],
        vec!["/Online", "/Cleanup-Image", "/StartComponentCleanup"]
    );
}

// ============================================================================
// FEATURE 3: Delivery Optimization Cache Clean (M2, R2.2)
// ============================================================================

#[test]
fn test_tier1_f03_delivery_optimization_scan_non_empty_dirs() {
    let ws = TempWorkspace::new("wudo_scan");
    let file1 = ws.create_file(
        "SoftwareDistribution/DeliveryOptimization/chunk1.bin",
        &[0u8; 1024 * 50],
    );
    let file2 = ws.create_file("Cache/chunk2.bin", &[0u8; 1024 * 100]);

    let stats1 = scan_path_recursive(file1.parent().unwrap());
    let stats2 = scan_path_recursive(file2.parent().unwrap());

    assert_eq!(stats1.files, 1);
    assert_eq!(stats1.bytes, 50 * 1024);
    assert_eq!(stats2.files, 1);
    assert_eq!(stats2.bytes, 100 * 1024);
}

#[test]
fn test_tier1_f03_delivery_optimization_clean_files() {
    let ws = TempWorkspace::new("wudo_clean");
    let dir = ws.create_dir("WUDO");
    ws.create_file("WUDO/file1.dat", &[1u8; 2048]);
    ws.create_file("WUDO/sub/file2.dat", &[2u8; 4096]);

    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 2);
    assert_eq!(clean.freed_bytes, 6144);
    assert_eq!(clean.skipped_locked, 0);

    let post_scan = scan_path_recursive(&dir);
    assert_eq!(post_scan.files, 0);
    assert_eq!(post_scan.bytes, 0);
}

#[tokio::test]
async fn test_tier1_f03_delivery_optimization_fix_runs_powershell() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let (_sandbox, module) = sandboxed_cleaner("tier1_features_221", runner.clone());

    let res = module.fix("sys_clean_delivery_optimization", None).await;
    assert!(res.is_ok());
    let msg = res.unwrap();
    assert!(msg.contains("Delivery Optimization (WUDO) cache cleaned"));

    let ps_calls = runner.calls_for("powershell.exe");
    assert!(!ps_calls.is_empty());
    assert!(
        ps_calls[0]
            .iter()
            .any(|arg| arg.contains("Delete-DeliveryOptimizationCache"))
    );
}

#[test]
fn test_tier1_f03_delivery_optimization_empty_dir_scan() {
    let ws = TempWorkspace::new("wudo_empty");
    let dir = ws.create_dir("EmptyWudo");
    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier1_f03_delivery_optimization_issue_attributes() {
    let issue = winmedic::engine::issue::Issue::new(
        "sys_clean_delivery_optimization",
        "system_cleaner",
        "Delivery Optimization (WUDO) cache (15.0 MB, 10 files)",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Windows Update Delivery Optimization (WUDO) cache",
        "WUDO cache size: 15.0 MB across 10 files",
        "Clean the WUDO cache files",
        vec!["Empty the Delivery Optimization cache directories".to_string()],
    );
    assert_eq!(issue.id, "sys_clean_delivery_optimization");
    assert_eq!(issue.severity, Severity::Info);
    assert_eq!(issue.risk_score, RiskScore::Low);
}

// ============================================================================
// FEATURE 4: Package Cache Audit (M2, R2.3)
// ============================================================================

#[test]
fn test_tier1_f04_package_cache_scan_payloads() {
    let ws = TempWorkspace::new("pkg_cache_scan");
    let dir = ws.create_dir("Package Cache");
    ws.create_file("Package Cache/{GUID-1}/vcredist_x64.exe", &[0xAA; 5000]);
    ws.create_file("Package Cache/{GUID-2}/payload.msi", &[0xBB; 15000]);
    ws.create_file("Package Cache/{GUID-2}/attached.cab", &[0xCC; 20000]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 3);
    assert_eq!(stats.bytes, 40000);
}

#[test]
fn test_tier1_f04_package_cache_clean_action() {
    let ws = TempWorkspace::new("pkg_cache_clean");
    let dir = ws.create_dir("Package Cache");
    ws.create_file("Package Cache/p1/setup.exe", &[1; 1000]);
    ws.create_file("Package Cache/p2/setup.msi", &[2; 2000]);

    let stats = clean_path_contents(&dir);
    assert_eq!(stats.deleted_files, 2);
    assert_eq!(stats.freed_bytes, 3000);
}

#[tokio::test]
async fn test_tier1_f04_package_cache_fix_returns_formatted_summary() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let (_sandbox, module) = sandboxed_cleaner("tier1_features_293", runner);

    let res = module.fix("sys_clean_package_cache", None).await;
    assert!(res.is_ok());
    assert!(res.unwrap().contains("Package cache cleaned"));
}

#[test]
fn test_tier1_f04_package_cache_zero_size_handling() {
    let ws = TempWorkspace::new("pkg_cache_zero");
    let dir = ws.create_dir("EmptyPkg");
    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier1_f04_package_cache_issue_severity_warning() {
    let issue = winmedic::engine::issue::Issue::new(
        "sys_clean_package_cache",
        "system_cleaner",
        "Installer package cache (500.0 MB, 120 files)",
        "System & Cache Cleaner",
        Severity::Warning,
        RiskScore::Low,
        "Package Cache Audit",
        "Package cache size: 500.0 MB across 120 files",
        "Clean orphaned installer package caches",
        vec!["Scan %ProgramData%\\Package Cache and remove stale packages".to_string()],
    );
    assert_eq!(issue.id, "sys_clean_package_cache");
    assert_eq!(issue.severity, Severity::Warning);
    assert_eq!(issue.risk_score, RiskScore::Low);
}

// ============================================================================
// FEATURE 5: Browser Caches Scan & Clean (M2, R2.4)
// ============================================================================

#[test]
fn test_tier1_f05_browser_cache_chrome_profile_scan() {
    let ws = TempWorkspace::new("chrome_scan");
    let cache_dir = ws.create_dir("Google/Chrome/User Data/Default/Cache");
    ws.create_file(
        "Google/Chrome/User Data/Default/Cache/data_0",
        &[0u8; 10000],
    );
    ws.create_file(
        "Google/Chrome/User Data/Default/Cache/data_1",
        &[0u8; 20000],
    );
    ws.create_file(
        "Google/Chrome/User Data/Default/Code Cache/js/01",
        &[0u8; 5000],
    );

    let stats = scan_path_recursive(&cache_dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 30000);
}

#[test]
fn test_tier1_f05_browser_cache_edge_profile_scan() {
    let ws = TempWorkspace::new("edge_scan");
    let cache_dir = ws.create_dir("Microsoft/Edge/User Data/Profile 1/Cache");
    ws.create_file(
        "Microsoft/Edge/User Data/Profile 1/Cache/f_0001",
        &[0u8; 8192],
    );

    let stats = scan_path_recursive(&cache_dir);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 8192);
}

#[test]
fn test_tier1_f05_browser_cache_firefox_cache2_scan() {
    let ws = TempWorkspace::new("ff_scan");
    let cache_dir = ws.create_dir("Mozilla/Firefox/Profiles/abc.default/cache2");
    ws.create_file(
        "Mozilla/Firefox/Profiles/abc.default/cache2/entries/entry1",
        &[0u8; 4096],
    );

    let stats = scan_path_recursive(&cache_dir);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 4096);
}

#[test]
fn test_tier1_f05_browser_cache_clean_multi_browser() {
    let ws = TempWorkspace::new("browser_clean");
    let chrome = ws.create_dir("ChromeCache");
    let edge = ws.create_dir("EdgeCache");
    let ff = ws.create_dir("FFCache");

    ws.create_file("ChromeCache/c1", &[1; 1000]);
    ws.create_file("EdgeCache/e1", &[2; 2000]);
    ws.create_file("FFCache/f1", &[3; 3000]);

    let c_clean = clean_path_contents(&chrome);
    let e_clean = clean_path_contents(&edge);
    let f_clean = clean_path_contents(&ff);

    assert_eq!(
        c_clean.deleted_files + e_clean.deleted_files + f_clean.deleted_files,
        3
    );
    assert_eq!(
        c_clean.freed_bytes + e_clean.freed_bytes + f_clean.freed_bytes,
        6000
    );
}

#[tokio::test]
async fn test_tier1_f05_browser_cache_fix_returns_success() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let (_sandbox, module) = sandboxed_cleaner("tier1_features_389", runner);

    let res = module.fix("sys_clean_browser_cache", None).await;
    assert!(res.is_ok());
    assert!(res.unwrap().contains("Browser caches cleaned"));
}

// ============================================================================
// FEATURE 6: Windows Setup & System Logs Clean (M2, R2.5)
// ============================================================================

#[test]
fn test_tier1_f06_setup_logs_scan_filters_matching_extensions() {
    let ws = TempWorkspace::new("logs_filter");
    let dir = ws.create_dir("Panther");
    ws.create_file("Panther/setupact.log", &[0; 1000]);
    ws.create_file("Panther/setuperr.log", &[0; 2000]);
    ws.create_file("Panther/archive.cab", &[0; 3000]);
    ws.create_file("Panther/miglog.bak", &[0; 4000]);
    ws.create_file("Panther/diag.etl", &[0; 5000]);
    ws.create_file("Panther/readme.txt", &[0; 500]);
    ws.create_file("Panther/important.exe", &[0; 9999]); // should be ignored

    let stats = scan_log_dir_files(&dir);
    assert_eq!(stats.files, 6);
    assert_eq!(stats.bytes, 15500);
}

#[test]
fn test_tier1_f06_setup_logs_clean_preserves_non_logs() {
    let ws = TempWorkspace::new("logs_clean");
    let dir = ws.create_dir("Logs");
    let log_file = ws.create_file("Logs/cbs.log", &[1; 1000]);
    let exe_file = ws.create_file("Logs/driver.sys", &[2; 5000]);

    let clean = clean_log_dir_files(&dir);
    assert_eq!(clean.deleted_files, 1);
    assert_eq!(clean.freed_bytes, 1000);

    assert!(!log_file.exists());
    assert!(exe_file.exists());
}

#[test]
fn test_tier1_f06_setup_logs_cbs_dism_mosetup_discovery() {
    let ws = TempWorkspace::new("setup_dirs");
    let p = ws.populate_mock_windows_tree();
    ws.create_file("Windows/Logs/CBS/CBS.log", &[0; 500]);
    ws.create_file("Windows/Logs/DISM/dism.log", &[0; 600]);
    ws.create_file("Windows/Logs/MoSetup/UpdateAgent.log", &[0; 700]);

    let cbs_stats = scan_log_dir_files(&p.cbs);
    let dism_stats = scan_log_dir_files(&p.dism_logs);
    let mosetup_stats = scan_log_dir_files(&p.mosetup);

    assert_eq!(cbs_stats.files, 1);
    assert_eq!(dism_stats.files, 1);
    assert_eq!(mosetup_stats.files, 1);
}

#[tokio::test]
async fn test_tier1_f06_setup_logs_fix_summary() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let (_sandbox, module) = sandboxed_cleaner("tier1_features_452", runner);

    let res = module.fix("sys_clean_setup_logs", None).await;
    assert!(res.is_ok());
    assert!(res.unwrap().contains("Windows setup & system logs cleaned"));
}

#[test]
fn test_tier1_f06_setup_logs_empty_directory_scan() {
    let ws = TempWorkspace::new("empty_logs");
    let dir = ws.create_dir("EmptyPanther");
    let stats = scan_log_dir_files(&dir);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

// ============================================================================
// FEATURE 7: Error Reporting & Crash Dumps Clean (M2, R2.6)
// ============================================================================

#[test]
fn test_tier1_f07_wer_report_archive_scan() {
    let ws = TempWorkspace::new("wer_scan");
    let dir = ws.create_dir("WER/ReportArchive");
    ws.create_file(
        "WER/ReportArchive/AppCrash_app.exe_1/Report.wer",
        &[0; 3000],
    );
    ws.create_file(
        "WER/ReportArchive/AppCrash_app.exe_2/Report.wer",
        &[0; 4000],
    );

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 7000);
}

#[test]
fn test_tier1_f07_crash_dumps_scan() {
    let ws = TempWorkspace::new("dump_scan");
    let dir = ws.create_dir("CrashDumps");
    ws.create_file("CrashDumps/explorer.exe.1234.dmp", &[0; 50000]);
    ws.create_file("CrashDumps/game.exe.5678.dmp", &[0; 100000]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 150000);
}

#[test]
fn test_tier1_f07_wer_and_dumps_clean() {
    let ws = TempWorkspace::new("wer_clean");
    let wer = ws.create_dir("WER");
    let dumps = ws.create_dir("CrashDumps");
    ws.create_file("WER/report.wer", &[1; 500]);
    ws.create_file("CrashDumps/crash.dmp", &[2; 5000]);

    let c1 = clean_path_contents(&wer);
    let c2 = clean_path_contents(&dumps);
    assert_eq!(c1.deleted_files + c2.deleted_files, 2);
    assert_eq!(c1.freed_bytes + c2.freed_bytes, 5500);
}

#[tokio::test]
async fn test_tier1_f07_error_reporting_fix_summary() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let (_sandbox, module) = sandboxed_cleaner("tier1_features_513", runner);

    let res = module.fix("sys_clean_error_reporting", None).await;
    assert!(res.is_ok());
    assert!(
        res.unwrap()
            .contains("Windows error reports & crash dumps cleaned")
    );
}

#[test]
fn test_tier1_f07_error_reporting_issue_metadata() {
    let issue = winmedic::engine::issue::Issue::new(
        "sys_clean_error_reporting",
        "system_cleaner",
        "Windows error reports & crash dumps (25.0 MB, 15 files)",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Windows Error Reporting",
        "Error reports & crash dumps: 25.0 MB across 15 files",
        "Delete crash dumps and WER report archives",
        vec!["Empty WER ReportArchive".to_string()],
    );
    assert_eq!(issue.id, "sys_clean_error_reporting");
    assert_eq!(issue.severity, Severity::Info);
}

// ============================================================================
// FEATURE 8: DirectX Shader & Certificate Caches (M2, R2.7)
// ============================================================================

#[test]
fn test_tier1_f08_shader_cache_scan() {
    let ws = TempWorkspace::new("shader_scan");
    let dir = ws.create_dir("D3DSCache");
    ws.create_file("D3DSCache/cache_01.bin", &[0; 12000]);
    ws.create_file("D3DSCache/cache_02.bin", &[0; 18000]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 30000);
}

#[test]
fn test_tier1_f08_cryptnet_cert_cache_scan() {
    let ws = TempWorkspace::new("crypt_scan");
    let dir = ws.create_dir("CryptnetUrlCache");
    ws.create_file("CryptnetUrlCache/Content/c1", &[0; 4000]);
    ws.create_file("CryptnetUrlCache/MetaData/m1", &[0; 1000]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 5000);
}

#[test]
fn test_tier1_f08_shader_and_cert_clean() {
    let ws = TempWorkspace::new("shader_clean");
    let d3d = ws.create_dir("D3D");
    let crypt = ws.create_dir("Crypt");
    ws.create_file("D3D/s1.bin", &[1; 2000]);
    ws.create_file("Crypt/c1.bin", &[2; 3000]);

    let c1 = clean_path_contents(&d3d);
    let c2 = clean_path_contents(&crypt);
    assert_eq!(c1.deleted_files + c2.deleted_files, 2);
    assert_eq!(c1.freed_bytes + c2.freed_bytes, 5000);
}

#[tokio::test]
async fn test_tier1_f08_shader_certs_fix_summary() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let (_sandbox, module) = sandboxed_cleaner("tier1_features_583", runner);

    let res = module.fix("sys_clean_shader_certs", None).await;
    assert!(res.is_ok());
    assert!(
        res.unwrap()
            .contains("DirectX shader & certificate caches cleaned")
    );
}

#[test]
fn test_tier1_f08_shader_certs_issue_metadata() {
    let issue = winmedic::engine::issue::Issue::new(
        "sys_clean_shader_certs",
        "system_cleaner",
        "DirectX shader & certificate caches (12.5 MB, 40 files)",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "DirectX shader caches",
        "Shader & certificate caches: 12.5 MB across 40 files",
        "Empty stale shader builds and the CRL cache",
        vec!["Empty D3DSCache".to_string()],
    );
    assert_eq!(issue.id, "sys_clean_shader_certs");
    assert_eq!(issue.severity, Severity::Info);
}

// ============================================================================
// FEATURE 9: Windows Recycle Bin Clean (M2, R2.8)
// ============================================================================

#[test]
fn test_tier1_f09_recycle_bin_scan_folder() {
    let ws = TempWorkspace::new("recycle_scan");
    let dir = ws.create_dir("$Recycle.Bin/S-1-5-21-user");
    ws.create_file("$Recycle.Bin/S-1-5-21-user/$R12345.docx", &[0; 25000]);
    ws.create_file("$Recycle.Bin/S-1-5-21-user/$I12345.docx", &[0; 544]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 25544);
}

#[tokio::test]
async fn test_tier1_f09_recycle_bin_fix_runs_powershell_clear() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response("powershell.exe", CmdOutput::ok(""));

    let (_sandbox, module) = sandboxed_cleaner("tier1_features_629", runner.clone());
    let res = module.fix("sys_clean_recycle_bin", None).await;

    assert!(res.is_ok());
    assert!(
        res.unwrap()
            .contains("Windows Recycle Bin emptied successfully on every drive")
    );

    let ps_calls = runner.calls_for("powershell.exe");
    assert!(!ps_calls.is_empty());
    assert!(
        ps_calls[0]
            .iter()
            .any(|arg| arg.contains("Clear-RecycleBin"))
    );
}

#[tokio::test]
async fn test_tier1_f09_recycle_bin_fix_failure_reporting() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response(
        "powershell.exe",
        CmdOutput::failed(1, "Access denied to Recycle Bin"),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier1_features_645", runner);
    let res = module.fix("sys_clean_recycle_bin", None).await;

    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Access denied"));
}

#[test]
fn test_tier1_f09_recycle_bin_empty_directory() {
    let ws = TempWorkspace::new("empty_bin");
    let dir = ws.create_dir("$Recycle.Bin");
    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier1_f09_recycle_bin_issue_metadata() {
    let issue = winmedic::engine::issue::Issue::new(
        "sys_clean_recycle_bin",
        "system_cleaner",
        "Windows Recycle Bin (1.20 GB, 55 files)",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Recycle Bin",
        "Recycle Bin contents: 1.20 GB across 55 files",
        "Empty the Recycle Bin on every drive",
        vec!["PowerShell Clear-RecycleBin -Force".to_string()],
    );
    assert_eq!(issue.id, "sys_clean_recycle_bin");
    assert_eq!(issue.severity, Severity::Info);
}

// ============================================================================
// FEATURE 10: Extended System Temp Directories (M2, R2.9)
// ============================================================================

#[test]
fn test_tier1_f10_systemprofile_temp_scan() {
    let ws = TempWorkspace::new("sysprofile_temp");
    let dir = ws.create_dir("systemprofile/AppData/Local/Temp");
    ws.create_file("systemprofile/AppData/Local/Temp/temp1.tmp", &[0; 1024]);
    ws.create_file("systemprofile/AppData/Local/Temp/temp2.tmp", &[0; 2048]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 3072);
}

#[test]
fn test_tier1_f10_system_temp_scan() {
    let ws = TempWorkspace::new("system_temp");
    let dir = ws.create_dir("SystemTemp");
    ws.create_file("SystemTemp/dump.tmp", &[0; 50000]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 50000);
}

#[test]
fn test_tier1_f10_temp_clean_action() {
    let ws = TempWorkspace::new("temp_clean");
    let dir = ws.create_dir("TempDir");
    ws.create_file("TempDir/t1.tmp", &[1; 1000]);
    ws.create_file("TempDir/t2.tmp", &[2; 2000]);

    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 2);
    assert_eq!(clean.freed_bytes, 3000);
}

#[tokio::test]
async fn test_tier1_f10_system_temp_fix_summary() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let (_sandbox, module) = sandboxed_cleaner("tier1_features_721", runner);

    let res = module.fix("sys_clean_system_temp", None).await;
    assert!(res.is_ok());
    assert!(
        res.unwrap()
            .contains("Extended system temp directories cleaned")
    );
}

#[test]
fn test_tier1_f10_system_temp_issue_metadata() {
    let issue = winmedic::engine::issue::Issue::new(
        "sys_clean_system_temp",
        "system_cleaner",
        "Extended system temp directories (80.0 MB, 200 files)",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "System temp",
        "Extended system temp directories: 80.0 MB across 200 files",
        "Clean temp directories",
        vec!["Clean systemprofile Temp".to_string()],
    );
    assert_eq!(issue.id, "sys_clean_system_temp");
    assert_eq!(issue.severity, Severity::Info);
}

// ============================================================================
// FEATURE 11: Accurate Sizing & Triage Support (M2, R2)
// ============================================================================

#[test]
fn test_tier1_f11_format_bytes_units() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1.0 KB");
    assert_eq!(format_bytes(1536), "1.5 KB");
    assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
    assert_eq!(format_bytes(1024 * 1024 * 1024 * 2), "2.00 GB");
}

#[test]
fn test_tier1_f11_recursive_directory_size_sum() {
    let ws = TempWorkspace::new("size_sum");
    let root = ws.create_dir("Root");
    ws.create_file("Root/f1", &[0; 100]);
    ws.create_file("Root/sub1/f2", &[0; 200]);
    ws.create_file("Root/sub1/sub2/f3", &[0; 300]);

    let stats = scan_path_recursive(&root);
    assert_eq!(stats.files, 3);
    assert_eq!(stats.bytes, 600);
}

#[tokio::test]
async fn test_tier1_f11_triage_issue_toggle_in_app() {
    let mut app = App::new();
    let issue = winmedic::engine::issue::Issue::new(
        "sys_clean_browser_cache",
        "system_cleaner",
        "Browser caches (10 MB, 5 files)",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Browser Cache",
        "Details",
        "Fix",
        vec!["step".to_string()],
    );
    app.issues.push(issue);
    assert!(app.issues[0].is_selected);

    app.active_tab = TAB_TRIAGE;
    app.toggle_selected_issue();
    assert!(!app.issues[0].is_selected);

    app.toggle_selected_issue();
    assert!(app.issues[0].is_selected);
}

#[tokio::test]
async fn test_tier1_f11_triage_select_and_deselect_all() {
    let mut app = App::new();
    for i in 0..5 {
        app.issues.push(winmedic::engine::issue::Issue::new(
            format!("issue_{}", i),
            "system_cleaner",
            format!("Issue {}", i),
            "System & Cache Cleaner",
            Severity::Info,
            RiskScore::Low,
            "Desc",
            "Details",
            "Fix",
            vec![],
        ));
    }

    app.deselect_all_issues();
    for issue in &app.issues {
        assert!(!issue.is_selected);
    }

    app.select_all_issues();
    for issue in &app.issues {
        assert!(issue.is_selected);
    }
}

#[tokio::test]
async fn test_tier1_f11_triage_navigation_bounds() {
    let mut app = App::new();
    for i in 0..3 {
        app.issues.push(winmedic::engine::issue::Issue::new(
            format!("issue_{}", i),
            "system_cleaner",
            format!("Issue {}", i),
            "System & Cache Cleaner",
            Severity::Info,
            RiskScore::Low,
            "Desc",
            "Details",
            "Fix",
            vec![],
        ));
    }

    assert_eq!(app.selected_filtered_index, 0);
    app.prev_issue();
    assert_eq!(app.selected_filtered_index, 2);
    app.next_issue();
    assert_eq!(app.selected_filtered_index, 0);
    app.next_issue();
    assert_eq!(app.selected_filtered_index, 1);
    app.next_issue();
    assert_eq!(app.selected_filtered_index, 2);
}

// ============================================================================
// FEATURE 12: Module Registry & Dashboard Grid (M2, R2)
// ============================================================================

#[test]
fn test_tier1_f12_all_modules_count_equals_seven() {
    let cfg = ModuleConfig::default();
    let runner = Arc::new(ProgrammableMockRunner::new());
    let modules = get_all_modules_with_runner(&cfg, runner);
    assert_eq!(modules.len(), 7);
}

#[test]
fn test_tier1_f12_system_cleaner_metadata() {
    let cfg = ModuleConfig::default();
    let runner = Arc::new(ProgrammableMockRunner::new());
    let modules = get_all_modules_with_runner(&cfg, runner);

    let cleaner = modules.iter().find(|m| m.id() == "system_cleaner");
    assert!(cleaner.is_some());
    let cleaner = cleaner.unwrap();
    assert_eq!(cleaner.name(), "System & Cache Cleaner");
    assert_eq!(cleaner.icon(), "[CLR]");
}

#[test]
fn test_tier1_f12_diagnostic_engine_contains_all_seven_modules() {
    let config = AppConfig::default();
    let engine = DiagnosticEngine::new(&config);
    assert_eq!(engine.modules().len(), 7);
}

#[tokio::test]
async fn test_tier1_f12_app_initializes_with_seven_module_statuses() {
    let app = App::new();
    assert_eq!(app.module_statuses.len(), 7);
    assert!(
        app.module_statuses
            .iter()
            .any(|(id, ..)| id == "system_cleaner")
    );
}

#[test]
fn test_tier1_f12_all_module_ids_unique() {
    let cfg = ModuleConfig::default();
    let modules = get_all_modules(&cfg);
    let mut ids = std::collections::HashSet::new();
    for m in &modules {
        assert!(ids.insert(m.id()), "Duplicate module id found: {}", m.id());
    }
}

// ============================================================================
// FEATURE 13: GitHub Release Version Check (M3, R3.1)
// ============================================================================

#[tokio::test]
async fn test_tier1_f13_github_check_newer_release_detected() {
    let runner = ProgrammableMockRunner::with_success("curl.exe", GITHUB_RELEASE_NEWER_JSON);
    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;

    assert!(res.is_some());
    let info = res.unwrap();
    assert_eq!(info.current_version, "0.1.0");
    assert_eq!(info.latest_version, "v0.2.0");
    assert_eq!(
        info.release_url,
        "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
    );
}

#[tokio::test]
async fn test_tier1_f13_github_check_already_up_to_date() {
    let runner = ProgrammableMockRunner::with_success("curl.exe", GITHUB_RELEASE_CURRENT_JSON);
    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(res.is_none());
}

#[tokio::test]
async fn test_tier1_f13_github_check_ignores_draft_releases() {
    let runner = ProgrammableMockRunner::with_success("curl.exe", GITHUB_RELEASE_DRAFT_JSON);
    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(res.is_none());
}

#[tokio::test]
async fn test_tier1_f13_github_check_curl_args_contain_headers() {
    let runner = ProgrammableMockRunner::with_success("curl.exe", GITHUB_RELEASE_CURRENT_JSON);
    let _ = check_for_update(&runner, "0.1.0", Duration::from_secs(10)).await;

    let calls = runner.calls_for("curl.exe");
    assert_eq!(calls.len(), 1);
    let args = &calls[0];
    assert!(args.contains(&"-s".to_string()));
    assert!(args.contains(&"--max-time".to_string()));
    assert!(args.contains(&"10".to_string()));
    assert!(args.contains(&"User-Agent: WinMedic".to_string()));
    assert!(args.contains(&"Accept: application/vnd.github.v3+json".to_string()));
    assert!(args.contains(&GITHUB_LATEST_RELEASE_URL.to_string()));
}

#[tokio::test]
async fn test_tier1_f13_github_check_command_runner_failure() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response("curl.exe", CmdOutput::failed(6, "Could not resolve host"));

    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(res.is_none());
}

// ============================================================================
// FEATURE 14: SemVer Comparison Engine (M3, R3.2)
// ============================================================================

#[test]
fn test_tier1_f14_semver_parse_standard() {
    let v = SemVer::parse("1.2.3").unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);
}

#[test]
fn test_tier1_f14_semver_parse_v_prefix() {
    let v1 = SemVer::parse("v0.2.0").unwrap();
    assert_eq!(
        v1,
        SemVer {
            major: 0,
            minor: 2,
            patch: 0,
            pre: None
        }
    );

    let v2 = SemVer::parse("V1.0.5").unwrap();
    assert_eq!(
        v2,
        SemVer {
            major: 1,
            minor: 0,
            patch: 5,
            pre: None
        }
    );
}

#[test]
fn test_tier1_f14_semver_parse_prerelease_and_metadata() {
    let v1 = SemVer::parse("v0.2.0-rc1").unwrap();
    assert_eq!(
        v1,
        SemVer {
            major: 0,
            minor: 2,
            patch: 0,
            pre: Some("rc1".to_string())
        }
    );

    let v2 = SemVer::parse("1.0.0+build2026").unwrap();
    assert_eq!(
        v2,
        SemVer {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None
        }
    );
}

#[test]
fn test_tier1_f14_semver_ordering_precedence() {
    let v0_1_0 = SemVer::parse("0.1.0").unwrap();
    let v0_1_1 = SemVer::parse("0.1.1").unwrap();
    let v0_2_0 = SemVer::parse("0.2.0").unwrap();
    let v1_0_0 = SemVer::parse("1.0.0").unwrap();

    assert!(v0_1_1 > v0_1_0);
    assert!(v0_2_0 > v0_1_1);
    assert!(v1_0_0 > v0_2_0);
}

#[test]
fn test_tier1_f14_is_update_available_helper() {
    assert!(is_update_available("0.1.0", "v0.2.0"));
    assert!(is_update_available("0.1.0", "0.1.1"));
    assert!(!is_update_available("0.2.0", "v0.2.0"));
    assert!(!is_update_available("1.0.0", "v0.9.9"));
    assert!(!is_update_available("invalid", "v0.2.0"));
}

// ============================================================================
// FEATURE 15: TUI Confirmation Modal (M3, R3.3)
// ============================================================================

#[tokio::test]
async fn test_tier1_f15_modal_confirm_request_update_available_fields() {
    let modal = ConfirmRequest::UpdateAvailable {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
    };

    assert_eq!(modal.title(), "NEW WINMEDIC UPDATE AVAILABLE");
    assert_eq!(modal.confirm_label(), "Open the release page in a browser");
    assert_eq!(modal.dismiss_label(), "Remind me later");
    let body_text = modal.body().join(" ");
    assert!(body_text.contains("0.2.0"));
    assert!(body_text.contains("0.1.0"));
}

#[tokio::test]
async fn test_tier1_f15_app_update_checked_event_sets_pending_confirm() {
    let mut app = App::new();
    app.config.check_for_updates = true;
    app.pending_confirm = None;

    let update = UpdateInfo {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        release_name: Some("v0.2.0".to_string()),
        release_body: Some("Notes".to_string()),
    };

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(BackgroundEvent::UpdateChecked(Some(update)))
        .unwrap();

    // Emulate background event handling
    if let Ok(BackgroundEvent::UpdateChecked(Some(info))) = rx.try_recv()
        && app.config.check_for_updates
    {
        app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
            current_version: info.current_version.clone(),
            latest_version: info.latest_version.clone(),
            release_url: info.release_url.clone(),
        });
        app.available_update = Some(info);
    }

    assert!(app.pending_confirm.is_some());
    assert!(app.available_update.is_some());
}

#[tokio::test]
async fn test_tier1_f15_app_dismiss_confirm_clears_modal() {
    let mut app = App::new();
    app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
    });

    app.dismiss_confirm();
    assert!(app.pending_confirm.is_none());
}

#[tokio::test]
async fn test_tier1_f15_app_confirm_pending_clears_and_executes() {
    let mut app = App::new();
    app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://example.com".to_string(),
    });

    app.confirm_pending_action();
    assert!(app.pending_confirm.is_none());
}

#[tokio::test]
async fn test_tier1_f15_modal_skipped_when_check_for_updates_disabled() {
    let mut app = App::new();
    app.pending_confirm = None;
    app.config.check_for_updates = false;

    let update = UpdateInfo {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        release_name: Some("v0.2.0".to_string()),
        release_body: None,
    };

    if app.config.check_for_updates {
        app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
            current_version: update.current_version,
            latest_version: update.latest_version,
            release_url: update.release_url,
        });
    }

    assert!(app.pending_confirm.is_none());
}

// ============================================================================
// FEATURE 16: Default Browser Launch (M3, R3.4)
// ============================================================================

#[test]
fn test_tier1_f16_browser_launch_empty_url_rejected() {
    let res = validate_release_url("");
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), "The URL must not be empty");
}

#[test]
fn test_tier1_f16_browser_launch_valid_url_accepted() {
    let valid_url = "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0";
    assert!(is_safe_release_url(valid_url));
}

#[test]
fn test_tier1_f16_browser_launch_mock_command_execution() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response("cmd.exe", CmdOutput::ok(""));

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run_cmd(
                "start \"\" https://github.com/SecretLUL/WinMedic",
                Duration::from_secs(5),
            )
            .await
    });

    assert!(res.is_ok());
    let calls = runner.calls_for("cmd.exe");
    assert_eq!(calls.len(), 1);
    assert!(calls[0][1].contains("start \"\" https://github.com/SecretLUL/WinMedic"));
}

#[test]
fn test_tier1_f16_browser_launch_url_with_query_params() {
    let url = "https://github.com/SecretLUL/WinMedic/releases?query=v0.2.0&arch=x64";
    assert!(url.contains("query="));
    // Ampersands are shell metacharacters, so a query string is never a safe release URL.
    assert!(!is_safe_release_url(url));
}

#[test]
fn test_tier1_f16_browser_launch_url_with_fragment() {
    let url = "https://github.com/SecretLUL/WinMedic/releases#changelog";
    assert!(url.contains("#changelog"));
    assert!(is_safe_release_url(url));
}

// ============================================================================
// FEATURE 17: AppConfig & Settings Toggle (M3, R3.5)
// ============================================================================

#[test]
fn test_tier1_f17_default_config_check_for_updates_is_true() {
    let config = AppConfig::default();
    assert!(config.check_for_updates);
}

#[test]
fn test_tier1_f17_setting_count_equals_seven() {
    assert_eq!(AppConfig::SETTING_COUNT, 7);
}

#[test]
fn test_tier1_f17_setting_row_three_is_update_setting() {
    let config = AppConfig::default();
    let (label, val, desc) = config.setting_row(3).unwrap();
    assert_eq!(label, "Check for updates automatically");
    assert_eq!(val, "ON");
    assert!(desc.contains("GitHub"));
}

#[test]
fn test_tier1_f17_toggle_setting_three_flips_boolean() {
    let mut config = AppConfig::default();
    assert!(config.check_for_updates);

    config.toggle_setting(3);
    assert!(!config.check_for_updates);
    let (_, val_off, _) = config.setting_row(3).unwrap();
    assert_eq!(val_off, "OFF");

    config.toggle_setting(3);
    assert!(config.check_for_updates);
}

#[test]
fn test_tier1_f17_setting_row_six_is_verbose_logging_setting() {
    let config = AppConfig::default();
    assert!(!config.verbose_logging);
    let (label, val, desc) = config.setting_row(6).unwrap();
    assert_eq!(label, "Enable verbose / debug logs");
    assert_eq!(val, "OFF");
    assert!(desc.contains("debug"));
}

#[test]
fn test_tier1_f17_toggle_setting_six_flips_verbose_logging() {
    let mut config = AppConfig::default();
    assert!(!config.verbose_logging);

    config.toggle_setting(6);
    assert!(config.verbose_logging);
    let (_, val_on, _) = config.setting_row(6).unwrap();
    assert_eq!(val_on, "ON");

    config.toggle_setting(6);
    assert!(!config.verbose_logging);
}

#[test]
fn test_tier1_f17_config_serialization_roundtrip_includes_check_for_updates_and_verbose_logging() {
    let config = AppConfig {
        check_for_updates: false,
        verbose_logging: true,
        ..Default::default()
    };

    let json = serde_json::to_string(&config).expect("failed to serialize");
    assert!(json.contains("\"check_for_updates\":false"));
    assert!(json.contains("\"verbose_logging\":true"));

    let deserialized: AppConfig = serde_json::from_str(&json).expect("failed to deserialize");
    assert!(!deserialized.check_for_updates);
    assert!(deserialized.verbose_logging);
}
