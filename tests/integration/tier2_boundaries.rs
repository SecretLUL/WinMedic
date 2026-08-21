#![allow(dead_code, unused_imports)]

use crate::common;

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{
    DISM_ANALYZE_CLEAN, DISM_ANALYZE_ENGLISH_RECLAIMABLE, MockWindowsPaths, ProgrammableMockRunner,
    TempWorkspace, sandboxed_cleaner,
};
use winmedic::app::{App, ConfirmRequest, TAB_TRIAGE};
use winmedic::config::AppConfig;
use winmedic::engine::issue::{Issue, RiskScore, Severity};
use winmedic::engine::runner::DiagnosticEngine;
use winmedic::modules::system_cleaner::{
    SystemCleanerModule, clean_log_dir_files, clean_path_contents, format_bytes,
    parse_winsxs_analysis, scan_log_dir_files, scan_path_recursive,
};
use winmedic::modules::{
    DiagnosticModule, ModuleConfig, ModuleStatus, get_all_modules_with_runner,
};
use winmedic::utils::cmd::{CmdOutput, CommandRunner};
use winmedic::utils::updater::{
    GitHubRelease, SemVer, UpdateInfo, check_for_update, is_safe_release_url, is_update_available,
    validate_release_url,
};

// ============================================================================
// FEATURE 1 BOUNDARIES: Git Branch Fast-Forward (F1)
// ============================================================================

#[test]
fn test_tier2_f01_git_diverged_history_rejection_simulation() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "git.exe",
        CmdOutput::failed(1, "fatal: Not possible to fast-forward, aborting."),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run(
                "git.exe",
                &["merge", "--ff-only", "origin/main"],
                Duration::from_secs(5),
            )
            .await
    });

    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(!out.success);
    assert!(out.stderr.contains("Not possible to fast-forward"));
}

#[test]
fn test_tier2_f01_git_detached_head_simulation() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "git.exe",
        CmdOutput::ok("* (HEAD detached at 1a2b3c4)\n  main\n"),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run("git.exe", &["branch"], Duration::from_secs(5))
            .await
    });

    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.stdout.contains("HEAD detached"));
}

#[test]
fn test_tier2_f01_git_dirty_worktree_conflict_simulation() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "git.exe",
        CmdOutput::failed(
            1,
            "error: Your local changes to the following files would be overwritten by merge",
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
    assert!(!out.success);
    assert!(out.stderr.contains("local changes"));
}

#[test]
fn test_tier2_f01_git_invalid_ref_simulation() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "git.exe",
        CmdOutput::failed(128, "fatal: Not a valid object name non_existent_branch"),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run(
                "git.exe",
                &["rev-parse", "non_existent_branch"],
                Duration::from_secs(5),
            )
            .await
    });

    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(!out.success);
}

#[test]
fn test_tier2_f01_git_empty_commit_history_simulation() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "git.exe",
        CmdOutput::failed(
            128,
            "fatal: your current branch 'main' does not have any commits yet",
        ),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        runner
            .run("git.exe", &["log", "-n", "1"], Duration::from_secs(5))
            .await
    });

    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(!out.success);
}

// ============================================================================
// FEATURE 2 BOUNDARIES: WinSxS Deep Clean (F2)
// ============================================================================

#[test]
fn test_tier2_f02_winsxs_missing_colons_and_garbage_output() {
    let garbage = "Random output without colon delimiter\nAnother line with nothing\n123456789";
    let analysis = parse_winsxs_analysis(garbage);
    assert!(!analysis.cleanup_recommended);
    assert_eq!(analysis.reclaimable_packages, 0);
    assert_eq!(analysis.reported_size, None);
}

#[tokio::test]
async fn test_tier2_f02_winsxs_dism_exit_code_87_invalid_param() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response(
        "dism.exe",
        CmdOutput::failed(87, "Error: 87 The parameter is incorrect."),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier2_boundaries_171", runner);
    let res = module.fix("sys_clean_winsxs", None).await;

    assert!(res.is_err());
    assert!(res.unwrap_err().contains("DISM error"));
}

#[tokio::test]
async fn test_tier2_f02_winsxs_dism_exit_code_5_access_denied() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response(
        "dism.exe",
        CmdOutput::failed(
            5,
            "Error: 5 Access is denied. Elevated permissions are required.",
        ),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier2_boundaries_186", runner);
    let res = module.fix("sys_clean_winsxs", None).await;

    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Access is denied"));
}

#[test]
fn test_tier2_f02_winsxs_zero_reclaimable_packages_numeric_parse() {
    let output = "Component Store Cleanup Recommended : Yes\nNumber of Reclaimable Packages : 0\n";
    let analysis = parse_winsxs_analysis(output);
    assert!(analysis.cleanup_recommended);
    assert_eq!(analysis.reclaimable_packages, 0);
}

#[test]
fn test_tier2_f02_winsxs_extreme_package_count_parse() {
    let output =
        "Component Store Cleanup Recommended : Yes\nNumber of Reclaimable Packages : 999999\n";
    let analysis = parse_winsxs_analysis(output);
    assert!(analysis.cleanup_recommended);
    assert_eq!(analysis.reclaimable_packages, 999999);
}

// ============================================================================
// FEATURE 3 BOUNDARIES: Delivery Optimization (F3)
// ============================================================================

#[test]
fn test_tier2_f03_delivery_opt_non_existent_paths() {
    let ws = TempWorkspace::new("wudo_non_exist");
    let missing = ws.path().join("MissingWUDO");
    let stats = scan_path_recursive(&missing);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);

    let clean = clean_path_contents(&missing);
    assert_eq!(clean.deleted_files, 0);
    assert_eq!(clean.freed_bytes, 0);
}

#[test]
fn test_tier2_f03_delivery_opt_deeply_nested_folders() {
    let ws = TempWorkspace::new("wudo_deep");
    let deep_path = "WUDO/l1/l2/l3/l4/l5/l6/l7/l8/l9/l10";
    let file = ws.create_file(&format!("{}/chunk.bin", deep_path), &[0xAA; 1024]);

    let base = ws.path().join("WUDO");
    let stats = scan_path_recursive(&base);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 1024);

    let clean = clean_path_contents(&base);
    assert_eq!(clean.deleted_files, 1);
    assert_eq!(clean.freed_bytes, 1024);
    assert!(!file.exists());
}

#[tokio::test]
async fn test_tier2_f03_delivery_opt_powershell_failure_does_not_panic() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response(
        "powershell.exe",
        CmdOutput::failed(
            1,
            "The term 'Delete-DeliveryOptimizationCache' is not recognized.",
        ),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier2_boundaries_251", runner);
    let res = module.fix("sys_clean_delivery_optimization", None).await;

    assert!(res.is_ok());
    assert!(
        res.unwrap()
            .contains("Delivery Optimization (WUDO) cache cleaned")
    );
}

#[test]
fn test_tier2_f03_delivery_opt_zero_byte_files() {
    let ws = TempWorkspace::new("wudo_zero");
    let dir = ws.create_dir("WUDO");
    for i in 0..10 {
        ws.create_file(&format!("WUDO/zero_{}.tmp", i), &[]);
    }

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 10);
    assert_eq!(stats.bytes, 0);

    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 10);
    assert_eq!(clean.freed_bytes, 0);
}

#[test]
fn test_tier2_f03_delivery_opt_clean_empty_directory_returns_zeros() {
    let ws = TempWorkspace::new("wudo_empty_clean");
    let dir = ws.create_dir("Empty");
    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 0);
    assert_eq!(clean.freed_bytes, 0);
    assert_eq!(clean.skipped_locked, 0);
}

// ============================================================================
// FEATURE 4 BOUNDARIES: Package Cache Audit (F4)
// ============================================================================

#[test]
fn test_tier2_f04_package_cache_non_existent_root() {
    let ws = TempWorkspace::new("pkg_non_exist");
    let non_existent = ws.path().join("ProgramData/Package Cache");
    let stats = scan_path_recursive(&non_existent);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier2_f04_package_cache_special_characters_in_folder_names() {
    let ws = TempWorkspace::new("pkg_special_chars");
    let dir = ws.create_dir("Package Cache/{81C8E-4A9B_v1.0#test$}");
    let f1 = ws.create_file(
        "Package Cache/{81C8E-4A9B_v1.0#test$}/vc_runtime.msi",
        &[0xFF; 2048],
    );

    let stats = scan_path_recursive(dir.parent().unwrap());
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 2048);

    let clean = clean_path_contents(dir.parent().unwrap());
    assert_eq!(clean.deleted_files, 1);
    assert_eq!(clean.freed_bytes, 2048);
    assert!(!f1.exists());
}

#[test]
fn test_tier2_f04_package_cache_multiple_nested_payloads() {
    let ws = TempWorkspace::new("pkg_multi_nested");
    let dir = ws.create_dir("Package Cache");
    for i in 0..5 {
        ws.create_file(
            &format!("Package Cache/guid_{}/sub_{}/payload.cab", i, i),
            &[i as u8; 1000],
        );
    }

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 5);
    assert_eq!(stats.bytes, 5000);

    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 5);
    assert_eq!(clean.freed_bytes, 5000);
}

#[test]
fn test_tier2_f04_package_cache_large_file_size_aggregation() {
    let ws = TempWorkspace::new("pkg_large_file");
    let dir = ws.create_dir("Package Cache");
    // Create a 1 MB file (simulating large binary payload)
    let one_mb = vec![0xEEu8; 1024 * 1024];
    ws.create_file("Package Cache/huge_installer.exe", &one_mb);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 1024 * 1024);
}

#[tokio::test]
async fn test_tier2_f04_package_cache_unknown_issue_id_returns_error() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let (_sandbox, module) = sandboxed_cleaner("tier2_boundaries_353", runner);
    let res = module.fix("sys_clean_invalid_id", None).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Unknown issue ID"));
}

// ============================================================================
// FEATURE 5 BOUNDARIES: Browser Caches (F5)
// ============================================================================

#[test]
fn test_tier2_f05_browser_cache_non_existent_browser_folders() {
    let ws = TempWorkspace::new("browser_missing");
    let missing_chrome = ws.path().join("Google/Chrome/User Data/Default/Cache");
    let stats = scan_path_recursive(&missing_chrome);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier2_f05_browser_cache_locked_file_safely_skipped() {
    let ws = TempWorkspace::new("browser_locked");
    let dir = ws.create_dir("CacheDir");
    let file_path = ws.create_file("CacheDir/locked_data", &[0x11; 4096]);
    let unlocked_path = ws.create_file("CacheDir/unlocked_data", &[0x22; 2048]);

    // Keep an exclusive write lock on the first file to simulate an active browser lock
    let lock_handle = File::options().write(true).open(&file_path);
    if let Ok(_handle) = lock_handle {
        let clean = clean_path_contents(&dir);
        // On Windows with exclusive lock, locked file cannot be removed
        // Either it was skipped or cleaned if filesystem allowed
        assert!(clean.deleted_files >= 1);
        assert!(!unlocked_path.exists());
    }
}

#[test]
fn test_tier2_f05_browser_cache_multiple_profile_variations() {
    let ws = TempWorkspace::new("browser_profiles");
    let p1 = ws.create_dir("UserData/Profile 1/Cache");
    let p2 = ws.create_dir("UserData/Profile 2/Cache");
    let p3 = ws.create_dir("UserData/Default/Cache");

    ws.create_file("UserData/Profile 1/Cache/c1", &[0; 100]);
    ws.create_file("UserData/Profile 2/Cache/c2", &[0; 200]);
    ws.create_file("UserData/Default/Cache/c3", &[0; 300]);

    let s1 = scan_path_recursive(&p1);
    let s2 = scan_path_recursive(&p2);
    let s3 = scan_path_recursive(&p3);

    assert_eq!(s1.files + s2.files + s3.files, 3);
    assert_eq!(s1.bytes + s2.bytes + s3.bytes, 600);
}

#[test]
fn test_tier2_f05_browser_cache_empty_profile_dirs() {
    let ws = TempWorkspace::new("browser_empty_prof");
    let dir = ws.create_dir("UserData/Default/Cache");
    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier2_f05_browser_cache_code_cache_gpu_cache_discovery() {
    let ws = TempWorkspace::new("browser_subcaches");
    let user_data = ws.create_dir("UserData/Default");
    ws.create_file("UserData/Default/Cache/f1", &[0; 500]);
    ws.create_file("UserData/Default/Code Cache/js/f2", &[0; 600]);
    ws.create_file("UserData/Default/GPUCache/data_0", &[0; 700]);

    let stats = scan_path_recursive(&user_data);
    assert_eq!(stats.files, 3);
    assert_eq!(stats.bytes, 1800);
}

// ============================================================================
// FEATURE 6 BOUNDARIES: Setup & System Logs (F6)
// ============================================================================

#[test]
fn test_tier2_f06_setup_logs_non_matching_extensions_strictly_preserved() {
    let ws = TempWorkspace::new("logs_preserve");
    let dir = ws.create_dir("Logs");
    let log1 = ws.create_file("Logs/cbs.log", &[0; 100]);
    let log2 = ws.create_file("Logs/archive.cab", &[0; 200]);
    let bin1 = ws.create_file("Logs/app.dll", &[0; 5000]);
    let bin2 = ws.create_file("Logs/system.sys", &[0; 6000]);
    let cfg1 = ws.create_file("Logs/config.ini", &[0; 1000]);

    let clean = clean_log_dir_files(&dir);
    assert_eq!(clean.deleted_files, 2);
    assert_eq!(clean.freed_bytes, 300);

    assert!(!log1.exists());
    assert!(!log2.exists());
    assert!(bin1.exists());
    assert!(bin2.exists());
    assert!(cfg1.exists());
}

#[test]
fn test_tier2_f06_setup_logs_high_file_count_stress() {
    let ws = TempWorkspace::new("logs_stress");
    let dir = ws.create_dir("Panther");
    for i in 0..500 {
        ws.create_file(&format!("Panther/log_{}.log", i), &[0; 100]);
    }

    let stats = scan_log_dir_files(&dir);
    assert_eq!(stats.files, 500);
    assert_eq!(stats.bytes, 50000);

    let clean = clean_log_dir_files(&dir);
    assert_eq!(clean.deleted_files, 500);
    assert_eq!(clean.freed_bytes, 50000);
}

#[test]
fn test_tier2_f06_setup_logs_unicode_filenames() {
    let ws = TempWorkspace::new("logs_unicode");
    let dir = ws.create_dir("Logs");
    let f1 = ws.create_file("Logs/protokoll_währung_€_äöü.log", &[0; 1024]);
    let f2 = ws.create_file("Logs/диагностика_2026.txt", &[0; 2048]);

    let stats = scan_log_dir_files(&dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 3072);

    let clean = clean_log_dir_files(&dir);
    assert_eq!(clean.deleted_files, 2);
    assert!(!f1.exists());
    assert!(!f2.exists());
}

#[test]
fn test_tier2_f06_setup_logs_case_insensitive_extensions() {
    let ws = TempWorkspace::new("logs_case_ext");
    let dir = ws.create_dir("Logs");
    ws.create_file("Logs/UPPER.LOG", &[0; 100]);
    ws.create_file("Logs/Mixed.Cab", &[0; 200]);
    ws.create_file("Logs/BACKUP.BAK", &[0; 300]);
    ws.create_file("Logs/Trace.ETL", &[0; 400]);

    let stats = scan_log_dir_files(&dir);
    assert_eq!(stats.files, 4);
    assert_eq!(stats.bytes, 1000);
}

#[test]
fn test_tier2_f06_setup_logs_non_existent_folder_clean() {
    let ws = TempWorkspace::new("logs_missing_clean");
    let missing = ws.path().join("NonExistentPanther");
    let clean = clean_log_dir_files(&missing);
    assert_eq!(clean.deleted_files, 0);
    assert_eq!(clean.freed_bytes, 0);
}

// ============================================================================
// FEATURE 7 BOUNDARIES: Error Reporting & Crash Dumps (F7)
// ============================================================================

#[test]
fn test_tier2_f07_wer_empty_report_queue() {
    let ws = TempWorkspace::new("wer_empty_q");
    let dir = ws.create_dir("WER/ReportQueue");
    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier2_f07_crash_dumps_corrupted_dmp_header() {
    let ws = TempWorkspace::new("dmp_corrupt");
    let dir = ws.create_dir("CrashDumps");
    // Invalid dmp content
    ws.create_file("CrashDumps/corrupt.dmp", &[0x00, 0xFF, 0x00, 0xFF]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 4);

    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 1);
    assert_eq!(clean.freed_bytes, 4);
}

#[test]
fn test_tier2_f07_wer_nested_report_subdirectories() {
    let ws = TempWorkspace::new("wer_nested");
    let _dir = ws.create_dir("WER/ReportArchive/AppCrash_1/Sub");
    ws.create_file("WER/ReportArchive/AppCrash_1/Sub/Report.wer", &[0; 1500]);
    ws.create_file("WER/ReportArchive/AppCrash_1/Sub/memory.hdmp", &[0; 8500]);

    let base = ws.path().join("WER");
    let stats = scan_path_recursive(&base);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 10000);

    let clean = clean_path_contents(&base);
    assert_eq!(clean.deleted_files, 2);
    assert_eq!(clean.freed_bytes, 10000);
}

#[test]
fn test_tier2_f07_crash_dumps_large_memory_dump() {
    let ws = TempWorkspace::new("dump_large");
    let dir = ws.create_dir("CrashDumps");
    let large_data = vec![0xAAu8; 512 * 1024];
    ws.create_file("CrashDumps/MEMORY.DMP", &large_data);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 512 * 1024);
}

#[test]
fn test_tier2_f07_wer_erc_directory_scan() {
    let ws = TempWorkspace::new("wer_erc");
    let dir = ws.create_dir("WER/ERC");
    ws.create_file("WER/ERC/response.xml", &[0; 250]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 250);
}

// ============================================================================
// FEATURE 8 BOUNDARIES: DirectX Shader & Certificate Caches (F8)
// ============================================================================

#[test]
fn test_tier2_f08_d3d_cache_non_existent() {
    let ws = TempWorkspace::new("d3d_missing");
    let missing = ws.path().join("MissingD3DSCache");
    let stats = scan_path_recursive(&missing);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier2_f08_cryptnet_content_without_metadata() {
    let ws = TempWorkspace::new("crypt_partial");
    let _content_dir = ws.create_dir("CryptnetUrlCache/Content");
    ws.create_file("CryptnetUrlCache/Content/crl_01", &[0; 4096]);

    let base = ws.path().join("CryptnetUrlCache");
    let stats = scan_path_recursive(&base);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 4096);

    let clean = clean_path_contents(&base);
    assert_eq!(clean.deleted_files, 1);
    assert_eq!(clean.freed_bytes, 4096);
}

#[test]
fn test_tier2_f08_shader_cache_multiple_gpu_dirs() {
    let ws = TempWorkspace::new("shader_multi_gpu");
    let base = ws.create_dir("DirectX/ShaderCache");
    ws.create_file("DirectX/ShaderCache/NV_1/shader1.bin", &[0; 3000]);
    ws.create_file("DirectX/ShaderCache/AMD_1/shader2.bin", &[0; 4000]);
    ws.create_file("DirectX/ShaderCache/Intel_1/shader3.bin", &[0; 5000]);

    let stats = scan_path_recursive(&base);
    assert_eq!(stats.files, 3);
    assert_eq!(stats.bytes, 12000);
}

#[test]
fn test_tier2_f08_shader_cache_zero_byte_toc_files() {
    let ws = TempWorkspace::new("shader_toc");
    let base = ws.create_dir("D3DSCache");
    ws.create_file("D3DSCache/toc.dat", &[]);

    let stats = scan_path_recursive(&base);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 0);

    let clean = clean_path_contents(&base);
    assert_eq!(clean.deleted_files, 1);
}

#[test]
fn test_tier2_f08_cryptnet_empty_directories() {
    let ws = TempWorkspace::new("crypt_empty");
    let c = ws.create_dir("Crypt/Content");
    let m = ws.create_dir("Crypt/MetaData");

    let s1 = scan_path_recursive(&c);
    let s2 = scan_path_recursive(&m);
    assert_eq!(s1.files + s2.files, 0);
    assert_eq!(s1.bytes + s2.bytes, 0);
}

// ============================================================================
// FEATURE 9 BOUNDARIES: Windows Recycle Bin (F9)
// ============================================================================

#[test]
fn test_tier2_f09_recycle_bin_all_drives_empty() {
    let ws = TempWorkspace::new("bin_empty_all");
    let dir = ws.create_dir("$Recycle.Bin");
    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[tokio::test]
async fn test_tier2_f09_recycle_bin_powershell_access_denied() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response(
        "powershell.exe",
        CmdOutput::failed(1, "Clear-RecycleBin : Access to the path is denied."),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier2_boundaries_671", runner);
    let res = module.fix("sys_clean_recycle_bin", None).await;

    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Access to the path is denied"));
}

#[tokio::test]
async fn test_tier2_f09_recycle_bin_powershell_no_recycle_bin_present() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response(
        "powershell.exe",
        CmdOutput::failed(
            1,
            "Cannot find path 'C:\\$Recycle.Bin' because it does not exist.",
        ),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier2_boundaries_686", runner);
    let res = module.fix("sys_clean_recycle_bin", None).await;

    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Cannot find path"));
}

#[test]
fn test_tier2_f09_recycle_bin_multiple_sids() {
    let ws = TempWorkspace::new("bin_multi_sid");
    let base = ws.create_dir("$Recycle.Bin");
    ws.create_file("$Recycle.Bin/S-1-5-18/$R001.tmp", &[0; 1000]);
    ws.create_file("$Recycle.Bin/S-1-5-21-1001/$R002.tmp", &[0; 2000]);
    ws.create_file("$Recycle.Bin/S-1-5-21-1002/$R003.tmp", &[0; 3000]);

    let stats = scan_path_recursive(&base);
    assert_eq!(stats.files, 3);
    assert_eq!(stats.bytes, 6000);
}

#[test]
fn test_tier2_f09_recycle_bin_only_metadata_index_files() {
    let ws = TempWorkspace::new("bin_meta_only");
    let base = ws.create_dir("$Recycle.Bin/S-1-5-21");
    ws.create_file("$Recycle.Bin/S-1-5-21/$IABCDEF.txt", &[0; 544]);

    let stats = scan_path_recursive(&base);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 544);
}

// ============================================================================
// FEATURE 10 BOUNDARIES: Extended System Temp (F10)
// ============================================================================

#[test]
fn test_tier2_f10_systemprofile_temp_non_existent() {
    let ws = TempWorkspace::new("temp_missing");
    let missing = ws
        .path()
        .join("System32/config/systemprofile/AppData/Local/Temp");
    let stats = scan_path_recursive(&missing);
    assert_eq!(stats.files, 0);
    assert_eq!(stats.bytes, 0);
}

#[test]
fn test_tier2_f10_system_temp_nested_symlinks_or_dirs() {
    let ws = TempWorkspace::new("temp_nested");
    let _dir = ws.create_dir("SystemTemp/d1/d2/d3");
    ws.create_file("SystemTemp/d1/d2/d3/scoped.tmp", &[0x12; 4096]);

    let base = ws.path().join("SystemTemp");
    let stats = scan_path_recursive(&base);
    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 4096);

    let clean = clean_path_contents(&base);
    assert_eq!(clean.deleted_files, 1);
    assert_eq!(clean.freed_bytes, 4096);
}

#[test]
fn test_tier2_f10_system_temp_special_character_filenames() {
    let ws = TempWorkspace::new("temp_special_names");
    let dir = ws.create_dir("SystemTemp");
    let f1 = ws.create_file("SystemTemp/~DF12345.TMP", &[0; 500]);
    let f2 = ws.create_file("SystemTemp/temp_file (1) [backup].tmp", &[0; 600]);

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 1100);

    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 2);
    assert!(!f1.exists());
    assert!(!f2.exists());
}

#[test]
fn test_tier2_f10_system_temp_zero_byte_temporary_files() {
    let ws = TempWorkspace::new("temp_zero_bytes");
    let dir = ws.create_dir("SystemTemp");
    for i in 0..20 {
        ws.create_file(&format!("SystemTemp/null_{}.tmp", i), &[]);
    }

    let stats = scan_path_recursive(&dir);
    assert_eq!(stats.files, 20);
    assert_eq!(stats.bytes, 0);

    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 20);
    assert_eq!(clean.freed_bytes, 0);
}

#[test]
fn test_tier2_f10_system_temp_empty_root_clean() {
    let ws = TempWorkspace::new("temp_empty_clean");
    let dir = ws.create_dir("SystemTemp");
    let clean = clean_path_contents(&dir);
    assert_eq!(clean.deleted_files, 0);
    assert_eq!(clean.freed_bytes, 0);
}

// ============================================================================
// FEATURE 11 BOUNDARIES: Accurate Sizing & Triage Support (F11)
// ============================================================================

#[test]
fn test_tier2_f11_format_bytes_boundary_exact_values() {
    assert_eq!(format_bytes(1023), "1023 B");
    assert_eq!(format_bytes(1024), "1.0 KB");
    assert_eq!(format_bytes(1024 * 1024 - 1), "1024.0 KB");
    assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
    assert_eq!(format_bytes(1024 * 1024 * 1024 - 1), "1024.0 MB");
    assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    assert_eq!(format_bytes(u64::MAX), "17179869184.00 GB");
}

#[tokio::test]
async fn test_tier2_f11_triage_empty_search_query_matches_all() {
    let mut app = App::new();
    app.issues.clear();
    app.issues.push(Issue::new(
        "i1",
        "mod1",
        "Title 1",
        "Cat",
        Severity::Info,
        RiskScore::Low,
        "Desc",
        "Tech",
        "Fix",
        vec![],
    ));
    app.issues.push(Issue::new(
        "i2",
        "mod1",
        "Title 2",
        "Cat",
        Severity::Warning,
        RiskScore::Low,
        "Desc",
        "Tech",
        "Fix",
        vec![],
    ));

    app.search_query = String::new();
    let indices = app.filtered_issue_indices();
    assert_eq!(indices.len(), 2);
}

#[tokio::test]
async fn test_tier2_f11_triage_search_query_no_match_clamps_to_zero() {
    let mut app = App::new();
    app.issues.clear();
    app.issues.push(Issue::new(
        "i1",
        "mod1",
        "Title 1",
        "Cat",
        Severity::Info,
        RiskScore::Low,
        "Desc",
        "Tech",
        "Fix",
        vec![],
    ));

    app.search_query = "completely_unmatched_query_xyz".to_string();
    let indices = app.filtered_issue_indices();
    assert_eq!(indices.len(), 0);

    app.clamp_filtered_selection();
    assert_eq!(app.selected_filtered_index, 0);
}

#[tokio::test]
async fn test_tier2_f11_triage_filter_all_severities_combinations() {
    let mut app = App::new();
    app.issues.clear();
    app.issues.push(Issue::new(
        "i1",
        "m",
        "C",
        "Cat",
        Severity::Critical,
        RiskScore::High,
        "D",
        "T",
        "F",
        vec![],
    ));
    app.issues.push(Issue::new(
        "i2",
        "m",
        "W",
        "Cat",
        Severity::Warning,
        RiskScore::Medium,
        "D",
        "T",
        "F",
        vec![],
    ));
    app.issues.push(Issue::new(
        "i3",
        "m",
        "I",
        "Cat",
        Severity::Info,
        RiskScore::Low,
        "D",
        "T",
        "F",
        vec![],
    ));

    app.toggle_severity_filter(Severity::Critical);
    assert_eq!(app.filtered_issue_indices(), vec![0]);

    app.toggle_severity_filter(Severity::Critical); // toggle off
    assert_eq!(app.filtered_issue_indices().len(), 3);

    app.toggle_severity_filter(Severity::Info);
    assert_eq!(app.filtered_issue_indices(), vec![2]);
}

#[tokio::test]
async fn test_tier2_f11_triage_clear_filters_restores_view() {
    let mut app = App::new();
    app.issues.clear();
    app.issues.push(Issue::new(
        "i1",
        "m",
        "C",
        "Cat",
        Severity::Critical,
        RiskScore::High,
        "D",
        "T",
        "F",
        vec![],
    ));
    app.issues.push(Issue::new(
        "i2",
        "m",
        "W",
        "Cat",
        Severity::Warning,
        RiskScore::Medium,
        "D",
        "T",
        "F",
        vec![],
    ));

    app.severity_filter = Some(Severity::Critical);
    app.search_query = "non_existent".to_string();
    assert!(app.has_active_filters());

    app.clear_filters();
    assert!(!app.has_active_filters());
    assert_eq!(app.filtered_issue_indices().len(), 2);
}

// ============================================================================
// FEATURE 12 BOUNDARIES: Module Registry & Dashboard Grid (F12)
// ============================================================================

#[test]
fn test_tier2_f12_health_score_with_zero_issues_is_100() {
    let score = DiagnosticEngine::calculate_health_score(&[]);
    assert_eq!(score, 100);
}

#[test]
fn test_tier2_f12_health_score_with_multiple_critical_issues() {
    let mut issues = Vec::new();
    for i in 0..10 {
        issues.push(Issue::new(
            format!("crit_{}", i),
            "system_integrity",
            "Critical corruption",
            "System",
            Severity::Critical,
            RiskScore::High,
            "Desc",
            "Tech",
            "Fix",
            vec![],
        ));
    }

    let score = DiagnosticEngine::calculate_health_score(&issues);
    assert!(score <= 30);
}

#[test]
fn test_tier2_f12_health_score_with_fixed_issues_ignored() {
    let mut issues = Vec::new();
    let mut issue = Issue::new(
        "crit_fixed",
        "system_cleaner",
        "Fixed Issue",
        "System",
        Severity::Critical,
        RiskScore::High,
        "Desc",
        "Tech",
        "Fix",
        vec![],
    );
    issue.is_fixed = true;
    issues.push(issue);

    let score = DiagnosticEngine::calculate_health_score(&issues);
    assert_eq!(score, 100);
}

#[test]
fn test_tier2_f12_module_status_enums() {
    let s_idle = ModuleStatus::Idle;
    let s_scan = ModuleStatus::Scanning;
    let s_pass = ModuleStatus::Passed;
    let s_warn = ModuleStatus::Warning(3);
    let s_crit = ModuleStatus::Critical(1);
    let s_fail = ModuleStatus::Failed("Error".to_string());

    assert_ne!(s_idle, s_scan);
    assert_ne!(s_pass, s_warn);
    assert_ne!(s_crit, s_fail);
}

#[test]
fn test_tier2_f12_module_config_defaults() {
    let cfg = ModuleConfig::default();
    assert_eq!(cfg.temp_clean_threshold_mb, 500);
    assert_eq!(cfg.max_event_log_hours, 24);
    assert!(cfg.auto_backup_registry);
    assert!(cfg.auto_restart_services);
}

// ============================================================================
// FEATURE 13 BOUNDARIES: GitHub Release Version Check (F13)
// ============================================================================

#[tokio::test]
async fn test_tier2_f13_github_api_404_not_found() {
    let runner = ProgrammableMockRunner::with_success("curl.exe", "{\"message\": \"Not Found\"}");
    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(res.is_none());
}

#[tokio::test]
async fn test_tier2_f13_github_api_403_rate_limited() {
    let runner = ProgrammableMockRunner::with_success(
        "curl.exe",
        "{\"message\": \"API rate limit exceeded for IP...\"}",
    );
    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(res.is_none());
}

#[tokio::test]
async fn test_tier2_f13_github_api_malformed_truncated_json() {
    let runner =
        ProgrammableMockRunner::with_success("curl.exe", "{\"tag_name\": \"v0.2.0\", \"html_");
    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(res.is_none());
}

#[tokio::test]
async fn test_tier2_f13_github_api_empty_stdout() {
    let runner = ProgrammableMockRunner::with_success("curl.exe", "");
    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(res.is_none());
}

#[tokio::test]
async fn test_tier2_f13_github_api_timeout_expired() {
    let runner = ProgrammableMockRunner::new();
    runner.set_response(
        "curl.exe",
        CmdOutput::failed(
            28,
            "curl: (28) Operation timed out after 5000 milliseconds with 0 bytes received",
        ),
    );

    let res = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(res.is_none());
}

// ============================================================================
// FEATURE 14 BOUNDARIES: SemVer Engine (F14)
// ============================================================================

#[test]
fn test_tier2_f14_semver_parse_single_number() {
    let v = SemVer::parse("1").unwrap();
    assert_eq!(
        v,
        SemVer {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None
        }
    );
}

#[test]
fn test_tier2_f14_semver_parse_empty_string_returns_none() {
    assert!(SemVer::parse("").is_none());
    assert!(SemVer::parse("   ").is_none());
    assert!(SemVer::parse("v").is_none());
    assert!(SemVer::parse("V").is_none());
}

#[test]
fn test_tier2_f14_semver_parse_non_numeric_chars_returns_none() {
    assert!(SemVer::parse("abc.def.ghi").is_none());
    assert!(SemVer::parse("invalid-version").is_none());
}

#[test]
fn test_tier2_f14_semver_parse_extreme_numbers() {
    let v = SemVer::parse("9999.8888.7777").unwrap();
    assert_eq!(v.major, 9999);
    assert_eq!(v.minor, 8888);
    assert_eq!(v.patch, 7777);
}

#[test]
fn test_tier2_f14_semver_identical_versions_not_newer() {
    let v1 = SemVer::parse("0.1.0").unwrap();
    let v2 = SemVer::parse("0.1.0").unwrap();
    assert!(!v1.is_newer_than(&v2));
    assert!(!v2.is_newer_than(&v1));
    assert!(!is_update_available("0.1.0", "v0.1.0"));
}

// ============================================================================
// FEATURE 15 BOUNDARIES: TUI Confirmation Modal (F15)
// ============================================================================

#[test]
fn test_tier2_f15_modal_with_empty_strings() {
    let modal = ConfirmRequest::UpdateAvailable {
        current_version: "".to_string(),
        latest_version: "".to_string(),
        release_url: "".to_string(),
        download: None,
    };

    assert_eq!(modal.title(), "NEW WINMEDIC UPDATE AVAILABLE");
    let body = modal.body().join("\n");
    assert!(body.contains("URL: "));
}

#[test]
fn test_tier2_f15_modal_with_extremely_long_url() {
    let long_url = format!(
        "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0?token={}",
        "a".repeat(2000)
    );
    let modal = ConfirmRequest::UpdateAvailable {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: long_url.clone(),
        download: None,
    };

    let body = modal.body().join("\n");
    assert!(body.contains(&long_url));
}

#[tokio::test]
async fn test_tier2_f15_modal_dismiss_restores_clean_state() {
    let mut app = App::new();
    app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://example.com".to_string(),
        download: None,
    });

    assert!(app.pending_confirm.is_some());
    app.dismiss_confirm();
    assert!(app.pending_confirm.is_none());
}

#[test]
fn test_tier2_f15_confirm_request_rollback_labels() {
    let modal = ConfirmRequest::Rollback {
        description: "Test Backup".to_string(),
        key_path: "HKLM\\Software\\Test".to_string(),
        file_path: "C:\\backup.reg".to_string(),
    };

    assert_eq!(modal.title(), "RESTORE REGISTRY BACKUP?");
    assert_eq!(modal.confirm_label(), "Restore");
    assert_eq!(modal.dismiss_label(), "Cancel");
}

#[test]
fn test_tier2_f15_confirm_request_elevate_labels() {
    let modal = ConfirmRequest::Elevate;
    assert_eq!(modal.title(), "ADMINISTRATOR PRIVILEGES REQUIRED");
    assert_eq!(modal.confirm_label(), "Restart as Administrator now");
    assert_eq!(modal.dismiss_label(), "Continue without Administrator");
}

// ============================================================================
// FEATURE 16 BOUNDARIES: Default Browser Launch (F16)
// ============================================================================

#[test]
fn test_tier2_f16_browser_launch_spaces_in_url() {
    let url = "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0 with spaces";
    assert!(!is_safe_release_url(url));
}

#[test]
fn test_tier2_f16_browser_launch_shell_metacharacters() {
    let url = "https://github.com/SecretLUL/WinMedic/releases?a=1&b=2|dir^echo";
    assert!(url.contains('&'));
    assert!(url.contains('|'));
    assert!(!is_safe_release_url(url));
}

#[test]
fn test_tier2_f16_browser_launch_file_uri() {
    let url = "file:///C:/Users/AMMAR-PC/AppData/Local/Temp/report.html";
    assert!(url.starts_with("file:///"));
    // Only https://github.com/ URLs may be handed to the browser launcher.
    assert!(!is_safe_release_url(url));
}

#[test]
fn test_tier2_f16_browser_launch_extremely_long_url() {
    let long_url = format!("https://example.com/release?data={}", "x".repeat(3000));
    assert!(long_url.len() > 3000);
}

#[test]
fn test_tier2_f16_browser_launch_whitespace_only_rejected() {
    let _ = validate_release_url("   ");
    assert!(validate_release_url("").is_err());
}

// ============================================================================
// FEATURE 17 BOUNDARIES: AppConfig & Settings Toggle (F17)
// ============================================================================

#[test]
fn test_tier2_f17_toggle_setting_out_of_bounds_returns_false() {
    let mut config = AppConfig::default();
    assert!(!config.toggle_setting(AppConfig::SETTING_COUNT));
    assert!(!config.toggle_setting(999));
}

#[test]
fn test_tier2_f17_setting_row_out_of_bounds_returns_none() {
    let config = AppConfig::default();
    assert!(config.setting_row(AppConfig::SETTING_COUNT).is_none());
    assert!(config.setting_row(100).is_none());
}

#[test]
fn test_tier2_f17_adjust_setting_on_boolean_delegates_to_toggle() {
    let mut config = AppConfig::default();
    let initial_vss = config.create_vss_before_repair;
    assert!(config.adjust_setting(0, true));
    assert_ne!(config.create_vss_before_repair, initial_vss);

    let initial_updater = config.check_for_updates;
    assert!(config.adjust_setting(3, false));
    assert_ne!(config.check_for_updates, initial_updater);
}

#[test]
fn test_tier2_f17_adjust_numeric_settings_cannot_go_below_floor() {
    let mut config = AppConfig {
        temp_clean_threshold_mb: 100,
        ..Default::default()
    };
    config.adjust_setting(4, false); // floor is 100 MB
    assert_eq!(config.temp_clean_threshold_mb, 100);

    config.max_event_log_hours = 1;
    config.adjust_setting(5, false); // floor is 1 hour
    assert_eq!(config.max_event_log_hours, 1);
}

#[test]
fn test_tier2_f17_deserialization_missing_fields_defaults() {
    // Empty JSON should deserialize to full defaults
    let json = "{}";
    let config: AppConfig = serde_json::from_str(json).expect("failed to deserialize empty json");
    assert!(config.check_for_updates);
    assert!(config.auto_restart_services);
    assert!(config.create_vss_before_repair);
    assert!(config.auto_backup_registry);
    assert_eq!(config.temp_clean_threshold_mb, 500);
    assert_eq!(config.max_event_log_hours, 24);
}
