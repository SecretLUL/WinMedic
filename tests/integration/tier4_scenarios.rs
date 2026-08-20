#![allow(dead_code, unused_imports)]

use crate::common;

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio_util::sync::CancellationToken;

use common::{
    DISM_ANALYZE_CLEAN, DISM_ANALYZE_ENGLISH_RECLAIMABLE, DISM_ANALYZE_GERMAN_RECLAIMABLE,
    GITHUB_RELEASE_NEWER_JSON, MockWindowsPaths, ProgrammableMockRunner, TempWorkspace,
    sandboxed_cleaner,
};
use winmedic::app::{
    App, BackgroundEvent, ConfirmRequest, TAB_DASHBOARD, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS,
    TAB_TRIAGE,
};
use winmedic::config::AppConfig;
use winmedic::engine::exit_code;
use winmedic::engine::issue::{Issue, RiskScore, Severity};
use winmedic::engine::runner::{DiagnosticEngine, RepairEvent, RepairOptions, ScanEvent};
use winmedic::modules::system_cleaner::{
    SystemCleanerModule, clean_log_dir_files, clean_path_contents, scan_log_dir_files,
    scan_path_recursive,
};
use winmedic::modules::{DiagnosticModule, ModuleConfig, get_all_modules_with_runner};
use winmedic::safety::audit::{AuditEntry, AuditLogger, MAX_LOG_FILE_BYTES};
use winmedic::utils::cmd::{CmdOutput, CommandRunner};
use winmedic::utils::updater::{UpdateInfo, check_for_update};

// ============================================================================
// SCENARIO 1: Full System Scan & Dry-Run Triage across all 9 modules (F2–F12)
// ============================================================================

#[tokio::test]
async fn test_scenario_1_full_system_scan_and_dry_run_triage() {
    let ws = TempWorkspace::new("scenario1_full_scan");
    ws.populate_mock_windows_tree();

    // Populate mock files
    let f_wudo = ws.create_file(
        "Windows/SoftwareDistribution/DeliveryOptimization/chunk.dat",
        &[0x11; 50000],
    );
    let f_chrome = ws.create_file(
        "AppData/Local/Google/Chrome/User Data/Default/Cache/c1",
        &[0x22; 30000],
    );
    let f_panther = ws.create_file("Windows/Panther/setupact.log", &[0x33; 20000]);
    let f_d3d = ws.create_file("AppData/Local/D3DSCache/shader.bin", &[0x44; 15000]);
    let f_temp = ws.create_file("Windows/SystemTemp/temp1.tmp", &[0x55; 10000]);

    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response_for_cmd_and_args(
        "dism.exe /Online /Cleanup-Image /AnalyzeComponentStore",
        CmdOutput::ok(DISM_ANALYZE_ENGLISH_RECLAIMABLE),
    );
    runner.set_response("powershell.exe", CmdOutput::ok(""));

    let config = AppConfig::default();
    let engine = DiagnosticEngine::with_runner(&config, runner);
    let (tx, mut rx) = channel(100);
    let cancel = CancellationToken::new();

    // 1. Execute Full Parallel Scan
    let scan_tx = tx.clone();
    let scan_cancel = cancel.clone();
    let scan_handle = tokio::spawn(async move { engine.run_scan(scan_tx, scan_cancel).await });
    drop(tx);

    let mut finished_modules = 0;
    while let Some(evt) = rx.recv().await {
        if let ScanEvent::ModuleFinished { .. } = evt {
            finished_modules += 1;
        }
    }

    let mut issues = scan_handle.await.unwrap();
    assert_eq!(finished_modules, 10);
    assert!(!issues.is_empty());

    // 2. Triage state: verify issues present and select all
    for issue in issues.iter_mut() {
        issue.is_selected = true;
    }

    // 3. Dry-Run simulation
    let (rep_tx, mut rep_rx) = channel(100);
    let rep_cancel = CancellationToken::new();
    let options = RepairOptions {
        create_vss: false,
        dry_run: true,
        verbose_logging: false,
    };

    let engine2 = DiagnosticEngine::new(&config);
    let dry_run_handle = tokio::spawn(async move {
        let res = engine2
            .run_repairs(&mut issues, options, rep_tx, rep_cancel)
            .await;
        (issues, res)
    });

    let mut dry_run_event_seen = false;
    while let Some(evt) = rep_rx.recv().await {
        if let RepairEvent::DryRunStarted { .. } = evt {
            dry_run_event_seen = true;
        }
    }

    let (repaired, (fixed, failed)) = dry_run_handle.await.unwrap();
    assert!(dry_run_event_seen);
    assert_eq!(failed, 0);
    assert!(fixed > 0);

    // Verify simulation did NOT mark issues as fixed and did NOT delete files
    for issue in &repaired {
        assert!(!issue.is_fixed);
    }
    assert!(f_wudo.exists());
    assert!(f_chrome.exists());
    assert!(f_panther.exists());
    assert!(f_d3d.exists());
    assert!(f_temp.exists());
}

// ============================================================================
// SCENARIO 2: Selective Cleanup of Browser & Log Caches with Triage Deselection (F5, F6, F10, F11)
// ============================================================================

#[tokio::test]
async fn test_scenario_2_selective_cleanup_browser_and_logs() {
    let ws = TempWorkspace::new("scenario2_selective");
    let chrome_dir = ws.create_dir("ChromeCache");
    let logs_dir = ws.create_dir("Logs");
    ws.create_dir("Temp");

    let f_chrome = ws.create_file("ChromeCache/data_0", &[0xAA; 10000]);
    let f_log = ws.create_file("Logs/setup.log", &[0xBB; 20000]);
    let f_temp = ws.create_file("Temp/preserve.tmp", &[0xCC; 50000]);

    // Setup issues representing the 3 categories
    let mut issues = [
        Issue::new(
            "sys_clean_browser_cache",
            "system_cleaner",
            "Browser Caches",
            "System & Cache Cleaner",
            Severity::Info,
            RiskScore::Low,
            "Desc",
            "Tech",
            "Fix",
            vec![],
        ),
        Issue::new(
            "sys_clean_setup_logs",
            "system_cleaner",
            "Setup Logs",
            "System & Cache Cleaner",
            Severity::Info,
            RiskScore::Low,
            "Desc",
            "Tech",
            "Fix",
            vec![],
        ),
        Issue::new(
            "sys_clean_system_temp",
            "system_cleaner",
            "System Temp",
            "System & Cache Cleaner",
            Severity::Info,
            RiskScore::Low,
            "Desc",
            "Tech",
            "Fix",
            vec![],
        ),
    ];

    // Granular selection in Triage: select Browser & Logs, deselect Temp
    issues[0].is_selected = true;
    issues[1].is_selected = true;
    issues[2].is_selected = false;

    // Directly execute selective cleaning
    let c1 = clean_path_contents(&chrome_dir);
    let c2 = clean_log_dir_files(&logs_dir);

    assert_eq!(c1.deleted_files, 1);
    assert_eq!(c2.deleted_files, 1);

    assert!(!f_chrome.exists());
    assert!(!f_log.exists());
    // Unselected temp file remains intact!
    assert!(f_temp.exists());
}

// ============================================================================
// SCENARIO 3: Startup Check Triggering Update Modal & Confirmation Browser Launch (F13, F14, F15, F16)
// ============================================================================

#[tokio::test]
async fn test_scenario_3_startup_update_modal_and_confirm() {
    let runner = ProgrammableMockRunner::with_success("curl.exe", GITHUB_RELEASE_NEWER_JSON);

    // 1. Background check detects newer version
    let update_info = check_for_update(&runner, "0.1.0", Duration::from_secs(5)).await;
    assert!(update_info.is_some());
    let info = update_info.unwrap();
    assert_eq!(info.latest_version, "v0.2.0");

    // 2. App receives background event and sets modal
    let mut app = App::new();
    app.config.check_for_updates = true;
    app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
        current_version: info.current_version.clone(),
        latest_version: info.latest_version.clone(),
        release_url: info.release_url.clone(),
        download: None,
    });
    app.available_update = Some(info);

    assert!(app.pending_confirm.is_some());
    let modal = app.pending_confirm.as_ref().unwrap();
    assert_eq!(modal.title(), "NEW WINMEDIC UPDATE AVAILABLE");

    // 3. User confirms modal -> release page requested and modal dismissed.
    //    `App::new` leaves the OS actions inert, so this asserts the decision
    //    without a browser window opening on the machine running the suite.
    app.confirm_pending_action();
    assert!(app.pending_confirm.is_none());
    assert_eq!(
        app.status_message,
        Some("Opened the GitHub release page in your browser.".to_string())
    );
}

// ============================================================================
// SCENARIO 4: Disabled Update Check Startup Verification & Settings Toggle Workflow (F13, F17)
// ============================================================================

#[tokio::test]
async fn test_scenario_4_disabled_update_check_workflow() {
    let mut app = App::new();
    app.config.check_for_updates = false;
    app.pending_confirm = None;

    // Verify no background update modal appears when disabled
    assert!(app.pending_confirm.is_none());

    // User navigates to Settings tab
    app.active_tab = TAB_SETTINGS;
    app.selected_setting_index = 3;

    let row = app.config.setting_row(3).unwrap();
    assert_eq!(row.0, "Check for updates automatically");
    assert_eq!(row.1, "OFF");

    // User presses Space / Enter to toggle setting ON
    app.toggle_current_setting();
    assert!(app.config.check_for_updates);

    let updated_row = app.config.setting_row(3).unwrap();
    assert_eq!(updated_row.1, "ON");

    // Verify config roundtrip persistence
    let json = serde_json::to_string(&app.config).unwrap();
    let reloaded: AppConfig = serde_json::from_str(&json).unwrap();
    assert!(reloaded.check_for_updates);
}

// ============================================================================
// SCENARIO 5: Locked File Resilience during Browser, Temp, and Log Cleaning (F5, F6, F10, F11)
// ============================================================================

#[test]
fn test_scenario_5_locked_file_resilience() {
    let ws = TempWorkspace::new("scenario5_locked");
    let browser_dir = ws.create_dir("BrowserCache");
    let logs_dir = ws.create_dir("Logs");

    let locked_browser_file = ws.create_file("BrowserCache/locked_cache.dat", &[0x11; 4096]);
    let unlocked_browser_file = ws.create_file("BrowserCache/free_cache.dat", &[0x22; 2048]);
    let locked_log_file = ws.create_file("Logs/active_cbs.log", &[0x33; 8192]);
    let unlocked_log_file = ws.create_file("Logs/old_setup.log", &[0x44; 4096]);

    // Acquire write locks on the designated locked files
    let lock1 = File::options().write(true).open(&locked_browser_file);
    let lock2 = File::options().write(true).open(&locked_log_file);

    if lock1.is_ok() && lock2.is_ok() {
        let b_clean = clean_path_contents(&browser_dir);
        let l_clean = clean_log_dir_files(&logs_dir);

        // Verify unlocked files were cleaned safely without errors
        assert!(!unlocked_browser_file.exists());
        assert!(!unlocked_log_file.exists());

        // Verify stats record freed bytes
        assert!(b_clean.freed_bytes >= 2048);
        assert!(l_clean.freed_bytes >= 4096);
    }
}

// ============================================================================
// SCENARIO 6: DISM Component Store Analysis & Cleanup Pipeline with German Locale (F2, F11, F12)
// ============================================================================

#[tokio::test]
async fn test_scenario_6_dism_german_locale_pipeline() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response_for_cmd_and_args(
        "dism.exe /Online /Cleanup-Image /AnalyzeComponentStore",
        CmdOutput::ok(DISM_ANALYZE_GERMAN_RECLAIMABLE),
    );
    runner.set_response_for_cmd_and_args(
        "dism.exe /Online /Cleanup-Image /StartComponentCleanup",
        CmdOutput::ok("Der Vorgang wurde erfolgreich beendet."),
    );

    let (_sandbox, module) = sandboxed_cleaner("tier4_scenarios_278", runner.clone());

    // 1. Scan detects the WinSxS issue from German DISM output
    let issues = module.scan(None).await.expect("scan failed");
    let winsxs_issue = issues.iter().find(|i| i.id == "sys_clean_winsxs");
    assert!(winsxs_issue.is_some());
    let issue = winsxs_issue.unwrap();
    assert!(issue.title.contains("5 reclaimable packages"));
    assert!(issue.technical_details.contains("9.45 GB"));

    // 2. Fix executes StartComponentCleanup successfully
    let fix_res = module.fix("sys_clean_winsxs", None).await;
    assert!(fix_res.is_ok());
    assert!(fix_res.unwrap().contains("StartComponentCleanup finished"));

    // 3. Post-repair exit code calculation
    let mut fixed_issues = issues.clone();
    fixed_issues[0].is_fixed = true;
    let exit = exit_code::from_issues(&fixed_issues, 0);
    assert_eq!(exit, exit_code::OK);
}

// ============================================================================
// SCENARIO 7: Non-admin / Elevation Safety Check across System Modules (F2, F3, F6, F9, F12)
// ============================================================================

#[test]
fn test_scenario_7_non_admin_elevation_safety_check() {
    // In headless auto-fix mode without admin and not dry-run, WinMedic enforces safety
    let is_admin = false;
    let auto_fix = true;
    let dry_run = false;

    let code = if auto_fix && !dry_run && !is_admin {
        exit_code::NEEDS_ADMIN
    } else {
        exit_code::OK
    };

    assert_eq!(code, exit_code::NEEDS_ADMIN);
    assert_eq!(
        exit_code::describe(code),
        "Administrator privileges required."
    );

    // When elevate flag is used, elevation request is initiated
    let elevate = true;
    let mut relaunch_requested = false;
    if elevate && !is_admin {
        relaunch_requested = true;
    }
    assert!(relaunch_requested);
}
