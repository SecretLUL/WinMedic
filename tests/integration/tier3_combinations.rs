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
    DISM_ANALYZE_CLEAN, DISM_ANALYZE_ENGLISH_RECLAIMABLE, GITHUB_RELEASE_NEWER_JSON,
    MockWindowsPaths, ProgrammableMockRunner, TempWorkspace,
};
use winmedic::app::{App, BackgroundEvent, ConfirmRequest, TAB_SETTINGS, TAB_TRIAGE};
use winmedic::config::AppConfig;
use winmedic::engine::exit_code;
use winmedic::engine::issue::{Issue, RiskScore, Severity};
use winmedic::engine::reporter::DiagnosticReporter;
use winmedic::engine::runner::{DiagnosticEngine, RepairEvent, RepairOptions, ScanEvent};
use winmedic::modules::system_cleaner::{
    CleanerPaths, SystemCleanerModule, clean_path_contents, scan_path_recursive,
};
use winmedic::modules::{DiagnosticModule, ModuleConfig, get_all_modules_with_runner};
use winmedic::safety::audit::{AuditEntry, AuditLogger, MAX_LOG_FILE_BYTES};
use winmedic::utils::cmd::{CmdOutput, CommandRunner};
use winmedic::utils::updater::{UpdateInfo, check_for_update};

// ============================================================================
// TIER 3: Cross-Feature Combination Tests
// ============================================================================

#[tokio::test]
async fn test_tier3_scan_cleaner_and_updater_startup_flow() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response_for_cmd_and_args(
        "dism.exe /Online /Cleanup-Image /AnalyzeComponentStore",
        CmdOutput::ok(DISM_ANALYZE_ENGLISH_RECLAIMABLE),
    );
    runner.set_response("curl.exe", CmdOutput::ok(GITHUB_RELEASE_NEWER_JSON));

    let config = AppConfig::default();
    let engine = Arc::new(DiagnosticEngine::with_runner(&config, runner.clone()));
    let (tx, mut rx) = channel(50);
    let cancel = CancellationToken::new();

    // 1. Run diagnostic scan
    let scan_engine = engine.clone();
    let scan_tx = tx.clone();
    let scan_cancel = cancel.clone();
    let scan_handle = tokio::spawn(async move { scan_engine.run_scan(scan_tx, scan_cancel).await });

    // 2. Concurrently check for updates
    let runner_clone = runner.clone();
    let update_handle = tokio::spawn(async move {
        check_for_update(&*runner_clone, "0.1.0", Duration::from_secs(5)).await
    });
    drop(tx);

    let mut event_count = 0;
    while let Some(_evt) = rx.recv().await {
        event_count += 1;
    }

    let issues = scan_handle.await.unwrap();
    let update = update_handle.await.unwrap();

    assert!(event_count > 0);
    assert!(!issues.is_empty());
    assert!(update.is_some());
    assert_eq!(update.unwrap().latest_version, "v0.2.0");
}

#[tokio::test]
async fn test_tier3_triage_selection_winsxs_browser_with_dry_run() {
    let ws = TempWorkspace::new("tier3_dry_run");
    let _dir = ws.create_dir("BrowserCache");
    let f1 = ws.create_file("BrowserCache/data1", &[0xAA; 1000]);

    let mut issues = vec![
        Issue::new(
            "sys_clean_winsxs",
            "system_cleaner",
            "WinSxS Deep Clean",
            "System & Cache Cleaner",
            Severity::Warning,
            RiskScore::Medium,
            "Desc",
            "Details",
            "Fix",
            vec![],
        ),
        Issue::new(
            "sys_clean_browser_cache",
            "system_cleaner",
            "Browser Cache",
            "System & Cache Cleaner",
            Severity::Info,
            RiskScore::Low,
            "Desc",
            "Details",
            "Fix",
            vec![],
        ),
    ];

    issues[0].is_selected = true;
    issues[1].is_selected = true;

    let config = AppConfig::default();
    let runner = Arc::new(ProgrammableMockRunner::new());
    let engine = DiagnosticEngine::with_runner(&config, runner);
    let (tx, mut rx) = channel(50);
    let cancel = CancellationToken::new();
    let options = RepairOptions {
        create_vss: false,
        dry_run: true,
        verbose_logging: false,
    };

    let mut dry_run_started = false;
    let fix_handle = tokio::spawn(async move {
        let res = engine.run_repairs(&mut issues, options, tx, cancel).await;
        (issues, res)
    });

    while let Some(evt) = rx.recv().await {
        if let RepairEvent::DryRunStarted { .. } = evt {
            dry_run_started = true;
        }
    }

    let (repaired_issues, (fixed, failed)) = fix_handle.await.unwrap();
    assert!(dry_run_started);
    assert_eq!(fixed, 2);
    assert_eq!(failed, 0);

    // In dry-run, issues remain is_fixed = false and files are untouched
    assert!(!repaired_issues[0].is_fixed);
    assert!(!repaired_issues[1].is_fixed);
    assert!(f1.exists());
}

#[tokio::test]
async fn test_tier3_triage_selection_logs_temp_with_real_fix() {
    let ws = TempWorkspace::new("tier3_real_fix");
    let _dir = ws.create_dir("Logs");
    let log_file = ws.create_file("Logs/setup.log", &[0xBB; 2000]);
    // The payload the repair is expected to remove, inside the sandbox.
    let pkg_payload = ws.create_file("ProgramData/Package Cache/vs/setup.msi", &[0xAA; 1500]);

    let mut issues = vec![Issue::new(
        "sys_clean_package_cache",
        "system_cleaner",
        "Package Cache",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Desc",
        "Details",
        "Fix",
        vec![],
    )];
    issues[0].is_selected = true;

    // This is a *real* (non-dry-run) repair, and the package-cache fix deletes
    // files. The engine therefore gets a cleaner rooted in the sandbox — built
    // from `DiagnosticEngine::with_runner` it would empty the test machine's own
    // %ProgramData%\Package Cache.
    let runner = Arc::new(ProgrammableMockRunner::new());
    let cleaner = SystemCleanerModule::with_runner_and_paths(
        ModuleConfig::default(),
        runner,
        CleanerPaths::rooted_at(ws.path()),
    );
    let engine = DiagnosticEngine::with_modules(vec![Arc::new(cleaner)]);
    let (tx, mut rx) = channel(50);
    let cancel = CancellationToken::new();
    let options = RepairOptions {
        create_vss: false,
        dry_run: false,
        verbose_logging: false,
    };

    let fix_handle = tokio::spawn(async move {
        let res = engine.run_repairs(&mut issues, options, tx, cancel).await;
        (issues, res)
    });

    while let Some(_evt) = rx.recv().await {}

    let (repaired_issues, (fixed, _failed)) = fix_handle.await.unwrap();
    assert_eq!(fixed, 1);
    assert!(repaired_issues[0].is_fixed);
    // Only the package cache was swept; the unrelated log file survives.
    assert!(!pkg_payload.exists());
    assert!(log_file.exists());
}

#[tokio::test]
async fn test_tier3_multi_module_scan_parallelism() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response_for_cmd_and_args(
        "dism.exe /Online /Cleanup-Image /AnalyzeComponentStore",
        CmdOutput::ok(DISM_ANALYZE_CLEAN),
    );

    let config = AppConfig::default();
    let engine = DiagnosticEngine::with_runner(&config, runner);
    let (tx, mut rx) = channel(100);
    let cancel = CancellationToken::new();

    let scan_handle = tokio::spawn(async move { engine.run_scan(tx, cancel).await });

    let mut finished_modules = 0;
    while let Some(evt) = rx.recv().await {
        if let ScanEvent::ModuleFinished { .. } = evt {
            finished_modules += 1;
        }
    }

    let _issues = scan_handle.await.unwrap();
    assert_eq!(finished_modules, 9);
}

/// `create_vss: true` used to run `Checkpoint-Computer` on the machine running
/// the suite — up to a minute per run, and a real restore point when elevated.
/// The engine now only asks Windows for one if the caller installed a live
/// `RestorePointService`, which no test does; the events below are still
/// emitted, so this keeps testing the wiring it always tested.
#[tokio::test]
async fn test_tier3_system_cleaner_vss_enabled_repair() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    runner.set_response("powershell.exe", CmdOutput::ok(""));

    let mut issues = vec![Issue::new(
        "sys_clean_recycle_bin",
        "system_cleaner",
        "Recycle Bin",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Desc",
        "Details",
        "Fix",
        vec![],
    )];
    issues[0].is_selected = true;

    let config = AppConfig::default();
    let engine = DiagnosticEngine::with_runner(&config, runner);
    let (tx, mut rx) = channel(50);
    let cancel = CancellationToken::new();
    let options = RepairOptions {
        create_vss: true,
        dry_run: false,
        verbose_logging: false,
    };

    let fix_handle = tokio::spawn(async move {
        let res = engine.run_repairs(&mut issues, options, tx, cancel).await;
        (issues, res)
    });

    let mut vss_started = false;
    let mut vss_completed = false;
    while let Some(evt) = rx.recv().await {
        match evt {
            RepairEvent::VssStarted => vss_started = true,
            RepairEvent::VssCompleted { .. } => vss_completed = true,
            _ => {}
        }
    }

    let (repaired_issues, _) = fix_handle.await.unwrap();
    assert!(vss_started);
    assert!(vss_completed);
    assert!(repaired_issues[0].is_fixed);
}

#[tokio::test]
async fn test_tier3_system_cleaner_vss_disabled_repair() {
    let runner = Arc::new(ProgrammableMockRunner::new());
    let mut issues = vec![Issue::new(
        "sys_clean_recycle_bin",
        "system_cleaner",
        "Recycle Bin",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Desc",
        "Details",
        "Fix",
        vec![],
    )];
    issues[0].is_selected = true;

    let config = AppConfig::default();
    let engine = DiagnosticEngine::with_runner(&config, runner);
    let (tx, mut rx) = channel(50);
    let cancel = CancellationToken::new();
    let options = RepairOptions {
        create_vss: false,
        dry_run: false,
        verbose_logging: false,
    };

    let fix_handle = tokio::spawn(async move {
        let res = engine.run_repairs(&mut issues, options, tx, cancel).await;
        (issues, res)
    });

    let mut vss_seen = false;
    while let Some(evt) = rx.recv().await {
        if let RepairEvent::VssStarted = evt {
            vss_seen = true;
        }
    }

    let _ = fix_handle.await.unwrap();
    assert!(!vss_seen);
}

#[test]
fn test_tier3_exit_code_after_system_cleaner_fixes() {
    let mut issues = vec![
        Issue::new(
            "i1",
            "system_cleaner",
            "T1",
            "C",
            Severity::Warning,
            RiskScore::Low,
            "D",
            "T",
            "F",
            vec![],
        ),
        Issue::new(
            "i2",
            "system_cleaner",
            "T2",
            "C",
            Severity::Info,
            RiskScore::Low,
            "D",
            "T",
            "F",
            vec![],
        ),
    ];

    // Pre-fix: warnings present -> exit code 1
    assert_eq!(exit_code::from_issues(&issues, 0), exit_code::WARNINGS);

    // Post-fix: all issues fixed -> exit code 0
    issues[0].is_fixed = true;
    issues[1].is_fixed = true;
    assert_eq!(exit_code::from_issues(&issues, 0), exit_code::OK);
}

#[test]
fn test_tier3_exit_code_on_failed_winsxs_repair() {
    let issues = vec![Issue::new(
        "i1",
        "system_cleaner",
        "T1",
        "C",
        Severity::Warning,
        RiskScore::Medium,
        "D",
        "T",
        "F",
        vec![],
    )];

    // 1 failed fix outranks severity -> exit code 3
    assert_eq!(exit_code::from_issues(&issues, 1), exit_code::FIX_FAILED);
}

#[test]
fn test_tier3_reporter_json_with_system_cleaner_issues() {
    let issues = vec![Issue::new(
        "sys_clean_winsxs",
        "system_cleaner",
        "WinSxS Component Store",
        "System & Cache Cleaner",
        Severity::Warning,
        RiskScore::Medium,
        "Description of WinSxS",
        "8.12 GB reclaimable",
        "DISM StartComponentCleanup",
        vec!["Step 1".to_string()],
    )];
    let health = DiagnosticEngine::calculate_health_score(&issues);
    let audit_entries = vec![];

    let json_str = DiagnosticReporter::to_json(&issues, health, &audit_entries);
    assert!(json_str.contains("\"sys_clean_winsxs\""));
    assert!(json_str.contains("\"system_cleaner\""));
    assert!(json_str.contains("\"health_score\""));
}

#[test]
fn test_tier3_reporter_html_with_system_cleaner_issues() {
    let issues = vec![Issue::new(
        "sys_clean_browser_cache",
        "system_cleaner",
        "Browser caches (150 MB, 500 files)",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Description",
        "Details",
        "Fix",
        vec![],
    )];
    let health = DiagnosticEngine::calculate_health_score(&issues);
    let audit_entries = vec![];

    let html = DiagnosticReporter::to_html(&issues, health, &audit_entries);
    assert!(html.contains("Browser caches"));
    assert!(html.contains("System &amp; Cache Cleaner") || html.contains("System & Cache Cleaner"));
}

#[test]
fn test_tier3_reporter_markdown_with_system_cleaner_issues() {
    let issues = vec![Issue::new(
        "sys_clean_package_cache",
        "system_cleaner",
        "Installer package cache (1.20 GB, 50 files)",
        "System & Cache Cleaner",
        Severity::Warning,
        RiskScore::Low,
        "Description",
        "Details",
        "Fix",
        vec![],
    )];
    let health = DiagnosticEngine::calculate_health_score(&issues);
    let audit_entries = vec![];

    let md = DiagnosticReporter::to_markdown(&issues, health, &audit_entries);
    assert!(md.contains("Installer package cache"));
    assert!(md.contains("system_cleaner"));
}

#[test]
fn test_tier3_audit_logger_records_system_cleaner_fixes() {
    let ws = TempWorkspace::new("audit_log_test");
    let logger = AuditLogger::with_dir_and_size(ws.root.clone(), MAX_LOG_FILE_BYTES);
    logger.log(
        "FIX",
        "system_cleaner",
        "Clean browser caches",
        "SUCCESS",
        "50 MB freed",
    );

    let history = logger.get_history();
    assert_eq!(history.len(), 1);
    let last = &history[0];
    assert_eq!(last.module_id, "system_cleaner");
    assert_eq!(last.title, "Clean browser caches");
    assert_eq!(last.status, "SUCCESS");
}

#[tokio::test]
async fn test_tier3_triage_search_filtering_by_system_cleaner_title() {
    let mut app = App::new();
    app.issues.push(Issue::new(
        "sys_clean_winsxs",
        "system_cleaner",
        "WinSxS Komponentenspeicher",
        "System & Cache Cleaner",
        Severity::Warning,
        RiskScore::Medium,
        "Desc",
        "Details",
        "Fix",
        vec![],
    ));
    app.issues.push(Issue::new(
        "sys_clean_browser_cache",
        "system_cleaner",
        "Browser-Caches Chrome & Edge",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Desc",
        "Details",
        "Fix",
        vec![],
    ));

    app.search_query = "Chrome".to_string();
    let filtered = app.filtered_issue_indices();
    assert_eq!(filtered.len(), 1);
    assert_eq!(app.issues[filtered[0]].id, "sys_clean_browser_cache");
}

#[tokio::test]
async fn test_tier3_triage_module_filtering_cycle() {
    let mut app = App::new();
    app.issues.push(Issue::new(
        "sys_clean_winsxs",
        "system_cleaner",
        "WinSxS",
        "System & Cache Cleaner",
        Severity::Warning,
        RiskScore::Medium,
        "Desc",
        "Details",
        "Fix",
        vec![],
    ));
    app.issues.push(Issue::new(
        "net_dns",
        "network",
        "DNS Fail",
        "Network",
        Severity::Critical,
        RiskScore::High,
        "Desc",
        "Details",
        "Fix",
        vec![],
    ));

    app.module_filter = Some("system_cleaner".to_string());
    let filtered = app.filtered_issue_indices();
    assert_eq!(filtered.len(), 1);
    assert_eq!(app.issues[filtered[0]].module_id, "system_cleaner");
}

#[tokio::test]
async fn test_tier3_app_config_toggle_updater_affects_startup() {
    let mut app = App::new();
    app.active_tab = TAB_SETTINGS;
    app.selected_setting_index = 3;

    // Toggle off
    app.toggle_current_setting();
    assert!(!app.config.check_for_updates);

    // Toggle on
    app.toggle_current_setting();
    assert!(app.config.check_for_updates);
}

#[tokio::test]
async fn test_tier3_scan_cancellation_during_system_cleaner() {
    let config = AppConfig::default();
    let runner = Arc::new(ProgrammableMockRunner::new());
    let engine = DiagnosticEngine::with_runner(&config, runner);
    let (tx, mut rx) = channel(50);
    let cancel = CancellationToken::new();

    // Cancel immediately
    cancel.cancel();

    let scan_handle = tokio::spawn(async move { engine.run_scan(tx, cancel).await });

    let mut scan_cancelled = false;
    while let Some(evt) = rx.recv().await {
        if let ScanEvent::ScanCancelled { .. } = evt {
            scan_cancelled = true;
        }
    }

    let issues = scan_handle.await.unwrap();
    assert!(scan_cancelled);
    assert!(issues.is_empty());
}

#[tokio::test]
async fn test_tier3_repair_cancellation_between_cleaner_fixes() {
    let mut issues = vec![
        Issue::new(
            "i1",
            "system_cleaner",
            "T1",
            "C",
            Severity::Info,
            RiskScore::Low,
            "D",
            "T",
            "F",
            vec![],
        ),
        Issue::new(
            "i2",
            "system_cleaner",
            "T2",
            "C",
            Severity::Info,
            RiskScore::Low,
            "D",
            "T",
            "F",
            vec![],
        ),
    ];
    issues[0].is_selected = true;
    issues[1].is_selected = true;

    let config = AppConfig::default();
    let runner = Arc::new(ProgrammableMockRunner::new());
    let engine = DiagnosticEngine::with_runner(&config, runner);
    let (tx, mut rx) = channel(50);
    let cancel = CancellationToken::new();
    cancel.cancel(); // cancel before start

    let options = RepairOptions {
        create_vss: false,
        dry_run: false,
        verbose_logging: false,
    };

    let fix_handle = tokio::spawn(async move {
        let res = engine.run_repairs(&mut issues, options, tx, cancel).await;
        (issues, res)
    });

    let mut cancelled = false;
    while let Some(evt) = rx.recv().await {
        if let RepairEvent::RepairsCancelled { .. } = evt {
            cancelled = true;
        }
    }

    let (repaired_issues, (fixed, _)) = fix_handle.await.unwrap();
    assert!(cancelled);
    assert_eq!(fixed, 0);
    assert!(!repaired_issues[0].is_fixed);
}

#[tokio::test]
async fn test_tier3_app_export_report_with_cleaner_issues() {
    let mut app = App::new();
    app.issues.push(Issue::new(
        "sys_clean_system_temp",
        "system_cleaner",
        "System Temp Files (50 MB)",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Desc",
        "Details",
        "Fix",
        vec![],
    ));

    let res = app.export_report();
    assert!(res.is_ok());
    let path = res.unwrap();
    assert!(path.exists());
    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("System Temp Files"));
    let _ = fs::remove_file(path);
}

#[tokio::test]
async fn test_tier3_dry_run_flag_in_app_state() {
    let mut app = App::new();
    assert!(!app.dry_run);

    app.toggle_dry_run();
    assert!(app.dry_run);

    app.toggle_dry_run();
    assert!(!app.dry_run);
}

#[tokio::test]
async fn test_tier3_update_check_with_subsequent_triage_cleanup() {
    let mut app = App::new();
    app.pending_confirm = None;

    // 1. Update detected on startup
    let info = UpdateInfo {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        release_name: Some("v0.2.0".to_string()),
        release_body: None,
        download: None,
    };
    app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
        current_version: info.current_version,
        latest_version: info.latest_version,
        release_url: info.release_url,
        download: None,
    });

    // 2. User dismisses update modal
    app.dismiss_confirm();
    assert!(app.pending_confirm.is_none());

    // 3. User switches to Triage and toggles issue
    app.active_tab = TAB_TRIAGE;
    app.issues.push(Issue::new(
        "sys_clean_recycle_bin",
        "system_cleaner",
        "Recycle Bin",
        "System & Cache Cleaner",
        Severity::Info,
        RiskScore::Low,
        "Desc",
        "Details",
        "Fix",
        vec![],
    ));
    assert!(app.issues[0].is_selected);
    app.toggle_selected_issue();
    assert!(!app.issues[0].is_selected);
}

#[tokio::test]
async fn test_tier3_mixed_cleaner_and_integrity_repairs() {
    let mut issues = vec![
        Issue::new(
            "integrity_dism",
            "system_integrity",
            "DISM corrupt",
            "System",
            Severity::Critical,
            RiskScore::Medium,
            "D",
            "T",
            "F",
            vec![],
        ),
        Issue::new(
            "sys_clean_shader_certs",
            "system_cleaner",
            "Shader Caches",
            "System & Cache Cleaner",
            Severity::Info,
            RiskScore::Low,
            "D",
            "T",
            "F",
            vec![],
        ),
    ];
    issues[0].is_selected = true;
    issues[1].is_selected = true;

    let config = AppConfig::default();
    let runner = Arc::new(ProgrammableMockRunner::new());
    let engine = DiagnosticEngine::with_runner(&config, runner);
    let (tx, mut rx) = channel(50);
    let cancel = CancellationToken::new();
    let options = RepairOptions {
        create_vss: false,
        dry_run: true,
        verbose_logging: false,
    };

    let fix_handle = tokio::spawn(async move {
        let res = engine.run_repairs(&mut issues, options, tx, cancel).await;
        (issues, res)
    });

    while let Some(_evt) = rx.recv().await {}

    let (_, (fixed, failed)) = fix_handle.await.unwrap();
    assert_eq!(fixed, 2);
    assert_eq!(failed, 0);
}
