use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use winmedic::modules::system_cleaner::{
    CleanerPaths, SystemCleanerModule, clean_log_dir_files, discover_browser_cache_dirs,
    discover_delivery_optimization_dirs, discover_shader_and_cert_dirs, discover_system_temp_dirs,
    discover_wer_and_dump_dirs, format_bytes, parse_winsxs_analysis, scan_log_dir_files,
    scan_path_recursive,
};
use winmedic::modules::{DiagnosticModule, ModuleConfig, ModuleProgress};
use winmedic::utils::cmd::{CmdOutput, CommandRunner, MockCommandRunner};

struct TempDirFixture {
    path: PathBuf,
}

impl TempDirFixture {
    fn new(suffix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "winmedic_adv_test_{}_{}",
            suffix,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        create_dir_all(&path).unwrap();
        Self { path }
    }

    fn create_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
        let full = self.path.join(rel_path);
        if let Some(p) = full.parent() {
            create_dir_all(p).unwrap();
        }
        let mut f = File::create(&full).unwrap();
        f.write_all(content).unwrap();
        full
    }
}

impl Drop for TempDirFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Build a cleaner whose filesystem roots all live inside a fresh fixture dir.
///
/// `scan` and `fix` delete for real, so no test may construct the module with
/// the default env-derived paths — that aims it at the test machine's own
/// browser caches, WER archives and `C:\Windows\Panther`.
fn sandboxed_cleaner(
    suffix: &str,
    runner: Arc<dyn CommandRunner>,
) -> (TempDirFixture, SystemCleanerModule) {
    let fixture = TempDirFixture::new(suffix);
    let module = SystemCleanerModule::with_runner_and_paths(
        ModuleConfig::default(),
        runner,
        CleanerPaths::rooted_at(&fixture.path),
    );
    (fixture, module)
}

#[test]
fn adv_test_format_bytes_edge_cases() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(1), "1 B");
    assert_eq!(format_bytes(1023), "1023 B");
    assert_eq!(format_bytes(1024), "1.0 KB");
    assert_eq!(format_bytes(1536), "1.5 KB");
    assert_eq!(format_bytes(1024 * 1024 - 1), "1024.0 KB");
    assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
    assert_eq!(format_bytes(500 * 1024 * 1024), "500.0 MB");
    assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    assert_eq!(format_bytes(15 * 1024 * 1024 * 1024), "15.00 GB");
    assert_eq!(format_bytes(u64::MAX), "17179869184.00 GB");
}

#[test]
fn adv_test_parse_winsxs_adversarial_outputs() {
    // 1. Whitespace chaos and strange casing
    let weird_whitespace = "\
        Explorer Reported Size of Component Store   :   12.34 GB   \r\n\
        Actual Size of Component Store   :   10.00 GB   \r\n\
        Shared with Windows   :   6.00 GB   \r\n\
        Backups and Disabled Features   :   3.50 GB   \r\n\
        Cache and Temporary Data   :   0.50 GB   \r\n\
        Number of Reclaimable Packages   :   99   \r\n\
        Component Store Cleanup Recommended   :   yEs   \r\n";
    let res1 = parse_winsxs_analysis(weird_whitespace);
    assert!(res1.cleanup_recommended);
    assert_eq!(res1.reclaimable_packages, 99);
    assert_eq!(res1.reported_size, Some("12.34 GB".to_string()));
    assert_eq!(res1.backups_size, Some("3.50 GB".to_string()));
    assert_eq!(res1.cache_size, Some("0.50 GB".to_string()));

    // 2. German format with tabs and spaces
    let de_output = "\
\tGröße des Komponentenspeichers laut Explorer\t:\t14.88 GB\r\n\
\tTatsächliche Größe des Komponentenspeichers\t:\t11.20 GB\r\n\
\tFür Windows freigegeben\t:\t7.10 GB\r\n\
\tSicherungen und deaktivierte Features\t:\t4.10 GB\r\n\
\tCache und temporäre Daten\t:\t0.90 GB\r\n\
\tAnzahl der wiederverwendbaren Pakete\t:\t12\r\n\
\tBereinigung des Komponentenspeichers empfohlen\t:\tJA\r\n";
    let res2 = parse_winsxs_analysis(de_output);
    assert!(res2.cleanup_recommended);
    assert_eq!(res2.reclaimable_packages, 12);
    assert_eq!(res2.reported_size, Some("14.88 GB".to_string()));
    assert_eq!(res2.backups_size, Some("4.10 GB".to_string()));
    assert_eq!(res2.cache_size, Some("0.90 GB".to_string()));

    // 3. 0 reclaimable and No cleanup
    let clean_output = "\
Explorer Reported Size of Component Store : 5.12 GB
Actual Size of Component Store : 5.10 GB
Number of Reclaimable Packages : 0
Component Store Cleanup Recommended : No
";
    let res3 = parse_winsxs_analysis(clean_output);
    assert!(!res3.cleanup_recommended);
    assert_eq!(res3.reclaimable_packages, 0);

    // 4. Broken / Error output
    let err_output = "Error: 0x800f0806\nDISM failed to analyze component store.\n";
    let res4 = parse_winsxs_analysis(err_output);
    assert!(!res4.cleanup_recommended);
    assert_eq!(res4.reclaimable_packages, 0);
    assert_eq!(res4.reported_size, None);

    // 5. Empty string
    let res5 = parse_winsxs_analysis("");
    assert!(!res5.cleanup_recommended);
    assert_eq!(res5.reclaimable_packages, 0);
}

#[tokio::test]
async fn adv_test_winsxs_scan_error_handling() {
    let mock = MockCommandRunner::new();
    // Simulate DISM failing on scan
    mock.add_response(
        "AnalyzeComponentStore",
        CmdOutput::failed(1, "Error: 0x80004005 Unspecified error"),
    );

    let (_sandbox, module) = sandboxed_cleaner("winsxs_scan_err", Arc::new(mock.clone()));
    let issues = module
        .scan(None)
        .await
        .expect("Scan should not fail even if DISM fails");
    assert!(
        issues.iter().all(|i| i.id != "sys_clean_winsxs"),
        "Should not emit winsxs issue when DISM fails"
    );
}

#[tokio::test]
async fn adv_test_winsxs_fix_failure_reporting() {
    let mock = MockCommandRunner::new();
    // Simulate DISM failing on StartComponentCleanup
    mock.add_response(
        "StartComponentCleanup",
        CmdOutput::failed(1, "Error: 0x800f0806 The component store is corrupted."),
    );

    let (_sandbox, module) = sandboxed_cleaner("winsxs_fix_fail", Arc::new(mock.clone()));
    let res = module.fix("sys_clean_winsxs", None).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert!(err_msg.contains("DISM error during StartComponentCleanup"));
    assert!(err_msg.contains("0x800f0806"));
}

#[test]
fn adv_test_log_cleaner_file_extension_preservation() {
    let fix = TempDirFixture::new("log_ext_preserve");

    // Files that MUST be deleted
    fix.create_file("panther/setupact.log", b"setup log");
    fix.create_file("panther/setuperr.log", b"setup error");
    fix.create_file("cbs/CbsPersist_2026.cab", b"cbs cab archive");
    fix.create_file("dism/dism.bak", b"dism backup");
    fix.create_file("traces/eventtrace.etl", b"etl trace log");
    fix.create_file("mosetup/update.txt", b"text log");

    // Files that MUST be PRESERVED (non-log files)
    let preserve_dll = fix.create_file("panther/unattend.xml", b"<xml>keep me</xml>");
    let preserve_ini = fix.create_file("panther/setup.ini", b"[settings]\nkeep=1");
    let preserve_dat = fix.create_file("cbs/registry.dat", b"binary dat");
    let preserve_exe = fix.create_file("dism/helper.exe", b"executable");

    let stats_before = scan_log_dir_files(&fix.path);
    assert_eq!(stats_before.files, 6); // 6 log/archive files

    let clean = clean_log_dir_files(&fix.path);
    assert_eq!(clean.deleted_files, 6);
    assert_eq!(clean.skipped_locked, 0);

    // Verify non-logs still exist
    assert!(preserve_dll.exists(), "unattend.xml should be preserved");
    assert!(preserve_ini.exists(), "setup.ini should be preserved");
    assert!(preserve_dat.exists(), "registry.dat should be preserved");
    assert!(preserve_exe.exists(), "helper.exe should be preserved");

    // Verify logs are gone
    assert!(!fix.path.join("panther/setupact.log").exists());
    assert!(!fix.path.join("cbs/CbsPersist_2026.cab").exists());
}

#[test]
fn adv_test_browser_profile_discovery_all_variations() {
    let fix = TempDirFixture::new("browser_multi_profile");
    let local = fix.path.join("Local");
    let roaming = fix.path.join("Roaming");

    // Chrome: Default + multiple Profiles
    fix.create_file(
        "Local/Google/Chrome/User Data/Default/Cache/f_001",
        b"data1",
    );
    fix.create_file(
        "Local/Google/Chrome/User Data/Default/Code Cache/js/f_002",
        b"data2",
    );
    fix.create_file(
        "Local/Google/Chrome/User Data/Default/GPUCache/data_0",
        b"data3",
    );
    fix.create_file(
        "Local/Google/Chrome/User Data/Profile 1/Cache/f_003",
        b"data4",
    );
    fix.create_file(
        "Local/Google/Chrome/User Data/Profile Work/Code Cache/wasm/f_004",
        b"data5",
    );
    // Non-profile Chrome dirs should NOT be recognized as profiles
    fix.create_file(
        "Local/Google/Chrome/User Data/Crashpad/reports/c1",
        b"crash",
    );
    fix.create_file("Local/Google/Chrome/User Data/GrShaderCache/c2", b"shader");

    // Edge: Default + Profile 2
    fix.create_file(
        "Local/Microsoft/Edge/User Data/Default/Cache/f_005",
        b"data6",
    );
    fix.create_file(
        "Local/Microsoft/Edge/User Data/Profile 2/Cache/f_006",
        b"data7",
    );

    // Firefox: Multiple profiles in LocalAppData and Roaming
    fix.create_file(
        "Local/Mozilla/Firefox/Profiles/abcd.default-release/cache2/entries/1",
        b"data8",
    );
    fix.create_file(
        "Roaming/Mozilla/Firefox/Profiles/efgh.dev-edition/cache2/entries/2",
        b"data9",
    );

    let dirs = discover_browser_cache_dirs(&local, &roaming);
    // Chrome: 3 dirs for Default + 3 dirs for Profile 1 + 3 dirs for Profile Work = 9
    // Edge: 3 dirs for Default + 3 dirs for Profile 2 = 6
    // Firefox: 1 dir from Local + 1 dir from Roaming = 2
    // Total dirs = 17
    assert_eq!(dirs.len(), 17);

    let mut total_stats = winmedic::modules::system_cleaner::DirStats::default();
    for d in &dirs {
        let st = scan_path_recursive(d);
        total_stats.bytes += st.bytes;
        total_stats.files += st.files;
    }
    assert_eq!(total_stats.files, 9); // 9 cache files created across the profile cache dirs
}

#[test]
fn adv_test_wer_and_crash_dumps_discovery() {
    let fix = TempDirFixture::new("wer_crashdumps");
    let local = fix.path.join("Local");
    let prog = fix.path.join("ProgramData");

    fix.create_file(
        "Local/Microsoft/Windows/WER/ReportArchive/AppCrash_1.wer",
        b"wer1",
    );
    fix.create_file(
        "Local/Microsoft/Windows/WER/ReportQueue/AppCrash_2.wer",
        b"wer2",
    );
    fix.create_file("Local/Microsoft/Windows/WER/Temp/tmp1.tmp", b"wer3");
    fix.create_file("Local/Microsoft/Windows/WER/ERC/erc1.dat", b"wer4");
    fix.create_file(
        "ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_3.wer",
        b"wer5",
    );
    fix.create_file("Local/CrashDumps/app.exe.1234.dmp", b"dump1");

    let dirs = discover_wer_and_dump_dirs(&local, &prog);
    assert_eq!(dirs.len(), 9); // 4 local WER + 4 prog WER + 1 CrashDumps

    let mut stats = winmedic::modules::system_cleaner::DirStats::default();
    for d in &dirs {
        let s = scan_path_recursive(d);
        stats.bytes += s.bytes;
        stats.files += s.files;
    }
    assert_eq!(stats.files, 6);
}

#[test]
fn adv_test_shader_and_cert_cache_discovery() {
    let fix = TempDirFixture::new("shader_certs");
    let local = fix.path.join("Local");
    let user = fix.path.join("User");

    fix.create_file("Local/D3DSCache/a1b2/shader.bin", b"shader1");
    fix.create_file("Local/Microsoft/DirectX/ShaderCache/dx.bin", b"shader2");
    fix.create_file(
        "User/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/crl1",
        b"cert content",
    );
    fix.create_file(
        "User/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/meta1",
        b"cert meta",
    );

    let dirs = discover_shader_and_cert_dirs(&local, &user);
    assert_eq!(dirs.len(), 4);

    let mut stats = winmedic::modules::system_cleaner::DirStats::default();
    for d in &dirs {
        let s = scan_path_recursive(d);
        stats.bytes += s.bytes;
        stats.files += s.files;
    }
    assert_eq!(stats.files, 4);
}

#[test]
fn adv_test_system_temp_discovery() {
    let fix = TempDirFixture::new("system_temp");
    let sys_root = fix.path.join("Windows");

    fix.create_file(
        "Windows/System32/config/systemprofile/AppData/Local/Temp/svc.tmp",
        b"svc temp",
    );
    fix.create_file("Windows/SystemTemp/win.tmp", b"system temp");

    let dirs = discover_system_temp_dirs(&sys_root);
    assert_eq!(dirs.len(), 2);

    let mut stats = winmedic::modules::system_cleaner::DirStats::default();
    for d in &dirs {
        let s = scan_path_recursive(d);
        stats.bytes += s.bytes;
        stats.files += s.files;
    }
    assert_eq!(stats.files, 2);
}

#[test]
fn adv_test_delivery_optimization_discovery() {
    let fix = TempDirFixture::new("delivery_opt");
    let sys_root = fix.path.join("Windows");

    fix.create_file(
        "Windows/SoftwareDistribution/DeliveryOptimization/chunk1.bin",
        b"chunk1",
    );
    fix.create_file("Windows/ServiceProfiles/NetworkService/AppData/Local/Microsoft/Windows/DeliveryOptimization/Cache/chunk2.bin", b"chunk2");

    let dirs = discover_delivery_optimization_dirs(&sys_root);
    assert_eq!(dirs.len(), 2);

    let mut stats = winmedic::modules::system_cleaner::DirStats::default();
    for d in &dirs {
        let s = scan_path_recursive(d);
        stats.bytes += s.bytes;
        stats.files += s.files;
    }
    assert_eq!(stats.files, 2);
}

#[tokio::test]
async fn adv_test_progress_reporting_all_steps() {
    let mock = MockCommandRunner::new();
    mock.add_response(
        "AnalyzeComponentStore",
        CmdOutput::ok(
            "Component Store Cleanup Recommended : No\nNumber of Reclaimable Packages : 0\n",
        ),
    );

    let (_sandbox, module) = sandboxed_cleaner("progress_steps", Arc::new(mock));
    let (tx, mut rx) = mpsc::channel::<ModuleProgress>(20);

    let handle = tokio::spawn(async move {
        let mut steps = Vec::new();
        while let Some(prog) = rx.recv().await {
            steps.push((prog.progress_percent, prog.current_step));
        }
        steps
    });

    let _ = module.scan(Some(tx)).await.unwrap();
    let steps = handle.await.unwrap();

    assert!(steps.iter().any(|(pct, _)| *pct == 10));
    assert!(steps.iter().any(|(pct, _)| *pct == 22));
    assert!(steps.iter().any(|(pct, _)| *pct == 34));
    assert!(steps.iter().any(|(pct, _)| *pct == 46));
    assert!(steps.iter().any(|(pct, _)| *pct == 58));
    assert!(steps.iter().any(|(pct, _)| *pct == 70));
    assert!(steps.iter().any(|(pct, _)| *pct == 80));
    assert!(steps.iter().any(|(pct, _)| *pct == 90));
    assert!(steps.iter().any(|(pct, _)| *pct == 95));
    assert!(steps.iter().any(|(pct, _)| *pct == 100));
}

#[tokio::test]
async fn adv_test_module_metadata_and_trait_conformance() {
    let mock = MockCommandRunner::new();
    let (_sandbox, module) = sandboxed_cleaner("module_metadata", Arc::new(mock));

    assert_eq!(module.id(), "system_cleaner");
    assert_eq!(module.name(), "System & Cache Cleaner");
    assert_eq!(module.icon(), "[CLR]");
    assert!(module.description().contains("WinSxS"));
    assert!(module.description().contains("Delivery Optimization"));
    assert!(module.description().contains("browser caches"));
}

#[tokio::test]
async fn adv_test_all_9_fix_issue_ids_respond() {
    let mock = MockCommandRunner::new();
    mock.add_response("StartComponentCleanup", CmdOutput::ok("Success"));
    mock.add_response("Delete-DeliveryOptimizationCache", CmdOutput::ok(""));
    mock.add_response("Clear-RecycleBin", CmdOutput::ok(""));

    let (_sandbox, module) = sandboxed_cleaner("all_fix_ids", Arc::new(mock));

    let ids = [
        "sys_clean_winsxs",
        "sys_clean_delivery_optimization",
        "sys_clean_package_cache",
        "sys_clean_browser_cache",
        "sys_clean_setup_logs",
        "sys_clean_error_reporting",
        "sys_clean_shader_certs",
        "sys_clean_recycle_bin",
        "sys_clean_system_temp",
    ];

    for id in &ids {
        let res = module.fix(id, None).await;
        assert!(
            res.is_ok(),
            "Fix for {} returned unexpected error: {:?}",
            id,
            res.err()
        );
    }

    let invalid = module.fix("sys_clean_invalid_random", None).await;
    assert!(invalid.is_err(), "Fix for invalid ID must return Err");
}

#[cfg(windows)]
#[test]
fn adv_test_clean_locked_file_tolerance() {
    use std::os::windows::fs::OpenOptionsExt;

    let fix = TempDirFixture::new("locked_file_tolerance");

    let unlocked_path = fix.create_file("unlocked.txt", b"freely deletable");
    let locked_path = fix.create_file("locked.txt", b"locked with FILE_SHARE_NONE");

    // Hold the lock in this process. `share_mode(0)` is FILE_SHARE_NONE: while
    // the handle lives, every other open on the file fails with a sharing
    // violation — including the one `DeleteFile` needs — so the sweep must skip
    // it. Locking from a spawned helper instead would race the sweep against
    // that process's startup, which is what made this test fail on CI.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&locked_path)
        .expect("failed to acquire exclusive lock on locked.txt");

    let clean_res = winmedic::modules::system_cleaner::clean_path_contents(&fix.path);

    drop(lock);

    // unlocked.txt is deleted, locked.txt was locked and skipped gracefully
    assert_eq!(clean_res.deleted_files, 1);
    assert_eq!(clean_res.freed_bytes, 16);
    assert_eq!(clean_res.skipped_locked, 1);
    assert!(!unlocked_path.exists());
    assert!(locked_path.exists());
}

#[tokio::test]
async fn adv_test_winsxs_reclaimable_packages_without_cleanup_recommended() {
    let mock = MockCommandRunner::new();
    mock.add_response(
        "AnalyzeComponentStore",
        CmdOutput::ok(
            "Explorer Reported Size of Component Store : 9.00 GB\n\
             Actual Size of Component Store : 8.50 GB\n\
             Number of Reclaimable Packages : 4\n\
             Component Store Cleanup Recommended : No\n\
             The operation completed successfully.",
        ),
    );

    let (_sandbox, module) = sandboxed_cleaner("reclaimable_no_rec", Arc::new(mock));
    let issues = module.scan(None).await.unwrap();

    let winsxs = issues.iter().find(|i| i.id == "sys_clean_winsxs");
    assert!(
        winsxs.is_some(),
        "Should trigger when reclaimable packages > 0 even if recommended is No"
    );
    let issue = winsxs.unwrap();
    assert!(issue.title.contains("4 reclaimable packages"));
}

#[tokio::test]
async fn adv_test_diagnostic_engine_full_integration_with_system_cleaner() {
    use tokio_util::sync::CancellationToken;
    use winmedic::config::AppConfig;
    use winmedic::engine::runner::{DiagnosticEngine, RepairEvent, RepairOptions, ScanEvent};

    let mock = MockCommandRunner::new();
    mock.add_response(
        "AnalyzeComponentStore",
        CmdOutput::ok(
            "Explorer Reported Size of Component Store : 10.00 GB\n\
             Number of Reclaimable Packages : 2\n\
             Component Store Cleanup Recommended : Yes\n",
        ),
    );
    mock.add_response("StartComponentCleanup", CmdOutput::ok("Success"));
    mock.add_response("vssadmin.exe", CmdOutput::ok("Shadow copies found"));
    mock.add_response("dism.exe", CmdOutput::ok("No corruption detected"));
    mock.add_response(
        "sfc.exe",
        CmdOutput::ok("Windows Resource Protection did not find any integrity violations."),
    );

    let config = AppConfig::default();
    let engine = DiagnosticEngine::with_runner(&config, Arc::new(mock.clone()));
    assert_eq!(
        engine.modules().len(),
        7,
        "DiagnosticEngine must register exactly 7 modules"
    );

    let (tx, mut rx) = mpsc::channel::<ScanEvent>(100);
    let cancel = CancellationToken::new();

    let event_collector = tokio::spawn(async move {
        let mut events = Vec::new();
        while let Some(evt) = rx.recv().await {
            events.push(evt);
        }
        events
    });

    let mut detected_issues = engine.run_scan(tx, cancel.clone()).await;
    let events = event_collector.await.unwrap();

    // Verify system_cleaner started and finished
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ScanEvent::ModuleStarted(id) if id == "system_cleaner"))
    );
    assert!(events.iter().any(|e| matches!(e, ScanEvent::ModuleFinished { module_id, .. } if module_id == "system_cleaner")));

    // Verify winsxs issue was detected by the engine
    assert!(detected_issues.iter().any(|i| i.id == "sys_clean_winsxs"));

    // Select ONLY sys_clean_winsxs for targeted repair test
    for issue in &mut detected_issues {
        issue.is_selected = issue.id == "sys_clean_winsxs";
    }

    // 1. Dry run repair simulation
    let (dry_tx, mut dry_rx) = mpsc::channel::<RepairEvent>(20);
    let dry_events_h = tokio::spawn(async move {
        let mut evts = Vec::new();
        while let Some(evt) = dry_rx.recv().await {
            evts.push(evt);
        }
        evts
    });

    let (succeeded, failed) = engine
        .run_repairs(
            &mut detected_issues,
            RepairOptions {
                dry_run: true,
                create_vss: false,
                verbose_logging: false,
            },
            dry_tx,
            cancel.clone(),
        )
        .await;

    let dry_evts = dry_events_h.await.unwrap();
    assert!(
        dry_evts
            .iter()
            .any(|e| matches!(e, RepairEvent::DryRunStarted { .. }))
    );
    assert_eq!(succeeded, 1); // 1 simulated repair
    assert_eq!(failed, 0);
    // Crucial invariant: dry run must NOT mark the issue as fixed
    assert!(
        !detected_issues
            .iter()
            .find(|i| i.id == "sys_clean_winsxs")
            .unwrap()
            .is_fixed
    );

    // 2. Real repair execution
    let (rep_tx, mut rep_rx) = mpsc::channel::<RepairEvent>(20);
    let rep_events_h = tokio::spawn(async move {
        let mut evts = Vec::new();
        while let Some(evt) = rep_rx.recv().await {
            evts.push(evt);
        }
        evts
    });

    let (succeeded, failed) = engine
        .run_repairs(
            &mut detected_issues,
            RepairOptions {
                dry_run: false,
                create_vss: false,
                verbose_logging: false,
            },
            rep_tx,
            cancel,
        )
        .await;

    let rep_evts = rep_events_h.await.unwrap();
    assert!(rep_evts.iter().any(|e| matches!(e, RepairEvent::FixFinished { issue_id, success: true, .. } if issue_id == "sys_clean_winsxs")));
    assert_eq!(succeeded, 1);
    assert_eq!(failed, 0);
    // Real repair MUST mark the issue as fixed
    assert!(
        detected_issues
            .iter()
            .find(|i| i.id == "sys_clean_winsxs")
            .unwrap()
            .is_fixed
    );
}
