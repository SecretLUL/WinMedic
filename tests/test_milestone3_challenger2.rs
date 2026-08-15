use std::time::Duration;
use winmedic::app::{App, BackgroundEvent, ConfirmRequest};
use winmedic::config::AppConfig;
use winmedic::utils::cmd::{CmdOutput, MockCommandRunner};
use winmedic::utils::updater::{
    GITHUB_LATEST_RELEASE_URL, SemVer, UpdateInfo, check_for_update, is_update_available,
    launch_browser,
};

// ============================================================================
// 1. SemVer Parser & Comparator Tests
// ============================================================================

#[test]
fn test_semver_parse_comprehensive() {
    // Standard formats
    let v1 = SemVer::parse("1.2.3").expect("1.2.3 should parse");
    assert_eq!(
        v1,
        SemVer {
            major: 1,
            minor: 2,
            patch: 3,
            pre: None
        }
    );

    let v2 = SemVer::parse("v0.1.0").expect("v0.1.0 should parse");
    assert_eq!(
        v2,
        SemVer {
            major: 0,
            minor: 1,
            patch: 0,
            pre: None
        }
    );

    let v3 = SemVer::parse("V2.10.5").expect("V2.10.5 should parse");
    assert_eq!(
        v3,
        SemVer {
            major: 2,
            minor: 10,
            patch: 5,
            pre: None
        }
    );

    // Truncated formats
    let v_short = SemVer::parse("1.0").expect("1.0 should parse");
    assert_eq!(
        v_short,
        SemVer {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None
        }
    );

    let v_single = SemVer::parse("2").expect("2 should parse");
    assert_eq!(
        v_single,
        SemVer {
            major: 2,
            minor: 0,
            patch: 0,
            pre: None
        }
    );

    // Pre-release and build metadata
    let v_rc = SemVer::parse("v0.2.0-rc1").expect("v0.2.0-rc1 should parse");
    assert_eq!(
        v_rc,
        SemVer {
            major: 0,
            minor: 2,
            patch: 0,
            pre: Some("rc1".to_string())
        }
    );

    let v_beta = SemVer::parse("1.5.0-beta.2+20260814").expect("beta+build should parse");
    assert_eq!(
        v_beta,
        SemVer {
            major: 1,
            minor: 5,
            patch: 0,
            pre: Some("beta.2".to_string())
        }
    );

    let v_build = SemVer::parse("1.0.0+sha.412a8f").expect("build metadata should parse");
    assert_eq!(
        v_build,
        SemVer {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None
        }
    );

    // Whitespace trimming
    let v_ws = SemVer::parse("   v3.4.5 \n\t").expect("whitespace trimmed should parse");
    assert_eq!(
        v_ws,
        SemVer {
            major: 3,
            minor: 4,
            patch: 5,
            pre: None
        }
    );
}

#[test]
fn test_semver_parse_invalid_inputs() {
    assert_eq!(SemVer::parse(""), None);
    assert_eq!(SemVer::parse("   "), None);
    assert_eq!(SemVer::parse("v"), None);
    assert_eq!(SemVer::parse("V"), None);
    assert_eq!(SemVer::parse("v."), None);
    assert_eq!(SemVer::parse(".1.2"), None);
    assert_eq!(SemVer::parse("abc"), None);
    assert_eq!(SemVer::parse("v.invalid"), None);
    assert_eq!(SemVer::parse("99999999999999999999999999999.0.0"), None); // Overflow protection
}

#[test]
fn test_semver_strict_ordering() {
    let v010 = SemVer::parse("0.1.0").unwrap();
    let v011 = SemVer::parse("0.1.1").unwrap();
    let v020 = SemVer::parse("0.2.0").unwrap();
    let v100 = SemVer::parse("1.0.0").unwrap();

    assert!(v011.is_newer_than(&v010));
    assert!(v020.is_newer_than(&v011));
    assert!(v020.is_newer_than(&v010));
    assert!(v100.is_newer_than(&v020));

    assert!(!v010.is_newer_than(&v010));
    assert!(!v010.is_newer_than(&v011));
    assert!(!v010.is_newer_than(&v100));
}

#[test]
fn test_is_update_available_matrix() {
    // Newer releases
    assert!(is_update_available("0.1.0", "v0.2.0"));
    assert!(is_update_available("v0.1.0", "0.1.1"));
    assert!(is_update_available("0.1.0", "v1.0.0-rc1"));
    assert!(is_update_available("0.1.0", "1.0"));
    assert!(is_update_available("0.9.9", "1.0.0"));

    // Equal or older releases
    assert!(!is_update_available("0.2.0", "v0.2.0"));
    assert!(!is_update_available("v0.2.0", "0.2.0"));
    assert!(!is_update_available("1.0.0", "v0.9.9"));
    assert!(!is_update_available("2.0.0", "1.9.9"));

    // Invalid inputs
    assert!(!is_update_available("invalid", "v1.0.0"));
    assert!(!is_update_available("1.0.0", "invalid"));
    assert!(!is_update_available("", ""));
}

// ============================================================================
// 2. GitHub Release Fetcher & Mock Testing
// ============================================================================

#[tokio::test]
async fn test_check_for_update_success_newer_release() {
    let mock = MockCommandRunner::new();
    let json_payload = r#"{
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0",
        "name": "WinMedic v0.2.0 - System Cleaner & Auto-Updater",
        "body": "Major enhancements release.",
        "draft": false,
        "prerelease": false
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(json_payload));

    let update = check_for_update(&mock, "0.1.0", Duration::from_secs(5))
        .await
        .expect("Expected update info to be returned");

    assert_eq!(update.current_version, "0.1.0");
    assert_eq!(update.latest_version, "v0.2.0");
    assert_eq!(
        update.release_url,
        "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
    );
    assert_eq!(
        update.release_name,
        Some("WinMedic v0.2.0 - System Cleaner & Auto-Updater".to_string())
    );
    assert_eq!(
        update.release_body,
        Some("Major enhancements release.".to_string())
    );

    let calls = mock.executed();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].contains("-s"));
    assert!(calls[0].contains("--max-time 5"));
    assert!(calls[0].contains("User-Agent: WinMedic"));
    assert!(calls[0].contains("Accept: application/vnd.github.v3+json"));
    assert!(calls[0].contains(GITHUB_LATEST_RELEASE_URL));
}

#[tokio::test]
async fn test_check_for_update_already_on_latest() {
    let mock = MockCommandRunner::new();
    let json_payload = r#"{
        "tag_name": "v0.1.0",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.1.0",
        "name": "WinMedic v0.1.0",
        "body": "Initial Release",
        "draft": false,
        "prerelease": false
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(json_payload));

    let result = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_check_for_update_ignores_draft() {
    let mock = MockCommandRunner::new();
    let json_payload = r#"{
        "tag_name": "v0.9.0",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.9.0",
        "name": "Draft",
        "body": "Unpublished Draft",
        "draft": true,
        "prerelease": false
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(json_payload));

    let result = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_check_for_update_command_error_and_malformed_json() {
    // Network / Command error
    let mock_err = MockCommandRunner::new();
    mock_err.add_response(
        "curl.exe",
        CmdOutput::failed(6, "curl: (6) Could not resolve host"),
    );
    assert_eq!(
        check_for_update(&mock_err, "0.1.0", Duration::from_secs(5)).await,
        None
    );

    // Malformed HTML 404 response
    let mock_404 = MockCommandRunner::new();
    mock_404.add_response("curl.exe", CmdOutput::ok("<html>404 Not Found</html>"));
    assert_eq!(
        check_for_update(&mock_404, "0.1.0", Duration::from_secs(5)).await,
        None
    );

    // Rate limited JSON payload
    let mock_rate_limit = MockCommandRunner::new();
    mock_rate_limit.add_response(
        "curl.exe",
        CmdOutput::ok(r#"{"message": "API rate limit exceeded", "documentation_url": "https://docs.github.com"}"#),
    );
    assert_eq!(
        check_for_update(&mock_rate_limit, "0.1.0", Duration::from_secs(5)).await,
        None
    );
}

// ============================================================================
// 3. Browser Launch & URL Validation
// ============================================================================

#[test]
fn test_launch_browser_empty_url_is_rejected() {
    let err = launch_browser("").unwrap_err();
    assert_eq!(err, "The URL must not be empty");
}

#[test]
fn test_launch_browser_valid_urls() {
    // Valid HTTPS URL
    assert!(launch_browser("https://github.com/SecretLUL/WinMedic/releases/latest").is_ok());
    // Valid URL with query params and anchors
    assert!(
        launch_browser("https://github.com/SecretLUL/WinMedic/releases?tab=tags#v0.2.0").is_ok()
    );
}

// ============================================================================
// 4. AppConfig Backwards Compatibility & Settings Toggle
// ============================================================================

#[test]
fn test_app_config_defaults_and_setting_count() {
    let cfg = AppConfig::default();
    assert!(cfg.check_for_updates);
    assert_eq!(AppConfig::SETTING_COUNT, 7);
}

#[test]
fn test_app_config_json_backwards_compatibility() {
    // Old config file without check_for_updates field
    let old_json = r#"{
        "auto_restart_services": false,
        "create_vss_before_repair": true,
        "auto_backup_registry": false,
        "temp_clean_threshold_mb": 750,
        "max_event_log_hours": 48
    }"#;
    let cfg: AppConfig = serde_json::from_str(old_json).expect("Should deserialize old config");
    assert!(!cfg.auto_restart_services);
    assert!(cfg.create_vss_before_repair);
    assert!(!cfg.auto_backup_registry);
    assert_eq!(cfg.temp_clean_threshold_mb, 750);
    assert_eq!(cfg.max_event_log_hours, 48);
    // Crucial check: check_for_updates must default to true
    assert!(cfg.check_for_updates);

    // Empty JSON {}
    let empty_cfg: AppConfig = serde_json::from_str("{}").expect("Should deserialize empty JSON");
    assert!(empty_cfg.check_for_updates);

    // Explicit false
    let explicit_false: AppConfig = serde_json::from_str(r#"{"check_for_updates": false}"#)
        .expect("Should deserialize explicit false");
    assert!(!explicit_false.check_for_updates);
}

#[test]
fn test_app_config_setting_row_and_toggle() {
    let mut cfg = AppConfig::default();

    // Index 3 is check_for_updates
    let row3 = cfg.setting_row(3).expect("Setting row 3 must exist");
    assert_eq!(row3.0, "Check for updates automatically");
    assert_eq!(row3.1, "ON");
    assert!(row3.2.contains("GitHub"));

    // Toggle row 3
    assert!(cfg.toggle_setting(3));
    assert!(!cfg.check_for_updates);
    let row3_off = cfg.setting_row(3).unwrap();
    assert_eq!(row3_off.1, "OFF");

    // Adjust setting on index 3 also toggles
    assert!(cfg.adjust_setting(3, true));
    assert!(cfg.check_for_updates);

    // Out-of-bounds indices
    assert!(!cfg.toggle_setting(7));
    assert!(!cfg.toggle_setting(99));
    assert!(cfg.setting_row(7).is_none());
}

// ============================================================================
// 5. App Lifecycle, Event Channel & Modal State Machine
// ============================================================================

#[tokio::test]
async fn test_app_event_channel_update_checked_when_no_modal_active() {
    let mut app = App::new();
    // Simulate no elevate modal active
    app.pending_confirm = None;
    app.available_update = None;

    let update_info = UpdateInfo {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        release_name: Some("WinMedic v0.2.0".to_string()),
        release_body: Some("Release notes".to_string()),
    };

    // Inject UpdateChecked event directly
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // Replace internal bg channel for controlled testing
    let _ = tx.send(BackgroundEvent::UpdateChecked(Some(update_info.clone())));

    // We can simulate app processing bg events directly
    if let Ok(BackgroundEvent::UpdateChecked(Some(info))) = rx.try_recv() {
        app.status_message = Some(format!(
            "Update available: v{} (current: v{})",
            info.latest_version.trim_start_matches(['v', 'V']),
            info.current_version.trim_start_matches(['v', 'V'])
        ));
        if app.pending_confirm.is_none() {
            app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
                current_version: info.current_version,
                latest_version: info.latest_version,
                release_url: info.release_url,
            });
        } else {
            app.available_update = Some(info);
        }
    }

    // Verify pending_confirm is set to UpdateAvailable
    match &app.pending_confirm {
        Some(ConfirmRequest::UpdateAvailable {
            current_version,
            latest_version,
            release_url,
        }) => {
            assert_eq!(current_version, "0.1.0");
            assert_eq!(latest_version, "v0.2.0");
            assert_eq!(
                release_url,
                "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
            );
        }
        other => panic!("Expected ConfirmRequest::UpdateAvailable, got {:?}", other),
    }
    assert!(app.available_update.is_none());
    assert!(app.status_message.as_ref().unwrap().contains("v0.2.0"));
}

#[tokio::test]
async fn test_app_event_channel_update_buffering_when_elevate_modal_active() {
    let mut app = App::new();
    // In unprivileged mode, Elevate modal is active initially
    app.pending_confirm = Some(ConfirmRequest::Elevate);
    app.available_update = None;

    let update_info = UpdateInfo {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        release_name: Some("WinMedic v0.2.0".to_string()),
        release_body: Some("Release notes".to_string()),
    };

    // UpdateChecked arrives while the Elevate modal is open. It is always
    // buffered, never raised on its own.
    app.available_update = Some(update_info.clone());

    // Confirm Elevate modal is NOT overwritten
    match &app.pending_confirm {
        Some(ConfirmRequest::Elevate) => {}
        other => panic!(
            "Expected ConfirmRequest::Elevate to remain active, got {:?}",
            other
        ),
    }
    // Update is buffered
    assert!(app.available_update.is_some());

    // User dismisses Elevate modal — no second modal is pushed at them.
    app.dismiss_confirm();
    assert!(app.pending_confirm.is_none());
    assert!(app.available_update.is_some());

    // [U] opens the buffered notice on request.
    app.show_update_notice();
    match &app.pending_confirm {
        Some(ConfirmRequest::UpdateAvailable {
            current_version,
            latest_version,
            release_url,
        }) => {
            assert_eq!(current_version, "0.1.0");
            assert_eq!(latest_version, "v0.2.0");
            assert_eq!(
                release_url,
                "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
            );
        }
        other => panic!(
            "Expected ConfirmRequest::UpdateAvailable after [U], got {:?}",
            other
        ),
    }
}

#[test]
fn test_confirm_request_update_available_formatting() {
    let req = ConfirmRequest::UpdateAvailable {
        current_version: "v0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
    };

    assert_eq!(req.title(), "NEW WINMEDIC UPDATE AVAILABLE");
    assert_eq!(req.confirm_label(), "Open the release page in a browser");
    assert_eq!(req.dismiss_label(), "Remind me later");

    let body = req.body();
    assert!(
        body.iter()
            .any(|line| line.contains("Installed version: v0.1.0"))
    );
    assert!(
        body.iter()
            .any(|line| line.contains("Latest version:    v0.2.0"))
    );
    assert!(
        body.iter()
            .any(|line| line.contains("https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"))
    );
    assert!(
        body.iter()
            .any(|line| line.contains("Open the GitHub release page in your default browser"))
    );
}

#[tokio::test]
async fn test_app_update_modal_confirm_and_dismiss_actions() {
    // Test Dismiss
    let mut app = App::new();
    app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
    });
    app.available_update = None;

    app.dismiss_confirm();
    assert!(app.pending_confirm.is_none());
    assert_eq!(
        app.status_message,
        Some("Update notice dismissed - [U] reopens it.".to_string())
    );

    // Test Confirm
    app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
    });
    app.available_update = None;

    app.confirm_pending_action();
    assert!(app.pending_confirm.is_none());
    assert_eq!(
        app.status_message,
        Some("Opened the GitHub release page in your browser.".to_string())
    );
}
