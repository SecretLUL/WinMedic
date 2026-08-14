//! Adversarial stress test suite for Milestone 3: Startup Auto-Updater & Settings
//!
//! Author: Challenger 1
//! Scope: SemVer parser fuzzing/edge cases, comparison truth table, MockCommandRunner
//! GitHub API response matrix, AppConfig boundary toggles/persistence, and App modal buffering.

use std::time::Duration;
use winmedic::app::{App, BackgroundEvent, ConfirmRequest};
use winmedic::config::AppConfig;
use winmedic::utils::cmd::{CmdOutput, MockCommandRunner};
use winmedic::utils::updater::{
    check_for_update, is_update_available, launch_browser, SemVer, UpdateInfo,
};

// ============================================================================
// 1. SEMVER PARSING ADVERSARIAL CASES
// ============================================================================

#[test]
fn test_semver_adversarial_standard_and_prefixed() {
    let cases = vec![
        ("1.2.3", Some(SemVer { major: 1, minor: 2, patch: 3 })),
        ("v1.2.3", Some(SemVer { major: 1, minor: 2, patch: 3 })),
        ("V1.2.3", Some(SemVer { major: 1, minor: 2, patch: 3 })),
        ("V10.20.30", Some(SemVer { major: 10, minor: 20, patch: 30 })),
        ("v0.0.0", Some(SemVer { major: 0, minor: 0, patch: 0 })),
        ("0.0.0", Some(SemVer { major: 0, minor: 0, patch: 0 })),
        ("v0.1.0", Some(SemVer { major: 0, minor: 1, patch: 0 })),
        ("v100.200.300", Some(SemVer { major: 100, minor: 200, patch: 300 })),
    ];

    for (input, expected) in cases {
        let parsed = SemVer::parse(input);
        assert_eq!(parsed, expected, "Failed for input: '{}'", input);
    }
}

#[test]
fn test_semver_adversarial_whitespace_handling() {
    let whitespace_cases = vec![
        ("  1.2.3  ", Some(SemVer { major: 1, minor: 2, patch: 3 })),
        ("\t\n\r  v2.4.6 \n\t", Some(SemVer { major: 2, minor: 4, patch: 6 })),
        ("   V0.9.1   ", Some(SemVer { major: 0, minor: 9, patch: 1 })),
        (" \r\n v0.0.1-rc1 \t", Some(SemVer { major: 0, minor: 0, patch: 1 })),
    ];

    for (input, expected) in whitespace_cases {
        assert_eq!(SemVer::parse(input), expected, "Failed whitespace trim for: '{}'", input);
    }
}

#[test]
fn test_semver_adversarial_prerelease_and_build_metadata() {
    let cases = vec![
        ("1.0.0-alpha.1", Some(SemVer { major: 1, minor: 0, patch: 0 })),
        ("2.0.0+build.184", Some(SemVer { major: 2, minor: 0, patch: 0 })),
        ("v1.2.3-beta.2+20260814", Some(SemVer { major: 1, minor: 2, patch: 3 })),
        ("V0.3.0-nightly-2026-08-14", Some(SemVer { major: 0, minor: 3, patch: 0 })),
        ("1.0.0-rc.1+sha.5114f85", Some(SemVer { major: 1, minor: 0, patch: 0 })),
        ("0.1.0-SNAPSHOT", Some(SemVer { major: 0, minor: 1, patch: 0 })),
    ];

    for (input, expected) in cases {
        assert_eq!(SemVer::parse(input), expected, "Failed prerelease/build parse for: '{}'", input);
    }
}

#[test]
fn test_semver_adversarial_partial_versions() {
    // 2-segment and 1-segment versions should parse with remaining fields defaulted to 0
    assert_eq!(SemVer::parse("1.2"), Some(SemVer { major: 1, minor: 2, patch: 0 }));
    assert_eq!(SemVer::parse("v3"), Some(SemVer { major: 3, minor: 0, patch: 0 }));
    assert_eq!(SemVer::parse("0"), Some(SemVer { major: 0, minor: 0, patch: 0 }));
    assert_eq!(SemVer::parse("0.1"), Some(SemVer { major: 0, minor: 1, patch: 0 }));
    // 4-segment inputs parse the first 3 segments
    assert_eq!(SemVer::parse("1.2.3.4"), Some(SemVer { major: 1, minor: 2, patch: 3 }));
}

#[test]
fn test_semver_adversarial_lenient_parsing() {
    // Lenient recovery for multi-v prefixes, trailing dots, and skipped components
    assert_eq!(SemVer::parse("vv1.0.0"), Some(SemVer { major: 1, minor: 0, patch: 0 }));
    assert_eq!(SemVer::parse("VVV2.1.0"), Some(SemVer { major: 2, minor: 1, patch: 0 }));
    assert_eq!(SemVer::parse("1..2"), Some(SemVer { major: 1, minor: 0, patch: 2 }));
    assert_eq!(SemVer::parse("1."), Some(SemVer { major: 1, minor: 0, patch: 0 }));
    assert_eq!(SemVer::parse("1.2."), Some(SemVer { major: 1, minor: 2, patch: 0 }));
    assert_eq!(SemVer::parse("1.2.x"), Some(SemVer { major: 1, minor: 2, patch: 0 }));
    assert_eq!(SemVer::parse("1.-2.3"), Some(SemVer { major: 1, minor: 0, patch: 0 }));
}

#[test]
fn test_semver_adversarial_malformed_inputs_rejected() {
    let malformed_inputs = vec![
        "",
        "   ",
        "\t\n",
        "v",
        "V",
        "vv",
        "VVV",
        "v_1.0.0",
        "abc",
        "winmedic",
        "..",
        ".",
        "...",
        ".1.2",
        "-1.0.0",
        "v-1.0.0",
        "v.1.2",
        "a.b.c",
        "99999999999999999999999999999.0.0", // u32 overflow on major
        "!@#$%^&*()",
        "v 1.2.3", // internal space after prefix
    ];

    for input in malformed_inputs {
        assert_eq!(SemVer::parse(input), None, "Expected None for malformed input: '{}'", input);
    }
}

// ============================================================================
// 2. SEMVER COMPARISON TRUTH TABLE
// ============================================================================

#[test]
fn test_semver_comparison_truth_table() {
    struct Case<'a> {
        current: &'a str,
        latest: &'a str,
        update_available: bool,
    }

    let truth_table = vec![
        // Newer patch
        Case { current: "1.0.0", latest: "1.0.1", update_available: true },
        Case { current: "1.0.0", latest: "v1.0.1", update_available: true },
        Case { current: "v1.0.0", latest: "1.0.1", update_available: true },
        // Newer minor
        Case { current: "1.0.0", latest: "1.1.0", update_available: true },
        Case { current: "1.2.3", latest: "1.3.0", update_available: true },
        // Newer major
        Case { current: "1.9.9", latest: "2.0.0", update_available: true },
        Case { current: "0.9.9", latest: "1.0.0", update_available: true },
        // Equal versions
        Case { current: "1.2.3", latest: "1.2.3", update_available: false },
        Case { current: "v1.2.3", latest: "1.2.3", update_available: false },
        Case { current: "1.2.3", latest: "v1.2.3", update_available: false },
        Case { current: "V1.2.3", latest: "v1.2.3", update_available: false },
        Case { current: "0.0.0", latest: "0.0.0", update_available: false },
        // Pre-release versions with same core (parsed identically)
        Case { current: "1.0.0", latest: "1.0.0-rc1", update_available: false },
        Case { current: "1.0.0-beta", latest: "1.0.0", update_available: false },
        // Older versions (downgrades / stale releases)
        Case { current: "2.0.0", latest: "1.9.9", update_available: false },
        Case { current: "1.0.1", latest: "1.0.0", update_available: false },
        Case { current: "1.1.0", latest: "1.0.9", update_available: false },
        Case { current: "1.2.3", latest: "1.2.2", update_available: false },
        Case { current: "0.0.1", latest: "0.0.0", update_available: false },
        // Boundary versions
        Case { current: "0.0.0", latest: "0.0.1", update_available: true },
        Case { current: "0.0.0", latest: "1.0.0", update_available: true },
        // Malformed / Unparseable
        Case { current: "malformed", latest: "1.0.0", update_available: false },
        Case { current: "1.0.0", latest: "malformed", update_available: false },
        Case { current: "", latest: "", update_available: false },
        Case { current: "1.0.0", latest: "", update_available: false },
        Case { current: "", latest: "1.0.0", update_available: false },
        Case { current: "abc", latest: "def", update_available: false },
    ];

    for Case { current, latest, update_available } in truth_table {
        let result = is_update_available(current, latest);
        assert_eq!(
            result,
            update_available,
            "Truth table failure: is_update_available('{}', '{}') was expected to be {}",
            current,
            latest,
            update_available
        );
    }
}

// ============================================================================
// 3. MOCK COMMAND RUNNER & GITHUB API RESPONSE MATRIX
// ============================================================================

#[tokio::test]
async fn test_github_api_valid_newer_release_full_payload() {
    let mock = MockCommandRunner::new();
    let payload = serde_json::json!({
        "tag_name": "v0.3.5",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.3.5",
        "name": "WinMedic v0.3.5 – System Cleaner & Auto-Updater",
        "body": "### Änderungen\n- WinSxS Component Store Deep Clean\n- WUDO Bereinigung",
        "draft": false,
        "prerelease": false
    }).to_string();
    mock.add_response("curl.exe", CmdOutput::ok(payload));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5))
        .await
        .expect("Expected UpdateInfo for valid newer release");

    assert_eq!(info.current_version, "0.1.0");
    assert_eq!(info.latest_version, "v0.3.5");
    assert_eq!(info.release_url, "https://github.com/SecretLUL/WinMedic/releases/tag/v0.3.5");
    assert_eq!(info.release_name, Some("WinMedic v0.3.5 – System Cleaner & Auto-Updater".to_string()));
    assert!(info.release_body.as_ref().unwrap().contains("WinSxS"));
}

#[tokio::test]
async fn test_github_api_valid_newer_release_minimal_payload() {
    // Release JSON with only required fields (name and body missing, draft/prerelease omitted)
    let mock = MockCommandRunner::new();
    let payload = r#"{
        "tag_name": "v1.0.0",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v1.0.0"
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(payload));

    let info = check_for_update(&mock, "0.9.0", Duration::from_secs(5))
        .await
        .expect("Expected UpdateInfo for minimal release payload");

    assert_eq!(info.current_version, "0.9.0");
    assert_eq!(info.latest_version, "v1.0.0");
    assert_eq!(info.release_name, None);
    assert_eq!(info.release_body, None);
}

#[tokio::test]
async fn test_github_api_equal_version_payload_returns_none() {
    let mock = MockCommandRunner::new();
    let payload = r#"{
        "tag_name": "v0.1.0",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.1.0",
        "draft": false,
        "prerelease": false
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(payload));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info, None, "Expected None when release tag matches current version");
}

#[tokio::test]
async fn test_github_api_older_version_payload_returns_none() {
    let mock = MockCommandRunner::new();
    let payload = r#"{
        "tag_name": "v0.0.9",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.0.9",
        "draft": false,
        "prerelease": false
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(payload));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info, None, "Expected None when release tag is older than current version");
}

#[tokio::test]
async fn test_github_api_draft_release_ignored() {
    let mock = MockCommandRunner::new();
    let payload = r#"{
        "tag_name": "v9.9.9",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v9.9.9",
        "draft": true,
        "prerelease": false
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(payload));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info, None, "Draft release must never trigger an update prompt");
}

#[tokio::test]
async fn test_github_api_network_timeout_exit_code_28() {
    let mock = MockCommandRunner::new();
    mock.add_response("curl.exe", CmdOutput::failed(28, "curl: (28) Operation timed out after 5001 milliseconds"));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info, None, "Timeout error must gracefully yield None without panic");
}

#[tokio::test]
async fn test_github_api_dns_resolution_failure_exit_code_6() {
    let mock = MockCommandRunner::new();
    mock.add_response("curl.exe", CmdOutput::failed(6, "curl: (6) Could not resolve host: api.github.com"));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info, None, "DNS resolution failure must yield None");
}

#[tokio::test]
async fn test_github_api_404_not_found_json_response() {
    let mock = MockCommandRunner::new();
    let not_found_payload = r#"{
        "message": "Not Found",
        "documentation_url": "https://docs.github.com/rest/releases/releases#get-the-latest-release"
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(not_found_payload));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info, None, "404 Not Found JSON without tag_name must safely yield None");
}

#[tokio::test]
async fn test_github_api_403_rate_limit_json_response() {
    let mock = MockCommandRunner::new();
    let rate_limit_payload = r#"{
        "message": "API rate limit exceeded for 192.0.2.1. (But here's the good news: Authenticated requests get a higher rate limit.)",
        "documentation_url": "https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting"
    }"#;
    mock.add_response("curl.exe", CmdOutput::ok(rate_limit_payload));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info, None, "403 Rate Limit response must safely yield None");
}

#[tokio::test]
async fn test_github_api_500_html_error_response() {
    let mock = MockCommandRunner::new();
    let html_payload = r#"<!DOCTYPE html>
    <html>
    <head><title>500 Internal Server Error</title></head>
    <body><center><h1>500 Internal Server Error</h1></center></body>
    </html>"#;
    mock.add_response("curl.exe", CmdOutput::ok(html_payload));

    let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info, None, "HTML error response must safely yield None");
}

#[tokio::test]
async fn test_github_api_malformed_json_and_empty_payload() {
    let mock = MockCommandRunner::new();
    mock.add_response("curl.exe", CmdOutput::ok("{ invalid json tag_name: v0.2.0 }"));

    let info1 = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info1, None);

    let mock_empty = MockCommandRunner::new();
    mock_empty.add_response("curl.exe", CmdOutput::ok(""));

    let info2 = check_for_update(&mock_empty, "0.1.0", Duration::from_secs(5)).await;
    assert_eq!(info2, None);
}

#[tokio::test]
async fn test_github_api_large_payload_stress() {
    let mock = MockCommandRunner::new();
    // 64 KB release notes body with unicode
    let big_body = "A".repeat(65536) + " — Sonderzeichen: äöüß € §";
    let payload = serde_json::json!({
        "tag_name": "v2.0.0",
        "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v2.0.0",
        "name": "WinMedic 2.0 Großes Update",
        "body": big_body,
        "draft": false,
        "prerelease": false
    }).to_string();

    mock.add_response("curl.exe", CmdOutput::ok(payload));

    let info = check_for_update(&mock, "1.0.0", Duration::from_secs(5))
        .await
        .expect("Expected UpdateInfo for large payload");

    assert_eq!(info.latest_version, "v2.0.0");
    assert!(info.release_body.unwrap().len() > 65536);
}

// ============================================================================
// 4. APPCONFIG BOUNDARY SETTINGS & PERSISTENCE
// ============================================================================

#[test]
fn test_appconfig_default_and_setting_count() {
    let cfg = AppConfig::default();
    assert!(cfg.check_for_updates);
    assert_eq!(AppConfig::SETTING_COUNT, 6);
}

#[test]
fn test_appconfig_setting_row_3_metadata() {
    let mut cfg = AppConfig::default();
    let (label, val, desc) = cfg.setting_row(3).expect("Setting row 3 must exist");
    assert_eq!(label, "Automatisch nach Updates suchen");
    assert_eq!(val, "AN");
    assert!(desc.contains("GitHub"));

    cfg.check_for_updates = false;
    let (_, val_off, _) = cfg.setting_row(3).unwrap();
    assert_eq!(val_off, "AUS");
}

#[test]
fn test_appconfig_toggle_and_adjust_boundary_cases() {
    let mut cfg = AppConfig::default();

    // Toggle row 3
    assert!(cfg.toggle_setting(3));
    assert!(!cfg.check_for_updates);
    assert!(cfg.toggle_setting(3));
    assert!(cfg.check_for_updates);

    // Adjust row 3 (delegates to toggle)
    assert!(cfg.adjust_setting(3, true));
    assert!(!cfg.check_for_updates);
    assert!(cfg.adjust_setting(3, false));
    assert!(cfg.check_for_updates);

    // Out of bounds indices
    assert!(!cfg.toggle_setting(6));
    assert!(!cfg.toggle_setting(100));
    assert!(!cfg.toggle_setting(usize::MAX));

    assert!(!cfg.adjust_setting(6, true));
    assert!(!cfg.adjust_setting(100, false));
    assert!(!cfg.adjust_setting(usize::MAX, true));

    assert_eq!(cfg.setting_row(6), None);
    assert_eq!(cfg.setting_row(100), None);
    assert_eq!(cfg.setting_row(usize::MAX), None);
}

#[test]
fn test_appconfig_serde_backward_and_forward_compatibility() {
    // 1. Deserializing empty JSON should yield all defaults including check_for_updates: true
    let cfg1: AppConfig = serde_json::from_str("{}").expect("Failed to deserialize empty JSON");
    assert!(cfg1.check_for_updates);
    assert!(cfg1.create_vss_before_repair);
    assert_eq!(cfg1.temp_clean_threshold_mb, 500);

    // 2. Legacy JSON missing check_for_updates
    let legacy_json = r#"{
        "auto_restart_services": false,
        "create_vss_before_repair": true,
        "temp_clean_threshold_mb": 1000
    }"#;
    let cfg2: AppConfig = serde_json::from_str(legacy_json).expect("Failed legacy deserialization");
    assert!(!cfg2.auto_restart_services);
    assert!(cfg2.check_for_updates); // defaulted to true
    assert_eq!(cfg2.temp_clean_threshold_mb, 1000);

    // 3. Explicit check_for_updates: false
    let explicit_json = r#"{"check_for_updates": false}"#;
    let cfg3: AppConfig = serde_json::from_str(explicit_json).expect("Failed explicit deserialization");
    assert!(!cfg3.check_for_updates);
    assert!(cfg3.create_vss_before_repair);

    // 4. Roundtrip with extra future fields ignored by serde
    let future_json = r#"{
        "check_for_updates": false,
        "future_ai_engine_enabled": true,
        "cloud_sync": "enterprise"
    }"#;
    let cfg4: AppConfig = serde_json::from_str(future_json).expect("Failed future field deserialization");
    assert!(!cfg4.check_for_updates);

    // 5. Full roundtrip serialization
    let serialized = serde_json::to_string_pretty(&cfg4).expect("Failed serialization");
    assert!(serialized.contains("\"check_for_updates\": false"));
    let restored: AppConfig = serde_json::from_str(&serialized).expect("Failed restore");
    assert_eq!(cfg4, restored);
}

// ============================================================================
// 5. APP LIFECYCLE, MODAL BUFFERING & BROWSER LAUNCH
// ============================================================================

#[test]
fn test_browser_launch_validation() {
    assert!(launch_browser("").is_err(), "Empty URL must return Err");
    assert!(launch_browser("https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0").is_ok());
}

#[test]
fn test_confirm_request_update_available_dialog_contract() {
    let req = ConfirmRequest::UpdateAvailable {
        current_version: "v0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
    };

    assert_eq!(req.title(), "NEUES WINMEDIC UPDATE VERFÜGBAR");
    assert_eq!(req.confirm_label(), "Release-Seite im Browser öffnen");
    assert_eq!(req.dismiss_label(), "Später erinnern");

    let body = req.body().join("\n");
    assert!(body.contains("v0.1.0"));
    assert!(body.contains("v0.2.0"));
    assert!(body.contains("https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"));
    assert!(body.contains("Standardbrowser"));
}

#[tokio::test]
async fn test_app_update_buffering_when_elevate_dialog_is_active() {
    let mut app = App::new();
    // Simulate non-admin initial state where Elevate confirm is active
    app.pending_confirm = Some(ConfirmRequest::Elevate);
    app.available_update = None;

    let update_info = UpdateInfo {
        current_version: "0.1.0".to_string(),
        latest_version: "v0.2.0".to_string(),
        release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        release_name: Some("v0.2.0".to_string()),
        release_body: Some("Changelog".to_string()),
    };

    // Inject BackgroundEvent::UpdateChecked into App's bg_rx channel via bg_tx
    // We can simulate calling process_background_events by manually pushing to background events
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(BackgroundEvent::UpdateChecked(Some(update_info.clone()))).unwrap();

    if let Ok(BackgroundEvent::UpdateChecked(Some(info))) = rx.try_recv() {
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

    // Elevate dialog is still active, update is buffered in available_update
    assert!(matches!(app.pending_confirm, Some(ConfirmRequest::Elevate)));
    assert!(app.available_update.is_some());

    // Dismiss the Elevate dialog
    app.dismiss_confirm();

    // Now the buffered UpdateAvailable dialog is presented to the user!
    assert!(matches!(
        app.pending_confirm,
        Some(ConfirmRequest::UpdateAvailable { .. })
    ));
    assert!(app.available_update.is_none());

    // Dismiss the update dialog
    app.dismiss_confirm();
    assert!(app.pending_confirm.is_none());
}
