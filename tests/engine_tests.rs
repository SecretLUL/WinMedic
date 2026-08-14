use winmedic::config::AppConfig;
use winmedic::engine::issue::{Issue, RiskScore, Severity};
use winmedic::engine::runner::DiagnosticEngine;
use winmedic::safety::audit::AuditLogger;

#[test]
fn test_default_config() {
    let cfg = AppConfig::default();
    assert!(cfg.create_vss_before_repair);
    assert!(cfg.auto_restart_services);
    assert_eq!(cfg.max_event_log_hours, 24);
    assert_eq!(cfg.temp_clean_threshold_mb, 500);
}

#[test]
fn test_health_score_calculation() {
    let mut issues = vec![
        Issue::new(
            "test_1",
            "system_integrity",
            "Critical Issue",
            "Category",
            Severity::Critical,
            RiskScore::Low,
            "Description",
            "Details",
            "Fix",
            vec!["Step 1".to_string()],
        ),
        Issue::new(
            "test_2",
            "storage",
            "Warning Issue",
            "Category",
            Severity::Warning,
            RiskScore::Low,
            "Description",
            "Details",
            "Fix",
            vec!["Step 1".to_string()],
        ),
    ];

    // 100 - 25 (Critical) - 10 (Warning) = 65
    let score = DiagnosticEngine::calculate_health_score(&issues);
    assert_eq!(score, 65);

    // After fixing the critical issue: 100 - 10 = 90
    issues[0].is_fixed = true;
    let score_after_fix = DiagnosticEngine::calculate_health_score(&issues);
    assert_eq!(score_after_fix, 90);
}

#[test]
fn test_audit_logger_creation() {
    let logger = AuditLogger::new();
    assert!(logger.log_dir().exists());
}
