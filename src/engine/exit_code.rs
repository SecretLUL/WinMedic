//! Process exit codes for headless / automation use.
//!
//! `winmedic.exe --scan` is meant to be callable from scripts, RMM agents and
//! CI pipelines, so the outcome has to be visible in `%ERRORLEVEL%` rather than
//! only in the printed report.

use crate::engine::issue::{Issue, Severity};

/// No open issues above informational level.
pub const OK: u8 = 0;
/// At least one unresolved warning.
pub const WARNINGS: u8 = 1;
/// At least one unresolved critical issue.
pub const CRITICAL: u8 = 2;
/// At least one repair was attempted and failed.
pub const FIX_FAILED: u8 = 3;
/// WinMedic was started without Administrator privileges.
pub const NEEDS_ADMIN: u8 = 4;
/// WinMedic itself failed (terminal, I/O, task join, ...).
pub const INTERNAL_ERROR: u8 = 5;
/// The run was aborted before finishing (Ctrl+C), so findings are incomplete.
pub const CANCELLED: u8 = 6;
/// At least one check could not run, so the findings are incomplete.
pub const INCOMPLETE: u8 = 7;

/// Derive an exit code from the state of the issue list.
///
/// `failed_fixes` is the number of repairs that were attempted and did not
/// succeed; it outranks the severity of what is left over, because a failed
/// repair is a WinMedic problem while a remaining finding is a system problem.
///
/// `failed_modules` is the number of modules whose check could not run. Their
/// findings are missing, so a clean list proves nothing about them: it outranks
/// the warnings and an all-clear, but not a critical finding, which is definite.
pub fn from_issues(issues: &[Issue], failed_fixes: usize, failed_modules: usize) -> u8 {
    if failed_fixes > 0 {
        return FIX_FAILED;
    }

    let open = || issues.iter().filter(|i| !i.is_fixed);

    if open().any(|i| i.severity == Severity::Critical) {
        CRITICAL
    } else if failed_modules > 0 {
        INCOMPLETE
    } else if open().any(|i| i.severity == Severity::Warning) {
        WARNINGS
    } else {
        OK
    }
}

/// One-line explanation of a code, printed at the end of a headless run.
pub fn describe(code: u8) -> &'static str {
    match code {
        OK => "No open issues above informational level.",
        WARNINGS => "Open warnings present.",
        CRITICAL => "Open critical issues present.",
        FIX_FAILED => "At least one repair failed.",
        NEEDS_ADMIN => "WinMedic needs Administrator privileges.",
        INTERNAL_ERROR => "Internal WinMedic error.",
        CANCELLED => "Run aborted - results are incomplete.",
        INCOMPLETE => "At least one check could not run, so the findings are incomplete.",
        _ => "Unknown status.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::issue::RiskScore;

    fn issue(id: &str, severity: Severity) -> Issue {
        Issue::new(
            id,
            "storage",
            "Title",
            "Category",
            severity,
            RiskScore::Low,
            "Description",
            "Details",
            "Fix",
            vec!["Step".to_string()],
        )
    }

    #[test]
    fn test_clean_system_is_zero() {
        assert_eq!(from_issues(&[], 0, 0), OK);
        assert_eq!(from_issues(&[issue("a", Severity::Info)], 0, 0), OK);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(
            from_issues(&[issue("a", Severity::Warning)], 0, 0),
            WARNINGS
        );
        assert_eq!(
            from_issues(&[issue("a", Severity::Critical)], 0, 0),
            CRITICAL
        );
        // The worst open severity wins.
        let mixed = vec![
            issue("a", Severity::Warning),
            issue("b", Severity::Critical),
        ];
        assert_eq!(from_issues(&mixed, 0, 0), CRITICAL);
    }

    #[test]
    fn test_fixed_issues_do_not_count() {
        let mut issues = vec![issue("a", Severity::Critical)];
        issues[0].is_fixed = true;
        assert_eq!(from_issues(&issues, 0, 0), OK);
    }

    #[test]
    fn test_failed_fix_outranks_severity() {
        let mut issues = vec![issue("a", Severity::Critical)];
        issues[0].is_fixed = true;
        assert_eq!(from_issues(&issues, 1, 0), FIX_FAILED);
    }

    #[test]
    fn test_failed_module_is_incomplete() {
        // Nothing else is open, so the missing check is the only news.
        assert_eq!(from_issues(&[], 0, 1), INCOMPLETE);
        assert_eq!(from_issues(&[issue("a", Severity::Info)], 0, 1), INCOMPLETE);
        // Several failed modules are still one code.
        assert_eq!(from_issues(&[], 0, 3), INCOMPLETE);
    }

    #[test]
    fn test_incomplete_ranks_between_critical_and_warnings() {
        // A critical finding is definite, so it still wins over a missing check.
        let critical = [issue("a", Severity::Critical)];
        assert_eq!(from_issues(&critical, 0, 1), CRITICAL);
        // A missing check outranks a warning.
        let warning = [issue("a", Severity::Warning)];
        assert_eq!(from_issues(&warning, 0, 1), INCOMPLETE);
    }

    #[test]
    fn test_failed_fix_outranks_incomplete() {
        assert_eq!(from_issues(&[], 1, 1), FIX_FAILED);
        assert_eq!(
            from_issues(&[issue("a", Severity::Critical)], 1, 1),
            FIX_FAILED
        );
    }

    #[test]
    fn test_fixed_issues_do_not_count_against_incomplete() {
        let mut issues = vec![issue("a", Severity::Critical)];
        issues[0].is_fixed = true;
        assert_eq!(from_issues(&issues, 0, 1), INCOMPLETE);
    }
}
