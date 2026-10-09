//! Archived findings: the ones the user chose to stop seeing.
//!
//! They are sorted out as findings come in (a scan, the last scan on disk,
//! the background scan's results) into [`App::archived_issues`], so nothing
//! that reads [`App::issues`] has to know about them: the list and its counts,
//! Easy mode, the restart banner, a repair run and the health score leave them
//! out by themselves. Settings lists them and brings them back.

use super::state::App;
use crate::config::ArchivedFinding;
use crate::engine::issue::Issue;
use crate::engine::runner::DiagnosticEngine;
use crate::modules::ModuleStatus;

/// Sort `issues` into the ones shown and the ones archived, each in the order
/// they came.
pub fn split(
    issues: impl IntoIterator<Item = Issue>,
    archived: &[ArchivedFinding],
) -> (Vec<Issue>, Vec<Issue>) {
    issues
        .into_iter()
        .partition(|issue| !archived.iter().any(|entry| entry.id == issue.id))
}

impl App {
    /// Archive the finding at `index` in [`App::issues`]. Not while a scan or
    /// a repair runs, and not a fixed one, which is history already.
    pub fn archive_issue(&mut self, index: usize) {
        if self.is_busy() {
            return;
        }
        let Some(issue) = self.issues.get(index).filter(|issue| !issue.is_fixed) else {
            return;
        };
        let title = issue.title.clone();
        if !self
            .config
            .archived_findings
            .iter()
            .any(|entry| entry.id == issue.id)
        {
            self.config.archived_findings.push(ArchivedFinding {
                id: issue.id.clone(),
                title: title.clone(),
                archived_at: chrono::Local::now().format("%Y-%m-%d").to_string(),
            });
        }
        let (shown, archived) = split(
            std::mem::take(&mut self.issues),
            &self.config.archived_findings,
        );
        self.issues = shown;
        self.archived_issues.extend(archived);
        let unsaved = self.archive_changed();
        self.status_message = Some(format!(
            "Archived: {title}. Settings brings it back.{unsaved}"
        ));
    }

    /// Take the finding `id` out of the archive. One the last scan reported
    /// is shown again at once; any other returns with the next scan.
    pub fn show_archived_again(&mut self, id: &str) {
        if self.is_busy() {
            return;
        }
        self.config.archived_findings.retain(|entry| entry.id != id);
        let (back, still): (Vec<Issue>, Vec<Issue>) = std::mem::take(&mut self.archived_issues)
            .into_iter()
            .partition(|issue| issue.id == id);
        self.archived_issues = still;
        let message = match back.first() {
            Some(issue) => format!("Shown again: {}.", issue.title),
            None => "It returns with the next scan.".to_string(),
        };
        self.issues.extend(back);
        let unsaved = self.archive_changed();
        self.status_message = Some(format!("{message}{unsaved}"));
    }

    /// The health score and the module badges follow the findings shown, and
    /// the scan and the archive are saved. Returns a sentence to append when
    /// the archive could not be saved.
    fn archive_changed(&mut self) -> String {
        self.health_score = DiagnosticEngine::calculate_health_score(&self.issues);
        self.recount_module_statuses();
        self.clamp_filtered_selection();
        self.save_scan_state();
        if self.system_actions.persist_config
            && let Err(e) = self.config.save()
        {
            return format!(" The archive could not be saved: {e}");
        }
        String::new()
    }

    /// The badge of each module that finished, from the findings shown.
    pub(super) fn recount_module_statuses(&mut self) {
        for (id, _, _, status) in &mut self.module_statuses {
            if matches!(
                status,
                ModuleStatus::Passed | ModuleStatus::Warning(_) | ModuleStatus::Critical(_)
            ) {
                *status = ModuleStatus::from_findings(
                    self.issues.iter().filter(|issue| &issue.module_id == id),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::ScanState;
    use crate::config::{AppConfig, ConfigStatus};
    use crate::engine::issue::{RiskScore, Severity};
    use crate::engine::runner::ScanEvent;

    fn finding(id: &str, severity: Severity) -> Issue {
        Issue::new(
            id,
            "network",
            format!("Title {id}"),
            "Network",
            severity,
            RiskScore::Low,
            "",
            "",
            "",
            vec![],
        )
    }

    fn entry(id: &str) -> ArchivedFinding {
        ArchivedFinding {
            id: id.to_string(),
            title: format!("Title {id}"),
            archived_at: "2026-10-09".to_string(),
        }
    }

    fn ids(issues: &[Issue]) -> Vec<&str> {
        issues.iter().map(|issue| issue.id.as_str()).collect()
    }

    fn health(issues: &[Issue]) -> u8 {
        DiagnosticEngine::calculate_health_score(issues)
    }

    #[test]
    fn split_sorts_out_the_archived_ids_and_keeps_the_order() {
        let issues = ["a", "b", "c", "d"].map(|id| finding(id, Severity::Warning));
        let (shown, archived) = split(issues, &[entry("d"), entry("b"), entry("gone")]);
        assert_eq!(ids(&shown), ["a", "c"]);
        assert_eq!(ids(&archived), ["b", "d"]);
    }

    /// A scan on screen: a critical finding and a warning.
    fn scanned() -> App {
        let mut app = App::new();
        app.issues = vec![
            finding("crit", Severity::Critical),
            finding("warn", Severity::Warning),
        ];
        app.health_score = health(&app.issues);
        app.last_scan_timestamp = Some("2026-10-09 18:30:00".to_string());
        app
    }

    #[test]
    fn an_archived_finding_leaves_the_list_and_the_health_score() {
        let mut app = scanned();
        let before = app.health_score;

        app.archive_issue(0);

        assert_eq!(ids(&app.issues), ["warn"]);
        assert_eq!(ids(&app.archived_issues), ["crit"]);
        let [archived] = app.config.archived_findings.as_slice() else {
            panic!("{:?}", app.config.archived_findings);
        };
        assert_eq!(
            (archived.id.as_str(), archived.title.as_str()),
            ("crit", "Title crit")
        );
        assert!(chrono::NaiveDate::parse_from_str(&archived.archived_at, "%Y-%m-%d").is_ok());
        assert!(app.health_score > before);
        assert_eq!(app.health_score, health(&app.issues));
    }

    #[test]
    fn showing_it_again_brings_it_back_at_once() {
        let mut app = scanned();
        let before = app.health_score;
        app.archive_issue(0);

        app.show_archived_again("crit");

        assert!(app.config.archived_findings.is_empty());
        assert!(app.archived_issues.is_empty());
        assert_eq!(ids(&app.issues), ["warn", "crit"]);
        assert_eq!(app.health_score, before);
        assert_eq!(
            app.status_message.as_deref(),
            Some("Shown again: Title crit.")
        );
    }

    #[test]
    fn one_the_last_scan_did_not_report_returns_with_the_next_scan() {
        let mut app = scanned();
        app.config.archived_findings.push(entry("elsewhere"));

        app.show_archived_again("elsewhere");

        assert!(app.config.archived_findings.is_empty());
        assert_eq!(ids(&app.issues), ["crit", "warn"]);
        assert_eq!(
            app.status_message.as_deref(),
            Some("It returns with the next scan.")
        );
    }

    #[test]
    fn a_fixed_finding_and_any_during_a_run_stay_where_they_are() {
        let mut app = scanned();
        app.issues[0].is_fixed = true;
        app.archive_issue(0);

        app.is_fixing = true;
        app.archive_issue(1);

        assert!(app.config.archived_findings.is_empty());
        assert_eq!(ids(&app.issues), ["crit", "warn"]);
    }

    /// A repair run never sees an archived finding.
    #[test]
    fn a_repair_run_leaves_archived_findings_alone() {
        let mut app = scanned();
        app.archive_issue(0);
        app.archive_issue(0);

        app.start_repairs();

        assert!(!app.is_fixing);
        assert_eq!(
            app.status_message.as_deref(),
            Some("No open issues selected for repair.")
        );
    }

    /// Sorted out as the scan reports them: the list, the module's badge and
    /// the health score never see them, whatever the engine counted.
    #[test]
    fn a_scan_sorts_out_archived_findings_as_they_come_in() {
        let mut app = App::new();
        app.config.archived_findings.push(entry("crit"));
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        app.scan_event_rx = Some(rx);
        app.is_scanning = true;
        tx.try_send(ScanEvent::ModuleFinished {
            module_id: "network".to_string(),
            issues: vec![
                finding("crit", Severity::Critical),
                finding("warn", Severity::Warning),
            ],
        })
        .unwrap();
        tx.try_send(ScanEvent::ScanCompleted {
            total_issues: 2,
            health_score: 0,
        })
        .unwrap();

        app.process_background_events();

        assert_eq!(ids(&app.issues), ["warn"]);
        assert_eq!(ids(&app.archived_issues), ["crit"]);
        let network = app.module_statuses.iter().find(|m| m.0 == "network");
        assert_eq!(network.map(|m| &m.3), Some(&ModuleStatus::Warning(1)));
        assert_eq!(app.health_score, health(&app.issues));
        assert_eq!(
            app.status_message,
            Some(format!(
                "Scan finished: 1 issues found (health: {}/100)",
                app.health_score
            ))
        );
    }

    /// A new scan starts from nothing, archived findings included.
    #[tokio::test]
    async fn a_new_scan_clears_both_lists() {
        let mut app = scanned();
        app.archive_issue(0);
        // No modules: the scan must not check this machine.
        app.engine = std::sync::Arc::new(DiagnosticEngine::with_modules(Vec::new()));

        app.start_scan();

        assert!(app.issues.is_empty() && app.archived_issues.is_empty());
    }

    /// The last scan on disk is sorted by what is archived now, not by what
    /// was archived when it was saved.
    #[test]
    fn the_saved_scan_is_sorted_by_what_is_archived_now() {
        let saved = ScanState::new(
            0,
            vec![
                finding("crit", Severity::Critical),
                finding("warn", Severity::Warning),
            ],
            Vec::new(),
            None,
        )
        .with_archived(vec![finding("old", Severity::Warning)]);
        let mut config = AppConfig::default();
        config.archived_findings.push(entry("crit"));

        let app = App::build(config, ConfigStatus::Loaded, Some(saved), false);

        assert_eq!(ids(&app.issues), ["warn", "old"]);
        assert_eq!(ids(&app.archived_issues), ["crit"]);
        assert_eq!(app.health_score, health(&app.issues));
    }

    #[test]
    fn a_background_scan_is_sorted_the_same_way() {
        let mut app = App::new();
        app.config.archived_findings.push(entry("crit"));
        let saved = ScanState::new(
            0,
            vec![
                finding("crit", Severity::Critical),
                finding("warn", Severity::Warning),
            ],
            Vec::new(),
            None,
        );

        app.take_in_background_scan(saved);

        assert_eq!(ids(&app.issues), ["warn"]);
        assert_eq!(ids(&app.archived_issues), ["crit"]);
        assert_eq!(app.health_score, health(&app.issues));
    }

    /// The window saves both lists and a score without the archived
    /// findings, so after a restart one brought back is shown at once.
    #[test]
    fn the_saved_scan_keeps_the_archived_findings_out_of_the_score() {
        let mut app = scanned();
        app.archive_issue(0);

        let state = app.scan_to_save().expect("a scan is on screen");
        assert_eq!(ids(&state.issues), ["warn"]);
        assert_eq!(ids(&state.archived_issues), ["crit"]);
        assert_eq!(
            state.health_score,
            health(&[finding("warn", Severity::Warning)])
        );

        let path =
            std::env::temp_dir().join(format!("winmedic_archive_scan_{}.json", std::process::id()));
        state.save_to(&path).unwrap();
        let loaded = ScanState::load_from(&path);
        let _ = std::fs::remove_file(&path);
        let mut reopened = App::build(app.config.clone(), ConfigStatus::Loaded, loaded, false);
        assert_eq!(ids(&reopened.issues), ["warn"]);
        assert_eq!(ids(&reopened.archived_issues), ["crit"]);

        reopened.show_archived_again("crit");
        assert_eq!(ids(&reopened.issues), ["warn", "crit"]);
    }
}
