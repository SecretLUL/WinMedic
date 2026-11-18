//! Anonymous usage data: asking for it, showing it and handing it to the
//! sender ([`crate::utils::usage_data`]).
//!
//! It is asked for once, after a first start's introduction, and off unless
//! the answer is yes. Only the window reports: `--scan`, `--auto-fix` and the
//! background scan never do.

use super::state::App;
use crate::config::AppConfig;
use crate::engine::runner::DiagnosticEngine;
use crate::modules::ModuleStatus;
use crate::utils::crash_log;
use crate::utils::usage_data::{self, Report};
use chrono::Utc;

/// What a report calls a check it does not know.
const OTHER_CHECK: &str = "other";

/// The checks a report may name: the ids of the modules WinMedic is built
/// with, each a word from its source.
///
/// A finding carries the id of its check as text, and one restored from a
/// saved scan carries whatever that file says. So a report never repeats
/// that text: it names a check from this list, or [`OTHER_CHECK`].
fn known_checks() -> Vec<String> {
    DiagnosticEngine::new(&AppConfig::default())
        .modules()
        .iter()
        .map(|module| module.id().to_string())
        .collect()
}

fn check_name<'a>(known: &'a [String], module_id: &str) -> &'a str {
    known
        .iter()
        .find(|check| check.as_str() == module_id)
        .map_or(OTHER_CHECK, String::as_str)
}

impl App {
    /// Whether this build has somewhere to send usage data. Without it the
    /// question is not asked, Settings offers no switch and nothing is sent.
    pub fn offers_usage_data(&self) -> bool {
        self.usage_receiver.is_some()
    }

    /// Answer the question after the introduction. Only a yes switches the
    /// reports on; leaving the page any other way is a no.
    pub fn answer_usage_question(&mut self, share: bool) {
        if !std::mem::take(&mut self.usage_question) {
            return;
        }
        self.usage_preview = None;
        self.config.share_usage_data = share && self.offers_usage_data();
        let unsaved = if self.system_actions.persist_config {
            self.config.save().err()
        } else {
            None
        };
        let said = if self.config.share_usage_data {
            "Anonymous usage data is on. Settings > General switches it off."
        } else {
            "No usage data is sent. Settings > General can switch it on."
        };
        self.status_message = Some(match unsaved {
            None => said.to_string(),
            Some(e) => format!("{said} The choice could not be saved: {e}"),
        });
    }

    /// Show the report a scan sends, with the numbers of the last scan: the
    /// same text the sender is handed.
    pub fn open_usage_preview(&mut self) {
        let shown = self.scan_usage_report().shown(
            &self.usage_session,
            Utc::now(),
            &crash_log::windows_build(),
        );
        self.usage_preview = Some(shown);
    }

    pub fn close_usage_preview(&mut self) {
        self.usage_preview = None;
    }

    /// The report of the scan on screen: the check of every finding, and the
    /// checks that could not run.
    pub(super) fn scan_usage_report(&self) -> Report {
        let known = known_checks();
        let found: Vec<&str> = self
            .issues
            .iter()
            .map(|issue| check_name(&known, &issue.module_id))
            .collect();
        let failed: Vec<&str> = self
            .module_statuses
            .iter()
            .filter(|status| matches!(status.3, ModuleStatus::Failed(_)))
            .map(|status| check_name(&known, &status.0))
            .collect();
        Report::scan(
            self.config.advanced_mode,
            self.scan_duration.map_or(0, |duration| duration.as_secs()),
            self.health_score,
            &found,
            &failed,
        )
    }

    /// The report of the repair run that just ended, or none when it
    /// repaired nothing and failed at nothing: a simulation, or a run
    /// cancelled before its first repair.
    pub(super) fn repair_usage_report(&self) -> Option<Report> {
        if self.dry_run || self.repair_tally.is_empty() {
            return None;
        }
        let known = known_checks();
        let mut by_check = std::collections::BTreeMap::new();
        for (module_id, (repaired, failed)) in &self.repair_tally {
            let counts: &mut (u64, u64) = by_check
                .entry(check_name(&known, module_id).to_string())
                .or_default();
            counts.0 += repaired;
            counts.1 += failed;
        }
        Some(Report::repair(self.config.advanced_mode, &by_check))
    }

    /// Hand `report` to the sender, if the user said yes and there is a
    /// receiver. Every other path ends here without a word leaving the PC.
    pub(super) fn report_usage(&mut self, report: Report) {
        if !self.config.share_usage_data {
            return;
        }
        let Some(receiver) = self.usage_receiver else {
            return;
        };
        let now = Utc::now();
        if now - self.usage_session_since > chrono::Duration::days(1) {
            self.usage_session = usage_data::new_session(now);
            self.usage_session_since = now;
        }
        let sent = report.json(&self.usage_session, now, &crash_log::windows_build());
        self.last_usage_report = Some(sent.to_string());
        (self.system_actions.send_usage_data)(receiver, sent.to_string());
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::engine::issue::{Issue, RiskScore, Severity};
    use crate::utils::usage_data::Receiver;

    pub(crate) const RECEIVER: Receiver = Receiver {
        where_it_goes: "To an example server in Germany, which does not store your IP address.",
        url: "https://usage.example.test/api/v0/events",
        app_key: "A-EU-0000000000",
    };

    fn issue(id: &str, module: &str) -> Issue {
        Issue::new(
            id,
            module,
            "'Logitech BRIO' has no driver",
            "Devices",
            Severity::Warning,
            RiskScore::Low,
            r"C:\Users\Bob\AppData is full",
            r"Device: USB\VID_046D",
            "fix",
            vec![],
        )
    }

    fn asked() -> App {
        let mut app = App::new();
        app.usage_receiver = Some(RECEIVER);
        app.usage_question = true;
        app
    }

    #[test]
    fn only_a_yes_switches_the_reports_on() {
        let mut app = asked();
        app.answer_usage_question(false);
        assert!(!app.usage_question);
        assert!(!app.config.share_usage_data);

        let mut app = asked();
        app.answer_usage_question(true);
        assert!(!app.usage_question);
        assert!(app.config.share_usage_data);
        assert!(
            app.status_message
                .as_deref()
                .is_some_and(|said| said.contains("Settings > General"))
        );

        // No question on screen: nothing to answer.
        let mut app = App::new();
        app.usage_receiver = Some(RECEIVER);
        app.answer_usage_question(true);
        assert!(!app.config.share_usage_data);
    }

    /// A build without a receiver cannot be talked into sending.
    #[test]
    fn without_a_receiver_nothing_is_on_and_nothing_is_sent() {
        let mut app = App::new();
        app.usage_receiver = None;
        assert!(!app.offers_usage_data());
        app.usage_question = true;
        app.answer_usage_question(true);
        assert!(!app.config.share_usage_data);

        // Switched on by hand in config.json.
        app.config.share_usage_data = true;
        let report = app.scan_usage_report();
        app.report_usage(report);
        assert_eq!(app.last_usage_report, None);
    }

    #[test]
    fn nothing_is_reported_until_the_user_said_yes() {
        let mut app = App::new();
        app.usage_receiver = Some(RECEIVER);
        let report = app.scan_usage_report();
        app.report_usage(report);
        assert_eq!(app.last_usage_report, None);

        app.config.share_usage_data = true;
        let report = app.scan_usage_report();
        app.report_usage(report);
        assert!(app.last_usage_report.is_some());
    }

    /// The names a finding carries, in its id, its title and its details,
    /// stay on the PC: a report has the check's own word and a count.
    #[test]
    fn a_report_names_checks_and_counts_and_nothing_of_the_pc() {
        let mut app = App::new();
        app.usage_receiver = Some(RECEIVER);
        app.config.share_usage_data = true;
        app.issues = vec![
            issue(r"dev_problem_USB\VID_046D", "devices"),
            issue("dev_problem_other", "devices"),
            issue("dns", "network"),
        ];
        app.health_score = 70;
        app.scan_duration = Some(std::time::Duration::from_secs(74));
        if let Some(status) = app.module_statuses.first_mut() {
            status.3 = ModuleStatus::Failed(r"C:\Users\Bob could not be read".to_string());
        }
        let failed_check = app.module_statuses[0].0.clone();

        let report = app.scan_usage_report();
        app.report_usage(report);
        let sent = app.last_usage_report.clone().unwrap();
        let json: serde_json::Value = serde_json::from_str(&sent).unwrap();
        let props = &json[0]["props"];
        assert_eq!(props["findings"], 3);
        assert_eq!(props["found_devices"], 2);
        assert_eq!(props["found_network"], 1);
        assert_eq!(props["health"], 70);
        assert_eq!(props["seconds"], 74);
        assert_eq!(props[format!("check_failed_{failed_check}")], 1);
        for private in ["Logitech", "VID_046D", "Bob", "Users", "AppData"] {
            assert!(!sent.contains(private), "{private} is in {sent}");
        }
        for name in [std::env::var("USERNAME"), std::env::var("COMPUTERNAME")]
            .into_iter()
            .flatten()
            .filter(|name| name.len() > 3)
        {
            assert!(!sent.contains(&name), "{name} is in {sent}");
        }
    }

    /// A saved scan is a file anyone can edit, and a finding in it names its
    /// check as free text. A report repeats none of it.
    #[test]
    fn a_check_the_build_does_not_know_is_reported_as_other() {
        let mut app = App::new();
        app.usage_receiver = Some(RECEIVER);
        app.config.share_usage_data = true;
        app.issues = vec![
            issue("a", r"C:\Users\Bob"),
            issue("b", "DESKTOP-BOB"),
            issue("c", "network"),
        ];
        app.repair_tally.insert("DESKTOP-BOB".to_string(), (1, 0));
        app.repair_tally.insert(r"C:\Users\Bob".to_string(), (0, 2));

        for report in [app.scan_usage_report(), app.repair_usage_report().unwrap()] {
            app.report_usage(report);
            let sent = app.last_usage_report.take().unwrap();
            assert!(!sent.contains("Bob") && !sent.contains("BOB"), "{sent}");
            assert!(sent.contains("_other\""), "{sent}");
        }
        assert!(
            known_checks()
                .iter()
                .all(|check| check.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
            "{:?}",
            known_checks()
        );
    }

    /// The receiver drops a report whose number is older than a week.
    #[test]
    fn a_window_open_for_days_gets_a_new_number() {
        let mut app = App::new();
        app.usage_receiver = Some(RECEIVER);
        app.config.share_usage_data = true;
        let first = app.usage_session.clone();

        let report = app.scan_usage_report();
        app.report_usage(report);
        assert!(app.last_usage_report.as_ref().unwrap().contains(&first));

        app.usage_session_since = Utc::now() - chrono::Duration::days(2);
        let report = app.scan_usage_report();
        app.report_usage(report);
        assert_ne!(app.usage_session, first);
        assert!(!app.last_usage_report.as_ref().unwrap().contains(&first));
    }

    /// The preview is the report itself, for the scan on screen.
    #[test]
    fn show_what_is_sent_shows_the_report_of_the_last_scan() {
        let mut app = App::new();
        app.usage_receiver = Some(RECEIVER);
        app.issues = vec![issue("dns", "network")];
        app.open_usage_preview();
        let shown = app.usage_preview.clone().unwrap();
        let json: serde_json::Value = serde_json::from_str(&shown).unwrap();
        assert_eq!(json[0]["eventName"], "scan");
        assert_eq!(json[0]["props"]["found_network"], 1);
        assert_eq!(json[0]["sessionId"], app.usage_session.as_str());

        app.close_usage_preview();
        assert_eq!(app.usage_preview, None);
    }

    #[test]
    fn a_simulation_and_an_empty_run_report_no_repair() {
        let mut app = App::new();
        assert!(app.repair_usage_report().is_none());

        app.repair_tally.insert("network".to_string(), (1, 0));
        app.dry_run = true;
        assert!(app.repair_usage_report().is_none());
        app.dry_run = false;
        assert!(app.repair_usage_report().is_some());
    }
}
