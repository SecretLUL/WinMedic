//! Offering WinMedic's own last crash, and sending the report (#236).
//!
//! Only the window offers; `--scan`, `--auto-fix` and the helper only leave
//! their crash logs behind. Each crash is offered once, at the next start of
//! the window, in a banner that takes no keys.

use super::BackgroundEvent;
use super::state::App;
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::crash_log;
use crate::utils::crash_report::{self, Crash, Identity, Report};
use crate::utils::event_xml::{EventRecord, read_events};
use chrono::{DateTime, Utc};
use std::time::Duration;

/// The crash the banner offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashOffer {
    pub crash: Crash,
    /// How many crashes before it came since the last offer.
    pub earlier: usize,
}

/// How far back the first start of a version with these offers looks: the
/// crashes of the version it replaced are worth offering once too.
const FIRST_LOOK_BACK_DAYS: i64 = 7;

impl App {
    /// Read the crash logs and what Windows logged of WinMedic's crashes, for
    /// [`App::offer_crashes`]. The desktop front end calls it once, as it
    /// calls the update check.
    pub fn start_crash_check(&mut self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Some(dir) = crate::safety::audit::AuditLogger::real()
            .log_dir()
            .map(ToOwned::to_owned)
        else {
            return;
        };
        let tx = self.bg_tx.clone();
        handle.spawn(async move {
            let logs = crash_log::crash_logs(&dir)
                .iter()
                .filter_map(|path| std::fs::read_to_string(path).ok())
                .collect();
            let query = crash_report::own_crashes_query();
            let query: Vec<&str> = query.iter().map(String::as_str).collect();
            let events = read_events(
                SystemCommandRunner::new()
                    .run("wevtutil.exe", &query, Duration::from_secs(20))
                    .await,
            )
            .unwrap_or_default();
            let _ = tx.send(BackgroundEvent::CrashesFound { logs, events });
        });
    }

    /// Offer the newest crash since the last look, and remember that everything
    /// up to `now` has been looked at: each crash is offered once.
    pub fn offer_crashes(&mut self, logs: &[String], events: &[EventRecord], now: DateTime<Utc>) {
        let seen_until = self
            .config
            .crashes_offered_until
            .unwrap_or(now - chrono::Duration::days(FIRST_LOOK_BACK_DAYS));
        let crashes = crash_report::crashes_since(logs, events, seen_until);
        self.config.crashes_offered_until = Some(now);
        if self.system_actions.persist_config {
            // A failed save offers the same crash again at the next start,
            // which is better than not at all.
            let _ = self.config.save();
        }
        self.crash_offer = crashes.first().map(|crash| CrashOffer {
            crash: crash.clone(),
            earlier: crashes.len() - 1,
        });
    }

    pub fn dismiss_crash_offer(&mut self) {
        self.crash_offer = None;
    }

    /// Show what the report will say, before anything is sent.
    pub fn open_crash_report(&mut self) {
        if let Some(offer) = &self.crash_offer {
            self.crash_report = Some(Report::of(
                &offer.crash,
                &Identity::of_this_pc(),
                &crash_log::windows_build(),
            ));
        }
    }

    pub fn close_crash_report(&mut self) {
        self.crash_report = None;
    }

    /// Open the filled-in form in the browser. Returns what has to go on the
    /// clipboard, because the URL could not carry it.
    pub fn send_crash_report(&mut self) -> Option<String> {
        let draft = self.crash_report.as_ref()?.draft();
        match (self.system_actions.open_issue_form)(&draft.url) {
            Ok(()) => {
                self.status_message = Some(if draft.to_paste.is_some() {
                    "The bug report form is open in your browser. The crash log is on the clipboard: paste it into \"Anything else\".".to_string()
                } else {
                    "The bug report form is open in your browser.".to_string()
                });
                self.crash_report = None;
                self.crash_offer = None;
                draft.to_paste
            }
            Err(e) => {
                self.status_message = Some(e);
                None
            }
        }
    }

    /// Save the report into the reports folder, for sending some other way.
    pub fn save_crash_report(&mut self) {
        let Some(report) = &self.crash_report else {
            return;
        };
        let dir = (self.system_actions.reports_dir)();
        let path = dir.join(format!(
            "winmedic_crash_report_{}.txt",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        ));
        let written =
            std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&path, report.preview()));
        self.status_message = Some(match written {
            Ok(()) => format!("Crash report saved: {}", path.display()),
            Err(e) => format!("The crash report could not be saved: {e}"),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::decode::decode_output;
    use crate::utils::event_xml::parse_events;
    use chrono::TimeZone;

    const OWN_CRASH: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_app_error_1000_winmedic.bin");

    fn own_crash() -> Vec<EventRecord> {
        parse_events(&decode_output(OWN_CRASH))
    }

    fn a_day_after_it() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 13, 22, 0, 0).unwrap()
    }

    #[test]
    fn the_newest_crash_is_offered_once() {
        let mut app = App::new();
        app.offer_crashes(&[], &own_crash(), a_day_after_it());
        let offer = app.crash_offer.clone().unwrap();
        assert_eq!(
            offer.crash.summary,
            "Exception c0000409 in winmedic.exe+0x1035"
        );
        assert_eq!(offer.earlier, 0);
        assert_eq!(app.config.crashes_offered_until, Some(a_day_after_it()));

        app.dismiss_crash_offer();
        app.offer_crashes(
            &[],
            &own_crash(),
            a_day_after_it() + chrono::Duration::hours(1),
        );
        assert_eq!(app.crash_offer, None);
    }

    #[test]
    fn the_first_look_goes_back_a_week_and_no_further() {
        let mut app = App::new();
        app.offer_crashes(
            &[],
            &own_crash(),
            a_day_after_it() + chrono::Duration::days(FIRST_LOOK_BACK_DAYS),
        );
        assert_eq!(app.crash_offer, None);
    }

    #[test]
    fn a_report_is_sent_only_after_it_was_shown() {
        let mut app = App::new();
        assert_eq!(app.send_crash_report(), None);

        app.offer_crashes(&[], &own_crash(), a_day_after_it());
        app.open_crash_report();
        let shown = app.crash_report.clone().unwrap();
        assert!(shown.preview().contains("winmedic.exe+0x1035"));

        // The inert action opens nothing and says yes.
        assert_eq!(app.send_crash_report(), None);
        assert_eq!(app.crash_report, None);
        assert_eq!(app.crash_offer, None);
        assert_eq!(
            app.status_message.as_deref(),
            Some("The bug report form is open in your browser.")
        );
    }

    #[test]
    fn a_refused_url_keeps_the_report_open() {
        let mut app = App::new();
        app.system_actions.open_issue_form = |_| Err("URL rejected".to_string());
        app.offer_crashes(&[], &own_crash(), a_day_after_it());
        app.open_crash_report();
        assert_eq!(app.send_crash_report(), None);
        assert!(app.crash_report.is_some());
        assert_eq!(app.status_message.as_deref(), Some("URL rejected"));
    }

    #[test]
    fn a_saved_report_is_what_the_preview_showed() {
        let dir = std::env::temp_dir().join(format!("winmedic_crash_offer_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app = App::new();
        app.offer_crashes(&[], &own_crash(), a_day_after_it());
        app.open_crash_report();
        app.system_actions.reports_dir =
            || std::env::temp_dir().join(format!("winmedic_crash_offer_{}", std::process::id()));
        app.save_crash_report();

        let saved: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(saved.len(), 1);
        assert_eq!(
            std::fs::read_to_string(saved[0].path()).unwrap(),
            app.crash_report.as_ref().unwrap().preview()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
