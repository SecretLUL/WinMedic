//! The introduction a first start opens with: what WinMedic does, the two
//! buttons that do it, and what can be left alone.
//!
//! It is for someone who has never repaired Windows. Whoever has skips it
//! with one click, and Help brings it back.

use super::state::App;
use crate::config::ConfigStatus;

/// How many pages the introduction has.
pub const PAGES: usize = 3;

/// Whether this is the first start on this PC: no settings file and no saved
/// scan.
///
/// A start of the window writes the settings file once it has looked for
/// crashes ([`App::offer_crashes`]), and so does leaving the introduction
/// ([`App::close_welcome`]): whoever has opened WinMedic before has one, and
/// an update shows them no introduction. A file that could not be read is
/// someone's settings too.
pub(super) fn is_first_start(config: &ConfigStatus, has_scan: bool) -> bool {
    *config == ConfigStatus::Missing && !has_scan
}

impl App {
    /// Show the introduction from its first page.
    pub fn open_welcome(&mut self) {
        self.show_help = false;
        self.welcome = Some(0);
    }

    /// The next page, and out of the introduction after the last.
    pub fn welcome_next(&mut self) {
        match self.welcome {
            Some(page) if page + 1 < PAGES => self.welcome = Some(page + 1),
            Some(_) => self.close_welcome(),
            None => {}
        }
    }

    pub fn welcome_back(&mut self) {
        if let Some(page) = self.welcome {
            self.welcome = Some(page.saturating_sub(1));
        }
    }

    /// Leave the introduction, read to the end or skipped.
    ///
    /// The settings are written so that the next start is not a first one,
    /// whatever else wrote them or did not. A save that fails shows the
    /// introduction once more, which is better than an error about a file on
    /// the first page a new user sees.
    ///
    /// After a first start's introduction comes the one question WinMedic
    /// asks ([`super::usage`]), whichever way the introduction was left: a
    /// skipped tour is no answer to it.
    pub fn close_welcome(&mut self) {
        if self.welcome.take().is_none() {
            return;
        }
        if self.system_actions.persist_config {
            let _ = self.config.save();
        }
        if std::mem::take(&mut self.ask_usage_after_welcome) && self.offers_usage_data() {
            self.usage_question = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_pc_without_settings_and_without_a_scan_is_a_first_start() {
        assert!(is_first_start(&ConfigStatus::Missing, false));
        // Scanned before, by a version that wrote no settings at start.
        assert!(!is_first_start(&ConfigStatus::Missing, true));
        for has_scan in [false, true] {
            assert!(!is_first_start(&ConfigStatus::Loaded, has_scan));
            assert!(!is_first_start(
                &ConfigStatus::Corrupt {
                    error: "malformed".to_string(),
                    quarantined: None,
                },
                has_scan
            ));
            assert!(!is_first_start(
                &ConfigStatus::LeftInPlace {
                    error: "malformed".to_string(),
                },
                has_scan
            ));
        }
    }

    /// What the window opens with, by what it found on disk.
    #[test]
    fn the_window_opens_on_the_introduction_only_at_a_first_start() {
        use crate::app::ScanState;
        use crate::config::AppConfig;
        let scan = || ScanState::new(0, Vec::new(), Vec::new(), None);
        let opening = |status, saved| App::opening(AppConfig::default(), status, saved, false);

        assert_eq!(opening(ConfigStatus::Missing, None).welcome, Some(0));
        assert_eq!(opening(ConfigStatus::Missing, Some(scan())).welcome, None);
        assert_eq!(opening(ConfigStatus::Loaded, None).welcome, None);
        assert_eq!(opening(ConfigStatus::Loaded, Some(scan())).welcome, None);
    }

    /// `App::new` is what every test and every off-screen render builds, and
    /// none of them is a first start.
    #[test]
    fn an_app_built_for_a_test_opens_without_the_introduction() {
        assert_eq!(App::new().welcome, None);
    }

    #[test]
    fn the_introduction_is_read_page_by_page_and_closes_after_the_last() {
        let mut app = App::new();
        app.show_help = true;
        app.open_welcome();
        assert_eq!(app.welcome, Some(0));
        assert!(!app.show_help, "it is not drawn under the help sheet");

        app.welcome_back();
        assert_eq!(app.welcome, Some(0), "there is no page before the first");
        for page in 1..PAGES {
            app.welcome_next();
            assert_eq!(app.welcome, Some(page));
        }
        app.welcome_back();
        assert_eq!(app.welcome, Some(PAGES - 2));
        app.welcome_next();
        app.welcome_next();
        assert_eq!(app.welcome, None);

        // Closed, the keys that moved through it move nothing.
        app.welcome_next();
        app.welcome_back();
        assert_eq!(app.welcome, None);
    }

    /// The question follows a first start's introduction, read or skipped,
    /// and only that one: Help's introduction ends where it began.
    #[test]
    fn a_first_start_asks_for_usage_data_after_the_introduction() {
        use crate::app::ScanState;
        use crate::config::AppConfig;
        use crate::utils::usage_data::Receiver;
        const RECEIVER: Receiver = Receiver {
            where_it_goes: "To an example server in Germany, which does not store your IP address.",
            url: "https://usage.example.test/api/v0/events",
            app_key: "A-EU-0000000000",
        };
        let first_start = || {
            let mut app = App::opening(AppConfig::default(), ConfigStatus::Missing, None, false);
            app.usage_receiver = Some(RECEIVER);
            app
        };

        // Read to the end.
        let mut app = first_start();
        for _ in 0..PAGES {
            assert!(!app.usage_question);
            app.welcome_next();
        }
        assert_eq!(app.welcome, None);
        assert!(app.usage_question);
        assert!(!app.config.share_usage_data, "asked is not agreed");

        // Skipped on the first page.
        let mut app = first_start();
        app.close_welcome();
        assert!(app.usage_question);

        // Asked once: the introduction from Help does not ask again.
        app.answer_usage_question(false);
        app.open_welcome();
        app.close_welcome();
        assert!(!app.usage_question);

        // Not a first start: no question, also after Help's introduction.
        let scan = ScanState::new(0, Vec::new(), Vec::new(), None);
        let mut app = App::opening(
            AppConfig::default(),
            ConfigStatus::Loaded,
            Some(scan),
            false,
        );
        app.usage_receiver = Some(RECEIVER);
        app.open_welcome();
        app.close_welcome();
        assert!(!app.usage_question);

        // A build without a receiver has nothing to ask for.
        let mut app = App::opening(AppConfig::default(), ConfigStatus::Missing, None, false);
        app.usage_receiver = None;
        app.close_welcome();
        assert!(!app.usage_question);
    }

    #[test]
    fn skipping_leaves_from_any_page() {
        for page in 0..PAGES {
            let mut app = App::new();
            app.welcome = Some(page);
            app.close_welcome();
            assert_eq!(app.welcome, None);
        }
    }
}
