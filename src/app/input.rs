//! Key dispatch.
//!
//! This lived in `main.rs` before, which put the single largest piece of
//! interaction logic in the binary target — where no integration test can reach
//! it, because the test suite links against the library. It is the same code,
//! moved somewhere it can be exercised.
//!
//! Dispatch is layered, and the order matters: a pending confirmation swallows
//! everything, then the help overlay, then search input capture, and only then
//! the normal bindings.

use super::state::App;
use super::{
    TAB_COUNT, TAB_DASHBOARD, TAB_HISTORY, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS, TAB_TRIAGE,
};
use crate::engine::issue::Severity;
use crossterm::event::KeyCode;

pub fn handle_key(app: &mut App, code: KeyCode) {
    // A pending confirmation swallows every other key.
    if app.pending_confirm.is_some() {
        match code {
            KeyCode::Char('j')
            | KeyCode::Char('J')
            | KeyCode::Char('y')
            | KeyCode::Char('Y')
            | KeyCode::Enter => app.confirm_pending_action(),
            _ => app.dismiss_confirm(),
        }
        return;
    }

    if app.show_help {
        match code {
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                app.show_help = false;
            }
            _ => {}
        }
        return;
    }

    if app.active_tab == TAB_TRIAGE && app.is_searching {
        match code {
            KeyCode::Esc | KeyCode::Enter => {
                app.is_searching = false;
            }
            KeyCode::Backspace => {
                app.search_query.pop();
                app.clamp_filtered_selection();
            }
            KeyCode::Char(c) => {
                app.search_query.push(c);
                app.clamp_filtered_selection();
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,
        KeyCode::Char('?') => app.show_help = true,

        KeyCode::Char('1') => app.active_tab = 0,
        KeyCode::Char('2') => app.active_tab = 1,
        KeyCode::Char('3') => app.active_tab = 2,
        KeyCode::Char('4') => app.active_tab = 3,
        KeyCode::Char('5') => {
            app.active_tab = TAB_HISTORY;
            app.load_history_data();
        }
        KeyCode::Char('6') => app.active_tab = TAB_SETTINGS,

        KeyCode::Tab => {
            app.active_tab = (app.active_tab + 1) % TAB_COUNT;
            if app.active_tab == TAB_HISTORY {
                app.load_history_data();
            }
        }
        KeyCode::BackTab => {
            app.active_tab = if app.active_tab == 0 {
                TAB_COUNT - 1
            } else {
                app.active_tab - 1
            };
            if app.active_tab == TAB_HISTORY {
                app.load_history_data();
            }
        }

        KeyCode::Char('s') | KeyCode::Char('S') => app.start_scan(),
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if app.active_tab == TAB_HISTORY {
                app.load_history_data();
                app.refresh_restore_points();
            } else {
                app.start_scan();
            }
        }

        KeyCode::Char('d') | KeyCode::Char('D') => app.toggle_dry_run(),

        KeyCode::Char('f') | KeyCode::Char('F') => {
            if app.active_tab == TAB_TRIAGE || app.active_tab == TAB_REPAIR {
                app.start_repairs();
            } else {
                app.active_tab = TAB_TRIAGE;
            }
        }

        KeyCode::Char('a') | KeyCode::Char('A') => {
            if app.active_tab == TAB_DASHBOARD {
                app.start_scan();
            } else {
                app.select_all_issues();
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') => app.deselect_all_issues(),

        KeyCode::Char('u') | KeyCode::Char('U') => {
            if app.active_tab == TAB_HISTORY {
                app.request_rollback();
            } else {
                // Opens the parked "update available" notice, if there is one.
                app.show_update_notice();
            }
        }

        KeyCode::Char('e') | KeyCode::Char('E') => match app.export_report() {
            Ok(path) => {
                app.status_message = Some(format!("📄 Report exported: {}", path.display()));
            }
            Err(err) => {
                app.status_message = Some(err);
            }
        },

        KeyCode::Char(' ') | KeyCode::Enter => match app.active_tab {
            TAB_TRIAGE => app.toggle_selected_issue(),
            TAB_SETTINGS => app.toggle_current_setting(),
            _ => {}
        },

        KeyCode::Up | KeyCode::Char('k') => match app.active_tab {
            TAB_TRIAGE => app.prev_issue(),
            TAB_HISTORY => app.prev_backup(),
            TAB_SETTINGS => app.prev_setting(),
            TAB_SCANNER | TAB_REPAIR => app.scroll_log_up(1),
            _ => {}
        },
        KeyCode::Down | KeyCode::Char('j') => match app.active_tab {
            TAB_TRIAGE => app.next_issue(),
            TAB_HISTORY => app.next_backup(),
            TAB_SETTINGS => app.next_setting(),
            TAB_SCANNER | TAB_REPAIR => app.scroll_log_down(1),
            _ => {}
        },
        KeyCode::PageUp => match app.active_tab {
            TAB_SCANNER | TAB_REPAIR => app.scroll_log_up(10),
            _ => {}
        },
        KeyCode::PageDown => match app.active_tab {
            TAB_SCANNER | TAB_REPAIR => app.scroll_log_down(10),
            _ => {}
        },
        KeyCode::Home => match app.active_tab {
            TAB_SCANNER | TAB_REPAIR => app.scroll_log_top(),
            _ => {}
        },
        KeyCode::End => match app.active_tab {
            TAB_SCANNER | TAB_REPAIR => app.scroll_log_bottom(),
            _ => {}
        },

        KeyCode::Char('/') if app.active_tab == TAB_TRIAGE => app.is_searching = true,
        KeyCode::Char('c') | KeyCode::Char('C') if app.active_tab == TAB_TRIAGE => {
            app.toggle_severity_filter(Severity::Critical);
        }
        KeyCode::Char('w') | KeyCode::Char('W') if app.active_tab == TAB_TRIAGE => {
            app.toggle_severity_filter(Severity::Warning);
        }
        KeyCode::Char('i') | KeyCode::Char('I') if app.active_tab == TAB_TRIAGE => {
            app.toggle_severity_filter(Severity::Info);
        }
        KeyCode::Char('m') | KeyCode::Char('M') if app.active_tab == TAB_TRIAGE => {
            app.cycle_module_filter();
        }
        KeyCode::Char('x') | KeyCode::Char('X') if app.active_tab == TAB_TRIAGE => {
            app.clear_filters();
        }

        KeyCode::Left | KeyCode::Char('h') => {
            if app.active_tab == TAB_SETTINGS {
                app.adjust_current_setting(false);
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if app.active_tab == TAB_SETTINGS {
                app.adjust_current_setting(true);
            }
        }

        // Esc clears active filters first, cancels a running operation second, and navigates back to dashboard third.
        KeyCode::Esc => {
            if app.active_tab == TAB_TRIAGE && app.has_active_filters() {
                app.clear_filters();
            } else if !app.cancel_current_operation() && app.active_tab != TAB_DASHBOARD {
                app.active_tab = TAB_DASHBOARD;
            }
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::ConfirmRequest;
    use crate::engine::issue::{Issue, RiskScore};

    /// An `App` with no modal in the way.
    ///
    /// `App::new` raises the elevation prompt when WinMedic is not running as
    /// Administrator, and that modal swallows every key — so a dispatch test
    /// that skipped this would be testing the modal, not the binding.
    fn app() -> App {
        let mut app = App::new();
        app.pending_confirm = None;
        app
    }

    fn app_with_issues() -> App {
        let mut app = app();
        app.issues = vec![
            Issue::new(
                "a",
                "network",
                "DNS cache full",
                "Network",
                Severity::Critical,
                RiskScore::Low,
                "description",
                "details",
                "fix",
                vec![],
            ),
            Issue::new(
                "b",
                "storage",
                "Temp bloat",
                "Storage",
                Severity::Warning,
                RiskScore::Low,
                "description",
                "details",
                "fix",
                vec![],
            ),
        ];
        app
    }

    #[test]
    fn a_pending_confirmation_swallows_every_other_key() {
        let mut app = app();
        app.pending_confirm = Some(ConfirmRequest::Elevate);

        // 'q' would normally quit.
        handle_key(&mut app, KeyCode::Char('q'));
        assert!(!app.should_quit, "the modal must absorb the keystroke");
        assert!(app.pending_confirm.is_none(), "and dismiss itself");
    }

    #[test]
    fn help_overlay_only_responds_to_its_own_keys() {
        let mut app = app();
        app.show_help = true;
        app.active_tab = TAB_DASHBOARD;

        handle_key(&mut app, KeyCode::Char('3'));
        assert!(app.show_help, "still open");
        assert_eq!(app.active_tab, TAB_DASHBOARD, "tab switch was swallowed");

        handle_key(&mut app, KeyCode::Esc);
        assert!(!app.show_help);
    }

    #[test]
    fn search_mode_captures_letters_instead_of_triggering_bindings() {
        let mut app = app_with_issues();
        app.active_tab = TAB_TRIAGE;
        app.is_searching = true;

        // 'q' and 's' are quit and scan outside search mode.
        for c in "qs".chars() {
            handle_key(&mut app, KeyCode::Char(c));
        }

        assert_eq!(app.search_query, "qs");
        assert!(!app.should_quit);
        assert!(!app.is_scanning);

        handle_key(&mut app, KeyCode::Backspace);
        assert_eq!(app.search_query, "q");

        handle_key(&mut app, KeyCode::Enter);
        assert!(!app.is_searching, "Enter leaves search mode");
        assert_eq!(app.search_query, "q", "and keeps the query");
    }

    #[test]
    fn tab_navigation_wraps_in_both_directions() {
        let mut app = app();
        app.active_tab = TAB_COUNT - 1;

        handle_key(&mut app, KeyCode::Tab);
        assert_eq!(app.active_tab, 0);

        handle_key(&mut app, KeyCode::BackTab);
        assert_eq!(app.active_tab, TAB_COUNT - 1);
    }

    #[test]
    fn severity_filter_keys_only_apply_on_the_triage_tab() {
        let mut app = app_with_issues();

        app.active_tab = TAB_DASHBOARD;
        handle_key(&mut app, KeyCode::Char('c'));
        assert_eq!(app.severity_filter, None, "no filtering outside triage");

        app.active_tab = TAB_TRIAGE;
        handle_key(&mut app, KeyCode::Char('c'));
        assert_eq!(app.severity_filter, Some(Severity::Critical));

        // Pressing it again clears it.
        handle_key(&mut app, KeyCode::Char('c'));
        assert_eq!(app.severity_filter, None);
    }

    #[test]
    fn escape_clears_filters_before_it_navigates_away() {
        let mut app = app_with_issues();
        app.active_tab = TAB_TRIAGE;
        app.toggle_severity_filter(Severity::Critical);

        handle_key(&mut app, KeyCode::Esc);
        assert!(!app.has_active_filters(), "first Esc clears the filter");
        assert_eq!(app.active_tab, TAB_TRIAGE, "and stays put");

        handle_key(&mut app, KeyCode::Esc);
        assert_eq!(app.active_tab, TAB_DASHBOARD, "second Esc navigates back");
    }

    #[test]
    fn u_means_rollback_on_history_and_update_notice_everywhere_else() {
        let mut app = app();
        app.active_tab = TAB_DASHBOARD;
        app.available_update = None;

        // Nothing parked, so this is a no-op rather than a modal.
        handle_key(&mut app, KeyCode::Char('u'));
        assert!(app.pending_confirm.is_none());

        app.active_tab = TAB_HISTORY;
        app.backup_records.clear();
        handle_key(&mut app, KeyCode::Char('u'));
        // No backups to roll back, so it explains itself instead.
        assert!(app.pending_confirm.is_none());
        assert!(app.status_message.is_some());
    }

    #[test]
    fn space_toggles_the_selected_issue_on_triage() {
        let mut app = app_with_issues();
        app.active_tab = TAB_TRIAGE;
        app.selected_filtered_index = 0;
        assert!(app.issues[0].is_selected, "issues start selected");

        handle_key(&mut app, KeyCode::Char(' '));
        assert!(!app.issues[0].is_selected);

        handle_key(&mut app, KeyCode::Char(' '));
        assert!(app.issues[0].is_selected);
    }

    #[test]
    fn arrow_keys_scroll_logs_on_the_scanner_tab() {
        let mut app = app();
        app.active_tab = TAB_SCANNER;
        app.scan_log_messages.clear();
        for i in 0..50 {
            app.push_scan_log(format!("line {i}"));
        }

        handle_key(&mut app, KeyCode::PageUp);
        assert_eq!(app.scan_log_scroll, 10);

        handle_key(&mut app, KeyCode::Up);
        assert_eq!(app.scan_log_scroll, 11);

        handle_key(&mut app, KeyCode::End);
        assert_eq!(app.scan_log_scroll, 0, "End returns to live");
    }

    #[test]
    fn dry_run_toggles_and_reports_itself() {
        let mut app = app();
        assert!(!app.dry_run);

        handle_key(&mut app, KeyCode::Char('d'));
        assert!(app.dry_run);
        assert!(app.status_message.is_some());

        handle_key(&mut app, KeyCode::Char('D'));
        assert!(!app.dry_run);
    }

    #[test]
    fn quit_is_bound_in_both_cases() {
        for c in ['q', 'Q'] {
            let mut app = app();
            handle_key(&mut app, KeyCode::Char(c));
            assert!(app.should_quit, "'{c}' should quit");
        }
    }

    #[test]
    fn unbound_keys_are_ignored() {
        let mut app = app();
        let before = app.active_tab;

        for code in [
            KeyCode::F(5),
            KeyCode::Insert,
            KeyCode::Delete,
            KeyCode::Char('§'),
        ] {
            handle_key(&mut app, code);
        }

        assert_eq!(app.active_tab, before);
        assert!(!app.should_quit);
        assert!(!app.show_help);
    }
}
