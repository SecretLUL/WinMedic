//! Key dispatch.
//!
//! This lived in `main.rs` before, which put the single largest piece of
//! interaction logic in the binary target — where no integration test can reach
//! it, because the test suite links against the library. It is the same code,
//! moved somewhere it can be exercised.
//!
//! Dispatch is layered, and the order matters: a pending confirmation swallows
//! everything, then the help overlay, and only then the normal bindings.
//!
//! Text entry is deliberately absent from that list. It used to be a layer of
//! its own, because a terminal has no text fields and the search box and the
//! numeric setting editor had to be assembled a keystroke at a time. The window
//! has real fields bound to the same state, and while one of them holds focus
//! the front end sends nothing here at all.

use super::state::App;
use super::{TAB_DASHBOARD, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS, TAB_TRIAGE};
use crate::engine::issue::Severity;

/// A keystroke, expressed independently of any UI toolkit.
///
/// Dispatch used to take `crossterm::event::KeyCode` directly, which made this
/// module — the single largest piece of interaction logic in the crate — a
/// dependent of whichever library happened to be drawing the screen. It is the
/// only thing in `app` that ever was. Naming the keys ourselves keeps the
/// dispatch table and its tests intact across a change of front end; the front
/// end's job is to translate its own key events into these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Esc,
    Backspace,
    Tab,
    /// Shift+Tab.
    BackTab,
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    /// Everything the front end recognises but this table does not bind.
    ///
    /// Mapping the unbound keys onto one variant rather than dropping them at
    /// the front end keeps "this key does nothing" a statement the dispatch
    /// table makes, and therefore one a test can check.
    Unbound,
}

/// How far Page Up and Page Down move the triage selection.
///
/// The terminal build derived this from the height of the visible list. A
/// window resizes freely, so a fixed step is both simpler and steadier: the
/// same keypress moves the same distance whatever the user has done to the
/// window.
const PAGE_STEP: usize = 10;

pub fn handle_key(app: &mut App, code: Key) {
    // A pending confirmation swallows every other key.
    if app.pending_confirm.is_some() {
        match code {
            Key::Char('y') | Key::Char('Y') | Key::Char('j') | Key::Char('J') | Key::Enter => {
                app.confirm_pending_action()
            }
            Key::Char('n') | Key::Char('N') | Key::Esc => app.dismiss_confirm(),
            _ => {}
        }
        return;
    }

    // A pending setting numeric input modal captures typing until saved or cancelled.
    if let Some(input) = app.setting_input.as_mut() {
        match code {
            Key::Char(c) if c.is_ascii_digit() => {
                if input.buffer.len() < 10 {
                    input.buffer.push(c);
                    input.error_msg = None;
                }
            }
            Key::Backspace => {
                input.buffer.pop();
                input.error_msg = None;
            }
            Key::Enter => {
                app.submit_setting_input();
            }
            Key::Esc => {
                app.cancel_setting_input();
            }
            _ => {}
        }
        return;
    }

    if app.show_help {
        match code {
            Key::Char('?') | Key::Esc | Key::Char('q') | Key::Char('Q') => {
                app.show_help = false;
            }
            _ => {}
        }
        return;
    }

    match code {
        Key::Char('q') | Key::Char('Q') => app.should_quit = true,
        Key::Char('?') => app.show_help = true,

        Key::Char('1') => app.goto_tab(TAB_DASHBOARD),
        Key::Char('2') => app.goto_tab(TAB_SCANNER),
        Key::Char('3') => app.goto_tab(TAB_TRIAGE),
        Key::Char('4') => app.goto_tab(TAB_REPAIR),
        Key::Char('5') => app.goto_tab(TAB_SETTINGS),

        Key::Tab => app.next_tab(),
        Key::BackTab => app.prev_tab(),

        Key::Char('s') | Key::Char('S') => app.start_scan(),
        Key::Char('r') | Key::Char('R') => {
            if app.active_tab == TAB_SETTINGS {
                app.load_safety_data();
                app.refresh_restore_points();
            } else {
                app.start_scan();
            }
        }

        // Hands the arrow keys to the backup list and back, so one tab can carry
        // both the settings list and the rollback target selection.
        Key::Char('b') | Key::Char('B') if app.active_tab == TAB_SETTINGS => {
            app.toggle_safety_focus();
        }

        Key::Char('d') | Key::Char('D') => app.toggle_dry_run(),

        Key::Char('f') | Key::Char('F') => {
            if app.active_tab == TAB_TRIAGE || app.active_tab == TAB_REPAIR {
                app.start_repairs();
            } else {
                app.active_tab = TAB_TRIAGE;
            }
        }

        Key::Char('a') | Key::Char('A') => {
            if app.active_tab == TAB_DASHBOARD {
                app.start_scan();
            } else if app.active_tab == TAB_TRIAGE {
                app.toggle_select_all_issues();
            } else {
                app.select_all_issues();
            }
        }
        Key::Char('n') | Key::Char('N') => app.deselect_all_issues(),

        Key::Char('u') | Key::Char('U') => {
            if app.active_tab == TAB_SETTINGS {
                app.request_rollback();
            } else {
                // Opens the parked "update available" notice, if there is one.
                app.show_update_notice();
            }
        }

        Key::Char('e') | Key::Char('E') => match app.export_report() {
            Ok(path) => {
                app.status_message = Some(format!("Report exported: {}", path.display()));
            }
            Err(err) => {
                app.status_message = Some(err);
            }
        },

        // Enter and Space edit settings, so they stay inert while the backup
        // list holds focus — there is nothing on that side to toggle, and
        // silently editing the hidden selection would be worse than doing
        // nothing.
        Key::Enter => match app.active_tab {
            TAB_TRIAGE => app.toggle_selected_issue(),
            TAB_SETTINGS if !app.backups_focused() => app.open_setting_input(),
            _ => {}
        },

        Key::Char(' ') => match app.active_tab {
            TAB_TRIAGE => app.toggle_selected_issue(),
            TAB_SETTINGS if !app.backups_focused() => app.toggle_current_setting(),
            _ => {}
        },

        // The scan and repair logs used to be scrolled from here. They are
        // scroll areas now, which the mouse wheel and their own scrollbars
        // drive, so there is nothing left for these keys to move.
        Key::Up | Key::Char('k') => match app.active_tab {
            TAB_TRIAGE => app.prev_issue(),
            TAB_SETTINGS if app.backups_focused() => app.prev_backup(),
            TAB_SETTINGS => app.prev_setting(),
            _ => {}
        },
        Key::Down | Key::Char('j') => match app.active_tab {
            TAB_TRIAGE => app.next_issue(),
            TAB_SETTINGS if app.backups_focused() => app.next_backup(),
            TAB_SETTINGS => app.next_setting(),
            _ => {}
        },

        // Jumping through the triage list, on the other hand, is still ours.
        // The list is a scroll area too, but the mouse only moves the viewport;
        // these keys move the selection, which is what Enter and Space act on.
        Key::PageUp if app.active_tab == TAB_TRIAGE => app.page_up_issue(PAGE_STEP),
        Key::PageDown if app.active_tab == TAB_TRIAGE => app.page_down_issue(PAGE_STEP),
        Key::Home if app.active_tab == TAB_TRIAGE => app.first_issue(),
        Key::End if app.active_tab == TAB_TRIAGE => app.last_issue(),

        Key::Char('/') if app.active_tab == TAB_TRIAGE => app.focus_search = true,
        Key::Char('c') | Key::Char('C') if app.active_tab == TAB_TRIAGE => {
            app.toggle_severity_filter(Severity::Critical);
        }
        Key::Char('w') | Key::Char('W') if app.active_tab == TAB_TRIAGE => {
            app.toggle_severity_filter(Severity::Warning);
        }
        Key::Char('i') | Key::Char('I') if app.active_tab == TAB_TRIAGE => {
            app.toggle_severity_filter(Severity::Info);
        }
        Key::Char('m') | Key::Char('M') if app.active_tab == TAB_TRIAGE => {
            app.cycle_module_filter();
        }
        Key::Char('x') | Key::Char('X') if app.active_tab == TAB_TRIAGE => {
            app.clear_filters();
        }

        Key::Left | Key::Char('h') => app.prev_tab(),
        Key::Right | Key::Char('l') => app.next_tab(),

        Key::Char('+') | Key::Char('=') | Key::Char(']')
            if app.active_tab == TAB_SETTINGS && !app.backups_focused() =>
        {
            app.adjust_current_setting(true);
        }
        Key::Char('-') | Key::Char('_') | Key::Char('[')
            if app.active_tab == TAB_SETTINGS && !app.backups_focused() =>
        {
            app.adjust_current_setting(false);
        }

        // Esc unwinds one layer at a time: filters, then backup focus, then a
        // running operation, then the tab itself.
        Key::Esc => {
            if app.active_tab == TAB_TRIAGE && app.has_active_filters() {
                app.clear_filters();
            } else if app.active_tab == TAB_SETTINGS && app.backups_focused() {
                app.toggle_safety_focus();
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
    use crate::app::{ConfirmRequest, TAB_COUNT};
    use crate::engine::issue::{Issue, RiskScore};
    use crate::safety::reg_backup::BackupRecord;

    fn backup(id: &str) -> BackupRecord {
        BackupRecord {
            id: id.to_string(),
            timestamp: "2026-01-01 12:00:00".to_string(),
            description: format!("backup {}", id),
            key_path: format!("HKCU\\Test\\{}", id),
            file_path: format!("C:\\backups\\{}.reg", id),
        }
    }

    /// An `App` with no modal in the way.
    ///
    /// `App::new` raises the elevation prompt when WinMedic is not running as
    /// Administrator, and that modal swallows every key — so a dispatch test
    /// that skipped this would be testing the modal, not the binding.
    fn app() -> App {
        let mut app = App::new();
        app.pending_confirm = None;
        app.issues.clear();
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

        // 'q' or other arbitrary keys would normally trigger actions, but must be swallowed without dismissing.
        handle_key(&mut app, Key::Char('q'));
        assert!(!app.should_quit, "the modal must absorb the keystroke");
        assert!(
            app.pending_confirm.is_some(),
            "unrelated keys must not dismiss the modal"
        );

        // 'n' or Esc dismisses the confirmation.
        handle_key(&mut app, Key::Esc);
        assert!(app.pending_confirm.is_none(), "Esc dismisses the modal");
    }

    #[test]
    fn confirm_modal_keys_test() {
        let mut app = app();

        // Dismiss via 'n'
        app.pending_confirm = Some(ConfirmRequest::Elevate);
        handle_key(&mut app, Key::Char(' '));
        assert!(app.pending_confirm.is_some(), "Space ignored");
        handle_key(&mut app, Key::Char('n'));
        assert!(app.pending_confirm.is_none(), "'n' dismisses");

        // Dismiss via 'N'
        app.pending_confirm = Some(ConfirmRequest::Elevate);
        handle_key(&mut app, Key::Char('N'));
        assert!(app.pending_confirm.is_none(), "'N' dismisses");

        // Confirm via 'y'
        app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
            current_version: "0.1.0".into(),
            latest_version: "0.2.0".into(),
            release_url: "https://example.com".into(),
            download: None,
        });
        handle_key(&mut app, Key::Char('y'));
        assert!(app.pending_confirm.is_none(), "'y' confirms");

        // Confirm via 'Enter'
        app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
            current_version: "0.1.0".into(),
            latest_version: "0.2.0".into(),
            release_url: "https://example.com".into(),
            download: None,
        });
        handle_key(&mut app, Key::Enter);
        assert!(app.pending_confirm.is_none(), "'Enter' confirms");
    }

    #[test]
    fn help_overlay_only_responds_to_its_own_keys() {
        let mut app = app();
        app.show_help = true;
        app.active_tab = TAB_DASHBOARD;

        handle_key(&mut app, Key::Char('3'));
        assert!(app.show_help, "still open");
        assert_eq!(app.active_tab, TAB_DASHBOARD, "tab switch was swallowed");

        handle_key(&mut app, Key::Esc);
        assert!(!app.show_help);
    }

    /// `/` asks for the search box; it does not start capturing text itself.
    #[test]
    fn slash_requests_the_search_box_only_on_the_triage_tab() {
        let mut app = app_with_issues();

        app.active_tab = TAB_DASHBOARD;
        handle_key(&mut app, Key::Char('/'));
        assert!(!app.focus_search, "nothing to focus outside triage");

        app.active_tab = TAB_TRIAGE;
        handle_key(&mut app, Key::Char('/'));
        assert!(app.focus_search);
        assert_eq!(app.search_query, "", "and types nothing by itself");
    }

    #[test]
    fn tab_navigation_wraps_in_both_directions() {
        let mut app = app();
        app.active_tab = TAB_COUNT - 1;

        handle_key(&mut app, Key::Tab);
        assert_eq!(app.active_tab, 0);

        handle_key(&mut app, Key::BackTab);
        assert_eq!(app.active_tab, TAB_COUNT - 1);
    }

    #[test]
    fn arrow_keys_and_hl_navigate_tabs_bios_style() {
        let mut app = app();
        app.active_tab = 0;

        // Right arrow advances tab
        handle_key(&mut app, Key::Right);
        assert_eq!(app.active_tab, 1);

        // 'l' advances tab
        handle_key(&mut app, Key::Char('l'));
        assert_eq!(app.active_tab, 2);

        // Left arrow goes back
        handle_key(&mut app, Key::Left);
        assert_eq!(app.active_tab, 1);

        // 'h' goes back
        handle_key(&mut app, Key::Char('h'));
        assert_eq!(app.active_tab, 0);

        // Left arrow wraps to last tab
        handle_key(&mut app, Key::Left);
        assert_eq!(app.active_tab, TAB_COUNT - 1);

        // Right arrow wraps back to first tab
        handle_key(&mut app, Key::Right);
        assert_eq!(app.active_tab, 0);
    }

    #[test]
    fn plus_and_minus_adjust_settings_on_settings_tab() {
        let mut app = app();
        app.active_tab = TAB_SETTINGS;
        app.selected_setting_index = 4; // temp_clean_threshold_mb (default 500)
        let initial = app.config.temp_clean_threshold_mb;

        handle_key(&mut app, Key::Char('+'));
        assert_eq!(app.config.temp_clean_threshold_mb, initial + 100);

        handle_key(&mut app, Key::Char('-'));
        assert_eq!(app.config.temp_clean_threshold_mb, initial);

        handle_key(&mut app, Key::Char(']'));
        assert_eq!(app.config.temp_clean_threshold_mb, initial + 100);

        handle_key(&mut app, Key::Char('['));
        assert_eq!(app.config.temp_clean_threshold_mb, initial);
    }

    #[test]
    fn severity_filter_keys_only_apply_on_the_triage_tab() {
        let mut app = app_with_issues();

        app.active_tab = TAB_DASHBOARD;
        handle_key(&mut app, Key::Char('c'));
        assert_eq!(app.severity_filter, None, "no filtering outside triage");

        app.active_tab = TAB_TRIAGE;
        handle_key(&mut app, Key::Char('c'));
        assert_eq!(app.severity_filter, Some(Severity::Critical));

        // Pressing it again clears it.
        handle_key(&mut app, Key::Char('c'));
        assert_eq!(app.severity_filter, None);
    }

    #[test]
    fn escape_clears_filters_before_it_navigates_away() {
        let mut app = app_with_issues();
        app.active_tab = TAB_TRIAGE;
        app.toggle_severity_filter(Severity::Critical);

        handle_key(&mut app, Key::Esc);
        assert!(!app.has_active_filters(), "first Esc clears the filter");
        assert_eq!(app.active_tab, TAB_TRIAGE, "and stays put");

        handle_key(&mut app, Key::Esc);
        assert_eq!(app.active_tab, TAB_DASHBOARD, "second Esc navigates back");
    }

    #[test]
    fn u_means_rollback_on_settings_and_update_notice_everywhere_else() {
        let mut app = app();
        app.active_tab = TAB_DASHBOARD;
        app.available_update = None;

        // Nothing parked, so this is a no-op rather than a modal.
        handle_key(&mut app, Key::Char('u'));
        assert!(app.pending_confirm.is_none());

        app.active_tab = TAB_SETTINGS;
        app.backup_records.clear();
        handle_key(&mut app, Key::Char('u'));
        // No backups to roll back, so it explains itself instead.
        assert!(app.pending_confirm.is_none());
        assert!(app.status_message.is_some());
    }

    #[test]
    fn b_hands_the_arrow_keys_to_the_backup_list_and_back() {
        let mut app = app();
        app.active_tab = TAB_SETTINGS;
        app.backup_records = vec![backup("a"), backup("b"), backup("c")];
        app.selected_setting_index = 0;

        // Focus starts on the settings list.
        handle_key(&mut app, Key::Down);
        assert_eq!(app.selected_setting_index, 1);
        assert_eq!(app.selected_backup_index, 0, "the backup list stayed put");

        handle_key(&mut app, Key::Char('b'));
        handle_key(&mut app, Key::Down);
        assert_eq!(app.selected_backup_index, 1);
        assert_eq!(
            app.selected_setting_index, 1,
            "the settings list stayed put"
        );

        // While backups hold focus, the setting editors are inert.
        let before = app.config.temp_clean_threshold_mb;
        app.selected_setting_index = 4; // temp_clean_threshold_mb
        handle_key(&mut app, Key::Char('+'));
        assert_eq!(app.config.temp_clean_threshold_mb, before);
        handle_key(&mut app, Key::Enter);
        assert!(app.setting_input.is_none(), "Enter opens no input dialog");

        // Esc gives the arrow keys back before it navigates anywhere.
        handle_key(&mut app, Key::Esc);
        assert!(!app.backups_focused());
        assert_eq!(app.active_tab, TAB_SETTINGS, "and stays on the tab");

        handle_key(&mut app, Key::Esc);
        assert_eq!(app.active_tab, TAB_DASHBOARD);
    }

    #[test]
    fn b_does_nothing_outside_the_settings_tab() {
        let mut app = app();
        app.active_tab = TAB_TRIAGE;

        handle_key(&mut app, Key::Char('b'));
        assert!(!app.backups_focused());
    }

    #[test]
    fn number_keys_reach_every_tab_and_ignore_the_retired_sixth() {
        let mut app = app();

        for (key, expected) in [
            ('1', TAB_DASHBOARD),
            ('2', TAB_SCANNER),
            ('3', TAB_TRIAGE),
            ('4', TAB_REPAIR),
            ('5', TAB_SETTINGS),
        ] {
            handle_key(&mut app, Key::Char(key));
            assert_eq!(
                app.active_tab, expected,
                "'{key}' should open tab {expected}"
            );
        }

        // '6' used to be Settings. It now points past the last tab and must not
        // move the user anywhere.
        handle_key(&mut app, Key::Char('6'));
        assert_eq!(app.active_tab, TAB_SETTINGS, "'6' is no longer bound");
    }

    #[test]
    fn space_toggles_the_selected_issue_on_triage() {
        let mut app = app_with_issues();
        app.active_tab = TAB_TRIAGE;
        app.selected_filtered_index = 0;
        assert!(app.issues[0].is_selected, "issues start selected");

        handle_key(&mut app, Key::Char(' '));
        assert!(!app.issues[0].is_selected);

        handle_key(&mut app, Key::Char(' '));
        assert!(app.issues[0].is_selected);
    }

    #[test]
    fn dry_run_toggles_and_reports_itself() {
        let mut app = app();
        assert!(!app.dry_run);

        handle_key(&mut app, Key::Char('d'));
        assert!(app.dry_run);
        assert!(app.status_message.is_some());

        handle_key(&mut app, Key::Char('D'));
        assert!(!app.dry_run);
    }

    #[test]
    fn quit_is_bound_in_both_cases() {
        for c in ['q', 'Q'] {
            let mut app = app();
            handle_key(&mut app, Key::Char(c));
            assert!(app.should_quit, "'{c}' should quit");
        }
    }

    #[test]
    fn unbound_keys_are_ignored() {
        let mut app = app();
        let before = app.active_tab;

        for code in [Key::Unbound, Key::Char('§')] {
            handle_key(&mut app, code);
        }

        assert_eq!(app.active_tab, before);
        assert!(!app.should_quit);
        assert!(!app.show_help);
    }

    #[test]
    fn setting_input_modal_captures_digits_and_submits_on_enter() {
        let mut app = app();
        app.config.temp_clean_threshold_mb = 500;
        app.active_tab = TAB_SETTINGS;
        app.selected_setting_index = 4; // Temp clean threshold
        assert_eq!(app.config.temp_clean_threshold_mb, 500);

        // Enter opens input modal
        handle_key(&mut app, Key::Enter);
        assert!(app.setting_input.is_some());

        // Backspace 3 times
        handle_key(&mut app, Key::Backspace);
        handle_key(&mut app, Key::Backspace);
        handle_key(&mut app, Key::Backspace);
        assert_eq!(app.setting_input.as_ref().unwrap().buffer, "");

        // Type '8', '0', '0'
        handle_key(&mut app, Key::Char('8'));
        handle_key(&mut app, Key::Char('0'));
        handle_key(&mut app, Key::Char('0'));
        assert_eq!(app.setting_input.as_ref().unwrap().buffer, "800");

        // Non-digits are ignored
        handle_key(&mut app, Key::Char('a'));
        handle_key(&mut app, Key::Char('q'));
        assert_eq!(app.setting_input.as_ref().unwrap().buffer, "800");
        assert!(!app.should_quit, "modal swallows 'q'");

        // Enter submits and saves
        handle_key(&mut app, Key::Enter);
        assert!(app.setting_input.is_none());
        assert_eq!(app.config.temp_clean_threshold_mb, 800);

        // Esc cancels without saving
        handle_key(&mut app, Key::Enter);
        assert!(app.setting_input.is_some());
        handle_key(&mut app, Key::Char('9'));
        handle_key(&mut app, Key::Esc);
        assert!(app.setting_input.is_none());
        assert_eq!(app.config.temp_clean_threshold_mb, 800);
    }

    #[test]
    fn triage_navigation_keys() {
        let mut app = app();
        app.active_tab = TAB_TRIAGE;
        for i in 0..15 {
            app.issues.push(Issue::new(
                format!("iss_{i}"),
                "sys",
                format!("Issue {i}"),
                "Category",
                Severity::Info,
                RiskScore::Low,
                "Desc",
                "Details",
                "Fix",
                vec![],
            ));
        }

        assert_eq!(app.selected_filtered_index, 0);

        handle_key(&mut app, Key::Down);
        assert_eq!(app.selected_filtered_index, 1);

        handle_key(&mut app, Key::Char('j'));
        assert_eq!(app.selected_filtered_index, 2);

        handle_key(&mut app, Key::Up);
        assert_eq!(app.selected_filtered_index, 1);

        handle_key(&mut app, Key::Char('k'));
        assert_eq!(app.selected_filtered_index, 0);

        handle_key(&mut app, Key::End);
        assert_eq!(app.selected_filtered_index, 14);

        handle_key(&mut app, Key::Home);
        assert_eq!(app.selected_filtered_index, 0);

        handle_key(&mut app, Key::PageDown);
        assert_eq!(app.selected_filtered_index, 10);

        handle_key(&mut app, Key::PageDown);
        assert_eq!(app.selected_filtered_index, 14);

        handle_key(&mut app, Key::PageUp);
        assert_eq!(app.selected_filtered_index, 4);

        handle_key(&mut app, Key::PageUp);
        assert_eq!(app.selected_filtered_index, 0);
    }
}
