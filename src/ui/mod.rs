pub mod theme;
pub mod views;
pub mod widgets;

use crate::app::{App, TAB_DASHBOARD, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS, TAB_TRIAGE};
use crate::ui::views::dashboard::render_dashboard;
use crate::ui::views::fix_progress::render_fix_progress;
use crate::ui::views::issue_list::{IssueListViewState, render_issue_list};
use crate::ui::views::scanner::{ModuleRow, ScannerViewState, render_scanner};
use crate::ui::views::settings::{SettingsViewState, render_settings};
use crate::ui::widgets::confirm_popup::render_confirm_popup;
use crate::ui::widgets::footer::render_footer;
use crate::ui::widgets::header::render_header;
use crate::ui::widgets::help_popup::render_help_popup;
use crate::ui::widgets::safety_panel::SafetyPanelState;
use crate::ui::widgets::setting_input_popup::render_setting_input_popup;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};

pub fn render_app(f: &mut Frame, app: &App) {
    let area = f.area();

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // Header + Tabs
            Constraint::Min(12),   // Active Tab View Body
            Constraint::Length(3), // Hotkey / Status Footer
        ])
        .split(area);

    // 1. Render Header Bar
    render_header(
        f,
        main_layout[0],
        app.active_tab,
        app.telemetry.as_ref(),
        app.is_admin,
        app.issues.iter().filter(|i| !i.is_fixed).count(),
        app.is_scanning,
        app.dry_run,
    );

    // 2. Render Active Tab View
    let body_area = main_layout[1];
    match app.active_tab {
        TAB_DASHBOARD => {
            render_dashboard(
                f,
                body_area,
                app.telemetry.as_ref(),
                app.health_score,
                &app.issues,
                &app.module_statuses,
                &app.audit_entries,
            );
        }
        TAB_SCANNER => {
            // Elapsed times are read once here rather than inside the view, so
            // the view stays a pure function of its inputs and a test can pin
            // the clock instead of racing it.
            let modules: Vec<ModuleRow> = app
                .module_progress_list
                .iter()
                .map(|m| ModuleRow {
                    name: &m.name,
                    icon: &m.icon,
                    percent: m.percent,
                    is_done: m.is_done,
                    failed: m.failure.is_some(),
                    step: &m.step,
                    step_elapsed: m.step_elapsed(),
                })
                .collect();

            let state = ScannerViewState {
                is_scanning: app.is_scanning,
                overall_progress: app.scan_overall_progress,
                modules: &modules,
                log_messages: &app.scan_log_messages,
                issues: &app.issues,
                log_scroll: app.scan_log_scroll,
                elapsed: app.scan_elapsed(),
            };
            render_scanner(f, body_area, &state);
        }
        TAB_TRIAGE => {
            let filtered_indices = app.filtered_issue_indices();
            let state = IssueListViewState {
                issues: &app.issues,
                filtered_indices: &filtered_indices,
                selected_filtered_index: app.selected_filtered_index,
                severity_filter: app.severity_filter,
                module_filter: app.module_filter.as_deref(),
                search_query: &app.search_query,
                is_searching: app.is_searching,
            };
            render_issue_list(f, body_area, &state);
        }
        TAB_REPAIR => {
            render_fix_progress(
                f,
                body_area,
                app.is_fixing,
                &app.current_fix_title,
                app.fixed_count,
                app.failed_count,
                app.total_to_fix,
                &app.vss_status,
                &app.repair_console_lines,
                app.dry_run,
                app.repair_log_scroll,
            );
        }
        TAB_SETTINGS => {
            let backups = app.backups_newest_first();
            let state = SettingsViewState {
                config: &app.config,
                selected_setting_index: app.selected_setting_index,
                dry_run: app.dry_run,
                safety: SafetyPanelState {
                    backup_records: &backups,
                    selected_backup_index: app.selected_backup_index,
                    vss_restore_points: &app.vss_restore_points,
                    restore_points_loading: app.restore_points_loading,
                    is_restoring: app.is_restoring,
                    is_focused: app.backups_focused(),
                },
                log_dir_path: &app.audit_logger.log_dir().to_string_lossy(),
            };
            render_settings(f, body_area, &state);
        }
        _ => {}
    }

    // 3. Render Footer
    render_footer(
        f,
        main_layout[2],
        app.active_tab,
        app.status_message.as_deref(),
        app.is_busy(),
        app.dry_run,
        app.backups_focused(),
    );

    // 4. Modal overlays — confirmation takes precedence, then setting input, then help.
    if let Some(request) = app.pending_confirm.as_ref() {
        render_confirm_popup(f, area, request);
    } else if let Some(input) = app.setting_input.as_ref() {
        render_setting_input_popup(f, area, input);
    } else if app.show_help {
        render_help_popup(f, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{SafetyFocus, TAB_COUNT};
    use crate::safety::audit::AuditEntry;
    use crate::safety::reg_backup::BackupRecord;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Render one frame and return every cell's text, row by row.
    fn draw(app: &App, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| render_app(f, app)).unwrap();

        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn screen(app: &App, width: u16, height: u16) -> String {
        draw(app, width, height).join("\n")
    }

    fn populated_app() -> App {
        let mut app = App::new();
        app.pending_confirm = None;
        app.backup_records = vec![BackupRecord {
            id: "b1".to_string(),
            timestamp: "2026-01-01 12:00:00".to_string(),
            description: "Startup entry removed".to_string(),
            key_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            file_path: "C:\\backups\\b1.reg".to_string(),
        }];
        app.vss_restore_points = vec!["2026-01-01 11:59 - WinMedic pre-repair".to_string()];
        app.audit_entries = vec![AuditEntry {
            timestamp: "2026-01-01 12:00:00".to_string(),
            action_type: "FIX".to_string(),
            module_id: "registry_startup".to_string(),
            title: "Disabled a startup entry".to_string(),
            status: "SUCCESS".to_string(),
            details: String::new(),
        }];
        app
    }

    /// Layout constraints are only checked at draw time, so a tab that no
    /// terminal size can satisfy fails here rather than in front of a user.
    #[test]
    fn every_tab_renders_at_small_and_large_terminal_sizes() {
        let mut app = populated_app();

        for tab in 0..TAB_COUNT {
            app.active_tab = tab;
            for (w, h) in [(80, 24), (120, 40), (200, 60)] {
                let rows = draw(&app, w, h);
                assert_eq!(rows.len(), h as usize, "tab {tab} at {w}x{h}");
            }
        }
    }

    #[test]
    fn the_header_offers_exactly_five_tabs() {
        let app = populated_app();
        let rendered = screen(&app, 140, 40);

        for title in [
            "[1] Dashboard",
            "[2] Health Scan",
            "[3] Issue Triage",
            "[4] Repair Center",
            "[5] Settings & Safety",
        ] {
            assert!(rendered.contains(title), "missing tab title: {title}");
        }

        assert!(
            !rendered.contains("[6]"),
            "the sixth tab was merged away and must not be advertised"
        );
    }

    /// The whole point of the merge: none of the safety surface may go missing.
    #[test]
    fn the_settings_tab_carries_the_whole_safety_surface() {
        let mut app = populated_app();
        app.active_tab = TAB_SETTINGS;

        let rendered = screen(&app, 160, 45);

        assert!(rendered.contains("SETTINGS"), "the settings list");
        assert!(rendered.contains("BACKUPS & VSS"), "the backup pane");
        assert!(rendered.contains("restore points"), "the VSS section");
        assert!(rendered.contains("[REG]"), "the registry snapshot list");
        assert!(rendered.contains("Startup entry removed"), "the snapshot");
        assert!(
            rendered.contains("Logs & backups:"),
            "the log directory path"
        );
        assert!(rendered.contains("[U]"), "the rollback binding");
        assert!(rendered.contains("[R]"), "the VSS refresh binding");
    }

    /// The audit trail is written and reported, just not listed on this tab.
    ///
    /// It survives in the file the "Logs & backups" path points at, in the
    /// exported report, and as the dashboard's one-line summary.
    #[test]
    fn the_settings_tab_no_longer_lists_recent_actions() {
        let mut app = populated_app();
        app.active_tab = TAB_SETTINGS;

        let rendered = screen(&app, 160, 45);

        assert!(!rendered.contains("RECENT ACTIONS"));
        assert!(!rendered.contains("Disabled a startup entry"));
    }

    #[test]
    fn the_focused_list_is_the_one_advertising_the_arrow_keys() {
        let mut app = populated_app();
        app.active_tab = TAB_SETTINGS;

        let on_settings = screen(&app, 160, 45);
        assert!(
            on_settings.contains("SETTINGS  ◄ [↑/↓]"),
            "the settings list should claim the arrows first"
        );
        assert!(on_settings.contains("BACKUPS & VSS  ([B] to focus)"));

        app.safety_focus = SafetyFocus::Backups;
        let on_backups = screen(&app, 160, 45);
        assert!(
            on_backups.contains("BACKUPS & VSS  ◄ [↑/↓]"),
            "after [B] the backup list should claim them"
        );
        assert!(on_backups.contains("SETTINGS  ([B] to focus)"));
    }

    #[test]
    fn the_dashboard_links_back_to_the_audit_trail_it_no_longer_owns() {
        let mut app = populated_app();
        app.active_tab = TAB_DASHBOARD;

        let rendered = screen(&app, 160, 45);
        assert!(rendered.contains("Last action:"));
        assert!(rendered.contains("Disabled a startup entry"));
        assert!(
            rendered.contains("[5] Full log, backups & rollback"),
            "and points at the tab that now holds it"
        );
    }

    #[test]
    fn a_machine_with_no_audit_trail_shows_no_empty_last_action_row() {
        let mut app = populated_app();
        app.active_tab = TAB_DASHBOARD;
        app.audit_entries.clear();

        assert!(!screen(&app, 160, 45).contains("Last action:"));
    }

    #[test]
    fn triage_scrolls_down_when_navigating_to_lower_issues() {
        let mut app = App::new();
        app.pending_confirm = None;
        app.active_tab = TAB_TRIAGE;
        for i in 0..30 {
            app.issues.push(crate::engine::issue::Issue::new(
                format!("issue_{i}"),
                "system_integrity",
                format!("Issue #{i:02} Finding Title"),
                "System & Integrity",
                crate::engine::issue::Severity::Warning,
                crate::engine::issue::RiskScore::Low,
                "Description",
                "Technical details",
                "Fix step",
                vec![],
            ));
        }

        // At index 0, Issue #00 is visible and Issue #25 is off-screen
        app.selected_filtered_index = 0;
        let rendered_top = screen(&app, 120, 24);
        assert!(rendered_top.contains("Issue #00 Finding Title"));
        assert!(!rendered_top.contains("Issue #25 Finding Title"));

        // When navigating down to index 25, the list must scroll down and display Issue #25
        app.selected_filtered_index = 25;
        let rendered_bottom = screen(&app, 120, 24);
        assert!(rendered_bottom.contains("Issue #25 Finding Title"));
    }
}
