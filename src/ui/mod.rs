pub mod theme;
pub mod views;
pub mod widgets;

use crate::app::{
    App, TAB_DASHBOARD, TAB_HISTORY, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS, TAB_TRIAGE,
};
use crate::ui::views::dashboard::render_dashboard;
use crate::ui::views::fix_progress::render_fix_progress;
use crate::ui::views::history::{HistoryViewState, render_history};
use crate::ui::views::issue_list::render_issue_list;
use crate::ui::views::scanner::render_scanner;
use crate::ui::views::settings::render_settings;
use crate::ui::widgets::confirm_popup::render_confirm_popup;
use crate::ui::widgets::footer::render_footer;
use crate::ui::widgets::header::render_header;
use crate::ui::widgets::help_popup::render_help_popup;
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
            );
        }
        TAB_SCANNER => {
            let mod_tuples: Vec<(&str, &str, &str, u8, bool)> = app
                .module_progress_list
                .iter()
                .map(|(id, name, icon, percent, is_done)| {
                    (
                        id.as_str(),
                        name.as_str(),
                        icon.as_str(),
                        *percent,
                        *is_done,
                    )
                })
                .collect();

            render_scanner(
                f,
                body_area,
                app.is_scanning,
                app.scan_overall_progress,
                &app.scan_active_module_name,
                &app.scan_current_step_text,
                &mod_tuples,
                &app.scan_log_messages,
                &app.issues,
            );
        }
        TAB_TRIAGE => {
            render_issue_list(f, body_area, &app.issues, app.selected_issue_index);
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
            );
        }
        TAB_HISTORY => {
            let backups = app.backups_newest_first();
            let state = HistoryViewState {
                audit_entries: &app.audit_entries,
                backup_records: &backups,
                selected_backup_index: app.selected_backup_index,
                vss_restore_points: &app.vss_restore_points,
                restore_points_loading: app.restore_points_loading,
                is_restoring: app.is_restoring,
                log_dir_path: &app.audit_logger.log_dir().to_string_lossy(),
            };
            render_history(f, body_area, &state);
        }
        TAB_SETTINGS => {
            render_settings(
                f,
                body_area,
                &app.config,
                app.selected_setting_index,
                app.dry_run,
            );
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
    );

    // 4. Modal overlays — confirmation takes precedence over help.
    if let Some(request) = app.pending_confirm.as_ref() {
        render_confirm_popup(f, area, request);
    } else if app.show_help {
        render_help_popup(f, area);
    }
}
