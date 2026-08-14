pub mod theme;
pub mod views;
pub mod widgets;

use crate::app::App;
use crate::ui::views::dashboard::render_dashboard;
use crate::ui::views::fix_progress::render_fix_progress;
use crate::ui::views::history::render_history;
use crate::ui::views::issue_list::render_issue_list;
use crate::ui::views::scanner::render_scanner;
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
    );

    // 2. Render Active Tab View
    let body_area = main_layout[1];
    match app.active_tab {
        0 => {
            render_dashboard(
                f,
                body_area,
                app.telemetry.as_ref(),
                app.health_score,
                &app.issues,
                &app.module_statuses,
            );
        }
        1 => {
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
        2 => {
            render_issue_list(f, body_area, &app.issues, app.selected_issue_index);
        }
        3 => {
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
            );
        }
        4 => {
            render_history(
                f,
                body_area,
                &app.audit_entries,
                &app.backup_records,
                &app.vss_restore_points,
                &app.audit_logger.log_dir().to_string_lossy(),
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
    );

    // 4. Render Help Modal if opened
    if app.show_help {
        render_help_popup(f, area);
    }
}
