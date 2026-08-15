use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Wrap};
use std::collections::VecDeque;

// See `ui::widgets::header` — render functions take explicit state slices
// rather than borrowing the whole `App`.
#[allow(clippy::too_many_arguments)]
pub fn render_fix_progress(
    f: &mut Frame,
    area: Rect,
    is_fixing: bool,
    current_issue_title: &str,
    fixed_count: usize,
    failed_count: usize,
    total_to_fix: usize,
    vss_status: &str,
    console_lines: &VecDeque<String>,
    dry_run: bool,
    scroll_offset: usize,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Repair Progress Gauge & VSS Badge
            Constraint::Min(10),   // Live Repair Console Output
            Constraint::Length(5), // Execution Summary & Reboot Alert
        ])
        .split(area);

    // Top: Repair Progress Gauge
    let progress_percent = if total_to_fix > 0 {
        (((fixed_count + failed_count) as f32 / total_to_fix as f32) * 100.0).clamp(0.0, 100.0)
            as u16
    } else {
        0
    };

    let title_str = match (dry_run, is_fixing) {
        (true, true) => format!(
            " [!] SIMULATION RUNNING - current: {} ",
            current_issue_title
        ),
        (true, false) if total_to_fix > 0 && (fixed_count + failed_count >= total_to_fix) => {
            " [!] SIMULATION COMPLETE - nothing was changed ".to_string()
        }
        (true, false) => {
            " [!] SIMULATION MODE - [F] shows the planned steps, [D] switches back ".to_string()
        }
        (false, true) => format!(" REPAIRS RUNNING - current: {} ", current_issue_title),
        (false, false) if total_to_fix > 0 && (fixed_count + failed_count >= total_to_fix) => {
            " REPAIR RUN COMPLETE ".to_string()
        }
        (false, false) => " REPAIR CENTRE - ready to run (press [F]) ".to_string(),
    };

    let gauge_color = if dry_run {
        Theme::AMBER
    } else if progress_percent >= 100 && failed_count == 0 {
        Theme::EMERALD
    } else if failed_count > 0 {
        Theme::AMBER
    } else {
        Theme::CYAN
    };

    let top_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(gauge_color))
                .title(title_str),
        )
        .gauge_style(Style::default().fg(gauge_color).bg(Theme::BG_DEEP))
        .percent(progress_percent)
        .label(format!(
            " {}/{} Fixes ({:.0}%) │ VSS: {} ",
            fixed_count + failed_count,
            total_to_fix,
            progress_percent,
            vss_status
        ));

    f.render_widget(top_gauge, chunks[0]);

    // Center: Live Repair Console with scroll offset
    let viewport_height = chunks[1].height.saturating_sub(2) as usize;
    let total_logs = console_lines.len();

    let end_idx = total_logs.saturating_sub(scroll_offset);
    let start_idx = end_idx.saturating_sub(viewport_height);

    let lines: Vec<Line> = (start_idx..end_idx)
        .filter_map(|idx| console_lines.get(idx))
        .map(|line| {
            if line.starts_with("[STDERR]")
                || line.to_lowercase().contains("error")
                || line.to_lowercase().contains("failed")
            {
                Line::from(vec![
                    Span::styled(
                        " [X] ",
                        Style::default()
                            .fg(Theme::CORAL)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(line.as_str(), Style::default().fg(Theme::CORAL)),
                ])
            } else if line.contains("SUCCESS")
                || line.contains("Repaired")
                || line.contains("finished")
            {
                Line::from(vec![
                    Span::styled(
                        " [OK] ",
                        Style::default()
                            .fg(Theme::EMERALD)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(line.as_str(), Style::default().fg(Theme::EMERALD)),
                ])
            } else {
                Line::from(vec![
                    Span::styled(" > ", Style::default().fg(Theme::CYAN)),
                    Span::styled(line.as_str(), Style::default().fg(Theme::TEXT_WHITE)),
                ])
            }
        })
        .collect();

    let console_title = if scroll_offset > 0 {
        format!(
            " LIVE REPAIR CONSOLE [lines {}-{} of {} | End = live] ",
            start_idx + 1,
            end_idx,
            total_logs
        )
    } else {
        format!(
            " LIVE REPAIR CONSOLE & COMMAND OUTPUT [{}] [PgUp/PgDn to scroll] ",
            total_logs
        )
    };

    let console_box = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if scroll_offset > 0 {
                    Theme::AMBER
                } else {
                    Theme::CYAN
                }))
                .title(console_title),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(console_box, chunks[1]);

    // Bottom: Summary & Next Steps
    let summary_lines = vec![
        Line::from(vec![
            Span::styled(
                " Status: ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if dry_run {
                    format!("{} repair(s) planned", fixed_count)
                } else {
                    format!("{} fixed successfully", fixed_count)
                },
                Style::default()
                    .fg(if dry_run {
                        Theme::AMBER
                    } else {
                        Theme::EMERALD
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
            Span::styled(
                format!("{} failed", failed_count),
                Style::default()
                    .fg(if failed_count > 0 {
                        Theme::CORAL
                    } else {
                        Theme::TEXT_WHITE
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
            Span::styled(
                if dry_run {
                    " Press [D] to run repairs for real "
                } else if progress_percent >= 100 && failed_count == 0 {
                    " All repairs completed successfully. "
                } else if progress_percent >= 100 {
                    " Some repairs need a system restart. "
                } else if is_fixing {
                    " Working through the repair scripts... "
                } else {
                    " Press [F] to start repairs, [D] to simulate "
                },
                Style::default()
                    .fg(Theme::TEXT_WHITE)
                    .add_modifier(Modifier::ITALIC),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Keys: ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                "[PgUp/PgDn] Scroll log  [Home/End] Top/Live  [F] Start  [D] Simulate  [E] Report",
                Style::default().fg(Theme::CYAN),
            ),
        ]),
    ];

    let summary_box = Paragraph::new(summary_lines).block(Theme::card_block("SUMMARY & NOTES"));
    f.render_widget(summary_box, chunks[2]);
}
