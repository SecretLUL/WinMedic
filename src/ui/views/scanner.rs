use crate::engine::issue::{Issue, Severity};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};
use std::collections::VecDeque;

// See `ui::widgets::header` — render functions take explicit state slices
// rather than borrowing the whole `App`.
#[allow(clippy::too_many_arguments)]
pub fn render_scanner(
    f: &mut Frame,
    area: Rect,
    is_scanning: bool,
    overall_progress: u8,
    active_module_name: &str,
    current_step_text: &str,
    module_progresses: &[(&str, &str, &str, u8, bool)],
    log_messages: &VecDeque<String>,
    issues: &[Issue],
    scroll_offset: usize,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Overall Progress Bar & Current Status
            Constraint::Min(10),   // Split: Modules list & Live Log Terminal
            Constraint::Length(4), // Scan Summary / Result counter
        ])
        .split(area);

    // Top: Overall Progress Bar
    let gauge_title = if is_scanning {
        format!(
            " DIAGNOSTICS RUNNING - {} (step: {}) ",
            active_module_name, current_step_text
        )
    } else {
        " DIAGNOSTICS COMPLETE - ready for triage & repair ".to_string()
    };

    let gauge_color = if overall_progress >= 100 {
        Theme::EMERALD
    } else {
        Theme::CYAN
    };

    let overall_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(gauge_color))
                .title(gauge_title),
        )
        .gauge_style(Style::default().fg(gauge_color).bg(Theme::BG_DEEP))
        .percent(overall_progress as u16)
        .label(format!(" {}% ", overall_progress));

    f.render_widget(overall_gauge, chunks[0]);

    // Center: Split (Left: Modules Progress, Right: Live Log Output)
    let center_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);

    // Left: Modules List
    let items: Vec<ListItem> = module_progresses
        .iter()
        .map(|(_id, name, icon, percent, is_done)| {
            let (status_symbol, status_color) = if *is_done {
                ("✔ DONE", Theme::EMERALD)
            } else if *percent > 0 && *percent < 100 {
                ("⚡ CHECKING...", Theme::CYAN)
            } else {
                ("⏳ WAITING", Theme::MUTED)
            };

            let line = Line::from(vec![
                Span::styled(format!(" {} ", icon), Style::default().fg(Theme::CYAN)),
                Span::styled(
                    format!("{:<30}", name),
                    Style::default()
                        .fg(Theme::TEXT_WHITE)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {:>4}% ", percent),
                    Style::default().fg(Theme::AMBER),
                ),
                Span::styled(
                    format!(" [{}]", status_symbol),
                    Style::default()
                        .fg(status_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let module_list = List::new(items).block(Theme::card_block("DIAGNOSTIC MODULES"));
    f.render_widget(module_list, center_chunks[0]);

    // Right: Live Log Output with scroll offset
    let viewport_height = center_chunks[1].height.saturating_sub(2) as usize;
    let total_logs = log_messages.len();

    let end_idx = total_logs.saturating_sub(scroll_offset);
    let start_idx = end_idx.saturating_sub(viewport_height);

    let log_lines: Vec<Line> = (start_idx..end_idx)
        .filter_map(|idx| log_messages.get(idx))
        .map(|msg| {
            Line::from(vec![
                Span::styled(" ❯ ", Style::default().fg(Theme::CYAN)),
                Span::styled(msg.as_str(), Style::default().fg(Theme::TEXT_WHITE)),
            ])
        })
        .collect();

    let log_title = if scroll_offset > 0 {
        format!(
            " LIVE DIAGNOSTIC LOG [lines {}-{} of {} | End = live] ",
            start_idx + 1,
            end_idx,
            total_logs
        )
    } else {
        format!(
            " LIVE DIAGNOSTIC LOG [{}] [PgUp/PgDn to scroll] ",
            total_logs
        )
    };

    let log_box = Paragraph::new(log_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if scroll_offset > 0 {
                Theme::AMBER
            } else {
                Theme::BORDER
            }))
            .title(log_title),
    );
    f.render_widget(log_box, center_chunks[1]);

    // Bottom: Issue Counters
    let crit_count = issues
        .iter()
        .filter(|i| i.severity == Severity::Critical)
        .count();
    let warn_count = issues
        .iter()
        .filter(|i| i.severity == Severity::Warning)
        .count();
    let info_count = issues
        .iter()
        .filter(|i| i.severity == Severity::Info)
        .count();

    let summary_line = Line::from(vec![
        Span::styled(
            " Scan result: ",
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} issues in total ", issues.len()),
            Style::default()
                .fg(Theme::TEXT_WHITE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" 🔴 {} critical ", crit_count),
            Style::default()
                .fg(Theme::CORAL)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" ▲ {} warnings ", warn_count),
            Style::default()
                .fg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" ℹ {} informational ", info_count),
            Style::default().fg(Theme::CYAN),
        ),
        Span::styled(
            "   👉 Press [3] for issue triage & selection ",
            Style::default()
                .fg(Theme::EMERALD)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let summary_bar = Paragraph::new(summary_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::BORDER)),
    );

    f.render_widget(summary_bar, chunks[2]);
}
