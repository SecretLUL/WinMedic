use crate::engine::issue::{Issue, Severity};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};

pub fn render_scanner(
    f: &mut Frame,
    area: Rect,
    is_scanning: bool,
    overall_progress: u8,
    active_module_name: &str,
    current_step_text: &str,
    module_progresses: &[(&str, &str, &str, u8, bool)],
    log_messages: &[String],
    issues: &[Issue],
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
            " DIAGNOSE LÄUFT – {} (Schritt: {}) ",
            active_module_name, current_step_text
        )
    } else {
        " DIAGNOSE ABGESCHLOSSEN – Bereit für Triage & Reparatur ".to_string()
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
                ("✔ FERTIG", Theme::EMERALD)
            } else if *percent > 0 && *percent < 100 {
                ("⚡ PRÜFUNG...", Theme::CYAN)
            } else {
                ("⏳ WARTET", Theme::MUTED)
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

    let module_list = List::new(items).block(Theme::card_block("DIAGNOSE-MODULE"));
    f.render_widget(module_list, center_chunks[0]);

    // Right: Live Log Output
    let log_lines: Vec<Line> = log_messages
        .iter()
        .rev()
        .take(15)
        .map(|msg| {
            Line::from(vec![
                Span::styled(" ❯ ", Style::default().fg(Theme::CYAN)),
                Span::styled(msg.as_str(), Style::default().fg(Theme::TEXT_WHITE)),
            ])
        })
        .collect();

    let log_box = Paragraph::new(log_lines).block(Theme::card_block("LIVE-DIAGNOSE PROTOKOLL"));
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
            " Scan-Ergebnis: ",
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} Probleme insgesamt ", issues.len()),
            Style::default()
                .fg(Theme::TEXT_WHITE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" 🔴 {} Kritisch ", crit_count),
            Style::default()
                .fg(Theme::CORAL)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" ▲ {} Warnungen ", warn_count),
            Style::default()
                .fg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" ℹ {} Hinweise ", info_count),
            Style::default().fg(Theme::CYAN),
        ),
        Span::styled(
            "   👉 Drücken Sie [3] für die Problem-Triage & Auswahl ",
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
