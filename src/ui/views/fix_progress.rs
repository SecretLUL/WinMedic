use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Wrap};

pub fn render_fix_progress(
    f: &mut Frame,
    area: Rect,
    is_fixing: bool,
    current_issue_title: &str,
    fixed_count: usize,
    failed_count: usize,
    total_to_fix: usize,
    vss_status: &str,
    console_lines: &[String],
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

    let title_str = if is_fixing {
        format!(" REPARATUR LÄUFT – Aktuell: {} ", current_issue_title)
    } else if total_to_fix > 0 && (fixed_count + failed_count >= total_to_fix) {
        " REPARATUR-DURCHLAUF ABGESCHLOSSEN ".to_string()
    } else {
        " REPARATUR-CENTER – Bereit zur Ausführung (Drücken Sie [F]) ".to_string()
    };

    let gauge_color = if progress_percent >= 100 && failed_count == 0 {
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

    // Center: Live Repair Console
    let lines: Vec<Line> = console_lines
        .iter()
        .rev()
        .take(18)
        .map(|line| {
            if line.starts_with("[STDERR]")
                || line.to_lowercase().contains("error")
                || line.to_lowercase().contains("fehler")
            {
                Line::from(vec![
                    Span::styled(
                        " ✖ ",
                        Style::default()
                            .fg(Theme::CORAL)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(line.as_str(), Style::default().fg(Theme::CORAL)),
                ])
            } else if line.contains("SUCCESS")
                || line.contains("erfolgreich")
                || line.contains("repariert")
            {
                Line::from(vec![
                    Span::styled(
                        " ✔ ",
                        Style::default()
                            .fg(Theme::EMERALD)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(line.as_str(), Style::default().fg(Theme::EMERALD)),
                ])
            } else {
                Line::from(vec![
                    Span::styled(" ❯ ", Style::default().fg(Theme::CYAN)),
                    Span::styled(line.as_str(), Style::default().fg(Theme::TEXT_WHITE)),
                ])
            }
        })
        .collect();

    let console_box = Paragraph::new(lines)
        .block(Theme::focused_block(
            "LIVE-REPARATUR KONSOLE & BEFEHLSAUSGABE",
        ))
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
                format!("✔ {} erfolgreich behoben", fixed_count),
                Style::default()
                    .fg(Theme::EMERALD)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
            Span::styled(
                format!("✖ {} fehlgeschlagen", failed_count),
                Style::default()
                    .fg(if failed_count > 0 {
                        Theme::CORAL
                    } else {
                        Theme::MUTED
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
            Span::styled(
                format!(
                    "Ausstehend: {}",
                    total_to_fix.saturating_sub(fixed_count + failed_count)
                ),
                Style::default().fg(Theme::MUTED),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                " Nächste Schritte: ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " [F] ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Reparatur starten/wiederholen   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [R] ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Erneuten System-Scan durchführen   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [5] ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Audit-Logs & Backups einsehen",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
    ];

    let summary_box =
        Paragraph::new(summary_lines).block(Theme::card_block("REPARATUR-ZUSAMMENFASSUNG"));
    f.render_widget(summary_box, chunks[2]);
}
