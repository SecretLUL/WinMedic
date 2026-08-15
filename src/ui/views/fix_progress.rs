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
        (true, true) => format!(" ⚠ SIMULATION LÄUFT – Aktuell: {} ", current_issue_title),
        (true, false) if total_to_fix > 0 && (fixed_count + failed_count >= total_to_fix) => {
            " ⚠ SIMULATION ABGESCHLOSSEN – es wurde nichts verändert ".to_string()
        }
        (true, false) => {
            " ⚠ SIMULATIONSMODUS – [F] zeigt die geplanten Schritte, [D] schaltet um ".to_string()
        }
        (false, true) => format!(" REPARATUR LÄUFT – Aktuell: {} ", current_issue_title),
        (false, false) if total_to_fix > 0 && (fixed_count + failed_count >= total_to_fix) => {
            " REPARATUR-DURCHLAUF ABGESCHLOSSEN ".to_string()
        }
        (false, false) => {
            " REPARATUR-CENTER – Bereit zur Ausführung (Drücken Sie [F]) ".to_string()
        }
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

    let console_title = if scroll_offset > 0 {
        format!(
            " LIVE-REPARATUR KONSOLE [Zeilen {}-{} von {} | End = Live] ",
            start_idx + 1,
            end_idx,
            total_logs
        )
    } else {
        format!(
            " LIVE-REPARATUR KONSOLE & BEFEHLSAUSGABE [{}] [PgUp/PgDn zum Scrollen] ",
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
                    format!("◻ {} Reparatur(en) geplant", fixed_count)
                } else {
                    format!("✔ {} erfolgreich behoben", fixed_count)
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
                format!("✖ {} fehlgeschlagen", failed_count),
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
                    " 💡 [D] drücken für echte Reparatur "
                } else if progress_percent >= 100 && failed_count == 0 {
                    " 🎉 Alle Reparaturen erfolgreich durchgeführt! "
                } else if progress_percent >= 100 {
                    " ⚠ Einige Reparaturen erfordern einen System-Neustart. "
                } else if is_fixing {
                    " ⚙ Reparatur-Skripte werden abgearbeitet... "
                } else {
                    " 👉 Drücken Sie [F] um Reparatur zu starten, [D] für Simulation "
                },
                Style::default()
                    .fg(Theme::TEXT_WHITE)
                    .add_modifier(Modifier::ITALIC),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Tastatur: ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                "[PgUp/PgDn] Log scrollen  [Home/End] Oben/Live  [F] Start  [D] Simulation  [E] Bericht",
                Style::default().fg(Theme::CYAN),
            ),
        ]),
    ];

    let summary_box =
        Paragraph::new(summary_lines).block(Theme::card_block("ABSCHLUSS & HINWEISE"));
    f.render_widget(summary_box, chunks[2]);
}
