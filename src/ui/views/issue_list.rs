use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

pub fn render_issue_list(f: &mut Frame, area: Rect, issues: &[Issue], selected_index: usize) {
    if issues.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "  ✔ Keine offenen Probleme gefunden! ",
                Style::default()
                    .fg(Theme::EMERALD)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "  Ihr System befindet sich in einem einwandfreien Zustand.",
                Style::default().fg(Theme::TEXT_WHITE),
            )]),
            Line::from(vec![
                Span::styled("  Drücken Sie ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    "[S]",
                    Style::default()
                        .fg(Theme::AMBER)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" oder ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    "[R]",
                    Style::default()
                        .fg(Theme::AMBER)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    ", um einen neuen System-Health-Scan zu starten.",
                    Style::default().fg(Theme::MUTED),
                ),
            ]),
        ];
        let empty_box = Paragraph::new(empty_msg).block(Theme::card_block("PROBLEM-TRIAGE"));
        f.render_widget(empty_box, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // Left Pane: List of Issues with Checkboxes
    let items: Vec<ListItem> = issues
        .iter()
        .enumerate()
        .map(|(idx, issue)| {
            let is_current = idx == selected_index;
            let check_box = if issue.is_fixed {
                "[✔ BEHOBEN]"
            } else if issue.is_selected {
                "[X]"
            } else {
                "[ ]"
            };

            let check_color = if issue.is_fixed {
                Theme::EMERALD
            } else if issue.is_selected {
                Theme::CYAN
            } else {
                Theme::MUTED
            };

            let (sev_str, sev_color) = match issue.severity {
                Severity::Critical => ("🔴", Theme::CORAL),
                Severity::Warning => ("▲", Theme::AMBER),
                Severity::Info => ("ℹ", Theme::CYAN),
            };

            let line = Line::from(vec![
                Span::styled(
                    format!(" {} ", check_box),
                    Style::default()
                        .fg(check_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{} ", sev_str), Style::default().fg(sev_color)),
                Span::styled(
                    issue.title.clone(),
                    if is_current {
                        Style::default()
                            .fg(Theme::BG_DEEP)
                            .bg(Theme::CYAN)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Theme::TEXT_WHITE)
                    },
                ),
            ]);

            ListItem::new(line)
        })
        .collect();

    let issue_list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::CYAN))
            .title(format!(
                " GEFUNDENE PROBLEME [{}] – [Space] An-/Abwählen ",
                issues.len()
            )),
    );

    f.render_widget(issue_list, chunks[0]);

    // Right Pane: Detailed Issue View
    if let Some(issue) = issues.get(selected_index) {
        let (sev_badge, sev_color) = match issue.severity {
            Severity::Critical => ("🔴 KRITISCH", Theme::CORAL),
            Severity::Warning => ("▲ WARNUNG", Theme::AMBER),
            Severity::Info => ("ℹ HINWEIS", Theme::CYAN),
        };

        let (risk_badge, risk_color) = match issue.risk_score {
            RiskScore::Low => ("🟢 GERING (Safe Auto-Fix)", Theme::EMERALD),
            RiskScore::Medium => ("🟡 MITTEL (Dienst-Neustart)", Theme::AMBER),
            RiskScore::High => ("🟠 HOCH (Reboot/System)", Theme::CORAL),
        };

        let mut detail_lines = vec![
            Line::from(vec![
                Span::styled(" Titel:       ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    issue.title.clone(),
                    Style::default()
                        .fg(Theme::TEXT_WHITE)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Kategorie:   ", Style::default().fg(Theme::MUTED)),
                Span::styled(issue.category.clone(), Style::default().fg(Theme::CYAN)),
            ]),
            Line::from(vec![
                Span::styled(" Schweregrad: ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    sev_badge,
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled("    Risiko-Score: ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    risk_badge,
                    Style::default().fg(risk_color).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                " Beschreibung:",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![Span::styled(
                format!("  {}", issue.description),
                Style::default().fg(Theme::TEXT_WHITE),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                " Technische Diagnose / Fund:",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![Span::styled(
                format!("  {}", issue.technical_details),
                Style::default().fg(Theme::MUTED),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                " Empfohlene Reparatur (Auto-Fix):",
                Style::default()
                    .fg(Theme::EMERALD)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![Span::styled(
                format!("  👉 {}", issue.recommended_fix),
                Style::default().fg(Theme::TEXT_WHITE),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                " Reparatur-Schritte:",
                Style::default()
                    .fg(Theme::MUTED)
                    .add_modifier(Modifier::BOLD),
            )]),
        ];

        for (step_idx, step) in issue.fix_steps.iter().enumerate() {
            detail_lines.push(Line::from(vec![
                Span::styled(
                    format!("   {}. ", step_idx + 1),
                    Style::default().fg(Theme::CYAN),
                ),
                Span::styled(step.as_str(), Style::default().fg(Theme::TEXT_WHITE)),
            ]));
        }

        detail_lines.push(Line::from(""));
        detail_lines.push(Line::from(vec![Span::styled(
            " 🛡 VSS Wiederherstellungspunkt wird vor Reparatur automatisch erstellt.",
            Style::default()
                .fg(Theme::EMERALD)
                .add_modifier(Modifier::ITALIC),
        )]));

        let detail_box = Paragraph::new(detail_lines)
            .block(Theme::card_block("PROBLEM-DETAILS & REPARATUR-VORSCHLAG"))
            .wrap(Wrap { trim: true });

        f.render_widget(detail_box, chunks[1]);
    }
}
