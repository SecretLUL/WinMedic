use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

pub struct IssueListViewState<'a> {
    pub issues: &'a [Issue],
    pub filtered_indices: &'a [usize],
    pub selected_filtered_index: usize,
    pub severity_filter: Option<Severity>,
    pub module_filter: Option<&'a str>,
    pub search_query: &'a str,
    pub is_searching: bool,
}

pub fn render_issue_list(f: &mut Frame, area: Rect, state: &IssueListViewState) {
    if state.issues.is_empty() {
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

    let vertical_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Filter & Search Bar
            Constraint::Min(8),    // Split: Issues List & Details
        ])
        .split(area);

    // Top Filter & Search Bar
    render_filter_bar(f, vertical_chunks[0], state);

    // Split Left/Right
    let main_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(vertical_chunks[1]);

    // Left Pane: List of Filtered Issues
    if state.filtered_indices.is_empty() {
        let no_match_lines = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "  Keine Befunde für aktiven Filter",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Drücken Sie ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    "[x]",
                    Style::default()
                        .fg(Theme::CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" oder ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    "[Esc]",
                    Style::default()
                        .fg(Theme::CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    ", um alle Filter zurückzusetzen.",
                    Style::default().fg(Theme::MUTED),
                ),
            ]),
        ];
        let no_match_box =
            Paragraph::new(no_match_lines).block(Theme::card_block("GEFUNDENE PROBLEME [0]"));
        f.render_widget(no_match_box, main_split[0]);
    } else {
        let items: Vec<ListItem> = state
            .filtered_indices
            .iter()
            .enumerate()
            .map(|(pos, &orig_idx)| {
                let issue = &state.issues[orig_idx];
                let is_current = pos == state.selected_filtered_index;
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

        let list_title = format!(
            " GEFUNDENE PROBLEME [{}/{}] – [Space] An-/Abwählen ",
            state.filtered_indices.len(),
            state.issues.len()
        );

        let issue_list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::CYAN))
                .title(list_title),
        );

        f.render_widget(issue_list, main_split[0]);
    }

    // Right Pane: Detailed Issue View
    if let Some(&orig_idx) = state.filtered_indices.get(state.selected_filtered_index) {
        let issue = &state.issues[orig_idx];

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
                Span::styled("    Modul: ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    issue.module_id.clone(),
                    Style::default().fg(Theme::TEXT_WHITE),
                ),
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

        if let Some(ref err) = issue.fix_error {
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(vec![
                Span::styled(
                    " ✖ Letzter Reparatur-Fehler: ",
                    Style::default()
                        .fg(Theme::CORAL)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(err.as_str(), Style::default().fg(Theme::CORAL)),
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

        f.render_widget(detail_box, main_split[1]);
    } else {
        let empty_detail =
            Paragraph::new("Kein Problem ausgewählt.").block(Theme::card_block("PROBLEM-DETAILS"));
        f.render_widget(empty_detail, main_split[1]);
    }
}

fn render_filter_bar(f: &mut Frame, area: Rect, state: &IssueListViewState) {
    let mut spans = vec![Span::styled(" Filter: ", Style::default().fg(Theme::MUTED))];

    // Severity pills
    let crit_active = state.severity_filter == Some(Severity::Critical);
    spans.push(Span::styled(
        " [c] 🔴 Kritisch ",
        if crit_active {
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::CORAL)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Theme::CORAL)
        },
    ));
    spans.push(Span::styled(" ", Style::default()));

    let warn_active = state.severity_filter == Some(Severity::Warning);
    spans.push(Span::styled(
        " [w] ▲ Warnung ",
        if warn_active {
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::AMBER)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Theme::AMBER)
        },
    ));
    spans.push(Span::styled(" ", Style::default()));

    let info_active = state.severity_filter == Some(Severity::Info);
    spans.push(Span::styled(
        " [i] ℹ Info ",
        if info_active {
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::CYAN)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Theme::CYAN)
        },
    ));
    spans.push(Span::styled(" │ ", Style::default().fg(Theme::BORDER)));

    // Module filter
    let mod_label = match state.module_filter {
        Some(m) => format!(" [m] Modul: {} ", m),
        None => " [m] Modul: Alle ".to_string(),
    };
    spans.push(Span::styled(
        mod_label,
        if state.module_filter.is_some() {
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::CYAN)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Theme::TEXT_WHITE)
        },
    ));
    spans.push(Span::styled(" │ ", Style::default().fg(Theme::BORDER)));

    // Search query
    let search_text = if state.is_searching {
        format!(" [/] 🔍 Suche: \"{}\"█ ", state.search_query)
    } else if !state.search_query.is_empty() {
        format!(" [/] 🔍 Suche: \"{}\" ", state.search_query)
    } else {
        " [/] 🔍 Suche ".to_string()
    };

    spans.push(Span::styled(
        search_text,
        if state.is_searching {
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::CYAN)
                .add_modifier(Modifier::BOLD)
        } else if !state.search_query.is_empty() {
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Theme::MUTED)
        },
    ));

    // Reset button hint if filters active
    let has_filter = state.severity_filter.is_some()
        || state.module_filter.is_some()
        || !state.search_query.is_empty();

    if has_filter {
        spans.push(Span::styled(" ", Style::default()));
        spans.push(Span::styled(
            " [x] Reset ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if state.is_searching {
            Theme::CYAN
        } else {
            Theme::BORDER
        }))
        .title(" FILTER & SUCHE ");

    let paragraph = Paragraph::new(Line::from(spans)).block(block);
    f.render_widget(paragraph, area);
}
