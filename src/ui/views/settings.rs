use crate::config::AppConfig;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph, Wrap};

pub fn render_settings(
    f: &mut Frame,
    area: Rect,
    config: &AppConfig,
    selected_index: usize,
    dry_run: bool,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(9), Constraint::Length(8)])
        .split(area);

    let mut items: Vec<ListItem> = Vec::new();
    for idx in 0..AppConfig::SETTING_COUNT {
        let Some((label, value, _)) = config.setting_row(idx) else {
            continue;
        };
        let is_current = idx == selected_index;

        let value_color = match value.as_str() {
            "AN" => Theme::EMERALD,
            "AUS" => Theme::CORAL,
            _ => Theme::CYAN,
        };

        let marker = if is_current { " ▶ " } else { "   " };
        let line = Line::from(vec![
            Span::styled(
                marker,
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:<44}", label),
                if is_current {
                    Style::default()
                        .fg(Theme::BG_DEEP)
                        .bg(Theme::CYAN)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Theme::TEXT_WHITE)
                },
            ),
            Span::styled(
                format!("  {}", value),
                Style::default()
                    .fg(value_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        items.push(ListItem::new(line));
    }

    let list = List::new(items).block(Theme::card_block(
        "EINSTELLUNGEN – [↑/↓] Auswahl  [Space/Enter] Umschalten  [←/→] Wert ändern",
    ));
    f.render_widget(list, chunks[0]);

    // Explanation of the highlighted setting plus the persistence location.
    let mut info_lines = Vec::new();
    if let Some((label, value, help)) = config.setting_row(selected_index) {
        info_lines.push(Line::from(vec![
            Span::styled(" Einstellung: ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                label,
                Style::default()
                    .fg(Theme::TEXT_WHITE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Aktuell: ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                value,
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        info_lines.push(Line::from(vec![Span::styled(
            format!(" {}", help),
            Style::default().fg(Theme::MUTED),
        )]));
    }

    info_lines.push(Line::from(""));
    info_lines.push(Line::from(vec![
        Span::styled(" Simulationsmodus [D]: ", Style::default().fg(Theme::MUTED)),
        if dry_run {
            Span::styled(
                "AN – Reparaturen werden nur angezeigt, nicht ausgeführt",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                "AUS – Reparaturen werden wirklich ausgeführt",
                Style::default().fg(Theme::EMERALD),
            )
        },
    ]));
    info_lines.push(Line::from(vec![
        Span::styled(" Gespeichert in: ", Style::default().fg(Theme::MUTED)),
        Span::styled(
            AppConfig::config_path().display().to_string(),
            Style::default().fg(Theme::EMERALD),
        ),
    ]));
    info_lines.push(Line::from(vec![Span::styled(
        " Änderungen werden sofort gespeichert und gelten ab dem nächsten Scan.",
        Style::default()
            .fg(Theme::MUTED)
            .add_modifier(Modifier::ITALIC),
    )]));

    let info_box = Paragraph::new(info_lines)
        .block(Theme::card_block("BESCHREIBUNG"))
        .wrap(Wrap { trim: true });
    f.render_widget(info_box, chunks[1]);
}
