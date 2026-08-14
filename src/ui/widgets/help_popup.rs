use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

pub fn render_help_popup(f: &mut Frame, area: Rect) {
    let popup_width = 74.min(area.width.saturating_sub(4));
    let popup_height = 24.min(area.height.saturating_sub(4));

    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let text = vec![
        Line::from(vec![Span::styled(
            "  🩺 WinMedic – Keyboard Shortcuts & Guide",
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Navigation:",
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::UNDERLINED),
        )]),
        Line::from(vec![
            Span::styled(
                "    [1] - [5]         ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Zwischen den Tabs wechseln (Dashboard, Scan, Triage, Fix, Logs)",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [Tab]             ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Fokus zwischen Listen und Detail-Panels umschalten",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [↑] / [↓] / [j/k] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "In Listen und Protokollen navigieren",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Aktionen & Reparatur:",
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::UNDERLINED),
        )]),
        Line::from(vec![
            Span::styled(
                "    [S]               ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Gesamten System-Health-Scan starten",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [Space]           ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Ausgewähltes Problem für Reparatur an-/abwählen",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [A]               ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Alle sicheren Probleme auswählen (1-Klick Auto-Fix)",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [N]               ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Alle Probleme abwählen",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [F]               ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Reparatur-Center öffnen und ausgewählte Fixes anwenden",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [R]               ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Re-Scan ausführen / Ansicht aktualisieren",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Sicherheit:",
                Style::default()
                    .fg(Theme::EMERALD)
                    .add_modifier(Modifier::UNDERLINED),
            ),
            Span::styled(
                " Vor jedem Fix wird automatisch ein VSS Restore Point & Registry-Backup erstellt.",
                Style::default().fg(Theme::MUTED),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Drücken Sie [?] oder [Esc], um diese Hilfe zu schließen.",
            Style::default()
                .fg(Theme::MUTED)
                .add_modifier(Modifier::ITALIC),
        )]),
    ];

    let block = Block::default()
        .title(" HILFE & TASTENKÜRZEL ")
        .title_style(
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::CYAN));

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, popup_area);
}
