use crate::app::{TAB_DASHBOARD, TAB_HISTORY, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS, TAB_TRIAGE};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn render_footer(
    f: &mut Frame,
    area: Rect,
    active_tab_index: usize,
    status_msg: Option<&str>,
    is_busy: bool,
    dry_run: bool,
) {
    // While something is running, Esc is the key that matters most.
    let key_hints: Vec<(&str, &str)> = if is_busy {
        vec![
            ("Esc", "Abbrechen"),
            ("1-6", "Tabs"),
            ("?", "Hilfe"),
            ("Q", "Beenden"),
        ]
    } else {
        match active_tab_index {
            TAB_DASHBOARD => vec![
                ("1-6", "Tabs"),
                ("S", "Scan starten"),
                ("D", "Simulation"),
                ("?", "Hilfe"),
                ("Q", "Beenden"),
            ],
            TAB_SCANNER => vec![
                ("1-6", "Tabs"),
                ("R", "Erneut scannen"),
                ("?", "Hilfe"),
                ("Q", "Beenden"),
            ],
            TAB_TRIAGE => vec![
                ("↑/↓", "Navigieren"),
                ("Space", "An-/Abwählen"),
                ("A", "Alle"),
                ("N", "Keine"),
                ("D", "Simulation"),
                ("F", "Reparieren"),
                ("E", "Bericht"),
                ("Q", "Beenden"),
            ],
            TAB_REPAIR => vec![
                ("F", "Reparaturen ausführen"),
                ("D", "Simulation"),
                ("E", "Bericht"),
                ("R", "Erneut scannen"),
                ("?", "Hilfe"),
                ("Q", "Beenden"),
            ],
            TAB_HISTORY => vec![
                ("↑/↓", "Sicherung wählen"),
                ("U", "Rollback"),
                ("E", "Bericht"),
                ("R", "Aktualisieren"),
                ("?", "Hilfe"),
                ("Q", "Beenden"),
            ],
            TAB_SETTINGS => vec![
                ("↑/↓", "Auswahl"),
                ("Space", "Umschalten"),
                ("←/→", "Wert ändern"),
                ("?", "Hilfe"),
                ("Q", "Beenden"),
            ],
            _ => vec![("1-6", "Tabs"), ("?", "Hilfe"), ("Q", "Beenden")],
        }
    };

    let mut spans = vec![Span::styled(" ", Style::default())];

    if dry_run {
        spans.push(Span::styled(
            " SIMULATION ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(" ", Style::default()));
    }

    for (key, desc) in key_hints {
        spans.push(Span::styled(
            format!(" [{}] ", key),
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!("{}  ", desc),
            Style::default().fg(Theme::TEXT_WHITE),
        ));
    }

    if let Some(msg) = status_msg {
        spans.push(Span::styled(" │ ", Style::default().fg(Theme::BORDER)));
        spans.push(Span::styled(
            msg,
            Style::default()
                .fg(Theme::EMERALD)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let footer = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::BORDER)),
    );

    f.render_widget(footer, area);
}
