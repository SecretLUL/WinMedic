use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

/// A section heading followed by its `(key, description)` pairs.
type Section = (&'static str, &'static [(&'static str, &'static str)]);

const SECTIONS: &[Section] = &[
    (
        "Navigation",
        &[
            (
                "[1] - [6]",
                "Tab wechseln (Dashboard, Scan, Triage, Fix, Logs, Einstellungen)",
            ),
            ("[Tab] / [Shift+Tab]", "Vorwärts / rückwärts durch die Tabs"),
            ("[↑]/[↓] oder [j]/[k]", "In Listen navigieren"),
            ("[Esc]", "Zurück zum Dashboard"),
        ],
    ),
    (
        "Scan & Reparatur",
        &[
            ("[S] / [R]", "System-Health-Scan starten bzw. wiederholen"),
            ("[F]", "Ausgewählte Reparaturen ausführen"),
            ("[D]", "Simulationsmodus – zeigt Schritte, ändert nichts"),
            (
                "[PgUp] / [PgDn]",
                "Live-Log/Terminal nach oben/unten scrollen",
            ),
            (
                "[Home] / [End]",
                "Zum Log-Anfang / zurück zum Live-Tail springen",
            ),
            ("[E]", "Diagnosebericht als HTML exportieren"),
            ("[Esc]", "Laufenden Scan oder Reparaturlauf abbrechen"),
        ],
    ),
    (
        "Problem-Triage & Filter (Tab 3)",
        &[
            (
                "[c] / [w] / [i]",
                "Nach Schweregrad filtern (Kritisch / Warnung / Info)",
            ),
            ("[m]", "Nach Diagnose-Modul filtern (durchschalten)"),
            ("[/]", "Volltextsuche in Befunden & Details starten"),
            ("[x]", "Alle aktiven Filter & Suche zurücksetzen"),
            ("[Space]", "Problem für Reparatur an-/abwählen"),
            ("[A] / [N]", "Alle sichtbaren Probleme aus-/abwählen"),
        ],
    ),
    (
        "Sicherungen & Rollback (Tab 5)",
        &[
            ("[↑]/[↓]", "Registry-Sicherung auswählen"),
            (
                "[U]",
                "Markierte .reg-Sicherung nach Rückfrage zurückspielen",
            ),
            ("[R]", "Wiederherstellungspunkte & Log neu laden"),
        ],
    ),
    (
        "Einstellungen (Tab 6)",
        &[
            ("[Space] / [Enter]", "Schalter umlegen"),
            ("[←] / [→]", "Zahlenwert verringern / erhöhen"),
        ],
    ),
];

pub fn render_help_popup(f: &mut Frame, area: Rect) {
    let mut text: Vec<Line> = vec![
        Line::from(vec![Span::styled(
            format!(
                "  🩺 WinMedic v{} – Tastenkürzel",
                env!("CARGO_PKG_VERSION")
            ),
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    for (heading, entries) in SECTIONS {
        text.push(Line::from(vec![Span::styled(
            format!("  {}:", heading),
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::UNDERLINED),
        )]));
        for (key, desc) in *entries {
            text.push(Line::from(vec![
                Span::styled(
                    format!("    {:<22}", key),
                    Style::default()
                        .fg(Theme::AMBER)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(*desc, Style::default().fg(Theme::TEXT_WHITE)),
            ]));
        }
        text.push(Line::from(""));
    }

    text.push(Line::from(vec![
        Span::styled(
            "  Sicherheit:",
            Style::default()
                .fg(Theme::EMERALD)
                .add_modifier(Modifier::UNDERLINED),
        ),
        Span::styled(
            " VSS-Wiederherstellungspunkt und Registry-Backup sind in Tab [6] konfigurierbar.",
            Style::default().fg(Theme::MUTED),
        ),
    ]));
    text.push(Line::from(""));
    text.push(Line::from(vec![Span::styled(
        "  Drücken Sie [?] oder [Esc], um diese Hilfe zu schließen.",
        Style::default()
            .fg(Theme::MUTED)
            .add_modifier(Modifier::ITALIC),
    )]));

    let popup_width = 86.min(area.width.saturating_sub(4));
    let popup_height = (text.len() as u16 + 2).min(area.height.saturating_sub(2));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

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
