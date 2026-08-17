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
            ("[←]/[→] or [h]/[l]", "Switch tab (BIOS-style navigation)"),
            (
                "[1] - [5]",
                "Jump directly to tab (Dashboard, Scan, Triage, Repair, Settings & Safety)",
            ),
            (
                "[Tab] / [Shift+Tab]",
                "Cycle forwards / backwards through tabs",
            ),
            ("[↑]/[↓] or [j]/[k]", "Navigate lists / items"),
            ("[U]", "Show available update (outside tab 5)"),
            ("[Esc]", "Back to dashboard"),
        ],
    ),
    (
        "Scan & Repair",
        &[
            ("[S] / [R]", "Start or repeat the system health scan"),
            ("[F]", "Run the selected repairs"),
            ("[D]", "Simulation mode - shows steps, changes nothing"),
            ("[PgUp] / [PgDn]", "Scroll the live log up / down"),
            (
                "[Home] / [End]",
                "Jump to the top of the log / back to the live tail",
            ),
            ("[E]", "Export the diagnostic report as HTML"),
            ("[Esc]", "Cancel a running scan or repair"),
        ],
    ),
    (
        "Issue Triage & Filters (tab 3)",
        &[
            (
                "[c] / [w] / [i]",
                "Filter by severity (critical / warning / info)",
            ),
            ("[m]", "Filter by diagnostic module (cycles through)"),
            ("[/]", "Search findings and details full-text"),
            ("[x]", "Clear all active filters and the search"),
            ("[Space]", "Select / deselect an issue for repair"),
            ("[A] / [N]", "Select / deselect every visible issue"),
        ],
    ),
    (
        "Settings & Safety (tab 5)",
        &[
            (
                "[Enter]",
                "Open custom value input dialog (or toggle switch)",
            ),
            ("[Space]", "Toggle a switch or step numeric value (+Step)"),
            (
                "[+] / [-] or [[]/[]]",
                "Increase / decrease a numeric value",
            ),
            (
                "[B]",
                "Move [↑]/[↓] between the settings and the backup list",
            ),
            ("[U]", "Restore the selected .reg backup, after confirming"),
            ("[R]", "Reload the restore points, backups and audit log"),
        ],
    ),
];

pub fn render_help_popup(f: &mut Frame, area: Rect) {
    let mut text: Vec<Line> = vec![
        Line::from(vec![Span::styled(
            format!(
                "  WinMedic v{} - Keyboard Shortcuts",
                env!("CARGO_PKG_VERSION")
            ),
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    for (heading, entries) in SECTIONS {
        text.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                format!("{}:", heading),
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        for (key, desc) in *entries {
            text.push(Line::from(vec![
                Span::styled(
                    format!("    {:<26} ", key),
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
        Span::styled("  ", Style::default()),
        Span::styled(
            "Safety:",
            Style::default()
                .fg(Theme::EMERALD)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " VSS restore points, registry backups and the rollback all live in tab [5].",
            Style::default().fg(Theme::MUTED),
        ),
    ]));
    text.push(Line::from(""));
    text.push(Line::from(vec![Span::styled(
        "  Press [?] or [Esc] to close this help.",
        Style::default()
            .fg(Theme::MUTED)
            .add_modifier(Modifier::ITALIC),
    )]));

    let popup_width = 88.min(area.width.saturating_sub(4));
    let popup_height = (text.len() as u16 + 2).min(area.height.saturating_sub(2));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(" HELP & KEYBOARD SHORTCUTS ")
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
