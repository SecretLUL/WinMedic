use crate::app::{TAB_DASHBOARD, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS, TAB_TRIAGE};
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
    // Which of the two lists on the Settings & Safety tab owns the arrow keys.
    backups_focused: bool,
) {
    // While something is running, Esc is the key that matters most.
    let key_hints: Vec<(&str, &str)> = if is_busy {
        vec![
            ("Esc", "Cancel"),
            ("←/→", "Tabs"),
            ("?", "Help"),
            ("Q", "Quit"),
        ]
    } else {
        match active_tab_index {
            TAB_DASHBOARD => vec![
                ("←/→", "Tabs"),
                ("D", "Simulate"),
                ("?", "Help"),
                ("Q", "Quit"),
            ],
            TAB_SCANNER => vec![
                ("←/→", "Tabs"),
                ("PgUp/Dn", "Scroll"),
                ("R", "Scan"),
                ("?", "Help"),
                ("Q", "Quit"),
            ],
            TAB_TRIAGE => vec![
                ("←/→", "Tabs"),
                ("↑/↓", "Select"),
                ("Space", "On/Off"),
                ("C/W/I", "Filter"),
                ("/", "Search"),
                ("F", "Repair"),
                ("E", "Report"),
                ("?", "Help"),
                ("Q", "Quit"),
            ],
            TAB_REPAIR => vec![
                ("←/→", "Tabs"),
                ("F", "Start"),
                ("PgUp/Dn", "Scroll"),
                ("D", "Simulate"),
                ("E", "Report"),
                ("?", "Help"),
                ("Q", "Quit"),
            ],
            // One tab, two lists: the hints follow whichever one has the arrows.
            TAB_SETTINGS if backups_focused => vec![
                ("←/→", "Tabs"),
                ("↑/↓", "Select Backup"),
                ("U", "Rollback"),
                ("R", "Refresh VSS"),
                ("B/Esc", "Settings"),
                ("?", "Help"),
                ("Q", "Quit"),
            ],
            TAB_SETTINGS => vec![
                ("←/→", "Tabs"),
                ("↑/↓", "Select"),
                ("Space/Enter", "Toggle"),
                ("+/-", "Value"),
                ("B", "Backups"),
                ("?", "Help"),
                ("Q", "Quit"),
            ],
            _ => vec![("←/→", "Tabs"), ("?", "Help"), ("Q", "Quit")],
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
