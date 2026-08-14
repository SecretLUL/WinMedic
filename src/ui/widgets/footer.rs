use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use crate::ui::theme::Theme;

pub fn render_footer(f: &mut Frame, area: Rect, active_tab_index: usize, status_msg: Option<&str>) {
    let key_hints = match active_tab_index {
        0 => vec![
            ("1-5", "Tabs"),
            ("S", "Start Full Scan"),
            ("A", "Auto-Fix"),
            ("?", "Help"),
            ("Q", "Exit"),
        ],
        1 => vec![
            ("1-5", "Tabs"),
            ("R", "Re-Scan"),
            ("Esc", "Stop"),
            ("?", "Help"),
            ("Q", "Exit"),
        ],
        2 => vec![
            ("↑/↓", "Navigate"),
            ("Space", "Toggle Select"),
            ("A", "Select All"),
            ("N", "Deselect All"),
            ("F", "Proceed to Fix"),
            ("?", "Help"),
            ("Q", "Exit"),
        ],
        3 => vec![
            ("F", "Execute Repairs"),
            ("R", "Re-Scan"),
            ("?", "Help"),
            ("Q", "Exit"),
        ],
        4 => vec![
            ("↑/↓", "Scroll"),
            ("R", "Refresh"),
            ("?", "Help"),
            ("Q", "Exit"),
        ],
        _ => vec![("1-5", "Tabs"), ("?", "Help"), ("Q", "Exit")],
    };

    let mut spans = Vec::new();
    spans.push(Span::styled(" ", Style::default()));

    for (key, desc) in key_hints {
        spans.push(Span::styled(
            format!(" [{}] ", key),
            Style::default().fg(Theme::CYAN).add_modifier(Modifier::BOLD),
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
            Style::default().fg(Theme::EMERALD).add_modifier(Modifier::BOLD),
        ));
    }

    let footer = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::BORDER)),
    );

    f.render_widget(footer, area);
}
