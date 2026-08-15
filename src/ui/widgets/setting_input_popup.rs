use crate::app::state::SettingInput;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

/// Modal shown when editing a numeric setting threshold via direct input.
pub fn render_setting_input_popup(f: &mut Frame, area: Rect, input: &SettingInput) {
    let popup_width = 68.min(area.width.saturating_sub(4));
    let popup_height = 11.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let display_buffer = format!("{}_", input.buffer);

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Setting: ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                &input.setting_name,
                Style::default()
                    .fg(Theme::TEXT_WHITE)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Unit:    ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                format!(
                    "{} (Range: {} - {})",
                    input.unit, input.min_value, input.max_value
                ),
                Style::default().fg(Theme::CYAN),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Value:   [ ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                format!("{:<16}", display_buffer),
                Style::default()
                    .fg(Theme::BG_DEEP)
                    .bg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" ]", Style::default().fg(Theme::MUTED)),
        ]),
    ];

    if let Some(err) = &input.error_msg {
        lines.push(Line::from(vec![
            Span::styled(
                "  [!] ",
                Style::default()
                    .fg(Theme::CORAL)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(err, Style::default().fg(Theme::CORAL)),
        ]));
    } else {
        lines.push(Line::from(""));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            " [Enter] ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::EMERALD)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Save    ", Style::default().fg(Theme::TEXT_WHITE)),
        Span::styled(
            " [Esc] ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::CORAL)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Cancel    ", Style::default().fg(Theme::TEXT_WHITE)),
        Span::styled(
            " [Bksp] ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Delete", Style::default().fg(Theme::TEXT_WHITE)),
    ]));

    let block = Block::default()
        .title(" EDIT SETTING VALUE ")
        .title_style(
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::CYAN));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, popup_area);
}
