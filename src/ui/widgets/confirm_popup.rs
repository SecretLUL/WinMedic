use crate::app::ConfirmRequest;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

/// Modal shown before an action that changes the system without a prior scan.
pub fn render_confirm_popup(f: &mut Frame, area: Rect, request: &ConfirmRequest) {
    let body = request.body();

    let popup_width = 86.min(area.width.saturating_sub(4));
    let popup_height = (body.len() as u16 + 8).min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let mut lines = vec![Line::from("")];
    for text in body {
        lines.push(Line::from(vec![Span::styled(
            format!("  {}", text),
            Style::default().fg(Theme::TEXT_WHITE),
        )]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            " [Y] / [Enter] ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}    ", request.confirm_label()),
            Style::default().fg(Theme::TEXT_WHITE),
        ),
        Span::styled(
            " [N] / [Esc] ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::EMERALD)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}", request.dismiss_label()),
            Style::default().fg(Theme::TEXT_WHITE),
        ),
    ]));

    let block = Block::default()
        .title(format!(" [!] {} ", request.title()))
        .title_style(
            Style::default()
                .fg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::AMBER));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, popup_area);
}
