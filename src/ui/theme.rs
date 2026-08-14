use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders};

pub struct Theme;

impl Theme {
    // Cyber-Medic / Dark Slate Color Palette
    pub const CYAN: Color = Color::Rgb(0, 210, 255);       // #00D2FF Primary Brand
    pub const EMERALD: Color = Color::Rgb(16, 185, 129);   // #10B981 Success / Healthy
    pub const AMBER: Color = Color::Rgb(245, 158, 11);     // #F59E0B Warning
    pub const CORAL: Color = Color::Rgb(239, 68, 68);      // #EF4444 Critical / Error
    pub const BG_DEEP: Color = Color::Rgb(15, 23, 42);     // #0F172A Terminal Background
    pub const CARD_SURFACE: Color = Color::Rgb(30, 41, 59);// #1E293B Card / Box Surface
    pub const BORDER: Color = Color::Rgb(71, 85, 105);     // #475569 Borders & Inactive
    pub const MUTED: Color = Color::Rgb(148, 163, 184);    // #94A3B8 Muted Text
    pub const TEXT_WHITE: Color = Color::Rgb(248, 250, 252);// Bright White Text
    pub const ACCENT_PURPLE: Color = Color::Rgb(168, 85, 247);

    // Styles
    pub fn title_style() -> Style {
        Style::default().fg(Self::CYAN).add_modifier(Modifier::BOLD)
    }

    pub fn active_tab_style() -> Style {
        Style::default()
            .fg(Self::TEXT_WHITE)
            .bg(Self::CYAN)
            .add_modifier(Modifier::BOLD)
    }

    pub fn inactive_tab_style() -> Style {
        Style::default().fg(Self::MUTED)
    }

    pub fn card_block(title: &str) -> Block<'static> {
        Block::default()
            .title(format!(" {} ", title))
            .title_style(Self::title_style())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Self::BORDER))
    }

    pub fn focused_block(title: &str) -> Block<'static> {
        Block::default()
            .title(format!(" {} ", title))
            .title_style(Style::default().fg(Self::CYAN).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Self::CYAN))
    }

    pub fn critical_style() -> Style {
        Style::default().fg(Self::CORAL).add_modifier(Modifier::BOLD)
    }

    pub fn warning_style() -> Style {
        Style::default().fg(Self::AMBER).add_modifier(Modifier::BOLD)
    }

    pub fn success_style() -> Style {
        Style::default().fg(Self::EMERALD).add_modifier(Modifier::BOLD)
    }

    pub fn info_style() -> Style {
        Style::default().fg(Self::CYAN)
    }

    pub fn muted_style() -> Style {
        Style::default().fg(Self::MUTED)
    }
}
