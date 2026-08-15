use crate::ui::theme::Theme;
use crate::utils::hardware::SystemTelemetry;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};

// Ratatui render functions receive the slice of app state they draw. Passing
// `&App` instead would couple every widget to the whole application struct, so
// the long signature is the deliberate trade-off.
#[allow(clippy::too_many_arguments)]
pub fn render_header(
    f: &mut Frame,
    area: Rect,
    active_tab_index: usize,
    telemetry: Option<&SystemTelemetry>,
    is_admin: bool,
    issue_count: usize,
    is_scanning: bool,
    dry_run: bool,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3)])
        .split(area);

    // Top System Bar
    let (cpu_str, ram_str, os_str) = if let Some(t) = telemetry {
        (
            format!("CPU: {:.1}%", t.cpu_usage),
            format!(
                "RAM: {:.1}/{:.1}GB",
                (t.ram_used_mb as f32 / 1024.0),
                (t.ram_total_mb as f32 / 1024.0)
            ),
            format!("{} {}", t.os_name, t.os_version),
        )
    } else {
        (
            "CPU: --%".to_string(),
            "RAM: --/--GB".to_string(),
            "Windows".to_string(),
        )
    };

    let admin_badge = if is_admin {
        Span::styled(
            " [ADMIN: YES] ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::EMERALD)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " [ADMIN: NO] ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::CORAL)
                .add_modifier(Modifier::BOLD),
        )
    };

    let mode_badge = if dry_run {
        Span::styled(
            " [SIMULATION] ",
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("", Style::default())
    };

    let top_line = Line::from(vec![
        Span::styled(
            format!(" 🩺 WinMedic v{} ", env!("CARGO_PKG_VERSION")),
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("─ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            "Windows Self-Healing Engine ",
            Style::default().fg(Theme::MUTED),
        ),
        mode_badge,
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" {} ", cpu_str),
            Style::default().fg(Theme::TEXT_WHITE),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" {} ", ram_str),
            Style::default().fg(Theme::TEXT_WHITE),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" {} ", os_str),
            Style::default().fg(Theme::TEXT_WHITE),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(" VSS: Ready ", Style::default().fg(Theme::EMERALD)),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        admin_badge,
    ]);

    let top_bar = Paragraph::new(top_line)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::BORDER)),
        )
        .alignment(Alignment::Left);

    f.render_widget(top_bar, chunks[0]);

    // Navigation Tabs
    let scan_indicator = if is_scanning { " (● Scan...)" } else { "" };
    let triage_badge = if issue_count > 0 {
        format!(" [{}]", issue_count)
    } else {
        "".to_string()
    };

    let tab_titles = vec![
        " [1] Dashboard ".to_string(),
        format!(" [2] Health Scan{} ", scan_indicator),
        format!(" [3] Issue Triage{} ", triage_badge),
        " [4] Repair Center ".to_string(),
        " [5] Backups & Logs ".to_string(),
        " [6] Settings ".to_string(),
    ];

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .title(" ◄ [←/→] Tabs ► ")
                .title_alignment(Alignment::Right)
                .title_style(
                    Style::default()
                        .fg(Theme::CYAN)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::CYAN)),
        )
        .select(active_tab_index)
        .style(Style::default().fg(Theme::MUTED))
        .highlight_style(
            Style::default()
                .fg(Theme::BG_DEEP)
                .bg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");

    f.render_widget(tabs, chunks[1]);
}
