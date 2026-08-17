//! Tab 5 — "Settings & Safety".
//!
//! Two lists side by side: what WinMedic is configured to do (left) and what it
//! has already done, plus how to undo it (right). The `[B]` key decides which of
//! the two the arrow keys drive; [`SafetyPanelState::is_focused`] is what tells
//! the user which one that currently is.

use crate::config::AppConfig;
use crate::safety::audit::AuditEntry;
use crate::ui::theme::Theme;
use crate::ui::widgets::safety_panel::{SafetyPanelState, render_audit_log, render_safety_panel};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

pub struct SettingsViewState<'a> {
    pub config: &'a AppConfig,
    pub selected_setting_index: usize,
    pub dry_run: bool,
    pub audit_entries: &'a [AuditEntry],
    pub safety: SafetyPanelState<'a>,
    /// Where the audit log and the `.reg` snapshots are written.
    pub log_dir_path: &'a str,
}

pub fn render_settings(f: &mut Frame, area: Rect, state: &SettingsViewState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(8),    // Settings list | Backups & VSS
            Constraint::Length(8), // Selected setting | Recent actions
            Constraint::Length(5), // Storage locations & rollback hint
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(rows[0]);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(rows[1]);

    render_setting_list(
        f,
        top[0],
        state.config,
        state.selected_setting_index,
        !state.safety.is_focused,
    );
    render_safety_panel(f, top[1], &state.safety);
    render_description(
        f,
        middle[0],
        state.config,
        state.selected_setting_index,
        state.dry_run,
    );
    render_audit_log(f, middle[1], state.audit_entries, "RECENT ACTIONS");
    render_storage_locations(f, rows[2], state.log_dir_path);
}

/// The configuration list itself.
fn render_setting_list(
    f: &mut Frame,
    area: Rect,
    config: &AppConfig,
    selected_index: usize,
    is_focused: bool,
) {
    let mut items: Vec<ListItem> = Vec::new();
    for idx in 0..AppConfig::SETTING_COUNT {
        let Some((label, value, _)) = config.setting_row(idx) else {
            continue;
        };
        let is_current = idx == selected_index;

        let value_color = match value.as_str() {
            "ON" => Theme::EMERALD,
            "OFF" => Theme::CORAL,
            _ => Theme::CYAN,
        };

        // The cursor is only reverse-videoed while this list owns the arrow
        // keys; otherwise it is a dimmer marker that still shows where you were.
        let (marker, label_style) = match (is_current, is_focused) {
            (true, true) => (
                " > ",
                Style::default()
                    .fg(Theme::BG_DEEP)
                    .bg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            (true, false) => (
                " · ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            _ => ("   ", Style::default().fg(Theme::TEXT_WHITE)),
        };

        let line = Line::from(vec![
            Span::styled(
                marker,
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:<40}", label), label_style),
            Span::styled(
                format!("  {}", value),
                Style::default()
                    .fg(value_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        items.push(ListItem::new(line));
    }

    let border_color = if is_focused {
        Theme::CYAN
    } else {
        Theme::BORDER
    };
    let title = if is_focused {
        "SETTINGS  ◄ [↑/↓]"
    } else {
        "SETTINGS  ([B] to focus)"
    };

    let list = List::new(items)
        .block(Theme::card_block(title).border_style(Style::default().fg(border_color)));
    f.render_widget(list, area);
}

/// What the highlighted setting means, and whether repairs are simulated.
fn render_description(
    f: &mut Frame,
    area: Rect,
    config: &AppConfig,
    selected_index: usize,
    dry_run: bool,
) {
    let mut lines = Vec::new();
    if let Some((label, value, help)) = config.setting_row(selected_index) {
        lines.push(Line::from(vec![
            Span::styled(" Setting: ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                label,
                Style::default()
                    .fg(Theme::TEXT_WHITE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Current: ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                value,
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(vec![Span::styled(
            format!(" {}", help),
            Style::default().fg(Theme::MUTED),
        )]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Simulation mode [D]: ", Style::default().fg(Theme::MUTED)),
        if dry_run {
            Span::styled(
                "ON - repairs are only shown, never executed",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                "OFF - repairs really are executed",
                Style::default().fg(Theme::EMERALD),
            )
        },
    ]));

    let info_box = Paragraph::new(lines)
        .block(Theme::card_block("DESCRIPTION"))
        .wrap(Wrap { trim: false });
    f.render_widget(info_box, area);
}

/// Where settings, logs and backups live on disk, and how to roll back by hand.
fn render_storage_locations(f: &mut Frame, area: Rect, log_dir_path: &str) {
    // One path per line: side by side, two full `%APPDATA%` paths overrun even a
    // 120-column terminal and the second one gets cut off mid-directory.
    let lines = vec![
        Line::from(vec![
            Span::styled(
                "  Settings file:   ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                AppConfig::config_path().display().to_string(),
                Style::default().fg(Theme::EMERALD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  Logs & backups:  ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(log_dir_path, Style::default().fg(Theme::EMERALD)),
        ]),
        // The footer only advertises [R] while the backup pane holds focus, so
        // this line is what keeps the refresh discoverable from either side.
        Line::from(vec![
            Span::styled(
                "  Rollback: ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "[B] picks a snapshot, [U] restores it after confirming, [R] reloads. Or run 'reg import <file.reg>'.",
                Style::default().fg(Theme::MUTED),
            ),
        ]),
    ];

    let bottom_box = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::BORDER)),
    );

    f.render_widget(bottom_box, area);
}
