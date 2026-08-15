use crate::safety::audit::AuditEntry;
use crate::safety::reg_backup::BackupRecord;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

pub struct HistoryViewState<'a> {
    pub audit_entries: &'a [AuditEntry],
    /// Backup records, newest first — the order shown and selected against.
    pub backup_records: &'a [&'a BackupRecord],
    pub selected_backup_index: usize,
    pub vss_restore_points: &'a [String],
    pub restore_points_loading: bool,
    pub is_restoring: bool,
    pub log_dir_path: &'a str,
}

pub fn render_history(f: &mut Frame, area: Rect, state: &HistoryViewState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(12),   // Split: Audit Log & Backups/VSS List
            Constraint::Length(4), // Log Path & Rollback Instructions
        ])
        .split(area);

    let main_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[0]);

    // Left Pane: Audit History List
    let audit_items: Vec<ListItem> = state
        .audit_entries
        .iter()
        .rev()
        .take(25)
        .map(|entry| {
            let (status_icon, status_color) = match entry.status.as_str() {
                "SUCCESS" => ("✔", Theme::EMERALD),
                "FAILED" => ("✖", Theme::CORAL),
                "WARNING" => ("▲", Theme::AMBER),
                _ => ("ℹ", Theme::CYAN),
            };

            let line = Line::from(vec![
                Span::styled(
                    format!("[{}] ", entry.timestamp),
                    Style::default().fg(Theme::MUTED),
                ),
                Span::styled(
                    format!("[{}] ", entry.action_type),
                    Style::default()
                        .fg(Theme::CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} ", status_icon),
                    Style::default()
                        .fg(status_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(entry.title.clone(), Style::default().fg(Theme::TEXT_WHITE)),
            ]);

            ListItem::new(line)
        })
        .collect();

    let audit_list = List::new(audit_items).block(Theme::card_block("AUDIT LOG & ACTIONS TAKEN"));
    f.render_widget(audit_list, main_split[0]);

    // Right Pane: Registry Backups & VSS Points
    let mut backup_lines = vec![Line::from(vec![Span::styled(
        " 🛡 System restore points (VSS):",
        Style::default()
            .fg(Theme::CYAN)
            .add_modifier(Modifier::BOLD),
    )])];

    if state.restore_points_loading {
        backup_lines.push(Line::from(vec![Span::styled(
            "   ⏳ Querying Windows restore points...",
            Style::default().fg(Theme::AMBER),
        )]));
    } else if state.vss_restore_points.is_empty() {
        backup_lines.push(Line::from(vec![Span::styled(
            "   (No restore points found - [R] refreshes)",
            Style::default().fg(Theme::MUTED),
        )]));
    } else {
        for rp in state.vss_restore_points.iter().take(5) {
            backup_lines.push(Line::from(vec![
                Span::styled("   ✔ ", Style::default().fg(Theme::EMERALD)),
                Span::styled(rp.as_str(), Style::default().fg(Theme::TEXT_WHITE)),
            ]));
        }
    }

    backup_lines.push(Line::from(""));
    backup_lines.push(Line::from(vec![Span::styled(
        " 🗄 Saved registry snapshots (.reg):",
        Style::default()
            .fg(Theme::CYAN)
            .add_modifier(Modifier::BOLD),
    )]));

    if state.backup_records.is_empty() {
        backup_lines.push(Line::from(vec![Span::styled(
            "   (No backed-up registry modifications yet)",
            Style::default().fg(Theme::MUTED),
        )]));
    } else {
        // Only a handful of entries fit; scroll the window so the selected
        // backup stays visible even with a long backup history.
        const VISIBLE: usize = 6;
        let offset = state
            .selected_backup_index
            .saturating_sub(VISIBLE - 1)
            .min(state.backup_records.len().saturating_sub(VISIBLE));

        if offset > 0 {
            backup_lines.push(Line::from(vec![Span::styled(
                format!("   ↑ {} newer backup(s)", offset),
                Style::default().fg(Theme::MUTED),
            )]));
        }

        for (idx, rec) in state
            .backup_records
            .iter()
            .enumerate()
            .skip(offset)
            .take(VISIBLE)
        {
            let is_current = idx == state.selected_backup_index;
            let (marker, title_style) = if is_current {
                (
                    " ▶ ",
                    Style::default()
                        .fg(Theme::BG_DEEP)
                        .bg(Theme::CYAN)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                ("   ", Style::default().fg(Theme::TEXT_WHITE))
            };

            backup_lines.push(Line::from(vec![
                Span::styled(marker, Style::default().fg(Theme::CYAN)),
                Span::styled("📦 ", Style::default().fg(Theme::AMBER)),
                Span::styled(
                    format!("[{}] ", rec.timestamp),
                    Style::default().fg(Theme::MUTED),
                ),
                Span::styled(rec.description.clone(), title_style),
            ]));
            backup_lines.push(Line::from(vec![Span::styled(
                format!("      {}", rec.key_path),
                Style::default().fg(Theme::MUTED),
            )]));
        }
    }

    let backup_title = if state.is_restoring {
        "BACKUPS - ⏳ ROLLBACK RUNNING..."
    } else {
        "BACKUPS - [↑/↓] Select  [U] Rollback  [R] Refresh VSS"
    };

    let backup_box = Paragraph::new(backup_lines)
        .block(Theme::card_block(backup_title))
        .wrap(Wrap { trim: true });

    f.render_widget(backup_box, main_split[1]);

    // Bottom Pane: Log Path Information
    let bottom_text = vec![
        Line::from(vec![
            Span::styled(
                "  Location for logs & backups: ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(state.log_dir_path, Style::default().fg(Theme::EMERALD)),
        ]),
        Line::from(vec![
            Span::styled(
                "  Rollback: ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "[U] restores the selected .reg backup after confirming. Alternatively run 'reg import <file.reg>'.",
                Style::default().fg(Theme::MUTED),
            ),
        ]),
    ];

    let bottom_box = Paragraph::new(bottom_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::BORDER)),
    );

    f.render_widget(bottom_box, chunks[1]);
}
