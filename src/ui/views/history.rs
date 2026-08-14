use crate::safety::audit::AuditEntry;
use crate::safety::reg_backup::BackupRecord;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

pub fn render_history(
    f: &mut Frame,
    area: Rect,
    audit_entries: &[AuditEntry],
    backup_records: &[BackupRecord],
    vss_restore_points: &[String],
    log_dir_path: &str,
) {
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
    let audit_items: Vec<ListItem> = audit_entries
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

    let audit_list =
        List::new(audit_items).block(Theme::card_block("AUDIT-LOG & DURCHGEFÜHRTE AKTIONEN"));
    f.render_widget(audit_list, main_split[0]);

    // Right Pane: Registry Backups & VSS Points
    let mut backup_lines = vec![Line::from(vec![Span::styled(
        " 🛡 Systemwiederherstellungspunkte (VSS):",
        Style::default()
            .fg(Theme::CYAN)
            .add_modifier(Modifier::BOLD),
    )])];

    if vss_restore_points.is_empty() {
        backup_lines.push(Line::from(vec![Span::styled(
            "   (Keine vorherigen VSS-Restore-Points abgefragt)",
            Style::default().fg(Theme::MUTED),
        )]));
    } else {
        for rp in vss_restore_points.iter().take(5) {
            backup_lines.push(Line::from(vec![
                Span::styled("   ✔ ", Style::default().fg(Theme::EMERALD)),
                Span::styled(rp.as_str(), Style::default().fg(Theme::TEXT_WHITE)),
            ]));
        }
    }

    backup_lines.push(Line::from(""));
    backup_lines.push(Line::from(vec![Span::styled(
        " 🗄 Gespeicherte Registry-Snapshots (.reg):",
        Style::default()
            .fg(Theme::CYAN)
            .add_modifier(Modifier::BOLD),
    )]));

    if backup_records.is_empty() {
        backup_lines.push(Line::from(vec![Span::styled(
            "   (Bisher keine Registry-Modifikationen mit Backup)",
            Style::default().fg(Theme::MUTED),
        )]));
    } else {
        for rec in backup_records.iter().rev().take(6) {
            backup_lines.push(Line::from(vec![
                Span::styled("   📦 ", Style::default().fg(Theme::AMBER)),
                Span::styled(
                    format!("[{}] ", rec.timestamp),
                    Style::default().fg(Theme::MUTED),
                ),
                Span::styled(
                    rec.description.clone(),
                    Style::default().fg(Theme::TEXT_WHITE),
                ),
            ]));
            backup_lines.push(Line::from(vec![Span::styled(
                format!("      Pfad: {}", rec.file_path),
                Style::default().fg(Theme::MUTED),
            )]));
        }
    }

    let backup_box = Paragraph::new(backup_lines)
        .block(Theme::card_block("SICHERUNGEN & WIEDERHERSTELLUNG"))
        .wrap(Wrap { trim: true });

    f.render_widget(backup_box, main_split[1]);

    // Bottom Pane: Log Path Information
    let bottom_text = vec![
        Line::from(vec![
            Span::styled(
                "  Speicherort für Logs & Backups: ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(log_dir_path, Style::default().fg(Theme::EMERALD)),
        ]),
        Line::from(vec![
            Span::styled(
                "  Rollback-Tipp: ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Um eine Registry-Sicherung wiederherzustellen, doppelklicken Sie auf die entsprechende .reg-Datei oder führen Sie 'reg import <datei.reg>' aus.",
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
