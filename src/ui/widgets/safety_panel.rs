//! The safety surface: VSS restore points, registry snapshots and the audit log.
//!
//! These three panes used to be a tab of their own ("Backups & Logs"). They are
//! widgets rather than a view because the Settings & Safety tab now composes
//! them next to the configuration list, and the dashboard renders the audit
//! summary on its own.

use crate::safety::audit::AuditEntry;
use crate::safety::reg_backup::BackupRecord;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph, Wrap};

pub struct SafetyPanelState<'a> {
    /// Backup records, newest first — the order shown and selected against.
    pub backup_records: &'a [&'a BackupRecord],
    pub selected_backup_index: usize,
    pub vss_restore_points: &'a [String],
    pub restore_points_loading: bool,
    pub is_restoring: bool,
    /// True while `↑`/`↓` drive the backup list rather than the settings list.
    pub is_focused: bool,
}

/// How many backup records fit in the pane before it starts scrolling.
const VISIBLE_BACKUPS: usize = 5;

/// How many VSS restore points to list before collapsing the rest into a count.
const VISIBLE_RESTORE_POINTS: usize = 2;

/// Restore points and registry snapshots, with the `[U]` rollback target marked.
pub fn render_safety_panel(f: &mut Frame, area: Rect, state: &SafetyPanelState) {
    let mut lines = vec![Line::from(vec![Span::styled(
        " System restore points (VSS):",
        Style::default()
            .fg(Theme::CYAN)
            .add_modifier(Modifier::BOLD),
    )])];

    if state.restore_points_loading {
        lines.push(Line::from(vec![Span::styled(
            "   Querying Windows restore points...",
            Style::default().fg(Theme::AMBER),
        )]));
    } else if state.vss_restore_points.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "   (No restore points found - [R] refreshes)",
            Style::default().fg(Theme::MUTED),
        )]));
    } else {
        // Deliberately short. Restore points are read-only context; the
        // snapshot list below is the part the user can act on, and on an 80
        // column terminal a long VSS list pushes it off the pane entirely.
        for rp in state.vss_restore_points.iter().take(VISIBLE_RESTORE_POINTS) {
            lines.push(Line::from(vec![
                Span::styled("   [OK] ", Style::default().fg(Theme::EMERALD)),
                Span::styled(rp.as_str(), Style::default().fg(Theme::TEXT_WHITE)),
            ]));
        }
        if let Some(hidden) = state
            .vss_restore_points
            .len()
            .checked_sub(VISIBLE_RESTORE_POINTS)
            .filter(|n| *n > 0)
        {
            lines.push(Line::from(vec![Span::styled(
                format!("   + {} more restore point(s)", hidden),
                Style::default().fg(Theme::MUTED),
            )]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        " Saved registry snapshots (.reg):",
        Style::default()
            .fg(Theme::CYAN)
            .add_modifier(Modifier::BOLD),
    )]));

    if state.backup_records.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "   (No backed-up registry modifications yet)",
            Style::default().fg(Theme::MUTED),
        )]));
    } else {
        // Only a handful of entries fit; scroll the window so the selected
        // backup stays visible even with a long backup history.
        let offset = state
            .selected_backup_index
            .saturating_sub(VISIBLE_BACKUPS - 1)
            .min(state.backup_records.len().saturating_sub(VISIBLE_BACKUPS));

        if offset > 0 {
            lines.push(Line::from(vec![Span::styled(
                format!("   ↑ {} newer backup(s)", offset),
                Style::default().fg(Theme::MUTED),
            )]));
        }

        for (idx, rec) in state
            .backup_records
            .iter()
            .enumerate()
            .skip(offset)
            .take(VISIBLE_BACKUPS)
        {
            // The cursor is only highlighted while this pane owns the arrow
            // keys. A reverse-video row on an unfocused list reads as "this is
            // what [U] will restore right now", which is only true after [B].
            let is_current = idx == state.selected_backup_index;
            let (marker, title_style) = match (is_current, state.is_focused) {
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

            lines.push(Line::from(vec![
                Span::styled(marker, Style::default().fg(Theme::CYAN)),
                Span::styled("[REG] ", Style::default().fg(Theme::AMBER)),
                Span::styled(
                    format!("[{}] ", rec.timestamp),
                    Style::default().fg(Theme::MUTED),
                ),
                Span::styled(rec.description.clone(), title_style),
            ]));
            lines.push(Line::from(vec![Span::styled(
                format!("      {}", rec.key_path),
                Style::default().fg(Theme::MUTED),
            )]));
        }
    }

    // The full key list lives in the footer; the title only has to say which
    // pane the arrows are pointed at. Spelling out [U]/[R] here too made the
    // title longer than the pane at 120 columns, so it clipped mid-word.
    let title = if state.is_restoring {
        "BACKUPS & VSS - ROLLBACK RUNNING..."
    } else if state.is_focused {
        "BACKUPS & VSS  ◄ [↑/↓]"
    } else {
        "BACKUPS & VSS  ([B] to focus)"
    };

    // A cyan border marks which of the tab's two lists the arrow keys drive.
    let border_color = if state.is_focused {
        Theme::CYAN
    } else {
        Theme::BORDER
    };

    let panel = Paragraph::new(lines)
        .block(Theme::card_block(title).border_style(Style::default().fg(border_color)))
        // `trim: false` keeps the two-space indent that groups a snapshot's key
        // path under its description; trimming flattens the whole pane.
        .wrap(Wrap { trim: false });

    f.render_widget(panel, area);
}

/// The audit trail, newest first — what WinMedic has actually done to this machine.
pub fn render_audit_log(f: &mut Frame, area: Rect, entries: &[AuditEntry], title: &str) {
    if entries.is_empty() {
        let empty = Paragraph::new(vec![Line::from(vec![Span::styled(
            " No actions recorded yet. Repairs and rollbacks are logged here.",
            Style::default().fg(Theme::MUTED),
        )])])
        .block(Theme::card_block(title))
        .wrap(Wrap { trim: true });
        f.render_widget(empty, area);
        return;
    }

    // Two rows of the block are borders; the rest is one entry per line.
    let capacity = area.height.saturating_sub(2) as usize;

    let items: Vec<ListItem> = entries
        .iter()
        .rev()
        .take(capacity)
        .map(|entry| ListItem::new(audit_line(entry)))
        .collect();

    f.render_widget(List::new(items).block(Theme::card_block(title)), area);
}

/// One audit entry as `[time] [ACTION] [STATUS] title`.
fn audit_line(entry: &AuditEntry) -> Line<'static> {
    let (status_icon, status_color) = match entry.status.as_str() {
        "SUCCESS" => ("[OK]", Theme::EMERALD),
        "FAILED" => ("[X]", Theme::CORAL),
        "WARNING" => ("[WARN]", Theme::AMBER),
        _ => ("[INFO]", Theme::CYAN),
    };

    Line::from(vec![
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
    ])
}

/// A single-line summary of the newest audit entry, for the dashboard.
///
/// Returns `None` when nothing has been logged yet, so the caller can decide
/// whether an empty row is worth the vertical space.
pub fn latest_action_line(entries: &[AuditEntry]) -> Option<Line<'static>> {
    let entry = entries.last()?;
    let mut spans = vec![Span::styled(
        "  Last action: ",
        Style::default()
            .fg(Theme::CYAN)
            .add_modifier(Modifier::BOLD),
    )];
    spans.extend(audit_line(entry).spans);
    spans.push(Span::styled(
        "  │  [5] Full log, backups & rollback",
        Style::default().fg(Theme::MUTED),
    ));
    Some(Line::from(spans))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(status: &str, title: &str) -> AuditEntry {
        AuditEntry {
            timestamp: "2026-01-01 12:00:00".to_string(),
            action_type: "REPAIR".to_string(),
            module_id: "registry_startup".to_string(),
            title: title.to_string(),
            status: status.to_string(),
            details: String::new(),
        }
    }

    #[test]
    fn latest_action_line_reports_the_newest_entry() {
        let entries = vec![entry("SUCCESS", "older"), entry("FAILED", "newest")];

        let line = latest_action_line(&entries).expect("an entry exists");
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();

        assert!(rendered.contains("newest"), "got: {rendered}");
        assert!(!rendered.contains("older"), "got: {rendered}");
        assert!(
            rendered.contains("[X]"),
            "failures stay visible: {rendered}"
        );
    }

    #[test]
    fn latest_action_line_is_absent_before_anything_is_logged() {
        assert!(latest_action_line(&[]).is_none());
    }
}
