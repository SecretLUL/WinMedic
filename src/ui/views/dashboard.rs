use crate::engine::issue::{Issue, Severity};
use crate::modules::ModuleStatus;
use crate::safety::audit::AuditEntry;
use crate::ui::theme::Theme;
use crate::ui::widgets::safety_panel::latest_action_line;
use crate::utils::hardware::SystemTelemetry;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Wrap};

// Ratatui render functions receive the slice of app state they draw rather than
// `&App`, which is what makes the signature long.
#[allow(clippy::too_many_arguments)]
pub fn render_dashboard(
    f: &mut Frame,
    area: Rect,
    telemetry: Option<&SystemTelemetry>,
    health_score: u8,
    issues: &[Issue],
    module_statuses: &[(String, String, String, ModuleStatus)],
    audit_entries: &[AuditEntry],
) {
    // The summary bar grows by a line once there is an audit trail to show, so
    // an untouched machine does not reserve space for an empty row.
    let summary_height = if audit_entries.is_empty() { 5 } else { 6 };

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),              // Health Score & Telemetry Gauges
            Constraint::Min(12),                // 7 Module Status Cards
            Constraint::Length(summary_height), // Quick Action & Status Summary
        ])
        .split(area);

    // Top Section: 3 Columns (Health Gauge, CPU Gauge, RAM Gauge & OS Info)
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33), // Health Score
            Constraint::Percentage(33), // CPU & RAM Gauges
            Constraint::Percentage(34), // System & Hardware Specs
        ])
        .split(main_chunks[0]);

    // 1. Health Score Gauge
    let health_color = if health_score >= 80 {
        Theme::EMERALD
    } else if health_score >= 50 {
        Theme::AMBER
    } else {
        Theme::CORAL
    };

    let health_status_text = if health_score == 100 {
        "OPTIMAL - all systems healthy"
    } else if health_score >= 80 {
        "GOOD - minor optimisations possible"
    } else if health_score >= 50 {
        "WARNING - action needed"
    } else {
        "CRITICAL - immediate repair recommended"
    };

    let critical_count = issues
        .iter()
        .filter(|i| i.severity == Severity::Critical && !i.is_fixed)
        .count();
    let warning_count = issues
        .iter()
        .filter(|i| i.severity == Severity::Warning && !i.is_fixed)
        .count();

    let health_gauge = Gauge::default()
        .block(Theme::card_block("SYSTEM HEALTH INDEX"))
        .gauge_style(Style::default().fg(health_color).bg(Theme::BG_DEEP))
        .percent(health_score as u16)
        .label(format!(
            " {}/100 ({} critical, {} warnings) ",
            health_score, critical_count, warning_count
        ));

    f.render_widget(health_gauge, top_chunks[0]);

    // 2. CPU & RAM Telemetry
    let (cpu_val, ram_val, ram_str) = if let Some(t) = telemetry {
        (
            t.cpu_usage.clamp(0.0, 100.0) as u16,
            t.ram_usage_percent.clamp(0.0, 100.0) as u16,
            format!(
                "{:.1} / {:.1} GB",
                t.ram_used_mb as f32 / 1024.0,
                t.ram_total_mb as f32 / 1024.0
            ),
        )
    } else {
        (0, 0, "-- / -- GB".to_string())
    };

    let telem_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(top_chunks[1]);

    let cpu_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::BORDER))
                .title(" CPU Usage "),
        )
        .gauge_style(Style::default().fg(Theme::CYAN).bg(Theme::BG_DEEP))
        .percent(cpu_val)
        .label(format!(" {}% ", cpu_val));

    let ram_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::BORDER))
                .title(" RAM Usage "),
        )
        .gauge_style(Style::default().fg(Theme::ACCENT_PURPLE).bg(Theme::BG_DEEP))
        .percent(ram_val)
        .label(format!(" {}% ({}) ", ram_val, ram_str));

    f.render_widget(cpu_gauge, telem_chunks[0]);
    f.render_widget(ram_gauge, telem_chunks[1]);

    // 3. System Specs Card
    let sys_lines = if let Some(t) = telemetry {
        let uptime_h = t.uptime_secs / 3600;
        let uptime_m = (t.uptime_secs % 3600) / 60;
        vec![
            Line::from(vec![
                Span::styled("OS:      ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    format!("{} {}", t.os_name, t.os_version),
                    Style::default()
                        .fg(Theme::TEXT_WHITE)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("CPU:     ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    format!("{} ({} cores)", t.cpu_name, t.cpu_count),
                    Style::default().fg(Theme::TEXT_WHITE),
                ),
            ]),
            Line::from(vec![
                Span::styled("Uptime:  ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    format!("{} h {} min", uptime_h, uptime_m),
                    Style::default().fg(Theme::EMERALD),
                ),
            ]),
        ]
    } else {
        vec![Line::from("Loading system data...")]
    };

    let sys_card = Paragraph::new(sys_lines).block(Theme::card_block("SYSTEM SPECIFICATION"));
    f.render_widget(sys_card, top_chunks[2]);

    // Middle Section: 7 Diagnostic Modules (Row 1: 4 Cards, Row 2: 3 Cards)
    let mod_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    let row1 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(mod_rows[0]);

    // Same four-column grid as row 1 — the trailing cell stays empty. Splitting
    // row 2 into thirds would render the same kind of card at two different
    // widths, and clip the longer module names differently in each row.
    let row2 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(mod_rows[1]);

    let card_slots = [
        (0, row1[0]),
        (1, row1[1]),
        (2, row1[2]),
        (3, row1[3]),
        (4, row2[0]),
        (5, row2[1]),
        (6, row2[2]),
    ];

    for (idx, slot_rect) in card_slots {
        if let Some((_id, name, icon, status)) = module_statuses.get(idx) {
            let (status_badge, status_color, status_text) = match status {
                ModuleStatus::Idle => ("[READY]", Theme::MUTED, "Ready for a diagnostic scan"),
                ModuleStatus::Scanning => ("[SCAN...]", Theme::CYAN, "Diagnostics in progress..."),
                ModuleStatus::Passed => ("[OPTIMAL]", Theme::EMERALD, "No issues detected"),
                ModuleStatus::Warning(_cnt) => ("[WARNING]", Theme::AMBER, "One or more warnings"),
                ModuleStatus::Critical(_cnt) => {
                    ("[CRITICAL]", Theme::CORAL, "Critical faults found")
                }
                ModuleStatus::Failed(_err) => ("[ERROR]", Theme::CORAL, "Diagnostics failed"),
            };

            let card_content = vec![
                Line::from(vec![
                    Span::styled(
                        format!(" {} ", icon),
                        Style::default()
                            .fg(Theme::CYAN)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        name.as_str(),
                        Style::default()
                            .fg(Theme::TEXT_WHITE)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Status: ", Style::default().fg(Theme::MUTED)),
                    Span::styled(
                        status_badge,
                        Style::default()
                            .fg(status_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![Span::styled(
                    format!("Detail: {}", status_text),
                    Style::default().fg(Theme::MUTED),
                )]),
            ];

            // Four cards per row leave ~28 usable columns at 120 terminal
            // columns, which is narrower than several module names. Wrapping
            // pushes the overflow onto a second line instead of silently
            // truncating the name mid-word.
            let card = Paragraph::new(card_content)
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(if *status != ModuleStatus::Idle {
                            status_color
                        } else {
                            Theme::BORDER
                        }))
                        .title(format!(" Module {} ", idx + 1)),
                );

            f.render_widget(card, slot_rect);
        }
    }

    // Bottom Section: Quick Action Bar
    let mut bottom_content = vec![
        Line::from(vec![
            Span::styled(
                "  Quick actions: ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " [S] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Start a full health scan   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [A] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "One-click auto-fix all   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [3] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Open issue triage   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [5] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Settings & safety   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [?] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Help", Style::default().fg(Theme::TEXT_WHITE)),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  Safety status: {}", health_status_text),
                Style::default()
                    .fg(health_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  │  VSS restore points are created automatically before every change.",
                Style::default().fg(Theme::MUTED),
            ),
        ]),
    ];

    // The audit trail moved onto tab 5 when "Backups & Logs" was merged into
    // Settings. This one line keeps the most recent action where the user
    // already is, and points at the tab that holds the rest of it.
    if let Some(line) = latest_action_line(audit_entries) {
        bottom_content.push(line);
    }

    let bottom_bar =
        Paragraph::new(bottom_content).block(Theme::card_block("QUICK ACCESS & RECOMMENDATIONS"));
    f.render_widget(bottom_bar, main_chunks[2]);
}
