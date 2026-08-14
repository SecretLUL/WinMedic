use crate::engine::issue::{Issue, Severity};
use crate::modules::ModuleStatus;
use crate::ui::theme::Theme;
use crate::utils::hardware::SystemTelemetry;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};

pub fn render_dashboard(
    f: &mut Frame,
    area: Rect,
    telemetry: Option<&SystemTelemetry>,
    health_score: u8,
    issues: &[Issue],
    module_statuses: &[(String, String, String, ModuleStatus)],
) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Health Score & Telemetry Gauges
            Constraint::Min(12),   // 6 Module Status Cards
            Constraint::Length(5), // Quick Action & Status Summary
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
        "OPTIMAL – Alle Systeme gesund"
    } else if health_score >= 80 {
        "GUT – Geringfügige Optimierungen möglich"
    } else if health_score >= 50 {
        "WARNUNG – Handlungsbedarf vorhanden"
    } else {
        "KRITISCH – Sofortige Reparatur empfohlen"
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
        .block(Theme::card_block("SYSTEM-GESUNDHEITS-INDEX"))
        .gauge_style(Style::default().fg(health_color).bg(Theme::BG_DEEP))
        .percent(health_score as u16)
        .label(format!(
            " {}/100 ({} Kritisch, {} Warnungen) ",
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
                .title(" CPU Auslastung "),
        )
        .gauge_style(Style::default().fg(Theme::CYAN).bg(Theme::BG_DEEP))
        .percent(cpu_val)
        .label(format!(" {}% ", cpu_val));

    let ram_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::BORDER))
                .title(" RAM Belegung "),
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
                    format!("{} ({} Kerne)", t.cpu_name, t.cpu_count),
                    Style::default().fg(Theme::TEXT_WHITE),
                ),
            ]),
            Line::from(vec![
                Span::styled("Uptime:  ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    format!("{} Std. {} Min.", uptime_h, uptime_m),
                    Style::default().fg(Theme::EMERALD),
                ),
            ]),
        ]
    } else {
        vec![Line::from("Lade Systemdaten...")]
    };

    let sys_card = Paragraph::new(sys_lines).block(Theme::card_block("SYSTEM-SPEZIFIKATION"));
    f.render_widget(sys_card, top_chunks[2]);

    // Middle Section: 6 Diagnostic Modules (2 Rows of 3 Columns)
    let mod_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    let row1 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(mod_rows[0]);

    let row2 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(mod_rows[1]);

    let card_slots = [
        (0, row1[0]),
        (1, row1[1]),
        (2, row1[2]),
        (3, row2[0]),
        (4, row2[1]),
        (5, row2[2]),
    ];

    for (idx, slot_rect) in card_slots {
        if let Some((_id, name, icon, status)) = module_statuses.get(idx) {
            let (status_badge, status_color, status_text) = match status {
                ModuleStatus::Idle => ("[● BEREIT]", Theme::MUTED, "Bereit für Diagnose-Scan"),
                ModuleStatus::Scanning => ("[⚡ SCAN...]", Theme::CYAN, "Diagnose läuft gerade..."),
                ModuleStatus::Passed => {
                    ("[✔ OPTIMAL]", Theme::EMERALD, "Keine Probleme festgestellt")
                }
                ModuleStatus::Warning(_cnt) => {
                    ("[▲ WARNUNG]", Theme::AMBER, "1 oder mehr Warnungen")
                }
                ModuleStatus::Critical(_cnt) => {
                    ("[✖ KRITISCH]", Theme::CORAL, "Kritische Fehler gefunden")
                }
                ModuleStatus::Failed(_err) => {
                    ("[⚠ FEHLER]", Theme::CORAL, "Diagnose fehlgeschlagen")
                }
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

            let card = Paragraph::new(card_content).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if *status != ModuleStatus::Idle {
                        status_color
                    } else {
                        Theme::BORDER
                    }))
                    .title(format!(" Modul {} ", idx + 1)),
            );

            f.render_widget(card, slot_rect);
        }
    }

    // Bottom Section: Quick Action Bar
    let bottom_content = vec![
        Line::from(vec![
            Span::styled(
                "  Schnell-Aktionen: ",
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
                "Vollständigen Health-Scan starten   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [A] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "1-Klick Auto-Fix All   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [3] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Problem-Triage öffnen   ",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
            Span::styled(
                " [?] ",
                Style::default()
                    .fg(Theme::AMBER)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Hilfe & Dokumentation",
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  Sicherheits-Status: {}", health_status_text),
                Style::default()
                    .fg(health_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  │  VSS Wiederherstellungspunkte werden automatisch vor jedem Eingriff erstellt.",
                Style::default().fg(Theme::MUTED),
            ),
        ]),
    ];

    let bottom_bar =
        Paragraph::new(bottom_content).block(Theme::card_block("SCHNELLZUGRIFF & EMPFEHLUNGEN"));
    f.render_widget(bottom_bar, main_chunks[2]);
}
