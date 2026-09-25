//! Scan, review and repair, on one page.
//!
//! The header answers the two questions a user opens the window with — what
//! state is this machine in, and what should I do now — and offers exactly the
//! action that answers the second one. The body shows whatever that state has
//! to show: the checks while a scan runs, the findings once there are any, and
//! the list of checks when there is nothing to report.
//!
//! That is Advanced mode. Easy mode draws its own page, [`super::easy`].

use super::{easy, findings};
use crate::app::{App, ConfirmRequest};
use crate::engine::issue::Severity;
use crate::gui::theme;
use crate::modules::ModuleStatus;
use eframe::egui::{self, RichText};
use std::collections::VecDeque;
use std::time::Duration;

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    if !app.config.advanced_mode {
        easy::show(ui, app);
        return;
    }

    header(ui, app);
    ui.add_space(6.0);
    ui.separator();

    // Before the body, so the body gets whatever height the log leaves.
    log_panel(ui, app);

    if app.is_scanning || app.issues.is_empty() {
        checks(ui, app);
    } else {
        findings::show(ui, app);
    }
}

fn open_findings(app: &App) -> usize {
    app.issues.iter().filter(|i| !i.is_fixed).count()
}

pub(super) fn selected_for_repair(app: &App) -> usize {
    app.issues.iter().filter(|i| i.will_repair()).count()
}

/// What the repair button says: how many, and whether it only simulates.
pub(super) fn repair_label(dry_run: bool, selected: usize, noun: &str) -> String {
    match (dry_run, selected) {
        (_, 0) => "Repair".to_string(),
        (true, n) => format!("Simulate {}", plural(n, "repair")),
        (false, n) => format!("Repair {}", plural(n, noun)),
    }
}

pub(super) fn has_scanned(app: &App) -> bool {
    app.scan_duration.is_some() || app.last_scan_timestamp.is_some() || !app.issues.is_empty()
}

/// The one button per state that moves the user forward.
///
/// Filled, so the eye finds it first. Every other control on the page is a
/// plain button and can wait.
fn primary(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    let visuals = ui.visuals();
    let button = egui::Button::new(
        RichText::new(text)
            .strong()
            .color(visuals.strong_text_color()),
    )
    .fill(visuals.selection.bg_fill)
    .min_size(egui::vec2(0.0, 28.0));
    ui.add_enabled(enabled, button)
}

fn header(ui: &mut egui::Ui, app: &mut App) {
    let palette = theme::palette(ui);

    if app.is_scanning {
        headline(ui, "Scanning this PC...", None);
        progress(ui, app.scan_overall_progress as f32 / 100.0, None);
        let mut line = vec![format!("{}% complete", app.scan_overall_progress)];
        if let Some(elapsed) = app.scan_elapsed() {
            line.push(format!("running for {}", format_duration(elapsed)));
        }
        let running: Vec<&str> = app
            .module_progress_list
            .iter()
            .filter(|m| !m.is_done && m.percent > 0)
            .map(|m| m.name.as_str())
            .collect();
        if !running.is_empty() {
            line.push(format!("checking {}", running.join(", ")));
        }
        ui.add(egui::Label::new(line.join(" · ")).truncate());
        ui.add_space(4.0);
        if ui.button("Cancel scan").on_hover_text("Esc").clicked() {
            app.cancel_current_operation();
        }
    } else if app.is_fixing {
        headline(
            ui,
            if app.dry_run {
                "Simulating repairs..."
            } else {
                "Repairing..."
            },
            None,
        );
        let done = app.fixed_count + app.failed_count;
        progress(
            ui,
            app.repair_fraction(),
            (app.failed_count > 0).then_some(palette.amber),
        );
        let mut line = format!("{done} of {} done", app.total_to_fix);
        if !app.current_fix_title.is_empty() {
            line.push_str(&format!(" · now: {}", app.current_fix_title));
        }
        if let Some(percent) = app.repair_step_percent {
            line.push_str(&format!(" · {percent:.0}%"));
        }
        if let Some(elapsed) = app.repair_step_elapsed() {
            line.push_str(&format!(" · running for {}", format_duration(elapsed)));
        }
        ui.add(egui::Label::new(line).truncate());
        ui.add_space(4.0);
        if ui.button("Cancel repair").on_hover_text("Esc").clicked() {
            app.cancel_current_operation();
        }
    } else if !has_scanned(app) {
        headline(ui, "This PC has not been checked yet", None);
        ui.label(
            "A scan looks for problems with system files, updates, network, storage, \
             startup entries and more. It only reads - nothing is changed until you \
             choose to repair something.",
        );
        ui.add_space(4.0);
        if primary(ui, true, "Scan now").on_hover_text("S").clicked() {
            app.start_scan();
        }
    } else {
        let open = open_findings(app);
        if open == 0 {
            headline(ui, "No open findings", Some(palette.green));
        } else {
            let worst = [Severity::Critical, Severity::Warning, Severity::Info]
                .into_iter()
                .find(|s| app.issues.iter().any(|i| !i.is_fixed && i.severity == *s))
                .unwrap_or(Severity::Info);
            headline(
                ui,
                &format!(
                    "{open} open {}",
                    if open == 1 { "finding" } else { "findings" }
                ),
                Some(theme::severity_color(ui, worst)),
            );
            ui.label(if app.config.create_vss_before_repair || app.dry_run {
                "Tick what you want fixed, then click Repair. A restore point is created first, \
                 so every change can be undone."
            } else {
                "Tick what you want fixed, then click Repair. Restore points are switched off \
                 in Settings."
            });
        }
        last_runs(ui, app);
        ui.add_space(4.0);
        actions(ui, app, open);
    }

    notices(ui, app);
}

fn headline(ui: &mut egui::Ui, text: &str, color: Option<egui::Color32>) {
    let mut text = RichText::new(text).size(18.0).strong();
    if let Some(color) = color {
        text = text.color(color);
    }
    ui.label(text);
}

fn progress(ui: &mut egui::Ui, fraction: f32, fill: Option<egui::Color32>) {
    let mut bar = egui::ProgressBar::new(fraction)
        .desired_height(12.0)
        .corner_radius(2);
    if let Some(fill) = fill {
        bar = bar.fill(fill);
    }
    ui.add(bar);
}

/// When the machine was last scanned and, if a repair ran, how it went.
fn last_runs(ui: &mut egui::Ui, app: &App) {
    let palette = theme::palette(ui);
    ui.horizontal_wrapped(|ui| {
        match (&app.last_scan_timestamp, app.scan_duration) {
            (Some(timestamp), Some(duration)) => {
                ui.label(theme::muted(format!(
                    "Last scan: {timestamp} (took {})",
                    format_duration(duration)
                )));
            }
            (Some(timestamp), None) => {
                ui.label(theme::muted(format!("Last scan: {timestamp}")));
            }
            (None, Some(duration)) => {
                ui.label(theme::muted(format!(
                    "Last scan took {}",
                    format_duration(duration)
                )));
            }
            (None, None) => {}
        }
        ui.label(theme::muted(format!("· Health {} / 100", app.health_score)));
        if app.total_to_fix > 0 {
            ui.label(theme::muted("· Last repair:"));
            ui.colored_label(palette.green, format!("{} repaired", app.fixed_count));
            if app.failed_count > 0 {
                ui.colored_label(palette.red, format!("{} failed", app.failed_count));
            }
        }
    });
}

fn actions(ui: &mut egui::Ui, app: &mut App, open: usize) {
    ui.horizontal(|ui| {
        if open > 0 {
            let selected = selected_for_repair(app);
            let label = repair_label(app.dry_run, selected, "finding");
            let response = primary(ui, selected > 0, &label);
            let response = if selected == 0 {
                response.on_disabled_hover_text("Tick at least one finding below first")
            } else {
                response.on_hover_text("F")
            };
            if response.clicked() {
                app.start_repairs();
            }
            if ui.button("Scan again").on_hover_text("S").clicked() {
                app.start_scan();
            }
        } else if primary(ui, true, "Scan again").on_hover_text("S").clicked() {
            app.start_scan();
        }

        let mut dry_run = app.dry_run;
        if ui
            .checkbox(&mut dry_run, "Simulate only (change nothing)")
            .on_hover_text("D - list the steps each repair would run, without running them")
            .changed()
        {
            app.toggle_dry_run();
        }
    });
}

/// Things the user should know before acting, one line each.
fn notices(ui: &mut egui::Ui, app: &mut App) {
    let palette = theme::palette(ui);

    if !app.is_admin {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(
                palette.amber,
                "Running without administrator rights: some checks are limited and repairs \
                 need elevation.",
            );
            if ui
                .add_enabled(
                    !app.is_busy(),
                    egui::Button::new("Restart as administrator"),
                )
                .clicked()
            {
                app.pending_confirm = Some(ConfirmRequest::Elevate);
            }
        });
    }

    let restarts = app.issues.iter().filter(|i| i.is_reboot_pending).count();
    if restarts > 0 {
        ui.colored_label(
            palette.amber,
            format!("Restart Windows to finish {}.", plural(restarts, "repair")),
        );
    }

    if !app.is_scanning {
        for (_, name, _, status) in &app.module_statuses {
            if let ModuleStatus::Failed(reason) = status {
                ui.colored_label(
                    palette.red,
                    format!("{name} could not be checked: {reason}"),
                );
            }
        }
    }
}

/// Every diagnostic module, with its progress during a scan and its result after.
fn checks(ui: &mut egui::Ui, app: &mut App) {
    let palette = theme::palette(ui);
    ui.add_space(4.0);
    theme::section(
        ui,
        &format!("What the scan checks ({})", app.module_progress_list.len()),
    );
    egui::ScrollArea::vertical()
        .id_salt("checks")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("checks_table")
                .num_columns(3)
                .striped(true)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    for module in &app.module_progress_list {
                        ui.label(&module.name).on_hover_text(&module.id);

                        if app.is_scanning {
                            let mut bar = egui::ProgressBar::new(module.percent as f32 / 100.0)
                                .desired_width(120.0)
                                .desired_height(10.0)
                                .corner_radius(2);
                            if module.failure.is_some() {
                                bar = bar.fill(palette.red);
                            } else if module.is_done {
                                bar = bar.fill(palette.green);
                            }
                            ui.add(bar);

                            ui.horizontal(|ui| {
                                let (text, color) = if module.step.is_empty() {
                                    ("Waiting", None)
                                } else if module.failure.is_some() {
                                    (module.step.as_str(), Some(palette.red))
                                } else {
                                    (module.step.as_str(), None)
                                };
                                let text = RichText::new(text);
                                ui.label(match color {
                                    Some(color) => text.color(color),
                                    None if module.step.is_empty() => text.weak(),
                                    None => text,
                                });

                                // How long the current step has been running is
                                // the difference between "working" and "hung"
                                // for a module sitting on a slow DISM call with
                                // nothing to report.
                                if let Some(elapsed) = module.step_elapsed()
                                    && elapsed >= Duration::from_secs(3)
                                {
                                    ui.label(theme::muted(format!(
                                        "({})",
                                        format_duration(elapsed)
                                    )));
                                }
                            });
                        } else {
                            let status = app
                                .module_statuses
                                .iter()
                                .find(|(id, ..)| *id == module.id)
                                .map(|(.., status)| status);
                            let (text, color) = match status {
                                Some(ModuleStatus::Passed) => {
                                    ("Passed".to_string(), Some(palette.green))
                                }
                                Some(ModuleStatus::Warning(n)) => {
                                    (plural(*n, "warning"), Some(palette.amber))
                                }
                                Some(ModuleStatus::Critical(n)) => {
                                    (plural(*n, "critical finding"), Some(palette.red))
                                }
                                Some(ModuleStatus::Failed(error)) => {
                                    (format!("Failed: {error}"), Some(palette.red))
                                }
                                _ => ("Not checked yet".to_string(), None),
                            };
                            let text = RichText::new(text);
                            ui.label(match color {
                                Some(color) => text.color(color),
                                None => text.weak(),
                            });
                            ui.label("");
                        }
                        ui.end_row();
                    }
                });
        });
}

pub(super) fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// Which log the panel shows; kept in egui's memory, not in [`App`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum LogKind {
    Scan,
    Repair,
}

/// The scan log and the repair output, folded away until asked for.
///
/// Both are raw command-level detail. The header and the findings already say
/// what happened; the log is for when the user wants to know how.
fn log_panel(ui: &mut egui::Ui, app: &mut App) {
    let open_id = egui::Id::new("log_panel_open");
    let kind_id = egui::Id::new("log_panel_kind");
    let mut open = ui.data_mut(|d| *d.get_persisted_mut_or(open_id, false));
    // Until the user picks one, show whichever run happened last.
    let default_kind = if app.is_fixing || app.total_to_fix > 0 {
        LogKind::Repair
    } else {
        LogKind::Scan
    };
    let mut kind = ui
        .data(|d| d.get_temp::<LogKind>(kind_id))
        .unwrap_or(default_kind);

    // Two ids, because a panel remembers its height: the folded bar is one
    // button tall, and the open log must not start out that small.
    let panel = egui::Panel::bottom(if open {
        "log_panel_open"
    } else {
        "log_panel_folded"
    })
    .show_separator_line(true)
    .frame(egui::Frame::NONE.inner_margin(egui::Margin {
        top: 6,
        ..Default::default()
    }));
    let panel = if open {
        panel
            .resizable(true)
            .default_size(220.0)
            .size_range(120.0..=600.0)
    } else {
        panel.resizable(false)
    };

    panel.show(ui, |ui| {
        ui.horizontal(|ui| {
            if ui
                .button(if open { "Hide log" } else { "Show log" })
                .clicked()
            {
                open = !open;
            }
            if open {
                ui.separator();
                for (choice, label) in [
                    (LogKind::Scan, "Scan log"),
                    (LogKind::Repair, "Repair output"),
                ] {
                    if ui.selectable_label(kind == choice, label).clicked() {
                        kind = choice;
                    }
                }
            }
        });
        if open {
            ui.add_space(4.0);
            match kind {
                LogKind::Scan => log_view(ui, "scan_log", &app.scan_log_messages, |_, _| None),
                LogKind::Repair => log_view(
                    ui,
                    "repair_log",
                    &app.repair_console_lines,
                    // The engine already marks its own outcomes in the text, so
                    // colouring on those markers keeps a long run scannable
                    // without the view having to parse anything.
                    |ui, line| {
                        let palette = theme::palette(ui);
                        if line.contains("[X]") || line.contains("Failed") {
                            Some(palette.red)
                        } else if line.contains("[OK]") {
                            Some(palette.green)
                        } else {
                            None
                        }
                    },
                ),
            }
        }
    });

    ui.data_mut(|d| {
        d.insert_persisted(open_id, open);
        d.insert_temp(kind_id, kind);
    });
}

/// A monospace log that keeps up with a 2000-line buffer.
///
/// Only the rows in view are laid out, so a long run costs the same to draw as
/// a short one. `color` may pick a colour per line from its text.
fn log_view(
    ui: &mut egui::Ui,
    id: &str,
    lines: &VecDeque<String>,
    color: impl Fn(&egui::Ui, &str) -> Option<egui::Color32>,
) {
    egui::Frame::NONE
        .fill(ui.visuals().extreme_bg_color)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .corner_radius(3)
        .inner_margin(8)
        .show(ui, |ui| {
            let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
            egui::ScrollArea::both()
                .id_salt(id)
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show_rows(ui, row_height, lines.len(), |ui, rows| {
                    for line in lines.range(rows) {
                        let mut text = RichText::new(line).monospace();
                        if let Some(color) = color(ui, line) {
                            text = text.color(color);
                        }
                        ui.add(egui::Label::new(text).extend());
                    }
                });
        });
}

/// `1m 04s` rather than `64.213s`, which is what a progress readout wants.
pub fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 60 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}
