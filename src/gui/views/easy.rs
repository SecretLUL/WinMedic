//! Easy mode: the Scan & Repair page for someone who has never had to fix
//! Windows before.
//!
//! One column, one big button. The page says how the PC is doing, what the
//! repair will do — the disk space it frees and what works again, as the scan
//! measured it ([`crate::app::preview`]) — and offers Repair and Scan again.
//! No list of findings, no ticks, filters, logs or technical detail: Advanced
//! mode (F7) has all of that, and the Repair button repairs exactly what is
//! ticked there, which out of the box is what the checks recommend.

use super::home::{format_duration, has_scanned, plural, repair_label, selected_for_repair};
use crate::app::{App, ConfirmRequest};
use crate::engine::issue::Severity;
use crate::gui::theme;
use crate::modules::ModuleStatus;
use eframe::egui::{self, RichText};

/// Wide enough for the forecast's longest line, narrow enough to read at a
/// glance on a wide window.
const COLUMN: f32 = 620.0;

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical()
        .id_salt("easy_page")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let width = ui.available_width().min(COLUMN);
            ui.add_space(28.0);
            ui.horizontal_top(|ui| {
                ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
                ui.vertical(|ui| {
                    ui.set_width(width);
                    if app.is_scanning {
                        scanning(ui, app);
                    } else if app.is_fixing {
                        repairing(ui, app);
                    } else if !has_scanned(app) {
                        unscanned(ui, app);
                    } else {
                        result(ui, app);
                    }
                    notices(ui, app);
                });
            });
        });
}

fn headline(ui: &mut egui::Ui, text: &str, color: Option<egui::Color32>) {
    let mut text = RichText::new(text).size(26.0).strong();
    if let Some(color) = color {
        text = text.color(color);
    }
    ui.label(text);
}

fn line(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).size(15.0));
}

fn note(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(theme::muted(text));
}

fn progress(ui: &mut egui::Ui, fraction: f32) {
    ui.add(
        egui::ProgressBar::new(fraction)
            .desired_height(16.0)
            .corner_radius(3),
    );
}

fn unscanned(ui: &mut egui::Ui, app: &mut App) {
    headline(ui, "This PC has not been checked yet", None);
    ui.add_space(4.0);
    line(
        ui,
        "A scan finds common Windows problems. It changes nothing.",
    );
    ui.add_space(20.0);
    if theme::big_button(ui, "Scan now", true, true)
        .on_hover_text("S")
        .clicked()
    {
        app.start_scan();
    }
}

fn scanning(ui: &mut egui::Ui, app: &mut App) {
    headline(ui, "Checking your PC...", None);
    ui.add_space(10.0);
    progress(ui, app.scan_overall_progress as f32 / 100.0);
    let mut status = format!("{}%", app.scan_overall_progress);
    if let Some(elapsed) = app.scan_elapsed() {
        status.push_str(&format!(" · {}", format_duration(elapsed)));
    }
    note(ui, status);
    ui.add_space(6.0);
    line(ui, "This takes a minute or two. Nothing is changed.");
    ui.add_space(16.0);
    if ui.button("Cancel").on_hover_text("Esc").clicked() {
        app.cancel_current_operation();
    }
}

fn repairing(ui: &mut egui::Ui, app: &mut App) {
    headline(
        ui,
        if app.dry_run {
            "Simulating the repair..."
        } else {
            "Repairing..."
        },
        None,
    );
    ui.add_space(10.0);
    let done = app.fixed_count + app.failed_count;
    progress(ui, app.repair_fraction());
    note(ui, format!("{done} of {} done", app.total_to_fix));
    ui.add_space(16.0);
    if ui.button("Cancel").on_hover_text("Esc").clicked() {
        app.cancel_current_operation();
    }
}

/// After a scan or a repair: how the PC is doing, and the next step.
fn result(ui: &mut egui::Ui, app: &mut App) {
    let palette = theme::palette(ui);
    let open: Vec<Severity> = app
        .issues
        .iter()
        .filter(|i| !i.is_fixed && !i.is_reboot_pending)
        .map(|i| i.severity)
        .collect();
    let problems = open.len();
    let to_repair = selected_for_repair(app);
    let restarts = app.issues.iter().filter(|i| i.is_reboot_pending).count();

    if problems == 0 && restarts > 0 {
        headline(ui, "Almost done", Some(palette.amber));
        ui.add_space(4.0);
        line(ui, "Restart Windows to finish the repair.");
        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if theme::big_button(ui, "Restart now", true, true).clicked() {
                app.show_reboot_notice();
            }
            scan_again(ui, app, false);
        });
        return;
    }

    if problems == 0 {
        let repaired = app.issues.iter().any(|i| i.is_fixed);
        headline(
            ui,
            if repaired {
                "All problems are fixed"
            } else {
                "Your PC is in good shape"
            },
            Some(palette.green),
        );
        ui.add_space(4.0);
        line(ui, format!("Health {} / 100", app.health_score));
        ui.add_space(20.0);
        scan_again(ui, app, true);
        return;
    }

    let worst = [Severity::Critical, Severity::Warning, Severity::Info]
        .into_iter()
        .find(|s| open.contains(s))
        .unwrap_or(Severity::Info);
    headline(
        ui,
        &format!("{} found", plural(problems, "problem")),
        Some(theme::severity_color(ui, worst)),
    );
    ui.add_space(4.0);
    line(ui, format!("Health {} / 100", app.health_score));
    ui.add_space(16.0);

    if to_repair > 0 {
        forecast(ui, app);
        ui.add_space(16.0);
    } else {
        line(ui, "None of them is repaired automatically.");
        ui.add_space(16.0);
    }

    ui.horizontal(|ui| {
        if to_repair > 0 {
            let label = repair_label(app.dry_run, to_repair, "problem");
            if theme::big_button(ui, &label, true, true)
                .on_hover_text("F")
                .clicked()
            {
                app.start_repairs();
            }
        }
        scan_again(ui, app, to_repair == 0);
    });

    ui.add_space(10.0);
    if to_repair > 0 {
        let preview = app.repair_preview();
        note(
            ui,
            match (app.config.create_vss_before_repair, preview.needs_restart) {
                (true, false) => "A restore point is created first, so everything can be undone.",
                (true, true) => {
                    "A restore point is created first. Windows needs a restart afterwards."
                }
                (false, false) => "Restore points are switched off in Settings.",
                (false, true) => {
                    "Restore points are switched off in Settings. Windows needs a restart afterwards."
                }
            },
        );
    }

    let failed = app
        .issues
        .iter()
        .filter(|i| !i.is_fixed && i.fix_error.is_some())
        .count();
    if failed > 0 {
        ui.colored_label(
            palette.red,
            format!(
                "{} did not work. Advanced mode (F7) shows why.",
                plural(failed, "repair")
            ),
        );
    }

    let left_alone = problems - to_repair;
    if left_alone > 0 {
        ui.horizontal_wrapped(|ui| {
            ui.label(theme::muted(format!(
                "{} more {} your decision.",
                left_alone,
                if left_alone == 1 { "needs" } else { "need" }
            )));
            if ui.link("Show in Advanced mode (F7)").clicked() {
                app.toggle_advanced_mode();
            }
        });
    }
}

/// What the Repair button will do, in a few short lines.
fn forecast(ui: &mut egui::Ui, app: &App) {
    let preview = app.repair_preview();
    let mut lines: Vec<String> = Vec::new();
    lines.extend(preview.space_line());
    lines.extend(preview.benefits.iter().map(|b| b.text().to_string()));
    if preview.health_after > app.health_score {
        lines.push(format!(
            "Health goes up to about {} / 100",
            preview.health_after
        ));
    }
    if lines.is_empty() {
        return;
    }

    egui::Frame::NONE
        .fill(ui.visuals().faint_bg_color)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .corner_radius(6)
        .inner_margin(14)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("What Repair does").strong().size(15.0));
            ui.add_space(6.0);
            for text in lines {
                ui.horizontal(|ui| {
                    theme::check_mark(ui, 16.0);
                    line(ui, text);
                });
            }
        });
}

fn scan_again(ui: &mut egui::Ui, app: &mut App, primary: bool) {
    if theme::big_button(ui, "Scan again", primary, true)
        .on_hover_text("S")
        .clicked()
    {
        app.start_scan();
    }
}

/// The two things that can stand in the way, one line each.
fn notices(ui: &mut egui::Ui, app: &mut App) {
    let palette = theme::palette(ui);

    if !app.is_admin {
        ui.add_space(14.0);
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(palette.amber, "Repairs need administrator rights.");
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

    if !app.is_scanning {
        // A command's error text says nothing to someone who has never opened
        // a terminal, so the module is named and the reason left to Advanced.
        let failed: Vec<&str> = app
            .module_statuses
            .iter()
            .filter(|(.., status)| matches!(status, ModuleStatus::Failed(_)))
            .map(|(_, name, ..)| name.as_str())
            .collect();
        if !failed.is_empty() {
            ui.add_space(6.0);
            ui.colored_label(
                palette.red,
                format!(
                    "Could not check {}. Advanced mode (F7) shows why.",
                    failed.join(", ")
                ),
            );
        }
    }
}
