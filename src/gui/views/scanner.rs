//! The live scan: one row per diagnostic module, and the log they all write to.

use crate::app::App;
use crate::gui::theme;
use eframe::egui::{self, RichText};
use std::time::Duration;

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    controls(ui, app);
    ui.add_space(8.0);

    // The log takes whatever the module list leaves over, with a floor, so a
    // short window shows a usable amount of both instead of squeezing the log
    // to a single line.
    let log_height = (ui.available_height() * 0.35).max(140.0);

    egui::Panel::bottom("scan_log")
        .exact_size(log_height)
        .show_separator_line(false)
        .frame(egui::Frame::NONE)
        .show(ui, |ui| log(ui, app));

    modules(ui, app);
}

fn controls(ui: &mut egui::Ui, app: &mut App) {
    ui.horizontal(|ui| {
        if app.is_scanning {
            if ui.button("Cancel scan").clicked() {
                app.cancel_current_operation();
            }
        } else if ui.button("Start health scan").clicked() {
            app.start_scan();
        }

        ui.add_space(12.0);

        let progress = app.scan_overall_progress as f32 / 100.0;
        ui.add(
            egui::ProgressBar::new(progress)
                .fill(theme::CYAN)
                .desired_width(260.0)
                .text(format!("{}%", app.scan_overall_progress)),
        );

        if let Some(elapsed) = app.scan_elapsed() {
            ui.label(theme::muted(format!(
                "{} {}",
                if app.is_scanning { "running" } else { "took" },
                format_duration(elapsed)
            )));
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(theme::muted(format!("{} issues found", app.issues.len())));
        });
    });
}

fn modules(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical()
        .id_salt("scan_modules")
        .show(ui, |ui| {
            for module in &app.module_progress_list {
                theme::card(ui, &format!("{} {}", module.icon, module.name), |ui| {
                    let color = if module.failure.is_some() {
                        theme::CORAL
                    } else if module.is_done {
                        theme::EMERALD
                    } else {
                        theme::CYAN
                    };

                    ui.add(
                        egui::ProgressBar::new(module.percent as f32 / 100.0)
                            .fill(color)
                            .desired_height(8.0),
                    );

                    ui.horizontal(|ui| {
                        let step = if module.step.is_empty() {
                            "Waiting..."
                        } else {
                            &module.step
                        };
                        ui.label(RichText::new(step).color(color));

                        // How long the current step has been running is the
                        // difference between "working" and "hung" for a module
                        // sitting on a slow DISM call with nothing to report.
                        if let Some(elapsed) = module.step_elapsed()
                            && elapsed >= Duration::from_secs(3)
                        {
                            ui.label(theme::muted(format!("({})", format_duration(elapsed))));
                        }
                    });
                });
            }
        });
}

fn log(ui: &mut egui::Ui, app: &mut App) {
    theme::card(ui, "SCAN LOG", |ui| {
        egui::ScrollArea::vertical()
            .id_salt("scan_log_scroll")
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for line in &app.scan_log_messages {
                    ui.label(RichText::new(line).monospace().color(theme::MUTED));
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
