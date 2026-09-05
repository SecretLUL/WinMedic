//! The repair run: what is being fixed, how far along it is, and the console
//! output of the commands doing it.

use crate::app::App;
use crate::gui::theme;
use eframe::egui::{self, RichText};

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    status(ui, app);
    ui.add_space(8.0);
    console(ui, app);
}

fn status(ui: &mut egui::Ui, app: &mut App) {
    theme::card(
        ui,
        if app.dry_run {
            "SIMULATED REPAIR RUN"
        } else {
            "REPAIR RUN"
        },
        |ui| {
            let selected = app
                .issues
                .iter()
                .filter(|i| i.is_selected && !i.is_fixed)
                .count();

            ui.horizontal(|ui| {
                if app.is_fixing {
                    if ui.button("Cancel").clicked() {
                        app.cancel_current_operation();
                    }
                } else {
                    if ui
                        .add_enabled(
                            selected > 0 && !app.is_busy(),
                            theme::primary_button(if app.dry_run {
                                "Simulate repairs"
                            } else {
                                "Start repairs"
                            }),
                        )
                        .clicked()
                    {
                        app.start_repairs();
                    }
                    let mut dry_run = app.dry_run;
                    if ui.checkbox(&mut dry_run, "Simulation mode").changed() {
                        app.toggle_dry_run();
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(theme::muted(format!("VSS: {}", app.vss_status)));
                });
            });

            ui.add_space(8.0);

            let total = app.total_to_fix.max(1);
            let done = app.fixed_count + app.failed_count;
            ui.add(
                egui::ProgressBar::new(done as f32 / total as f32)
                    .fill(if app.failed_count > 0 {
                        theme::AMBER
                    } else {
                        theme::EMERALD
                    })
                    .desired_height(8.0),
            );

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(
                    theme::muted(format!("{done} / {} completed", app.total_to_fix)).size(12.0),
                );
                theme::badge(ui, &format!("{} repaired", app.fixed_count), theme::EMERALD);
                if app.failed_count > 0 {
                    theme::badge(ui, &format!("{} failed", app.failed_count), theme::CORAL);
                }
                if !app.current_fix_title.is_empty() {
                    ui.label(theme::muted(&app.current_fix_title));
                }
            });

            if !app.is_fixing && app.total_to_fix == 0 && selected == 0 {
                ui.add_space(6.0);
                ui.label(theme::muted(
                    "Nothing is selected. Pick the findings to repair on the Issue Triage tab.",
                ));
            }
        },
    );
}

fn console(ui: &mut egui::Ui, app: &mut App) {
    theme::card(ui, "CONSOLE", |ui| {
        egui::ScrollArea::vertical()
            .id_salt("repair_console")
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if app.repair_console_lines.is_empty() {
                    ui.label(theme::muted(
                        "Repair output will appear here. Every step is recorded in your audit log.",
                    ));
                }
                for line in &app.repair_console_lines {
                    // The engine already marks its own outcomes in the text, so
                    // colouring on those markers keeps a long run scannable
                    // without the view having to parse anything.
                    let color = if line.contains("[X]") || line.contains("Failed") {
                        theme::CORAL
                    } else if line.contains("[OK]") {
                        theme::EMERALD
                    } else {
                        theme::MUTED
                    };
                    ui.label(RichText::new(line).monospace().color(color));
                }
            });
    });
}
