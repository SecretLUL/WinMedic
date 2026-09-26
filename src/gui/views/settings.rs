//! Settings and the safety surface on one tab: what WinMedic is allowed to do
//! to this machine, and how to undo what it has already done.
//!
//! These were two tabs in the terminal front end and were merged for a reason
//! that still holds — every action the backup list offers is the same kind of
//! "what may this tool touch" decision the settings list is made of.

use crate::app::{App, SafetyFocus};
use crate::config::AppConfig;
use crate::gui::theme;
use eframe::egui::{self, RichText};

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    ui.columns(2, |columns| {
        theme::plain(&mut columns[0], |ui| settings(ui, app));
        theme::plain(&mut columns[1], |ui| safety(ui, app));
    });
}

/// The settings that take a number, and open the input dialog to get one.
fn is_numeric(index: usize) -> bool {
    matches!(index, 4 | 5 | 8)
}

/// The row the arrow keys point at, so the keyboard moves something visible.
fn keyboard_row<R>(ui: &mut egui::Ui, focused: bool, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let fill = if focused {
        ui.visuals().selection.bg_fill.gamma_multiply(0.35)
    } else {
        egui::Color32::TRANSPARENT
    };
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(2)
        .inner_margin(egui::Margin::symmetric(6, 4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn settings(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical()
        .id_salt("settings_list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            theme::section(ui, "Options");
            let focused = !app.backups_focused();
            for index in 0..AppConfig::SETTING_COUNT {
                let Some((label, value, explanation)) = app.config.setting_row(index) else {
                    continue;
                };
                // The keyboard hints live in the help sheet; the description
                // keeps only what the setting does.
                let description = explanation.split(" [").next().unwrap_or(explanation);
                let keyboard = focused && index == app.selected_setting_index;

                keyboard_row(ui, keyboard, |ui| {
                    let clicked = if is_numeric(index) {
                        ui.horizontal(|ui| {
                            ui.label(label);
                            ui.label(RichText::new(&value).strong());
                            ui.button("Change").clicked()
                        })
                        .inner
                    } else {
                        let mut on = value == "ON";
                        ui.checkbox(&mut on, label).changed()
                    };
                    ui.label(theme::muted(description));

                    if clicked {
                        app.safety_focus = SafetyFocus::Settings;
                        app.selected_setting_index = index;
                        if is_numeric(index) {
                            app.open_setting_input();
                        } else {
                            app.toggle_current_setting();
                        }
                    }
                });
            }
        });
}

fn safety(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical()
        .id_salt("safety_panel")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            backups(ui, app);
            ui.add_space(14.0);
            restore_points(ui, app);
            ui.add_space(14.0);
            activity(ui, app);
            ui.add_space(14.0);

            theme::section(ui, "Log folder");
            let folder = app
                .audit_logger
                .log_dir()
                .map_or_else(|| "Not recorded".into(), |dir| dir.to_string_lossy());
            ui.label(RichText::new(folder).monospace());
            ui.label(theme::muted(
                "Every scan, repair, simulation and rollback is recorded here.",
            ));
            ui.add_space(14.0);

            theme::section(ui, "Remove from this PC");
            ui.label(theme::muted(
                "Before deleting winmedic.exe: removes the background scan task and the \
                 Start with Windows entry, and turns both settings off.",
            ));
            ui.add_space(4.0);
            if ui
                .button("Remove WinMedic from Windows")
                .on_hover_text("Asks for confirmation first")
                .clicked()
            {
                app.request_unregister();
            }
        });
}

fn backups(ui: &mut egui::Ui, app: &mut App) {
    theme::section(ui, "Registry backups");
    let records: Vec<_> = app.backups_newest_first().into_iter().cloned().collect();

    if records.is_empty() {
        ui.label(theme::muted(
            "No registry snapshot has been taken yet. WinMedic writes one before it changes a key.",
        ));
        return;
    }

    let focused = app.backups_focused();
    for (position, record) in records.iter().enumerate() {
        let selected = position == app.selected_backup_index;
        let response = ui
            .selectable_label(
                selected,
                format!("{}   {}", record.timestamp, record.description),
            )
            .on_hover_text(&record.key_path);
        if response.clicked() {
            app.safety_focus = SafetyFocus::Backups;
            app.selected_backup_index = position;
        }
        if selected {
            ui.label(RichText::new(&record.key_path).monospace().weak());
        }
    }

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !app.is_restoring,
                egui::Button::new("Restore the selected snapshot"),
            )
            .on_hover_text("U - asks for confirmation first")
            .clicked()
        {
            app.request_rollback();
        }
        if !focused {
            ui.label(theme::muted("B moves the arrow keys here"));
        }
    });
}

fn restore_points(ui: &mut egui::Ui, app: &mut App) {
    theme::section(ui, "System restore points");
    if app.restore_points_loading {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(theme::muted("Asking Windows for its restore points..."));
        });
        return;
    }

    if app.vss_restore_points.is_empty() {
        ui.label(theme::muted("No restore points reported."));
    } else {
        for point in &app.vss_restore_points {
            ui.label(point);
        }
    }

    ui.add_space(4.0);
    if ui.button("Refresh").clicked() {
        app.refresh_restore_points();
    }
}

/// What WinMedic did to this machine lately, newest first.
fn activity(ui: &mut egui::Ui, app: &mut App) {
    const SHOWN: usize = 10;
    theme::section(ui, "Recent activity");
    if app.audit_entries.is_empty() {
        ui.label(theme::muted("Nothing recorded yet."));
        return;
    }
    let palette = theme::palette(ui);
    for entry in app.audit_entries.iter().rev().take(SHOWN) {
        ui.horizontal(|ui| {
            ui.label(theme::muted(&entry.timestamp));
            let status = entry.status.to_uppercase();
            let color = if status.contains("FAIL") || status.contains("ERROR") {
                Some(palette.red)
            } else if status.contains("SUCCESS") || status == "OK" {
                Some(palette.green)
            } else {
                None
            };
            let text = RichText::new(entry.status.to_lowercase());
            ui.add_sized(
                [56.0, ui.available_height()],
                egui::Label::new(match color {
                    Some(color) => text.color(color),
                    None => text.weak(),
                }),
            );
            let title = ui.add(egui::Label::new(&entry.title).truncate());
            if !entry.details.is_empty() {
                title.on_hover_text(&entry.details);
            }
        });
    }
}
