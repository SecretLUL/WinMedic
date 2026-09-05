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
        settings(&mut columns[0], app);
        safety(&mut columns[1], app);
    });
}

fn settings(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical()
        .id_salt("settings_list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let focused = !app.backups_focused();
            theme::card(ui, &focus_title("SETTINGS", focused), |ui| {
                for index in 0..AppConfig::SETTING_COUNT {
                    let Some((label, value, explanation)) = app.config.setting_row(index) else {
                        continue;
                    };

                    // The arrow keys move `selected_setting_index`, so the row
                    // it points at has to be visible. Without this the keyboard
                    // moves a selection nothing on screen shows.
                    let fill = if focused && index == app.selected_setting_index {
                        theme::BG_SUNKEN
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    egui::Frame::NONE
                        .fill(fill)
                        .corner_radius(10)
                        .inner_margin(egui::Margin::symmetric(12, 12))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        // The two numeric settings open the input
                                        // dialog; the rest are booleans a click
                                        // can flip outright.
                                        let numeric = matches!(index, 4 | 5);
                                        let button = egui::Button::new(
                                            RichText::new(&value).size(12.0).strong().color(
                                                if value == "ON" {
                                                    theme::CYAN
                                                } else {
                                                    theme::TEXT_WHITE
                                                },
                                            ),
                                        )
                                        .fill(if value == "ON" {
                                            theme::SELECTED
                                        } else {
                                            theme::HOVER
                                        });
                                        if ui.add(button).on_hover_text(label).clicked() {
                                            app.safety_focus = SafetyFocus::Settings;
                                            app.selected_setting_index = index;
                                            if numeric {
                                                app.open_setting_input();
                                            } else {
                                                app.toggle_current_setting();
                                            }
                                        }
                                        ui.with_layout(
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                ui.add(
                                                    egui::Label::new(RichText::new(label).strong())
                                                        .wrap(),
                                                );
                                            },
                                        );
                                    },
                                );
                            });
                            // Keyboard hints stay available on hover without repeating
                            // terminal instructions in every settings description.
                            let description = explanation.split(" [").next().unwrap_or(explanation);
                            ui.label(theme::muted(description).size(12.0))
                                .on_hover_text(explanation);
                        });
                    ui.add_space(4.0);
                }
            });
        });
}

/// Say which of the two lists the arrow keys are currently driving.
///
/// The terminal front end put this in the pane titles, and it is needed just as
/// much here: `[B]` moves the arrows between the settings and the snapshots,
/// and a focus the user cannot see is a focus they cannot use.
///
/// Spelled out in words rather than drawn with the arrow glyphs the terminal
/// front end used: the fonts egui bundles have no glyph for U+25C4 or
/// U+2191/U+2193, so all three reached the screen as empty boxes.
fn focus_title(title: &str, focused: bool) -> String {
    if focused {
        format!("{title}  (arrow keys)")
    } else {
        format!("{title}  ([B] to focus)")
    }
}

fn safety(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical()
        .id_salt("safety_panel")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            backups(ui, app);
            ui.add_space(8.0);
            restore_points(ui, app);
            ui.add_space(8.0);

            theme::card(ui, "LOGS & BACKUPS", |ui| {
                ui.label(
                    RichText::new(app.audit_logger.log_dir().to_string_lossy())
                        .monospace()
                        .size(11.0),
                );
                if ui.button("Export HTML report").clicked() {
                    app.status_message = Some(match app.export_report() {
                        Ok(path) => format!("Report exported: {}", path.display()),
                        Err(error) => error,
                    });
                }
            });
        });
}

fn backups(ui: &mut egui::Ui, app: &mut App) {
    let focused = app.backups_focused();
    theme::card(ui, &focus_title("REGISTRY BACKUPS", focused), |ui| {
        let records: Vec<_> = app.backups_newest_first().into_iter().cloned().collect();

        if records.is_empty() {
            ui.label(theme::muted(
                "No registry snapshot has been taken yet. WinMedic writes one before it changes a key.",
            ));
            return;
        }

        for (position, record) in records.iter().enumerate() {
            let selected = position == app.selected_backup_index;
            let response = ui.selectable_label(
                selected,
                RichText::new(format!("{}  {}", record.timestamp, record.description)),
            );
            if response.clicked() {
                app.safety_focus = SafetyFocus::Backups;
                app.selected_backup_index = position;
            }
            if selected {
                ui.label(theme::muted(&record.key_path));
            }
        }

        ui.add_space(8.0);
        if ui
            .add_enabled(
                !app.is_restoring,
                egui::Button::new("Restore the selected snapshot"),
            )
            .clicked()
        {
            app.request_rollback();
        }
    });
}

fn restore_points(ui: &mut egui::Ui, app: &mut App) {
    theme::card(ui, "SYSTEM RESTORE POINTS", |ui| {
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
                ui.label(RichText::new(point).size(12.0));
            }
        }

        ui.add_space(8.0);
        if ui.button("Refresh").clicked() {
            app.refresh_restore_points();
        }
    });
}
