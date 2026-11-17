//! Settings and the safety surface on one tab: what WinMedic is allowed to do
//! to this machine, and how to undo what it has already done.
//!
//! These were two tabs in the terminal front end and were merged for a reason
//! that still holds — every action the backup list offers is the same kind of
//! "what may this tool touch" decision the settings list is made of.
//!
//! The tab shows one page at a time ([`SettingsPage`]), picked from a list on
//! the left, as the Settings of Windows do. All of it at once was two columns
//! of small print in Easy mode's window, which cannot be made larger.

use crate::app::{App, SafetyFocus, SettingsPage};
use crate::gui::theme;
use eframe::egui::{self, RichText};

/// The width of the list of pages on the left.
const RAIL: f32 = 180.0;

/// The room between the list of pages and the page.
const GUTTER: f32 = 24.0;

/// The widest a page's column gets: a line of explanation stays a line the
/// eye follows without the head turning, also in a maximized window.
const COLUMN: f32 = 640.0;

/// How far a setting's name stands in from the left: the width of a tick
/// box and its gap, so that the names form one edge whether or not a box
/// hangs in front of them.
const NAME_INDENT: f32 = 24.0;

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    let page = app.settings_page();
    let whole = ui.available_rect_before_wrap();
    let (list, rest) = whole.split_left_right_at_x(whole.left() + RAIL);
    let rest = rest.with_min_x(rest.left() + GUTTER);

    let top_down = egui::Layout::top_down(egui::Align::Min);
    ui.scope_builder(
        egui::UiBuilder::new().max_rect(list).layout(top_down),
        |ui| pages(ui, app, page),
    );
    ui.scope_builder(
        egui::UiBuilder::new().max_rect(rest).layout(top_down),
        |ui| {
            egui::ScrollArea::vertical()
                .id_salt(("settings_page", page.title()))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_max_width(ui.available_width().min(COLUMN));
                    ui.label(theme::heading(ui, page.title(), 20.0));
                    ui.label(theme::muted(page.summary()));
                    ui.add_space(10.0);
                    for &index in page.settings() {
                        setting(ui, app, index);
                    }
                    match page {
                        SettingsPage::Repairs => {}
                        SettingsPage::Undo => {
                            backups(ui, app);
                            ui.add_space(SECTION_GAP);
                            restore_points(ui, app);
                        }
                        SettingsPage::Scans => {
                            ui.add_space(SECTION_GAP);
                            archived(ui, app);
                        }
                        SettingsPage::Logs => {
                            ui.add_space(SECTION_GAP);
                            activity(ui, app);
                            ui.add_space(SECTION_GAP);
                            log_folder(ui, app);
                        }
                        SettingsPage::General => {
                            ui.add_space(SECTION_GAP);
                            remove(ui, app);
                        }
                    }
                });
        },
    );
}

/// The room above a section that follows something else on its page.
const SECTION_GAP: f32 = 16.0;

/// The list of pages. The one on screen carries the accent mark Windows
/// gives the current entry of a navigation list.
fn pages(ui: &mut egui::Ui, app: &mut App, current: SettingsPage) {
    ui.spacing_mut().item_spacing.y = 2.0;
    for page in SettingsPage::ALL {
        let selected = page == current;
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 32.0), egui::Sense::click());
        response.widget_info(|| {
            egui::WidgetInfo::selected(egui::Role::Tab, true, selected, page.title())
        });

        let widgets = &ui.visuals().widgets;
        let fill = if selected {
            Some(widgets.inactive.weak_bg_fill)
        } else if response.hovered() {
            Some(widgets.hovered.weak_bg_fill.gamma_multiply(0.6))
        } else {
            None
        };
        if let Some(fill) = fill {
            ui.painter().rect_filled(rect, 4, fill);
        }
        if selected {
            let mark = egui::Rect::from_center_size(
                egui::pos2(rect.left() + 1.5, rect.center().y),
                egui::vec2(3.0, 16.0),
            );
            ui.painter()
                .rect_filled(mark, 1.5, theme::palette(ui).accent);
        }
        let color = if selected {
            ui.visuals().strong_text_color()
        } else {
            ui.visuals().text_color()
        };
        ui.painter().text(
            egui::pos2(rect.left() + 12.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            page.title(),
            egui::TextStyle::Body.resolve(ui.style()),
            color,
        );

        if response.clicked() {
            app.open_settings_page(page);
        }
    }
}

/// The settings that take a number, and open the input dialog to get one.
fn is_numeric(index: usize) -> bool {
    matches!(index, 4 | 5 | 8)
}

/// The two lists of the Settings view the arrow keys move through, as
/// [`theme::keep_in_view`] tells them apart: going from one to the other is a
/// move too.
const SETTING_ROWS: usize = 0;
const BACKUP_ROWS: usize = 1;

/// One setting: its name with the tick box or the value, and under it one
/// line on what it does. The row the arrow keys point at is tinted, so the
/// keyboard moves something visible.
fn setting(ui: &mut egui::Ui, app: &mut App, index: usize) {
    let Some((label, value, explanation)) = app.config.setting_row(index) else {
        return;
    };
    // The keyboard hints live in the help sheet; the description keeps only
    // what the setting does.
    let description = explanation.split(" [").next().unwrap_or(explanation);
    let keyboard = !app.backups_focused() && index == app.selected_setting_index;

    let fill = if keyboard {
        ui.visuals().selection.bg_fill.gamma_multiply(0.2)
    } else {
        egui::Color32::TRANSPARENT
    };
    let row = egui::Frame::NONE
        .fill(fill)
        .corner_radius(4)
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let clicked = if is_numeric(index) {
                ui.horizontal(|ui| {
                    ui.add_space(NAME_INDENT);
                    ui.label(label);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let clicked = ui.button("Change").clicked();
                        ui.label(RichText::new(&value).strong());
                        clicked
                    })
                    .inner
                })
                .inner
            } else {
                let mut on = value == "ON";
                theme::checkbox(ui, &mut on, label).changed()
            };
            egui::Frame::NONE
                .inner_margin(egui::Margin {
                    left: NAME_INDENT as i8,
                    ..egui::Margin::ZERO
                })
                .show(ui, |ui| ui.label(theme::muted(description).size(12.5)));
            clicked
        });
    if keyboard {
        theme::keep_in_view(ui, "settings", (SETTING_ROWS, index), row.response.rect);
    }

    if row.inner {
        app.safety_focus = SafetyFocus::Settings;
        app.selected_setting_index = index;
        if is_numeric(index) {
            app.open_setting_input();
        } else {
            app.toggle_current_setting();
        }
    }
}

/// The findings the user archived, each with the way back.
fn archived(ui: &mut egui::Ui, app: &mut App) {
    theme::section(ui, "Archived findings");
    if app.config.archived_findings.is_empty() {
        ui.label(theme::muted("Nothing archived."));
        return;
    }
    let busy = app.is_busy();
    let mut show_again = None;
    for entry in &app.config.archived_findings {
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new("Show again"))
                    .clicked()
                {
                    show_again = Some(entry.id.clone());
                }
                ui.label(theme::muted(&entry.archived_at));
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add(egui::Label::new(&entry.title).truncate());
                });
            });
        });
    }
    if let Some(id) = show_again {
        app.show_archived_again(&id);
    }
}

fn log_folder(ui: &mut egui::Ui, app: &App) {
    theme::section(ui, "Log folder");
    let folder = app
        .audit_logger
        .log_dir()
        .map_or_else(|| "Not recorded".into(), |dir| dir.to_string_lossy());
    ui.label(RichText::new(folder).monospace());
    ui.label(theme::muted(
        "Every scan, repair, simulation and rollback is recorded here.",
    ));
}

fn remove(ui: &mut egui::Ui, app: &mut App) {
    theme::section(ui, "Remove from this PC");
    ui.label(theme::muted(
        "Deletes WinMedic and everything it keeps on this PC: the program, its \
         settings, logs, reports and registry backups. Nothing is left to do by hand.",
    ));
    ui.add_space(4.0);
    if theme::danger_button(ui, "Remove WinMedic from this PC")
        .on_hover_text("Asks for confirmation first")
        .clicked()
    {
        app.request_remove();
    }
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
        if selected && focused {
            theme::keep_in_view(ui, "settings", (BACKUP_ROWS, position), response.rect);
        }
        if selected {
            // Under the text of its row, which a selectable label insets.
            ui.horizontal(|ui| {
                ui.add_space(ui.spacing().button_padding.x - ui.spacing().item_spacing.x);
                ui.label(RichText::new(&record.key_path).monospace().weak());
            });
        }
    }

    ui.add_space(4.0);
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
    const SHOWN: usize = crate::safety::audit::RECENT_ENTRIES;
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
