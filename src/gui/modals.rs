//! The three overlays, stacked in the order the terminal front end stacked them.
//!
//! Precedence matters and is not cosmetic: a pending confirmation is a question
//! about the machine that must be answered before anything else happens, so it
//! outranks a setting being edited, which in turn outranks the help sheet.
//! [`crate::app::input`] enforces exactly the same order for the keyboard.

use crate::app::App;
use crate::gui::theme;
use eframe::egui::{self, RichText};

pub fn show(ctx: &egui::Context, app: &mut App) {
    if app.pending_confirm.is_some() {
        confirm(ctx, app);
    } else if app.setting_input.is_some() {
        setting_input(ctx, app);
    } else if app.show_help {
        help(ctx, app);
    }
}

/// The frame every overlay shares: modal, centred, not resizable.
fn modal_window(title: &str) -> egui::Modal {
    egui::Modal::new(egui::Id::new(title))
        .frame(theme::surface().inner_margin(24))
        .backdrop_color(egui::Color32::from_black_alpha(150))
}

fn confirm(ctx: &egui::Context, app: &mut App) {
    let Some(request) = app.pending_confirm.as_ref() else {
        return;
    };

    // Cloned out of `app` before the closure, which needs `app` mutably in
    // order to answer the question the request is asking.
    let title = request.title();
    let body = request.body();
    let confirm_label = request.confirm_label();
    let dismiss_label = request.dismiss_label();

    let mut confirmed = false;
    let mut dismissed = false;

    modal_window(title).show(ctx, |ui| {
        ui.set_max_width(560.0);
        ui.label(RichText::new(title).size(18.0).strong());
        ui.add_space(12.0);

        for line in &body {
            if line.is_empty() {
                ui.add_space(6.0);
            } else {
                ui.label(line);
            }
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            if ui.add(theme::primary_button(confirm_label)).clicked() {
                confirmed = true;
            }
            if ui.button(dismiss_label).clicked() {
                dismissed = true;
            }
        });
    });

    if confirmed {
        app.confirm_pending_action();
    } else if dismissed {
        app.dismiss_confirm();
    }
}

fn setting_input(ctx: &egui::Context, app: &mut App) {
    let mut submitted = false;
    let mut cancelled = false;

    // Held across the closure so the text field can write straight into the
    // buffer `submit_setting_input` validates.
    let Some(input) = app.setting_input.as_mut() else {
        return;
    };
    let title = input.setting_name.clone();
    let unit = input.unit.clone();
    let min = input.min_value;
    let max = input.max_value;
    let error = input.error_msg.clone();

    modal_window("Edit setting").show(ctx, |ui| {
        ui.set_max_width(420.0);
        ui.label(RichText::new("Edit setting").size(20.0).strong());
        ui.add_space(12.0);

        ui.label(RichText::new(&title).color(theme::CYAN).strong());
        ui.label(theme::muted(format!("Allowed: {min}–{max} {unit}")));
        ui.add_space(8.0);

        let field = ui.add(
            egui::TextEdit::singleline(&mut input.buffer)
                .desired_width(f32::INFINITY)
                .hint_text("Enter a number"),
        );
        // Opening the dialog should put the caret in the field, the way the
        // terminal front end put every keystroke there.
        if field.changed() {
            input.error_msg = None;
        }
        field.request_focus();

        if let Some(message) = error.as_deref() {
            ui.add_space(4.0);
            ui.label(RichText::new(message).color(theme::CORAL));
        }

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button("Save").clicked() || enter_pressed {
                submitted = true;
            }
            if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                cancelled = true;
            }
        });
    });

    if submitted {
        app.submit_setting_input();
    } else if cancelled {
        app.cancel_setting_input();
    }
}

fn help(ctx: &egui::Context, app: &mut App) {
    let mut close = false;

    modal_window("Keyboard shortcuts").show(ctx, |ui| {
        ui.set_max_width(520.0);
        ui.label(RichText::new("Keyboard shortcuts").size(20.0).strong());
        ui.add_space(12.0);
        ui.label(theme::muted(
            "Every action below is also a button in the window; these are the shortcuts.",
        ));
        ui.add_space(8.0);

        for (keys, description) in SHORTCUTS {
            ui.horizontal(|ui| {
                ui.label(RichText::new(*keys).color(theme::CYAN).strong());
                ui.label(*description);
            });
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);
        if ui.button("Close").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            close = true;
        }
    });

    if close {
        app.show_help = false;
    }
}

const SHORTCUTS: &[(&str, &str)] = &[
    ("1 – 5", "Jump to a tab"),
    ("Ctrl+Tab / Ctrl+Shift+Tab", "Cycle through the tabs"),
    ("S / R", "Start a health scan"),
    ("F", "Repair the selected issues"),
    ("D", "Toggle simulation mode"),
    ("A / N", "Select or deselect every issue"),
    ("Space", "Toggle the highlighted issue"),
    ("C / W / I", "Filter by critical, warning or info"),
    ("M / X", "Cycle the module filter, clear all filters"),
    ("E", "Export an HTML report"),
    ("U", "Roll back a registry backup (Settings & Safety)"),
    ("B", "Move focus between settings and backups"),
    (
        "Esc",
        "Unwind: filters, then focus, then a running operation",
    ),
    ("Q", "Quit"),
];
