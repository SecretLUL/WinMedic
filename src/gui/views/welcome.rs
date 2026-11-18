//! The introduction a first start opens with ([`crate::app::welcome`]).
//!
//! Three short pages in Easy mode's column: what WinMedic does, the two
//! buttons that do it, and what can be left alone. Each says only what the
//! window itself says later. Skip is as big as Next, for whoever has done
//! this before.

use crate::app::App;
use crate::app::welcome::PAGES;
use crate::gui::theme;
use eframe::egui::{self, RichText};

/// As wide as Easy mode's page, which is what comes after it.
const COLUMN: f32 = 620.0;

/// The room every page's text gets, so that the buttons under it stand where
/// they stood on the page before: Next is clicked three times in one place.
const TEXT_HEIGHT: f32 = 270.0;

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    let Some(page) = app.welcome else {
        return;
    };
    egui::ScrollArea::vertical()
        .id_salt("welcome_page")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let width = ui.available_width().min(COLUMN);
            ui.add_space(28.0);
            ui.horizontal_top(|ui| {
                ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
                ui.vertical(|ui| {
                    ui.set_width(width);
                    ui.allocate_ui_with_layout(
                        egui::vec2(width, TEXT_HEIGHT),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_min_height(TEXT_HEIGHT);
                            ui.label(theme::muted(format!(
                                "Introduction, page {} of {PAGES}",
                                page + 1
                            )));
                            ui.add_space(6.0);
                            match page {
                                0 => what_it_does(ui),
                                1 => what_to_press(ui, app),
                                _ => what_to_leave_alone(ui),
                            }
                        },
                    );
                    ui.add_space(16.0);
                    buttons(ui, app, page);
                });
            });
        });
}

fn headline(ui: &mut egui::Ui, text: &str) {
    ui.label(theme::heading(ui, text, 26.0));
    ui.add_space(8.0);
}

fn line(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).size(15.0));
}

fn what_it_does(ui: &mut egui::Ui) {
    headline(ui, "Welcome to WinMedic");
    line(
        ui,
        "WinMedic finds common Windows problems and repairs them.",
    );
    ui.add_space(6.0);
    line(
        ui,
        "Two buttons do all of it. The next pages show which they are, \
         and what you can leave alone.",
    );
    ui.add_space(14.0);
    ui.label(theme::muted(
        "You have repaired Windows before? Skip the introduction.",
    ));
}

fn what_to_press(ui: &mut egui::Ui, app: &App) {
    headline(ui, "Scan first, then repair");
    step(
        ui,
        "1",
        "Scan now",
        "Checks your PC for problems. A scan changes nothing.",
    );
    ui.add_space(12.0);
    // Only what the next repair does: Help shows this page again, and the
    // restore point may have been switched off in Settings since.
    // "What it can": hardware errors and the like are advice, which no
    // repair run touches.
    let repair = if app.config.create_vss_before_repair {
        "Repairs what WinMedic can fix. A restore point is created first."
    } else {
        "Repairs what WinMedic can fix."
    };
    step(ui, "2", "Repair", repair);
    ui.add_space(14.0);
    ui.label(theme::muted(
        "Before you repair, the page says what the repair does and about how long it takes. \
         WinMedic never restarts your PC without asking.",
    ));
}

fn what_to_leave_alone(ui: &mut egui::Ui) {
    headline(ui, "What you can leave alone");
    line(ui, "You need neither of these to repair your PC:");
    ui.add_space(10.0);
    item(
        ui,
        "Advanced mode (F7)",
        "Every finding with its technical details, the filters and the logs.",
    );
    ui.add_space(10.0);
    item(
        ui,
        "Settings",
        "How WinMedic works. Nothing there has to be changed.",
    );
    ui.add_space(14.0);
    ui.label(theme::muted(
        "Help, at the top right, shows this introduction again.",
    ));
}

/// One of the two things to press: its number, the button's name, what it
/// does.
fn step(ui: &mut egui::Ui, number: &str, name: &str, text: &str) {
    ui.horizontal_top(|ui| {
        let palette = theme::palette(ui);
        let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(30.0), egui::Sense::hover());
        ui.painter()
            .circle_filled(rect.center(), 15.0, palette.accent);
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            number,
            egui::FontId::proportional(16.0),
            palette.on_accent,
        );
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.label(theme::heading(ui, name, 17.0));
            line(ui, text);
        });
    });
}

fn item(ui: &mut egui::Ui, name: &str, text: &str) {
    ui.label(theme::heading(ui, name, 17.0));
    line(ui, text);
}

fn buttons(ui: &mut egui::Ui, app: &mut App, page: usize) {
    let last = page + 1 == PAGES;
    ui.horizontal(|ui| {
        let forward = if last { "Get started" } else { "Next" };
        if theme::big_button(ui, forward, Some("Enter"), true, true).clicked() {
            app.welcome_next();
        }
        // The last page's own button leaves the introduction.
        if !last && theme::big_button(ui, "Skip", Some("Esc"), false, true).clicked() {
            app.close_welcome();
        }
        if page > 0 && ui.button("Back").clicked() {
            app.welcome_back();
        }
    });
}
