//! The one question WinMedic asks: whether to share anonymous usage data
//! ([`crate::app::usage`]).
//!
//! It follows a first start's introduction and takes the whole window, as
//! the introduction does. The page says what is sent, what never is, where
//! it goes and what it is for, and "Show exactly what is sent" opens the
//! report itself. Nothing is hidden behind a second click that a yes would
//! cover.
//!
//! Neither button is the filled one, and No stands where the introduction's
//! Next stood: whoever clicked through the introduction in one place has not
//! agreed to anything by the click after it.

use crate::app::{App, TAB_SETTINGS};
use crate::gui::theme;
use eframe::egui::{self, RichText};

/// As wide as the introduction's column, which came before it.
const COLUMN: f32 = 620.0;

/// The room the two answers take under the text, with the space above them.
const ANSWERS: f32 = 70.0;

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    let Some(receiver) = app.usage_receiver else {
        return;
    };
    let whole = ui.available_rect_before_wrap();
    let width = whole.width().min(COLUMN);
    let left = whole.left() + (whole.width() - width) / 2.0;
    let column = egui::Rect::from_min_max(
        egui::pos2(left, whole.top()),
        egui::pos2(left + width, whole.bottom()),
    );
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(column)
            .layout(egui::Layout::top_down(egui::Align::Min)),
        |ui| {
            ui.add_space(28.0);
            // The text scrolls where the window is too small for it (1920 x
            // 1080 at 175 % leaves 527 points); the answers never do. A
            // question whose buttons are below the fold is not asked.
            egui::ScrollArea::vertical()
                .id_salt("usage_question")
                .max_height((ui.available_height() - ANSWERS).max(0.0))
                .auto_shrink([false, true])
                .show(ui, |ui| text(ui, app, receiver));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if theme::big_button(ui, "No, thanks", Some("Esc"), false, true).clicked() {
                    app.answer_usage_question(false);
                }
                if theme::big_button(ui, "Yes, share", None, false, true).clicked() {
                    app.answer_usage_question(true);
                }
            });
        },
    );
}

fn text(ui: &mut egui::Ui, app: &mut App, receiver: crate::utils::usage_data::Receiver) {
    // The same page answers the switch in Settings, which has no "start".
    ui.label(theme::muted(if app.active_tab == TAB_SETTINGS {
        "Settings > General"
    } else {
        "One question before you start"
    }));
    ui.add_space(6.0);
    ui.label(theme::heading(ui, "Share anonymous usage data?", 26.0));
    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "If you agree, WinMedic sends a short report after each scan and each repair. It \
             shows which checks find problems and which repairs fail, so that the next \
             version fixes what goes wrong most.",
        )
        .size(15.0),
    );
    ui.add_space(12.0);
    part(
        ui,
        "What is sent",
        "The WinMedic version, the Windows build number, Easy or Advanced mode, how long the \
         scan took, the health score, and for each check only numbers: found, repaired, \
         failed. With them go the time of the report and a random number that is new every \
         time WinMedic starts.",
    );
    part(
        ui,
        "What is never sent",
        "Names of devices, files or folders, your user name, the name of your computer, the \
         text of a finding, or any number that stays the same from one start to the next.",
    );
    part(ui, "Where it goes", receiver.where_it_goes);
    if ui.link("Show exactly what is sent").clicked() {
        app.open_usage_preview();
    }
    ui.add_space(12.0);
    ui.label(theme::muted(
        "Nothing is sent unless you choose Yes. Settings > General changes it at any time.",
    ));
}

/// One of the three things the page owes an answer to: its name, and the
/// answer in a sentence or two.
fn part(ui: &mut egui::Ui, name: &str, text: &str) {
    ui.label(theme::heading(ui, name, 15.0));
    ui.label(text);
    ui.add_space(8.0);
}
