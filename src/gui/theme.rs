//! The visual identity, carried over unchanged from the terminal front end.
//!
//! The palette is the same set of colours WinMedic has always used, because it
//! is the same product: cyan is the brand, and emerald / amber / coral are the
//! three severities the whole tool is organised around. What changed is only
//! how they reach the screen — egui takes `Color32` where ratatui took `Color`.

use crate::engine::issue::Severity;
use eframe::egui::{self, Color32, RichText, Stroke, Visuals};

// Cyber-Medic / Dark Slate palette.
/// Primary brand colour.
pub const CYAN: Color32 = Color32::from_rgb(0, 210, 255);
/// Success / healthy.
pub const EMERALD: Color32 = Color32::from_rgb(16, 185, 129);
/// Warning.
pub const AMBER: Color32 = Color32::from_rgb(245, 158, 11);
/// Critical / error.
pub const CORAL: Color32 = Color32::from_rgb(239, 68, 68);
/// Window background.
pub const BG_DEEP: Color32 = Color32::from_rgb(15, 23, 42);
/// Card and panel surface.
pub const CARD_SURFACE: Color32 = Color32::from_rgb(30, 41, 59);
/// Borders and inactive elements.
pub const BORDER: Color32 = Color32::from_rgb(71, 85, 105);
/// Secondary text.
pub const MUTED: Color32 = Color32::from_rgb(148, 163, 184);
/// Primary text.
pub const TEXT_WHITE: Color32 = Color32::from_rgb(248, 250, 252);
pub const ACCENT_PURPLE: Color32 = Color32::from_rgb(168, 85, 247);

/// The darkest surface, for sunken areas: log views and text fields.
///
/// The terminal front end got this for free — anything it did not paint was the
/// terminal's own background. A window has no such default, so the shade the
/// logs used to sit on has to be named.
pub const BG_SUNKEN: Color32 = Color32::from_rgb(2, 6, 23);

/// Install the palette on a freshly created context.
///
/// Called once at startup rather than per frame: egui keeps the style until it
/// is replaced, and rebuilding it every frame would throw away any adjustment
/// made in between.
pub fn apply(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    visuals.panel_fill = BG_DEEP;
    visuals.window_fill = CARD_SURFACE;
    visuals.faint_bg_color = CARD_SURFACE;
    visuals.extreme_bg_color = BG_SUNKEN;
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.hyperlink_color = CYAN;
    visuals.selection.bg_fill = CYAN.linear_multiply(0.35);
    visuals.selection.stroke = Stroke::new(1.0, CYAN);

    ctx.set_visuals(visuals);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
    });
}

/// The colour that stands for a severity, everywhere it is shown.
pub fn severity_color(severity: Severity) -> Color32 {
    match severity {
        Severity::Critical => CORAL,
        Severity::Warning => AMBER,
        Severity::Info => CYAN,
    }
}

/// The colour a health score should be read in.
///
/// The thresholds match what the score already means elsewhere in the tool, so
/// a machine the dashboard calls healthy is never painted in the warning colour.
pub fn health_color(score: u8) -> Color32 {
    match score {
        80..=100 => EMERALD,
        50..=79 => AMBER,
        _ => CORAL,
    }
}

/// A titled surface, the direct equivalent of the terminal front end's bordered
/// block. Everything that was a box on screen stays a box.
pub fn card<R>(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui) -> R) {
    egui::Frame::group(ui.style())
        .fill(CARD_SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .show(ui, |ui| {
            // Without this the frame shrinks to its content and a row of cards
            // ends up ragged, each one a different width.
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).color(CYAN).strong());
            ui.separator();
            add(ui);
        });
}

/// A small filled badge: the admin state, the simulation mode, a severity count.
pub fn badge(ui: &mut egui::Ui, text: &str, fill: Color32) {
    egui::Frame::NONE
        .fill(fill)
        .inner_margin(egui::Margin::symmetric(6, 2))
        .corner_radius(3)
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(BG_DEEP).strong().size(11.0));
        });
}

/// Muted secondary text, for everything that labels rather than reports.
pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).color(MUTED)
}
