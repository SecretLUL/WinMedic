//! Shared desktop palette, typography and reusable controls.

use crate::engine::issue::Severity;
use eframe::egui::{self, Color32, RichText, Stroke, Visuals};

pub const CYAN: Color32 = Color32::from_rgb(91, 214, 201);
pub const EMERALD: Color32 = Color32::from_rgb(105, 216, 162);
pub const AMBER: Color32 = Color32::from_rgb(239, 190, 104);
pub const CORAL: Color32 = Color32::from_rgb(244, 133, 143);
pub const BG_DEEP: Color32 = Color32::from_rgb(17, 22, 31);
pub const CARD_SURFACE: Color32 = Color32::from_rgb(25, 32, 43);
pub const BORDER: Color32 = Color32::from_rgb(43, 53, 67);
pub const MUTED: Color32 = Color32::from_rgb(153, 168, 187);
pub const TEXT_WHITE: Color32 = Color32::from_rgb(233, 239, 247);
pub const ACCENT_PURPLE: Color32 = Color32::from_rgb(183, 165, 239);
pub const BG_SUNKEN: Color32 = Color32::from_rgb(13, 18, 26);
pub const SELECTED: Color32 = Color32::from_rgb(31, 58, 62);
pub const HOVER: Color32 = Color32::from_rgb(36, 46, 60);

pub fn apply(ctx: &egui::Context) {
    // Use the Windows UI font when available, retaining the bundled fallbacks.
    if let Some(windows) = std::env::var_os("SystemRoot")
        && let Ok(data) = std::fs::read(std::path::PathBuf::from(windows).join("Fonts/segoeui.ttf"))
    {
        let mut fonts = egui::FontDefinitions::default();
        fonts
            .font_data
            .insert("Segoe UI".into(), egui::FontData::from_owned(data).into());
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "Segoe UI".into());
        ctx.set_fonts(fonts);
    }
    let mut visuals = Visuals::dark();
    visuals.panel_fill = BG_DEEP;
    visuals.window_fill = CARD_SURFACE;
    visuals.faint_bg_color = CARD_SURFACE;
    visuals.extreme_bg_color = BG_SUNKEN;
    visuals.override_text_color = Some(TEXT_WHITE);
    visuals.weak_text_color = Some(MUTED);
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.window_corner_radius = 16.into();
    visuals.hyperlink_color = CYAN;
    visuals.selection.bg_fill = SELECTED;
    visuals.selection.stroke = Stroke::new(1.0, CYAN);
    visuals.text_edit_bg_color = Some(BG_SUNKEN);
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = 8.into();
        widget.bg_stroke = Stroke::new(1.0, BORDER);
        widget.fg_stroke = Stroke::new(1.0, TEXT_WHITE);
        widget.expansion = 0.0;
    }
    visuals.widgets.noninteractive.bg_fill = CARD_SURFACE;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, MUTED);
    visuals.widgets.inactive.bg_fill = HOVER;
    visuals.widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
    visuals.widgets.hovered.bg_fill = HOVER;
    visuals.widgets.hovered.weak_bg_fill = HOVER;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, MUTED);
    visuals.widgets.active.bg_fill = SELECTED;
    visuals.widgets.active.weak_bg_fill = SELECTED;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, CYAN);
    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        for (kind, size) in [
            (egui::TextStyle::Heading, 28.0),
            (egui::TextStyle::Body, 14.0),
            (egui::TextStyle::Button, 14.0),
            (egui::TextStyle::Small, 12.0),
        ] {
            style
                .text_styles
                .insert(kind, egui::FontId::proportional(size));
        }
        style
            .text_styles
            .insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.0));
        style.spacing.item_spacing = egui::vec2(12.0, 8.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.spacing.interact_size.y = 34.0;
        style.spacing.window_margin = egui::Margin::same(24);
    });
}

pub fn severity_color(severity: Severity) -> Color32 {
    match severity {
        Severity::Critical => CORAL,
        Severity::Warning => AMBER,
        Severity::Info => CYAN,
    }
}

pub fn health_color(score: u8) -> Color32 {
    match score {
        80..=100 => EMERALD,
        50..=79 => AMBER,
        _ => CORAL,
    }
}

pub fn surface() -> egui::Frame {
    egui::Frame::NONE
        .fill(CARD_SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(14)
        .inner_margin(20)
}

pub fn card<R>(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui) -> R) {
    surface().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(muted(title).size(12.0).strong());
        ui.add_space(6.0);
        add(ui);
    });
}

pub fn primary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.into()).color(BG_SUNKEN).strong())
        .fill(CYAN)
        .stroke(Stroke::NONE)
        .min_size(egui::vec2(0.0, 38.0))
}

pub fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    let galley =
        ui.painter()
            .layout_no_wrap(text.to_owned(), egui::FontId::proportional(12.0), color);
    let (rect, response) =
        ui.allocate_exact_size(galley.size() + egui::vec2(16.0, 8.0), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, 6, color.gamma_multiply(0.12));
    ui.painter()
        .galley(rect.min + egui::vec2(8.0, 4.0), galley, color);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, text));
}

pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).color(MUTED)
}

/// Geometry stays crisp at every scale without relying on platform emoji fonts.
pub fn icon(ui: &egui::Ui, rect: egui::Rect, kind: usize, color: Color32) {
    let painter = ui.painter();
    let stroke = Stroke::new(1.6, color);
    let point = |x: f32, y: f32| rect.min + egui::vec2(x, y) * rect.width() / 20.0;
    let line = |points: &[(f32, f32)]| {
        painter.add(egui::Shape::line(
            points.iter().map(|&(x, y)| point(x, y)).collect(),
            stroke,
        ));
    };
    match kind {
        0 => {
            for (x, y) in [(2.0, 2.0), (12.0, 2.0), (2.0, 12.0), (12.0, 12.0)] {
                painter.rect_stroke(
                    egui::Rect::from_min_max(point(x, y), point(x + 6.0, y + 6.0)),
                    1,
                    stroke,
                    egui::StrokeKind::Inside,
                );
            }
        }
        1 => line(&[
            (1.0, 10.0),
            (5.0, 10.0),
            (8.0, 3.0),
            (12.0, 17.0),
            (15.0, 10.0),
            (19.0, 10.0),
        ]),
        2 => {
            for y in [4.0, 10.0, 16.0] {
                painter.circle_filled(point(3.0, y), 1.3, color);
                line(&[(7.0, y), (18.0, y)]);
            }
        }
        3 => {
            line(&[
                (10.0, 2.0),
                (17.0, 5.0),
                (16.0, 13.0),
                (10.0, 18.0),
                (4.0, 13.0),
                (3.0, 5.0),
                (10.0, 2.0),
            ]);
            line(&[(7.0, 10.0), (13.0, 10.0)]);
            line(&[(10.0, 7.0), (10.0, 13.0)]);
        }
        _ => {
            for (y, x) in [(4.0, 7.0), (10.0, 14.0), (16.0, 7.0)] {
                line(&[(2.0, y), (18.0, y)]);
                painter.circle_filled(point(x, y), 2.5, CARD_SURFACE);
                painter.circle_stroke(point(x, y), 2.5, stroke);
            }
        }
    }
}
