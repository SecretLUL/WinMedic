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

/// A polygon with its corners traded for curves.
///
/// A triangle drawn from three points has three needle-sharp corners: at list
/// size they alias into stray bright pixels, and beside the octagon and the
/// disc they read as a shape from a different family. Each corner becomes a
/// quadratic curve through it, which at these sizes is indistinguishable from
/// an arc and far less arithmetic.
fn rounded_corners(points: &[egui::Pos2], radius: f32) -> Vec<egui::Pos2> {
    const STEPS: usize = 4;
    let count = points.len();
    let mut path = Vec::with_capacity(count * (STEPS + 1));
    for index in 0..count {
        let corner = points[index];
        let cut = |neighbour: egui::Pos2| corner + (neighbour - corner).normalized() * radius;
        let (from, to) = (
            cut(points[(index + count - 1) % count]),
            cut(points[(index + 1) % count]),
        );
        for step in 0..=STEPS {
            let t = step as f32 / STEPS as f32;
            path.push(from.lerp(corner, t).lerp(corner.lerp(to, t), t));
        }
    }
    path
}

/// The mark that stands for a severity: an octagon, a triangle, a disc.
///
/// Painted rather than typed, for the same reason [`icon`] is. A window ships
/// its own fonts, egui's have no warning sign in them, and a written mark would
/// reach some machines as an empty box. Geometry reaches all of them, and stays
/// sharp at the 13px a list row gives it and the 20px a card does.
pub fn severity_icon(ui: &egui::Ui, rect: egui::Rect, severity: Severity) {
    let painter = ui.painter();
    let color = severity_color(severity);
    let center = rect.center();
    let radius = rect.width().min(rect.height()) / 2.0;
    let outline = Stroke::new((radius * 0.2).max(1.0), color);
    // Washed with its own colour rather than left hollow: at list size that is
    // what lets the three outlines tell themselves apart at a glance.
    let wash = color.gamma_multiply(0.18);

    // Each outline, and where the exclamation inside it belongs — in fractions
    // of the radius. A triangle carries its weight low, so its mark sits lower
    // than the octagon's, and an `i` is the one that is upside down.
    let (stem, dot) = match severity {
        Severity::Critical => {
            // The stop sign, for the findings that cannot wait.
            let corners = (0..8)
                .map(|corner| {
                    let angle = std::f32::consts::TAU * (corner as f32 + 0.5) / 8.0;
                    center + egui::vec2(angle.cos(), angle.sin()) * radius
                })
                .collect();
            painter.add(egui::Shape::convex_polygon(corners, wash, outline));
            (-0.46..0.12, 0.40)
        }
        Severity::Warning => {
            painter.add(egui::Shape::convex_polygon(
                rounded_corners(
                    &[
                        center + egui::vec2(0.0, -radius * 0.98),
                        center + egui::vec2(radius * 1.0, radius * 0.72),
                        center + egui::vec2(-radius * 1.0, radius * 0.72),
                    ],
                    radius * 0.22,
                ),
                wash,
                outline,
            ));
            (-0.34..0.14, 0.42)
        }
        Severity::Info => {
            painter.circle_filled(center, radius * 0.94, wash);
            painter.circle_stroke(center, radius * 0.94, outline);
            (-0.12..0.50, -0.44)
        }
    };

    let width = (radius * 0.26).max(1.5);
    painter.rect_filled(
        egui::Rect::from_min_max(
            center + egui::vec2(-width / 2.0, stem.start * radius),
            center + egui::vec2(width / 2.0, stem.end * radius),
        ),
        width / 2.0,
        color,
    );
    painter.circle_filled(center + egui::vec2(0.0, dot * radius), width * 0.6, color);
}

/// The severity mark on its own, for a row with no room for a word.
///
/// It still announces itself: the shape is the whole label on screen, so a
/// reader that cannot see it would otherwise be told nothing at all.
pub fn severity_mark(ui: &mut egui::Ui, severity: Severity, size: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::Vec2::splat(size), egui::Sense::hover());
    severity_icon(ui, rect, severity);
    let name = severity.name();
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, name));
    response.on_hover_text(name)
}

/// A severity pill: the mark, then the word, in the severity's colour.
pub fn severity_badge(ui: &mut egui::Ui, severity: Severity) -> egui::Response {
    let color = severity_color(severity);
    let name = severity.name();
    let galley =
        ui.painter()
            .layout_no_wrap(name.to_owned(), egui::FontId::proportional(11.0), color);
    let mark = 14.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(
            galley.size().x + mark + 24.0,
            galley.size().y.max(mark) + 8.0,
        ),
        egui::Sense::hover(),
    );
    ui.painter()
        .rect_filled(rect, 7, color.gamma_multiply(0.12));
    severity_icon(
        ui,
        egui::Rect::from_center_size(
            egui::pos2(rect.left() + 9.0 + mark / 2.0, rect.center().y),
            egui::Vec2::splat(mark),
        ),
        severity,
    );
    ui.painter().galley(
        egui::pos2(
            rect.left() + mark + 15.0,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        color,
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, name));
    response
}

/// The triage filter for one severity: the same mark, but it can be pressed.
pub fn severity_chip(ui: &mut egui::Ui, severity: Severity, active: bool) -> egui::Response {
    let color = severity_color(severity);
    let label = severity.short_label();
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::FontId::proportional(12.0),
        if active { color } else { MUTED },
    );
    let mark = 13.0;
    let response = ui.allocate_response(
        egui::vec2(galley.size().x + mark + 26.0, 30.0),
        egui::Sense::click(),
    );
    let rect = response.rect;
    let (fill, border) = if active {
        (color.gamma_multiply(0.18), color)
    } else if response.hovered() {
        (HOVER, MUTED)
    } else {
        (Color32::TRANSPARENT, BORDER)
    };
    ui.painter().rect(
        rect,
        8,
        fill,
        Stroke::new(1.0, border),
        egui::StrokeKind::Inside,
    );
    severity_icon(
        ui,
        egui::Rect::from_center_size(
            egui::pos2(rect.left() + 9.0 + mark / 2.0, rect.center().y),
            egui::Vec2::splat(mark),
        ),
        severity,
    );
    ui.painter().galley(
        egui::pos2(
            rect.left() + mark + 16.0,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        color,
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, active, label)
    });
    response
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
