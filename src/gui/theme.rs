//! Typography, spacing and the few colours the views share.
//!
//! Deliberately plain. The window uses egui's stock light and dark visuals,
//! follows the Windows app theme, and draws in Segoe UI at the density of a
//! regular Windows tool. Colour is kept for what it means — severity and the
//! outcome of a check or repair — and not spent on decoration.

use crate::engine::issue::Severity;
use eframe::egui::{self, Color32, RichText, Stroke};

/// The status colours, picked per theme so each stays legible on its panel.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub red: Color32,
    pub amber: Color32,
    pub green: Color32,
    pub blue: Color32,
}

const DARK: Palette = Palette {
    red: Color32::from_rgb(240, 110, 110),
    amber: Color32::from_rgb(230, 175, 60),
    green: Color32::from_rgb(100, 195, 120),
    blue: Color32::from_rgb(100, 170, 240),
};

/// The Windows 11 status colours for light surfaces.
const LIGHT: Palette = Palette {
    red: Color32::from_rgb(196, 43, 28),
    amber: Color32::from_rgb(157, 93, 0),
    green: Color32::from_rgb(15, 123, 15),
    blue: Color32::from_rgb(0, 95, 184),
};

pub fn palette(ui: &egui::Ui) -> Palette {
    if ui.visuals().dark_mode { DARK } else { LIGHT }
}

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

    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        let mut visuals = theme.default_visuals();
        // egui's stock body text is a mid grey, which is fine for a demo and
        // tiring for a findings list. Lift it toward the panel's opposite end;
        // secondary text stays where egui put body text.
        let (text, weak) = match theme {
            egui::Theme::Dark => (Color32::from_gray(215), Color32::from_gray(145)),
            egui::Theme::Light => (Color32::from_gray(25), Color32::from_gray(105)),
        };
        visuals.widgets.noninteractive.fg_stroke.color = text;
        visuals.weak_text_color = Some(weak);
        // A resting control gets an outline, as it does in Windows. Without
        // one, an unticked checkbox and an empty search field are all but
        // invisible on the light panel.
        visuals.widgets.inactive.bg_stroke = Stroke::new(
            1.0,
            match theme {
                egui::Theme::Dark => Color32::from_gray(80),
                egui::Theme::Light => Color32::from_gray(165),
            },
        );
        visuals.window_corner_radius = 4.into();
        visuals.menu_corner_radius = 4.into();
        for widget in [
            &mut visuals.widgets.noninteractive,
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            widget.corner_radius = 3.into();
        }
        ctx.set_visuals_of(theme, visuals);
    }

    ctx.all_styles_mut(|style| {
        for (kind, size) in [
            (egui::TextStyle::Heading, 16.0),
            (egui::TextStyle::Body, 13.5),
            (egui::TextStyle::Button, 13.5),
            (egui::TextStyle::Small, 11.5),
        ] {
            style
                .text_styles
                .insert(kind, egui::FontId::proportional(size));
        }
        style
            .text_styles
            .insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.0));
        style.spacing.item_spacing = egui::vec2(8.0, 5.0);
        style.spacing.button_padding = egui::vec2(10.0, 3.0);
        style.spacing.interact_size.y = 22.0;
        style.spacing.window_margin = egui::Margin::same(14);
    });
}

pub fn severity_color(ui: &egui::Ui, severity: Severity) -> Color32 {
    let palette = palette(ui);
    match severity {
        Severity::Critical => palette.red,
        Severity::Warning => palette.amber,
        Severity::Info => palette.blue,
    }
}

pub fn health_color(ui: &egui::Ui, score: u8) -> Color32 {
    let palette = palette(ui);
    match score {
        80..=100 => palette.green,
        50..=79 => palette.amber,
        _ => palette.red,
    }
}

/// Secondary text: hints, metadata, anything the eye should pass over.
pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).weak()
}

/// A section heading inside a tab.
pub fn section(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(title).strong().size(14.5));
    ui.add_space(2.0);
}

/// Lay out `add` top to bottom, left aligned and *not* justified.
///
/// `ui.columns` hands each column a justified layout, and justified text is
/// spread word by word to the column edge — which reads as broken prose.
pub fn plain<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.with_layout(egui::Layout::top_down(egui::Align::Min), add)
        .inner
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
/// Painted rather than typed. A window ships its own fonts, egui's have no
/// warning sign in them, and a written mark would reach some machines as an
/// empty box. Geometry reaches all of them. The shapes differ as well as the
/// colours, so the three stay apart for a reader who cannot tell red from amber.
pub fn severity_icon(ui: &egui::Ui, rect: egui::Rect, severity: Severity) {
    let painter = ui.painter();
    let color = severity_color(ui, severity);
    let center = rect.center();
    let radius = rect.width().min(rect.height()) / 2.0;
    let outline = Stroke::new((radius * 0.2).max(1.0), color);
    let wash = color.gamma_multiply(0.15);

    // Each outline, and where the exclamation inside it belongs — in fractions
    // of the radius. A triangle carries its weight low, so its mark sits lower
    // than the octagon's, and an `i` is the one that is upside down.
    let (stem, dot) = match severity {
        Severity::Critical => {
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

/// A usage bar that turns amber, then red, as it fills.
pub fn usage_bar(ui: &mut egui::Ui, fraction: f32, width: f32) -> egui::Response {
    let fraction = fraction.clamp(0.0, 1.0);
    let palette = palette(ui);
    let mut bar = egui::ProgressBar::new(fraction)
        .desired_width(width)
        .desired_height(10.0)
        .corner_radius(2);
    if fraction >= 0.9 {
        bar = bar.fill(palette.red);
    } else if fraction >= 0.75 {
        bar = bar.fill(palette.amber);
    }
    ui.add(bar)
}
