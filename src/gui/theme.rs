//! Typography, spacing and the few colours the views share.
//!
//! Deliberately plain. The window uses egui's stock light and dark visuals,
//! follows the Windows app theme, and draws in Segoe UI at the density of a
//! regular Windows tool. Colour is kept for what it means — severity, the
//! outcome of a check or repair, what is ticked and the one button that takes
//! something away — and not spent on decoration.

use crate::engine::issue::Severity;
use eframe::egui::{self, Color32, RichText, Stroke};

/// The status colours, picked per theme so each stays legible on its panel.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub red: Color32,
    pub amber: Color32,
    pub green: Color32,
    pub blue: Color32,
    /// What Windows 11 fills a ticked box with: its default accent colour.
    pub accent: Color32,
    /// The tick on [`Palette::accent`].
    pub on_accent: Color32,
}

const DARK: Palette = Palette {
    red: Color32::from_rgb(240, 110, 110),
    amber: Color32::from_rgb(230, 175, 60),
    green: Color32::from_rgb(100, 195, 120),
    blue: Color32::from_rgb(100, 170, 240),
    accent: Color32::from_rgb(96, 205, 255),
    on_accent: Color32::BLACK,
};

/// The Windows 11 status colours for light surfaces.
const LIGHT: Palette = Palette {
    red: Color32::from_rgb(196, 43, 28),
    amber: Color32::from_rgb(157, 93, 0),
    green: Color32::from_rgb(15, 123, 15),
    blue: Color32::from_rgb(0, 95, 184),
    accent: Color32::from_rgb(0, 95, 184),
    on_accent: Color32::WHITE,
};

/// The fill of a button that takes something away, in either theme: Windows
/// 11's critical red, which carries white text at 5.7:1.
const DANGER: Color32 = Color32::from_rgb(196, 43, 28);

pub fn palette(ui: &egui::Ui) -> Palette {
    palette_of(ui.visuals())
}

/// The status colours for `visuals`, the dark or the light theme.
pub fn palette_of(visuals: &egui::Visuals) -> Palette {
    if visuals.dark_mode { DARK } else { LIGHT }
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

/// The background of a Windows 11 caution bar: something to do, not an error.
pub fn caution_fill(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(67, 53, 25)
    } else {
        Color32::from_rgb(255, 244, 206)
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

/// A large button for Easy mode, where the next step should be impossible to
/// miss. `primary` fills it with the accent colour.
pub fn big_button(ui: &mut egui::Ui, text: &str, primary: bool, enabled: bool) -> egui::Response {
    let visuals = ui.visuals();
    let mut label = RichText::new(text).size(17.0).strong();
    if primary {
        label = label.color(visuals.strong_text_color());
    }
    let mut button = egui::Button::new(label).min_size(egui::vec2(210.0, 46.0));
    if primary {
        button = button.fill(visuals.selection.bg_fill);
    }
    ui.add_enabled(enabled, button)
}

/// A button that takes something away, filled red.
pub fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    filled_button(ui, RichText::new(text), DANGER, Color32::WHITE)
}

/// How much of a filled control's colour still shows over the panel under
/// the pointer, and while it is pressed. Windows fades its accent controls
/// the same way, by a tenth and a fifth; a little less here, so that the text
/// on them keeps 4.5:1 in every state.
const HOVERED: f32 = 0.92;
const PRESSED: f32 = 0.85;

/// A button in `fill` with its label in `text`, fading toward the panel
/// under the pointer the way a Windows accent button does.
fn filled_button(
    ui: &mut egui::Ui,
    label: RichText,
    fill: Color32,
    text: Color32,
) -> egui::Response {
    ui.scope(|ui| {
        let panel = ui.visuals().panel_fill;
        let widgets = &mut ui.visuals_mut().widgets;
        for (state, share) in [
            (&mut widgets.inactive, 1.0),
            (&mut widgets.hovered, HOVERED),
            (&mut widgets.active, PRESSED),
        ] {
            state.weak_bg_fill = panel.lerp_to_gamma(fill, share);
            state.bg_stroke = Stroke::NONE;
        }
        ui.add(egui::Button::new(label.color(text)))
    })
    .inner
}

/// The side of a checkbox, in points.
const CHECKBOX: f32 = 16.0;

/// A checkbox the way Windows 11 draws one: ticked, the box is filled with
/// the accent colour around a bold tick; clear, it is an empty outline.
///
/// egui paints both states in the same grey and the tick as a hairline, and
/// down a list of findings the ticked and the clear ones looked alike.
pub fn checkbox(
    ui: &mut egui::Ui,
    checked: &mut bool,
    text: impl Into<egui::WidgetText>,
) -> egui::Response {
    let text = text.into();
    let gap = ui.spacing().icon_spacing;
    let galley = (!text.is_empty()).then(|| {
        text.into_galley(
            ui,
            None,
            ui.available_width() - CHECKBOX - gap,
            egui::TextStyle::Body,
        )
    });
    let mut size = egui::vec2(CHECKBOX, ui.spacing().interact_size.y);
    if let Some(galley) = &galley {
        size.x += gap + galley.size().x;
        size.y = size.y.max(galley.size().y);
    }

    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::Checkbox,
            ui.is_enabled(),
            *checked,
            galley.as_ref().map_or("", |galley| galley.text()),
        )
    });

    if ui.is_rect_visible(rect) {
        let visuals = ui.visuals();
        let palette = palette(ui);
        let painter = ui.painter();
        let square = egui::Rect::from_center_size(
            egui::pos2(rect.left() + CHECKBOX / 2.0, rect.center().y),
            egui::Vec2::splat(CHECKBOX),
        );
        if *checked {
            let share = if response.is_pointer_button_down_on() {
                PRESSED
            } else if response.hovered() {
                HOVERED
            } else {
                1.0
            };
            painter.rect_filled(
                square,
                4,
                visuals.panel_fill.lerp_to_gamma(palette.accent, share),
            );
            tick(
                painter,
                square.shrink(3.0),
                Stroke::new(2.0, palette.on_accent),
            );
        } else {
            painter.rect(
                square,
                4,
                clear_box(visuals, response.hovered()),
                Stroke::new(1.0, visuals.weak_text_color()),
                egui::StrokeKind::Inside,
            );
        }
        if response.has_focus() {
            painter.rect_stroke(
                square.expand(2.0),
                6,
                visuals.selection.stroke,
                egui::StrokeKind::Outside,
            );
        }
        if let Some(galley) = galley {
            let at = egui::pos2(
                square.right() + gap,
                rect.center().y - galley.size().y / 2.0,
            );
            painter.galley(at, galley, visuals.text_color());
        }
    }
    response
}

/// The inside of a clear checkbox: the colour of a text field, lifted a
/// shade toward the text under the pointer.
fn clear_box(visuals: &egui::Visuals, hovered: bool) -> Color32 {
    if hovered {
        visuals
            .extreme_bg_color
            .lerp_to_gamma(visuals.text_color(), 0.1)
    } else {
        visuals.extreme_bg_color
    }
}

/// A tick filling `rect`: a short stroke down, a long one up.
fn tick(painter: &egui::Painter, rect: egui::Rect, stroke: Stroke) {
    let point = |x: f32, y: f32| rect.min + egui::vec2(x * rect.width(), y * rect.height());
    painter.add(egui::Shape::line(
        vec![point(0.15, 0.55), point(0.4, 0.8), point(0.88, 0.25)],
        stroke,
    ));
}

/// A green tick, painted for the same reason as [`severity_icon`]: egui's
/// fonts cannot be relied on to have one.
pub fn check_mark(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(size), egui::Sense::hover());
    let stroke = Stroke::new((size * 0.14).max(1.5), palette(ui).green);
    tick(ui.painter(), rect, stroke);
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The WCAG 2 contrast ratio of two opaque colours.
    pub(crate) fn contrast(a: Color32, b: Color32) -> f32 {
        let luminance = |c: Color32| {
            let channel = |v: u8| {
                let v = f32::from(v) / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * channel(c.r()) + 0.7152 * channel(c.g()) + 0.0722 * channel(c.b())
        };
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// In both themes a ticked box stands out from the panel and its tick
    /// from the box, and a clear one keeps its outline, at WCAG's 3:1 for a
    /// control; the text on the red button stays at 4.5:1. Both at rest,
    /// under the pointer and pressed.
    #[test]
    fn checkboxes_and_filled_buttons_stay_legible() {
        let ctx = egui::Context::default();
        apply(&ctx);
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let visuals = ctx.style_of(theme).visuals.clone();
            let palette = palette_of(&visuals);
            let panel = visuals.panel_fill;

            assert!(
                contrast(palette.accent, panel) >= 3.0,
                "{theme:?}: ticked box"
            );
            let outline = visuals.weak_text_color();
            for (against, fill) in [
                ("the panel", panel),
                ("the box", clear_box(&visuals, false)),
                ("the hovered box", clear_box(&visuals, true)),
            ] {
                let ratio = contrast(outline, fill);
                assert!(
                    ratio >= 3.0,
                    "{theme:?}: outline on {against}: {ratio:.2}:1"
                );
            }

            for share in [1.0, HOVERED, PRESSED] {
                let tick = contrast(
                    palette.on_accent,
                    panel.lerp_to_gamma(palette.accent, share),
                );
                assert!(tick >= 3.0, "{theme:?}: tick at {share}: {tick:.2}:1");
                let text = contrast(Color32::WHITE, panel.lerp_to_gamma(DANGER, share));
                assert!(text >= 4.5, "{theme:?}: red button at {share}: {text:.2}:1");
            }
        }
    }
}
