//! Typography, spacing and the few colours the views share.
//!
//! Deliberately plain. The window uses egui's stock light and dark visuals,
//! follows the Windows app theme, and draws in Segoe UI at the density of a
//! regular Windows tool, with Windows 11's rounded corners and semibold
//! headings. Colour is kept for what it means — severity, the outcome of a
//! check or repair, what is ticked, the one button that moves the user
//! forward and the one that takes something away — and not spent on
//! decoration.

use crate::engine::issue::Severity;
use eframe::egui::{self, Color32, RichText, Stroke};
use std::sync::{Arc, Mutex};

/// The status colours, picked per theme so each stays legible on its panel.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub red: Color32,
    pub amber: Color32,
    pub green: Color32,
    pub blue: Color32,
    /// What Windows 11 fills a ticked box, a progress bar and the default
    /// button of a page with: its default accent colour.
    pub accent: Color32,
    /// Text and ticks on [`Palette::accent`].
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

/// The font family headings are set in; [`apply`] binds it to Segoe UI
/// Semibold.
const SEMIBOLD: &str = "Segoe UI Semibold";

pub fn palette(ui: &egui::Ui) -> Palette {
    palette_of(ui.visuals())
}

/// The status colours for `visuals`, the dark or the light theme.
pub fn palette_of(visuals: &egui::Visuals) -> Palette {
    if visuals.dark_mode { DARK } else { LIGHT }
}

/// A script neither Segoe UI nor the bundled fonts hold, which Windows
/// brings a font for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    /// Chinese characters, as Chinese, Japanese and Korean write them.
    Han,
    /// Hiragana and Katakana.
    Kana,
    Hangul,
    /// Thai and Lao.
    Thai,
    /// Devanagari, Bengali, Tamil and the other scripts of India.
    Indic,
}

fn script_of(c: char) -> Option<Script> {
    Some(match u32::from(c) {
        0x3040..=0x30FF | 0x31F0..=0x31FF | 0xFF66..=0xFF9F => Script::Kana,
        0x1100..=0x11FF | 0x3130..=0x318F | 0xA960..=0xA97F | 0xAC00..=0xD7FF => Script::Hangul,
        0x2E80..=0x2FDF
        | 0x3000..=0x303F
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFFEF
        | 0x20000..=0x2FA1F => Script::Han,
        0x0E00..=0x0EFF => Script::Thai,
        0x0900..=0x0DFF => Script::Indic,
        _ => return None,
    })
}

/// The files in the Windows `Fonts` folder that hold `script`, the best
/// first. Windows 10 and 11 install all but Yu Gothic and Meiryo with every
/// language.
///
/// Chinese, Japanese and Korean share the Han characters and draw some of
/// them differently, so the font follows the display language, `language`
/// (a Windows language id): Japanese shapes on a Japanese Windows.
fn font_files(script: Script, language: u16) -> &'static [&'static str] {
    const JAPANESE: &[&str] = &["YuGothR.ttc", "meiryo.ttc", "msgothic.ttc", "msyh.ttc"];
    const KOREAN: &[&str] = &["malgun.ttf", "msyh.ttc"];
    const SIMPLIFIED: &[&str] = &["msyh.ttc", "msjh.ttc", "simsun.ttc"];
    const TRADITIONAL: &[&str] = &["msjh.ttc", "msyh.ttc", "mingliub.ttc"];
    const LANG_CHINESE: u16 = 0x04;
    const LANG_JAPANESE: u16 = 0x11;
    const LANG_KOREAN: u16 = 0x12;
    /// Taiwan, Hong Kong and Macao write traditional characters.
    const TRADITIONAL_SUBLANGUAGES: [u16; 3] = [0x01, 0x03, 0x05];

    match script {
        Script::Kana => JAPANESE,
        Script::Hangul => &["malgun.ttf"],
        Script::Thai => &["LeelawUI.ttf", "tahoma.ttf"],
        Script::Indic => &["Nirmala.ttc", "Nirmala.ttf"],
        Script::Han => match (language & 0x3FF, language >> 10) {
            (LANG_JAPANESE, _) => JAPANESE,
            (LANG_KOREAN, _) => KOREAN,
            (LANG_CHINESE, sub) if TRADITIONAL_SUBLANGUAGES.contains(&sub) => TRADITIONAL,
            _ => SIMPLIFIED,
        },
    }
}

/// The display language of this Windows, as a language id.
fn ui_language() -> u16 {
    #[cfg(windows)]
    {
        unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() }
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Finds the Windows font for a character no installed font has, and loads
/// it then: the files run to twenty megabytes each, far too much to read at
/// every start for a text that may never come.
///
/// What Windows names is drawn as Windows wrote it: a device or an adapter
/// named in Chinese or Japanese, the path of a user with such a name, the
/// output of a translated tool. Without a font for them they were empty
/// boxes (#271). The font joins every family, so a heading and a log line
/// find it as well.
fn windows_font_for(
    folder: std::path::PathBuf,
    language: u16,
) -> impl Fn(&egui::epaint::text::FallbackRequest<'_>) -> Option<egui::epaint::text::FontInsert> {
    use egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};

    // egui asks once for each family and character. A file is read the
    // first time and handed out again after that; the data is shared.
    let loaded: Mutex<Vec<(&'static str, egui::FontData)>> = Mutex::new(Vec::new());
    move |request| {
        let script = script_of(request.cluster.chars().next()?)?;
        let mut loaded = loaded.lock().ok()?;
        for file in font_files(script, language) {
            let known = loaded.iter().find(|(name, _)| name == file);
            let data = match known {
                Some((_, data)) => data.clone(),
                None => {
                    let Ok(bytes) = std::fs::read(folder.join(file)) else {
                        continue;
                    };
                    let data = egui::FontData::from_owned(bytes);
                    loaded.push((*file, data.clone()));
                    data
                }
            };
            return Some(FontInsert {
                name: (*file).to_string(),
                data,
                families: [
                    egui::FontFamily::Proportional,
                    egui::FontFamily::Monospace,
                    egui::FontFamily::Name(SEMIBOLD.into()),
                ]
                .into_iter()
                .map(|family| InsertFontFamily {
                    family,
                    priority: FontPriority::Lowest,
                })
                .collect(),
            });
        }
        None
    }
}

pub fn apply(ctx: &egui::Context) {
    // Use the Windows UI font when available, retaining the bundled fallbacks.
    if let Some(windows) = std::env::var_os("SystemRoot") {
        let folder = std::path::PathBuf::from(windows).join("Fonts");
        let mut fonts = egui::FontDefinitions::default();
        if let Ok(data) = std::fs::read(folder.join("segoeui.ttf")) {
            fonts
                .font_data
                .insert("Segoe UI".into(), egui::FontData::from_owned(data).into());
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "Segoe UI".into());
        }
        // egui has no font weights, only families. Headings get their own,
        // which falls back on the body face for anything Semibold lacks.
        if let Ok(data) = std::fs::read(folder.join("seguisb.ttf")) {
            fonts
                .font_data
                .insert(SEMIBOLD.into(), egui::FontData::from_owned(data).into());
            let mut family = vec![SEMIBOLD.to_string()];
            family.extend(fonts.families[&egui::FontFamily::Proportional].clone());
            fonts
                .families
                .insert(egui::FontFamily::Name(SEMIBOLD.into()), family);
        }
        // Logs, paths and technical details are set in the monospace
        // family, whose fonts have no Arabic or Hebrew. Segoe UI has, so it
        // comes last there, for what the others lack.
        if fonts.font_data.contains_key("Segoe UI") {
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("Segoe UI".into());
        }
        ctx.set_fonts(fonts);
        ctx.add_font_provider(Arc::new(windows_font_for(folder, ui_language())));
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
        // Windows 11 rounds a control by 4 and a dialog or a menu by 8.
        visuals.window_corner_radius = 8.into();
        visuals.menu_corner_radius = 8.into();
        for widget in [
            &mut visuals.widgets.noninteractive,
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            widget.corner_radius = 4.into();
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

/// Heading text: Segoe UI Semibold at `size`.
pub fn heading(ui: &egui::Ui, text: impl Into<String>, size: f32) -> RichText {
    let text = RichText::new(text).size(size).strong();
    let family = egui::FontFamily::Name(SEMIBOLD.into());
    // Fonts arrive a frame after `apply` asks for them, and a family egui has
    // not been given is a panic: a test harness draws its first frame before
    // it applies the theme, and a Windows without the font never has it.
    if ui.fonts(|fonts| fonts.definitions().families.contains_key(&family)) {
        text.family(family)
    } else {
        text
    }
}

/// Bring the row the keyboard is on into view when the keyboard moved there.
///
/// Down, PgDn and End changed the detail pane while the list stayed where it
/// was, and Space then ticked a row the user could not see. `row` names the
/// row within `list`. The list is scrolled once per move, so the mouse wheel
/// is free to leave the row afterwards.
pub fn keep_in_view(ui: &egui::Ui, list: &'static str, row: (usize, usize), rect: egui::Rect) {
    let id = egui::Id::unique(("winmedic_keyboard_row", list));
    let last: Option<(usize, usize)> = ui.data(|data| data.get_temp(id));
    if last != Some(row) {
        ui.data_mut(|data| data.insert_temp(id, row));
        ui.scroll_to_rect(rect, None);
    }
}

/// A section heading inside a tab.
pub fn section(ui: &mut egui::Ui, title: &str) {
    ui.label(heading(ui, title, 14.5));
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
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, name));
    response.on_hover_text(name)
}

/// A large button for Easy mode, where the next step should be impossible to
/// miss. `primary` fills it with the accent colour.
pub fn big_button(ui: &mut egui::Ui, text: &str, primary: bool, enabled: bool) -> egui::Response {
    let label = RichText::new(text).size(17.0);
    let size = egui::vec2(210.0, 46.0);
    if primary {
        primary_button(ui, enabled, label, size)
    } else {
        ui.add_enabled(enabled, egui::Button::new(label.strong()).min_size(size))
    }
}

/// The one button on a page that moves the user forward, filled with the
/// accent colour so the eye finds it first.
pub fn primary_button(
    ui: &mut egui::Ui,
    enabled: bool,
    label: RichText,
    min_size: egui::Vec2,
) -> egui::Response {
    let palette = palette(ui);
    filled_button(
        ui,
        enabled,
        label,
        min_size,
        palette.accent,
        palette.on_accent,
    )
}

/// A button that takes something away, filled red.
pub fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    filled_button(
        ui,
        true,
        RichText::new(text),
        egui::Vec2::ZERO,
        DANGER,
        Color32::WHITE,
    )
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
    enabled: bool,
    label: RichText,
    min_size: egui::Vec2,
    fill: Color32,
    text: Color32,
) -> egui::Response {
    // Disabled, it is a plain grey button: Windows greys its accent buttons
    // out too, where a faded fill would look washed out rather than off.
    if !enabled {
        return ui.add_enabled(false, egui::Button::new(label).min_size(min_size));
    }
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
        ui.add(egui::Button::new(label.color(text)).min_size(min_size))
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
            egui::Role::CheckBox,
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

    const GERMAN: u16 = 0x0407;
    const JAPANESE: u16 = 0x0411;
    const KOREAN: u16 = 0x0412;
    const CHINESE_PRC: u16 = 0x0804;
    const CHINESE_TAIWAN: u16 = 0x0404;

    #[test]
    fn a_character_is_told_by_its_script() {
        for (c, script) in [
            ('\u{9ad8}', Some(Script::Han)),    // a Chinese character
            ('\u{3001}', Some(Script::Han)),    // the ideographic comma
            ('\u{30a4}', Some(Script::Kana)),   // Katakana I
            ('\u{3042}', Some(Script::Kana)),   // Hiragana A
            ('\u{ff72}', Some(Script::Kana)),   // half-width Katakana I
            ('\u{d55c}', Some(Script::Hangul)), // Hangul HAN
            ('\u{0e01}', Some(Script::Thai)),
            ('\u{0905}', Some(Script::Indic)), // Devanagari A
            ('\u{0bb0}', Some(Script::Indic)), // Tamil RA
            ('a', None),
            ('\u{00e4}', None),
            ('\u{0416}', None), // Cyrillic: Segoe UI has it
            ('\u{0627}', None), // Arabic: Segoe UI has it
        ] {
            assert_eq!(script_of(c), script, "U+{:04X}", u32::from(c));
        }
    }

    /// Han characters are drawn by the font of the display language; every
    /// list ends in a font Windows installs with every language.
    #[test]
    fn han_characters_follow_the_display_language() {
        assert_eq!(font_files(Script::Han, GERMAN)[0], "msyh.ttc");
        assert_eq!(font_files(Script::Han, CHINESE_PRC)[0], "msyh.ttc");
        assert_eq!(font_files(Script::Han, CHINESE_TAIWAN)[0], "msjh.ttc");
        assert_eq!(font_files(Script::Han, JAPANESE)[0], "YuGothR.ttc");
        assert_eq!(font_files(Script::Han, KOREAN)[0], "malgun.ttf");
        assert_eq!(
            font_files(Script::Kana, GERMAN),
            font_files(Script::Han, JAPANESE)
        );
        for language in [GERMAN, JAPANESE, KOREAN, CHINESE_PRC, CHINESE_TAIWAN] {
            assert!(font_files(Script::Han, language).contains(&"msyh.ttc"));
        }
    }

    /// #271. With the fonts of this Windows, text in these scripts has
    /// glyphs in every family, and none of the fonts is read before it is
    /// needed. A Windows without the file (a server without the language's
    /// fonts) is not judged.
    #[test]
    fn the_windows_font_of_a_script_is_loaded_when_a_character_needs_it() {
        let folder =
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("Fonts");
        let ctx = egui::Context::default();
        apply(&ctx);
        // The provider counts from the next pass on.
        let mut pass = ctx.run_ui(egui::RawInput::default(), |_| {});
        pass.textures_delta.clear();

        for (file, text) in [
            ("msyh.ttc", "\u{9ad8}\u{7cbe}\u{5ea6}"),
            ("malgun.ttf", "\u{d55c}\u{ae00}"),
            ("LeelawUI.ttf", "\u{0e01}\u{0e02}"),
        ] {
            if !folder.join(file).exists() {
                continue;
            }
            for family in [
                egui::FontFamily::Proportional,
                egui::FontFamily::Monospace,
                egui::FontFamily::Name(SEMIBOLD.into()),
            ] {
                let font = egui::FontId::new(14.0, family.clone());
                assert!(
                    ctx.fonts_mut(|fonts| fonts.has_glyphs(&font, text)),
                    "{file} in {family:?}"
                );
            }
        }
    }

    /// The provider reads a file once, however often egui asks, and only
    /// for a script it has a font for.
    #[test]
    fn a_font_file_is_read_once() {
        use egui::epaint::text::FallbackRequest;

        let folder = std::env::temp_dir().join(format!("winmedic_fonts_{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("malgun.ttf"), b"not a font, only a file").unwrap();
        let provider = windows_font_for(folder.clone(), GERMAN);
        let ask = |cluster: &str| {
            provider(&FallbackRequest {
                cluster,
                family: &egui::FontFamily::Proportional,
            })
        };

        assert!(ask("a").is_none(), "Latin is not looked for");
        assert!(ask("\u{9ad8}").is_none(), "no file for it in this folder");
        let found = ask("\u{d55c}").expect("the Korean font");
        assert_eq!(found.name, "malgun.ttf");
        assert_eq!(found.families.len(), 3);

        // The file is gone; the next character gets what was read.
        std::fs::remove_dir_all(&folder).unwrap();
        let again = ask("\u{ae00}").expect("handed out again");
        assert!(std::sync::Arc::ptr_eq(&found.data.font, &again.data.font));
    }

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

    /// In both themes a ticked box stands out from the panel and a clear one
    /// keeps its outline, at WCAG's 3:1 for a control, and the text on a
    /// filled button stays at 4.5:1 at rest, under the pointer and pressed.
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
                for (name, fill, text) in [
                    ("accent", palette.accent, palette.on_accent),
                    ("red", DANGER, Color32::WHITE),
                ] {
                    let ratio = contrast(text, panel.lerp_to_gamma(fill, share));
                    assert!(
                        ratio >= 4.5,
                        "{theme:?}: {name} button at {share}: {ratio:.2}:1"
                    );
                }
            }
        }
    }
}
