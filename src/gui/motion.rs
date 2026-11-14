//! Motion: how the window gets from one state to the next.
//!
//! The way Windows 11 moves: short, and fast at the start, so nothing waits
//! for an animation. A page comes up into its place, the navigation's bar
//! glides to the page picked, a tick is drawn, a dialog settles, a progress
//! bar runs to its value where it used to jump.
//!
//! Every animation here ends. While one runs it asks for repaints, and after
//! it the window is as still as before: a scan or a repair is redrawn every
//! `BUSY_REPAINT` and no more often (#280). [`follow`] asks for none at all.
//!
//! "Animation effects" switched off in Windows (Settings, Accessibility,
//! Visual effects) switches them off here: [`switch_off`].

use eframe::egui::{self, Id};

/// What follows the pointer: the tint under it.
pub const FAST: f32 = 0.083;
/// A control changing its state, and a dialog opening.
pub const NORMAL: f32 = 0.167;
/// A page coming in, and the navigation's bar on its way.
pub const SLOW: f32 = 0.25;

/// How far below its place a page starts, in points.
const RISE: f32 = 12.0;
/// How much larger than its size a dialog starts.
const DIALOG_GROWTH: f32 = 0.04;
/// The time in which [`follow`] covers two thirds of the way, in seconds.
const CATCH_UP: f32 = 0.15;

/// Fast at the start, slow into the end: how Windows 11 brings things in.
pub fn decelerate(t: f32) -> f32 {
    1.0 - (1.0 - t.clamp(0.0, 1.0)).powi(4)
}

/// No animations from here on, egui's own included: every state is drawn as
/// it is at once.
pub fn switch_off(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| style.animation_time = 0.0);
}

fn is_off(ctx: &egui::Context) -> bool {
    ctx.global_style().animation_time <= 0.0
}

/// Whether Windows shows animations: "Animation effects" in Settings. A
/// remote desktop session has them off as well.
pub fn windows_animates() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SPI_GETCLIENTAREAANIMATION, SystemParametersInfoW,
        };
        let mut on: i32 = 1;
        let read = unsafe {
            SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&raw mut on).cast(), 0)
        };
        read == 0 || on != 0
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// How far `on` has come true, from 0 to 1, moving there in `seconds`. The
/// first time it is asked, it is there already: nothing animates in a window
/// that is only just drawn.
pub fn toggled(ctx: &egui::Context, id: Id, on: bool, seconds: f32) -> f32 {
    // In no time, egui's division by it is not finite, which it takes for
    // "there already".
    let seconds = if is_off(ctx) { 0.0 } else { seconds };
    ctx.animate_bool_with_time_and_easing(id, on, seconds, decelerate)
}

/// How far the frame at `now` is into an animation of `seconds` that began at
/// `since`, from 0 to 1.
fn progress(ctx: &egui::Context, now: f64, since: f64, seconds: f32) -> f32 {
    if is_off(ctx) {
        return 1.0;
    }
    // Half a frame ahead, as egui does it: the frame that starts an animation
    // is already a step into it, not a frame of the old state.
    let ahead = ctx.input(|input| input.predicted_dt) * 0.5;
    (((now - since) as f32 + ahead) / seconds).clamp(0.0, 1.0)
}

/// How far what `slot` shows has arrived since `key` last changed, from 0 to
/// 1 over `seconds`. What it shows first is there already.
pub fn since_change(ctx: &egui::Context, slot: Id, key: Id, seconds: f32) -> f32 {
    let now = ctx.input(|input| input.time);
    let since = ctx.data_mut(|data| {
        let state = data.get_temp_mut_or_insert_with(slot, || (key, f64::NEG_INFINITY));
        if state.0 != key {
            *state = (key, now);
        }
        state.1
    });
    let t = progress(ctx, now, since, seconds);
    if t < 1.0 {
        ctx.request_repaint();
    }
    decelerate(t)
}

/// Draw a page, coming up into its place when `key` is not the page that was
/// drawn before: a little below and transparent at first.
///
/// The page is laid out lower, not painted lower: what is under the pointer
/// is what is drawn there.
pub fn entrance<R>(ui: &mut egui::Ui, key: Id, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let arrived = since_change(ui.ctx(), Id::unique("winmedic_page"), key, SLOW);
    let below = egui::vec2(0.0, ((1.0 - arrived) * RISE).round());
    let place = ui.available_rect_before_wrap().translate(below);
    // A scope in either case, so that a widget keeps its id, and with it its
    // focus and its scroll position, when the animation ends.
    ui.scope_builder(egui::UiBuilder::new().max_rect(place), |ui| {
        ui.multiply_opacity(arrived);
        add(ui)
    })
    .inner
}

/// The size a dialog is drawn at while it opens: a little larger than it is,
/// around the middle of the window, settling as `arrived` goes from 0 to 1.
pub fn settling(ctx: &egui::Context, arrived: f32) -> egui::emath::TSTransform {
    let scale = 1.0 + DIALOG_GROWTH * (1.0 - arrived);
    let middle = ctx.content_rect().center().to_vec2();
    egui::emath::TSTransform::new(middle * (1.0 - scale), scale)
}

#[derive(Clone, Copy)]
struct Glide {
    from: f32,
    to: f32,
    since: f64,
}

/// Where a mark is on its way to `target`, which it reaches in `seconds`: its
/// leading and its trailing end. The leading end sets off at once and the
/// other follows, so the mark stretches toward where it is going, as the bar
/// of Windows 11's navigation does.
pub fn glide(ctx: &egui::Context, id: Id, target: f32, seconds: f32) -> (f32, f32) {
    let now = ctx.input(|input| input.time);
    let state = ctx.data(|data| data.get_temp::<Glide>(id));
    let state = match state {
        Some(state) if state.to == target => state,
        // On its way somewhere else: it turns from where its leading end is.
        Some(state) => Glide {
            from: egui::lerp(
                state.from..=state.to,
                decelerate(progress(ctx, now, state.since, seconds)),
            ),
            to: target,
            since: now,
        },
        None => Glide {
            from: target,
            to: target,
            since: f64::NEG_INFINITY,
        },
    };
    ctx.data_mut(|data| data.insert_temp(id, state));

    let t = progress(ctx, now, state.since, seconds);
    if t >= 1.0 {
        return (target, target);
    }
    ctx.request_repaint();
    let at = |share: f32| egui::lerp(state.from..=target, share);
    (at(decelerate(t)), at(egui::emath::easing::cubic_in_out(t)))
}

/// `target`, followed a little behind: a progress bar that runs to its value
/// where the value jumps. A value that goes back, a new scan's, is taken at
/// once.
///
/// It asks for no repaint. It moves as far as the clock says whenever the
/// window is drawn, which while something runs is every `BUSY_REPAINT`.
pub fn follow(ctx: &egui::Context, id: Id, target: f32) -> f32 {
    if is_off(ctx) {
        return target;
    }
    let now = ctx.input(|input| input.time);
    ctx.data_mut(|data| {
        let (shown, at) = data.get_temp_mut_or_insert_with(id, || (target, now));
        let passed = (now - *at) as f32;
        *at = now;
        let left = target - *shown;
        // Not drawn for a while, it has nothing to catch up from.
        if !(0.002..=1.0).contains(&left) || passed > 1.0 {
            *shown = target;
        } else {
            *shown += left * (1.0 - (-passed / CATCH_UP).exp());
        }
        *shown
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One frame at `time`, and whether it asked for another.
    fn frame<R>(ctx: &egui::Context, time: f64, ask: impl Fn(&egui::Context) -> R) -> (R, bool) {
        let input = egui::RawInput {
            time: Some(time),
            ..Default::default()
        };
        let mut answer = None;
        let mut output = ctx.run_ui(input, |ui| answer = Some(ask(ui.ctx())));
        output.textures_delta.clear();
        let again = output
            .viewport_output
            .values()
            .any(|viewport| viewport.repaint_delay.is_zero());
        (answer.expect("the frame ran"), again)
    }

    /// A context past its first frames, in which egui asks for a repaint of
    /// its own.
    fn context() -> egui::Context {
        let ctx = egui::Context::default();
        for time in [0.0, 0.25, 0.5] {
            frame(&ctx, time, |_| {});
        }
        assert!(!frame(&ctx, 0.75, |_| {}).1, "egui is still settling");
        ctx
    }

    #[test]
    fn deceleration_starts_fast_and_ends_at_its_end() {
        assert_eq!(decelerate(0.0), 0.0);
        assert_eq!(decelerate(1.0), 1.0);
        assert!(
            decelerate(0.25) > 0.6,
            "most of the way in the first quarter"
        );
        let steps: Vec<f32> = (0..=20).map(|i| decelerate(i as f32 / 20.0)).collect();
        assert!(steps.windows(2).all(|pair| pair[0] < pair[1]));
    }

    /// A page or a dialog that is there when the window is first drawn does
    /// not animate; one that replaces it does, and then stands still.
    #[test]
    fn a_change_animates_once_and_ends() {
        let ctx = context();
        let slot = Id::unique("slot");
        let ask = |key: &'static str| {
            move |ctx: &egui::Context| since_change(ctx, slot, Id::unique(key), SLOW)
        };

        assert_eq!(frame(&ctx, 1.0, ask("a")), (1.0, false));
        let (started, again) = frame(&ctx, 2.0, ask("b"));
        assert!(started < 0.5 && again, "{started}");
        let (halfway, again) = frame(&ctx, 2.1, ask("b"));
        assert!(started < halfway && halfway < 1.0 && again, "{halfway}");
        // egui draws one frame more than it was asked for, the one after the
        // animation's last. Then the window is still.
        assert_eq!(frame(&ctx, 2.3, ask("b")).0, 1.0);
        assert_eq!(frame(&ctx, 2.4, ask("b")), (1.0, false));
        assert_eq!(frame(&ctx, 9.0, ask("b")), (1.0, false));
    }

    #[test]
    fn a_toggle_moves_to_its_state_and_stays() {
        let ctx = context();
        let id = Id::unique("tick");
        let ask = |on: bool| move |ctx: &egui::Context| toggled(ctx, id, on, NORMAL);

        assert_eq!(frame(&ctx, 1.0, ask(false)), (0.0, false));
        let mut time = 1.0;
        let mut last = 0.0;
        while last < 1.0 {
            time += 1.0 / 60.0;
            let (now, again) = frame(&ctx, time, ask(true));
            assert!(now > last, "{now} after {last}");
            assert!(again || now == 1.0, "it stopped at {now}");
            assert!(time < 1.5, "the tick never arrives");
            last = now;
        }
        frame(&ctx, time + 0.1, ask(true));
        assert_eq!(frame(&ctx, time + 0.2, ask(true)), (1.0, false));
    }

    /// The bar's leading end is ahead of its trailing end the whole way, and
    /// both arrive.
    #[test]
    fn a_gliding_mark_stretches_toward_its_target() {
        let ctx = context();
        let id = Id::unique("bar");
        let ask = |target: f32| move |ctx: &egui::Context| glide(ctx, id, target, SLOW);

        assert_eq!(frame(&ctx, 1.0, ask(10.0)), ((10.0, 10.0), false));
        let ((lead, trail), again) = frame(&ctx, 2.0, ask(110.0));
        assert!(again && 10.0 < trail && trail < lead && lead < 110.0);
        let ((lead, trail), _) = frame(&ctx, 2.1, ask(110.0));
        assert!(trail < lead && lead > 90.0, "{trail} {lead}");
        assert_eq!(frame(&ctx, 2.3, ask(110.0)).0, (110.0, 110.0));
        assert_eq!(frame(&ctx, 2.4, ask(110.0)), ((110.0, 110.0), false));

        // Turned around on the way, it sets off from where it is.
        frame(&ctx, 3.0, ask(10.0));
        let ((lead, _), _) = frame(&ctx, 3.05, ask(110.0));
        assert!(10.0 < lead && lead < 110.0, "{lead}");
    }

    /// #280: the bar catches up without asking for a single repaint, never
    /// runs past its value, and a new scan starts it at nothing.
    #[test]
    fn a_followed_value_catches_up_without_asking_for_repaints() {
        let ctx = context();
        let id = Id::unique("progress");
        let ask = |target: f32| move |ctx: &egui::Context| follow(ctx, id, target);

        assert_eq!(frame(&ctx, 1.0, ask(0.2)), (0.2, false));
        let mut last = 0.2;
        for step in 1..=40 {
            let (shown, again) = frame(&ctx, 1.0 + f64::from(step) * 0.04, ask(0.8));
            assert!(!again, "it asked for a repaint");
            assert!(last <= shown && shown <= 0.8, "{shown} after {last}");
            last = shown;
        }
        assert_eq!(last, 0.8);
        assert_eq!(frame(&ctx, 3.0, ask(0.0)), (0.0, false));
    }

    /// With Windows' animations off, every state is there at once and nothing
    /// asks for a repaint.
    #[test]
    fn switched_off_nothing_moves() {
        let ctx = context();
        let id = Id::unique("off");
        switch_off(&ctx);
        frame(&ctx, 1.0, |ctx| {
            since_change(ctx, id.with("change"), Id::unique("a"), SLOW);
            toggled(ctx, id.with("toggle"), false, NORMAL);
            glide(ctx, id.with("glide"), 10.0, SLOW);
            follow(ctx, id.with("follow"), 0.2);
        });
        let (all, again) = frame(&ctx, 2.0, |ctx| {
            (
                since_change(ctx, id.with("change"), Id::unique("b"), SLOW),
                toggled(ctx, id.with("toggle"), true, NORMAL),
                glide(ctx, id.with("glide"), 110.0, SLOW),
                follow(ctx, id.with("follow"), 0.8),
            )
        });
        assert_eq!(all, (1.0, 1.0, (110.0, 110.0), 0.8));
        assert!(!again);
    }
}
