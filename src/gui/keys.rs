//! Translating egui's key events into the toolkit-neutral [`Key`].
//!
//! The mirror image of what the terminal front end did with crossterm: the
//! front end names its own key type, [`crate::app::input`] names none. Keeping
//! the whole dispatch table on the far side of this translation is what let it
//! survive the move from terminal to window unchanged.

use crate::app::Key;
use eframe::egui;

/// Collect this frame's keystrokes, in the order they arrived.
///
/// Returns nothing but F7 while a text field holds focus. That is the rule that
/// makes single-letter bindings safe in a window: typing "storage" into the
/// triage search box must not start a scan on the `s`, and the widget that owns
/// the keyboard is the one egui already tracks. F7 types nothing, so it switches
/// the mode from anywhere, as it does in a BIOS setup screen.
///
/// An Esc that egui uses itself is not passed on either, see
/// [`remember_keyboard_owner`].
pub fn shortcuts(ctx: &egui::Context) -> Vec<Key> {
    let typing = ctx.memory(|memory| memory.focused().is_some());
    let esc_is_eguis = ctx.data(|data| data.get_temp::<bool>(esc_owner()).unwrap_or(false));

    ctx.input(|input| {
        input
            .events
            .iter()
            .filter_map(translate)
            .filter(|key| !typing || *key == Key::F7)
            .filter(|key| !(esc_is_eguis && *key == Key::Esc))
            .collect()
    })
}

fn esc_owner() -> egui::Id {
    egui::Id::unique("winmedic_esc_belongs_to_egui")
}

/// Note, at the end of a frame, whether the next Esc is egui's: a widget has
/// the keyboard or a drop-down is open, and no dialog of WinMedic's is
/// (`dialog_open`), whose Esc closes the dialog.
///
/// egui takes the focus away at the start of the frame an Esc arrives in, so
/// by the time [`shortcuts`] looks, nothing is focused: the Esc that left
/// the search box or closed the module list also cancelled the running
/// repair, or cleared every filter (#269). What the frame before ended with
/// is the only record of whose key it is.
pub fn remember_keyboard_owner(ctx: &egui::Context, dialog_open: bool) {
    let eguis = !dialog_open
        && (ctx.memory(|memory| memory.focused().is_some()) || egui::Popup::is_any_open(ctx));
    ctx.data_mut(|data| data.insert_temp(esc_owner(), eguis));
}

fn translate(event: &egui::Event) -> Option<Key> {
    match event {
        // Characters come from `Text` rather than from `Key`, and only from
        // there. egui emits both for a printable key, so reading them from both
        // would dispatch every letter twice — pressing `d` would toggle
        // simulation mode on and straight back off again.
        egui::Event::Text(text) => text.chars().next().map(Key::Char),
        //
        // A key held down arrives again and again. Only where that is what
        // holding it means is it passed on: Esc held a moment cleared the
        // filters, cancelled the run and left Settings in one press, and F7
        // flipped the mode thirty times a second (#269).
        egui::Event::Key {
            key,
            pressed: true,
            repeat,
            modifiers,
            ..
        } if !*repeat || repeats_when_held(*key) => named_key(*key, *modifiers),
        _ => None,
    }
}

/// Moving through a list, and deleting what was typed.
fn repeats_when_held(key: egui::Key) -> bool {
    matches!(
        key,
        egui::Key::ArrowUp
            | egui::Key::ArrowDown
            | egui::Key::PageUp
            | egui::Key::PageDown
            | egui::Key::Backspace
    )
}

fn named_key(key: egui::Key, modifiers: egui::Modifiers) -> Option<Key> {
    Some(match key {
        egui::Key::Enter => Key::Enter,
        egui::Key::Escape => Key::Esc,
        egui::Key::Backspace => Key::Backspace,
        egui::Key::ArrowUp => Key::Up,
        egui::Key::ArrowDown => Key::Down,
        egui::Key::ArrowLeft => Key::Left,
        egui::Key::ArrowRight => Key::Right,
        egui::Key::PageUp => Key::PageUp,
        egui::Key::PageDown => Key::PageDown,
        egui::Key::Home => Key::Home,
        egui::Key::End => Key::End,
        egui::Key::F7 => Key::F7,
        // Bare Tab belongs to egui, which moves focus between widgets with it —
        // taking it away would strip the window of keyboard navigation. Ctrl+Tab
        // is free, and is what Windows applications cycle views with anyway.
        egui::Key::Tab if modifiers.ctrl => {
            if modifiers.shift {
                Key::BackTab
            } else {
                Key::Tab
            }
        }
        _ => return None,
    })
}
