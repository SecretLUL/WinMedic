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
/// Returns nothing at all while a text field holds focus. That is the rule that
/// makes single-letter bindings safe in a window: typing "storage" into the
/// triage search box must not start a scan on the `s`, and the widget that owns
/// the keyboard is the one egui already tracks.
pub fn shortcuts(ctx: &egui::Context) -> Vec<Key> {
    if ctx.memory(|memory| memory.focused().is_some()) {
        return Vec::new();
    }

    ctx.input(|input| input.events.iter().filter_map(translate).collect())
}

fn translate(event: &egui::Event) -> Option<Key> {
    match event {
        // Characters come from `Text` rather than from `Key`, and only from
        // there. egui emits both for a printable key, so reading them from both
        // would dispatch every letter twice — pressing `d` would toggle
        // simulation mode on and straight back off again.
        egui::Event::Text(text) => text.chars().next().map(Key::Char),
        egui::Event::Key {
            key,
            pressed: true,
            modifiers,
            ..
        } => named_key(*key, *modifiers),
        _ => None,
    }
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
