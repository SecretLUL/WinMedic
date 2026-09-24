//! The window's size follows the mode.
//!
//! Easy mode is one short column, so the window is locked at its smallest size
//! — the size every view, Settings included, is drawn and tested at — and
//! cannot be resized or maximized. Advanced mode hands the window back, at the
//! size or maximized state it had before Easy mode locked it.

use eframe::egui::{self, ViewportCommand};

/// The smallest window every view fits in.
pub const MIN_SIZE: egui::Vec2 = egui::vec2(960.0, 640.0);

/// Where the window was, so that leaving Easy mode can put it back.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Geometry {
    pub size: egui::Vec2,
    pub maximized: bool,
}

impl Geometry {
    /// The root window's geometry this frame, once the platform has said.
    pub fn of(ctx: &egui::Context) -> Option<Self> {
        ctx.input(|input| {
            let viewport = input.viewport();
            viewport.inner_rect.map(|rect| Self {
                size: rect.size(),
                maximized: viewport.maximized.unwrap_or(false),
            })
        })
    }
}

/// Which mode the window was last set up for.
#[derive(Debug, Default)]
pub struct WindowLock {
    applied: Option<bool>,
    before_lock: Option<Geometry>,
}

impl WindowLock {
    /// What the window has to be told to match `advanced`: nothing while it
    /// already does, which is every frame but the first and the ones right
    /// after a switch.
    pub fn commands(&mut self, advanced: bool, current: Option<Geometry>) -> Vec<ViewportCommand> {
        if self.applied == Some(advanced) {
            return Vec::new();
        }
        self.applied = Some(advanced);

        if advanced {
            let mut commands = vec![
                ViewportCommand::Resizable(true),
                ViewportCommand::EnableButtons {
                    close: true,
                    minimized: true,
                    maximize: true,
                },
            ];
            match self.before_lock.take() {
                Some(before) if before.maximized => commands.push(ViewportCommand::Maximized(true)),
                Some(before) => commands.push(ViewportCommand::InnerSize(before.size)),
                // Opened in Advanced mode: the window is where the user left it.
                None => {}
            }
            commands
        } else {
            self.before_lock = current;
            vec![
                // First, or un-maximizing afterwards would restore the old size.
                ViewportCommand::Maximized(false),
                ViewportCommand::Resizable(false),
                ViewportCommand::EnableButtons {
                    close: true,
                    minimized: true,
                    maximize: false,
                },
                ViewportCommand::InnerSize(MIN_SIZE),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(width: f32, height: f32) -> Option<Geometry> {
        Some(Geometry {
            size: egui::vec2(width, height),
            maximized: false,
        })
    }

    fn resizable(commands: &[ViewportCommand]) -> Option<bool> {
        commands.iter().find_map(|command| match command {
            ViewportCommand::Resizable(on) => Some(*on),
            _ => None,
        })
    }

    #[test]
    fn easy_mode_locks_the_window_at_its_smallest_size() {
        let mut lock = WindowLock::default();
        let commands = lock.commands(false, at(1600.0, 1000.0));

        assert_eq!(resizable(&commands), Some(false));
        assert!(commands.contains(&ViewportCommand::InnerSize(MIN_SIZE)));
        assert!(commands.contains(&ViewportCommand::Maximized(false)));
        assert!(commands.contains(&ViewportCommand::EnableButtons {
            close: true,
            minimized: true,
            maximize: false,
        }));
    }

    #[test]
    fn advanced_mode_unlocks_it_and_puts_the_old_size_back() {
        let mut lock = WindowLock::default();
        lock.commands(false, at(1600.0, 1000.0));

        let commands = lock.commands(true, at(MIN_SIZE.x, MIN_SIZE.y));
        assert_eq!(resizable(&commands), Some(true));
        assert!(commands.contains(&ViewportCommand::InnerSize(egui::vec2(1600.0, 1000.0))));
        assert!(commands.contains(&ViewportCommand::EnableButtons {
            close: true,
            minimized: true,
            maximize: true,
        }));
    }

    #[test]
    fn a_maximized_window_comes_back_maximized() {
        let mut lock = WindowLock::default();
        lock.commands(
            false,
            Some(Geometry {
                size: egui::vec2(2560.0, 1400.0),
                maximized: true,
            }),
        );
        let commands = lock.commands(true, at(MIN_SIZE.x, MIN_SIZE.y));
        assert!(commands.contains(&ViewportCommand::Maximized(true)));
    }

    /// Told once per switch, not once per frame: a window told its size every
    /// frame would snap back whenever Advanced mode's user resized it.
    #[test]
    fn nothing_is_sent_while_the_mode_stays_the_same() {
        let mut lock = WindowLock::default();
        assert!(!lock.commands(false, at(1600.0, 1000.0)).is_empty());
        assert!(lock.commands(false, at(MIN_SIZE.x, MIN_SIZE.y)).is_empty());
        assert!(!lock.commands(true, at(MIN_SIZE.x, MIN_SIZE.y)).is_empty());
        assert!(lock.commands(true, at(1200.0, 800.0)).is_empty());
    }

    #[test]
    fn opening_in_advanced_mode_leaves_the_size_alone() {
        let mut lock = WindowLock::default();
        let commands = lock.commands(true, at(1400.0, 900.0));
        assert_eq!(resizable(&commands), Some(true));
        assert!(
            !commands.iter().any(|c| matches!(
                c,
                ViewportCommand::InnerSize(_) | ViewportCommand::Maximized(_)
            )),
            "the window stays where the user left it"
        );
    }
}
