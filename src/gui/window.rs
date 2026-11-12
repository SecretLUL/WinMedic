//! The window's size follows the mode.
//!
//! Easy mode is one short column, so the window is locked at its smallest size
//! — the size every view, Settings included, is drawn and tested at — and
//! cannot be resized or maximized. Advanced mode hands the window back, at the
//! size or maximized state it had before Easy mode locked it.
//!
//! A screen too small for that size (1920 x 1080 at 175 % leaves about
//! 1097 x 617 points) gets a maximized window that can be resized in either
//! mode: locked at 960 x 640, its bottom was off the screen, Repair button
//! and all.

use eframe::egui::{self, ViewportCommand};

/// The smallest window every view fits in.
pub const MIN_SIZE: egui::Vec2 = egui::vec2(960.0, 640.0);

/// Room the title bar and the taskbar take from the screen, in points.
const SCREEN_CHROME: egui::Vec2 = egui::vec2(16.0, 90.0);

/// Where the window was, so that leaving Easy mode can put it back.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Geometry {
    pub size: egui::Vec2,
    pub maximized: bool,
    /// The screen the window is on, in points, once the platform has said.
    pub monitor: Option<egui::Vec2>,
    /// Pixels per point on that screen: 2.0 at 200 % scaling.
    pub scale: f32,
}

impl Geometry {
    /// Whether [`MIN_SIZE`] fits on the screen. An unknown screen is taken
    /// to fit, as before; the window is set up again once it is known.
    fn min_size_fits(&self) -> bool {
        self.monitor.is_none_or(|screen| {
            screen.x >= MIN_SIZE.x + SCREEN_CHROME.x && screen.y >= MIN_SIZE.y + SCREEN_CHROME.y
        })
    }
}

/// The name the Advanced window's geometry is stored under, in eframe's own
/// storage beside the window's position.
pub const KEPT_AS: &str = "winmedic_advanced_window";

impl Geometry {
    /// `1600 1000 0`: width, height and whether it was maximized.
    pub fn stored(&self) -> String {
        format!(
            "{} {} {}",
            self.size.x.round(),
            self.size.y.round(),
            u8::from(self.maximized)
        )
    }

    /// What [`Self::stored`] wrote. Anything else, a size no window has
    /// included, is no geometry.
    pub fn from_stored(text: &str) -> Option<Self> {
        let mut parts = text.split_whitespace();
        let width: f32 = parts.next()?.parse().ok()?;
        let height: f32 = parts.next()?.parse().ok()?;
        let maximized = match parts.next()? {
            "0" => false,
            "1" => true,
            _ => return None,
        };
        let sane = |length: f32, least: f32| (least..=16384.0).contains(&length);
        (parts.next().is_none() && sane(width, MIN_SIZE.x) && sane(height, MIN_SIZE.y)).then_some(
            Self {
                size: egui::vec2(width, height),
                maximized,
                monitor: None,
                scale: 1.0,
            },
        )
    }

    /// The root window's geometry this frame, once the platform has said.
    pub fn of(ctx: &egui::Context) -> Option<Self> {
        ctx.input(|input| {
            let viewport = input.viewport();
            viewport.inner_rect.map(|rect| Self {
                size: rect.size(),
                maximized: viewport.maximized.unwrap_or(false),
                monitor: viewport.monitor_size,
                scale: input.pixels_per_point,
            })
        })
    }
}

/// Which mode the window was last set up for.
#[derive(Debug, Default)]
pub struct WindowLock {
    /// The mode, whether [`MIN_SIZE`] fitted on the screen, and the screen's
    /// scaling, last set up.
    ///
    /// The scaling, because the window takes its smallest size in pixels,
    /// worked out when it is told: 960 x 640 points told at 200 % stayed
    /// 1920 x 1280 pixels on a screen at 100 %, taller than a 1080p monitor
    /// and, in Easy mode, not resizable. Moved the other way, the Advanced
    /// window could be shrunk to half its smallest size.
    applied: Option<(bool, bool, f32)>,
    before_lock: Option<Geometry>,
}

impl WindowLock {
    /// The lock of a window that opens in Easy mode, with the geometry the
    /// Advanced window had when the last session ended in Easy mode.
    ///
    /// `before_lock` lived in memory only. Quitting in Easy mode, the
    /// default, left eframe with the locked 960 x 640 as the window's size,
    /// and from the next start on F7 opened Advanced at that size instead of
    /// the one the user had chosen.
    pub fn remembering(advanced_window: Option<Geometry>) -> Self {
        Self {
            applied: None,
            before_lock: advanced_window,
        }
    }

    /// The Advanced window's geometry while Easy mode has the window locked,
    /// for the next session.
    pub fn kept(&self) -> Option<Geometry> {
        self.before_lock
    }

    /// What the window has to be told to match `advanced`: nothing while it
    /// already does, which is every frame but the first and the ones right
    /// after a switch.
    pub fn commands(&mut self, advanced: bool, current: Option<Geometry>) -> Vec<ViewportCommand> {
        let fits = current.is_none_or(|c| c.min_size_fits());
        // An unknown window keeps the scaling it was set up for.
        let scale = current
            .map(|c| c.scale)
            .or(self.applied.map(|(_, _, scale)| scale))
            .unwrap_or(1.0);
        if self.applied == Some((advanced, fits, scale)) {
            return Vec::new();
        }
        let was_advanced = self.applied.map(|(mode, _, _)| mode);
        self.applied = Some((advanced, fits, scale));

        if !fits {
            let screen = current.and_then(|c| c.monitor).unwrap_or(MIN_SIZE);
            let smallest = (screen - SCREEN_CHROME).min(MIN_SIZE);
            return vec![
                ViewportCommand::MinInnerSize(smallest),
                ViewportCommand::Resizable(true),
                ViewportCommand::EnableButtons {
                    close: true,
                    minimized: true,
                    maximize: true,
                },
                ViewportCommand::Maximized(true),
            ];
        }

        if advanced {
            if was_advanced == Some(true) {
                // Only the screen changed: to one MIN_SIZE fits on, or to
                // one with another scaling.
                return vec![ViewportCommand::MinInnerSize(MIN_SIZE)];
            }
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
            // Coming from Advanced mode, or opening in Easy mode with nothing
            // remembered from the last session.
            if was_advanced == Some(true) || (was_advanced.is_none() && self.before_lock.is_none())
            {
                self.before_lock = current;
            }
            vec![
                ViewportCommand::MinInnerSize(MIN_SIZE),
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
            monitor: Some(egui::vec2(1920.0, 1080.0)),
            scale: 1.0,
        })
    }

    /// The window dragged from a laptop panel at 200 % to a monitor at 100 %:
    /// the smallest size is told again, since Windows holds it in pixels.
    #[test]
    fn another_scaling_tells_the_smallest_size_again() {
        let at_scale = |scale| {
            Some(Geometry {
                scale,
                ..at(MIN_SIZE.x, MIN_SIZE.y).unwrap()
            })
        };

        let mut easy = WindowLock::default();
        easy.commands(false, at_scale(2.0));
        assert!(easy.commands(false, at_scale(2.0)).is_empty());
        let commands = easy.commands(false, at_scale(1.0));
        assert!(commands.contains(&ViewportCommand::MinInnerSize(MIN_SIZE)));
        assert!(commands.contains(&ViewportCommand::InnerSize(MIN_SIZE)));
        assert_eq!(resizable(&commands), Some(false));

        let mut advanced = WindowLock::default();
        advanced.commands(true, at_scale(1.0));
        assert_eq!(
            advanced.commands(true, at_scale(2.0)),
            [ViewportCommand::MinInnerSize(MIN_SIZE)],
            "the size the user chose stays"
        );
        assert!(advanced.commands(true, at_scale(2.0)).is_empty());
    }

    /// 1920 x 1080 at 175 %.
    fn on_small_screen() -> Option<Geometry> {
        Some(Geometry {
            size: MIN_SIZE,
            maximized: false,
            monitor: Some(egui::vec2(1097.0, 617.0)),
            scale: 1.75,
        })
    }

    #[test]
    fn a_screen_too_small_for_the_lock_gets_a_maximized_window() {
        let mut lock = WindowLock::default();
        let commands = lock.commands(false, on_small_screen());
        assert_eq!(resizable(&commands), Some(true));
        assert!(commands.contains(&ViewportCommand::Maximized(true)));
        assert!(!commands.contains(&ViewportCommand::InnerSize(MIN_SIZE)));
        assert!(commands.contains(&ViewportCommand::MinInnerSize(egui::vec2(960.0, 527.0))));
    }

    /// The first frames may not know the screen yet; once it is known and
    /// too small, the window is set up again.
    #[test]
    fn a_screen_learned_late_still_counts() {
        let mut lock = WindowLock::default();
        let unknown = Some(Geometry {
            monitor: None,
            ..on_small_screen().unwrap()
        });
        assert!(
            lock.commands(false, unknown)
                .contains(&ViewportCommand::InnerSize(MIN_SIZE))
        );
        assert!(
            lock.commands(false, on_small_screen())
                .contains(&ViewportCommand::Maximized(true))
        );
        assert!(lock.commands(false, on_small_screen()).is_empty());
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
                monitor: Some(egui::vec2(2560.0, 1440.0)),
                scale: 1.0,
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

    /// Quit in Easy mode, start again, press F7: Advanced opens as it was.
    #[test]
    fn the_advanced_window_is_remembered_across_a_quit_in_easy_mode() {
        let mut first = WindowLock::default();
        first.commands(true, at(1600.0, 1000.0));
        assert_eq!(first.kept(), None, "nothing to keep while Advanced is open");
        first.commands(false, at(1600.0, 1000.0));
        let stored = first.kept().unwrap().stored();
        assert_eq!(stored, "1600 1000 0");

        // The next session opens locked, at the size eframe saved.
        let mut second = WindowLock::remembering(Geometry::from_stored(&stored));
        second.commands(false, at(MIN_SIZE.x, MIN_SIZE.y));
        assert_eq!(second.kept().unwrap().stored(), stored);
        let commands = second.commands(true, at(MIN_SIZE.x, MIN_SIZE.y));
        assert!(commands.contains(&ViewportCommand::InnerSize(egui::vec2(1600.0, 1000.0))));

        let maximized = Geometry::from_stored("2560 1400 1").unwrap();
        assert!(maximized.maximized);
        let mut third = WindowLock::remembering(Some(maximized));
        third.commands(false, at(MIN_SIZE.x, MIN_SIZE.y));
        assert!(
            third
                .commands(true, at(MIN_SIZE.x, MIN_SIZE.y))
                .contains(&ViewportCommand::Maximized(true))
        );

        for unusable in [
            "",
            "1600",
            "1600 1000",
            "1600 1000 2",
            "10 10 0",
            "NaN 1000 0",
            "1e9 1000 0",
            "1600 1000 0 7",
        ] {
            assert_eq!(Geometry::from_stored(unusable), None, "{unusable:?}");
        }
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
