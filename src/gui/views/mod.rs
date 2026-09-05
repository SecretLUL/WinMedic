//! One module per tab, in the order the tab strip shows them.
//!
//! Each exposes a single `show(ui, app)`. They take `&mut App` rather than the
//! handful of fields they read, because in an immediate-mode UI a button *is*
//! the action: the Repair Center's start button calls `App::start_repairs`
//! directly instead of routing a keystroke through the dispatch table first.

pub mod dashboard;
pub mod repair;
pub mod scanner;
pub mod settings;
pub mod triage;
