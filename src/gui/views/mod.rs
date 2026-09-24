//! The two views, and the findings list the main one is built around.
//!
//! Each view exposes a single `show(ui, app)`. They take `&mut App` rather than
//! the handful of fields they read, because in an immediate-mode UI a button
//! *is* the action: the repair button calls `App::start_repairs` directly
//! instead of routing a keystroke through the dispatch table first.

pub mod findings;
pub mod home;
pub mod settings;
