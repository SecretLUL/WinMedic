//! Application state and behaviour for the interactive TUI.
//!
//! This used to be one 1400-line file holding UI state, key dispatch, filtering,
//! run orchestration, backup listing and the update notice together. The split
//! follows what each piece is *for*, so a change to triage filtering does not
//! touch the same file as a change to how a repair run starts:
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | [`state`] | The [`App`] struct, construction, telemetry, log buffers |
//! | [`input`] | Key dispatch — the only place a keystroke maps to an action |
//! | [`run_control`] | Starting, cancelling and simulating scans and repairs |
//! | [`events`] | Draining scan, repair and background channels into state |
//! | [`filters`] | Severity/module filtering, live search, issue selection |
//! | [`safety`] | Registry backups, restore points, rollback requests |
//! | [`confirm`] | The confirmation modal and the parked update notice |
//! | [`settings`] | Settings navigation and persistence |

use crate::utils::updater::UpdateInfo;
use std::collections::VecDeque;

pub mod confirm;
pub mod events;
pub mod filters;
pub mod input;
pub mod run_control;
pub mod safety;
pub mod settings;
pub mod state;

pub use confirm::{ConfirmRequest, SystemActions};
pub use input::handle_key;
pub use state::{App, SafetyFocus, SettingInput};

/// Maximum number of log lines kept in memory for scan and repair terminal buffers.
pub const MAX_LOG_LINES: usize = 2000;

/// Number of tabs in the main navigation.
pub const TAB_COUNT: usize = 5;

pub const TAB_DASHBOARD: usize = 0;
pub const TAB_SCANNER: usize = 1;
pub const TAB_TRIAGE: usize = 2;
pub const TAB_REPAIR: usize = 3;
/// Settings *and* the safety surface — audit log, registry backups, VSS
/// restore points and the `[U]` rollback.
///
/// These used to be two tabs. They were merged because the old "Backups & Logs"
/// tab was a read-only wall of text that nobody navigated to, while every action
/// it offered ([U] rollback, [R] refresh) is the same kind of "what is this tool
/// allowed to do to my machine" decision the settings list already covers.
pub const TAB_SETTINGS: usize = 4;

/// Results of short-lived background tasks that are not part of a scan or a
/// repair run (restore point lookups, registry rollbacks, update checks).
#[derive(Debug, Clone)]
pub enum BackgroundEvent {
    RestorePointsLoaded(Vec<String>),
    RollbackFinished { success: bool, message: String },
    UpdateChecked(Option<UpdateInfo>),
}

/// Append to a log buffer, evicting the oldest line once it is full.
///
/// Private to `app`, but visible to every child module because a private item
/// is in scope for the module it is declared in and all of its descendants.
fn push_bounded_log(buffer: &mut VecDeque<String>, line: impl Into<String>) {
    if buffer.len() >= MAX_LOG_LINES {
        buffer.pop_front();
    }
    buffer.push_back(line.into());
}
