//! The confirmation modal and the parked update notice.
//!
//! Anything that touches the system without the user having just pressed the
//! key for it goes through a [`ConfirmRequest`] first.

use super::state::App;
use crate::safety::reg_backup::RegBackupManager;
use crate::safety::restore_point::RestorePointService;
use crate::utils::admin::relaunch_as_admin;
use crate::utils::updater;

use super::BackgroundEvent;

/// Everything this app is allowed to do to the machine it is running on.
///
/// This is the app's OS seam, in the spirit of the `CommandRunner` and
/// `CleanerPaths` seams the modules already use: it exists so that accepting a
/// dialog or starting a repair run can be exercised without the machine running
/// the code opening a browser window, raising a UAC prompt or collecting
/// restore points.
///
/// [`Default`] is deliberately the *inert* set, so an [`App`] built anywhere —
/// a test, a future tool, a benchmark — cannot reach the desktop by accident.
/// The real actions are installed once, explicitly, by the TUI entry point via
/// [`App::enable_real_system_actions`].
#[derive(Debug, Clone, Copy)]
pub struct SystemActions {
    /// Hand a release URL to the OS so it opens in the default browser.
    pub open_release_page: fn(&str) -> Result<(), String>,
    /// Relaunch WinMedic through UAC, asking for Administrator rights.
    pub relaunch_elevated: fn() -> std::io::Result<()>,
    /// Where a repair run's restore point comes from. Read when the engine is
    /// built, so changing it means rebuilding the engine — which is why
    /// [`App::enable_real_system_actions`] exists instead of a plain
    /// assignment.
    pub restore_point: RestorePointService,
}

impl SystemActions {
    /// The real thing: opens a browser window, raises a UAC prompt, runs
    /// `Checkpoint-Computer`.
    pub fn real() -> Self {
        Self {
            open_release_page: updater::launch_browser,
            relaunch_elevated: relaunch_as_admin,
            restore_point: RestorePointService::real(),
        }
    }

    /// Accepts every request and does nothing. The default.
    pub fn inert() -> Self {
        Self {
            open_release_page: |_| Ok(()),
            relaunch_elevated: || Ok(()),
            restore_point: RestorePointService::inert(),
        }
    }
}

impl Default for SystemActions {
    fn default() -> Self {
        Self::inert()
    }
}

/// An action that needs an explicit yes before it touches the system.
#[derive(Debug, Clone)]
pub enum ConfirmRequest {
    Rollback {
        description: String,
        key_path: String,
        file_path: String,
    },
    Elevate,
    UpdateAvailable {
        current_version: String,
        latest_version: String,
        release_url: String,
    },
}

impl ConfirmRequest {
    pub fn title(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "RESTORE REGISTRY BACKUP?",
            ConfirmRequest::Elevate => "ADMINISTRATOR PRIVILEGES REQUIRED",
            ConfirmRequest::UpdateAvailable { .. } => "NEW WINMEDIC UPDATE AVAILABLE",
        }
    }

    pub fn confirm_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Restore",
            ConfirmRequest::Elevate => "Restart as Administrator now",
            ConfirmRequest::UpdateAvailable { .. } => "Open the release page in a browser",
        }
    }

    pub fn dismiss_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Cancel",
            ConfirmRequest::Elevate => "Continue without Administrator",
            ConfirmRequest::UpdateAvailable { .. } => "Remind me later",
        }
    }

    pub fn body(&self) -> Vec<String> {
        match self {
            ConfirmRequest::Rollback {
                description,
                key_path,
                file_path,
            } => vec![
                "The following registry backup will be restored with 'reg import'.".to_string(),
                "Existing values under this key will be overwritten.".to_string(),
                String::new(),
                format!("Backup: {}", description),
                format!("Key:    {}", key_path),
                format!("File:   {}", file_path),
            ],
            ConfirmRequest::Elevate => vec![
                "WinMedic is running without Administrator privileges.".to_string(),
                "Full diagnostics and repairs (system files via SFC/DISM, services and".to_string(),
                "the registry) need elevated privileges.".to_string(),
                String::new(),
                "Restart WinMedic as Administrator (UAC) now?".to_string(),
            ],
            ConfirmRequest::UpdateAvailable {
                current_version,
                latest_version,
                release_url,
            } => vec![
                "A new version of WinMedic is available on GitHub.".to_string(),
                String::new(),
                format!(
                    "Installed version: v{}",
                    current_version.trim_start_matches(['v', 'V'])
                ),
                format!(
                    "Latest version:    v{}",
                    latest_version.trim_start_matches(['v', 'V'])
                ),
                String::new(),
                format!("URL: {}", release_url),
                String::new(),
                "Open the GitHub release page in your default browser?".to_string(),
            ],
        }
    }
}

impl App {
    pub fn dismiss_confirm(&mut self) {
        if let Some(request) = self.pending_confirm.take() {
            match request {
                ConfirmRequest::Rollback { .. } => {
                    self.status_message = Some("Cancelled - nothing was changed.".to_string());
                }
                ConfirmRequest::Elevate => {
                    self.status_message = Some(
                        "Limited mode: repairs without Administrator privileges may fail."
                            .to_string(),
                    );
                }
                ConfirmRequest::UpdateAvailable { .. } => {
                    // "Remind me later" - the notice stays parked in
                    // `available_update` so [U] can bring it back.
                    self.status_message =
                        Some("Update notice dismissed - [U] reopens it.".to_string());
                }
            }
        }
    }

    /// Open the parked update notice as a confirmation dialog.
    ///
    /// This is the only path that raises the update modal, so it can never
    /// intercept a keystroke the user meant for something else.
    pub fn show_update_notice(&mut self) {
        if self.pending_confirm.is_some() {
            return;
        }
        let Some(info) = self.available_update.clone() else {
            return;
        };
        self.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
            current_version: info.current_version,
            latest_version: info.latest_version,
            release_url: info.release_url,
        });
    }

    /// Execute whatever action the confirmation dialog was asking about.
    pub fn confirm_pending_action(&mut self) {
        let Some(request) = self.pending_confirm.take() else {
            return;
        };

        match request {
            ConfirmRequest::Rollback {
                description,
                file_path,
                ..
            } => {
                self.is_restoring = true;
                self.status_message = Some(format!("Restoring '{}'...", description));

                let tx = self.bg_tx.clone();
                let mgr = RegBackupManager::new();
                tokio::spawn(async move {
                    let (success, message) = match mgr.restore_key(&file_path).await {
                        Ok(msg) => (true, msg),
                        Err(err) => (false, format!("Rollback failed: {}", err)),
                    };
                    let _ = tx.send(BackgroundEvent::RollbackFinished { success, message });
                });
            }
            ConfirmRequest::Elevate => {
                if let Err(e) = (self.system_actions.relaunch_elevated)() {
                    self.status_message = Some(format!("Elevation failed: {}", e));
                } else {
                    self.should_quit = true;
                }
            }
            ConfirmRequest::UpdateAvailable { release_url, .. } => {
                if let Err(e) = (self.system_actions.open_release_page)(&release_url) {
                    self.status_message = Some(format!("Could not launch a browser: {}", e));
                } else {
                    self.status_message =
                        Some("Opened the GitHub release page in your browser.".to_string());
                }
                // The user has acted on it; stop offering it under [U].
                self.available_update = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A default-built [`App`] must not be able to reach the desktop. Accepting
    /// a dialog used to open a browser window and raise a UAC prompt on whoever
    /// ran the suite — several times per run, since more than one test accepts
    /// one. The real actions are opt-in, and only the TUI opts in.
    #[test]
    fn a_default_app_cannot_reach_the_desktop() {
        let actions = App::new().system_actions;

        // The real launcher refuses anything that is not a github.com release
        // page; the inert one accepts everything, because it does nothing.
        assert!(
            (actions.open_release_page)("definitely not a release url").is_ok(),
            "App::new installed the real browser launcher"
        );
        assert!(
            (actions.relaunch_elevated)().is_ok(),
            "App::new installed the real UAC relaunch"
        );
        assert!(
            !actions.restore_point.is_live(),
            "App::new installed the real restore point service"
        );
    }

    /// The engine an [`App`] hands a repair run must inherit that inertness —
    /// `Checkpoint-Computer` is the one thing `run_repairs` does before any
    /// module gets a turn.
    #[test]
    fn a_default_app_repairs_without_creating_restore_points() {
        assert!(!App::new().engine.creates_real_restore_points());
    }

    /// Confirming the update dialog reports success without anything opening.
    #[test]
    fn confirming_the_update_dialog_opens_nothing_by_default() {
        let mut app = App::new();
        app.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
            current_version: "0.1.0".to_string(),
            latest_version: "v0.2.0".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        });

        app.confirm_pending_action();

        assert!(app.pending_confirm.is_none());
        assert_eq!(
            app.status_message,
            Some("Opened the GitHub release page in your browser.".to_string())
        );
    }

    #[test]
    fn test_confirm_request_elevate() {
        let req = ConfirmRequest::Elevate;
        assert_eq!(req.title(), "ADMINISTRATOR PRIVILEGES REQUIRED");
        assert_eq!(req.confirm_label(), "Restart as Administrator now");
        assert_eq!(req.dismiss_label(), "Continue without Administrator");
        assert!(!req.body().is_empty());
    }

    #[test]
    fn test_confirm_request_rollback() {
        let req = ConfirmRequest::Rollback {
            description: "Test Backup".to_string(),
            key_path: "HKCU\\Test".to_string(),
            file_path: "C:\\test.reg".to_string(),
        };
        assert_eq!(req.title(), "RESTORE REGISTRY BACKUP?");
        assert_eq!(req.confirm_label(), "Restore");
        assert_eq!(req.dismiss_label(), "Cancel");
        assert!(!req.body().is_empty());
    }

    #[test]
    fn test_confirm_request_update_available() {
        let req = ConfirmRequest::UpdateAvailable {
            current_version: "0.1.0".to_string(),
            latest_version: "v0.2.0".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        };
        assert_eq!(req.title(), "NEW WINMEDIC UPDATE AVAILABLE");
        assert_eq!(req.confirm_label(), "Open the release page in a browser");
        assert_eq!(req.dismiss_label(), "Remind me later");
        let body = req.body().join("\n");
        assert!(body.contains("v0.1.0"));
        assert!(body.contains("v0.2.0"));
        assert!(body.contains("https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"));
    }
}
