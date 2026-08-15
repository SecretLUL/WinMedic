//! The confirmation modal and the parked update notice.
//!
//! Anything that touches the system without the user having just pressed the
//! key for it goes through a [`ConfirmRequest`] first.

use super::state::App;
use crate::safety::reg_backup::RegBackupManager;
use crate::utils::admin::relaunch_as_admin;
use crate::utils::updater;

use super::BackgroundEvent;

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
                if let Err(e) = relaunch_as_admin() {
                    self.status_message = Some(format!("Elevation failed: {}", e));
                } else {
                    self.should_quit = true;
                }
            }
            ConfirmRequest::UpdateAvailable { release_url, .. } => {
                if let Err(e) = updater::launch_browser(&release_url) {
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
