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
            ConfirmRequest::Rollback { .. } => "REGISTRY-SICHERUNG WIEDERHERSTELLEN?",
            ConfirmRequest::Elevate => "ADMINISTRATORRECHTE ERFORDERLICH",
            ConfirmRequest::UpdateAvailable { .. } => "NEUES WINMEDIC UPDATE VERFÜGBAR",
        }
    }

    pub fn confirm_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Wiederherstellen",
            ConfirmRequest::Elevate => "Jetzt als Admin neu starten",
            ConfirmRequest::UpdateAvailable { .. } => "Release-Seite im Browser öffnen",
        }
    }

    pub fn dismiss_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Abbrechen",
            ConfirmRequest::Elevate => "Ohne Admin fortfahren",
            ConfirmRequest::UpdateAvailable { .. } => "Später erinnern",
        }
    }

    pub fn body(&self) -> Vec<String> {
        match self {
            ConfirmRequest::Rollback {
                description,
                key_path,
                file_path,
            } => vec![
                "Die folgende Registry-Sicherung wird per 'reg import' zurückgespielt.".to_string(),
                "Bestehende Werte unter diesem Schlüssel werden dabei überschrieben.".to_string(),
                String::new(),
                format!("Sicherung:  {}", description),
                format!("Schlüssel:  {}", key_path),
                format!("Datei:      {}", file_path),
            ],
            ConfirmRequest::Elevate => vec![
                "WinMedic wurde ohne Administratorrechte ausgeführt.".to_string(),
                "Vollständige Diagnose- und Reparaturfunktionen (Systemdateien via SFC/DISM,"
                    .to_string(),
                "Dienste und Registry) erfordern erhöhte Administratorrechte.".to_string(),
                String::new(),
                "Möchten Sie WinMedic jetzt mit Administratorrechten (UAC) neu starten?"
                    .to_string(),
            ],
            ConfirmRequest::UpdateAvailable {
                current_version,
                latest_version,
                release_url,
            } => vec![
                "Eine neue Version von WinMedic ist auf GitHub verfügbar!".to_string(),
                String::new(),
                format!(
                    "Installierte Version:  v{}",
                    current_version.trim_start_matches(['v', 'V'])
                ),
                format!(
                    "Neueste Version:       v{}",
                    latest_version.trim_start_matches(['v', 'V'])
                ),
                String::new(),
                format!("URL: {}", release_url),
                String::new(),
                "Möchten Sie die GitHub Release-Seite im Standardbrowser öffnen?".to_string(),
            ],
        }
    }
}

impl App {
    pub fn dismiss_confirm(&mut self) {
        if let Some(request) = self.pending_confirm.take() {
            match request {
                ConfirmRequest::Rollback { .. } => {
                    self.status_message =
                        Some("Abgebrochen – es wurde nichts verändert.".to_string());
                }
                ConfirmRequest::Elevate => {
                    self.status_message = Some(
                        "Eingeschränkter Modus: Reparaturen ohne Administratorrechte können fehlschlagen."
                            .to_string(),
                    );
                }
                ConfirmRequest::UpdateAvailable { .. } => {
                    // "Später erinnern" — the notice stays parked in
                    // `available_update` so [U] can bring it back.
                    self.status_message =
                        Some("Update-Hinweis geschlossen – [U] öffnet ihn erneut.".to_string());
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
                self.status_message = Some(format!("Stelle '{}' wieder her...", description));

                let tx = self.bg_tx.clone();
                let mgr = RegBackupManager::new();
                tokio::spawn(async move {
                    let (success, message) = match mgr.restore_key(&file_path).await {
                        Ok(msg) => (true, msg),
                        Err(err) => (false, format!("Rollback fehlgeschlagen: {}", err)),
                    };
                    let _ = tx.send(BackgroundEvent::RollbackFinished { success, message });
                });
            }
            ConfirmRequest::Elevate => {
                if let Err(e) = relaunch_as_admin() {
                    self.status_message = Some(format!("Elevierung fehlgeschlagen: {}", e));
                } else {
                    self.should_quit = true;
                }
            }
            ConfirmRequest::UpdateAvailable { release_url, .. } => {
                if let Err(e) = updater::launch_browser(&release_url) {
                    self.status_message = Some(format!("Browser-Start fehlgeschlagen: {}", e));
                } else {
                    self.status_message =
                        Some("GitHub Release-Seite im Browser geöffnet.".to_string());
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
        assert_eq!(req.title(), "ADMINISTRATORRECHTE ERFORDERLICH");
        assert_eq!(req.confirm_label(), "Jetzt als Admin neu starten");
        assert_eq!(req.dismiss_label(), "Ohne Admin fortfahren");
        assert!(!req.body().is_empty());
    }

    #[test]
    fn test_confirm_request_rollback() {
        let req = ConfirmRequest::Rollback {
            description: "Test Backup".to_string(),
            key_path: "HKCU\\Test".to_string(),
            file_path: "C:\\test.reg".to_string(),
        };
        assert_eq!(req.title(), "REGISTRY-SICHERUNG WIEDERHERSTELLEN?");
        assert_eq!(req.confirm_label(), "Wiederherstellen");
        assert_eq!(req.dismiss_label(), "Abbrechen");
        assert!(!req.body().is_empty());
    }

    #[test]
    fn test_confirm_request_update_available() {
        let req = ConfirmRequest::UpdateAvailable {
            current_version: "0.1.0".to_string(),
            latest_version: "v0.2.0".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
        };
        assert_eq!(req.title(), "NEUES WINMEDIC UPDATE VERFÜGBAR");
        assert_eq!(req.confirm_label(), "Release-Seite im Browser öffnen");
        assert_eq!(req.dismiss_label(), "Später erinnern");
        let body = req.body().join("\n");
        assert!(body.contains("v0.1.0"));
        assert!(body.contains("v0.2.0"));
        assert!(body.contains("https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"));
    }
}
