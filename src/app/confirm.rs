//! The confirmation modal and the parked update notice.
//!
//! Anything that touches the system without the user having just pressed the
//! key for it goes through a [`ConfirmRequest`] first.

use super::state::App;
use crate::safety::reg_backup::RegBackupManager;
use crate::safety::restore_point::RestorePointService;
use crate::utils::admin::relaunch_as_admin;
use crate::utils::self_update::{InstallPlan, SelfUpdateService};
use crate::utils::updater::{self, UpdateDownload};

use super::BackgroundEvent;

/// Budget for each transfer an in-place update makes.
///
/// Generous compared to the five seconds the *check* gets: this one is moving a
/// several-megabyte binary over whatever connection the user has, and a timeout
/// here throws the download away.
const UPDATE_TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

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
    /// Download a release, verify it and replace this executable with it.
    /// Inert by default, for the same reason as the rest of this struct: a
    /// test that accepts the update dialog must not start downloading
    /// executables onto the machine running the suite.
    pub self_update: SelfUpdateService,
    /// Where a repair run's restore point comes from. Read when the engine is
    /// built, so changing it means rebuilding the engine — which is why
    /// [`App::enable_real_system_actions`] exists instead of a plain
    /// assignment.
    pub restore_point: RestorePointService,
    /// Reboot the machine to finalize repairs that require a system restart.
    pub restart_system: fn() -> Result<(), String>,
}

fn real_restart_system() -> Result<(), String> {
    std::process::Command::new("shutdown.exe")
        .args([
            "/r",
            "/t",
            "0",
            "/c",
            "WinMedic: Restarting to apply system repairs",
        ])
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not initiate restart: {}", e))
}

impl SystemActions {
    /// The real thing: opens a browser window, raises a UAC prompt, runs
    /// `Checkpoint-Computer`, reboots the system.
    pub fn real() -> Self {
        Self {
            open_release_page: updater::launch_browser,
            relaunch_elevated: relaunch_as_admin,
            self_update: SelfUpdateService::real(),
            restore_point: RestorePointService::real(),
            restart_system: real_restart_system,
        }
    }

    /// Accepts every request and does nothing. The default.
    pub fn inert() -> Self {
        Self {
            open_release_page: |_| Ok(()),
            relaunch_elevated: || Ok(()),
            self_update: SelfUpdateService::inert(),
            restore_point: RestorePointService::inert(),
            restart_system: || Ok(()),
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
        /// The checksum-backed download for this release, when it has one.
        ///
        /// Its presence is what decides whether the dialog offers to install
        /// the update or only to open the release page: a release WinMedic
        /// cannot verify is never installed in place.
        download: Option<UpdateDownload>,
    },
    RestartRequired {
        issues: Vec<String>,
    },
}

impl ConfirmRequest {
    pub fn title(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "RESTORE REGISTRY BACKUP?",
            ConfirmRequest::Elevate => "ADMINISTRATOR PRIVILEGES REQUIRED",
            ConfirmRequest::UpdateAvailable { .. } => "NEW WINMEDIC UPDATE AVAILABLE",
            ConfirmRequest::RestartRequired { .. } => "SYSTEM RESTART REQUIRED",
        }
    }

    pub fn confirm_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Restore",
            ConfirmRequest::Elevate => "Restart as Administrator now",
            ConfirmRequest::UpdateAvailable {
                download: Some(_), ..
            } => "Download, verify and install it",
            ConfirmRequest::UpdateAvailable { download: None, .. } => {
                "Open the release page in a browser"
            }
            ConfirmRequest::RestartRequired { .. } => "Restart now",
        }
    }

    pub fn dismiss_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Cancel",
            ConfirmRequest::Elevate => "Continue without Administrator",
            ConfirmRequest::UpdateAvailable { .. } => "Remind me later",
            ConfirmRequest::RestartRequired { .. } => "Later",
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
                download,
            } => {
                let mut body = vec![
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
                ];

                match download {
                    // Everything the install will do, before it does any of it.
                    // Replacing the executable a user runs as Administrator is
                    // not something to describe as "updating" and leave at that.
                    Some(download) => body.extend([
                        format!("WinMedic will download {}", download.binary_name),
                        "from the release, check it against the SHA256 checksum published"
                            .to_string(),
                        "with it, and only then replace this executable.".to_string(),
                        String::new(),
                        "If the checksum does not match, nothing is replaced and the".to_string(),
                        "release page opens in your browser instead.".to_string(),
                        String::new(),
                        "The running WinMedic keeps working until you restart it.".to_string(),
                    ]),
                    // No checksum, no in-place install: there would be nothing
                    // to hold the downloaded bytes to.
                    None => body.extend([
                        "This release publishes no checksum, so WinMedic will not".to_string(),
                        "install it in place - the download is not verifiable.".to_string(),
                        String::new(),
                        format!("URL: {}", release_url),
                        String::new(),
                        "Open the GitHub release page in your default browser?".to_string(),
                    ]),
                }

                body
            }
            ConfirmRequest::RestartRequired { issues } => {
                let mut body = vec![
                    "One or more applied repairs require a system restart to take effect:"
                        .to_string(),
                    String::new(),
                ];
                for issue_title in issues {
                    body.push(format!("  • {}", issue_title));
                }
                body.push(String::new());
                body.push("Restart the system now to complete these repairs?".to_string());
                body
            }
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
                ConfirmRequest::RestartRequired { .. } => {
                    self.status_message = Some(
                        "Restart postponed. A system restart is pending to finalize repairs."
                            .to_string(),
                    );
                }
            }
        }
    }

    /// Open the parked update notice as a confirmation dialog.
    ///
    /// This is the only path that raises the update modal, so it can never
    /// intercept a keystroke the user meant for something else.
    pub fn show_update_notice(&mut self) {
        // Reopening the dialog mid-install would offer to start a second
        // download onto the same staging file.
        if self.pending_confirm.is_some() || self.is_updating {
            return;
        }
        let Some(info) = self.available_update.clone() else {
            return;
        };
        self.pending_confirm = Some(ConfirmRequest::UpdateAvailable {
            current_version: info.current_version,
            latest_version: info.latest_version,
            release_url: info.release_url,
            download: info.download,
        });
    }

    /// Open the release page because the in-place update did not happen, and
    /// say why.
    ///
    /// Every failure path lands here: a download that never arrived, a checksum
    /// that did not match, a binary that could not be replaced. The user is left
    /// with a working WinMedic and the manual route, plus the reason the
    /// automatic one was abandoned.
    pub(super) fn fall_back_to_browser(&mut self, release_url: &str, reason: &str) {
        self.status_message = Some(match (self.system_actions.open_release_page)(release_url) {
            Ok(()) => format!(
                "Update not installed ({}). The release page is open in your browser.",
                reason
            ),
            Err(e) => format!(
                "Update not installed ({}), and the browser could not be opened either: {}",
                reason, e
            ),
        });
        // The user has acted on it; stop offering it under [U].
        self.available_update = None;
    }

    /// Download, verify and install the release the user just accepted.
    ///
    /// Returns immediately: the work runs on the Tokio runtime and reports back
    /// through [`BackgroundEvent::UpdateInstallStep`] and
    /// [`BackgroundEvent::UpdateInstallFinished`], so the TUI keeps drawing
    /// while a multi-megabyte download is in flight.
    fn start_update_install(
        &mut self,
        version: String,
        release_url: String,
        download: UpdateDownload,
    ) {
        let plan = match InstallPlan::for_current_exe(download, &version, UPDATE_TRANSFER_TIMEOUT) {
            Ok(plan) => plan,
            Err(err) => return self.fall_back_to_browser(&release_url, &err.reason()),
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return self.fall_back_to_browser(&release_url, "there is no runtime to download on");
        };

        self.is_updating = true;
        self.status_message = Some(format!(
            "Downloading WinMedic v{}...",
            version.trim_start_matches(['v', 'V'])
        ));

        // Progress travels on its own channel of plain strings so the updater
        // never has to know what a `BackgroundEvent` is; this task is the
        // adapter between the two.
        let (step_tx, mut step_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let step_bg = self.bg_tx.clone();
        handle.spawn(async move {
            while let Some(step) = step_rx.recv().await {
                if step_bg
                    .send(BackgroundEvent::UpdateInstallStep(step))
                    .is_err()
                {
                    break;
                }
            }
        });

        let service = self.system_actions.self_update;
        let tx = self.bg_tx.clone();
        handle.spawn(async move {
            let result = service.install(plan, Some(step_tx)).await;
            let _ = tx.send(BackgroundEvent::UpdateInstallFinished {
                version,
                release_url,
                result,
            });
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
            ConfirmRequest::UpdateAvailable {
                latest_version,
                release_url,
                download,
                ..
            } => match download {
                Some(download) => self.start_update_install(latest_version, release_url, download),
                None => {
                    // Without a checksum the browser *is* what the button
                    // offered, so this is not a fallback from a failure.
                    if let Err(e) = (self.system_actions.open_release_page)(&release_url) {
                        self.status_message = Some(format!("Could not launch a browser: {}", e));
                    } else {
                        self.status_message =
                            Some("Opened the GitHub release page in your browser.".to_string());
                    }
                    // The user has acted on it; stop offering it under [U].
                    self.available_update = None;
                }
            },
            ConfirmRequest::RestartRequired { .. } => {
                if let Err(e) = (self.system_actions.restart_system)() {
                    self.status_message = Some(format!("System restart failed: {}", e));
                } else {
                    self.should_quit = true;
                }
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
        assert!(
            !actions.self_update.is_live(),
            "App::new installed the real self-updater: accepting the update \
             dialog would download and replace an executable on this machine"
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
            download: None,
        });

        app.confirm_pending_action();

        assert!(app.pending_confirm.is_none());
        assert_eq!(
            app.status_message,
            Some("Opened the GitHub release page in your browser.".to_string())
        );
    }

    /// A download pair pointing at the real release path, for dialog tests.
    fn a_download() -> UpdateDownload {
        UpdateDownload {
            binary_name: "winmedic-v0.2.0.exe".to_string(),
            binary_url:
                "https://github.com/SecretLUL/WinMedic/releases/download/v0.2.0/winmedic-v0.2.0.exe"
                    .to_string(),
            checksum_url:
                "https://github.com/SecretLUL/WinMedic/releases/download/v0.2.0/winmedic-v0.2.0.exe.sha256"
                    .to_string(),
            size: 4_200_000,
        }
    }

    fn update_request(download: Option<UpdateDownload>) -> ConfirmRequest {
        ConfirmRequest::UpdateAvailable {
            current_version: "0.1.0".to_string(),
            latest_version: "v0.2.0".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
            download,
        }
    }

    /// The button has to say which of the two things it does, because they are
    /// very different things: one opens a web page, the other replaces the
    /// executable the user runs as Administrator.
    #[test]
    fn the_dialog_offers_an_install_only_when_the_release_can_be_verified() {
        let verifiable = update_request(Some(a_download()));
        assert_eq!(
            verifiable.confirm_label(),
            "Download, verify and install it"
        );
        let body = verifiable.body().join("\n");
        assert!(body.contains("winmedic-v0.2.0.exe"), "{}", body);
        assert!(body.contains("SHA256"), "{}", body);
        // What happens if it does not verify is part of the offer, not a
        // surprise afterwards.
        assert!(body.contains("nothing is replaced"), "{}", body);

        let unverifiable = update_request(None);
        assert_eq!(
            unverifiable.confirm_label(),
            "Open the release page in a browser"
        );
        let body = unverifiable.body().join("\n");
        assert!(body.contains("publishes no checksum"), "{}", body);
        assert!(body.contains("https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"));
    }

    /// The parked notice has to carry the download with it, or pressing [U]
    /// would silently downgrade an installable update to the browser flow.
    #[test]
    fn the_parked_notice_keeps_the_download_it_was_offered_with() {
        let mut app = App::new();
        // A non-elevated run parks the Elevate dialog at construction.
        app.pending_confirm = None;
        app.available_update = Some(crate::utils::updater::UpdateInfo {
            current_version: "0.1.0".to_string(),
            latest_version: "v0.2.0".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
            release_name: None,
            release_body: None,
            download: Some(a_download()),
        });

        app.show_update_notice();

        match app.pending_confirm {
            Some(ConfirmRequest::UpdateAvailable {
                download: Some(ref download),
                ..
            }) => assert_eq!(download.binary_name, "winmedic-v0.2.0.exe"),
            other => panic!("expected an installable update notice, got {:?}", other),
        }
    }

    /// Reopening the dialog mid-install would offer a second download onto the
    /// same staging file.
    #[test]
    fn the_notice_does_not_reopen_while_an_install_is_running() {
        let mut app = App::new();
        app.pending_confirm = None;
        app.available_update = Some(crate::utils::updater::UpdateInfo {
            current_version: "0.1.0".to_string(),
            latest_version: "v0.2.0".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
            release_name: None,
            release_body: None,
            download: Some(a_download()),
        });
        app.is_updating = true;

        app.show_update_notice();

        assert!(app.pending_confirm.is_none());
    }

    /// Accepting an installable update starts a background job rather than
    /// blocking the frame, and says so while it runs.
    #[tokio::test]
    async fn accepting_an_installable_update_starts_a_background_install() {
        let mut app = App::new();
        app.pending_confirm = Some(update_request(Some(a_download())));

        app.confirm_pending_action();

        assert!(app.pending_confirm.is_none());
        assert!(app.is_updating, "the install was not marked as running");
        assert!(
            app.status_message
                .as_deref()
                .is_some_and(|m| m.contains("Downloading WinMedic v0.2.0")),
            "{:?}",
            app.status_message
        );
        // The default app's updater is inert, so nothing was downloaded — the
        // failure arrives as an event and is asserted in `events`.
    }

    /// Every way an install can fail ends in the same place: a working WinMedic,
    /// the release page open, and the reason on screen.
    #[test]
    fn the_browser_fallback_states_why_the_install_did_not_happen() {
        let mut app = App::new();
        app.available_update = Some(crate::utils::updater::UpdateInfo {
            current_version: "0.1.0".to_string(),
            latest_version: "v0.2.0".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0".to_string(),
            release_name: None,
            release_body: None,
            download: Some(a_download()),
        });

        app.fall_back_to_browser(
            "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0",
            "SHA256 mismatch",
        );

        let message = app.status_message.clone().unwrap();
        assert!(message.contains("SHA256 mismatch"), "{}", message);
        assert!(message.contains("release page"), "{}", message);
        assert!(app.available_update.is_none(), "[U] still offers it");
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
            download: None,
        };
        assert_eq!(req.title(), "NEW WINMEDIC UPDATE AVAILABLE");
        assert_eq!(req.confirm_label(), "Open the release page in a browser");
        assert_eq!(req.dismiss_label(), "Remind me later");
        let body = req.body().join("\n");
        assert!(body.contains("v0.1.0"));
        assert!(body.contains("v0.2.0"));
        assert!(body.contains("https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"));
    }

    #[test]
    fn test_confirm_request_restart_required() {
        let req = ConfirmRequest::RestartRequired {
            issues: vec![
                "System reboot pending after updates".to_string(),
                "Page file disabled on every drive".to_string(),
            ],
        };
        assert_eq!(req.title(), "SYSTEM RESTART REQUIRED");
        assert_eq!(req.confirm_label(), "Restart now");
        assert_eq!(req.dismiss_label(), "Later");
        let body = req.body().join("\n");
        assert!(body.contains("System reboot pending after updates"));
        assert!(body.contains("Page file disabled on every drive"));
        assert!(body.contains("Restart the system now"));
    }

    #[test]
    fn test_confirm_restart_action_in_inert_mode() {
        let mut app = App::new();
        app.pending_confirm = Some(ConfirmRequest::RestartRequired {
            issues: vec!["System reboot pending after updates".to_string()],
        });

        app.confirm_pending_action();

        assert!(app.pending_confirm.is_none());
        assert!(app.should_quit);
    }

    #[test]
    fn test_dismiss_restart_action_leaves_status_message() {
        let mut app = App::new();
        app.pending_confirm = Some(ConfirmRequest::RestartRequired {
            issues: vec!["System reboot pending after updates".to_string()],
        });

        app.dismiss_confirm();

        assert!(app.pending_confirm.is_none());
        assert!(!app.should_quit);
        assert!(
            app.status_message
                .as_deref()
                .is_some_and(|m| m.contains("Restart postponed"))
        );
    }
}
