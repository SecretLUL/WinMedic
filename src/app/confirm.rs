//! The confirmation modal and the parked update notice.
//!
//! Anything that touches the system without the user having just pressed the
//! key for it goes through a [`ConfirmRequest`] first.

use super::state::App;
use crate::config::AppConfig;
use crate::safety::reg_backup::RegBackupManager;
use crate::safety::restore_point::RestorePointService;
use crate::utils::self_remove;
use crate::utils::self_update::{self, InstallPlan, InstallProgress, SelfUpdateService};
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
/// the code opening a browser window or collecting restore points.
///
/// [`Default`] is deliberately the *inert* set, so an [`App`] built anywhere —
/// a test, a future tool, a benchmark — cannot reach the desktop by accident.
/// The real actions are installed once, explicitly, by the desktop front end
/// via [`App::enable_real_system_actions`].
#[derive(Debug, Clone, Copy)]
pub struct SystemActions {
    /// Hand a release URL to the OS so it opens in the default browser.
    pub open_release_page: fn(&str) -> Result<(), String>,
    /// Open WinMedic's bug report form, filled in for a crash, in the default
    /// browser.
    pub open_issue_form: fn(&str) -> Result<(), String>,
    /// Download a release, verify it and replace this executable with it.
    /// Inert by default, for the same reason as the rest of this struct: a
    /// test that accepts the update dialog must not start downloading
    /// executables onto the machine running the suite.
    pub self_update: SelfUpdateService,
    /// Start the executable an update just installed, so the new version is
    /// running without the user starting it again.
    pub start_installed_update: fn(&std::path::Path) -> Result<(), String>,
    /// Where a repair run's restore point comes from. Read when the engine is
    /// built, so changing it means rebuilding the engine — which is why
    /// [`App::enable_real_system_actions`] exists instead of a plain
    /// assignment.
    pub restore_point: RestorePointService,
    /// Import a registry backup (`reg import`), from a blocking thread.
    pub restore_registry: fn(&str) -> Result<String, String>,
    /// Where the window's "Export report" writes. The inert one is the temp
    /// folder, so a test that exports leaves the real reports folder alone.
    pub reports_dir: fn() -> std::path::PathBuf,
    /// Reboot the machine to finalize repairs that require a system restart.
    pub restart_system: fn() -> Result<(), String>,
    /// Whether the latest scan may be written back to `%APPDATA%`.
    ///
    /// Off by default for the same reason as everything above it: `cargo test`
    /// builds dozens of `App`s and ticks their checkboxes, and none of that may
    /// overwrite the scan the developer's own WinMedic left behind.
    pub persist_scan_state: bool,
    /// Whether settings may be written back to `%APPDATA%`.
    ///
    /// Off by default for the same reason: a test that changes a setting must
    /// not rewrite the developer's own configuration — least of all the helper
    /// switch the real app acts on.
    pub persist_config: bool,
    /// Synchronize the WinMedicHelper scheduled background task.
    pub sync_helper_task: fn(bool, u32) -> Result<(), String>,
    /// Repair the task when its setting is on, and remove the Run entry of
    /// the "Start with Windows" setting older versions had.
    pub reconcile_background: fn(&AppConfig, &std::path::Path) -> Result<(), String>,
    /// Note that WinMedic is to be removed from this PC. The window then
    /// closes, and `main` does the removing once it has
    /// ([`crate::utils::self_remove`]). Inert by default: a test that
    /// confirms the dialog must not have the test run delete the settings,
    /// logs and registry backups of the developer's own WinMedic.
    pub request_removal: fn(),
}

fn real_restore_registry(file_path: &str) -> Result<String, String> {
    tokio::runtime::Handle::current().block_on(RegBackupManager::new().restore_key(file_path))
}

fn real_reports_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("WinMedic")
        .join("reports")
}

/// shutdown.exe returns as soon as Windows has accepted the restart or refused
/// it, so it is waited for: a refusal keeps the window open and says so.
///
/// Without a window, or it gets a console of its own that flashes up: this
/// process gave its console back. Without stdio, because there is none to pass
/// on.
fn real_restart_system() -> Result<(), String> {
    use std::process::Stdio;

    let mut cmd = std::process::Command::new(crate::utils::cmd::system_program("shutdown.exe")?);
    cmd.args([
        "/r",
        "/t",
        "0",
        "/c",
        "WinMedic: Restarting to apply system repairs",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let status = cmd
        .status()
        .map_err(|e| format!("Could not initiate restart: {}", e))?;
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(format!("shutdown.exe exited with code {code}")),
        None => Err("shutdown.exe ended without an exit code".to_string()),
    }
}

impl SystemActions {
    /// The real thing: opens a browser window, runs `Checkpoint-Computer`,
    /// reboots the system.
    pub fn real() -> Self {
        Self {
            open_release_page: updater::launch_browser,
            open_issue_form: crate::utils::crash_report::launch_issue_form,
            self_update: SelfUpdateService::real(),
            start_installed_update: self_update::start_installed,
            restore_point: RestorePointService::real(),
            restore_registry: real_restore_registry,
            reports_dir: real_reports_dir,
            restart_system: real_restart_system,
            persist_scan_state: true,
            persist_config: true,
            sync_helper_task: crate::utils::background_task::sync_helper_task,
            reconcile_background: crate::utils::background_task::reconcile,
            request_removal: crate::utils::self_remove::request,
        }
    }

    /// Accepts every request and does nothing. The default.
    pub fn inert() -> Self {
        Self {
            open_release_page: |_| Ok(()),
            open_issue_form: |_| Ok(()),
            self_update: SelfUpdateService::inert(),
            start_installed_update: |_| Ok(()),
            restore_point: RestorePointService::inert(),
            restore_registry: |_| Ok("Nothing was imported.".to_string()),
            reports_dir: std::env::temp_dir,
            restart_system: || Ok(()),
            persist_scan_state: false,
            persist_config: false,
            sync_helper_task: |_, _| Ok(()),
            reconcile_background: |_, _| Ok(()),
            request_removal: || {},
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
    /// Take WinMedic off this PC: the program, its scheduled task, and the
    /// settings, logs, reports and registry backups it keeps.
    Remove,
    /// Windows created no restore point, so the repair run stopped before
    /// its first repair. Going on without one is the user's call.
    RepairWithoutRestorePoint {
        reason: String,
    },
}

impl ConfirmRequest {
    pub fn title(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "RESTORE REGISTRY BACKUP?",
            ConfirmRequest::UpdateAvailable { .. } => "NEW WINMEDIC UPDATE AVAILABLE",
            ConfirmRequest::RestartRequired { .. } => "SYSTEM RESTART REQUIRED",
            ConfirmRequest::Remove => "REMOVE WINMEDIC FROM THIS PC?",
            ConfirmRequest::RepairWithoutRestorePoint { .. } => "REPAIR WITHOUT A RESTORE POINT?",
        }
    }

    pub fn confirm_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Restore",
            ConfirmRequest::UpdateAvailable {
                download: Some(_), ..
            } => "Download and restart",
            ConfirmRequest::UpdateAvailable { download: None, .. } => {
                "Open the release page in a browser"
            }
            ConfirmRequest::RestartRequired { .. } => "Restart now",
            ConfirmRequest::Remove => "Remove",
            ConfirmRequest::RepairWithoutRestorePoint { .. } => "Repair without one",
        }
    }

    pub fn dismiss_label(&self) -> &'static str {
        match self {
            ConfirmRequest::Rollback { .. } => "Cancel",
            ConfirmRequest::UpdateAvailable { .. } => "Remind me later",
            ConfirmRequest::RestartRequired { .. } => "Later",
            ConfirmRequest::Remove => "Cancel",
            ConfirmRequest::RepairWithoutRestorePoint { .. } => "Cancel",
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
            // Not "repairs": Windows' own pending restart can be all there is.
            ConfirmRequest::RestartRequired { issues } => {
                let mut body = vec!["Restarting Windows finishes:".to_string(), String::new()];
                for issue_title in issues {
                    body.push(format!("  • {}", issue_title));
                }
                body.push(String::new());
                body.push("Restart Windows now?".to_string());
                body
            }
            // Named with their places, so "everything" is not taken on
            // trust: the registry backups are what a rollback needs.
            ConfirmRequest::Remove => {
                let shown = |path: Option<std::path::PathBuf>| {
                    path.map(|path| path.display().to_string())
                        .unwrap_or_default()
                };
                let exe = std::env::current_exe().ok();
                let from_winget = exe
                    .as_deref()
                    .and_then(self_remove::winget_product_code)
                    .is_some();
                let mut body = vec![
                    "WinMedic closes and deletes itself, with everything it keeps on this PC:"
                        .to_string(),
                    String::new(),
                    format!("  • the program: {}", shown(exe)),
                    "  • the background scan task".to_string(),
                    format!(
                        "  • settings, logs and reports: {}",
                        shown(AppConfig::config_path().parent().map(Into::into))
                    ),
                    format!(
                        "  • registry backups: {}",
                        shown(
                            crate::safety::reg_backup::default_backup_dir()
                                .parent()
                                .map(Into::into)
                        )
                    ),
                ];
                if from_winget {
                    body.push("  • WinGet's entry for WinMedic".to_string());
                }
                body.extend([
                    String::new(),
                    "Without the backups, earlier repairs can no longer be undone from WinMedic."
                        .to_string(),
                    "Windows' own restore points stay.".to_string(),
                ]);
                body
            }
            ConfirmRequest::RepairWithoutRestorePoint { reason } => vec![
                "Windows did not create a restore point, so nothing was repaired yet:".to_string(),
                String::new(),
                reason.clone(),
                String::new(),
                "Without one, System Restore cannot take the PC back to how it".to_string(),
                "was before these repairs.".to_string(),
                String::new(),
                "Repair anyway?".to_string(),
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
                ConfirmRequest::UpdateAvailable { .. } => {
                    // "Remind me later" - the notice stays parked in
                    // `available_update` so [U] can bring it back.
                    self.status_message =
                        Some("Update notice dismissed - [U] reopens it.".to_string());
                }
                ConfirmRequest::RestartRequired { .. } => {
                    self.status_message = Some("Restart postponed.".to_string());
                }
                ConfirmRequest::Remove => {
                    self.status_message = Some("Cancelled - nothing was changed.".to_string());
                }
                ConfirmRequest::RepairWithoutRestorePoint { .. } => {
                    self.status_message = Some(
                        "Nothing was repaired. Windows creates restore points only while System Protection is on for the system drive."
                            .to_string(),
                    );
                }
            }
        }
    }

    /// Ask before taking WinMedic off this PC.
    ///
    /// Not while it works: the removal closes the window, and a repair cut
    /// short there is left half done, a download half written.
    pub fn request_remove(&mut self) {
        if self.is_busy() || self.is_restoring || self.is_updating {
            self.status_message =
                Some("WinMedic is still working. Remove it once that has finished.".to_string());
            return;
        }
        self.pending_confirm = Some(ConfirmRequest::Remove);
    }

    /// Close the window and have `main` remove WinMedic once it has closed
    /// ([`self_remove`]).
    ///
    /// The window cannot do it itself: on its way out eframe writes the
    /// window's position into the very folder that has to go.
    fn remove_from_this_pc(&mut self) {
        // Nothing of this window is written back into folders that are
        // about to be deleted, and no update is started on the way out.
        self.system_actions.persist_config = false;
        self.system_actions.persist_scan_state = false;
        self.restart_into = None;

        (self.system_actions.request_removal)();
        self.status_message = Some("Removing WinMedic from this PC...".to_string());
        self.should_quit = true;
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
    /// [`BackgroundEvent::UpdateInstallFinished`], so the window keeps drawing
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
        self.update_step = None;
        self.update_download = None;
        self.status_message = Some(format!(
            "Downloading WinMedic v{}...",
            version.trim_start_matches(['v', 'V'])
        ));

        // Progress travels on its own channel so the updater never has to
        // know what a `BackgroundEvent` is; this task is the adapter between
        // the two.
        let (step_tx, mut step_rx) = tokio::sync::mpsc::unbounded_channel::<InstallProgress>();
        let step_bg = self.bg_tx.clone();
        handle.spawn(async move {
            while let Some(progress) = step_rx.recv().await {
                let event = match progress {
                    InstallProgress::Step(step) => BackgroundEvent::UpdateInstallStep(step),
                    InstallProgress::Downloaded { received, total } => {
                        BackgroundEvent::UpdateDownloaded { received, total }
                    }
                };
                if step_bg.send(event).is_err() {
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

    /// Start the installed update and close this window, once nothing is
    /// running that closing it would cut short.
    ///
    /// The download can finish in the middle of a scan, a repair run or a
    /// registry restore, and ending the process there would leave a repair half
    /// done. So the restart waits for it; this runs every frame.
    pub(super) fn restart_into_update_when_idle(&mut self) {
        if self.is_busy() || self.is_restoring {
            return;
        }
        let Some(exe) = self.restart_into.take() else {
            return;
        };
        match (self.system_actions.start_installed_update)(&exe) {
            Ok(()) => self.should_quit = true,
            Err(e) => {
                self.status_message = Some(format!(
                    "The update is installed, but it could not be started ({e}). Restart WinMedic to run it."
                ));
            }
        }
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
                let restore = self.system_actions.restore_registry;
                tokio::task::spawn_blocking(move || {
                    let (success, message) = match restore(&file_path) {
                        Ok(msg) => (true, msg),
                        Err(err) => (false, format!("Rollback failed: {}", err)),
                    };
                    let _ = tx.send(BackgroundEvent::RollbackFinished { success, message });
                });
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
            ConfirmRequest::Remove => self.remove_from_this_pc(),
            ConfirmRequest::RepairWithoutRestorePoint { .. } => {
                self.start_repairs_without_restore_point()
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
    /// one. The real actions are opt-in, and only the desktop front end opts in.
    #[test]
    fn a_default_app_cannot_reach_the_desktop() {
        let actions = App::new().system_actions;

        // The real launcher refuses anything that is not a github.com release
        // page; the inert one accepts everything, because it does nothing.
        assert!(
            (actions.open_release_page)("definitely not a release url").is_ok(),
            "App::new installed the real browser launcher"
        );
        assert_eq!(
            (actions.restore_registry)("definitely not a backup").as_deref(),
            Ok("Nothing was imported."),
            "App::new installed the real reg import"
        );
        // The real one fails to start a file that does not exist.
        assert!(
            (actions.start_installed_update)(std::path::Path::new("definitely not an exe")).is_ok(),
            "App::new installed the real restart into an update"
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
        (actions.request_removal)();
        assert!(
            !self_remove::requested(),
            "App::new installed the real removal of WinMedic from this PC"
        );
        assert!(
            !actions.persist_scan_state,
            "App::new was allowed to write to %APPDATA%: ticking a checkbox in \
             a test would overwrite the developer's own last scan"
        );
        assert!(
            !actions.persist_config,
            "App::new was allowed to write config.json: changing a setting in \
             a test would overwrite the developer's own settings"
        );
    }

    /// And the front end that does opt in gets all of it, persistence
    /// included: a real run has to remember its findings across restarts.
    #[test]
    fn the_desktop_front_end_gets_the_real_machine() {
        let mut app = App::new();
        app.enable_real_system_actions();

        assert!(app.system_actions.restore_point.is_live());
        assert!(app.system_actions.self_update.is_live());
        assert!(app.system_actions.persist_scan_state);
        assert!(app.system_actions.persist_config);
        assert!(app.audit_logger.is_live());
        assert!(app.engine.records_audit_log());
    }

    /// The engine an [`App`] hands a repair run must inherit that inertness —
    /// `Checkpoint-Computer` is the one thing `run_repairs` does before any
    /// module gets a turn.
    #[test]
    fn a_default_app_repairs_without_creating_restore_points() {
        assert!(!App::new().engine.creates_real_restore_points());
    }

    /// Neither the app nor its engine records anything by default: the scans,
    /// repairs and rollbacks of `cargo test` used to end up in the
    /// developer's own `%APPDATA%\WinMedic\logs\audit.log`.
    #[test]
    fn a_default_app_writes_no_audit_log() {
        let app = App::new();

        assert!(!app.audit_logger.is_live());
        assert!(!app.engine.records_audit_log());
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
        assert_eq!(verifiable.confirm_label(), "Download and restart");
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
        assert!(body.starts_with("Restarting Windows finishes:"));
        assert!(body.ends_with("Restart Windows now?"));
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

    /// A restart Windows refused leaves the window open and says why.
    #[test]
    fn a_refused_restart_keeps_the_window_open() {
        let mut app = App::new();
        app.system_actions.restart_system =
            || Err("shutdown.exe exited with code 1190".to_string());
        app.pending_confirm = Some(ConfirmRequest::RestartRequired {
            issues: vec!["Page file disabled on every drive".to_string()],
        });

        app.confirm_pending_action();

        assert!(!app.should_quit);
        assert_eq!(
            app.status_message.as_deref(),
            Some("System restart failed: shutdown.exe exited with code 1190")
        );
    }

    /// One click and one answer: the dialog says what goes and where it
    /// is, and confirming it closes the window with the removal noted.
    #[test]
    fn confirming_the_removal_notes_it_and_closes_the_window() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NOTED: AtomicUsize = AtomicUsize::new(0);

        let mut app = App::new();
        app.system_actions.request_removal = || {
            NOTED.fetch_add(1, Ordering::SeqCst);
        };
        app.system_actions.persist_config = true;
        app.system_actions.persist_scan_state = true;
        app.restart_into = Some(std::path::PathBuf::from("winmedic-v9.9.9.exe"));

        app.request_remove();
        let request = app.pending_confirm.clone().expect("the button did not ask");
        assert_eq!(request.title(), "REMOVE WINMEDIC FROM THIS PC?");
        let body = request.body().join("\n");
        let backups = crate::safety::reg_backup::default_backup_dir();
        for named in [
            "the program: ",
            "the background scan task",
            &AppConfig::config_path()
                .parent()
                .unwrap()
                .display()
                .to_string(),
            &backups.parent().unwrap().display().to_string(),
            "can no longer be undone",
            "restore points stay",
        ] {
            assert!(
                body.contains(named),
                "the dialog does not name {named}: {body}"
            );
        }
        assert_eq!(NOTED.load(Ordering::SeqCst), 0, "removed before the answer");

        app.confirm_pending_action();

        assert_eq!(NOTED.load(Ordering::SeqCst), 1);
        assert!(app.should_quit, "the window stays open");
        // What the window writes on its way out would land in the folders
        // `main` is about to delete, and bring them back.
        assert!(!app.system_actions.persist_config);
        assert!(!app.system_actions.persist_scan_state);
        assert_eq!(app.restart_into, None, "it would restart into an update");
    }

    /// The default app's removal does nothing, like its other actions.
    #[test]
    fn a_default_app_removes_nothing() {
        let mut app = App::new();
        app.request_remove();
        app.confirm_pending_action();

        assert!(app.should_quit);
        assert!(
            !self_remove::requested(),
            "App::new installed the real removal: `main` would delete WinMedic's \
             folders, registry key and executable after this test run"
        );
    }

    /// Closing the window ends a repair halfway and throws a download away.
    #[test]
    fn the_removal_is_not_offered_while_winmedic_works() {
        let busy: [fn(&mut App); 4] = [
            |app| app.is_scanning = true,
            |app| app.is_fixing = true,
            |app| app.is_restoring = true,
            |app| app.is_updating = true,
        ];
        for make_busy in busy {
            let mut app = App::new();
            make_busy(&mut app);

            app.request_remove();

            assert!(app.pending_confirm.is_none());
            assert_eq!(
                app.status_message.as_deref(),
                Some("WinMedic is still working. Remove it once that has finished.")
            );
        }
    }

    #[test]
    fn cancelling_the_removal_changes_nothing() {
        let mut app = App::new();
        app.config.helper_enabled = true;
        app.request_remove();

        app.dismiss_confirm();

        assert!(app.config.helper_enabled);
        assert!(app.pending_confirm.is_none());
        assert!(!app.should_quit);
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
