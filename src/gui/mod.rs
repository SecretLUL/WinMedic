//! The desktop front end.
//!
//! This replaced a ratatui terminal interface, and the replacement was mostly a
//! matter of drawing: [`crate::app::App`] holds the state, [`crate::engine`]
//! reports over channels, and neither had to learn anything about windows. The
//! immediate-mode loop below does what the terminal draw loop did — drain the
//! channels, poll for background results once a second, render every frame
//! from state — because that is the shape the application already had.
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | [`theme`] | Typography, spacing, status and severity colours |
//! | [`keys`] | egui key events into the neutral [`crate::app::Key`] |
//! | [`modals`] | Confirmation, setting entry and help overlays |
//! | [`views`] | The two views, the findings list and Easy mode's short list |
//! | [`window`] | Locking the window's size in Easy mode, and handing it back |

pub mod keys;
pub mod modals;
pub mod theme;
pub mod views;
pub mod window;

use crate::app::{App, TAB_SETTINGS, handle_key};
use crate::utils::updater::UpdateInfo;
use eframe::egui::{self, RichText};
use std::time::{Duration, Instant};
use views::home::plural;

/// Navigation destinations, in the order of the `TAB_*` constants.
const TABS: [&str; 2] = ["Scan & Repair", "Settings"];

/// How often to redraw while a scan or repair run is in flight.
///
/// The terminal front end polled every 40ms and this matches it: fast enough
/// that a progress bar moves smoothly, slow enough to stay off the CPU.
const BUSY_REPAINT: Duration = Duration::from_millis(40);

/// How often to redraw when nothing is running.
///
/// Not never, because results still arrive with nobody touching the window:
/// the update check, the restore point list, a scan the background helper
/// finished. Each is drained on the next frame, and this is the longest the
/// window waits for one.
const IDLE_REPAINT: Duration = Duration::from_secs(1);

pub struct WinMedicApp {
    app: App,
    last_poll: Instant,
    initial_minimize: bool,
    window: window::WindowLock,
}

/// Draw the navigation, the current view, the status bar and overlays.
///
/// Separate from [`WinMedicApp::ui`], which owns the parts a test has no use
/// for — reading the keyboard and closing the window — so that a test can put
/// an [`App`] in a given state and assert on what the window then says.
pub fn show(ui: &mut egui::Ui, app: &mut App) {
    // Cloned because the overlays are windows, which are addressed on the
    // context rather than nested inside a `Ui`.
    let ctx = ui.ctx().clone();

    egui::Panel::top("navigation").show(ui, |ui| {
        ui.add_space(4.0);
        navigation(ui, app);
        ui.add_space(4.0);
    });

    // Easy mode's page is the restart prompt itself once nothing else is left.
    let page_asks = app.active_tab != TAB_SETTINGS && views::easy::asks_for_restart(app);
    if app.restart_pending() && !page_asks {
        banner_panel("restart_banner", theme::caution_fill(ui))
            .show(ui, |ui| restart_banner(ui, app));
    }
    if let Some(update) = app.available_update.clone() {
        banner_panel("update_banner", ui.visuals().selection.bg_fill)
            .show(ui, |ui| update_banner(ui, app, &update));
    }

    egui::Panel::bottom("status_bar").show(ui, |ui| status_bar(ui, app));

    egui::CentralPanel::default()
        .frame(egui::Frame::central_panel(ui.style()).inner_margin(12))
        .show(ui, |ui| match app.active_tab {
            TAB_SETTINGS => views::settings::show(ui, app),
            _ => views::home::show(ui, app),
        });

    // Overlays, in the order the terminal front end stacked them: a pending
    // confirmation outranks a setting being edited, which outranks help.
    modals::show(&ctx, app);
}

impl WinMedicApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::with_autostart(cc, false)
    }

    pub fn with_autostart(cc: &eframe::CreationContext<'_>, autostart: bool) -> Self {
        theme::apply(&cc.egui_ctx);

        let mut app = App::new();
        // `App::new` builds an app that cannot touch the desktop. This is the
        // one place that wants it to: accepting the update dialog should really
        // open a browser, accepting the elevation dialog should really raise
        // UAC, and a repair run should really leave a restore point behind.
        app.enable_real_system_actions();
        app.reconcile_background_integration();
        app.start_update_check();

        Self {
            app,
            last_poll: Instant::now(),
            initial_minimize: autostart,
            window: window::WindowLock::default(),
        }
    }
}

fn navigation(ui: &mut egui::Ui, app: &mut App) {
    ui.horizontal(|ui| {
        for (index, title) in TABS.iter().enumerate() {
            let selected = app.active_tab == index;
            if ui
                .selectable_label(selected, *title)
                .on_hover_text(format!("Shortcut: {}", index + 1))
                .clicked()
            {
                app.goto_tab(index);
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Help").on_hover_text("?").clicked() {
                app.show_help = true;
            }
            if ui
                .button("Export report")
                .on_hover_text("E - save the findings as an HTML report")
                .clicked()
            {
                app.status_message = Some(match app.export_report() {
                    Ok(path) => format!("Report exported: {}", path.display()),
                    Err(error) => error,
                });
            }
            // Named after where it goes, the way a BIOS labels the same key.
            let (label, hover) = if app.config.advanced_mode {
                ("Easy mode (F7)", "Show only what needs doing")
            } else {
                (
                    "Advanced mode (F7)",
                    "Show every finding with its details, the filters, the logs and simulation",
                )
            };
            if ui.button(label).on_hover_text(hover).clicked() {
                app.toggle_advanced_mode();
            }
        });
    });
}

/// An update WinMedic has not installed yet, across the top of both modes.
///
/// A repair tool that is behind repairs with yesterday's fixes, so this is
/// not left to the status line, which the next message overwrites. It stays
/// until the update is installed: "Remind me later" closes the dialog, not
/// this. It does not open the dialog by itself — a dialog that appears while
/// someone types takes the keystrokes meant for something else.
fn update_banner(ui: &mut egui::Ui, app: &mut App, update: &UpdateInfo) {
    let text = ui.visuals().selection.stroke.color;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Even medics need their booster shot.")
                .strong()
                .size(15.0)
                .color(text),
        );
        ui.label(
            RichText::new(format!(
                "WinMedic {} is ready, you have {}.",
                version(&update.latest_version),
                version(&update.current_version)
            ))
            .color(text),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if app.is_updating {
                ui.label(RichText::new("Updating...").color(text));
                ui.spinner();
            } else if ui
                .add(egui::Button::new(RichText::new("Update now").strong()))
                .on_hover_text("U")
                .clicked()
            {
                app.show_update_notice();
            }
        });
    });
}

/// Windows waits for a restart, across the top of both modes until it has had
/// one. WinMedic notices the restart the next time it starts, and only then
/// takes this down.
fn restart_banner(ui: &mut egui::Ui, app: &mut App) {
    let text = ui.visuals().strong_text_color();
    let repairs = app.issues.iter().filter(|i| i.is_reboot_pending).count();
    let detail = if repairs > 0 {
        format!("Restart Windows to finish {}.", plural(repairs, "repair"))
    } else {
        "Windows is waiting for a restart to finish its updates.".to_string()
    };
    ui.horizontal(|ui| {
        ui.label(RichText::new(detail).strong().size(15.0).color(text));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let restart = egui::Button::new(RichText::new("Restart now").strong());
            if ui.add_enabled(!app.is_busy(), restart).clicked() {
                app.show_reboot_notice();
            }
        });
    });
}

/// A banner across the top of the window, below the navigation.
fn banner_panel(id: &'static str, fill: egui::Color32) -> egui::Panel {
    egui::Panel::top(id).frame(
        egui::Frame::NONE
            .fill(fill)
            .inner_margin(egui::Margin::symmetric(12, 8)),
    )
}

/// `v0.5.3`, however the release was tagged.
fn version(tag: &str) -> String {
    format!("v{}", tag.trim_start_matches(['v', 'V']))
}

fn status_bar(ui: &mut egui::Ui, app: &mut App) {
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(theme::muted(format!(
                "WinMedic {}",
                env!("CARGO_PKG_VERSION")
            )));
            ui.separator();
            let message = app.status_message.as_deref().unwrap_or("Ready");
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                if app.is_busy() {
                    ui.spinner();
                }
                ui.add(egui::Label::new(message).truncate())
                    .on_hover_text(message);
            });
        });
    });
}

impl eframe::App for WinMedicApp {
    /// Everything that is not drawing.
    ///
    /// eframe calls this before every `ui` pass, and — unlike `ui` — it keeps
    /// calling it while the window is hidden. That is exactly what this work
    /// needs: a scan started before the window was minimised must still drain
    /// its channels, or it would appear to have frozen the moment it was out of
    /// sight and finish all at once on the way back.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.app.process_background_events();

        if self.last_poll.elapsed() >= Duration::from_secs(1) {
            self.app.poll_external_scan_updates();
            self.last_poll = Instant::now();
        }

        // egui only repaints in response to input, and almost nothing this
        // window shows is driven by input: progress bars and log lines come
        // from work happening elsewhere.
        ctx.request_repaint_after(if self.app.is_busy() {
            BUSY_REPAINT
        } else {
            IDLE_REPAINT
        });
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.initial_minimize {
            self.initial_minimize = false;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }

        for key in keys::shortcuts(ui.ctx()) {
            handle_key(&mut self.app, key);
        }

        let current = window::Geometry::of(ui.ctx());
        for command in self.window.commands(self.app.config.advanced_mode, current) {
            ui.ctx().send_viewport_cmd(command);
        }

        show(ui, &mut self.app);

        if self.app.should_quit {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{ConfirmRequest, TAB_COUNT, TAB_HOME};
    use crate::engine::issue::{Issue, RiskScore, Severity};
    use crate::modules::ModuleStatus;
    use crate::safety::audit::AuditEntry;
    use crate::safety::reg_backup::BackupRecord;
    use eframe::egui::accesskit::Role;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    /// Drive one frame of the whole window and hand back the result to query.
    ///
    /// The terminal front end's equivalent read the character buffer back out
    /// of a `TestBackend`. A window has no character buffer, so these assert
    /// against the accessibility tree instead — which is the more honest
    /// target anyway: it is what a screen reader is given, so a label missing
    /// from it is missing for a user, not merely for a test.
    fn window(app: App) -> Harness<'static, App> {
        sized_window(app, (1400.0, 900.0))
    }

    fn sized_window(app: App, size: (f32, f32)) -> Harness<'static, App> {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(size.0, size.1))
            .build_ui_state(|ui, app: &mut App| show(ui, app), app);
        theme::apply(&harness.ctx);
        // A fixed number of frames rather than `run`, which waits for the
        // window to stop asking for repaints — and a busy window, with its
        // spinner, never does.
        harness.run_steps(3);
        harness
    }

    /// A machine that has never been scanned, with a little history in the
    /// safety views, in Advanced mode.
    fn fresh_app() -> App {
        let mut app = App::new();
        // `App::new` raises the elevation prompt when WinMedic is not running
        // as Administrator, and that modal covers the view it is asked about.
        app.pending_confirm = None;
        // It also reads the mode from the developer's own config. Most of what
        // these tests look for is only drawn in Advanced mode; the Easy mode
        // tests below switch it off.
        app.config.advanced_mode = true;
        // And whether this process is elevated, which differs between a
        // developer's terminal and the CI runner, and with it whether the
        // page carries the administrator notice. Fixed, so a test draws the
        // same page on both.
        app.is_admin = true;
        // It also restores the last scan from `%APPDATA%`, which on a machine
        // that has actually run WinMedic is a real one — and these tests
        // describe the state they want to draw. Start from nothing scanned.
        app.issues.clear();
        app.health_score = 100;
        app.scan_duration = None;
        app.last_scan_timestamp = None;
        for status in &mut app.module_statuses {
            status.3 = ModuleStatus::Idle;
        }
        app.selected_filtered_index = 0;
        app.backup_records = vec![BackupRecord {
            id: "b1".to_string(),
            timestamp: "2026-01-01 12:00:00".to_string(),
            description: "Startup entry removed".to_string(),
            key_path: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            file_path: r"C:\backups\b1.reg".to_string(),
        }];
        app.vss_restore_points = vec!["2026-01-01 11:59 - WinMedic pre-repair".to_string()];
        app.audit_entries = vec![AuditEntry {
            timestamp: "2026-01-01 12:00:00".to_string(),
            action_type: "FIX".to_string(),
            module_id: "registry_startup".to_string(),
            title: "Disabled a startup entry".to_string(),
            status: "SUCCESS".to_string(),
            details: String::new(),
        }];
        app
    }

    fn issue(id: &str, title: &str, severity: Severity) -> Issue {
        Issue::new(
            id,
            "network",
            title,
            "Network",
            severity,
            RiskScore::Low,
            "description",
            "details",
            "fix",
            vec![],
        )
    }

    /// A finished scan and a finished repair run: findings to review, a module
    /// that gave up, and a log for each.
    fn scanned_app() -> App {
        let mut app = fresh_app();
        app.issues = vec![
            issue("a", "DNS cache full", Severity::Critical),
            issue("b", "Temp bloat files", Severity::Warning),
        ];
        app.health_score = 60;
        app.last_scan_timestamp = Some("2026-09-22 14:30:00".to_string());
        app.scan_duration = Some(Duration::from_secs(74));
        app.push_scan_log("Module 'network' finished.");
        // Shaped the way `app::events` shapes it when the engine reports: a
        // module that failed carries both the reason and the step line that
        // states it, and its dashboard status says the same.
        if let Some(module) = app.module_progress_list.get_mut(1) {
            module.percent = 100;
            module.is_done = true;
            module.failure = Some("DISM returned 0x800f081f".to_string());
            module.step = "Failed - DISM returned 0x800f081f".to_string();
        }
        if let Some(status) = app.module_statuses.get_mut(1) {
            status.3 = ModuleStatus::Failed("DISM returned 0x800f081f".to_string());
        }

        app.total_to_fix = 3;
        app.fixed_count = 2;
        app.failed_count = 1;
        app.push_repair_log("[OK] DNS cache flushed.");
        app.push_repair_log("[X] Failed: access denied.");
        app
    }

    fn easy(mut app: App) -> App {
        app.config.advanced_mode = false;
        app
    }

    fn easy_fresh_app() -> App {
        easy(fresh_app())
    }

    fn easy_scanned_app() -> App {
        easy(scanned_app())
    }

    /// Both states the main view is built around — nothing scanned, and a run
    /// with findings, a failure and a repair behind it — in both modes.
    const FIXTURES: [fn() -> App; 4] = [fresh_app, scanned_app, easy_fresh_app, easy_scanned_app];

    /// A window that also reads the keyboard, the way [`WinMedicApp::ui`] does.
    fn window_with_keys(app: App) -> Harness<'static, App> {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(1400.0, 900.0))
            .build_ui_state(
                |ui, app: &mut App| {
                    for key in keys::shortcuts(ui.ctx()) {
                        handle_key(app, key);
                    }
                    show(ui, app);
                },
                app,
            );
        theme::apply(&harness.ctx);
        harness.run_steps(3);
        harness
    }

    /// Layout only fails at draw time, so a view no window size can satisfy
    /// fails here rather than in front of a user. The smallest size is the
    /// one Easy mode locks the window at, so every view has to fit it.
    #[test]
    fn every_view_draws_at_small_and_large_window_sizes() {
        let smallest = (window::MIN_SIZE.x, window::MIN_SIZE.y);
        for tab in 0..TAB_COUNT {
            for fixture in FIXTURES {
                for size in [smallest, (1400.0, 900.0), (1920.0, 1200.0)] {
                    let mut app = fixture();
                    app.active_tab = tab;
                    let harness = sized_window(app, size);

                    let help = harness.get_by_label("Help").rect();
                    assert!(
                        help.bottom() < 60.0 && help.right() <= size.0,
                        "view {tab}: the navigation lost its Help button at {size:?}: {help:?}"
                    );
                    for title in TABS {
                        assert!(
                            harness.query_by_label(title).is_some(),
                            "view {tab} at {size:?} did not draw its navigation entry {title}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_navigation_offers_exactly_two_views() {
        // The navigation and the `TAB_*` constants index each other, so they
        // have to agree; a label added to one without the other silently
        // misroutes every click past it.
        assert_eq!(TABS.len(), TAB_COUNT);

        let harness = window(scanned_app());
        for title in TABS {
            assert!(harness.query_by_label(title).is_some(), "missing: {title}");
        }

        // The four tabs merged into one page must not come back as labels the
        // user can look for, and neither may the settings view's old name.
        for retired in [
            "Dashboard",
            "Health Scan",
            "Issue Triage",
            "Repair Center",
            "Backups & Logs",
            "Settings & Safety",
        ] {
            assert!(
                harness.query_by_label(retired).is_none(),
                "retired tab is back: {retired}"
            );
        }
    }

    #[test]
    fn navigation_buttons_open_their_destination() {
        let mut harness = window(scanned_app());
        for (index, title) in TABS.iter().enumerate().rev() {
            harness.get_by_label(title).click();
            harness.run();
            assert_eq!(harness.state().active_tab, index);
        }
    }

    /// The first thing a new user sees has to tell them what to do.
    #[test]
    fn a_machine_never_scanned_is_asked_to_scan_and_nothing_else() {
        let harness = window(fresh_app());

        assert!(
            harness
                .query_by_label_contains("has not been checked yet")
                .is_some()
        );
        assert!(harness.query_by_label("Scan now").is_some());
        assert_eq!(
            harness
                .query_all_by(|node| {
                    node.role() == Role::Button
                        && node
                            .label()
                            .is_some_and(|label| label.starts_with("Repair"))
                })
                .count(),
            0,
            "there is nothing to repair yet, so no button may offer to"
        );
        assert!(
            harness
                .query_by_label_contains("What the scan checks")
                .is_some(),
            "and the page says what a scan covers"
        );
    }

    /// Once there are findings, the header counts them and the button repairs
    /// exactly what is ticked.
    #[test]
    fn findings_are_counted_and_the_repair_button_follows_the_ticks() {
        let mut harness = window(scanned_app());

        assert!(harness.query_by_label("2 open findings").is_some());
        assert!(harness.query_by_label("Repair 2 findings").is_some());

        harness.get_by_label("Select none").click();
        harness.run();
        assert!(
            harness.query_by_label("Repair").is_some(),
            "nothing ticked: the button stays, without a count"
        );
    }

    #[test]
    fn the_header_displays_exact_last_scan_timestamp() {
        let mut app = scanned_app();
        app.scan_duration = Some(Duration::from_secs(15));

        let harness = window(app);
        assert!(
            harness
                .query_by_label_contains("Last scan: 2026-09-22 14:30:00 (took 15s)")
                .is_some()
        );
    }

    /// A finished run has to be legible after the fact: which module gave up
    /// and why, and what the repair pass managed. The failure line matters
    /// most — a module that quit mid-scan is the single thing a user most
    /// needs to see.
    #[test]
    fn a_finished_run_reports_its_failures_and_repairs() {
        let harness = window(scanned_app());

        assert!(
            harness
                .query_by_label_contains("could not be checked: DISM returned 0x800f081f")
                .is_some(),
            "a module that failed must say so"
        );
        assert!(harness.query_by_label("2 repaired").is_some());
        assert!(harness.query_by_label("1 failed").is_some());
    }

    /// While a scan runs, the page shows every check and how far it got.
    #[test]
    fn a_running_scan_shows_each_check() {
        let mut app = scanned_app();
        app.is_scanning = true;
        app.scan_overall_progress = 40;
        let harness = window(app);

        assert!(harness.query_by_label("Scanning this PC...").is_some());
        assert!(harness.query_by_label("Cancel scan").is_some());
        assert!(
            harness
                .query_by_label_contains("running for 1m 14s")
                .is_some(),
            "the elapsed time is missing"
        );
        assert!(
            harness
                .query_by_label("Failed - DISM returned 0x800f081f")
                .is_some(),
            "a module that failed mid-scan must say so"
        );
    }

    /// A repair step that runs for minutes says how far its tool got and how
    /// long it has been at it, so it does not look hung.
    #[test]
    fn a_running_repair_says_how_far_its_step_got() {
        let mut app = scanned_app();
        app.is_fixing = true;
        app.total_to_fix = 8;
        app.fixed_count = 1;
        app.failed_count = 0;
        app.current_fix_title = "Windows component store is corrupted".to_string();
        app.repair_step_percent = Some(62.3);
        app.repair_step_since = Instant::now().checked_sub(Duration::from_secs(252));
        let harness = window(app);

        assert!(
            harness
                .query_by_label_contains(
                    "1 of 8 done · now: Windows component store is corrupted · 62% · running for 4m 1"
                )
                .is_some()
        );
    }

    /// The logs are folded away, and one click away.
    #[test]
    fn both_logs_are_one_click_away() {
        let mut harness = window(scanned_app());
        assert!(
            harness
                .query_by_label_contains("[X] Failed: access denied.")
                .is_none(),
            "the log starts folded"
        );

        harness.get_by_label("Show log").click();
        harness.run();
        assert!(
            harness
                .query_by_label_contains("[X] Failed: access denied.")
                .is_some(),
            "after a repair run, the repair output is what opens"
        );

        harness.get_by_label("Scan log").click();
        harness.run();
        assert!(
            harness
                .query_by_label_contains("Module 'network' finished.")
                .is_some()
        );
    }

    #[test]
    fn confirmation_blocks_clicks_on_the_navigation() {
        let mut app = fresh_app();
        app.pending_confirm = Some(ConfirmRequest::Elevate);
        let mut harness = window(app);
        harness.get_by_label("Settings").click();
        harness.run();
        assert_eq!(harness.state().active_tab, TAB_HOME);
        assert!(harness.state().pending_confirm.is_some());
        harness
            .get_by_label("Continue without Administrator")
            .click();
        harness.run();
        assert!(harness.state().pending_confirm.is_none());
    }

    /// The whole point of that merge: none of the safety surface may go missing.
    #[test]
    fn the_settings_view_carries_the_whole_safety_surface() {
        let mut app = fresh_app();
        app.active_tab = TAB_SETTINGS;
        let harness = window(app);

        for expected in [
            "Options",
            "Registry backups",
            "System restore points",
            "Recent activity",
            "Log folder",
            "Startup entry removed",
            "Restore the selected snapshot",
            "Disabled a startup entry",
        ] {
            assert!(
                harness.query_by_label_contains(expected).is_some(),
                "the safety surface lost: {expected}"
            );
        }
    }

    /// A confirmation is a question about the machine, and it has to be visible
    /// whichever view the user happened to be on when it was raised.
    #[test]
    fn a_pending_confirmation_is_drawn_over_every_view() {
        for tab in 0..TAB_COUNT {
            let mut app = fresh_app();
            app.active_tab = tab;
            app.pending_confirm = Some(ConfirmRequest::Elevate);

            let harness = window(app);
            assert!(
                harness
                    .query_by_label_contains("ADMINISTRATOR PRIVILEGES REQUIRED")
                    .is_some(),
                "the elevation dialog is missing on view {tab}"
            );
            assert!(
                harness
                    .query_by_label_contains("Continue without Administrator")
                    .is_some(),
                "and offers no way out on view {tab}"
            );
        }
    }

    /// Every character the window draws must exist in the fonts egui bundles.
    ///
    /// This guard has a specific history. The settings pane announced which
    /// list owned the arrow keys with the glyphs the terminal front end used,
    /// and all three reached the screen as empty boxes: a terminal inherits the
    /// system's font coverage, while a window ships its own, and egui's is a
    /// Latin text face with no arrows or geometric shapes in it. Nothing failed
    /// — it just looked broken.
    #[test]
    fn every_character_the_window_draws_has_a_glyph() {
        for tab in 0..TAB_COUNT {
            for fixture in FIXTURES {
                let mut app = fixture();
                app.active_tab = tab;
                let advanced = app.config.advanced_mode;
                let mut harness = window(app);
                if tab == TAB_HOME && advanced {
                    harness.get_by_label("Show log").click();
                    harness.run();
                }

                // Both properties, because AccessKit splits them: an
                // interactive widget carries its text in `label`, while a
                // plain piece of text — which is most of what this window is —
                // is a node of role `Label` carrying its text in `value`.
                // Reading only the former collects the buttons and none of the
                // prose.
                let drawn = std::cell::RefCell::new(Vec::new());
                harness
                    .query_all_by(|node| {
                        let mut drawn = drawn.borrow_mut();
                        drawn.extend(node.label());
                        drawn.extend(node.value());
                        false
                    })
                    .count();
                let drawn = drawn.into_inner();
                // Easy mode before the first scan is the sparsest page the
                // window draws, at 14 strings. Reading only the labels, the
                // mistake this guards against, collects about six.
                assert!(
                    drawn.len() >= 10,
                    "view {tab} produced only {} strings, so this asserts on nothing",
                    drawn.len()
                );

                let font = egui::FontId::proportional(14.0);
                harness.ctx.fonts_mut(|fonts| {
                    for label in &drawn {
                        for character in label.chars() {
                            assert!(
                                fonts.has_glyph(&font, character),
                                "view {tab}: no glyph for U+{:04X} ({character:?}) in {label:?}",
                                character as u32
                            );
                        }
                    }
                });
            }
        }
    }

    const GB: u64 = 1024 * 1024 * 1024;

    /// A scan whose findings Easy mode can say something about: a cleanup
    /// that measured its size, and a repair that fixes something you notice.
    fn easy_forecast_app() -> App {
        let mut app = easy_scanned_app();
        app.issues[0].id = "net_dns_failure".to_string();
        app.issues[1].id = "storage_temp_bloat".to_string();
        app.issues[1].reclaimable_bytes = Some(7 * GB);
        app
    }

    /// Easy mode is the page for someone who has never repaired Windows: how
    /// the PC is doing, what Repair will do, two big buttons. Everything a
    /// technician reaches for stays in Advanced mode.
    #[test]
    fn easy_mode_says_how_the_pc_is_and_what_repair_will_do() {
        let harness = window(easy_forecast_app());

        for expected in [
            "2 problems found",
            "Health 60 / 100",
            "What Repair does",
            "Frees about 7.0 GB of disk space",
            "The internet connection is repaired",
            "Health goes up to about 100 / 100",
            "Repair 2 problems",
            "Scan again",
            "A restore point is created first, so everything can be undone.",
        ] {
            assert!(
                harness.query_by_label(expected).is_some(),
                "Easy mode does not say {expected:?}"
            );
        }

        // No list of findings, and nothing a technician reaches for.
        for advanced_only in [
            "DNS cache full",
            "Temp bloat files",
            "Select none",
            "All modules",
            "Show log",
            "Simulate only (change nothing)",
            "Technical details",
        ] {
            assert!(
                harness.query_by_label(advanced_only).is_none(),
                "Easy mode draws {advanced_only:?}"
            );
        }
        assert!(harness.query_by_role(Role::TextInput).is_none());
        assert_eq!(harness.query_all_by_role(Role::CheckBox).count(), 0);

        // A module that gave up is named, but its error text is not.
        assert!(harness.query_by_label_contains("Could not check").is_some());
        assert!(harness.query_by_label_contains("0x800f081f").is_none());
    }

    /// The next step should be impossible to miss.
    #[test]
    fn the_easy_buttons_are_big() {
        let easy = window(easy_forecast_app());
        let advanced = window(scanned_app());
        let normal = advanced.get_by_label("Scan again").rect().height();

        for label in ["Repair 2 problems", "Scan again"] {
            let height = easy.get_by_label(label).rect().height();
            assert!(
                height >= 44.0 && height > normal + 10.0,
                "{label} is {height} px tall, Advanced mode's buttons {normal} px"
            );
        }
    }

    /// Repair runs what the checks recommend; the rest is one line and one
    /// link away.
    #[test]
    fn easy_mode_counts_what_it_leaves_alone_and_links_to_it() {
        let mut app = easy_forecast_app();
        app.issues[1].is_selected = false;
        let mut harness = window(app);

        assert!(harness.query_by_label("Repair 1 problem").is_some());
        assert!(
            harness
                .query_by_label("Frees about 7.0 GB of disk space")
                .is_none(),
            "an unticked cleanup frees nothing"
        );
        assert!(
            harness
                .query_by_label("1 more needs your decision.")
                .is_some()
        );

        harness.get_by_label("Show in Advanced mode (F7)").click();
        harness.run();
        assert!(harness.state().config.advanced_mode);
    }

    #[test]
    fn easy_mode_with_nothing_repaired_automatically_offers_only_the_scan() {
        let mut app = easy_forecast_app();
        for issue in &mut app.issues {
            issue.is_selected = false;
        }
        let harness = window(app);

        assert!(
            harness
                .query_by_label("None of them is repaired automatically.")
                .is_some()
        );
        assert!(harness.query_by_label("What Repair does").is_none());
        assert!(harness.query_by_label("Scan again").is_some());
        assert!(
            harness
                .query_by_label("2 more need your decision.")
                .is_some()
        );
    }

    #[test]
    fn easy_mode_on_a_machine_never_scanned_offers_the_scan_and_nothing_else() {
        let harness = window(easy_fresh_app());

        assert!(
            harness
                .query_by_label("This PC has not been checked yet")
                .is_some()
        );
        assert!(harness.query_by_label("Scan now").is_some());
        assert!(
            harness
                .query_by_label_contains("What the scan checks")
                .is_none(),
            "the table of modules is Advanced mode's"
        );
        assert!(harness.query_by_label("Show log").is_none());
    }

    #[test]
    fn easy_mode_on_a_healthy_pc_says_so() {
        let mut app = easy_scanned_app();
        app.issues.clear();
        app.health_score = 100;
        for status in &mut app.module_statuses {
            status.3 = ModuleStatus::Passed;
        }
        let harness = window(app);

        assert!(harness.query_by_label("Your PC is in good shape").is_some());
        assert!(harness.query_by_label("Health 100 / 100").is_some());
        assert!(harness.query_by_label("Scan again").is_some());
    }

    /// While a scan runs, Easy mode shows how far it got, not each module.
    #[test]
    fn a_running_scan_in_easy_mode_shows_progress_but_no_module_table() {
        let mut app = easy_scanned_app();
        app.is_scanning = true;
        app.scan_overall_progress = 40;
        let harness = window(app);

        assert!(harness.query_by_label("Checking your PC...").is_some());
        assert!(harness.query_by_label("Cancel").is_some());
        assert!(
            harness
                .query_by_label("This takes a minute or two. Nothing is changed.")
                .is_some()
        );
        assert!(
            harness
                .query_by_label("Failed - DISM returned 0x800f081f")
                .is_none()
        );
    }

    /// Easy mode repairing, with the running step started `minutes` ago and
    /// its tool at `percent`.
    fn easy_repairing(minutes: u64, percent: Option<f32>) -> Harness<'static, App> {
        let mut app = easy_scanned_app();
        app.is_fixing = true;
        app.total_to_fix = 8;
        app.fixed_count = 1;
        app.failed_count = 0;
        app.repair_step_since = Instant::now().checked_sub(Duration::from_secs(minutes * 60));
        app.repair_step_percent = percent;
        window(app)
    }

    const PATIENCE: &str = "Don't worry, everything is fine. WinMedic needs some time to heal.";

    /// A step that takes minutes gets a word that this is normal, and how long
    /// it will take at the pace its tool reports.
    #[test]
    fn a_long_repair_in_easy_mode_says_all_is_well_and_how_long_it_takes() {
        let harness = easy_repairing(3, Some(30.0));
        assert!(harness.query_by_label(PATIENCE).is_some());
        assert!(
            harness
                .query_by_label("About 7 minutes left for this step.")
                .is_some()
        );
    }

    #[test]
    fn a_long_repair_without_progress_says_how_long_it_has_run() {
        let harness = easy_repairing(3, None);
        assert!(harness.query_by_label(PATIENCE).is_some());
        assert!(harness.query_by_label("Running for 3 minutes.").is_some());
    }

    #[test]
    fn a_short_repair_needs_no_reassurance() {
        let harness = easy_repairing(1, Some(30.0));
        assert!(harness.query_by_label("Repairing...").is_some());
        assert!(harness.query_by_label(PATIENCE).is_none());
    }

    /// Once only restarts are left, that is the one thing the page asks for,
    /// once, and it offers to do it.
    #[test]
    fn easy_mode_asks_for_the_restart_once_and_offers_it() {
        let mut app = easy_scanned_app();
        for issue in &mut app.issues {
            issue.is_reboot_pending = true;
        }
        let mut harness = window(app);

        assert!(harness.query_by_label("Almost done").is_some());
        assert_eq!(
            harness
                .query_all_by_label_contains("Restart Windows to finish")
                .count(),
            1
        );

        harness.get_by_label("Restart now").click();
        harness.run();
        assert!(matches!(
            harness.state().pending_confirm,
            Some(ConfirmRequest::RestartRequired { .. })
        ));
    }

    fn with_update(mut app: App) -> App {
        app.available_update = Some(UpdateInfo {
            current_version: "0.5.2".to_string(),
            latest_version: "v0.5.3".to_string(),
            release_url: "https://github.com/SecretLUL/WinMedic/releases/tag/v0.5.3".to_string(),
            release_name: None,
            release_body: None,
            download: None,
        });
        app
    }

    const BOOSTER: &str = "Even medics need their booster shot.";

    /// An update is announced across the top of either mode, not only in the
    /// status line, and the banner leads to the update dialog.
    #[test]
    fn an_available_update_gets_a_banner_that_opens_the_dialog() {
        for app in [with_update(scanned_app()), with_update(easy_scanned_app())] {
            let mut harness = window(app);
            assert!(harness.query_by_label(BOOSTER).is_some());
            assert!(
                harness
                    .query_by_label("WinMedic v0.5.3 is ready, you have v0.5.2.")
                    .is_some()
            );

            harness.get_by_label("Update now").click();
            harness.run_steps(2);
            assert!(matches!(
                harness.state().pending_confirm,
                Some(ConfirmRequest::UpdateAvailable { .. })
            ));
        }
    }

    /// "Remind me later" closes the dialog; the banner stays until the update
    /// is installed.
    #[test]
    fn the_banner_stays_after_remind_me_later() {
        let mut app = with_update(scanned_app());
        app.show_update_notice();
        app.dismiss_confirm();
        let harness = window(app);
        assert!(harness.query_by_label(BOOSTER).is_some());
        assert!(harness.query_by_label("Update now").is_some());
    }

    /// A repair waiting for a restart: the banner says so in either mode and
    /// its button asks to restart.
    #[test]
    fn a_pending_restart_gets_a_banner_that_asks_to_restart() {
        for mut app in [scanned_app(), easy_scanned_app()] {
            app.issues[0].is_reboot_pending = true;
            let mut harness = window(app);
            assert!(
                harness
                    .query_by_label("Restart Windows to finish 1 repair.")
                    .is_some()
            );

            harness.get_by_label("Restart now").click();
            harness.run_steps(2);
            assert!(matches!(
                harness.state().pending_confirm,
                Some(ConfirmRequest::RestartRequired { .. })
            ));
        }
    }

    /// Restart work Windows queued itself, found by the scan, gets the banner
    /// too, and the restart dialog names it.
    #[test]
    fn windows_waiting_for_a_restart_gets_the_banner_too() {
        let mut app = scanned_app();
        app.issues.push(issue(
            crate::modules::windows_updates::REBOOT_PENDING,
            "System reboot pending after updates",
            Severity::Info,
        ));
        let mut harness = window(app);
        assert!(
            harness
                .query_by_label("Windows is waiting for a restart to finish its updates.")
                .is_some()
        );

        harness.get_by_label("Restart now").click();
        harness.run_steps(2);
        match &harness.state().pending_confirm {
            Some(ConfirmRequest::RestartRequired { issues }) => {
                assert_eq!(issues, &["System reboot pending after updates"]);
            }
            other => panic!("expected the restart dialog, got {other:?}"),
        }
    }

    /// Once a restart is all that is left, Easy mode's page is the prompt,
    /// and the banner would only say it twice. On the Settings tab the page
    /// shows something else, so the banner is back.
    #[test]
    fn easy_mode_asks_for_the_restart_on_the_page_or_in_the_banner() {
        let mut app = easy_scanned_app();
        for issue in &mut app.issues {
            issue.is_reboot_pending = true;
        }
        const BANNER: &str = "Restart Windows to finish 2 repairs.";
        let harness = window(app);
        assert!(harness.query_by_label("Almost done").is_some());
        assert!(harness.query_by_label(BANNER).is_none());

        let mut app = harness.into_state();
        app.active_tab = TAB_SETTINGS;
        assert!(window(app).query_by_label(BANNER).is_some());
    }

    #[test]
    fn no_update_no_banner() {
        let harness = window(scanned_app());
        assert!(harness.query_by_label(BOOSTER).is_none());
    }

    /// Easy mode locks the window at its smallest size; the banner has to fit.
    #[test]
    fn the_banner_fits_the_smallest_window() {
        let size = (window::MIN_SIZE.x, window::MIN_SIZE.y);
        let harness = sized_window(with_update(easy_scanned_app()), size);
        let button = harness.get_by_label("Update now").rect();
        assert!(button.right() <= size.0, "{button:?}");
        assert!(harness.query_by_label("Help").is_some());
    }

    /// Where the user asked for it: top right, left of "Export report". It is
    /// named after where it goes, the way a BIOS labels the same key.
    #[test]
    fn the_mode_button_sits_left_of_export_report_and_switches_modes() {
        let mut harness = window(easy_fresh_app());

        let export = harness.get_by_label("Export report").rect();
        let mode = harness.get_by_label("Advanced mode (F7)").rect();
        assert!(
            mode.right() <= export.left() && (mode.center().y - export.center().y).abs() < 2.0,
            "the button is not beside Export report: {mode:?} vs {export:?}"
        );

        harness.get_by_label("Advanced mode (F7)").click();
        harness.run();
        assert!(harness.state().config.advanced_mode);
        assert!(harness.query_by_label("Show log").is_some());

        harness.get_by_label("Easy mode (F7)").click();
        harness.run();
        assert!(!harness.state().config.advanced_mode);
    }

    /// F7 types nothing, so it works from inside the search box too — and
    /// every other key still goes to the box while it has the caret.
    #[test]
    fn f7_switches_modes_even_while_typing_in_the_search_box() {
        let mut harness = window_with_keys(scanned_app());

        harness.get_by_role(Role::TextInput).click();
        harness.run();
        harness.event(egui::Event::Text("n".to_string()));
        harness.run();
        assert_eq!(harness.state().search_query, "n", "the letter was typed");
        assert!(
            harness.state().issues.iter().all(|i| i.is_selected),
            "and did not untick everything"
        );

        harness.key_press(egui::Key::F7);
        harness.run();
        assert!(!harness.state().config.advanced_mode);
        assert!(harness.query_by_role(Role::TextInput).is_none());

        // The box is gone, and with it the caret: shortcuts answer again.
        harness.event(egui::Event::Text("?".to_string()));
        harness.run();
        assert!(harness.state().show_help);
    }

    /// Help lists the keys the current mode binds, and no others.
    #[test]
    fn help_lists_only_the_keys_the_current_mode_binds() {
        let mut app = easy_fresh_app();
        app.show_help = true;
        let harness = window(app);
        assert!(harness.query_by_label("F7").is_some());
        assert!(harness.query_by_label("Tick all or none").is_none());

        let mut app = fresh_app();
        app.show_help = true;
        let harness = window(app);
        assert!(harness.query_by_label("F7").is_some());
        assert!(harness.query_by_label("Tick all or none").is_some());
    }

    /// An empty list has to say why it is empty once the user has filtered
    /// everything away.
    #[test]
    fn filtering_everything_away_says_so() {
        let mut app = scanned_app();
        app.search_query = "nothing matches this".to_string();

        let harness = window(app);
        assert!(
            harness
                .query_by_label_contains("Nothing matches the current filters.")
                .is_some()
        );
    }
}
