//! The desktop front end.
//!
//! This replaced a ratatui terminal interface, and the replacement was mostly a
//! matter of drawing: [`crate::app::App`] holds the state, [`crate::engine`]
//! reports over channels, and neither had to learn anything about windows. The
//! immediate-mode loop below does what the terminal draw loop did — drain the
//! channels, refresh telemetry once a second, render every frame from state —
//! because that is the shape the application already had.
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | [`theme`] | Palette, shared surfaces, severity colours |
//! | [`keys`] | egui key events into the neutral [`crate::app::Key`] |
//! | [`modals`] | Confirmation, setting entry and help overlays |
//! | [`views`] | One module per tab |

pub mod keys;
pub mod modals;
pub mod theme;
pub mod views;

use crate::app::{
    App, TAB_DASHBOARD, TAB_REPAIR, TAB_SCANNER, TAB_SETTINGS, TAB_TRIAGE, handle_key,
};
use eframe::egui::{self, RichText};
use std::time::{Duration, Instant};

/// The tab strip, in order. The indices are the `TAB_*` constants.
const TABS: [&str; 5] = [
    "Dashboard",
    "Health Scan",
    "Issue Triage",
    "Repair Center",
    "Settings & Safety",
];

/// How often to redraw while a scan or repair run is in flight.
///
/// The terminal front end polled every 40ms and this matches it: fast enough
/// that a progress bar moves smoothly, slow enough to stay off the CPU.
const BUSY_REPAINT: Duration = Duration::from_millis(40);

/// How often to redraw when nothing is running.
///
/// Not zero, because the header carries live CPU and memory figures that would
/// otherwise freeze until the user moved the mouse.
const IDLE_REPAINT: Duration = Duration::from_millis(500);

pub struct WinMedicApp {
    app: App,
    last_telemetry_tick: Instant,
}

/// Draw the whole frame: header, tab strip, body, status bar and overlays.
///
/// Separate from [`WinMedicApp::ui`], which owns the parts a test has no use
/// for — reading the keyboard and closing the window — so that a test can put
/// an [`App`] in a given state and assert on what the window then says.
pub fn show(ui: &mut egui::Ui, app: &mut App) {
    // Cloned because the overlays are windows, which are addressed on the
    // context rather than nested inside a `Ui`.
    let ctx = ui.ctx().clone();

    egui::Panel::top("header").show(ui, |ui| {
        header(ui, app);
        tab_bar(ui, app);
    });

    egui::Panel::bottom("footer").show(ui, |ui| {
        footer(ui, app);
    });

    egui::CentralPanel::default().show(ui, |ui| {
        body(ui, app);
    });

    // Overlays, in the order the terminal front end stacked them: a pending
    // confirmation outranks a setting being edited, which outranks help.
    modals::show(&ctx, app);
}

impl WinMedicApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);

        let mut app = App::new();
        // `App::new` builds an app that cannot touch the desktop. This is the
        // one place that wants it to: accepting the update dialog should really
        // open a browser, accepting the elevation dialog should really raise
        // UAC, and a repair run should really leave a restore point behind.
        app.enable_real_system_actions();
        app.start_update_check();

        Self {
            app,
            last_telemetry_tick: Instant::now(),
        }
    }
}

fn header(ui: &mut egui::Ui, app: &mut App) {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("WinMedic v{}", env!("CARGO_PKG_VERSION")))
                .color(theme::CYAN)
                .strong()
                .size(16.0),
        );
        ui.label(theme::muted("Windows Self-Healing Engine"));

        if app.dry_run {
            theme::badge(ui, "SIMULATION", theme::AMBER);
        }

        // A repair that has done its half of the work and is waiting on the
        // machine. Saying so beside the brand keeps it visible from every tab,
        // which is the point: the findings behind it read as unfixed until the
        // restart happens.
        if app.has_pending_reboot() {
            theme::badge(ui, "REBOOT PENDING", theme::AMBER);
        }

        // Right-aligned, so the system readout sits opposite the brand and
        // does not shift as the numbers change width.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if app.is_admin {
                theme::badge(ui, "ADMIN", theme::EMERALD);
            } else {
                theme::badge(ui, "NO ADMIN", theme::CORAL);
            }

            match app.telemetry.as_ref() {
                Some(telemetry) => {
                    ui.label(theme::muted(format!(
                        "{} {}",
                        telemetry.os_name, telemetry.os_version
                    )));
                    ui.separator();
                    ui.label(format!(
                        "RAM {:.1}/{:.1} GB",
                        telemetry.ram_used_mb as f32 / 1024.0,
                        telemetry.ram_total_mb as f32 / 1024.0
                    ));
                    ui.separator();
                    ui.label(format!("CPU {:.1}%", telemetry.cpu_usage));
                }
                None => {
                    ui.label(theme::muted("Reading system telemetry..."));
                }
            }
        });
    });
    ui.add_space(4.0);
}

fn tab_bar(ui: &mut egui::Ui, app: &mut App) {
    let open_issues = app.issues.iter().filter(|i| !i.is_fixed).count();

    ui.horizontal(|ui| {
        for (index, title) in TABS.iter().enumerate() {
            // The two tabs that carry live information say so in the strip,
            // so a user watching another tab still sees a scan finish.
            let label = match index {
                TAB_SCANNER if app.is_scanning => format!("{title}  (running)"),
                TAB_TRIAGE if open_issues > 0 => format!("{title}  [{open_issues}]"),
                _ => (*title).to_string(),
            };

            let selected = app.active_tab == index;
            let text = if selected {
                RichText::new(label).color(theme::CYAN).strong()
            } else {
                RichText::new(label).color(theme::MUTED)
            };

            if ui.selectable_label(selected, text).clicked() {
                app.goto_tab(index);
            }
        }
    });
    ui.add_space(2.0);
}

fn footer(ui: &mut egui::Ui, app: &mut App) {
    ui.add_space(3.0);
    ui.horizontal(|ui| {
        if app.dry_run {
            theme::badge(ui, "SIMULATION", theme::AMBER);
        }

        match app.status_message.as_deref() {
            Some(message) => {
                ui.label(RichText::new(message).color(theme::EMERALD));
            }
            None => {
                ui.label(theme::muted("Ready"));
            }
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Help").clicked() {
                app.show_help = true;
            }
            if app.is_busy() && ui.button("Cancel").clicked() {
                app.cancel_current_operation();
            }
        });
    });
    ui.add_space(3.0);
}

fn body(ui: &mut egui::Ui, app: &mut App) {
    match app.active_tab {
        TAB_DASHBOARD => views::dashboard::show(ui, app),
        TAB_SCANNER => views::scanner::show(ui, app),
        TAB_TRIAGE => views::triage::show(ui, app),
        TAB_REPAIR => views::repair::show(ui, app),
        TAB_SETTINGS => views::settings::show(ui, app),
        _ => {}
    }
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

        if self.last_telemetry_tick.elapsed() >= Duration::from_secs(1) {
            self.app.refresh_telemetry();
            self.last_telemetry_tick = Instant::now();
        }

        // egui only repaints in response to input, and almost nothing this
        // window shows is driven by input: progress bars, log lines and the CPU
        // readout in the header all come from work happening elsewhere.
        ctx.request_repaint_after(if self.app.is_busy() {
            BUSY_REPAINT
        } else {
            IDLE_REPAINT
        });
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        for key in keys::shortcuts(ui.ctx()) {
            handle_key(&mut self.app, key);
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
    use crate::app::{ConfirmRequest, TAB_COUNT};
    use crate::safety::audit::AuditEntry;
    use crate::safety::reg_backup::BackupRecord;
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
        let mut harness = Harness::builder()
            .with_size(egui::vec2(1400.0, 900.0))
            .build_ui_state(|ui, app: &mut App| show(ui, app), app);
        harness.run();
        harness
    }

    fn populated_app() -> App {
        let mut app = App::new();
        // `App::new` raises the elevation prompt when WinMedic is not running
        // as Administrator, and that modal covers the tab it is asked about.
        app.pending_confirm = None;
        // It also restores the last scan from `%APPDATA%`, which on a machine
        // that has actually run WinMedic is a real one — and these tests
        // describe the findings they want to draw. Start from nothing scanned;
        // the tests that need issues add their own.
        app.issues.clear();
        app.health_score = 100;
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

        // A finished run, so the Health Scan and Repair Center tabs are drawn
        // with something in them. Their empty states are what a fresh `App`
        // already gives; what these two tabs exist to show is a run.
        app.scan_overall_progress = 100;
        app.scan_duration = Some(Duration::from_secs(74));
        app.push_scan_log("Module 'network' finished.");
        // Shaped the way `app::events` shapes it when the engine reports: a
        // module that failed carries both the reason and the step line that
        // states it, because the step line is what the scanner draws.
        if let Some(module) = app.module_progress_list.first_mut() {
            module.percent = 100;
            module.is_done = true;
            module.step = "Finished - 2 findings".to_string();
        }
        if let Some(module) = app.module_progress_list.get_mut(1) {
            module.percent = 100;
            module.is_done = true;
            module.failure = Some("DISM returned 0x800f081f".to_string());
            module.step = "Failed - DISM returned 0x800f081f".to_string();
        }

        app.total_to_fix = 3;
        app.fixed_count = 2;
        app.failed_count = 1;
        app.current_fix_title = "Flushing the DNS resolver cache".to_string();
        app.vss_status = "Created".to_string();
        app.push_repair_log("[OK] DNS cache flushed.");
        app.push_repair_log("[X] Failed: access denied.");

        app
    }

    /// Layout only fails at draw time, so a tab no window size can satisfy
    /// fails here rather than in front of a user.
    #[test]
    fn every_tab_draws_at_small_and_large_window_sizes() {
        for (tab, title) in TABS.iter().enumerate() {
            for size in [(960.0, 640.0), (1400.0, 900.0), (1920.0, 1200.0)] {
                let mut app = populated_app();
                app.active_tab = tab;

                let mut harness = Harness::builder()
                    .with_size(egui::vec2(size.0, size.1))
                    .build_ui_state(|ui, app: &mut App| show(ui, app), app);
                harness.run();

                assert!(
                    harness.query_by_label_contains(title).is_some(),
                    "tab {tab} at {}x{} did not draw its own strip entry",
                    size.0,
                    size.1
                );
            }
        }
    }

    #[test]
    fn the_strip_offers_exactly_five_tabs() {
        // The strip and the `TAB_*` constants index each other, so they have to
        // agree; a label added to one without the other silently misroutes
        // every click past it.
        assert_eq!(TABS.len(), TAB_COUNT);

        let harness = window(populated_app());

        for title in TABS {
            assert!(
                harness.query_by_label_contains(title).is_some(),
                "missing tab: {title}"
            );
        }

        // The sixth tab was merged into Settings & Safety and must not come
        // back as a label the user can look for.
        assert!(harness.query_by_label_contains("Backups & Logs").is_none());
    }

    /// The whole point of that merge: none of the safety surface may go missing.
    #[test]
    fn the_settings_tab_carries_the_whole_safety_surface() {
        let mut app = populated_app();
        app.active_tab = TAB_SETTINGS;
        let harness = window(app);

        for expected in [
            "SETTINGS",
            "REGISTRY BACKUPS",
            "SYSTEM RESTORE POINTS",
            "LOGS & BACKUPS",
            "Startup entry removed",
            "Restore the selected snapshot",
        ] {
            assert!(
                harness.query_by_label_contains(expected).is_some(),
                "the safety surface lost: {expected}"
            );
        }
    }

    #[test]
    fn the_dashboard_links_back_to_the_audit_trail_it_does_not_own() {
        let mut app = populated_app();
        app.active_tab = TAB_DASHBOARD;
        let harness = window(app);

        assert!(harness.query_by_label_contains("Last action:").is_some());
        assert!(
            harness
                .query_by_label_contains("Disabled a startup entry")
                .is_some()
        );
        assert!(
            harness
                .query_by_label_contains("Full log, backups & rollback")
                .is_some(),
            "and points at the tab that now holds it"
        );
    }

    #[test]
    fn a_machine_with_no_audit_trail_shows_no_empty_last_action_row() {
        let mut app = populated_app();
        app.active_tab = TAB_DASHBOARD;
        app.audit_entries.clear();

        let harness = window(app);
        assert!(harness.query_by_label_contains("Last action:").is_none());
    }

    /// A confirmation is a question about the machine, and it has to be visible
    /// whichever tab the user happened to be on when it was raised.
    #[test]
    fn a_pending_confirmation_is_drawn_over_every_tab() {
        for tab in 0..TAB_COUNT {
            let mut app = populated_app();
            app.active_tab = tab;
            app.pending_confirm = Some(ConfirmRequest::Elevate);

            let harness = window(app);
            assert!(
                harness
                    .query_by_label_contains("ADMINISTRATOR PRIVILEGES REQUIRED")
                    .is_some(),
                "the elevation dialog is missing on tab {tab}"
            );
            assert!(
                harness
                    .query_by_label_contains("Continue without Administrator")
                    .is_some(),
                "and offers no way out on tab {tab}"
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
            let mut app = populated_app();
            app.active_tab = tab;
            // Machine-supplied text — the CPU model, the host name — is not
            // ours to word and differs per machine, which would make this
            // assert on the test runner's hardware instead of on WinMedic.
            app.telemetry = None;

            let harness = window(app);

            // Both properties, because AccessKit splits them: an interactive
            // widget carries its text in `label`, while a plain piece of text —
            // which is most of what this window is — is a node of role `Label`
            // carrying its text in `value`. Reading only the former collects
            // the buttons and none of the prose.
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
            assert!(
                drawn.len() > 20,
                "tab {tab} produced only {} strings, so this asserts on nothing",
                drawn.len()
            );

            let font = egui::FontId::proportional(14.0);
            harness.ctx.fonts_mut(|fonts| {
                for label in &drawn {
                    for character in label.chars() {
                        assert!(
                            fonts.has_glyph(&font, character),
                            "tab {tab}: no glyph for U+{:04X} ({character:?}) in {label:?}",
                            character as u32
                        );
                    }
                }
            });
        }
    }

    /// A finished run has to be legible after the fact, not only while it runs:
    /// how long it took, which module gave up and why, and what the repair pass
    /// managed. The failure line matters most — a module that quit mid-scan is
    /// the single thing a user most needs to see.
    #[test]
    fn the_scan_and_repair_tabs_report_a_finished_run() {
        let mut app = populated_app();
        app.active_tab = TAB_SCANNER;
        let harness = window(app);

        assert!(
            harness.query_by_label_contains("1m 14s").is_some(),
            "the scan duration is missing"
        );
        assert!(
            harness
                .query_by_label_contains("DISM returned 0x800f081f")
                .is_some(),
            "a module that failed must say so"
        );
        assert!(
            harness
                .query_by_label_contains("Module 'network' finished.")
                .is_some(),
            "the scan log is missing"
        );

        let mut app = populated_app();
        app.active_tab = TAB_REPAIR;
        let harness = window(app);

        assert!(harness.query_by_label_contains("2 repaired").is_some());
        assert!(harness.query_by_label_contains("1 failed").is_some());
        assert!(harness.query_by_label_contains("VSS: Created").is_some());
        assert!(
            harness
                .query_by_label_contains("[X] Failed: access denied.")
                .is_some(),
            "the repair console is missing"
        );
    }

    /// An empty triage tab has to say why it is empty, and the two reasons are
    /// not the same: nothing scanned yet, versus nothing left after filtering.
    #[test]
    fn the_triage_tab_distinguishes_no_scan_from_no_matches() {
        let mut app = populated_app();
        app.active_tab = TAB_TRIAGE;
        let harness = window(app);
        assert!(
            harness
                .query_by_label_contains("No scan has run yet.")
                .is_some()
        );

        let mut app = populated_app();
        app.active_tab = TAB_TRIAGE;
        app.issues = vec![crate::engine::issue::Issue::new(
            "a",
            "network",
            "DNS cache full",
            "Network",
            crate::engine::issue::Severity::Critical,
            crate::engine::issue::RiskScore::Low,
            "description",
            "details",
            "fix",
            vec![],
        )];
        app.search_query = "nothing matches this".to_string();

        let harness = window(app);
        assert!(
            harness
                .query_by_label_contains("Nothing matches the current filters.")
                .is_some()
        );
    }
}
