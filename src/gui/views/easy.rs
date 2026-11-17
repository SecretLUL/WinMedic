//! Easy mode: the Scan & Repair page for someone who has never had to fix
//! Windows before.
//!
//! One column, one big button. The page says how the PC is doing, what the
//! repair will do — the disk space it frees and what works again, as the scan
//! measured it ([`crate::app::preview`]) — and offers Repair and Scan again.
//! No list of findings, no ticks, filters, logs or technical detail: Advanced
//! mode (F7) has all of that, and the Repair button repairs exactly what is
//! ticked there, which out of the box is what the checks recommend.

use super::home::{
    deletes_ticked_files, followed, format_duration, has_scanned, plural, repair_label,
    selected_for_repair,
};
use crate::app::App;
use crate::app::state::waits_for_restart;
use crate::engine::issue::Severity;
use crate::gui::theme;
use crate::modules::ModuleStatus;
use eframe::egui::{self, RichText};
use std::time::Duration;

/// Wide enough for the forecast's longest line, narrow enough to read at a
/// glance on a wide window.
const COLUMN: f32 = 620.0;

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical()
        .id_salt("easy_page")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let width = ui.available_width().min(COLUMN);
            ui.add_space(28.0);
            ui.horizontal_top(|ui| {
                ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
                ui.vertical(|ui| {
                    ui.set_width(width);
                    let mut more = false;
                    if app.is_scanning {
                        scanning(ui, app);
                    } else if app.is_fixing {
                        repairing(ui, app);
                    } else if !has_scanned(app) {
                        unscanned(ui, app);
                    } else {
                        more = result(ui, app);
                    }
                    notices(ui, app, more);
                });
            });
        });
}

fn headline(ui: &mut egui::Ui, text: &str, color: Option<egui::Color32>) {
    let mut text = theme::heading(ui, text, 26.0);
    if let Some(color) = color {
        text = text.color(color);
    }
    ui.label(text);
}

fn line(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).size(15.0));
}

fn note(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(theme::muted(text));
}

fn progress(ui: &mut egui::Ui, fraction: f32) {
    let fill = theme::palette(ui).accent;
    ui.add(
        egui::ProgressBar::new(followed(ui, fraction))
            .desired_height(16.0)
            .corner_radius(3)
            .fill(fill),
    );
}

fn unscanned(ui: &mut egui::Ui, app: &mut App) {
    headline(ui, "This PC has not been checked yet", None);
    ui.add_space(4.0);
    line(
        ui,
        "A scan finds common Windows problems. It changes nothing.",
    );
    ui.add_space(20.0);
    if theme::big_button(ui, "Scan now", Some("S"), true, true).clicked() {
        app.start_scan();
    }
}

fn scanning(ui: &mut egui::Ui, app: &mut App) {
    headline(ui, "Checking your PC...", None);
    ui.add_space(10.0);
    progress(ui, app.scan_overall_progress as f32 / 100.0);
    let mut status = format!("{}%", app.scan_overall_progress);
    if let Some(elapsed) = app.scan_elapsed() {
        status.push_str(&format!(" · {}", format_duration(elapsed)));
    }
    note(ui, status);
    ui.add_space(6.0);
    line(ui, "This takes a minute or two. Nothing is changed.");
    ui.add_space(16.0);
    if ui.add(theme::keyed(ui, "Cancel", "Esc")).clicked() {
        app.cancel_current_operation();
    }
    // Below the button, as on the repair page. The bar reaches 99 % within
    // seconds and then waits for the slowest check, the component store's,
    // for a minute or more: that is where it looks stuck.
    if app
        .scan_elapsed()
        .is_some_and(|elapsed| app.is_scanning && elapsed >= PATIENCE)
    {
        ui.add_space(16.0);
        reassurance(
            ui,
            "All good, WinMedic is still checking. The last checks take the longest.",
            still_checking(app),
        );
    }
}

/// Which checks the scan is still waiting for: their names while there are
/// one or two, so the page says what takes so long, and their number else.
fn still_checking(app: &App) -> Option<String> {
    let running: Vec<&str> = app
        .module_progress_list
        .iter()
        .filter(|module| !module.is_done)
        .map(|module| module.name.as_str())
        .collect();
    match running[..] {
        [] => None,
        [one] => Some(format!("Still running: {one}.")),
        [one, other] => Some(format!("Still running: {one} and {other}.")),
        _ => Some(format!("Still running: {} checks.", running.len())),
    }
}

fn repairing(ui: &mut egui::Ui, app: &mut App) {
    headline(
        ui,
        if app.dry_run {
            "Simulating the repair..."
        } else {
            "Repairing..."
        },
        None,
    );
    ui.add_space(10.0);
    let done = app.fixed_count + app.failed_count;
    progress(ui, app.repair_fraction());
    note(ui, format!("{done} of {} done", app.total_to_fix));
    ui.add_space(16.0);
    if ui.add(theme::keyed(ui, "Cancel", "Esc")).clicked() {
        app.cancel_current_operation();
    }
    // Below the button, so it does not move away from the pointer when this
    // appears.
    if let Some(elapsed) = app.repair_step_elapsed().filter(|e| *e >= PATIENCE) {
        ui.add_space(16.0);
        reassurance(
            ui,
            "Don't worry, everything is fine. WinMedic needs some time to heal.",
            patience_time(app, elapsed),
        );
    }
}

/// How long a scan, or one repair, runs before the page says that this is
/// normal. Nearly
/// every repair is done within seconds, so one still running after half a
/// minute is most likely one of the servicing tools: DISM, which ran for 13
/// minutes on one PC, with a bar that hardly moves. Half a minute of that is
/// where someone who has never seen it starts to wonder whether the window
/// hangs.
const PATIENCE: Duration = Duration::from_secs(30);

/// From when the reassurance also says how long. Earlier there are no whole
/// minutes to count, and DISM's first percent say little about its pace: the
/// estimate from them would be the number that frightens.
const TIMED: Duration = Duration::from_secs(2 * 60);

/// How long the running step still takes, or has taken; nothing before
/// [`TIMED`].
fn patience_time(app: &App, elapsed: Duration) -> Option<String> {
    if elapsed < TIMED {
        return None;
    }
    Some(match app.repair_step_remaining() {
        Some(left) if left < Duration::from_secs(60) => {
            "Less than a minute left for this step.".to_string()
        }
        Some(left) => match (left.as_secs_f64() / 60.0).round() as usize {
            1 => "About a minute left for this step.".to_string(),
            minutes => format!("About {minutes} minutes left for this step."),
        },
        // The tool reports no progress, so there is nothing to go on.
        None => format!(
            "Running for {}.",
            plural(elapsed.as_secs() as usize / 60, "minute")
        ),
    })
}

/// Nothing is wrong, in the words of the page it is on, and under them what
/// the page knows about the wait: how long it still takes, or what it is
/// waiting for.
fn reassurance(ui: &mut egui::Ui, text: &str, detail: Option<String>) {
    egui::Frame::NONE
        .fill(ui.visuals().faint_bg_color)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .corner_radius(6)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                theme::severity_mark(ui, Severity::Info, 18.0);
                ui.vertical(|ui| {
                    line(ui, text);
                    if let Some(detail) = detail {
                        note(ui, detail);
                    }
                });
            });
        });
}

/// Whether the page is the restart prompt itself: after a scan or a repair,
/// with a restart all that is left, for repairs or for Windows' own updates.
/// The restart banner stays away then, or the window would ask twice.
pub(crate) fn asks_for_restart(app: &App) -> bool {
    !app.config.advanced_mode
        && !app.is_scanning
        && !app.is_fixing
        && has_scanned(app)
        && app.restart_pending()
        && app
            .issues
            .iter()
            .all(|i| i.is_fixed || waits_for_restart(i))
}

/// After a scan or a repair: how the PC is doing, and the next step.
///
/// Returns whether it said something only Advanced mode shows in full, so
/// that [`notices`] points there once for the whole page.
fn result(ui: &mut egui::Ui, app: &mut App) -> bool {
    let palette = theme::palette(ui);
    let open: Vec<Severity> = app
        .issues
        .iter()
        .filter(|i| !i.is_fixed && !i.is_reboot_pending)
        .map(|i| i.severity)
        .collect();
    let problems = open.len();
    let to_repair = selected_for_repair(app);

    if asks_for_restart(app) {
        headline(ui, "Almost done", Some(palette.amber));
        ui.add_space(4.0);
        line(
            ui,
            if app.repairs_waiting_for_restart() > 0 {
                "Restart Windows to finish the repair."
            } else {
                "Windows is waiting for a restart to finish its updates."
            },
        );
        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if theme::big_button(ui, "Restart now", None, true, true).clicked() {
                app.show_reboot_notice();
            }
            scan_again(ui, app, false);
        });
        return false;
    }

    if problems == 0 {
        // A repair that found nothing to remove fixed nothing.
        let repaired = app
            .issues
            .iter()
            .any(|i| i.is_fixed && i.nothing_to_remove.is_none());
        headline(
            ui,
            if repaired {
                "All problems are fixed"
            } else {
                "Your PC is in good shape"
            },
            Some(palette.green),
        );
        ui.add_space(4.0);
        line(ui, format!("Health {} / 100", app.health_score));
        ui.add_space(20.0);
        scan_again(ui, app, true);
        return false;
    }

    let worst = [Severity::Critical, Severity::Warning, Severity::Info]
        .into_iter()
        .find(|s| open.contains(s))
        .unwrap_or(Severity::Info);
    headline(
        ui,
        &format!("{} found", plural(problems, "problem")),
        Some(theme::severity_color(ui, worst)),
    );
    ui.add_space(4.0);
    line(ui, format!("Health {} / 100", app.health_score));
    ui.add_space(16.0);

    if to_repair > 0 {
        forecast(ui, app);
        // A simulation runs no repair, so it is over in a moment.
        if !app.dry_run {
            ui.add_space(10.0);
            line(ui, app.repair_preview().pace.text());
        }
        ui.add_space(16.0);
    } else {
        line(ui, "None of them is repaired automatically.");
        ui.add_space(16.0);
    }

    ui.horizontal(|ui| {
        if to_repair > 0 {
            let label = repair_label(app.dry_run, to_repair, "problem");
            if theme::big_button(ui, &label, Some("F"), true, true).clicked() {
                app.start_repairs();
            }
        }
        scan_again(ui, app, to_repair == 0);
    });

    ui.add_space(10.0);
    if to_repair > 0 {
        let mut text = Vec::new();
        if app.dry_run {
            // Nothing is changed, so nothing needs a restore point or a
            // restart.
            text.push("A simulation changes nothing and creates no restore point.");
        } else {
            if app.config.create_vss_before_repair {
                text.push(
                    "A restore point is created first. \
                     It can undo changes to system files, settings and programs.",
                );
                if deletes_ticked_files(app) {
                    text.push("Deleted files do not come back.");
                }
            } else {
                text.push("Restore points are switched off in Settings.");
            }
            if app.repair_preview().needs_restart {
                text.push("Windows needs a restart afterwards.");
            }
        }
        note(ui, text.join(" "));
    }

    let failed = app
        .issues
        .iter()
        .filter(|i| !i.is_fixed && i.fix_error.is_some())
        .count();
    if failed > 0 {
        ui.colored_label(
            palette.red,
            format!("{} did not work.", plural(failed, "repair")),
        );
    }

    let left_alone = problems - to_repair;
    if left_alone > 0 {
        ui.label(theme::muted(format!(
            "{} more {} your decision.",
            left_alone,
            if left_alone == 1 { "needs" } else { "need" }
        )));
    }
    failed > 0 || left_alone > 0
}

/// What the Repair button will do, in a few short lines.
fn forecast(ui: &mut egui::Ui, app: &App) {
    let preview = app.repair_preview();
    let mut lines: Vec<String> = Vec::new();
    lines.extend(preview.space_line());
    lines.extend(preview.benefits.iter().map(|b| b.text().to_string()));
    if preview.health_after > app.health_score {
        lines.push(format!(
            "Health goes up to about {} / 100",
            preview.health_after
        ));
    }
    if lines.is_empty() {
        return;
    }

    egui::Frame::NONE
        .fill(ui.visuals().faint_bg_color)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .corner_radius(6)
        .inner_margin(14)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(theme::heading(ui, "What Repair does", 15.0));
            ui.add_space(6.0);
            for text in lines {
                ui.horizontal(|ui| {
                    theme::check_mark(ui, 16.0);
                    line(ui, text);
                });
            }
        });
}

fn scan_again(ui: &mut egui::Ui, app: &mut App, primary: bool) {
    if theme::big_button(ui, "Scan again", Some("S"), primary, true).clicked() {
        app.start_scan();
    }
}

/// Modules that could not be checked, in one line, and below everything the
/// page left to Advanced mode, the one link that goes there. `more` is
/// whether the page above already said something of that kind.
///
/// Each of those lines named Advanced mode itself, and a page with a failed
/// repair and a finding left alone pointed there three times.
fn notices(ui: &mut egui::Ui, app: &mut App, mut more: bool) {
    let palette = theme::palette(ui);

    if !app.is_scanning {
        // A command's error text says nothing to someone who has never opened
        // a terminal, so the module is named and the reason left to Advanced.
        let failed: Vec<&str> = app
            .module_statuses
            .iter()
            .filter(|(.., status)| matches!(status, ModuleStatus::Failed(_)))
            .map(|(_, name, ..)| name.as_str())
            .collect();
        if !failed.is_empty() {
            ui.add_space(6.0);
            ui.colored_label(
                palette.red,
                format!("Could not check {}.", failed.join(", ")),
            );
            more = true;
        }
    }

    if more {
        ui.add_space(2.0);
        if ui.link("Show details in Advanced mode (F7)").clicked() {
            app.toggle_advanced_mode();
        }
    }
}
