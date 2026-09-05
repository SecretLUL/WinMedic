//! The landing tab: how healthy the machine is, what the last scan found, and
//! the one button that starts another one.

use crate::app::{App, TAB_SETTINGS};
use crate::engine::issue::Severity;
use crate::gui::theme;
use crate::modules::ModuleStatus;
use eframe::egui::{self, RichText};

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.columns(2, |columns| {
            health(&mut columns[0], app);
            system(&mut columns[1], app);
        });

        ui.add_space(8.0);
        modules(ui, app);
        ui.add_space(8.0);
        last_action(ui, app);
    });
}

fn health(ui: &mut egui::Ui, app: &mut App) {
    theme::card(ui, "SYSTEM HEALTH", |ui| {
        let score = app.health_score;

        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{score}"))
                    .color(theme::health_color(score))
                    .strong()
                    .size(46.0),
            );
            ui.vertical(|ui| {
                ui.add_space(14.0);
                ui.label(theme::muted("out of 100"));
                ui.label(RichText::new(verdict(score)).color(theme::health_color(score)));
            });
        });

        ui.add_space(6.0);
        ui.add(
            egui::ProgressBar::new(score as f32 / 100.0)
                .fill(theme::health_color(score))
                .desired_height(8.0),
        );
        ui.add_space(10.0);

        let counts = severity_counts(app);
        ui.horizontal(|ui| {
            theme::badge(ui, &format!("{} critical", counts.0), theme::CORAL);
            theme::badge(ui, &format!("{} warnings", counts.1), theme::AMBER);
            theme::badge(ui, &format!("{} info", counts.2), theme::CYAN);
        });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let busy = app.is_busy();
            if ui
                .add_enabled(!busy, egui::Button::new("Start health scan"))
                .clicked()
            {
                app.start_scan();
            }
            let mut dry_run = app.dry_run;
            if ui.checkbox(&mut dry_run, "Simulation mode").changed() {
                app.toggle_dry_run();
            }
        });
    });
}

fn verdict(score: u8) -> &'static str {
    match score {
        95..=100 => "Healthy",
        80..=94 => "Minor findings",
        50..=79 => "Needs attention",
        _ => "Critical",
    }
}

fn severity_counts(app: &App) -> (usize, usize, usize) {
    let open = || app.issues.iter().filter(|issue| !issue.is_fixed);
    (
        open().filter(|i| i.severity == Severity::Critical).count(),
        open().filter(|i| i.severity == Severity::Warning).count(),
        open().filter(|i| i.severity == Severity::Info).count(),
    )
}

fn system(ui: &mut egui::Ui, app: &mut App) {
    theme::card(ui, "SYSTEM", |ui| {
        let Some(telemetry) = app.telemetry.as_ref() else {
            ui.label(theme::muted("Reading system telemetry..."));
            return;
        };

        ui.label(RichText::new(&telemetry.cpu_name).strong());
        ui.label(theme::muted(format!(
            "{} {} · {} · {} cores",
            telemetry.os_name, telemetry.os_version, telemetry.host_name, telemetry.cpu_count
        )));
        ui.add_space(8.0);

        meter(
            ui,
            "CPU",
            telemetry.cpu_usage / 100.0,
            &format!("{:.1}%", telemetry.cpu_usage),
        );
        meter(
            ui,
            "Memory",
            telemetry.ram_usage_percent / 100.0,
            &format!(
                "{:.1} / {:.1} GB",
                telemetry.ram_used_mb as f32 / 1024.0,
                telemetry.ram_total_mb as f32 / 1024.0
            ),
        );

        ui.add_space(8.0);
        for disk in &telemetry.disks {
            meter(
                ui,
                &disk.mount_point,
                disk.used_percent / 100.0,
                &format!(
                    "{:.0} GB free of {:.0} GB",
                    disk.available_space_gb, disk.total_space_gb
                ),
            );
        }
    });
}

/// A labelled bar. Load is coloured the same way a health score is, so a disk
/// at 95% reads as critical without needing a legend.
fn meter(ui: &mut egui::Ui, label: &str, fraction: f32, value: &str) {
    ui.horizontal(|ui| {
        ui.label(theme::muted(label));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(value);
        });
    });
    ui.add(
        egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
            .fill(theme::health_color(
                100u8.saturating_sub((fraction * 100.0) as u8),
            ))
            .desired_height(6.0),
    );
    ui.add_space(4.0);
}

fn modules(ui: &mut egui::Ui, app: &mut App) {
    theme::card(ui, "DIAGNOSTIC MODULES", |ui| {
        for (_, name, icon, status) in &app.module_statuses {
            ui.horizontal(|ui| {
                ui.label(icon.as_str());
                ui.label(name.as_str());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (text, color) = describe(status);
                    ui.label(RichText::new(text).color(color));
                });
            });
        }
    });
}

fn describe(status: &ModuleStatus) -> (String, egui::Color32) {
    match status {
        ModuleStatus::Idle => ("Not scanned".to_string(), theme::MUTED),
        ModuleStatus::Scanning => ("Scanning...".to_string(), theme::CYAN),
        ModuleStatus::Passed => ("Passed".to_string(), theme::EMERALD),
        ModuleStatus::Warning(n) => (format!("{n} warnings"), theme::AMBER),
        ModuleStatus::Critical(n) => (format!("{n} critical"), theme::CORAL),
        ModuleStatus::Failed(error) => (format!("Failed: {error}"), theme::CORAL),
    }
}

/// The audit trail's most recent entry, and a way to the rest of it.
///
/// A machine that has never been repaired has no last action, and an empty row
/// saying so is worse than no row at all.
fn last_action(ui: &mut egui::Ui, app: &mut App) {
    let Some(entry) = app.audit_entries.last().cloned() else {
        return;
    };

    theme::card(ui, "AUDIT TRAIL", |ui| {
        ui.horizontal(|ui| {
            ui.label(theme::muted("Last action:"));
            ui.label(RichText::new(&entry.title).strong());
            ui.label(theme::muted(format!("({})", entry.timestamp)));
        });
        if ui.link("Full log, backups & rollback").clicked() {
            app.goto_tab(TAB_SETTINGS);
        }
    });
}
