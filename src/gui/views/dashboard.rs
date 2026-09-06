//! System overview: health, live resources and the latest diagnostic results.

use crate::app::{App, TAB_SETTINGS, TAB_TRIAGE};
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
        ui.add_space(12.0);
        findings(ui, app);
        ui.add_space(18.0);
        modules(ui, app);
        ui.add_space(12.0);
        last_action(ui, app);
    });
}

fn has_results(app: &App) -> bool {
    app.scan_duration.is_some()
        || !app.issues.is_empty()
        || app
            .module_statuses
            .iter()
            .any(|(_, _, _, state)| !matches!(state, ModuleStatus::Idle))
}

fn health(ui: &mut egui::Ui, app: &mut App) {
    theme::card(ui, "SYSTEM HEALTH", |ui| {
        ui.set_min_height(230.0);
        let assessed = has_results(app) && !app.is_scanning;
        let color = if assessed {
            theme::health_color(app.health_score)
        } else {
            theme::CYAN
        };
        ui.horizontal(|ui| {
            let diameter = if ui.available_width() < 380.0 {
                110.0
            } else {
                132.0
            };
            let (rect, response) =
                ui.allocate_exact_size(egui::vec2(diameter, diameter), egui::Sense::hover());
            let center = rect.center();
            let radius = diameter / 2.0 - 7.0;
            ui.painter()
                .circle_stroke(center, radius, egui::Stroke::new(7.0, theme::BORDER));
            let fraction = if assessed {
                app.health_score as f32 / 100.0
            } else if app.is_scanning {
                app.scan_overall_progress as f32 / 100.0
            } else {
                0.0
            };
            if fraction > 0.0 {
                let points = (0..=80)
                    .map(|n| {
                        let angle = -std::f32::consts::FRAC_PI_2
                            + std::f32::consts::TAU * fraction * n as f32 / 80.0;
                        center + egui::vec2(angle.cos(), angle.sin()) * radius
                    })
                    .collect();
                ui.painter()
                    .add(egui::Shape::line(points, egui::Stroke::new(7.0, color)));
            }
            let value = if assessed {
                app.health_score.to_string()
            } else if app.is_scanning {
                format!("{}%", app.scan_overall_progress)
            } else {
                "--".to_string()
            };
            ui.painter().text(
                center - egui::vec2(0.0, 7.0),
                egui::Align2::CENTER_CENTER,
                &value,
                egui::FontId::proportional(34.0),
                theme::TEXT_WHITE,
            );
            ui.painter().text(
                center + egui::vec2(0.0, 24.0),
                egui::Align2::CENTER_CENTER,
                if assessed {
                    "OUT OF 100"
                } else if app.is_scanning {
                    "SCANNING"
                } else {
                    "NOT SCANNED"
                },
                egui::FontId::proportional(9.0),
                theme::MUTED,
            );
            response.widget_info(|| {
                egui::WidgetInfo::labeled(
                    egui::WidgetType::Label,
                    true,
                    format!("System health: {value}"),
                )
            });
            ui.vertical(|ui| {
                ui.add_space(12.0);
                let title = if app.is_scanning {
                    "Checking your PC"
                } else if assessed {
                    verdict(app.health_score)
                } else {
                    "Ready for a checkup"
                };
                ui.label(RichText::new(title).size(20.0).strong().color(color));
                ui.label(
                    theme::muted(if app.is_scanning {
                        "Results will appear as the checks finish."
                    } else if assessed {
                        "Based on your latest diagnostic findings."
                    } else {
                        "Run a scan to discover what needs your attention."
                    })
                    .size(13.0),
                );
                if let Some(duration) = app.scan_duration {
                    ui.label(
                        theme::muted(format!(
                            "Last scan took {}",
                            super::scanner::format_duration(duration)
                        ))
                        .size(11.0),
                    );
                }
            });
        });
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!app.is_busy(), theme::primary_button("Start health scan"))
                .clicked()
            {
                app.start_scan();
            }
            ui.label(theme::muted("S to scan").size(11.0));
        });
    });
}

fn verdict(score: u8) -> &'static str {
    match score {
        95..=100 => "Looking healthy",
        80..=94 => "Minor findings",
        50..=79 => "Needs attention",
        _ => "Needs your attention",
    }
}

fn findings(ui: &mut egui::Ui, app: &mut App) {
    let counts = [Severity::Critical, Severity::Warning, Severity::Info].map(|severity| {
        app.issues
            .iter()
            .filter(|i| !i.is_fixed && i.severity == severity)
            .count()
    });
    ui.columns(3, |columns| {
        for (index, (label, severity)) in [
            ("Critical", Severity::Critical),
            ("Warnings", Severity::Warning),
            ("Informational", Severity::Info),
        ]
        .iter()
        .enumerate()
        {
            theme::surface()
                .inner_margin(egui::Margin::symmetric(16, 12))
                .show(&mut columns[index], |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        theme::severity_mark(ui, *severity, 20.0);
                        ui.label(
                            RichText::new(counts[index].to_string())
                                .size(27.0)
                                .strong()
                                .color(theme::severity_color(*severity)),
                        );
                        if ui.link(*label).clicked() {
                            app.clear_filters();
                            app.severity_filter = Some(*severity);
                            app.clamp_filtered_selection();
                            app.goto_tab(TAB_TRIAGE);
                        }
                    });
                });
        }
    });
}

fn system(ui: &mut egui::Ui, app: &mut App) {
    theme::card(ui, "LIVE RESOURCES", |ui| {
        ui.set_min_height(230.0);
        ui.spacing_mut().item_spacing.y = 6.0;
        let Some(telemetry) = app.telemetry.as_ref() else {
            ui.label(theme::muted("Reading system telemetry..."));
            return;
        };
        ui.add(egui::Label::new(RichText::new(&telemetry.cpu_name).strong()).truncate())
            .on_hover_text(&telemetry.cpu_name);
        ui.add(
            egui::Label::new(
                theme::muted(format!(
                    "{} {} · {} cores",
                    telemetry.os_name, telemetry.os_version, telemetry.cpu_count
                ))
                .size(12.0),
            )
            .truncate(),
        )
        .on_hover_text(format!(
            "{} · {} {}",
            telemetry.host_name, telemetry.os_name, telemetry.os_version
        ));
        ui.add_space(4.0);
        meter(
            ui,
            "Processor",
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
        egui::ScrollArea::vertical()
            .id_salt("dashboard_disks")
            .max_height(60.0)
            .show(ui, |ui| {
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
    });
}

fn meter(ui: &mut egui::Ui, label: &str, fraction: f32, value: &str) {
    ui.horizontal(|ui| {
        ui.label(theme::muted(label).size(12.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(value).size(12.0));
        });
    });
    ui.add(
        egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
            .fill(if fraction >= 0.9 {
                theme::CORAL
            } else if fraction >= 0.75 {
                theme::AMBER
            } else {
                theme::CYAN
            })
            .desired_height(5.0),
    );
}

fn modules(ui: &mut egui::Ui, app: &mut App) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Diagnostic coverage").size(17.0).strong());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(theme::muted(format!("{} modules", app.module_statuses.len())).size(12.0));
        });
    });
    ui.add_space(4.0);
    for pair in app.module_statuses.chunks(2) {
        ui.columns(2, |columns| {
            for (index, (id, name, _, status)) in pair.iter().enumerate() {
                theme::surface()
                    .inner_margin(egui::Margin::symmetric(14, 10))
                    .corner_radius(10)
                    .show(&mut columns[index], |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let (text, color) = describe(status);
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 3.0, color);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 3.0;
                                ui.add(
                                    egui::Label::new(RichText::new(name).size(13.0).strong())
                                        .truncate(),
                                )
                                .on_hover_text(id);
                                ui.add(
                                    egui::Label::new(RichText::new(&text).size(11.0).color(color))
                                        .truncate(),
                                )
                                .on_hover_text(text);
                            });
                        });
                    });
            }
        });
    }
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

fn last_action(ui: &mut egui::Ui, app: &mut App) {
    let Some(entry) = app.audit_entries.last().cloned() else {
        return;
    };
    theme::card(ui, "RECENT ACTIVITY", |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(theme::muted("Last action:"));
            ui.label(RichText::new(&entry.title).strong());
            ui.label(theme::muted(&entry.timestamp).size(12.0));
        });
        if ui.link("Full log, backups & rollback").clicked() {
            app.goto_tab(TAB_SETTINGS);
        }
    });
}
