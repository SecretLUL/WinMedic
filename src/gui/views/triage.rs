//! Issue triage: what the scan found, filtered, and which of it to repair.
//!
//! The list decides what a repair run will touch — every issue whose checkbox is
//! ticked — so selection state lives on the issue itself and not on the view.

use crate::app::App;
use crate::engine::issue::{Issue, Severity};
use crate::gui::theme;
use eframe::egui::{self, RichText};

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    filters(ui, app);
    ui.add_space(16.0);

    let indices = app.filtered_issue_indices();

    if app.issues.is_empty() {
        empty(
            ui,
            app,
            "No scan has run yet.",
            "Start a health scan to see what this machine is dealing with.",
        );
        return;
    }
    if indices.is_empty() {
        empty(
            ui,
            app,
            "Nothing matches the current filters.",
            "Clear them to see the rest of the findings.",
        );
        return;
    }

    ui.columns(2, |columns| {
        list(&mut columns[0], app, &indices);
        detail(&mut columns[1], app, &indices);
    });
}

fn filters(ui: &mut egui::Ui, app: &mut App) {
    ui.horizontal_wrapped(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut app.search_query)
                .desired_width(220.0)
                .margin(egui::vec2(12.0, 10.0))
                .hint_text("Search findings..."),
        );
        // `[/]` asks for this field; honouring the request here is what keeps
        // the shortcut from having to know anything about widgets.
        if app.focus_search {
            field.request_focus();
            app.focus_search = false;
        }
        if field.changed() {
            app.clamp_filtered_selection();
        }

        ui.separator();

        for severity in [Severity::Critical, Severity::Warning, Severity::Info] {
            let active = app.severity_filter == Some(severity);
            let text = RichText::new(severity.short_label()).color(theme::severity_color(severity));
            if ui.selectable_label(active, text).clicked() {
                app.toggle_severity_filter(severity);
            }
        }

        ui.separator();

        let module_label = app
            .module_filter
            .clone()
            .unwrap_or_else(|| "All modules".to_string());
        if ui.button(module_label).clicked() {
            app.cycle_module_filter();
        }

        if app.has_active_filters() && ui.button("Clear filters").clicked() {
            app.clear_filters();
        }
    });
    ui.horizontal(|ui| {
        ui.label(
            theme::muted(format!("{} findings", app.filtered_issue_indices().len())).size(12.0),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let selected = app
                .issues
                .iter()
                .filter(|i| i.is_selected && !i.is_fixed)
                .count();
            if ui
                .add_enabled(
                    selected > 0 && !app.is_busy(),
                    theme::primary_button(if app.dry_run {
                        format!("Simulate {selected} repairs")
                    } else {
                        format!("Repair {selected} issues")
                    }),
                )
                .clicked()
            {
                app.start_repairs();
            }
            if ui.button("None").clicked() {
                app.deselect_all_issues();
            }
            if ui.button("All").clicked() {
                app.select_all_issues();
            }
        });
    });
}

fn list(ui: &mut egui::Ui, app: &mut App, indices: &[usize]) {
    egui::ScrollArea::vertical()
        .id_salt("issue_list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (position, &issue_index) in indices.iter().enumerate() {
                let highlighted = position == app.selected_filtered_index;
                row(ui, app, issue_index, highlighted, position);
            }
        });
}

fn row(ui: &mut egui::Ui, app: &mut App, issue_index: usize, highlighted: bool, position: usize) {
    let fill = if highlighted {
        theme::SELECTED
    } else {
        theme::CARD_SURFACE
    };

    let response = egui::Frame::NONE
        .fill(fill)
        .corner_radius(10)
        .stroke(egui::Stroke::new(
            1.0,
            if highlighted {
                theme::CYAN.gamma_multiply(0.5)
            } else {
                theme::BORDER
            },
        ))
        .inner_margin(egui::Margin::symmetric(12, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let issue = &mut app.issues[issue_index];

                // A fixed issue is history: it cannot be selected for another
                // repair run, so the checkbox stops offering. One waiting on a
                // restart is in the same position for the same reason, and
                // `toggle_select_all_issues` passes over both.
                if issue.is_fixed {
                    ui.label(RichText::new("done").color(theme::EMERALD).size(11.0));
                } else if issue.is_reboot_pending {
                    ui.label(RichText::new("reboot").color(theme::AMBER).size(11.0));
                } else {
                    ui.checkbox(&mut issue.is_selected, "");
                }

                let severity = issue.severity;
                ui.label(
                    RichText::new(severity.badge())
                        .color(theme::severity_color(severity))
                        .strong()
                        .size(11.0),
                );
                ui.add(egui::Label::new(RichText::new(&issue.title).strong()).wrap());
            });
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                let issue = &app.issues[issue_index];
                ui.add(
                    egui::Label::new(
                        theme::muted(format!("{} · {}", issue.category, issue.module_id))
                            .size(11.0),
                    )
                    .truncate(),
                );
            });
        })
        .response;

    if response.interact(egui::Sense::click()).clicked() {
        app.selected_filtered_index = position;
    }
}

fn detail(ui: &mut egui::Ui, app: &mut App, indices: &[usize]) {
    let Some(&issue_index) = indices.get(app.selected_filtered_index) else {
        return;
    };
    let issue: &Issue = &app.issues[issue_index];

    egui::ScrollArea::vertical()
        .id_salt("issue_detail")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            theme::card(ui, "DETAILS", |ui| {
                ui.horizontal_wrapped(|ui| {
                    theme::badge(
                        ui,
                        issue.severity.badge(),
                        theme::severity_color(issue.severity),
                    );
                    theme::badge(ui, issue.risk_score.badge(), theme::ACCENT_PURPLE);
                    ui.label(theme::muted(&issue.category));
                });
                ui.add_space(6.0);
                ui.label(RichText::new(&issue.title).strong().size(15.0));
                ui.add_space(6.0);
                ui.label(&issue.description);

                if !issue.technical_details.is_empty() {
                    ui.add_space(10.0);
                    ui.label(theme::muted("Technical detail"));
                    ui.label(
                        RichText::new(&issue.technical_details)
                            .monospace()
                            .size(11.0),
                    );
                }

                ui.add_space(10.0);
                ui.label(theme::muted("Recommended fix"));
                ui.label(&issue.recommended_fix);

                if !issue.fix_steps.is_empty() {
                    ui.add_space(6.0);
                    for (number, step) in issue.fix_steps.iter().enumerate() {
                        ui.label(format!("{}. {}", number + 1, step));
                    }
                }

                if let Some(error) = issue.fix_error.as_deref() {
                    ui.add_space(10.0);
                    ui.label(RichText::new(format!("Repair failed: {error}")).color(theme::CORAL));
                }
            });
        });
}

fn empty(ui: &mut egui::Ui, app: &mut App, headline: &str, hint: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(70.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(64.0, 64.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 18, theme::SELECTED);
        theme::icon(ui, rect.shrink(17.0), 2, theme::CYAN);
        ui.add_space(16.0);
        ui.label(RichText::new(headline).size(21.0).strong());
        ui.label(theme::muted(hint));
        ui.add_space(12.0);
        if app.issues.is_empty() {
            if ui
                .add_enabled(!app.is_busy(), theme::primary_button("Start health scan"))
                .clicked()
            {
                app.start_scan();
            }
        } else if ui.button("Clear filters").clicked() {
            app.clear_filters();
        }
    });
}
