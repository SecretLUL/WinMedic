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
            if theme::severity_chip(ui, severity, active)
                .on_hover_text(format!("Show only {} findings", severity.name()))
                .clicked()
            {
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
    // The row is a `Ui` that senses clicks, rather than a `Frame` whose response
    // was handed a click sense afterwards. That distinction is the whole reason
    // this list works at all: a `Frame` registers its response *after*
    // everything drawn inside it, so a click sense there sits on top of the
    // row's own checkbox and swallows every click meant for it — nothing in the
    // list could be ticked. A `Ui` registers itself before its contents, which
    // leaves the checkbox where the pointer can reach it and the rest of the
    // row still clickable.
    let row = ui.scope_builder(
        egui::UiBuilder::new()
            .id_salt(("issue_row", issue_index))
            .sense(egui::Sense::click()),
        |ui| {
            // Labels sense clicks so that their text can be selected, and a
            // label sits on top of the row that contains it. A finding's title
            // is a list entry rather than prose, so the row keeps the click.
            ui.style_mut().interaction.selectable_labels = false;
            let hovered = ui.response().hovered();
            let (fill, border) = if highlighted {
                (theme::SELECTED, theme::CYAN.gamma_multiply(0.5))
            } else if hovered {
                (theme::HOVER, theme::BORDER)
            } else {
                (theme::CARD_SURFACE, theme::BORDER)
            };

            egui::Frame::NONE
                .fill(fill)
                .corner_radius(10)
                .stroke(egui::Stroke::new(1.0, border))
                .inner_margin(egui::Margin::symmetric(12, 12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let ticked = ui
                        .horizontal(|ui| {
                            let issue = &mut app.issues[issue_index];

                            // A fixed issue is history: it cannot be selected
                            // for another repair run, so the checkbox stops
                            // offering. One waiting on a restart is in the same
                            // position for the same reason, and
                            // `toggle_select_all_issues` passes over both.
                            let ticked = if issue.is_fixed {
                                ui.label(RichText::new("done").color(theme::EMERALD).size(11.0));
                                false
                            } else if issue.is_reboot_pending {
                                ui.label(RichText::new("reboot").color(theme::AMBER).size(11.0));
                                false
                            } else {
                                ui.checkbox(&mut issue.is_selected, "").changed()
                            };

                            theme::severity_mark(ui, issue.severity, 15.0);
                            ui.add(egui::Label::new(RichText::new(&issue.title).strong()).wrap());
                            ticked
                        })
                        .inner;
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
                    ticked
                })
                .inner
        },
    );

    if row.inner {
        // Ticking a box is also a statement about which finding the user is
        // reading, so the detail pane follows it — and the choice is written out
        // the same way the keyboard's `space` writes it.
        app.selected_filtered_index = position;
        app.save_scan_state();
    } else if row.response.clicked() {
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
                    theme::severity_badge(ui, issue.severity);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::issue::RiskScore;
    use eframe::egui::accesskit::Role;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    fn triage_app() -> App {
        let mut app = App::new();
        app.pending_confirm = None;
        app.issues = ["CBS log corrupt", "Temp bloat files", "DNS cache full"]
            .iter()
            .enumerate()
            .map(|(index, title)| {
                let mut issue = Issue::new(
                    format!("id_{index}"),
                    "network",
                    *title,
                    "Network",
                    [Severity::Critical, Severity::Warning, Severity::Info][index],
                    RiskScore::Low,
                    "description",
                    "details",
                    "fix",
                    vec![],
                );
                // `Issue::new` arrives pre-selected; these tests are about what
                // clicking does, so they start from nothing selected.
                issue.is_selected = false;
                issue
            })
            .collect();
        app.selected_filtered_index = 0;
        app
    }

    fn harness(app: App) -> Harness<'static, App> {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(1200.0, 800.0))
            .build_ui_state(|ui, app: &mut App| show(ui, app), app);
        theme::apply(&harness.ctx);
        harness.run();
        harness
    }

    /// The one thing this tab exists for: choosing what a repair run will touch.
    ///
    /// It regressed once, and invisibly — the checkboxes were drawn and the
    /// rows highlighted, but the row's own click target covered every box, so
    /// nothing in the list could actually be selected.
    #[test]
    fn a_row_checkbox_selects_the_issue_it_belongs_to() {
        let mut harness = harness(triage_app());

        assert_eq!(
            harness.get_all_by_role(Role::CheckBox).count(),
            3,
            "every unfixed finding offers a checkbox"
        );

        harness
            .get_all_by_role(Role::CheckBox)
            .next()
            .expect("the first finding has a checkbox")
            .click();
        harness.run();
        assert!(
            harness.state().issues[0].is_selected,
            "clicking a row's checkbox has to select that issue"
        );

        harness
            .get_all_by_role(Role::CheckBox)
            .next()
            .expect("the first finding has a checkbox")
            .click();
        harness.run();
        assert!(
            !harness.state().issues[0].is_selected,
            "and clicking it again has to clear it"
        );
    }

    /// Every box is its own: ticking one must not tick the rest.
    #[test]
    fn each_checkbox_belongs_to_its_own_row() {
        let mut harness = harness(triage_app());

        harness
            .get_all_by_role(Role::CheckBox)
            .nth(2)
            .expect("the third finding has a checkbox")
            .click();
        harness.run();

        let selected: Vec<bool> = harness
            .state()
            .issues
            .iter()
            .map(|issue| issue.is_selected)
            .collect();
        assert_eq!(selected, vec![false, false, true]);
        assert_eq!(
            harness.state().selected_filtered_index,
            2,
            "and the detail pane follows the box that was ticked"
        );
    }

    /// Clicking the row itself still moves the cursor, which is what fills the
    /// detail pane beside the list.
    #[test]
    fn clicking_a_row_body_moves_the_detail_pane_to_it() {
        let mut harness = harness(triage_app());

        harness.get_by_label("DNS cache full").click();
        harness.run();
        assert_eq!(harness.state().selected_filtered_index, 2);
        assert!(
            harness.state().issues.iter().all(|i| !i.is_selected),
            "moving the cursor is not the same as ticking the box"
        );
    }

    /// The severity marks are drawn shapes, so the only thing a screen reader
    /// has to go on is the label each one carries.
    #[test]
    fn every_severity_mark_announces_itself() {
        let harness = harness(triage_app());

        for name in ["CRITICAL", "WARNING", "INFO"] {
            assert!(
                harness.query_all_by_label(name).next().is_some(),
                "the {name} mark is drawn without a label"
            );
        }
    }

    /// The filter row is the other place a severity is chosen.
    #[test]
    fn a_severity_chip_filters_the_list_and_releases_it_again() {
        let mut harness = harness(triage_app());

        harness.get_by_label("WARN").click();
        harness.run();
        assert_eq!(harness.state().severity_filter, Some(Severity::Warning));
        assert_eq!(harness.state().filtered_issue_indices(), vec![1]);

        harness.get_by_label("WARN").click();
        harness.run();
        assert_eq!(harness.state().severity_filter, None);
    }
}
