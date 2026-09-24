//! The findings: what the scan found, filtered, and which of it to repair.
//!
//! The list decides what a repair run will touch — every issue whose checkbox is
//! ticked — so selection state lives on the issue itself and not on the view.
//! During a run the same list shows each finding's outcome as it lands.

use crate::app::App;
use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::gui::theme;
use eframe::egui::{self, RichText};

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    filters(ui, app);
    ui.add_space(4.0);
    ui.separator();

    let indices = app.filtered_issue_indices();

    if indices.is_empty() {
        empty(
            ui,
            "Nothing matches the current filters.",
            "Clear them to see the rest of the findings.",
        );
        return;
    }

    egui::Panel::right("issue_detail")
        .resizable(true)
        .default_size(440.0)
        .size_range(280.0..=900.0)
        .frame(egui::Frame::NONE.inner_margin(egui::Margin {
            left: 12,
            ..Default::default()
        }))
        .show(ui, |ui| detail(ui, app, &indices));

    list(ui, app, &indices);
}

fn filters(ui: &mut egui::Ui, app: &mut App) {
    ui.horizontal_wrapped(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut app.search_query)
                .desired_width(200.0)
                .hint_text("Search findings (/)"),
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
            if ui
                .selectable_label(active, severity_word(severity))
                .on_hover_text(format!(
                    "Show only {} findings ({})",
                    severity.name(),
                    severity_key(severity)
                ))
                .clicked()
            {
                app.toggle_severity_filter(severity);
            }
        }

        ui.separator();

        module_filter(ui, app);

        if app.has_active_filters() && ui.button("Clear filters").clicked() {
            app.clear_filters();
        }
    });

    ui.horizontal(|ui| {
        let shown = app.filtered_issue_indices().len();
        let selected = app
            .issues
            .iter()
            .filter(|i| i.is_selected && !i.is_fixed)
            .count();
        ui.label(theme::muted(format!(
            "{shown} of {} findings shown · {selected} selected for repair",
            app.issues.len()
        )));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Select none").on_hover_text("N").clicked() {
                app.deselect_all_issues();
            }
            if ui.button("Select all").on_hover_text("A").clicked() {
                app.select_all_issues();
            }
        });
    });
}

fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::Warning => "Warning",
        Severity::Info => "Info",
    }
}

fn severity_key(severity: Severity) -> char {
    match severity {
        Severity::Critical => 'C',
        Severity::Warning => 'W',
        Severity::Info => 'I',
    }
}

/// The module filter, by the name the dashboard shows rather than its id.
fn module_filter(ui: &mut egui::Ui, app: &mut App) {
    let current = app.module_filter.clone();
    let name_of = |id: &str| {
        app.module_statuses
            .iter()
            .find(|(module_id, ..)| module_id == id)
            .map_or_else(|| id.to_string(), |(_, name, ..)| name.clone())
    };
    let selected_text = current
        .as_deref()
        .map_or_else(|| "All modules".to_string(), name_of);

    let mut choice = None;
    egui::ComboBox::from_id_salt("module_filter")
        .selected_text(selected_text)
        .width(220.0)
        .show_ui(ui, |ui| {
            if ui
                .selectable_label(current.is_none(), "All modules")
                .clicked()
            {
                choice = Some(None);
            }
            for (id, name, ..) in &app.module_statuses {
                let count = app.issues.iter().filter(|i| &i.module_id == id).count();
                let label = format!("{name} ({count})");
                if ui
                    .selectable_label(current.as_deref() == Some(id), label)
                    .clicked()
                {
                    choice = Some(Some(id.clone()));
                }
            }
        });
    if let Some(choice) = choice {
        app.module_filter = choice;
        app.clamp_filtered_selection();
    }
}

fn list(ui: &mut egui::Ui, app: &mut App, indices: &[usize]) {
    egui::ScrollArea::vertical()
        .id_salt("issue_list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
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
            let visuals = ui.visuals();
            let fill = if highlighted {
                visuals.selection.bg_fill
            } else if hovered {
                visuals.widgets.hovered.weak_bg_fill
            } else {
                egui::Color32::TRANSPARENT
            };
            let palette = theme::palette(ui);

            egui::Frame::NONE
                .fill(fill)
                .corner_radius(2)
                .inner_margin(egui::Margin::symmetric(6, 3))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let issue = &mut app.issues[issue_index];

                        // A fixed issue is history: it cannot be selected for
                        // another repair run, so the checkbox stops offering.
                        // One waiting on a restart is in the same position for
                        // the same reason, and `toggle_select_all_issues`
                        // passes over both.
                        let start = ui.cursor().min.x;
                        let ticked = if issue.is_fixed {
                            ui.colored_label(palette.green, "Fixed");
                            false
                        } else if issue.is_reboot_pending {
                            ui.colored_label(palette.amber, "Restart");
                            false
                        } else {
                            ui.checkbox(&mut issue.is_selected, "").changed()
                        };
                        // A fixed-width first column, so the titles line up
                        // whether a row carries a checkbox or a word.
                        ui.add_space((start + 48.0 - ui.cursor().min.x).max(0.0));

                        theme::severity_mark(ui, issue.severity, 14.0);
                        let title = RichText::new(&issue.title);
                        let category = issue.category.clone();
                        let title = if issue.is_fixed { title.weak() } else { title };
                        let failed = !issue.is_fixed && issue.fix_error.is_some();
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.allocate_ui_with_layout(
                                egui::vec2(170.0, ui.available_height()),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| ui.add(egui::Label::new(theme::muted(category)).truncate()),
                            );
                            if failed {
                                ui.colored_label(palette.red, "Repair failed");
                            }
                            ui.with_layout(
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.add(egui::Label::new(title).truncate());
                                },
                            );
                        });
                        ticked
                    })
                    .inner
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

fn risk_text(risk: RiskScore) -> &'static str {
    match risk {
        RiskScore::Low => "Low risk - safe to repair",
        RiskScore::Medium => "Medium risk - may restart a service",
        RiskScore::High => "High risk - needs a restart or changes the system",
    }
}

fn detail(ui: &mut egui::Ui, app: &mut App, indices: &[usize]) {
    let Some(&issue_index) = indices.get(app.selected_filtered_index) else {
        return;
    };
    let issue: &Issue = &app.issues[issue_index];
    let palette = theme::palette(ui);

    egui::ScrollArea::vertical()
        .id_salt("issue_detail")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                theme::severity_mark(ui, issue.severity, 16.0);
                ui.label(
                    RichText::new(format!("Severity: {}", severity_word(issue.severity)))
                        .color(theme::severity_color(ui, issue.severity)),
                );
                ui.label(theme::muted("·"));
                let risk = RichText::new(risk_text(issue.risk_score));
                ui.label(if issue.risk_score == RiskScore::High {
                    risk.color(palette.amber)
                } else {
                    risk
                });
            });
            ui.label(theme::muted(format!(
                "{} · {}",
                issue.category, issue.module_id
            )));
            ui.add_space(6.0);
            ui.label(RichText::new(&issue.title).strong().size(15.0));
            ui.add_space(4.0);
            ui.label(&issue.description);

            if let Some(error) = issue.fix_error.as_deref() {
                ui.add_space(8.0);
                ui.colored_label(palette.red, format!("Repair failed: {error}"));
            }

            if !issue.technical_details.is_empty() {
                ui.add_space(10.0);
                theme::section(ui, "Technical details");
                ui.label(RichText::new(&issue.technical_details).monospace());
            }

            ui.add_space(10.0);
            theme::section(ui, "Recommended fix");
            ui.label(&issue.recommended_fix);

            if !issue.fix_steps.is_empty() {
                ui.add_space(6.0);
                for (number, step) in issue.fix_steps.iter().enumerate() {
                    ui.label(format!("{}. {}", number + 1, step));
                }
            }
        });
}

fn empty(ui: &mut egui::Ui, headline: &str, hint: &str) {
    ui.add_space(12.0);
    ui.label(RichText::new(headline).strong());
    ui.label(theme::muted(hint));
    ui.add_space(6.0);
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn a_severity_filter_narrows_the_list_and_releases_it_again() {
        let mut harness = harness(triage_app());

        harness.get_by_label("Warning").click();
        harness.run();
        assert_eq!(harness.state().severity_filter, Some(Severity::Warning));
        assert_eq!(harness.state().filtered_issue_indices(), vec![1]);

        harness.get_by_label("Warning").click();
        harness.run();
        assert_eq!(harness.state().severity_filter, None);
    }
}
