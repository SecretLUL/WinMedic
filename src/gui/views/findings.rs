//! The findings: what the scan found, filtered, and which of it to repair.
//!
//! The list decides what a repair run will touch — every issue whose checkbox is
//! ticked — so selection state lives on the issue itself and not on the view.
//! During a run the same list shows each finding's outcome as it lands.

use crate::app::App;
use crate::app::state::waits_for_restart;
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

    let archive = egui::Panel::right("issue_detail")
        .resizable(true)
        .default_size(440.0)
        .size_range(280.0..=900.0)
        .frame(egui::Frame::NONE.inner_margin(egui::Margin {
            left: 12,
            ..Default::default()
        }))
        .show(ui, |ui| detail(ui, app, &indices))
        .inner;

    list(ui, app, &indices);
    // Only now: the list was drawn from the findings as they were.
    if let Some(issue_index) = archive {
        app.archive_issue(issue_index);
    }
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
        let selected = app.issues.iter().filter(|i| i.will_repair()).count();
        let archived = match app.archived_issues.len() {
            0 => String::new(),
            n => format!(" · {n} archived"),
        };
        ui.label(theme::muted(format!(
            "{shown} of {} findings shown · {selected} selected for repair{archived}",
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

/// The background of a finding's row.
///
/// egui's own selection fill (a saturated blue) and hover fill left the
/// status words on a row below 4.5:1 contrast: "Repair failed" at 2.5:1 on
/// the dark theme's selection. A tint of the selection colour over the panel
/// keeps every status colour and the muted text at 4.5:1 or more in both
/// themes, which `the_status_words_stay_legible_on_every_row` checks.
fn row_fill(visuals: &egui::Visuals, highlighted: bool, hovered: bool) -> egui::Color32 {
    let tint = |share| {
        visuals
            .panel_fill
            .lerp_to_gamma(visuals.selection.bg_fill, share)
    };
    if highlighted {
        tint(0.2)
    } else if hovered {
        tint(0.1)
    } else {
        egui::Color32::TRANSPARENT
    }
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
            let fill = row_fill(ui.visuals(), highlighted, hovered);
            let marker = ui.visuals().selection.stroke.color;
            let palette = theme::palette(ui);

            let shown = egui::Frame::NONE
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
                        // the same reason, and so is advice, which no repair
                        // run touches; `toggle_select_all_issues` passes over
                        // all three. Windows' own pending restart is advice,
                        // but the restart settles it.
                        let start = ui.cursor().min.x;
                        let ticked = if issue.is_fixed {
                            ui.colored_label(palette.green, "Fixed");
                            false
                        } else if waits_for_restart(issue) {
                            ui.colored_label(palette.amber, "Restart");
                            false
                        } else if issue.advice_only {
                            ui.label(theme::muted("Advice")).on_hover_text(
                                "WinMedic cannot repair this. The details say what to do.",
                            );
                            false
                        } else {
                            theme::checkbox(ui, &mut issue.is_selected, "").changed()
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
                });
            // The row the arrow keys are on, marked by a bar in the selection's
            // text colour at its left edge as well as by its tint.
            if highlighted {
                let rect = shown.response.rect;
                ui.painter().rect_filled(
                    egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())),
                    1,
                    marker,
                );
            }
            shown.inner
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

/// The selected finding in full. Returns its index when the user asked to
/// archive it.
fn detail(ui: &mut egui::Ui, app: &App, indices: &[usize]) -> Option<usize> {
    let &issue_index = indices.get(app.selected_filtered_index)?;
    let issue: &Issue = &app.issues[issue_index];
    let palette = theme::palette(ui);
    let busy = app.is_busy();
    let mut archive = false;

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
                if issue.advice_only {
                    ui.label("No automatic repair");
                } else {
                    let risk = RichText::new(risk_text(issue.risk_score));
                    ui.label(if issue.risk_score == RiskScore::High {
                        risk.color(palette.amber)
                    } else {
                        risk
                    });
                }
            });
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // A fixed finding is history; there is nothing to hide.
                    if !issue.is_fixed {
                        archive = ui
                            .add_enabled(!busy, egui::Button::new("Archive"))
                            .on_hover_text(
                                "Hide this finding and leave it out of the health score. \
                                 Settings brings it back.",
                            )
                            .clicked();
                    }
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.add(
                            egui::Label::new(theme::muted(format!(
                                "{} · {}",
                                issue.category, issue.module_id
                            )))
                            .truncate(),
                        );
                    });
                });
            });
            ui.add_space(6.0);
            ui.label(theme::heading(ui, &issue.title, 15.0));
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
            theme::section(
                ui,
                if issue.advice_only {
                    "What to do"
                } else {
                    "Recommended fix"
                },
            );
            ui.label(&issue.recommended_fix);

            if !issue.fix_steps.is_empty() {
                ui.add_space(6.0);
                for (number, step) in issue.fix_steps.iter().enumerate() {
                    ui.label(format!("{}. {}", number + 1, step));
                }
            }
        });
    archive.then_some(issue_index)
}

fn empty(ui: &mut egui::Ui, headline: &str, hint: &str) {
    ui.add_space(12.0);
    ui.label(RichText::new(headline).strong());
    ui.label(theme::muted(hint));
    ui.add_space(6.0);
}

#[cfg(test)]
mod tests {
    use crate::gui::theme::tests::contrast;

    /// Every word a row can carry, on every background a row can have, in
    /// both themes: 4.5:1 at least, the WCAG minimum for text.
    #[test]
    fn the_status_words_stay_legible_on_every_row() {
        let ctx = egui::Context::default();
        crate::gui::theme::apply(&ctx);
        for kind in [egui::Theme::Dark, egui::Theme::Light] {
            let visuals = ctx.style_of(kind).visuals.clone();
            let palette = crate::gui::theme::palette_of(&visuals);
            let words = [
                ("Fixed", palette.green),
                ("Restart", palette.amber),
                ("Repair failed", palette.red),
                ("muted", visuals.weak_text_color()),
                ("title", visuals.text_color()),
            ];
            for (highlighted, hovered) in [(true, false), (false, true), (false, false)] {
                let fill = super::row_fill(&visuals, highlighted, hovered);
                let background = if fill == egui::Color32::TRANSPARENT {
                    visuals.panel_fill
                } else {
                    fill
                };
                for (word, colour) in words {
                    let ratio = contrast(colour, background);
                    assert!(
                        ratio >= 4.5,
                        "{kind:?}, highlighted {highlighted}, hovered {hovered}: {word} at {ratio:.2}:1"
                    );
                }
            }
            // The bar marking the highlighted row stands out from the panel.
            assert!(contrast(visuals.selection.stroke.color, visuals.panel_fill) >= 3.0);
        }
    }

    use super::*;
    use eframe::egui::accesskit::Role;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    fn triage_app() -> App {
        let mut app = App::new();
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

    /// Advice has nothing to repair, so it offers no box and "select all"
    /// passes over it.
    #[test]
    fn advice_offers_no_checkbox() {
        let mut app = triage_app();
        app.issues[1] = app.issues[1].clone().with_advice_only();
        app.select_all_issues();
        let harness = harness(app);

        assert_eq!(harness.get_all_by_role(Role::CheckBox).count(), 2);
        harness.get_by_label("Advice");
        assert!(!harness.state().issues[1].is_selected);
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

    /// The box is painted by WinMedic, not egui, so whether it is ticked
    /// reaches a screen reader only if the box says so itself.
    #[test]
    fn a_checkbox_tells_a_screen_reader_whether_it_is_ticked() {
        use eframe::egui::accesskit::Toggled;
        use egui_kittest::kittest::NodeT;

        let mut app = triage_app();
        app.issues[1].is_selected = true;
        let harness = harness(app);

        let ticks: Vec<_> = harness
            .get_all_by_role(Role::CheckBox)
            .map(|node| node.accesskit_node().toggled())
            .collect();
        assert_eq!(
            ticks,
            vec![
                Some(Toggled::False),
                Some(Toggled::True),
                Some(Toggled::False)
            ]
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
