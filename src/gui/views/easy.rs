//! Easy mode's findings: one short list for someone who has never had to fix
//! Windows before.
//!
//! No ticks, filters, detail pane or logs — the header's one button repairs
//! the first group below, and the rest of the list says what happens to
//! everything else. That first group is the set the checks themselves
//! recommend: a finding arrives ticked unless repairing it needs a restart,
//! removes something the user may want to keep, or is a judgement call.
//! Advanced mode (F7) shows the details and lets the user change the ticks.

use crate::app::App;
use crate::engine::issue::{Issue, Severity};
use crate::gui::theme;
use eframe::egui::{self, RichText};

/// Why a finding sits where it does, which is all Easy mode says about it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Repairs,
    Restart,
    LeftAlone,
    Repaired,
}

impl Group {
    const ORDER: [Group; 4] = [
        Group::Repairs,
        Group::Restart,
        Group::LeftAlone,
        Group::Repaired,
    ];

    fn of(issue: &Issue) -> Self {
        if issue.is_fixed {
            Group::Repaired
        } else if issue.is_reboot_pending {
            Group::Restart
        } else if issue.is_selected {
            Group::Repairs
        } else {
            Group::LeftAlone
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Group::Repairs => "WinMedic repairs these",
            Group::Restart => "Repaired, waiting for a restart",
            Group::LeftAlone => "Left for you to decide",
            Group::Repaired => "Repaired",
        }
    }

    fn explanation(self) -> Option<&'static str> {
        match self {
            Group::LeftAlone => Some(
                "WinMedic leaves these alone unless you tick them in Advanced mode (F7): \
                 they need a restart, remove something you may want to keep, or are advice only.",
            ),
            _ => None,
        }
    }
}

pub fn show(ui: &mut egui::Ui, app: &mut App) {
    if app.is_scanning {
        ui.add_space(8.0);
        ui.label(theme::muted(
            "This can take a few minutes. WinMedic only looks while it checks - nothing is changed.",
        ));
        return;
    }
    if app.issues.is_empty() {
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("easy_list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for group in Group::ORDER {
                let mut members: Vec<&Issue> = app
                    .issues
                    .iter()
                    .filter(|i| Group::of(i) == group)
                    .collect();
                if members.is_empty() {
                    continue;
                }
                // The worst first, which is the order a reader cares about.
                members.sort_by_key(|i| match i.severity {
                    Severity::Critical => 0,
                    Severity::Warning => 1,
                    Severity::Info => 2,
                });

                ui.add_space(8.0);
                theme::section(ui, &format!("{} ({})", group.heading(), members.len()));
                if let Some(text) = group.explanation() {
                    ui.label(theme::muted(text));
                    ui.add_space(4.0);
                }
                for issue in members {
                    row(ui, issue);
                }
            }
        });
}

/// A finding in plain words: its title, what it means, and what went wrong
/// if its repair failed.
fn row(ui: &mut egui::Ui, issue: &Issue) {
    let palette = theme::palette(ui);
    ui.horizontal_top(|ui| {
        theme::severity_mark(ui, issue.severity, 14.0);
        ui.vertical(|ui| {
            let title = RichText::new(&issue.title).strong();
            if issue.is_fixed {
                ui.label(title.weak());
                return;
            }
            ui.label(title);
            ui.label(theme::muted(&issue.description));
            if let Some(error) = issue.fix_error.as_deref() {
                ui.colored_label(palette.red, format!("Repair failed: {error}"));
            }
        });
    });
    ui.add_space(6.0);
}
