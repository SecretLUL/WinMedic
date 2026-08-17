use crate::ui::theme::Theme;
use crate::utils::debug_log::{DebugTag, parse_debug_line};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Wrap};
use std::collections::VecDeque;

/// Colour a verbose tag by what it says.
///
/// The tag carries the meaning, so it keeps its own colour while the rest of the
/// line stays dim: a trace has to be readable without competing with the repair
/// output it sits between.
fn debug_tag_color(tag: DebugTag) -> Color {
    match tag {
        DebugTag::Warn => Theme::AMBER,
        DebugTag::Hint => Theme::CYAN,
        DebugTag::Exec => Theme::ACCENT_PURPLE,
        DebugTag::Exit => Theme::EMERALD,
        DebugTag::Step => Theme::ACCENT_PURPLE,
        DebugTag::Time | DebugTag::Data => Theme::MUTED,
    }
}

/// What a console line turned out to be saying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Failure,
    Success,
    /// Anything the run has not called a failure: progress, notices, plain output.
    Neutral,
}

impl Outcome {
    /// The gutter printed in front of the line.
    fn marker(self) -> &'static str {
        match self {
            Outcome::Failure => " [X] ",
            Outcome::Success => " [OK] ",
            Outcome::Neutral => " > ",
        }
    }

    /// Styles for the gutter and the line text, in that order.
    fn styles(self) -> (Style, Style) {
        match self {
            Outcome::Failure => (
                Style::default()
                    .fg(Theme::CORAL)
                    .add_modifier(Modifier::BOLD),
                Style::default().fg(Theme::CORAL),
            ),
            Outcome::Success => (
                Style::default()
                    .fg(Theme::EMERALD)
                    .add_modifier(Modifier::BOLD),
                Style::default().fg(Theme::EMERALD),
            ),
            Outcome::Neutral => (
                Style::default().fg(Theme::CYAN),
                Style::default().fg(Theme::TEXT_WHITE),
            ),
        }
    }
}

/// Line prefixes the repair pipeline writes itself, and what each one means.
///
/// [`crate::app::events`] already knows whether a step failed, so its own marker
/// settles the question before the keyword scan gets a look at the line. That
/// order is what stops a repair from being judged by the thing it repaired:
/// "Windows error reports & crash dumps" is the name of a Windows feature, so a
/// run that cleans it *successfully* used to come out coral on both the
/// `Repairing:` line and the `[OK]` line that followed it.
const EMITTED_PREFIXES: &[(&str, Outcome)] = &[
    ("[X]", Outcome::Failure),
    ("[STDERR]", Outcome::Failure),
    ("[OK]", Outcome::Success),
    // A cancellation is the user's decision, not a fault — and its tally reads
    // "0 failed" on a clean stop, which the keyword scan would take literally.
    ("[STOP]", Outcome::Neutral),
    ("Repairing:", Outcome::Neutral),
    ("Simulating:", Outcome::Neutral),
];

/// Decide what an unparsed console line is reporting, and what of it to print.
///
/// The returned text is the line minus any prefix the gutter is about to repeat
/// verbatim — an emitted `[OK] …` rendered as-is comes out `[OK] [OK] …`.
/// Prefixes the gutter does *not* echo, `[STDERR]` above all, are left in place:
/// they say something the gutter does not.
fn classify(line: &str) -> (Outcome, &str) {
    if let Some((prefix, outcome)) = EMITTED_PREFIXES
        .iter()
        .find(|(prefix, _)| line.starts_with(prefix))
    {
        let text = if outcome.marker().trim() == *prefix {
            line[prefix.len()..].trim_start()
        } else {
            line
        };
        return (*outcome, text);
    }

    // Everything left is raw output from sfc, dism, chkdsk and friends, where
    // the wording is all there is to go on.
    let lower = line.to_lowercase();
    let is_negative_assertion = lower.starts_with("no ")
        || lower.starts_with("0 errors")
        || lower.contains("no errors")
        || lower.contains("0 errors");

    if !is_negative_assertion && (lower.contains("error") || lower.contains("failed")) {
        return (Outcome::Failure, line);
    }

    if line.contains("SUCCESS") || line.contains("Repaired") || line.contains("finished") {
        return (Outcome::Success, line);
    }

    (Outcome::Neutral, line)
}

/// Style one console line for the repair log.
///
/// Verbose traces are matched *before* [`classify`]: a trace explaining a
/// failure necessarily contains the words "error" and "failed", and colouring
/// those lines coral would make a single failed repair look like a dozen.
pub fn style_console_line(line: &str) -> Line<'_> {
    if let Some(parsed) = parse_debug_line(line) {
        return Line::from(vec![
            Span::styled(
                " [D] ",
                Style::default()
                    .fg(Theme::ACCENT_PURPLE)
                    .add_modifier(Modifier::DIM),
            ),
            Span::styled(
                parsed.stamp,
                Style::default()
                    .fg(Theme::BORDER)
                    .add_modifier(Modifier::DIM),
            ),
            Span::styled(
                format!(" {} ", parsed.tag.label()),
                Style::default()
                    .fg(debug_tag_color(parsed.tag))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(parsed.message, Style::default().fg(Theme::MUTED)),
        ]);
    }

    let (outcome, text) = classify(line);
    let (marker_style, text_style) = outcome.styles();

    Line::from(vec![
        Span::styled(outcome.marker(), marker_style),
        Span::styled(text, text_style),
    ])
}

// See `ui::widgets::header` — render functions take explicit state slices
// rather than borrowing the whole `App`.
#[allow(clippy::too_many_arguments)]
pub fn render_fix_progress(
    f: &mut Frame,
    area: Rect,
    is_fixing: bool,
    current_issue_title: &str,
    fixed_count: usize,
    failed_count: usize,
    total_to_fix: usize,
    vss_status: &str,
    console_lines: &VecDeque<String>,
    dry_run: bool,
    scroll_offset: usize,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Repair Progress Gauge & VSS Badge
            Constraint::Min(10),   // Live Repair Console Output
            Constraint::Length(5), // Execution Summary & Reboot Alert
        ])
        .split(area);

    // Top: Repair Progress Gauge
    let progress_percent = if total_to_fix > 0 {
        (((fixed_count + failed_count) as f32 / total_to_fix as f32) * 100.0).clamp(0.0, 100.0)
            as u16
    } else {
        0
    };

    let title_str = match (dry_run, is_fixing) {
        (true, true) => format!(
            " [!] SIMULATION RUNNING - current: {} ",
            current_issue_title
        ),
        (true, false) if total_to_fix > 0 && (fixed_count + failed_count >= total_to_fix) => {
            " [!] SIMULATION COMPLETE - nothing was changed ".to_string()
        }
        (true, false) => {
            " [!] SIMULATION MODE - [F] shows the planned steps, [D] switches back ".to_string()
        }
        (false, true) => format!(" REPAIRS RUNNING - current: {} ", current_issue_title),
        (false, false) if total_to_fix > 0 && (fixed_count + failed_count >= total_to_fix) => {
            " REPAIR RUN COMPLETE ".to_string()
        }
        (false, false) => " REPAIR CENTRE - ready to run (press [F]) ".to_string(),
    };

    let gauge_color = if dry_run {
        Theme::AMBER
    } else if progress_percent >= 100 && failed_count == 0 {
        Theme::EMERALD
    } else if failed_count > 0 {
        Theme::AMBER
    } else {
        Theme::CYAN
    };

    let top_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(gauge_color))
                .title(title_str),
        )
        .gauge_style(Style::default().fg(gauge_color).bg(Theme::BG_DEEP))
        .percent(progress_percent)
        .label(format!(
            " {}/{} Fixes ({:.0}%) │ VSS: {} ",
            fixed_count + failed_count,
            total_to_fix,
            progress_percent,
            vss_status
        ));

    f.render_widget(top_gauge, chunks[0]);

    // Center: Live Repair Console with scroll offset
    let viewport_height = chunks[1].height.saturating_sub(2) as usize;
    let total_logs = console_lines.len();

    let end_idx = total_logs.saturating_sub(scroll_offset);
    let start_idx = end_idx.saturating_sub(viewport_height);

    let lines: Vec<Line> = (start_idx..end_idx)
        .filter_map(|idx| console_lines.get(idx))
        .map(|line| style_console_line(line))
        .collect();

    let debug_lines = console_lines
        .iter()
        .filter(|line| parse_debug_line(line).is_some())
        .count();

    let console_title = if scroll_offset > 0 {
        format!(
            " LIVE REPAIR CONSOLE [lines {}-{} of {} | End = live] ",
            start_idx + 1,
            end_idx,
            total_logs
        )
    } else if debug_lines > 0 {
        format!(
            " LIVE REPAIR CONSOLE & COMMAND OUTPUT [{} | {} debug] [PgUp/PgDn to scroll] ",
            total_logs, debug_lines
        )
    } else {
        format!(
            " LIVE REPAIR CONSOLE & COMMAND OUTPUT [{}] [PgUp/PgDn to scroll] ",
            total_logs
        )
    };

    let console_box = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if scroll_offset > 0 {
                    Theme::AMBER
                } else {
                    Theme::CYAN
                }))
                .title(console_title),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(console_box, chunks[1]);

    // Bottom: Summary & Next Steps
    let summary_lines = vec![
        Line::from(vec![
            Span::styled(
                " Status: ",
                Style::default()
                    .fg(Theme::CYAN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if dry_run {
                    format!("{} repair(s) planned", fixed_count)
                } else {
                    format!("{} fixed successfully", fixed_count)
                },
                Style::default()
                    .fg(if dry_run {
                        Theme::AMBER
                    } else {
                        Theme::EMERALD
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
            Span::styled(
                format!("{} failed", failed_count),
                Style::default()
                    .fg(if failed_count > 0 {
                        Theme::CORAL
                    } else {
                        Theme::TEXT_WHITE
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │ ", Style::default().fg(Theme::BORDER)),
            Span::styled(
                if dry_run {
                    " Press [D] to run repairs for real "
                } else if progress_percent >= 100 && failed_count == 0 {
                    " All repairs completed successfully. "
                } else if progress_percent >= 100 {
                    " Some repairs need a system restart. "
                } else if is_fixing {
                    " Working through the repair scripts... "
                } else {
                    " Press [F] to start repairs, [D] to simulate "
                },
                Style::default()
                    .fg(Theme::TEXT_WHITE)
                    .add_modifier(Modifier::ITALIC),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Keys: ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                "[PgUp/PgDn] Scroll log  [Home/End] Top/Live  [F] Start  [D] Simulate  [E] Report",
                Style::default().fg(Theme::CYAN),
            ),
        ]),
    ];

    let summary_box = Paragraph::new(summary_lines).block(Theme::card_block("SUMMARY & NOTES"));
    f.render_widget(summary_box, chunks[2]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::debug_log::{DebugTag, render_debug_line};

    fn gutter(line: &str) -> String {
        style_console_line(line).spans[0].content.to_string()
    }

    /// The whole styled line as the user reads it, gutter included.
    fn rendered(line: &str) -> String {
        style_console_line(line)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect()
    }

    fn color_of(line: &str, span: usize) -> Option<Color> {
        style_console_line(line).spans[span].style.fg
    }

    #[test]
    fn a_trace_gets_its_own_gutter_and_never_the_error_colour() {
        // The wording here is the point: this trace explains a failure, so it
        // contains both keywords the plain classifier looks for.
        let line = render_debug_line(
            DebugTag::Warn,
            "could not run 'chkdsk.exe': failed, error 5",
        );

        assert_eq!(gutter(&line), " [D] ");
        assert_ne!(
            color_of(&line, 3),
            Some(Theme::CORAL),
            "a trace must not be painted as a failed repair"
        );
    }

    #[test]
    fn each_tag_keeps_its_own_colour() {
        let warn = render_debug_line(DebugTag::Warn, "something looks wrong");
        let hint = render_debug_line(DebugTag::Hint, "here is why");

        assert_eq!(color_of(&warn, 2), Some(Theme::AMBER));
        assert_eq!(color_of(&hint, 2), Some(Theme::CYAN));
    }

    #[test]
    fn ordinary_repair_output_keeps_its_existing_styling() {
        assert_eq!(
            gutter("[X] Error: Failed to empty the Recycle Bin"),
            " [X] "
        );
        assert_eq!(gutter("[STDERR] dism reported a problem"), " [X] ");
        assert_eq!(gutter("chkdsk /scan finished"), " [OK] ");
        assert_eq!(gutter("Repairing: Browser caches"), " > ");
        assert_eq!(
            gutter("No WHEA hardware faults or PCIe/CPU errors logged."),
            " > "
        );
        assert_eq!(gutter("No errors found in registry"), " > ");
    }

    /// A repair is judged by its own marker, never by what it repaired.
    ///
    /// Both of these lines are about Windows Error Reporting, so both carry the
    /// word "error" while reporting a successful clean-up.
    #[test]
    fn a_fix_whose_subject_is_named_error_is_not_painted_as_one() {
        assert_eq!(
            gutter("Repairing: Windows error reports & crash dumps (0 B, 1 files)"),
            " > "
        );
        assert_eq!(
            gutter(
                "[OK] Windows error reports & crash dumps cleaned: 1 files deleted (0 B freed, 0 locked files skipped)."
            ),
            " [OK] "
        );
        assert_eq!(
            gutter("Simulating: Windows error reports & crash dumps (0 B, 1 files)"),
            " > "
        );
    }

    #[test]
    fn a_cancelled_run_is_a_notice_rather_than_a_failure() {
        assert_eq!(
            gutter("[STOP] Repairs cancelled: 2 done, 0 failed, 3 never attempted."),
            " > "
        );
    }

    /// The marker still has to lose to a genuine failure it announces itself.
    #[test]
    fn an_emitted_failure_keeps_the_error_gutter() {
        assert_eq!(
            gutter("[X] Error: Windows error reports & crash dumps could not be cleaned"),
            " [X] "
        );
    }

    /// The gutter is the marker, so the line must not carry a second copy.
    #[test]
    fn a_line_that_already_names_its_outcome_is_not_marked_twice() {
        assert_eq!(
            rendered("[OK] Pending reboot recorded."),
            " [OK] Pending reboot recorded."
        );
        assert_eq!(
            rendered("[X] Error: could not empty the Recycle Bin"),
            " [X] Error: could not empty the Recycle Bin"
        );
    }

    /// `[STDERR]` says where the line came from, which the `[X]` gutter does not.
    #[test]
    fn a_prefix_the_gutter_does_not_repeat_is_left_alone() {
        assert_eq!(
            rendered("[STDERR] dism reported a problem"),
            " [X] [STDERR] dism reported a problem"
        );
        assert_eq!(
            rendered("Repairing: Browser caches"),
            " > Repairing: Browser caches"
        );
    }
}
