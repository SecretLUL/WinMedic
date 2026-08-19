//! Tab 2 — "Health Scan".
//!
//! Every diagnostic module runs at the same time, which is what makes this tab
//! harder to draw than a plain progress bar: there is no single "current" step
//! to report. The modules pane therefore lets each module speak for itself, and
//! puts a running clock on whatever it is doing — some steps shell out to DISM
//! and hold one percentage for minutes, and a stopped number is
//! indistinguishable from a hung program without one.

use crate::engine::issue::{Issue, Severity};
use crate::ui::theme::Theme;
use crate::ui::views::fix_progress::style_console_line;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};
use std::collections::VecDeque;
use std::time::Duration;

/// One module's row in the modules pane.
pub struct ModuleRow<'a> {
    pub name: &'a str,
    pub icon: &'a str,
    pub percent: u8,
    pub is_done: bool,
    pub failed: bool,
    /// What the module last reported it was doing.
    pub step: &'a str,
    /// How long it has been on that step, while it is still running.
    pub step_elapsed: Option<Duration>,
}

pub struct ScannerViewState<'a> {
    pub is_scanning: bool,
    pub overall_progress: u8,
    pub modules: &'a [ModuleRow<'a>],
    pub log_messages: &'a VecDeque<String>,
    pub issues: &'a [Issue],
    pub log_scroll: usize,
    /// Wall-clock time since the scan started.
    pub elapsed: Option<Duration>,
}

/// Frames of the activity marker on a running module.
///
/// Deliberately ASCII: the modules pane is the one place a user stares at while
/// wondering whether the program is alive, which is the worst possible place to
/// risk a missing glyph on a machine still running the raster console font.
const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

/// How long a step has to run before its clock is worth showing.
///
/// Most steps finish inside a second, and a timer flickering on and off next to
/// every one of them reads as noise rather than as reassurance.
const CLOCK_AFTER: Duration = Duration::from_secs(2);

/// Rows a one-line widget in a bordered block needs.
const BAR_HEIGHT: u16 = 3;

/// Below this the live log stops carrying enough scrollback to be worth the
/// row it costs, so the layout changes shape instead of shrinking it further.
const MIN_LOG_HEIGHT: u16 = 5;

pub fn render_scanner(f: &mut Frame, area: Rect, state: &ScannerViewState) {
    let modules_height = state.modules.len() as u16 + 2;

    // Two layouts, chosen by the height available.
    //
    // Given the room, the modules pane spans the full width and each module
    // states its current step on its own line. That step is the whole answer to
    // "what is it doing", and half a terminal width truncates it to uselessness
    // — "Analysing the WinSxS component s..." tells nobody anything. On a short
    // terminal modules and log go back to sharing the row and the step text is
    // what gives way, because seven visible modules beat three detailed ones.
    let full_width = area.height >= modules_height + BAR_HEIGHT * 2 + MIN_LOG_HEIGHT;

    if full_width {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(BAR_HEIGHT),     // Overall progress
                Constraint::Length(modules_height), // Modules, one line each
                Constraint::Min(MIN_LOG_HEIGHT),    // Live log
                Constraint::Length(BAR_HEIGHT),     // Findings summary
            ])
            .split(area);

        render_overall_gauge(f, rows[0], state);
        render_modules(f, rows[1], state, true);
        render_log(f, rows[2], state);
        render_summary(f, rows[3], state.issues);
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(BAR_HEIGHT),
                Constraint::Min(4),
                Constraint::Length(BAR_HEIGHT),
            ])
            .split(area);

        let center = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(rows[1]);

        render_overall_gauge(f, rows[0], state);
        render_modules(f, center[0], state, false);
        render_log(f, center[1], state);
        render_summary(f, rows[2], state.issues);
    }
}

/// The run as a whole: how much is done, and how long it has been going.
///
/// The title used to name the module that reported most recently and the step
/// it was on. With every module running at once that is a lottery, not a
/// status — the winner was whichever module happened to be chatty, never the
/// slow one actually holding the run up.
fn render_overall_gauge(f: &mut Frame, area: Rect, state: &ScannerViewState) {
    let done = state.modules.iter().filter(|m| m.is_done).count();
    let clock = state
        .elapsed
        .map(|d| format!(" - {} elapsed", format_duration(d)))
        .unwrap_or_default();

    let title = if state.is_scanning {
        format!(
            " DIAGNOSTICS RUNNING - {}/{} modules complete{} ",
            done,
            state.modules.len(),
            clock
        )
    } else if done > 0 {
        format!(
            " DIAGNOSTICS COMPLETE - {} modules{} - ready for triage & repair ",
            done, clock
        )
    } else {
        " DIAGNOSTICS - press [S] to start a system health scan ".to_string()
    };

    let color = if state.overall_progress >= 100 {
        Theme::EMERALD
    } else {
        Theme::CYAN
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(color))
                .title(title),
        )
        .gauge_style(Style::default().fg(color).bg(Theme::BG_DEEP))
        .percent(state.overall_progress as u16)
        .label(format!(" {}% ", state.overall_progress));

    f.render_widget(gauge, area);
}

/// Columns consumed by the marker, the percentage and the icon: `" | 100% [CLR] "`.
const ROW_PREFIX_WIDTH: usize = 14;

/// Widest the module-name column may grow before it starts costing the step
/// text room it needs more. The longest name, "System Integrity (DISM / SFC /
/// VSS)", loses its closing bracket here — worth it, because during a scan the
/// name is the part the reader already knows and the step is the part they are
/// waiting on.
const NAME_COLUMN_MAX: usize = 30;

/// One line per module: marker, percentage, icon, name, and — when the layout
/// gave this pane the full width — what the module is doing and for how long.
fn render_modules(f: &mut Frame, area: Rect, state: &ScannerViewState, with_steps: bool) {
    let inner_width = area.width.saturating_sub(2) as usize;

    let spinner = state
        .elapsed
        .map(|d| SPINNER[(d.as_millis() / 150) as usize % SPINNER.len()])
        .unwrap_or(SPINNER[0]);

    // Names share one column width so the step texts start at the same offset.
    // A ragged left edge on seven steps that all update independently is much
    // harder to skim than a straight one.
    let widest_name = state
        .modules
        .iter()
        .map(|m| m.name.chars().count())
        .max()
        .unwrap_or(0);
    let name_col = widest_name
        .min(NAME_COLUMN_MAX)
        .min(inner_width.saturating_sub(ROW_PREFIX_WIDTH) * 2 / 5);

    let items: Vec<ListItem> = state
        .modules
        .iter()
        .map(|module| {
            let (marker, marker_color) = match (module.is_done, module.failed) {
                (_, true) => ('x', Theme::CORAL),
                (true, false) => ('+', Theme::EMERALD),
                (false, false) if state.is_scanning => (spinner, Theme::CYAN),
                _ => ('.', Theme::MUTED),
            };

            let name_style = if module.is_done {
                Style::default().fg(Theme::TEXT_WHITE)
            } else {
                Style::default()
                    .fg(Theme::TEXT_WHITE)
                    .add_modifier(Modifier::BOLD)
            };

            let name_room = if with_steps {
                name_col
            } else {
                inner_width.saturating_sub(ROW_PREFIX_WIDTH)
            };

            let mut spans = vec![
                Span::styled(
                    format!(" {} ", marker),
                    Style::default()
                        .fg(marker_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:>3}% ", module.percent),
                    Style::default().fg(percent_color(module)),
                ),
                Span::styled(
                    format!("{} ", module.icon),
                    Style::default().fg(Theme::CYAN),
                ),
                Span::styled(
                    format!(
                        "{:<width$}",
                        truncate(module.name, name_room),
                        width = name_room
                    ),
                    name_style,
                ),
            ];

            if with_steps {
                spans.extend(step_spans(
                    module,
                    inner_width.saturating_sub(ROW_PREFIX_WIDTH + name_col),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items).block(Theme::card_block("DIAGNOSTIC MODULES"));
    f.render_widget(list, area);
}

/// What this module is doing, and how long it has been doing it.
fn step_spans<'a>(module: &ModuleRow<'a>, room: usize) -> Vec<Span<'a>> {
    let clock = module
        .step_elapsed
        .filter(|d| *d >= CLOCK_AFTER)
        .map(|d| format!("  {}", format_duration(d)))
        .unwrap_or_default();

    let step = if module.step.is_empty() {
        "Waiting to start..."
    } else {
        module.step
    };

    let gap = 2;
    let step_room = room
        .saturating_sub(gap)
        .saturating_sub(clock.chars().count());

    let step_style = if module.failed {
        Style::default().fg(Theme::CORAL)
    } else if module.is_done {
        Style::default().fg(Theme::MUTED)
    } else {
        Style::default().fg(Theme::CYAN)
    };

    vec![
        Span::styled(" ".repeat(gap), Style::default()),
        Span::styled(truncate(step, step_room), step_style),
        // A clock only appears once a step has been running long enough to be
        // worth a second look, so it earns the colour that says "look here".
        Span::styled(clock, Style::default().fg(Theme::AMBER)),
    ]
}

fn percent_color(module: &ModuleRow) -> ratatui::style::Color {
    if module.failed {
        Theme::CORAL
    } else if module.is_done {
        Theme::EMERALD
    } else {
        Theme::AMBER
    }
}

fn render_log(f: &mut Frame, area: Rect, state: &ScannerViewState) {
    let viewport_height = area.height.saturating_sub(2) as usize;
    let total_logs = state.log_messages.len();

    let end_idx = total_logs.saturating_sub(state.log_scroll);
    let start_idx = end_idx.saturating_sub(viewport_height);

    let log_lines: Vec<Line> = (start_idx..end_idx)
        .filter_map(|idx| state.log_messages.get(idx))
        .map(|msg| style_console_line(msg))
        .collect();

    let title = if state.log_scroll > 0 {
        format!(
            " LIVE DIAGNOSTIC LOG [lines {}-{} of {} | End = live] ",
            start_idx + 1,
            end_idx,
            total_logs
        )
    } else {
        format!(
            " LIVE DIAGNOSTIC LOG [{}] [PgUp/PgDn to scroll] ",
            total_logs
        )
    };

    let log_box = Paragraph::new(log_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if state.log_scroll > 0 {
                Theme::AMBER
            } else {
                Theme::BORDER
            }))
            .title(title),
    );
    f.render_widget(log_box, area);
}

fn render_summary(f: &mut Frame, area: Rect, issues: &[Issue]) {
    let count = |severity: Severity| issues.iter().filter(|i| i.severity == severity).count();

    let summary_line = Line::from(vec![
        Span::styled(
            " Scan result: ",
            Style::default()
                .fg(Theme::CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} issues in total ", issues.len()),
            Style::default()
                .fg(Theme::TEXT_WHITE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" [!] {} critical ", count(Severity::Critical)),
            Style::default()
                .fg(Theme::CORAL)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" [!] {} warnings ", count(Severity::Warning)),
            Style::default()
                .fg(Theme::AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Theme::BORDER)),
        Span::styled(
            format!(" [i] {} informational ", count(Severity::Info)),
            Style::default().fg(Theme::CYAN),
        ),
        Span::styled(
            "   -> Press [3] for issue triage & selection ",
            Style::default()
                .fg(Theme::EMERALD)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let summary_bar = Paragraph::new(summary_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::BORDER)),
    );

    f.render_widget(summary_bar, area);
}

/// Cut `text` to `width` columns, marking the cut with an ellipsis.
///
/// Ratatui would clip an overlong span for us, but silently and at whatever the
/// pane edge happens to be; a visible "..." is the difference between a name
/// that is abbreviated and one that looks corrupted.
fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    let kept: String = text.chars().take(width - 3).collect();
    format!("{}...", kept.trim_end())
}

/// Seconds under a minute, `m:ss` above it.
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else {
        format!("{}:{:02}", secs / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn row<'a>(name: &'a str, percent: u8, step: &'a str, secs: u64) -> ModuleRow<'a> {
        ModuleRow {
            name,
            icon: "[CLR]",
            percent,
            is_done: false,
            failed: false,
            step,
            step_elapsed: Some(Duration::from_secs(secs)),
        }
    }

    /// Renders into the *body* area, which is what `render_app` passes: the
    /// header and footer take nine rows off the terminal before this view sees
    /// it, so a 30-row terminal is `height = 21` here.
    fn screen(state: &ScannerViewState, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|f| render_scanner(f, f.area(), state))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn state<'a>(modules: &'a [ModuleRow<'a>], logs: &'a VecDeque<String>) -> ScannerViewState<'a> {
        ScannerViewState {
            is_scanning: true,
            overall_progress: 30,
            modules,
            log_messages: logs,
            issues: &[],
            log_scroll: 0,
            elapsed: Some(Duration::from_secs(75)),
        }
    }

    /// The reported bug: a module parked on a long DISM call showed a bare
    /// "10%" and nothing else, so it was indistinguishable from a hang.
    #[test]
    fn a_running_module_shows_what_it_is_doing_and_for_how_long() {
        let logs = VecDeque::new();
        let modules = [row(
            "System & Cache Cleaner",
            10,
            "Analysing the WinSxS component store (DISM, 1-2 min)...",
            62,
        )];
        let rendered = screen(&state(&modules, &logs), 120, 21);

        assert!(rendered.contains("System & Cache Cleaner"));
        assert!(
            rendered.contains("Analysing the WinSxS component store (DISM, 1-2 min)..."),
            "the step, in full, on the module's own row: {rendered}"
        );
        assert!(
            rendered.contains("1:02"),
            "and how long it has been running: {rendered}"
        );
    }

    /// The step is the answer to the user's question, so the layout has to keep
    /// it whole at the sizes people actually run a terminal at — with all seven
    /// modules present, which is what sets the name column width.
    ///
    /// These two are the longest step labels the modules emit; if a new one
    /// outgrows them, this is where that shows up rather than on a user's
    /// screen as "Checking the Windows Update services (wuause...".
    #[test]
    fn the_longest_steps_survive_intact_at_ordinary_terminal_sizes() {
        let logs = VecDeque::new();
        let names = [
            "Network & DNS Connectivity",
            "Storage & File System",
            "System & Cache Cleaner",
            "Windows Update & Services",
            "Registry & Autostart",
            "Event-Log & Crash-Dump Analyse",
            "System Integrity (DISM / SFC / VSS)",
        ];

        for step in [
            "Checking the Windows Update services (wuauserv, bits, cryptsvc)...",
            "Analysing the WinSxS component store (DISM, 1-2 min)...",
        ] {
            let modules: Vec<ModuleRow> = names.iter().map(|n| row(n, 10, step, 62)).collect();
            // Body heights for 30-, 36- and 60-row terminals.
            for (w, h) in [(120, 21), (140, 27), (200, 51)] {
                let rendered = screen(&state(&modules, &logs), w, h);
                assert!(
                    rendered.contains(step),
                    "'{step}' was cut short at {w}x{h}:\n{rendered}"
                );
            }
        }
    }

    /// A step that has only just started does not need a clock next to it.
    #[test]
    fn a_short_step_is_not_cluttered_with_a_timer() {
        let logs = VecDeque::new();
        let modules = [row("Network & DNS Connectivity", 20, "Testing DNS...", 1)];
        let rendered = screen(&state(&modules, &logs), 100, 30);

        assert!(rendered.contains("Testing DNS..."));
        assert!(!rendered.contains("1s"), "got: {rendered}");
    }

    /// The header has to describe the run, not whichever module spoke last.
    #[test]
    fn the_gauge_counts_completed_modules_rather_than_naming_one() {
        let logs = VecDeque::new();
        let mut modules = [
            row("Network & DNS Connectivity", 100, "Finished", 0),
            row("System & Cache Cleaner", 10, "Analysing...", 62),
        ];
        modules[0].is_done = true;

        let rendered = screen(&state(&modules, &logs), 100, 30);
        assert!(rendered.contains("1/2 modules complete"), "got: {rendered}");
        assert!(rendered.contains("1:15 elapsed"), "got: {rendered}");
    }

    /// A failed module has stopped working and must stop looking busy.
    #[test]
    fn a_failed_module_is_marked_as_finished_not_as_running() {
        let logs = VecDeque::new();
        let mut modules = [row(
            "Storage & File System",
            100,
            "Failed - access denied",
            0,
        )];
        modules[0].is_done = true;
        modules[0].failed = true;

        let rendered = screen(&state(&modules, &logs), 100, 30);
        assert!(
            rendered.contains("Failed - access denied"),
            "got: {rendered}"
        );
        assert!(rendered.contains(" x "), "the failure marker: {rendered}");
    }

    /// On a terminal too short for the stacked layout the step text is what
    /// gives way — every module stays listed, and the log keeps its pane.
    #[test]
    fn a_short_terminal_keeps_every_module_and_the_log_visible() {
        let logs = VecDeque::new();
        let names = [
            "Network & DNS Connectivity",
            "Storage & File System",
            "System & Cache Cleaner",
            "Windows Update & Services",
            "Registry & Autostart",
            "Event-Log & Crash-Dump Analyse",
            "System Integrity (DISM / SFC / VSS)",
        ];
        let modules: Vec<ModuleRow> = names
            .iter()
            .map(|n| row(n, 10, "Analysing the WinSxS component store...", 30))
            .collect();

        // The body of an 80x24 terminal, the smallest size the app supports.
        let rendered = screen(&state(&modules, &logs), 80, 15);

        // Names are abbreviated hard at this width, so match on enough of each
        // to tell them apart rather than on an assumed truncation point.
        for name in names {
            let identifiable: String = name.chars().take(15).collect();
            assert!(
                rendered.contains(&identifiable),
                "module '{name}' fell off the pane:\n{rendered}"
            );
        }
        assert!(
            rendered.contains("LIVE DIAGNOSTIC LOG"),
            "the log keeps its pane:\n{rendered}"
        );
    }

    #[test]
    fn durations_read_as_seconds_below_a_minute_and_clock_time_above() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1:00");
        assert_eq!(format_duration(Duration::from_secs(125)), "2:05");
        assert_eq!(format_duration(Duration::from_secs(3600)), "60:00");
    }

    #[test]
    fn truncation_marks_the_cut_and_never_exceeds_the_width() {
        assert_eq!(truncate("short", 20), "short");
        assert_eq!(truncate("System Integrity (DISM)", 12), "System In...");
        assert_eq!(truncate("anything", 2), "..");
        for width in 0..30 {
            assert!(
                truncate("System Integrity (DISM / SFC / VSS)", width)
                    .chars()
                    .count()
                    <= width
            );
        }
    }
}
