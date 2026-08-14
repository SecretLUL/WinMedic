#![allow(
    dead_code,
    clippy::too_many_arguments,
    clippy::collapsible_if,
    clippy::new_without_default,
    clippy::collapsible_str_replace,
    clippy::manual_let_else,
    clippy::iter_kv_map,
    clippy::single_match
)]

mod app;
mod config;
mod engine;
mod modules;
mod safety;
mod ui;
mod utils;

use clap::Parser;
use crossterm::cursor::Show;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::stdout;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::channel;
use tokio_util::sync::CancellationToken;

use app::{App, TAB_COUNT, TAB_DASHBOARD, TAB_HISTORY, TAB_REPAIR, TAB_SETTINGS, TAB_TRIAGE};
use config::AppConfig;
use engine::exit_code;
use engine::reporter::DiagnosticReporter;
use engine::runner::{DiagnosticEngine, RepairOptions, ScanEvent};
use utils::admin::{is_admin, relaunch_as_admin};

#[derive(Parser, Debug)]
#[command(
    name = "WinMedic",
    version,
    about = "🩺 WinMedic – Advanced Windows Self-Healing & Diagnostic TUI in Rust",
    long_about = "A high-performance terminal utility that automatically diagnoses, categorizes, and safely repairs Windows errors, update stalls, registry bloat, and network issues.

Exit codes (headless mode):
  0  no open issues above info level
  1  open warnings
  2  open critical issues
  3  at least one repair failed
  4  Administrator privileges required
  5  internal error
  6  aborted with Ctrl+C"
)]
struct CliArgs {
    /// Run diagnostic scan in headless CLI mode and output report
    #[arg(short, long)]
    scan: bool,

    /// Automatically repair all safe detected issues in headless mode
    #[arg(short, long)]
    auto_fix: bool,

    /// Show what would be repaired without changing anything (implies a scan)
    #[arg(short, long)]
    dry_run: bool,

    /// Output scan results as JSON
    #[arg(short, long)]
    json: bool,

    /// Skip creating a Windows System Restore point before repairs
    #[arg(long)]
    no_vss: bool,

    /// Request Windows Administrator elevation
    #[arg(short, long)]
    elevate: bool,
}

impl CliArgs {
    /// Anything that runs without the interactive TUI.
    fn is_headless(&self) -> bool {
        self.scan || self.auto_fix || self.json || self.dry_run
    }

    /// Whether a repair pass (real or simulated) should follow the scan.
    fn runs_repairs(&self) -> bool {
        self.auto_fix || self.dry_run
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = CliArgs::parse();

    match run(args).await {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            // The TUI path may have died mid-frame; make sure the terminal is
            // usable before the error reaches the user.
            restore_terminal();
            eprintln!("WinMedic: {}", err);
            ExitCode::from(exit_code::INTERNAL_ERROR)
        }
    }
}

async fn run(args: CliArgs) -> Result<u8, Box<dyn std::error::Error>> {
    if args.elevate {
        if !is_admin() {
            println!("Fordere Administratorrechte an...");
            let _ = relaunch_as_admin();
            return Ok(exit_code::OK);
        }
        println!("Bereits mit Administratorrechten ausgeführt.");
    }

    if args.is_headless() {
        run_headless(args).await
    } else {
        run_tui().await
    }
}

/// Put the terminal back into a usable state.
///
/// Safe to call more than once and safe to call when the TUI never started —
/// which is what makes it usable from the panic hook.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture, Show);
}

/// Install a panic hook that hands the terminal back before printing.
///
/// Without this a panic inside the draw loop leaves the user with a terminal
/// stuck in raw mode on the alternate screen: no echo, no cursor, no output.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        eprintln!("\nWinMedic ist unerwartet abgestürzt. Das Terminal wurde zurückgesetzt.");
        default_hook(info);
    }));
}

// ---------------------------------------------------------------- headless

async fn run_headless(args: CliArgs) -> Result<u8, Box<dyn std::error::Error>> {
    // Real repairs without elevation just produce a wall of access-denied
    // errors, so refuse up front with a code a script can branch on.
    if args.auto_fix && !args.dry_run && !is_admin() {
        eprintln!(
            "Administratorrechte erforderlich: '--auto-fix' kann Systemdateien, Dienste und die Registry nur als Administrator reparieren.\nStarten Sie WinMedic in einer erhöhten Konsole oder verwenden Sie '--elevate'."
        );
        return Ok(exit_code::NEEDS_ADMIN);
    }

    let config = AppConfig::load();
    let quiet = args.json;

    // Ctrl+C cancels the run instead of leaving orphaned DISM/chkdsk children.
    let cancel = CancellationToken::new();
    let ctrlc_token = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            ctrlc_token.cancel();
        }
    });

    let engine = DiagnosticEngine::new(&config);
    let (tx, mut rx) = channel::<ScanEvent>(100);

    if !quiet {
        DiagnosticReporter::print_banner();
        println!("Starte WinMedic Diagnose-Engine...\n");
        if args.dry_run {
            println!("⚠ SIMULATIONSMODUS: Es werden keine Änderungen vorgenommen.\n");
        }
    }

    let scan_cancel = cancel.clone();
    let engine_handle = tokio::spawn(async move { engine.run_scan(tx, scan_cancel).await });

    let mut scan_cancelled = false;
    while let Some(evt) = rx.recv().await {
        match evt {
            ScanEvent::ScanCancelled { .. } => scan_cancelled = true,
            _ => {}
        }
        if quiet {
            continue;
        }
        match evt {
            ScanEvent::ModuleStarted(id) => println!("⏳ Scanne Modul '{}'...", id),
            ScanEvent::ModuleProgressUpdate(prog) => {
                if let Some(msg) = prog.log_message {
                    println!("   └─ {}", msg);
                }
            }
            ScanEvent::ModuleFinished { module_id, issues } => {
                println!(
                    "✔ Modul '{}' fertig ({} Probleme gefunden)",
                    module_id,
                    issues.len()
                );
            }
            ScanEvent::ModuleFailed { module_id, error } => {
                println!("✖ Modul '{}' fehlgeschlagen: {}", module_id, error);
            }
            ScanEvent::ScanCancelled {
                completed_modules,
                total_modules,
            } => {
                println!(
                    "\n⏹ Abgebrochen nach {}/{} Modulen.",
                    completed_modules, total_modules
                );
            }
            ScanEvent::ScanCompleted { .. } => {}
        }
    }

    let mut issues = engine_handle.await?;

    // With repairs to follow, the JSON document is emitted at the very end so it
    // reflects the post-repair state instead of a snapshot that is already stale.
    let defer_json = args.json && args.runs_repairs() && !scan_cancelled;
    if !args.json {
        DiagnosticReporter::print_cli_report(
            &issues,
            DiagnosticEngine::calculate_health_score(&issues),
        );
    } else if !defer_json {
        println!(
            "{}",
            DiagnosticReporter::to_json(&issues, DiagnosticEngine::calculate_health_score(&issues))
        );
    }

    let mut failed_fixes = 0;
    let mut repairs_cancelled = false;

    if args.runs_repairs() && !scan_cancelled {
        if !quiet {
            println!(
                "\n{}",
                if args.dry_run {
                    "🔍 Simuliere Reparaturen (keine Änderungen)..."
                } else {
                    "⚡ Starte automatische Reparatur..."
                }
            );
        }

        let engine = DiagnosticEngine::new(&config);
        let (fix_tx, mut fix_rx) = channel(100);
        let options = RepairOptions {
            create_vss: !args.no_vss && config.create_vss_before_repair,
            dry_run: args.dry_run,
        };

        let fix_cancel = cancel.clone();
        let mut issues_for_fix = std::mem::take(&mut issues);
        let fix_handle = tokio::spawn(async move {
            let result = engine
                .run_repairs(&mut issues_for_fix, options, fix_tx, fix_cancel)
                .await;
            (issues_for_fix, result)
        });

        while let Some(evt) = fix_rx.recv().await {
            use engine::runner::RepairEvent;
            if let RepairEvent::RepairsCancelled { .. } = evt {
                repairs_cancelled = true;
            }
            if quiet {
                continue;
            }
            match evt {
                RepairEvent::DryRunStarted { issue_count } => {
                    println!("🔍 {} Problem(e) werden simuliert.", issue_count)
                }
                RepairEvent::VssStarted => {
                    println!("🛡 Erstelle Windows Systemwiederherstellungspunkt...")
                }
                RepairEvent::VssCompleted { success, message } => println!(
                    "   └─ VSS Status: {} ({})",
                    if success { "Erstellt" } else { "Hinweis" },
                    message
                ),
                RepairEvent::FixStarted { title, .. } => println!("🔧 {}", title),
                RepairEvent::FixOutput { line, .. } => println!("   [LOG] {}", line),
                RepairEvent::FixFinished {
                    success, message, ..
                } => {
                    if success {
                        println!("   ✔ {}", message);
                    } else {
                        println!("   ✖ Fehlgeschlagen: {}", message);
                    }
                }
                RepairEvent::RepairsCancelled {
                    fixed_count,
                    failed_count,
                    remaining,
                } => println!(
                    "\n⏹ Abgebrochen: {} erledigt, {} fehlgeschlagen, {} übersprungen.",
                    fixed_count, failed_count, remaining
                ),
                RepairEvent::AllRepairsCompleted { .. } => {}
            }
        }

        let (fixed_issues, (fixed, failed)) = fix_handle.await?;
        issues = fixed_issues;
        failed_fixes = failed;

        if !quiet {
            println!(
                "\n🎉 {}: {} {}, {} fehlgeschlagen.\n",
                if args.dry_run {
                    "Simulation abgeschlossen"
                } else {
                    "Reparatur abgeschlossen"
                },
                fixed,
                if args.dry_run { "geplant" } else { "behoben" },
                failed
            );
        }
    }

    if defer_json {
        println!(
            "{}",
            DiagnosticReporter::to_json(&issues, DiagnosticEngine::calculate_health_score(&issues))
        );
    }

    let code = if scan_cancelled || repairs_cancelled {
        exit_code::CANCELLED
    } else {
        exit_code::from_issues(&issues, failed_fixes)
    };

    if !quiet {
        println!("Exit-Code {}: {}", code, exit_code::describe(code));
    }

    Ok(code)
}

// --------------------------------------------------------------------- TUI

async fn run_tui() -> Result<u8, Box<dyn std::error::Error>> {
    install_panic_hook();

    enable_raw_mode()?;
    let mut stdout_handle = stdout();
    execute!(stdout_handle, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout_handle);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let mut last_telemetry_tick = Instant::now();

    let loop_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        loop {
            terminal.draw(|f| {
                ui::render_app(f, &app);
            })?;

            if event::poll(Duration::from_millis(40))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        handle_key(&mut app, key.code);
                    }
                }
            }

            app.process_background_events();

            if last_telemetry_tick.elapsed() >= Duration::from_secs(1) {
                app.refresh_telemetry();
                last_telemetry_tick = Instant::now();
            }

            if app.should_quit {
                return Ok(());
            }
        }
    })();

    restore_terminal();
    loop_result?;

    Ok(exit_code::OK)
}

fn handle_key(app: &mut App, code: KeyCode) {
    // A pending confirmation swallows every other key.
    if app.pending_confirm.is_some() {
        match code {
            KeyCode::Char('j')
            | KeyCode::Char('J')
            | KeyCode::Char('y')
            | KeyCode::Char('Y')
            | KeyCode::Enter => app.confirm_pending_action(),
            _ => app.dismiss_confirm(),
        }
        return;
    }

    if app.show_help {
        match code {
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                app.show_help = false;
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,
        KeyCode::Char('?') => app.show_help = true,

        KeyCode::Char('1') => app.active_tab = 0,
        KeyCode::Char('2') => app.active_tab = 1,
        KeyCode::Char('3') => app.active_tab = 2,
        KeyCode::Char('4') => app.active_tab = 3,
        KeyCode::Char('5') => {
            app.active_tab = TAB_HISTORY;
            app.load_history_data();
        }
        KeyCode::Char('6') => app.active_tab = TAB_SETTINGS,

        KeyCode::Tab => {
            app.active_tab = (app.active_tab + 1) % TAB_COUNT;
            if app.active_tab == TAB_HISTORY {
                app.load_history_data();
            }
        }
        KeyCode::BackTab => {
            app.active_tab = if app.active_tab == 0 {
                TAB_COUNT - 1
            } else {
                app.active_tab - 1
            };
            if app.active_tab == TAB_HISTORY {
                app.load_history_data();
            }
        }

        KeyCode::Char('s') | KeyCode::Char('S') => app.start_scan(),
        KeyCode::Char('r') | KeyCode::Char('R') => {
            if app.active_tab == TAB_HISTORY {
                app.load_history_data();
                app.refresh_restore_points();
            } else {
                app.start_scan();
            }
        }

        KeyCode::Char('d') | KeyCode::Char('D') => app.toggle_dry_run(),

        KeyCode::Char('f') | KeyCode::Char('F') => {
            if app.active_tab == TAB_TRIAGE || app.active_tab == TAB_REPAIR {
                app.start_repairs();
            } else {
                app.active_tab = TAB_TRIAGE;
            }
        }

        KeyCode::Char('a') | KeyCode::Char('A') => {
            if app.active_tab == TAB_DASHBOARD {
                app.start_scan();
            } else {
                app.select_all_issues();
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') => app.deselect_all_issues(),

        KeyCode::Char('u') | KeyCode::Char('U') => {
            if app.active_tab == TAB_HISTORY {
                app.request_rollback();
            }
        }

        KeyCode::Char(' ') | KeyCode::Enter => match app.active_tab {
            TAB_TRIAGE => app.toggle_selected_issue(),
            TAB_SETTINGS => app.toggle_current_setting(),
            _ => {}
        },

        KeyCode::Up | KeyCode::Char('k') => match app.active_tab {
            TAB_TRIAGE => app.prev_issue(),
            TAB_HISTORY => app.prev_backup(),
            TAB_SETTINGS => app.prev_setting(),
            _ => {}
        },
        KeyCode::Down | KeyCode::Char('j') => match app.active_tab {
            TAB_TRIAGE => app.next_issue(),
            TAB_HISTORY => app.next_backup(),
            TAB_SETTINGS => app.next_setting(),
            _ => {}
        },

        KeyCode::Left | KeyCode::Char('h') => {
            if app.active_tab == TAB_SETTINGS {
                app.adjust_current_setting(false);
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if app.active_tab == TAB_SETTINGS {
                app.adjust_current_setting(true);
            }
        }

        // Esc cancels a running operation first, and only then navigates back.
        KeyCode::Esc => {
            if !app.cancel_current_operation() && app.active_tab != TAB_DASHBOARD {
                app.active_tab = TAB_DASHBOARD;
            }
        }

        _ => {}
    }
}
