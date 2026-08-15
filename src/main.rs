// Everything lives in the `winmedic` library target (see `src/lib.rs`), which is
// also what the integration tests link against. The binary is a thin front end
// over it — declaring `mod app; mod config; …` here again would compile every
// module a second time into a separate, untested set of types.
use winmedic::{app, config, engine, safety, ui, utils};

use clap::Parser;
use crossterm::cursor::Show;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
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

use app::{App, handle_key};
use config::AppConfig;
use engine::exit_code;
use engine::reporter::DiagnosticReporter;
use engine::runner::{DiagnosticEngine, RepairOptions, ScanEvent};
use utils::admin::{is_admin, relaunch_as_admin};

#[derive(Parser, Debug)]
#[command(
    name = "WinMedic",
    version,
    about = "WinMedic - Advanced Windows Self-Healing & Diagnostic TUI in Rust",
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

    /// Save report to file (.html, .md, or .json based on extension)
    #[arg(short, long, value_name = "FILE")]
    output: Option<std::path::PathBuf>,

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
        self.scan || self.auto_fix || self.json || self.dry_run || self.output.is_some()
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
            println!("Requesting Administrator privileges...");
            let _ = relaunch_as_admin();
            return Ok(exit_code::OK);
        }
        println!("Already running with Administrator privileges.");
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
        eprintln!("\nWinMedic crashed unexpectedly. The terminal has been restored.");
        default_hook(info);
    }));
}

// ---------------------------------------------------------------- headless

// Scoped rather than a crate-level allow list: the library crate root carries
// its own, and duplicating it here is what this file just stopped doing.
#[allow(clippy::single_match)]
async fn run_headless(args: CliArgs) -> Result<u8, Box<dyn std::error::Error>> {
    // Real repairs without elevation just produce a wall of access-denied
    // errors, so refuse up front with a code a script can branch on.
    if args.auto_fix && !args.dry_run && !is_admin() {
        eprintln!(
            "Administrator privileges required: '--auto-fix' can only repair system files, services and the registry as Administrator.\nStart WinMedic from an elevated console, or use '--elevate'."
        );
        return Ok(exit_code::NEEDS_ADMIN);
    }

    let (config, config_status) = AppConfig::load_reporting();
    // Goes to stderr so it cannot corrupt `--json` output being piped into
    // something. A run using default settings the user did not choose is worth
    // knowing about even in a scripted context.
    if let Some(warning) = config_status.warning() {
        eprintln!("WinMedic: {}", warning);
    }
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
        println!("Starting the WinMedic diagnostic engine...\n");
        if args.dry_run {
            println!("[!] SIMULATION MODE: nothing will be changed.\n");
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
            ScanEvent::ModuleStarted(id) => println!("Scanning module '{}'...", id),
            ScanEvent::ModuleProgressUpdate(prog) => {
                if let Some(msg) = prog.log_message {
                    println!("   └─ {}", msg);
                }
            }
            ScanEvent::ModuleFinished { module_id, issues } => {
                println!(
                    "[OK] Module '{}' finished ({} issues found)",
                    module_id,
                    issues.len()
                );
            }
            ScanEvent::ModuleFailed { module_id, error } => {
                println!("[X] Module '{}' failed: {}", module_id, error);
            }
            ScanEvent::ScanCancelled {
                completed_modules,
                total_modules,
            } => {
                println!(
                    "\n[STOP] Cancelled after {}/{} modules.",
                    completed_modules, total_modules
                );
            }
            ScanEvent::ScanCompleted { .. } => {}
        }
    }

    let mut issues = engine_handle.await?;

    let audit_logger = safety::audit::AuditLogger::new();

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
            DiagnosticReporter::to_json(
                &issues,
                DiagnosticEngine::calculate_health_score(&issues),
                &audit_logger.get_history()
            )
        );
    }

    let mut failed_fixes = 0;
    let mut repairs_cancelled = false;

    if args.runs_repairs() && !scan_cancelled {
        if !quiet {
            println!(
                "\n{}",
                if args.dry_run {
                    "Simulating repairs (nothing will be changed)..."
                } else {
                    "Starting automatic repairs..."
                }
            );
        }

        let engine = DiagnosticEngine::new(&config);
        let (fix_tx, mut fix_rx) = channel(100);
        let options = RepairOptions {
            create_vss: !args.no_vss && config.create_vss_before_repair,
            dry_run: args.dry_run,
            verbose_logging: config.verbose_logging,
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
                    println!("Simulating {} issue(s).", issue_count)
                }
                RepairEvent::VssStarted => {
                    println!("Creating a Windows System Restore point...")
                }
                RepairEvent::VssCompleted { success, message } => println!(
                    "   └─ VSS Status: {} ({})",
                    if success { "Created" } else { "Notice" },
                    message
                ),
                RepairEvent::FixStarted { title, .. } => println!("Fix: {}", title),
                RepairEvent::FixOutput { line, .. } => println!("   [LOG] {}", line),
                RepairEvent::FixFinished {
                    success, message, ..
                } => {
                    if success {
                        println!("   [OK] {}", message);
                    } else {
                        println!("   [X] Failed: {}", message);
                    }
                }
                RepairEvent::RepairsCancelled {
                    fixed_count,
                    failed_count,
                    remaining,
                } => println!(
                    "\n[STOP] Cancelled: {} done, {} failed, {} skipped.",
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
                "\n{}: {} {}, {} failed.\n",
                if args.dry_run {
                    "Simulation finished"
                } else {
                    "Repairs finished"
                },
                fixed,
                if args.dry_run { "planned" } else { "fixed" },
                failed
            );
        }
    }

    if defer_json {
        println!(
            "{}",
            DiagnosticReporter::to_json(
                &issues,
                DiagnosticEngine::calculate_health_score(&issues),
                &audit_logger.get_history()
            )
        );
    }

    if let Some(ref out_path) = args.output {
        let health = DiagnosticEngine::calculate_health_score(&issues);
        let audit_entries = audit_logger.get_history();
        match DiagnosticReporter::save_report(out_path, &issues, health, &audit_entries) {
            Ok(()) => {
                if !quiet {
                    println!("Report saved: {}", out_path.display());
                }
            }
            Err(e) => {
                eprintln!(
                    "Could not save the report to '{}': {}",
                    out_path.display(),
                    e
                );
            }
        }
    }

    let code = if scan_cancelled || repairs_cancelled {
        exit_code::CANCELLED
    } else {
        exit_code::from_issues(&issues, failed_fixes)
    };

    if !quiet {
        println!("Exit code {}: {}", code, exit_code::describe(code));
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
    app.start_update_check();
    let mut last_telemetry_tick = Instant::now();

    let loop_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        loop {
            terminal.draw(|f| {
                ui::render_app(f, &app);
            })?;

            // `event::read()` only runs when `poll` said something is waiting,
            // so short-circuiting keeps it from blocking the draw loop.
            if event::poll(Duration::from_millis(40))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                handle_key(&mut app, key.code);
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
