// Everything lives in the `winmedic` library target (see `src/lib.rs`), which is
// also what the integration tests link against. The binary is a thin front end
// over it — declaring `mod app; mod config; …` here again would compile every
// module a second time into a separate, untested set of types.
use winmedic::{config, engine, gui, safety, utils};

use clap::Parser;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::mpsc::channel;
use tokio_util::sync::CancellationToken;

use config::AppConfig;
use engine::exit_code;
use engine::reporter::DiagnosticReporter;
use engine::runner::{DiagnosticEngine, RepairOptions, ScanEvent};
use safety::restore_point::RestorePointService;
use utils::admin::{is_admin, relaunch_as_admin};

#[derive(Parser, Debug)]
#[command(
    name = "WinMedic",
    version,
    about = "WinMedic - Advanced Windows Self-Healing & Diagnostic GUI in Rust",
    long_about = "A high-performance Windows utility that automatically diagnoses, categorizes, and safely repairs Windows errors, update stalls, registry bloat, and network issues.

Started with no arguments it opens its desktop window. Every flag below runs headless instead, reporting to the console it was started from.

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
    /// Anything that runs without opening the window.
    fn is_headless(&self) -> bool {
        self.scan || self.auto_fix || self.json || self.dry_run || self.output.is_some()
    }

    /// Whether a repair pass (real or simulated) should follow the scan.
    fn runs_repairs(&self) -> bool {
        self.auto_fix || self.dry_run
    }
}

fn main() -> ExitCode {
    let args = CliArgs::parse();

    match run(args) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("WinMedic: {}", err);
            ExitCode::from(exit_code::INTERNAL_ERROR)
        }
    }
}

/// Decide which of the two front ends this invocation wants, and give it a
/// runtime.
///
/// Deliberately not `#[tokio::main]`. That attribute would put `main` itself
/// inside a runtime, and `run_gui` has to build one it can hold open for the
/// life of the window — building a runtime from inside another one panics.
/// Each branch therefore owns its own.
fn run(args: CliArgs) -> Result<u8, Box<dyn std::error::Error>> {
    // A binary replaced by an in-place update is still mapped by the process
    // that replaced it, so it cannot delete itself; the next start is the first
    // moment it can go. Best-effort and silent: leftover junk beside the
    // executable is untidy, never a reason to refuse to run.
    utils::self_update::clean_leftovers_beside_current_exe();

    if args.elevate {
        if !is_admin() {
            println!("Requesting Administrator privileges...");
            let _ = relaunch_as_admin();
            return Ok(exit_code::OK);
        }
        println!("Already running with Administrator privileges.");
    }

    if args.is_headless() {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(run_headless(args))
    } else {
        run_gui()
    }
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

    // The other half of the seam described in `run_gui`: a run started from the
    // command line protects the machine the same way the window does, and this
    // is the only other place that says so. Scan and repairs share the one
    // engine, so the restore point covers both.
    let engine =
        Arc::new(DiagnosticEngine::new(&config).with_restore_points(RestorePointService::real()));
    let (tx, mut rx) = channel::<ScanEvent>(100);

    if !quiet {
        DiagnosticReporter::print_banner();
        println!("Starting the WinMedic diagnostic engine...\n");
        if args.dry_run {
            println!("[!] SIMULATION MODE: nothing will be changed.\n");
        }
    }

    let scan_cancel = cancel.clone();
    let engine_for_scan = engine.clone();
    let engine_handle =
        tokio::spawn(async move { engine_for_scan.run_scan(tx, scan_cancel).await });

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

        let (fix_tx, mut fix_rx) = channel(100);
        let options = RepairOptions {
            create_vss: !args.no_vss && config.create_vss_before_repair,
            dry_run: args.dry_run,
            verbose_logging: config.verbose_logging,
        };

        let fix_cancel = cancel.clone();
        let engine_for_fix = engine.clone();
        let mut issues_for_fix = std::mem::take(&mut issues);
        let fix_handle = tokio::spawn(async move {
            let result = engine_for_fix
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

// --------------------------------------------------------------------- GUI

fn run_gui() -> Result<u8, Box<dyn std::error::Error>> {
    // WinMedic links into the console subsystem so that its headless mode keeps
    // its exit codes and its pipes; see `utils::console` for the whole argument.
    // The window has no use for the console that came with it.
    utils::console::release_console_if_owned();

    // The engine is spawned onto tokio from inside the draw loop —
    // `App::start_scan` calls `tokio::spawn` directly — so a runtime has to be
    // current on the thread eframe draws from.
    let runtime = tokio::runtime::Runtime::new()?;

    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("WinMedic")
        .with_inner_size([1280.0, 820.0])
        .with_min_inner_size([960.0, 640.0]);

    // The same mark the executable carries in its PE resources, so the title
    // bar and the taskbar agree with Explorer. A window with no icon still
    // works, which is why a decode failure is not worth refusing to start over.
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/logo.png")) {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    let result = {
        let _guard = runtime.enter();
        eframe::run_native(
            "WinMedic",
            options,
            Box::new(|cc| Ok(Box::new(gui::WinMedicApp::new(cc)))),
        )
    };

    // Shut down rather than drop: a scan can still be in flight when the window
    // closes, and dropping the runtime would block on it. Closing the window
    // should not wait for a DISM call that has not come back yet.
    runtime.shutdown_background();

    result?;
    Ok(exit_code::OK)
}
