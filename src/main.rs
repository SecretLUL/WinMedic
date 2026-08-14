#![allow(dead_code)]

mod app;
mod config;
mod engine;
mod modules;
mod safety;
mod ui;
mod utils;

use clap::Parser;
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
use std::time::{Duration, Instant};
use tokio::sync::mpsc::channel;

use app::App;
use engine::reporter::DiagnosticReporter;
use engine::runner::{DiagnosticEngine, ScanEvent};
use utils::admin::{is_admin, relaunch_as_admin};

#[derive(Parser, Debug)]
#[command(
    name = "WinMedic",
    version = "0.1.0",
    about = "🩺 WinMedic – Advanced Windows Self-Healing & Diagnostic TUI in Rust",
    long_about = "A high-performance terminal utility that automatically diagnoses, categorizes, and safely repairs Windows errors, update stalls, registry bloat, and network issues."
)]
struct CliArgs {
    /// Run diagnostic scan in headless CLI mode and output report
    #[arg(short, long)]
    scan: bool,

    /// Automatically repair all safe detected issues in headless mode
    #[arg(short, long)]
    auto_fix: bool,

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    if args.elevate {
        if !is_admin() {
            println!("Fordere Administratorrechte an...");
            let _ = relaunch_as_admin();
            return Ok(());
        } else {
            println!("Bereits mit Administratorrechten ausgeführt.");
        }
    }

    // Headless CLI Mode
    if args.scan || args.auto_fix || args.json {
        let engine = DiagnosticEngine::new();
        let (tx, mut rx) = channel::<ScanEvent>(100);

        if !args.json {
            DiagnosticReporter::print_banner();
            println!("Starte WinMedic Diagnose-Engine...\n");
        }

        let engine_handle = tokio::spawn(async move { engine.run_scan(tx).await });

        while let Some(evt) = rx.recv().await {
            if !args.json {
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
                    _ => {}
                }
            }
        }

        let mut issues = engine_handle.await?;
        let health = DiagnosticEngine::calculate_health_score(&issues);

        if args.json {
            println!("{}", DiagnosticReporter::to_json(&issues, health));
        } else {
            DiagnosticReporter::print_cli_report(&issues, health);
        }

        if args.auto_fix {
            if !args.json {
                println!("\n⚡ Starte automatische Reparatur...");
            }
            let engine = DiagnosticEngine::new();
            let (fix_tx, mut fix_rx) = channel(100);
            let create_vss = !args.no_vss;

            let fix_handle =
                tokio::spawn(
                    async move { engine.run_repairs(&mut issues, create_vss, fix_tx).await },
                );

            while let Some(evt) = fix_rx.recv().await {
                if !args.json {
                    match evt {
                        engine::runner::RepairEvent::VssStarted => {
                            println!("🛡 Erstelle Windows Systemwiederherstellungspunkt...")
                        }
                        engine::runner::RepairEvent::VssCompleted { success, message } => println!(
                            "   └─ VSS Status: {} ({})",
                            if success { "Erstellt" } else { "Hinweis" },
                            message
                        ),
                        engine::runner::RepairEvent::FixStarted { title, .. } => {
                            println!("🔧 Behebe: {}", title)
                        }
                        engine::runner::RepairEvent::FixOutput { line, .. } => {
                            println!("   [LOG] {}", line)
                        }
                        engine::runner::RepairEvent::FixFinished {
                            success, message, ..
                        } => {
                            if success {
                                println!("   ✔ Behoben: {}", message);
                            } else {
                                println!("   ✖ Fehlgeschlagen: {}", message);
                            }
                        }
                        _ => {}
                    }
                }
            }

            let (fixed, failed) = fix_handle.await?;
            if !args.json {
                println!(
                    "\n🎉 Reparatur abgeschlossen: {} behoben, {} fehlgeschlagen.\n",
                    fixed, failed
                );
            }
        }

        return Ok(());
    }

    // Interactive Ratatui TUI Mode
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let mut last_telemetry_tick = Instant::now();

    loop {
        // Render UI Frame
        terminal.draw(|f| {
            ui::render_app(f, &app);
        })?;

        // Poll events
        if event::poll(Duration::from_millis(40))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if app.show_help {
                        match key.code {
                            KeyCode::Char('?')
                            | KeyCode::Esc
                            | KeyCode::Char('q')
                            | KeyCode::Char('Q') => {
                                app.show_help = false;
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') => {
                                app.should_quit = true;
                            }
                            KeyCode::Char('?') => {
                                app.show_help = true;
                            }
                            KeyCode::Char('1') => app.active_tab = 0,
                            KeyCode::Char('2') => app.active_tab = 1,
                            KeyCode::Char('3') => app.active_tab = 2,
                            KeyCode::Char('4') => app.active_tab = 3,
                            KeyCode::Char('5') => {
                                app.active_tab = 4;
                                app.load_history_data();
                            }
                            KeyCode::Tab => {
                                app.active_tab = (app.active_tab + 1) % 5;
                                if app.active_tab == 4 {
                                    app.load_history_data();
                                }
                            }
                            KeyCode::BackTab => {
                                if app.active_tab == 0 {
                                    app.active_tab = 4;
                                } else {
                                    app.active_tab -= 1;
                                }
                            }
                            KeyCode::Char('s') | KeyCode::Char('S') => {
                                app.start_scan();
                            }
                            KeyCode::Char('r') | KeyCode::Char('R') => {
                                app.start_scan();
                            }
                            KeyCode::Char('f') | KeyCode::Char('F') => {
                                if app.active_tab == 2 || app.active_tab == 3 {
                                    app.start_repairs();
                                } else {
                                    app.active_tab = 2;
                                }
                            }
                            KeyCode::Char('a') | KeyCode::Char('A') => {
                                if app.active_tab == 0 {
                                    app.start_scan();
                                } else {
                                    app.select_all_issues();
                                }
                            }
                            KeyCode::Char('n') | KeyCode::Char('N') => {
                                app.deselect_all_issues();
                            }
                            KeyCode::Char(' ') => {
                                if app.active_tab == 2 {
                                    app.toggle_selected_issue();
                                }
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if app.active_tab == 2 {
                                    app.prev_issue();
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                if app.active_tab == 2 {
                                    app.next_issue();
                                }
                            }
                            KeyCode::Esc => {
                                if app.active_tab != 0 {
                                    app.active_tab = 0;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Process background scan / fix channels
        app.process_background_events();

        // Refresh telemetry every 1 second
        if last_telemetry_tick.elapsed() >= Duration::from_secs(1) {
            app.refresh_telemetry();
            last_telemetry_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
