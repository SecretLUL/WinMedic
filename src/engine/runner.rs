use crate::config::AppConfig;
use crate::engine::issue::{Issue, Severity};
use crate::modules::{
    DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress, get_all_modules,
    get_all_modules_with_runner,
};
use crate::safety::audit::AuditLogger;
use crate::safety::restore_point::RestorePointService;
use crate::utils::admin::is_admin;
use crate::utils::cmd::{CommandRunner, describe_os_error};
use crate::utils::debug_log::{
    DebugTag, extract_os_error_code, render_debug_kv, render_debug_line,
};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc::{Sender, channel};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub enum ScanEvent {
    ModuleStarted(String),
    ModuleProgressUpdate(ModuleProgress),
    ModuleFinished {
        module_id: String,
        issues: Vec<Issue>,
    },
    ModuleFailed {
        module_id: String,
        error: String,
    },
    ScanCancelled {
        completed_modules: usize,
        total_modules: usize,
    },
    ScanCompleted {
        total_issues: usize,
        health_score: u8,
    },
}

#[derive(Debug, Clone)]
pub enum RepairEvent {
    /// Emitted instead of [`RepairEvent::VssStarted`] when running a simulation.
    DryRunStarted {
        issue_count: usize,
    },
    VssStarted,
    VssCompleted {
        success: bool,
        message: String,
    },
    FixStarted {
        issue_id: String,
        title: String,
    },
    FixOutput {
        issue_id: String,
        line: String,
    },
    FixFinished {
        issue_id: String,
        success: bool,
        message: String,
    },
    RepairsCancelled {
        fixed_count: usize,
        failed_count: usize,
        remaining: usize,
    },
    AllRepairsCompleted {
        fixed_count: usize,
        failed_count: usize,
    },
}

/// How a repair run should behave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairOptions {
    /// Create a VSS restore point before touching anything.
    pub create_vss: bool,
    /// Report what each fix *would* do without executing it.
    pub dry_run: bool,
    /// Output detailed debug logs during repairs.
    pub verbose_logging: bool,
}

impl RepairOptions {
    pub fn from_config(config: &AppConfig, dry_run: bool) -> Self {
        Self {
            create_vss: config.create_vss_before_repair,
            dry_run,
            verbose_logging: config.verbose_logging,
        }
    }
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            create_vss: true,
            dry_run: false,
            verbose_logging: false,
        }
    }
}

/// Verbose tracing for the repair loop itself.
///
/// The modules trace through [`crate::utils::debug_log::DebugTrace`], which
/// writes into their own progress channel. The engine sits one level above that
/// and owns the repair event channel instead, so it renders the same line
/// format into [`RepairEvent::FixOutput`].
struct RepairTrace<'a> {
    event_tx: &'a Sender<RepairEvent>,
    issue_id: String,
    enabled: bool,
}

impl<'a> RepairTrace<'a> {
    fn new(event_tx: &'a Sender<RepairEvent>, issue_id: impl Into<String>, enabled: bool) -> Self {
        Self {
            event_tx,
            issue_id: issue_id.into(),
            enabled,
        }
    }

    async fn send(&self, line: String) {
        let _ = self
            .event_tx
            .send(RepairEvent::FixOutput {
                issue_id: self.issue_id.clone(),
                line,
            })
            .await;
    }

    async fn emit(&self, tag: DebugTag, message: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        self.send(render_debug_line(tag, message.as_ref())).await;
    }

    async fn section(&self, title: &str) {
        self.emit(DebugTag::Step, format!("--- {} ---", title))
            .await;
    }

    async fn kv(&self, key: &str, value: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        self.send(render_debug_kv(key, value.as_ref())).await;
    }

    async fn data(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Data, message).await;
    }

    async fn warn(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Warn, message).await;
    }

    async fn hint(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Hint, message).await;
    }

    async fn time(&self, message: impl AsRef<str>) {
        self.emit(DebugTag::Time, message).await;
    }

    /// Spell out a failed repair: the message, and what it means if the failure
    /// came from Windows refusing to start the tool rather than from the tool.
    async fn explain_failure(&self, error: &str) {
        if !self.enabled {
            return;
        }
        self.warn(format!("repair reported: {}", error)).await;

        if error.trim().is_empty() || error.trim().ends_with(':') {
            self.hint(
                "the failure message is empty - the underlying command discarded its own error text before WinMedic could read it",
            )
            .await;
        }

        if let Some(code) = extract_os_error_code(error) {
            match describe_os_error(code) {
                Some(desc) => {
                    if !error.contains(desc.name) {
                        self.hint(format!(
                            "os error {} is {}: {}",
                            code, desc.name, desc.meaning
                        ))
                        .await;
                    }
                    for cause in desc.likely_causes {
                        self.hint(format!("  possible cause: {}", cause)).await;
                    }
                }
                None => {
                    self.hint(format!("os error {} has no stored explanation", code))
                        .await;
                }
            }
        }
    }
}

pub struct DiagnosticEngine {
    modules: Vec<Arc<dyn DiagnosticModule>>,
    audit_logger: AuditLogger,
    pub verbose_logging: bool,
    /// Where the pre-repair restore point comes from.
    ///
    /// Inert on every constructor, so an engine built anywhere — a test, a
    /// benchmark, a future tool — cannot run `Checkpoint-Computer` on the
    /// machine it happens to be running on. The entry points opt in through
    /// [`DiagnosticEngine::with_restore_points`].
    restore_point: RestorePointService,
}

impl DiagnosticEngine {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            modules: get_all_modules(&ModuleConfig::from(config)),
            audit_logger: AuditLogger::new(),
            verbose_logging: config.verbose_logging,
            restore_point: RestorePointService::inert(),
        }
    }

    pub fn with_runner(config: &AppConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            modules: get_all_modules_with_runner(&ModuleConfig::from(config), runner),
            audit_logger: AuditLogger::new(),
            verbose_logging: config.verbose_logging,
            restore_point: RestorePointService::inert(),
        }
    }

    /// Choose where `run_repairs` gets its restore point from.
    ///
    /// Only the two entry points that repair a real machine pass
    /// [`RestorePointService::real`] here — the TUI (through
    /// [`crate::app::SystemActions`]) and the `--fix` command line.
    pub fn with_restore_points(mut self, service: RestorePointService) -> Self {
        self.restore_point = service;
        self
    }

    /// Whether a repair run on this engine would really ask Windows for a
    /// checkpoint.
    pub fn creates_real_restore_points(&self) -> bool {
        self.restore_point.is_live()
    }

    /// Build an engine over an explicit module list.
    ///
    /// Lets a caller substitute modules that are pointed somewhere other than
    /// the live system — which is how tests exercise `run_repairs` end to end
    /// without the file-deleting fixes reaching the real machine.
    pub fn with_modules(modules: Vec<Arc<dyn DiagnosticModule>>) -> Self {
        Self {
            modules,
            audit_logger: AuditLogger::new(),
            verbose_logging: false,
            restore_point: RestorePointService::inert(),
        }
    }

    pub fn modules(&self) -> &[Arc<dyn DiagnosticModule>] {
        &self.modules
    }

    /// Calculate health score (0-100) based on detected issues
    pub fn calculate_health_score(issues: &[Issue]) -> u8 {
        let mut score: i32 = 100;
        for issue in issues {
            if !issue.is_fixed {
                match issue.severity {
                    Severity::Critical => score -= 25,
                    Severity::Warning => score -= 10,
                    Severity::Info => score -= 2,
                }
            }
        }
        score.clamp(0, 100) as u8
    }

    /// Run full diagnostic scan across all modules concurrently.
    ///
    /// Modules are executed in parallel via a Tokio `JoinSet`. Cancelling
    /// `cancel` aborts the running tasks and drops the active module futures,
    /// which in turn drops child process handles — `kill_on_drop` then
    /// terminates long-running tools such as DISM or SFC. Issues collected by
    /// already finished modules are kept and returned.
    pub async fn run_scan(
        &self,
        event_tx: Sender<ScanEvent>,
        cancel: CancellationToken,
    ) -> Vec<Issue> {
        let mut all_issues = Vec::new();
        let total_modules = self.modules.len();

        if cancel.is_cancelled() {
            self.finish_cancelled_scan(&event_tx, 0, total_modules)
                .await;
            return all_issues;
        }

        let (prog_tx, mut prog_rx) = channel::<ModuleProgress>(100);
        let evt_tx_clone = event_tx.clone();

        if self.verbose_logging {
            let _ = event_tx
                .send(ScanEvent::ModuleProgressUpdate(ModuleProgress {
                    module_id: "engine".to_string(),
                    progress_percent: 0,
                    current_step: "Verbose diagnostic mode enabled".to_string(),
                    log_message: Some(render_debug_line(
                        DebugTag::Step,
                        &format!(
                            "--- scan run: {} modules in parallel, elevated: {} ---",
                            total_modules,
                            if is_admin() { "yes" } else { "no" }
                        ),
                    )),
                }))
                .await;
        }

        let forward_handle = tokio::spawn(async move {
            while let Some(prog) = prog_rx.recv().await {
                let _ = evt_tx_clone
                    .send(ScanEvent::ModuleProgressUpdate(prog))
                    .await;
            }
        });

        let mut set = JoinSet::new();
        for module in &self.modules {
            let mod_id = module.id().to_string();
            let mod_name = module.name().to_string();
            let module = Arc::clone(module);
            let p_tx = prog_tx.clone();
            let verbose = self.verbose_logging;

            let _ = event_tx
                .send(ScanEvent::ModuleStarted(mod_id.clone()))
                .await;

            set.spawn(async move {
                if verbose {
                    let _ = p_tx
                        .send(ModuleProgress {
                            module_id: mod_id.clone(),
                            progress_percent: 0,
                            current_step: format!("Starting {} check", mod_name),
                            log_message: Some(render_debug_line(
                                DebugTag::Step,
                                &format!("module '{}' ({}) spawned", mod_name, mod_id),
                            )),
                        })
                        .await;
                }
                let result = module.scan(Some(p_tx)).await;
                (mod_id, mod_name, result)
            });
        }
        // Drop the extra sender reference so prog_rx closes once all module tasks complete
        drop(prog_tx);

        let mut completed_modules = 0;

        while !set.is_empty() {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    set.shutdown().await;
                    let _ = forward_handle.await;
                    self.audit_logger.log(
                        "SCAN",
                        "all",
                        "System diagnostics",
                        "WARNING",
                        &format!(
                            "Scan cancelled by the user after {}/{} modules.",
                            completed_modules, total_modules
                        ),
                    );
                    self.finish_cancelled_scan(&event_tx, completed_modules, total_modules)
                        .await;
                    return all_issues;
                }
                res = set.join_next() => {
                    let Some(join_result) = res else { break };
                    completed_modules += 1;
                    match join_result {
                        Ok((mod_id, mod_name, scan_result)) => {
                            match scan_result {
                                Ok(issues) => {
                                    if self.verbose_logging {
                                        let crit = issues
                                            .iter()
                                            .filter(|i| i.severity == Severity::Critical)
                                            .count();
                                        let warn = issues
                                            .iter()
                                            .filter(|i| i.severity == Severity::Warning)
                                            .count();
                                        let info = issues
                                            .iter()
                                            .filter(|i| i.severity == Severity::Info)
                                            .count();
                                        let _ = event_tx
                                            .send(ScanEvent::ModuleProgressUpdate(
                                                ModuleProgress {
                                                    module_id: mod_id.clone(),
                                                    progress_percent: 100,
                                                    current_step: "Module finished".to_string(),
                                                    log_message: Some(render_debug_line(
                                                        DebugTag::Exit,
                                                        &format!(
                                                            "module '{}' finished: {} findings (critical {}, warning {}, info {})",
                                                            mod_id,
                                                            issues.len(),
                                                            crit,
                                                            warn,
                                                            info
                                                        ),
                                                    )),
                                                },
                                            ))
                                            .await;
                                    }

                                    let _ = event_tx
                                        .send(ScanEvent::ModuleFinished {
                                            module_id: mod_id.clone(),
                                            issues: issues.clone(),
                                        })
                                        .await;

                                    self.audit_logger.log(
                                        "SCAN",
                                        &mod_id,
                                        &mod_name,
                                        "SUCCESS",
                                        &format!("Scan completed with {} issues detected.", issues.len()),
                                    );

                                    all_issues.extend(issues);
                                }
                                Err(err) => {
                                    if self.verbose_logging {
                                        let mut lines = vec![render_debug_line(
                                            DebugTag::Warn,
                                            &format!("module '{}' aborted: {}", mod_id, err),
                                        )];
                                        if let Some(code) = extract_os_error_code(&err)
                                            && let Some(desc) = describe_os_error(code)
                                        {
                                            lines.push(render_debug_line(
                                                DebugTag::Hint,
                                                &format!("{} - {}", desc.name, desc.meaning),
                                            ));
                                        }
                                        for line in lines {
                                            let _ = event_tx
                                                .send(ScanEvent::ModuleProgressUpdate(
                                                    ModuleProgress {
                                                        module_id: mod_id.clone(),
                                                        progress_percent: 100,
                                                        current_step: "Module failed".to_string(),
                                                        log_message: Some(line),
                                                    },
                                                ))
                                                .await;
                                        }
                                    }

                                    let _ = event_tx
                                        .send(ScanEvent::ModuleFailed {
                                            module_id: mod_id.clone(),
                                            error: err.clone(),
                                        })
                                        .await;

                                    self.audit_logger.log(
                                        "SCAN",
                                        &mod_id,
                                        &mod_name,
                                        "FAILED",
                                        &format!("Scan error: {}", err),
                                    );
                                }
                            }
                        }
                        Err(join_err) => {
                            eprintln!("Scan task was aborted or failed: {}", join_err);
                        }
                    }
                }
            }
        }

        let _ = forward_handle.await;

        let total = all_issues.len();
        let health = Self::calculate_health_score(&all_issues);
        let _ = event_tx
            .send(ScanEvent::ScanCompleted {
                total_issues: total,
                health_score: health,
            })
            .await;

        all_issues
    }

    async fn finish_cancelled_scan(
        &self,
        event_tx: &Sender<ScanEvent>,
        completed_modules: usize,
        total_modules: usize,
    ) {
        let _ = event_tx
            .send(ScanEvent::ScanCancelled {
                completed_modules,
                total_modules,
            })
            .await;
    }

    /// Execute (or simulate) repairs for the selected issues.
    pub async fn run_repairs(
        &self,
        issues: &mut [Issue],
        options: RepairOptions,
        event_tx: Sender<RepairEvent>,
        cancel: CancellationToken,
    ) -> (usize, usize) {
        let pending = issues
            .iter()
            .filter(|i| i.is_selected && !i.is_fixed)
            .count();

        let run_trace = RepairTrace::new(&event_tx, "engine", options.verbose_logging);
        run_trace.section("repair run environment").await;
        run_trace.kv("winmedic", env!("CARGO_PKG_VERSION")).await;
        run_trace
            .kv(
                "elevated",
                if is_admin() {
                    "yes (Administrator)"
                } else {
                    "NO - system-level repairs will be refused by Windows"
                },
            )
            .await;
        run_trace.kv("architecture", std::env::consts::ARCH).await;
        run_trace
            .kv(
                "mode",
                if options.dry_run {
                    "simulation"
                } else {
                    "live repair"
                },
            )
            .await;
        run_trace
            .kv(
                "restore point",
                match (
                    options.create_vss && !options.dry_run,
                    self.restore_point.is_live(),
                ) {
                    (true, true) => "requested before the first repair",
                    (true, false) => "engine has no restore point service - none will be created",
                    (false, _) => "skipped",
                },
            )
            .await;
        run_trace.kv("selected repairs", pending.to_string()).await;
        if !is_admin() && !options.dry_run {
            run_trace
                .hint("without elevation expect os error 5 / 740 from chkdsk, DISM, SFC and every service or registry fix")
                .await;
        }

        if options.dry_run {
            let _ = event_tx
                .send(RepairEvent::DryRunStarted {
                    issue_count: pending,
                })
                .await;
            self.audit_logger.log(
                "DRYRUN",
                "engine",
                "Repair simulation",
                "INFO",
                &format!(
                    "Simulation started for {} selected issues. Nothing was changed.",
                    pending
                ),
            );
        } else if options.create_vss {
            let _ = event_tx.send(RepairEvent::VssStarted).await;
            let vss_started = Instant::now();
            let vss_res = self
                .restore_point
                .create("WinMedic Auto-Restore Point (before repairs)")
                .await;
            run_trace
                .time(format!("restore point took {:.2?}", vss_started.elapsed()))
                .await;
            if !vss_res.success {
                run_trace.explain_failure(&vss_res.message).await;
                run_trace
                    .hint("repairs continue without a rollback point - System Protection may be off for C:")
                    .await;
            }
            let _ = event_tx
                .send(RepairEvent::VssCompleted {
                    success: vss_res.success,
                    message: vss_res.message.clone(),
                })
                .await;

            self.audit_logger.log(
                "BACKUP",
                "vss",
                "System Restore Point",
                if vss_res.success {
                    "SUCCESS"
                } else {
                    "WARNING"
                },
                &vss_res.message,
            );
        }

        let mut fixed_count = 0;
        let mut failed_count = 0;
        let mut processed = 0;

        for issue in issues.iter_mut() {
            if !issue.is_selected || issue.is_fixed {
                continue;
            }

            if cancel.is_cancelled() {
                let _ = event_tx
                    .send(RepairEvent::RepairsCancelled {
                        fixed_count,
                        failed_count,
                        remaining: pending.saturating_sub(processed),
                    })
                    .await;
                self.audit_logger.log(
                    "FIX",
                    "engine",
                    "Repair run",
                    "WARNING",
                    &format!(
                        "Cancelled after {} repairs ({} still open).",
                        processed,
                        pending.saturating_sub(processed)
                    ),
                );
                return (fixed_count, failed_count);
            }

            processed += 1;

            let _ = event_tx
                .send(RepairEvent::FixStarted {
                    issue_id: issue.id.clone(),
                    title: issue.title.clone(),
                })
                .await;

            let trace = RepairTrace::new(&event_tx, issue.id.clone(), options.verbose_logging);
            trace
                .section(&format!("fix {} ({}/{})", issue.id, processed, pending))
                .await;
            trace.kv("module", &issue.module_id).await;
            trace.kv("category", &issue.category).await;
            trace
                .kv(
                    "severity / risk",
                    format!("{:?} / {:?}", issue.severity, issue.risk_score),
                )
                .await;
            trace.kv("detected", &issue.technical_details).await;
            trace.kv("planned action", &issue.recommended_fix).await;
            for (idx, step) in issue.fix_steps.iter().enumerate() {
                trace.data(format!("  step {}: {}", idx + 1, step)).await;
            }
            if issue.fix_steps.is_empty() {
                trace
                    .data("  (the module records no individual steps)")
                    .await;
            }

            if options.dry_run {
                self.simulate_fix(issue, &event_tx).await;
                fixed_count += 1;
                continue;
            }

            let mod_opt = self.modules.iter().find(|m| m.id() == issue.module_id);
            let Some(module) = mod_opt else {
                failed_count += 1;
                let _ = event_tx
                    .send(RepairEvent::FixFinished {
                        issue_id: issue.id.clone(),
                        success: false,
                        message: "Module not found".to_string(),
                    })
                    .await;
                continue;
            };

            let (prog_tx, mut prog_rx) = channel::<FixProgress>(50);
            let evt_tx_clone = event_tx.clone();
            let issue_id_clone = issue.id.clone();

            let forward_handle = tokio::spawn(async move {
                while let Some(prog) = prog_rx.recv().await {
                    if let Some(line) = prog.console_line {
                        let _ = evt_tx_clone
                            .send(RepairEvent::FixOutput {
                                issue_id: issue_id_clone.clone(),
                                line,
                            })
                            .await;
                    }
                }
            });

            let fix_started = Instant::now();
            let outcome = tokio::select! {
                biased;
                _ = cancel.cancelled() => None,
                result = module.fix(&issue.id, Some(prog_tx)) => Some(result),
            };

            let _ = forward_handle.await;

            trace
                .time(format!("fix returned after {:.2?}", fix_started.elapsed()))
                .await;

            let Some(result) = outcome else {
                issue.fix_error = Some("Repair cancelled by the user.".to_string());
                let _ = event_tx
                    .send(RepairEvent::FixFinished {
                        issue_id: issue.id.clone(),
                        success: false,
                        message: "Cancelled by the user.".to_string(),
                    })
                    .await;
                self.audit_logger.log(
                    "FIX",
                    &issue.module_id,
                    &issue.title,
                    "WARNING",
                    "Repair cancelled by the user.",
                );
                let _ = event_tx
                    .send(RepairEvent::RepairsCancelled {
                        fixed_count,
                        failed_count,
                        remaining: pending.saturating_sub(processed),
                    })
                    .await;
                return (fixed_count, failed_count);
            };

            match result {
                Ok(msg) => {
                    if issue.requires_reboot {
                        issue.is_reboot_pending = true;
                        issue.is_fixed = false;
                        issue.is_selected = false;
                    } else {
                        issue.is_fixed = true;
                        issue.is_reboot_pending = false;
                    }
                    issue.fix_error = None;
                    fixed_count += 1;

                    let _ = event_tx
                        .send(RepairEvent::FixFinished {
                            issue_id: issue.id.clone(),
                            success: true,
                            message: msg.clone(),
                        })
                        .await;

                    self.audit_logger
                        .log("FIX", &issue.module_id, &issue.title, "SUCCESS", &msg);
                }
                Err(err) => {
                    issue.is_fixed = false;
                    issue.is_reboot_pending = false;
                    issue.fix_error = Some(err.clone());
                    failed_count += 1;

                    trace.explain_failure(&err).await;

                    let _ = event_tx
                        .send(RepairEvent::FixFinished {
                            issue_id: issue.id.clone(),
                            success: false,
                            message: err.clone(),
                        })
                        .await;

                    self.audit_logger
                        .log("FIX", &issue.module_id, &issue.title, "FAILED", &err);
                }
            }
        }

        let _ = event_tx
            .send(RepairEvent::AllRepairsCompleted {
                fixed_count,
                failed_count,
            })
            .await;

        (fixed_count, failed_count)
    }

    /// Report the planned steps for `issue` without touching the system.
    ///
    /// Deliberately leaves `is_fixed` untouched so a simulation never makes the
    /// health score look better than the machine actually is.
    async fn simulate_fix(&self, issue: &Issue, event_tx: &Sender<RepairEvent>) {
        let emit = |line: String| async {
            let _ = event_tx
                .send(RepairEvent::FixOutput {
                    issue_id: issue.id.clone(),
                    line,
                })
                .await;
        };

        emit(format!("[SIMULATION] Planned: {}", issue.recommended_fix)).await;
        for (idx, step) in issue.fix_steps.iter().enumerate() {
            emit(format!("[SIMULATION]   {}. {}", idx + 1, step)).await;
        }
        if issue.fix_steps.is_empty() {
            emit("[SIMULATION]   (no individual steps recorded)".to_string()).await;
        }

        let message = format!(
            "Simulation: {} step(s) would run. Nothing was changed.",
            issue.fix_steps.len()
        );

        let _ = event_tx
            .send(RepairEvent::FixFinished {
                issue_id: issue.id.clone(),
                success: true,
                message: message.clone(),
            })
            .await;

        self.audit_logger
            .log("DRYRUN", &issue.module_id, &issue.title, "INFO", &message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::issue::{RiskScore, Severity};
    use crate::utils::debug_log::parse_debug_line;

    /// Deliberately a literal rather than `get_all_modules().len()`: derived
    /// from the registry these assertions would be tautologies, and would stop
    /// noticing a module that quietly fell out of it.
    const MODULE_COUNT: usize = 10;

    fn sample_issues() -> Vec<Issue> {
        vec![
            Issue::new(
                "test_1",
                "system_integrity",
                "Critical Issue",
                "Category",
                Severity::Critical,
                RiskScore::Low,
                "Description",
                "Details",
                "Fix",
                vec!["Step 1".to_string()],
            ),
            Issue::new(
                "test_2",
                "storage",
                "Warning Issue",
                "Category",
                Severity::Warning,
                RiskScore::Low,
                "Description",
                "Details",
                "Fix",
                vec!["Step 1".to_string()],
            ),
        ]
    }

    #[test]
    fn test_health_score_calculation() {
        let mut issues = sample_issues();

        // 100 - 25 (Critical) - 10 (Warning) = 65
        let score = DiagnosticEngine::calculate_health_score(&issues);
        assert_eq!(score, 65);

        // After fixing the critical issue: 100 - 10 = 90
        issues[0].is_fixed = true;
        let score_after_fix = DiagnosticEngine::calculate_health_score(&issues);
        assert_eq!(score_after_fix, 90);
    }

    #[tokio::test]
    async fn test_dry_run_does_not_mark_issues_fixed() {
        let engine = DiagnosticEngine::new(&AppConfig::default());
        let mut issues = sample_issues();
        let (tx, mut rx) = channel::<RepairEvent>(100);

        let options = RepairOptions {
            create_vss: true,
            dry_run: true,
            verbose_logging: false,
        };
        let (fixed, failed) = engine
            .run_repairs(&mut issues, options, tx, CancellationToken::new())
            .await;

        assert_eq!(fixed, 2, "both issues should be simulated");
        assert_eq!(failed, 0);
        assert!(
            issues.iter().all(|i| !i.is_fixed),
            "a simulation must not mark anything as fixed"
        );
        assert_eq!(
            DiagnosticEngine::calculate_health_score(&issues),
            65,
            "health score must be unaffected by a simulation"
        );

        let mut saw_dry_run_start = false;
        let mut saw_vss = false;
        while let Ok(evt) = rx.try_recv() {
            match evt {
                RepairEvent::DryRunStarted { issue_count } => {
                    saw_dry_run_start = true;
                    assert_eq!(issue_count, 2);
                }
                RepairEvent::VssStarted => saw_vss = true,
                _ => {}
            }
        }
        assert!(saw_dry_run_start);
        assert!(!saw_vss, "a simulation must not create a restore point");
    }

    #[tokio::test]
    async fn test_cancelled_repairs_stop_before_first_fix() {
        let engine = DiagnosticEngine::new(&AppConfig::default());
        let mut issues = sample_issues();
        let (tx, mut rx) = channel::<RepairEvent>(100);

        let cancel = CancellationToken::new();
        cancel.cancel();

        let options = RepairOptions {
            create_vss: false,
            dry_run: false,
            verbose_logging: false,
        };
        let (fixed, failed) = engine.run_repairs(&mut issues, options, tx, cancel).await;

        assert_eq!((fixed, failed), (0, 0));
        assert!(issues.iter().all(|i| !i.is_fixed));

        let mut cancelled_remaining = None;
        while let Ok(evt) = rx.try_recv() {
            if let RepairEvent::RepairsCancelled { remaining, .. } = evt {
                cancelled_remaining = Some(remaining);
            }
        }
        assert_eq!(cancelled_remaining, Some(2));
    }

    #[tokio::test]
    async fn test_cancelled_scan_reports_progress() {
        let mock = Arc::new(crate::utils::cmd::MockCommandRunner::new());
        let engine = DiagnosticEngine::with_runner(&AppConfig::default(), mock);
        let (tx, mut rx) = channel::<ScanEvent>(200);

        let cancel = CancellationToken::new();
        cancel.cancel();

        let issues = engine.run_scan(tx, cancel).await;
        assert!(issues.is_empty());

        let mut cancelled = None;
        while let Ok(evt) = rx.try_recv() {
            if let ScanEvent::ScanCancelled {
                completed_modules,
                total_modules,
            } = evt
            {
                cancelled = Some((completed_modules, total_modules));
            }
        }
        assert_eq!(cancelled, Some((0, MODULE_COUNT)));
    }

    #[tokio::test]
    async fn test_run_scan_emits_events_and_completes() {
        let mock = Arc::new(crate::utils::cmd::MockCommandRunner::new());
        let engine = DiagnosticEngine::with_runner(&AppConfig::default(), mock);
        let (tx, mut rx) = channel::<ScanEvent>(200);

        let _issues = engine.run_scan(tx, CancellationToken::new()).await;

        let mut started_modules = Vec::new();
        let mut finished_or_failed = 0;
        let mut saw_completed = false;

        while let Ok(evt) = rx.try_recv() {
            match evt {
                ScanEvent::ModuleStarted(id) => started_modules.push(id),
                ScanEvent::ModuleFinished { .. } | ScanEvent::ModuleFailed { .. } => {
                    finished_or_failed += 1;
                }
                ScanEvent::ScanCompleted { .. } => saw_completed = true,
                _ => {}
            }
        }

        assert_eq!(
            started_modules.len(),
            MODULE_COUNT,
            "every registered module should start"
        );
        assert_eq!(
            finished_or_failed, MODULE_COUNT,
            "every registered module should finish or fail"
        );
        assert!(saw_completed, "scan should emit ScanCompleted");
    }

    #[tokio::test]
    async fn test_diagnostic_engine_with_mock_runner() {
        use crate::utils::cmd::{CmdOutput, MockCommandRunner};

        let mock = MockCommandRunner::new();
        // Mock DISM corruption
        mock.add_response(
            "dism.exe",
            CmdOutput::ok(
                "The component store is repairable. The operation completed successfully.",
            ),
        );
        // Mock disabled Windows Update service
        mock.add_response(
            "query wuauserv",
            CmdOutput::ok("STATE: 1 STOPPED \n START_TYPE: DISABLED"),
        );
        // Mock disabled VSS
        mock.add_response(
            "query vss",
            CmdOutput::ok("STATE: 1 STOPPED \n START_TYPE: DISABLED"),
        );
        mock.add_response("query bits", CmdOutput::ok("STATE: 4 RUNNING"));
        mock.add_response("query cryptsvc", CmdOutput::ok("STATE: 4 RUNNING"));
        mock.add_response("dirty query C:", CmdOutput::ok("Volume - C: is clean"));
        mock.add_response("Get-PhysicalDisk", CmdOutput::ok("SSD | Health: Healthy"));
        mock.add_response("nslookup.exe", CmdOutput::ok("Address: 8.8.8.8"));
        mock.add_response("show catalog", CmdOutput::ok("Winsock Provider"));
        mock.add_response("Level=1", CmdOutput::ok(""));
        mock.add_response("WHEA-Logger", CmdOutput::ok(""));

        let engine = DiagnosticEngine::with_runner(&AppConfig::default(), Arc::new(mock));
        let (tx, _rx) = channel::<ScanEvent>(200);

        let issues = engine.run_scan(tx, CancellationToken::new()).await;

        // Should detect DISM corruption and disabled WU / VSS services
        assert!(issues.iter().any(|i| i.id == "sys_dism_corrupt"));
        assert!(issues.iter().any(|i| i.id == "wu_svc_disabled_wuauserv"));
        assert!(issues.iter().any(|i| i.id == "sys_vss_disabled"));
    }

    #[tokio::test]
    async fn test_verbose_scan_and_repair_emits_debug_logs() {
        let config = AppConfig {
            verbose_logging: true,
            ..Default::default()
        };
        let mock = Arc::new(crate::utils::cmd::MockCommandRunner::new());
        let engine = DiagnosticEngine::with_runner(&config, mock);
        assert!(engine.verbose_logging);

        let (tx, mut rx) = channel::<ScanEvent>(200);
        let _issues = engine.run_scan(tx, CancellationToken::new()).await;

        let mut saw_debug_log = false;
        while let Ok(evt) = rx.try_recv() {
            if let ScanEvent::ModuleProgressUpdate(prog) = evt
                && let Some(log) = prog.log_message
                && parse_debug_line(&log).is_some()
            {
                saw_debug_log = true;
            }
        }
        assert!(
            saw_debug_log,
            "verbose scan should emit lines the UI recognises as traces"
        );
    }

    /// Verbose mode is what the user reaches for once a repair has failed, so
    /// the failing path in particular has to say what went wrong and what the
    /// error code means — not just repeat the message.
    #[tokio::test]
    async fn a_failed_repair_is_explained_in_the_verbose_log() {
        let (tx, mut rx) = channel::<RepairEvent>(200);
        let trace = RepairTrace::new(&tx, "storage_dirty_bit", true);

        trace
            .explain_failure("Failed to spawn command 'chkdsk.exe': Access is denied. (os error 5)")
            .await;

        let mut lines = Vec::new();
        while let Ok(RepairEvent::FixOutput { line, .. }) = rx.try_recv() {
            lines.push(line);
        }

        assert!(
            lines.iter().all(|l| parse_debug_line(l).is_some()),
            "every explanation line must be tagged as a trace: {:?}",
            lines
        );
        let joined = lines.join("\n");
        assert!(joined.contains("ACCESS_DENIED"), "{}", joined);
        assert!(joined.contains("never started"), "{}", joined);
        assert!(
            joined.contains("security driver"),
            "the likely causes must be listed: {}",
            joined
        );
    }

    /// An empty failure message is the specific case that sent the user looking
    /// at the log in the first place, so it gets called out by name.
    #[tokio::test]
    async fn an_empty_failure_message_is_called_out() {
        let (tx, mut rx) = channel::<RepairEvent>(200);
        let trace = RepairTrace::new(&tx, "sys_clean_recycle_bin", true);

        trace
            .explain_failure("Failed to empty the Recycle Bin:")
            .await;

        let mut joined = String::new();
        while let Ok(RepairEvent::FixOutput { line, .. }) = rx.try_recv() {
            joined.push_str(&line);
            joined.push('\n');
        }
        assert!(
            joined.contains("discarded its own error text"),
            "{}",
            joined
        );
    }

    #[tokio::test]
    async fn a_trace_stays_silent_when_verbose_logging_is_off() {
        let (tx, mut rx) = channel::<RepairEvent>(16);
        let trace = RepairTrace::new(&tx, "storage_dirty_bit", false);

        trace.section("nothing").await;
        trace.kv("key", "value").await;
        trace.explain_failure("boom (os error 5)").await;

        assert!(rx.try_recv().is_err());
    }
}
