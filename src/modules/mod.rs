pub mod clock_restart;
pub mod crash_analysis;
/// What changed before the crashes began, for the crash analysis.
pub mod crash_timeline;
pub mod devices;
pub mod event_log;
/// Windows features whose installation was rolled back, for System
/// Integrity.
pub mod feature_rollback;
/// Windows installation media as the repair source for DISM.
pub mod install_media;
pub mod network;
/// A graphics card whose OpenGL driver Windows cannot find, for the devices
/// check.
pub mod opengl_driver;
pub mod page_file;
pub mod registry_startup;
pub mod scheduled_tasks;
/// Why a service cannot start, down to the device, for the tweaks check.
pub mod service_chain;
/// Explorer crashing in a program's add-on, for the crash analysis.
pub mod shell_extensions;
pub mod storage;
pub mod system_cleaner;
pub mod system_integrity;
pub mod tweaks;
pub mod whea_logger;
pub mod windows_updates;

use crate::config::AppConfig;
use crate::engine::issue::{Issue, Severity};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

/// How long a repair through Windows' servicing tools — DISM and SFC — may
/// run.
///
/// DISM /RestoreHealth downloads the files it replaces from Windows Update
/// and went past ten minutes on the development machine, which is where the
/// old limit stopped it. The user can cancel at any time, so this only has to
/// catch a tool that never comes back.
pub const SERVICING_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Keeps DISM from asking whether to restart Windows; every DISM call passes
/// it.
///
/// DISM asks when an operation leaves Windows waiting for a restart - while an
/// installed update waits for one, `/AnalyzeComponentStore` does too - and
/// reads the answer from the console (`_getwch`), not from its input. In the
/// console without a window that WinMedic starts it in, nobody can answer:
/// DISM waited until its time ran out, and the analysis was lost for as long
/// as the restart was pending (#222).
pub const DISM_NO_RESTART: &str = "/NoRestart";

/// The subset of [`AppConfig`] that diagnostic modules need at scan/fix time.
///
/// Modules receive this at construction, so changing a setting means rebuilding
/// the engine rather than threading config through every call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleConfig {
    pub temp_clean_threshold_mb: u64,
    pub max_event_log_hours: u32,
    pub auto_backup_registry: bool,
    pub auto_restart_services: bool,
    pub verbose_logging: bool,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self::from(&AppConfig::default())
    }
}

impl From<&AppConfig> for ModuleConfig {
    fn from(cfg: &AppConfig) -> Self {
        Self {
            temp_clean_threshold_mb: cfg.temp_clean_threshold_mb,
            max_event_log_hours: cfg.max_event_log_hours,
            auto_backup_registry: cfg.auto_backup_registry,
            auto_restart_services: cfg.auto_restart_services,
            verbose_logging: cfg.verbose_logging,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleStatus {
    Idle,
    Scanning,
    Passed,
    Warning(usize),
    Critical(usize),
    Failed(String),
}

impl ModuleStatus {
    /// The badge a module that finished earns from the findings it reported.
    ///
    /// Only for a module that finished: one that failed reported nothing, and
    /// counting its findings would call it passed.
    pub fn from_findings<'a>(issues: impl IntoIterator<Item = &'a Issue>) -> Self {
        let (mut critical, mut warnings) = (0, 0);
        for issue in issues {
            match issue.severity {
                Severity::Critical => critical += 1,
                Severity::Warning => warnings += 1,
                Severity::Info => {}
            }
        }
        if critical > 0 {
            Self::Critical(critical)
        } else if warnings > 0 {
            Self::Warning(warnings)
        } else {
            Self::Passed
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModuleProgress {
    pub module_id: String,
    pub progress_percent: u8,
    pub current_step: String,
    pub log_message: Option<String>,
}

impl ModuleProgress {
    /// An event that carries only a log line, such as a verbose trace.
    ///
    /// It has no percentage and no step, so applying it to a module's bar would
    /// reset the bar. [`Self::is_log_only`] is how the scan tells it apart.
    pub fn log_only(module_id: &str, line: String) -> Self {
        Self {
            module_id: module_id.to_string(),
            progress_percent: 0,
            current_step: String::new(),
            log_message: Some(line),
        }
    }

    /// Whether this event only carries a log line. Every real progress event
    /// names the step its module is on, so an empty step marks a log-only one.
    pub fn is_log_only(&self) -> bool {
        self.current_step.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct FixProgress {
    pub issue_id: String,
    pub step_description: String,
    pub is_success: bool,
    pub error: Option<String>,
    pub console_line: Option<String>,
}

/// A channel for a repair command's output that hands every line on to the
/// repair's progress channel, which puts it in the repair log.
pub fn console_lines(
    issue_id: &str,
    progress_tx: Option<&Sender<FixProgress>>,
) -> Option<Sender<String>> {
    let progress_tx = progress_tx?.clone();
    let issue_id = issue_id.to_string();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(100);
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            let _ = progress_tx
                .send(FixProgress {
                    issue_id: issue_id.clone(),
                    step_description: "Repair in progress...".to_string(),
                    is_success: true,
                    error: None,
                    console_line: Some(line),
                })
                .await;
        }
    });
    Some(tx)
}

/// What a repair that did not fail came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repaired {
    /// It changed what the finding is about. The message says what.
    Changed(String),
    /// It ran, but Windows had nothing it would remove. The finding was a
    /// false alarm, not a failure; the message says why.
    NothingToRemove(String),
}

impl Repaired {
    /// The line for the repair log and the audit log.
    pub fn message(&self) -> String {
        match self {
            Self::Changed(message) => message.clone(),
            Self::NothingToRemove(why) => format!("Nothing to remove: {why}"),
        }
    }
}

#[async_trait::async_trait]
pub trait DiagnosticModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn icon(&self) -> &'static str;

    /// Run diagnostic checks and return any detected issues
    async fn scan(&self, progress_tx: Option<Sender<ModuleProgress>>)
    -> Result<Vec<Issue>, String>;

    /// Apply fix for a specific issue id
    async fn fix(
        &self,
        issue_id: &str,
        progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String>;

    /// [`Self::fix`], told apart from a repair that found nothing to remove.
    ///
    /// The engine calls this. A module whose repair can come up empty
    /// overrides it; any other repair that succeeded changed something.
    async fn repair(
        &self,
        issue_id: &str,
        progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<Repaired, String> {
        self.fix(issue_id, progress_tx).await.map(Repaired::Changed)
    }
}

/// Create every diagnostic module, configured from the user's settings with a specific CommandRunner.
pub fn get_all_modules_with_runner(
    cfg: &ModuleConfig,
    runner: Arc<dyn crate::utils::cmd::CommandRunner>,
) -> Vec<Arc<dyn DiagnosticModule>> {
    all_modules(cfg, runner, system_cleaner::CleanerPaths::from_env())
}

fn all_modules(
    cfg: &ModuleConfig,
    runner: Arc<dyn crate::utils::cmd::CommandRunner>,
    cleaner_paths: system_cleaner::CleanerPaths,
) -> Vec<Arc<dyn DiagnosticModule>> {
    vec![
        Arc::new(
            system_integrity::SystemIntegrityModule::with_runner(runner.clone())
                .restarting_services(cfg.auto_restart_services),
        ),
        Arc::new(windows_updates::WindowsUpdatesModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(network::NetworkModule::with_runner(runner.clone())),
        Arc::new(event_log::EventLogModule::with_runner(runner.clone())),
        Arc::new(storage::StorageModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(registry_startup::RegistryStartupModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(system_cleaner::SystemCleanerModule::with_runner_and_paths(
            cfg.clone(),
            runner.clone(),
            cleaner_paths,
        )),
        Arc::new(scheduled_tasks::ScheduledTasksModule::with_runner(
            runner.clone(),
        )),
        Arc::new(page_file::PageFileModule::with_runner(runner.clone())),
        Arc::new(whea_logger::WheaLoggerModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(crash_analysis::CrashAnalysisModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(tweaks::TweaksModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(clock_restart::ClockRestartModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(
            devices::DevicesModule::with_runner(runner)
                .restarting_services(cfg.auto_restart_services)
                .backing_up_registry(cfg.auto_backup_registry),
        ),
    ]
}

/// Create every diagnostic module, configured from the user's settings using the default OS runner.
///
/// Only here, with the machine's own DISM, does the cleaner remember what its
/// last component store cleanup left, in `%APPDATA%\WinMedic`; built around
/// any other runner it remembers nothing.
pub fn get_all_modules(cfg: &ModuleConfig) -> Vec<Arc<dyn DiagnosticModule>> {
    all_modules(
        cfg,
        Arc::new(crate::utils::cmd::SystemCommandRunner::new()),
        system_cleaner::CleanerPaths::from_env_remembering(),
    )
}
