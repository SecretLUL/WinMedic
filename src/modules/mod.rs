pub mod event_log;
pub mod network;
pub mod registry_startup;
pub mod storage;
pub mod system_cleaner;
pub mod system_integrity;
pub mod windows_updates;

use crate::config::AppConfig;
use crate::engine::issue::Issue;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleStatus {
    Idle,
    Scanning,
    Passed,
    Warning(usize),
    Critical(usize),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ModuleProgress {
    pub module_id: String,
    pub progress_percent: u8,
    pub current_step: String,
    pub log_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FixProgress {
    pub issue_id: String,
    pub step_description: String,
    pub is_success: bool,
    pub error: Option<String>,
    pub console_line: Option<String>,
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
}

/// Create all 7 diagnostic modules, configured from the user's settings with a specific CommandRunner.
pub fn get_all_modules_with_runner(
    cfg: &ModuleConfig,
    runner: Arc<dyn crate::utils::cmd::CommandRunner>,
) -> Vec<Arc<dyn DiagnosticModule>> {
    vec![
        Arc::new(system_integrity::SystemIntegrityModule::with_runner(
            runner.clone(),
        )),
        Arc::new(windows_updates::WindowsUpdatesModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(network::NetworkModule::with_runner(runner.clone())),
        Arc::new(event_log::EventLogModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(storage::StorageModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(registry_startup::RegistryStartupModule::with_runner(
            cfg.clone(),
            runner.clone(),
        )),
        Arc::new(system_cleaner::SystemCleanerModule::with_runner(
            cfg.clone(),
            runner,
        )),
    ]
}

/// Create all 7 diagnostic modules, configured from the user's settings using the default OS runner.
pub fn get_all_modules(cfg: &ModuleConfig) -> Vec<Arc<dyn DiagnosticModule>> {
    get_all_modules_with_runner(cfg, Arc::new(crate::utils::cmd::SystemCommandRunner::new()))
}
