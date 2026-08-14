pub mod event_log;
pub mod network;
pub mod registry_startup;
pub mod storage;
pub mod system_integrity;
pub mod windows_updates;

use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use crate::engine::issue::Issue;

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
    async fn scan(&self, progress_tx: Option<Sender<ModuleProgress>>) -> Result<Vec<Issue>, String>;

    /// Apply fix for a specific issue id
    async fn fix(&self, issue_id: &str, progress_tx: Option<Sender<FixProgress>>) -> Result<String, String>;
}

/// Create all 6 diagnostic modules
pub fn get_all_modules() -> Vec<Arc<dyn DiagnosticModule>> {
    vec![
        Arc::new(system_integrity::SystemIntegrityModule::new()),
        Arc::new(windows_updates::WindowsUpdatesModule::new()),
        Arc::new(network::NetworkModule::new()),
        Arc::new(event_log::EventLogModule::new()),
        Arc::new(storage::StorageModule::new()),
        Arc::new(registry_startup::RegistryStartupModule::new()),
    ]
}
