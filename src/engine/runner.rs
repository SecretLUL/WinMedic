use std::sync::Arc;
use tokio::sync::mpsc::{channel, Sender};
use crate::engine::issue::{Issue, Severity};
use crate::modules::{get_all_modules, DiagnosticModule, FixProgress, ModuleProgress};
use crate::safety::audit::AuditLogger;
use crate::safety::restore_point::create_system_restore_point;

#[derive(Debug, Clone)]
pub enum ScanEvent {
    ModuleStarted(String),
    ModuleProgressUpdate(ModuleProgress),
    ModuleFinished { module_id: String, issues: Vec<Issue> },
    ModuleFailed { module_id: String, error: String },
    ScanCompleted { total_issues: usize, health_score: u8 },
}

#[derive(Debug, Clone)]
pub enum RepairEvent {
    VssStarted,
    VssCompleted { success: bool, message: String },
    FixStarted { issue_id: String, title: String },
    FixOutput { issue_id: String, line: String },
    FixFinished { issue_id: String, success: bool, message: String },
    AllRepairsCompleted { fixed_count: usize, failed_count: usize },
}

pub struct DiagnosticEngine {
    modules: Vec<Arc<dyn DiagnosticModule>>,
    audit_logger: AuditLogger,
}

impl DiagnosticEngine {
    pub fn new() -> Self {
        Self {
            modules: get_all_modules(),
            audit_logger: AuditLogger::new(),
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

    /// Run full diagnostic scan across all modules
    pub async fn run_scan(&self, event_tx: Sender<ScanEvent>) -> Vec<Issue> {
        let mut all_issues = Vec::new();

        for module in &self.modules {
            let mod_id = module.id().to_string();
            let _ = event_tx.send(ScanEvent::ModuleStarted(mod_id.clone())).await;

            let (prog_tx, mut prog_rx) = channel::<ModuleProgress>(50);
            let evt_tx_clone = event_tx.clone();

            let forward_handle = tokio::spawn(async move {
                while let Some(prog) = prog_rx.recv().await {
                    let _ = evt_tx_clone.send(ScanEvent::ModuleProgressUpdate(prog)).await;
                }
            });

            match module.scan(Some(prog_tx)).await {
                Ok(issues) => {
                    let _ = forward_handle.await;
                    let _ = event_tx
                        .send(ScanEvent::ModuleFinished {
                            module_id: mod_id.clone(),
                            issues: issues.clone(),
                        })
                        .await;

                    self.audit_logger.log(
                        "SCAN",
                        &mod_id,
                        module.name(),
                        "SUCCESS",
                        &format!("Scan completed with {} issues detected.", issues.len()),
                    );

                    all_issues.extend(issues);
                }
                Err(err) => {
                    let _ = forward_handle.await;
                    let _ = event_tx
                        .send(ScanEvent::ModuleFailed {
                            module_id: mod_id.clone(),
                            error: err.clone(),
                        })
                        .await;

                    self.audit_logger.log(
                        "SCAN",
                        &mod_id,
                        module.name(),
                        "FAILED",
                        &format!("Scan error: {}", err),
                    );
                }
            }
        }

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

    /// Execute repairs for selected issues
    pub async fn run_repairs(
        &self,
        issues: &mut [Issue],
        create_vss: bool,
        event_tx: Sender<RepairEvent>,
    ) -> (usize, usize) {
        if create_vss {
            let _ = event_tx.send(RepairEvent::VssStarted).await;
            let vss_res = create_system_restore_point("WinMedic Auto-Restore Point (Vor Reparatur)").await;
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
                if vss_res.success { "SUCCESS" } else { "WARNING" },
                &vss_res.message,
            );
        }

        let mut fixed_count = 0;
        let mut failed_count = 0;

        for issue in issues.iter_mut() {
            if !issue.is_selected || issue.is_fixed {
                continue;
            }

            let _ = event_tx
                .send(RepairEvent::FixStarted {
                    issue_id: issue.id.clone(),
                    title: issue.title.clone(),
                })
                .await;

            let mod_opt = self.modules.iter().find(|m| m.id() == issue.module_id);
            if let Some(module) = mod_opt {
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

                match module.fix(&issue.id, Some(prog_tx)).await {
                    Ok(msg) => {
                        let _ = forward_handle.await;
                        issue.is_fixed = true;
                        issue.fix_error = None;
                        fixed_count += 1;

                        let _ = event_tx
                            .send(RepairEvent::FixFinished {
                                issue_id: issue.id.clone(),
                                success: true,
                                message: msg.clone(),
                            })
                            .await;

                        self.audit_logger.log(
                            "FIX",
                            &issue.module_id,
                            &issue.title,
                            "SUCCESS",
                            &msg,
                        );
                    }
                    Err(err) => {
                        let _ = forward_handle.await;
                        issue.is_fixed = false;
                        issue.fix_error = Some(err.clone());
                        failed_count += 1;

                        let _ = event_tx
                            .send(RepairEvent::FixFinished {
                                issue_id: issue.id.clone(),
                                success: false,
                                message: err.clone(),
                            })
                            .await;

                        self.audit_logger.log(
                            "FIX",
                            &issue.module_id,
                            &issue.title,
                            "FAILED",
                            &err,
                        );
                    }
                }
            } else {
                failed_count += 1;
                let _ = event_tx
                    .send(RepairEvent::FixFinished {
                        issue_id: issue.id.clone(),
                        success: false,
                        message: "Modul nicht gefunden".to_string(),
                    })
                    .await;
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
}
