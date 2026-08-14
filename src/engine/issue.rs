use chrono::Local;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical, // Coral Red (#EF4444)
    Warning,  // Amber (#F59E0B)
    Info,     // Cyan / Slate (#00D2FF)
}

impl Severity {
    pub fn badge(&self) -> &'static str {
        match self {
            Severity::Critical => "🔴 KRITISCH",
            Severity::Warning => "▲ WARNUNG",
            Severity::Info => "ℹ INFO",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::Warning => "WARN",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskScore {
    Low,    // Safe to auto-fix, zero disruption
    Medium, // Safe with backup, may restart a service
    High,   // Advanced fix, requires reboot or user verification
}

impl RiskScore {
    pub fn badge(&self) -> &'static str {
        match self {
            RiskScore::Low => "🟢 GERING (Safe)",
            RiskScore::Medium => "🟡 MITTEL (Service-Restart)",
            RiskScore::High => "🟠 HOCH (Reboot/System)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: String,
    pub module_id: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub risk_score: RiskScore,
    pub description: String,
    pub technical_details: String,
    pub recommended_fix: String,
    pub fix_steps: Vec<String>,
    pub is_selected: bool,
    pub is_fixed: bool,
    pub fix_error: Option<String>,
    pub timestamp: String,
}

impl Issue {
    pub fn new(
        id: impl Into<String>,
        module_id: impl Into<String>,
        title: impl Into<String>,
        category: impl Into<String>,
        severity: Severity,
        risk_score: RiskScore,
        description: impl Into<String>,
        technical_details: impl Into<String>,
        recommended_fix: impl Into<String>,
        fix_steps: Vec<String>,
    ) -> Self {
        Self {
            id: id.into(),
            module_id: module_id.into(),
            title: title.into(),
            category: category.into(),
            severity,
            risk_score,
            description: description.into(),
            technical_details: technical_details.into(),
            recommended_fix: recommended_fix.into(),
            fix_steps,
            is_selected: true,
            is_fixed: false,
            fix_error: None,
            timestamp: Local::now().format("%H:%M:%S").to_string(),
        }
    }
}
