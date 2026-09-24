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
            Severity::Critical => "[!] CRITICAL",
            Severity::Warning => "[!] WARNING",
            Severity::Info => "[i] INFO",
        }
    }

    /// The severity on its own, for surfaces that draw their own mark.
    ///
    /// [`Self::badge`] is the same thing for surfaces that cannot: a report
    /// file or a terminal has no way to paint an octagon.
    pub fn name(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::Warning => "WARNING",
            Severity::Info => "INFO",
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
            RiskScore::Low => "[OK] LOW (safe)",
            RiskScore::Medium => "[~] MEDIUM (service restart)",
            RiskScore::High => "[!] HIGH (reboot/system)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub requires_reboot: bool,
    #[serde(default)]
    pub is_reboot_pending: bool,
    pub fix_error: Option<String>,
    pub timestamp: String,
    /// What the repair would free on disk, for a cleanup the scan measured.
    ///
    /// A number rather than something read back out of the title, so Easy
    /// mode can add the findings up. `None` for everything that frees nothing
    /// and for cleanups whose size is not known before they run.
    #[serde(default)]
    pub reclaimable_bytes: Option<u64>,
    /// WinMedic has nothing to run for this finding; it tells the user what
    /// to do. It can never be ticked, so a repair run neither touches it nor
    /// counts it as fixed, and it keeps weighing on the health score.
    #[serde(default)]
    pub advice_only: bool,
}

impl Issue {
    // Every parameter maps to one required field of a fully-described finding.
    // Bundling them into a builder is worthwhile, but it touches every module's
    // scan path, so it is tracked separately rather than hidden behind a
    // crate-wide lint allow.
    #[allow(clippy::too_many_arguments)]
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
            requires_reboot: false,
            is_reboot_pending: false,
            fix_error: None,
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            reclaimable_bytes: None,
            advice_only: false,
        }
    }

    /// Mark the finding as advice only. It starts unticked, like every finding
    /// the user has to act on.
    pub fn with_advice_only(mut self) -> Self {
        self.advice_only = true;
        self.is_selected = false;
        self
    }

    /// Whether a repair run could still do something for this finding.
    pub fn is_repairable(&self) -> bool {
        !self.advice_only && !self.is_fixed && !self.is_reboot_pending
    }

    /// Whether the next repair run works on this finding.
    pub fn will_repair(&self) -> bool {
        self.is_selected && self.is_repairable()
    }

    pub fn with_requires_reboot(mut self, requires_reboot: bool) -> Self {
        self.requires_reboot = requires_reboot;
        self
    }

    pub fn with_reclaimable_bytes(mut self, bytes: u64) -> Self {
        self.reclaimable_bytes = Some(bytes);
        self
    }
}
