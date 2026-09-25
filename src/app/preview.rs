//! What a repair run is expected to achieve, in the few words Easy mode uses.
//!
//! Everything here comes from what the scan measured, never from a guess: the
//! disk space is the sum of the sizes the cleanup checks counted, and each
//! "works again" line belongs to a repair that actually changes the thing it
//! names. A finding no repair can change — hardware errors, crash
//! history, a pending restart — promises nothing, so it adds no line.

use super::state::App;
use crate::engine::issue::{Issue, Severity};
use crate::engine::runner::DiagnosticEngine;

/// One kind of improvement, in the order Easy mode lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Benefit {
    Updates,
    SystemFiles,
    Internet,
    Devices,
    WindowsParts,
    Recovery,
    Disk,
    Clock,
    Leftovers,
    Memory,
    FreshStart,
}

impl Benefit {
    pub fn text(self) -> &'static str {
        match self {
            Benefit::Updates => "Windows Update works again",
            Benefit::SystemFiles => "Damaged Windows files are repaired",
            Benefit::Internet => "The internet connection is repaired",
            Benefit::Devices => "Stopped devices are started again",
            Benefit::WindowsParts => "Switched-off Windows services work again",
            Benefit::Recovery => "Restore points and recovery work again",
            Benefit::Disk => "The disk is checked for errors",
            Benefit::Clock => "The clock is right again",
            Benefit::Leftovers => "Leftovers of removed programs are gone",
            Benefit::Memory => "Windows manages its memory itself again",
            Benefit::FreshStart => "Shutting down starts Windows fresh",
        }
    }

    /// What repairing `issue` brings that a user would notice, if anything.
    pub fn of(issue: &Issue) -> Option<Self> {
        let id = issue.id.as_str();
        let service = id.strip_prefix("tweak_svc_");
        Some(match id {
            "sys_dism_corrupt" | "sys_sfc_corrupt" => Benefit::SystemFiles,
            "sys_vss_disabled" | "sys_winre_disabled" => Benefit::Recovery,
            "sys_wmi_broken" | "tweak_policy_store_off" | "tweak_hosts_blocks_windows" => {
                Benefit::WindowsParts
            }
            "tweak_policy_wu_blocked"
            | "tweak_policy_no_auto_update"
            | "tweak_policy_wsus"
            | "net_winhttp_proxy_dead" => Benefit::Updates,
            _ if id.starts_with("wu_svc_disabled_") => Benefit::Updates,
            _ if matches!(service, Some("usosvc" | "trustedinstaller")) => Benefit::Updates,
            _ if matches!(service, Some("dhcp" | "dnscache" | "nsi" | "wcmsvc")) => {
                Benefit::Internet
            }
            _ if service.is_some() => Benefit::WindowsParts,
            "net_dns_failure"
            | "net_winsock_corrupt"
            | "net_proxy_active"
            | "net_offline_warning" => Benefit::Internet,
            _ if id.starts_with("net_no_dhcp_") => Benefit::Internet,
            // A missing driver is only looked for again, which promises nothing.
            _ if id.starts_with("dev_failed_") => Benefit::Devices,
            "storage_dirty_bit" => Benefit::Disk,
            "clock_offset" => Benefit::Clock,
            _ if id.starts_with("reg_orphaned_") || id.starts_with("sched_orphaned_") => {
                Benefit::Leftovers
            }
            _ if id == "pagefile_disabled" || id.starts_with("pagefile_fixed_size_") => {
                Benefit::Memory
            }
            // The same finding is advice only when Fast Startup is already off;
            // only the warning turns it off.
            "restart_overdue" if issue.severity == Severity::Warning => Benefit::FreshStart,
            _ => return None,
        })
    }
}

/// The repair run the Repair button would start, told in advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPreview {
    /// Disk space the ticked cleanups measured.
    pub freed_bytes: u64,
    /// A ticked cleanup frees space it could not measure beforehand, so
    /// [`Self::freed_bytes`] is a lower bound.
    pub frees_unmeasured: bool,
    pub benefits: Vec<Benefit>,
    /// The health score the page will show once every ticked repair worked.
    pub health_after: u8,
    /// At least one ticked repair only takes effect after a restart.
    pub needs_restart: bool,
}

impl RepairPreview {
    /// "Frees about 9.0 GB of disk space", or nothing when nothing is freed.
    pub fn space_line(&self) -> Option<String> {
        match (self.freed_bytes, self.frees_unmeasured) {
            (0, false) => None,
            (0, true) => Some("Frees disk space".to_string()),
            (bytes, false) => Some(format!("Frees about {} of disk space", size(bytes))),
            (bytes, true) => Some(format!("Frees at least {} of disk space", size(bytes))),
        }
    }
}

/// Rounded the way a person says it: "9.0 GB", "280 MB".
fn size(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = MB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GB {
        format!("{:.1} GB", bytes / GB)
    } else {
        format!("{:.0} MB", (bytes / MB).max(1.0))
    }
}

impl App {
    pub fn repair_preview(&self) -> RepairPreview {
        let planned: Vec<&Issue> = self.issues.iter().filter(|i| i.will_repair()).collect();

        let mut benefits: Vec<Benefit> = planned.iter().filter_map(|i| Benefit::of(i)).collect();
        benefits.sort();
        benefits.dedup();

        let after: Vec<Issue> = self
            .issues
            .iter()
            .map(|issue| {
                let mut issue = issue.clone();
                if issue.will_repair() {
                    issue.is_fixed = true;
                }
                issue
            })
            .collect();

        RepairPreview {
            freed_bytes: planned.iter().filter_map(|i| i.reclaimable_bytes).sum(),
            // The component store cleanup is the one cleanup DISM cannot size
            // before it runs.
            frees_unmeasured: planned.iter().any(|i| i.id == "sys_clean_winsxs"),
            benefits,
            health_after: DiagnosticEngine::calculate_health_score(&after),
            needs_restart: planned.iter().any(|i| i.requires_reboot),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::issue::RiskScore;

    fn issue(id: &str, severity: Severity) -> Issue {
        Issue::new(
            id,
            "module",
            id,
            "Category",
            severity,
            RiskScore::Low,
            "description",
            "details",
            "fix",
            vec![],
        )
    }

    fn app_with(issues: Vec<Issue>) -> App {
        let mut app = App::new();
        app.issues = issues;
        app
    }

    const GB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn the_space_is_what_the_ticked_cleanups_measured() {
        let mut unticked =
            issue("sys_clean_package_cache", Severity::Warning).with_reclaimable_bytes(5 * GB);
        unticked.is_selected = false;
        let mut done =
            issue("sys_clean_browser_cache", Severity::Info).with_reclaimable_bytes(3 * GB);
        done.is_fixed = true;
        let app = app_with(vec![
            issue("storage_temp_bloat", Severity::Warning).with_reclaimable_bytes(7 * GB),
            issue("sys_clean_system_temp", Severity::Info).with_reclaimable_bytes(2 * GB),
            unticked,
            done,
        ]);

        let preview = app.repair_preview();
        assert_eq!(preview.freed_bytes, 9 * GB, "only what Repair would clean");
        assert_eq!(
            preview.space_line().as_deref(),
            Some("Frees about 9.0 GB of disk space")
        );
    }

    #[test]
    fn a_cleanup_it_cannot_size_makes_the_space_a_lower_bound() {
        let app = app_with(vec![
            issue("sys_clean_winsxs", Severity::Warning),
            issue("sys_clean_setup_logs", Severity::Info).with_reclaimable_bytes(158 * 1024 * 1024),
        ]);
        assert_eq!(
            app.repair_preview().space_line().as_deref(),
            Some("Frees at least 158 MB of disk space")
        );

        let app = app_with(vec![issue("sys_clean_winsxs", Severity::Warning)]);
        assert_eq!(
            app.repair_preview().space_line().as_deref(),
            Some("Frees disk space")
        );

        let app = app_with(vec![issue("net_dns_failure", Severity::Critical)]);
        assert_eq!(app.repair_preview().space_line(), None, "nothing to free");
    }

    /// A line only for a repair that changes what it names; recording a
    /// finding in the audit log improves nothing a user would notice.
    #[test]
    fn only_repairs_that_change_something_promise_something() {
        let app = app_with(vec![
            issue("evt_whea_hardware_error", Severity::Critical),
            issue("wu_reboot_pending", Severity::Info),
            issue("crash_bugcheck_history", Severity::Warning),
            issue("sched_failing_foo", Severity::Info),
        ]);
        assert!(app.repair_preview().benefits.is_empty());
    }

    /// Advice is never repaired, so it is left in the health forecast even
    /// when something ticked it.
    #[test]
    fn advice_raises_no_health_forecast() {
        let mut advice = issue("storage_smart_warning", Severity::Warning).with_advice_only();
        advice.is_selected = true;
        let app = app_with(vec![advice]);
        assert_eq!(app.repair_preview().health_after, 90);
    }

    #[test]
    fn each_kind_of_benefit_is_listed_once_in_a_fixed_order() {
        let app = app_with(vec![
            issue("net_dns_failure", Severity::Critical),
            issue("sys_sfc_corrupt", Severity::Critical),
            issue("tweak_svc_dhcp", Severity::Critical),
            issue("wu_svc_disabled_bits", Severity::Warning),
            issue("sys_dism_corrupt", Severity::Critical),
        ]);
        assert_eq!(
            app.repair_preview().benefits,
            vec![Benefit::Updates, Benefit::SystemFiles, Benefit::Internet]
        );
    }

    #[test]
    fn an_overdue_restart_promises_a_fresh_start_only_when_it_changes_one() {
        assert_eq!(
            Benefit::of(&issue("restart_overdue", Severity::Warning)),
            Some(Benefit::FreshStart)
        );
        assert_eq!(Benefit::of(&issue("restart_overdue", Severity::Info)), None);
    }

    #[test]
    fn a_stopped_device_promises_a_restart_and_a_missing_driver_nothing() {
        assert_eq!(
            Benefit::of(&issue("dev_failed_usb_vid_046d", Severity::Warning)),
            Some(Benefit::Devices)
        );
        assert_eq!(
            Benefit::of(&issue("dev_no_driver_acpi_amdi0204", Severity::Info)),
            None
        );
    }

    #[test]
    fn health_after_is_the_score_once_every_ticked_repair_worked() {
        let mut unticked = issue("sys_clean_package_cache", Severity::Warning);
        unticked.is_selected = false;
        let app = app_with(vec![
            issue("sys_dism_corrupt", Severity::Critical),
            issue("storage_temp_bloat", Severity::Warning),
            unticked,
        ]);
        assert_eq!(
            app.repair_preview().health_after,
            90,
            "only the unticked warning is left"
        );
    }

    #[test]
    fn a_ticked_repair_that_needs_a_restart_says_so() {
        let app = app_with(vec![
            issue("pagefile_disabled", Severity::Critical).with_requires_reboot(true),
        ]);
        let preview = app.repair_preview();
        assert!(preview.needs_restart);
        assert_eq!(preview.benefits, vec![Benefit::Memory]);
    }
}
