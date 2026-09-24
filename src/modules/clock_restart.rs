//! Whether the clock is right, and whether Windows has really been restarted
//! lately.
//!
//! Both fail quietly. A clock that is minutes off breaks authenticator codes
//! and hours off breaks every HTTPS connection, with errors that name
//! certificates rather than time. And a Windows that "shuts down" every
//! evening can still have been running for weeks: Fast Startup hibernates
//! the running system instead of ending it, and sleep does not end it either.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleConfig, ModuleProgress};
use crate::safety::reg_backup::RegBackupManager;
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::registry::{self, RegKeyValues};
use crate::utils::service;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

/// The server Windows itself synchronises with when it is not in a domain.
const TIME_SERVER: &str = "time.windows.com";

/// Off by a minute, codes from authenticator apps stop being accepted.
/// Ordinary drift between two synchronisations stays well below it.
const CLOCK_WARNING_SECS: f64 = 60.0;

/// Off by an hour, sign-ins and certificate checks start to fail.
const CLOCK_CRITICAL_SECS: f64 = 3600.0;

/// Running this long without a restart is worth a finding.
const RESTART_OVERDUE_DAYS: u64 = 14;

const SESSION_POWER_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power";
const POWER_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Power";
/// "Require use of fast startup" (WinInit.admx): 1 forces it on, anything
/// else leaves the local setting in charge.
const FAST_STARTUP_POLICY_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System";

/// The clock offset in seconds from `w32tm /stripchart ... /dataonly`.
///
/// The sample line is `19:23:06, +02.2742473s`: positive when this clock is
/// behind the server. The header lines are in the display language, and so
/// is the failure (`19:23:06, Fehler: 0x800705B4`), which is why only a
/// number followed by `s` counts as a measurement.
pub fn parse_stripchart_offset(output: &str) -> Option<f64> {
    output.lines().rev().find_map(|line| {
        let (_, sample) = line.rsplit_once(", ")?;
        sample.trim().strip_suffix('s')?.parse().ok()
    })
}

/// `3 min 12 s`, `2 h 5 min`, `3 days 4 h`.
fn describe_duration(secs: f64) -> String {
    let secs = secs.abs();
    if secs < 60.0 {
        return format!("{secs:.1} s");
    }
    let whole = secs.round() as u64;
    let (days, hours, mins, rest) = (
        whole / 86_400,
        whole % 86_400 / 3600,
        whole % 3600 / 60,
        whole % 60,
    );
    if days > 0 {
        let unit = if days == 1 { "day" } else { "days" };
        format!("{days} {unit} {hours} h")
    } else if hours > 0 {
        format!("{hours} h {mins} min")
    } else {
        format!("{mins} min {rest} s")
    }
}

/// What decides whether "Shut down" really ends Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastStartup {
    /// `HiberbootEnabled` under Session Manager\Power: the Control Panel
    /// switch "Turn on fast startup".
    pub setting: Option<u64>,
    /// `HiberbootEnabled` set by group policy.
    pub policy: Option<u64>,
    /// `HibernateEnabled`, else `HibernateEnabledDefault`. Fast Startup is a
    /// hibernation, so without one there is no other.
    pub hibernation: Option<u64>,
}

impl FastStartup {
    pub fn from_registry(
        session_power: &[RegKeyValues],
        power: &[RegKeyValues],
        policy: &[RegKeyValues],
    ) -> Self {
        let number = |keys: &[RegKeyValues], key: &str, name: &str| {
            registry::find(keys, key, name).and_then(|v| v.number())
        };
        Self {
            setting: number(session_power, SESSION_POWER_KEY, "HiberbootEnabled"),
            policy: number(policy, FAST_STARTUP_POLICY_KEY, "HiberbootEnabled"),
            hibernation: number(power, POWER_KEY, "HibernateEnabled")
                .or_else(|| number(power, POWER_KEY, "HibernateEnabledDefault")),
        }
    }

    pub fn active(&self) -> bool {
        (self.policy == Some(1) || self.setting == Some(1)) && self.hibernation.unwrap_or(1) == 1
    }

    fn describe(&self) -> String {
        let show = |v: Option<u64>| v.map_or("not set".to_string(), |v| v.to_string());
        format!(
            "HiberbootEnabled: {}\nHiberbootEnabled (policy): {}\nHibernateEnabled: {}",
            show(self.setting),
            show(self.policy),
            show(self.hibernation)
        )
    }
}

/// How long Windows has been running since it last really started.
pub type UptimeSource = Arc<dyn Fn() -> Duration + Send + Sync>;

/// `GetTickCount64`, which keeps counting through sleep and hibernation - and
/// so through a Fast Startup "shutdown" - just like Task Manager's uptime.
fn real_uptime() -> UptimeSource {
    Arc::new(|| Duration::from_secs(sysinfo::System::uptime()))
}

pub struct ClockRestartModule {
    config: ModuleConfig,
    runner: Arc<dyn CommandRunner>,
    uptime: UptimeSource,
    backup_dir: PathBuf,
}

impl ClockRestartModule {
    pub fn new(config: ModuleConfig) -> Self {
        Self::with_runner(config, Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(config: ModuleConfig, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            config,
            runner,
            uptime: real_uptime(),
            backup_dir: RegBackupManager::new().backup_dir().to_path_buf(),
        }
    }

    /// For tests: an uptime other than the machine's own.
    pub fn with_uptime(mut self, uptime: UptimeSource) -> Self {
        self.uptime = uptime;
        self
    }

    /// The clock offset against [`TIME_SERVER`], or `None` when the server
    /// did not answer. Asks the server directly, so it works while the time
    /// service is stopped.
    async fn clock_offset(&self) -> Result<Option<f64>, String> {
        let computer = format!("/computer:{TIME_SERVER}");
        let out = self
            .runner
            .run(
                "w32tm.exe",
                &["/stripchart", &computer, "/samples:1", "/dataonly"],
                Duration::from_secs(20),
            )
            .await?;
        Ok(parse_stripchart_offset(&out.stdout))
    }

    async fn fast_startup(&self) -> Result<FastStartup, String> {
        let read = |key: &'static str| async move {
            registry::query(&*self.runner, key, false)
                .await
                .map(Option::unwrap_or_default)
        };
        Ok(FastStartup::from_registry(
            &read(SESSION_POWER_KEY).await?,
            &read(POWER_KEY).await?,
            &read(FAST_STARTUP_POLICY_KEY).await?,
        ))
    }

    async fn fix_clock(&self) -> Result<String, String> {
        if service::start_type(&*self.runner, "W32Time").await? == Some(service::SERVICE_DISABLED) {
            return Err("The Windows Time service (W32Time) is disabled, so Windows cannot set its clock. Nothing was changed; re-enable the service first (the Tweaks & Policies check reports it).".to_string());
        }
        // Already running is fine; anything else shows in the result below.
        let _ = self
            .runner
            .run("sc.exe", &["start", "W32Time"], Duration::from_secs(15))
            .await;
        // Waits for the synchronisation unless /nowait is given.
        let _ = self
            .runner
            .run("w32tm.exe", &["/resync", "/force"], Duration::from_secs(60))
            .await;

        match self.clock_offset().await? {
            Some(offset) if offset.abs() < CLOCK_WARNING_SECS => Ok(format!(
                "The clock was synchronised with {TIME_SERVER} and is now off by {}. If it shows the wrong hour, the time zone is wrong: Settings -> Time & language.",
                describe_duration(offset)
            )),
            Some(offset) => Err(format!(
                "The clock was asked to synchronise but is still off by {}. Windows may refuse to move the clock that far in one step: set the date and time once by hand under Settings -> Time & language, then run the repair again.",
                describe_duration(offset)
            )),
            None => Err(format!(
                "{TIME_SERVER} did not answer after the synchronisation, so the clock could not be checked. The time server has to be reachable over UDP port 123."
            )),
        }
    }

    async fn fix_restart(&self) -> Result<String, String> {
        let state = self.fast_startup().await?;
        if !state.active() {
            return Ok("No change was made. Restart Windows (Start -> Power -> Restart) to start it fresh.".to_string());
        }
        if state.policy == Some(1) {
            return Err("A group policy (\"Require use of fast startup\") keeps Fast Startup on. Nothing was changed; restart Windows with Start -> Power -> Restart instead.".to_string());
        }

        if self.config.auto_backup_registry {
            RegBackupManager::with_dir(self.backup_dir.clone())
                .export_key(SESSION_POWER_KEY, "Before turning Fast Startup off")
                .await
                .map_err(|e| {
                    format!("Aborted: the registry backup failed ({e}). Nothing was changed.")
                })?;
        }
        let out = self
            .runner
            .run(
                "reg.exe",
                &[
                    "add",
                    SESSION_POWER_KEY,
                    "/v",
                    "HiberbootEnabled",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ],
                Duration::from_secs(10),
            )
            .await?;
        if !out.success {
            return Err(format!(
                "Could not turn Fast Startup off (exit code {:?}): {}",
                out.exit_code,
                out.stderr.trim()
            ));
        }
        if self.fast_startup().await?.active() {
            return Err(
                "HiberbootEnabled was set to 0 but Fast Startup still reads as on.".to_string(),
            );
        }
        Ok("Fast Startup is off: \"Shut down\" now ends Windows completely. Restart once now to start fresh. To turn it back on: Control Panel -> Power Options -> Choose what the power buttons do.".to_string())
    }

    async fn send_progress(
        progress_tx: &Option<Sender<ModuleProgress>>,
        percent: u8,
        step: &str,
        log: Option<&str>,
    ) {
        if let Some(tx) = progress_tx {
            let _ = tx
                .send(ModuleProgress {
                    module_id: "clock_restart".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(str::to_string),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for ClockRestartModule {
    fn id(&self) -> &'static str {
        "clock_restart"
    }

    fn name(&self) -> &'static str {
        "Clock & Restart"
    }

    fn description(&self) -> &'static str {
        "Compares the clock with an internet time server and checks whether Windows has really been restarted in the last two weeks"
    }

    fn icon(&self) -> &'static str {
        "[CLK]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        Self::send_progress(
            &progress_tx,
            10,
            "Comparing the clock with time.windows.com...",
            Some("w32tm /stripchart"),
        )
        .await;
        match self.clock_offset().await {
            Ok(Some(offset)) if offset.abs() >= CLOCK_WARNING_SECS => {
                let off = describe_duration(offset);
                let direction = if offset > 0.0 { "behind" } else { "ahead" };
                let severity = if offset.abs() >= CLOCK_CRITICAL_SECS {
                    Severity::Critical
                } else {
                    Severity::Warning
                };
                issues.push(Issue::new(
                    "clock_offset",
                    self.id(),
                    format!("The clock is {off} {direction}"),
                    "Clock & Restart",
                    severity,
                    RiskScore::Low,
                    format!(
                        "Windows' clock is {off} {direction} of the internet time. Beyond a minute, codes from authenticator apps are rejected; beyond an hour, websites and sign-ins fail with certificate errors. Windows corrects its clock by itself - when it has not, the Windows Time service is stopped or cannot reach its server."
                    ),
                    format!("w32tm /stripchart /computer:{TIME_SERVER}: offset {offset:+.3} s (positive: this clock is behind)"),
                    "Synchronise the clock now and measure again",
                    vec![
                        "Start the Windows Time service".to_string(),
                        "Run w32tm /resync /force".to_string(),
                        "Measure the offset again".to_string(),
                    ],
                ));
            }
            Ok(Some(offset)) => {
                Self::send_progress(
                    &progress_tx,
                    40,
                    "The clock is right",
                    Some(&format!("Off by {}.", describe_duration(offset))),
                )
                .await;
            }
            Ok(None) | Err(_) => {
                Self::send_progress(
                    &progress_tx,
                    40,
                    "The time server did not answer - the clock was not judged",
                    None,
                )
                .await;
            }
        }

        Self::send_progress(
            &progress_tx,
            60,
            "Checking when Windows last really started...",
            None,
        )
        .await;
        let uptime = (self.uptime)();
        let days = uptime.as_secs() / 86_400;
        if days >= RESTART_OVERDUE_DAYS {
            let state = self.fast_startup().await;
            let fast = state.as_ref().is_ok_and(FastStartup::active);
            let details = format!(
                "Running since the last start: {}\n{}",
                describe_duration(uptime.as_secs_f64()),
                match &state {
                    Ok(state) => state.describe(),
                    Err(err) => format!("Fast Startup state unknown: {err}"),
                }
            );
            let issue = if fast {
                Issue::new(
                    "restart_overdue",
                    self.id(),
                    format!("Windows has not restarted in {days} days"),
                    "Clock & Restart",
                    Severity::Warning,
                    RiskScore::Medium,
                    format!(
                        "Windows has been running for {days} days. Fast Startup is on, so \"Shut down\" does not end Windows: it hibernates the running system and resumes it at the next power-on - and sleep does not end it either. Stuck drivers, leaked memory and half-installed updates are carried along until a real restart. Only \"Restart\" starts Windows fresh, or \"Shut down\" once Fast Startup is off."
                    ),
                    details,
                    "Turn Fast Startup off so that \"Shut down\" starts Windows fresh, then restart once",
                    vec![
                        "Set HiberbootEnabled to 0 (Control Panel -> Power Options -> Choose what the power buttons do)".to_string(),
                        "Restart Windows".to_string(),
                    ],
                )
            } else {
                Issue::new(
                    "restart_overdue",
                    self.id(),
                    format!("Windows has not restarted in {days} days"),
                    "Clock & Restart",
                    Severity::Info,
                    RiskScore::Low,
                    format!(
                        "Windows has been running for {days} days; sleep does not end it. Stuck drivers, leaked memory and half-installed updates are carried along until a restart, which is the first thing to try when the PC has become slow or unreliable."
                    ),
                    details,
                    "Restart Windows (nothing is changed)",
                    vec!["Restart Windows".to_string()],
                )
            };
            let mut issue = issue.with_requires_reboot(true);
            // Turning Fast Startup off trades boot speed for it; that is the
            // user's call, not an unattended repair's.
            issue.is_selected = false;
            issues.push(issue);
        }

        Self::send_progress(&progress_tx, 100, "Clock and restart check complete", None).await;
        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        match issue_id {
            "clock_offset" => self.fix_clock().await,
            "restart_overdue" => self.fix_restart().await,
            _ => Err(format!("Unknown clock & restart issue id: {issue_id}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;
    use crate::utils::service::test_support::sc_qc_output;

    // Captured on a German Windows 11; see tests/fixtures/README.md.
    const STRIPCHART: &[u8] =
        include_bytes!("../../tests/fixtures/console/w32tm_stripchart_de.bin");
    const STRIPCHART_UNREACHABLE: &[u8] =
        include_bytes!("../../tests/fixtures/console/w32tm_stripchart_unreachable_de.bin");
    const SESSION_POWER: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_session_manager_power.bin");
    const POWER: &[u8] = include_bytes!("../../tests/fixtures/console/reg_query_power.bin");
    const MISSING_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_missing_key_de.bin");

    /// The captured measurement with another offset.
    fn stripchart(offset: &str) -> String {
        decode_output(STRIPCHART).replace("+02.2742473s", offset)
    }

    /// The captured Session Manager\Power key, Fast Startup switched `on`.
    fn session_power(on: bool) -> String {
        let value = if on { "0x1" } else { "0x0" };
        decode_output(SESSION_POWER).replace(
            "HiberbootEnabled    REG_DWORD    0x0",
            &format!("HiberbootEnabled    REG_DWORD    {value}"),
        )
    }

    fn missing_key() -> CmdOutput {
        CmdOutput {
            success: false,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: decode_output(MISSING_KEY),
        }
    }

    fn query(key: &str) -> String {
        format!("query {key}")
    }

    /// A machine as captured: clock 2.3 s behind, Fast Startup `fast`, no
    /// policy.
    fn machine(fast: bool) -> MockCommandRunner {
        machine_with(
            fast,
            CmdOutput::ok(decode_output(STRIPCHART)),
            missing_key(),
        )
    }

    fn machine_with(fast: bool, clock: CmdOutput, policy: CmdOutput) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("/stripchart", clock);
        mock.add_response("reg.exe add", CmdOutput::ok(""));
        mock.add_response(query(SESSION_POWER_KEY), CmdOutput::ok(session_power(fast)));
        mock.add_response(query(POWER_KEY), CmdOutput::ok(decode_output(POWER)));
        mock.add_response(query(FAST_STARTUP_POLICY_KEY), policy);
        mock
    }

    fn clock_off(offset: &str) -> MockCommandRunner {
        machine_with(false, CmdOutput::ok(stripchart(offset)), missing_key())
    }

    /// `reg query` of the policy key with "Require use of fast startup" on.
    fn forcing_policy() -> String {
        format!(
            "\r\n{}\r\n    HiberbootEnabled    REG_DWORD    0x1\r\n",
            FAST_STARTUP_POLICY_KEY.replace("HKLM", "HKEY_LOCAL_MACHINE")
        )
    }

    fn module(mock: &MockCommandRunner, uptime_days: u64) -> ClockRestartModule {
        let config = ModuleConfig {
            auto_backup_registry: false,
            ..ModuleConfig::default()
        };
        ClockRestartModule::with_runner(config, Arc::new(mock.clone())).with_uptime(Arc::new(
            move || Duration::from_secs(uptime_days * 86_400 + 3_600),
        ))
    }

    #[test]
    fn the_offset_is_read_from_the_sample_line_only() {
        assert_eq!(
            parse_stripchart_offset(&decode_output(STRIPCHART)),
            Some(2.2742473)
        );
        // "19:23:06, Fehler: 0x800705B4" - translated, and not a measurement.
        assert_eq!(
            parse_stripchart_offset(&decode_output(STRIPCHART_UNREACHABLE)),
            None
        );
        assert_eq!(
            parse_stripchart_offset(&stripchart("-125.5000000s")),
            Some(-125.5)
        );
        assert_eq!(parse_stripchart_offset(""), None);
    }

    #[test]
    fn durations_read_like_a_clock() {
        assert_eq!(describe_duration(-12.34), "12.3 s");
        assert_eq!(describe_duration(192.0), "3 min 12 s");
        assert_eq!(describe_duration(7_500.0), "2 h 5 min");
        assert_eq!(describe_duration(86_400.0), "1 day 0 h");
        assert_eq!(
            describe_duration(3.0 * 86_400.0 + 4.0 * 3_600.0),
            "3 days 4 h"
        );
    }

    fn keys(output: &str) -> Vec<RegKeyValues> {
        registry::parse_reg_query(output)
    }

    #[test]
    fn fast_startup_needs_the_switch_and_hibernation() {
        let power = keys(&decode_output(POWER));

        let captured = FastStartup::from_registry(&keys(&session_power(false)), &power, &[]);
        assert_eq!(
            captured,
            FastStartup {
                setting: Some(0),
                policy: None,
                hibernation: Some(1),
            }
        );
        assert!(!captured.active());

        assert!(FastStartup::from_registry(&keys(&session_power(true)), &power, &[]).active());

        let no_hibernation = decode_output(POWER).replace(
            "HibernateEnabled    REG_DWORD    0x1",
            "HibernateEnabled    REG_DWORD    0x0",
        );
        assert!(
            !FastStartup::from_registry(&keys(&session_power(true)), &keys(&no_hibernation), &[])
                .active()
        );

        let policy = keys(&forcing_policy());
        assert!(FastStartup::from_registry(&keys(&session_power(false)), &power, &policy).active());
    }

    #[tokio::test]
    async fn a_right_clock_and_a_recent_start_are_not_findings() {
        let issues = module(&machine(true), 3).scan(None).await.unwrap();
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[tokio::test]
    async fn a_clock_minutes_behind_is_a_warning() {
        let issues = module(&clock_off("+185.0000000s"), 0)
            .scan(None)
            .await
            .unwrap();
        let issue = issues.iter().find(|i| i.id == "clock_offset").unwrap();
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.title, "The clock is 3 min 5 s behind");
    }

    #[tokio::test]
    async fn a_clock_hours_ahead_is_critical() {
        let issues = module(&clock_off("-7500.0000000s"), 0)
            .scan(None)
            .await
            .unwrap();
        let issue = issues.iter().find(|i| i.id == "clock_offset").unwrap();
        assert_eq!(issue.severity, Severity::Critical);
        assert_eq!(issue.title, "The clock is 2 h 5 min ahead");
    }

    #[tokio::test]
    async fn an_unreachable_time_server_is_not_a_finding() {
        let mock = machine_with(
            false,
            CmdOutput::ok(decode_output(STRIPCHART_UNREACHABLE)),
            missing_key(),
        );
        let issues = module(&mock, 0).scan(None).await.unwrap();
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[tokio::test]
    async fn weeks_without_a_restart_through_fast_startup_are_a_warning() {
        let issues = module(&machine(true), 20).scan(None).await.unwrap();
        let issue = issues.iter().find(|i| i.id == "restart_overdue").unwrap();
        assert_eq!(issue.title, "Windows has not restarted in 20 days");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.requires_reboot);
        assert!(
            !issue.is_selected,
            "turning Fast Startup off is the user's call"
        );
        assert!(issue.technical_details.contains("HiberbootEnabled: 1"));
    }

    #[tokio::test]
    async fn weeks_without_a_restart_otherwise_are_information() {
        let issues = module(&machine(false), 20).scan(None).await.unwrap();
        let issue = issues.iter().find(|i| i.id == "restart_overdue").unwrap();
        assert_eq!(issue.severity, Severity::Info);
        assert!(issue.requires_reboot);
    }

    #[tokio::test]
    async fn turning_fast_startup_off_is_read_back() {
        let mock = machine(true);
        mock.add_response_after(
            "reg.exe add",
            query(SESSION_POWER_KEY),
            CmdOutput::ok(session_power(false)),
        );
        let msg = module(&mock, 20)
            .fix("restart_overdue", None)
            .await
            .unwrap();
        assert!(msg.contains("Fast Startup is off"), "{msg}");
        assert!(mock.executed().iter().any(|c| c.contains(
            r"reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power /v HiberbootEnabled /t REG_DWORD /d 0 /f"
        )));
    }

    #[tokio::test]
    async fn a_value_that_does_not_change_is_a_failure() {
        let err = module(&machine(true), 20)
            .fix("restart_overdue", None)
            .await
            .unwrap_err();
        assert!(err.contains("still reads as on"), "{err}");
    }

    #[tokio::test]
    async fn a_policy_that_forces_fast_startup_is_not_fought() {
        let mock = machine_with(
            false,
            CmdOutput::ok(decode_output(STRIPCHART)),
            CmdOutput::ok(forcing_policy()),
        );
        let err = module(&mock, 20)
            .fix("restart_overdue", None)
            .await
            .unwrap_err();
        assert!(err.contains("group policy"), "{err}");
        assert!(!mock.executed().iter().any(|c| c.contains("reg.exe add")));
    }

    #[tokio::test]
    async fn without_fast_startup_the_restart_repair_changes_nothing() {
        let mock = machine(false);
        let msg = module(&mock, 20)
            .fix("restart_overdue", None)
            .await
            .unwrap();
        assert!(msg.starts_with("No change was made."), "{msg}");
        assert!(!mock.executed().iter().any(|c| c.contains("reg.exe add")));
    }

    fn clock_mock(time_service: u32, after_resync: &str) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "sc.exe qc",
            CmdOutput::ok(sc_qc_output("W32Time", time_service)),
        );
        mock.add_response("sc.exe start", CmdOutput::ok(""));
        mock.add_response("/resync", CmdOutput::ok(""));
        mock.add_response("/stripchart", CmdOutput::ok(stripchart("+185.0000000s")));
        mock.add_response_after(
            "/resync",
            "/stripchart",
            CmdOutput::ok(stripchart(after_resync)),
        );
        mock
    }

    #[tokio::test]
    async fn a_synchronised_clock_is_measured_again() {
        let mock = clock_mock(3, "+00.0123000s");
        let msg = module(&mock, 0).fix("clock_offset", None).await.unwrap();
        assert!(msg.contains("now off by 0.0 s"), "{msg}");
        assert!(
            mock.executed()
                .contains(&"w32tm.exe /resync /force".to_string())
        );
    }

    #[tokio::test]
    async fn a_clock_that_stays_off_is_a_failure() {
        let mock = clock_mock(3, "+185.0000000s");
        let err = module(&mock, 0)
            .fix("clock_offset", None)
            .await
            .unwrap_err();
        assert!(err.contains("still off by 3 min 5 s"), "{err}");
    }

    #[tokio::test]
    async fn a_disabled_time_service_is_named_not_worked_around() {
        let mock = clock_mock(4, "+00.0123000s");
        let err = module(&mock, 0)
            .fix("clock_offset", None)
            .await
            .unwrap_err();
        assert!(err.contains("W32Time) is disabled"), "{err}");
        assert!(!mock.executed().iter().any(|c| c.contains("/resync")));
    }
}
