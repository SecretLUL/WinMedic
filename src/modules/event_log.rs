use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::event_xml::{read_events, system_log_query};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

// There is no check for "errors in the System log" as such: every Windows logs
// some, a fresh CI runner included, so it fired on every PC and told nobody
// what to do. Crashes, WHEA faults, disks, services and updates have checks of
// their own that name the cause. Minidumps are the crash analysis' evidence,
// and WHEA faults the WHEA logger's: counted here as well, each weighed twice
// on the health score.

const MEMORY_DIAGNOSTICS_PROVIDER: &str = "Microsoft-Windows-MemoryDiagnostics-Results";

/// A memory test is run rarely and on purpose, so its result stays relevant
/// for months.
const MEMORY_TEST_LOOKBACK_MS: u64 = 90 * 24 * 3_600_000;

/// Whether a MemoryDiagnostics-Results event reports defective RAM.
///
/// The IDs are from the provider's own manifest
/// (`wevtutil gp Microsoft-Windows-MemoryDiagnostics-Results /ge /gm:true`):
/// 1101 and 1201 are "no errors", 1102 and 1202 "hardware errors", and 1103
/// and 1104 a test that was cancelled or could not finish, which says nothing
/// about the RAM and is not queried.
pub fn memory_test_found_errors(event_id: u32) -> bool {
    matches!(event_id, 1102 | 1202)
}

/// What scheduling the memory test runs.
pub const SCHEDULE_MEMORY_TEST: [&str; 2] = ["/bootsequence", "{memdiag}"];

/// Schedule the Windows Memory Diagnostic for the next start, the way its
/// "Check for problems the next time I start my computer" does: a one-time
/// boot entry for the memory tester.
///
/// `mdsched.exe` itself is only that dialog. Started with a five-second limit,
/// it was killed before anyone could click and the repair failed; clicking
/// "Restart now" in time restarted the PC in the middle of the repair run.
/// The test's verdict comes back as [`memory_test_found_errors`].
/// A finding whose repair is [`schedule_memory_test`]: it takes effect at
/// the next start, which the test then holds up for half an hour, so it
/// waits to be ticked.
pub fn memory_test_finding(issue: Issue) -> Issue {
    let mut issue = issue.with_requires_reboot(true);
    issue.risk_score = RiskScore::High;
    issue.is_selected = false;
    issue
}

pub async fn schedule_memory_test(runner: &dyn CommandRunner) -> Result<String, String> {
    let out = runner
        .run(
            "bcdedit.exe",
            &SCHEDULE_MEMORY_TEST,
            Duration::from_secs(15),
        )
        .await?;
    if out.success {
        Ok("The Windows Memory Diagnostic runs at the next restart and takes 15 to 30 minutes. The next scan shows its result.".to_string())
    } else {
        Err(format!(
            "The memory test could not be scheduled (bcdedit exit code {:?}): {}. Start 'Windows Memory Diagnostic' from the Start menu instead.",
            out.exit_code,
            [out.stdout.trim(), out.stderr.trim()].join(" ").trim()
        ))
    }
}

pub struct EventLogModule {
    runner: Arc<dyn CommandRunner>,
}

impl Default for EventLogModule {
    fn default() -> Self {
        Self::new()
    }
}

impl EventLogModule {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
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
                    module_id: "event_log".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for EventLogModule {
    fn id(&self) -> &'static str {
        "event_log"
    }

    fn name(&self) -> &'static str {
        "Memory Test Results"
    }

    fn description(&self) -> &'static str {
        "Reads the verdict of the last Windows Memory Diagnostic"
    }

    fn icon(&self) -> &'static str {
        "[LOG]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // The last Windows Memory Diagnostic result. WinMedic schedules the
        // test when a crash or a WHEA record points at RAM; this is where its
        // verdict comes back.
        let memtest_query = system_log_query(
            &format!(
                "Provider[@Name='{MEMORY_DIAGNOSTICS_PROVIDER}'] and (EventID=1101 or EventID=1102 or EventID=1201 or EventID=1202)"
            ),
            MEMORY_TEST_LOOKBACK_MS,
            1,
        );
        let memtest_query: Vec<&str> = memtest_query.iter().map(String::as_str).collect();
        let latest_memtest = read_events(
            self.runner
                .run("wevtutil.exe", &memtest_query, Duration::from_secs(10))
                .await,
        )?
        .into_iter()
        .next();
        if let Some(test) = latest_memtest {
            let when = test.summary();
            if memory_test_found_errors(test.event_id) {
                issues.push(Issue::new(
                    "evt_memory_test_failed",
                    self.id(),
                    "The Windows Memory Diagnostic found hardware errors",
                    "Event-Log & Crashes",
                    Severity::Critical,
                    RiskScore::High,
                    "The last memory test found defective RAM. Blue screens, corrupted files, failed updates and random crashes follow from it, and no software repair fixes any of them. A later test that finds no errors clears this finding.",
                    when,
                    "Find and replace the faulty memory module",
                    vec![
                        "Reset memory overclocking (XMP/EXPO) in the BIOS/UEFI and test again"
                            .to_string(),
                        "Test one module at a time with mdsched.exe to find the faulty one"
                            .to_string(),
                        "Replace the faulty module".to_string(),
                    ],
                ).with_advice_only());
            } else {
                Self::send_progress(
                    &progress_tx,
                    98,
                    "Last memory test passed",
                    Some(&format!(
                        "Windows Memory Diagnostic found no errors: {when}"
                    )),
                )
                .await;
            }
        }

        Self::send_progress(&progress_tx, 100, "Event log analysis complete", None).await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        // The memory-test finding is advice: nothing here can repair RAM, so a
        // repair run never asks.
        Err(format!("Unknown issue id: {}", issue_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    const SYSTEM_ERRORS: &str = include_str!("../../tests/fixtures/events/system_errors.xml");

    /// Every Windows logs errors; the five real ones in the fixture are what a
    /// healthy PC has. Asked for them or not, they are not a finding.
    #[tokio::test]
    async fn errors_in_the_system_log_are_not_a_finding_by_themselves() {
        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil", CmdOutput::ok(SYSTEM_ERRORS));

        let module = EventLogModule::with_runner(Arc::new(mock.clone()));
        let issues = module.scan(None).await.unwrap();

        assert!(issues.is_empty(), "{issues:?}");
        assert!(
            !mock
                .executed()
                .iter()
                .any(|c| c.contains("Level=1 or Level=2")),
            "the System log is not searched for errors as such"
        );
        assert!(
            !mock.executed().iter().any(|c| c.contains("WHEA-Logger")),
            "WHEA faults are the WHEA logger's; counted here too, they weighed twice"
        );
    }

    #[tokio::test]
    async fn a_refused_event_query_fails_the_module_instead_of_passing_it() {
        let mock = MockCommandRunner::new();
        // What wevtutil answered to every query WinMedic used to send.
        mock.add_response(
            "MemoryDiagnostics",
            CmdOutput::with_output(87, "Es wurden zu viele Argumente angegeben.", ""),
        );

        let module = EventLogModule::with_runner(Arc::new(mock.clone()));
        let err = module.scan(None).await.unwrap_err();
        assert!(err.contains("exit code 87"), "{err}");

        let query = mock
            .executed()
            .into_iter()
            .find(|c| c.contains("wevtutil"))
            .unwrap();
        assert!(query.contains("/q:*[System[Provider["), "{query}");
        assert!(query.contains("timediff(@SystemTime)"), "{query}");
    }

    /// A MemoryDiagnostics-Results event in the shape wevtutil prints it.
    fn memtest_event(id: u32) -> String {
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-MemoryDiagnostics-Results' Guid='{{5f92bc59-248f-4111-86a9-e393e12c6139}}'/><EventID>{id}</EventID><Level>{}</Level><TimeCreated SystemTime='2026-09-20T06:12:03.0000000Z'/></System><EventData></EventData></Event>",
            if memory_test_found_errors(id) { 2 } else { 4 }
        )
    }

    async fn scan_with_memtest(output: String) -> Vec<Issue> {
        let mock = MockCommandRunner::new();
        mock.add_response("WHEA-Logger", CmdOutput::ok(""));
        mock.add_response("MemoryDiagnostics", CmdOutput::ok(output));
        EventLogModule::with_runner(Arc::new(mock))
            .scan(None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_memory_test_that_found_errors_is_reported() {
        for id in [1102, 1202] {
            let issues = scan_with_memtest(memtest_event(id)).await;
            let issue = issues
                .iter()
                .find(|i| i.id == "evt_memory_test_failed")
                .unwrap_or_else(|| panic!("event {id} is a failed test"));
            assert_eq!(issue.severity, Severity::Critical);
            assert!(issue.advice_only, "no software repair fixes RAM");
            assert!(!issue.is_selected);
            assert!(issue.technical_details.contains("2026-09-20"));
        }
    }

    #[tokio::test]
    async fn a_passed_memory_test_is_not_a_finding() {
        for id in [1101, 1201] {
            let issues = scan_with_memtest(memtest_event(id)).await;
            assert!(
                !issues.iter().any(|i| i.id == "evt_memory_test_failed"),
                "{id}"
            );
        }
    }

    #[tokio::test]
    async fn the_memory_test_is_scheduled_for_the_next_start() {
        let mock = MockCommandRunner::new();
        mock.add_response("bcdedit.exe", CmdOutput::ok(""));
        let msg = schedule_memory_test(&mock).await.unwrap();
        assert!(msg.contains("next restart"), "{msg}");
        assert_eq!(mock.executed(), ["bcdedit.exe /bootsequence {memdiag}"]);
    }

    #[tokio::test]
    async fn a_memory_test_that_could_not_be_scheduled_is_a_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "bcdedit.exe",
            CmdOutput::with_output(1, "", "Zugriff verweigert"),
        );
        let err = schedule_memory_test(&mock).await.unwrap_err();
        assert!(err.contains("Zugriff verweigert"), "{err}");
        assert!(err.contains("Start menu"), "{err}");
    }
}
