use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::event_xml::{EventRecord, read_events, system_log_query};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

// There is no check for "errors in the System log" as such: every Windows logs
// some, a fresh CI runner included, so it fired on every PC and told nobody
// what to do. Crashes, WHEA faults, disks, services and updates have checks of
// their own that name the cause.

/// WHEA faults are rare enough that a week is the window, whatever the event
/// log setting says.
const WHEA_LOOKBACK_MS: u64 = 7 * 24 * 3_600_000;

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
        "Event-Log & Crash-Dump Analyse"
    }

    fn description(&self) -> &'static str {
        "Analyses the Windows event logs (System/Application), BSOD minidumps and WHEA hardware faults"
    }

    fn icon(&self) -> &'static str {
        "[LOG]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. Minidumps
        Self::send_progress(
            &progress_tx,
            15,
            "Checking for BSOD minidumps (%SystemRoot%\\Minidump)...",
            Some("Scanning the minidump directory..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let minidump_dir = Path::new(r"C:\Windows\Minidump");
        if minidump_dir.exists() {
            let mut dmp_files = Vec::new();
            if let Ok(entries) = std::fs::read_dir(minidump_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e.to_string_lossy().to_lowercase())
                        == Some("dmp".to_string())
                        && let Ok(meta) = entry.metadata()
                    {
                        let size_kb = meta.len() / 1024;
                        dmp_files.push(format!(
                            "{} ({} KB)",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            size_kb
                        ));
                    }
                }
            }

            if !dmp_files.is_empty() {
                let count = dmp_files.len();
                let sample_list = dmp_files
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                issues.push(Issue::new(
                    "evt_bsod_dumps_found",
                    self.id(),
                    format!("{} blue screen (BSOD) minidump crash reports found", count),
                    "Event-Log & Crashes",
                    Severity::Critical,
                    RiskScore::Low,
                    format!("{} minidump files were found under C:\\Windows\\Minidump. These point to previous kernel crashes or driver faults.", count),
                    format!("Dumps found:\n{}", sample_list),
                    "Check drivers for updates and clean up old minidumps once analysed",
                    vec![
                        "Archive or clean up old minidump files".to_string(),
                        "Bring drivers and Windows updates up to date".to_string(),
                    ],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    35,
                    "No BSOD crash dumps",
                    Some("No blue screen minidumps found in %WINDIR%\\Minidump."),
                )
                .await;
            }
        } else {
            Self::send_progress(
                &progress_tx,
                35,
                "Minidump directory empty",
                Some("The minidump directory is clean."),
            )
            .await;
        }

        // 2. WHEA Hardware Logger
        Self::send_progress(
            &progress_tx,
            85,
            "Checking for WHEA hardware faults...",
            Some("Filtering for WHEA-Logger..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let whea_query = system_log_query(
            "Provider[@Name='Microsoft-Windows-WHEA-Logger']",
            WHEA_LOOKBACK_MS,
            3,
        );
        let whea_query: Vec<&str> = whea_query.iter().map(String::as_str).collect();
        let whea_events: Vec<EventRecord> = read_events(
            self.runner
                .run("wevtutil.exe", &whea_query, Duration::from_secs(10))
                .await,
        )?
        .into_iter()
        .filter(|e| e.provider == "Microsoft-Windows-WHEA-Logger")
        .collect();

        if !whea_events.is_empty() {
            issues.push(Issue::new(
                "evt_whea_hardware_error",
                self.id(),
                "WHEA hardware faults found in the system log",
                "Event-Log & Crashes",
                Severity::Critical,
                RiskScore::High,
                "Windows Hardware Error Architecture (WHEA) is reporting hardware warnings (for example CPU voltage drops, PCIe bus errors or unstable RAM).",
                whea_events
                    .iter()
                    .map(EventRecord::details)
                    .collect::<Vec<_>>()
                    .join("\n"),
                "Apply a BIOS/UEFI update, reset any overclock and run a RAM diagnostic",
                vec!["Schedule the Windows memory diagnostic (mdsched.exe)".to_string()],
            ).with_advice_only());
        } else {
            Self::send_progress(
                &progress_tx,
                95,
                "WHEA hardware intact",
                Some("No WHEA hardware faults or PCIe/CPU issues logged."),
            )
            .await;
        }

        // 3. The last Windows Memory Diagnostic result. WinMedic schedules the
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
        match issue_id {
            "evt_bsod_dumps_found" => {
                let minidump_dir = Path::new(r"C:\Windows\Minidump");
                let mut removed = 0;
                if minidump_dir.exists()
                    && let Ok(entries) = std::fs::read_dir(minidump_dir)
                {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().map(|e| e.to_string_lossy().to_lowercase())
                            == Some("dmp".to_string())
                            && std::fs::remove_file(path).is_ok()
                        {
                            removed += 1;
                        }
                    }
                }
                Ok(format!(
                    "Safely cleaned up {} stale minidump files.",
                    removed
                ))
            }
            // The critical-event, WHEA and memory-test findings are advice:
            // nothing here can repair them, so a repair run never asks.
            _ => Err(format!("Unknown issue id: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    const WHEA_EVENTS: &str = include_str!("../../tests/fixtures/events/whea_constructed.xml");
    const SYSTEM_ERRORS: &str = include_str!("../../tests/fixtures/events/system_errors.xml");

    #[tokio::test]
    async fn test_event_log_detects_whea_error() {
        let mock = MockCommandRunner::new();
        mock.add_response("WHEA-Logger", CmdOutput::ok(WHEA_EVENTS));
        mock.add_response("MemoryDiagnostics", CmdOutput::ok(""));

        let module = EventLogModule::with_runner(Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        let whea_issue = issues.iter().find(|i| i.id == "evt_whea_hardware_error");
        assert!(whea_issue.is_some());
        let whea_issue = whea_issue.unwrap();
        assert_eq!(whea_issue.severity, Severity::Critical);
        assert!(whea_issue.technical_details.contains("ApicId: 4"));
        assert!(!whea_issue.technical_details.contains("RawData"));
        assert!(
            whea_issue.advice_only,
            "a hardware fault is not repaired in software"
        );
    }

    /// Every Windows logs errors; the five real ones in the fixture are what a
    /// healthy PC has. Asked for them or not, they are not a finding.
    #[tokio::test]
    async fn errors_in_the_system_log_are_not_a_finding_by_themselves() {
        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil", CmdOutput::ok(SYSTEM_ERRORS));

        let module = EventLogModule::with_runner(Arc::new(mock.clone()));
        let issues = module.scan(None).await.unwrap();

        assert!(
            issues.iter().all(|i| i.id == "evt_bsod_dumps_found"),
            "{issues:?}"
        );
        assert!(
            !mock
                .executed()
                .iter()
                .any(|c| c.contains("Level=1 or Level=2")),
            "the System log is not searched for errors as such"
        );
    }

    #[tokio::test]
    async fn a_refused_event_query_fails_the_module_instead_of_passing_it() {
        let mock = MockCommandRunner::new();
        // What wevtutil answered to every query WinMedic used to send.
        mock.add_response(
            "WHEA-Logger",
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
}
