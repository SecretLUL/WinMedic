use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CmdOutput, CommandRunner, SystemCommandRunner};
use crate::utils::service::{self, SERVICE_DISABLED};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

/// `/English` pins DISM's output language. Its verdict is a sentence in the
/// display language otherwise, and the German one ("Der Komponentenspeicher
/// kann repariert werden.") matched none of the words this check looked for,
/// so a damaged store was reported as intact on every German machine.
const DISM_CHECK_HEALTH_ARGS: &[&str] = &["/English", "/Online", "/Cleanup-Image", "/CheckHealth"];
const DISM_RESTORE_HEALTH_ARGS: &[&str] =
    &["/English", "/Online", "/Cleanup-Image", "/RestoreHealth"];

/// How much of the end of CBS.log to read. The log grows to hundreds of
/// megabytes; the last SFC or DISM run is all that matters, and its summary
/// sits at the very end.
const CBS_TAIL_BYTES: u64 = 64 * 1024;

/// What `DISM /CheckHealth` said about the component store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentStoreHealth {
    Healthy,
    Repairable,
    NotRepairable,
    /// DISM did not run to a verdict; the reason is for the log.
    Unknown(String),
}

impl ComponentStoreHealth {
    pub fn from_dism(output: &CmdOutput) -> Self {
        if !output.success {
            return Self::Unknown(match output.exit_code {
                Some(740) => "DISM needs Administrator rights".to_string(),
                Some(code) => format!("DISM exited with code {code}"),
                None => "DISM was terminated".to_string(),
            });
        }
        let text = output.stdout.to_lowercase();
        // The English sentences come from DISM's own resources. The German
        // ones stay for a DISM that ignores /English; they are the same
        // resources' de-DE versions.
        let says = |phrases: &[&str]| phrases.iter().any(|p| text.contains(p));
        if says(&[
            "the component store cannot be repaired",
            "der komponentenspeicher kann nicht repariert werden",
        ]) {
            Self::NotRepairable
        } else if says(&[
            "the component store is repairable",
            "der komponentenspeicher kann repariert werden",
        ]) {
            Self::Repairable
        } else if says(&[
            "no component store corruption detected",
            "es wurde keine komponentenspeicherbeschädigung erkannt",
        ]) {
            Self::Healthy
        } else {
            Self::Unknown("DISM reported no health verdict".to_string())
        }
    }
}

/// Whether the end of CBS.log records corruption the last run left unrepaired,
/// with the lines that say so.
///
/// Matching the bare word "Corrupt" fired on DISM's own summary, whose
/// "Total Detected Corruption: 0" says the opposite — so every DISM run,
/// WinMedic's own repair included, made the next scan report damaged system
/// files. Only statements of an unrepaired file count here: SFC giving up on
/// one, or a DISM summary that detected more than it repaired.
pub fn cbs_unrepaired_corruption(tail: &str) -> Option<String> {
    const SFC_GAVE_UP: [&str; 2] = [
        "Cannot repair member file",
        "Could not reproject corrupted file",
    ];
    let mut evidence: Vec<String> = tail
        .lines()
        .filter(|line| SFC_GAVE_UP.iter().any(|marker| line.contains(marker)))
        .take(3)
        .map(|line| line.trim().to_string())
        .collect();

    let count_after = |label: &str, text: &str| -> Option<(usize, u32)> {
        let at = text.rfind(label)?;
        let value = text[at + label.len()..]
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()?;
        Some((at, value))
    };
    if let Some((at, detected)) = count_after("Total Detected Corruption:", tail) {
        let repaired = count_after("Total Repaired Corruption:", &tail[at..])
            .map(|(_, repaired)| repaired)
            .unwrap_or(0);
        if detected > repaired {
            evidence.push(format!(
                "DISM summary: {detected} corruption(s) detected, {repaired} repaired"
            ));
        }
    }

    (!evidence.is_empty()).then(|| evidence.join("\n"))
}

fn read_tail(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(max_bytes)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn default_cbs_log() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join(r"Logs\CBS\CBS.log")
}

pub struct SystemIntegrityModule {
    runner: Arc<dyn CommandRunner>,
    cbs_log: PathBuf,
}

impl Default for SystemIntegrityModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemIntegrityModule {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self::with_runner_and_cbs_log(runner, default_cbs_log())
    }

    /// For tests: read `cbs_log` instead of the machine's own CBS.log.
    pub fn with_runner_and_cbs_log(runner: Arc<dyn CommandRunner>, cbs_log: PathBuf) -> Self {
        Self { runner, cbs_log }
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
                    module_id: "system_integrity".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for SystemIntegrityModule {
    fn id(&self) -> &'static str {
        "system_integrity"
    }

    fn name(&self) -> &'static str {
        "System Integrity (DISM / SFC / VSS)"
    }

    fn description(&self) -> &'static str {
        "Checks the component store (DISM), system files (SFC) and Volume Shadow Copy services"
    }

    fn icon(&self) -> &'static str {
        "[SYS]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. DISM CheckHealth
        Self::send_progress(
            &progress_tx,
            15,
            "Checking the component store (DISM CheckHealth, ~45s)...",
            Some("Running DISM /Online /Cleanup-Image /CheckHealth..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let dism_check = self
            .runner
            .run("dism.exe", DISM_CHECK_HEALTH_ARGS, Duration::from_secs(45))
            .await;

        match dism_check {
            Ok(output) => match ComponentStoreHealth::from_dism(&output) {
                ComponentStoreHealth::Repairable => {
                    issues.push(Issue::new(
                        "sys_dism_corrupt",
                        self.id(),
                        "Windows component store is corrupted",
                        "System Integrity",
                        Severity::Critical,
                        RiskScore::Low,
                        "The Windows component store (WinSxS) holds corrupted or inconsistent packages. This causes update and system failures.",
                        output.stdout.clone(),
                        "Repair automatically via DISM /Online /Cleanup-Image /RestoreHealth",
                        vec![
                            "Run DISM RestoreHealth with Windows Update as the repair source".to_string(),
                            "Synchronise the component store and refresh its cache".to_string(),
                        ],
                    ));
                }
                ComponentStoreHealth::NotRepairable => {
                    // RestoreHealth cannot fix a store DISM itself calls
                    // unrepairable, so offering it would be a repair that is
                    // bound to fail. What does work keeps apps and files.
                    issues.push(Issue::new(
                        "sys_dism_unrepairable",
                        self.id(),
                        "Windows component store cannot be repaired",
                        "System Integrity",
                        Severity::Critical,
                        RiskScore::High,
                        "DISM reports that the component store is damaged beyond what it can repair. Updates and feature changes will keep failing. A repair install of Windows replaces the system files while keeping installed apps and personal files.",
                        output.stdout.clone(),
                        "Run a Windows repair install that keeps apps and files",
                        vec![
                            "Windows 11: Settings > System > Recovery > 'Fix problems using Windows Update'".to_string(),
                            "Otherwise: mount a Windows ISO of the same edition and run setup.exe, choosing 'Keep personal files and apps'".to_string(),
                        ],
                    ));
                }
                ComponentStoreHealth::Healthy => {
                    Self::send_progress(
                        &progress_tx,
                        35,
                        "DISM component store is intact",
                        Some("DISM CheckHealth: no corruption found in the component store."),
                    )
                    .await;
                }
                ComponentStoreHealth::Unknown(reason) => {
                    // Not "intact": nothing was checked, and saying otherwise
                    // is how an unelevated scan used to pass a damaged store.
                    Self::send_progress(
                        &progress_tx,
                        35,
                        "DISM check skipped",
                        Some(&format!("DISM CheckHealth gave no verdict: {reason}")),
                    )
                    .await;
                }
            },
            Err(e) => {
                Self::send_progress(
                    &progress_tx,
                    35,
                    "DISM check skipped (insufficient privileges)",
                    Some(&e),
                )
                .await;
            }
        }

        // 2. VSS Service Status
        Self::send_progress(
            &progress_tx,
            55,
            "Checking Volume Shadow Copy & VSS services...",
            Some("Querying the VSS and swprv service status..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        match service::start_type(&*self.runner, "vss").await {
            Ok(Some(SERVICE_DISABLED)) => {
                issues.push(Issue::new(
                    "sys_vss_disabled",
                    self.id(),
                    "Volume Shadow Copy service (VSS) is disabled",
                    "System Integrity",
                    Severity::Warning,
                    RiskScore::Low,
                    "The VSS service is disabled, so Windows can create neither system restore points nor consistent backups.",
                    "sc qc vss: START_TYPE 4 (DISABLED)",
                    "Reset the VSS service start type to 'Manual/Demand' and enable the service",
                    vec!["sc config vss start= demand".to_string(), "net start vss".to_string()],
                ));
            }
            Ok(Some(_)) => {
                Self::send_progress(
                    &progress_tx,
                    70,
                    "VSS service ready",
                    Some("VSS service status: ready for restore points."),
                )
                .await;
            }
            Ok(None) | Err(_) => {
                Self::send_progress(
                    &progress_tx,
                    70,
                    "VSS service state unknown",
                    Some("sc qc vss reported no start type; the VSS check was skipped."),
                )
                .await;
            }
        }

        // 3. CBS Logs Inspection
        Self::send_progress(
            &progress_tx,
            85,
            "Checking the CBS system logs for integrity errors...",
            Some("Inspecting CBS.log..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        if let Ok(tail) = read_tail(&self.cbs_log, CBS_TAIL_BYTES) {
            if let Some(evidence) = cbs_unrepaired_corruption(&tail) {
                issues.push(Issue::new(
                    "sys_sfc_corrupt",
                    self.id(),
                    "System files show integrity violations (CBS)",
                    "System Integrity",
                    Severity::Warning,
                    RiskScore::Low,
                    "The Windows CBS logs report integrity errors on protected system files.",
                    format!("Found in CBS.log:\n{evidence}"),
                    "Run SFC /scannow to restore system files from the local component store",
                    vec![
                        "Run sfc /scannow in the background and repair damaged system files"
                            .to_string(),
                    ],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    95,
                    "CBS logs unremarkable",
                    Some("No critical CBS integrity violations reported."),
                )
                .await;
            }
        }

        Self::send_progress(&progress_tx, 100, "System integrity check complete", None).await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        let log_tx = if let Some(ref tx) = progress_tx {
            let (str_tx, mut str_rx) = tokio::sync::mpsc::channel::<String>(100);
            let tx_clone = tx.clone();
            let issue_id_clone = issue_id.to_string();
            tokio::spawn(async move {
                while let Some(line) = str_rx.recv().await {
                    let _ = tx_clone
                        .send(FixProgress {
                            issue_id: issue_id_clone.clone(),
                            step_description: "Repair in progress...".to_string(),
                            is_success: true,
                            error: None,
                            console_line: Some(line),
                        })
                        .await;
                }
            });
            Some(str_tx)
        } else {
            None
        };

        match issue_id {
            "sys_dism_corrupt" => {
                let out = self
                    .runner
                    .run_streaming(
                        "dism.exe",
                        DISM_RESTORE_HEALTH_ARGS,
                        log_tx,
                        Duration::from_secs(600),
                    )
                    .await?;
                if out.success {
                    Ok(
                        "DISM /RestoreHealth completed successfully. Component store repaired."
                            .to_string(),
                    )
                } else {
                    Err(format!("DISM repair failed: {}", out.stderr))
                }
            }
            "sys_vss_disabled" => {
                let config = self
                    .runner
                    .run(
                        "sc.exe",
                        &["config", "vss", "start=", "demand"],
                        Duration::from_secs(10),
                    )
                    .await?;
                if !config.success {
                    return Err(format!(
                        "sc config vss failed: {}",
                        config.stdout.trim()
                    ));
                }
                // VSS is a demand-start service: it only has to be startable,
                // so a start that fails because it is already running is fine.
                let _ = self
                    .runner
                    .run("net.exe", &["start", "vss"], Duration::from_secs(10))
                    .await;
                match service::start_type(&*self.runner, "vss").await? {
                    Some(SERVICE_DISABLED) => Err(
                        "Windows accepted the change but VSS is still disabled - a group policy may enforce it"
                            .to_string(),
                    ),
                    _ => Ok("Volume Shadow Copy (VSS) service set to start on demand.".to_string()),
                }
            }
            "sys_dism_unrepairable" => Ok(
                "Advisory recorded in the audit log. Only a repair install of Windows clears this - see the fix steps."
                    .to_string(),
            ),
            "sys_sfc_corrupt" => {
                let out = self
                    .runner
                    .run_streaming("sfc.exe", &["/scannow"], log_tx, Duration::from_secs(600))
                    .await?;
                if out.success {
                    Ok("SFC /scannow completed successfully. System files repaired.".to_string())
                } else {
                    Ok(format!("SFC ran: {}", out.stdout))
                }
            }
            _ => Err(format!("Unknown issue ID: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;
    use crate::utils::service::test_support::sc_qc_output;

    // DISM's verdicts, word for word from its en-US resources
    // (CbsProvider.dll.mui), framed the way DISM prints them.
    fn dism_says(verdict: &str) -> CmdOutput {
        CmdOutput::ok(format!(
            "\r\nDeployment Image Servicing and Management tool\r\nVersion: 10.0.26100.1\r\n\r\nImage Version: 10.0.26100.4652\r\n\r\n{verdict}\r\nThe operation completed successfully.\r\n"
        ))
    }
    const HEALTHY: &str = "No component store corruption detected.";
    const REPAIRABLE: &str = "The component store is repairable.";
    const NOT_REPAIRABLE: &str = "The component store cannot be repaired.";

    /// A module that reads no CBS.log, so the machine running the tests does
    /// not decide what they see.
    fn module_with(mock: MockCommandRunner) -> SystemIntegrityModule {
        SystemIntegrityModule::with_runner_and_cbs_log(
            Arc::new(mock),
            std::env::temp_dir().join("winmedic-test-no-such-cbs.log"),
        )
    }

    fn healthy_vss(mock: &MockCommandRunner) {
        mock.add_response("qc vss", CmdOutput::ok(sc_qc_output("vss", 3)));
    }

    #[tokio::test]
    async fn test_system_integrity_detects_dism_corruption() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(REPAIRABLE));
        healthy_vss(&mock);

        let issues = module_with(mock).scan(None).await.unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "sys_dism_corrupt");
        assert_eq!(issues[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn dism_is_asked_in_english() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        healthy_vss(&mock);

        let issues = module_with(mock.clone()).scan(None).await.unwrap();

        assert!(issues.is_empty());
        let dism = mock
            .executed()
            .into_iter()
            .find(|c| c.contains("dism.exe"))
            .expect("DISM ran");
        assert!(dism.contains("/English"), "{dism}");
    }

    #[tokio::test]
    async fn an_unrepairable_store_is_not_offered_restorehealth() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(NOT_REPAIRABLE));
        healthy_vss(&mock);

        let issues = module_with(mock).scan(None).await.unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "sys_dism_unrepairable");
        assert_eq!(issues[0].risk_score, RiskScore::High);
    }

    #[tokio::test]
    async fn an_unelevated_dism_is_no_verdict_at_all() {
        // Captured: German DISM refusing to run without elevation, exit 740.
        let refused = CmdOutput::with_output(
            740,
            decode_output(include_bytes!(
                "../../tests/fixtures/console/dism_elevation_required_de.bin"
            )),
            "",
        );
        assert!(matches!(
            ComponentStoreHealth::from_dism(&refused),
            ComponentStoreHealth::Unknown(reason) if reason.contains("Administrator")
        ));

        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", refused);
        healthy_vss(&mock);
        assert!(module_with(mock).scan(None).await.unwrap().is_empty());
    }

    #[test]
    fn the_german_verdicts_are_read_if_dism_ignores_english() {
        // These are the de-DE resource strings. The old check looked for
        // "reparierbar" and "beschädigt" and matched neither.
        let de = |text: &str| ComponentStoreHealth::from_dism(&CmdOutput::ok(text));
        assert_eq!(
            de("Der Komponentenspeicher kann repariert werden."),
            ComponentStoreHealth::Repairable
        );
        assert_eq!(
            de("Der Komponentenspeicher kann nicht repariert werden."),
            ComponentStoreHealth::NotRepairable
        );
        assert_eq!(
            de("Es wurde keine Komponentenspeicherbeschädigung erkannt."),
            ComponentStoreHealth::Healthy
        );
    }

    #[tokio::test]
    async fn test_system_integrity_detects_vss_disabled() {
        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        mock.add_response("qc vss", CmdOutput::ok(sc_qc_output("vss", 4)));

        let issues = module_with(mock).scan(None).await.unwrap();

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].id, "sys_vss_disabled");
        assert_eq!(issues[0].severity, Severity::Warning);
    }

    #[tokio::test]
    async fn a_vss_repair_windows_does_not_keep_fails() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "config vss",
            CmdOutput::ok("[SC] ChangeServiceConfig ERFOLG"),
        );
        mock.add_response("net.exe", CmdOutput::ok(""));
        mock.add_response("qc vss", CmdOutput::ok(sc_qc_output("vss", 4)));

        let err = module_with(mock)
            .fix("sys_vss_disabled", None)
            .await
            .unwrap_err();
        assert!(err.contains("still disabled"), "{err}");
    }

    fn cbs_line(text: &str) -> String {
        format!("2026-09-01 10:00:00, Info                  CBS    {text}\r\n")
    }

    fn dism_summary(detected: u32, repaired: u32) -> String {
        [
            "Summary:".to_string(),
            "Operation: Detect and Repair ".to_string(),
            "Operation result: 0x0".to_string(),
            "Last Successful Step: Entire operation completes.".to_string(),
            format!("Total Detected Corruption:\t{detected}"),
            "\tCBS Manifest Corruption:\t0".to_string(),
            format!("\tCSI Payload Corruption:\t{detected}"),
            format!("Total Repaired Corruption:\t{repaired}"),
            format!("\tCSI Payload Repaired:\t{repaired}"),
        ]
        .iter()
        .map(|l| cbs_line(l))
        .collect()
    }

    #[test]
    fn a_clean_dism_summary_is_not_corruption() {
        // "Total Detected Corruption: 0" contains "Corrupt"; the old check
        // raised a finding on it after every DISM run, its own repair included.
        assert_eq!(cbs_unrepaired_corruption(&dism_summary(0, 0)), None);
        assert_eq!(cbs_unrepaired_corruption(&dism_summary(3, 3)), None);
    }

    #[test]
    fn corruption_left_unrepaired_is_reported() {
        let evidence = cbs_unrepaired_corruption(&dism_summary(2, 1)).expect("1 left over");
        assert!(
            evidence.contains("2 corruption(s) detected, 1 repaired"),
            "{evidence}"
        );

        let sfc = cbs_line(
            "[SR] Cannot repair member file [l:10]\"winload.efi\" of Microsoft-Windows-BootEnvironment-OSLoader",
        );
        let evidence = cbs_unrepaired_corruption(&sfc).expect("SFC gave up on a file");
        assert!(evidence.contains("winload.efi"));
    }

    #[test]
    fn only_the_latest_dism_summary_counts() {
        let log = format!("{}{}", dism_summary(2, 0), dism_summary(2, 2));
        assert_eq!(cbs_unrepaired_corruption(&log), None);
    }

    #[tokio::test]
    async fn the_cbs_log_is_read_from_its_tail() {
        let path = std::env::temp_dir().join(format!("winmedic-cbs-{}.log", std::process::id()));
        // Old damage far above the tail, then a clean run at the end.
        let mut log = cbs_line("[SR] Cannot repair member file [l:4]\"old.dll\"");
        log.push_str(&"x".repeat(CBS_TAIL_BYTES as usize * 2));
        log.push('\n');
        log.push_str(&dism_summary(0, 0));
        std::fs::write(&path, log).unwrap();

        let mock = MockCommandRunner::new();
        mock.add_response("dism.exe", dism_says(HEALTHY));
        healthy_vss(&mock);
        let module = SystemIntegrityModule::with_runner_and_cbs_log(Arc::new(mock), path.clone());
        let issues = module.scan(None).await.unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(!issues.iter().any(|i| i.id == "sys_sfc_corrupt"));
    }
}
