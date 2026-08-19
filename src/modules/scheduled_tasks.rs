//! Scheduled task diagnostics.
//!
//! Structurally the sibling of [`crate::modules::registry_startup`]: both look
//! for launch points that survived the software they were installed for. The
//! difference is what a repair may do. An orphaned `Run` value is a registry
//! value that can be exported and put back verbatim, so that module deletes it.
//! A scheduled task carries triggers, principals and settings that no `.reg`
//! snapshot covers, so nothing here deletes anything — the fix disables the
//! task, which Task Scheduler reverses with a single `Enable-ScheduledTask`.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner, ps_single_quoted};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

/// One line per registered task: path, name, state, last result, missed runs,
/// and the executable of the first action that has one.
///
/// `Get-ScheduledTaskInfo` is asked for separately per task because the task
/// object itself carries no run history. Tasks it cannot report on (a
/// permission it lacks, a task removed mid-enumeration) yield empty fields
/// rather than aborting the inventory, which is why every numeric field is
/// parsed as optional below.
const TASK_INVENTORY_SCRIPT: &str = concat!(
    "Get-ScheduledTask | ForEach-Object { ",
    "$info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; ",
    "$exec = ($_.Actions | Where-Object { $_.Execute } | Select-Object -First 1).Execute; ",
    r#""$($_.TaskPath)|$($_.TaskName)|$($_.State)|$($info.LastTaskResult)|$($info.NumberOfMissedRuns)|$exec" }"#,
);

/// Task Scheduler result codes that report a *state*, not a failed run.
///
/// `LastTaskResult` is overloaded: it holds either the exit code of the last
/// run or one of the `SCHED_S_*` status values. Treating the latter as failures
/// would flag every task that has simply never run yet — on a fresh install
/// that is most of them.
const BENIGN_TASK_RESULTS: &[i64] = &[
    0,      // the last run succeeded
    267008, // 0x41300 SCHED_S_TASK_READY
    267009, // 0x41301 SCHED_S_TASK_RUNNING
    267010, // 0x41302 SCHED_S_TASK_DISABLED
    267011, // 0x41303 SCHED_S_TASK_HAS_NOT_RUN
    267012, // 0x41304 SCHED_S_TASK_NO_MORE_RUNS
    267014, // 0x41306 SCHED_S_TASK_TERMINATED (stopped by the user)
    267045, // 0x41325 SCHED_S_TASK_QUEUED
];

/// Stands in for a PowerShell failure that carried no stderr of its own.
const NO_DETAIL: &str = "PowerShell reported no detail";

/// A task as the inventory script reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScheduledTask {
    /// Folder, always with a leading and trailing backslash, e.g. `\Microsoft\`.
    path: String,
    name: String,
    state: String,
    last_result: Option<i64>,
    missed_runs: u32,
    /// The action's program, exactly as registered — unexpanded and unquoted.
    execute: String,
}

impl ScheduledTask {
    /// Fully qualified task identifier, the form Task Scheduler itself prints.
    fn full_path(&self) -> String {
        format!("{}{}", self.path, self.name)
    }

    /// Whether the last run reported a real failure rather than a status code.
    fn last_run_failed(&self) -> bool {
        match self.last_result {
            Some(code) => !BENIGN_TASK_RESULTS.contains(&code),
            None => false,
        }
    }
}

/// What [`ScheduledTasksModule::fix`] needs to address a finding, kept from the
/// scan that raised it.
///
/// The issue id cannot carry the task path losslessly — task names contain
/// spaces, braces and non-ASCII characters that would have to survive a round
/// trip through an identifier that is also shown in the UI and written to the
/// audit log. Remembering the pair is exact where re-deriving it is guesswork.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskRef {
    path: String,
    name: String,
}

pub struct ScheduledTasksModule {
    runner: Arc<dyn CommandRunner>,
    /// Issue id -> the task that issue was raised for, filled in by `scan`.
    known_tasks: Arc<Mutex<HashMap<String, TaskRef>>>,
}

impl Default for ScheduledTasksModule {
    fn default() -> Self {
        Self::new()
    }
}

impl ScheduledTasksModule {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            known_tasks: Arc::new(Mutex::new(HashMap::new())),
        }
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
                    module_id: "scheduled_tasks".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }

    /// Parse one `path|name|state|result|missed|execute` line.
    ///
    /// Split into exactly six fields from the left, so a `|` inside the program
    /// path stays part of the program path instead of shifting every later
    /// field by one. A line without all six separators is skipped rather than
    /// guessed at.
    fn parse_task_line(line: &str) -> Option<ScheduledTask> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        let mut fields = line.splitn(6, '|');
        let path = fields.next()?.trim().to_string();
        let name = fields.next()?.trim().to_string();
        let state = fields.next()?.trim().to_string();
        let last_result_raw = fields.next()?.trim();
        let missed_raw = fields.next()?.trim();
        let execute = fields.next()?.trim().to_string();

        if name.is_empty() {
            return None;
        }

        Some(ScheduledTask {
            path,
            name,
            state,
            last_result: last_result_raw.parse::<i64>().ok(),
            missed_runs: missed_raw.parse::<u32>().unwrap_or(0),
            execute,
        })
    }

    /// Expand `%NAME%` references against this process's environment.
    ///
    /// An unset variable is left standing rather than replaced with nothing:
    /// `%AppDir%\tool.exe` collapsing to `\tool.exe` would look like a real
    /// absolute path to a file that does not exist, which is exactly the
    /// false positive this module must not produce.
    fn expand_env_vars(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;

        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];

            match after.find('%') {
                Some(end) => {
                    let var_name = &after[..end];
                    match std::env::var(var_name) {
                        Ok(value) if !var_name.is_empty() => out.push_str(&value),
                        _ => {
                            // Unset, or an empty `%%`: keep the text verbatim.
                            out.push('%');
                            out.push_str(var_name);
                            out.push('%');
                        }
                    }
                    rest = &after[end + 1..];
                }
                None => {
                    // A lone `%` with no closing partner ends the expansion.
                    out.push('%');
                    out.push_str(after);
                    return out;
                }
            }
        }

        out.push_str(rest);
        out
    }

    /// The program a task launches, if it can be resolved to an absolute path
    /// that is definitely missing.
    ///
    /// Deliberately conservative — every branch that cannot *prove* the target
    /// is gone returns `None`, because the cost of a false positive here is
    /// telling the user to switch off a task that works:
    ///
    /// - A bare command name (`powershell.exe`, `sc.exe`) is resolved through
    ///   `PATH` by Task Scheduler, which this module does not replicate.
    /// - A path still holding an unexpanded `%VAR%` is not absolute, so it
    ///   never reaches the existence check.
    /// - A relative path is interpreted against the task's working directory,
    ///   which the inventory does not read.
    ///
    /// The 64-bit builds WinMedic ships see `System32` unredirected, so a task
    /// launching a 64-bit-only system binary is checked against the directory
    /// Task Scheduler itself would use.
    fn missing_target(execute: &str) -> Option<PathBuf> {
        let trimmed = execute.trim().trim_matches('"').trim();
        if trimmed.is_empty() {
            return None;
        }

        let expanded = Self::expand_env_vars(trimmed);
        let path = PathBuf::from(expanded.trim().trim_matches('"'));

        if !path.is_absolute() || path.exists() {
            return None;
        }
        Some(path)
    }

    /// Build a stable, unique and still human-readable issue id for a task.
    ///
    /// The slug is what the user sees in the issue list; the hash suffix is
    /// what keeps two tasks whose names differ only in punctuation — or beyond
    /// the slug's length limit — from colliding into one id.
    fn issue_id(prefix: &str, full_path: &str) -> String {
        let mut slug: String = full_path
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();

        // ASCII by construction, so a byte-index truncation cannot split a char.
        slug.truncate(48);
        let slug = slug.trim_matches('_');

        let digest = Sha256::digest(full_path.as_bytes());
        // Hex by hand: the sha2 0.11 digest output has no LowerHex impl, and four
        // bytes are exactly the eight characters the suffix wants.
        let short_hash: String = digest[..4].iter().map(|b| format!("{:02x}", b)).collect();

        if slug.is_empty() {
            format!("{}_{}", prefix, short_hash)
        } else {
            format!("{}_{}_{}", prefix, slug, short_hash)
        }
    }

    /// Record which task an issue belongs to so `fix` can act on it later.
    fn remember(&self, issue_id: &str, task: &ScheduledTask) {
        if let Ok(mut known) = self.known_tasks.lock() {
            known.insert(
                issue_id.to_string(),
                TaskRef {
                    path: task.path.clone(),
                    name: task.name.clone(),
                },
            );
        }
    }

    fn lookup(&self, issue_id: &str) -> Option<TaskRef> {
        self.known_tasks.lock().ok()?.get(issue_id).cloned()
    }

    /// Disable a task by its exact folder and name.
    ///
    /// Both values come from the system, not from WinMedic, so both go through
    /// [`ps_single_quoted`] — a task can be named by anyone who can create one,
    /// and this command frequently runs elevated.
    async fn disable_task(&self, task: &TaskRef) -> Result<String, String> {
        let script = format!(
            "Disable-ScheduledTask -TaskPath {} -TaskName {} -ErrorAction Stop | Out-Null",
            ps_single_quoted(&task.path),
            ps_single_quoted(&task.name),
        );

        let out = self
            .runner
            .run_powershell(&script, Duration::from_secs(20))
            .await?;

        if out.success {
            return Ok(format!(
                "Scheduled task '{}{}' disabled. Re-enable it at any time with 'Enable-ScheduledTask'.",
                task.path, task.name
            ));
        }

        let detail = out.stderr.trim();
        let detail = if detail.is_empty() { NO_DETAIL } else { detail };
        Err(format!(
            "Could not disable '{}{}': {}",
            task.path, task.name, detail
        ))
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for ScheduledTasksModule {
    fn id(&self) -> &'static str {
        "scheduled_tasks"
    }

    fn name(&self) -> &'static str {
        "Scheduled Tasks"
    }

    fn description(&self) -> &'static str {
        "Checks for scheduled tasks pointing at deleted programs and tasks whose last run failed"
    }

    fn icon(&self) -> &'static str {
        "[TSK]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        Self::send_progress(
            &progress_tx,
            15,
            "Reading the registered scheduled tasks...",
            Some("Get-ScheduledTask | Get-ScheduledTaskInfo..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let inventory = self
            .runner
            .run_powershell(TASK_INVENTORY_SCRIPT, Duration::from_secs(45))
            .await?;

        // A non-zero exit with usable output is normal here: a single task the
        // service refuses to describe makes PowerShell report failure while
        // every other task was still enumerated.
        if !inventory.success && inventory.stdout.trim().is_empty() {
            let detail = inventory.stderr.trim();
            let detail = if detail.is_empty() { NO_DETAIL } else { detail };
            return Err(format!(
                "The scheduled task inventory could not be read: {}",
                detail
            ));
        }

        let tasks: Vec<ScheduledTask> = inventory
            .stdout
            .lines()
            .filter_map(Self::parse_task_line)
            .collect();

        Self::send_progress(
            &progress_tx,
            45,
            "Checking task targets...",
            Some(&format!("{} registered tasks read.", tasks.len())),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        // 1. Tasks whose program no longer exists.
        let mut orphaned = 0;
        for task in &tasks {
            let Some(missing) = Self::missing_target(&task.execute) else {
                continue;
            };
            orphaned += 1;

            let full = task.full_path();
            let id = Self::issue_id("sched_orphaned", &full);
            self.remember(&id, task);

            issues.push(Issue::new(
                id,
                self.id(),
                format!("Scheduled task points at a deleted program: '{}'", task.name),
                "Scheduled Tasks",
                Severity::Warning,
                // Reversible with one command and touching nothing but this one
                // task's enabled flag, but it does stop something the machine
                // was configured to run.
                RiskScore::Medium,
                format!(
                    "The task '{}' launches '{}', which does not exist. Every trigger it fires on now ends in an error, and the leftover usually belongs to software that was uninstalled.",
                    full,
                    missing.display()
                ),
                format!(
                    "Task: {}\nState: {}\nAction: {}\nResolved target (missing): {}",
                    full,
                    task.state,
                    task.execute,
                    missing.display()
                ),
                "Disable the task (reversible with Enable-ScheduledTask); nothing is deleted",
                vec![format!(
                    "Run Disable-ScheduledTask -TaskPath '{}' -TaskName '{}'",
                    task.path, task.name
                )],
            ));
        }

        Self::send_progress(
            &progress_tx,
            75,
            "Checking the last run results...",
            Some(&format!("{} tasks with a missing target found.", orphaned)),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        // 2. Tasks whose last run failed. Reported separately from the orphans:
        //    a task that fails while its program is still installed may well be
        //    something the user wants repaired rather than switched off.
        let mut failing = 0;
        for task in &tasks {
            if !task.last_run_failed() {
                continue;
            }
            // Already reported above, with a more specific explanation.
            if Self::missing_target(&task.execute).is_some() {
                continue;
            }
            failing += 1;

            let full = task.full_path();
            let id = Self::issue_id("sched_failing", &full);
            self.remember(&id, task);

            let code = task.last_result.unwrap_or_default();
            let repeatedly = task.missed_runs > 0;
            let missed_clause = if repeatedly {
                format!(" and has missed {} scheduled run(s)", task.missed_runs)
            } else {
                String::new()
            };

            let mut issue = Issue::new(
                id,
                self.id(),
                format!(
                    "Scheduled task '{}' last run failed (0x{:X})",
                    task.name, code
                ),
                "Scheduled Tasks",
                if repeatedly {
                    Severity::Warning
                } else {
                    Severity::Info
                },
                RiskScore::Medium,
                format!(
                    "The task '{}' ended its last run with 0x{:X}{}. Its program is still installed, so this is a failing task rather than an orphaned one.",
                    full, code, missed_clause
                ),
                format!(
                    "Task: {}\nState: {}\nAction: {}\nLastTaskResult: {} (0x{:X})\nNumberOfMissedRuns: {}",
                    full, task.state, task.execute, code, code, task.missed_runs
                ),
                "Check the task in Task Scheduler; disabling it stops the recurring failure without deleting it",
                vec![format!(
                    "Run Disable-ScheduledTask -TaskPath '{}' -TaskName '{}'",
                    task.path, task.name
                )],
            );
            // A failing task is a judgement call in a way a task pointing at a
            // deleted binary is not, so `--auto-fix` never switches one off on
            // its own; the user has to tick it deliberately.
            issue.is_selected = false;
            issues.push(issue);
        }

        Self::send_progress(
            &progress_tx,
            100,
            "Scheduled task diagnostics complete",
            Some(&format!(
                "{} tasks checked: {} with a missing target, {} with a failed last run.",
                tasks.len(),
                orphaned,
                failing
            )),
        )
        .await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        if !issue_id.starts_with("sched_orphaned_") && !issue_id.starts_with("sched_failing_") {
            return Err(format!("Unknown issue id: {}", issue_id));
        }

        let Some(task) = self.lookup(issue_id) else {
            return Err(format!(
                "No scheduled task is on record for '{}'. Run the scan again before repairing.",
                issue_id
            ));
        };

        self.disable_task(&task).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    /// A target that is absolute and definitely gone, in a directory no test
    /// machine has.
    const MISSING_EXE: &str = r"C:\Program Files\WinMedicDeletedVendor\ghost.exe";

    /// A target that certainly exists while the test runs: the test binary.
    ///
    /// Preferred over a system path like `C:\Windows\system32\cmd.exe`, which
    /// assumes both the drive letter and the Windows directory.
    fn live_exe() -> String {
        std::env::current_exe()
            .expect("the test binary has a path")
            .to_string_lossy()
            .into_owned()
    }

    fn inventory(lines: Vec<String>) -> CmdOutput {
        CmdOutput::ok(lines.join("\r\n"))
    }

    fn module_with(lines: Vec<String>) -> ScheduledTasksModule {
        let mock = MockCommandRunner::new();
        mock.add_response("Get-ScheduledTask", inventory(lines));
        ScheduledTasksModule::with_runner(Arc::new(mock))
    }

    #[test]
    fn a_line_keeps_a_pipe_inside_the_program_path() {
        // The program path is the last field, so anything after the fifth
        // separator belongs to it.
        let line = r"\Vendor\|Backup|Ready|0|0|C:\Tools\odd|name.exe";
        let task = ScheduledTasksModule::parse_task_line(line).unwrap();

        assert_eq!(task.path, r"\Vendor\");
        assert_eq!(task.name, "Backup");
        assert_eq!(task.execute, r"C:\Tools\odd|name.exe");
    }

    #[test]
    fn a_line_missing_fields_is_skipped_rather_than_guessed_at() {
        assert!(ScheduledTasksModule::parse_task_line(r"\Vendor\|Backup|Ready").is_none());
        assert!(ScheduledTasksModule::parse_task_line("").is_none());
        assert!(ScheduledTasksModule::parse_task_line("   ").is_none());
    }

    #[test]
    fn an_unreadable_task_info_leaves_the_numbers_unset_instead_of_zero() {
        // `Get-ScheduledTaskInfo` failing renders as empty fields. Parsing
        // those as 0 would read as "last run succeeded".
        let task = ScheduledTasksModule::parse_task_line(r"\Vendor\|Backup|Ready|||C:\Tools\b.exe")
            .unwrap();

        assert_eq!(task.last_result, None);
        assert!(!task.last_run_failed());
    }

    #[test]
    fn status_codes_are_not_mistaken_for_failed_runs() {
        for benign in BENIGN_TASK_RESULTS {
            let line = format!(r"\V\|T|Ready|{}|0|C:\t.exe", benign);
            let task = ScheduledTasksModule::parse_task_line(&line).unwrap();
            assert!(!task.last_run_failed(), "0x{:X} must not count", benign);
        }

        // 0x80070002 — the file was not found.
        let task =
            ScheduledTasksModule::parse_task_line(r"\V\|T|Ready|2147942402|0|C:\t.exe").unwrap();
        assert!(task.last_run_failed());
    }

    #[test]
    fn an_unset_variable_is_left_standing_rather_than_collapsed() {
        let raw = r"%WinMedicUnsetTestVar%\tool.exe";
        let expanded = ScheduledTasksModule::expand_env_vars(raw);

        assert_eq!(expanded, raw, "an unset variable must survive verbatim");
        // Which is what keeps it out of the orphan check.
        assert!(ScheduledTasksModule::missing_target(raw).is_none());
    }

    #[test]
    fn a_set_variable_is_expanded() {
        // SystemRoot is present on every Windows host and on the CI runner.
        if let Ok(root) = std::env::var("SystemRoot") {
            let expanded = ScheduledTasksModule::expand_env_vars(r"%SystemRoot%\system32\x.exe");
            assert_eq!(expanded, format!(r"{}\system32\x.exe", root));
        }
    }

    #[test]
    fn a_lone_percent_sign_does_not_swallow_the_path() {
        assert_eq!(
            ScheduledTasksModule::expand_env_vars(r"C:\100%\tool.exe"),
            r"C:\100%\tool.exe"
        );
    }

    #[test]
    fn only_a_provably_missing_absolute_path_counts_as_orphaned() {
        // Resolved through PATH by Task Scheduler, not by this module.
        assert!(ScheduledTasksModule::missing_target("powershell.exe").is_none());
        // Relative to the task's working directory, which is not read.
        assert!(ScheduledTasksModule::missing_target(r"..\tools\run.bat").is_none());
        assert!(ScheduledTasksModule::missing_target("").is_none());
        assert!(ScheduledTasksModule::missing_target("   ").is_none());
        // A file that does exist on every Windows host.
        if let Ok(root) = std::env::var("SystemRoot") {
            let real = format!(r"{}\system32\cmd.exe", root);
            assert!(ScheduledTasksModule::missing_target(&real).is_none());
        }
        // Absolute, quoted, and gone.
        assert!(ScheduledTasksModule::missing_target(MISSING_EXE).is_some());
        assert!(ScheduledTasksModule::missing_target(&format!("\"{}\"", MISSING_EXE)).is_some());
    }

    #[test]
    fn two_tasks_differing_only_in_punctuation_get_different_ids() {
        let a = ScheduledTasksModule::issue_id("sched_orphaned", r"\Vendor\Nightly Backup");
        let b = ScheduledTasksModule::issue_id("sched_orphaned", r"\Vendor\Nightly-Backup");

        assert_ne!(a, b, "the hash suffix must separate them");
        assert!(a.starts_with("sched_orphaned_"));
        // Still readable in the issue list.
        assert!(a.contains("nightly_backup"));
    }

    #[test]
    fn an_id_stays_stable_for_the_same_task() {
        let full = r"\Microsoft\Windows\Foo\Bar";
        assert_eq!(
            ScheduledTasksModule::issue_id("sched_failing", full),
            ScheduledTasksModule::issue_id("sched_failing", full)
        );
    }

    #[tokio::test]
    async fn a_task_pointing_at_a_deleted_program_is_reported() {
        let module = module_with(vec![
            format!(r"\Vendor\|Ghost Updater|Ready|0|0|{}", MISSING_EXE),
            format!(r"\Microsoft\Windows\|Healthy|Ready|0|0|{}", live_exe()),
        ]);

        let issues = module.scan(None).await.unwrap();

        let orphan = issues
            .iter()
            .find(|i| i.id.starts_with("sched_orphaned_"))
            .expect("the orphaned task must be reported");
        assert_eq!(orphan.severity, Severity::Warning);
        assert_eq!(orphan.risk_score, RiskScore::Medium);
        assert!(orphan.is_selected, "a dead target is not a judgement call");
        assert!(orphan.title.contains("Ghost Updater"));
        // The dry-run preview has to name the exact command.
        assert!(orphan.fix_steps[0].contains("Disable-ScheduledTask"));
        // Nothing is destroyed, so nothing may claim to delete.
        assert!(!orphan.recommended_fix.to_lowercase().contains("delete "));

        assert_eq!(
            issues.len(),
            1,
            "the task with a live target must not be reported"
        );
    }

    #[tokio::test]
    async fn a_failing_task_is_reported_but_never_auto_fixed() {
        let module = module_with(vec![format!(
            r"\Vendor\|Flaky Sync|Ready|2147942402|3|{}",
            live_exe()
        )]);

        let issues = module.scan(None).await.unwrap();
        let failing = issues
            .iter()
            .find(|i| i.id.starts_with("sched_failing_"))
            .expect("the failing task must be reported");

        assert!(
            !failing.is_selected,
            "--auto-fix must not switch off a task on its own"
        );
        assert_eq!(
            failing.severity,
            Severity::Warning,
            "missed runs escalate it"
        );
        assert!(failing.title.contains("0x80070002"));
        assert!(failing.technical_details.contains("NumberOfMissedRuns: 3"));
    }

    #[tokio::test]
    async fn a_dead_target_is_reported_once_even_when_its_last_run_also_failed() {
        let module = module_with(vec![format!(
            r"\Vendor\|Ghost|Ready|2147942402|2|{}",
            MISSING_EXE
        )]);

        let issues = module.scan(None).await.unwrap();

        assert_eq!(issues.len(), 1, "the two checks must not both fire");
        assert!(issues[0].id.starts_with("sched_orphaned_"));
    }

    #[tokio::test]
    async fn a_healthy_machine_produces_no_findings() {
        let module = module_with(vec![
            format!(r"\Microsoft\Windows\|A|Ready|0|0|{}", live_exe()),
            r"\Microsoft\Windows\|B|Ready|267011|0|powershell.exe".to_string(),
            r"\Microsoft\Windows\|C|Disabled|267010|0|".to_string(),
        ]);

        assert!(module.scan(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_fix_disables_exactly_the_task_that_was_scanned() {
        let mock = MockCommandRunner::new();
        // Registered first: `add_response` returns the first pattern that
        // matches, and the inventory command contains this substring too.
        mock.add_response("Disable-ScheduledTask", CmdOutput::ok(""));
        mock.add_response(
            "Get-ScheduledTask",
            inventory(vec![format!(
                r"\Vendor\|Ghost Updater|Ready|0|0|{}",
                MISSING_EXE
            )]),
        );
        let module = ScheduledTasksModule::with_runner(Arc::new(mock.clone()));

        let issues = module.scan(None).await.unwrap();
        let result = module.fix(&issues[0].id, None).await.unwrap();

        assert!(result.contains("Ghost Updater"));
        let disable = mock
            .executed()
            .into_iter()
            .find(|c| c.contains("Disable-ScheduledTask"))
            .expect("the fix must issue the disable command");
        assert!(disable.contains(r"-TaskPath '\Vendor\'"));
        assert!(disable.contains("-TaskName 'Ghost Updater'"));
    }

    #[tokio::test]
    async fn a_task_name_cannot_break_out_of_the_powershell_string() {
        let hostile = r"Evil'; Remove-Item -Recurse C:\Windows; '";
        let mock = MockCommandRunner::new();
        mock.add_response("Disable-ScheduledTask", CmdOutput::ok(""));
        mock.add_response(
            "Get-ScheduledTask",
            inventory(vec![format!(
                r"\Vendor\|{}|Ready|0|0|{}",
                hostile, MISSING_EXE
            )]),
        );
        let module = ScheduledTasksModule::with_runner(Arc::new(mock.clone()));

        let issues = module.scan(None).await.unwrap();
        module.fix(&issues[0].id, None).await.unwrap();

        let disable = mock
            .executed()
            .into_iter()
            .find(|c| c.contains("Disable-ScheduledTask"))
            .unwrap();
        // Every embedded quote is doubled, so the name never stops being data.
        assert!(disable.contains(r"'Evil''; Remove-Item -Recurse C:\Windows; '''"));
    }

    #[tokio::test]
    async fn a_fix_without_a_preceding_scan_refuses_instead_of_guessing() {
        let module = module_with(Vec::new());

        let err = module
            .fix("sched_orphaned_vendor_ghost_deadbeef", None)
            .await
            .unwrap_err();
        assert!(err.contains("Run the scan again"));

        let err = module.fix("something_else", None).await.unwrap_err();
        assert!(err.contains("Unknown issue id"));
    }

    #[tokio::test]
    async fn an_inventory_that_cannot_be_read_fails_the_module() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "Get-ScheduledTask",
            CmdOutput::failed(1, "Access to the task scheduler service was denied."),
        );
        let module = ScheduledTasksModule::with_runner(Arc::new(mock));

        let err = module.scan(None).await.unwrap_err();
        assert!(err.contains("Access to the task scheduler service was denied."));
    }
}
