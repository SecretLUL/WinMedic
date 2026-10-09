//! Explorer crashing in a program's add-on (a shell extension).
//!
//! Explorer loads the context menu handlers, icon overlays and preview
//! handlers other programs install. When one of them crashes, Explorer goes
//! with it: the taskbar and every open folder vanish and come back. Windows
//! logs each crash as Application Error 1000, with the module it crashed in
//! and that module's path, which is where the program is named.
//!
//! What decides is language-neutral: the event id, `AppName`, `ModulePath`,
//! the CLSID keys an extension is registered under.

use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::safety::reg_backup::RegBackupManager;
use crate::utils::cmd::{CommandRunner, ps_single_quoted};
use crate::utils::event_xml::{EventRecord, event_query, read_events};
use crate::utils::registry::{self, RegKeyValues};
use std::path::Path;
use std::time::Duration;

const APP_ERROR_PROVIDER: &str = "Application Error";
/// How far back Explorer's crashes are looked for.
const CRASH_DAYS: u64 = 30;
/// One crash may be bad luck.
const MIN_CRASHES: usize = 2;

/// Where Explorer is told not to load an extension: a value named after its
/// CLSID.
pub const BLOCKED_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";
/// Where extensions are registered, for every user and for this one.
const CLSID_KEYS: [&str; 2] = [
    r"HKLM\SOFTWARE\Classes\CLSID",
    r"HKCU\Software\Classes\CLSID",
];

/// The findings' id prefix; the DLL's file name follows.
pub const ID_PREFIX: &str = "crash_shellext_";

/// The newest program crashes of the last [`CRASH_DAYS`], from the
/// Application log.
pub fn app_crashes_query() -> Vec<String> {
    event_query(
        "Application",
        &format!(
            "Provider[@Name='{APP_ERROR_PROVIDER}'] and EventID=1000 and TimeCreated[timediff(@SystemTime) <= {}]",
            CRASH_DAYS * 86_400_000
        ),
        300,
    )
}

/// A module outside Windows that Explorer crashed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellExtCrash {
    pub module_path: String,
    pub crashes: usize,
}

impl ShellExtCrash {
    /// `7-zip.dll`.
    pub fn file_name(&self) -> &str {
        file_name(&self.module_path)
    }

    pub fn issue_id(&self) -> String {
        let slug: String = self
            .file_name()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        format!("{ID_PREFIX}{slug}")
    }
}

fn file_name(path: &str) -> &str {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
}

/// The modules outside `windows_dir` that Explorer crashed in at least
/// [`MIN_CRASHES`] times. A crash inside Windows' own files is not an
/// extension's, and a crash without a module path names nothing.
pub fn shell_extension_crashes(events: &[EventRecord], windows_dir: &str) -> Vec<ShellExtCrash> {
    let windows = format!(
        "{}\\",
        windows_dir.trim_end_matches('\\').to_ascii_lowercase()
    );
    let mut found: Vec<ShellExtCrash> = Vec::new();
    for event in events
        .iter()
        .filter(|e| e.provider == APP_ERROR_PROVIDER && e.event_id == 1000)
        .filter(|e| {
            e.data("AppName")
                .is_some_and(|app| app.eq_ignore_ascii_case("explorer.exe"))
        })
    {
        let Some(path) = event.data("ModulePath").map(str::trim) else {
            continue;
        };
        if path.is_empty() || path.to_ascii_lowercase().starts_with(&windows) {
            continue;
        }
        match found
            .iter_mut()
            .find(|c| c.module_path.eq_ignore_ascii_case(path))
        {
            Some(known) => known.crashes += 1,
            None => found.push(ShellExtCrash {
                module_path: path.to_string(),
                crashes: 1,
            }),
        }
    }
    found.retain(|c| c.crashes >= MIN_CRASHES);
    found
}

/// Prints `company|product` of the file at `path` from its version
/// resource, which the maker writes and Windows does not translate.
fn version_info_script(path: &str) -> String {
    format!(
        "$v = (Get-Item -LiteralPath {} -ErrorAction Stop).VersionInfo; '{{0}}|{{1}}' -f $v.CompanyName, $v.ProductName",
        ps_single_quoted(path)
    )
}

/// `Microsoft Office (Microsoft Corporation)` from what
/// [`version_info_script`] printed; `None` when it names nothing.
pub fn program_name(version_info: &str) -> Option<String> {
    let line = version_info.lines().find(|l| l.contains('|'))?;
    let (company, product) = line.split_once('|')?;
    let (company, product) = (company.trim(), product.trim());
    if product.is_empty() {
        return (!company.is_empty()).then(|| company.to_string());
    }
    if company.is_empty() || product.contains(company) {
        return Some(product.to_string());
    }
    Some(format!("{product} ({company})"))
}

/// Who made the module: its version resource, or else the folder it is in.
async fn program_of(runner: &dyn CommandRunner, path: &str) -> String {
    if let Ok(out) = runner
        .run_powershell(&version_info_script(path), Duration::from_secs(15))
        .await
        && out.success
        && let Some(name) = program_name(&out.stdout)
    {
        return name;
    }
    Path::new(path)
        .parent()
        .and_then(Path::file_name)
        .map(|folder| folder.to_string_lossy().into_owned())
        .unwrap_or_else(|| "an unknown program".to_string())
}

fn finding(module_id: &str, crash: &ShellExtCrash, program: &str) -> Issue {
    let mut issue = Issue::new(
        crash.issue_id(),
        module_id,
        format!(
            "Explorer keeps crashing in {}, an add-on of {program}",
            crash.file_name()
        ),
        "Hardware & Stability",
        Severity::Warning,
        RiskScore::Low,
        format!(
            "Explorer crashed {} times in the last {CRASH_DAYS} days inside {}, an add-on of {program}: the taskbar and open folders disappear and come back. Updating or uninstalling {program} fixes it. Blocking the add-on stops the crashes without uninstalling; its menu entries disappear.",
            crash.crashes,
            crash.file_name()
        ),
        format!(
            "Application Error 1000, AppName explorer.exe\nModulePath: {}\nCrashes: {}",
            crash.module_path, crash.crashes
        ),
        format!("Update or uninstall {program}, or block its Explorer add-on"),
        vec![
            format!("Update or uninstall {program}: Settings -> Apps -> Installed apps"),
            format!("Or block the add-on under {BLOCKED_KEY} (after a registry backup)"),
            "Sign out or restart for Explorer to leave it out".to_string(),
        ],
    );
    // Uninstalling the program is the better repair; blocking is a choice.
    issue.is_selected = false;
    issue
}

async fn crashes(
    runner: &dyn CommandRunner,
    windows_dir: &str,
) -> Result<Vec<ShellExtCrash>, String> {
    let query = app_crashes_query();
    let query: Vec<&str> = query.iter().map(String::as_str).collect();
    let events = read_events(
        runner
            .run("wevtutil.exe", &query, Duration::from_secs(20))
            .await,
    )?;
    Ok(shell_extension_crashes(&events, windows_dir))
}

/// One finding per module outside Windows that Explorer keeps crashing in.
pub async fn findings(
    runner: &dyn CommandRunner,
    module_id: &str,
    windows_dir: &str,
) -> Result<Vec<Issue>, String> {
    let mut issues = Vec::new();
    for crash in crashes(runner, windows_dir).await? {
        let program = program_of(runner, &crash.module_path).await;
        issues.push(finding(module_id, &crash, &program));
    }
    Ok(issues)
}

/// The CLSIDs whose in-process server is a file named `dll`, among the
/// keys `reg query /s /d /f` found. Compared by file name: the registry may
/// hold the path with `%ProgramFiles%` or in other case.
pub fn clsids_of(keys: &[RegKeyValues], dll: &str) -> Vec<String> {
    let mut clsids: Vec<String> = keys
        .iter()
        .filter(|key| {
            key.key.to_ascii_lowercase().ends_with("\\inprocserver32")
                && key
                    .values
                    .iter()
                    .any(|v| file_name(v.data.trim()).eq_ignore_ascii_case(dll))
        })
        .filter_map(|key| {
            let mut parts = key.key.rsplit('\\');
            parts.next();
            parts
                .next()
                .filter(|clsid| clsid.starts_with('{'))
                .map(str::to_string)
        })
        .collect();
    clsids.sort_unstable_by_key(|c| c.to_ascii_uppercase());
    clsids.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    clsids
}

/// The CLSIDs the DLL is registered under, for every user and for this one.
async fn registered_clsids(runner: &dyn CommandRunner, dll: &str) -> Result<Vec<String>, String> {
    let mut clsids = Vec::new();
    for root in CLSID_KEYS {
        let out = runner
            .run(
                "reg.exe",
                &["query", root, "/s", "/d", "/f", dll],
                Duration::from_secs(60),
            )
            .await?;
        // Exit 1: nothing found. Its message is translated; not read.
        if out.exit_code == Some(0) {
            clsids.extend(clsids_of(&registry::parse_reg_query(&out.stdout), dll));
        }
    }
    clsids.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    Ok(clsids)
}

/// The CLSIDs among `clsids` the Blocked key does not hold.
async fn not_blocked(runner: &dyn CommandRunner, clsids: &[String]) -> Result<Vec<String>, String> {
    let blocked = registry::query(runner, BLOCKED_KEY, false)
        .await?
        .unwrap_or_default();
    Ok(clsids
        .iter()
        .filter(|clsid| registry::find(&blocked, BLOCKED_KEY, clsid).is_none())
        .cloned()
        .collect())
}

/// Block every extension the crashing DLL is registered as: back the
/// Blocked key up, add a value per CLSID, read the key back.
pub async fn block(
    runner: &dyn CommandRunner,
    issue_id: &str,
    windows_dir: &str,
    backup_dir: &Path,
) -> Result<String, String> {
    let Some(crash) = crashes(runner, windows_dir)
        .await?
        .into_iter()
        .find(|c| c.issue_id() == issue_id)
    else {
        return Ok("Explorer no longer crashes in that module - nothing to block.".to_string());
    };
    let dll = crash.file_name().to_string();
    let clsids = registered_clsids(runner, &dll).await?;
    if clsids.is_empty() {
        return Err(format!(
            "{dll} is not registered as an Explorer add-on under any CLSID, so there is nothing to block. Update or uninstall the program it belongs to."
        ));
    }
    let to_block = not_blocked(runner, &clsids).await?;
    if to_block.is_empty() {
        return Ok(format!(
            "{dll} is blocked already. Sign out or restart for Explorer to leave it out."
        ));
    }
    if registry::query(runner, BLOCKED_KEY, false).await?.is_some() {
        RegBackupManager::with_dir(backup_dir.to_path_buf())
            .export_key_with(runner, BLOCKED_KEY, &format!("Before blocking {dll}"))
            .await
            .map_err(|e| {
                format!("Aborted: the registry backup of the Blocked key failed ({e}). Nothing was changed.")
            })?;
    }
    for clsid in &to_block {
        let out = runner
            .run(
                "reg.exe",
                &[
                    "add",
                    BLOCKED_KEY,
                    "/v",
                    clsid,
                    "/t",
                    "REG_SZ",
                    "/d",
                    &format!("Blocked by WinMedic: {dll}"),
                    "/f",
                ],
                Duration::from_secs(10),
            )
            .await?;
        if !out.success {
            return Err(format!(
                "{clsid} could not be blocked (reg add exit code {:?}): {}",
                out.exit_code,
                out.stderr.trim()
            ));
        }
    }
    let missing = not_blocked(runner, &to_block).await?;
    if !missing.is_empty() {
        return Err(format!(
            "reg add ran, but the Blocked key does not hold {}.",
            missing.join(", ")
        ));
    }
    Ok(format!(
        "Blocked {} Explorer add-on(s) of {dll}: {}. Sign out or restart for Explorer to leave it out. To undo, delete these values under {BLOCKED_KEY}.",
        to_block.len(),
        to_block.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::{CodePage, decode_output, decode_output_in};
    use crate::utils::event_xml::parse_events;

    // Captured on a German Windows 11; see tests/fixtures/README.md.
    const APP_ERRORS: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_app_error_1000.bin");
    const CLSID_SEARCH: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_clsid_find_dll_de.bin");
    const BLOCKED: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_shell_ext_blocked.bin");
    const VERSION_INFO: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_version_info.bin");

    const VISSHE: &str = r"C:\Program Files\Microsoft Office\root\Office16\VISSHE.DLL";

    fn app_errors() -> String {
        decode_output_in(APP_ERRORS, CodePage::Ansi)
    }

    /// The captured crashes with the Snipping Tool's turned into Explorer
    /// crashing in the Visio shell extension.
    fn explorer_crashing() -> String {
        app_errors()
            .replace(
                "<Data Name='AppName'>SnippingTool.exe<",
                "<Data Name='AppName'>explorer.exe<",
            )
            .replace(r"C:\WINDOWS\System32\ucrtbase.dll", VISSHE)
    }

    #[test]
    fn crashes_of_other_programs_are_not_counted() {
        let events = parse_events(&app_errors());
        assert!(events.len() >= 10);
        assert!(shell_extension_crashes(&events, r"C:\WINDOWS").is_empty());
    }

    #[test]
    fn explorer_crashing_in_a_program_s_module_is_found() {
        let crashes = shell_extension_crashes(&parse_events(&explorer_crashing()), r"C:\Windows");
        assert_eq!(crashes.len(), 1, "{crashes:?}");
        assert_eq!(crashes[0].module_path, VISSHE);
        assert!(crashes[0].crashes >= MIN_CRASHES);
        assert_eq!(crashes[0].issue_id(), "crash_shellext_visshe_dll");
    }

    #[test]
    fn explorer_crashing_inside_windows_is_not_an_extension() {
        let inside = app_errors().replace(
            "<Data Name='AppName'>SnippingTool.exe<",
            "<Data Name='AppName'>explorer.exe<",
        );
        assert!(shell_extension_crashes(&parse_events(&inside), r"C:\Windows").is_empty());
    }

    #[test]
    fn the_program_is_named_from_its_version_resource() {
        assert_eq!(
            program_name(&decode_output(VERSION_INFO)).as_deref(),
            Some("Microsoft Office (Microsoft Corporation)")
        );
        assert_eq!(program_name("7-Zip|7-Zip").as_deref(), Some("7-Zip"));
        assert_eq!(program_name("|").as_deref(), None);
        assert_eq!(program_name("").as_deref(), None);
    }

    #[test]
    fn the_clsids_are_read_from_the_search() {
        let keys = registry::parse_reg_query(&decode_output(CLSID_SEARCH));
        assert_eq!(
            clsids_of(&keys, "visshe.dll"),
            [
                "{506F4668-F13E-4AA1-BB04-B43203AB3CC0}",
                "{A394DCA9-3727-11D4-BD85-00C04F6B93A4}",
                "{D66DC78C-4F61-447F-942B-3FB6980118CF}"
            ]
        );
        assert!(clsids_of(&keys, "other.dll").is_empty());
    }

    /// Explorer crashing in the Visio extension; the Blocked key answers
    /// `blocked_after` once a value was added.
    fn block_mock(blocked_after: String) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil.exe", CmdOutput::ok(explorer_crashing()));
        mock.add_response(
            r"query HKLM\SOFTWARE\Classes\CLSID",
            CmdOutput::ok(decode_output(CLSID_SEARCH)),
        );
        mock.add_response(
            r"query HKCU\Software\Classes\CLSID",
            CmdOutput::with_output(
                1,
                "Suchvorgang abgeschlossen: 0 übereinstimmende Zeichenfolge(n) gefunden.",
                "",
            ),
        );
        mock.add_response_after("reg.exe add", "Blocked", CmdOutput::ok(blocked_after));
        mock.add_response(
            "reg.exe query HKLM\\SOFTWARE\\Microsoft",
            CmdOutput::ok(decode_output(BLOCKED)),
        );
        mock.add_written_file("reg.exe export", 2, "(what reg export wrote)");
        mock.add_response("reg.exe export", CmdOutput::ok(""));
        mock.add_response("reg.exe add", CmdOutput::ok(""));
        mock
    }

    /// The captured Blocked key with these CLSIDs added.
    fn blocked_with(clsids: &[&str]) -> String {
        let mut text = decode_output(BLOCKED).trim_end().to_string();
        for clsid in clsids {
            text.push_str(&format!(
                "\r\n    {clsid}    REG_SZ    Blocked by WinMedic: VISSHE.DLL"
            ));
        }
        text + "\r\n\r\n"
    }

    struct Backups(std::path::PathBuf);

    impl Drop for Backups {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn backups(tag: &str) -> Backups {
        let dir =
            std::env::temp_dir().join(format!("winmedic_shellext_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Backups(dir)
    }

    #[tokio::test]
    async fn blocking_backs_up_adds_and_reads_back() {
        let backups = backups("block");
        let all = [
            "{506F4668-F13E-4AA1-BB04-B43203AB3CC0}",
            "{A394DCA9-3727-11D4-BD85-00C04F6B93A4}",
            "{D66DC78C-4F61-447F-942B-3FB6980118CF}",
        ];
        let mock = block_mock(blocked_with(&all));
        let msg = block(
            &mock,
            "crash_shellext_visshe_dll",
            r"C:\Windows",
            &backups.0,
        )
        .await
        .unwrap();
        assert!(
            msg.contains("Blocked 3 Explorer add-on(s) of VISSHE.DLL"),
            "{msg}"
        );
        let executed = mock.executed();
        let export = executed
            .iter()
            .position(|c| c.starts_with("reg.exe export"))
            .unwrap();
        let add = executed
            .iter()
            .position(|c| c.starts_with("reg.exe add"))
            .unwrap();
        assert!(export < add, "{executed:?}");
        assert_eq!(
            executed
                .iter()
                .filter(|c| c.starts_with("reg.exe add"))
                .count(),
            3
        );
        // The Epson entry already in the key stays as it is.
        assert!(!executed.iter().any(|c| c.contains("9421DD08")));
    }

    #[tokio::test]
    async fn a_value_that_is_not_there_afterwards_is_a_failure() {
        let backups = backups("missing");
        let mock = block_mock(blocked_with(&["{506F4668-F13E-4AA1-BB04-B43203AB3CC0}"]));
        let err = block(
            &mock,
            "crash_shellext_visshe_dll",
            r"C:\Windows",
            &backups.0,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("{A394DCA9-3727-11D4-BD85-00C04F6B93A4}"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_finding_names_the_program_and_waits_to_be_ticked() {
        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil.exe", CmdOutput::ok(explorer_crashing()));
        mock.add_response("VersionInfo", CmdOutput::ok(decode_output(VERSION_INFO)));
        let issues = findings(&mock, "crash_analysis", r"C:\Windows")
            .await
            .unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].title,
            "Explorer keeps crashing in VISSHE.DLL, an add-on of Microsoft Office (Microsoft Corporation)"
        );
        assert!(!issues[0].is_selected);
        let query = mock
            .executed()
            .into_iter()
            .find(|c| c.starts_with("wevtutil.exe"))
            .unwrap();
        assert!(query.starts_with("wevtutil.exe qe Application"), "{query}");

        // Without a version resource the folder names it.
        let mock = MockCommandRunner::new();
        mock.add_response("wevtutil.exe", CmdOutput::ok(explorer_crashing()));
        mock.add_response("VersionInfo", CmdOutput::failed(1, "not found"));
        let issues = findings(&mock, "crash_analysis", r"C:\Windows")
            .await
            .unwrap();
        assert!(
            issues[0].title.ends_with("an add-on of Office16"),
            "{}",
            issues[0].title
        );
    }

    #[tokio::test]
    async fn the_version_script_parses() {
        let script = version_info_script(r"C:\A'B\x.dll");
        assert_eq!(crate::utils::cmd::powershell_parse_errors(&script).await, 0);
    }
}
