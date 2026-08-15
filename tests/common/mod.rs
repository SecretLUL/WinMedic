#![allow(dead_code, unused_imports)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::Sender;

use winmedic::config::AppConfig;
use winmedic::engine::issue::Issue;
use winmedic::engine::runner::DiagnosticEngine;
use winmedic::modules::ModuleConfig;
use winmedic::modules::system_cleaner::{
    CleanStats, CleanerPaths, DirStats, SystemCleanerModule, clean_log_dir_files,
    clean_path_contents, scan_log_dir_files, scan_path_recursive,
};
use winmedic::utils::cmd::{CmdOutput, CommandRunner};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

/// Build a `SystemCleanerModule` whose filesystem roots all live inside a fresh
/// temporary workspace.
///
/// `scan` and `fix` delete for real. A test must never build this module with
/// the default env-derived paths: that aims it at the *test machine's* own
/// browser caches, WER archives, `%ProgramData%\Package Cache` and
/// `C:\Windows\Panther`, and `cargo test` would wipe them.
///
/// The returned workspace owns the directory — keep it bound for the duration of
/// the test (`let (_sandbox, module) = ...`) so cleanup happens on drop.
pub fn sandboxed_cleaner(
    prefix: &str,
    runner: Arc<dyn CommandRunner>,
) -> (TempWorkspace, SystemCleanerModule) {
    let ws = TempWorkspace::new(prefix);
    let module = SystemCleanerModule::with_runner_and_paths(
        ModuleConfig::default(),
        runner,
        CleanerPaths::rooted_at(ws.path()),
    );
    (ws, module)
}

/// An isolated temporary filesystem workspace for simulating Windows directories.
pub struct TempWorkspace {
    pub root: PathBuf,
}

impl TempWorkspace {
    pub fn new(prefix: &str) -> Self {
        let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir_name = format!("winmedic_e2e_{}_{}_{}", prefix, std::process::id(), count);
        let root = std::env::temp_dir().join(dir_name);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("failed to create temp workspace");
        Self { root }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn create_dir(&self, rel_path: &str) -> PathBuf {
        let p = self.root.join(rel_path);
        fs::create_dir_all(&p).expect("failed to create directory in temp workspace");
        p
    }

    pub fn create_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
        let p = self.root.join(rel_path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("failed to create parent dir");
        }
        let mut file = File::create(&p).expect("failed to create file");
        file.write_all(content).expect("failed to write content");
        p
    }

    pub fn populate_mock_windows_tree(&self) -> MockWindowsPaths {
        let sys_root = self.create_dir("Windows");
        let panther = self.create_dir("Windows/Panther");
        let cbs = self.create_dir("Windows/Logs/CBS");
        let dism_logs = self.create_dir("Windows/Logs/DISM");
        let mosetup = self.create_dir("Windows/Logs/MoSetup");
        let wudo_sd = self.create_dir("Windows/SoftwareDistribution/DeliveryOptimization");
        let wudo_sp = self.create_dir("Windows/ServiceProfiles/NetworkService/AppData/Local/Microsoft/Windows/DeliveryOptimization/Cache");
        let sys_temp = self.create_dir("Windows/SystemTemp");
        let sysprofile_temp =
            self.create_dir("Windows/System32/config/systemprofile/AppData/Local/Temp");

        let prog_data = self.create_dir("ProgramData");
        let pkg_cache = self.create_dir("ProgramData/Package Cache");
        let pd_wer = self.create_dir("ProgramData/Microsoft/Windows/WER/ReportArchive");

        let local_app_data = self.create_dir("AppData/Local");
        let chrome_cache = self.create_dir("AppData/Local/Google/Chrome/User Data/Default/Cache");
        let chrome_code_cache =
            self.create_dir("AppData/Local/Google/Chrome/User Data/Default/Code Cache");
        let edge_cache = self.create_dir("AppData/Local/Microsoft/Edge/User Data/Default/Cache");
        let local_wer = self.create_dir("AppData/Local/Microsoft/Windows/WER/ReportArchive");
        let crash_dumps = self.create_dir("AppData/Local/CrashDumps");
        let d3d_cache = self.create_dir("AppData/Local/D3DSCache");
        let shader_cache = self.create_dir("AppData/Local/Microsoft/DirectX/ShaderCache");

        let app_data = self.create_dir("AppData/Roaming");
        let ff_cache =
            self.create_dir("AppData/Roaming/Mozilla/Firefox/Profiles/test.default/cache2");

        let user_profile = self.create_dir("UserProfile");
        let crypt_content =
            self.create_dir("UserProfile/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content");
        let crypt_meta =
            self.create_dir("UserProfile/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData");

        let recycle_bin = self.create_dir("$Recycle.Bin/S-1-5-21");

        MockWindowsPaths {
            sys_root,
            panther,
            cbs,
            dism_logs,
            mosetup,
            wudo_sd,
            wudo_sp,
            sys_temp,
            sysprofile_temp,
            prog_data,
            pkg_cache,
            pd_wer,
            local_app_data,
            chrome_cache,
            chrome_code_cache,
            edge_cache,
            local_wer,
            crash_dumps,
            d3d_cache,
            shader_cache,
            app_data,
            ff_cache,
            user_profile,
            crypt_content,
            crypt_meta,
            recycle_bin,
        }
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub struct MockWindowsPaths {
    pub sys_root: PathBuf,
    pub panther: PathBuf,
    pub cbs: PathBuf,
    pub dism_logs: PathBuf,
    pub mosetup: PathBuf,
    pub wudo_sd: PathBuf,
    pub wudo_sp: PathBuf,
    pub sys_temp: PathBuf,
    pub sysprofile_temp: PathBuf,
    pub prog_data: PathBuf,
    pub pkg_cache: PathBuf,
    pub pd_wer: PathBuf,
    pub local_app_data: PathBuf,
    pub chrome_cache: PathBuf,
    pub chrome_code_cache: PathBuf,
    pub edge_cache: PathBuf,
    pub local_wer: PathBuf,
    pub crash_dumps: PathBuf,
    pub d3d_cache: PathBuf,
    pub shader_cache: PathBuf,
    pub app_data: PathBuf,
    pub ff_cache: PathBuf,
    pub user_profile: PathBuf,
    pub crypt_content: PathBuf,
    pub crypt_meta: PathBuf,
    pub recycle_bin: PathBuf,
}

/// Shared record of every `(program, args)` pair a mock runner was asked to execute.
pub type ExecutionLog = Arc<Mutex<Vec<(String, Vec<String>)>>>;

/// Flexible programmable command runner for opaque-box testing.
#[derive(Clone, Default)]
pub struct ProgrammableMockRunner {
    pub responses: Arc<Mutex<HashMap<String, CmdOutput>>>,
    pub execution_log: ExecutionLog,
}

impl ProgrammableMockRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_success(program: &str, stdout: &str) -> Self {
        let runner = Self::new();
        runner.set_response(program, CmdOutput::ok(stdout));
        runner
    }

    pub fn set_response(&self, program: &str, output: CmdOutput) {
        let mut map = self.responses.lock().unwrap();
        map.insert(program.to_string(), output);
    }

    pub fn set_response_for_cmd_and_args(&self, key: &str, output: CmdOutput) {
        let mut map = self.responses.lock().unwrap();
        map.insert(key.to_string(), output);
    }

    pub fn calls_for(&self, program: &str) -> Vec<Vec<String>> {
        let log = self.execution_log.lock().unwrap();
        log.iter()
            .filter(|(prog, _)| prog == program)
            .map(|(_, args)| args.clone())
            .collect()
    }

    pub fn total_calls(&self) -> usize {
        self.execution_log.lock().unwrap().len()
    }

    pub async fn run_cmd(&self, command: &str, timeout: Duration) -> Result<CmdOutput, String> {
        self.run("cmd.exe", &["/c", command], timeout).await
    }
}

#[async_trait::async_trait]
impl CommandRunner for ProgrammableMockRunner {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        _timeout: Duration,
    ) -> Result<CmdOutput, String> {
        let arg_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        {
            let mut log = self.execution_log.lock().unwrap();
            log.push((program.to_string(), arg_vec.clone()));
        }

        let map = self.responses.lock().unwrap();

        let full_key = format!("{} {}", program, arg_vec.join(" "));
        if let Some(out) = map.get(&full_key) {
            return Ok(out.clone());
        }

        if let Some(out) = map.get(program) {
            return Ok(out.clone());
        }

        Ok(CmdOutput::ok(""))
    }

    async fn run_streaming(
        &self,
        program: &str,
        args: &[&str],
        log_tx: Option<Sender<String>>,
        timeout: Duration,
    ) -> Result<CmdOutput, String> {
        let out = self.run(program, args, timeout).await?;
        if let Some(tx) = log_tx {
            for line in out.stdout.lines() {
                let _ = tx.send(line.to_string()).await;
            }
        }
        Ok(out)
    }

    async fn run_powershell(&self, script: &str, timeout: Duration) -> Result<CmdOutput, String> {
        self.run(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", script],
            timeout,
        )
        .await
    }
}

pub const DISM_ANALYZE_ENGLISH_RECLAIMABLE: &str = "\
Deployment Image Servicing and Management tool
Version: 10.0.22621.1

Image Version: 10.0.22621.1

[==========================100.0%==========================]
Explorer Reported Size of Component Store : 8.12 GB
Actual Size of Component Store : 7.85 GB
    Shared with Windows : 4.50 GB
    Backups and Disabled Features : 2.50 GB
    Cache and Temporary Data : 0.85 GB
Date of Last Cleanup : 2026-08-10 14:00:00
Number of Reclaimable Packages : 3
Component Store Cleanup Recommended : Yes
The operation completed successfully.
";

pub const DISM_ANALYZE_GERMAN_RECLAIMABLE: &str = "\
Abbildverwaltung für die Bereitstellung
Version: 10.0.22621.1

Abbildversion: 10.0.22621.1

[==========================100.0%==========================]
Größe des Komponentenspeichers laut Explorer : 9.45 GB
Tatsächliche Größe des Komponentenspeichers : 8.90 GB
    Für Windows freigegeben : 5.10 GB
    Sicherungen und deaktivierte Features : 3.15 GB
    Cache und temporäre Daten : 0.65 GB
Datum der letzten Bereinigung : 2026-08-01 10:00:00
Anzahl der wiederverwendbaren Pakete : 5
Bereinigung des Komponentenspeichers empfohlen : Ja
Der Vorgang wurde erfolgreich beendet.
";

pub const DISM_ANALYZE_CLEAN: &str = "\
Deployment Image Servicing and Management tool
Version: 10.0.22621.1

Image Version: 10.0.22621.1

[==========================100.0%==========================]
Explorer Reported Size of Component Store : 5.12 GB
Actual Size of Component Store : 5.10 GB
    Shared with Windows : 4.80 GB
    Backups and Disabled Features : 0.20 GB
    Cache and Temporary Data : 0.10 GB
Date of Last Cleanup : 2026-08-14 10:00:00
Number of Reclaimable Packages : 0
Component Store Cleanup Recommended : No
The operation completed successfully.
";

pub const GITHUB_RELEASE_NEWER_JSON: &str = "{\n  \"tag_name\": \"v0.2.0\",\n  \"html_url\": \"https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0\",\n  \"name\": \"WinMedic v0.2.0 - System Cleaner & Auto-Updater\",\n  \"body\": \"New Features\",\n  \"draft\": false,\n  \"prerelease\": false\n}";

pub const GITHUB_RELEASE_CURRENT_JSON: &str = "{\n  \"tag_name\": \"v0.1.0\",\n  \"html_url\": \"https://github.com/SecretLUL/WinMedic/releases/tag/v0.1.0\",\n  \"name\": \"WinMedic v0.1.0\",\n  \"body\": \"Initial release\",\n  \"draft\": false,\n  \"prerelease\": false\n}";

pub const GITHUB_RELEASE_DRAFT_JSON: &str = "{\n  \"tag_name\": \"v0.9.0\",\n  \"html_url\": \"https://github.com/SecretLUL/WinMedic/releases/tag/v0.9.0\",\n  \"name\": \"WinMedic v0.9.0 Draft\",\n  \"body\": \"Draft notes\",\n  \"draft\": true,\n  \"prerelease\": false\n}";
