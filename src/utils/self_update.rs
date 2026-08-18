//! Replacing the running WinMedic executable with a newer release.
//!
//! Downloading is the easy half. The binary this module puts on disk is the one
//! the user launches next — very often as Administrator — so it has to *prove*
//! it is the artifact the release published before it is allowed anywhere near
//! that path. The order here is therefore fixed and has no shortcut:
//!
//! 1. fetch the release `.exe` into a staging file beside the current one,
//! 2. fetch the `.sha256` the release workflow publishes alongside it,
//! 3. hash the staged bytes and require the two to agree,
//! 4. reject a download whose Authenticode signature Windows itself rejects,
//! 5. only then swap it into place.
//!
//! Any failure before step 5 leaves the installed binary byte-for-byte
//! untouched and the staging file deleted, and the caller falls back to the
//! browser download — see [`crate::app::confirm`].
//!
//! What the checksum does and does not buy is worth stating plainly: it is
//! fetched over the same channel as the binary, from the same host, so it
//! proves the download is intact and matches what the release *says*, not that
//! the release itself is trustworthy. WinMedic ships unsigned today, so the
//! Authenticode check in step 4 can only reject a *broken* signature; once the
//! project has a code-signing certificate it becomes the check that closes that
//! gap. [`SignatureStatus`] reports which of the two happened so the UI can say
//! so rather than implying a guarantee that is not there.
//!
//! The swap itself is the standard Windows dance. A running image can be
//! renamed but neither deleted nor overwritten, so the current executable moves
//! aside to `<name>.old-<tag>`, the staged file takes its place, and the retired
//! image is deleted by [`clean_leftovers`] on the next start — by which point
//! nothing has it mapped any more.

use crate::utils::cmd::{CommandRunner, SystemCommandRunner, ps_single_quoted};
use crate::utils::updater::{
    GITHUB_RELEASE_DOWNLOAD_PREFIX, GITHUB_USER_AGENT, MAX_UPDATE_BYTES, UpdateDownload,
    is_safe_download_url, parse_sha256_manifest,
};

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

/// The checksum manifest is one short line. Anything bigger is not one, and
/// this is the ceiling handed to curl for that download.
pub const MAX_CHECKSUM_BYTES: u64 = 4 * 1024;

/// Marker the Authenticode script prints, so the Rust side never has to match
/// on Windows' localized status text. Mirrors the same trick in
/// [`crate::safety::restore_point`].
const SIGNATURE_MARKER: &str = "WINMEDIC_SIG:";

/// Infix of a staged download: `winmedic.exe.new-v0.3.3`.
const STAGING_INFIX: &str = ".new-";

/// Infix of a binary an update replaced: `winmedic.exe.old-v0.3.3`.
const RETIRED_INFIX: &str = ".old-";

/// Why an in-place update did not happen.
///
/// The variants exist because the fallback message has to be truthful about
/// *which* step refused: "the download could not be verified" and "the download
/// could not be written" are very different things to read when deciding
/// whether to trust the release page instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateFailure {
    /// This build has no access to the in-place updater. Only an app built with
    /// the inert [`SelfUpdateService`] reports this — see
    /// [`SelfUpdateService::inert`].
    NotRequested,
    /// Where the running executable lives, or where its staging files would go,
    /// could not be worked out.
    Environment(String),
    /// The bytes never arrived: curl failed, timed out, or wrote nothing.
    Download(String),
    /// The bytes arrived and are not what the release says they are. The one
    /// variant that means "someone may be lying to you" rather than "something
    /// went wrong".
    Verification(String),
    /// The download is genuine; putting it in place failed.
    Install(String),
}

impl UpdateFailure {
    /// A short tag for the audit log.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotRequested => "NOT_REQUESTED",
            Self::Environment(_) => "ENVIRONMENT",
            Self::Download(_) => "DOWNLOAD",
            Self::Verification(_) => "VERIFICATION",
            Self::Install(_) => "INSTALL",
        }
    }

    /// What to tell the user, phrased so it can follow "the update was not
    /// installed because ...".
    pub fn reason(&self) -> String {
        match self {
            Self::NotRequested => "this build has no access to the in-place updater".to_string(),
            Self::Environment(detail)
            | Self::Download(detail)
            | Self::Verification(detail)
            | Self::Install(detail) => detail.clone(),
        }
    }

    /// Whether the download failed to prove it is the release's own artifact.
    ///
    /// Worth separating from the rest: every other variant is an accident,
    /// while this one is the case the whole verification step exists for.
    pub fn is_verification_failure(&self) -> bool {
        matches!(self, Self::Verification(_))
    }
}

/// What Authenticode says about a downloaded binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Windows accepted the signature. The string is the signer's subject.
    Valid(String),
    /// The file carries no signature at all. WinMedic ships unsigned, so this
    /// is today's expected answer — not a failure, but not a guarantee either.
    Unsigned,
    /// A signature is present and Windows rejected it. Treated as fatal: a
    /// broken signature says more than a matching checksum does.
    Invalid(String),
    /// The question could not be asked (PowerShell unavailable, file format not
    /// understood). Not fatal — the checksum has already been verified by the
    /// time this runs.
    Unknown(String),
}

impl SignatureStatus {
    /// One line for the status bar and the audit log.
    pub fn summary(&self) -> String {
        match self {
            Self::Valid(subject) if subject.is_empty() => {
                "Authenticode signature valid".to_string()
            }
            Self::Valid(subject) => format!("Authenticode signature valid ({})", subject),
            Self::Unsigned => "unsigned (WinMedic ships without a code-signing certificate; \
                 the SHA256 checksum is the only guarantee)"
                .to_string(),
            Self::Invalid(status) => format!("Authenticode signature rejected: {}", status),
            Self::Unknown(detail) => format!("signature not checked: {}", detail),
        }
    }
}

/// Map the Authenticode script's marker line onto a status.
pub fn parse_signature_output(output: &str) -> SignatureStatus {
    let Some(line) = output
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(SIGNATURE_MARKER))
    else {
        return SignatureStatus::Unknown(
            "Get-AuthenticodeSignature printed no recognisable status".to_string(),
        );
    };

    let (status, subject) = line.split_once('|').unwrap_or((line, ""));
    match status.trim() {
        "Valid" => SignatureStatus::Valid(subject.trim().to_string()),
        "NotSigned" => SignatureStatus::Unsigned,
        // Windows understood the question but could not answer it. The checksum
        // has already passed at this point, so this is reported, not fatal.
        "" | "UnknownError" | "NotSupportedFileFormat" => SignatureStatus::Unknown(format!(
            "Get-AuthenticodeSignature returned '{}'",
            status.trim()
        )),
        // HashMismatch, NotTrusted, Incompatible: a signature exists and does
        // not hold up.
        other => SignatureStatus::Invalid(other.to_string()),
    }
}

/// One file to fetch onto disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub url: String,
    pub dest: PathBuf,
    /// Ceiling handed to curl, so an oversized response is abandoned mid-flight
    /// rather than after it has filled the disk.
    pub max_bytes: u64,
    pub timeout: Duration,
}

/// A future produced by a [`Fetcher`].
pub type FetchFuture = Pin<Box<dyn Future<Output = Result<(), UpdateFailure>> + Send>>;

/// How this module gets a URL onto disk.
///
/// A seam rather than a direct `curl.exe` call, so the part that decides whether
/// a binary may replace the running one can be tested end to end without a
/// network: a test installs a fetcher that writes known bytes — including
/// deliberately wrong ones — and asserts that the wrong ones never get
/// installed.
#[derive(Debug, Clone, Copy)]
pub struct Fetcher(fn(FetchRequest) -> FetchFuture);

impl Fetcher {
    /// The real thing: `curl.exe`, which every supported Windows build ships.
    pub fn curl() -> Self {
        fn fetch(request: FetchRequest) -> FetchFuture {
            Box::pin(async move {
                let runner = SystemCommandRunner::new();
                curl_download(&runner, &request).await
            })
        }
        Self(fetch)
    }

    /// Build a fetcher from a plain function. Exists for tests.
    pub fn from_fn(f: fn(FetchRequest) -> FetchFuture) -> Self {
        Self(f)
    }

    pub async fn get(&self, request: FetchRequest) -> Result<(), UpdateFailure> {
        (self.0)(request).await
    }
}

/// Fetch `request.url` to `request.dest` with curl.
///
/// The allow-list is re-applied here rather than trusted from upstream: this is
/// the function that actually hands a URL to a process, and it is `pub` so a
/// future caller could reach it with a URL that never passed through
/// [`crate::utils::updater::pick_update_download`].
pub async fn curl_download(
    runner: &dyn CommandRunner,
    request: &FetchRequest,
) -> Result<(), UpdateFailure> {
    if !is_safe_download_url(&request.url) {
        return Err(UpdateFailure::Verification(format!(
            "refused to download from an address outside {}: {}",
            GITHUB_RELEASE_DOWNLOAD_PREFIX, request.url
        )));
    }
    let Some(dest) = request.dest.to_str() else {
        return Err(UpdateFailure::Environment(format!(
            "the download path is not valid UTF-8: {}",
            request.dest.display()
        )));
    };

    // A partial file from an abandoned attempt would otherwise be hashed as
    // though curl had just written it.
    let _ = fs::remove_file(&request.dest);

    let max_time = request.timeout.as_secs().max(1).to_string();
    let max_filesize = request.max_bytes.to_string();
    let user_agent = format!("User-Agent: {}", GITHUB_USER_AGENT);
    let args = [
        // Silent, but still report transport errors, and treat an HTTP error
        // as a failure instead of writing the error page to disk as if it were
        // the binary.
        "-sSf",
        // Release asset URLs redirect to GitHub's asset CDN...
        "-L",
        // ...and every hop of that redirect chain has to stay HTTPS. Without
        // --proto-redir a redirect could downgrade the transfer to plain HTTP.
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-time",
        &max_time,
        "--max-filesize",
        &max_filesize,
        "-H",
        &user_agent,
        "-o",
        dest,
        &request.url,
    ];

    // The process gets a little longer than the transfer budget it was given,
    // so a curl that honours --max-time reports its own error rather than being
    // killed and reported as a generic timeout.
    let output = runner
        .run("curl.exe", &args, request.timeout + Duration::from_secs(5))
        .await
        .map_err(UpdateFailure::Download)?;

    if !output.success {
        let _ = fs::remove_file(&request.dest);
        let detail = output.stderr.trim();
        return Err(UpdateFailure::Download(format!(
            "curl could not download {} (exit {}){}",
            request.url,
            output
                .exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string()),
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {}", detail)
            }
        )));
    }

    Ok(())
}

/// Everything an in-place install needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    pub download: UpdateDownload,
    /// The executable to replace — normally the running one.
    pub exe: PathBuf,
    /// Release tag, used to name the staging and retired files.
    pub tag: String,
    /// Budget for each individual transfer.
    pub timeout: Duration,
}

impl InstallPlan {
    /// Target the running executable.
    pub fn for_current_exe(
        download: UpdateDownload,
        tag: &str,
        timeout: Duration,
    ) -> Result<Self, UpdateFailure> {
        let exe = std::env::current_exe().map_err(|e| {
            UpdateFailure::Environment(format!(
                "could not work out where WinMedic is installed: {}",
                e
            ))
        })?;
        Ok(Self {
            download,
            exe,
            tag: tag.to_string(),
            timeout,
        })
    }
}

/// A completed in-place update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledUpdate {
    /// The path that now holds the new binary — the one the user launches.
    pub installed: PathBuf,
    /// Where the replaced image was parked. Still mapped by the running
    /// process, so it is deleted on the next start by [`clean_leftovers`].
    pub retired: PathBuf,
    /// The digest the download and the release's manifest agreed on.
    pub sha256: String,
    pub signature: SignatureStatus,
}

/// Download, verify and install the release described by `plan`.
///
/// On any error the installed binary is exactly as it was and no staged file
/// survives.
pub async fn install(
    fetch: Fetcher,
    runner: &dyn CommandRunner,
    plan: &InstallPlan,
    progress: Option<&UnboundedSender<String>>,
) -> Result<InstalledUpdate, UpdateFailure> {
    let staged = sibling(&plan.exe, STAGING_INFIX, &plan.tag)?;
    let retired = sibling(&plan.exe, RETIRED_INFIX, &plan.tag)?;
    let manifest = with_suffix(&staged, ".sha256");

    let result =
        stage_verify_and_swap(fetch, runner, plan, &staged, &manifest, &retired, progress).await;

    // The manifest has served its purpose either way. A staged file that never
    // made it into place is a *rejected* binary sitting next to the one the user
    // runs, which is the last thing to leave lying around.
    let _ = fs::remove_file(&manifest);
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn stage_verify_and_swap(
    fetch: Fetcher,
    runner: &dyn CommandRunner,
    plan: &InstallPlan,
    staged: &Path,
    manifest: &Path,
    retired: &Path,
    progress: Option<&UnboundedSender<String>>,
) -> Result<InstalledUpdate, UpdateFailure> {
    step(
        progress,
        format!("Downloading {}...", plan.download.binary_name),
    );
    fetch
        .get(FetchRequest {
            url: plan.download.binary_url.clone(),
            dest: staged.to_path_buf(),
            max_bytes: MAX_UPDATE_BYTES,
            timeout: plan.timeout,
        })
        .await?;

    // curl's --max-filesize only fires when the server announced a length, so
    // the size the download actually reached is checked here as well.
    let downloaded = fs::metadata(staged)
        .map_err(|e| {
            UpdateFailure::Download(format!(
                "the download produced no file at {}: {}",
                staged.display(),
                e
            ))
        })?
        .len();
    if downloaded == 0 {
        return Err(UpdateFailure::Download(
            "the download produced an empty file".to_string(),
        ));
    }
    if downloaded > MAX_UPDATE_BYTES {
        return Err(UpdateFailure::Download(format!(
            "the download reached {} bytes, past the {} byte ceiling",
            downloaded, MAX_UPDATE_BYTES
        )));
    }

    step(progress, "Downloading the published checksum...");
    fetch
        .get(FetchRequest {
            url: plan.download.checksum_url.clone(),
            dest: manifest.to_path_buf(),
            max_bytes: MAX_CHECKSUM_BYTES,
            timeout: plan.timeout,
        })
        .await?;

    step(progress, "Verifying the SHA256 checksum...");
    let expected = read_checksum_manifest(manifest, &plan.download.binary_name)?;
    let sha256 = verify_staged(staged, &expected)?;

    step(progress, "Checking the Authenticode signature...");
    let signature = authenticode_status(runner, staged, plan.timeout).await;
    if let SignatureStatus::Invalid(status) = &signature {
        return Err(UpdateFailure::Verification(format!(
            "the download carries an Authenticode signature that Windows rejects ({}). \
             A broken signature says more than a matching checksum does, so it is not installed",
            status
        )));
    }

    step(progress, "Installing the new binary...");
    swap_in_place(&plan.exe, staged, retired)?;

    Ok(InstalledUpdate {
        installed: plan.exe.clone(),
        retired: retired.to_path_buf(),
        sha256,
        signature,
    })
}

/// Read the digest the release published for `binary_name`.
pub fn read_checksum_manifest(manifest: &Path, binary_name: &str) -> Result<String, UpdateFailure> {
    let size = fs::metadata(manifest)
        .map_err(|e| {
            UpdateFailure::Download(format!("the checksum file could not be read: {}", e))
        })?
        .len();
    if size > MAX_CHECKSUM_BYTES {
        return Err(UpdateFailure::Verification(format!(
            "the checksum file is {} bytes; a sha256sum line is under a hundred",
            size
        )));
    }

    let content = fs::read_to_string(manifest).map_err(|e| {
        UpdateFailure::Download(format!("the checksum file could not be read: {}", e))
    })?;

    parse_sha256_manifest(&content, binary_name).map_err(UpdateFailure::Verification)
}

/// Hold the staged file to the digest the release published for it.
pub fn verify_staged(staged: &Path, expected_hex: &str) -> Result<String, UpdateFailure> {
    let actual = sha256_file(staged).map_err(|e| {
        UpdateFailure::Verification(format!(
            "the download could not be read back for hashing: {}",
            e
        ))
    })?;

    if !actual.eq_ignore_ascii_case(expected_hex) {
        return Err(UpdateFailure::Verification(format!(
            "SHA256 mismatch - the release publishes {}, the download hashes to {}",
            expected_hex.to_ascii_lowercase(),
            actual
        )));
    }
    Ok(actual)
}

/// SHA256 of a file, streamed so a whole binary never lands in memory at once.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(hex, "{:02x}", byte);
    }
    Ok(hex)
}

/// Ask Windows what it thinks of the signature on `path`.
pub async fn authenticode_status(
    runner: &dyn CommandRunner,
    path: &Path,
    timeout: Duration,
) -> SignatureStatus {
    let Some(path_str) = path.to_str() else {
        return SignatureStatus::Unknown("the staged path is not valid UTF-8".to_string());
    };

    // Single-quoted throughout: PowerShell interpolates nothing inside those,
    // and the one metacharacter left is handled by `ps_single_quoted`.
    let script = format!(
        "$sig = Get-AuthenticodeSignature -LiteralPath {path}; \
         Write-Output ('{marker}' + $sig.Status + '|' + $sig.SignerCertificate.Subject)",
        path = ps_single_quoted(path_str),
        marker = SIGNATURE_MARKER,
    );

    match runner.run_powershell(&script, timeout).await {
        Ok(output) => parse_signature_output(&output.stdout),
        Err(e) => SignatureStatus::Unknown(e),
    }
}

/// Move `staged` into `exe`'s place, parking the running image at `retired`.
///
/// The two renames are the whole reason this works while WinMedic is running:
/// Windows refuses to delete or overwrite a mapped image but is happy to rename
/// one. If the second rename fails the first is undone, because "the update did
/// not install" must never also mean "and now there is no WinMedic here".
pub fn swap_in_place(exe: &Path, staged: &Path, retired: &Path) -> Result<(), UpdateFailure> {
    // A retired binary from an earlier update in this same session is still
    // mapped and cannot be removed; the rename below would then fail. Sweeping
    // it first costs nothing and covers the case where it *is* removable.
    let _ = fs::remove_file(retired);

    fs::rename(exe, retired).map_err(|e| {
        UpdateFailure::Install(format!(
            "could not move the running binary aside to {}: {}",
            retired.display(),
            e
        ))
    })?;

    if let Err(e) = fs::rename(staged, exe) {
        let recovery = match fs::rename(retired, exe) {
            Ok(()) => "the installed version was put back and is unchanged".to_string(),
            Err(restore_err) => format!(
                "and it could not be put back ({}); the previous binary is at {}",
                restore_err,
                retired.display()
            ),
        };
        return Err(UpdateFailure::Install(format!(
            "could not move the verified download into place: {} - {}",
            e, recovery
        )));
    }

    Ok(())
}

/// Delete the files a previous in-place update left beside `exe`.
///
/// A running image cannot delete itself, so the binary an update replaced
/// survives until the *next* start — this one. Staging files from an attempt
/// that died between the download and the swap are swept up too; on Windows an
/// attempt still in flight holds its staging file open, so a concurrent update
/// is protected by the OS rather than by a guess about timing.
///
/// Returns how many files were removed. Every failure is ignored: leftover junk
/// is untidy, not a reason to refuse to start.
pub fn clean_leftovers(exe: &Path) -> usize {
    let (Some(dir), Some(name)) = (exe.parent(), exe.file_name().and_then(|n| n.to_str())) else {
        return 0;
    };
    let staging_prefix = format!("{}{}", name, STAGING_INFIX);
    let retired_prefix = format!("{}{}", name, RETIRED_INFIX);

    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };

    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(candidate) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if (candidate.starts_with(&staging_prefix) || candidate.starts_with(&retired_prefix))
            && fs::remove_file(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// [`clean_leftovers`] for the running executable.
///
/// Best-effort by design and safe to call before anything else in `main`: it
/// only ever removes files whose name starts with the running executable's own
/// file name plus an update infix this module writes.
pub fn clean_leftovers_beside_current_exe() -> usize {
    match std::env::current_exe() {
        Ok(exe) => clean_leftovers(&exe),
        Err(_) => 0,
    }
}

/// The app's seam onto replacing its own executable.
///
/// Same shape and same reason as
/// [`crate::safety::restore_point::RestorePointService`]: [`Self::inert`] is the
/// default, so an [`crate::app::App`] built in a test cannot download or install
/// anything, and only the TUI entry point installs the real one.
pub type InstallFuture =
    Pin<Box<dyn Future<Output = Result<InstalledUpdate, UpdateFailure>> + Send>>;

#[derive(Debug, Clone, Copy)]
pub struct SelfUpdateService {
    install: fn(InstallPlan, Option<UnboundedSender<String>>) -> InstallFuture,
    /// Whether `install` really downloads and replaces a file. Carried as data
    /// so a guard test can assert an app is inert *without* invoking it.
    live: bool,
}

impl SelfUpdateService {
    /// The real thing: downloads from GitHub and replaces the binary on disk.
    pub fn real() -> Self {
        fn install(plan: InstallPlan, progress: Option<UnboundedSender<String>>) -> InstallFuture {
            Box::pin(async move {
                let runner = SystemCommandRunner::new();
                super::self_update::install(Fetcher::curl(), &runner, &plan, progress.as_ref())
                    .await
            })
        }
        Self {
            install,
            live: true,
        }
    }

    /// Reports [`UpdateFailure::NotRequested`] without touching the network or
    /// the disk. The default.
    pub fn inert() -> Self {
        fn install(_: InstallPlan, _: Option<UnboundedSender<String>>) -> InstallFuture {
            Box::pin(std::future::ready(Err(UpdateFailure::NotRequested)))
        }
        Self {
            install,
            live: false,
        }
    }

    /// Whether [`Self::install`] reaches the network and the filesystem.
    pub fn is_live(&self) -> bool {
        self.live
    }

    pub fn install(
        &self,
        plan: InstallPlan,
        progress: Option<UnboundedSender<String>>,
    ) -> InstallFuture {
        (self.install)(plan, progress)
    }
}

impl Default for SelfUpdateService {
    fn default() -> Self {
        Self::inert()
    }
}

// ------------------------------------------------------------------ helpers

fn step(progress: Option<&UnboundedSender<String>>, message: impl Into<String>) {
    if let Some(tx) = progress {
        let _ = tx.send(message.into());
    }
}

/// `<exe file name><infix><tag>`, in the executable's own directory.
fn sibling(exe: &Path, infix: &str, tag: &str) -> Result<PathBuf, UpdateFailure> {
    let name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            UpdateFailure::Environment(format!(
                "the executable path has no usable file name: {}",
                exe.display()
            ))
        })?
        .to_string();
    Ok(exe.with_file_name(format!("{}{}{}", name, infix, tag_slug(tag))))
}

/// Append `suffix` to a path's file name without going through lossy `Display`.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.to_path_buf().into_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// A release tag comes off the network and ends up inside a file name, so
/// anything that is not plainly a tag character becomes `_`.
fn tag_slug(tag: &str) -> String {
    let slug: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();

    if slug.is_empty() {
        "update".to_string()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// Minimal scoped temp directory; the crate has no dev-dependency on
    /// `tempfile`. Mirrors the helper in `config`.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = format!(
                "winmedic_selfupdate_{}_{}_{:?}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(unique);
            fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        fn file(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("failed to write temp file");
            path
        }

        fn names(&self) -> Vec<String> {
            let mut found: Vec<String> = fs::read_dir(&self.path)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            found.sort();
            found
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Bytes the stub fetcher hands back, keyed by URL.
    ///
    /// A `Fetcher` is a plain function pointer — that is what keeps
    /// [`SelfUpdateService`] `Copy` — so a stub cannot capture per-test data.
    /// Keying on the URL gives each test its own entries and keeps the suite
    /// safe to run in parallel.
    fn stub_bodies() -> &'static Mutex<HashMap<String, Vec<u8>>> {
        static BODIES: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
        BODIES.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn serve(url: &str, body: &[u8]) {
        stub_bodies()
            .lock()
            .unwrap()
            .insert(url.to_string(), body.to_vec());
    }

    fn stub_fetcher() -> Fetcher {
        fn fetch(request: FetchRequest) -> FetchFuture {
            Box::pin(async move {
                let body = stub_bodies().lock().unwrap().get(&request.url).cloned();
                match body {
                    Some(bytes) => fs::write(&request.dest, bytes).map_err(|e| {
                        UpdateFailure::Download(format!("stub could not write: {}", e))
                    }),
                    None => Err(UpdateFailure::Download(format!(
                        "stub has nothing for {}",
                        request.url
                    ))),
                }
            })
        }
        Fetcher::from_fn(fetch)
    }

    const DOWNLOAD_BASE: &str = "https://github.com/SecretLUL/WinMedic/releases/download/v9.9.9";

    /// A plan whose two URLs are unique to `label`, so parallel tests never
    /// share stub entries.
    fn plan_for(dir: &TempDir, label: &str) -> InstallPlan {
        let binary_url = format!("{}/winmedic-{}.exe", DOWNLOAD_BASE, label);
        InstallPlan {
            download: UpdateDownload {
                binary_name: format!("winmedic-{}.exe", label),
                checksum_url: format!("{}.sha256", binary_url),
                binary_url,
                size: 0,
            },
            exe: dir.path.join("winmedic.exe"),
            tag: "v9.9.9".to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    // ------------------------------------------------------------- hashing

    /// The two shortest NIST vectors, so a wrong hash function cannot pass.
    #[test]
    fn sha256_matches_the_published_vectors() {
        let dir = TempDir::new("vectors");

        let empty = dir.file("empty", "");
        assert_eq!(
            sha256_file(&empty).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc = dir.file("abc", "abc");
        assert_eq!(
            sha256_file(&abc).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Longer than the read buffer, so the streaming loop is actually exercised
    /// rather than a single-chunk special case.
    #[test]
    fn sha256_hashes_a_file_larger_than_the_read_buffer() {
        let dir = TempDir::new("large");
        let big = dir.file("big", &"a".repeat(200_000));

        let digest = sha256_file(&big).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        // Same bytes, same digest — the loop must not depend on chunk edges.
        let again = dir.file("big2", &"a".repeat(200_000));
        assert_eq!(digest, sha256_file(&again).unwrap());
    }

    #[test]
    fn verify_staged_accepts_the_matching_digest_in_either_case() {
        let dir = TempDir::new("verify_ok");
        let file = dir.file("payload", "abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        assert_eq!(verify_staged(&file, expected).unwrap(), expected);
        assert_eq!(
            verify_staged(&file, &expected.to_ascii_uppercase()).unwrap(),
            expected
        );
    }

    #[test]
    fn verify_staged_reports_both_digests_on_a_mismatch() {
        let dir = TempDir::new("verify_bad");
        let file = dir.file("payload", "abc");

        let err = verify_staged(&file, &"0".repeat(64)).unwrap_err();
        assert!(err.is_verification_failure());
        assert!(err.reason().contains("ba7816bf"), "{}", err.reason());
        assert!(err.reason().contains(&"0".repeat(64)));
    }

    // ------------------------------------------------------------ manifest

    #[test]
    fn a_manifest_naming_another_file_is_rejected() {
        let dir = TempDir::new("manifest_other");
        let hash = "a".repeat(64);
        let manifest = dir.file("m.sha256", &format!("{}  winmedic-v0.0.1.exe\n", hash));

        let err = read_checksum_manifest(&manifest, "winmedic-v0.3.3.exe").unwrap_err();
        assert!(err.is_verification_failure());
        assert!(err.reason().contains("winmedic-v0.0.1.exe"));
    }

    #[test]
    fn a_manifest_for_the_expected_file_yields_its_digest() {
        let dir = TempDir::new("manifest_ok");
        let hash = "A".repeat(64);
        let manifest = dir.file("m.sha256", &format!("{}  winmedic-v0.3.3.exe\n", hash));

        assert_eq!(
            read_checksum_manifest(&manifest, "winmedic-v0.3.3.exe").unwrap(),
            "a".repeat(64)
        );
    }

    #[test]
    fn an_oversized_manifest_is_refused_before_it_is_parsed() {
        let dir = TempDir::new("manifest_big");
        let manifest = dir.file("m.sha256", &"x".repeat(MAX_CHECKSUM_BYTES as usize + 1));

        let err = read_checksum_manifest(&manifest, "winmedic.exe").unwrap_err();
        assert!(err.is_verification_failure());
    }

    // ---------------------------------------------------------------- swap

    #[test]
    fn the_swap_installs_the_new_binary_and_parks_the_old_one() {
        let dir = TempDir::new("swap_ok");
        let exe = dir.file("winmedic.exe", "old");
        let staged = dir.file("winmedic.exe.new-v1", "new");
        let retired = dir.path.join("winmedic.exe.old-v1");

        swap_in_place(&exe, &staged, &retired).unwrap();

        assert_eq!(fs::read_to_string(&exe).unwrap(), "new");
        assert_eq!(fs::read_to_string(&retired).unwrap(), "old");
        assert!(!staged.exists());
    }

    /// The half-applied state is the dangerous one: the old binary has already
    /// moved aside when the second rename fails, so there would be no WinMedic
    /// at the path the user launches.
    #[test]
    fn a_failed_second_rename_puts_the_old_binary_back() {
        let dir = TempDir::new("swap_rollback");
        let exe = dir.file("winmedic.exe", "old");
        let staged = dir.path.join("winmedic.exe.new-v1"); // never created
        let retired = dir.path.join("winmedic.exe.old-v1");

        let err = swap_in_place(&exe, &staged, &retired).unwrap_err();

        assert_eq!(err.kind(), "INSTALL");
        assert!(err.reason().contains("put back"), "{}", err.reason());
        assert_eq!(fs::read_to_string(&exe).unwrap(), "old");
        assert!(!retired.exists());
    }

    // ------------------------------------------------------------- cleanup

    #[test]
    fn cleanup_removes_only_this_executables_update_leftovers() {
        let dir = TempDir::new("cleanup");
        let exe = dir.file("winmedic.exe", "current");
        dir.file("winmedic.exe.old-v0.3.1", "retired");
        dir.file("winmedic.exe.new-v0.3.2", "staged");
        dir.file("winmedic.exe.new-v0.3.2.sha256", "manifest");
        // Neither belongs to this executable's update machinery.
        dir.file("winmedic.exe.config", "keep");
        dir.file("other.exe.old-v1", "keep");

        assert_eq!(clean_leftovers(&exe), 3);
        assert_eq!(
            dir.names(),
            vec!["other.exe.old-v1", "winmedic.exe", "winmedic.exe.config"]
        );
    }

    /// The startup sweep in `main` resolves the running executable itself, and
    /// this is the only test that can check that half — the running executable
    /// here is the test binary, so the file it plants is named after that.
    #[test]
    fn the_startup_sweep_finds_the_running_executables_own_leftovers() {
        let exe = std::env::current_exe().expect("a test binary has a path");
        let mut planted = exe.clone().into_os_string();
        planted.push(".old-v0.0.0-probe");
        let planted = PathBuf::from(planted);
        fs::write(&planted, "a retired build").expect("failed to plant a leftover");

        assert!(clean_leftovers_beside_current_exe() >= 1);
        assert!(!planted.exists(), "the startup sweep missed {:?}", planted);
    }

    #[test]
    fn cleanup_on_a_directory_without_leftovers_removes_nothing() {
        let dir = TempDir::new("cleanup_empty");
        let exe = dir.file("winmedic.exe", "current");

        assert_eq!(clean_leftovers(&exe), 0);
        assert_eq!(dir.names(), vec!["winmedic.exe"]);
    }

    // ------------------------------------------------------- curl arguments

    #[tokio::test]
    async fn the_download_pins_https_across_redirects_and_caps_the_size() {
        let dir = TempDir::new("curl_args");
        let mock = MockCommandRunner::new();
        mock.add_response("curl.exe", CmdOutput::ok(""));

        let dest = dir.path.join("winmedic.exe.new-v1");
        curl_download(
            &mock,
            &FetchRequest {
                url: format!("{}/winmedic-v9.9.9.exe", DOWNLOAD_BASE),
                dest: dest.clone(),
                max_bytes: 1234,
                timeout: Duration::from_secs(30),
            },
        )
        .await
        .unwrap();

        let executed = mock.executed();
        assert_eq!(executed.len(), 1);
        let cmd = &executed[0];
        assert!(cmd.contains("-sSf"), "{}", cmd);
        assert!(cmd.contains("--proto =https"), "{}", cmd);
        // Without this a redirect could drop the transfer onto plain HTTP.
        assert!(cmd.contains("--proto-redir =https"), "{}", cmd);
        assert!(cmd.contains("--max-filesize 1234"), "{}", cmd);
        assert!(cmd.contains("--max-time 30"), "{}", cmd);
        assert!(cmd.contains(dest.to_str().unwrap()), "{}", cmd);
    }

    #[tokio::test]
    async fn the_download_refuses_a_url_outside_the_release_download_path() {
        let dir = TempDir::new("curl_offsite");
        let mock = MockCommandRunner::new();
        mock.add_response("curl.exe", CmdOutput::ok(""));

        for url in [
            // Right host, wrong path: a repository page is not a release asset.
            "https://github.com/SecretLUL/WinMedic/raw/main/evil.exe",
            // Another account's release assets are still not this project's.
            "https://github.com/attacker/WinMedic/releases/download/v1/winmedic.exe",
            "https://evil.example/winmedic.exe",
        ] {
            let err = curl_download(
                &mock,
                &FetchRequest {
                    url: url.to_string(),
                    dest: dir.path.join("out"),
                    max_bytes: 1024,
                    timeout: Duration::from_secs(5),
                },
            )
            .await
            .unwrap_err();

            assert!(err.is_verification_failure(), "{} was accepted", url);
        }
        assert!(
            mock.executed().is_empty(),
            "curl ran for a rejected URL: {:?}",
            mock.executed()
        );
    }

    #[tokio::test]
    async fn a_failing_curl_leaves_no_partial_file_behind() {
        let dir = TempDir::new("curl_fail");
        let mock = MockCommandRunner::new();
        mock.add_response("curl.exe", CmdOutput::failed(22, "curl: (22) HTTP 404"));

        let dest = dir.path.join("winmedic.exe.new-v1");
        fs::write(&dest, "half a download").unwrap();

        let err = curl_download(
            &mock,
            &FetchRequest {
                url: format!("{}/winmedic-v9.9.9.exe", DOWNLOAD_BASE),
                dest: dest.clone(),
                max_bytes: 1024,
                timeout: Duration::from_secs(5),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.kind(), "DOWNLOAD");
        assert!(err.reason().contains("404"), "{}", err.reason());
        assert!(!dest.exists());
    }

    // ----------------------------------------------------------- signatures

    #[test]
    fn signature_statuses_map_onto_what_windows_reports() {
        assert_eq!(
            parse_signature_output("WINMEDIC_SIG:Valid|CN=Example, O=Example"),
            SignatureStatus::Valid("CN=Example, O=Example".to_string())
        );
        assert_eq!(
            parse_signature_output("WINMEDIC_SIG:NotSigned|"),
            SignatureStatus::Unsigned
        );
        assert_eq!(
            parse_signature_output("WINMEDIC_SIG:HashMismatch|CN=Example"),
            SignatureStatus::Invalid("HashMismatch".to_string())
        );
        assert_eq!(
            parse_signature_output("WINMEDIC_SIG:NotTrusted|CN=Self"),
            SignatureStatus::Invalid("NotTrusted".to_string())
        );
        assert!(matches!(
            parse_signature_output("WINMEDIC_SIG:UnknownError|"),
            SignatureStatus::Unknown(_)
        ));
        // A localized error instead of the marker must not read as "signed".
        assert!(matches!(
            parse_signature_output("Der Befehl wurde nicht gefunden."),
            SignatureStatus::Unknown(_)
        ));
    }

    // ------------------------------------------------------- orchestration

    #[tokio::test]
    async fn a_verified_download_replaces_the_binary_and_leaves_no_staging_files() {
        let dir = TempDir::new("install_ok");
        fs::write(dir.path.join("winmedic.exe"), "the old build").unwrap();
        let plan = plan_for(&dir, "ok");

        let payload = b"the new build";
        serve(&plan.download.binary_url, payload);
        // The digest has to be the real one, so it is computed the same way the
        // release workflow computes it rather than hard-coded.
        let probe = dir.file("probe", "");
        fs::write(&probe, payload).unwrap();
        let real_digest = sha256_file(&probe).unwrap();
        fs::remove_file(&probe).unwrap();
        serve(
            &plan.download.checksum_url,
            format!("{}  {}\n", real_digest, plan.download.binary_name).as_bytes(),
        );

        let mock = MockCommandRunner::new();
        mock.add_response("powershell", CmdOutput::ok("WINMEDIC_SIG:NotSigned|"));

        let installed = install(stub_fetcher(), &mock, &plan, None).await.unwrap();

        assert_eq!(installed.sha256, real_digest);
        assert_eq!(installed.signature, SignatureStatus::Unsigned);
        assert_eq!(
            fs::read_to_string(dir.path.join("winmedic.exe")).unwrap(),
            "the new build"
        );
        assert_eq!(
            fs::read_to_string(&installed.retired).unwrap(),
            "the old build"
        );
        // The manifest is gone and nothing is staged.
        assert_eq!(dir.names(), vec!["winmedic.exe", "winmedic.exe.old-v9.9.9"]);
    }

    /// The case the whole module exists for: bytes that are not what the release
    /// says they are must not reach the path the user launches.
    #[tokio::test]
    async fn a_tampered_download_is_never_installed() {
        let dir = TempDir::new("install_tampered");
        fs::write(dir.path.join("winmedic.exe"), "the old build").unwrap();
        let plan = plan_for(&dir, "tampered");

        serve(&plan.download.binary_url, b"a payload nobody published");
        serve(
            &plan.download.checksum_url,
            format!("{}  {}\n", "b".repeat(64), plan.download.binary_name).as_bytes(),
        );

        let mock = MockCommandRunner::new();
        mock.add_response("powershell", CmdOutput::ok("WINMEDIC_SIG:NotSigned|"));

        let err = install(stub_fetcher(), &mock, &plan, None)
            .await
            .unwrap_err();

        assert!(err.is_verification_failure(), "{:?}", err);
        assert_eq!(
            fs::read_to_string(dir.path.join("winmedic.exe")).unwrap(),
            "the old build"
        );
        // The rejected bytes are not left sitting next to the real binary.
        assert_eq!(dir.names(), vec!["winmedic.exe"]);
        // The signature was never consulted: verification failed first.
        assert!(mock.executed().is_empty());
    }

    /// A signature Windows rejects outranks a checksum that matches — the
    /// checksum only proves the file matches the manifest next to it.
    #[tokio::test]
    async fn a_rejected_authenticode_signature_blocks_an_otherwise_valid_download() {
        let dir = TempDir::new("install_badsig");
        fs::write(dir.path.join("winmedic.exe"), "the old build").unwrap();
        let plan = plan_for(&dir, "badsig");

        let payload = b"signed but broken";
        serve(&plan.download.binary_url, payload);
        let probe = dir.file("probe", "");
        fs::write(&probe, payload).unwrap();
        let real_digest = sha256_file(&probe).unwrap();
        fs::remove_file(&probe).unwrap();
        serve(
            &plan.download.checksum_url,
            format!("{}  {}\n", real_digest, plan.download.binary_name).as_bytes(),
        );

        let mock = MockCommandRunner::new();
        mock.add_response(
            "powershell",
            CmdOutput::ok("WINMEDIC_SIG:HashMismatch|CN=X"),
        );

        let err = install(stub_fetcher(), &mock, &plan, None)
            .await
            .unwrap_err();

        assert!(err.is_verification_failure());
        assert!(err.reason().contains("HashMismatch"), "{}", err.reason());
        assert_eq!(
            fs::read_to_string(dir.path.join("winmedic.exe")).unwrap(),
            "the old build"
        );
        assert_eq!(dir.names(), vec!["winmedic.exe"]);
    }

    #[tokio::test]
    async fn a_download_that_writes_nothing_is_reported_as_a_download_failure() {
        let dir = TempDir::new("install_nofile");
        fs::write(dir.path.join("winmedic.exe"), "the old build").unwrap();
        let plan = plan_for(&dir, "nofile");
        // Nothing served: the stub fetcher errors instead of writing.

        let mock = MockCommandRunner::new();
        let err = install(stub_fetcher(), &mock, &plan, None)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), "DOWNLOAD");
        assert_eq!(
            fs::read_to_string(dir.path.join("winmedic.exe")).unwrap(),
            "the old build"
        );
    }

    #[tokio::test]
    async fn the_progress_channel_narrates_every_step_in_order() {
        let dir = TempDir::new("install_progress");
        fs::write(dir.path.join("winmedic.exe"), "old").unwrap();
        let plan = plan_for(&dir, "progress");

        let payload = b"new";
        serve(&plan.download.binary_url, payload);
        let probe = dir.file("probe", "");
        fs::write(&probe, payload).unwrap();
        let digest = sha256_file(&probe).unwrap();
        fs::remove_file(&probe).unwrap();
        serve(
            &plan.download.checksum_url,
            format!("{}  {}\n", digest, plan.download.binary_name).as_bytes(),
        );

        let mock = MockCommandRunner::new();
        mock.add_response("powershell", CmdOutput::ok("WINMEDIC_SIG:NotSigned|"));

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        install(stub_fetcher(), &mock, &plan, Some(&tx))
            .await
            .unwrap();
        drop(tx);

        let mut steps = Vec::new();
        while let Ok(step) = rx.try_recv() {
            steps.push(step);
        }
        assert_eq!(steps.len(), 5, "{:?}", steps);
        assert!(steps[0].starts_with("Downloading winmedic-progress.exe"));
        assert!(steps[2].contains("SHA256"));
        assert!(steps[4].contains("Installing"));
    }

    // ------------------------------------------------------------- the seam

    #[tokio::test]
    async fn the_inert_service_installs_nothing() {
        let service = SelfUpdateService::default();
        assert!(!service.is_live());

        let dir = TempDir::new("inert");
        fs::write(dir.path.join("winmedic.exe"), "untouched").unwrap();
        let plan = plan_for(&dir, "inert");

        let err = service.install(plan, None).await.unwrap_err();
        assert_eq!(err, UpdateFailure::NotRequested);
        assert_eq!(
            fs::read_to_string(dir.path.join("winmedic.exe")).unwrap(),
            "untouched"
        );
        assert_eq!(dir.names(), vec!["winmedic.exe"]);
    }

    /// No test may build the real updater. `SelfUpdateService::real` and
    /// `Fetcher::curl` reach GitHub and then rename the running binary — in a
    /// test that binary is the test harness itself. Everything worth asserting
    /// is reachable through [`install`] with a stub [`Fetcher`], as the tests
    /// above do, so there is never a reason to reach for the real one.
    #[test]
    fn no_test_in_the_tree_builds_the_real_self_updater() {
        let mut offenders =
            crate::utils::test_guard::integration_test_lines_mentioning("SelfUpdateService::real(");
        offenders.extend(crate::utils::test_guard::integration_test_lines_mentioning(
            "Fetcher::curl(",
        ));

        assert!(
            offenders.is_empty(),
            "these tests would download and replace an executable; use install() with a              stub Fetcher instead: {:?}",
            offenders
        );
    }

    // ------------------------------------------------------------- naming

    #[test]
    fn a_hostile_tag_cannot_escape_the_executables_directory() {
        let exe = Path::new(r"C:\Tools\winmedic.exe");

        let staged = sibling(exe, STAGING_INFIX, "../../Windows/System32/evil").unwrap();
        assert_eq!(staged.parent(), Some(Path::new(r"C:\Tools")));
        assert_eq!(
            staged.file_name().unwrap().to_str().unwrap(),
            "winmedic.exe.new-.._.._Windows_System32_evil"
        );

        // An empty or entirely hostile tag still produces a usable name.
        let empty = sibling(exe, RETIRED_INFIX, "///").unwrap();
        assert_eq!(
            empty.file_name().unwrap().to_str().unwrap(),
            "winmedic.exe.old-___"
        );
    }

    #[test]
    fn staging_files_are_named_after_the_executable_they_replace() {
        // A user who renamed the binary must still get their leftovers cleaned.
        let exe = Path::new(r"C:\Tools\wm.exe");
        let staged = sibling(exe, STAGING_INFIX, "v0.3.3").unwrap();
        assert_eq!(
            staged.file_name().unwrap().to_str().unwrap(),
            "wm.exe.new-v0.3.3"
        );
        assert_eq!(
            with_suffix(&staged, ".sha256")
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            "wm.exe.new-v0.3.3.sha256"
        );
    }
}
