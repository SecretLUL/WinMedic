use crate::utils::cmd::CommandRunner;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::time::Duration;

/// GitHub API endpoint for the latest published release.
pub const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/SecretLUL/WinMedic/releases/latest";

/// User-Agent header required by the GitHub API.
pub const GITHUB_USER_AGENT: &str = "WinMedic";

/// Only release pages on this host are ever handed to the shell — see
/// [`launch_browser`].
pub const GITHUB_RELEASE_URL_PREFIX: &str = "https://github.com/";

/// Release assets are downloaded from this prefix and from nowhere else.
///
/// `/releases/download/` is the only path GitHub serves uploaded release assets
/// from, so pinning it means a tampered API response cannot aim the downloader
/// at an arbitrary attacker-controlled file that merely happens to live on
/// github.com — a gist, a raw blob, another account's repository.
pub const GITHUB_RELEASE_DOWNLOAD_PREFIX: &str =
    "https://github.com/SecretLUL/WinMedic/releases/download/";

/// Refuse to download anything larger than this.
///
/// WinMedic's release binary is a few megabytes. A release advertising an asset
/// far past that is not describing the artifact the release workflow builds, and
/// the download would be landing next to the executable the user runs.
pub const MAX_UPDATE_BYTES: u64 = 64 * 1024 * 1024;

/// Minimal SemVer parser supporting standard `major.minor.patch` version strings,
/// optional `v` or `V` prefixes, and pre-release or build metadata suffixes (e.g. `v0.2.0-rc1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// Pre-release tag without the leading `-` (`rc1` for `v1.0.0-rc1`).
    ///
    /// Build metadata (`+2026814`) is dropped, but the pre-release tag has to be
    /// kept: SemVer precedence puts `1.0.0-rc1` *below* `1.0.0`, so a user
    /// running a release candidate must still be offered the final build.
    pub pre: Option<String>,
}

impl SemVer {
    /// Parse a semantic version string.
    ///
    /// Examples:
    /// - `"v1.2.3"` -> `1.2.3`
    /// - `"V0.2.0-rc1"` -> `0.2.0` with pre-release `rc1`
    /// - `"1.0"` -> `1.0.0`
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches(['v', 'V']);
        if s.is_empty() {
            return None;
        }

        // Build metadata never affects precedence, so it goes first.
        let without_build = s.split('+').next()?;
        // Separate the core version from the pre-release tag ("0.2.0-rc1").
        let (core, pre) = match without_build.split_once('-') {
            Some((core, pre)) if !pre.is_empty() => (core, Some(pre.to_string())),
            _ => (without_build, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        if parts.is_empty() {
            return None;
        }

        let major = parts.first()?.parse::<u32>().ok()?;
        let minor = parts
            .get(1)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0);
        let patch = parts
            .get(2)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0);

        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// Check whether this version is strictly newer than `other`.
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self > other
    }
}

impl Ord for SemVer {
    /// SemVer precedence: compare the core triple, then let a version *without*
    /// a pre-release tag outrank the same core version *with* one.
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compare a current version against a latest tag to determine if an update is available.
pub fn is_update_available(current_version: &str, latest_tag: &str) -> bool {
    match (SemVer::parse(current_version), SemVer::parse(latest_tag)) {
        (Some(curr), Some(latest)) => latest.is_newer_than(&curr),
        _ => false,
    }
}

/// One file attached to a GitHub release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    /// Size GitHub reports for the asset, or `0` when the payload omitted it.
    #[serde(default)]
    pub size: u64,
}

/// JSON payload structure returned by GitHub's `/releases/latest` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub html_url: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

/// The pair of assets an in-place update needs: the binary, and the checksum
/// that vouches for it.
///
/// Both URLs have already passed [`is_safe_download_url`] by the time one of
/// these exists — [`pick_update_download`] is the only constructor — so the
/// downloader inherits the allow-list instead of re-deriving it. The two travel
/// together because neither is any use alone: a binary with no checksum cannot
/// be verified, and a checksum with no binary has nothing to vouch for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateDownload {
    /// File name of the release binary, e.g. `winmedic-v0.3.3.exe`. The
    /// checksum manifest has to name this exact file.
    pub binary_name: String,
    pub binary_url: String,
    pub checksum_url: String,
    /// Size GitHub reports for the binary, or `0` when it is unknown.
    pub size: u64,
}

/// Summary information for an available update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub release_url: String,
    pub release_name: Option<String>,
    pub release_body: Option<String>,
    /// The verifiable download pair for this release, when it publishes one.
    ///
    /// `None` means the release cannot be installed in place — there is no
    /// checksum to hold the download to — so the browser flow is all that is
    /// offered for it.
    pub download: Option<UpdateDownload>,
}

/// Query GitHub for the latest release and determine if a newer version is available.
///
/// Uses `curl.exe` through `CommandRunner` with timeout and required GitHub API headers.
pub async fn check_for_update(
    runner: &dyn CommandRunner,
    current_version: &str,
    timeout_dur: Duration,
) -> Option<UpdateInfo> {
    let max_time_str = timeout_dur.as_secs().max(1).to_string();
    let user_agent_header = format!("User-Agent: {}", GITHUB_USER_AGENT);
    let args = [
        "-s",
        "--max-time",
        &max_time_str,
        "-H",
        &user_agent_header,
        "-H",
        "Accept: application/vnd.github.v3+json",
        GITHUB_LATEST_RELEASE_URL,
    ];

    let output = runner.run("curl.exe", &args, timeout_dur).await.ok()?;
    if !output.success {
        return None;
    }

    let release: GitHubRelease = serde_json::from_str(&output.stdout).ok()?;
    // Never nudge anyone onto an unfinished build. `/releases/latest` already
    // excludes both, but the endpoint is not the only way this struct is filled.
    if release.draft || release.prerelease {
        return None;
    }

    // The URL is about to reach the shell, so anything that is not a plain
    // github.com release page is dropped rather than launched.
    if !is_safe_release_url(&release.html_url) {
        return None;
    }

    if is_update_available(current_version, &release.tag_name) {
        Some(UpdateInfo {
            current_version: current_version.to_string(),
            latest_version: release.tag_name,
            release_url: release.html_url,
            release_name: release.name,
            release_body: release.body,
            download: pick_update_download(&release.assets),
        })
    } else {
        None
    }
}

/// Find the release binary and its `.sha256` manifest among a release's assets.
///
/// Returns `None` unless *both* exist, both are served from
/// [`GITHUB_RELEASE_DOWNLOAD_PREFIX`], and both carry a file name that is safe
/// to write next to the running executable. A missing checksum is not a detail
/// to work around: it is the entire reason the caller may replace a binary that
/// will later run as Administrator, so its absence downgrades the release to the
/// browser flow rather than relaxing the requirement.
pub fn pick_update_download(assets: &[ReleaseAsset]) -> Option<UpdateDownload> {
    let binary = assets.iter().find(|a| is_release_binary_name(&a.name))?;
    let checksum_name = format!("{}.sha256", binary.name);
    let checksum = assets.iter().find(|a| a.name == checksum_name)?;

    if !is_safe_download_url(&binary.browser_download_url)
        || !is_safe_download_url(&checksum.browser_download_url)
    {
        return None;
    }
    if binary.size > MAX_UPDATE_BYTES {
        return None;
    }

    Some(UpdateDownload {
        binary_name: binary.name.clone(),
        binary_url: binary.browser_download_url.clone(),
        checksum_url: checksum.browser_download_url.clone(),
        size: binary.size,
    })
}

/// Whether an asset name is the release's Windows binary.
///
/// The release workflow uploads exactly one `.exe` (`winmedic-<tag>.exe`); the
/// only other asset is its `.sha256`, which the `.exe` suffix rejects.
fn is_release_binary_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_safe_asset_name(name) && lower.starts_with("winmedic") && lower.ends_with(".exe")
}

/// Whether `name` is safe to use as a file name next to the running binary.
///
/// The name arrives from the network and is then joined onto a directory path,
/// so a separator, a drive letter or a `..` in it would let the release response
/// choose *where* the download lands. Only a flat name built from unremarkable
/// characters is accepted — including no leading `.`, which is what the staging
/// files this crate writes itself are never confused with.
pub fn is_safe_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains("..")
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Whether `url` is a release *asset* download that may be fetched to disk.
///
/// Stricter than [`is_safe_release_url`] and built on top of it, so the
/// shell-metacharacter, scheme and length rules cover the download URL too — the
/// release page is not the only URL in this flow that arrives off the wire.
pub fn is_safe_download_url(url: &str) -> bool {
    is_safe_release_url(url) && url.starts_with(GITHUB_RELEASE_DOWNLOAD_PREFIX)
}

/// Whether `s` is a 64-character SHA256 digest in hex.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Read the expected SHA256 out of a `sha256sum`-style manifest.
///
/// The release workflow writes a single `"<hash>  <filename>"` line. A manifest
/// naming a *different* file is rejected rather than used: it would mean the
/// digest being compared against belongs to some other artifact, which is
/// exactly the confusion someone able to shuffle release assets would want.
pub fn parse_sha256_manifest(content: &str, expected_name: &str) -> Result<String, String> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else {
            continue;
        };
        if !is_sha256_hex(hash) {
            return Err("the checksum file does not start with a SHA256 digest".to_string());
        }

        // `sha256sum` marks binary mode with a `*` in front of the name.
        if let Some(name) = fields.next() {
            let name = name.trim_start_matches('*');
            if !name.eq_ignore_ascii_case(expected_name) {
                return Err(format!(
                    "the checksum file covers '{}', not '{}'",
                    name, expected_name
                ));
            }
        }

        return Ok(hash.to_ascii_lowercase());
    }

    Err("the checksum file contained no digest".to_string())
}

/// Whether `url` is a plain GitHub release page that is safe to hand to the OS.
///
/// The URL arrives from a network response, so it is treated as untrusted input:
/// only `https://github.com/` targets are accepted, and any whitespace, control
/// character or shell metacharacter disqualifies it outright.
pub fn is_safe_release_url(url: &str) -> bool {
    if !url.starts_with(GITHUB_RELEASE_URL_PREFIX) || url.len() > 2048 {
        return false;
    }
    !url.chars().any(|c| {
        c.is_whitespace() || c.is_control() || matches!(c, '&' | '|' | '^' | '<' | '>' | '"' | '%')
    })
}

/// Check whether [`launch_browser`] would accept `url`, without launching it.
///
/// Exists so the acceptance rules can be tested directly. Asserting them through
/// `launch_browser` means every run of the suite really does open the release
/// page in the developer's browser — once per test, across parallel test
/// binaries — which is exactly as disruptive as it sounds.
pub fn validate_release_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("The URL must not be empty".to_string());
    }
    if !is_safe_release_url(url) {
        return Err(format!(
            "URL rejected (only {}... is allowed): {}",
            GITHUB_RELEASE_URL_PREFIX, url
        ));
    }
    Ok(())
}

/// Launch the user's default browser targeting the given URL.
///
/// The URL is validated by [`validate_release_url`] first and then handed to
/// `explorer.exe`, which resolves the default handler *without* going through a
/// command interpreter. The previous `cmd /c start "" <url>` form was unsafe:
/// Rust only quotes arguments containing whitespace, so a `&` in the URL would
/// have been parsed by cmd.exe as a command separator.
///
/// Tests must assert against [`validate_release_url`] instead: this function
/// opens a real browser window on the machine running it.
pub fn launch_browser(url: &str) -> Result<(), String> {
    validate_release_url(url)?;

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let mut cmd = Command::new("explorer.exe");
        cmd.arg(url);
        cmd.creation_flags(CREATE_NO_WINDOW);

        cmd.spawn()
            .map_err(|e| format!("Could not launch the default browser: {}", e))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    #[test]
    fn test_semver_parsing_standard() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(
            v,
            SemVer {
                major: 1,
                minor: 2,
                patch: 3,
                pre: None
            }
        );

        let v_prefix = SemVer::parse("v0.1.0").unwrap();
        assert_eq!(
            v_prefix,
            SemVer {
                major: 0,
                minor: 1,
                patch: 0,
                pre: None
            }
        );

        let v_upper = SemVer::parse("V2.10.5").unwrap();
        assert_eq!(
            v_upper,
            SemVer {
                major: 2,
                minor: 10,
                patch: 5,
                pre: None
            }
        );
    }

    #[test]
    fn test_semver_parsing_short_and_prerelease() {
        let v_short = SemVer::parse("1.0").unwrap();
        assert_eq!(
            v_short,
            SemVer {
                major: 1,
                minor: 0,
                patch: 0,
                pre: None
            }
        );

        let v_single = SemVer::parse("2").unwrap();
        assert_eq!(
            v_single,
            SemVer {
                major: 2,
                minor: 0,
                patch: 0,
                pre: None
            }
        );

        let v_rc = SemVer::parse("v0.2.0-rc1").unwrap();
        assert_eq!(
            v_rc,
            SemVer {
                major: 0,
                minor: 2,
                patch: 0,
                pre: Some("rc1".to_string())
            }
        );

        // Build metadata is dropped entirely; it never affects precedence.
        let v_build = SemVer::parse("1.0.0+20260814").unwrap();
        assert_eq!(
            v_build,
            SemVer {
                major: 1,
                minor: 0,
                patch: 0,
                pre: None
            }
        );
    }

    #[test]
    fn test_semver_prerelease_sorts_below_final() {
        let rc = SemVer::parse("1.0.0-rc1").unwrap();
        let final_release = SemVer::parse("1.0.0").unwrap();

        assert!(final_release.is_newer_than(&rc));
        assert!(!rc.is_newer_than(&final_release));
        // A user on a release candidate must still be offered the final build.
        assert!(is_update_available("1.0.0-rc1", "v1.0.0"));
        assert!(!is_update_available("1.0.0", "v1.0.0-rc1"));
    }

    #[test]
    fn test_semver_parsing_invalid() {
        assert_eq!(SemVer::parse(""), None);
        assert_eq!(SemVer::parse("invalid"), None);
        assert_eq!(SemVer::parse("v"), None);
        assert_eq!(SemVer::parse("v.1.2"), None);
        assert_eq!(SemVer::parse("a.b.c"), None);
    }

    #[test]
    fn test_semver_comparison() {
        let v1 = SemVer::parse("0.1.0").unwrap();
        let v2 = SemVer::parse("0.2.0").unwrap();
        let v3 = SemVer::parse("1.0.0").unwrap();
        let v4 = SemVer::parse("0.1.1").unwrap();

        assert!(v2.is_newer_than(&v1));
        assert!(v3.is_newer_than(&v2));
        assert!(v4.is_newer_than(&v1));
        assert!(!v1.is_newer_than(&v2));
        assert!(!v1.is_newer_than(&v1));
    }

    #[test]
    fn test_is_update_available() {
        assert!(is_update_available("0.1.0", "v0.2.0"));
        assert!(is_update_available("v0.1.0", "0.1.1"));
        assert!(is_update_available("0.1.0", "v1.0.0-rc1"));
        assert!(!is_update_available("0.2.0", "v0.2.0"));
        assert!(!is_update_available("1.0.0", "v0.9.9"));
        assert!(!is_update_available("invalid", "v1.0.0"));
        assert!(!is_update_available("1.0.0", "invalid"));
    }

    #[tokio::test]
    async fn test_check_for_update_success_newer() {
        let mock = MockCommandRunner::new();
        let payload = r#"{
            "tag_name": "v0.2.0",
            "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0",
            "name": "WinMedic v0.2.0",
            "body": "New System Cleaner and Auto-Updater",
            "draft": false,
            "prerelease": false
        }"#;
        mock.add_response("curl.exe", CmdOutput::ok(payload));

        let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5))
            .await
            .expect("expected UpdateInfo");

        assert_eq!(info.current_version, "0.1.0");
        assert_eq!(info.latest_version, "v0.2.0");
        assert_eq!(
            info.release_url,
            "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
        );
        assert_eq!(info.release_name, Some("WinMedic v0.2.0".to_string()));
        assert_eq!(
            info.release_body,
            Some("New System Cleaner and Auto-Updater".to_string())
        );

        let executed = mock.executed();
        assert_eq!(executed.len(), 1);
        assert!(executed[0].contains("User-Agent: WinMedic"));
        assert!(executed[0].contains("Accept: application/vnd.github.v3+json"));
        assert!(executed[0].contains(GITHUB_LATEST_RELEASE_URL));
    }

    #[tokio::test]
    async fn test_check_for_update_already_up_to_date() {
        let mock = MockCommandRunner::new();
        let payload = r#"{
            "tag_name": "v0.1.0",
            "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.1.0",
            "name": "WinMedic v0.1.0",
            "body": "Initial Release",
            "draft": false,
            "prerelease": false
        }"#;
        mock.add_response("curl.exe", CmdOutput::ok(payload));

        let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
        assert_eq!(info, None);
    }

    #[tokio::test]
    async fn test_check_for_update_command_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "curl.exe",
            CmdOutput::failed(6, "curl: (6) Could not resolve host"),
        );

        let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
        assert_eq!(info, None);
    }

    #[tokio::test]
    async fn test_check_for_update_invalid_json() {
        let mock = MockCommandRunner::new();
        mock.add_response("curl.exe", CmdOutput::ok("<html>404 Not Found</html>"));

        let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
        assert_eq!(info, None);
    }

    #[tokio::test]
    async fn test_check_for_update_draft_release_ignored() {
        let mock = MockCommandRunner::new();
        let payload = r#"{
            "tag_name": "v0.9.0",
            "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.9.0",
            "name": "Draft Release",
            "body": "Draft",
            "draft": true,
            "prerelease": false
        }"#;
        mock.add_response("curl.exe", CmdOutput::ok(payload));

        let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
        assert_eq!(info, None);
    }

    #[tokio::test]
    async fn test_check_for_update_prerelease_ignored() {
        let mock = MockCommandRunner::new();
        let payload = r#"{
            "tag_name": "v0.9.0",
            "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.9.0",
            "name": "Release Candidate",
            "body": "RC",
            "draft": false,
            "prerelease": true
        }"#;
        mock.add_response("curl.exe", CmdOutput::ok(payload));

        let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
        assert_eq!(
            info, None,
            "prereleases must not be offered to stable users"
        );
    }

    #[tokio::test]
    async fn test_check_for_update_rejects_offsite_release_url() {
        let mock = MockCommandRunner::new();
        let payload = r#"{
            "tag_name": "v0.2.0",
            "html_url": "https://evil.example/pwn?a=1&calc",
            "name": "Tampered",
            "body": "Tampered",
            "draft": false,
            "prerelease": false
        }"#;
        mock.add_response("curl.exe", CmdOutput::ok(payload));

        let info = check_for_update(&mock, "0.1.0", Duration::from_secs(5)).await;
        assert_eq!(info, None);
    }

    #[test]
    fn test_is_safe_release_url() {
        assert!(is_safe_release_url(
            "https://github.com/SecretLUL/WinMedic/releases/tag/v0.2.0"
        ));

        // Wrong host / scheme.
        assert!(!is_safe_release_url("https://evil.example/releases"));
        assert!(!is_safe_release_url("http://github.com/a/b"));
        assert!(!is_safe_release_url("file://github.com/a/b"));
        assert!(!is_safe_release_url(r"\\server\share"));

        // cmd.exe metacharacters must never reach a shell.
        assert!(!is_safe_release_url("https://github.com/a?x=1&calc"));
        assert!(!is_safe_release_url("https://github.com/a|calc"));
        assert!(!is_safe_release_url("https://github.com/a^calc"));
        assert!(!is_safe_release_url("https://github.com/a>out.txt"));
        assert!(!is_safe_release_url("https://github.com/a b"));
    }

    #[test]
    fn test_launch_browser_empty_url() {
        let res = validate_release_url("");
        assert!(res.is_err());
    }

    #[test]
    fn test_launch_browser_rejects_unsafe_url() {
        assert!(validate_release_url("https://github.com/a&calc").is_err());
        assert!(validate_release_url("https://evil.example/x").is_err());
    }

    // ------------------------------------------------------ release assets

    const DOWNLOAD_BASE: &str = "https://github.com/SecretLUL/WinMedic/releases/download/v0.3.3";

    fn asset(name: &str, size: u64) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_string(),
            browser_download_url: format!("{}/{}", DOWNLOAD_BASE, name),
            size,
        }
    }

    #[test]
    fn the_binary_and_its_checksum_are_picked_out_of_a_release() {
        let assets = vec![
            asset("winmedic-v0.3.3.exe.sha256", 84),
            asset("winmedic-v0.3.3.exe", 4_200_000),
        ];

        let picked = pick_update_download(&assets).expect("expected a download pair");
        assert_eq!(picked.binary_name, "winmedic-v0.3.3.exe");
        assert_eq!(
            picked.binary_url,
            format!("{}/winmedic-v0.3.3.exe", DOWNLOAD_BASE)
        );
        assert_eq!(
            picked.checksum_url,
            format!("{}/winmedic-v0.3.3.exe.sha256", DOWNLOAD_BASE)
        );
        assert_eq!(picked.size, 4_200_000);
    }

    /// The checksum is the entire basis for replacing an executable that later
    /// runs as Administrator, so a release without one is not installable.
    #[test]
    fn a_release_without_a_checksum_offers_no_download() {
        let assets = vec![asset("winmedic-v0.3.3.exe", 4_200_000)];
        assert_eq!(pick_update_download(&assets), None);

        // A checksum for some *other* file is not this binary's checksum.
        let mismatched = vec![
            asset("winmedic-v0.3.3.exe", 4_200_000),
            asset("winmedic-v0.3.2.exe.sha256", 84),
        ];
        assert_eq!(pick_update_download(&mismatched), None);
    }

    #[test]
    fn a_release_with_no_windows_binary_offers_no_download() {
        let assets = vec![
            asset("winmedic-v0.3.3-source.zip", 900),
            asset("README.md", 100),
        ];
        assert_eq!(pick_update_download(&assets), None);
    }

    /// The download URL is attacker-controlled input in exactly the same way
    /// the release page URL is, and gets the same allow-list.
    #[test]
    fn a_download_url_outside_the_release_download_path_is_refused() {
        for hostile in [
            "https://evil.example/releases/download/v1/winmedic-v0.3.3.exe",
            // Right host, wrong path: a repository blob is not a release asset.
            "https://github.com/SecretLUL/WinMedic/raw/main/winmedic-v0.3.3.exe",
            // Another account's releases are still not this project's.
            "https://github.com/attacker/WinMedic/releases/download/v1/winmedic-v0.3.3.exe",
            // Downgraded scheme.
            "http://github.com/SecretLUL/WinMedic/releases/download/v1/winmedic-v0.3.3.exe",
        ] {
            let assets = vec![
                ReleaseAsset {
                    name: "winmedic-v0.3.3.exe".to_string(),
                    browser_download_url: hostile.to_string(),
                    size: 100,
                },
                asset("winmedic-v0.3.3.exe.sha256", 84),
            ];
            assert_eq!(
                pick_update_download(&assets),
                None,
                "accepted a binary from {}",
                hostile
            );
        }

        // A safe binary paired with an off-site checksum is no better: the
        // digest would then come from wherever the response pointed.
        let assets = vec![
            asset("winmedic-v0.3.3.exe", 100),
            ReleaseAsset {
                name: "winmedic-v0.3.3.exe.sha256".to_string(),
                browser_download_url: "https://evil.example/x.sha256".to_string(),
                size: 84,
            },
        ];
        assert_eq!(pick_update_download(&assets), None);
    }

    #[test]
    fn an_absurdly_large_asset_is_refused() {
        let assets = vec![
            asset("winmedic-v0.3.3.exe", MAX_UPDATE_BYTES + 1),
            asset("winmedic-v0.3.3.exe.sha256", 84),
        ];
        assert_eq!(pick_update_download(&assets), None);
    }

    /// The asset name becomes a file name beside the running executable, so a
    /// separator or a `..` in it would choose where the download lands.
    #[test]
    fn an_asset_name_that_could_escape_a_directory_is_refused() {
        for hostile in [
            "..\\..\\Windows\\System32\\winmedic.exe",
            "../../winmedic.exe",
            "winmedic/../../evil.exe",
            "C:\\Windows\\winmedic.exe",
            "winmedic .exe",
            ".winmedic.exe",
        ] {
            assert!(
                !is_safe_asset_name(hostile),
                "'{}' was accepted as a file name",
                hostile
            );
        }

        assert!(is_safe_asset_name("winmedic-v0.3.3.exe"));
        assert!(is_safe_asset_name("winmedic-v0.3.3.exe.sha256"));
        assert!(is_safe_asset_name("winmedic_v1-0-0.exe"));
        assert!(!is_safe_asset_name(""));
        assert!(!is_safe_asset_name(&"a".repeat(129)));
    }

    #[test]
    fn is_safe_download_url_inherits_the_release_url_rules() {
        assert!(is_safe_download_url(&format!(
            "{}/winmedic-v0.3.3.exe",
            DOWNLOAD_BASE
        )));
        // Shell metacharacters are rejected here just as they are on the page
        // URL — the download URL reaches a process too.
        assert!(!is_safe_download_url(&format!(
            "{}/winmedic.exe&calc",
            DOWNLOAD_BASE
        )));
        assert!(!is_safe_download_url(&format!(
            "{}/winmedic .exe",
            DOWNLOAD_BASE
        )));
        assert!(!is_safe_download_url(
            "https://github.com/SecretLUL/WinMedic/releases/tag/v0.3.3"
        ));
    }

    // ------------------------------------------------------ checksum files

    #[test]
    fn the_workflows_own_checksum_layout_parses() {
        // Exactly what .github/workflows/release.yml writes.
        let hash = "3b1f2a".to_string() + &"0".repeat(58);
        let manifest = format!("{}  winmedic-v0.3.3.exe\n", hash);

        assert_eq!(
            parse_sha256_manifest(&manifest, "winmedic-v0.3.3.exe").unwrap(),
            hash
        );
    }

    #[test]
    fn checksum_variants_and_junk_are_told_apart() {
        let hash = "a".repeat(64);

        // sha256sum binary mode, single space, and a bare digest.
        assert!(parse_sha256_manifest(&format!("{} *winmedic.exe", hash), "winmedic.exe").is_ok());
        assert!(parse_sha256_manifest(&format!("{} winmedic.exe", hash), "winmedic.exe").is_ok());
        assert!(parse_sha256_manifest(&hash, "winmedic.exe").is_ok());
        // Case in the digest does not matter; case in the name does not either.
        assert_eq!(
            parse_sha256_manifest(
                &format!("{}  WinMedic.exe", hash.to_uppercase()),
                "winmedic.exe"
            )
            .unwrap(),
            hash
        );

        // A digest that is not one, a truncated one, and an empty file.
        assert!(parse_sha256_manifest("not-a-hash  winmedic.exe", "winmedic.exe").is_err());
        assert!(
            parse_sha256_manifest(&format!("{}  winmedic.exe", "a".repeat(63)), "winmedic.exe")
                .is_err()
        );
        assert!(parse_sha256_manifest("", "winmedic.exe").is_err());
        assert!(parse_sha256_manifest("   \n\n", "winmedic.exe").is_err());
        // A manifest for a different artifact must not vouch for this one.
        assert!(parse_sha256_manifest(&format!("{}  other.exe", hash), "winmedic.exe").is_err());
    }

    #[test]
    fn is_sha256_hex_accepts_only_a_full_digest() {
        assert!(is_sha256_hex(&"0".repeat(64)));
        assert!(is_sha256_hex(&"F".repeat(64)));
        assert!(!is_sha256_hex(&"0".repeat(63)));
        assert!(!is_sha256_hex(&"0".repeat(65)));
        assert!(!is_sha256_hex(&"g".repeat(64)));
        assert!(!is_sha256_hex(""));
    }

    // --------------------------------------------- assets through the check

    #[tokio::test]
    async fn a_release_with_assets_carries_its_download_through_the_check() {
        let mock = MockCommandRunner::new();
        let payload = format!(
            r#"{{
                "tag_name": "v0.3.3",
                "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.3.3",
                "draft": false,
                "prerelease": false,
                "assets": [
                    {{"name": "winmedic-v0.3.3.exe", "browser_download_url": "{base}/winmedic-v0.3.3.exe", "size": 4200000}},
                    {{"name": "winmedic-v0.3.3.exe.sha256", "browser_download_url": "{base}/winmedic-v0.3.3.exe.sha256", "size": 84}}
                ]
            }}"#,
            base = DOWNLOAD_BASE
        );
        mock.add_response("curl.exe", CmdOutput::ok(payload));

        let info = check_for_update(&mock, "0.3.2", Duration::from_secs(5))
            .await
            .expect("expected UpdateInfo");

        let download = info.download.expect("expected a verifiable download");
        assert_eq!(download.binary_name, "winmedic-v0.3.3.exe");
        assert!(download.checksum_url.ends_with(".sha256"));
    }

    /// An older release, or one uploaded by hand without a checksum, is still
    /// worth telling the user about — it just cannot be installed in place.
    #[tokio::test]
    async fn a_release_without_assets_is_still_offered_via_the_browser() {
        let mock = MockCommandRunner::new();
        let payload = r#"{
            "tag_name": "v0.3.3",
            "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.3.3",
            "draft": false,
            "prerelease": false
        }"#;
        mock.add_response("curl.exe", CmdOutput::ok(payload));

        let info = check_for_update(&mock, "0.3.2", Duration::from_secs(5))
            .await
            .expect("expected UpdateInfo");

        assert_eq!(info.download, None);
        assert_eq!(
            info.release_url,
            "https://github.com/SecretLUL/WinMedic/releases/tag/v0.3.3"
        );
    }

    /// A tampered response that keeps a legitimate release page but points the
    /// download somewhere else must not produce an installable update.
    #[tokio::test]
    async fn a_tampered_asset_url_downgrades_the_update_to_the_browser_flow() {
        let mock = MockCommandRunner::new();
        let payload = r#"{
            "tag_name": "v0.3.3",
            "html_url": "https://github.com/SecretLUL/WinMedic/releases/tag/v0.3.3",
            "draft": false,
            "prerelease": false,
            "assets": [
                {"name": "winmedic-v0.3.3.exe", "browser_download_url": "https://evil.example/winmedic.exe", "size": 4200000},
                {"name": "winmedic-v0.3.3.exe.sha256", "browser_download_url": "https://evil.example/winmedic.exe.sha256", "size": 84}
            ]
        }"#;
        mock.add_response("curl.exe", CmdOutput::ok(payload));

        let info = check_for_update(&mock, "0.3.2", Duration::from_secs(5))
            .await
            .expect("expected UpdateInfo");

        assert_eq!(
            info.download, None,
            "an off-site asset URL must never become an installable download"
        );
    }

    /// No test may call [`launch_browser`]: it hands the URL to the OS, so an
    /// assertion on its return value opens a real browser window on whoever runs
    /// the suite — every run, once per call, across parallel test binaries.
    /// [`validate_release_url`] carries the entire acceptance rule, so there is
    /// never a reason to reach for the launching one in a test.
    #[test]
    fn no_test_in_the_tree_launches_a_browser() {
        let offenders =
            crate::utils::test_guard::integration_test_lines_mentioning("launch_browser(");

        assert!(
            offenders.is_empty(),
            "these tests would open a browser window; assert on validate_release_url instead: {:?}",
            offenders
        );
    }
}
