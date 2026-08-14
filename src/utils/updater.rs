use crate::utils::cmd::CommandRunner;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// GitHub API endpoint for the latest published release.
pub const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/SecretLUL/WinMedic/releases/latest";

/// User-Agent header required by the GitHub API.
pub const GITHUB_USER_AGENT: &str = "WinMedic";

/// Minimal SemVer parser supporting standard `major.minor.patch` version strings,
/// optional `v` or `V` prefixes, and pre-release or build metadata suffixes (e.g. `v0.2.0-rc1`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    /// Parse a semantic version string.
    ///
    /// Examples:
    /// - `"v1.2.3"` -> `SemVer { major: 1, minor: 2, patch: 3 }`
    /// - `"V0.2.0-rc1"` -> `SemVer { major: 0, minor: 2, patch: 0 }`
    /// - `"1.0"` -> `SemVer { major: 1, minor: 0, patch: 0 }`
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches(['v', 'V']);
        if s.is_empty() {
            return None;
        }

        // Separate core version from pre-release or build metadata (e.g. "0.2.0-rc1" or "1.0.0+build")
        let core = s.split(['-', '+']).next()?;
        let parts: Vec<&str> = core.split('.').collect();
        if parts.is_empty() {
            return None;
        }

        let major = parts.first()?.parse::<u32>().ok()?;
        let minor = parts.get(1).and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);

        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// Check whether this version is strictly newer than `other`.
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self > other
    }
}

/// Compare a current version against a latest tag to determine if an update is available.
pub fn is_update_available(current_version: &str, latest_tag: &str) -> bool {
    match (SemVer::parse(current_version), SemVer::parse(latest_tag)) {
        (Some(curr), Some(latest)) => latest.is_newer_than(&curr),
        _ => false,
    }
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
}

/// Summary information for an available update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub release_url: String,
    pub release_name: Option<String>,
    pub release_body: Option<String>,
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
    let args = [
        "-s",
        "--max-time",
        &max_time_str,
        "-H",
        "User-Agent: WinMedic",
        "-H",
        "Accept: application/vnd.github.v3+json",
        GITHUB_LATEST_RELEASE_URL,
    ];

    let output = runner.run("curl.exe", &args, timeout_dur).await.ok()?;
    if !output.success {
        return None;
    }

    let release: GitHubRelease = serde_json::from_str(&output.stdout).ok()?;
    if release.draft {
        return None;
    }

    if is_update_available(current_version, &release.tag_name) {
        Some(UpdateInfo {
            current_version: current_version.to_string(),
            latest_version: release.tag_name,
            release_url: release.html_url,
            release_name: release.name,
            release_body: release.body,
        })
    } else {
        None
    }
}

/// Launch the user's default browser targeting the given URL.
///
/// On Windows, executes `cmd /c start "" <url>` with `CREATE_NO_WINDOW` flag.
pub fn launch_browser(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("URL darf nicht leer sein".to_string());
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let mut cmd = Command::new("cmd");
        cmd.args(["/c", "start", "", url]);
        cmd.creation_flags(CREATE_NO_WINDOW);

        cmd.spawn()
            .map_err(|e| format!("Konnte Standardbrowser nicht starten: {}", e))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = url;
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
                patch: 3
            }
        );

        let v_prefix = SemVer::parse("v0.1.0").unwrap();
        assert_eq!(
            v_prefix,
            SemVer {
                major: 0,
                minor: 1,
                patch: 0
            }
        );

        let v_upper = SemVer::parse("V2.10.5").unwrap();
        assert_eq!(
            v_upper,
            SemVer {
                major: 2,
                minor: 10,
                patch: 5
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
                patch: 0
            }
        );

        let v_single = SemVer::parse("2").unwrap();
        assert_eq!(
            v_single,
            SemVer {
                major: 2,
                minor: 0,
                patch: 0
            }
        );

        let v_rc = SemVer::parse("v0.2.0-rc1").unwrap();
        assert_eq!(
            v_rc,
            SemVer {
                major: 0,
                minor: 2,
                patch: 0
            }
        );

        let v_build = SemVer::parse("1.0.0+20260814").unwrap();
        assert_eq!(
            v_build,
            SemVer {
                major: 1,
                minor: 0,
                patch: 0
            }
        );
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

    #[test]
    fn test_launch_browser_empty_url() {
        let res = launch_browser("");
        assert!(res.is_err());
    }
}
