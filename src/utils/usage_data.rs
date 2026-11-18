//! Anonymous usage data: what WinMedic sends after a scan or a repair when
//! the user said yes, and never otherwise.
//!
//! It is counts: which checks found something, which repairs failed. No
//! device, file or folder name is in it, no user or computer name, no text
//! of a finding, and no number that stays the same from one start to the
//! next.
//!
//! One function builds what goes out ([`Report::json`]). The sender and the
//! window's "Show what is sent" both read it, so what is shown is what is
//! sent.

use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use crate::utils::updater::CURL_NO_CONFIG;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::hash::{BuildHasher, RandomState};
use std::path::Path;
use std::time::Duration;

/// Where the reports go, and what the window says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receiver {
    /// Where the reports go and who sees the sender's IP address on the way,
    /// in the words the window shows under "Where it goes". It is a promise
    /// about servers WinMedic does not control from here: whoever changes
    /// the receiver, its proxy or its logs changes this text with it.
    pub where_it_goes: &'static str,
    /// The address the reports are posted to.
    pub url: &'static str,
    /// The key that names WinMedic to the receiver. It is in every copy of
    /// the program and so is not a secret.
    pub app_key: &'static str,
}

/// The receiver this build sends to: an Aptabase the maintainer hosts
/// himself, so that no analytics company sits in between.
///
/// With `None` nothing asks for usage data, Settings offers no switch for it
/// and nothing is sent, whatever config.json says.
///
/// The address is in every released copy, which goes on posting to it: it
/// must keep answering there. What `where_it_goes` promises is kept by the
/// server's own setup: its entry proxy hands the statistics no address and
/// writes no log, and the reverse proxy in front has both of its logs
/// switched off for this address.
pub const RECEIVER: Option<Receiver> = Some(Receiver {
    where_it_goes: "To the developer's own server in Germany, by way of Cloudflare. Like every \
                    server, both see your IP address. The developer's server does not write \
                    it down and does not pass it on to the statistics.",
    url: "https://winmedic-usage.ammarnashar.dev/api/v0/events",
    app_key: "A-SH-4549551502",
});

/// One report: its name and its numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    event: &'static str,
    props: Map<String, Value>,
}

/// Easy or Advanced mode, as a report names it.
fn mode(advanced: bool) -> &'static str {
    if advanced { "advanced" } else { "easy" }
}

impl Report {
    /// A scan that ran to its end.
    ///
    /// `found` is the check (the module's id, such as `network`) of every
    /// finding, `failed_checks` the checks that could not run. A check's id
    /// is a word from WinMedic's own source and names nothing on the PC.
    pub fn scan(
        advanced: bool,
        seconds: u64,
        health: u8,
        found: &[&str],
        failed_checks: &[&str],
    ) -> Self {
        let mut props = Map::new();
        props.insert("mode".into(), mode(advanced).into());
        props.insert("seconds".into(), seconds.into());
        props.insert("health".into(), health.into());
        props.insert("findings".into(), found.len().into());
        let mut by_check: BTreeMap<&str, u64> = BTreeMap::new();
        for check in found {
            *by_check.entry(check).or_default() += 1;
        }
        for (check, count) in by_check {
            props.insert(format!("found_{check}"), count.into());
        }
        for check in failed_checks {
            props.insert(format!("check_failed_{check}"), 1.into());
        }
        Self {
            event: "scan",
            props,
        }
    }

    /// A repair run that ended, with what it repaired and what failed for
    /// each check: `(repaired, failed)`.
    pub fn repair(advanced: bool, by_check: &BTreeMap<String, (u64, u64)>) -> Self {
        let mut props = Map::new();
        props.insert("mode".into(), mode(advanced).into());
        let total = |pick: fn(&(u64, u64)) -> u64| by_check.values().map(pick).sum::<u64>();
        props.insert("repaired".into(), total(|counts| counts.0).into());
        props.insert("failed".into(), total(|counts| counts.1).into());
        for (check, (repaired, failed)) in by_check {
            if *repaired > 0 {
                props.insert(format!("repaired_{check}"), (*repaired).into());
            }
            if *failed > 0 {
                props.insert(format!("repair_failed_{check}"), (*failed).into());
            }
        }
        Self {
            event: "repair",
            props,
        }
    }

    /// The report as it is sent: all of it, and the only place that puts one
    /// together.
    ///
    /// `session` is [`new_session`]'s number and `windows` what
    /// [`crate::utils::crash_log::windows_build`] says, of which only the
    /// build number is kept: the edition is not sent.
    pub fn json(&self, session: &str, at: DateTime<Utc>, windows: &str) -> Value {
        let version = env!("CARGO_PKG_VERSION");
        json!([{
            "timestamp": at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "sessionId": session,
            "eventName": self.event,
            "systemProps": {
                "osName": "Windows",
                "osVersion": build_number(windows),
                "isDebug": cfg!(debug_assertions),
                "appVersion": version,
                "sdkVersion": format!("winmedic@{version}"),
            },
            "props": self.props,
        }])
    }

    /// [`Self::json`] laid out for reading.
    pub fn shown(&self, session: &str, at: DateTime<Utc>, windows: &str) -> String {
        serde_json::to_string_pretty(&self.json(session, at, windows)).unwrap_or_default()
    }
}

/// `26200.9550` out of "Windows 11 Pro 25H2, build 26200.9550".
fn build_number(windows: &str) -> &str {
    windows
        .rsplit_once("build ")
        .map_or("unknown", |(_, number)| number)
}

/// The number that ties the reports of one start of WinMedic together, in
/// the form the receiver asks for: the second it was made and eight random
/// digits. The next start makes another, and none is kept anywhere.
pub fn new_session(now: DateTime<Utc>) -> String {
    let random = RandomState::new().hash_one(now.timestamp_nanos_opt()) % 100_000_000;
    format!("{}{random:08}", now.timestamp())
}

/// Post `body` to `receiver`. `Ok` only when the server took it: a 2xx
/// answer that names no error. Aptabase answers 200 to a report it drops,
/// for a missing or unknown key say, and gives the reason in the body.
pub async fn send(
    runner: &dyn CommandRunner,
    receiver: &Receiver,
    body: &str,
    timeout: Duration,
) -> Result<(), String> {
    // Only ever https: the address is WinMedic's own, but a redirect is not.
    if !receiver.url.starts_with("https://") {
        return Err("the receiver's address is not https".to_string());
    }
    let seconds = timeout.as_secs().to_string();
    let key = format!("App-Key: {}", receiver.app_key);
    let args = [
        CURL_NO_CONFIG,
        "-s",
        "--proto",
        "=https",
        "--max-time",
        &seconds,
        // Not curl's own name and version, which nobody was told about.
        "-A",
        "WinMedic",
        "-H",
        "Content-Type: application/json",
        "-H",
        &key,
        "--data-raw",
        body,
        // The answer, then the status on a line of its own.
        "-w",
        "\n%{http_code}",
        receiver.url,
    ];
    let output = runner
        .run("curl.exe", &args, timeout + Duration::from_secs(2))
        .await?;
    let (answer, status) = output
        .stdout
        .trim_end()
        .rsplit_once('\n')
        .unwrap_or(("", output.stdout.trim()));
    match status.trim() {
        status if status.len() == 3 && status.starts_with('2') => {
            match serde_json::from_str::<Value>(answer) {
                Ok(json) if json.get("error").is_some() => Err(format!(
                    "the server dropped it: {}",
                    json["error"].as_str().unwrap_or("no reason given")
                )),
                _ => Ok(()),
            }
        }
        "" | "000" => Err("no answer from the server".to_string()),
        status => Err(format!("the server answered {status}")),
    }
}

/// The file in the log folder that keeps every report as it went out.
pub const SENT_LOG: &str = "usage-data.log";

/// Past this size the file starts over, so it cannot grow without end.
const SENT_LOG_MAX_BYTES: u64 = 512 * 1024;

/// Write down, in `dir`, what was sent and whether it arrived.
pub fn record(dir: &Path, at: DateTime<Utc>, body: &str, outcome: &Result<(), String>) {
    use std::io::Write;

    let path = dir.join(SENT_LOG);
    let full = std::fs::metadata(&path).is_ok_and(|file| file.len() > SENT_LOG_MAX_BYTES);
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(!full)
        .write(true)
        .truncate(full)
        .open(&path)
    else {
        return;
    };
    let outcome = match outcome {
        Ok(()) => "sent".to_string(),
        Err(why) => format!("not sent ({why})"),
    };
    let _ = writeln!(
        file,
        "{} {outcome}: {body}",
        at.to_rfc3339_opts(SecondsFormat::Secs, true)
    );
}

/// Send `body` without holding up the window, and write it into the log
/// folder. What [`crate::app::SystemActions::real`] sends reports with.
///
/// A report that does not arrive is not tried again: nothing depends on it.
pub fn send_in_background(receiver: Receiver, body: String) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let outcome = send(
            &SystemCommandRunner::new(),
            &receiver,
            &body,
            Duration::from_secs(10),
        )
        .await;
        if let Some(dir) = crate::safety::audit::AuditLogger::real().log_dir() {
            record(dir, Utc::now(), &body, &outcome);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use chrono::TimeZone;

    const RECEIVER: Receiver = Receiver {
        where_it_goes: "To an example server in Germany, which does not store your IP address.",
        url: "https://usage.example.test/api/v0/events",
        app_key: "A-EU-0000000000",
    };

    fn noon() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap()
    }

    fn scan() -> Report {
        Report::scan(
            false,
            74,
            60,
            &["network", "network", "system_cleaner"],
            &["system_integrity"],
        )
    }

    /// What the window promises under "Where it goes" names everyone who
    /// sees the sender's address, and the reports go out encrypted.
    #[test]
    fn the_receiver_of_this_build_says_who_sees_the_ip_address() {
        let receiver = super::RECEIVER.expect("this build has a receiver");
        assert!(receiver.url.starts_with("https://"), "{}", receiver.url);
        assert!(receiver.url.ends_with("/api/v0/events"), "{}", receiver.url);
        assert!(receiver.app_key.starts_with("A-"), "{}", receiver.app_key);
        for named in [
            "IP address",
            "Cloudflare",
            "own server",
            "does not write it down",
        ] {
            assert!(
                receiver.where_it_goes.contains(named),
                "{named} is missing: {}",
                receiver.where_it_goes
            );
        }
    }

    /// The whole report, so that a field added to it shows up here: what a
    /// user agreed to is this and nothing more.
    #[test]
    fn a_scan_report_is_exactly_these_fields() {
        let sent = scan().json(
            "173184480012345678",
            noon(),
            "Windows 11 Pro 25H2, build 26200.9550",
        );
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            sent,
            json!([{
                "timestamp": "2026-11-17T12:00:00Z",
                "sessionId": "173184480012345678",
                "eventName": "scan",
                "systemProps": {
                    "osName": "Windows",
                    "osVersion": "26200.9550",
                    "isDebug": cfg!(debug_assertions),
                    "appVersion": version,
                    "sdkVersion": format!("winmedic@{version}"),
                },
                "props": {
                    "mode": "easy",
                    "seconds": 74,
                    "health": 60,
                    "findings": 3,
                    "found_network": 2,
                    "found_system_cleaner": 1,
                    "check_failed_system_integrity": 1,
                },
            }])
        );
    }

    #[test]
    fn a_repair_report_counts_per_check_and_leaves_zeros_out() {
        let mut by_check = BTreeMap::new();
        by_check.insert("network".to_string(), (2, 0));
        by_check.insert("system_integrity".to_string(), (0, 1));
        let sent = Report::repair(true, &by_check).json("1", noon(), "unknown");
        assert_eq!(
            sent[0]["props"],
            json!({
                "mode": "advanced",
                "repaired": 2,
                "failed": 1,
                "repaired_network": 2,
                "repair_failed_system_integrity": 1,
            })
        );
        assert_eq!(sent[0]["eventName"], "repair");
        assert_eq!(sent[0]["systemProps"]["osVersion"], "unknown");
    }

    /// The edition and the release ("Pro 25H2") stay on the PC.
    #[test]
    fn only_the_build_number_of_windows_is_sent() {
        assert_eq!(
            build_number("Windows 11 Pro 25H2, build 26200.9550"),
            "26200.9550"
        );
        assert_eq!(build_number("unknown"), "unknown");
        let text = scan().shown("1", noon(), "Windows 11 Pro 25H2, build 26200.9550");
        assert!(
            !text.contains("25H2") && !text.contains("Windows 11"),
            "{text}"
        );
    }

    #[test]
    fn what_is_shown_is_what_is_sent() {
        let report = scan();
        let shown = report.shown("1", noon(), "build 1");
        let sent = report.json("1", noon(), "build 1");
        assert_eq!(serde_json::from_str::<Value>(&shown).unwrap(), sent);
    }

    #[test]
    fn a_session_number_is_the_second_and_eight_digits_and_new_each_time() {
        let first = new_session(noon());
        assert!(first.starts_with(&noon().timestamp().to_string()));
        assert_eq!(first.len(), noon().timestamp().to_string().len() + 8);
        assert!(first.chars().all(|c| c.is_ascii_digit()));
        // Eight random digits: three in a row alike would be one in 10^16.
        assert!(new_session(noon()) != first || new_session(noon()) != first);
    }

    #[tokio::test]
    async fn a_report_is_posted_with_curl_over_https_only() {
        let mock = MockCommandRunner::new();
        mock.add_response("curl.exe", CmdOutput::ok("{}\n200"));
        let body = scan().json("1", noon(), "build 1").to_string();

        assert_eq!(
            send(&mock, &RECEIVER, &body, Duration::from_secs(10)).await,
            Ok(())
        );
        let ran = mock.executed();
        assert_eq!(ran.len(), 1);
        // First, or curl has read the user's .curlrc by then.
        assert!(ran[0].starts_with("curl.exe -q "), "{}", ran[0]);
        assert!(ran[0].contains("--proto =https"), "{}", ran[0]);
        assert!(ran[0].contains("App-Key: A-EU-0000000000"), "{}", ran[0]);
        assert!(ran[0].contains(&body), "{}", ran[0]);
        assert!(ran[0].ends_with(RECEIVER.url), "{}", ran[0]);

        let plain = Receiver {
            url: "http://usage.example.test/api/v0/events",
            ..RECEIVER
        };
        assert!(
            send(&mock, &plain, &body, Duration::from_secs(10))
                .await
                .is_err()
        );
        assert_eq!(mock.executed().len(), 1, "nothing was run for http");
    }

    #[tokio::test]
    async fn only_a_2xx_answer_is_an_arrival() {
        for taken in ["{}\n200", "\n202", "204", "{\"ok\":true}\n200"] {
            let mock = MockCommandRunner::new();
            mock.add_response("curl.exe", CmdOutput::ok(taken));
            assert_eq!(
                send(&mock, &RECEIVER, "[]", Duration::from_secs(10)).await,
                Ok(()),
                "{taken}"
            );
        }
        for (answer, expected) in [
            // What Aptabase answers when it records nothing.
            (
                "{\"error\":\"Missing App-Key header. Events are not being recorded.\"}\n200",
                "the server dropped it: Missing App-Key header. Events are not being recorded.",
            ),
            ("Unauthorized\n401", "the server answered 401"),
            ("401", "the server answered 401"),
            ("302", "the server answered 302"),
            ("000", "no answer from the server"),
            ("", "no answer from the server"),
        ] {
            let mock = MockCommandRunner::new();
            mock.add_response("curl.exe", CmdOutput::ok(answer));
            assert_eq!(
                send(&mock, &RECEIVER, "[]", Duration::from_secs(10)).await,
                Err(expected.to_string())
            );
        }
    }

    /// What curl printed for the sender's own command line against the real
    /// receiver (tests/fixtures/README.md): the answers above are typed, these
    /// are captured.
    #[tokio::test]
    async fn the_receivers_real_answers_are_read_as_what_they_are() {
        let captured: [(&[u8], Result<(), String>); 4] = [
            (
                include_bytes!("../../tests/fixtures/console/curl_usage_report_accepted.bin"),
                Ok(()),
            ),
            (
                include_bytes!("../../tests/fixtures/console/curl_usage_report_unknown_key.bin"),
                Err(
                    "the server dropped it: Application not found with given app key: \
                     A-SH-0000000000. Events are not being recorded."
                        .to_string(),
                ),
            ),
            (
                include_bytes!("../../tests/fixtures/console/curl_usage_report_rate_limited.bin"),
                Err("the server answered 429".to_string()),
            ),
            (
                include_bytes!("../../tests/fixtures/console/curl_usage_report_no_answer.bin"),
                Err("no answer from the server".to_string()),
            ),
        ];
        for (bytes, expected) in captured {
            let printed = String::from_utf8(bytes.to_vec()).unwrap();
            let mock = MockCommandRunner::new();
            mock.add_response("curl.exe", CmdOutput::ok(printed.clone()));
            assert_eq!(
                send(&mock, &RECEIVER, "[]", Duration::from_secs(10)).await,
                expected,
                "{printed:?}"
            );
        }
    }

    #[test]
    fn every_report_is_written_down_as_it_went_out() {
        let dir = std::env::temp_dir().join(format!("winmedic_usage_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        record(&dir, noon(), "[1]", &Ok(()));
        record(&dir, noon(), "[2]", &Err("no answer".to_string()));
        assert_eq!(
            std::fs::read_to_string(dir.join(SENT_LOG)).unwrap(),
            "2026-11-17T12:00:00Z sent: [1]\n2026-11-17T12:00:00Z not sent (no answer): [2]\n"
        );

        // Past its size the file starts over with the newest report.
        let filler = "x".repeat(SENT_LOG_MAX_BYTES as usize);
        record(&dir, noon(), &filler, &Ok(()));
        record(&dir, noon(), "[3]", &Ok(()));
        assert_eq!(
            std::fs::read_to_string(dir.join(SENT_LOG)).unwrap(),
            "2026-11-17T12:00:00Z sent: [3]\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
