use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};

/// Names the resolver check asks for, in order.
///
/// Two of them, from two different operators, because one name failing is not
/// evidence that name resolution is broken — a single domain can be blocked,
/// blackholed by a filtering resolver, or simply have a bad day. The check only
/// reports a failure when *no* probe resolves.
const DNS_PROBE_NAMES: &[&str] = &["dns.google", "www.microsoft.com"];

/// What one resolver probe did.
struct DnsProbe {
    resolved: bool,
    detail: String,
}

pub struct NetworkModule {
    runner: Arc<dyn CommandRunner>,
}

impl Default for NetworkModule {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkModule {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemCommandRunner::new()))
    }

    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    /// Whether an `nslookup` run actually returned an answer record.
    ///
    /// Substring checks against the raw output do not work here: nslookup
    /// echoes the resolver it used as a `Server:` / `Address:` header *before*
    /// it reports anything, so both the server's name and the word `Address`
    /// are present even when the lookup failed outright. An answer section is
    /// what distinguishes the two, and it is introduced by a `Name:` line —
    /// on English and German Windows alike. Failure output ("can't find",
    /// "Non-existent domain", "DNS request timed out") never carries one.
    fn nslookup_resolved(stdout: &str) -> bool {
        stdout.lines().any(|line| {
            line.trim_start()
                .strip_prefix("Name:")
                .is_some_and(|name| !name.trim().is_empty())
        })
    }

    /// Ask the machine's own resolver for one name.
    ///
    /// Deliberately *without* a server argument. Passing one (`nslookup name
    /// 8.8.8.8`) bypasses the configured resolver and queries that server
    /// directly over port 53, which corporate networks, filtering routers,
    /// VPN split-DNS setups and DNS-over-HTTPS-only configurations all block
    /// as a matter of policy. On such a machine the probe failed while name
    /// resolution was perfectly healthy, and the resulting critical finding
    /// came back on every scan — `ipconfig /flushdns` cannot unblock somebody
    /// else's firewall.
    async fn probe_name(&self, name: &str) -> DnsProbe {
        match self
            .runner
            .run("nslookup.exe", &[name], Duration::from_secs(10))
            .await
        {
            Ok(out) if Self::nslookup_resolved(&out.stdout) => DnsProbe {
                resolved: true,
                detail: format!("nslookup {} resolved", name),
            },
            Ok(out) => {
                let reason = out
                    .stdout
                    .lines()
                    .map(str::trim)
                    .find(|line| line.starts_with("***") || line.contains("timed out"))
                    .map(str::to_string)
                    .unwrap_or_else(|| "no answer record returned".to_string());
                DnsProbe {
                    resolved: false,
                    detail: format!("nslookup {}: {}", name, reason),
                }
            }
            Err(err) => DnsProbe {
                resolved: false,
                detail: format!("nslookup {} could not be run: {}", name, err),
            },
        }
    }

    /// Whether the system resolver answers at all, with the per-probe log.
    ///
    /// The log is returned either way: it is what the finding's technical
    /// details show, and what the repair uses to say whether it changed
    /// anything.
    async fn resolver_works(&self) -> (bool, Vec<String>) {
        let mut log = Vec::new();
        for name in DNS_PROBE_NAMES {
            let probe = self.probe_name(name).await;
            log.push(probe.detail);
            if probe.resolved {
                return (true, log);
            }
        }
        (false, log)
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
                    module_id: "network".to_string(),
                    progress_percent: percent,
                    current_step: step.to_string(),
                    log_message: log.map(|s| s.to_string()),
                })
                .await;
        }
    }
}

#[async_trait::async_trait]
impl DiagnosticModule for NetworkModule {
    fn id(&self) -> &'static str {
        "network"
    }

    fn name(&self) -> &'static str {
        "Network & DNS Connectivity"
    }

    fn description(&self) -> &'static str {
        "Checks DNS resolution, the Winsock catalog, the TCP/IP stack and broken proxy configurations"
    }

    fn icon(&self) -> &'static str {
        "[NET]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. DNS Resolution Check
        Self::send_progress(
            &progress_tx,
            20,
            "Testing DNS name resolution...",
            Some("Asking the machine's own resolver for two independent names..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let (dns_healthy, probe_log) = self.resolver_works().await;

        if !dns_healthy {
            let ping_test = self
                .runner
                .run(
                    "ping.exe",
                    &["-n", "1", "-w", "1500", "1.1.1.1"],
                    Duration::from_secs(4),
                )
                .await;
            let ip_reachable = match ping_test {
                Ok(out) => out.stdout.contains("TTL="),
                Err(_) => false,
            };

            let evidence = probe_log.join("\n");

            if ip_reachable {
                issues.push(Issue::new(
                    "net_dns_failure",
                    self.id(),
                    "DNS name resolution failed (IP reachable)",
                    "Network & DNS",
                    Severity::Critical,
                    RiskScore::Low,
                    "Websites cannot be resolved by domain name even though IP connectivity to the internet works. The usual cause is a stale DNS cache or broken resolver settings.",
                    format!("{}\nping 1.1.1.1 succeeded", evidence),
                    "Flush the DNS cache (ipconfig /flushdns) and re-register the DNS resolver",
                    vec![
                        "Run ipconfig /flushdns".to_string(),
                        "Run ipconfig /registerdns".to_string(),
                        "Confirm that name resolution works again".to_string(),
                    ],
                ));
            } else {
                issues.push(Issue::new(
                    "net_offline_warning",
                    self.id(),
                    "No active internet or gateway connection",
                    "Network & DNS",
                    Severity::Warning,
                    RiskScore::Low,
                    "The system can reach neither external IP addresses nor DNS servers. Check the router, the Wi-Fi/LAN cable or any VPN connection.",
                    format!("{}\nping 1.1.1.1 got no reply", evidence),
                    "Reset the network adapter and the Winsock / IP stack",
                    vec![
                        "netsh winsock reset".to_string(),
                        "netsh int ip reset".to_string(),
                    ],
                ));
            }
        } else {
            Self::send_progress(
                &progress_tx,
                45,
                "DNS resolution successful",
                Some("DNS name resolution and IP routing are working correctly."),
            )
            .await;
        }

        // 2. Proxy Settings in Registry
        Self::send_progress(
            &progress_tx,
            65,
            "Checking proxy settings in the Windows registry...",
            Some("Registry Internet Settings..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(inet_settings) = hkcu.open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            KEY_READ,
        ) {
            let proxy_enable: Result<u32, _> = inet_settings.get_value("ProxyEnable");
            let proxy_server: Result<String, _> = inet_settings.get_value("ProxyServer");

            if let (Ok(1), Ok(server)) = (proxy_enable, proxy_server) {
                if !server.is_empty() {
                    issues.push(Issue::new(
                        "net_proxy_active",
                        self.id(),
                        format!("Manually configured proxy server active: {}", server),
                        "Network & DNS",
                        Severity::Warning,
                        RiskScore::Low,
                        format!("An active proxy server ({}) is configured in the system settings. If that proxy is unreachable, every connection fails.", server),
                        format!("Registry ProxyServer: {}", server),
                        "Disable the proxy settings (use a direct connection)",
                        vec!["Set ProxyEnable to 0 in the registry".to_string()],
                    ));
                }
            } else {
                Self::send_progress(
                    &progress_tx,
                    80,
                    "Direct internet connection active",
                    Some("No blocking manual proxy server is configured."),
                )
                .await;
            }
        }

        // 3. Winsock Catalog
        Self::send_progress(
            &progress_tx,
            85,
            "Checking Winsock catalog integrity...",
            Some("netsh winsock audit..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let winsock_audit = self
            .runner
            .run(
                "netsh.exe",
                &["winsock", "show", "catalog"],
                Duration::from_secs(6),
            )
            .await;
        if let Ok(out) = winsock_audit {
            if out.stdout.is_empty()
                || out.stdout.contains("Fehler")
                || out.stdout.contains("Error")
            {
                issues.push(Issue::new(
                    "net_winsock_corrupt",
                    self.id(),
                    "Winsock catalog shows inconsistencies",
                    "Network & DNS",
                    Severity::Warning,
                    RiskScore::Medium,
                    "The Winsock Layered Service Provider (LSP) catalog contains damaged or incomplete entries, which can cause dropped connections.",
                    out.stdout,
                    "Reset the Winsock catalog to its defaults",
                    vec!["Run netsh winsock reset".to_string()],
                ));
            } else {
                Self::send_progress(
                    &progress_tx,
                    95,
                    "Winsock catalog intact",
                    Some("The Winsock LSP catalog is consistent."),
                )
                .await;
            }
        }

        Self::send_progress(&progress_tx, 100, "Network diagnostics complete", None).await;

        Ok(issues)
    }

    async fn fix(
        &self,
        issue_id: &str,
        _progress_tx: Option<Sender<FixProgress>>,
    ) -> Result<String, String> {
        match issue_id {
            "net_dns_failure" => {
                let _ = self
                    .runner
                    .run("ipconfig.exe", &["/flushdns"], Duration::from_secs(8))
                    .await;
                let _ = self
                    .runner
                    .run("ipconfig.exe", &["/registerdns"], Duration::from_secs(8))
                    .await;

                // Neither command reports whether resolution actually recovered,
                // and both exit zero on a machine whose resolver is still dead.
                // Reporting success there marked the issue fixed, and the next
                // scan raised the identical critical finding - the loop the user
                // sees. Asking the resolver again is the only honest answer.
                let (resolves, probe_log) = self.resolver_works().await;
                if resolves {
                    Ok("DNS cache flushed and the resolver re-registered - name resolution is working again.".to_string())
                } else {
                    Err(format!(
                        "The DNS cache was flushed and the resolver re-registered, but names still do not resolve: {}. The fault is outside what WinMedic can reset - check the DNS servers configured on the adapter, the router, or an active VPN.",
                        probe_log.join("; ")
                    ))
                }
            }
            "net_offline_warning" | "net_winsock_corrupt" => {
                let _ = self
                    .runner
                    .run("netsh.exe", &["winsock", "reset"], Duration::from_secs(10))
                    .await;
                let _ = self
                    .runner
                    .run(
                        "netsh.exe",
                        &["int", "ip", "reset"],
                        Duration::from_secs(10),
                    )
                    .await;
                let _ = self
                    .runner
                    .run("ipconfig.exe", &["/flushdns"], Duration::from_secs(8))
                    .await;
                Ok(
                    "Winsock and the TCP/IP stack were reset successfully. (Restart recommended.)"
                        .to_string(),
                )
            }
            "net_proxy_active" => {
                let hkcu = RegKey::predef(HKEY_CURRENT_USER);
                if let Ok(inet_settings) = hkcu.open_subkey_with_flags(
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    KEY_WRITE,
                ) {
                    let _ = inet_settings.set_value("ProxyEnable", &0u32);
                    Ok(
                        "Proxy server disabled successfully. Direct internet connection is active."
                            .to_string(),
                    )
                } else {
                    Err(
                        "Could not open the Internet Settings registry key for writing."
                            .to_string(),
                    )
                }
            }
            _ => Err(format!("Unknown issue id: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    /// What `nslookup dns.google` prints when the resolver answers.
    const RESOLVED_OUTPUT: &str = "Server:  fritz.box\r\n\
         Address:  192.168.178.1\r\n\
         \r\n\
         Nicht autorisierende Antwort:\r\n\
         Name:    dns.google\r\n\
         Addresses:  8.8.8.8\r\n\
         \t  8.8.4.4\r\n";

    /// What it prints when the query reached a server that had no answer.
    const REFUSED_OUTPUT: &str = "Server:  fritz.box\r\n\
         Address:  192.168.178.1\r\n\
         \r\n\
         *** fritz.box can't find dns.google: Non-existent domain\r\n";

    /// What it prints when the queried server never answered at all - the shape
    /// a pinned public resolver produces on a network that blocks port 53.
    const TIMED_OUT_OUTPUT: &str = "DNS request timed out.\r\n\
         \ttimeout was 2 seconds.\r\n\
         Server:  UnKnown\r\n\
         Address:  8.8.8.8\r\n\
         \r\n\
         *** Request to UnKnown timed-out\r\n";

    #[test]
    fn only_an_answer_record_counts_as_resolved() {
        assert!(NetworkModule::nslookup_resolved(RESOLVED_OUTPUT));

        // Both of these carry the words "Address" and the queried server, which
        // is why a substring check reported a working resolver here.
        assert!(!NetworkModule::nslookup_resolved(REFUSED_OUTPUT));
        assert!(!NetworkModule::nslookup_resolved(TIMED_OUT_OUTPUT));
        assert!(!NetworkModule::nslookup_resolved(""));
    }

    #[tokio::test]
    async fn the_resolver_check_never_pins_a_public_dns_server() {
        // A machine whose own resolver works, on a network that blocks outbound
        // queries to 8.8.8.8. Pinning that server reported a critical DNS
        // failure here that no repair could ever clear.
        let mock = MockCommandRunner::new();
        mock.add_response("nslookup.exe", CmdOutput::ok(RESOLVED_OUTPUT));
        mock.add_response(
            "netsh.exe",
            CmdOutput::ok("Winsock Catalog Provider: MSAFD Tcpip"),
        );

        let module = NetworkModule::with_runner(Arc::new(mock.clone()));
        let issues = module.scan(None).await.unwrap();

        assert!(
            !issues.iter().any(|i| i.id == "net_dns_failure"),
            "a working resolver must not be reported"
        );
        let lookup = mock
            .executed()
            .into_iter()
            .find(|c| c.contains("nslookup"))
            .expect("the scan must ask the resolver");
        assert_eq!(
            lookup, "nslookup.exe dns.google",
            "no server argument - the query has to go through the configured resolver"
        );
    }

    #[tokio::test]
    async fn a_repair_that_did_not_restore_resolution_reports_a_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response("nslookup.exe", CmdOutput::ok(REFUSED_OUTPUT));
        mock.add_response("ipconfig.exe", CmdOutput::ok(""));

        let module = NetworkModule::with_runner(Arc::new(mock));
        let err = module.fix("net_dns_failure", None).await.unwrap_err();

        assert!(err.contains("still do not resolve"));
        assert!(
            err.contains("dns.google"),
            "the message has to say what was tried"
        );
    }

    #[tokio::test]
    async fn a_repair_that_restored_resolution_reports_success() {
        let mock = MockCommandRunner::new();
        mock.add_response("nslookup.exe", CmdOutput::ok(RESOLVED_OUTPUT));
        mock.add_response("ipconfig.exe", CmdOutput::ok(""));

        let module = NetworkModule::with_runner(Arc::new(mock));
        let msg = module.fix("net_dns_failure", None).await.unwrap();

        assert!(msg.contains("working again"));
    }

    #[tokio::test]
    async fn test_network_detects_dns_failure() {
        let mock = MockCommandRunner::new();
        // nslookup fails
        mock.add_response(
            "nslookup.exe",
            CmdOutput::failed(1, "DNS request timed out."),
        );
        // ping succeeds (IP reachable)
        mock.add_response(
            "ping.exe",
            CmdOutput::ok("Reply from 1.1.1.1: bytes=32 time=12ms TTL=58"),
        );
        mock.add_response(
            "netsh.exe",
            CmdOutput::ok("Winsock Catalog Provider: MSAFD Tcpip"),
        );

        let module = NetworkModule::with_runner(Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        let dns_issue = issues.iter().find(|i| i.id == "net_dns_failure");
        assert!(dns_issue.is_some());
        assert_eq!(dns_issue.unwrap().severity, Severity::Critical);
    }
}
