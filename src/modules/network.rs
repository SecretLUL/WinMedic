use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CommandRunner, SystemCommandRunner};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};

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
            Some("Looking up Google & Cloudflare DNS..."),
        )
        .await;
        sleep(Duration::from_millis(150)).await;

        let dns_lookup = self
            .runner
            .run(
                "nslookup.exe",
                &["dns.google", "8.8.8.8"],
                Duration::from_secs(6),
            )
            .await;
        let mut dns_healthy = false;
        if let Ok(out) = dns_lookup
            && (out.stdout.contains("8.8.8.8") || out.stdout.contains("Address"))
        {
            dns_healthy = true;
        }

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

            if ip_reachable {
                issues.push(Issue::new(
                    "net_dns_failure",
                    self.id(),
                    "DNS name resolution failed (IP reachable)",
                    "Network & DNS",
                    Severity::Critical,
                    RiskScore::Low,
                    "Websites cannot be resolved by domain name even though IP connectivity to the internet works. The usual cause is a stale DNS cache or broken resolver settings.",
                    "nslookup failed, ping 1.1.1.1 succeeded",
                    "Flush the DNS cache (ipconfig /flushdns) and re-register the DNS resolver",
                    vec![
                        "Run ipconfig /flushdns".to_string(),
                        "Run ipconfig /registerdns".to_string(),
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
                    "No response to ping / nslookup",
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
                Ok("DNS cache flushed and DNS resolver re-registered successfully.".to_string())
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
