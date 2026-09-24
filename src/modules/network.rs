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

/// The provider DLL paths `netsh winsock show catalog` lists, in order.
///
/// The field labels are in the display language ("Anbieterpfad" on a German
/// system), the values are not: whatever follows the first colon and ends in
/// `.dll` is a provider path. Description lines that point into a DLL's
/// resources (`@%SystemRoot%\system32\nlasvc.dll,-1000`) do not end in `.dll`.
///
/// The check this replaces looked for the words "Error" and "Fehler" in the
/// catalog, which says nothing about its health and nothing at all in any
/// third language.
pub fn winsock_provider_paths(catalog: &str) -> Vec<String> {
    catalog
        .lines()
        .filter_map(|line| {
            let (_, value) = line.split_once(':')?;
            let value = value.trim();
            value
                .to_ascii_lowercase()
                .ends_with(".dll")
                .then(|| value.to_string())
        })
        .collect()
}

/// Whether a provider path names a file that is not there.
///
/// This is the corruption that breaks networking: an LSP left in the catalog
/// by software that has since been removed. A path with an environment
/// variable this process cannot expand is not judged — an unverifiable entry
/// is not evidence of a broken one.
pub fn provider_is_missing(path: &str) -> bool {
    match expand_env_vars(path) {
        Some(expanded) => {
            let expanded = std::path::Path::new(&expanded);
            expanded.is_absolute() && !expanded.exists()
        }
        None => false,
    }
}

/// `%SystemRoot%\x` → `C:\WINDOWS\x`; `None` when a variable is not set.
fn expand_env_vars(path: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = path;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        out.push_str(&std::env::var(&after[..end]).ok()?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// What one resolver probe did.
struct DnsProbe {
    resolved: bool,
    detail: String,
}

/// Every physical, connected adapter's IPv4 setup as `name|dhcp|addresses`,
/// e.g. `Ethernet|Enabled|192.168.1.10`. `Enabled` / `Disabled` are enum
/// names, printed the same in every display language. Virtual adapters are
/// left out: VPN and Hyper-V adapters sit on 169.254.x.x by design.
const ADAPTER_IPV4_SCRIPT: &str = "Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object { $ip = Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue; $addr = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object IPAddress) -join ','; '{0}|{1}|{2}' -f $_.Name, $ip.Dhcp, $addr }";

/// One line of [`ADAPTER_IPV4_SCRIPT`]'s output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterIpv4 {
    pub name: String,
    pub dhcp: bool,
    pub addresses: Vec<String>,
}

impl AdapterIpv4 {
    /// Set to DHCP and holding nothing but a self-assigned 169.254.x.x
    /// address: the adapter asked for an address and no DHCP server answered.
    /// Without DHCP the address is set by hand, and such an adapter is left
    /// alone — a direct cable to a device often runs on 169.254 on purpose.
    pub fn dhcp_failed(&self) -> bool {
        self.dhcp && !self.addresses.is_empty() && self.addresses.iter().all(|a| is_apipa(a))
    }

    fn has_usable_address(&self) -> bool {
        self.addresses.iter().any(|a| !is_apipa(a))
    }
}

fn is_apipa(address: &str) -> bool {
    address.starts_with("169.254.")
}

/// The adapters [`ADAPTER_IPV4_SCRIPT`] printed. Read from the right, so an
/// adapter the user named with a `|` in it still parses.
pub fn parse_adapters(output: &str) -> Vec<AdapterIpv4> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim().rsplitn(3, '|');
            let addresses = fields.next()?;
            let dhcp = fields.next()?;
            let name = fields.next()?;
            Some(AdapterIpv4 {
                name: name.to_string(),
                dhcp: dhcp.eq_ignore_ascii_case("Enabled"),
                addresses: addresses
                    .split(',')
                    .map(str::trim)
                    .filter(|a| !a.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect()
}

fn no_dhcp_issue_id(adapter: &str) -> String {
    let slug: String = adapter
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("net_no_dhcp_{slug}")
}

const WINHTTP_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

/// The proxy WinHTTP is set to, as `netsh winhttp set proxy` stored it.
///
/// WinHTTP is what Windows Update, BITS, the Store and most services connect
/// through, and it keeps its own proxy apart from the browser's - so a
/// leftover proxy here breaks updates while every browser works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinHttpProxy {
    /// `proxy:8080`, or a list such as `http=proxy:8080;https=secure:8443`.
    pub server: String,
    pub bypass: Option<String>,
}

impl WinHttpProxy {
    /// The command that sets this proxy again.
    pub fn restore_command(&self) -> String {
        match &self.bypass {
            Some(bypass) => format!(
                "netsh winhttp set proxy proxy-server=\"{}\" bypass-list=\"{bypass}\"",
                self.server
            ),
            None => format!("netsh winhttp set proxy proxy-server=\"{}\"", self.server),
        }
    }
}

/// The proxy in the `WinHttpSettings` value as `reg` prints it, or `None` for
/// a direct connection.
///
/// The value is a structure of little-endian DWORDs: size, a counter, the
/// access type, then the proxy's length and name, then the bypass list's
/// length and text. `netsh winhttp show proxy` prints the same, in the
/// display language.
pub fn winhttp_proxy(hex: &str) -> Option<WinHttpProxy> {
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect();
    let text_at = |offset: usize| -> Option<(String, usize)> {
        let len = u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize;
        let text = String::from_utf8_lossy(bytes.get(offset + 4..offset + 4 + len)?)
            .trim()
            .to_string();
        Some((text, offset + 4 + len))
    };
    let (server, end) = text_at(12)?;
    if server.is_empty() {
        return None;
    }
    let bypass = text_at(end)
        .map(|(bypass, _)| bypass)
        .filter(|b| !b.is_empty());
    Some(WinHttpProxy { server, bypass })
}

/// Every `host:port` a WinHTTP proxy list names, without repeats.
pub fn proxy_endpoints(server: &str) -> Vec<String> {
    let mut endpoints: Vec<String> = Vec::new();
    for entry in server.split([';', ' ']).filter(|p| !p.is_empty()) {
        let host = entry.split_once('=').map_or(entry, |(_, host)| host);
        let host = host
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');
        if host.is_empty() {
            continue;
        }
        let endpoint = if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:80")
        };
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

/// Whether something accepts a TCP connection at `host:port`, and if not,
/// why not.
pub type ProxyProbe = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

fn real_proxy_probe() -> ProxyProbe {
    Arc::new(|endpoint: &str| {
        use std::net::{TcpStream, ToSocketAddrs};
        let addrs: Vec<_> = endpoint
            .to_socket_addrs()
            .map_err(|e| format!("cannot be resolved ({e})"))?
            .take(3)
            .collect();
        let mut last = "resolves to no address".to_string();
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(_) => return Ok(()),
                Err(e) => last = format!("{addr}: {e}"),
            }
        }
        Err(last)
    })
}

pub struct NetworkModule {
    runner: Arc<dyn CommandRunner>,
    proxy_probe: ProxyProbe,
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
        Self {
            runner,
            proxy_probe: real_proxy_probe(),
        }
    }

    /// For tests: decide whether a proxy answers without touching the network.
    pub fn with_proxy_probe(mut self, probe: ProxyProbe) -> Self {
        self.proxy_probe = probe;
        self
    }

    async fn configured_winhttp_proxy(&self) -> Result<Option<WinHttpProxy>, String> {
        let keys = crate::utils::registry::query(&*self.runner, WINHTTP_KEY, false)
            .await?
            .unwrap_or_default();
        Ok(
            crate::utils::registry::find(&keys, WINHTTP_KEY, "WinHttpSettings")
                .and_then(|v| winhttp_proxy(&v.data)),
        )
    }

    /// `Ok(())` as soon as one endpoint answers, otherwise what each one did.
    /// A list that names no endpoint cannot be judged and counts as answering.
    async fn proxy_answers(&self, proxy: &WinHttpProxy) -> Result<(), Vec<String>> {
        let mut log = Vec::new();
        for endpoint in proxy_endpoints(&proxy.server) {
            let probe = self.proxy_probe.clone();
            let target = endpoint.clone();
            let result = tokio::task::spawn_blocking(move || probe(&target))
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
            match result {
                Ok(()) => return Ok(()),
                Err(why) => log.push(format!("{endpoint}: {why}")),
            }
        }
        if log.is_empty() { Ok(()) } else { Err(log) }
    }

    /// Switch WinHTTP back to a direct connection, then read the value back.
    async fn fix_winhttp_proxy(&self) -> Result<String, String> {
        let Some(before) = self.configured_winhttp_proxy().await? else {
            return Ok("WinHTTP already connects directly.".to_string());
        };
        let out = self
            .runner
            .run(
                "netsh.exe",
                &["winhttp", "reset", "proxy"],
                Duration::from_secs(15),
            )
            .await?;
        if !out.success {
            // Without elevation: "Error writing proxy settings. (5)".
            let said = [out.stdout.trim(), out.stderr.trim()]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            return Err(format!(
                "netsh winhttp reset proxy failed (exit code {:?}): {said}",
                out.exit_code
            ));
        }
        match self.configured_winhttp_proxy().await? {
            None => Ok(format!(
                "WinHTTP connects directly again. It pointed at {}; `{}` puts that back.",
                before.server,
                before.restore_command()
            )),
            Some(still) => Err(format!(
                "netsh winhttp reset proxy ran (exit code {:?}) but WinHTTP still points at {}. A group policy, or the software that set the proxy, is putting it back.",
                out.exit_code, still.server
            )),
        }
    }

    async fn adapters(&self) -> Result<Vec<AdapterIpv4>, String> {
        let out = self
            .runner
            .run_powershell(ADAPTER_IPV4_SCRIPT, Duration::from_secs(20))
            .await?;
        if !out.success {
            return Err(format!(
                "the adapter query failed (exit code {:?}): {}",
                out.exit_code,
                out.stderr.trim()
            ));
        }
        Ok(parse_adapters(&out.stdout))
    }

    /// Ask the adapter's DHCP server again, then look at the address it holds.
    ///
    /// `ipconfig /renew` exits with an error when no server answers, but that
    /// message is in the display language; the address afterwards is not.
    async fn fix_no_dhcp(&self, issue_id: &str) -> Result<String, String> {
        let Some(adapter) = self
            .adapters()
            .await?
            .into_iter()
            .find(|a| no_dhcp_issue_id(&a.name) == issue_id)
        else {
            return Ok("The adapter is no longer connected - nothing to renew.".to_string());
        };
        if !adapter.dhcp_failed() {
            return Ok(format!(
                "'{}' already holds an address from DHCP ({}).",
                adapter.name,
                adapter.addresses.join(", ")
            ));
        }

        let _ = self
            .runner
            .run(
                "ipconfig.exe",
                &["/renew", &adapter.name],
                Duration::from_secs(90),
            )
            .await;

        match self
            .adapters()
            .await?
            .into_iter()
            .find(|a| a.name == adapter.name)
        {
            Some(after) if after.has_usable_address() => Ok(format!(
                "'{}' received an address from the DHCP server: {}.",
                after.name,
                after.addresses.join(", ")
            )),
            _ => Err(format!(
                "'{}' asked for an address again, but no DHCP server answered. The fault is outside this PC: restart the router, check the cable or the Wi-Fi connection, and whether the router's DHCP server is switched on.",
                adapter.name
            )),
        }
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
        "Checks DHCP addresses, DNS resolution, the Winsock catalog, the TCP/IP stack and broken proxy configurations"
    }

    fn icon(&self) -> &'static str {
        "[NET]"
    }

    async fn scan(
        &self,
        progress_tx: Option<Sender<ModuleProgress>>,
    ) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. Adapters that got no address from DHCP
        Self::send_progress(
            &progress_tx,
            10,
            "Checking the network adapters' addresses...",
            Some("Get-NetAdapter / Get-NetIPAddress..."),
        )
        .await;

        let adapters = match self.adapters().await {
            Ok(adapters) => adapters,
            Err(err) => {
                Self::send_progress(
                    &progress_tx,
                    15,
                    "Adapter addresses could not be read",
                    Some(&err),
                )
                .await;
                Vec::new()
            }
        };
        let connected = adapters.iter().any(AdapterIpv4::has_usable_address);
        for adapter in adapters.iter().filter(|a| a.dhcp_failed()) {
            let (severity, consequence) = if connected {
                (
                    Severity::Info,
                    "Another adapter is connected, so this may be a cable to a device that hands out no addresses.",
                )
            } else {
                (
                    Severity::Warning,
                    "No other adapter has an address either, so this PC is cut off from the network.",
                )
            };
            let mut issue = Issue::new(
                no_dhcp_issue_id(&adapter.name),
                self.id(),
                format!("'{}' received no address from the router", adapter.name),
                "Network & DNS",
                severity,
                RiskScore::Low,
                format!(
                    "The adapter asked for an address (DHCP) and nobody answered, so Windows gave it a stand-in address from 169.254.x.x that reaches nothing. {consequence} Usual causes: the router is off or hung, a loose cable, or a Wi-Fi connection that has not finished."
                ),
                format!(
                    "Adapter: {}\nDHCP: enabled\nIPv4: {}",
                    adapter.name,
                    adapter.addresses.join(", ")
                ),
                "Ask the DHCP server for an address again (ipconfig /renew)",
                vec![
                    format!("Run ipconfig /renew \"{}\"", adapter.name),
                    "Check that the adapter now holds a real address".to_string(),
                ],
            );
            issue.is_selected = severity == Severity::Warning;
            issues.push(issue);
        }
        let dhcp_explains_offline = !connected && adapters.iter().any(AdapterIpv4::dhcp_failed);

        // 2. DNS Resolution Check
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
            } else if dhcp_explains_offline {
                // Resetting Winsock and the IP stack cannot hand out an address;
                // the DHCP finding above names the actual fault and its repair.
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

        // 3. Proxy Settings in Registry
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

        // 4. The WinHTTP proxy services and Windows Update connect through
        match self.configured_winhttp_proxy().await {
            Ok(Some(proxy)) => {
                Self::send_progress(
                    &progress_tx,
                    75,
                    "Checking the WinHTTP proxy...",
                    Some(&format!("WinHTTP proxy: {}", proxy.server)),
                )
                .await;
                if let Err(log) = self.proxy_answers(&proxy).await {
                    issues.push(Issue::new(
                        "net_winhttp_proxy_dead",
                        self.id(),
                        format!("Windows Update's proxy does not answer: {}", proxy.server),
                        "Network & DNS",
                        Severity::Warning,
                        RiskScore::Low,
                        format!(
                            "Windows Update, the Microsoft Store and many background services connect through the WinHTTP proxy, which is set apart from the browser's. It points at {}, and nothing answers there, so those connections fail while the browser still works. VPN clients, debugging proxies and company networks leave such a setting behind. If this PC is managed by a company, ask its IT first.",
                            proxy.server
                        ),
                        format!(
                            "{WINHTTP_KEY}\\WinHttpSettings\nProxy: {}\nBypass list: {}\n{}",
                            proxy.server,
                            proxy.bypass.as_deref().unwrap_or("(none)"),
                            log.join("\n")
                        ),
                        "Switch WinHTTP back to a direct connection (netsh winhttp reset proxy)",
                        vec![
                            "Run netsh winhttp reset proxy".to_string(),
                            "Check that WinHTTP no longer names a proxy".to_string(),
                        ],
                    ));
                }
            }
            Ok(None) => {}
            Err(err) => {
                Self::send_progress(
                    &progress_tx,
                    75,
                    "The WinHTTP proxy could not be read",
                    Some(&err),
                )
                .await;
            }
        }

        // 5. Winsock Catalog
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
            let providers = winsock_provider_paths(&out.stdout);
            let missing: Vec<&String> = providers
                .iter()
                .filter(|path| provider_is_missing(path))
                .collect();
            let evidence = if !out.success || providers.is_empty() {
                Some(format!(
                    "netsh winsock show catalog listed no provider (exit code {:?}).",
                    out.exit_code
                ))
            } else if !missing.is_empty() {
                Some(format!(
                    "Catalog entries whose provider DLL does not exist:\n{}",
                    missing
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                ))
            } else {
                None
            };
            if let Some(evidence) = evidence {
                issues.push(Issue::new(
                    "net_winsock_corrupt",
                    self.id(),
                    "Winsock catalog shows inconsistencies",
                    "Network & DNS",
                    Severity::Warning,
                    RiskScore::Medium,
                    "The Winsock Layered Service Provider (LSP) catalog contains damaged or incomplete entries, which can cause dropped connections.",
                    evidence,
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
            id if id.starts_with("net_no_dhcp_") => self.fix_no_dhcp(id).await,
            "net_winhttp_proxy_dead" => self.fix_winhttp_proxy().await,
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

    /// `netsh winsock show catalog` on a German Windows 11, as captured.
    fn real_catalog() -> String {
        crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/netsh_winsock_catalog_de.bin"
        ))
    }

    #[test]
    fn provider_paths_are_read_whatever_the_labels_say() {
        let paths = winsock_provider_paths(&real_catalog());
        assert_eq!(paths.len(), 28, "{paths:?}");
        assert!(
            paths
                .iter()
                .all(|p| p == r"%SystemRoot%\system32\mswsock.dll")
        );
    }

    #[test]
    fn a_provider_that_exists_is_not_missing() {
        assert!(!provider_is_missing(r"%SystemRoot%\system32\mswsock.dll"));
        assert!(provider_is_missing(
            r"%SystemRoot%\system32\winmedic-uninstalled-lsp.dll"
        ));
        // Cannot be expanded here, so it cannot be judged.
        assert!(!provider_is_missing(r"%WINMEDIC_NO_SUCH_VAR%\lsp.dll"));
    }

    async fn scan_winsock(catalog: CmdOutput) -> Vec<Issue> {
        let mock = MockCommandRunner::new();
        mock.add_response("nslookup.exe", CmdOutput::ok(RESOLVED_OUTPUT));
        mock.add_response("netsh.exe", catalog);
        NetworkModule::with_runner(Arc::new(mock))
            .scan(None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_healthy_german_catalog_is_not_a_finding() {
        let issues = scan_winsock(CmdOutput::ok(real_catalog())).await;
        assert!(!issues.iter().any(|i| i.id == "net_winsock_corrupt"));
    }

    #[tokio::test]
    async fn a_catalog_entry_without_its_dll_is_a_finding() {
        let catalog = real_catalog().replacen(
            r"%SystemRoot%\system32\mswsock.dll",
            r"C:\Program Files\GoneVPN\gone_lsp.dll",
            1,
        );
        let issues = scan_winsock(CmdOutput::ok(catalog)).await;
        let issue = issues
            .iter()
            .find(|i| i.id == "net_winsock_corrupt")
            .expect("a dangling LSP is corruption");
        assert!(issue.technical_details.contains("gone_lsp.dll"));
    }

    #[tokio::test]
    async fn an_empty_catalog_is_a_finding() {
        let issues = scan_winsock(CmdOutput::ok("")).await;
        assert!(issues.iter().any(|i| i.id == "net_winsock_corrupt"));
    }

    #[tokio::test]
    async fn the_resolver_check_never_pins_a_public_dns_server() {
        // A machine whose own resolver works, on a network that blocks outbound
        // queries to 8.8.8.8. Pinning that server reported a critical DNS
        // failure here that no repair could ever clear.
        let mock = MockCommandRunner::new();
        mock.add_response("nslookup.exe", CmdOutput::ok(RESOLVED_OUTPUT));
        mock.add_response("netsh.exe", CmdOutput::ok(real_catalog()));

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
            CmdOutput::ok("Antwort von 1.1.1.1: Bytes=32 Zeit=7ms TTL=57"),
        );
        mock.add_response("netsh.exe", CmdOutput::ok(real_catalog()));

        let module = NetworkModule::with_runner(Arc::new(mock));
        let issues = module.scan(None).await.unwrap();

        let dns_issue = issues.iter().find(|i| i.id == "net_dns_failure");
        assert!(dns_issue.is_some());
        assert_eq!(dns_issue.unwrap().severity, Severity::Critical);
    }

    /// [`ADAPTER_IPV4_SCRIPT`] on a German Windows 11, LAN address replaced.
    fn real_adapters() -> String {
        crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/powershell_adapters_ipv4.bin"
        ))
    }

    /// The same adapter after its DHCP request went unanswered.
    fn apipa_adapters() -> String {
        real_adapters().replace("192.168.1.10", "169.254.83.107")
    }

    #[test]
    fn adapters_are_read_as_captured() {
        let adapters = parse_adapters(&real_adapters());
        assert_eq!(
            adapters,
            vec![AdapterIpv4 {
                name: "Ethernet".to_string(),
                dhcp: true,
                addresses: vec!["192.168.1.10".to_string()],
            }]
        );
        assert!(!adapters[0].dhcp_failed());
        assert!(parse_adapters(&apipa_adapters())[0].dhcp_failed());
    }

    #[test]
    fn only_an_unanswered_dhcp_request_is_a_failure() {
        let adapter = |line: &str| parse_adapters(line).remove(0);
        // Set by hand, e.g. a direct cable to a camera or a NAS.
        assert!(!adapter("Ethernet 2|Disabled|169.254.10.20").dhcp_failed());
        // A real lease next to the stand-in address.
        assert!(!adapter("WLAN|Enabled|169.254.1.1,192.168.1.20").dhcp_failed());
        // No address at all is not the 169.254 case this check is about.
        assert!(!adapter("WLAN|Enabled|").dhcp_failed());

        let odd = adapter("LAN | Dock|Enabled|169.254.1.1");
        assert_eq!(odd.name, "LAN | Dock");
        assert!(odd.dhcp_failed());
        assert_eq!(no_dhcp_issue_id(&odd.name), "net_no_dhcp_lan___dock");
    }

    fn offline_mock(adapters: String) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("Get-NetAdapter", CmdOutput::ok(adapters));
        mock.add_response(
            "nslookup.exe",
            CmdOutput::failed(1, "DNS request timed out."),
        );
        mock.add_response("ping.exe", CmdOutput::failed(1, ""));
        mock.add_response("netsh.exe", CmdOutput::ok(real_catalog()));
        mock
    }

    #[tokio::test]
    async fn a_healthy_adapter_is_not_a_finding() {
        let mock = MockCommandRunner::new();
        mock.add_response("Get-NetAdapter", CmdOutput::ok(real_adapters()));
        mock.add_response("nslookup.exe", CmdOutput::ok(RESOLVED_OUTPUT));
        mock.add_response("netsh.exe", CmdOutput::ok(real_catalog()));
        let issues = NetworkModule::with_runner(Arc::new(mock))
            .scan(None)
            .await
            .unwrap();
        assert!(!issues.iter().any(|i| i.id.starts_with("net_no_dhcp_")));
    }

    #[tokio::test]
    async fn no_dhcp_answer_replaces_the_stack_reset() {
        let issues = NetworkModule::with_runner(Arc::new(offline_mock(apipa_adapters())))
            .scan(None)
            .await
            .unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "net_no_dhcp_ethernet")
            .expect("the adapter got no address");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.is_selected);
        assert!(issue.technical_details.contains("169.254.83.107"));
        assert!(
            !issues.iter().any(|i| i.id == "net_offline_warning"),
            "a Winsock reset cannot hand out an address"
        );
    }

    #[tokio::test]
    async fn without_an_adapter_finding_the_offline_warning_stays() {
        let issues = NetworkModule::with_runner(Arc::new(offline_mock(real_adapters())))
            .scan(None)
            .await
            .unwrap();
        assert!(issues.iter().any(|i| i.id == "net_offline_warning"));
    }

    #[tokio::test]
    async fn a_second_adapter_without_dhcp_is_only_information() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "Get-NetAdapter",
            CmdOutput::ok(format!(
                "{}Ethernet 2|Enabled|169.254.7.7\r\n",
                real_adapters()
            )),
        );
        mock.add_response("nslookup.exe", CmdOutput::ok(RESOLVED_OUTPUT));
        mock.add_response("netsh.exe", CmdOutput::ok(real_catalog()));
        let issues = NetworkModule::with_runner(Arc::new(mock))
            .scan(None)
            .await
            .unwrap();
        let issue = issues
            .iter()
            .find(|i| i.id == "net_no_dhcp_ethernet_2")
            .unwrap();
        assert_eq!(issue.severity, Severity::Info);
        assert!(!issue.is_selected, "the PC is online through 'Ethernet'");
    }

    /// Answers every query with `before` until the repair command ran, then
    /// with `after` - what a repair's read-back sees on a real machine.
    struct RepairRunner {
        repair: &'static str,
        repair_output: CmdOutput,
        before: CmdOutput,
        after: CmdOutput,
        repaired: std::sync::atomic::AtomicBool,
        executed: std::sync::Mutex<Vec<String>>,
    }

    impl RepairRunner {
        fn new(repair: &'static str, before: CmdOutput, after: CmdOutput) -> Self {
            Self {
                repair,
                repair_output: CmdOutput::ok(""),
                before,
                after,
                repaired: Default::default(),
                executed: Default::default(),
            }
        }

        fn repair_answers(mut self, output: CmdOutput) -> Self {
            self.repair_output = output;
            self
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for RepairRunner {
        async fn run(
            &self,
            program: &str,
            args: &[&str],
            _timeout: Duration,
        ) -> Result<CmdOutput, String> {
            use std::sync::atomic::Ordering;
            self.executed
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            if program == self.repair {
                self.repaired.store(true, Ordering::SeqCst);
                return Ok(self.repair_output.clone());
            }
            Ok(if self.repaired.load(Ordering::SeqCst) {
                self.after.clone()
            } else {
                self.before.clone()
            })
        }

        async fn run_streaming(
            &self,
            program: &str,
            args: &[&str],
            _log_tx: Option<Sender<String>>,
            timeout: Duration,
        ) -> Result<CmdOutput, String> {
            self.run(program, args, timeout).await
        }
    }

    #[tokio::test]
    async fn a_renewed_lease_is_read_back() {
        let runner = Arc::new(RepairRunner::new(
            "ipconfig.exe",
            CmdOutput::ok(apipa_adapters()),
            CmdOutput::ok(real_adapters()),
        ));
        let msg = NetworkModule::with_runner(runner.clone())
            .fix("net_no_dhcp_ethernet", None)
            .await
            .unwrap();
        assert!(msg.contains("192.168.1.10"), "{msg}");
        assert!(
            runner
                .executed
                .lock()
                .unwrap()
                .contains(&"ipconfig.exe /renew Ethernet".to_string())
        );
    }

    #[tokio::test]
    async fn a_renew_nobody_answered_is_a_failure() {
        let runner = RepairRunner::new(
            "ipconfig.exe",
            CmdOutput::ok(apipa_adapters()),
            CmdOutput::ok(apipa_adapters()),
        );
        let err = NetworkModule::with_runner(Arc::new(runner))
            .fix("net_no_dhcp_ethernet", None)
            .await
            .unwrap_err();
        assert!(err.contains("no DHCP server answered"), "{err}");
    }

    /// `reg query ...\Connections` on a machine without a WinHTTP proxy.
    fn real_winhttp_direct() -> String {
        crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/reg_query_winhttp_direct.bin"
        ))
    }

    /// The same `reg` output with a proxy set.
    ///
    /// Constructed: setting a proxy needs elevation and changes the machine.
    /// The header is the captured value's; access type 3 is a named proxy,
    /// and the proxy and the bypass list follow as length and text, the
    /// shape `netsh winhttp set proxy` writes.
    fn winhttp_with_proxy(server: &str, bypass: &str) -> String {
        let mut bytes = vec![0x18, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0];
        for text in [server, bypass] {
            bytes.extend((text.len() as u32).to_le_bytes());
            bytes.extend(text.as_bytes());
        }
        let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
        real_winhttp_direct().replace("1800000000000000010000000000000000000000", &hex)
    }

    fn winhttp_value(reg_output: &str) -> Option<WinHttpProxy> {
        let keys = crate::utils::registry::parse_reg_query(reg_output);
        winhttp_proxy(&crate::utils::registry::find(&keys, WINHTTP_KEY, "WinHttpSettings")?.data)
    }

    #[test]
    fn the_captured_direct_connection_has_no_proxy() {
        let keys = crate::utils::registry::parse_reg_query(&real_winhttp_direct());
        assert!(crate::utils::registry::find(&keys, WINHTTP_KEY, "WinHttpSettings").is_some());
        assert_eq!(winhttp_value(&real_winhttp_direct()), None);
    }

    #[test]
    fn proxy_and_bypass_list_are_read() {
        let proxy = winhttp_value(&winhttp_with_proxy("proxy.corp:8080", "<local>")).unwrap();
        assert_eq!(proxy.server, "proxy.corp:8080");
        assert_eq!(proxy.bypass.as_deref(), Some("<local>"));
        assert_eq!(
            proxy.restore_command(),
            "netsh winhttp set proxy proxy-server=\"proxy.corp:8080\" bypass-list=\"<local>\""
        );

        let bare = winhttp_value(&winhttp_with_proxy("127.0.0.1:8888", "")).unwrap();
        assert_eq!(bare.bypass, None);
        assert_eq!(
            bare.restore_command(),
            "netsh winhttp set proxy proxy-server=\"127.0.0.1:8888\""
        );
    }

    #[test]
    fn the_real_probe_tells_an_open_port_from_a_closed_one() {
        // Loopback only: nothing leaves the machine.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().to_string();
        assert_eq!(real_proxy_probe()(&open), Ok(()));
        drop(listener);
        assert!(real_proxy_probe()(&open).is_err());
    }

    #[test]
    fn every_endpoint_of_a_proxy_list_is_named_once() {
        assert_eq!(proxy_endpoints("proxy:8080"), ["proxy:8080"]);
        assert_eq!(proxy_endpoints("http://proxy/"), ["proxy:80"]);
        assert_eq!(
            proxy_endpoints("http=a:3128;https=b:8443"),
            ["a:3128", "b:8443"]
        );
        assert_eq!(proxy_endpoints("http=a:3128;https=a:3128"), ["a:3128"]);
        assert!(proxy_endpoints(";").is_empty());
    }

    /// A healthy machine whose WinHTTP value is `winhttp`, with a proxy
    /// probe that answers `probe` and records what it was asked.
    async fn scan_winhttp(winhttp: String, probe: Result<(), String>) -> (Vec<Issue>, Vec<String>) {
        let mock = MockCommandRunner::new();
        mock.add_response("reg.exe", CmdOutput::ok(winhttp));
        mock.add_response("nslookup.exe", CmdOutput::ok(RESOLVED_OUTPUT));
        mock.add_response("netsh.exe", CmdOutput::ok(real_catalog()));
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = asked.clone();
        let module = NetworkModule::with_runner(Arc::new(mock)).with_proxy_probe(Arc::new(
            move |endpoint: &str| {
                log.lock().unwrap().push(endpoint.to_string());
                probe.clone()
            },
        ));
        let issues = module.scan(None).await.unwrap();
        let asked = asked.lock().unwrap().clone();
        (issues, asked)
    }

    #[tokio::test]
    async fn a_direct_connection_is_not_probed() {
        let (issues, asked) = scan_winhttp(real_winhttp_direct(), Ok(())).await;
        assert!(!issues.iter().any(|i| i.id == "net_winhttp_proxy_dead"));
        assert!(asked.is_empty());
    }

    #[tokio::test]
    async fn a_proxy_that_answers_is_left_alone() {
        let (issues, asked) =
            scan_winhttp(winhttp_with_proxy("proxy.corp:8080", "<local>"), Ok(())).await;
        assert!(!issues.iter().any(|i| i.id == "net_winhttp_proxy_dead"));
        assert_eq!(asked, ["proxy.corp:8080"]);
    }

    #[tokio::test]
    async fn a_proxy_nobody_answers_at_is_a_finding() {
        let (issues, asked) = scan_winhttp(
            winhttp_with_proxy("http=127.0.0.1:8888;https=127.0.0.1:8889", ""),
            Err("connection refused".to_string()),
        )
        .await;
        assert_eq!(asked, ["127.0.0.1:8888", "127.0.0.1:8889"]);
        let issue = issues
            .iter()
            .find(|i| i.id == "net_winhttp_proxy_dead")
            .expect("no endpoint answered");
        assert!(issue.title.contains("127.0.0.1:8888"));
        assert!(
            issue
                .technical_details
                .contains("127.0.0.1:8889: connection refused")
        );
    }

    fn winhttp_repair(before: String, after: String) -> RepairRunner {
        RepairRunner::new("netsh.exe", CmdOutput::ok(before), CmdOutput::ok(after))
    }

    #[tokio::test]
    async fn a_reset_proxy_is_read_back_and_can_be_put_back() {
        let runner = Arc::new(winhttp_repair(
            winhttp_with_proxy("proxy.corp:8080", "<local>"),
            real_winhttp_direct(),
        ));
        let msg = NetworkModule::with_runner(runner.clone())
            .fix("net_winhttp_proxy_dead", None)
            .await
            .unwrap();
        assert!(
            msg.contains("bypass-list=\"<local>\""),
            "the message has to say how to undo it: {msg}"
        );
        assert!(
            runner
                .executed
                .lock()
                .unwrap()
                .contains(&"netsh.exe winhttp reset proxy".to_string())
        );
    }

    #[tokio::test]
    async fn a_proxy_that_comes_back_is_a_failure() {
        let proxy = winhttp_with_proxy("proxy.corp:8080", "");
        let err = NetworkModule::with_runner(Arc::new(winhttp_repair(proxy.clone(), proxy)))
            .fix("net_winhttp_proxy_dead", None)
            .await
            .unwrap_err();
        assert!(err.contains("still points at proxy.corp:8080"), "{err}");
    }

    #[tokio::test]
    async fn a_refused_reset_says_what_netsh_said() {
        let proxy = winhttp_with_proxy("proxy.corp:8080", "");
        let runner = winhttp_repair(proxy.clone(), proxy).repair_answers(CmdOutput::with_output(
            1,
            "Error writing proxy settings. (5) Access is denied.",
            "",
        ));
        let err = NetworkModule::with_runner(Arc::new(runner))
            .fix("net_winhttp_proxy_dead", None)
            .await
            .unwrap_err();
        assert!(err.contains("Access is denied"), "{err}");
    }
}
