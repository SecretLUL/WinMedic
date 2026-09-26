use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::{CmdOutput, CommandRunner, SystemCommandRunner};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

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

/// Ask the machine's own resolver for `name`: its addresses, one per line, or
/// `FAILED|<error id>|<message>` and exit code 1.
///
/// Addresses and the error id (`DNS_ERROR_RCODE_NAME_ERROR`) read the same in
/// every display language. `nslookup`, which this replaces, labels its answer
/// `Name:` in English and German but `Nom :` in French, so the check reported
/// a dead resolver on every French PC.
fn dns_probe_script(name: &str) -> String {
    format!(
        "try {{ Resolve-DnsName -Name {} -Type A_AAAA -DnsOnly -ErrorAction Stop | ForEach-Object {{ $_.IPAddress }} | Where-Object {{ $_ }} }} catch {{ 'FAILED|' + $_.FullyQualifiedErrorId + '|' + $_.Exception.Message; exit 1 }}",
        crate::utils::cmd::ps_single_quoted(name)
    )
}

/// Whether [`dns_probe_script`] returned an address.
pub fn dns_probe_resolved(out: &CmdOutput) -> bool {
    out.success
        && out
            .stdout
            .lines()
            .any(|line| line.trim().parse::<std::net::IpAddr>().is_ok())
}

/// Why [`dns_probe_script`] returned no address, e.g.
/// `DNS_ERROR_RCODE_NAME_ERROR: The DNS name does not exist`.
fn dns_probe_failure(out: &CmdOutput) -> String {
    let failed = out
        .stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("FAILED|"));
    match failed {
        Some(rest) => {
            let (id, message) = rest.split_once('|').unwrap_or((rest, ""));
            let id = id.split(',').next().unwrap_or(id);
            format!("{id}: {}", message.trim())
        }
        None => format!(
            "no address returned (exit code {:?}) {}",
            out.exit_code,
            out.stderr.lines().next().unwrap_or("").trim()
        )
        .trim_end()
        .to_string(),
    }
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

/// Where the user's own proxy is set: `ProxyEnable` and `ProxyServer`.
const INTERNET_SETTINGS_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

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

    /// The proxy this user's connections go through (Settings > Network &
    /// internet > Proxy), or `None` when it is switched off.
    async fn configured_user_proxy(&self) -> Result<Option<String>, String> {
        let keys = crate::utils::registry::query(&*self.runner, INTERNET_SETTINGS_KEY, false)
            .await?
            .unwrap_or_default();
        let enabled = crate::utils::registry::find(&keys, INTERNET_SETTINGS_KEY, "ProxyEnable")
            .and_then(|v| v.number())
            == Some(1);
        let server = crate::utils::registry::find(&keys, INTERNET_SETTINGS_KEY, "ProxyServer")
            .map(|v| v.data.trim().to_string())
            .filter(|s| !s.is_empty());
        Ok(server.filter(|_| enabled))
    }

    /// Switch the user's proxy off, then read the setting back. The proxy's
    /// address stays where it is, so switching it on again restores it.
    async fn fix_user_proxy(&self) -> Result<String, String> {
        let Some(server) = self.configured_user_proxy().await? else {
            return Ok("The proxy is already switched off.".to_string());
        };
        let out = self
            .runner
            .run(
                "reg.exe",
                &[
                    "add",
                    INTERNET_SETTINGS_KEY,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ],
                Duration::from_secs(10),
            )
            .await?;
        if !out.success {
            return Err(format!(
                "The proxy could not be switched off (reg add exit code {:?}): {}",
                out.exit_code,
                out.stderr.trim()
            ));
        }
        match self.configured_user_proxy().await? {
            None => Ok(format!(
                "The proxy {server} is switched off. Its address is kept: to use it again, switch on 'Use a proxy server' under Settings > Network & internet > Proxy."
            )),
            Some(_) => Err(format!(
                "The proxy {server} is still switched on after the change. A group policy or the program that set it is putting it back."
            )),
        }
    }

    /// `Ok(())` as soon as one endpoint of `server` answers, otherwise what
    /// each one did. A list that names no endpoint cannot be judged and counts
    /// as answering.
    async fn proxy_answers(&self, server: &str) -> Result<(), Vec<String>> {
        let mut log = Vec::new();
        for endpoint in proxy_endpoints(server) {
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
            .query_powershell(ADAPTER_IPV4_SCRIPT, Duration::from_secs(20))
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

    /// Ask the machine's own resolver for one name.
    ///
    /// Deliberately *without* a server argument. Naming one (`-Server
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
            .run_powershell(&dns_probe_script(name), Duration::from_secs(20))
            .await
        {
            Ok(out) if dns_probe_resolved(&out) => DnsProbe {
                resolved: true,
                detail: format!("{name} resolved"),
            },
            Ok(out) => DnsProbe {
                resolved: false,
                detail: format!("{name}: {}", dns_probe_failure(&out)),
            },
            Err(err) => DnsProbe {
                resolved: false,
                detail: format!("{name} could not be looked up: {err}"),
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
                // A reset of Winsock and the IP stack cannot bring back a
                // router that is off, and it wipes static addresses and VPN
                // entries on the way, so this is advice.
                issues.push(
                    Issue::new(
                        "net_offline_warning",
                        self.id(),
                        "No connection to the internet",
                        "Network & DNS",
                        Severity::Warning,
                        RiskScore::Low,
                        "This PC reaches neither the internet nor a DNS server. That is almost always the router, the cable, the Wi-Fi or a VPN, not Windows.",
                        format!("{}\nping 1.1.1.1 got no reply", evidence),
                        "Restart the router and check the cable or the Wi-Fi connection",
                        vec![
                            "Restart the router and wait until it is back online".to_string(),
                            "Check the network cable, or connect to the Wi-Fi again".to_string(),
                            "Disconnect a VPN, then scan again".to_string(),
                        ],
                    )
                    .with_advice_only(),
                );
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

        // 3. The proxy set for this user. A company or school proxy that
        // answers is how that network works, so only a dead one is a finding.
        Self::send_progress(
            &progress_tx,
            65,
            "Checking the proxy settings...",
            Some("Internet Settings: ProxyEnable / ProxyServer..."),
        )
        .await;

        match self.configured_user_proxy().await {
            Ok(Some(server)) => {
                if let Err(log) = self.proxy_answers(&server).await {
                    issues.push(Issue::new(
                        "net_proxy_active",
                        self.id(),
                        format!("The proxy set for this user does not answer: {server}"),
                        "Network & DNS",
                        Severity::Warning,
                        RiskScore::Low,
                        format!(
                            "Browsers and most programs connect through the proxy {server}, and nothing answers there, so their connections fail. VPN clients and debugging tools leave such a setting behind. If this PC is managed by a company or school, ask its IT first."
                        ),
                        format!(
                            "{INTERNET_SETTINGS_KEY}\nProxyEnable: 1\nProxyServer: {server}\n{}",
                            log.join("\n")
                        ),
                        "Switch the proxy off (the address is kept)",
                        vec![
                            format!("Set ProxyEnable to 0 under {INTERNET_SETTINGS_KEY}"),
                            "Check that the proxy is switched off".to_string(),
                        ],
                    ));
                }
            }
            Ok(None) => {
                Self::send_progress(
                    &progress_tx,
                    70,
                    "No proxy set",
                    Some("Connections go out directly."),
                )
                .await;
            }
            Err(err) => {
                Self::send_progress(
                    &progress_tx,
                    70,
                    "The proxy settings could not be read",
                    Some(&err),
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
                if let Err(log) = self.proxy_answers(&proxy.server).await {
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
                // The reset also removes the entries of VPN and security
                // software that is still installed, and needs a restart.
                let mut issue = Issue::new(
                    "net_winsock_corrupt",
                    self.id(),
                    "The Winsock catalog is damaged",
                    "Network & DNS",
                    Severity::Warning,
                    RiskScore::High,
                    "The Winsock catalog names network components whose files are gone, usually left by an uninstalled VPN or security program. That breaks connections. The reset removes every added component, also those of programs still installed, which may need reinstalling afterwards.",
                    evidence,
                    "Reset the Winsock catalog (netsh winsock reset), then restart",
                    vec![
                        "Run netsh winsock reset".to_string(),
                        "Restart Windows".to_string(),
                    ],
                )
                .with_requires_reboot(true);
                issue.is_selected = false;
                issues.push(issue);
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
            // Only Winsock: `netsh int ip reset` would also wipe static
            // addresses and DNS servers, which have nothing to do with a
            // catalog entry whose file is gone.
            "net_winsock_corrupt" => {
                let out = self
                    .runner
                    .run("netsh.exe", &["winsock", "reset"], Duration::from_secs(30))
                    .await?;
                if out.success {
                    Ok(
                        "The Winsock catalog was reset. It takes effect after a restart."
                            .to_string(),
                    )
                } else {
                    Err(format!(
                        "netsh winsock reset failed (exit code {:?}): {}",
                        out.exit_code,
                        [out.stdout.trim(), out.stderr.trim()].join(" ").trim()
                    ))
                }
            }
            "net_proxy_active" => self.fix_user_proxy().await,
            _ => Err(format!("Unknown issue id: {}", issue_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};

    /// What the resolver probe prints for `dns.google`, as captured.
    fn resolved() -> CmdOutput {
        CmdOutput::ok(crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/powershell_resolve_dns_google.bin"
        )))
    }

    /// The probe for a name that does not exist, on a German Windows: exit 1.
    fn not_resolved() -> CmdOutput {
        CmdOutput::with_output(
            1,
            crate::utils::decode::decode_output(include_bytes!(
                "../../tests/fixtures/console/powershell_resolve_dns_nxdomain_de.bin"
            )),
            "",
        )
    }

    /// What the mock matches the resolver probe by.
    const PROBE: &str = "Resolve-DnsName";

    #[test]
    fn only_an_address_counts_as_resolved() {
        assert!(dns_probe_resolved(&resolved()));
        assert!(!dns_probe_resolved(&not_resolved()));
        assert!(!dns_probe_resolved(&CmdOutput::ok("")));
        assert!(!dns_probe_resolved(&CmdOutput::with_output(
            1, "8.8.8.8", ""
        )));
    }

    #[test]
    fn a_failed_probe_is_named_by_its_error_id() {
        let why = dns_probe_failure(&not_resolved());
        assert!(why.starts_with("DNS_ERROR_RCODE_NAME_ERROR: "), "{why}");
        assert_eq!(
            dns_probe_failure(&CmdOutput::failed(1, "boom\r\nmore")),
            "no address returned (exit code Some(1)) boom"
        );
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
        mock.add_response(PROBE, resolved());
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
        mock.add_response(PROBE, resolved());
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
            .find(|c| c.contains(PROBE))
            .expect("the scan must ask the resolver");
        assert!(lookup.contains("-Name 'dns.google'"), "{lookup}");
        assert!(
            !lookup.contains("-Server"),
            "no server argument - the query has to go through the configured resolver"
        );
    }

    #[tokio::test]
    async fn a_repair_that_did_not_restore_resolution_reports_a_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response(PROBE, not_resolved());
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
        mock.add_response(PROBE, resolved());
        mock.add_response("ipconfig.exe", CmdOutput::ok(""));

        let module = NetworkModule::with_runner(Arc::new(mock));
        let msg = module.fix("net_dns_failure", None).await.unwrap();

        assert!(msg.contains("working again"));
    }

    #[tokio::test]
    async fn test_network_detects_dns_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response(PROBE, not_resolved());
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
        mock.add_response(PROBE, not_resolved());
        mock.add_response("ping.exe", CmdOutput::failed(1, ""));
        mock.add_response("netsh.exe", CmdOutput::ok(real_catalog()));
        mock
    }

    #[tokio::test]
    async fn a_healthy_adapter_is_not_a_finding() {
        let mock = MockCommandRunner::new();
        mock.add_response("Get-NetAdapter", CmdOutput::ok(real_adapters()));
        mock.add_response(PROBE, resolved());
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
        let issue = issues
            .iter()
            .find(|i| i.id == "net_offline_warning")
            .expect("nothing answers");
        assert!(
            issue.advice_only && !issue.is_selected,
            "a stack reset cannot bring back a router"
        );
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
        mock.add_response(PROBE, resolved());
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

    /// The adapter query answers `before` until `ipconfig` ran, then `after`.
    fn renew_mock(before: String, after: String) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("Get-NetAdapter", CmdOutput::ok(before));
        mock.add_response("ipconfig.exe", CmdOutput::ok(""));
        mock.add_response_after("ipconfig.exe", "Get-NetAdapter", CmdOutput::ok(after));
        mock
    }

    #[tokio::test]
    async fn a_renewed_lease_is_read_back() {
        let mock = renew_mock(apipa_adapters(), real_adapters());
        let msg = NetworkModule::with_runner(Arc::new(mock.clone()))
            .fix("net_no_dhcp_ethernet", None)
            .await
            .unwrap();
        assert!(msg.contains("192.168.1.10"), "{msg}");
        assert!(
            mock.executed()
                .contains(&"ipconfig.exe /renew Ethernet".to_string())
        );
    }

    #[tokio::test]
    async fn a_renew_nobody_answered_is_a_failure() {
        let mock = renew_mock(apipa_adapters(), apipa_adapters());
        let err = NetworkModule::with_runner(Arc::new(mock))
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
        mock.add_response(PROBE, resolved());
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

    /// `reg` answers `before` until the reset ran, then `after`; the reset
    /// itself answers `reset`.
    fn winhttp_repair(before: String, reset: CmdOutput, after: String) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response("reg.exe", CmdOutput::ok(before));
        mock.add_response("reset proxy", reset);
        mock.add_response_after("reset proxy", "reg.exe", CmdOutput::ok(after));
        mock
    }

    #[tokio::test]
    async fn a_reset_proxy_is_read_back_and_can_be_put_back() {
        let mock = winhttp_repair(
            winhttp_with_proxy("proxy.corp:8080", "<local>"),
            CmdOutput::ok(""),
            real_winhttp_direct(),
        );
        let msg = NetworkModule::with_runner(Arc::new(mock.clone()))
            .fix("net_winhttp_proxy_dead", None)
            .await
            .unwrap();
        assert!(
            msg.contains("bypass-list=\"<local>\""),
            "the message has to say how to undo it: {msg}"
        );
        assert!(
            mock.executed()
                .contains(&"netsh.exe winhttp reset proxy".to_string())
        );
    }

    #[tokio::test]
    async fn a_proxy_that_comes_back_is_a_failure() {
        let proxy = winhttp_with_proxy("proxy.corp:8080", "");
        let mock = winhttp_repair(proxy.clone(), CmdOutput::ok(""), proxy);
        let err = NetworkModule::with_runner(Arc::new(mock))
            .fix("net_winhttp_proxy_dead", None)
            .await
            .unwrap_err();
        assert!(err.contains("still points at proxy.corp:8080"), "{err}");
    }

    #[tokio::test]
    async fn a_refused_reset_says_what_netsh_said() {
        let proxy = winhttp_with_proxy("proxy.corp:8080", "");
        let refused =
            CmdOutput::with_output(1, "Error writing proxy settings. (5) Access is denied.", "");
        let mock = winhttp_repair(proxy.clone(), refused, proxy);
        let err = NetworkModule::with_runner(Arc::new(mock))
            .fix("net_winhttp_proxy_dead", None)
            .await
            .unwrap_err();
        assert!(err.contains("Access is denied"), "{err}");
    }

    #[tokio::test]
    async fn a_winsock_finding_waits_to_be_ticked_and_needs_a_restart() {
        let catalog = real_catalog().replacen(
            r"%SystemRoot%\system32\mswsock.dll",
            r"C:\Program Files\GoneVPN\gone_lsp.dll",
            1,
        );
        let issues = scan_winsock(CmdOutput::ok(catalog)).await;
        let issue = issues
            .iter()
            .find(|i| i.id == "net_winsock_corrupt")
            .unwrap();
        assert!(!issue.is_selected);
        assert!(issue.requires_reboot);
        assert_eq!(issue.risk_score, RiskScore::High);
    }

    #[tokio::test]
    async fn the_winsock_repair_leaves_the_ip_settings_alone() {
        let mock = MockCommandRunner::new();
        mock.add_response("netsh.exe", CmdOutput::ok(""));
        let msg = NetworkModule::with_runner(Arc::new(mock.clone()))
            .fix("net_winsock_corrupt", None)
            .await
            .unwrap();
        assert!(msg.contains("restart"), "{msg}");
        assert_eq!(mock.executed(), ["netsh.exe winsock reset"]);
    }

    #[tokio::test]
    async fn a_refused_winsock_reset_is_a_failure() {
        let mock = MockCommandRunner::new();
        mock.add_response("netsh.exe", CmdOutput::with_output(1, "", "denied"));
        let err = NetworkModule::with_runner(Arc::new(mock))
            .fix("net_winsock_corrupt", None)
            .await
            .unwrap_err();
        assert!(
            err.contains("exit code Some(1)") && err.contains("denied"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn being_offline_is_never_repaired() {
        let mock = MockCommandRunner::with_default_success();
        let err = NetworkModule::with_runner(Arc::new(mock.clone()))
            .fix("net_offline_warning", None)
            .await
            .unwrap_err();
        assert!(err.contains("Unknown issue id"), "{err}");
        assert!(mock.executed().is_empty());
    }

    /// `reg query` of the user's Internet Settings, as captured: no proxy.
    fn real_internet_settings() -> String {
        crate::utils::decode::decode_output(include_bytes!(
            "../../tests/fixtures/console/reg_query_internet_settings.bin"
        ))
    }

    /// The same with the proxy switched on and pointed at `server`, as the
    /// Settings app writes it.
    fn internet_settings_with_proxy(server: &str) -> String {
        real_internet_settings().replace(
            "    ProxyEnable    REG_DWORD    0x0\r\n",
            &format!(
                "    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    {server}\r\n"
            ),
        )
    }

    async fn scan_user_proxy(settings: String, probe: Result<(), String>) -> Vec<Issue> {
        let mock = MockCommandRunner::new();
        mock.add_response("reg.exe", CmdOutput::ok(settings));
        mock.add_response(PROBE, resolved());
        mock.add_response("netsh.exe", CmdOutput::ok(real_catalog()));
        NetworkModule::with_runner(Arc::new(mock))
            .with_proxy_probe(Arc::new(move |_: &str| probe.clone()))
            .scan(None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_captured_settings_have_no_proxy() {
        let issues = scan_user_proxy(real_internet_settings(), Err("x".into())).await;
        assert!(!issues.iter().any(|i| i.id == "net_proxy_active"));
    }

    #[tokio::test]
    async fn a_company_proxy_that_answers_is_left_alone() {
        let issues =
            scan_user_proxy(internet_settings_with_proxy("proxy.school:3128"), Ok(())).await;
        assert!(!issues.iter().any(|i| i.id == "net_proxy_active"));
    }

    #[tokio::test]
    async fn a_proxy_nothing_answers_at_is_a_finding() {
        let issues = scan_user_proxy(
            internet_settings_with_proxy("127.0.0.1:8888"),
            Err("connection refused".to_string()),
        )
        .await;
        let issue = issues
            .iter()
            .find(|i| i.id == "net_proxy_active")
            .expect("nothing answers at the proxy");
        assert!(issue.title.contains("127.0.0.1:8888"));
        assert!(
            issue
                .technical_details
                .contains("127.0.0.1:8888: connection refused")
        );
    }

    fn user_proxy_repair(write: CmdOutput, after: String) -> MockCommandRunner {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "reg.exe query",
            CmdOutput::ok(internet_settings_with_proxy("127.0.0.1:8888")),
        );
        mock.add_response("reg.exe add", write);
        mock.add_response_after("reg.exe add", "reg.exe query", CmdOutput::ok(after));
        mock
    }

    #[tokio::test]
    async fn switching_the_proxy_off_is_read_back() {
        let mock = user_proxy_repair(CmdOutput::ok(""), real_internet_settings());
        let msg = NetworkModule::with_runner(Arc::new(mock.clone()))
            .fix("net_proxy_active", None)
            .await
            .unwrap();
        assert!(
            msg.contains("127.0.0.1:8888") && msg.contains("Settings"),
            "{msg}"
        );
        assert!(mock.executed().iter().any(|c| c.contains(
            r"add HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings /v ProxyEnable /t REG_DWORD /d 0 /f"
        )));
    }

    #[tokio::test]
    async fn a_proxy_that_stays_on_is_a_failure() {
        let mock = user_proxy_repair(
            CmdOutput::ok(""),
            internet_settings_with_proxy("127.0.0.1:8888"),
        );
        let err = NetworkModule::with_runner(Arc::new(mock))
            .fix("net_proxy_active", None)
            .await
            .unwrap_err();
        assert!(err.contains("still switched on"), "{err}");
    }

    #[tokio::test]
    async fn a_refused_write_is_a_failure() {
        let mock = user_proxy_repair(
            CmdOutput::with_output(1, "", "Zugriff verweigert"),
            real_internet_settings(),
        );
        let err = NetworkModule::with_runner(Arc::new(mock))
            .fix("net_proxy_active", None)
            .await
            .unwrap_err();
        assert!(err.contains("could not be switched off"), "{err}");
    }

    #[tokio::test]
    async fn the_resolver_probe_parses() {
        let script = dns_probe_script("dns.google");
        assert_eq!(crate::utils::cmd::powershell_parse_errors(&script).await, 0);
    }
}
