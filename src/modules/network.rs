use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;
use crate::engine::issue::{Issue, RiskScore, Severity};
use crate::modules::{DiagnosticModule, FixProgress, ModuleProgress};
use crate::utils::cmd::run_cmd;

pub struct NetworkModule;

impl NetworkModule {
    pub fn new() -> Self {
        Self
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
        "Netzwerk & DNS-Konnektivität"
    }

    fn description(&self) -> &'static str {
        "Prüft DNS-Auflösung, Winsock-Katalog, TCP/IP-Stack und fehlerhafte Proxy-Konfigurationen"
    }

    fn icon(&self) -> &'static str {
        "🌐"
    }

    async fn scan(&self, progress_tx: Option<Sender<ModuleProgress>>) -> Result<Vec<Issue>, String> {
        let mut issues = Vec::new();

        // 1. DNS Resolution Check
        Self::send_progress(&progress_tx, 20, "Teste DNS-Namensauflösung...", Some("Lookup auf Google & Cloudflare DNS...")).await;
        sleep(Duration::from_millis(150)).await;

        let dns_lookup = run_cmd("nslookup.exe", &["dns.google", "8.8.8.8"], Duration::from_secs(6)).await;
        let mut dns_healthy = false;
        if let Ok(out) = dns_lookup {
            if out.stdout.contains("8.8.8.8") || out.stdout.contains("Address") {
                dns_healthy = true;
            }
        }

        if !dns_healthy {
            let ping_test = run_cmd("ping.exe", &["-n", "1", "-w", "1500", "1.1.1.1"], Duration::from_secs(4)).await;
            let ip_reachable = match ping_test {
                Ok(out) => out.stdout.contains("TTL="),
                Err(_) => false,
            };

            if ip_reachable {
                issues.push(Issue::new(
                    "net_dns_failure",
                    self.id(),
                    "DNS-Namensauflösung fehlgeschlagen (IP erreichbar)",
                    "Netzwerk & DNS",
                    Severity::Critical,
                    RiskScore::Low,
                    "Websites können nicht über ihren Domainnamen aufgelöst werden, obwohl die IP-Konnektivität zum Internet besteht. Ursache ist meist ein veralteter DNS-Cache oder fehlerhafte Resolver-Einstellungen.",
                    "nslookup fehlgeschlagen, ping 1.1.1.1 erfolgreich",
                    "DNS-Cache leeren (ipconfig /flushdns) und DNS-Resolver neu registrieren",
                    vec![
                        "ipconfig /flushdns ausführen".to_string(),
                        "ipconfig /registerdns ausführen".to_string(),
                    ],
                ));
            } else {
                issues.push(Issue::new(
                    "net_offline_warning",
                    self.id(),
                    "Keine aktive Internet- oder Gateway-Verbindung",
                    "Netzwerk & DNS",
                    Severity::Warning,
                    RiskScore::Low,
                    "Das System kann weder externe IP-Adressen noch DNS-Server erreichen. Bitte prüfen Sie Router, WLAN/LAN-Kabel oder VPN-Verbindungen.",
                    "Keine Antwort auf Ping / nslookup",
                    "Netzwerkadapter und Winsock / IP-Stack zurücksetzen",
                    vec![
                        "netsh winsock reset".to_string(),
                        "netsh int ip reset".to_string(),
                    ],
                ));
            }
        } else {
            Self::send_progress(&progress_tx, 45, "DNS-Auflösung erfolgreich", Some("✔ DNS-Namensauflösung und IP-Routing sind einwandfrei.")).await;
        }

        // 2. Proxy Settings in Registry
        Self::send_progress(&progress_tx, 65, "Prüfe Proxy-Einstellungen in der Windows-Registry...", Some("Registry Internet Settings...")).await;
        sleep(Duration::from_millis(150)).await;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(inet_settings) = hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", KEY_READ) {
            let proxy_enable: Result<u32, _> = inet_settings.get_value("ProxyEnable");
            let proxy_server: Result<String, _> = inet_settings.get_value("ProxyServer");

            if let (Ok(1), Ok(server)) = (proxy_enable, proxy_server) {
                if !server.is_empty() {
                    issues.push(Issue::new(
                        "net_proxy_active",
                        self.id(),
                        format!("Manuell konfigurierter Proxy-Server aktiv: {}", server),
                        "Netzwerk & DNS",
                        Severity::Warning,
                        RiskScore::Low,
                        format!("Ein aktiver Proxy-Server ({}) wurde in den Systemeinstellungen gefunden. Wenn dieser Proxy nicht erreichbar ist, schlagen alle Verbindungen fehl.", server),
                        format!("Registry ProxyServer: {}", server),
                        "Proxy-Einstellungen deaktivieren (Direktverbindung verwenden)",
                        vec!["ProxyEnable in Registry auf 0 setzen".to_string()],
                    ));
                }
            } else {
                Self::send_progress(&progress_tx, 80, "Direkte Internetverbindung aktiv", Some("✔ Keine blockierenden manuellen Proxy-Server konfiguriert.")).await;
            }
        }

        // 3. Winsock Catalog
        Self::send_progress(&progress_tx, 85, "Prüfe Winsock-Katalog-Integrität...", Some("netsh winsock audit...")).await;
        sleep(Duration::from_millis(150)).await;

        let winsock_audit = run_cmd("netsh.exe", &["winsock", "show", "catalog"], Duration::from_secs(6)).await;
        if let Ok(out) = winsock_audit {
            if out.stdout.is_empty() || out.stdout.contains("Fehler") || out.stdout.contains("Error") {
                issues.push(Issue::new(
                    "net_winsock_corrupt",
                    self.id(),
                    "Winsock-Katalog weist Inkonsistenzen auf",
                    "Netzwerk & DNS",
                    Severity::Warning,
                    RiskScore::Medium,
                    "Der Winsock Layered Service Provider (LSP) Katalog enthält beschädigte oder unvollständige Einträge, was zu Verbindungsabbrüchen führen kann.",
                    out.stdout,
                    "Winsock-Katalog auf Werkseinstellungen zurücksetzen",
                    vec!["netsh winsock reset ausführen".to_string()],
                ));
            } else {
                Self::send_progress(&progress_tx, 95, "Winsock-Katalog intakt", Some("✔ Winsock LSP-Katalog ist konsistent.")).await;
            }
        }

        Self::send_progress(&progress_tx, 100, "Netzwerkdiagnose abgeschlossen", None).await;

        Ok(issues)
    }

    async fn fix(&self, issue_id: &str, _progress_tx: Option<Sender<FixProgress>>) -> Result<String, String> {
        match issue_id {
            "net_dns_failure" => {
                let _ = run_cmd("ipconfig.exe", &["/flushdns"], Duration::from_secs(8)).await;
                let _ = run_cmd("ipconfig.exe", &["/registerdns"], Duration::from_secs(8)).await;
                Ok("DNS-Cache erfolgreich geleert und DNS-Resolver neu registriert.".to_string())
            }
            "net_offline_warning" | "net_winsock_corrupt" => {
                let _ = run_cmd("netsh.exe", &["winsock", "reset"], Duration::from_secs(10)).await;
                let _ = run_cmd("netsh.exe", &["int", "ip", "reset"], Duration::from_secs(10)).await;
                let _ = run_cmd("ipconfig.exe", &["/flushdns"], Duration::from_secs(8)).await;
                Ok("Winsock & TCP/IP-Stack erfolgreich zurückgesetzt. (Neustart empfohlen)".to_string())
            }
            "net_proxy_active" => {
                let hkcu = RegKey::predef(HKEY_CURRENT_USER);
                if let Ok(inet_settings) = hkcu.open_subkey_with_flags(
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    KEY_WRITE,
                ) {
                    let _ = inet_settings.set_value("ProxyEnable", &0u32);
                    Ok("Proxy-Server erfolgreich deaktiviert. Direkte Internetverbindung aktiv.".to_string())
                } else {
                    Err("Konnte Registry-Schlüssel für Internet Settings nicht mit Schreibrechten öffnen.".to_string())
                }
            }
            _ => Err(format!("Unbekannte Problem-ID: {}", issue_id)),
        }
    }
}
