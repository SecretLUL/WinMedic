//! Reading a service's start type through `sc qc`.
//!
//! `sc query` reports whether a service is running, never how it starts, so a
//! check that looked for "disabled" in its output could not fire: a disabled
//! Windows Update or VSS service went unreported on every machine. `sc qc`
//! does report the start type, and as a number — its field names are the same
//! in every display language and the number is the value Windows stores, so
//! nothing here depends on the language.

use crate::utils::cmd::CommandRunner;
use std::sync::Arc;
use std::time::Duration;

/// `START_TYPE` 2: Windows starts the service at boot.
pub const SERVICE_AUTO_START: u32 = 2;
/// `START_TYPE` 4: the service cannot be started, not even on demand.
pub const SERVICE_DISABLED: u32 = 4;

/// The `START_TYPE` number in `sc qc` output.
pub fn parse_start_type(sc_qc_output: &str) -> Option<u32> {
    sc_qc_output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "START_TYPE" {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

/// `STATE` numbers `sc query` prints, the same in every language.
pub const SERVICE_STOPPED: u32 = 1;
pub const SERVICE_START_PENDING: u32 = 2;
pub const SERVICE_RUNNING: u32 = 4;

/// The `STATE` number in `sc query` output.
pub fn parse_state(sc_query_output: &str) -> Option<u32> {
    sc_query_output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "STATE" {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

/// Whether the service runs, is stopped, ..., or `None` when `sc query` did
/// not say. `net start` and `net stop` report in the display language, and
/// `net stop` of a service that is not running fails with exit code 2.
pub async fn state(runner: &dyn CommandRunner, service: &str) -> Result<Option<u32>, String> {
    let out = runner
        .run("sc.exe", &["query", service], Duration::from_secs(8))
        .await?;
    Ok(parse_state(&out.stdout))
}

/// The service's start type, or `None` when `sc qc` did not report one (no
/// such service, access denied).
pub async fn start_type(runner: &dyn CommandRunner, service: &str) -> Result<Option<u32>, String> {
    let out = runner
        .run("sc.exe", &["qc", service], Duration::from_secs(8))
        .await?;
    Ok(parse_start_type(&out.stdout))
}

/// Starts `services`, in the order given, when dropped while still armed: a
/// repair that is cancelled, or fails, between stopping a service and starting
/// it again must not leave it stopped. Through the runner, on the runtime,
/// because a destructor cannot wait. Armed by [`Self::new`]; [`Self::disarm`]
/// once the caller has started them itself.
pub struct StartAgain {
    runner: Arc<dyn CommandRunner>,
    services: &'static [&'static str],
    armed: bool,
}

impl StartAgain {
    /// Armed: dropping the guard runs `net start` for each of `services`.
    pub fn new(runner: Arc<dyn CommandRunner>, services: &'static [&'static str]) -> Self {
        Self {
            runner,
            services,
            armed: true,
        }
    }

    /// The caller has started the services, so dropping the guard does nothing.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartAgain {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let runner = self.runner.clone();
        let services = self.services;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for svc in services {
                    let _ = runner
                        .run("net.exe", &["start", svc], Duration::from_secs(30))
                        .await;
                }
            });
        }
    }
}

/// Real `sc qc` output for other modules' tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::utils::decode::decode_output;

    /// What `sc qc <service>` prints on a German Windows 11 for a service with
    /// this start type — the captured output of a disabled service, renamed and
    /// with its start type swapped.
    pub fn sc_qc_output(service: &str, start_type: u32) -> String {
        let name = match start_type {
            2 => "AUTO_START",
            3 => "DEMAND_START",
            4 => "DISABLED",
            _ => "BOOT_START",
        };
        decode_output(include_bytes!(
            "../../tests/fixtures/console/sc_qc_disabled.bin"
        ))
        .replace("AppVClient", service)
        .replace("4   DISABLED", &format!("{start_type}   {name}"))
    }

    /// What `sc query <service>` prints for a service in this state: the
    /// captured output of a stopped service, renamed and with its state
    /// swapped.
    pub fn sc_query_output(service: &str, state: u32) -> String {
        let name = match state {
            1 => "STOPPED",
            2 => "START_PENDING",
            _ => "RUNNING",
        };
        decode_output(include_bytes!(
            "../../tests/fixtures/console/sc_query_disabled_service.bin"
        ))
        .replace("AppVClient", service)
        .replace("1  STOPPED", &format!("{state}  {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::decode::decode_output;

    // Captured on a German Windows 11. `sc` keeps its field names in English
    // there, and the start type is a number either way.
    const QC_DISABLED: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_disabled.bin");
    const QC_DEMAND: &[u8] = include_bytes!("../../tests/fixtures/console/sc_qc_demand.bin");
    const QUERY_OF_DISABLED: &[u8] =
        include_bytes!("../../tests/fixtures/console/sc_query_disabled_service.bin");

    #[test]
    fn reads_the_start_type_from_sc_qc() {
        assert_eq!(
            parse_start_type(&decode_output(QC_DISABLED)),
            Some(SERVICE_DISABLED)
        );
        assert_eq!(parse_start_type(&decode_output(QC_DEMAND)), Some(3));
    }

    #[test]
    fn sc_query_never_says_how_a_service_starts() {
        // The same disabled service, asked with `sc query`: only its state.
        // This is why the old checks never found a disabled service.
        let text = decode_output(QUERY_OF_DISABLED);
        assert!(text.contains("STOPPED"));
        assert!(!text.to_lowercase().contains("disabled"));
        assert_eq!(parse_start_type(&text), None);
    }

    #[test]
    fn reads_the_state_from_sc_query() {
        assert_eq!(
            parse_state(&decode_output(QUERY_OF_DISABLED)),
            Some(SERVICE_STOPPED)
        );
        assert_eq!(parse_state(&decode_output(QC_DEMAND)), None);
    }

    #[test]
    fn output_without_a_start_type_yields_none() {
        assert_eq!(parse_start_type(""), None);
        assert_eq!(
            parse_start_type(
                "[SC] OpenService FEHLER 1060:\n\nDer angegebene Dienst ist nicht installiert."
            ),
            None
        );
    }
}
