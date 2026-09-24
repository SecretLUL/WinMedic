//! Reading the registry through `reg query`.
//!
//! Going through the [`CommandRunner`] keeps a module's registry checks as
//! testable as everything else it asks Windows. `reg` prints key paths, value
//! names, `REG_*` type names and data identically in every display language;
//! only its error messages are translated, and those come with exit code 1,
//! which is all that is read of them.

use crate::utils::cmd::CommandRunner;
use std::time::Duration;

/// One value as `reg query` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValue {
    pub name: String,
    /// `REG_DWORD`, `REG_SZ`, ...
    pub kind: String,
    /// The data as printed: `0x1` for a DWORD, the text for a string.
    pub data: String,
}

impl RegValue {
    /// The value as a number, for `REG_DWORD` and `REG_QWORD`.
    pub fn number(&self) -> Option<u64> {
        let hex = self.data.trim().strip_prefix("0x")?;
        u64::from_str_radix(hex, 16).ok()
    }
}

/// A key and the values directly under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegKeyValues {
    pub key: String,
    pub values: Vec<RegValue>,
}

impl RegKeyValues {
    pub fn value(&self, name: &str) -> Option<&RegValue> {
        self.values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(name))
    }
}

/// Parse the output of `reg query <key> [/v name] [/s]`.
pub fn parse_reg_query(output: &str) -> Vec<RegKeyValues> {
    let mut keys: Vec<RegKeyValues> = Vec::new();
    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("HKEY_") {
            keys.push(RegKeyValues {
                key: line.trim().to_string(),
                values: Vec::new(),
            });
            continue;
        }
        let Some(body) = line.strip_prefix("    ") else {
            continue;
        };
        // `<name>    REG_<TYPE>    <data>`; the data may be empty.
        let Some(type_at) = body.find("    REG_") else {
            continue;
        };
        let name = body[..type_at].to_string();
        let rest = &body[type_at + 4..];
        let (kind, data) = match rest.find("    ") {
            Some(end) => (&rest[..end], &rest[end + 4..]),
            None => (rest, ""),
        };
        if let Some(key) = keys.last_mut() {
            key.values.push(RegValue {
                name,
                kind: kind.trim().to_string(),
                data: data.to_string(),
            });
        }
    }
    keys
}

/// The values of `key` (and of every subkey, with `recursive`), or `None`
/// when the key does not exist.
pub async fn query(
    runner: &dyn CommandRunner,
    key: &str,
    recursive: bool,
) -> Result<Option<Vec<RegKeyValues>>, String> {
    let mut args = vec!["query", key];
    if recursive {
        args.push("/s");
    }
    let out = runner
        .run("reg.exe", &args, Duration::from_secs(10))
        .await?;
    match out.exit_code {
        Some(0) => Ok(Some(parse_reg_query(&out.stdout))),
        // "The system was unable to find the specified registry key or value."
        Some(1) => Ok(None),
        code => Err(format!(
            "reg query {key} failed (exit code {code:?}): {}",
            out.stderr.trim()
        )),
    }
}

/// The value `name` under exactly `key` among `keys`.
pub fn find<'a>(keys: &'a [RegKeyValues], key: &str, name: &str) -> Option<&'a RegValue> {
    let wanted = expand_hive(key);
    keys.iter()
        .find(|k| expand_hive(&k.key).eq_ignore_ascii_case(&wanted))
        .and_then(|k| k.value(name))
}

/// `reg` accepts `HKLM\...` but prints `HKEY_LOCAL_MACHINE\...`.
fn expand_hive(key: &str) -> String {
    for (short, long) in [
        ("HKLM\\", "HKEY_LOCAL_MACHINE\\"),
        ("HKCU\\", "HKEY_CURRENT_USER\\"),
    ] {
        if let Some(rest) = key.strip_prefix(short) {
            return format!("{long}{rest}");
        }
    }
    key.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cmd::{CmdOutput, MockCommandRunner};
    use crate::utils::decode::decode_output;

    // Captured on a German Windows 11; see tests/fixtures/README.md.
    const WU_POLICY: &[u8] = include_bytes!("../../tests/fixtures/console/reg_query_wu_policy.bin");
    const WINHTTP: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_winhttp_direct.bin");
    const MISSING_DE: &[u8] =
        include_bytes!("../../tests/fixtures/console/reg_query_missing_key_de.bin");

    #[test]
    fn reads_keys_values_and_types() {
        let keys = parse_reg_query(&decode_output(WU_POLICY));
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].key,
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        );
        let value = keys[0].value("ExcludeWUDriversInQualityUpdate").unwrap();
        assert_eq!(value.kind, "REG_DWORD");
        assert_eq!(value.number(), Some(1));
    }

    #[test]
    fn reads_binary_data() {
        let keys = parse_reg_query(&decode_output(WINHTTP));
        let value = keys[0].value("WinHttpSettings").unwrap();
        assert_eq!(value.kind, "REG_BINARY");
        assert_eq!(value.data, "1800000000000000010000000000000000000000");
    }

    #[test]
    fn names_with_spaces_and_empty_data() {
        let keys = parse_reg_query(
            "\r\nHKEY_CURRENT_USER\\Software\\X\r\n    My Value    REG_SZ    a  b\r\n    Empty    REG_SZ    \r\n",
        );
        assert_eq!(keys[0].value("My Value").unwrap().data, "a  b");
        assert_eq!(keys[0].value("Empty").unwrap().data, "");
    }

    #[test]
    fn find_accepts_the_short_hive_name() {
        let keys = parse_reg_query(&decode_output(WU_POLICY));
        assert!(
            find(
                &keys,
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                "ExcludeWUDriversInQualityUpdate"
            )
            .is_some()
        );
        assert!(
            find(
                &keys,
                r"HKLM\SOFTWARE\Other",
                "ExcludeWUDriversInQualityUpdate"
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn a_missing_key_is_none_not_an_error() {
        let mock = MockCommandRunner::new();
        mock.add_response(
            "reg.exe",
            CmdOutput {
                success: false,
                exit_code: Some(1),
                stdout: String::new(),
                stderr: decode_output(MISSING_DE),
            },
        );
        assert_eq!(query(&mock, r"HKLM\SOFTWARE\Nope", false).await, Ok(None));
    }
}
