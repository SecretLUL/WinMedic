//! Turning a child process's output bytes into text.
//!
//! Windows console tools do not agree on an encoding once their output goes
//! into a pipe instead of a console window:
//!
//! - `dism.exe`, `chkdsk.exe`, `fsutil.exe` and most of the classic tools write
//!   in the OEM code page — 850 on a German system, 437 on an English one — so
//!   "Ausführen" arrives as `Ausf\x81hren`;
//! - `sfc.exe` writes UTF-16LE;
//! - `netsh.exe`, and PowerShell once [`crate::utils::cmd::run_powershell`] has
//!   told it to, write UTF-8.
//!
//! Decoding all of it as UTF-8 turned every umlaut the first group printed into
//! U+FFFD, so no German keyword containing one could ever match, and a line
//! reader gave up at the first such line and dropped the rest of the output.
//!
//! The rule here: UTF-16LE when the bytes look like it, otherwise each line as
//! UTF-8 when it is valid UTF-8 and in the OEM code page when it is not. OEM
//! text with a byte above 0x7F is almost never valid UTF-8, so the two cannot
//! be mistaken for each other in practice.

/// Decode a complete output buffer, line endings included.
pub fn decode_output(bytes: &[u8]) -> String {
    if looks_like_utf16le(bytes) {
        return decode_utf16le(bytes);
    }
    let bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    bytes
        .split_inclusive(|&b| b == b'\n')
        .map(decode_byte_line)
        .collect()
}

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Splits a stream of output bytes into decoded lines as they arrive.
///
/// The encoding is settled from the first bytes, because a UTF-16 stream has to
/// be split on the two-byte newline rather than on every `0x0A`.
#[derive(Debug, Default)]
pub struct LineDecoder {
    utf16: Option<bool>,
    pending: Vec<u8>,
}

impl LineDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next chunk and take every line it completed, without its line
    /// ending.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.pending.extend_from_slice(chunk);
        if self.utf16.is_none() && self.pending.len() >= 2 {
            self.utf16 = Some(looks_like_utf16le(&self.pending));
        }
        let Some(utf16) = self.utf16 else {
            return Vec::new();
        };

        let mut lines = Vec::new();
        loop {
            let end = if utf16 {
                self.pending
                    .chunks_exact(2)
                    .position(|unit| unit == [b'\n', 0])
                    .map(|unit| (unit * 2, 2))
            } else {
                self.pending
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|at| (at, 1))
            };
            let Some((at, newline_len)) = end else {
                break;
            };
            let line: Vec<u8> = self.pending.drain(..at + newline_len).take(at).collect();
            lines.push(self.decode_line(&line));
        }
        lines
    }

    /// The last line, when the output did not end with a newline.
    pub fn finish(mut self) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        if self.utf16.is_none() {
            self.utf16 = Some(looks_like_utf16le(&self.pending));
        }
        let rest = std::mem::take(&mut self.pending);
        Some(self.decode_line(&rest))
    }

    fn decode_line(&self, line: &[u8]) -> String {
        let text = if self.utf16 == Some(true) {
            decode_utf16le(line)
        } else {
            decode_byte_line(line.strip_prefix(UTF8_BOM).unwrap_or(line))
        };
        text.trim_end_matches('\r').to_string()
    }
}

/// Whether `bytes` are UTF-16LE text: a byte order mark, or mostly code units
/// whose high byte is zero, which is what ASCII-range text looks like in it.
/// Text in a byte encoding has no NUL bytes at all.
fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return true;
    }
    let units = bytes.chunks_exact(2).take(128);
    let total = units.len();
    let ascii_units = units.filter(|unit| unit[1] == 0 && unit[0] != 0).count();
    total > 0 && ascii_units * 2 > total
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode_byte_line(line: &[u8]) -> String {
    match std::str::from_utf8(line) {
        Ok(text) => text.to_string(),
        Err(_) => oem_to_string(line),
    }
}

/// Decode bytes in the system's OEM code page.
#[cfg(windows)]
fn oem_to_string(bytes: &[u8]) -> String {
    use windows_sys::Win32::Globalization::{CP_OEMCP, MultiByteToWideChar};

    let Ok(len) = i32::try_from(bytes.len()) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    if len == 0 {
        return String::new();
    }
    // SAFETY: the input pointer and length describe `bytes`; the first call
    // writes nothing and returns the number of UTF-16 units needed, the second
    // writes at most that many into a buffer of exactly that size.
    unsafe {
        let needed = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0);
        if needed <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; needed as usize];
        let written =
            MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), needed);
        if written <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        String::from_utf16_lossy(&wide[..written as usize])
    }
}

#[cfg(not(windows))]
fn oem_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from real tools on a German Windows 11, byte for byte as they
    // arrive through the pipe. See tests/fixtures/README.md.
    const DISM_DE: &[u8] =
        include_bytes!("../../tests/fixtures/console/dism_elevation_required_de.bin");
    const SFC_DE: &[u8] =
        include_bytes!("../../tests/fixtures/console/sfc_elevation_required_de.bin");
    const NETSH_DE: &[u8] =
        include_bytes!("../../tests/fixtures/console/netsh_winsock_catalog_de.bin");
    const POWERSHELL_UTF8: &[u8] =
        include_bytes!("../../tests/fixtures/console/powershell_utf8.bin");

    #[test]
    fn dism_output_in_the_oem_code_page_keeps_its_umlauts() {
        // The OEM code page decides this one, so it only holds where that is a
        // Latin code page with the German letters in it (437 and 850 both are).
        let text = decode_output(DISM_DE);
        assert!(!text.contains('\u{FFFD}'), "{text}");
        assert!(text.contains("Ausführen von DISM"), "{text}");
        assert!(text.contains("erhöhte Rechte"), "{text}");
    }

    #[test]
    fn sfc_output_is_recognised_as_utf16() {
        let text = decode_output(SFC_DE);
        assert!(
            text.contains("Sie müssen als Administrator angemeldet sein"),
            "{text}"
        );
        assert!(!text.contains('\0'));
    }

    #[test]
    fn utf8_output_is_taken_as_it_is() {
        assert_eq!(decode_output(POWERSHELL_UTF8).trim(), "Grüße Ä");
        let netsh = decode_output(NETSH_DE);
        assert!(netsh.contains("Max. Adresslänge"), "netsh writes UTF-8");
    }

    #[test]
    fn a_utf8_byte_order_mark_is_dropped() {
        assert_eq!(decode_output(b"\xEF\xBB\xBFok\r\n"), "ok\r\n");
    }

    #[test]
    fn the_line_decoder_splits_utf16_on_its_own_newline() {
        let mut decoder = LineDecoder::new();
        let mut lines = Vec::new();
        // Fed in awkward pieces, the way a pipe hands them over.
        for chunk in SFC_DE.chunks(7) {
            lines.extend(decoder.push(chunk));
        }
        lines.extend(decoder.finish());
        assert!(
            lines
                .iter()
                .any(|l| l == "ausführen, um das SFC-Hilfsprogramm verwenden zu können."),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .all(|l| !l.contains('\0') && !l.ends_with('\r'))
        );
    }

    #[test]
    fn the_line_decoder_keeps_reading_past_an_oem_line() {
        let mut decoder = LineDecoder::new();
        let mut lines = decoder.push(DISM_DE);
        lines.extend(decoder.finish());
        let joined = lines.join("\n");
        // The old line reader stopped at the first line that was not UTF-8,
        // which here is the very one that says what went wrong.
        assert!(joined.contains("erhöhte Rechte erforderlich"), "{joined}");
        assert!(joined.contains("abzuschließen"), "{joined}");
    }

    #[test]
    fn a_trailing_partial_line_is_not_lost() {
        let mut decoder = LineDecoder::new();
        assert_eq!(decoder.push(b"first\r\nsec"), vec!["first".to_string()]);
        assert_eq!(decoder.push(b"ond"), Vec::<String>::new());
        assert_eq!(decoder.finish().as_deref(), Some("second"));
    }

    #[test]
    fn empty_output_decodes_to_nothing() {
        assert_eq!(decode_output(b""), "");
        assert_eq!(LineDecoder::new().finish(), None);
    }
}
