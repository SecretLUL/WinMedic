//! Turning a child process's output bytes into text.
//!
//! Windows console tools do not agree on an encoding once their output goes
//! into a pipe instead of a console window:
//!
//! - `dism.exe`, `chkdsk.exe`, `fsutil.exe` and most of the classic tools write
//!   in the OEM code page — 850 on a German system, 437 on an English one — so
//!   "Ausführen" arrives as `Ausf\x81hren`;
//! - `wevtutil.exe` and `pnputil.exe` write in the ANSI code page — 1252 on
//!   both — so "für" arrives as `f\xFCr`, which the OEM code page reads as
//!   "f³r";
//! - `sfc.exe` writes UTF-16LE;
//! - `netsh.exe`, and PowerShell once [`crate::utils::cmd::run_powershell`] has
//!   told it to, write UTF-8.
//!
//! Decoding all of it as UTF-8 turned every umlaut the first group printed into
//! U+FFFD, so no German keyword containing one could ever match, and a line
//! reader gave up at the first such line and dropped the rest of the output.
//!
//! The rule here: UTF-16LE when the bytes look like it, otherwise each line as
//! UTF-8 when it is valid UTF-8 and in the tool's [`CodePage`] when it is not.
//! Text in either code page with a byte above 0x7F is almost never valid
//! UTF-8, so the two cannot be mistaken for each other in practice.

use super::progress::percent;

/// The code page a tool writes into a pipe when its text is neither UTF-8
/// nor UTF-16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePage {
    Oem,
    Ansi,
}

impl CodePage {
    /// The one `program` writes in, by its file name.
    pub fn of(program: &str) -> Self {
        let name = program.rsplit(['\\', '/']).next().unwrap_or(program);
        let stem = name.split('.').next().unwrap_or(name);
        if stem.eq_ignore_ascii_case("wevtutil") || stem.eq_ignore_ascii_case("pnputil") {
            CodePage::Ansi
        } else {
            CodePage::Oem
        }
    }
}

/// Decode a complete output buffer, line endings included, from a tool that
/// writes in the OEM code page.
pub fn decode_output(bytes: &[u8]) -> String {
    decode_output_in(bytes, CodePage::Oem)
}

/// Decode a complete output buffer, line endings included.
pub fn decode_output_in(bytes: &[u8], page: CodePage) -> String {
    if looks_like_utf16le(bytes) {
        return decode_utf16le(bytes);
    }
    let bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    bytes
        .split_inclusive(|&b| b == b'\n')
        .map(|line| decode_byte_line(line, page))
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
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .position(|unit| *unit == [b'\n', 0])
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

    /// The progress the line still being written shows right now.
    ///
    /// SFC draws its progress into one line, ending every update with a
    /// carriage return and the line itself only at 100 %. Split on newlines
    /// alone, none of it arrived before SFC had finished. This is the last
    /// finished redraw that carries a percentage; what follows the last
    /// carriage return can stop mid-word, where a 4 KB block of SFC's output
    /// ended.
    pub fn progress(&self) -> Option<String> {
        let utf16 = self.utf16?;
        let mut start = self.pending.len().saturating_sub(PROGRESS_TAIL);
        if utf16 {
            start += start % 2;
        }
        let tail = &self.pending[start..];
        let text = if utf16 {
            decode_utf16le(tail)
        } else {
            decode_byte_line(tail, CodePage::Oem)
        };
        text.rsplit('\r')
            .skip(1)
            .map(str::trim)
            .find(|redraw| percent(redraw).is_some())
            .map(str::to_string)
    }

    fn decode_line(&self, line: &[u8]) -> String {
        let text = if self.utf16 == Some(true) {
            decode_utf16le(line)
        } else {
            decode_byte_line(line.strip_prefix(UTF8_BOM).unwrap_or(line), CodePage::Oem)
        };
        shown(&text).to_string()
    }
}

/// How much of an unfinished line [`LineDecoder::progress`] looks at: the
/// newest few redraws, not the thousand before them.
const PROGRESS_TAIL: usize = 1024;

/// What a console shows of a line: the last thing written over it after a
/// carriage return. A line DISM redrew a thousand times is its final bar.
fn shown(text: &str) -> &str {
    let text = text.trim_end_matches('\r');
    text.rsplit('\r')
        .find(|redraw| !redraw.trim().is_empty())
        .unwrap_or(text)
}

/// Whether `bytes` are UTF-16LE text: a byte order mark, or mostly code units
/// whose high byte is zero, which is what ASCII-range text looks like in it.
/// Text in a byte encoding has no NUL bytes at all.
fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return true;
    }
    let units = bytes.as_chunks::<2>().0.iter().take(128);
    let total = units.len();
    let ascii_units = units.filter(|unit| unit[1] == 0 && unit[0] != 0).count();
    total > 0 && ascii_units * 2 > total
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&unit| u16::from_le_bytes(unit))
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode_byte_line(line: &[u8], page: CodePage) -> String {
    match std::str::from_utf8(line) {
        Ok(text) => text.to_string(),
        Err(_) => code_page_to_string(line, page),
    }
}

/// Decode bytes in the system's OEM or ANSI code page.
#[cfg(windows)]
fn code_page_to_string(bytes: &[u8], page: CodePage) -> String {
    use windows_sys::Win32::Globalization::{CP_ACP, CP_OEMCP, MultiByteToWideChar};

    let code_page = match page {
        CodePage::Oem => CP_OEMCP,
        CodePage::Ansi => CP_ACP,
    };

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
        let needed =
            MultiByteToWideChar(code_page, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0);
        if needed <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; needed as usize];
        let written =
            MultiByteToWideChar(code_page, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), needed);
        if written <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        String::from_utf16_lossy(&wide[..written as usize])
    }
}

#[cfg(not(windows))]
fn code_page_to_string(bytes: &[u8], _page: CodePage) -> String {
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
    const DISM_PROGRESS: &[u8] =
        include_bytes!("../../tests/fixtures/console/dism_scanhealth_progress.bin");
    const SFC_PROGRESS: &[u8] =
        include_bytes!("../../tests/fixtures/console/sfc_verifyonly_progress_de.bin");
    const PNPUTIL_DE: &[u8] =
        include_bytes!("../../tests/fixtures/console/pnputil_restart_device_denied_de.bin");
    const WEVTUTIL_DE: &[u8] =
        include_bytes!("../../tests/fixtures/events/wevtutil_wu_installed_19_de.bin");

    #[test]
    fn wevtutil_and_pnputil_write_in_the_ansi_code_page() {
        assert_eq!(CodePage::of("pnputil.exe"), CodePage::Ansi);
        assert_eq!(
            CodePage::of(r"C:\Windows\System32\wevtutil.exe"),
            CodePage::Ansi
        );
        assert_eq!(CodePage::of("WEVTUTIL"), CodePage::Ansi);
        assert_eq!(CodePage::of("dism.exe"), CodePage::Oem);

        // The ANSI code page decides these, so they only hold where it has
        // the German letters and the en dash in it (1252 does).
        let pnputil = decode_output_in(PNPUTIL_DE, CodePage::Ansi);
        assert!(
            pnputil.contains("Gerät konnte nicht neu gestartet werden"),
            "{pnputil}"
        );
        let wevtutil = decode_output_in(WEVTUTIL_DE, CodePage::Ansi);
        assert!(
            wevtutil.contains(
                "Security Intelligence-Update für Microsoft Defender Antivirus – KB2267602"
            ),
            "{wevtutil}"
        );
        // Read in the OEM code page, as all output was before.
        assert!(decode_output(WEVTUTIL_DE).contains("Update f³r Microsoft"));
    }

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

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn a_redrawn_line_is_what_the_console_shows() {
        let mut decoder = LineDecoder::new();
        assert_eq!(
            decoder.push(b"[=   10.0%   ]\r[==  20.0%   ]\r\nDone.\r\n"),
            vec!["[==  20.0%   ]".to_string(), "Done.".to_string()]
        );
    }

    #[test]
    fn progress_arrives_before_its_line_ends() {
        let mut decoder = LineDecoder::new();
        assert_eq!(
            decoder
                .push(b"Image Version: 10.0\r\n\r\n[=   10.0%   ]\r[==  2")
                .len(),
            2
        );
        assert_eq!(decoder.progress().as_deref(), Some("[=   10.0%   ]"));
        decoder.push(b"0.0%   ]\r");
        assert_eq!(decoder.progress().as_deref(), Some("[==  20.0%   ]"));
    }

    #[test]
    fn utf16_progress_arrives_before_its_line_ends() {
        let mut decoder = LineDecoder::new();
        let bytes = utf16("\r\nVerification 5% complete.\rVerification 6% complete.\r");
        for chunk in bytes.chunks(5) {
            decoder.push(chunk);
        }
        assert_eq!(
            decoder.progress().as_deref(),
            Some("Verification 6% complete.")
        );
    }

    /// Into a pipe, DISM writes each step of its bar as a line of its own,
    /// `\r[==  4.9%  ] \r\n`, flushed as it goes, in 64-byte pieces.
    #[test]
    fn dism_writes_every_step_of_its_bar_as_a_line() {
        let mut decoder = LineDecoder::new();
        let mut lines = Vec::new();
        for chunk in DISM_PROGRESS.chunks(64) {
            lines.extend(decoder.push(chunk));
        }
        lines.extend(decoder.finish());

        assert!(lines.iter().all(|l| !l.contains('\r')), "{lines:?}");
        let steps: Vec<f32> = lines.iter().filter_map(|l| percent(l)).collect();
        assert_eq!(steps.len(), 118);
        assert_eq!((steps[0], steps[117]), (4.9, 100.0));
        assert!(steps.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(
            lines[lines.len() - 2..],
            [
                "The component store is repairable.",
                "The operation completed successfully."
            ]
        );
    }

    /// SFC redraws its progress within one line and ends it at 100 %. Into
    /// a pipe it writes in 4 KB blocks, fed here as they arrived; each shows
    /// how far SFC had got long before the line was finished. The first block
    /// ends in the middle of "Überprüfung 27 % abgeschl", so it reports 26.
    #[test]
    fn sfc_progress_is_seen_block_by_block() {
        let mut decoder = LineDecoder::new();
        let mut lines = Vec::new();
        let mut seen = Vec::new();
        for block in [
            &SFC_PROGRESS[..4104],
            &SFC_PROGRESS[4104..8200],
            &SFC_PROGRESS[8200..12296],
        ] {
            lines.extend(decoder.push(block));
            seen.extend(decoder.progress());
        }
        assert_eq!(
            seen,
            [
                "Überprüfung 26 % abgeschlossen.",
                "Überprüfung 55 % abgeschlossen.",
                "Überprüfung 83 % abgeschlossen.",
            ]
        );

        lines.extend(decoder.push(&SFC_PROGRESS[12296..]));
        lines.extend(decoder.finish());
        assert!(lines.iter().all(|l| !l.contains('\r')), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "Überprüfung 100 % abgeschlossen.")
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Integritätsverletzungen gefunden"))
        );
    }

    #[test]
    fn a_line_without_a_percentage_shows_no_progress() {
        let mut decoder = LineDecoder::new();
        decoder.push(b"Beginning system scan.");
        assert_eq!(decoder.progress(), None);
    }

    #[test]
    fn empty_output_decodes_to_nothing() {
        assert_eq!(decode_output(b""), "");
        assert_eq!(LineDecoder::new().finish(), None);
    }
}
