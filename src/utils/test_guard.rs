//! Helpers for the guard tests that keep `cargo test` off the real machine.
//!
//! Running the suite used to open browser windows and raise UAC prompts on
//! whoever ran it. Every action that reaches the desktop now sits behind a seam
//! whose default does nothing ([`crate::app::SystemActions`],
//! [`crate::safety::restore_point::RestorePointService`]); the guard tests are
//! how that stays true once the next test file is written.

/// Every place in `tests/` where `needle` appears outside a line comment,
/// reported as `path:line`.
///
/// Deliberately a plain text scan: it does not need to understand Rust, it
/// needs to be impossible to fool by accident.
pub fn integration_test_lines_mentioning(needle: &str) -> Vec<String> {
    let mut offenders = Vec::new();
    let mut pending = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")];

    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (number, line) in source.lines().enumerate() {
                let code = line.trim_start();
                if !code.starts_with("//") && code.contains(needle) {
                    offenders.push(format!("{}:{}", path.display(), number + 1));
                }
            }
        }
    }

    offenders
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scanner is only worth anything if it can actually find something, so
    /// look for a string this repository's tests are full of.
    #[test]
    fn the_scanner_finds_what_is_there() {
        assert!(
            !integration_test_lines_mentioning("#[test]").is_empty(),
            "the tests directory scan found nothing at all - is the path wrong?"
        );
        assert!(integration_test_lines_mentioning("WinMedicDefinitelyNotInAnyTest").is_empty());
    }
}
