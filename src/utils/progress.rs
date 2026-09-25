//! How far a Windows tool says it got.
//!
//! DISM and SFC draw their progress into a single line: they return to its
//! start with a carriage return and write it again, `[====  62.3%  ]` and
//! `Verification 45% complete.` The number in front of the `%` is the one
//! language-neutral part, so that is what is read.

/// The percentage `line` reports, if it reports one.
///
/// Takes a decimal comma as well as a point and allows a space before the
/// sign, the way German text writes `45 %`.
pub fn percent(line: &str) -> Option<f32> {
    line.match_indices('%').find_map(|(at, _)| {
        let before = line[..at].trim_end_matches([' ', '\u{a0}', '\u{202f}']);
        let digits = before.len()
            - before
                .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ',')
                .len();
        let number = before[before.len() - digits..].trim_start_matches(['.', ',']);
        let value: f32 = number.replace(',', ".").parse().ok()?;
        (0.0..=100.0).contains(&value).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_progress_bar_is_read() {
        assert_eq!(
            percent("[==========================62.3%===                        ]"),
            Some(62.3)
        );
        assert_eq!(percent("[===========100.0%===========]"), Some(100.0));
    }

    #[test]
    fn a_sentence_is_read_in_either_language() {
        assert_eq!(percent("Verification 45% complete."), Some(45.0));
        assert_eq!(percent("Überprüfung 45 % abgeschlossen."), Some(45.0));
        assert_eq!(percent("[====  62,3%  ]"), Some(62.3));
    }

    #[test]
    fn a_line_without_a_percentage_is_not() {
        assert_eq!(percent("Image Version: 10.0.26200.9457"), None);
        assert_eq!(percent("The operation completed successfully."), None);
        assert_eq!(percent("% of nothing"), None);
        assert_eq!(percent("250%"), None);
    }
}
