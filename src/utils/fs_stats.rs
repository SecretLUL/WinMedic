//! Shared directory measurement.
//!
//! Several diagnostic modules need "how big is this tree, and how many files".
//! They used to each carry their own `read_dir` loop, which drifted apart on the
//! questions that actually matter — junction traversal, whether unreadable
//! subtrees abort the walk, and where the byte-to-megabyte rounding happens.
//! One implementation, one set of answers.

use std::path::Path;

/// File count and total size of a directory tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirStats {
    pub bytes: u64,
    pub files: usize,
}

/// Recursively total the file count and byte size under `path`.
///
/// Deliberate behaviours, relied on by every caller:
///
/// - `symlink_metadata` is used rather than `metadata`, so symlinks and Windows
///   directory junctions are measured as the links they are and never followed.
///   A junction pointing back at an ancestor would otherwise recurse forever.
/// - An unreadable directory contributes zero instead of failing the walk.
///   Callers measure system locations where access-denied subtrees are routine.
/// - Totals are returned in bytes; rounding to larger units is the caller's job,
///   so per-file truncation can never silently discard small files.
pub fn dir_stats_recursive(path: &Path) -> DirStats {
    let mut stats = DirStats::default();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = p.symlink_metadata() {
                if meta.is_file() || meta.is_symlink() {
                    stats.bytes += meta.len();
                    stats.files += 1;
                } else if meta.is_dir() {
                    let sub = dir_stats_recursive(&p);
                    stats.bytes += sub.bytes;
                    stats.files += sub.files;
                }
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, create_dir_all};
    use std::io::Write;

    #[test]
    fn test_dir_stats_recursive_counts_nested_files() {
        let root = std::env::temp_dir().join(format!("winmedic_fs_stats_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        create_dir_all(root.join("sub/deep")).unwrap();
        File::create(root.join("a.bin"))
            .unwrap()
            .write_all(&[0u8; 10])
            .unwrap();
        File::create(root.join("sub/b.bin"))
            .unwrap()
            .write_all(&[0u8; 20])
            .unwrap();
        File::create(root.join("sub/deep/c.bin"))
            .unwrap()
            .write_all(&[0u8; 30])
            .unwrap();

        let stats = dir_stats_recursive(&root);
        assert_eq!(stats.files, 3);
        assert_eq!(stats.bytes, 60);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_dir_stats_recursive_missing_path_is_zero() {
        let stats = dir_stats_recursive(Path::new(r"Z:\winmedic\does\not\exist"));
        assert_eq!(stats, DirStats::default());
    }
}
