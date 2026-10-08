//! Shared directory measurement.
//!
//! Several diagnostic modules need "how big is this tree, and how many files".
//! They used to each carry their own `read_dir` loop, which drifted apart on the
//! questions that actually matter — junction traversal, whether unreadable
//! subtrees abort the walk, and where the byte-to-megabyte rounding happens.
//! One implementation, one set of answers.

use std::path::{Path, PathBuf};

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

/// Measure each tree in `dirs` with `measure` and total the results, on a
/// blocking thread.
///
/// The walks are synchronous and can run for minutes over locations that hold
/// hundreds of thousands of files. Run inline they would pin a Tokio worker,
/// and having no await point they would make the calling task un-abortable:
/// cancelling a scan (`JoinSet::shutdown`) would wait for the whole walk. The
/// caller awaits the blocking task instead, which can be aborted; the walk runs
/// to its end on its own thread.
pub async fn measure_dirs(dirs: Vec<PathBuf>, measure: fn(&Path) -> DirStats) -> DirStats {
    tokio::task::spawn_blocking(move || {
        let mut total = DirStats::default();
        for dir in &dirs {
            let stats = measure(dir);
            total.bytes += stats.bytes;
            total.files += stats.files;
        }
        total
    })
    .await
    .unwrap_or_default()
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

    /// The blocking walk totals exactly what the synchronous one does, and
    /// several trees add up, each one counted once.
    #[tokio::test]
    async fn measuring_on_a_blocking_thread_matches_the_walker() {
        let root =
            std::env::temp_dir().join(format!("winmedic_fs_stats_async_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        create_dir_all(root.join("a/b")).unwrap();
        create_dir_all(root.join("c")).unwrap();
        File::create(root.join("a/one.bin"))
            .unwrap()
            .write_all(&[0u8; 10])
            .unwrap();
        File::create(root.join("a/b/two.bin"))
            .unwrap()
            .write_all(&[0u8; 20])
            .unwrap();
        File::create(root.join("c/three.bin"))
            .unwrap()
            .write_all(&[0u8; 30])
            .unwrap();

        let walked = dir_stats_recursive(&root);
        let measured = measure_dirs(vec![root.clone()], dir_stats_recursive).await;
        assert_eq!(measured, walked);

        // "a" holds 10 + 20 bytes in two files, and it lies inside "root" too.
        let both = measure_dirs(vec![root.clone(), root.join("a")], dir_stats_recursive).await;
        assert_eq!(both.bytes, walked.bytes + 30);
        assert_eq!(both.files, walked.files + 2);

        let _ = std::fs::remove_dir_all(&root);
    }
}
