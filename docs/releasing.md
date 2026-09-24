# Releasing

1. `./scripts/prepare-release.ps1 0.5.1` opens the `chore(release): v0.5.1`
   pull request with every version site updated. Add
   `docs/release-notes/v0.5.1.md` to that branch; without it the notes are
   generated from the commit list.
2. Merge it, wait for CI on `main`, then:

   ```powershell
   gh workflow run release.yml --ref main -f version=0.5.1
   ```

The workflow tags `main`, builds, refuses a binary that does not report the
tagged version, publishes the release with its `.sha256`, and hands the tag to
`winget.yml` ([WinGet](winget.md)).

- Never change the version by hand: `env!("CARGO_PKG_VERSION")` feeds the
  header, `--version`, the report and the update check, and `Cargo.lock` and the
  issue template repeat it. `./scripts/set-version.ps1 0.5.1 -Check` lists every
  place that disagrees.
- The bump goes through a pull request because `main` is protected and the
  workflow's token cannot pass its required checks. Skipping step 1 still
  publishes, but the run ends red, as it did for v0.4.0.
- A hand-pushed `v*` tag still releases, and fails if the tagged tree states a
  different version.
