# Releasing

Maintainer notes. Nothing here is needed to use or build WinMedic.

## A release

1. `./scripts/prepare-release.ps1 0.5.1` opens the `chore(release): v0.5.1`
   pull request with every version site updated. Add
   `docs/release-notes/v0.5.1.md` to that branch; without it the notes are
   generated from the commit list.
2. Merge it, wait for CI on `main`, then:

   ```powershell
   gh workflow run release.yml --ref main -f version=0.5.1
   ```

`release.yml` tags `main`, builds, refuses a binary that does not report the
tagged version, publishes the release with its `.sha256`, and calls
`winget.yml`.

- Never change the version by hand: `env!("CARGO_PKG_VERSION")` feeds the
  header, `--version`, the report and the update check, and `Cargo.lock` and the
  issue template repeat it. `./scripts/set-version.ps1 0.5.1 -Check` lists every
  place that disagrees.
- The bump goes through a pull request because `main` is protected and the
  workflow's token cannot pass its required checks. Skipping step 1 still
  publishes, but the run ends red, as it did for v0.4.0.
- A hand-pushed `v*` tag still releases, and fails if the tagged tree states a
  different version.

## WinGet

`winget.yml` runs [komac](https://github.com/russellbanks/Komac), a pinned
release checked against its SHA-256. It builds the next manifest from the
version already in [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)
and opens a pull request there from the `SecretLUL` fork. A moderator merges
it, usually within hours.

- Pre-releases (`v1.0.0-rc1`) are skipped.
- **Run workflow** on `winget.yml` takes a tag to submit a version again;
  `dry_run` rehearses without opening a pull request.
- `release.yml` calls it. A `release: published` trigger would never fire: a
  release published with `GITHUB_TOKEN` starts no further workflows.
- komac itself, not WinGet Releaser: that action first checks for the package
  with an anonymous request that fails from runners, so v0.4.0 and v0.4.1 never
  reached WinGet.
- komac copies description, tags and dependencies from the last published
  version. A change to them goes into that version's pull request.

### Set up once

1. A fork of microsoft/winget-pkgs under `SecretLUL`.
2. The repository secret `WINGET_TOKEN`: a **classic** personal access token
   with the `public_repo` and `workflow` scopes. komac brings the fork up to
   date before it pushes, which needs `workflow` whenever upstream changed its
   workflow files (it failed on that for v0.5.0). When the token expires, the
   submission fails and says so: replace the secret and run `winget.yml` with
   the tag.

`./scripts/winget-manifest.ps1 <version>` builds and validates the three
manifests by hand. It was needed once, for the first submission (0.3.4), because
komac only adds versions to a package that exists.

WinMedic's in-place updater also updates a WinGet install, after which WinGet
still lists the version it installed and `winget upgrade` offers the one that is
already there. For a WinGet install, `winget upgrade SecretLUL.WinMedic` is the
tidier path.
