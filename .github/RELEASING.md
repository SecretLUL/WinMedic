# Releasing

Maintainer notes. Nothing here is needed to use or build WinMedic.

## A release

**Run workflow** on `release.yml` in the Actions tab and pick which number goes
up, counted from the newest release tag: `patch` (0.5.2 → 0.5.3), `minor`
(→ 0.6.0) or `major` (→ 1.0.0). The same from a terminal:

```powershell
gh workflow run release.yml --ref main -f bump=patch
```

The run writes the version into every file that states it, tags, builds,
refuses a binary that does not report the tagged version, publishes the release
with its `.sha256`, pushes the version bump to `main`, and calls `winget.yml`.
`dry_run` rehearses all of it without tagging or publishing.

- Release notes go in `docs/release-notes/v0.5.3.md`, merged before the run.
  Without it the notes are generated from the commit list.
- The bump reaches `main` through the repository secret `RELEASE_TOKEN`: a
  fine-grained personal access token for this repository only, with
  **Contents: Read and write**. `main` takes changes only through pull requests
  with green checks; the workflow's own token cannot get past that, this one
  can because its owner is the admin the ruleset lets bypass. Once it has
  expired, the run ends red and leaves the bump on a `release/<tag>` branch:
  renew the secret and merge that branch with a pull request.
- Never change the version by hand: `env!("CARGO_PKG_VERSION")` feeds the
  header, `--version`, the report and the update check, and `Cargo.lock` and the
  issue template repeat it. `./scripts/set-version.ps1 0.5.2 -Check` lists every
  place that disagrees.
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
