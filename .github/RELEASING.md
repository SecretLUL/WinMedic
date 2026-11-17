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
with its `.sha256`, pushes the version bump to `main`, and calls `winget.yml`
and, after a clean VirusTotal scan, `chocolatey.yml`.
`dry_run` rehearses all of it without tagging or publishing.

- Release notes go in `docs/release-notes/<tag>.md` (`v0.6.0.md` for 0.6.0),
  merged before the run. Without it the notes are generated from the commit
  list.
- The run stops unless CI passed on the commit it releases; wait for CI on
  `main` to finish first. CI does not run on a push that changes
  documentation only, such as the release notes: then it has to have passed
  on the newest commit before it that CI ran on. A `dry_run` skips that
  check.
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
- `./scripts/next-version.ps1 -Bump minor` prints the version a run would
  pick, without starting one.

## A pre-release

For a change that should reach testers before it reaches everyone. It is the
same workflow with one more tick, **Pre-release**, run on the branch that holds
the change (*Use workflow from*) instead of on `main`:

```powershell
gh workflow run release.yml --ref <branch> -f bump=patch -f prerelease=true
```

The version is the next one by `bump` with `-pre.N` behind it, N counting up
per version: after v0.18.0, `patch` gives `v0.18.1-pre.1`, then
`v0.18.1-pre.2`; `minor` gives `v0.19.0-pre.1`. Everything else runs as for a
release: the build, the check of what the binary calls itself, the `.sha256`,
the PDB and VirusTotal.

- That `-` is what makes it a pre-release, everywhere: GitHub marks it and
  keeps *Latest* on the last release, WinGet and Chocolatey skip it, and the
  update check never offers one. Nobody is moved onto a pre-release, and nobody
  from one pre-release to the next: it is a download by hand. Whoever runs one
  is offered the next release as usual. A version without the `-`, such as
  `v0.18.1`, is a release whatever it is called, goes to WinGet and
  Chocolatey, and takes that number from the real 0.18.1.
- The branch keeps its version. The bump is committed for the tag alone and
  pushed nowhere, or it would reach `main` with the pull request.
- CI has to have passed on the branch's newest commit, in its pull request.
  Without the tick the run counts only CI's runs on `main`, so a release
  started on a branch by mistake stops there.
- The run uses the branch's own copy of `release.yml`, and counts from the
  newest release. So first release what is on `main`, then merge `main` into
  the branch, then run the pre-release: started before, it would be numbered
  below the release that follows it.
- Notes go in `docs/release-notes/<tag>.md` on that branch
  (`v0.18.1-pre.1.md`), or are generated from the commit list.
- Once the change is ready, merge the pull request and release as usual.

## VirusTotal

After publishing, `release.yml` uploads the binary to VirusTotal and goes red
when an engine flags it; the job summary lists which. A new, unsigned `.exe` is
what machine-learning scanners flag: Microsoft reported v0.6.0 as
`Trojan:Win32/Sabsik.EN.A!ml`. Report every false positive to its vendor,
Microsoft at <https://www.microsoft.com/en-us/wdsi/filesubmission> (*Software
developer*, *Incorrectly detected as malware/malicious*), the others through
[VirusTotal's list](https://docs.virustotal.com/docs/false-positive-contacts).

It needs the repository secret `VIRUSTOTAL_API_KEY`, the API key of a free
VirusTotal account (profile menu → *API key*). Without it the job says so and
skips the scan. `./scripts/virustotal-scan.ps1 <file>` scans by hand.

## Crash logs

When WinMedic panics, it writes a `crash-*.log` into `%APPDATA%\WinMedic\logs`
(the newest five stay). Its stack is a list of offsets such as
`winmedic-v0.12.0.exe+0x1a2b3c`, because the release ships without symbols. `release.yml` keeps each release's
PDB as the artifact `winmedic-<tag>-pdb` of its run, for 90 days;
`gh run download <run id> -n winmedic-<tag>-pdb` fetches it. With that PDB and
the release's `.exe`:

```powershell
./scripts/resolve-crash-log.ps1 crash-20261012-224107-1234-1.log -Exe winmedic-v0.12.0.exe -Pdb winmedic.pdb
```

A PDB matches only the binary built in its own run.

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
   with the `public_repo` and `workflow` scopes. The workflow first brings the
   fork up to date, which needs `workflow` whenever upstream changed its
   workflow files (it failed on that for v0.5.0). The submission depends on
   that: komac opens its branch in the fork at winget-pkgs' own head, which a
   fork that is behind does not have ("Ref cannot be created", v0.16.0). The
   sync gets three tries, because GitHub now and then fails it for no reason
   of ours (#144). When it still fails, the run says so: sync the fork
   (`gh repo sync SecretLUL/winget-pkgs --branch master`) and re-run the job.
   When the token expires, the submission fails and says so: replace the
   secret and run `winget.yml` with the tag.

`./scripts/winget-manifest.ps1 <version>` builds and validates the three
manifests by hand. It was needed once, for the first submission (0.3.4), because
komac only adds versions to a package that exists.

WinMedic's in-place updater also updates a WinGet install, after which WinGet
still lists the version it installed and `winget upgrade` offers the one that is
already there. For a WinGet install, `winget upgrade SecretLUL.WinMedic` is the
tidier path.

## Chocolatey

`chocolatey.yml` builds the package in `packaging/chocolatey/` with
`./scripts/chocolatey-package.ps1 <version>` and pushes it to the
[Chocolatey Community Repository](https://community.chocolatey.org/packages/winmedic).
The package downloads the release's `.exe` and checks it against the checksum
the script established, the same way `winget-manifest.ps1` does.

- `release.yml` calls it only when the VirusTotal job is green. Chocolatey scans
  every package on VirusTotal too, and a version an engine flags waits there for
  a moderator. A version held back that way goes out with **Run workflow** on
  `chocolatey.yml` once the vendor has cleared the detection.
- Every version is moderated: automated checks, a test install, VirusTotal, and
  a person until the package is trusted. Chocolatey answers by e-mail to the
  account. A version moderation sends back is fixed and pushed again under the
  same version, with **Run workflow** and its tag.
- Pre-releases are skipped; `dry_run` builds the package without pushing it.
- As with WinGet, the in-place updater leaves Chocolatey listing the version it
  installed; `choco upgrade winmedic` is the tidier path.

### Set up once

The repository secret `CHOCOLATEY_API_KEY`: the API key of the `SecretLUL`
account on community.chocolatey.org (*Account* → *API Keys*). Without it the job
goes red and says so.
