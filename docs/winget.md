# Publishing WinMedic to WinGet

`winget install SecretLUL.WinMedic` is the least friction WinMedic can offer:
no releases page, no unsigned download saved by hand, no SmartScreen prompt to
click past on first launch. WinGet accepts unsigned binaries as long as the
manifest carries the right `InstallerSha256`, and the release workflow already
publishes a `.sha256` next to every binary — so nothing about the way WinMedic
is built had to change for this.

The package is a **portable** one. WinMedic is a single self-contained
executable with no installer, so WinGet stores the `.exe` in its own package
directory and links it onto the `PATH` as `winmedic`.

## How a release reaches WinGet

`release.yml` calls `winget.yml` once the release assets are on the releases
page. That workflow runs [WinGet Releaser][winget-releaser], which reads the
GitHub release, builds the manifest with [komac][komac] and opens a pull request
against [microsoft/winget-pkgs][winget-pkgs] from the fork under this account.

Two things are deliberately not automatic:

- **Pre-releases are skipped.** A tag containing a SemVer pre-release suffix
  (`v1.0.0-rc1`) never reaches WinGet, so `winget upgrade` cannot move anyone
  onto one.
- **The pull request still has to be reviewed.** winget-pkgs runs its own
  validation and a moderator merges it. `winget install` offers the new version
  once that has happened, usually within a few hours.

`winget.yml` also has a **Run workflow** button that takes a tag, for
re-submitting a version whose pull request was closed.

### Why it is not triggered by `release: published`

Because that trigger would never fire. `release.yml` publishes with
`GITHUB_TOKEN`, and events raised by `GITHUB_TOKEN` do not start further
workflow runs — the same rule `release.yml` relies on to stop itself releasing
the same version twice. A `release: published` workflow would look correctly
wired up and silently do nothing on every release. `release.yml` therefore calls
`winget.yml` as a reusable workflow instead.

## One-time setup

WinGet Releaser needs both of these, and fails with an explanation in the job
summary until they exist.

1. **A fork of winget-pkgs** under the `SecretLUL` account. The action pushes
   its manifest branch there and opens the pull request from it. (If the fork
   ever has to live under a different account, pass `fork-user` in
   `winget.yml`.)

2. **A `WINGET_TOKEN` repository secret.** It has to be a **classic** personal
   access token with the `public_repo` scope — fine-grained tokens are
   [not supported by the action][fine-grained-issue]. `GITHUB_TOKEN` cannot be
   used, because the pull request is opened against a repository this one has no
   relationship to.

## The first submission, which has to be done by hand

WinGet Releaser refuses to run until at least one version of the package already
exists in winget-pkgs — it uses the existing manifest as the base for the next
one. The first version therefore has to be submitted manually, once:

```powershell
# Build the three manifests for a published release and validate them
./scripts/winget-manifest.ps1 0.3.4
```

The script downloads the released `.exe`, hashes it, and refuses to write
anything unless that hash matches the `.sha256` published beside it — the
manifest's `InstallerSha256` is the only thing tying it to a specific binary, so
it is established rather than copied. The result lands in
`target/winget/manifests/s/SecretLUL/WinMedic/<version>/`, mirroring the
winget-pkgs directory layout, and is checked with `winget validate` when winget
is installed locally.

Then copy that `manifests/` directory into a fork of winget-pkgs, commit it on a
branch, and open a pull request titled
`New package: SecretLUL.WinMedic version <version>`. Once it is merged, every
later release is submitted by the workflow.

## What WinGet users get

`winget install SecretLUL.WinMedic` puts `winmedic` on the `PATH`. Diagnostics
run unelevated; the repair paths need Administrator rights, so run
`winmedic --elevate` or start it from an elevated terminal.

One interaction is worth knowing about: WinMedic's own in-place updater replaces
the executable where it sits, including inside WinGet's package directory. That
works, but WinGet then still believes the installed version is the one it
installed, and `winget upgrade` will offer to "upgrade" to a version that is
already there. For a WinGet install, `winget upgrade SecretLUL.WinMedic` is the
tidier of the two paths; the built-in updater is what serves everyone who
downloaded the `.exe` directly.

[fine-grained-issue]: https://github.com/vedantmgoyal9/winget-releaser/issues/172
[komac]: https://github.com/russellbanks/Komac
[winget-pkgs]: https://github.com/microsoft/winget-pkgs
[winget-releaser]: https://github.com/vedantmgoyal9/winget-releaser
