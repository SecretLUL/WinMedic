# Contributing to WinMedic

Thanks for taking the time. WinMedic runs with Administrator privileges and
modifies the registry, so the bar for changes to the repair paths is higher
than for a typical CLI tool. This document explains what the checks expect and
where the risky parts of the codebase are.

## Prerequisites

- **Windows.** The crate is Windows-only and does not cross-compile for
  development — `winreg` refuses to build on other platforms with a
  `compile_error!`. A Windows VM works fine.
- **Rust 1.95 or newer.** This is the MSRV declared in `Cargo.toml` and
  enforced by the `msrv` CI job. Edition 2024 alone would only need 1.85; the
  floor comes from `egui`/`eframe`.
- **Administrator rights** to exercise the repair paths by hand. The test
  suite itself does not need them.

## Build and test

```powershell
cargo build --locked
cargo test  --locked
```

`--locked` matters: `Cargo.lock` is committed and CI builds against it, so a
change that silently updates a dependency will fail there.

## What CI enforces

Every pull request must pass all of these. Run them before pushing:

```powershell
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo check --locked --all-targets    # with the 1.88 toolchain, for the MSRV gate
```

Clippy runs with `-D warnings`, so a warning is a build failure. If a lint is
genuinely wrong for a piece of code, add a **targeted** `#[allow(...)]` on the
item with a comment explaining why — not a crate-wide allow in `lib.rs`.

Pull requests into *any* branch are gated, not just those targeting `main`.

## Test layout

| Suite | What it covers |
| --- | --- |
| `#[cfg(test)]` modules in `src/` | Unit tests next to the code they test |
| `tests/tier1_features.rs` | Feature-level behaviour of each module |
| `tests/tier2_boundaries.rs` | Boundary and edge-case inputs |
| `tests/tier3_combinations.rs` | Interactions between modules |
| `tests/tier4_scenarios.rs` | End-to-end scenarios |
| `tests/*adversarial*`, `tests/*challenger*` | Hostile and malformed inputs |

Diagnostics and repairs must be tested through `MockCommandRunner` rather than
by shelling out. A test that executes a real `DISM` or `reg` command is not
acceptable — it makes the suite machine-dependent and can damage the machine
running it.

## Areas that need extra care

**`src/safety/`** is the layer everything else depends on for not destroying a
system. Restore point creation, the registry backup index and the audit log
all live here. Changes need unit tests covering the failure paths, not just
the happy path.

**`src/modules/*.rs`** contain the `fix()` implementations that actually change
the system. A new repair should:

- carry a truthful `RiskScore` — `High` for anything destructive or requiring a
  reboot
- start deselected by default if it is risky
- produce a dry-run description listing the exact commands it would run
- back up whatever it modifies, via `safety::reg_backup` for registry keys

**`src/utils/self_update.rs`** replaces the executable the user runs, very
often as Administrator. The order — download, hash, compare against the
published `.sha256`, only then swap — is not negotiable, and every URL and
asset name arriving from the network is treated as hostile input. Nothing may
be installed that has not matched the checksum, and any failure has to leave the
installed binary untouched and fall back to the browser download. No test may
build `SelfUpdateService::real()` or `Fetcher::curl()`; a guard test enforces
that, and `install()` takes a stub `Fetcher` precisely so the verify-and-swap
sequence can be tested without a network.

**PowerShell invocation.** Never interpolate a runtime value into a script
string. Use `utils::cmd::ps_single_quoted` — see the module documentation there.

## Cutting a release

A release is two steps: land the version bump on `main`, then run the workflow.

```powershell
./scripts/prepare-release.ps1 0.3.3   # opens the "chore(release): v0.3.3" pull request
# merge it, wait for CI on main, then:
gh workflow run release.yml --ref main -f version=0.3.3
```

The bump goes through a pull request rather than being pushed to `main` by the
workflow because `main` is protected and `GITHUB_TOKEN` is not allowed through
its four required checks. The workflow does try — a direct push, then a pull
request as a fallback — and the fallback needs a repository setting that is
deliberately off, so the attempt fails and the run's last step goes red. Giving
CI a token that bypasses branch protection would fix the symptom by removing the
protection; sending the bump down the same reviewed, CI-gated road as every
other change costs one merge and removes nothing. v0.4.0 is the release that
shipped correctly and still went red this way.

Preparing first also makes the workflow's own bump step a no-op: it finds every
version site already correct, tags `HEAD` unchanged, and its "did the bump reach
the branch" check passes. Everything else it does is unchanged — it builds from
the tag it just made and refuses to publish a binary that does not introduce
itself as that version.

Do not edit `Cargo.toml` by hand to bump the version. `Cargo.lock` and the
issue-template placeholder repeat it, and the one place the number actually
matters — `env!("CARGO_PKG_VERSION")`, which feeds the header, the help popup,
`--version`, the HTML report and the update check — is the one nobody remembers
to check. `prepare-release.ps1` calls the script that owns all of them, and it
can be run on its own:

```powershell
./scripts/set-version.ps1 0.3.3          # rewrite every version site
./scripts/set-version.ps1 0.3.3 -Check   # report what disagrees, change nothing
```

The README's checksum example is deliberately not on that list: it globs
`winmedic-v*.exe` out of the download directory instead of naming a version, so
it never goes stale.

Pushing a `v*` tag by hand still builds and publishes, but a tag is immutable,
so that path can only run the `-Check` pass: if the tagged tree states a
different version than the tag, the release fails rather than shipping a
mislabelled binary.

Release notes are read from `docs/release-notes/<tag>.md` when that file exists,
and generated from the commit list when it does not.

Once the release is published, the workflow hands the tag to
`.github/workflows/winget.yml`, which opens a pull request against
microsoft/winget-pkgs so `winget install SecretLUL.WinMedic` catches up.
[docs/winget.md](docs/winget.md) explains the setup it needs and why it is not
triggered by `release: published`.

## Commits and pull requests

- Conventional-commit prefixes (`fix:`, `feat:`, `ci:`, `docs:`, `chore:`) are
  used throughout the history; please match it.
- Describe *why* the change is needed, not only what it does.
- Say what you verified and on which Windows version. If you could not test
  something, say so — an honest gap is more useful than an assumed pass.

## Language

All user-facing strings, code, comments and documentation are in **English**.
The project previously mixed German and English; please do not reintroduce it.
