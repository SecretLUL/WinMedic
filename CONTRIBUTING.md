# Contributing to WinMedic

WinMedic runs as Administrator and changes the registry, so the repair paths
get a higher bar than the rest.

## Setup

- **Windows.** `winreg` does not build anywhere else; a VM is fine.
- **Rust 1.95 or newer**, the MSRV in `Cargo.toml` (set by `egui`/`eframe`).
- **Administrator rights** only to try repairs by hand. The tests do not need
  them.

## Before you push

CI runs exactly this, on every pull request into any branch:

```powershell
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo check --locked --all-targets   # with the toolchain from rust-version (MSRV)
cargo run --locked -- --scan         # a real scan: no "[X] Module" line
```

`--locked` because CI builds against the committed `Cargo.lock`. A lint that
is wrong for one item gets a targeted `#[allow(...)]` with a comment, never a
crate-wide one.

## Tests

- Checks and repairs are tested through `MockCommandRunner`. No test runs a
  real `DISM`, `reg` or anything else that could change the machine.
- **Feed the mock what Windows prints, not what you expect it to print.** A
  module that parses a tool's output is tested with a capture from
  `tests/fixtures/`; add one if you need it ([rules](tests/fixtures/README.md)).
  The DISM, service and event log checks all had passing tests while none of
  them could fire on a real machine.

## Reading what Windows prints

WinMedic runs in every display language.

- Prefer language-neutral sources: numbers, exit codes, XML, registry values,
  enum names. DISM takes `/English`.
- Match a translated sentence only when nothing else exists, using the tool's
  own wording from its `.mui` files for English and German, and fail safe in
  every other language: a missed finding, never an invented one.
- Never decode process output yourself; `CommandRunner` already did.
- A refused command is "not checked", never "healthy". Check the exit code
  before reading the output as a verdict.

## Code that needs extra care

- **`src/safety/`** (restore points, registry backups, audit log): test the
  failure paths, not only the happy path.
- **`fix()` in `src/modules/`**: a truthful `RiskScore` (`High` when it is
  destructive or needs a reboot), risky repairs start unticked, the dry run
  lists the exact commands, and whatever is changed is backed up first
  (`safety::reg_backup` for registry keys).
- **`src/utils/self_update.rs`**: download, hash, compare with the published
  `.sha256`, only then swap. Everything from the network is hostile input, and
  any failure leaves the installed binary alone. No test builds
  `SelfUpdateService::real()` or `Fetcher::curl()`.
- **PowerShell**: never put a runtime value into a script string; use
  `utils::cmd::ps_single_quoted`.

## Commits and pull requests

- Conventional-commit prefixes: `fix:`, `feat:`, `ci:`, `docs:`, `chore:`.
- Say why, and what you verified on which Windows. If you could not test
  something, say so.
- Code, comments, docs and every user-facing string are in English.

Cutting a release: [.github/RELEASING.md](.github/RELEASING.md).
