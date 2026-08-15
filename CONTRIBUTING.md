# Contributing to WinMedic

Thanks for taking the time. WinMedic runs with Administrator privileges and
modifies the registry, so the bar for changes to the repair paths is higher
than for a typical CLI tool. This document explains what the checks expect and
where the risky parts of the codebase are.

## Prerequisites

- **Windows.** The crate is Windows-only and does not cross-compile for
  development — `winreg` refuses to build on other platforms with a
  `compile_error!`. A Windows VM works fine.
- **Rust 1.88 or newer.** This is the MSRV declared in `Cargo.toml` and
  enforced by the `msrv` CI job. Edition 2024 alone would only need 1.85; the
  floor comes from `ratatui → instability → darling`.
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

**PowerShell invocation.** Never interpolate a runtime value into a script
string. Use `utils::cmd::ps_single_quoted` — see the module documentation there.

## Commits and pull requests

- Conventional-commit prefixes (`fix:`, `feat:`, `ci:`, `docs:`, `chore:`) are
  used throughout the history; please match it.
- Describe *why* the change is needed, not only what it does.
- Say what you verified and on which Windows version. If you could not test
  something, say so — an honest gap is more useful than an assumed pass.

## Language

All user-facing strings, code, comments and documentation are in **English**.
The project previously mixed German and English; please do not reintroduce it.
