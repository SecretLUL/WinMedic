# Notes for AI agents

AI coding agents are welcome to work on WinMedic. Everything in
[CONTRIBUTING.md](CONTRIBUTING.md) applies to them. This file adds how to
work so that what an agent did can be reviewed, merged and trusted.

## Ask first

Pushing, opening or merging pull requests, force-pushing, releasing and
anything else that leaves the machine happens only when the maintainer asks
for it. Talk to the maintainer in the language they write in.

## Branches, commits, pull requests

- One commit per concern, with a conventional prefix. The message says why,
  and what was verified.
- Label every pull request as it is opened
  (`gh pr create --label <label>`), by the table under "Labels" in
  CONTRIBUTING.md. `documentation` only for documentation, never to skip CI.
- **Several pull requests form a chain.** The first targets `main`; each next
  branch starts from the previous one and targets it
  (`gh pr create --base <previous-branch>`). Opened side by side against
  `main`, two pull requests that touch the same file conflict as soon as the
  first is merged. After a merge, the next one moves to `main`
  (`gh pr edit <n> --base main`).
- Merge with a merge commit. Never bypass branch protection (`--admin`).
- Rewrite only history that is not pushed yet, or pushed history with
  `--force-with-lease` when the maintainer agreed. A commit message that turns
  out to be wrong is corrected before it is pushed.

## Tests run on the maintainer's desktop

- Nothing a test reaches may open a window, a browser or a UAC prompt, create
  a restore point, or touch files outside a temp directory. What could sits
  behind a seam that is inert by default (`SystemActions`,
  `RestorePointService`, `CommandRunner`, `CleanerPaths`); only `main.rs`
  switches on the real one.
- A test that starts a real process starts a harmless one, such as
  `ping 127.0.0.1`, without a window.
- Run the suite under a time limit, e.g. `timeout 400 cargo test --locked`. A
  test that deadlocks otherwise hangs until the agent's tool gives up.

## What Windows prints

- Capture a tool's output before writing the parser, commit the capture to
  `tests/fixtures/` and test against it ([how](tests/fixtures/README.md)). A
  test written from the code's own assumption proves nothing.
- When a capture needs Administrator rights the agent does not have, write a
  read-only capture script and ask the maintainer to run it in an elevated
  PowerShell.

## Before pushing

- Run everything under "Before you push" in CONTRIBUTING.md. CI lints with
  the newest stable Rust, which can be newer than the local one: run clippy
  with the newest installed toolchain, and check with the MSRV.
- Look at a UI change, not only at the accessibility tree. Render it, for
  example off screen with `ViewportCommand::Screenshot`, in dark and light and
  at the smallest window size.
- In the pull request, say on which Windows it was verified, how, and what was
  not verified.
