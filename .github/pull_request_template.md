## What this changes

<!-- What is different after this pull request, and why is it needed? -->

## Related issue

<!-- e.g. Closes #12 -->

## Does it change what WinMedic does to a system?

<!-- Delete the lines that do not apply. -->

- [ ] No — documentation, CI, tests or refactoring only
- [ ] Yes, detection only: it reports something new but changes nothing
- [ ] Yes, it modifies the system

If it modifies the system:

- [ ] The `RiskScore` is honest (`High` for destructive or reboot-requiring changes)
- [ ] Whatever it modifies is backed up first (`safety::reg_backup` for registry keys)
- [ ] The dry-run path describes the exact commands without executing them
- [ ] No runtime value is interpolated into a PowerShell script without `ps_single_quoted`

## Checks

- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo test --locked`
- [ ] New behaviour is covered by tests using `MockCommandRunner`, not real commands

## What was verified, and how

<!--
Which Windows version did you test on, and what did you actually exercise?
If something could not be tested, say so plainly — an honest gap is more
useful than an assumed pass.
-->
