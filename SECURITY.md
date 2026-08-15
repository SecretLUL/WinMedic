# Security Policy

WinMedic requests Administrator elevation, executes `DISM`, `sfc`, `reg`,
`netsh` and PowerShell, and writes to the Windows registry. A defect in those
paths can damage a system rather than merely crash the tool, so security
reports are taken seriously.

## Supported versions

Only the latest release receives fixes. Please reproduce against the newest
version before reporting.

| Version | Supported |
| --- | --- |
| 0.2.x | ✅ |
| < 0.2 | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private reporting instead:

1. Go to the [Security tab](https://github.com/SecretLUL/WinMedic/security)
2. Choose **Report a vulnerability**

That opens a private advisory visible only to the maintainers.

If private reporting is unavailable to you, open a public issue containing
nothing but a request for a private contact channel — no details.

## What to include

- WinMedic version (`winmedic.exe --version`) and Windows build number
- Whether WinMedic was running elevated
- Reproduction steps, ideally the smallest sequence that triggers it
- What an attacker gains — privilege escalation, arbitrary code execution as
  Administrator, destruction of data, or something else
- The relevant excerpt from `%APPDATA%\WinMedic\logs\history.jsonl`

## Response

You can expect an acknowledgement within a few days and an assessment of
severity and a planned fix after that. This is a spare-time project, not a
funded one — there is no bounty, and timelines are best effort.

Please give a reasonable window for a fix before publishing details.

## Scope

In scope:

- Privilege escalation, or any path that makes WinMedic run attacker-controlled
  code with the Administrator rights it holds
- Command or PowerShell injection through a value WinMedic reads from the
  system, a config file, or a network response
- A repair path that destroys data outside what it declares it will change
- A safety mechanism that reports success without having worked — a restore
  point that was not created, a backup that was not written

Out of scope:

- Requiring Administrator rights for repairs. This is by design and stated up
  front; the tool cannot repair system files without them.
- The SmartScreen warning on the released binary. It is unsigned; see the
  download section of the README.
- Advisories in transitive dependencies with no exploitable path in WinMedic.
  These are visible in the `Dependency Audit` CI job.
- Anything that requires the attacker to already be Administrator on the
  machine.
