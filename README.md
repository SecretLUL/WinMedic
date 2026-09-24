<div align="center">

![WinMedic: healing Windows at 1 HP. Fast. Reliable. Easy.](assets/banner.svg)

[![CI](https://img.shields.io/github/actions/workflow/status/SecretLUL/WinMedic/ci.yml?branch=main&label=CI)](https://github.com/SecretLUL/WinMedic/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/release/SecretLUL/WinMedic?label=Version&color=0F7B0F)](https://github.com/SecretLUL/WinMedic/releases/latest)
[![Windows 10 / 11](https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

</div>

**Windows acting up?** Updates that fail, no internet, a slow or crashing PC:
WinMedic finds out why and repairs it, so you do not have to reinstall Windows.

It is a single program. Nothing to install, nothing else to download. It only
looks until you click **Repair**, and it creates a restore point first, so every
change can be undone.

## Download

WinMedic runs on 64-bit Windows 10 and 11.

**With WinGet**, which comes with Windows 10 and 11:

```powershell
winget install SecretLUL.WinMedic
```

**Or by hand:** download `winmedic-<version>.exe` from the
[latest release](https://github.com/SecretLUL/WinMedic/releases/latest) and
start it. WinMedic is not code-signed yet, so Windows may warn you the first
time: click *More info*, then *Run anyway*.
[How to check the download first](docs/how-it-works.md#verify-a-download-by-hand)

## How to use it

1. **Start WinMedic.** Repairs need administrator rights; WinMedic offers to
   restart itself with them.
2. **Click Scan now.** It takes a minute or two and changes nothing.
3. **Click Repair.** WinMedic fixes what it can and tells you if Windows needs
   a restart.

WinMedic opens in **Easy mode**: how your PC is doing, what Repair will do (for
example "Frees about 8.4 GB of disk space") and two big buttons. Press **F7**,
or click *Advanced mode* top right, for **Advanced mode**:
every detail, filters, the logs, and a simulation that shows what a repair would
do without doing it.

## What it checks

| Area | What WinMedic looks for |
| :--- | :--- |
| **System files** | Damaged Windows files, the recovery environment, WMI |
| **Windows Update** | Stuck update services and download caches |
| **Internet** | No IP address, name resolution (DNS), the router, Winsock, broken proxies |
| **Crashes** | Blue screens, critical errors in the event log, the last memory test |
| **Hardware** | Processor, memory and PCIe errors Windows has logged |
| **Disk** | File system errors, drive health, temporary files |
| **Startup** | Autostart entries and scheduled tasks that point at deleted programs or keep failing |
| **Cleanup** | Caches and leftovers that take up space |
| **Memory** | A switched-off or too small page file |
| **Tweaks** | Services and policies that "tweak" and debloat tools switched off |
| **Clock and restart** | A wrong clock, a PC that has not been restarted for weeks |

Exactly what each check looks at and runs is in
[How WinMedic works](docs/how-it-works.md).

## Is it safe?

- Scanning only reads. Nothing changes until you click **Repair**.
- Before a repair, WinMedic creates a Windows restore point and backs up every
  registry key it changes. Registry changes can be rolled back under
  **Settings**.
- Repairs that delete something you may want to keep, or need a restart, are
  never picked for you. You decide on those in Advanced mode.
- WinMedic is open source. Its checks are tested against output captured from
  real Windows installations, and every change runs a real scan in CI.

## For IT admins

WinMedic also runs without its window, for scripts and remote support:

```powershell
winmedic --scan                        # check and print the findings
winmedic --scan --output report.html   # ... and save a report (.html, .md or .json)
winmedic --auto-fix                    # check and repair what is safe to repair
winmedic --dry-run                     # show what a repair would run, run nothing
```

The exit code tells a script how it went: `0` fine, `1` warnings, `2` critical
problems, `3` a repair failed. Every flag and code is listed in
[How WinMedic works](docs/how-it-works.md#cli-headless-automation-mode).

## Uninstall

First click *Settings → Remove WinMedic from Windows*, or run
`winmedic --uninstall`. That removes the background scan and the *Start with
Windows* entry, if you turned them on. Then delete `winmedic.exe`, or run
`winget uninstall SecretLUL.WinMedic` if you installed it with WinGet.

Your settings, logs and backups stay in `%APPDATA%\WinMedic`;
`winmedic --uninstall --purge` deletes them too.

## For developers

WinMedic is written in Rust. You need Windows 10 or 11, Rust 1.95 or newer and
the MSVC build tools:

```powershell
git clone https://github.com/SecretLUL/WinMedic.git
cd WinMedic
cargo build --locked --release   # creates target\release\winmedic.exe
```

[CONTRIBUTING.md](CONTRIBUTING.md) explains what CI checks and which parts need
extra care. Please report security problems privately, as described in
[SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
