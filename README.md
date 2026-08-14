<div align="center">

# 🩺 WinMedic – Windows Self-Healing & Diagnostic TUI

**A high-performance, modular Windows diagnostic and auto-repair utility written in 100% Rust.**

[![Rust](https://img.shields.io/badge/Language-Rust%202024-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![CI](https://github.com/SecretLUL/WinMedic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecretLUL/WinMedic/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20(x64)-0078D6.svg?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows)
[![Ratatui](https://img.shields.io/badge/TUI-Ratatui%200.29-00D2FF.svg?style=for-the-badge)](https://ratatui.rs/)
[![Release](https://img.shields.io/badge/Version-v0.1.0-10B981.svg?style=for-the-badge)](https://github.com/SecretLUL/WinMedic/releases)

<br/>

![WinMedic Hero Banner](assets/banner.jpg)

</div>

---

## 🌟 Overview

**WinMedic** is a state-of-the-art terminal application (TUI) designed to autonomously diagnose, categorize, and safely repair Windows operating system errors, performance bottlenecks, update stalls, and broken configurations.

Unlike opaque one-click cleanup tools, **WinMedic** is built on four fundamental principles:
1. **Zero Runtime Dependencies**: Single, compact, portable native `.exe` binary without .NET, Python, or external runtime requirements.
2. **Safety First**: Automatic **Windows System Restore Points (VSS)** and **Registry Snapshots** are taken prior to any modification.
3. **Full Transparency**: Every single issue is explained in plain language with technical logs, severity levels, risk scores, and step-by-step fix previews.
4. **Blazing Speed**: Tokio async parallelism executes multi-module system scans in seconds.

---

## ⚡ Core Diagnostic & Healing Modules

| Module | What It Checks | What It Fixes |
| :--- | :--- | :--- |
| **🛡 System Integrity** | DISM Component Store corruption, SFC system file integrity, CBS logs, VSS shadow copy health | Runs `DISM /RestoreHealth`, `sfc /scannow`, repairs Volume Shadow Copy services |
| **🔄 Windows Update & Services** | `wuauserv`, `bits`, `cryptsvc`, `trustedinstaller`, bloated `SoftwareDistribution\Download` cache, stuck reboot flags | Gracefully resets update queues, purges corrupted download caches, re-registers update DLLs |
| **🌐 Network & DNS** | DNS name resolution, gateway ping reachability, Winsock catalog integrity, rogue proxy settings | `ipconfig /flushdns`, `ipconfig /registerdns`, `netsh winsock reset`, `netsh int ip reset`, proxy cleanup |
| **📋 Event Log & Crash Analysis** | Critical/Error event bursts in last 24h, WHEA hardware error architecture logs, `%SystemRoot%\Minidump` BSOD crash dumps | Corrupted log channel cleanup, crash dump analysis, hardware diagnostic recommendations |
| **💾 Storage & Filesystem** | Dirty Bit detection (`fsutil dirty query C:`), SMART drive health, `%TEMP%` & `C:\Windows\Temp` junk accumulation, bloated `IconCache.db` | Triggers online `chkdsk C: /scan`, cleans temp files, resets icon/thumbnail cache & restarts Explorer |
| **⚡ Registry & Autostart** | Orphaned `Run`/`RunOnce` startup keys, broken User Startup folder shortcuts, broken COM/Shell extension keys | Backs up target registry keys to `.reg` and safely removes invalid startup entries |

---

## 🛡️ Safety & Backup Architecture

Before WinMedic touches your system:
1. **Windows System Restore Point (VSS)**: A checkpoint named `"WinMedic Auto-Restore Point (Vor Reparatur)"` is automatically triggered via WMI / PowerShell.
2. **Registry Snapshotting**: Every modified registry key is exported into `%APPDATA%\WinMedic\backups\reg_<timestamp>.reg` prior to modification.
3. **Structured Audit Log**: Every scan, fix, exit code, and action is logged in human-readable `%APPDATA%\WinMedic\logs\audit.log` and `%APPDATA%\WinMedic\logs\history.json`.

---

## ⌨️ Keyboard Navigation & Shortcuts

| Shortcut | Action |
| :--- | :--- |
| **`[1]` - `[5]`** | Switch tabs (Dashboard, Health Scan, Issue Triage, Repair Center, Backups & Logs) |
| **`[Tab]` / `[Shift+Tab]`** | Cycle forward / backward through tabs |
| **`[S]`** | Start full system health scan |
| **`[R]`** | Re-run scan / refresh current view |
| **`[Space]`** | Toggle checkbox selection for highlighted issue |
| **`[A]`** | Select all detected issues (1-Click Auto-Fix) |
| **`[N]`** | Deselect all issues |
| **`[F]`** | Proceed to Repair Center / Execute repairs |
| **`[↑]` / `[↓]` or `[j]` / `[k]`** | Navigate list items and logs |
| **`[?]`** | Open interactive Help Modal overlay |
| **`[Esc]`** | Close modal or return to Dashboard |
| **`[Q]`** | Exit WinMedic safely |

---

## 🚀 CLI Headless Automation Mode

WinMedic can also run without the TUI for automated scripts, CI/CD, or batch IT deployments:

```bash
# Run headless system scan and output styled summary
winmedic.exe --scan

# Run scan and automatically repair all safe detected issues
winmedic.exe --auto-fix

# Output diagnostic findings as structured JSON for automation
winmedic.exe --json

# Run fixes without creating a VSS restore point (e.g. for speed in VM testing)
winmedic.exe --auto-fix --no-vss

# Request Windows Administrator elevation
winmedic.exe --elevate
```

---

## 🛠️ Building From Source

### Prerequisites
* **Windows 10 / 11** (64-bit)
* **Rust** 1.80+ (`cargo` and `rustc`)

### Build Steps

```powershell
# 1. Clone the repository
git clone https://github.com/SecretLUL/WinMedic.git
cd WinMedic

# 2. Build optimized release binary
cargo build --release

# 3. The executable is located at:
.\target\release\winmedic.exe
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
Built with ❤️ for Windows Power Users and System Administrators.
</div>
