# How WinMedic works

The [README](../README.md) says what WinMedic does. This page is the detail
behind it: exactly what each check looks at and runs, how repairs are made safe
and undoable, the settings, the update check, every shortcut and the command
line.

## Core Diagnostic & Healing Modules

| Module | What It Checks | What It Fixes |
| :--- | :--- | :--- |
| **System Integrity** | DISM Component Store corruption, SFC system file integrity, CBS logs, VSS shadow copy health, a switched-off Windows Recovery Environment (`InstallState` in `ReAgent.xml`), WMI classes that fail to answer | Runs `DISM /RestoreHealth`, `sfc /scannow`, repairs Volume Shadow Copy services, `reagentc /enable`, `winmgmt /salvagerepository` — the last two read the state back afterwards |
| **Windows Update & Services** | `wuauserv`, `bits`, `cryptsvc`, `trustedinstaller`, bloated `SoftwareDistribution\Download` cache, stuck reboot flags | Gracefully resets update queues, purges corrupted download caches, re-registers update DLLs |
| **Network & DNS** | Physical adapters that asked for a DHCP address and got only a 169.254.x.x stand-in, DNS name resolution through the machine's *own* resolver (two independent names, never a pinned public server), gateway ping reachability, Winsock catalog integrity, rogue proxy settings, a WinHTTP proxy (the one Windows Update and the Store use) that nothing answers at | `ipconfig /renew <adapter>`, `ipconfig /flushdns`, `ipconfig /registerdns`, `netsh winsock reset`, `netsh int ip reset`, proxy cleanup, `netsh winhttp reset proxy` — each repair reads the result back (the address, the resolver, the WinHTTP value) and fails honestly if nothing changed; the WinHTTP repair names the command that restores the old proxy |
| **Event Log & Crash Analysis** | Critical/Error event bursts in last 24h, WHEA hardware error architecture logs, `%SystemRoot%\Minidump` BSOD crash dumps, the result of the last Windows Memory Diagnostic (90 days) | Corrupted log channel cleanup, crash dump analysis, hardware diagnostic recommendations; a failed memory test is reported unticked, since no software repair fixes RAM |
| **Storage & Filesystem** | Dirty Bit detection (`fsutil dirty query C:`), SMART drive health, `%TEMP%` & `C:\Windows\Temp` junk accumulation, bloated `IconCache.db` | Triggers online `chkdsk C: /scan`, cleans temp files, resets icon/thumbnail cache & restarts Explorer |
| **Registry & Autostart** | Orphaned `Run`/`RunOnce` startup keys, broken User Startup folder shortcuts, broken COM/Shell extension keys | Backs up target registry keys to `.reg` and safely removes invalid startup entries |
| **System & Cache Cleaner** | WinSxS component store bloat (`DISM /AnalyzeComponentStore`), Delivery Optimization cache, Installer package cache, browser caches (Chrome, Edge, Brave, every installed Opera flavour incl. GX, Firefox — all profiles), setup & CBS logs, WER crash archives, D3D shader & certificate caches, Recycle Bin, system temp | Runs `StartComponentCleanup`, purges the caches you select, and skips locked files instead of aborting the sweep. Only raises a finding once a target actually holds something worth reclaiming (10 MB, 50 MB for browser caches), so a directory Windows has begun refilling is not reported as an unfixed issue |
| **Scheduled Tasks** | Tasks whose action points at a deleted program (`Get-ScheduledTask`), tasks whose last run failed with a real error code rather than a `SCHED_S_*` status, tasks with missed runs — tasks that are already disabled are skipped, since they fire on no trigger | Disables the task with `Disable-ScheduledTask`, with dynamic task resolution and automated ACL escalation (`takeown` / `icacls`) for protected system tasks — reversible with `Enable-ScheduledTask`; nothing is deleted. The task's state is read back afterwards, so a disable Windows accepts without applying is reported as a failure rather than as a repair |
| **Page File & Memory** | Page file disabled with automatic management off (`Win32_PageFileUsage`), page file on a volume with under 10 % or 2 GB free, manually fixed limits below RAM/8 or with an inverted min/max range | Hands the page file back to Windows (system managed) or re-enables automatic management; the nearly-full-drive finding is advisory and changes nothing |
| **WHEA Hardware Logger** | Windows Hardware Error Architecture (WHEA) physical faults: CPU Cache Hierarchy (Event 19), Fatal Machine Checks (Event 18), PCIe Root Port bus errors (Event 17), RAM/Memory controller parity errors (Event 47), Storage CPER records (Event 1) | Automatic PCIe ASPM power management optimization (`powercfg`) to prevent bus dropouts, schedules Windows Memory Diagnostic (`mdsched.exe`), provides exact hardware core/APIC-ID and bus:device:function triangulation and BIOS tuning guidance |
| **Tweaks & Policies** | What tweak and debloat tools leave behind: 24 core services disabled (DHCP, DNS, Event Log, WMI, audio, update, Store, sign-in, time, search …), Windows Update and Store policies on a PC outside a domain, hosts entries that block update, Store, activation, sign-in or certificate-revocation endpoints (telemetry blocks are left alone) | Sets the service back to Automatic or Manual and reads the start type back; backs up and deletes exactly the policy values named (never ones from the local Group Policy); backs up the hosts file and comments out only the blocking names |
| **Clock & Restart** | Clock offset against `time.windows.com` (`w32tm /stripchart`, 1 min = warning, 1 h = critical), Windows running 14 days or more without a restart — counting sleep and Fast Startup "shutdowns", which do not end it | `w32tm /resync /force` and a new measurement; with Fast Startup on, turns it off (registry backup, read back) so "Shut down" starts Windows fresh, then asks for one restart |

Package Cache and Recycle Bin are classified `RiskScore::High` and are **deselected by default**, so `--auto-fix` never empties them unattended. Every Page File & Memory finding is `RiskScore::High` for the same reason — each one needs a restart before it takes effect — and is likewise deselected. A scheduled task that merely *fails*, rather than pointing at a deleted program, is deselected too: switching it off is a judgement call, so it is left for you to tick. So is the overdue restart: turning Fast Startup off trades boot speed for a clean start, which is yours to decide.

### A repaired finding stays repaired

A scan must not re-raise what a repair has already dealt with, and must not raise anything a repair could never clear. Three rules enforce that:

- **A disabled scheduled task is not a finding.** Disabling is the only thing the repair does, and Windows never resets a task's `LastTaskResult` or restores its deleted program — so a task the scan reported again after it had been switched off could never be cleared, no matter how often you repaired it.
- **Cleanup targets have a floor.** Every directory the cleaner sweeps is one the system refills by itself: a service writes its next log line, Explorer rewrites the Recycle Bin's `desktop.ini` shell stub, a browser caches the next favicon. Below the floor there is nothing to decide, so nothing is reported.
- **DNS is tested through your resolver, and verified after the repair.** The check never pins a public DNS server, because networks that block outbound port 53 would otherwise produce a permanent critical finding that `ipconfig /flushdns` cannot possibly fix. After the repair the resolver is asked again, and the fix fails with the reason if names still do not resolve.
- **A service repair is read back.** After setting a disabled service to start on demand, WinMedic asks Windows for the start type again; a group policy that silently keeps the service disabled turns the repair into a failure with that reason, not into a "fixed" that the next scan contradicts.

### Every display language, not just English

The tools WinMedic asks — DISM, `sc`, `wevtutil`, `netsh`, `fsutil` — answer in the Windows display language, and each writes into a pipe in its own encoding: the OEM code page, UTF-16 or UTF-8. WinMedic therefore:

- reads **language-neutral values** wherever one exists: `sc qc`'s numeric start type, DISM run with `/English`, event records as XML, WMI booleans, file paths and GUIDs;
- **decodes each tool's encoding** instead of assuming UTF-8, so an umlaut is an umlaut and a streamed repair log does not stop at the first one;
- treats a command that was **refused** — DISM without elevation, a rejected query — as "not checked", never as "healthy".

Where Windows offers nothing but a translated sentence, only the English and German wordings are known, and any other language yields a missed finding rather than an invented one. The parsers are tested against output captured from real Windows installations ([tests/fixtures](../tests/fixtures/README.md)), and CI runs a real scan on every change.


## Safety & Backup Architecture

Before WinMedic touches your system:
1. **Windows System Restore Point (VSS)**: A checkpoint named `"WinMedic Auto-Restore Point (Vor Reparatur)"` is automatically triggered via WMI / PowerShell. WinMedic then **verifies** that a new restore point actually appeared instead of trusting the exit status — Windows silently declines to create one if another was made within the last 24 hours (`SystemRestorePointCreationFrequency`), and reports that refusal as a warning rather than an error. A throttled run is surfaced as a warning, never as success.
2. **Registry Snapshotting**: Every modified registry key is exported into `%APPDATA%\WinMedic\backups\reg_<timestamp>.reg` prior to modification. If the export fails, the fix is aborted instead of applied. The backup index is written atomically, and an index that cannot be parsed is moved aside as `index.json.corrupt-<timestamp>` rather than overwritten, so previously recorded backups are never lost.
3. **One-Key Rollback**: Any stored snapshot can be restored directly from the **`[2]` Settings** view — `[B]` moves the arrow keys onto the snapshot list, `[U]` restores the highlighted one after an explicit confirmation prompt.
4. **Dry-Run First**: the simulation switch in the window or `--dry-run` on the CLI lists every command a repair would execute, without executing any of it.
5. **High-Performance Audit Logging**: Every scan, fix, simulation, rollback, and cancellation is appended in $O(1)$ to `%APPDATA%\WinMedic\logs\history.jsonl` (with automatic 5 MB log rotation) and formatted human-readable `%APPDATA%\WinMedic\logs\audit.log`.
6. **Self-Contained Report Export**: Complete diagnostic findings can be exported at any time with `[E]` or `--output <file>` as responsive, standalone HTML, Markdown, or JSON reports.


## Configuration

Settings live in the **`[2]` Settings** view and are persisted to `%APPDATA%\WinMedic\config.json` immediately on change. The same view carries the safety surface — VSS restore points, registry snapshots, recent activity from the audit trail and the `[U]` rollback — with `[B]` switching the arrow keys between the settings list and the snapshot list.

| Setting | Default | Effect |
| :--- | :--- | :--- |
| VSS restore point before repair | `on` | Creates a system checkpoint before the first fix of a run |
| Back up registry before change | `on` | Exports affected keys to `.reg`; when off, registry fixes run unprotected |
| Restart services automatically | `on` | Allows fixes to stop/start Windows services; when off, those fixes are skipped rather than half-applied |
| Check for updates automatically | `on` | Queries the latest GitHub release on startup and flags a newer version with `[U]`, which can then install it in place after verifying its checksum |
| Temp file threshold | `500 MB` | Size at which junk files are reported as an issue |
| Event log window | `24 h` | How far back the event log module searches for critical events |


## Update Check & In-Place Update

On startup WinMedic asks GitHub for the latest release and, if a newer version exists, announces it in the status line. Nothing happens until you press **`[U]`**, which opens a dialog describing exactly what it is about to do; nothing is ever downloaded or installed without that explicit yes.

When the release publishes both the binary and its `.sha256` — every release cut by the release workflow does — the dialog offers to **download, verify and install it in place**:

1. `winmedic-<tag>.exe` is downloaded to a staging file *next to the current executable*
2. the `.sha256` published with the release is downloaded as well
3. the staged file is hashed and must match that checksum exactly
4. if the download carries an Authenticode signature Windows rejects, it is refused
5. only then is the running binary renamed aside and the new one moved into its place

The old binary stays parked as `winmedic.exe.old-<tag>` until the next start — a running image cannot delete itself — and is swept up automatically then. **The running process is still the old version**; restart WinMedic to actually run the new one, which is what the confirmation message says.

If *any* of that fails — the download never arrives, the checksum does not match, the file cannot be replaced — nothing is touched, the release page opens in your browser instead, and the status line states the reason. Successful and refused updates are both written to `%APPDATA%\WinMedic\logs\history.jsonl`.

### What the verification is and is not worth

The checksum is fetched over the same channel, from the same host, as the binary. It proves the download is intact and is the file the release says it is; it does **not** independently prove the release itself is trustworthy. Since WinMedic ships unsigned (see *Download and uninstall* below), step 4 can today only reject a *broken* signature — once the project has a code-signing certificate, that step becomes the check that closes the gap. The dialog and the audit entry say which of the two you got rather than implying a guarantee that is not there.

Releases without a checksum are still announced, but are never installed in place: `[U]` offers only the browser download for them, because there would be nothing to hold the downloaded bytes to.

The check itself is deliberately conservative: release *and* asset URLs must start with `https://github.com/` and may not contain shell metacharacters, downloads additionally have to come from `https://github.com/SecretLUL/WinMedic/releases/download/`, curl is pinned to HTTPS across redirects, asset names may not contain path separators, the browser is launched via `explorer.exe` rather than a shell, and draft and pre-releases are skipped. Version comparison is full SemVer including pre-release ordering, so `1.0.0-beta` correctly sorts below `1.0.0`. Disable the whole thing with the *Check for updates automatically* setting.

If you installed WinMedic through WinGet, prefer `winget upgrade SecretLUL.WinMedic`. The in-place update works there too, but WinGet keeps believing the version it installed is the one on disk.


## The Window

The window has two views, and everything you need for a checkup is on the first one:

- **Scan & Repair** — the top of the page says what state the PC is in and offers the one step that makes sense next: *Scan now* on a machine that has never been checked, *Repair* once there is something to repair, *Cancel* while something runs. What the rest of the page shows depends on the mode:
  - **Easy mode** (what WinMedic opens in) is one short column: how many problems there are, the health score, a box *What Repair does*, and two big buttons, *Repair* and *Scan again*. The box is a forecast built only from what the scan measured: the disk space the ticked cleanups counted ("Frees about 8.4 GB", or "at least" when the component store cleanup is among them, whose size DISM cannot tell beforehand), one line for each kind of repair that changes something you notice ("Windows Update works again", "The internet connection is repaired" …), and the health score once every repair has worked. Findings WinMedic cannot repair — critical events, crash history, a failing drive — are advice: they cannot be ticked, a repair run leaves them alone, and they keep counting against the health score. *Repair* repairs what the checks recommend (the findings ticked by default); the rest is counted in one line with a link to Advanced mode. Once only restarts are left, the page asks for one and offers *Restart now*.
  - **Advanced mode** shows the checks while a scan runs, and afterwards every finding with a tick box, filters, a search box and the technical details on the right. Each finding shows its outcome (*Fixed*, *Repair failed*, *Restart*) as the run lands, the scan log and the repair output are one click away under *Show log*, and *Simulate only* lists what a repair would run without running it.

  `F7`, or the button top right next to *Export report*, switches between the two, as it does in a BIOS setup screen. WinMedic remembers the choice. In Easy mode the window keeps its smallest size, 960 × 640, and cannot be resized or maximized; Advanced mode gives it back at the size, or maximized, as it was.
- **Settings** — what WinMedic is allowed to do, plus everything to undo it: registry snapshots with rollback, system restore points, recent activity, the log folder, and *Remove WinMedic from Windows* for before you delete it.

The window follows the Windows light / dark app theme.

The window needs a graphics driver with OpenGL 2.0 or newer. On a PC whose driver has crashed back to the *Microsoft Basic Display Adapter*, and in some virtual machines and remote sessions, it cannot open; WinMedic then says so in a message box instead of silently doing nothing, and points to the command line below, where every check and repair still runs.


## Keyboard Navigation & Shortcuts

Every shortcut is also a button in the window; `[?]` lists them. Easy mode draws no tick boxes, filters or simulation switch, so on Scan & Repair it leaves the keys for them — `[Space]`, `[Enter]`, `[A]`, `[N]`, `[D]`, the filter keys and the list cursor — without effect, and `[?]` lists only the keys that work.

| Shortcut | Action |
| :--- | :--- |
| **`[F7]`** | Switch between Easy and Advanced mode — works from anywhere, even while typing in the search box |
| **`[1]` / `[2]`** | Switch views (Scan & Repair, Settings) |
| **`[Ctrl+Tab]` / `[Ctrl+Shift+Tab]`** | Cycle through the views (plain `[Tab]` moves focus between controls) |
| **`[S]`** | Start full system health scan |
| **`[R]`** | Re-run scan / refresh current view |
| **`[Space]`** | Toggle checkbox selection for highlighted issue (toggles a switch in Settings) |
| **`[c]` / `[w]` / `[i]`** | Filter findings by severity (Critical / Warning / Info) |
| **`[m]`** | Filter findings by diagnostic module (cycle through modules) |
| **`[/]`** | Fulltext live search across findings, details & descriptions |
| **`[x]`** | Reset all active filters and search queries |
| **`[A]`** | Toggle select / deselect all visible detected issues (1-Click Auto-Fix) |
| **`[N]`** | Deselect all issues |
| **`[F]`** | Repair the ticked findings |
| **`[D]`** | Toggle dry-run mode — repairs are shown, not executed |
| **`[E]`** | Export diagnostic & repair report as self-contained HTML |
| **`[B]`** | Settings: move `[↑]`/`[↓]` between the settings list and the registry snapshot list |
| **`[U]`** | Settings: restore the selected registry snapshot — elsewhere: open the pending "update available" notice, which can download, verify and install the new version |
| **`[PgUp]` / `[PgDn]` / `[Home]` / `[End]`** | Move the findings selection by a page, or to the first / last finding (the logs scroll with the mouse wheel and their own scrollbars) |
| **`[←]` / `[→]` or `[h]` / `[l]`** | Switch views (wraps around) |
| **`[+]` / `[-]` or `[[` / `]]`** | Adjust the highlighted numeric setting (Settings) |
| **`[↑]` / `[↓]` or `[j]` / `[k]`** | Navigate list items |
| **`[?]`** | Open interactive Help Modal overlay |
| **`[Esc]`** | Clear filters / abort a running operation / close modal / return to Scan & Repair |
| **`[Q]`** | Exit WinMedic safely |


## CLI Headless Automation Mode

WinMedic can also run without opening its window, for automated scripts, CI/CD, or batch IT deployments. Every flag below keeps the console it was started from, so exit codes, pipes and redirects behave exactly as a script expects:

```bash
# Run headless system scan and output styled summary
winmedic.exe --scan

# Run scan and export self-contained HTML report for clients / archiving
winmedic.exe --scan --output report.html

# Export report in Markdown or JSON format
winmedic.exe --scan --output report.md
winmedic.exe --scan --output report.json

# Run scan and automatically repair all safe detected issues
winmedic.exe --auto-fix

# Run fixes and export updated report with audit history
winmedic.exe --auto-fix --output final_report.html

# Show exactly which commands a repair run would execute, without executing them
winmedic.exe --dry-run

# Output diagnostic findings as structured JSON for automation
winmedic.exe --json

# Run fixes without creating a VSS restore point (e.g. for speed in VM testing)
winmedic.exe --auto-fix --no-vss

# Request Windows Administrator elevation
winmedic.exe --elevate

# Before deleting winmedic.exe: remove the background task and the "Start with Windows" entry
winmedic.exe --uninstall

# ...and delete settings, logs, reports and registry backups as well
winmedic.exe --uninstall --purge
```

A running headless job can be aborted with `Ctrl+C`; WinMedic terminates the child process it is currently waiting on instead of leaving an orphaned `DISM` or `chkdsk` behind.

### Exit Codes

Headless runs report their outcome through `%ERRORLEVEL%`, so scripts and monitoring agents can branch on the result:

| Code | Meaning |
| :---: | :--- |
| `0` | No open issues above informational level |
| `1` | Open warnings |
| `2` | Open critical issues |
| `3` | At least one repair failed |
| `4` | `--auto-fix` requested without Administrator privileges |
| `5` | Internal WinMedic error |
| `6` | Run aborted with `Ctrl+C`; findings are incomplete |

```powershell
winmedic.exe --scan
if ($LASTEXITCODE -ge 2) { Write-Host "Kritische Befunde – Ticket eroeffnen" }
```


## Download and uninstall

### Verify a download by hand

Grab `winmedic-<version>.exe` from the [latest release](https://github.com/SecretLUL/WinMedic/releases/latest).

WinMedic is **not code-signed**, so Windows SmartScreen will warn you on first launch ("Windows protected your PC" → *More info* → *Run anyway*). Because of that, every release ships a `.sha256` file next to the binary — verify the download before running it with Administrator rights:

```powershell
# Compare the published checksum against the file you downloaded
$exe      = Get-Item .\winmedic-v*.exe | Select-Object -First 1
$expected = (Get-Content "$($exe.FullName).sha256").Split(' ')[0]
$actual   = (Get-FileHash $exe.FullName -Algorithm SHA256).Hash.ToLower()
if ($expected -eq $actual) { "OK - checksum matches" } else { "MISMATCH - do not run this file" }
```

The checksum is generated by the release workflow from the exact binary it publishes, and release builds run with `--locked` so the published artifact is reproducible from the tagged source tree. WinMedic's own in-place updater runs this same comparison for you — see *Update Check & In-Place Update* above.

### Uninstall

WinMedic is one file with no installer, and it stays that way: it runs from a USB stick on a PC that is already in trouble, and it does not depend on the Windows Installer service, which can be broken too. What it does register with Windows — the background scan task and the *Start with Windows* entry, when you turn them on — has to be removed before the file goes, or both keep pointing at a program that no longer exists:

```powershell
winmedic --uninstall          # removes both and turns the settings off; data stays
winmedic --uninstall --purge  # also deletes %APPDATA%\WinMedic (settings, logs, registry backups)
winget uninstall SecretLUL.WinMedic   # or just delete the .exe
```

The window offers the first step as *Settings → Remove WinMedic from Windows*.


## Building From Source

### Prerequisites
* **Windows 10 / 11** (64-bit)
* **Rust 1.95+** (`cargo` and `rustc`) — the MSRV is declared as `rust-version` in `Cargo.toml` and enforced by CI
* **MSVC build tools** — the Windows SDK supplies the `rc.exe` that `build.rs` uses to embed the icon and version resources

### Build Steps

```powershell
# 1. Clone the repository
git clone https://github.com/SecretLUL/WinMedic.git
cd WinMedic

# 2. Build optimized release binary (--locked mirrors how releases are built)
cargo build --locked --release

# 3. The executable is located at:
.\target\release\winmedic.exe
```

