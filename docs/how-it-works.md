# How WinMedic works

The [README](../README.md) says what WinMedic does. This page is the detail
behind it: exactly what each check looks at and runs, how repairs are made safe,
what can be undone and how, the settings, the update check, every shortcut and the command
line.

## Core Diagnostic & Healing Modules

| Module | What It Checks | What It Fixes |
| :--- | :--- | :--- |
| **System Integrity** | DISM Component Store corruption, SFC system file integrity, CBS logs, VSS shadow copy health, a switched-off Windows Recovery Environment (`InstallState` in `ReAgent.xml`), WMI classes that fail to answer, app packages of this user whose `Status` is not `Ok` (`Get-AppxPackage`: Start, Settings, the Store), feature installations Windows rolled back at a start: an advanced installer's `Failed execution of queue item Installer: <name> ({GUID}) with HRESULT ...` and then the queue's `CBS_E_INSTALLERS_FAILED` (0x800f0922), in the last 8 MB of CBS.log and of each `CbsPersist_*.log`, unless a later start ran the same installer through (a rollback found there is checked against the logs as a whole, read a line at a time, so an installation further back in a newer log still counts). For the Container Installer (Windows Sandbox and other container features) it names what keeps the service it waits for, CmService, from starting, down to the device | Runs `DISM /RestoreHealth`, `sfc /scannow`, repairs Volume Shadow Copy services, `reagentc /enable`, `winmgmt /salvagerepository` — the last two read the state back afterwards. A rolled-back feature installation is advice: repair what its installer waited for, restart, then install the feature again. SFC exits 0 whatever it found, so its result is read from the lines it adds to CBS.log: files it repaired, and files it found damaged and left so. A damaged app package is registered again from its folder (`Add-AppxPackage -DisableDevelopmentMode -Register`), and its status is read back |
| **Windows Update & Services** | `wuauserv`, `bits`, `cryptsvc`, bloated `SoftwareDistribution\Download` cache, stuck reboot flags, updates that failed to install at least twice since the last install of the last 30 days (event 20 of `WindowsUpdateClient`, without Store apps and Defender signatures) | Sets a disabled service back to Manual and reads the start type back; empties the download cache between stopping the three services and starting them again, checking each one's state with `sc query`, and starts them again when the run ends early. Services that run and depend on them (`sc enumdepend`; AppLocker's Application Identity depends on `cryptsvc`) are stopped first and started again after them: `net stop` would ask before stopping them and, with nobody to answer, stop nothing. A failing update's `errorCode` names the repair: DISM for a damaged component store, free space, the network, proxy and hosts checks, the clock, a disabled service. Any other code offers the component reset Microsoft describes (starts unticked, the update history is empty afterwards): the three services stopped and checked, `SoftwareDistribution` and `catroot2` renamed, the services started and checked; the next scan shows whether the update installed. A restart Windows is waiting for is advice: the window offers the restart |
| **Network & DNS** | Physical adapters switched off in Windows (`AdminStatus` Down, which the address check never saw), physical adapters that asked for a DHCP address and got only a 169.254.x.x stand-in, DNS name resolution through the machine's *own* resolver (`Resolve-DnsName`, two independent names, never a pinned public server), DNS servers typed in on a connected adapter (`NameServer` under `Tcpip\Parameters\Interfaces`) of which none answers `Resolve-DnsName -Server` (judged only while 1.1.1.1 answers a ping), a ping to 1.1.1.1 by address (no name lookup), asked only when names do not resolve or none of the DNS servers typed in on an adapter answers, Winsock catalog entries whose DLL is gone, a proxy set for the user that nothing answers at, a WinHTTP proxy (the one Windows Update and the Store use) that nothing answers at | `Enable-NetAdapter` for a switched-off adapter (ticked only when no other adapter is connected), `ipconfig /renew <adapter>`, automatic DNS again for an adapter whose servers are dead (the adapter's TCP/IP key is backed up first, `Set-DnsClientServerAddress -ResetServerAddresses`, the old servers are named), `ipconfig /flushdns`, `ipconfig /registerdns`, `netsh winsock reset` (needs a restart, starts unticked), switching the dead user proxy off (its address is kept), `netsh winhttp reset proxy` — each repair reads the result back (the adapter's `AdminStatus`, the address, the DNS servers, the resolver, the proxy switch, the WinHTTP value) and fails honestly if nothing changed. The one exception is the Winsock reset: it takes effect only after a restart, so nothing is read back, and the next scan after the restart checks the catalog again. Being offline altogether is advice: the router, the cable or the Wi-Fi, not Windows |
| **Memory Test Results** | The result of the last Windows Memory Diagnostic (90 days) | Nothing: a failed memory test is advice, since no software repair fixes RAM |
| **Crash Dump & BSOD Analyzer** | Kernel minidumps of the last 30 days and bugcheck / unexpected-shutdown events: stop codes, GPU timeouts, memory-class stop codes. Any other crash is reported by its stop code; no driver is named, since a dump lists every driver that was loaded, not the one that crashed. One crash is reported as one, from two on as a recurring history. When there are at least two crashes: what changed in the week before the first one of the last 30 days, from the event logs — updates from Windows Update (without Store apps and Defender signatures), kernel drivers at their first install (only when the System log reaches back before that week, since tools register their driver again on every start), programs installed with Windows Installer. Explorer crashing at least twice in 30 days in a module outside Windows (Application Error 1000, `AppName` explorer.exe, `ModulePath`), named by the program its version resource names | Schedules the Windows Memory Diagnostic for the next start (`bcdedit /bootsequence {memdiag}`, needs a restart, starts unticked) for memory-class crashes; deletes crash dumps older than 30 days and reports how many were deleted. GPU crashes, the crash history and the changes before the crashes are advice: the dumps of the last 30 days are the evidence and stay. An Explorer add-on that keeps crashing it can be blocked (starts unticked; updating or uninstalling the program is the better fix): the CLSIDs the DLL is registered under (`reg query ... \CLSID /s /d /f`, HKLM and HKCU) are added to `Shell Extensions\Blocked` after a backup of that key, and read back |
| **Storage & Filesystem** | Dirty bit on C: (WMI `DirtyBitSet`, `fsutil dirty query` as the fallback), SMART drive health, storage errors Windows logged in the last 30 days (disk 7, 51, 153, Ntfs 55, stornvme and storahci 129, warnings and errors only), temporary files in `%TEMP%` and `%SystemRoot%\Temp` (counted in bytes), an icon cache (`Explorer\iconcache_*.db`) above 256 MB | Runs `chkdsk C: /scan` and reads its exit code and the dirty bit back (Windows checks the drive at the next start and clears the bit); cleans the temp folders and says what it freed; rebuilds the icon cache by stopping Explorer, deleting it and starting Explorer again (starts unticked). Storage errors are advice: back up first, then the cable and the maker's test tool |
| **Registry & Autostart** | `Run` entries (HKCU and HKLM) whose program is gone | Backs up the `Run` key to `.reg`, deletes the entry by its real name and reads the key back |
| **System & Cache Cleaner** | WinSxS component store bloat (`DISM /AnalyzeComponentStore`), Delivery Optimization cache, browser caches (Chrome, Edge, Brave, every installed Opera flavour incl. GX, Firefox — all profiles), setup & CBS logs (not CBS.log or the `CbsPersist_*.log` files, which System Integrity reads), WER crash archives, D3D shader & certificate caches, your Recycle Bin (this account's, on the fixed drives), system temp | Runs `StartComponentCleanup` and counts the reclaimable packages before and after it: a cleanup that removed none is a failed repair. DISM counts packages the cleanup never removes, such as the 24H2 checkpoint cumulative update, so the number it left is kept in `%APPDATA%\WinMedic` and the finding comes back only when DISM reports a different one. Purges the caches you select, and skips locked files instead of aborting the sweep. Only raises a finding once a target actually holds something worth reclaiming (10 MB, 50 MB for browser caches), so a directory Windows has begun refilling is not reported as an unfixed issue |
| **Scheduled Tasks** | Tasks whose action points at a deleted program (`Get-ScheduledTask`), tasks whose last run failed with a real error code rather than a `SCHED_S_*` status (1056 from `sc.exe` is a success: the service it was to start ran already), tasks with missed runs — tasks that are already disabled are skipped, since they fire on no trigger | Disables the task with `Disable-ScheduledTask` — reversible with `Enable-ScheduledTask`; nothing is deleted. A task Windows protects refuses, and stays as it is. Windows' own tasks (`\Microsoft\Windows\`, and Explorer's `CreateExplorerShellUnelevatedTask`) are never switched off: switched off, what they look after (the clock, Secure Boot updates) stops without a word, so their findings are advice. A failing Office task (`\Microsoft\Office\`) is advice too: Office registers its tasks again with every update, which switches a disabled one back on. The task's state is read back afterwards, so a disable Windows accepts without applying is reported as a failure rather than as a repair |
| **Page File & Memory** | No page file set up on any drive (`PagingFiles` in the registry), page file on a volume with under 10 % or 2 GB free, manually fixed limits below RAM/8 or with an inverted min/max range | Hands the page file back to Windows (system managed) or re-enables automatic management; the nearly-full-drive finding is advisory and changes nothing |
| **WHEA Hardware Logger** | Windows Hardware Error Architecture (WHEA) physical faults of the last week at least: CPU Cache Hierarchy (Event 19), Fatal Machine Checks (Event 18), PCIe Root Port bus errors (Event 17), RAM/Memory controller parity errors (Event 47), Storage CPER records (Event 1) | Switches PCIe Link State Power Management off (`powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0`, on mains and battery), reads it back and names the old values; schedules the Windows Memory Diagnostic for the next start (starts unticked); names the core (APIC ID) and bus:device:function |
| **Tweaks & Policies** | What tweak and debloat tools leave behind: 24 core services disabled (DHCP, DNS, Event Log, WMI, audio, update, Store, sign-in, time, search …), Windows system devices disabled in Device Manager (problem code 22, matched by hardware ID): the Microsoft Hypervisor Service, without which HvHost fails and Windows Sandbox does not install, and as unticked hints the NDIS Virtual Network Adapter Enumerator and the High Precision Event Timer; services that stopped with an error (`sc query`: stopped, an exit code other than 0 and 1077, "never started"), followed through what they depend on (`DependOnService` from `sc qc`, at most six services deep, past services that run) to the drivers and the devices bound to them that report a problem code - the chain, such as "CmService cannot start: HvHost failed (exit code 31) because the device 'Microsoft Hypervisor Service' is disabled", leads that device's finding and makes a hint a ticked warning, or is advice of its own for a device that is no Windows system device; `SvcHostSplitThresholdInKB` above the memory Windows has (`GlobalMemoryStatusEx`), which keeps services grouped in shared processes as on PCs with under 3.5 GB, Windows Update and Store policies on a PC outside a domain (the Store policies only on Enterprise and Education, by `EditionID`: Home and Pro do not read them; 'Check for updates' switched off by policy, `SetDisableUXWUAccess`, is a hint, since updates still install; `DoNotConnectToWindowsUpdateInternetLocations` counts only with a WSUS server, without which it does nothing), Defender switched off by policy (`DisableAntiSpyware`, `DisableRealtimeMonitoring` and the like) while `Get-MpComputerStatus` reports real-time protection off and Windows Security knows no other antivirus switched on, hosts entries that block update, Store, activation, sign-in or certificate-revocation endpoints (telemetry blocks are left alone) | Sets the service back to Automatic or Manual and reads the start type back. Windows does not let Administrators change six of them with `sc config` (DNS Client, Base Filtering Engine, Windows Defender Firewall, Windows Installer, AppX Deployment Service, Client License Service): for those it backs up `Start` under `HKLM\SYSTEM\CurrentControlSet\Services\<service>`, writes it and reads it back from the registry; Windows applies it at the next restart, so that repair starts unticked and waits for the restart; enables a disabled system device with `Enable-PnpDevice` (once, however many services wait for it) after backing up its `ConfigFlags`, and reads its problem code back (not `pnputil /enable-device`, which refuses a device that has been disabled since Windows started); sets `SvcHostSplitThresholdInKB` back to 3.5 GB (3670016) after backing it up and reads it back, which takes effect after a restart; backs up and deletes exactly the policy values named (never ones from the local Group Policy), and for Defender checks that real-time protection comes on again; backs up the hosts file and comments out only the blocking names |
| **Clock & Restart** | Clock offset against `time.windows.com` (`w32tm /stripchart`, 1 min = warning, 1 h = critical), Windows running 14 days or more without a restart — counting sleep and Fast Startup "shutdowns", which do not end it | `w32tm /resync /force` and a new measurement; with Fast Startup on, turns it off (registry backup, read back) so "Shut down" starts Windows fresh, then asks for one restart. With Fast Startup off, the overdue restart is advice: restart Windows |
| **Devices & Drivers** | Connected devices with a problem code, the warning sign in Device Manager, asked of the device manager itself (SetupAPI and CfgMgr32, no WMI): stopped, driver failed to load or start, no driver. Disabled, disconnected and safely removed devices are left alone; Windows' own system devices that tuning tools disable are reported by Tweaks & Policies. A stuck print queue: print jobs in `spool\PRINTERS` older than an hour, or a spooler set to start automatically that is stopped (a spooler switched off on purpose is left alone) | `pnputil /restart-device` for a stopped device, `pnputil /scan-devices` for a missing driver. Both read the device's state back, since pnputil exits 0 even when it was refused. Before Windows 10 2004 pnputil has neither switch, and the findings point to Device Manager instead. A blocked or unsigned driver, a switched-off driver service and a device waiting for Windows to restart are advice: restarting the device cannot clear them. The print queue: `net stop spooler`, after the services that run and depend on it (Fax, for one), and a check that it stopped, the waiting jobs deleted, `net start spooler` and then those services, then a check that they run and the folder is empty (the waiting jobs are lost) |

The Recycle Bin is classified `RiskScore::High` and is **deselected by default**, so `--auto-fix` never empties it unattended. Every Page File & Memory finding is `RiskScore::High` for the same reason — each one needs a restart before it takes effect — and is likewise deselected. A scheduled task that merely *fails*, rather than pointing at a deleted program, is deselected too: switching it off is a judgement call, so it is left for you to tick. So is the overdue restart: turning Fast Startup off trades boot speed for a clean start, which is yours to decide. And a device without a driver: Windows already looked for one when the device arrived, and it is often an extra function nobody uses. The Winsock reset, the memory test, the service grouping threshold and the icon cache rebuild start unticked as well: the first three need a restart, the last restarts Explorer. The installer package cache is deliberately left alone: Microsoft advises against emptying it, and repairing or uninstalling the products installed from it needs those installers.

### A repaired finding stays repaired

A scan must not re-raise what a repair has already dealt with, and must not raise anything a repair could never clear. Three rules enforce that:

- **A disabled scheduled task is not a finding.** Disabling is the only thing the repair does, and Windows never resets a task's `LastTaskResult` or restores its deleted program — so a task the scan reported again after it had been switched off could never be cleared, no matter how often you repaired it.
- **Cleanup targets have a floor.** Every directory the cleaner sweeps is one the system refills by itself: a service writes its next log line, Explorer rewrites the Recycle Bin's `desktop.ini` shell stub, a browser caches the next favicon. Below the floor there is nothing to decide, so nothing is reported.
- **DNS is tested through your resolver, and verified after the repair.** The check never pins a public DNS server, because networks that block outbound port 53 would otherwise produce a permanent critical finding that `ipconfig /flushdns` cannot possibly fix. After the repair the resolver is asked again, and the fix fails with the reason if names still do not resolve.
- **A service repair is read back.** After setting a disabled service to start on demand, WinMedic asks Windows for the start type again; a group policy that silently keeps the service disabled turns the repair into a failure with that reason, not into a "fixed" that the next scan contradicts. A service whose start type only the registry can change is read back from the registry: the service manager keeps reporting it disabled until Windows restarts.

### Every display language, not just English

The tools WinMedic asks — DISM, `sc`, `wevtutil`, `netsh`, `fsutil` — answer in the Windows display language, and each writes into a pipe in its own encoding: the OEM code page, UTF-16 or UTF-8. WinMedic therefore:

- reads **language-neutral values** wherever one exists: `sc qc`'s numeric start type, DISM run with `/English`, event records as XML, WMI booleans, file paths and GUIDs;
- **decodes each tool's encoding** instead of assuming UTF-8, so an umlaut is an umlaut and a streamed repair log does not stop at the first one;
- treats a command that was **refused** — DISM without elevation, a rejected query — as "not checked", never as "healthy".

Where Windows offers nothing but a translated sentence, only the English and German wordings are known, and any other language yields a missed finding rather than an invented one. The parsers are tested against output captured from real Windows installations ([tests/fixtures](../tests/fixtures/README.md)), and CI runs a real scan on every change.


## Safety & Backup Architecture

Before WinMedic touches your system:
1. **Windows System Restore Point (VSS)**: A checkpoint named `"WinMedic Auto-Restore Point (before repairs)"` is created through PowerShell before the first repair. Windows creates at most one restore point a day and silently skips the rest, so WinMedic sets `SystemRestorePointCreationFrequency` to 0 for its own checkpoint, as Microsoft documents, and puts the old value back right after. If System Protection is off for the system drive (`%SystemDrive%`, not always `C:`), `Enable-ComputerRestore` switches it on. WinMedic then **verifies** that a new restore point actually appeared instead of trusting the exit status. If none did, nothing is repaired: the window asks whether to repair without one, and the command line stops with exit code `3` unless it was started with `--no-vss`.
2. **Registry Snapshotting**: The registry keys WinMedic deletes values from or rewrites — `Run` entries, policy values, the Fast Startup switch — are exported into `%ProgramData%\WinMedic\backups\reg_<timestamp>.reg` first; a single value in a key too large to export whole, such as a device's `ConfigFlags` or `SvcHostSplitThresholdInKB`, and a service's `Start`, so that a rollback changes nothing else in its key, is backed up on its own, in a `.reg` file that holds just that value. The hosts file is copied there before it is edited; if the new hosts file does not read back as written, WinMedic puts back the bytes it read before. WinMedic creates that folder so that only Administrators and SYSTEM can change it, and writes into it only while that is so: a folder of that name that someone else made or can change is not used, and the message says to delete it. Each registry backup is then anchored in `HKLM\SOFTWARE\WinMedic\Backups`, which only Administrators and SYSTEM can change: one key per file, with the key that was backed up and the SHA-256 of the file, read through a handle that keeps the file from changing meanwhile. If the export fails or the backup cannot be anchored, the fix is aborted instead of applied. Other changes are not exported, and their message says how to undo them where that is possible: the user proxy switch (the address stays), `netsh winsock reset` and `netsh winhttp reset proxy`, service start types set with `sc config`, the page file (`PagingFiles`) and power settings (`powercfg`). The restore point covers them.
3. **One-Key Rollback**: Any stored snapshot can be restored directly from the **`[2]` Settings** view — `[B]` moves the arrow keys onto the snapshot list, `[U]` restores the highlighted one after an explicit confirmation prompt. `reg import` writes what the file says with Administrator rights, so a file is imported only when its anchor is there and nobody but Administrators and SYSTEM can change it, when the file hashes to the SHA-256 its anchor recorded, and when it holds nothing but the anchored key and the keys below it, the way `reg export` wrote it: no other key, and no `[-...]` line, which deletes a key. WinMedic holds the file open from reading it until `reg import` is done, so nobody can change, rename or delete it, or rename a folder above it, in between. Otherwise nothing is imported, and the message says which check failed. Who can change the folders above the backup folder does not matter: they decide whether a backup is still there, not whether it is genuine. Older versions kept the backups in `%APPDATA%\WinMedic\backups`, which every program the user runs can change; nothing anchors those, so WinMedic neither lists nor imports them. Look at one before importing it by hand with `reg import`.
4. **Dry-Run First**: the simulation switch in the window or `--dry-run` on the CLI lists every repair a run would make, by its description and its steps, without running any of it.
5. **High-Performance Audit Logging**: Every scan, fix, simulation, rollback, and cancellation is appended in $O(1)$ to `%APPDATA%\WinMedic\logs\history.jsonl` (with automatic 5 MB log rotation) and formatted human-readable `%APPDATA%\WinMedic\logs\audit.log`.
6. **Self-Contained Report Export**: Complete diagnostic findings can be exported at any time with `[E]` or `--output <file>` as responsive, standalone HTML, Markdown, or JSON reports. A report carries the audit entries of its own scan and repairs, not the whole history.


## Configuration

Settings live in the **`[2]` Settings** view and are persisted to `%APPDATA%\WinMedic\config.json` immediately on change. The same view carries the safety surface — VSS restore points, registry snapshots, recent activity from the audit trail and the `[U]` rollback — with `[B]` switching the arrow keys between the settings list and the snapshot list.

| Setting | Default | Effect |
| :--- | :--- | :--- |
| VSS restore point before repair | `on` | Creates a system checkpoint before the first fix of a run |
| Back up registry before change | `on` | Exports affected keys to `.reg`; when off, registry fixes run unprotected |
| Restart services automatically | `on` | Allows repairs to stop and start Windows services. When off, a repair that has to stop a service (the update cache, the component reset, the print queue) is skipped rather than half-applied, a repaired start type is left for Windows to start, and the clock is only set while the Windows Time service already runs |
| Check for updates automatically | `on` | Queries the latest GitHub release on startup and flags a newer version with `[U]`, which can then install it in place after verifying its checksum |
| Temp file threshold | `500 MB` | Size at which junk files are reported as an issue |
| Event log window | `24 h` | How far back crash events are read (WHEA faults: at least a week) |
| Verbose / debug logs | `off` | Adds command lines, timings and tool output to the scan and repair logs |
| WinMedicHelper background scan | `off` | A scheduled task scans in the background while you are signed in, with the highest rights. Only for a `winmedic.exe` that only administrators can change, such as one in `C:\Program Files\WinMedic` or installed with `winget install SecretLUL.WinMedic --scope machine`: whoever can change the file would decide what that task runs as Administrator. In Downloads the setting is refused, and a task an older version set up there is removed |
| WinMedicHelper scan frequency | `24 h` | Every 1–23 hours or every whole number of days |


## Update Check & In-Place Update

On startup WinMedic asks GitHub for the latest release and, if a newer version exists, announces it in the status line. Nothing happens until you press **`[U]`**, which opens a dialog describing exactly what it is about to do; nothing is ever downloaded or installed without that explicit yes.

When the release publishes both the binary and its `.sha256` — every release cut by the release workflow does — the dialog offers **Download and restart**, which installs it in place:

1. `winmedic-<tag>.exe` is downloaded to a staging file *next to the current executable*
2. the `.sha256` published with the release is downloaded as well
3. the staged file is hashed and must match that checksum exactly
4. if the download carries an Authenticode signature Windows rejects, it is refused
5. only then is the running binary renamed aside and the new one moved into its place

WinMedic then starts the new version and closes itself; a scan or repair still running is finished first. The old binary stays parked as `winmedic.exe.old-<tag>` — a running image cannot delete itself — and the new version deletes it as soon as the old process has exited.

If *any* of that fails — the download never arrives, the checksum does not match, the file cannot be replaced — nothing is touched, the release page opens in your browser instead, and the status line states the reason. Successful and refused updates are both written to `%APPDATA%\WinMedic\logs\history.jsonl`.

### What the verification is and is not worth

The checksum is fetched over the same channel, from the same host, as the binary. It proves the download is intact and is the file the release says it is; it does **not** independently prove the release itself is trustworthy. Since WinMedic ships unsigned (see *Download and uninstall* below), step 4 can today only reject a *broken* signature — once the project has a code-signing certificate, that step becomes the check that closes the gap. The dialog and the audit entry say which of the two you got rather than implying a guarantee that is not there.

Releases without a checksum are still announced, but are never installed in place: `[U]` offers only the browser download for them, because there would be nothing to hold the downloaded bytes to.

The check itself is deliberately conservative: release *and* asset URLs must start with `https://github.com/` and may not contain shell metacharacters, backslashes or `.`/`..` path segments, downloads additionally have to come from `https://github.com/SecretLUL/WinMedic/releases/download/`, curl is pinned to HTTPS across redirects, asset names may not contain path separators, the browser is launched via `explorer.exe` rather than a shell, and draft and pre-releases are skipped. Version comparison is full SemVer including pre-release ordering, so `1.0.0-beta` correctly sorts below `1.0.0`. Disable the whole thing with the *Check for updates automatically* setting.

If you installed WinMedic through WinGet, prefer `winget upgrade SecretLUL.WinMedic`. The in-place update works there too, but WinGet keeps believing the version it installed is the one on disk.


## The Window

The window has two views, and everything you need for a checkup is on the first one:

- **Scan & Repair** — the top of the page says what state the PC is in and offers the one step that makes sense next: *Scan now* on a machine that has never been checked, *Repair* once there is something to repair, *Cancel* while something runs. What the rest of the page shows depends on the mode:
  - **Easy mode** (what WinMedic opens in) is one short column: how many problems there are, the health score, a box *What Repair does*, and two big buttons, *Repair* and *Scan again*. The box is a forecast built only from what the scan measured: the disk space the ticked cleanups counted ("Frees about 8.4 GB", or "at least" when the component store cleanup is among them, whose size DISM cannot tell beforehand), one line for each kind of repair that changes something you notice ("Windows Update works again", "The internet connection is repaired" …), and the health score once every repair has worked. Findings WinMedic cannot repair — hardware errors, crash history, a failing drive — are advice: they cannot be ticked, a repair run leaves them alone, and they keep counting against the health score. *Repair* repairs what the checks recommend (the findings ticked by default); the rest is counted in one line with a link to Advanced mode. Once only restarts are left, for repairs or for Windows' own updates, the page asks for one and offers *Restart now*; WinMedic never opens the restart dialog by itself.
  - **Advanced mode** shows the checks while a scan runs, and afterwards every finding with a tick box, filters, a search box and the technical details on the right. Each finding shows its outcome (*Fixed*, *Repair failed*, *Restart*) as the run lands, the scan log and the repair output are one click away under *Show log*, and *Simulate only* lists each repair and its steps without running them. *Archive* in a finding's details hides it for good: it leaves the list, Easy mode and the health score, no repair run touches it, and later scans keep it hidden (it is remembered by the finding's id, which names the device, task or drive). The line above the list counts the archived findings of the last scan.

  `F7`, or the button top right next to *Export report*, switches between the two, as it does in a BIOS setup screen. WinMedic remembers the choice. In Easy mode the window keeps its smallest size, 960 × 640, and cannot be resized or maximized; Advanced mode gives it back at the size, or maximized, as it was. On a screen with less room than that (1920 × 1080 at 175 %, say) the window is maximized and can be resized in both modes.
- **Settings** — what WinMedic is allowed to do, plus everything to undo it: the archived findings, each with *Show again* (a finding of the last scan is back at once, any other with the next scan), registry snapshots with rollback, system restore points, recent activity, the log folder, and *Remove WinMedic from Windows* for before you delete it.

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
| **`[Y]` / `[N]`** | Answer a dialog. Only `[Y]` says yes: `[Enter]` and `[j]` also move through lists, and the restart dialog restarts at once |
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

# Run fixes and export the updated report, with this run's audit entries
winmedic.exe --auto-fix --output final_report.html

# List each repair a run would make, with its description and steps, without executing them
winmedic.exe --dry-run

# Output diagnostic findings as structured JSON for automation
winmedic.exe --json

# Run fixes without creating a VSS restore point (e.g. for speed in VM testing).
# Without it, a run stops before the first repair when Windows creates none.
winmedic.exe --auto-fix --no-vss

# Before deleting winmedic.exe: remove the background scan task
winmedic.exe --uninstall

# ...and delete settings, logs, reports and registry backups as well
winmedic.exe --uninstall --purge
```

Findings archived in the window stay out here as well: the health score, the exit code, the console report, `--json` and `--auto-fix` count only the others. The HTML and Markdown reports say how many they leave out.

A running headless job can be aborted with `Ctrl+C`; WinMedic terminates the child process it is currently waiting on instead of leaving an orphaned `DISM` or `chkdsk` behind.

### Exit Codes

Headless runs report their outcome through `%ERRORLEVEL%`, so scripts and monitoring agents can branch on the result:

| Code | Meaning |
| :---: | :--- |
| `0` | No open issues above informational level |
| `1` | Open warnings |
| `2` | Open critical issues |
| `3` | At least one repair failed |
| `4` | Started without Administrator privileges |
| `5` | Internal WinMedic error |
| `6` | Run aborted with `Ctrl+C`; findings are incomplete |
| `7` | At least one check could not run, so the findings are incomplete |

`2` and `3` can also come with an incomplete scan; without `--json`, the console names each failed module as `[X] Module ... failed`.

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

WinMedic is one file with no installer, and it stays that way: it runs from a USB stick on a PC that is already in trouble, and it does not depend on the Windows Installer service, which can be broken too. What it does register with Windows — the background scan task, when you turn it on — has to be removed before the file goes, or it keeps pointing at a program that no longer exists:

```powershell
winmedic --uninstall          # removes the task and turns its setting off; data stays
winmedic --uninstall --purge  # also deletes %APPDATA%\WinMedic (settings, logs), %ProgramData%\WinMedic and HKLM\SOFTWARE\WinMedic (registry backups)
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

