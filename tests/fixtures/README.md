# Test fixtures

What Windows tools actually print, so the parsers are tested against real
output instead of against what someone assumed the output looks like.

That distinction has cost this project before. The DISM check looked for
"reparierbar", the service checks read the start type from `sc query` (which
never prints one), the crash analysis asked the event log for a provider that
Windows 10 and 11 no longer log bugchecks under — and every one of those had a
passing test, because each test fed the module the same wrong assumption the
module was written against.

## Rules

- **Capture, don't type.** A fixture is the bytes a tool wrote into a pipe,
  saved unchanged. Console output is stored as `.bin` because the encoding is
  part of what is being tested (see `src/utils/decode.rs`).
- **Scrub, don't invent.** Replace machine names and user-specific paths; keep
  everything else as captured. Say what was replaced below.
- **Mark what is constructed.** When no real sample exists, a fixture may be
  built in the exact shape of the real format. It is listed as constructed here,
  with the reason.

## Console output — `console/`

Captured on Windows 11 Pro 10.0.26200, German display language, OEM code page
850, unelevated, 2026-09-24.

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `dism_elevation_required_de.bin` | `dism /Online /Cleanup-Image /CheckHealth` | CP850 | Exit 740. The umlauts are single CP850 bytes, invalid as UTF-8. |
| `dism_elevation_required_english.bin` | same, with `/English` | ASCII | Shows that `/English` switches the language even on a German system. |
| `sfc_elevation_required_de.bin` | `sfc /verifyonly` | UTF-16LE | `sfc` writes UTF-16 into a pipe. |
| `sc_qc_disabled.bin` | `sc qc AppVClient` | CP850 | A disabled service: `START_TYPE : 4 DISABLED`. |
| `sc_qc_demand.bin` | `sc qc vss` | CP850 | `START_TYPE : 3 DEMAND_START`. |
| `sc_query_disabled_service.bin` | `sc query AppVClient` | CP850 | The same disabled service via `sc query`: only its state, no start type. |
| `netsh_winsock_catalog_de.bin` | `netsh winsock show catalog` | UTF-8 | German field labels, language-neutral paths. |
| `powershell_utf8.bin` | PowerShell with `[Console]::OutputEncoding` set to UTF-8 without BOM | UTF-8 | Proves no byte order mark is written. |
| `powershell_adapters_ipv4.bin` | The network module's adapter query (`Get-NetAdapter -Physical`, `Get-NetIPInterface`, `Get-NetIPAddress`) | UTF-8 | One wired adapter with a DHCP lease; its LAN address replaced with `192.168.1.10`. `Enabled` is an enum name, not translated. |
| `reg_query_wu_policy.bin` | `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /s` | CP850 | One harmless policy value (`ExcludeWUDriversInQualityUpdate`). |
| `reg_query_winhttp_direct.bin` | `reg query ...\Internet Settings\Connections /v WinHttpSettings` | CP850 | The binary blob of a WinHTTP configuration without a proxy. The network tests with a proxy set are **constructed** from it (setting one needs elevation and changes the machine): same header, access type 3, then the proxy and the bypass list as length and text. |
| `w32tm_stripchart_de.bin` | `w32tm /stripchart /computer:time.windows.com /samples:1 /dataonly` | CP850, LF | The sample line `19:23:06, +02.2742473s` is the same in every language; positive means this clock is behind (checked against an HTTP `Date` header). |
| `w32tm_stripchart_unreachable_de.bin` | same, against `192.0.2.1` (a documentation address nothing answers at) | CP850, LF | Exit 0, and the failure is translated: `Fehler: 0x800705B4`. |
| `reg_query_session_manager_power.bin` | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power"` | CP850 | `HiberbootEnabled` 0: Fast Startup off. The tests switch it to 1. |
| `reg_query_power.bin` | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Power"` | CP850 | `HibernateEnabled` 1, subkeys listed without values. |
| `reg_query_memory_management.bin` | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"` | CP850 | Captured 2026-09-25. `PagingFiles` is `?:\pagefile.sys` while `Win32_ComputerSystem` reports `AutomaticManagedPagefile` True: "Automatically manage paging file size for all drives". The tests replace it with an empty list. A `REG_MULTI_SZ` with several entries prints them joined by a literal `\0` (seen on `ServiceGroupOrder\List`). |
| `reg_query_missing_key_de.bin` | `reg query` of a key that does not exist (stderr, exit 1) | CP850 | The only translated part of `reg`'s output. |
| `pnputil_restart_device_denied_de.bin` | `pnputil /restart-device` of the Brio's interface, unelevated | Windows-1252 | Captured 2026-09-25. "Zugriff verweigert", yet **exit 0**: only the device's state afterwards tells whether a restart worked. pnputil writes in the ANSI code page (`ä` is `0xE4`), not the OEM one. |
| `pnputil_scan_devices_denied_de.bin` | `pnputil /scan-devices`, unelevated | Windows-1252 | Captured 2026-09-25. Exit 5 (access denied). |

Captured elevated on 2026-09-25, read-only commands, with the time each piece
of the pipe arrived:

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `dism_scanhealth_progress.bin` | `dism /English /Online /Cleanup-Image /ScanHealth` | ASCII | Every step of the bar is a line of its own, `\r[====  4.9%  ] \r\n`, written the moment it changes: 64-byte pieces over 65 seconds, 4.9% to 100.0%. Ends with "The component store is repairable." |
| `pnputil_scan_devices_elevated_de.bin` | `pnputil /scan-devices` | Windows-1252 | Exit 0 in under a second. The two devices without a driver still had none afterwards. |
| `pnputil_restart_device_no_driver_elevated_de.bin` | `pnputil /restart-device` of the Brio's interface without a driver | Windows-1252 | "Das Gerät wurde erfolgreich neu gestartet.", exit 0 - and the device went on reporting code 28. |
| `sfc_scannow_repaired_de.bin` | `sfc /scannow`, 80 seconds | UTF-16LE | "Der Windows-Ressourcenschutz hat beschädigte Dateien gefunden und erfolgreich repariert." Exit 0, like every SFC run captured here. |
| `sfc_verifyonly_progress_de.bin` | `sfc /verifyonly` | UTF-16LE | The bar is one line redrawn after `\r`, `Überprüfung 26 % abgeschlossen.`, ended only at 100 %. SFC writes into a pipe in 4 KB blocks, which arrived after 16, 31, 49 and 57 seconds and reach 26, 55, 83 and 100 %; the first one stops mid-word. Exit code 0 although it reports integrity violations. |

## Files — `files/`

| File | Content |
| --- | --- |
| `reagent_enabled.xml` | `C:\Windows\System32\Recovery\ReAgent.xml` of the capture machine, unchanged: the recovery environment's configuration, readable without elevation, with `InstallState state="1"` (enabled). |
| `cbs_sfc_verifyonly_found_damage.bin` | What the `sfc /verifyonly` run of `sfc_verifyonly_progress_de.bin` added to `C:\Windows\Logs\CBS\CBS.log`, cut out byte for byte (CRLF). Only `[SR] Verify` lines, then `DEPLOY [Pnp] Corrupt file: ...\BthA2dp.sys` and two more Bluetooth drivers: the damage SFC reported, in a format the older `[SR] Cannot repair member file` check never saw. |
| `cbs_sfc_scannow_repaired.bin` | What `sfc /scannow` (`sfc_scannow_repaired_de.bin`) added to CBS.log, captured elevated on 2026-09-25: `[SR] Repairing 0 components`, then `Corrupt file:` and `Repaired file:` for each of the three drivers. |
| `cbs_sfc_verifyonly_clean.bin` | What an `sfc /verifyonly` run right after it added: no `DEPLOY` line; SFC said "keine Integritätsverletzungen". |
| `hosts_blocking_update.bin` | The hosts file of the capture machine, byte for byte (UTF-8 with BOM, CRLF), its LAN address replaced with `192.168.1.10`. Next to telemetry blocks it blocks `fe3.delivery.mp.microsoft.com` — Windows Update's and the Store's metadata endpoint — and `ocsp.digicert.com`, which is what the hosts check exists to find. |

The English DISM verdicts used in `src/modules/system_integrity.rs` are DISM's
own strings, taken from `C:\Windows\System32\Dism\en-US\CbsProvider.dll.mui`;
the German fallbacks come from the `de-DE` copy of the same file. "The
component store is repairable." is also in `dism_scanhealth_progress.bin`.

## Event log — `events/`

`wevtutil qe System /q:<query> /f:xml /rd:true` on the same machine. The
`<Computer>` element was replaced with `WINMEDIC-TEST`; nothing else was changed.
The `.bin` files are the bytes wevtutil wrote, captured on 2026-09-25 from the
System and Application logs; in them a user's SID was also replaced, with
`S-1-5-21-0-0-0-<RID>`.

| File | Content |
| --- | --- |
| `kernel_power_41.xml` | Two real unexpected shutdowns, `BugcheckCode` 0. |
| `wer_bugcheck_1001.xml` | A real 0x9F bugcheck, logged by `Microsoft-Windows-WER-SystemErrorReporting` — not by `BugCheck`, which a query for that provider proves by returning nothing. |
| `system_errors.xml` | Five real level-2 events (Service Control Manager, DCOM). |
| `wevtutil_wu_installed_19_de.bin` | Every event 19 of `Microsoft-Windows-WindowsUpdateClient` ("installed") from 10 to 26 July 2026, captured 2026-09-25 as the bytes wevtutil wrote: in the ANSI code page, `für` as `f\xFCr` and the dash as `\x96`. Defender signature updates (KB2267602), Store apps (`serviceGuid` `{855e8a7c-…}`) and one Visual C++ security update. |
| `wevtutil_crashes_july.bin` | The crash events (Kernel-Power 41, WER-SystemErrorReporting 1001) of 26 and 27 July 2026: the first crashes of that machine's series, the first at `2026-07-26T20:02:01.0258131Z`. |
| `wevtutil_service_installed_7045.bin` | Every event 7045 of the Service Control Manager ("a service was installed") from 10 to 26 July 2026. `BEDaisy.sys` (BattlEye) first on the 25th, then again on every start of a game; Samsung Magician's `magdrvamd64.sys` on nearly every day; services that run an `.exe`. `ServiceType` is translated ("Kernelmodustreiber"), `ImagePath` is not. |
| `wevtutil_msi_installed_1033.bin` | Every event 1033 of `MsiInstaller` over the same days. Its `<Data>` elements have no names: product, version, language, status, manufacturer. |
| `wevtutil_system_oldest_event.bin` | `wevtutil qe System /c:1 /rd:false`: the oldest event in that System log, from 16 July 2026 — how far back it reaches. |
| `whea_constructed.xml` | **Constructed.** The capture machine has never logged a WHEA event. Built in the exact shape of the real events above, with the `EventData` field names WHEA-Logger uses (`ApicId`, `MCABank`, `MciStat`, `MciAddr`, `Bus`/`Device`/`Function`, `PhysicalAddress`). Replace it with a capture when one turns up. |

## Capturing more

Raw bytes, exactly as WinMedic receives them:

```powershell
$psi = New-Object System.Diagnostics.ProcessStartInfo 'dism.exe', '/English /Online /Cleanup-Image /CheckHealth'
$psi.RedirectStandardOutput = $true; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($psi)
$ms = New-Object System.IO.MemoryStream; $p.StandardOutput.BaseStream.CopyTo($ms); $p.WaitForExit()
[IO.File]::WriteAllBytes("$PWD\tests\fixtures\console\dism_checkhealth_healthy_english.bin", $ms.ToArray())
```

Captures from an elevated prompt and from other display languages (French,
Spanish, Japanese) are the most useful additions: they are what the language
independence of the checks is claimed for.
