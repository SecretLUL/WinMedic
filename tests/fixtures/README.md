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

## Files — `files/`

| File | Content |
| --- | --- |
| `reagent_enabled.xml` | `C:\Windows\System32\Recovery\ReAgent.xml` of the capture machine, unchanged: the recovery environment's configuration, readable without elevation, with `InstallState state="1"` (enabled). |
| `hosts_blocking_update.bin` | The hosts file of the capture machine, byte for byte (UTF-8 with BOM, CRLF), its LAN address replaced with `192.168.1.10`. Next to telemetry blocks it blocks `fe3.delivery.mp.microsoft.com` — Windows Update's and the Store's metadata endpoint — and `ocsp.digicert.com`, which is what the hosts check exists to find. |

The English DISM verdicts used in `src/modules/system_integrity.rs` are not a
capture — reading them needs elevation — but they are DISM's own strings, taken
from `C:\Windows\System32\Dism\en-US\CbsProvider.dll.mui`; the German fallbacks
come from the `de-DE` copy of the same file.

## Event log — `events/`

`wevtutil qe System /q:<query> /f:xml /rd:true` on the same machine. The
`<Computer>` element was replaced with `WINMEDIC-TEST`; nothing else was changed.

| File | Content |
| --- | --- |
| `kernel_power_41.xml` | Two real unexpected shutdowns, `BugcheckCode` 0. |
| `wer_bugcheck_1001.xml` | A real 0x9F bugcheck, logged by `Microsoft-Windows-WER-SystemErrorReporting` — not by `BugCheck`, which a query for that provider proves by returning nothing. |
| `system_errors.xml` | Five real level-2 events (Service Control Manager, DCOM). |
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
