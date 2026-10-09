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
| `reg_query_wu_policy.bin` | `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /s` | CP850 | One policy value, `ExcludeWUDriversInQualityUpdate` 1, set through the local Group Policy: drivers are kept out of Windows Update. Harmless for the tweaks module; the devices module names it when a device has no driver. |
| `reg_query_winhttp_direct.bin` | `reg query ...\Internet Settings\Connections /v WinHttpSettings` | CP850 | The binary blob of a WinHTTP configuration without a proxy. The network tests with a proxy set are **constructed** from it (setting one needs elevation and changes the machine): same header, access type 3, then the proxy and the bypass list as length and text. |
| `w32tm_stripchart_de.bin` | `w32tm /stripchart /computer:time.windows.com /samples:1 /dataonly` | CP850, LF | The sample line `19:23:06, +02.2742473s` is the same in every language; positive means this clock is behind (checked against an HTTP `Date` header). |
| `w32tm_stripchart_unreachable_de.bin` | same, against `192.0.2.1` (a documentation address nothing answers at) | CP850, LF | Exit 0, and the failure is translated: `Fehler: 0x800705B4`. |
| `reg_query_session_manager_power.bin` | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power"` | CP850 | `HiberbootEnabled` 0: Fast Startup off. The tests switch it to 1. |
| `reg_query_power.bin` | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Power"` | CP850 | `HibernateEnabled` 1, subkeys listed without values. |
| `reg_query_memory_management.bin` | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"` | CP850 | Captured 2026-09-25. `PagingFiles` is `?:\pagefile.sys` while `Win32_ComputerSystem` reports `AutomaticManagedPagefile` True: "Automatically manage paging file size for all drives". The tests replace it with an empty list. A `REG_MULTI_SZ` with several entries prints them joined by a literal `\0` (seen on `ServiceGroupOrder\List`). |
| `reg_query_missing_key_de.bin` | `reg query` of a key that does not exist (stderr, exit 1) | CP850 | The only translated part of `reg`'s output. |
| `pnputil_restart_device_denied_de.bin` | `pnputil /restart-device` of the Brio's interface, unelevated | Windows-1252 | Captured 2026-09-25. "Zugriff verweigert", yet **exit 0**: only the device's state afterwards tells whether a restart worked. pnputil writes in the ANSI code page (`ä` is `0xE4`), not the OEM one. |
| `pnputil_scan_devices_denied_de.bin` | `pnputil /scan-devices`, unelevated | Windows-1252 | Captured 2026-09-25. Exit 5 (access denied). |

Captured on 2026-09-26 on the same machine, read-only commands:

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `powershell_resolve_dns_google.bin` | The network module's resolver probe (`Resolve-DnsName -Type A_AAAA -DnsOnly`) for `dns.google` | UTF-8 | Four addresses, one per line, exit 0. Nothing translated. |
| `powershell_resolve_dns_nxdomain_de.bin` | The same probe for `winmedic-does-not-exist.invalid` | UTF-8 | Exit 1 and `FAILED\|DNS_ERROR_RCODE_NAME_ERROR,...\|<message>`: the error id is the same in every language, the message is German. |
| `powercfg_query_aspm_de.bin` | `powercfg /query SCHEME_CURRENT SUB_PCIEXPRESS ASPM` | CP850 | Labels translated; the two `0x` numbers at the end are the current index on mains (1) and on battery (2). The tests set both to 0. |
| `powercfg_setacvalueindex_missing_setting_de.bin` | `powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS 0` (stderr) | CP850 | Exit 1, "Ungültige Parameter": the command the ASPM repair used to run, without the setting, and still counted as a success. |
| `reg_query_internet_settings.bin` | `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"` | CP850 | `ProxyEnable` 0 and no `ProxyServer`. The tests with a proxy switch it on and add the server. |
| `reg_query_run_hklm.bin` | `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | CP850 | Three autostart entries, one `REG_EXPAND_SZ` with `%windir%`, one name with a space. The tests add a value whose program is gone. |
| `reg_query_current_build.bin` | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild` | CP850 | `26200`. The tests replace it with a build from before Windows 10 2004. |

Captured on 2026-09-27 on the same machine, unelevated, read-only commands:

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `powershell_physical_adapters.bin` | The network module's physical adapter query (`Get-NetAdapter -Physical`: `InterfaceGuid`, `Status`, `AdminStatus`, `Name`) | UTF-8 | One wired adapter, `Up` and `Up`. Switching it off needs elevation and cuts the machine off, so the tests replace both with `Disabled` and `Down`, what Windows reports for an adapter switched off under Network Connections. |
| `reg_query_tcpip_interfaces.bin` | `reg query HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces /s` | CP850 | Every interface's TCP/IP settings by `InterfaceGuid`, in lower case (PowerShell prints it in upper case). `NameServer` is empty everywhere: DNS comes from DHCP (`DhcpNameServer`). LAN addresses `192.168.178.x` replaced with `192.168.1.x` in the text; the binary `DhcpInterfaceOptions` is unchanged. The tests type servers into the wired adapter's `NameServer`. |
| `powershell_resolve_dns_server_timeout_de.bin` | The network module's probe of one DNS server (`Resolve-DnsName dns.google -Server 192.0.2.1 -DnsOnly -QuickTimeout`), a documentation address nothing answers at | UTF-8 | Exit 1 after 8 seconds, `FAILED\|ERROR_TIMEOUT,...\|<message>`: the id is the same in every language, the message is German. |
| `powershell_resolve_dns_server.bin` | The same probe of the router's DNS server | UTF-8 | Four addresses, exit 0. |
| `powershell_appx_packages.bin` | System Integrity's package query (`Get-AppxPackage`: `Status`, `PackageFullName`, `InstallLocation`) | UTF-8 | 163 packages of that user, every one `Ok`; `Status` is an enum name. The tests mark Start's package `Modified`. |
| `reg_query_clsid_find_dll_de.bin` | `reg query HKLM\SOFTWARE\Classes\CLSID /s /d /f VISSHE.DLL`, Visio's Explorer add-on | CP850 | Three `{CLSID}\InprocServer32` keys, each with the default value (translated name "(Standard)") and a value `InprocServer32`, both the DLL's path; then the translated "Suchvorgang abgeschlossen: 6 ..." line, which is not read. Exit 1 when nothing is found. |
| `reg_query_shell_ext_blocked.bin` | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"` | CP850 | One add-on blocked by an Epson program: a value named after its CLSID. The tests add Visio's. |
| `powershell_version_info.bin` | The crash analysis' version query of `VISSHE.DLL` (`CompanyName`, `ProductName`) | UTF-8 | `Microsoft Corporation\|Microsoft Office`: what the maker wrote, not translated. |
| `reg_query_defender_policy.bin` | `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /s` | CP850 | Only an empty `Policy Manager` subkey: no policy switches Defender off. The tests add `DisableAntiSpyware` and `Real-Time Protection\DisableRealtimeMonitoring`, as debloat tools write them. |
| `powershell_defender_status.bin` | The tweaks module's Defender query (`Get-MpComputerStatus`, `root/SecurityCenter2` `AntiVirusProduct`) | UTF-8 | `MP\|True`, and Defender as the only antivirus: `productState` 397568 (bits 12-15 are 1, switched on), `instanceGuid` `{D68DDC3A-…}`. The tests set `MP\|False` and add a third-party product. |
| `sc_qc_spooler.bin` | `sc qc spooler` | CP850 | `START_TYPE : 2 AUTO_START`; the display name is translated ("Druckwarteschlange"), the numbers are not. |
| `sc_query_spooler.bin` | `sc query spooler` | CP850 | `STATE : 4 RUNNING`. The tests switch it to `1 STOPPED`. The print jobs in `spool\PRINTERS` need elevation to list; the tests write job files with an old modification time into a temp folder. |

Captured elevated on 2026-10-09 on the same machine, read-only commands:

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `reg_query_svchost_split_threshold.bin` | `reg query HKLM\SYSTEM\CurrentControlSet\Control /v SvcHostSplitThresholdInKB` | CP850 | `0x380000` (3670016 KB, 3.5 GB), the value since 2026-10-08. A tuning tool had set it to 32 GB (`0x2000000`); the tests put that back. |
| `reg_query_enum_configflags_disabled.bin` | `reg query "HKLM\SYSTEM\CurrentControlSet\Enum\ACPI\PNP0103\2&daba3ff&0" /v ConfigFlags` | CP850 | The High Precision Event Timer, disabled in Device Manager by a tuning tool: `ConfigFlags` 0x1. `reg` spells the instance ID as the registry does (`daba3ff`), SetupAPI in capitals. |
| `powershell_enable_pnpdevice_not_found_de.bin` | The tweaks module's enable script (`Enable-PnpDevice -InstanceId '…' -Confirm:$false -ErrorAction Stop`) for an instance ID that does not exist, stderr | UTF-8 | Exit 1. The message is German, the `FullyQualifiedErrorId` (`CmdletizationQuery_NotFound_DeviceID`) is not. It changed nothing. |
| `sc_qc_cmservice.bin` | `sc qc CmService` | CP850 | `DEPENDENCIES` over three lines: `rpcss`, `vmcompute`, `hvhost`, each further one as ` : name` under the first. |
| `sc_qc_hvhost.bin` | `sc qc HvHost` | CP850 | `TYPE 20 WIN32_SHARE_PROCESS` (the number is hex), depends on `hvservice`. The chain tests copy it for services of their own. |
| `sc_qc_hvservice.bin` | `sc qc hvservice` | CP850 | The driver HvHost depends on: `TYPE 1 KERNEL_DRIVER`, no dependencies. The tests rename it for other drivers. |
| `sc_qc_vmcompute.bin` | `sc qc vmcompute` | CP850 | Depends on `rpcss` and the drivers `wcifs`, `hvsocketcontrol`, `condrv`. |
| `sc_qc_group_dependency.bin` | `sc qc cdfs` | CP850 | `TYPE 2 FILE_SYSTEM_DRIVER`, and a dependency on a group, which `sc` prints with a `+`: `+SCSI CDROM Class`. |
| `sc_qc_not_installed_de.bin` | `sc qc` of a service that does not exist | CP850 | Exit 1060, "[SC] OpenService FEHLER 1060:" and a German sentence: no `TYPE`. |

The failing state of 2026-10-08 - HvHost stopped with 31 (298 while the
services were grouped), CmService stopped with 1068 - is gone, and HvHost
and CmService cannot be made to fail again without changing the machine.
The chain tests list them as stopped with those exit codes by renaming the
captured entry of a service that stopped the same way (WinMedicChainA in
`sc_query_service_list.bin`, below), and so are **constructed** from it.

The device lists in the tweaks tests are what SetupAPI listed on that day
(`SetupDiGetClassDevs` with `DIGCF_PRESENT`, `CM_Get_DevNode_Status`): HPET
and the NDIS enumerator with problem code 22, two devices without a driver.

Captured unelevated on 2026-10-09 on the same machine, read-only commands:

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `sc_enumdepend_cryptsvc.bin` | `sc enumdepend cryptsvc 65536` | CP850 | The services that depend on cryptsvc, directly or not, the one that starts last first: IsolationSession, the Smartlocker filter driver `applockerfltr` (`TYPE 1 KERNEL_DRIVER`), which depends on AppIDSvc too, and AppIDSvc (Application Identity, AppLocker's service). All `1 STOPPED`. With a buffer of 60 bytes `sc` fails instead, exit code 234 and "weitere Daten, benötigt 418 Bytes". |
| `sc_enumdepend_spooler.bin` | `sc enumdepend spooler 65536` | CP850 | Fax, `1 STOPPED`. The tests switch it to `4 RUNNING`. |
| `sc_enumdepend_none.bin` | `sc enumdepend wuauserv 65536` | ASCII | `entriesread = 0`; bits prints the same. |

Captured in Windows Sandbox on 2026-10-09 (Windows 11 24H2, 26100.9550,
German, the account the sandbox signs in with, an Administrator):

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `sc_query_service_list.bin` | `sc query type= service state= all` after two test services had been created and the sandbox restarted: `WinMedicChainA` starts automatically and depends on `WinMedicChainB`, whose program does not exist | CP850 | 268 services, each `SERVICE_NAME`, the translated `DISPLAY_NAME`, then `STATE` and `WIN32_EXIT_CODE` as numbers. `WinMedicChainA` is `1 STOPPED` with `1068 (0x42c)`, "the dependency service failed to start": Windows gives that code to a service whose dependency failed at boot, and again when it is started by hand. `WinMedicChainB`, whose program could not be found, has exit code 0. |
| `pnputil_enable_device_disabled_since_boot_de.bin` | `pnputil /enable-device "ROOT\NDISVIRTUALBUS\0000"` after the device had been disabled with `Disable-PnpDevice` and the sandbox restarted | Windows-1252 | Exit 1167 (`ERROR_DEVICE_NOT_CONNECTED`), "Das Gerät ist nicht angeschlossen." pnputil takes a device's state from its `DEVPKEY_Device_DevNodeStatus` property, which Windows does not report for a device that has been disabled since it started (`CM_Get_DevNode_PropertyW`: `CR_NO_SUCH_VALUE`, while `CM_Get_DevNode_Status` reports problem 22). `pnputil /enum-devices` lists it as "Getrennt", and the enable is refused. Disabled without a restart in between, pnputil enabled it. `Enable-PnpDevice` enabled it in both states, without a restart. The development PC's `ROOT\HVSERVICE\0000` was refused the same way on 2026-10-08. |

Captured in Windows Sandbox on 2026-10-09, the same build, as SYSTEM (`wsb
exec -r System`), while the three services that depend on cryptsvc ran:

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `sc_enumdepend_cryptsvc_running.bin` | `sc enumdepend cryptsvc 65536` | CP850 | The same three as on the development PC, in the same order, each `4 RUNNING` with a line of flags under the state. |
| `net_stop_dependents_running_de.bin` | `net stop cryptsvc`, its input on NUL as WinMedic starts it | CP850 | "Die folgenden Dienste hängen vom Dienst Kryptografiedienste ab.", the three by display name, then "Möchten Sie diesen Vorgang fortsetzen? (J/N) [N]:". On stderr, `net_stop_dependents_running_stderr_de.bin`: "Es wurde keine gültige Antwort gegeben." Exit code -1, and nothing stopped. WinMedic's own runner got the same. `net stop cryptsvc /y` stopped the dependents still running and cryptsvc, and `net start cryptsvc` then started cryptsvc alone. |

Captured elevated on 2026-09-25, read-only commands, with the time each piece
of the pipe arrived:

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `dism_scanhealth_progress.bin` | `dism /English /Online /Cleanup-Image /ScanHealth` | ASCII | Every step of the bar is a line of its own, `\r[====  4.9%  ] \r\n`, written the moment it changes: 64-byte pieces over 65 seconds, 4.9% to 100.0%. Ends with "The component store is repairable." |
| `pnputil_scan_devices_elevated_de.bin` | `pnputil /scan-devices` | Windows-1252 | Exit 0 in under a second. The two devices without a driver still had none afterwards. |
| `pnputil_restart_device_no_driver_elevated_de.bin` | `pnputil /restart-device` of the Brio's interface without a driver | Windows-1252 | "Das Gerät wurde erfolgreich neu gestartet.", exit 0 - and the device went on reporting code 28. |
| `sfc_scannow_repaired_de.bin` | `sfc /scannow`, 80 seconds | UTF-16LE | "Der Windows-Ressourcenschutz hat beschädigte Dateien gefunden und erfolgreich repariert." Exit 0, like every SFC run captured here. |
| `sfc_verifyonly_progress_de.bin` | `sfc /verifyonly` | UTF-16LE | The bar is one line redrawn after `\r`, `Überprüfung 26 % abgeschlossen.`, ended only at 100 %. SFC writes into a pipe in 4 KB blocks, which arrived after 16, 31, 49 and 57 seconds and reach 26, 55, 83 and 100 %; the first one stops mid-word. Exit code 0 although it reports integrity violations. |

Captured elevated on 2026-09-25 with the German Windows 11 25H2 ISO from
microsoft.com (`Win11_25H2_German_x64_v2.iso`, 7.9 GB, its images version
10.0.26200.8037) in Downloads. The user folder name in the paths was replaced
with `user`.

| File | Command | Encoding | Notes |
| --- | --- | --- | --- |
| `powershell_install_media_mount.bin` | `install_media::find_script` with that ISO, not mounted yet | UTF-8 | `MOUNTED`, the ISO on `D`, and ten `IMAGE` lines from `Core` to `ProfessionalWorkstationN`: the edition id, not the name, tells Pro from Pro N. 27 seconds, most of it PowerShell preparing the storage and DISM modules. |
| `powershell_install_media_mounted.bin` | the same with the ISO mounted already | UTF-8 | No `MOUNTED` line, so WinMedic leaves it mounted. |
| `powershell_install_media_not_an_iso.bin` | the same with a text file named `not-an-iso.iso` | UTF-8 | `FAILED` with Windows' translated message. The real ISO was still mounted and is found as drive `D`. |
| `dism_restorehealth_repair_content_missing.bin` | `dism /English /Online /Cleanup-Image /RestoreHealth /Source:wim:D:\sources\install.wim:5 /LimitAccess` | ASCII | Exit -2146498283, `Error: 0x800f0915` "The repair content could not be found anywhere.", after 81 seconds. CBS.log: 328 damaged payloads, all in 10.0.26100.1591 components that .9278 ones had replaced; the ISO holds neither version, so none was repaired. |
| `dism_get_wiminfo_not_a_wim.bin` | `dism /English /Get-WimInfo /WimFile:C:\Windows\notepad.exe` | ASCII | Exit 11 for `Error: 11`: DISM exits with the code it prints, an HRESULT as the negative number above. |

## Files — `files/`

| File | Content |
| --- | --- |
| `reagent_enabled.xml` | `C:\Windows\System32\Recovery\ReAgent.xml` of the capture machine, unchanged: the recovery environment's configuration, readable without elevation, with `InstallState state="1"` (enabled). |
| `cbs_sfc_verifyonly_found_damage.bin` | What the `sfc /verifyonly` run of `sfc_verifyonly_progress_de.bin` added to `C:\Windows\Logs\CBS\CBS.log`, cut out byte for byte (CRLF). Only `[SR] Verify` lines, then `DEPLOY [Pnp] Corrupt file: ...\BthA2dp.sys` and two more Bluetooth drivers: the damage SFC reported, in a format the older `[SR] Cannot repair member file` check never saw. |
| `cbs_sfc_scannow_repaired.bin` | What `sfc /scannow` (`sfc_scannow_repaired_de.bin`) added to CBS.log, captured elevated on 2026-09-25: `[SR] Repairing 0 components`, then `Corrupt file:` and `Repaired file:` for each of the three drivers. |
| `cbs_sfc_verifyonly_clean.bin` | What an `sfc /verifyonly` run right after it added: no `DEPLOY` line; SFC said "keine Integritätsverletzungen". |
| `cbs_scanhealth_backups_missing.bin` | The report of a `DISM /ScanHealth` on 2026-09-25 at 11:01, cut from CBS.log byte for byte, from "Checking System Update Readiness." to "Total Operation Time". 328 `CSI Payload Corrupt (n)` lines, every one a file in a component's `r` folder (its reverse differential, a backup copy), and the summary "Total Detected Corruption: 328". The `/RestoreHealth` twenty minutes before had reported 2049 repaired, among them `SetComponentFileFlag(100)` for exactly these 328 files; none of them exists on disk. |
| `cbs_restorehealth_backups_missing.bin` | The report of the `/RestoreHealth` from the ISO at 21:56 (`dism_restorehealth_repair_content_missing.bin`): the same 328 lines, each followed by "Repair failed: Missing replacement payload.", "Total Repaired Corruption: 0". The tests that need real damage next to them change one path so it is no longer in `r`. |
| `reg_export_session_manager_power.bin` | What `reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" <file> /y` wrote on 2026-10-08, unelevated, on Windows 11 Pro 25H2 (10.0.26200.9550): the file a rollback imports. UTF-16LE with a byte order mark, the line `Windows Registry Editor Version 5.00`, a blank line, the key line `[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]`, its 77 values in the order `reg query` lists them, long hex values wrapped after `,\` with two spaces, CRLF, a blank line at the end. `reg export` spells the root key out and writes the rest of the path as it was given (`CurrentControlSet`, `ControlSet001`, the letter case), a subkey as that path and its name. It leaves out, still with exit 0, subkeys it cannot read. The tests add keys and lines to it. |
| `cbs_container_installer_rolled_back.bin` | Cut from `CbsPersist_20261008190827.log` of 2026-10-08: the start at 20:50 that ran the advanced installers for Windows Sandbox and the start at 20:55 that rolled it back. Of each start its first and last line, the queue's summary and failure lines, and the Container Installer's lines - each run's head (`Begin executing ...` to `Installer name`), its own `Container ...` lines, and its end (perf trace, `CSIPERF:AIDONE`, `End executing ...`, `Completion status`); the other installers' runs and everything else are left out, every line kept is as it was. The installer failed after five minutes with `HRESULT_FROM_WIN32(1753)` ("Failed to create container base layer ... -2147023143", 0x800706D9: nothing answered at the Container Manager's RPC endpoint), the queue with `CBS_E_INSTALLERS_FAILED` (0x800f0922); at the next start it ran again, uninstalling, with `S_OK`, and that start ended `CBS_E_INSTALLERS_FAILED` too. |
| `cbs_container_installer_rolled_back_again.bin` | The same cut from `CbsPersist_20261008192300.log`: the second attempt, from 21:14 to 21:20, the same lines with other times. |
| `cbs_container_installer_installed.bin` | The same cut from `CbsPersist_20261008212907.log`: the start at 23:01, after the device had been enabled, when the Container Installer completed with `S_OK` after five and a half minutes and the start ended `[HRESULT = 0x00000000 - S_OK]`. Other installers ran and finished in between (the first `Finished running all AIs.`). In the log that run is 40 MB long; its end, the part WinMedic reads, was 150 KB from the end of the file. |
| `hosts_blocking_update.bin` | The hosts file of the capture machine, byte for byte (UTF-8 with BOM, CRLF), its LAN address replaced with `192.168.1.10`. Next to telemetry blocks it blocks `fe3.delivery.mp.microsoft.com` — Windows Update's and the Store's metadata endpoint — and `ocsp.digicert.com`, which is what the hosts check exists to find. |
| `history_glued_lines.bin` | The first 24 lines of the capture machine's `%APPDATA%\WinMedic\logs\history.jsonl`, byte for byte (UTF-8, LF), written on 2026-08-14 by tests running side by side while `cargo test` still logged there: 25 scan entries, five lines with two to four entries glued together (`}{`, no line break between them), and the eight empty lines their line breaks made. Up to 0.8.0 an entry and its line break were two writes. On 2026-10-09 the whole file held 17014 entries, 902 of them on 395 such lines, the last from 2026-09-26. |

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
| `wevtutil_wu_failed_20_store.bin` | Every event 20 of `Microsoft-Windows-WindowsUpdateClient` ("installation failed") in that System log, captured 2026-09-27: four Store apps between 10 and 18 August 2026, all `0x80073d02` and the Store's `serviceGuid`. The tests turn them into one update of Windows Update failing four times: its `serviceGuid` `{9482f4b4-…}`, one `updateGuid`, another `errorCode` for the newest. |
| `wevtutil_app_error_1000.bin` | Application log, every event 1000 of `Application Error` ("a program crashed"), captured 2026-09-27, the newest 40 without the 19 of a program in development: the Snipping Tool in `ucrtbase.dll` 14 times, two games. None from explorer.exe; the tests turn the Snipping Tool's into Explorer crashing in Visio's add-on `VISSHE.DLL`. The user folder in paths is `user`. |
| `storage_errors_constructed.xml` | **Constructed.** The storage module's query (disk 7/51/153, Ntfs 55, stornvme/storahci 129, `Level<=3`) returned nothing on the capture machine on 2026-09-27. Built in the shape of a real classic driver event of that log (`volmgr` 162: provider without GUID, `Qualifiers`, unnamed `<Data>` with the device, then `<Binary>`); `disk`, `stornvme` and `storahci` log through `IoLogMsg.dll` like it, and `Ntfs` 55 has no template in its manifest (`wevtutil gp Ntfs /ge`). The `Binary` blobs are made up. Replace it with a capture when one turns up. |
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
