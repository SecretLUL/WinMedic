#Requires -Version 7.0
<#
.SYNOPSIS
    Turn the winmedic.exe offsets in a crash log back into functions and lines.

.DESCRIPTION
    A crash log (%APPDATA%\WinMedic\logs\crash-*.log) gives its stack as
    module+offset, because the release ships without symbols. The release
    workflow keeps each release's PDB as the artifact winmedic-<tag>-pdb of its
    run. With that PDB and the release's winmedic.exe, Windows' own
    dbghelp.dll resolves the offsets:

        ./scripts/resolve-crash-log.ps1 crash-20261012-224107-1234-1.log -Exe winmedic-v0.12.0.exe -Pdb winmedic.pdb

    Both have to come from the release the crash log names: a PDB matches only
    the binary its own build produced. Frames in other modules, such as
    ntdll.dll, are printed as they are.

.PARAMETER CrashLog
    The crash log.

.PARAMETER Exe
    winmedic.exe of the release the crash log names, as published.

.PARAMETER Pdb
    winmedic.pdb from that release's artifact.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $CrashLog,

    [Parameter(Mandatory)]
    [string] $Exe,

    [Parameter(Mandatory)]
    [string] $Pdb
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class CrashLogSymbols
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Line
    {
        public uint SizeOfStruct;
        public IntPtr Key;
        public uint LineNumber;
        public IntPtr FileName;
        public ulong Address;
    }

    [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SymInitializeW(IntPtr process, string searchPath, bool invadeProcess);

    [DllImport("dbghelp.dll")]
    public static extern uint SymSetOptions(uint options);

    [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern ulong SymLoadModuleExW(IntPtr process, IntPtr file, string imageName,
        string moduleName, ulong baseOfDll, uint dllSize, IntPtr data, uint flags);

    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool SymFromAddrW(IntPtr process, ulong address, out ulong displacement, IntPtr symbol);

    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool SymGetLineFromAddrW64(IntPtr process, ulong address, out uint displacement, ref Line line);

    [DllImport("dbghelp.dll")]
    public static extern bool SymCleanup(IntPtr process);
}
'@

# Not a real process: dbghelp only needs a value to file the symbols under.
$session = [IntPtr]::new(0x57696E4D)
$base = [uint64]0x140000000
# SYMOPT_UNDNAME, SYMOPT_LOAD_LINES, SYMOPT_FAIL_CRITICAL_ERRORS. Not
# SYMOPT_DEFERRED_LOADS: with it, no address of winmedic.exe resolved.
[void][CrashLogSymbols]::SymSetOptions(0x2 -bor 0x10 -bor 0x200)
$pdbFolder = Split-Path (Resolve-Path $Pdb) -Parent
if (-not [CrashLogSymbols]::SymInitializeW($session, $pdbFolder, $false)) {
    throw "dbghelp did not start: error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

# SYMBOL_INFOW: 88 bytes up to its name, which follows at offset 84.
$maxName = 1024
$symbol = [Runtime.InteropServices.Marshal]::AllocHGlobal(88 + 2 * $maxName)
try {
    if ([CrashLogSymbols]::SymLoadModuleExW($session, [IntPtr]::Zero, (Resolve-Path $Exe).Path, 'winmedic', $base, 0, [IntPtr]::Zero, 0) -eq 0) {
        throw "dbghelp could not load $Exe`: error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    foreach ($text in Get-Content -LiteralPath $CrashLog) {
        if ($text -notmatch '^(\s+)winmedic\.exe\+0x([0-9a-fA-F]+)\s*$') {
            $text
            continue
        }
        # A return address: the call it returns from is the byte before it.
        $address = $base + [Convert]::ToUInt64($Matches[2], 16) - 1
        [Runtime.InteropServices.Marshal]::WriteInt32($symbol, 0, 88)
        [Runtime.InteropServices.Marshal]::WriteInt32($symbol, 80, $maxName)
        $displacement = [uint64]0
        if (-not [CrashLogSymbols]::SymFromAddrW($session, $address, [ref]$displacement, $symbol)) {
            "$text  (no symbol: is the PDB the one of this winmedic.exe?)"
            continue
        }
        $nameLength = [Runtime.InteropServices.Marshal]::ReadInt32($symbol, 76)
        $name = [Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr]::Add($symbol, 84), $nameLength)
        $line = [CrashLogSymbols+Line]::new()
        $line.SizeOfStruct = [Runtime.InteropServices.Marshal]::SizeOf([type][CrashLogSymbols+Line])
        $lineDisplacement = [uint32]0
        if ([CrashLogSymbols]::SymGetLineFromAddrW64($session, $address, [ref]$lineDisplacement, [ref]$line)) {
            $file = [Runtime.InteropServices.Marshal]::PtrToStringUni($line.FileName)
            "$text  $name ($file`:$($line.LineNumber))"
        } else {
            "$text  $name"
        }
    }
} finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($symbol)
    [void][CrashLogSymbols]::SymCleanup($session)
}
