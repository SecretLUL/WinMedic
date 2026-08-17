#Requires -Version 7.0
<#
.SYNOPSIS
    Write one version number into every file in the repository that states one.

.DESCRIPTION
    `Cargo.toml` is the single source of truth for the code: every version the
    binary shows — the header, the help popup, `--version`, the HTML report, the
    run trace and the update check — comes from `env!("CARGO_PKG_VERSION")`.

    Nothing was writing to that source of truth. v0.3.1 and v0.3.2 were tagged
    and published while `Cargo.toml` still said 0.3.0, so the shipped tool
    introduced itself as 0.3.0 and then, because the update check compares that
    same constant against the newest GitHub release, permanently offered its own
    release as an available update.

    This script is what the release workflow runs before it builds, so a tag and
    the tree it points at cannot disagree. Bumping by hand works the same way:

        ./scripts/set-version.ps1 0.3.3

.PARAMETER Version
    The SemVer version to write. A leading "v" is accepted and stripped.

.PARAMETER Check
    Report which files disagree with -Version and exit 1 instead of rewriting
    them. The release workflow uses this to police manually pushed tags, where
    the tree is already frozen and there is nothing left to fix.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $Version,

    [switch] $Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Version = $Version.Trim().TrimStart('v', 'V')
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
    throw "Not a SemVer version: '$Version' (expected something like 0.3.3 or 1.0.0-rc1)"
}

$repoRoot = Split-Path -Parent $PSScriptRoot

# Every pattern below matches whatever version the file states today rather than
# one specific old value, which is what makes a rewrite idempotent and lets the
# script recover a tree that has drifted to three different versions at once.
$targets = @(
    @{
        Path        = 'Cargo.toml'
        Purpose     = 'the package version behind every env!("CARGO_PKG_VERSION")'
        # Anchored to the start of a line so dependency versions further down the
        # file — `regex = "1.11"`, `windows-sys = { version = "0.61" }` — and the
        # `rust-version` key are all left alone.
        Pattern     = '(?m)^version\s*=\s*"[^"]*"'
        Replacement = "version = `"$Version`""
    }
    @{
        Path        = 'Cargo.lock'
        Purpose     = 'the lockfile entry, without which --locked builds fail'
        # The lock states every dependency in this exact shape, so the package
        # name has to be part of the match or the first crate alphabetically
        # would get WinMedic's version number.
        Pattern     = '(?m)^(name = "winmedic"\r?\nversion = )"[^"]*"'
        Replacement = "`${1}`"$Version`""
    }
    @{
        Path        = 'README.md'
        Purpose     = 'the checksum-verification example'
        Pattern     = 'winmedic-v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\.exe'
        Replacement = "winmedic-v$Version.exe"
    }
    @{
        Path        = '.github/ISSUE_TEMPLATE/bug_report.yml'
        Purpose     = 'the "WinMedic version" placeholder'
        # Matches the product name as `--version` actually prints it, so the
        # placeholder keeps showing a reporter exactly what to paste.
        Pattern     = '(placeholder:\s*")[Ww]in[Mm]edic [^"]*(")'
        Replacement = "`${1}WinMedic $Version`${2}"
    }
)

$stale = @()

foreach ($target in $targets) {
    $path = Join-Path $repoRoot $target.Path
    if (-not (Test-Path -LiteralPath $path)) {
        throw "$($target.Path) does not exist — this script's list of version sites is out of date."
    }

    # ReadAllText/WriteAllText round-trips CRLF and the trailing newline exactly,
    # so a version bump shows up as a one-line diff rather than a whole file.
    $before = [System.IO.File]::ReadAllText($path)

    if (-not [regex]::IsMatch($before, $target.Pattern)) {
        throw "$($target.Path) no longer contains $($target.Purpose) in the expected form. Fix the pattern in scripts/set-version.ps1 rather than releasing a mislabelled build."
    }

    $after = [regex]::Replace($before, $target.Pattern, $target.Replacement)

    # The replacement is canonical, so "nothing changed" and "already correct"
    # are the same statement.
    if ($after -eq $before) {
        Write-Host "  ok      $($target.Path) — already states $Version"
        continue
    }

    $stale += $target.Path

    if ($Check) {
        Write-Host "  STALE   $($target.Path) — $($target.Purpose)"
        continue
    }

    [System.IO.File]::WriteAllText($path, $after, [System.Text.UTF8Encoding]::new($false))
    Write-Host "  written $($target.Path) — $($target.Purpose)"
}

if ($Check -and $stale.Count -gt 0) {
    Write-Host ''
    Write-Host "$($stale.Count) file(s) do not state $Version. Run: ./scripts/set-version.ps1 $Version"
    exit 1
}

Write-Host ''
if ($Check) {
    Write-Host "Every version site states $Version."
} elseif ($stale.Count -eq 0) {
    Write-Host "Nothing to do; every version site already stated $Version."
} else {
    Write-Host "Set $($stale.Count) file(s) to $Version."
}
