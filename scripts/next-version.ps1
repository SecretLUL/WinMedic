#Requires -Version 7.0
<#
.SYNOPSIS
    Print the version the next release ships under.

.DESCRIPTION
    The release workflow asks which number goes up, not which version to
    release, and this works it out from the release tags that exist:

        ./scripts/next-version.ps1 -Bump minor                 # 0.17.0 -> 0.18.0
        ./scripts/next-version.ps1 -Bump patch -PreRelease     # 0.17.0 -> 0.17.1-pre.1

    It counts from the newest tag, not from Cargo.toml: after a run that could
    not bring the branch up, the branch still states the release before, and
    counting from it would pick a version that shipped.

    A pre-release is the same next version with `-pre.N` behind it, N being
    the first number no tag of that version has. The `-` is what makes it a
    pre-release everywhere: GitHub's flag, WinGet, Chocolatey and WinMedic's
    own update check all go by it. Pre-release tags never count as "the newest
    release", so a pre-release moves no later version.

    It used to be a block inside release.yml, where nothing could run it
    without starting a release.

.PARAMETER Bump
    Which number of the newest release goes up by one: patch, minor or major.

.PARAMETER PreRelease
    Print a pre-release of that version instead of the version itself.

.PARAMETER Tags
    The tags to count from, as `v0.17.0` or as `git ls-remote` prints them.
    Left out, they are read from `origin`.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('patch', 'minor', 'major')]
    [string] $Bump,

    [switch] $PreRelease,

    [string[]] $Tags
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $PSBoundParameters.ContainsKey('Tags')) {
    $Tags = @(git ls-remote --tags origin 'refs/tags/v*')
    if ($LASTEXITCODE) { throw 'Could not read the tags of origin.' }
}

# `git ls-remote` prints "<sha>\trefs/tags/v0.17.0", and for an annotated tag a
# second line ending in "^{}".
$names = @($Tags | ForEach-Object { ($_ -replace '^.*refs/tags/', '' -replace '\^\{\}$', '').Trim() } |
        Where-Object { $_ } | Sort-Object -Unique)

$latest = $names |
    ForEach-Object { if ($_ -match '^v(\d+\.\d+\.\d+)$') { [version]$Matches[1] } } |
    Sort-Object -Descending |
    Select-Object -First 1
if (-not $latest) { throw 'No release tag to count from.' }

$next = switch ($Bump) {
    'major' { "$($latest.Major + 1).0.0" }
    'minor' { "$($latest.Major).$($latest.Minor + 1).0" }
    'patch' { "$($latest.Major).$($latest.Minor).$($latest.Build + 1)" }
}

if ($PreRelease) {
    $pattern = '^v' + [regex]::Escape($next) + '-pre\.(\d+)$'
    $taken = @($names | ForEach-Object { if ($_ -match $pattern) { [int]$Matches[1] } })
    $number = if ($taken) { ($taken | Measure-Object -Maximum).Maximum + 1 } else { 1 }
    $next = "$next-pre.$number"
}

Write-Host "$Bump after v$latest$(if ($PreRelease) { ', as a pre-release' })" -ForegroundColor DarkGray
$next
