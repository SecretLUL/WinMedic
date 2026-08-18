#Requires -Version 7.0
<#
.SYNOPSIS
    Build the three WinGet manifests for a published WinMedic release.

.DESCRIPTION
    The Windows Package Manager describes a package with three YAML files — a
    version manifest, an installer manifest and a locale manifest — that live
    under `manifests/s/SecretLUL/WinMedic/<version>/` in the community
    repository, microsoft/winget-pkgs.

    Every release after the first is submitted automatically by
    `.github/workflows/winget.yml`, so this script exists for the two cases that
    automation cannot cover:

      * the very first submission, which has to be a hand-opened pull request
        because WinGet Releaser refuses to run until one version of the package
        already exists in winget-pkgs, and
      * checking, offline and before anyone else sees it, what a manifest for a
        given release actually says.

    WinMedic ships unsigned, so the `InstallerSha256` is the only thing tying a
    manifest to a specific binary — which makes it the one field that must not
    be taken on trust. This script downloads the released `.exe`, hashes it
    itself, and refuses to write a manifest unless that hash matches the
    `.sha256` published alongside it. A mismatch means the release assets
    disagree with each other and is a release problem, not a manifest problem.

.PARAMETER Version
    The released SemVer version to build manifests for, e.g. `0.3.4`. A leading
    "v" is accepted and stripped. The release must already be published, since
    its assets are what the manifest points at.

.PARAMETER OutDir
    Where to write the manifests. The winget-pkgs directory layout is recreated
    underneath it, so the result can be copied straight into a fork. Defaults to
    `target/winget`, which is already ignored by .gitignore.

.PARAMETER SkipValidate
    Do not run `winget validate` on the result. The check is skipped
    automatically when winget is not installed; this switch is for the rare case
    of building a manifest for a schema newer than the local winget knows.

.EXAMPLE
    ./scripts/winget-manifest.ps1 0.3.4

    Writes target/winget/manifests/s/SecretLUL/WinMedic/0.3.4/ and validates it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $Version,

    [string] $OutDir,

    [switch] $SkipValidate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Bumping this is how the manifests move to a newer WinGet schema. winget-pkgs
# accepts a window of versions, so the safe move is to match what the community
# repository has most recently merged rather than the newest one that exists.
$SchemaVersion = '1.12.0'

$PackageIdentifier = 'SecretLUL.WinMedic'
$Repo = 'SecretLUL/WinMedic'

$Version = $Version.Trim().TrimStart('v', 'V')
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw "Not a SemVer version: '$Version' (expected something like 0.3.4)"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) {
    $OutDir = Join-Path $repoRoot 'target/winget'
}

$tag = "v$Version"
$assetName = "winmedic-$tag.exe"
$installerUrl = "https://github.com/$Repo/releases/download/$tag/$assetName"

# ---------------------------------------------------------------------------
# The installer hash, established rather than assumed
# ---------------------------------------------------------------------------

$staging = Join-Path ([System.IO.Path]::GetTempPath()) "winmedic-winget-$Version-$(Get-Random)"
New-Item -ItemType Directory -Path $staging -Force | Out-Null

try {
    $exePath = Join-Path $staging $assetName
    $sumPath = "$exePath.sha256"

    Write-Host "Downloading $installerUrl"
    Invoke-WebRequest -Uri $installerUrl -OutFile $exePath

    Write-Host "Downloading $installerUrl.sha256"
    Invoke-WebRequest -Uri "$installerUrl.sha256" -OutFile $sumPath

    $actual = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToUpperInvariant()

    # sha256sum layout: "<hash>  <filename>". Only the hash is of interest; the
    # name is whatever the release workflow wrote next to it.
    $published = ((Get-Content -Path $sumPath -Raw).Trim() -split '\s+')[0].ToUpperInvariant()

    if ($actual -ne $published) {
        throw @"
The released binary does not match the checksum published with it.

  $assetName        $actual
  $assetName.sha256 $published

That is a broken release, not a broken manifest. Do not submit this version to
WinGet until the assets agree.
"@
    }

    Write-Host "  ok      $assetName matches its published checksum"
    $installerSha256 = $actual

    $sizeBytes = (Get-Item -LiteralPath $exePath).Length
    Write-Host "  ok      $([math]::Round($sizeBytes / 1MB, 2)) MB installer"
} finally {
    Remove-Item -Recurse -Force -LiteralPath $staging -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# The release date, which WinGet shows and komac carries forward
# ---------------------------------------------------------------------------

$releaseDate = $null
try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/tags/$tag" `
        -Headers @{ 'User-Agent' = 'winmedic-winget-manifest' }
    $releaseDate = ([datetime]$release.published_at).ToUniversalTime().ToString('yyyy-MM-dd')
    Write-Host "  ok      $tag was published on $releaseDate"
} catch {
    # Optional field: a manifest without it is still valid, and failing the
    # whole build over an unauthenticated API call that got rate-limited would
    # be out of proportion.
    Write-Warning "Could not read the release date from the GitHub API ($($_.Exception.Message)); ReleaseDate will be omitted."
}

# ---------------------------------------------------------------------------
# The manifests
# ---------------------------------------------------------------------------

$header = {
    param($type)
    @(
        "# Generated by scripts/winget-manifest.ps1 from the published $tag release"
        "# yaml-language-server: `$schema=https://aka.ms/winget-manifest.$type.$SchemaVersion.schema.json"
        ''
    )
}

$versionManifest = @(
    & $header 'version'
    "PackageIdentifier: $PackageIdentifier"
    "PackageVersion: $Version"
    'DefaultLocale: en-US'
    'ManifestType: version'
    "ManifestVersion: $SchemaVersion"
)

$installerManifest = @(
    & $header 'installer'
    "PackageIdentifier: $PackageIdentifier"
    "PackageVersion: $Version"
    # WinMedic is one self-contained executable with no installer of any kind,
    # which is exactly what `portable` describes: WinGet drops the binary in its
    # own package directory and links it onto the PATH.
    'InstallerType: portable'
    # The released file is called winmedic-v0.3.4.exe, so without this the
    # command on the PATH would be version-stamped and change with every
    # upgrade. `Commands` is what names the link, and `winmedic` is the name
    # every piece of documentation uses.
    'Commands:'
    '- winmedic'
    # The README promises Windows 10/11 (64-bit); 10.0.0.0 is how that promise
    # is stated in a manifest, and it stops WinGet offering the package on
    # anything older.
    'MinimumOSVersion: 10.0.0.0'
    if ($releaseDate) { "ReleaseDate: $releaseDate" }
    'Installers:'
    '- Architecture: x64'
    "  InstallerUrl: $installerUrl"
    "  InstallerSha256: $installerSha256"
    'ManifestType: installer'
    "ManifestVersion: $SchemaVersion"
)

$localeManifest = @(
    & $header 'defaultLocale'
    "PackageIdentifier: $PackageIdentifier"
    "PackageVersion: $Version"
    'PackageLocale: en-US'
    'Publisher: SecretLUL'
    'PublisherUrl: https://github.com/SecretLUL'
    "PublisherSupportUrl: https://github.com/$Repo/issues"
    'Author: SecretLUL'
    'PackageName: WinMedic'
    "PackageUrl: https://github.com/$Repo"
    'License: MIT'
    "LicenseUrl: https://github.com/$Repo/blob/main/LICENSE"
    'Copyright: Copyright (c) 2026 SecretLUL'
    "CopyrightUrl: https://github.com/$Repo/blob/main/LICENSE"
    'ShortDescription: High-performance Windows self-healing and diagnostic TUI written in Rust'
    'Description: |-'
    '  WinMedic is a terminal application that diagnoses and repairs Windows'
    '  problems: component-store and system-file corruption, stalled Windows'
    '  Update queues, broken services, network stack and DNS faults, disk health'
    '  and cache bloat. Diagnostic modules run in parallel and every finding is'
    '  reported with its severity, the evidence behind it and the exact commands'
    '  a fix would run.'
    ''
    '  Repairs are opt-in and reversible: a System Restore point and registry'
    '  snapshots are taken before anything is changed, a dry-run mode shows the'
    '  planned steps without touching the system, and any scan or repair can be'
    '  interrupted. It is a single native executable with no .NET, Python or'
    '  other runtime dependency.'
    'Moniker: winmedic'
    'Tags:'
    '- cleanup'
    '- diagnostics'
    '- dism'
    '- repair'
    '- rust'
    '- sfc'
    '- system'
    '- troubleshooting'
    '- tui'
    '- windows'
    'InstallationNotes: |-'
    '  WinMedic repairs system components, so the repair paths need Administrator'
    '  rights. Start it from an elevated terminal, or run "winmedic --elevate" to'
    '  raise a UAC prompt. Diagnostics alone run fine without elevation.'
    'Documentations:'
    '- DocumentLabel: README'
    "  DocumentUrl: https://github.com/$Repo/blob/main/README.md"
    "ReleaseNotesUrl: https://github.com/$Repo/releases/tag/$tag"
    'ManifestType: defaultLocale'
    "ManifestVersion: $SchemaVersion"
)

# The winget-pkgs layout, reproduced so the directory can be copied into a fork
# as-is: manifests/<first letter of publisher, lowercased>/<publisher>/<package>.
$targetDir = Join-Path $OutDir 'manifests/s/SecretLUL/WinMedic' | Join-Path -ChildPath $Version
New-Item -ItemType Directory -Path $targetDir -Force | Out-Null

$files = @{
    "$PackageIdentifier.yaml"              = $versionManifest
    "$PackageIdentifier.installer.yaml"    = $installerManifest
    "$PackageIdentifier.locale.en-US.yaml" = $localeManifest
}

foreach ($name in $files.Keys | Sort-Object) {
    $path = Join-Path $targetDir $name
    # winget-pkgs manifests are UTF-8 without a BOM and CRLF-terminated, and the
    # validation pipeline is picky about it.
    $text = ($files[$name] -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))
    Write-Host "  written $name"
}

Write-Host ''
Write-Host "Manifests for $PackageIdentifier $Version are in:"
Write-Host "  $targetDir"

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

if ($SkipValidate) {
    Write-Host ''
    Write-Host 'Skipping `winget validate` as requested.'
    exit 0
}

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host ''
    Write-Warning 'winget is not installed here, so the manifests were not validated. Run `winget validate --manifest <dir>` on a machine that has it before submitting.'
    exit 0
}

Write-Host ''
$PSNativeCommandUseErrorActionPreference = $false
winget validate --manifest $targetDir
if ($LASTEXITCODE -ne 0) {
    throw "winget validate rejected the manifests (exit code $LASTEXITCODE). Fix them before opening a pull request against microsoft/winget-pkgs."
}
