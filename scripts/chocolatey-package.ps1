#Requires -Version 7.0
<#
.SYNOPSIS
    Build the Chocolatey package for a published WinMedic release.

.DESCRIPTION
    packaging/chocolatey/ holds the package with two placeholders: the version,
    and the SHA-256 of the released .exe that the install script checks the
    download against. This script fills both in from the published release and
    runs `choco pack`. `.github/workflows/chocolatey.yml` pushes the result to
    the Chocolatey Community Repository.

    The checksum is the one value that must not be taken on trust, so it is
    established as in winget-manifest.ps1: the .exe is downloaded and hashed
    here, and no package is built unless that hash matches the .sha256
    published alongside it.

    Prints the path of the .nupkg it wrote; everything else goes to the host.

.PARAMETER Version
    The released version to package, e.g. `0.17.0`. A leading "v" is accepted
    and stripped. Pre-releases are refused: Chocolatey would offer them to
    `choco upgrade all`.

.PARAMETER OutDir
    Where to write the .nupkg. Defaults to `target/chocolatey`, which
    .gitignore already ignores.

.EXAMPLE
    ./scripts/chocolatey-package.ps1 0.17.0
    Writes target/chocolatey/winmedic.0.17.0.nupkg.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $Version,
    [string] $OutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo = 'SecretLUL/WinMedic'

$Version = $Version.Trim().TrimStart('v', 'V')
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Not a release version: '$Version' (expected something like 0.17.0; pre-releases do not go to Chocolatey)"
}

if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    throw 'choco was not found. The package is built with Chocolatey itself: https://chocolatey.org/install'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) {
    $OutDir = Join-Path $repoRoot 'target/chocolatey'
}

$tag = "v$Version"
$assetName = "winmedic-$tag.exe"
$exeUrl = "https://github.com/$Repo/releases/download/$tag/$assetName"

$staging = Join-Path ([System.IO.Path]::GetTempPath()) "winmedic-chocolatey-$Version-$(Get-Random)"
New-Item -ItemType Directory -Path $staging -Force | Out-Null
try {
    # -----------------------------------------------------------------------
    # The checksum, established rather than assumed
    # -----------------------------------------------------------------------
    $exePath = Join-Path $staging $assetName
    $sumPath = "$exePath.sha256"
    Write-Host "Downloading $exeUrl"
    Invoke-WebRequest -Uri $exeUrl -OutFile $exePath
    Write-Host "Downloading $exeUrl.sha256"
    Invoke-WebRequest -Uri "$exeUrl.sha256" -OutFile $sumPath

    $actual = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
    # sha256sum layout: "<hash>  <filename>".
    $published = ((Get-Content -Path $sumPath -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    if ($actual -ne $published) {
        throw @"
The released binary does not match the checksum published with it.
  $assetName        $actual
  $assetName.sha256 $published
That is a broken release, not a broken package. Do not push this version to
Chocolatey until the assets agree.
"@
    }
    Write-Host "  ok      $assetName matches its published checksum"

    # -----------------------------------------------------------------------
    # The package
    # -----------------------------------------------------------------------
    $package = Join-Path $staging 'package'
    Copy-Item -Recurse -Path (Join-Path $repoRoot 'packaging/chocolatey') -Destination $package
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    foreach ($file in Get-ChildItem -Path $package -Recurse -File) {
        $text = [System.IO.File]::ReadAllText($file.FullName)
        $text = $text.Replace('__VERSION__', $Version).Replace('__SHA256__', $actual)
        # A placeholder that survives would reach Chocolatey as a literal, and
        # its moderation rejects a nuspec with templated values (CPMR0019).
        if ($text -match '__[A-Z0-9_]+__') {
            throw "Placeholder $($Matches[0]) is still in $($file.Name) after filling in the release."
        }
        [System.IO.File]::WriteAllText($file.FullName, $text, $utf8)
    }

    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    # Out-Host, so that only the path printed below is this script's output.
    choco pack (Join-Path $package 'winmedic.nuspec') --out $OutDir --limit-output | Out-Host
    if ($LASTEXITCODE) {
        throw "choco pack failed with exit code $LASTEXITCODE."
    }
} finally {
    Remove-Item -Recurse -Force -LiteralPath $staging -ErrorAction SilentlyContinue
}

$nupkg = Join-Path $OutDir "winmedic.$Version.nupkg"
if (-not (Test-Path -LiteralPath $nupkg)) {
    throw "choco pack reported success, but $nupkg is not there."
}
Write-Host "  ok      $nupkg"
(Resolve-Path -LiteralPath $nupkg).Path
