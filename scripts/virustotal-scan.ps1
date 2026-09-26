#Requires -Version 7.0
<#
.SYNOPSIS
    Upload a file to VirusTotal, wait for the verdict and fail when any engine
    flags it.

.DESCRIPTION
    A new, unsigned .exe is what machine-learning scanners flag. v0.6.0 was
    reported as Trojan:Win32/Sabsik.EN.A!ml by Microsoft, 1 of 71 engines, and
    Microsoft Defender runs on every PC WinMedic is for. The release workflow
    runs this on every published binary, so a false positive is reported to the
    vendor before users run into it.

    The verdict goes to the console and, in GitHub Actions, to the job summary.
    Exit code 1 means at least one engine flags the file; an analysis that has
    not finished in time is a warning, not a failure.

        ./scripts/virustotal-scan.ps1 target/release/winmedic.exe

.PARAMETER Path
    The file to upload. Up to 32 MB; larger files need VirusTotal's upload_url.

.PARAMETER ApiKey
    A VirusTotal API key. Defaults to $env:VIRUSTOTAL_API_KEY.

.PARAMETER ApiBase
    The API root. Only a test points it anywhere else.

.PARAMETER PollSeconds
    Seconds between two looks at the analysis. The free API allows four
    requests a minute.

.PARAMETER MaxPolls
    How often to look before giving up.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $Path,

    [string] $ApiKey = $env:VIRUSTOTAL_API_KEY,

    [string] $ApiBase = 'https://www.virustotal.com/api/v3',

    [int] $PollSeconds = 30,

    [int] $MaxPolls = 40
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $ApiKey) {
    throw 'No VirusTotal API key: pass -ApiKey or set VIRUSTOTAL_API_KEY.'
}

$headers = @{ 'x-apikey' = $ApiKey }
$name = Split-Path $Path -Leaf
$sha256 = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
$report = "https://www.virustotal.com/gui/file/$sha256/detection"

$upload = Invoke-RestMethod -Method Post -Uri "$ApiBase/files" -Headers $headers -Form @{ file = Get-Item $Path }
$id = $upload.data.id
Write-Host "Uploaded $name ($sha256), analysis $id"

$attributes = $null
for ($i = 0; $i -lt $MaxPolls; $i++) {
    Start-Sleep -Seconds $PollSeconds
    try {
        $attributes = (Invoke-RestMethod -Uri "$ApiBase/analyses/$id" -Headers $headers).data.attributes
    } catch {
        # A rate limit or a hiccup; the next look may well succeed.
        Write-Host "Could not read the analysis: $($_.Exception.Message)"
        continue
    }
    Write-Host "Analysis: $($attributes.status)"
    if ($attributes.status -eq 'completed') { break }
}

if (-not $attributes -or $attributes.status -ne 'completed') {
    Write-Host "::warning::VirusTotal had not finished with $name after $($PollSeconds * $MaxPolls) s: $report"
    exit 0
}

$stats = $attributes.stats
$verdicts = $stats.malicious + $stats.suspicious + $stats.undetected + $stats.harmless
$flagged = @(
    $attributes.results.PSObject.Properties.Value |
        Where-Object { $_.category -in 'malicious', 'suspicious' } |
        Sort-Object engine_name
)

$summary = @("### VirusTotal: $($flagged.Count) of $verdicts engines flag $name", '', "[Report]($report)")
if ($flagged.Count) {
    $summary += '', '| Engine | Detection |', '| :--- | :--- |'
    $summary += $flagged | ForEach-Object { "| $($_.engine_name) | $($_.result) |" }
    $summary += '', 'Report each false positive to its vendor: [Microsoft](https://www.microsoft.com/en-us/wdsi/filesubmission) (Software developer, Incorrectly detected), [everyone else](https://docs.virustotal.com/docs/false-positive-contacts).'
}
$summary | ForEach-Object { Write-Host $_ }
if ($env:GITHUB_STEP_SUMMARY) {
    $summary | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}

foreach ($engine in $flagged) {
    Write-Host "::error::$($engine.engine_name) flags $name as $($engine.result): $report"
}
if ($flagged.Count) { exit 1 }
