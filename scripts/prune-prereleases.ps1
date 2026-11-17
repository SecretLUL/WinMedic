#Requires -Version 7.0
<#
.SYNOPSIS
    Take the pre-releases a new release replaces off the releases page.

.DESCRIPTION
    A pre-release is for testers until the next one, or the release, is out.
    Left on the releases page it sits between the releases as one more download
    nobody should take. The release workflow runs this once a release is
    published, pre-release or not, and every other pre-release goes.

    Without -Delete it only prints what would go:

        ./scripts/prune-prereleases.ps1 -Keep v0.19.0-pre.2
        ./scripts/prune-prereleases.ps1 -Keep v0.19.0-pre.2 -Delete

    Only the release and its files are deleted. The tag stays: the next
    pre-release takes the first `-pre.N` no tag has (next-version.ps1), and
    with the tag gone a second, different v0.19.0-pre.1 would be built. A crash
    log names its binary by nothing but that.

    What cannot be deleted is a warning, and the next release tries again.

.PARAMETER Keep
    The tag that was just published. It is never deleted.

.PARAMETER Delete
    Delete, instead of printing what would be deleted.

.PARAMETER Releases
    The releases to choose from, as the JSON of
    `gh release list --json tagName,isPrerelease,isDraft`. Left out, they are
    read from GitHub.

.PARAMETER Repo
    The repository, as `owner/name`. Defaults to $env:GITHUB_REPOSITORY, and
    without that to the one `gh` finds in the working directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Keep,

    [switch] $Delete,

    [string] $Releases,

    [string] $Repo = $env:GITHUB_REPOSITORY
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$where = @()
if ($Repo) { $where = @('--repo', $Repo) }

if (-not $PSBoundParameters.ContainsKey('Releases')) {
    # The default is the newest 30.
    $Releases = gh release list @where --limit 1000 --json tagName,isPrerelease,isDraft | Out-String
    if ($LASTEXITCODE) { throw 'Could not read the releases.' }
}

# Both have to say so: GitHub's flag and the `-` in the tag, which is what
# makes a version a pre-release everywhere else. A draft is somebody's work in
# progress.
$old = @($Releases | ConvertFrom-Json | Where-Object {
        $_.isPrerelease -and -not $_.isDraft -and
        $_.tagName -cmatch '^v\d+\.\d+\.\d+-' -and
        $_.tagName -ne $Keep
    } | ForEach-Object { $_.tagName })

if (-not $old) {
    Write-Host "No pre-release other than $Keep on the releases page."
    exit 0
}

foreach ($tag in $old) {
    if (-not $Delete) {
        Write-Host "Would delete the pre-release $tag (its tag stays)."
        continue
    }
    gh release delete $tag @where --yes
    if ($LASTEXITCODE) {
        Write-Host "::warning::The pre-release $tag could not be deleted. It stays on the releases page until the next release tries again."
    } else {
        Write-Host "Deleted the pre-release $tag (its tag stays)."
    }
}
exit 0
