#Requires -Version 7.0
<#
.SYNOPSIS
    Open the pull request that raises `main` to a new version, so the release
    workflow finds the bump already in place.

.DESCRIPTION
    `main` is protected: four strict status checks, and `GITHUB_TOKEN` is not
    allowed through them. So the release workflow's last step — the one that
    brings the branch up to the version it just released — cannot land its own
    commit. It tries a direct push, falls back to opening a pull request, and
    that fallback needs "Allow GitHub Actions to create and approve pull
    requests", which is off. v0.4.0 shipped correctly and its run still went
    red for exactly this reason.

    Rather than hand CI a credential that bypasses branch protection, the bump
    takes the same road as every other change: a pull request, reviewed and
    CI-gated, merged by a human. The release is then cut from a `main` that
    already states the version — at which point the workflow's own bump step
    finds nothing to write, tags `HEAD` unchanged, and its "did the bump land
    on the branch" check passes on the first try.

    This script is the first half of that. It branches off `origin/main`, runs
    set-version.ps1, commits and opens the pull request:

        ./scripts/prepare-release.ps1 0.4.1

    Merge what it opens, then release:

        gh workflow run release.yml --ref main -f version=0.4.1

.PARAMETER Version
    The SemVer version to release. A leading "v" is accepted and stripped.

.PARAMETER NoPush
    Prepare the branch and the commit locally, but push nothing and open no
    pull request. For checking what the bump would contain.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $Version,

    [switch] $NoPush
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# git and gh report failure through exit codes, and several of the calls below
# are questions whose "no" is not an error. Every one of them is read by hand.
$PSNativeCommandUseErrorActionPreference = $false

function Invoke-Checked {
    param([string] $What, [scriptblock] $Command)

    $output = & $Command 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed:`n$($output.Trim())"
    }
    return $output.Trim()
}

$Version = $Version.Trim().TrimStart('v', 'V')
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw "Not a SemVer version: '$Version' (expected something like 0.4.1 or 1.0.0-rc1)"
}
$tag      = "v$Version"
$branch   = "chore/release-$tag"
$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    if (-not $NoPush -and -not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'The GitHub CLI (gh) is not on PATH, so the pull request cannot be opened. Install it, or re-run with -NoPush and open the pull request by hand.'
    }

    # Cheapest failure available, and the same one the workflow leads with: a
    # tag that already exists means this version has shipped.
    Invoke-Checked 'git fetch' { git fetch origin --prune --tags --quiet }
    if (Invoke-Checked 'git ls-remote' { git ls-remote --tags origin "refs/tags/$tag" }) {
        throw "$tag already exists. Pick a version that has not shipped yet."
    }

    # An unrelated edit sitting in the tree would be swept into the release
    # commit by the `git add` below, which stages by path rather than by patch.
    if (git status --porcelain --untracked-files=no) {
        throw 'The working tree has uncommitted changes. Commit or stash them first — the release commit must contain the bump and nothing else.'
    }

    # -B would silently reset a branch that already holds work. Refusing and
    # naming the command to delete it leaves that decision where it belongs.
    if (Invoke-Checked 'git branch --list' { git branch --list $branch }) {
        throw "The branch $branch already exists locally. Delete it first (git branch -D $branch), or finish what is on it."
    }

    Write-Host "Branching $branch off origin/main"
    Invoke-Checked 'git checkout' { git checkout -q -b $branch origin/main }

    & (Join-Path $PSScriptRoot 'set-version.ps1') $Version
    if ($LASTEXITCODE -ne 0) {
        throw "set-version.ps1 failed, so nothing was committed. The branch $branch is still checked out."
    }

    # The workflow prefers docs/release-notes/<tag>.md over GitHub's generated
    # commit list, and this is the last moment where writing one is convenient:
    # after the merge it would take a second pull request.
    $notes = Join-Path $repoRoot "docs/release-notes/$tag.md"
    if (-not (Test-Path -LiteralPath $notes)) {
        Write-Host ''
        Write-Host "  note    docs/release-notes/$tag.md does not exist." -ForegroundColor Yellow
        Write-Host '          The release will fall back to GitHub-generated notes. Writing it now,' -ForegroundColor Yellow
        Write-Host '          before this pull request is merged, is cheaper than a second one after.' -ForegroundColor Yellow
    }

    Write-Host ''
    if (-not (git status --porcelain --untracked-files=no)) {
        throw "Every version site already states $Version and there is nothing to commit. If $tag is genuinely unreleased, main is already prepared for it — run: gh workflow run release.yml --ref main -f version=$Version"
    }

    # --update stages tracked files only, so an untracked release-notes file
    # written into the tree by hand has to be added deliberately.
    Invoke-Checked 'git add' { git add --update }
    Invoke-Checked 'git commit' { git commit -q -m "chore(release): $tag" }
    Write-Host "Committed chore(release): $tag"

    if ($NoPush) {
        Write-Host ''
        Write-Host "Nothing was pushed. The commit is on $branch; review it with: git show"
        return
    }

    Invoke-Checked 'git push' { git push -q -u origin $branch }
    Write-Host "Pushed $branch"

    $body = @"
Raises the version to ``$tag`` across every file that states one.

Merging this before the release runs is what lets the release finish green: the
workflow's own bump step cannot push to a protected ``main``, so it finds the
version already in place instead, tags ``HEAD`` unchanged, and its branch check
passes. See ``scripts/prepare-release.ps1`` for the reasoning.

After this is merged:

``````
gh workflow run release.yml --ref main -f version=$Version
``````
"@

    $created = Invoke-Checked 'gh pr create' {
        gh pr create --base main --head $branch --title "chore(release): $tag" --body $body
    }
    $url = ($created -split "`n" | Where-Object { $_ -match '^\s*https://' } | Select-Object -First 1)

    Write-Host ''
    Write-Host "Pull request: $($url ?? $created)"
    Write-Host ''
    Write-Host 'Next, once it is merged and CI on main is green:'
    Write-Host "  gh workflow run release.yml --ref main -f version=$Version"
}
finally {
    Pop-Location
}
