<#
.SYNOPSIS
Health check for the local security hooks. Never installs anything.

.DESCRIPTION
Reports what is installed, what this repository contains, and - most importantly
- what will silently run degraded if you push right now.

Safe to run at any time. This script has no side effects beyond reading files
and running --version probes.

.PARAMETER Json
Emit a single machine-readable JSON object instead of the human table. Used by
the setup-security-hooks skill.

.PARAMETER RepoRoot
Repository to inspect. Defaults to the git worktree containing the cwd.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File setup/doctor.ps1

.EXAMPLE
powershell -ExecutionPolicy Bypass -File setup/doctor.ps1 -Json

.OUTPUTS
Exit codes:
  0 - ready. Every required tool present, no language degraded.
  1 - usable but degraded. Hooks will run and find real issues, but findings
      are a floor rather than a clean bill of health.
  2 - not ready. A required tool is missing, or hooks are not installed.
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib\tools.ps1')
. (Join-Path $PSScriptRoot 'lib\detect.ps1')

if (-not $RepoRoot) { $RepoRoot = Get-RepoRoot -StartPath (Get-Location).Path }
if (-not $RepoRoot) {
    if ($Json) {
        ConvertTo-Json ([pscustomobject]@{ error = 'Not inside a git repository.' }) -Depth 3
    } else {
        Write-Host 'Not inside a git repository. Run this from the repo you want to check.' -ForegroundColor Red
    }
    exit 2
}

# --- Gather -----------------------------------------------------------------

$tools    = @(Get-AllToolStatus)
$profiles = @(Get-LanguageProfile -RepoRoot $RepoRoot)

# osv-check.ps1 runs osv-scanner --offline, which reads only the local cache
# primed by --download-offline-databases (see setup/install.ps1 and
# setup/templates/hooks/osv-check.ps1). That cache is not something install.ps1
# can guarantee stays fresh, so doctor.ps1 - the thing a developer actually
# reruns to check readiness - is where staleness gets reported.
# The database is PER ECOSYSTEM. A cache that holds npm but not Maven is not
# "primed" for a repo containing a pom.xml - it is a cache that will make the
# hook exit 127 on the first push. So this checks the repo's ecosystems against
# what is on disk rather than asking whether the cache directory exists.
$osvDbStaleAfterDays = 30
$osvDb        = Get-OsvDatabaseStatus -RepoRoot $RepoRoot
$osvCacheDir  = $osvDb.cacheDir
$osvDbAgeDays = $null
if ($osvDb.newestWriteUtc) {
    $osvDbAgeDays = [math]::Floor(((Get-Date).ToUniversalTime() - $osvDb.newestWriteUtc).TotalDays)
}

if (@($osvDb.expected).Count -eq 0) {
    # Nothing here osv-scanner can read, so no database is required. Reporting
    # this as MISSING would be a false alarm; reporting it as OK would imply a
    # dependency scan is happening. It is neither.
    $osvDbStatus = 'NOT_NEEDED'
} elseif (@($osvDb.missing).Count -gt 0) {
    $osvDbStatus = 'MISSING'
} elseif ($null -ne $osvDbAgeDays -and $osvDbAgeDays -gt $osvDbStaleAfterDays) {
    $osvDbStatus = 'STALE'
} else {
    $osvDbStatus = 'OK'
}

# Hook wiring. pre-commit writes shims into .git/hooks; core.hooksPath silently
# overrides that directory, which is a real and confusing failure mode.
$gitDir = & git -C $RepoRoot rev-parse --git-dir 2>$null
if ($gitDir) {
    $gitDir = $gitDir.Trim()
    if (-not [System.IO.Path]::IsPathRooted($gitDir)) {
        $gitDir = [System.IO.Path]::Combine($RepoRoot, $gitDir)
    }
} else {
    $gitDir = [System.IO.Path]::Combine($RepoRoot, '.git')
}

$hooksPathOverride = & git -C $RepoRoot config --get core.hooksPath 2>$null
if ($hooksPathOverride) { $hooksPathOverride = $hooksPathOverride.Trim() } else { $hooksPathOverride = $null }

function Test-PreCommitShim {
    param([string]$Path, [string]$HookType)
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject][ordered]@{ present = $false; managed = $false }
    }
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    $managed = $false
    if ($content -and $content -match 'hook-impl' -and $content -match [regex]::Escape($HookType)) {
        $managed = $true
    }
    return [pscustomobject][ordered]@{ present = $true; managed = $managed }
}

$preCommitShim = Test-PreCommitShim -Path ([System.IO.Path]::Combine($gitDir, 'hooks', 'pre-commit')) -HookType 'pre-commit'
$prePushShim   = Test-PreCommitShim -Path ([System.IO.Path]::Combine($gitDir, 'hooks', 'pre-push'))   -HookType 'pre-push'

$configPath  = [System.IO.Path]::Combine($RepoRoot, '.pre-commit-config.yaml')
$hooksDir    = [System.IO.Path]::Combine($RepoRoot, '.hooks')
$profilePath = [System.IO.Path]::Combine($hooksDir, 'security-profile.json')

$repoFiles = [pscustomobject][ordered]@{
    configPresent       = (Test-Path -LiteralPath $configPath)
    codeqlHookPresent   = (Test-Path -LiteralPath ([System.IO.Path]::Combine($hooksDir, 'codeql-check.ps1')))
    claudeHookPresent   = (Test-Path -LiteralPath ([System.IO.Path]::Combine($hooksDir, 'claude-check.ps1')))
    profilePresent      = (Test-Path -LiteralPath $profilePath)
    hooksDirIgnored     = $false
}

# .hooks/ being gitignored means the rest of the team does not actually get these checks,
# and nobody can review them. Worth surfacing as a finding, not a footnote.
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $null = & git -C $RepoRoot check-ignore -q '.hooks' 2>$null
    if ($LASTEXITCODE -eq 0) { $repoFiles.hooksDirIgnored = $true }
} finally {
    $ErrorActionPreference = $prev
}

# --- Evaluate ---------------------------------------------------------------

$missingRequired = @($tools | Where-Object { $_.required -and $_.status -ne 'OK' })
$degradedLangs   = @($profiles | Where-Object { $_.status -eq 'DEGRADED' })
$blockedLangs    = @($profiles | Where-Object { $_.status -eq 'NEEDS_BUILD' -or $_.status -eq 'UNSUPPORTED' })

$hooksWired = ($preCommitShim.managed -and $prePushShim.managed -and $repoFiles.configPresent)

$readiness = 'READY'
$exitCode  = 0
if ($missingRequired.Count -gt 0 -or -not $hooksWired) {
    $readiness = 'NOT_READY'
    $exitCode  = 2
} elseif ($degradedLangs.Count -gt 0 -or $osvDbStatus -eq 'MISSING' -or $osvDbStatus -eq 'STALE') {
    $readiness = 'DEGRADED'
    $exitCode  = 1
}

$blockers = @()
foreach ($t in $missingRequired) {
    $blockers += "$($t.name) is $($t.status)."
}
if (-not $repoFiles.configPresent) { $blockers += '.pre-commit-config.yaml is missing.' }
if (-not $preCommitShim.managed)   { $blockers += 'No pre-commit hook shim - secret scanning will not run on commit.' }
if (-not $prePushShim.managed)     { $blockers += 'No pre-push hook shim - CodeQL and Claude will not run on push.' }
if ($hooksPathOverride)            { $blockers += "core.hooksPath is set to '$hooksPathOverride', which overrides .git/hooks." }

# Not added to $blockers: that list is only printed under NOT_READY, and a
# missing/stale osv database is DEGRADED-level (the hook still runs, it just
# can't find anything until primed). Reported in its own always-shown section
# below instead, the same way language degradation gets its own section
# rather than living in $blockers.

# --- Output -----------------------------------------------------------------

if ($Json) {
    $out = [pscustomobject][ordered]@{
        readiness         = $readiness
        exitCode          = $exitCode
        repoRoot          = $RepoRoot
        codeqlHome        = Get-CodeQLHome
        toolRoot          = Get-ToolRootPath
        tools             = $tools
        languages         = $profiles
        hooks             = [pscustomobject][ordered]@{
            wired             = $hooksWired
            preCommitPresent  = $preCommitShim.present
            preCommitManaged  = $preCommitShim.managed
            prePushPresent    = $prePushShim.present
            prePushManaged    = $prePushShim.managed
            hooksPathOverride = $hooksPathOverride
        }
        repoFiles         = $repoFiles
        osvDatabase       = [pscustomobject][ordered]@{
            status             = $osvDbStatus
            ageDays            = $osvDbAgeDays
            staleAfterDays     = $osvDbStaleAfterDays
            cacheDir           = $osvCacheDir
            ecosystemsExpected = @($osvDb.expected)
            ecosystemsPresent  = @($osvDb.present)
            ecosystemsMissing  = @($osvDb.missing)
        }
        blockers          = @($blockers)
        degradedLanguages = @($degradedLangs | ForEach-Object { $_.language })
        blockedLanguages  = @($blockedLangs  | ForEach-Object { $_.language })
    }
    ConvertTo-Json $out -Depth 8
    exit $exitCode
}

function Write-StatusLine {
    param([string]$Label, [string]$Status, [string]$Detail)
    $colour = 'Red'
    if ($Status -eq 'OK')       { $colour = 'Green' }
    if ($Status -eq 'DEGRADED') { $colour = 'Yellow' }
    if ($Status -eq 'PARTIAL')  { $colour = 'Yellow' }
    # Not red: "no database needed here" is a correct state, not a fault.
    if ($Status -eq 'N/A')      { $colour = 'DarkGray' }
    Write-Host ('  {0,-24}' -f $Label) -NoNewline
    Write-Host ('{0,-12}' -f $Status) -ForegroundColor $colour -NoNewline
    Write-Host $Detail -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'Local security checks - health check' -ForegroundColor Cyan
Write-Host "Repository: $RepoRoot" -ForegroundColor DarkGray
Write-Host ''

Write-Host 'TOOLS' -ForegroundColor White
foreach ($t in $tools) {
    $detail = ''
    if ($t.status -eq 'OK') {
        $detail = "v$($t.version)"
        if ($t.version -ne $t.testedVersion) { $detail += " (POC tested $($t.testedVersion))" }
    } elseif ($t.status -eq 'PARTIAL') {
        $detail = 'on PATH but version probe failed'
    } elseif ($t.installMethod -eq 'none') {
        $detail = "install manually: $($t.docsUrl)"
    } else {
        $detail = "installable via $($t.installMethod)"
    }
    Write-StatusLine -Label $t.name -Status $t.status -Detail $detail
}

Write-Host ''
Write-Host 'HOOK WIRING' -ForegroundColor White
$ccStatus = 'MISSING'; if ($repoFiles.configPresent) { $ccStatus = 'OK' }
Write-StatusLine -Label '.pre-commit-config.yaml' -Status $ccStatus -Detail ''
$pcStatus = 'MISSING'; if ($preCommitShim.managed) { $pcStatus = 'OK' } elseif ($preCommitShim.present) { $pcStatus = 'PARTIAL' }
Write-StatusLine -Label 'pre-commit shim' -Status $pcStatus -Detail 'secret scan on commit'
$ppStatus = 'MISSING'; if ($prePushShim.managed) { $ppStatus = 'OK' } elseif ($prePushShim.present) { $ppStatus = 'PARTIAL' }
Write-StatusLine -Label 'pre-push shim' -Status $ppStatus -Detail 'CodeQL + Claude on push'
if ($hooksPathOverride) {
    Write-Host "  core.hooksPath is set to '$hooksPathOverride' and overrides .git/hooks." -ForegroundColor Yellow
}
if ($repoFiles.hooksDirIgnored) {
    Write-Host '  .hooks/ is gitignored, so the rest of the team will not receive these hooks and nobody can review them.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'LANGUAGES IN THIS REPO' -ForegroundColor White
if ($profiles.Count -eq 0) {
    Write-Host '  No files in a CodeQL-supported language were found.' -ForegroundColor DarkGray
} else {
    foreach ($p in $profiles) {
        Write-StatusLine -Label "$($p.language) ($($p.fileCount) files)" -Status $p.status -Detail ''
        foreach ($r in $p.reasons) {
            Write-Host "      $r" -ForegroundColor DarkGray
        }
        foreach ($m in $p.missingToolchain) {
            if ($m.installMethod -eq 'winget' -and $m.packageId) {
                Write-Host "      fix: winget install --id $($m.packageId)" -ForegroundColor DarkCyan
            }
        }
    }
}

Write-Host ''
Write-Host 'DEPENDENCY DATABASE (osv-scanner, offline mode)' -ForegroundColor White
switch ($osvDbStatus) {
    'OK' {
        Write-StatusLine -Label 'osv offline db' -Status 'OK' -Detail "refreshed $osvDbAgeDays day(s) ago"
    }
    'STALE' {
        Write-StatusLine -Label 'osv offline db' -Status 'DEGRADED' -Detail "$osvDbAgeDays days old (stale after $osvDbStaleAfterDays) - vulnerabilities disclosed since then will not be caught"
    }
    'MISSING' {
        Write-StatusLine -Label 'osv offline db' -Status 'MISSING' -Detail "no local database for: $(@($osvDb.missing) -join ', ')"
        Write-Host '      The database is PER ECOSYSTEM. osv-scanner exits 127 for an ecosystem it' -ForegroundColor DarkGray
        Write-Host '      has no database for, and writes {"results": []} while doing it - which is' -ForegroundColor DarkGray
        Write-Host '      why the hook judges the exit code and not just the report.' -ForegroundColor DarkGray
        Write-Host '      fix: osv-scanner scan source --offline-vulnerabilities --download-offline-databases --recursive .' -ForegroundColor DarkCyan
    }
    'NOT_NEEDED' {
        Write-StatusLine -Label 'osv offline db' -Status 'N/A' -Detail 'no dependency manifest osv-scanner can read, so nothing to prime'
        Write-Host '      The osv hook will report SKIPPED (NOT SCANNED) here, which is not a pass.' -ForegroundColor DarkGray
        Write-Host '      osv-scanner reads lockfiles: build.gradle and a bare Gemfile are invisible to it.' -ForegroundColor DarkGray
    }
}
if (@($osvDb.expected).Count -gt 0) {
    Write-Host "      ecosystems in this repo: $(@($osvDb.expected) -join ', ')" -ForegroundColor DarkGray
}

Write-Host ''
switch ($readiness) {
    'READY' {
        Write-Host 'READY. All required tools present, hooks wired, no degraded languages.' -ForegroundColor Green
    }
    'DEGRADED' {
        Write-Host 'USABLE BUT DEGRADED.' -ForegroundColor Yellow
        Write-Host 'The hooks will run and will catch real issues, but for the languages above'
        Write-Host 'the results are a floor, not a clean bill of health. A pass does not mean'
        Write-Host 'the code is clean - it means nothing was found with reduced visibility.'
    }
    'NOT_READY' {
        Write-Host 'NOT READY.' -ForegroundColor Red
        foreach ($b in $blockers) { Write-Host "  - $b" }
        Write-Host ''
        Write-Host 'Run setup/install.ps1 to fix, or ask Claude Code: /setup-security-hooks' -ForegroundColor Cyan
    }
}
Write-Host ''

exit $exitCode
