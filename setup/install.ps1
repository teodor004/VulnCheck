<#
.SYNOPSIS
Installs and wires up the local security checks in this repository.

.DESCRIPTION
Runs the same checks as doctor.ps1, then installs what is missing and wires the
git hooks. Nothing is installed without consent: either -Yes, or an interactive
confirmation, or -DryRun to see the plan and change nothing.

Idempotent. Running it on an already-configured machine installs nothing and
reports the current state.

.PARAMETER DryRun
Print the full plan and exit. Changes nothing. Recommended first run.

.PARAMETER Yes
Skip the interactive confirmation. Required for non-interactive use.

.PARAMETER SkipToolInstall
Wire up hooks and config but install no tools. Prints the commands instead.

.PARAMETER IncludeToolchains
Also install language toolchains that only affect result quality (JDK, Node).
Off by default because these are large and the hooks work without them - just
with reduced visibility.

.PARAMETER QuerySuite
code-scanning (default, security only) or security-and-quality (adds hygiene
queries; ~3x the query count and correspondingly slower).

.PARAMETER Blocking
Which pre-push checks block a push: none, codeql (default), claude, or both.
Defaults to codeql because the whole point of this mechanism is that
vulnerabilities do not reach GitHub. The POC measured a clean push at ~191 s,
almost all of it CodeQL rebuilding its database - the honest cost of the
default, not a reason to weaken it.

The dependency scan (osv) blocks under every value except none. It is grouped
with codeql rather than claude because its findings are deterministic and each
carries a CVE/GHSA id and a fixed version, and because it costs seconds.

.PARAMETER ClaudeBudgetUsd
Per-push spend cap for the Claude review. Default 1.00.

.PARAMETER AllowUnverifiedDownload
If a tool's published checksum cannot be fetched, install it anyway rather
than aborting for that tool. Off by default - see the parameter's own comment
below for why.

.PARAMETER InstallSkill
Copy every skill under plugins/shift-left-security/skills/ (setup-
security-hooks, compliance-audit) to the user-level Claude Code skills
directory so they work in every repository.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File setup/install.ps1 -DryRun

.EXAMPLE
powershell -ExecutionPolicy Bypass -File setup/install.ps1 -Yes -Blocking codeql

.OUTPUTS
Exit codes: 0 success (or dry run), 2 failed or aborted.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Yes,
    [switch]$SkipToolInstall,
    [switch]$IncludeToolchains,
    [ValidateSet('code-scanning', 'security-and-quality')]
    [string]$QuerySuite = 'code-scanning',
    # Default is 'codeql', not 'none'. The whole point of this mechanism is that
    # vulnerabilities do NOT reach GitHub, so that server-side code scanning has fewer
    # alerts to raise. An advisory default would let the vulnerable code through
    # and the alert would still be raised - which defeats the purpose.
    #
    # Claude stays advisory by default: it is a probabilistic reviewer with a
    # spend cap, so a budget exhaustion or a debatable judgement must not be able
    # to block a push. CodeQL findings are deterministic and reproducible.
    [ValidateSet('none', 'codeql', 'claude', 'both')]
    [string]$Blocking = 'codeql',
    [double]$ClaudeBudgetUsd = 1.00,
    [int]$ClaudeMaxTurns = 5,
    [switch]$InstallSkill,
    # Off by default: if the SHA-256 published alongside a tool's GitHub
    # release cannot be fetched, the install ABORTS for that tool rather than
    # installing and running an unverified binary. Pass this only when a known
    # proxy blocks the checksum file specifically (not the asset itself) - it
    # is the same escape hatch that has always existed for the CodeQL bundle,
    # now explicit and opt-in instead of a silent warn-and-proceed.
    [switch]$AllowUnverifiedDownload,
    [string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib\tools.ps1')
. (Join-Path $PSScriptRoot 'lib\detect.ps1')
. (Join-Path $PSScriptRoot 'lib\install-helpers.ps1')

$script:Actions  = @()
$script:Failures = @()

function Add-Action {
    param([string]$Kind, [string]$Description, [scriptblock]$Do)
    $script:Actions += [pscustomobject][ordered]@{
        kind        = $Kind
        description = $Description
        do          = $Do
    }
}

function Write-Section { param([string]$Text) Write-Host ''; Write-Host $Text -ForegroundColor Cyan }
function Write-Ok      { param([string]$Text) Write-Host "  [ok]   $Text" -ForegroundColor Green }
function Write-Plan    { param([string]$Text) Write-Host "  [plan] $Text" -ForegroundColor Yellow }
function Write-Skip    { param([string]$Text) Write-Host "  [skip] $Text" -ForegroundColor DarkGray }
function Write-Fail    { param([string]$Text) Write-Host "  [FAIL] $Text" -ForegroundColor Red }

# --- Preconditions ----------------------------------------------------------

if (-not $RepoRoot) { $RepoRoot = Get-RepoRoot -StartPath (Get-Location).Path }
if (-not $RepoRoot) {
    Write-Host 'Not inside a git repository. Run this from the repo you want to protect.' -ForegroundColor Red
    exit 2
}

Write-Host ''
Write-Host 'Local security checks - installer' -ForegroundColor Cyan
Write-Host "Repository: $RepoRoot" -ForegroundColor DarkGray
if ($DryRun) { Write-Host 'DRY RUN - nothing will be changed.' -ForegroundColor Yellow }

# --- Survey -----------------------------------------------------------------

Write-Section 'Checking tools'

$registry = Get-ToolRegistry
$toolById = @{}
foreach ($t in $registry) { $toolById[$t.Id] = $t }

$statuses = @(Get-AllToolStatus)
$needsShellRestart = $false

foreach ($s in $statuses) {
    $tool = $toolById[$s.id]

    if ($s.status -eq 'OK') {
        Write-Ok "$($s.name) v$($s.version)"
        continue
    }

    if ($s.status -eq 'PARTIAL') {
        Write-Host "  [warn] $($s.name) is on PATH but its version could not be read. Continuing." -ForegroundColor Yellow
        continue
    }

    # MISSING from here.
    if ($tool.InstallMethod -eq 'none') {
        Write-Fail "$($s.name) is missing and is not installed automatically."
        Write-Host "         $($tool.Why)" -ForegroundColor DarkGray
        Write-Host "         See: $($tool.DocsUrl)" -ForegroundColor DarkGray
        $script:Failures += "$($s.name) must be installed manually: $($tool.DocsUrl)"
        continue
    }

    if ($SkipToolInstall) {
        Write-Skip "$($s.name) is missing (-SkipToolInstall given)."
        continue
    }

    switch ($tool.InstallMethod) {
        'winget' {
            $pkg = $tool.InstallSpec.PackageId
            Write-Plan "install $($s.name) via winget ($pkg)"
            Add-Action -Kind 'tool' -Description "winget install $pkg" -Do {
                # --accept-*-agreements is mandatory here: without it winget can
                # block on an interactive licence prompt, which hangs a
                # non-interactive install forever.
                & winget install --id $pkg --exact --silent `
                    --accept-source-agreements --accept-package-agreements
                # $global: is required, not stylistic. GetNewClosure() snapshots
                # $LASTEXITCODE into the closure's own scope, and that stale copy
                # then shadows the global that native commands actually update.
                # A bare $LASTEXITCODE here reports whatever the exit code was
                # when the closure was BUILT - so a failed install can be
                # reported as success.
                if ($global:LASTEXITCODE -ne 0) { throw "winget exited $global:LASTEXITCODE for $pkg" }
            }.GetNewClosure()
            $needsShellRestart = $true
        }
        'pip' {
            $pkg = $tool.InstallSpec.Package
            Write-Plan "install $($s.name) via pip ($pkg)"
            Add-Action -Kind 'tool' -Description "pip install $pkg" -Do {
                & python -m pip install --user $pkg
                # $global: - see the winget branch above.
                if ($global:LASTEXITCODE -ne 0) { throw "pip exited $global:LASTEXITCODE for $pkg" }
            }.GetNewClosure()
            $needsShellRestart = $true
        }
        'manual' {
            $spec = $tool.InstallSpec
            if ($spec.Kind -eq 'targz') {
                Write-Plan "download and extract $($s.name) (~$($spec.ApproxSizeMB) MB) to $($spec.ExtractTo)"
                Write-Host '         This is the CodeQL BUNDLE, which includes every query pack.' -ForegroundColor DarkGray
                Write-Host '         The smaller codeql-cli-binaries download has no query packs and' -ForegroundColor DarkGray
                Write-Host '         would fail at push time when a query suite fails to resolve.' -ForegroundColor DarkGray
                Add-Action -Kind 'tool' -Description "download + extract CodeQL bundle to $($spec.ExtractTo)" -Do {
                    Install-CodeQLBundle -Spec $spec -AllowUnverified:$AllowUnverifiedDownload
                }.GetNewClosure()
            } else {
                # 'zip' (gitleaks) or 'exe' (osv-scanner): a pinned GitHub release
                # asset, checksum-verified against the file published alongside it.
                Write-Plan "download $($s.name) (~$($spec.ApproxSizeMB) MB, checksum-verified) to $($spec.ExtractTo)"
                Add-Action -Kind 'tool' -Description "download + verify $($s.name)" -Do {
                    Install-GithubReleaseAsset -Spec $spec -AllowUnverified:$AllowUnverifiedDownload
                }.GetNewClosure()
            }
            $needsShellRestart = $true
        }
    }
}

# --- Toolchains -------------------------------------------------------------

Write-Section 'Checking language support for this repository'

$profiles = @(Get-LanguageProfile -RepoRoot $RepoRoot)

if ($profiles.Count -eq 0) {
    Write-Skip 'No files in a CodeQL-supported language found. The secret scan still applies.'
}

foreach ($p in $profiles) {
    switch ($p.status) {
        'OK' { Write-Ok "$($p.language) ($($p.fileCount) files)" }
        'DEGRADED' {
            Write-Host "  [warn] $($p.language) ($($p.fileCount) files) will run DEGRADED" -ForegroundColor Yellow
            foreach ($r in $p.reasons) { Write-Host "         $r" -ForegroundColor DarkGray }
            foreach ($m in $p.missingToolchain) {
                if ($IncludeToolchains -and $m.installMethod -eq 'winget' -and $m.packageId -and -not $SkipToolInstall) {
                    $pid2 = $m.packageId
                    Write-Plan "install $($m.name) via winget ($pid2)"
                    Add-Action -Kind 'toolchain' -Description "winget install $pid2" -Do {
                        & winget install --id $pid2 --exact --silent `
                            --accept-source-agreements --accept-package-agreements
                        # $global: - see the tool install branch above.
                        if ($global:LASTEXITCODE -ne 0) { throw "winget exited $global:LASTEXITCODE for $pid2" }
                    }.GetNewClosure()
                    $needsShellRestart = $true
                } elseif ($IncludeToolchains -and $m.installMethod -eq 'manual' -and $m.installSpec -and -not $SkipToolInstall) {
                    $tcSpec = $m.installSpec
                    Write-Plan "download $($m.name) (~$($tcSpec.ApproxSizeMB) MB, checksum-verified) to $($tcSpec.ExtractTo)"
                    Add-Action -Kind 'toolchain' -Description "download + verify $($m.name)" -Do {
                        Install-GithubReleaseAsset -Spec $tcSpec -AllowUnverified:$AllowUnverifiedDownload
                    }.GetNewClosure()
                    $needsShellRestart = $true
                } elseif ($m.installMethod -eq 'winget' -and $m.packageId) {
                    Write-Host "         fix later: winget install --id $($m.packageId)  (or re-run with -IncludeToolchains)" -ForegroundColor DarkCyan
                } elseif ($m.installMethod -eq 'manual' -and $m.installSpec) {
                    Write-Host "         fix later: re-run with -IncludeToolchains (downloads a checksum-verified $($m.name), ~$($m.installSpec.ApproxSizeMB) MB)" -ForegroundColor DarkCyan
                }
            }
        }
        'NEEDS_BUILD' {
            Write-Host "  [warn] $($p.language) ($($p.fileCount) files) cannot be analysed buildless and will be SKIPPED" -ForegroundColor Yellow
            foreach ($r in $p.reasons) { Write-Host "         $r" -ForegroundColor DarkGray }
        }
        'UNSUPPORTED' {
            Write-Host "  [warn] $($p.language) ($($p.fileCount) files) is UNSUPPORTED here and will be SKIPPED" -ForegroundColor Yellow
            foreach ($r in $p.reasons) { Write-Host "         $r" -ForegroundColor DarkGray }
        }
    }
}

# Verify the chosen suite actually resolves, but only when CodeQL is already
# present - there is nothing to ask before it is installed.
if ((Get-CodeQLHome) -and $profiles.Count -gt 0) {
    $analysable = @($profiles | Where-Object { $_.status -eq 'OK' -or $_.status -eq 'DEGRADED' })
    foreach ($p in $analysable) {
        $suites = Get-AvailableQuerySuites -Language $p.language
        $chosen = $suites[$QuerySuite]
        if ($chosen.resolves) {
            Write-Ok "$($chosen.suite) resolves ($($chosen.queryCount) queries)"
        } else {
            Write-Fail "$($chosen.suite) does not resolve. This is the symptom of the bare CLI being installed instead of the bundle."
            $script:Failures += "Query suite $($chosen.suite) does not resolve. Reinstall the CodeQL bundle."
        }
    }
}

# --- Offline vulnerability database ------------------------------------------
#
# osv-check.ps1 runs osv-scanner --offline (see setup/templates/hooks/osv-check.ps1
# for why - an unflagged scan calls out to osv.dev/deps.dev on every push, which
# this tool must not do). --offline only works against a database primed by
# --download-offline-databases, and priming it is itself one network call -
# made once, here, at install time, not on every push. Gated behind
# -SkipToolInstall for the same reason the winget/pip installs above are: it
# changes machine state and needs network.
#
# The database is PER ECOSYSTEM, so "already primed" is not a yes/no question.
# Verified 2026-08-17: priming against an npm-only repo produces a cache holding
# only npm\all.zip, and that cache then answers "could not load db for Maven
# ecosystem" (exit 127) the first time somebody adds a pom.xml. An earlier version
# of this block tested only for "any file under the cache dir", which called that
# machine primed and let the gap through. It now compares the repo's ecosystems
# against the cache and primes when any are missing - see
# Get-OsvDatabaseStatus in lib\detect.ps1.
#
# Only the ecosystems this repo actually uses are downloaded, not every ecosystem
# OSV publishes. Measured 2026-08-17: npm is 210 MB, PyPI 32 MB, Maven 9.6 MB, so
# priming everything would cost a Java-only repo a 210 MB npm download it will
# never read. The cost of the narrower choice is that adding a new language needs
# a re-run, which is exactly what the hook's exit 127 message tells you to do.
#
# Staleness is doctor.ps1's job to report, not install.ps1's job to silently
# refresh on every idempotent re-run.

$osvStatus = $statuses | Where-Object { $_.id -eq 'osv-scanner' } | Select-Object -First 1
$osvDb     = Get-OsvDatabaseStatus -RepoRoot $RepoRoot

if ($osvStatus -and $osvStatus.status -eq 'OK') {
    if (@($osvDb.expected).Count -eq 0) {
        # Nothing in this repo that osv-scanner can read, so there is no database
        # to prime. Reported rather than passed over in silence: it means the
        # dependency hook will find nothing here, which a reader of this output
        # should not have to infer.
        Write-Skip 'no dependency manifests osv-scanner can read, so no offline database is needed. The osv hook will report SKIPPED (NOT SCANNED) until a lockfile is committed.'
    } elseif (@($osvDb.missing).Count -eq 0) {
        Write-Ok "osv-scanner offline database already primed for: $(@($osvDb.present) -join ', ')"
    } elseif ($SkipToolInstall) {
        Write-Skip "osv-scanner offline database missing for $(@($osvDb.missing) -join ', ') (-SkipToolInstall given). The osv hook will fail closed (TOOL ERROR, exit 127) until: osv-scanner scan source --offline-vulnerabilities --download-offline-databases --recursive ."
    } else {
        Write-Plan "prime osv-scanner offline vulnerability database for $(@($osvDb.missing) -join ', ') (one-time, needs network)"
        Add-Action -Kind 'tool' -Description "download osv-scanner offline vulnerability database ($(@($osvDb.missing) -join ', '))" -Do {
            $tmpOut = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "osv-db-prime-$([System.Guid]::NewGuid().ToString('N')).json")
            & $osvStatus.Path scan source --offline-vulnerabilities --download-offline-databases `
                --recursive --format json --output-file $tmpOut $RepoRoot | Out-Null
            $primeExit = $global:LASTEXITCODE

            # osv-scanner's own exit codes: 0 clean, 1 vulnerabilities found - both
            # mean the database downloaded and a real scan ran against this repo.
            # 128 means it found no package sources, which is not a download
            # failure and must not throw: it is the normal outcome for a repo whose
            # only manifest turns out to be unreadable after all.
            if ($primeExit -ne 0 -and $primeExit -ne 1 -and $primeExit -ne 128) {
                throw "osv-scanner --download-offline-databases exited $primeExit - see setup/templates/hooks/osv-check.ps1 for what this hook needs it for."
            }
            Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue

            # Verify rather than assume. A prime that exits 0 while leaving an
            # ecosystem unprimed would hand the developer a hook that fails 127 on
            # their first push, with nothing in this install log to explain it.
            $after = Get-OsvDatabaseStatus -RepoRoot $RepoRoot
            if (@($after.missing).Count -gt 0) {
                throw "osv-scanner reported success but the offline database is still missing for: $(@($after.missing) -join ', '). The osv hook would exit 127 on the first push."
            }
        }.GetNewClosure()
    }
}

# --- Repository files -------------------------------------------------------

Write-Section 'Wiring the repository'

$hooksDir    = [System.IO.Path]::Combine($RepoRoot, '.hooks')
$configPath  = [System.IO.Path]::Combine($RepoRoot, '.pre-commit-config.yaml')
$templateDir = Join-Path $PSScriptRoot 'templates'

# cyclonedx-init.gradle is not a hook, but it is a hook asset: osv-check.ps1 passes
# it to Gradle with -I so the SBOM plugin is applied without touching the repo's
# own build.gradle. Copied by the same hash-compare loop so it stays in step with
# the hook that uses it.
foreach ($hook in @('codeql-check.ps1', 'osv-check.ps1', 'claude-check.ps1', 'cyclonedx-init.gradle')) {
    $src = [System.IO.Path]::Combine($templateDir, 'hooks', $hook)
    $dst = [System.IO.Path]::Combine($hooksDir, $hook)
    if (-not (Test-Path -LiteralPath $src)) {
        Write-Fail "Template missing: $src"
        $script:Failures += "Template missing: $src"
        continue
    }
    $needsCopy = $true
    if (Test-Path -LiteralPath $dst) {
        $srcHash = Get-Sha256Hex -Path $src
        $dstHash = Get-Sha256Hex -Path $dst
        if ($srcHash -eq $dstHash) { $needsCopy = $false }
    }
    if ($needsCopy) {
        Write-Plan "write .hooks/$hook"
        Add-Action -Kind 'repo' -Description "copy $hook into .hooks/" -Do {
            $dir = [System.IO.Path]::GetDirectoryName($dst)
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Copy-Item -LiteralPath $src -Destination $dst -Force
        }.GetNewClosure()
    } else {
        Write-Ok ".hooks/$hook already current"
    }
}

# The config is the one file a repo is most likely to already own for unrelated
# reasons. Never clobber it - a silently replaced config would remove whatever
# other hooks the team depends on.
$configAction = 'create'
if (Test-Path -LiteralPath $configPath) {
    $existing = Get-Content -LiteralPath $configPath -Raw
    $hasOurs  = ($existing -match 'codeql-check\.ps1') -and ($existing -match 'claude-check\.ps1') -and ($existing -match 'gitleaks')
    if ($hasOurs) {
        # "Contains our checks" is not the same as "is up to date". An earlier
        # version of this config had no pre-push gitleaks safety net, so a repo
        # set up before that would get its hook scripts upgraded and keep a
        # config that silently omits the check - the exact silent-gap failure
        # this installer exists to prevent. Report each missing hook id by name
        # rather than offering to rewrite the file: it may have been edited on
        # purpose, and merging is the user's call.
        $configAction = 'keep'
        Write-Ok '.pre-commit-config.yaml already contains the core checks'

        $templateCfg = [System.IO.Path]::Combine($templateDir, 'pre-commit-config.yaml')
        if (Test-Path -LiteralPath $templateCfg) {
            $tmplText = Get-Content -LiteralPath $templateCfg -Raw
            $missingIds = @()
            foreach ($m in [regex]::Matches($tmplText, '(?m)^\s*-\s*id:\s*(\S+)')) {
                $id = $m.Groups[1].Value
                if ($existing -notmatch ('(?m)^\s*-\s*id:\s*' + [regex]::Escape($id) + '\s*$')) {
                    $missingIds += $id
                }
            }
            if ($missingIds.Count -gt 0) {
                Write-Host "  [warn] but it is missing $($missingIds.Count) check(s) this version adds: $($missingIds -join ', ')" -ForegroundColor Yellow
                Write-Host '         The config was NOT rewritten. Copy the missing block(s) from' -ForegroundColor DarkGray
                Write-Host '         setup/templates/pre-commit-config.yaml into your config.' -ForegroundColor DarkGray
                if ($missingIds -contains 'gitleaks-push') {
                    Write-Host '         gitleaks-push matters: without it, `git commit --no-verify` skips' -ForegroundColor DarkGray
                    Write-Host '         secret scanning and the secret is never caught before it is pushed.' -ForegroundColor DarkGray
                }
                if ($missingIds -contains 'osv') {
                    Write-Host '         osv matters: CodeQL only analyses code you wrote. Without this' -ForegroundColor DarkGray
                    Write-Host '         check, a known-vulnerable dependency is never looked at.' -ForegroundColor DarkGray
                }
            }
        }
    } else {
        $configAction = 'refuse'
        Write-Fail '.pre-commit-config.yaml exists but does not contain these three checks.'
        Write-Host '         Refusing to overwrite it. Merge the block from setup/templates/' -ForegroundColor DarkGray
        Write-Host '         pre-commit-config.yaml by hand, then re-run.' -ForegroundColor DarkGray
        $script:Failures += 'Existing .pre-commit-config.yaml needs a manual merge (not overwritten).'
    }
} else {
    Write-Plan 'create .pre-commit-config.yaml'
    Add-Action -Kind 'repo' -Description 'create .pre-commit-config.yaml' -Do {
        $src = [System.IO.Path]::Combine($templateDir, 'pre-commit-config.yaml')
        Copy-Item -LiteralPath $src -Destination $configPath -Force
    }.GetNewClosure()
}

# The manifest the hooks read at runtime.
Write-Plan 'write .hooks/security-profile.json'
$blockCodeql = ($Blocking -eq 'codeql' -or $Blocking -eq 'both')
$blockClaude = ($Blocking -eq 'claude' -or $Blocking -eq 'both')
# osv is grouped with codeql rather than claude, and blocks unless -Blocking none.
# Its findings are deterministic and each one arrives with a CVE/GHSA id and a
# fixed version, so there is nothing to debate and a concrete action to take -
# the same properties that make CodeQL blocking by default. It is also cheap: it
# reads lockfiles, so it cannot become the reason a push feels slow.
$blockOsv = ($Blocking -ne 'none')
Add-Action -Kind 'repo' -Description 'write .hooks/security-profile.json' -Do {
    Write-SecurityProfile -Path ([System.IO.Path]::Combine($hooksDir, 'security-profile.json')) `
        -Profiles $profiles -QuerySuite $QuerySuite `
        -BlockCodeql $blockCodeql -BlockClaude $blockClaude -BlockOsv $blockOsv `
        -BudgetUsd $ClaudeBudgetUsd -MaxTurns $ClaudeMaxTurns
}.GetNewClosure()

# .hooks/ gitignored means the rest of the team never receives these checks.
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $null = & git -C $RepoRoot check-ignore -q '.hooks' 2>$null
    $hooksIgnored = ($LASTEXITCODE -eq 0)
} finally {
    $ErrorActionPreference = $prev
}
if ($hooksIgnored) {
    Write-Host '  [warn] .hooks/ is gitignored. Commit it, or your team will not get these checks' -ForegroundColor Yellow
    Write-Host '         and nobody can review them. The installer will not edit .gitignore for you.' -ForegroundColor DarkGray
}

# --- Hook installation ------------------------------------------------------

$gitDir = & git -C $RepoRoot rev-parse --git-dir 2>$null
if ($gitDir) {
    $gitDir = $gitDir.Trim()
    if (-not [System.IO.Path]::IsPathRooted($gitDir)) { $gitDir = [System.IO.Path]::Combine($RepoRoot, $gitDir) }
} else {
    $gitDir = [System.IO.Path]::Combine($RepoRoot, '.git')
}

$hooksPathOverride = & git -C $RepoRoot config --get core.hooksPath 2>$null
if ($hooksPathOverride) {
    Write-Host "  [warn] core.hooksPath is '$($hooksPathOverride.Trim())' and overrides .git/hooks." -ForegroundColor Yellow
    Write-Host '         pre-commit install writes to .git/hooks, so the hooks may never fire.' -ForegroundColor DarkGray
}

$shimsOk = $true
foreach ($h in @('pre-commit', 'pre-push')) {
    $shim = [System.IO.Path]::Combine($gitDir, 'hooks', $h)
    $ok = $false
    if (Test-Path -LiteralPath $shim) {
        $c = Get-Content -LiteralPath $shim -Raw -ErrorAction SilentlyContinue
        if ($c -and $c -match 'hook-impl' -and $c -match [regex]::Escape($h)) { $ok = $true }
    }
    if ($ok) { Write-Ok "$h shim present" } else { $shimsOk = $false }
}

if (-not $shimsOk) {
    Write-Plan 'run pre-commit install --hook-type pre-commit --hook-type pre-push'
    Add-Action -Kind 'repo' -Description 'pre-commit install (both hook types)' -Do {
        Push-Location $RepoRoot
        try {
            # Both types are named explicitly rather than relying on
            # default_install_hook_types, which is easy to lose in a merged config.
            & pre-commit install --hook-type pre-commit --hook-type pre-push
            # $global: - see the tool install branch above. This is the call that
            # exposed the bug: pre-commit succeeded and printed both shims, yet a
            # bare $LASTEXITCODE reported 1, inherited from an earlier
            # `git config --get core.hooksPath` that exits 1 when unset.
            if ($global:LASTEXITCODE -ne 0) { throw "pre-commit install exited $global:LASTEXITCODE" }
        } finally { Pop-Location }
    }.GetNewClosure()
}

# --- Skill(s) -----------------------------------------------------------------
#
# Source lives under plugins/shift-left-security/skills/ so this repo's
# layout follows the Claude Code plugin convention (plugins/<name>/skills/
# <skill>/SKILL.md) rather than a VulnCheck-specific path. Installs every skill
# directory found there, not just setup-security-hooks - compliance-audit lives
# alongside it now and a developer running -InstallSkill almost certainly wants
# both, since they ship as one plugin.

if ($InstallSkill) {
    $skillsSrcRoot = [System.IO.Path]::Combine($PSScriptRoot, '..', 'plugins', 'shift-left-security', 'skills')
    if (Test-Path -LiteralPath $skillsSrcRoot) {
        Get-ChildItem -LiteralPath $skillsSrcRoot -Directory | ForEach-Object {
            $skillSrc = $_.FullName
            $skillName = $_.Name
            $skillDst = [System.IO.Path]::Combine($env:USERPROFILE, '.claude', 'skills', $skillName)
            Write-Plan "install skill '$skillName' to $skillDst"
            Add-Action -Kind 'skill' -Description "copy $skillName to user-level Claude Code skills" -Do {
                if (-not (Test-Path -LiteralPath $skillDst)) { New-Item -ItemType Directory -Path $skillDst -Force | Out-Null }
                Copy-Item -LiteralPath (Join-Path $skillSrc '*') -Destination $skillDst -Recurse -Force
            }.GetNewClosure()
        }
    } else {
        Write-Fail "Skills source missing: $skillsSrcRoot"
    }
}

# --- Plan summary and consent ----------------------------------------------

Write-Section 'Plan'

if ($script:Actions.Count -eq 0) {
    Write-Host '  Nothing to do. Everything is already in place.' -ForegroundColor Green
} else {
    $i = 1
    foreach ($a in $script:Actions) {
        Write-Host ("  {0}. [{1}] {2}" -f $i, $a.kind, $a.description)
        $i++
    }
}

Write-Host ''
Write-Host 'Configuration that will be written:' -ForegroundColor White
Write-Host "  query suite     : $QuerySuite"
Write-Host "  blocking        : $Blocking"
Write-Host "  claude budget   : `$$ClaudeBudgetUsd per push"
Write-Host "  claude maxTurns : $ClaudeMaxTurns"

if ($script:Failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'Problems that need a human:' -ForegroundColor Red
    foreach ($f in $script:Failures) { Write-Host "  - $f" }
}

if ($DryRun) {
    Write-Host ''
    Write-Host 'Dry run complete. Nothing was changed.' -ForegroundColor Yellow
    Write-Host 'Re-run without -DryRun to apply, or with -Yes to skip the prompt.' -ForegroundColor DarkGray
    exit 0
}

if ($script:Actions.Count -gt 0 -and -not $Yes) {
    Write-Host ''
    $answer = Read-Host 'Apply this plan? [y/N]'
    if ($answer -ne 'y' -and $answer -ne 'Y') {
        Write-Host 'Aborted. Nothing was changed.' -ForegroundColor Yellow
        exit 2
    }
}

# --- Apply ------------------------------------------------------------------

Write-Section 'Applying'

$applied = 0
foreach ($a in $script:Actions) {
    Write-Host "  -> $($a.description)"
    try {
        & $a.do
        $applied++
    } catch {
        Write-Fail "$($a.description): $_"
        $script:Failures += "$($a.description): $_"
    }
}

Write-Host ''
Write-Host "Applied $applied of $($script:Actions.Count) action(s)." -ForegroundColor Cyan

# --- Verify -----------------------------------------------------------------

Write-Section 'Verifying'
Write-Host '  Re-running doctor.ps1 for an independent check.' -ForegroundColor DarkGray
Write-Host ''

& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'doctor.ps1') -RepoRoot $RepoRoot
$doctorExit = $LASTEXITCODE

if ($needsShellRestart) {
    Write-Host 'A tool was installed and PATH was changed.' -ForegroundColor Yellow
    Write-Host 'This shell cannot see the new PATH. Open a new terminal before using the hooks.' -ForegroundColor Yellow
    Write-Host 'If doctor.ps1 above still reports a tool missing, that is why - re-run it in a new terminal.' -ForegroundColor DarkGray
    Write-Host ''
}

if ($script:Failures.Count -gt 0) {
    Write-Host 'Finished with problems:' -ForegroundColor Red
    foreach ($f in $script:Failures) { Write-Host "  - $f" }
    exit 2
}

exit 0
