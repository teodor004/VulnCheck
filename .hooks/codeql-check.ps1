# codeql-check.ps1 - pre-push CodeQL scan, scoped to the files this push changes.
#
# TEMPLATE: the installer copies this verbatim into <repo>\.hooks\. There is no
# placeholder substitution, so it must work as-is.
#
# Deliberately standalone - it does NOT dot-source setup\lib\*.ps1, because only
# .hooks\ is copied into a target repo. The handful of things it needs from
# lib\detect.ps1 are duplicated below.
#
# Targets Windows PowerShell 5.1: no ternary operator, no ?? operator, no
# ForEach-Object -Parallel. No Set-StrictMode either - strictness only adds new
# ways for a git hook to die on an unset property, and a dead hook is worse than
# a noisy one.
#
# EXIT CODE CONTRACT
#   0 - nothing to do, no findings, everything skipped, or advisory (non-blocking) mode.
#   1 - a REAL SECURITY FINDING in a file this push changes. Only ever this.
#   2 - a TOOL / INFRASTRUCTURE error. CodeQL missing, database build broken,
#       query suite unresolvable, SARIF unparseable.
#
# pre-commit treats ANY nonzero exit as a hook failure, so exit 2 blocks the push
# just like exit 1 does. That is intentional - we fail closed. The point of the
# separate code is that the OUTPUT tells the developer which kind of problem they
# have, so a broken toolchain is never mistaken for a vulnerability in their code.

# Cmdlet errors should be loud. Native commands (git, codeql) are invoked only
# through the two helpers below, which drop this back to Continue - CodeQL and
# git both write banners and warnings to stderr, and under Stop PowerShell
# promotes native stderr into a terminating error. That trap killed real runs.
$ErrorActionPreference = 'Stop'

$EXIT_PASS             = 0
$EXIT_SECURITY_FINDING = 1
$EXIT_TOOL_ERROR       = 2

# ---------------------------------------------------------------------------
# Native command helpers
# ---------------------------------------------------------------------------

function Invoke-NativeCapture {
    <#
    .SYNOPSIS
    Runs a native command, returning its combined output and exit code.

    .DESCRIPTION
    stderr is folded into stdout because the tools here put useful information
    there. $ErrorActionPreference is forced to Continue for the duration so a
    stderr banner cannot become a terminating error.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @()
    )

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $code = -1
    $out  = @()
    try {
        $out  = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } catch {
        $out  = @("$($_.Exception.Message)")
        $code = -1
    } finally {
        $ErrorActionPreference = $prev
    }

    # @() wrap: a single output line comes back as a bare string, which has no
    # .Count and would break every caller that asks for one.
    return [pscustomobject][ordered]@{ Output = @($out); ExitCode = $code }
}

function Invoke-NativeStreamed {
    <#
    .SYNOPSIS
    Runs a native command, echoing its output live, and returns the exit code.

    .DESCRIPTION
    Used for `codeql database create` / `analyze`, which take minutes and whose
    progress output is the only sign the hook has not hung. Output is piped
    through Write-Host rather than left to stream natively so that stderr lines
    render as plain text instead of red PowerShell error records - benign CodeQL
    warnings printed in red look exactly like a failure.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @()
    )

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $code = -1
    try {
        & $Exe @Arguments 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
        $code = $LASTEXITCODE
    } catch {
        Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkGray
        $code = -1
    } finally {
        $ErrorActionPreference = $prev
    }
    return $code
}

# ---------------------------------------------------------------------------
# Profile manifest
# ---------------------------------------------------------------------------

function Get-SecurityConfig {
    <#
    .SYNOPSIS
    Reads .hooks\security-profile.json, falling back to safe defaults.

    .DESCRIPTION
    The manifest is written by the installer and records what setup/doctor.ps1
    found: which query suite to use, whether each check blocks, and per-language
    analysis status. A missing or corrupt manifest must never kill the hook - the
    hook still has a job to do - so every field has a default and the only
    consequence is a warning.

    Defaults are deliberately the conservative choice: blocking for both checks.
    A repo with no manifest gets the strict behaviour, not the lax one.
    #>
    param([string]$Path)

    $cfg = [pscustomobject][ordered]@{
        querySuite      = 'code-scanning'
        blockCodeql     = $true
        blockClaude     = $true
        maxBudgetUsd    = 1.00
        maxTurns        = 5
        allowedTools    = 'Read'
        languageStatus  = @{}
        languageReasons = @{}
        loaded          = $false
        warning         = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        $cfg.warning = 'No .hooks\security-profile.json found.'
        return $cfg
    }

    $json = $null
    try {
        $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $cfg.warning = "Could not parse .hooks\security-profile.json ($($_.Exception.Message))."
        return $cfg
    }
    if ($null -eq $json) {
        $cfg.warning = '.hooks\security-profile.json is empty.'
        return $cfg
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$json.querySuite)) {
        $cfg.querySuite = ([string]$json.querySuite).Trim()
    }

    # Explicit property test rather than a truthiness check: $false and "absent"
    # are different answers, and $json.blocking.codeql being $false must be
    # honoured rather than treated as unset.
    if ($null -ne $json.blocking) {
        $names = @($json.blocking.PSObject.Properties.Name)
        if ($names -contains 'codeql') { $cfg.blockCodeql = [bool]$json.blocking.codeql }
        if ($names -contains 'claude') { $cfg.blockClaude = [bool]$json.blocking.claude }
    }

    if ($null -ne $json.claude) {
        $names = @($json.claude.PSObject.Properties.Name)
        if ($names -contains 'maxBudgetUsd' -and $null -ne $json.claude.maxBudgetUsd) {
            $cfg.maxBudgetUsd = [double]$json.claude.maxBudgetUsd
        }
        if ($names -contains 'maxTurns' -and $null -ne $json.claude.maxTurns) {
            $cfg.maxTurns = [int]$json.claude.maxTurns
        }
        if ($names -contains 'allowedTools' -and -not [string]::IsNullOrWhiteSpace([string]$json.claude.allowedTools)) {
            $cfg.allowedTools = ([string]$json.claude.allowedTools).Trim()
        }
    }

    foreach ($entry in @($json.languages)) {
        if ($null -eq $entry) { continue }
        $name = [string]$entry.language
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $name = $name.Trim().ToLowerInvariant()

        $status = 'UNKNOWN'
        if (-not [string]::IsNullOrWhiteSpace([string]$entry.status)) {
            $status = ([string]$entry.status).Trim().ToUpperInvariant()
        }
        $cfg.languageStatus[$name] = $status

        $reasons = @()
        foreach ($r in @($entry.reasons)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$r)) { $reasons += ([string]$r).Trim() }
        }
        $cfg.languageReasons[$name] = @($reasons)
    }

    $cfg.loaded = $true
    return $cfg
}

function Write-MissingProfileWarning {
    param($Config)
    if ($Config.loaded) { return }
    Write-Host ''
    Write-Host '--------------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host "PROFILE MISSING: $($Config.warning)" -ForegroundColor Yellow
    Write-Host 'Falling back to safe defaults: query suite code-scanning, blocking mode on.' -ForegroundColor Yellow
    Write-Host 'Nothing is known about which languages here analyse cleanly, so the' -ForegroundColor Yellow
    Write-Host 'degradation warnings below may be incomplete. Run:' -ForegroundColor Yellow
    Write-Host '    powershell -ExecutionPolicy Bypass -File setup\doctor.ps1' -ForegroundColor Yellow
    Write-Host '--------------------------------------------------------------------' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Degradation banner
# ---------------------------------------------------------------------------

function Write-DegradationBanner {
    <#
    .SYNOPSIS
    Loud warning that some language is being analysed with reduced visibility.

    .DESCRIPTION
    The single most important output this hook produces. The POC ran for its
    entire duration with no JDK installed; CodeQL said so, once, in the middle of
    several hundred lines of progress output, and it went unnoticed - which made
    every recall figure in the findings document a floor rather than an estimate.

    Printed BEFORE analysis (so it is on screen while the developer waits) and
    again AFTER the findings (so it is the last thing they read before deciding
    the code is fine). It must never be possible to see a green pass from this
    hook without also seeing this.

    Returns $true if anything was printed.
    #>
    param(
        $Config,
        [string[]]$Languages,
        [string]$When
    )

    $degraded = @()
    foreach ($lang in @($Languages)) {
        if ($Config.languageStatus.ContainsKey($lang) -and $Config.languageStatus[$lang] -eq 'DEGRADED') {
            $degraded += $lang
        }
    }
    if (@($degraded).Count -eq 0) { return $false }

    Write-Host ''
    Write-Host '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' -ForegroundColor Yellow
    Write-Host '!!  DEGRADED ANALYSIS - RESULTS ARE A FLOOR, NOT A CLEAN BILL OF   !!' -ForegroundColor Yellow
    Write-Host '!!  HEALTH. A PASS DOES NOT MEAN THIS CODE IS CLEAN.               !!' -ForegroundColor Yellow
    Write-Host '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' -ForegroundColor Yellow
    Write-Host "Degraded language(s): $(@($degraded) -join ', ')" -ForegroundColor Yellow
    foreach ($lang in @($degraded)) {
        $reasons = @()
        if ($Config.languageReasons.ContainsKey($lang)) { $reasons = @($Config.languageReasons[$lang]) }
        if (@($reasons).Count -eq 0) {
            Write-Host "  [$lang] Marked DEGRADED by setup/doctor.ps1; no reason recorded." -ForegroundColor Yellow
        } else {
            foreach ($r in $reasons) { Write-Host "  [$lang] $r" -ForegroundColor Yellow }
        }
    }
    Write-Host 'Whatever CodeQL reports below is the MINIMUM that is wrong, not the total.' -ForegroundColor Yellow
    Write-Host 'Fix the toolchain gaps above (setup\doctor.ps1 lists the exact commands)' -ForegroundColor Yellow
    Write-Host 'before treating a pass from this hook as evidence of anything.' -ForegroundColor Yellow
    if ($When) { Write-Host "($When)" -ForegroundColor DarkGray }
    Write-Host ''
    return $true
}

function Write-ToolError {
    <#
    .SYNOPSIS
    Reports an infrastructure failure in a way no-one can mistake for a finding.

    .DESCRIPTION
    POC rollout prerequisite #5. Previously a database-creation failure, an
    unresolvable query suite and a real SQL injection all produced red text and
    exit 1, so a developer could not tell whether their code was broken or their
    laptop was. Magenta plus an explicit TOOL ERROR prefix, kept visually
    distinct from the red used for genuine findings.
    #>
    param(
        [string]$Summary,
        [string[]]$Detail = @(),
        [string]$WhatToDo = ''
    )

    Write-Host ''
    Write-Host '====================================================================' -ForegroundColor Magenta
    Write-Host "TOOL ERROR: $Summary" -ForegroundColor Magenta
    Write-Host 'This is a TOOLING problem, not a security finding. Your code has not' -ForegroundColor Magenta
    Write-Host 'been judged - the scanner never got far enough to judge it.' -ForegroundColor Magenta
    if (@($Detail).Count -gt 0) {
        Write-Host '--------------------------------------------------------------------' -ForegroundColor Magenta
        foreach ($line in @($Detail)) { Write-Host "  $line" -ForegroundColor DarkGray }
    }
    if ($WhatToDo) {
        Write-Host '--------------------------------------------------------------------' -ForegroundColor Magenta
        Write-Host "What to do: $WhatToDo" -ForegroundColor Magenta
    }
    Write-Host '====================================================================' -ForegroundColor Magenta
}

function Resolve-FinalExitCode {
    <#
    .SYNOPSIS
    Applies advisory (non-blocking) mode to an intended exit code.

    .DESCRIPTION
    Non-blocking means "report everything, block nothing". Tool errors are
    downgraded too: a broken tool must not block a push that was explicitly
    configured not to be blocked by that tool.
    #>
    param([int]$Intended, [bool]$Blocking)

    if ($Intended -eq 0) { return 0 }
    if ($Blocking) { return $Intended }

    Write-Host ''
    Write-Host '********************************************************************' -ForegroundColor Cyan
    Write-Host '*  ADVISORY MODE: findings above were reported but NOT enforced.   *' -ForegroundColor Cyan
    Write-Host '*  CodeQL is configured non-blocking in .hooks\security-profile.json *' -ForegroundColor Cyan
    Write-Host '*  THE PUSH WAS ALLOWED. Nothing here has been fixed for you.       *' -ForegroundColor Cyan
    Write-Host '********************************************************************' -ForegroundColor Cyan
    return 0
}

# ---------------------------------------------------------------------------
# CodeQL capability probing (duplicated from setup\lib\detect.ps1 on purpose)
# ---------------------------------------------------------------------------

# PowerShell 5.1 has no $IsMacOS automatic variable, so derive it once.
$IsMacOSCompat = $false
if (Test-Path Variable:\IsMacOS) { $IsMacOSCompat = $IsMacOS }

function Get-CodeQLHome {
    # Directory containing codeql.exe, or $null when CodeQL is not on PATH. The
    # extractor manifests live alongside it, so this is also how we find them.
    $cmd = Get-Command 'codeql' -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandType -ne 'Alias' } |
        Select-Object -First 1
    if (-not $cmd -or -not $cmd.Path) { return $null }
    return (Split-Path -Parent $cmd.Path)
}

function Get-ExtractorBuildModes {
    <#
    .SYNOPSIS
    Build modes an extractor declares, read from its own manifest.

    .DESCRIPTION
    Read from <codeql-home>\<language>\codeql-extractor.yml rather than
    hardcoded, because the CLI's own --help text is demonstrably stale: it omits
    build-mode=none for C/C++ even though the extractor supports it. The manifest
    is what the CLI actually validates against, so it is the only honest source.

    Deliberately a line-based reader, not a YAML parser: the block is a flat
    sequence of scalars and PowerShell 5.1 ships no YAML support.

    Observed on CodeQL 2.26.1:
      java / cpp / csharp                              -> autobuild, manual, none
      python / javascript / ruby / rust / actions       -> none
      go / swift                                       -> autobuild, manual  (no none)

    Returns @() when the manifest is missing or declares no build_modes.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Language,
        [string]$CodeQLHome
    )

    if (-not $CodeQLHome) { $CodeQLHome = Get-CodeQLHome }
    if (-not $CodeQLHome) { return @() }

    # [IO.Path]::Combine, not Join-Path: Join-Path resolves the drive and throws
    # DriveNotFoundException when part of the path does not exist.
    $manifest = [System.IO.Path]::Combine($CodeQLHome, $Language, 'codeql-extractor.yml')
    if (-not (Test-Path -LiteralPath $manifest)) { return @() }

    $modes   = @()
    $inBlock = $false
    foreach ($line in (Get-Content -LiteralPath $manifest -ErrorAction SilentlyContinue)) {
        if ($line -match '^\s*build_modes\s*:\s*$') { $inBlock = $true; continue }
        if ($inBlock) {
            if ($line -match '^\s*-\s*(\S+)\s*$') {
                $modes += $Matches[1].ToLowerInvariant()
            } else {
                # First non-list line ends the block.
                break
            }
        }
    }
    return @($modes)
}

function Test-LanguageAnalysable {
    <#
    .SYNOPSIS
    Can this language be analysed by a BUILDLESS pre-push hook on this machine?

    .DESCRIPTION
    The deployed version of this hook mapped .swift and .go to extractors and
    then ran `database create --build-mode=none` unconditionally. Both hard fail,
    and the failure was reported with exit 1 and red text - indistinguishable
    from a security finding, and it blocked the push.

    Two independent gates:
      1. Platform. Swift ships a win64 extractor.exe that immediately exits with
         "[incompatible-os] Currently, Swift analysis is only supported on
         macOS." Its query pack still resolves, so suite resolvability is NOT
         evidence a language can be analysed.
      2. Declared build modes. No 'none' means the extractor needs a real build,
         which a pre-push hook has no business performing.

    Returns @{ analysable; kind; reason; buildModes }. kind is OK, SKIP_PLATFORM,
    SKIP_NEEDS_BUILD or TOOL_ERROR.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Language,
        [string]$CodeQLHome
    )

    $out = [pscustomobject][ordered]@{
        analysable = $true
        kind       = 'OK'
        reason     = $null
        buildModes = @()
    }

    if ($Language -eq 'swift' -and -not $IsMacOSCompat) {
        $out.analysable = $false
        $out.kind       = 'SKIP_PLATFORM'
        $out.reason     = 'The Swift extractor only runs on macOS. On Windows its win64 extractor.exe exits immediately with an [incompatible-os] error, regardless of build mode.'
        return $out
    }

    $modes = @(Get-ExtractorBuildModes -Language $Language -CodeQLHome $CodeQLHome)
    $out.buildModes = $modes

    if (@($modes).Count -eq 0) {
        # Never claim capability we have not verified. A missing manifest means a
        # broken or unexpected CodeQL layout, which is a tooling problem.
        $out.analysable = $false
        $out.kind       = 'TOOL_ERROR'
        $out.reason     = "Could not read the $Language extractor manifest (codeql-extractor.yml), so buildless support is unverified."
        return $out
    }

    if ($modes -notcontains 'none') {
        $out.analysable = $false
        $out.kind       = 'SKIP_NEEDS_BUILD'
        $out.reason     = "The $Language extractor declares only [$(@($modes) -join ', ')] - it does not support build-mode=none, so it requires a real compile. A buildless pre-push hook cannot analyse it."
        return $out
    }

    return $out
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$hooksDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($hooksDir)) { $hooksDir = '.hooks' }
$cfg = Get-SecurityConfig -Path ([System.IO.Path]::Combine($hooksDir, 'security-profile.json'))

# Scope to what this push actually changes. Showing a developer pre-existing
# issues they did not cause is the fastest way to get a hook disabled.
$mb = Invoke-NativeCapture -Exe 'git' -Arguments @('merge-base', '@{u}', 'HEAD')
$mergeBase = ''
if ($mb.ExitCode -eq 0) { $mergeBase = (@($mb.Output) -join "`n").Trim() }
if ([string]::IsNullOrWhiteSpace($mergeBase)) {
    # The first push of a brand-new repo has no upstream AND no parent commit.
    # Diffing against a missing HEAD~1 fails, and because stderr is folded into
    # the output, the git error text would then be parsed as file names. Diff
    # against the empty tree instead, so a first push analyses every file it adds.
    $parent = Invoke-NativeCapture -Exe 'git' -Arguments @('rev-parse', '--verify', '--quiet', 'HEAD~1^{commit}')
    if ($parent.ExitCode -eq 0) {
        Write-Host 'No upstream ref found; comparing against HEAD~1 instead.' -ForegroundColor Yellow
        $mergeBase = 'HEAD~1'
    } else {
        Write-Host 'No upstream ref and no parent commit (first push); comparing against the empty tree.' -ForegroundColor Yellow
        $mergeBase = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
    }
}

$diffCall = Invoke-NativeCapture -Exe 'git' -Arguments @('diff', '--name-only', '--diff-filter=ACMR', "$mergeBase", 'HEAD')
if ($diffCall.ExitCode -ne 0) {
    Write-ToolError -Summary 'git diff failed, so the files changed by this push could not be determined.' `
        -Detail @($diffCall.Output) `
        -WhatToDo 'Run the same command by hand to see why: git diff --name-only <upstream> HEAD'
    exit (Resolve-FinalExitCode -Intended $EXIT_TOOL_ERROR -Blocking $cfg.blockCodeql)
}
$changedFiles = @(@($diffCall.Output) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -ne '' })
if (@($changedFiles).Count -eq 0) {
    Write-Host 'No changed files to analyze.' -ForegroundColor Yellow
    exit $EXIT_PASS
}

# Maps file extensions to CodeQL extractor names. Kept in sync with
# Get-ExtensionLanguageMap in setup\lib\detect.ps1; duplicated because a hook
# cannot dot-source lib\.
$extensionToLanguage = @{
    '.java'  = 'java'
    '.kt'    = 'java'
    '.py'    = 'python'
    '.js'    = 'javascript'
    '.jsx'   = 'javascript'
    '.mjs'   = 'javascript'
    '.cjs'   = 'javascript'
    '.ts'    = 'javascript'
    '.tsx'   = 'javascript'
    '.vue'   = 'javascript'
    '.go'    = 'go'
    '.rb'    = 'ruby'
    '.erb'   = 'ruby'
    '.cs'    = 'csharp'
    '.c'     = 'cpp'
    '.cc'    = 'cpp'
    '.cpp'   = 'cpp'
    '.cxx'   = 'cpp'
    '.h'     = 'cpp'
    '.hpp'   = 'cpp'
    '.swift' = 'swift'
    '.rs'    = 'rust'
}

$languages = @($changedFiles |
    ForEach-Object { [System.IO.Path]::GetExtension($_).ToLowerInvariant() } |
    Where-Object { $extensionToLanguage.ContainsKey($_) } |
    ForEach-Object { $extensionToLanguage[$_] } |
    Sort-Object -Unique)

if (@($languages).Count -eq 0) {
    Write-Host 'No changed files map to a supported CodeQL language. Skipping.' -ForegroundColor Yellow
    exit $EXIT_PASS
}

Write-Host "Changed files map to language(s): $(@($languages) -join ', ')" -ForegroundColor Cyan
Write-MissingProfileWarning -Config $cfg

$codeqlHome = Get-CodeQLHome
if (-not $codeqlHome) {
    Write-ToolError -Summary 'CodeQL is not on PATH, so no analysis ran at all.' `
        -Detail @("The command 'codeql' could not be resolved to an executable.") `
        -WhatToDo 'Run setup\doctor.ps1, then setup\install.ps1. CodeQL must be the BUNDLE from github/codeql-action, not codeql-cli-binaries.'
    exit (Resolve-FinalExitCode -Intended $EXIT_TOOL_ERROR -Blocking $cfg.blockCodeql)
}

# Overridable so tests and non-standard machines are not forced onto C:\tools.
$dbRoot = $env:SECURITY_DB_ROOT
if ([string]::IsNullOrWhiteSpace($dbRoot)) { $dbRoot = 'C:\tools' }

# --- Gate each language BEFORE spending ~171s on a database build -----------

$analysable = @()
$skips      = @()
$toolErrors = @()

foreach ($language in $languages) {
    $verdict = Test-LanguageAnalysable -Language $language -CodeQLHome $codeqlHome
    if ($verdict.analysable) {
        $analysable += $language
        continue
    }
    if ($verdict.kind -eq 'TOOL_ERROR') {
        $toolErrors += "[$language] $($verdict.reason)"
    } else {
        $skips += [pscustomobject][ordered]@{ language = $language; kind = $verdict.kind; reason = $verdict.reason }
    }
}

# Loud, clearly-labelled skips. A SKIP is not a failure and must not block the
# push - the old behaviour turned "go needs a build" into what looked like a
# vulnerability report.
foreach ($s in @($skips)) {
    Write-Host ''
    Write-Host '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' -ForegroundColor Yellow
    Write-Host ">>  SKIPPED (NOT ANALYSED, NOT A FAILURE): $($s.language)" -ForegroundColor Yellow
    Write-Host ">>  $($s.reason)" -ForegroundColor Yellow
    Write-Host ">>  Your $($s.language) changes in this push received NO static analysis." -ForegroundColor Yellow
    Write-Host '>>  The push is not blocked for this. Review those files by hand or in CI.' -ForegroundColor Yellow
    Write-Host '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' -ForegroundColor Yellow
}

if (@($analysable).Count -eq 0 -and @($toolErrors).Count -eq 0) {
    Write-Host ''
    Write-Host 'No changed language can be analysed buildlessly. Nothing to scan.' -ForegroundColor Yellow
    exit $EXIT_PASS
}

# --- Degradation banner, before the wait ------------------------------------

$bannerShown = Write-DegradationBanner -Config $cfg -Languages $analysable -When 'shown before analysis'

# --- Analyse ----------------------------------------------------------------

# HashSet for O(1) membership: SARIF for a whole repo can carry thousands of
# results and only the ones touching this push are the developer's problem.
$changedFilesSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$changedFiles)
$allFindings = @()
$analysed    = @()

foreach ($language in $analysable) {
    $db    = [System.IO.Path]::Combine($dbRoot, "vulndb-$language")
    $sarif = [System.IO.Path]::Combine($dbRoot, "results-$language.sarif")

    # code-scanning by default, not security-and-quality: the POC found 59.7% of
    # security-and-quality findings were code hygiene rather than security
    # (java: 244 queries vs 80). The suite is configurable so a team can opt
    # back into the wider net.
    $suiteName = "$language-$($cfg.querySuite).qls"

    # Verify the suite resolves BEFORE building a database. Failure here is the
    # signature of someone having installed the bare codeql-cli-binaries instead
    # of the bundle: extractors present, query packs absent. That is a tooling
    # problem and must not be reported as a security failure.
    $resolve = Invoke-NativeCapture -Exe 'codeql' -Arguments @('resolve', 'queries', $suiteName)
    if ($resolve.ExitCode -ne 0) {
        $toolErrors += "[$language] Query suite '$suiteName' does not resolve. $(@($resolve.Output) -join ' ' )"
        continue
    }
    $queryCount = @(@($resolve.Output) | Where-Object { "$_" -match '\.ql$' }).Count
    Write-Host ''
    Write-Host "== CodeQL ($language): suite $suiteName resolved, $queryCount queries ==" -ForegroundColor Cyan

    Write-Host "== CodeQL ($language): building database (this is the slow part) ==" -ForegroundColor Cyan
    $code = Invoke-NativeStreamed -Exe 'codeql' -Arguments @(
        'database', 'create', $db, "--language=$language", '--source-root=.', '--build-mode=none', '--overwrite'
    )
    if ($code -ne 0) {
        $toolErrors += "[$language] 'codeql database create' exited $code. The database was never built, so nothing was analysed."
        continue
    }

    Write-Host "== CodeQL ($language): analyzing ==" -ForegroundColor Cyan
    $code = Invoke-NativeStreamed -Exe 'codeql' -Arguments @(
        'database', 'analyze', $db, '--format=sarif-latest', "--output=$sarif", $suiteName
    )
    if ($code -ne 0) {
        $toolErrors += "[$language] 'codeql database analyze' exited $code. No usable results were produced."
        continue
    }

    $results = @()
    try {
        $sarifJson = Get-Content -LiteralPath $sarif -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $results = @($sarifJson.runs[0].results)
    } catch {
        # Unparseable SARIF is a broken tool, NOT a clean scan and NOT a finding.
        $toolErrors += "[$language] Could not parse the SARIF output at $sarif ($($_.Exception.Message))."
        continue
    }

    $analysed += $language

    $scoped = @($results | Where-Object {
        $uri = $_.locations[0].physicalLocation.artifactLocation.uri
        $null -ne $uri -and $changedFilesSet.Contains([string]$uri)
    })
    if (@($scoped).Count -gt 0) { $allFindings += $scoped }
}

# --- Report -----------------------------------------------------------------

$intended = $EXIT_PASS

if (@($allFindings).Count -gt 0) {
    Write-Host ''
    Write-Host "SECURITY FINDINGS: CodeQL found $(@($allFindings).Count) issue(s) in files this push changes:" -ForegroundColor Red
    $allFindings |
        Select-Object ruleId,
            @{ n = 'file'; e = { $_.locations[0].physicalLocation.artifactLocation.uri } },
            @{ n = 'line'; e = { $_.locations[0].physicalLocation.region.startLine } } |
        Format-Table -AutoSize
    $intended = $EXIT_SECURITY_FINDING
} elseif (@($analysed).Count -gt 0) {
    Write-Host ''
    Write-Host "CodeQL: no issues found in changed files ($(@($analysed) -join ', '))." -ForegroundColor Green
}

if (@($toolErrors).Count -gt 0) {
    Write-ToolError -Summary "CodeQL could not complete for $(@($toolErrors).Count) language(s)." `
        -Detail @($toolErrors) `
        -WhatToDo 'Run setup\doctor.ps1. If the query suite failed to resolve, you likely have codeql-cli-binaries instead of the codeql-action BUNDLE, which ships no query packs.'
    # A genuine finding outranks a tool error for the exit code, because exit 1
    # is reserved for "there is something wrong with your code" and that is now
    # known to be true. Both blocks are printed either way.
    if ($intended -ne $EXIT_SECURITY_FINDING) { $intended = $EXIT_TOOL_ERROR }
}

# Repeat the banner AFTER the findings so it is the last thing read. A green
# "no issues found" line with a degraded extractor above it is exactly how the
# POC talked itself into trusting a floor.
if ($bannerShown) {
    $null = Write-DegradationBanner -Config $cfg -Languages $analysed -When 'repeated after findings - re-read this before trusting the result above'
}

exit (Resolve-FinalExitCode -Intended $intended -Blocking $cfg.blockCodeql)
