# osv-check.ps1 - pre-push dependency vulnerability scan via osv-scanner.
#
# TEMPLATE: the installer copies this verbatim into <repo>\.hooks\. There is no
# placeholder substitution, so it must work as-is.
#
# Deliberately standalone - it does NOT dot-source setup\lib\*.ps1, because only
# .hooks\ is copied into a target repo. The handful of things it needs from
# lib\detect.ps1 are duplicated below, same as codeql-check.ps1.
#
# Targets Windows PowerShell 5.1: no ternary operator, no ?? operator, no
# ForEach-Object -Parallel. No Set-StrictMode either - strictness only adds new
# ways for a git hook to die on an unset property, and a dead hook is worse than
# a noisy one.
#
# ASCII ONLY. No em-dashes, no curly quotes, no box-drawing characters. A hook
# that is saved in the wrong encoding dies at parse time, and a hook that dies at
# parse time is a hook nobody is running.
#
# NOT SCOPED TO THE DIFF, unlike codeql-check.ps1. osv-scanner reads
# manifest/lockfiles and resolves them against the OSV database; a vulnerable
# transitive dependency is a property of the whole tree, not of the lines this
# push happens to touch. Scoping to changed files would report nothing for the
# common case where the dangerous package arrived via a dependency of a
# dependency.
#
# .gitignore IS honoured (osv-scanner's default). That is correct for a pre-push
# hook: gitignored files are not being pushed, so a vulnerability in a local
# build output is not this hook's business. Do NOT add --no-ignore.
#
# --allow-no-lockfiles is deliberately NOT passed. That flag makes osv-scanner
# report success when it found nothing to scan, which is precisely the outcome
# this hook has to keep distinguishable from a clean result.
#
#
# WHY THERE ARE TWO SCANS
# ----------------------
# osv-scanner matches RESOLVED package versions against the OSV database. It
# reads lockfiles, not build scripts. For npm, PyPI, Go and friends the lockfile
# in the repo already states resolved versions, so a plain recursive scan is
# complete.
#
# Maven is the exception that matters here. A pom.xml states direct dependencies,
# often with versions that live in a parent POM, in dependencyManagement, or
# behind a property. osv-scanner cannot resolve those on its own; upstream it
# leans on the deps.dev network service to do it, which this hook must not use
# (see the --offline note below). The result is that a pom.xml alone gives either
# nothing or only the direct dependencies - and most real vulnerabilities arrive
# transitively.
#
# The fix is to let Maven do the resolution, since Maven is the only thing that
# genuinely knows how to. cyclonedx-maven-plugin walks the fully resolved graph
# and writes a CycloneDX SBOM, which osv-scanner reads as a first-class lockfile.
# Verified 2026-08-17: a CycloneDX bom.json containing log4j-core 2.14.1 and
# jackson-databind 2.9.8, scanned with --offline against a primed Maven database,
# returned 62 vulnerability groups and exit 1. No network, full transitive depth.
#
# So: scan 1 is the SBOM (Maven only, when Maven is available), scan 2 is the
# native recursive scan for every other ecosystem. Their results are combined.
#
#
# --offline IS passed. Verified 2026-08-17: without it, a plain `osv-scanner
# scan source` makes a live call to osv.dev for every push (and to deps.dev,
# for ecosystems it resolves transitively), which is an undeclared network
# dependency this tool must not have. The cost is that the local vulnerability
# database has to be primed once via `--download-offline-databases` before
# this hook can find anything - see setup/install.ps1.
#
# The offline database is PER ECOSYSTEM, which is the trap. Verified 2026-08-17:
# a cache primed against an npm-only repo contains only npm\all.zip. Point that
# same cache at a Maven SBOM and osv-scanner prints "could not load db for Maven
# ecosystem", exits 127, and writes {"results": []} - a file that is byte-for-byte
# indistinguishable from a clean scan. Exit code 127 therefore has its own branch
# below, and it means one of two things: the cache was never primed at all, or it
# was primed without the ecosystem this repo actually uses.
#
#
# EXIT CODE CONTRACT
#   0 - packages were scanned and no vulnerabilities were found, or nothing
#       scannable exists in this repo (reported loudly, see below), or advisory
#       (non-blocking) mode.
#   1 - a REAL SECURITY FINDING: at least one dependency has a known
#       vulnerability. Only ever this.
#   2 - a TOOL / INFRASTRUCTURE error. osv-scanner missing, an offline database
#       that cannot answer for an ecosystem actually present, unreadable or
#       unparseable output, an exit code this script does not recognise, or an
#       exit code that disagrees with the output it came with.
#
# NOTE ON 127: osv-scanner's own exit 127 is folded into OUR exit 2, not our
# exit 1. It is an "I could not judge your dependencies" outcome, not a finding.
# Reporting a broken database as a vulnerability would teach developers that the
# red banner is noise, which is how a real finding gets ignored later.
#
# pre-commit treats ANY nonzero exit as a hook failure, so exit 2 blocks the push
# just like exit 1 does. That is intentional - we fail closed. The point of the
# separate code is that the OUTPUT tells the developer which kind of problem they
# have, so a broken toolchain is never mistaken for a vulnerable dependency.

$ErrorActionPreference = 'Stop'

$EXIT_PASS             = 0
$EXIT_SECURITY_FINDING = 1
$EXIT_TOOL_ERROR       = 2

# osv-scanner's own documented exit codes. Anything not listed here is treated
# as an unknown outcome and fails closed rather than being guessed at.
$OSV_CLEAN              = 0
$OSV_VULNS_FOUND        = 1
$OSV_OFFLINE_DB_MISSING = 127
$OSV_NO_PACKAGES        = 128

# ---------------------------------------------------------------------------
# Native command helpers
# ---------------------------------------------------------------------------

function Invoke-NativeCapture {
    <#
    .SYNOPSIS
    Runs a native command, returning its combined output and exit code.

    .DESCRIPTION
    stderr is folded into stdout because the tools here put useful information
    there - osv-scanner writes its filesystem-walk progress, its "No package
    sources found" message and its "could not load db" message to stderr.
    $ErrorActionPreference is forced to Continue for the duration so a stderr
    banner cannot become a terminating error.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory
    )

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $code = -1
    $out  = @()

    $pushed = $false
    try {
        if ($WorkingDirectory -and (Test-Path -LiteralPath $WorkingDirectory)) {
            Push-Location -LiteralPath $WorkingDirectory
            $pushed = $true
        }
        $out  = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } catch {
        $out  = @("$($_.Exception.Message)")
        $code = -1
    } finally {
        if ($pushed) { Pop-Location }
        $ErrorActionPreference = $prev
    }

    # @() wrap: a single output line comes back as a bare string, which has no
    # .Count and would break every caller that asks for one.
    return [pscustomobject][ordered]@{ Output = @($out); ExitCode = $code }
}

function Get-ExecutablePath {
    <#
    .SYNOPSIS
    Full path to a native executable, or $null when it is not resolvable.

    .DESCRIPTION
    Aliases are filtered out for the same reason codeql-check.ps1 filters them: a
    PowerShell alias named after the tool would satisfy Get-Command without there
    being an executable anywhere, and the hook would then fail much later with a
    far less obvious message.

    Resolving a tool BEFORE running it is the whole point. A missing scanner
    produces an empty result set, and an empty result set is indistinguishable
    from "no vulnerabilities" unless somebody checks first.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandType -ne 'Alias' } |
        Select-Object -First 1
    if (-not $cmd -or -not $cmd.Path) { return $null }
    return $cmd.Path
}

# ---------------------------------------------------------------------------
# Profile manifest
# ---------------------------------------------------------------------------

function Get-SecurityConfig {
    <#
    .SYNOPSIS
    Reads .hooks\security-profile.json, falling back to safe defaults.

    .DESCRIPTION
    Only the fields this hook needs are read. A missing or corrupt manifest must
    never kill the hook - the hook still has a job to do - so every field has a
    default and the only consequence is a warning.

    The defaults are deliberately the conservative choice: blocking on, SBOM
    generation on. A repo with no manifest gets the strict, high-coverage
    behaviour, not the lax one.
    #>
    param([string]$Path)

    $cfg = [pscustomobject][ordered]@{
        blockOsv                  = $true
        generateMvnSbom           = $true
        generateGradleSbom        = $true
        gradleSbomFailureIsError  = $false
        loaded                    = $false
        warning                   = $null
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

    # Explicit property test rather than a truthiness check: $false and "absent"
    # are different answers, and blocking.osv being $false must be honoured
    # rather than treated as unset.
    if ($null -ne $json.blocking) {
        $names = @($json.blocking.PSObject.Properties.Name)
        if ($names -contains 'osv') { $cfg.blockOsv = [bool]$json.blocking.osv }
    }
    if ($null -ne $json.osv) {
        $names = @($json.osv.PSObject.Properties.Name)
        if ($names -contains 'generateMavenSbom')       { $cfg.generateMvnSbom          = [bool]$json.osv.generateMavenSbom }
        if ($names -contains 'generateGradleSbom')      { $cfg.generateGradleSbom       = [bool]$json.osv.generateGradleSbom }
        # Opt-in only. Defaults to false so that switching Gradle support on can
        # never turn a previously-passing push into a blocked one for an
        # environmental reason. See New-GradleSbom's failure-policy note.
        if ($names -contains 'gradleSbomFailureIsError') { $cfg.gradleSbomFailureIsError = [bool]$json.osv.gradleSbomFailureIsError }
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
    Write-Host 'Falling back to safe defaults: blocking mode on. Run:' -ForegroundColor Yellow
    Write-Host '    powershell -ExecutionPolicy Bypass -File setup\doctor.ps1' -ForegroundColor Yellow
    Write-Host '--------------------------------------------------------------------' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

function Write-ToolError {
    <#
    .SYNOPSIS
    Reports an infrastructure failure in a way no-one can mistake for a finding.

    .DESCRIPTION
    Magenta plus an explicit TOOL ERROR prefix, kept visually distinct from the
    red used for genuine findings. Same wording and colour as codeql-check.ps1 on
    purpose - a developer should learn this banner once.
    #>
    param(
        [string]$Summary,
        [string[]]$Detail = @(),
        [string]$WhatToDo = ''
    )

    Write-Host ''
    Write-Host '====================================================================' -ForegroundColor Magenta
    Write-Host "TOOL ERROR: $Summary" -ForegroundColor Magenta
    Write-Host 'This is a TOOLING problem, not a security finding. Your dependencies' -ForegroundColor Magenta
    Write-Host 'have not been judged - the scanner never got far enough to judge them.' -ForegroundColor Magenta
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

function Write-PartialCoverageWarning {
    <#
    .SYNOPSIS
    Warns that one ecosystem was skipped while others were still scanned.

    .DESCRIPTION
    Deliberately NOT a failure. A missing build tool means reduced depth, not a
    vulnerability, and blocking a push over it would get the hook uninstalled.
    But it must be loud, because "the scan passed" and "the scan passed on the
    half of your dependency tree it could see" are very different claims.
    #>
    param(
        [string]$Summary,
        [string[]]$Detail = @(),
        [string]$WhatToDo = ''
    )

    Write-Host ''
    Write-Host '####################################################################' -ForegroundColor Yellow
    Write-Host "PARTIAL COVERAGE: $Summary" -ForegroundColor Yellow
    Write-Host 'The push is NOT blocked for this. But a pass below covers only the' -ForegroundColor Yellow
    Write-Host 'dependencies that could actually be resolved, not all of them.' -ForegroundColor Yellow
    if (@($Detail).Count -gt 0) {
        Write-Host '--------------------------------------------------------------------' -ForegroundColor Yellow
        foreach ($line in @($Detail)) { Write-Host "  $line" -ForegroundColor DarkGray }
    }
    if ($WhatToDo) {
        Write-Host '--------------------------------------------------------------------' -ForegroundColor Yellow
        Write-Host "To get full coverage: $WhatToDo" -ForegroundColor Yellow
    }
    Write-Host '####################################################################' -ForegroundColor Yellow
}

function Write-NothingScannedBanner {
    <#
    .SYNOPSIS
    Loud notice that this repo contains nothing osv-scanner can read.

    .DESCRIPTION
    osv-scanner resolves LOCKFILES, not build scripts. A Gradle project with only
    build.gradle, or a Ruby project with only a Gemfile, presents it with zero
    package sources - it exits 128 and scans nothing.

    That is not a vulnerability and must not block the push, for the same reason
    codeql-check.ps1 does not block when a changed language needs a real build:
    turning "this tool has nothing to do here" into something that looks like a
    security failure is the fastest way to get the whole hook disabled.

    But it must never be printed as green either. A silent pass here reads as
    "your dependencies are clean" when the truth is "your dependencies were never
    looked at", and that is a worse outcome than a blocked push.
    #>
    param([string[]]$Detail = @())

    Write-Host ''
    Write-Host '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' -ForegroundColor Yellow
    Write-Host '>>  SKIPPED (NOT SCANNED, NOT A FAILURE): dependencies' -ForegroundColor Yellow
    Write-Host '>>  osv-scanner found no package sources it can read in this repo.' -ForegroundColor Yellow
    Write-Host '>>  It reads LOCKFILES, not build scripts. build.gradle, a bare' -ForegroundColor Yellow
    Write-Host '>>  Gemfile and an unpinned requirements-style file are all invisible' -ForegroundColor Yellow
    Write-Host '>>  to it, because none of them state a resolved version.' -ForegroundColor Yellow
    Write-Host '>>' -ForegroundColor Yellow
    Write-Host '>>  YOUR DEPENDENCIES RECEIVED NO SCAN AT ALL. This is not a clean' -ForegroundColor Yellow
    Write-Host '>>  bill of health - nothing was compared against the OSV database.' -ForegroundColor Yellow
    Write-Host '>>  The push is not blocked for this.' -ForegroundColor Yellow
    Write-Host '>>' -ForegroundColor Yellow
    Write-Host '>>  To get real coverage, commit a lockfile this tool understands:' -ForegroundColor Yellow
    Write-Host '>>    Gradle : gradle dependencies --write-locks   (gradle.lockfile)' -ForegroundColor Yellow
    Write-Host '>>             needs dependencyLocking enabled in build.gradle' -ForegroundColor Yellow
    Write-Host '>>    Maven  : commit pom.xml - this hook resolves it via an SBOM' -ForegroundColor Yellow
    Write-Host '>>    Ruby   : commit Gemfile.lock alongside the Gemfile' -ForegroundColor Yellow
    Write-Host '>>    Python : commit a pinned requirements.txt or poetry.lock' -ForegroundColor Yellow
    Write-Host '>>    npm    : commit package-lock.json' -ForegroundColor Yellow
    if (@($Detail).Count -gt 0) {
        Write-Host '>>' -ForegroundColor Yellow
        foreach ($line in @($Detail)) { Write-Host ">>  $line" -ForegroundColor DarkGray }
    }
    Write-Host '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' -ForegroundColor Yellow
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
    Write-Host '*  ADVISORY MODE: findings above were reported but NOT enforced.    *' -ForegroundColor Cyan
    Write-Host '*  osv is configured non-blocking in .hooks\security-profile.json    *' -ForegroundColor Cyan
    Write-Host '*  THE PUSH WAS ALLOWED. Nothing here has been fixed for you.       *' -ForegroundColor Cyan
    Write-Host '********************************************************************' -ForegroundColor Cyan
    return 0
}

# ---------------------------------------------------------------------------
# Result parsing
# ---------------------------------------------------------------------------

function Get-OsvFindings {
    <#
    .SYNOPSIS
    Flattens osv-scanner JSON into one row per vulnerability group.

    .DESCRIPTION
    Rows come from results[].packages[], keyed on the `groups` array rather than
    `vulnerabilities`, because osv-scanner collapses aliases (the same flaw as a
    GHSA and a CVE and an OSV id) into one group. Reporting `vulnerabilities`
    directly triple-counts a single problem and makes the headline number
    meaningless.

    Returns @{ rows; parsed; error }. parsed is $false whenever the file could
    not be read or did not have the shape this function expects - the caller must
    treat that as a tool error, never as an empty result.
    #>
    param([string]$Path, [string]$ScanLabel = '')

    $out = [pscustomobject][ordered]@{
        rows   = @()
        parsed = $false
        error  = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        $out.error = "osv-scanner wrote no output file at $Path."
        return $out
    }

    $raw = ''
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    } catch {
        $out.error = "Could not read $Path ($($_.Exception.Message))."
        return $out
    }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $out.error = "osv-scanner's output file at $Path is empty."
        return $out
    }

    $json = $null
    try {
        $json = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $out.error = "Could not parse $Path as JSON ($($_.Exception.Message))."
        return $out
    }
    if ($null -eq $json) {
        $out.error = "$Path parsed to nothing."
        return $out
    }

    # A valid clean scan is {"results":[]}. Absence of the key entirely means the
    # output shape changed under us, which is a tool error, not a clean result.
    if (-not (@($json.PSObject.Properties.Name) -contains 'results')) {
        $out.error = "$Path has no 'results' key, so osv-scanner's output format is not what this hook was written against."
        return $out
    }

    $rows = @()
    foreach ($result in @($json.results)) {
        if ($null -eq $result) { continue }
        $source = ''
        if ($null -ne $result.source) { $source = [string]$result.source.path }

        foreach ($entry in @($result.packages)) {
            if ($null -eq $entry) { continue }

            $name      = ''
            $version   = ''
            $ecosystem = ''
            if ($null -ne $entry.package) {
                $name      = [string]$entry.package.name
                $version   = [string]$entry.package.version
                $ecosystem = [string]$entry.package.ecosystem
            }

            foreach ($group in @($entry.groups)) {
                if ($null -eq $group) { continue }
                $ids = @(@($group.ids) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                if (@($ids).Count -eq 0) { continue }

                $severity = ''
                if (-not [string]::IsNullOrWhiteSpace([string]$group.max_severity)) {
                    $severity = ([string]$group.max_severity).Trim()
                }

                $rows += [pscustomobject][ordered]@{
                    scan      = $ScanLabel
                    ecosystem = $ecosystem
                    package   = $name
                    version   = $version
                    severity  = $severity
                    ids       = (@($ids) -join ', ')
                    source    = $source
                }
            }
        }
    }

    $out.rows   = @($rows)
    $out.parsed = $true
    return $out
}

# ---------------------------------------------------------------------------
# Maven SBOM generation
# ---------------------------------------------------------------------------

function New-MavenSbom {
    <#
    .SYNOPSIS
    Produces a CycloneDX SBOM for a Maven project by asking Maven to resolve it.

    .DESCRIPTION
    cyclonedx-maven-plugin:makeAggregateBom writes target\bom.json describing the
    fully resolved dependency graph, including transitives, parent POM inheritance,
    dependencyManagement and interpolated properties. Maven is the only thing on
    the machine that knows how to work all of that out, which is exactly why this
    detour exists instead of pointing osv-scanner at pom.xml directly.

    Returns an object the caller inspects rather than throwing, because "Maven is
    not installed" and "Maven failed to build" need very different treatment:
    the first is partial coverage, the second is a hard failure.

    Reuses an existing SBOM when it is newer than every pom.xml in the tree. A
    pre-push hook that shells into Maven on every single push is a hook developers
    learn to bypass, and the dependency graph only changes when a POM changes.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    $res = [pscustomobject][ordered]@{
        Attempted  = $false
        Generated  = $false
        Reused     = $false
        Failed     = $false
        SbomPath   = $null
        SkipReason = $null
        Output     = @()
    }

    $poms = @(Get-ChildItem -LiteralPath $RepoRoot -Filter 'pom.xml' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\target\\' })
    if (@($poms).Count -eq 0) {
        $res.SkipReason = 'no-pom'
        return $res
    }

    $res.Attempted = $true

    # makeAggregateBom writes to the root module's target directory.
    $bomJson = [System.IO.Path]::Combine($RepoRoot, 'target', 'bom.json')

    # Reuse if the SBOM is newer than every POM that feeds it.
    if (Test-Path -LiteralPath $bomJson) {
        $bomTime   = (Get-Item -LiteralPath $bomJson).LastWriteTimeUtc
        $newestPom = @($poms | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)[0]
        if ($bomTime -gt $newestPom.LastWriteTimeUtc) {
            $res.Generated = $true
            $res.Reused    = $true
            $res.SbomPath  = $bomJson
            return $res
        }
    }

    $mvn = Get-ExecutablePath -Name 'mvn'
    if (-not $mvn) {
        # A wrapper is just as good and is what most repos actually ship.
        $wrapper = [System.IO.Path]::Combine($RepoRoot, 'mvnw.cmd')
        if (Test-Path -LiteralPath $wrapper) { $mvn = $wrapper }
    }
    if (-not $mvn) {
        $res.SkipReason = 'no-mvn'
        return $res
    }

    Write-Host ''
    Write-Host 'Maven project detected. Resolving the full dependency graph via cyclonedx-maven-plugin.' -ForegroundColor DarkGray
    Write-Host 'This is the only way to see Maven TRANSITIVE dependencies without a network lookup.' -ForegroundColor DarkGray
    Write-Host "Using $mvn" -ForegroundColor DarkGray

    # -q keeps a normal build quiet; -DskipTests because this is a dependency
    # resolution step, not a verification step, and nobody wants a test suite in
    # their pre-push path.
    $build = Invoke-NativeCapture -Exe $mvn -WorkingDirectory $RepoRoot -Arguments @(
        '-q',
        '-DskipTests',
        'org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom'
    )
    $res.Output = @($build.Output)

    # The full Maven log goes to disk regardless of outcome - it is far too long
    # for a hook banner but it is the first thing anybody debugging will want.
    try {
        @($build.Output) | Out-File -FilePath $LogPath -Encoding utf8 -ErrorAction SilentlyContinue
    } catch { }

    if ($build.ExitCode -ne 0) {
        $res.Failed = $true
        return $res
    }

    if (-not (Test-Path -LiteralPath $bomJson)) {
        # Maven claimed success but produced nothing. Treated as a failure rather
        # than as "no Maven dependencies", because a silent absence here removes
        # the entire Java dependency tree from the scan.
        $res.Failed     = $true
        $res.SkipReason = 'no-bom-produced'
        return $res
    }

    $res.Generated = $true
    $res.SbomPath  = $bomJson
    return $res
}

# ---------------------------------------------------------------------------
# Gradle SBOM generation
# ---------------------------------------------------------------------------

function New-GradleSbom {
    <#
    .SYNOPSIS
    Produces a CycloneDX SBOM for a Gradle project by asking Gradle to resolve it.

    .DESCRIPTION
    Same idea as New-MavenSbom and the same justification: only the build tool can
    resolve a version that comes from a platform/BOM, and only the build tool knows
    the transitive graph. Measured on VulnerableApp (Spring Boot 2.7.18, no
    lockfile): 113 components, 27 vulnerable packages, 102 vulnerability groups,
    where a plain osv-scanner run over the same tree reports zero packages.

    The plugin is applied through an init script (-I) so the repository's own
    build.gradle is never modified.

    FAILURE POLICY DELIBERATELY DIFFERS FROM MAVEN. A failed Maven build is a hard
    error; a failed Gradle SBOM is partial coverage. The reason is not that Java
    matters less, it is that adding this capability must not create NEW blocking
    failures on repositories that until now got no dependency scan at all. Gradle
    fails for ordinary environmental reasons - most commonly a toolchain the
    developer does not have installed - and a security hook that blocks pushes over
    a missing JDK is a security hook that gets uninstalled. Set
    osv.gradleSbomFailureIsError in security-profile.json to make it blocking.

    Reuses an existing SBOM when it is newer than every Gradle build file.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$InitScript,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    $res = [pscustomobject][ordered]@{
        Attempted  = $false
        Generated  = $false
        Reused     = $false
        Failed     = $false
        SbomPath   = $null
        SkipReason = $null
        Output     = @()
    }

    # Build files that define the dependency graph. Deliberately excludes anything
    # under a build output directory or the .gradle cache.
    #
    # One -Filter per pattern rather than a single -Include list. -Include is
    # SILENTLY IGNORED when combined with -LiteralPath: measured 2026-08-17 on
    # VulnerableApp, the -Include form returned 501 files - every file in the repo -
    # instead of the 3 Gradle build files. That defect is invisible in the output
    # and fails in two nasty directions at once: the newest "build file" is then
    # always newer than the SBOM so the reuse check never hits and Gradle runs on
    # every single push, and every repo containing any file at all looks like a
    # Gradle project. -Filter is also the faster path, being handled by the
    # filesystem provider rather than by PowerShell.
    $buildFiles = @()
    foreach ($pattern in @('build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts', 'gradle.properties')) {
        $buildFiles += @(Get-ChildItem -LiteralPath $RepoRoot -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\build\\' -and $_.FullName -notmatch '\\\.gradle\\' })
    }
    if (@($buildFiles).Count -eq 0) {
        $res.SkipReason = 'no-gradle'
        return $res
    }

    # A committed gradle.lockfile is strictly better than this whole detour:
    # osv-scanner reads it natively, with no build tool and no JVM. If one exists,
    # the recursive scan already covers this project.
    $lockfiles = @(Get-ChildItem -LiteralPath $RepoRoot -Filter 'gradle.lockfile' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\build\\' })
    if (@($lockfiles).Count -gt 0) {
        $res.SkipReason = 'has-lockfile'
        return $res
    }

    $res.Attempted = $true

    if (-not (Test-Path -LiteralPath $InitScript)) {
        $res.Failed     = $true
        $res.SkipReason = 'no-init-script'
        return $res
    }

    # Where cyclonedx-gradle-plugin 3.x writes the aggregate BOM.
    $bomJson = [System.IO.Path]::Combine($RepoRoot, 'build', 'reports', 'cyclonedx', 'bom.json')

    if (Test-Path -LiteralPath $bomJson) {
        $bomTime  = (Get-Item -LiteralPath $bomJson).LastWriteTimeUtc
        $newest   = @($buildFiles | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)[0]
        if ($bomTime -gt $newest.LastWriteTimeUtc) {
            $res.Generated = $true
            $res.Reused    = $true
            $res.SbomPath  = $bomJson
            return $res
        }
    }

    # The wrapper is preferred over any gradle on PATH: it pins the version the
    # project is known to build with, and most repos ship one.
    $gradle  = $null
    $wrapper = [System.IO.Path]::Combine($RepoRoot, 'gradlew.bat')
    if (Test-Path -LiteralPath $wrapper) {
        $gradle = $wrapper
    } else {
        $gradle = Get-ExecutablePath -Name 'gradle'
    }
    if (-not $gradle) {
        $res.SkipReason = 'no-gradle-runner'
        return $res
    }

    Write-Host ''
    Write-Host 'Gradle project with no lockfile detected. Resolving the graph via cyclonedx-gradle-plugin.' -ForegroundColor DarkGray
    Write-Host 'Without this step osv-scanner sees ZERO packages in a Gradle project.' -ForegroundColor DarkGray
    Write-Host "Using $gradle" -ForegroundColor DarkGray

    # --no-daemon is REQUIRED here, not a performance preference. Measured
    # 2026-08-17: with the daemon enabled this hook hangs forever. Gradle forks a
    # daemon process that inherits the stdout handle, so the pipe never reaches
    # EOF, so the capture never returns - the hook sits there silently past 10
    # minutes with no output at all. A pre-push hook that hangs is worse than one
    # that is slow, and it costs about 35 s on a repo this size.
    #
    # --console=plain keeps the captured output parseable instead of full of
    # progress-bar control characters.
    $build = Invoke-NativeCapture -Exe $gradle -WorkingDirectory $RepoRoot -Arguments @(
        '--no-daemon',
        '--console=plain',
        '-I', $InitScript,
        'cyclonedxBom'
    )
    $res.Output = @($build.Output)

    try {
        @($build.Output) | Out-File -FilePath $LogPath -Encoding utf8 -ErrorAction SilentlyContinue
    } catch { }

    if ($build.ExitCode -ne 0) {
        $res.Failed = $true
        # Recognise the single most common cause so the banner can name the fix
        # instead of dumping a stack trace. Matching on Gradle's message text is
        # admittedly brittle; it degrades to the generic message if it stops
        # matching, which is why the full log is always written to disk.
        if (@($build.Output) -match 'No matching toolchains found') {
            $res.SkipReason = 'no-toolchain'
        }
        return $res
    }

    if (-not (Test-Path -LiteralPath $bomJson)) {
        $res.Failed     = $true
        $res.SkipReason = 'no-bom-produced'
        return $res
    }

    $res.Generated = $true
    $res.SbomPath  = $bomJson
    return $res
}

# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

function Invoke-OsvScan {
    <#
    .SYNOPSIS
    Runs one osv-scanner invocation and classifies its outcome.

    .DESCRIPTION
    Returns a record with the raw exit code, the parsed findings, and an
    Outcome of CLEAN / VULNS / NO_PACKAGES / TOOL_ERROR. Every branch that
    decides pass or fail reads Outcome, so the exit-code contract lives in one
    place instead of being re-derived per scan.

    Both cross-checks are applied here: an exit code claiming clean while the
    report lists vulnerabilities is the dangerous direction, and the reverse means
    the report is incomplete. Either way the two sources of truth disagree and
    this scan is no longer entitled to an opinion.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Osv,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$ScanArgs,
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [string]$WorkingDirectory
    )

    # Stale results from a previous push must not be mistaken for this run's. If
    # osv-scanner dies before writing, the parse step has to fail loudly rather
    # than quietly report last week's clean scan.
    if (Test-Path -LiteralPath $ResultPath) {
        Remove-Item -LiteralPath $ResultPath -Force -ErrorAction SilentlyContinue
    }

    $allArgs = @('scan', 'source', '--offline', '--format', 'json', '--output-file', $ResultPath) + $ScanArgs
    $run = Invoke-NativeCapture -Exe $Osv -Arguments $allArgs -WorkingDirectory $WorkingDirectory

    # Progress and diagnostics come back on stderr; keep them for the failure
    # paths but do not spray them over a clean run.
    $noise = @(@($run.Output) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -ne '' })

    $rec = [pscustomobject][ordered]@{
        Label      = $Label
        ExitCode   = $run.ExitCode
        Output     = $noise
        ResultPath = $ResultPath
        Findings   = @()
        Outcome    = 'TOOL_ERROR'
        Error      = $null
        WhatToDo   = $null
    }

    if ($run.ExitCode -eq $OSV_NO_PACKAGES) {
        $rec.Outcome = 'NO_PACKAGES'
        return $rec
    }

    if ($run.ExitCode -eq $OSV_OFFLINE_DB_MISSING) {
        $rec.Outcome  = 'TOOL_ERROR'
        $rec.Error    = 'osv-scanner has no local vulnerability database for at least one ecosystem in this repo.'
        $rec.WhatToDo = 'osv-scanner scan source --offline-vulnerabilities --download-offline-databases --recursive .   (one-time, needs network; the database is PER ECOSYSTEM, so re-run it whenever the repo starts using a new language, and periodically because it goes stale)'
        return $rec
    }

    if ($run.ExitCode -ne $OSV_CLEAN -and $run.ExitCode -ne $OSV_VULNS_FOUND) {
        $rec.Outcome  = 'TOOL_ERROR'
        $rec.Error    = "osv-scanner exited $($run.ExitCode), which this hook does not recognise. Recognised codes are 0 (clean), 1 (vulnerabilities found), 127 (offline database missing for an ecosystem) and 128 (no package sources)."
        $rec.WhatToDo = 'Run the scanner by hand to see the full error, adding --verbosity=info.'
        return $rec
    }

    $parsed = Get-OsvFindings -Path $ResultPath -ScanLabel $Label
    if (-not $parsed.parsed) {
        $rec.Outcome  = 'TOOL_ERROR'
        $rec.Error    = "osv-scanner ran but its output could not be read. $($parsed.error)"
        $rec.WhatToDo = 'Check the osv-scanner version against the one this hook was written for (2.4.0). A changed output schema needs this hook updated, not bypassed.'
        return $rec
    }

    $rec.Findings = @($parsed.rows)

    if ($run.ExitCode -eq $OSV_CLEAN -and @($rec.Findings).Count -gt 0) {
        $rec.Outcome  = 'TOOL_ERROR'
        $rec.Error    = "osv-scanner exited 0 (clean) but its report lists $(@($rec.Findings).Count) vulnerability group(s). The exit code and the report disagree, so neither can be trusted."
        $rec.WhatToDo = "Treat this as unscanned. Read $ResultPath and judge by hand before pushing."
        return $rec
    }

    if ($run.ExitCode -eq $OSV_VULNS_FOUND -and @($rec.Findings).Count -eq 0) {
        $rec.Outcome  = 'TOOL_ERROR'
        $rec.Error    = 'osv-scanner exited 1 (vulnerabilities found) but this hook parsed none out of its report. Either the report shape changed or the findings are recorded somewhere this hook does not look.'
        $rec.WhatToDo = "Read $ResultPath by hand, and check the osv-scanner version against the one this hook was written for (2.4.0)."
        return $rec
    }

    if ($run.ExitCode -eq $OSV_VULNS_FOUND) { $rec.Outcome = 'VULNS' } else { $rec.Outcome = 'CLEAN' }
    return $rec
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '== osv-scanner: dependency vulnerability scan ==' -ForegroundColor Cyan

$hooksDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($hooksDir)) { $hooksDir = '.hooks' }

$repoRoot = & git rev-parse --show-toplevel 2>$null
if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($repoRoot)) {
    $repoRoot = ([string]$repoRoot).Trim() -replace '/', '\'
} else {
    # The hook lives in <repo>\.hooks\, so its parent is the repo root.
    $repoRoot = Split-Path -Parent $hooksDir
}
if ([string]::IsNullOrWhiteSpace($repoRoot)) { $repoRoot = (Get-Location).Path }

$cfg = Get-SecurityConfig -Path ([System.IO.Path]::Combine($hooksDir, 'security-profile.json'))
Write-MissingProfileWarning -Config $cfg

$osv = Get-ExecutablePath -Name 'osv-scanner'
if (-not $osv) {
    Write-ToolError -Summary 'osv-scanner is not on PATH, so no dependency scan ran at all.' `
        -Detail @(
            "The command 'osv-scanner' could not be resolved to an executable.",
            'A missing scanner produces no findings, which looks exactly like a clean',
            'result. That is why this is checked before the scan rather than after.'
        ) `
        -WhatToDo 'Re-run setup/install.ps1 (it downloads a checksum-verified osv-scanner release, no winget needed), then open a new terminal so PATH is picked up. Manual install: https://google.github.io/osv-scanner/installation/'
    exit (Resolve-FinalExitCode -Intended $EXIT_TOOL_ERROR -Blocking $cfg.blockOsv)
}

Write-Host "Using $osv" -ForegroundColor DarkGray
Write-Host "Repository: $repoRoot" -ForegroundColor DarkGray
Write-Host 'Scanning the whole repository (lockfiles, not the diff), offline.' -ForegroundColor DarkGray

$scans = @()
# A list, not a single value: a repo can be both a Maven project with no Maven and
# a Gradle project with no toolchain, and silently reporting only the first
# degradation would misstate how much of the tree went unscanned.
$partialWarnings = @()

# --- Scan 1: Maven, via an SBOM Maven itself resolved -----------------------

if ($cfg.generateMvnSbom) {
    $sbomLog = [System.IO.Path]::Combine($hooksDir, 'osv-sbom-build.log')
    $sbom    = New-MavenSbom -RepoRoot $repoRoot -LogPath $sbomLog

    if ($sbom.Failed) {
        # A build failure is NOT partial coverage. Maven was present, was asked to
        # resolve the graph, and could not - so the Java dependency tree is
        # entirely unjudged and we have no idea how big the hole is.
        $detail = @(
            'Maven was available and was asked to resolve the dependency graph, but',
            'the build failed. That leaves the ENTIRE Java dependency tree unscanned,',
            'so this is a hard failure rather than reduced coverage.'
        )
        if ($sbom.SkipReason -eq 'no-bom-produced') {
            $detail += 'Maven reported success but wrote no target\bom.json.'
        }
        $detail += "Full Maven log: $sbomLog"
        $detail += '--- last lines of Maven output ---'
        $detail += @(@($sbom.Output) | Select-Object -Last 15)

        Write-ToolError -Summary 'Maven could not resolve the dependency graph, so Java dependencies were not scanned.' `
            -Detail $detail `
            -WhatToDo 'Run it by hand to see the real error: mvn -DskipTests org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom'
        exit (Resolve-FinalExitCode -Intended $EXIT_TOOL_ERROR -Blocking $cfg.blockOsv)
    }

    if ($sbom.Attempted -and -not $sbom.Generated -and $sbom.SkipReason -eq 'no-mvn') {
        # Deliberately not fatal - see Write-PartialCoverageWarning. The recursive
        # scan below still runs and still finds anything in another ecosystem.
        $partialWarnings += [pscustomobject]@{
            Summary  = 'a pom.xml is present but Maven is not installed, so Java dependencies were skipped.'
            Detail   = @(
                'osv-scanner cannot resolve a pom.xml on its own: versions can come from',
                'a parent POM, from dependencyManagement, or from a property, and only',
                'Maven itself can work that out.',
                'This hook therefore asks Maven to emit a CycloneDX SBOM and scans that.',
                'Without Maven there is no SBOM, so no Java dependency was checked -',
                'including transitive ones, which is where most real findings live.'
            )
            WhatToDo = 'winget install --id Apache.Maven   (then restart your shell)'
        }
    }

    if ($sbom.Generated) {
        $where = 'generated'
        if ($sbom.Reused) { $where = 'reused (newer than every pom.xml)' }
        Write-Host "Maven SBOM $where : $($sbom.SbomPath)" -ForegroundColor DarkGray

        $scans += Invoke-OsvScan -Osv $osv -Label 'maven-sbom' `
            -ScanArgs @('-L', $sbom.SbomPath) `
            -ResultPath ([System.IO.Path]::Combine($hooksDir, 'osv-results-maven.json')) `
            -WorkingDirectory $repoRoot
    }
}

# --- Scan 1b: Gradle, via an SBOM Gradle itself resolved ---------------------
#
# Only reached when there is no gradle.lockfile: with one, the recursive scan
# below already reads it natively and this whole detour is wasted time.

if ($cfg.generateGradleSbom) {
    $gradleLog  = [System.IO.Path]::Combine($hooksDir, 'osv-sbom-gradle.log')
    $initScript = [System.IO.Path]::Combine($hooksDir, 'cyclonedx-init.gradle')
    $gsbom      = New-GradleSbom -RepoRoot $repoRoot -InitScript $initScript -LogPath $gradleLog

    if ($gsbom.Failed -or ($gsbom.Attempted -and -not $gsbom.Generated)) {
        $summary = 'a Gradle project with no lockfile could not be resolved, so its dependencies were skipped.'
        $detail  = @(
            'osv-scanner reads LOCKFILES, and a Gradle project without a',
            'gradle.lockfile states no resolved version anywhere - so on its own the',
            'scan below sees ZERO packages here, not a partial list.',
            'This hook therefore asks Gradle to emit a CycloneDX SBOM, applying the',
            'plugin through an init script so your build.gradle is never modified.'
        )
        $what = 'Run it by hand to see the real error: gradlew --console=plain -I .hooks\cyclonedx-init.gradle cyclonedxBom'

        switch ($gsbom.SkipReason) {
            'no-gradle-runner' {
                $detail += 'No gradlew.bat in the repo and no gradle on PATH, so nothing could resolve it.'
                $what    = 'Commit the Gradle wrapper (gradle wrapper), or install Gradle and restart your shell.'
            }
            'no-toolchain' {
                # By far the most common failure, and the one most likely to be
                # mistaken for a broken hook.
                $detail += 'Gradle ran but this project pins a Java toolchain that is not installed'
                $detail += 'on this machine, so it could not even resolve the dependency graph.'
                $detail += 'This is the same reason the project itself will not build here.'
                $what    = 'Install the JDK version named in the log, then re-push. Full log: ' + $gradleLog
            }
            'no-init-script' {
                $detail += 'The init script .hooks\cyclonedx-init.gradle is missing, so the SBOM'
                $detail += 'plugin could not be applied. It ships alongside this hook.'
                $what    = 'Re-run the installer to restore .hooks\cyclonedx-init.gradle.'
            }
            'no-bom-produced' {
                $detail += 'Gradle reported success but wrote no build\reports\cyclonedx\bom.json.'
            }
            default {
                $detail += '--- last lines of Gradle output ---'
                $detail += @(@($gsbom.Output) | Select-Object -Last 12)
                $detail += "Full Gradle log: $gradleLog"
            }
        }

        if ($cfg.gradleSbomFailureIsError) {
            # Opt-in. Off by default so that gaining Gradle coverage cannot cost
            # anyone a blocked push over a missing JDK.
            Write-ToolError -Summary $summary -Detail $detail -WhatToDo $what
            exit (Resolve-FinalExitCode -Intended $EXIT_TOOL_ERROR -Blocking $cfg.blockOsv)
        }

        $partialWarnings += [pscustomobject]@{
            Summary  = $summary
            Detail   = $detail
            WhatToDo = $what
        }
    }

    if ($gsbom.Generated) {
        $where = 'generated'
        if ($gsbom.Reused) { $where = 'reused (newer than every Gradle build file)' }
        Write-Host "Gradle SBOM $where : $($gsbom.SbomPath)" -ForegroundColor DarkGray

        $scans += Invoke-OsvScan -Osv $osv -Label 'gradle-sbom' `
            -ScanArgs @('-L', $gsbom.SbomPath) `
            -ResultPath ([System.IO.Path]::Combine($hooksDir, 'osv-results-gradle.json')) `
            -WorkingDirectory $repoRoot
    }
}

# --- Scan 2: every other ecosystem, via its native lockfile ------------------
#
# Always runs, regardless of what happened above. npm package-lock.json, Python
# poetry.lock / uv.lock, Go go.mod and the rest need no extra setup at all,
# because those lockfiles already state resolved versions.

$scans += Invoke-OsvScan -Osv $osv -Label 'repo-lockfiles' `
    -ScanArgs @('--recursive', '.') `
    -ResultPath ([System.IO.Path]::Combine($hooksDir, 'osv-results.json')) `
    -WorkingDirectory $repoRoot

# --- Combine -----------------------------------------------------------------

foreach ($pw in @($partialWarnings)) {
    Write-PartialCoverageWarning -Summary $pw.Summary -Detail $pw.Detail -WhatToDo $pw.WhatToDo
}

# Written before any exit so a developer can always see what each scan did,
# including on the failure paths where the terminal output is the least readable.
$summaryPath = [System.IO.Path]::Combine($hooksDir, 'osv-summary.json')
try {
    $summary = [pscustomobject][ordered]@{
        repoRoot       = $repoRoot
        offline        = $true
        partialCoverage = ($null -ne $partialWarning)
        scans          = @($scans | ForEach-Object {
            [pscustomobject][ordered]@{
                label         = $_.Label
                osvExitCode   = $_.ExitCode
                outcome       = $_.Outcome
                findingGroups = @($_.Findings).Count
                resultFile    = $_.ResultPath
                error         = $_.Error
            }
        })
    }
    $summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $summaryPath -Encoding utf8 -ErrorAction SilentlyContinue
} catch { }

# Tool errors win over everything. If any scan could not judge its dependencies,
# the combined result cannot claim they were judged.
$broken = @($scans | Where-Object { $_.Outcome -eq 'TOOL_ERROR' })
if (@($broken).Count -gt 0) {
    $first  = @($broken)[0]
    $detail = @($first.Error, '')
    $detail += 'Scan outcomes this run:'
    foreach ($s in $scans) {
        $detail += "  $($s.Label): osv exit $($s.ExitCode) -> $($s.Outcome)"
    }
    $detail += ''
    $detail += '--- osv-scanner output ---'
    $detail += @(@($first.Output) | Select-Object -Last 20)

    Write-ToolError -Summary "the '$($first.Label)' scan could not judge your dependencies." `
        -Detail $detail `
        -WhatToDo $first.WhatToDo
    exit (Resolve-FinalExitCode -Intended $EXIT_TOOL_ERROR -Blocking $cfg.blockOsv)
}

# Dedupe across scans. If target\bom.json is not gitignored the recursive scan
# picks it up as well, and the same package would otherwise be reported twice.
$allFindings = @($scans | ForEach-Object { @($_.Findings) } | Where-Object { $null -ne $_ })
$seen        = @{}
$findings    = @()
foreach ($f in $allFindings) {
    $key = "$($f.ecosystem)|$($f.package)|$($f.version)|$($f.ids)"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $findings += $f
}

# --- Report -----------------------------------------------------------------

if (@($findings).Count -gt 0) {
    $packageCount = @($findings | Select-Object -ExpandProperty package -Unique).Count
    Write-Host ''
    Write-Host "SECURITY FINDINGS: osv-scanner found $(@($findings).Count) vulnerability group(s) across $packageCount package(s):" -ForegroundColor Red
    $findings |
        Sort-Object @{ Expression = { [double]('0' + $_.severity) }; Descending = $true }, package |
        Format-Table scan, ecosystem, package, version, severity, ids -AutoSize
    Write-Host "Summary: $summaryPath" -ForegroundColor DarkGray
    foreach ($s in $scans) {
        if (@($s.Findings).Count -gt 0) { Write-Host "  $($s.Label) report: $($s.ResultPath)" -ForegroundColor DarkGray }
    }
    Write-Host 'Upgrade the package(s) above, or record a documented exception, before pushing.' -ForegroundColor Red
    exit (Resolve-FinalExitCode -Intended $EXIT_SECURITY_FINDING -Blocking $cfg.blockOsv)
}

# Every scan that ran found nothing to scan. Not a pass worth printing green.
$scanned = @($scans | Where-Object { $_.Outcome -eq 'CLEAN' -or $_.Outcome -eq 'VULNS' })
if (@($scanned).Count -eq 0) {
    $detail = @()
    foreach ($s in $scans) { $detail += "$($s.Label): osv exit $($s.ExitCode) (no package sources found)." }
    Write-NothingScannedBanner -Detail $detail
    exit $EXIT_PASS
}

Write-Host ''
Write-Host 'osv-scanner: no known vulnerabilities in the dependencies it could resolve.' -ForegroundColor Green
foreach ($s in $scanned) {
    Write-Host "  $($s.Label): scanned, clean" -ForegroundColor DarkGray
}
Write-Host "Summary: $summaryPath" -ForegroundColor DarkGray
exit $EXIT_PASS
