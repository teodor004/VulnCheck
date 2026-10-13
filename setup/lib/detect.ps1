# detect.ps1 - profiles a repository and the local CodeQL installation.
#
# Answers the question the POC failed to ask: for the languages actually in this
# repo, can CodeQL analyse them properly here, or is it about to run degraded and
# tell us almost nothing?
#
# Dot-sourced by doctor.ps1 and install.ps1. Requires lib/tools.ps1.
# Targets Windows PowerShell 5.1.

Set-StrictMode -Version Latest

# Maps file extensions to CodeQL extractor names. Superset of the map in the
# original .hooks/codeql-check.ps1.
function Get-ExtensionLanguageMap {
    return @{
        '.java'   = 'java'
        '.kt'     = 'java'
        '.py'     = 'python'
        '.js'     = 'javascript'
        '.jsx'    = 'javascript'
        '.mjs'    = 'javascript'
        '.cjs'    = 'javascript'
        '.ts'     = 'javascript'
        '.tsx'    = 'javascript'
        '.vue'    = 'javascript'
        '.go'     = 'go'
        '.rb'     = 'ruby'
        '.erb'    = 'ruby'
        '.cs'     = 'csharp'
        '.c'      = 'cpp'
        '.cc'     = 'cpp'
        '.cpp'    = 'cpp'
        '.cxx'    = 'cpp'
        '.h'      = 'cpp'
        '.hpp'    = 'cpp'
        '.swift'  = 'swift'
        '.rs'     = 'rust'
    }
}

function Get-CodeQLHome {
    <#
    .SYNOPSIS
    Directory containing codeql.exe, or $null if CodeQL is not on PATH.
    #>
    $cmd = Get-Command 'codeql' -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandType -ne 'Alias' } |
        Select-Object -First 1
    if (-not $cmd -or -not $cmd.Path) { return $null }
    return (Split-Path -Parent $cmd.Path)
}

function Get-ExtractorBuildModes {
    <#
    .SYNOPSIS
    Build modes a CodeQL extractor declares, read from its own manifest.

    .DESCRIPTION
    Read from <codeql-home>\<language>\codeql-extractor.yml rather than
    hardcoded, because the CLI's own --help text is demonstrably stale: it omits
    build-mode=none for C/C++ even though cpp-all 12.0.0 shipped it as generally
    available. The manifest is what the CLI actually validates against.

    Deliberately a line-based reader, not a YAML parser: the block is a flat
    sequence of scalars and PowerShell 5.1 has no YAML support built in.

    Returns @() when the manifest is missing or has no build_modes block.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Language,
        [string]$CodeQLHome
    )

    if (-not $CodeQLHome) { $CodeQLHome = Get-CodeQLHome }
    if (-not $CodeQLHome) { return @() }

    $manifest = [System.IO.Path]::Combine($CodeQLHome, $Language, 'codeql-extractor.yml')
    if (-not (Test-Path -LiteralPath $manifest)) { return @() }

    $modes    = @()
    $inBlock  = $false
    foreach ($line in (Get-Content -LiteralPath $manifest)) {
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
    return $modes
}

function Test-LanguagePlatformSupport {
    <#
    .SYNOPSIS
    Whether a language's extractor can run on the current OS.

    .DESCRIPTION
    Swift ships a win64 extractor.exe that immediately exits with
    "[incompatible-os] Currently, Swift analysis is only supported on macOS."
    The query pack still resolves, so suite resolvability is NOT evidence the
    language can be analysed. This must be gated on platform.
    #>
    param([Parameter(Mandatory = $true)][string]$Language)

    $result = [pscustomobject][ordered]@{
        supported = $true
        reason    = $null
    }

    if ($Language -eq 'swift' -and -not $IsMacOSCompat) {
        $result.supported = $false
        $result.reason    = 'The Swift extractor only runs on macOS. On Windows it exits with an incompatible-os error.'
    }

    return $result
}

# PowerShell 5.1 has no $IsMacOS automatic variable, so derive it once.
$IsMacOSCompat = $false
if (Test-Path Variable:\IsMacOS) { $IsMacOSCompat = $IsMacOS }

function Get-BuildSystemMarkers {
    <#
    .SYNOPSIS
    Build-system files present at the repo root, as language -> marker names.
    #>
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $markers = @{
        'java'       = @('build.gradle', 'build.gradle.kts', 'pom.xml', 'settings.gradle', 'settings.gradle.kts')
        'javascript' = @('package.json', 'tsconfig.json')
        'python'     = @('requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile')
        'go'         = @('go.mod')
        'rust'       = @('Cargo.toml')
        'ruby'       = @('Gemfile')
        'csharp'     = @('*.csproj', '*.sln')
        'cpp'        = @('CMakeLists.txt', 'Makefile')
    }

    $found = @{}
    foreach ($lang in $markers.Keys) {
        $hits = @()
        foreach ($pattern in $markers[$lang]) {
            $matched = Get-ChildItem -LiteralPath $RepoRoot -Filter $pattern -File -ErrorAction SilentlyContinue
            foreach ($m in $matched) { $hits += $m.Name }
        }
        if ($hits.Count -gt 0) { $found[$lang] = @($hits | Sort-Object -Unique) }
    }
    return $found
}

function Get-DependencyEcosystems {
    <#
    .SYNOPSIS
    OSV ecosystems this repo has scannable dependency manifests for.

    .DESCRIPTION
    Exists because osv-scanner's offline database is PER ECOSYSTEM, which is not
    obvious and fails in the worst possible direction. Verified 2026-08-17: a
    cache primed against an npm-only repo contains only npm\all.zip; point that
    same cache at a Maven manifest and osv-scanner prints "could not load db for
    Maven ecosystem", exits 127, and writes {"results": []} - a file identical to
    a clean scan. So "is the database primed" is not a yes/no question, and
    install.ps1 and doctor.ps1 both need to ask it per ecosystem.

    The returned names are the OSV ecosystem names, which are also the directory
    names osv-scanner uses under %LOCALAPPDATA%\osv-scanner, so a caller can test
    for the cache directly.

    Mapped are the manifests osv-scanner can read directly, AND the build scripts
    osv-check.ps1 can turn into something it can read. gradle.lockfile maps to
    Maven because that is the ecosystem Gradle artifacts live in. pom.xml maps to
    Maven because osv-scanner does parse it - verified 2026-08-17, a pom.xml with a
    literal dependency version was resolved offline - though only for DIRECT
    dependencies, which is why osv-check.ps1 goes via an SBOM for the transitive
    graph.

    build.gradle and build.gradle.kts are mapped to Maven as of 2026-08-17. They
    were deliberately absent before, on the correct grounds that osv-scanner alone
    sees nothing in a build script. That is still true of osv-scanner alone, but the
    hook now generates a CycloneDX SBOM with cyclonedx-gradle-plugin and scans
    that, so a Gradle repo DOES need the Maven database primed. Of the two possible
    mistakes this was the dangerous one: omitting them meant priming skipped Maven
    entirely, and the first Gradle push then hit the exit-127 clean-looking-JSON
    trap that this function exists to prevent.

    Not exhaustive. An ecosystem missing from this map degrades to the hook's own
    exit 127 handling, which is loud and tells the developer how to fix it, so an
    omission here costs a confusing first push rather than a silent miss.
    #>
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $map = [ordered]@{
        'npm'       = @('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml')
        'Maven'     = @('pom.xml', 'gradle.lockfile', 'bom.json', 'bom.xml', 'build.gradle', 'build.gradle.kts')
        'PyPI'      = @('requirements.txt', 'poetry.lock', 'uv.lock', 'Pipfile.lock', 'pdm.lock')
        'Go'        = @('go.mod')
        'NuGet'     = @('packages.lock.json', 'packages.config')
        'RubyGems'  = @('Gemfile.lock')
        'crates.io' = @('Cargo.lock')
        'Packagist' = @('composer.lock')
        'Hex'       = @('mix.lock')
        'Pub'       = @('pubspec.lock')
    }

    $found = @()
    foreach ($eco in $map.Keys) {
        foreach ($pattern in $map[$eco]) {
            # Recurse: a monorepo keeps its lockfiles in subdirectories, and the
            # hook scans recursively, so priming must consider the same set.
            $hit = @(Get-ChildItem -LiteralPath $RepoRoot -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '\\node_modules\\' } |
                Select-Object -First 1)
            if (@($hit).Count -gt 0) { $found += $eco; break }
        }
    }
    return @($found)
}

function Get-OsvDatabaseStatus {
    <#
    .SYNOPSIS
    Which of the repo's ecosystems have a primed offline database, and which do not.

    .DESCRIPTION
    Returns @{ cacheDir; expected; present; missing; newestWriteUtc }. `missing`
    is the field that matters: any entry in it is an ecosystem the repo uses and
    the hook will exit 127 on.

    A repo with no scannable manifests at all yields an empty `expected`, and
    therefore an empty `missing` - correctly, because there is nothing for the
    database to answer. That case is reported by the hook's own
    "nothing scanned" banner, not as a database fault.
    #>
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $cacheDir = Join-Path $env:LOCALAPPDATA 'osv-scanner'
    $expected = @(Get-DependencyEcosystems -RepoRoot $RepoRoot)

    $present = @()
    $newest  = $null
    if (Test-Path -LiteralPath $cacheDir) {
        foreach ($d in @(Get-ChildItem -LiteralPath $cacheDir -Directory -ErrorAction SilentlyContinue)) {
            $zip = Join-Path $d.FullName 'all.zip'
            if (Test-Path -LiteralPath $zip) {
                $present += $d.Name
                $t = (Get-Item -LiteralPath $zip).LastWriteTimeUtc
                if ($null -eq $newest -or $t -gt $newest) { $newest = $t }
            }
        }
    }

    $missing = @($expected | Where-Object { $present -notcontains $_ })

    return [pscustomobject][ordered]@{
        cacheDir       = $cacheDir
        expected       = @($expected)
        present        = @($present)
        missing        = @($missing)
        newestWriteUtc = $newest
    }
}

function Get-RepoLanguageInventory {
    <#
    .SYNOPSIS
    Languages present in the repo, with file counts, from git-tracked files.

    .DESCRIPTION
    Uses `git ls-files` so build output, node_modules and other ignored trees
    cannot inflate the picture.
    #>
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $map = Get-ExtensionLanguageMap

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $files = & git -C $RepoRoot ls-files 2>$null
    } finally {
        $ErrorActionPreference = $prev
    }

    $counts = @{}
    foreach ($file in $files) {
        if ([string]::IsNullOrWhiteSpace($file)) { continue }
        $ext = [System.IO.Path]::GetExtension($file)
        if (-not $ext) { continue }
        $ext = $ext.ToLowerInvariant()
        if (-not $map.ContainsKey($ext)) { continue }
        $lang = $map[$ext]
        if ($counts.ContainsKey($lang)) {
            $counts[$lang] = $counts[$lang] + 1
        } else {
            $counts[$lang] = 1
        }
    }
    return $counts
}

function Get-LanguageProfile {
    <#
    .SYNOPSIS
    Per-language analysis capability for this repo on this machine.

    .DESCRIPTION
    status is one of:
      OK          - analysable buildless, supporting toolchain present
      DEGRADED    - analysable buildless, but a missing toolchain will quietly
                    reduce what is found. Findings are a floor.
      NEEDS_BUILD - the extractor does not support build-mode=none, so a
                    buildless pre-push hook cannot analyse it. Skipped, loudly.
      UNSUPPORTED - cannot run on this platform at all.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$CodeQLHome
    )

    if (-not $CodeQLHome) { $CodeQLHome = Get-CodeQLHome }

    $inventory  = Get-RepoLanguageInventory -RepoRoot $RepoRoot
    $buildFiles = Get-BuildSystemMarkers -RepoRoot $RepoRoot
    $toolchains = Get-LanguageToolchainRegistry

    $profiles = @()

    foreach ($lang in ($inventory.Keys | Sort-Object)) {
        $fileCount = $inventory[$lang]

        $status  = 'OK'
        $reasons = @()
        $missing = @()

        $platform = Test-LanguagePlatformSupport -Language $lang
        # @() wrap is required: PowerShell unwraps a one-element return to a
        # bare string, and under StrictMode a string has no .Count.
        $modes    = @(Get-ExtractorBuildModes -Language $lang -CodeQLHome $CodeQLHome)

        if (-not $platform.supported) {
            $status    = 'UNSUPPORTED'
            $reasons  += $platform.reason
        } elseif ($modes.Count -eq 0) {
            # No manifest found - CodeQL absent, or an unexpected layout. Do not
            # claim capability we have not verified.
            $status   = 'UNSUPPORTED'
            $reasons += 'Could not read the extractor manifest, so buildless support is unverified. Is CodeQL installed?'
        } elseif ($modes -notcontains 'none') {
            $status   = 'NEEDS_BUILD'
            $reasons += "The $lang extractor supports only [$($modes -join ', ')], not build-mode=none. A buildless pre-push hook cannot analyse it."
        }

        # Toolchain checks only matter if the language is analysable at all.
        if ($status -eq 'OK' -and $toolchains.ContainsKey($lang)) {
            foreach ($tc in $toolchains[$lang]) {
                $probe = Get-CommandVersion -Command $tc.Command `
                    -VersionArgs $tc.VersionArgs `
                    -VersionPattern $tc.VersionPattern
                if (-not $probe.Found) {
                    $status   = 'DEGRADED'
                    $reasons += $tc.Impact
                    $missing += [pscustomobject][ordered]@{
                        id            = $tc.Id
                        name          = $tc.Name
                        installMethod = $tc.InstallMethod
                        # .ContainsKey, not a bare truthy check: JDK's InstallSpec
                        # is a hashtable with no PackageId key at all (a manual
                        # download has no package id), and under Set-StrictMode
                        # a dotted access to a missing hashtable key throws rather
                        # than returning $null.
                        packageId     = $(if ($tc.InstallSpec -and $tc.InstallSpec.ContainsKey('PackageId')) { $tc.InstallSpec.PackageId } else { $null })
                        # Carried through so install.ps1 can act on a 'manual'
                        # toolchain (JDK) the same way it does for gitleaks/
                        # osv-scanner/CodeQL, without this projection needing to
                        # know how to install anything itself.
                        installSpec   = $(if ($tc.InstallMethod -eq 'manual') { $tc.InstallSpec } else { $null })
                    }
                }
            }
        }

        # A build system with no resolvable dependency graph is the specific
        # failure that made every Java recall figure in the POC a floor.
        $hasBuildFile = $buildFiles.ContainsKey($lang)
        if ($status -eq 'DEGRADED' -and $hasBuildFile) {
            $reasons += "Build files are present ($($buildFiles[$lang] -join ', ')) but cannot be resolved without the toolchain, so dependencies are guessed from package names."
        }

        $profiles += [pscustomobject][ordered]@{
            language        = $lang
            fileCount       = $fileCount
            status          = $status
            buildModes      = @($modes)
            buildFiles      = $(if ($hasBuildFile) { @($buildFiles[$lang]) } else { @() })
            missingToolchain = @($missing)
            reasons         = @($reasons)
        }
    }

    return $profiles
}

function Get-AvailableQuerySuites {
    <#
    .SYNOPSIS
    Which of the two candidate suites resolve locally for a language.

    .DESCRIPTION
    Verified on the POC bundle: code-scanning and security-and-quality both
    exist for all ten languages. Checked rather than assumed, because the bare
    codeql-cli-binaries download ships no query packs at all and would resolve
    neither - which is exactly the misinstall this setup is built to prevent.
    #>
    param([Parameter(Mandatory = $true)][string]$Language)

    $result = @{}
    foreach ($suite in @('code-scanning', 'security-and-quality')) {
        $name = "$Language-$suite.qls"
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $out = & codeql resolve queries $name 2>&1
            $ok  = ($LASTEXITCODE -eq 0)
        } catch {
            $ok = $false
            $out = @()
        } finally {
            $ErrorActionPreference = $prev
        }
        $count = 0
        if ($ok) { $count = @($out | Where-Object { $_ -match '\.ql$' }).Count }
        $result[$suite] = [pscustomobject][ordered]@{
            suite      = $name
            resolves   = $ok
            queryCount = $count
        }
    }
    return $result
}

function Get-RepoRoot {
    <#
    .SYNOPSIS
    Top level of the git worktree, or $null when not in a repo.
    #>
    param([string]$StartPath = '.')

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $root = & git -C $StartPath rev-parse --show-toplevel 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
    } finally {
        $ErrorActionPreference = $prev
    }
    if ([string]::IsNullOrWhiteSpace($root)) { return $null }
    return $root.Trim().Replace('/', '\')
}
