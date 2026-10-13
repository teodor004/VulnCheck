# tools.ps1 - single source of truth for external tool requirements.
#
# Dot-sourced by doctor.ps1 (check only) and install.ps1 (check + install), so
# the two can never disagree about what "installed" means.
#
# Targets Windows PowerShell 5.1: no ternary operator, no ?? operator, no
# ForEach-Object -Parallel.

Set-StrictMode -Version Latest

# Where a manual (no package manager) install puts things. Overridable via
# SECURITY_TOOL_ROOT so tests and non-standard machines are not forced onto
# C:\tools. Computed on demand rather than cached in a script-scope variable:
# under Set-StrictMode -Version Latest, reading an unset variable is an error,
# and dot-sourcing makes script scope depend on the caller.
function Get-ToolRootPath {
    if ($env:SECURITY_TOOL_ROOT) { return $env:SECURITY_TOOL_ROOT }
    return 'C:\tools'
}

function Get-ToolRegistry {
    <#
    .SYNOPSIS
    Returns the ordered list of tools the hooks depend on.

    .DESCRIPTION
    Each entry declares how to DETECT the tool and how to INSTALL it. Versions
    under TestedVersion are the versions the POC actually measured against
    (the POC findings document, kept outside this folder); they are reported for provenance,
    not enforced.

    InstallMethod values:
      winget  - one-line install via winget. Kept only for language toolchains
                (JDK, Node, ...) - see Get-LanguageToolchainRegistry. None of
                the three hook tools use it: winget is not available on every
                managed machine, and its silent-install path cannot be
                checksum-verified the way a direct release download can.
      pip     - install via pip
      manual  - download a pinned GitHub release asset, verify its published
                SHA-256, then extract (Spec.Kind 'zip', 'targz') or place
                directly (Spec.Kind 'exe'). Handled by Install-GithubReleaseAsset
                / Install-CodeQLBundle in install-helpers.ps1.
      none    - never installed automatically; reported only
    #>

    $toolRoot = Get-ToolRootPath
    # [IO.Path]::Combine, not Join-Path: Join-Path resolves the drive and throws
    # DriveNotFoundException for a path that does not exist yet, which is
    # exactly the situation before these tools are installed.
    $codeqlHome   = [System.IO.Path]::Combine($toolRoot, "codeql")
    $gitleaksHome = [System.IO.Path]::Combine($toolRoot, "gitleaks")
    $osvHome      = [System.IO.Path]::Combine($toolRoot, "osv-scanner")

    $tools = @()

    $tools += @{
        Id             = 'git'
        Name           = 'Git'
        Command        = 'git'
        VersionArgs    = @('--version')
        # Anchored to three components: git on Windows reports
        # "git version 2.54.0.windows.1", and a greedy [\d\.]+ captures a
        # trailing dot.
        VersionPattern = 'git version (\d+\.\d+\.\d+)'
        TestedVersion  = '2.x'
        Required       = $true
        InstallMethod  = 'none'
        InstallSpec    = $null
        DocsUrl        = 'https://git-scm.com'
        Why            = 'Everything here is a git hook. Without git there is nothing to hook.'
    }

    $tools += @{
        Id             = 'python'
        Name           = 'Python'
        Command        = 'python'
        VersionArgs    = @('--version')
        VersionPattern = 'Python ([\d\.]+)'
        TestedVersion  = '3.13.14'
        Required       = $true
        InstallMethod  = 'none'
        InstallSpec    = $null
        DocsUrl        = 'https://python.org'
        Why            = 'Only needed because pre-commit is a Python package.'
    }

    $tools += @{
        Id             = 'pre-commit'
        Name           = 'pre-commit framework'
        Command        = 'pre-commit'
        VersionArgs    = @('--version')
        VersionPattern = 'pre-commit ([\d\.]+)'
        TestedVersion  = '4.6.1'
        Required       = $true
        InstallMethod  = 'pip'
        InstallSpec    = @{ Package = 'pre-commit' }
        DocsUrl        = 'https://pre-commit.com'
        Why            = 'Drives both .git/hooks/pre-commit and .git/hooks/pre-push.'
    }

    # No winget: downloaded and verified by hand, same shape as CodeQL below.
    # gitleaks publishes ONE checksums file covering every platform's asset
    # (ten lines), unlike CodeQL's one-line-per-asset file - Get-ChecksumFromFile
    # in install-helpers.ps1 matches by filename rather than "take the first
    # hash" for exactly this reason. Verified 2026-08-26: the zip is flat
    # (gitleaks.exe at the archive root, no subfolder), unlike the CodeQL bundle.
    $tools += @{
        Id             = 'gitleaks'
        Name           = 'Gitleaks'
        Command        = 'gitleaks'
        VersionArgs    = @('version')
        VersionPattern = '([\d]+\.[\d]+\.[\d]+)'
        TestedVersion  = '8.30.1'
        Required       = $true
        InstallMethod  = 'manual'
        InstallSpec    = @{
            Kind         = 'zip'
            Url          = 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip'
            ChecksumUrl  = 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt'
            ApproxSizeMB = 9
            ExtractTo    = $gitleaksHome
            ExeFullPath  = [System.IO.Path]::Combine($gitleaksHome, 'gitleaks.exe')
            AddToUserPath = $gitleaksHome
            VersionArgs  = @('version')
        }
        DocsUrl        = 'https://github.com/gitleaks/gitleaks/releases'
        Why            = 'Secret scanning at commit time. Strongest result in the POC: 10/10 recall, 0 false positives.'
    }

    # Dependency scanning. Deliberately a separate tool rather than a CodeQL
    # query pack: CodeQL analyses the code in this repo, osv-scanner resolves
    # what the repo pulls in from elsewhere, and on a typical service the second
    # set is far larger than the first.
    #
    # Caveat worth knowing before trusting a green result: osv-scanner reads
    # LOCKFILES. build.gradle, a bare Gemfile and an unpinned requirements file
    # state no resolved version, so it can extract nothing from them and exits
    # 128 (no package sources). osv-check.ps1 reports that as a loud SKIP rather
    # than a pass. This repo is exactly that case.
    # No winget: downloaded and verified by hand. osv-scanner ships a bare .exe
    # for Windows - no archive at all - but named osv-scanner_windows_amd64.exe,
    # not osv-scanner.exe, so Install-GithubReleaseAsset (Kind 'exe') renames it
    # on placement rather than extracting anything.
    $tools += @{
        Id             = 'osv-scanner'
        Name           = 'OSV Scanner'
        Command        = 'osv-scanner'
        VersionArgs    = @('--version')
        VersionPattern = '([\d]+\.[\d]+\.[\d]+)'
        TestedVersion  = '2.4.0'
        Required       = $true
        InstallMethod  = 'manual'
        InstallSpec    = @{
            Kind         = 'exe'
            Url          = 'https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_windows_amd64.exe'
            ChecksumUrl  = 'https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_SHA256SUMS'
            ApproxSizeMB = 56
            ExtractTo    = $osvHome
            ExeFullPath  = [System.IO.Path]::Combine($osvHome, 'osv-scanner.exe')
            AddToUserPath = $osvHome
            VersionArgs  = @('--version')
        }
        DocsUrl        = 'https://github.com/google/osv-scanner/releases'
        Why            = 'Dependency vulnerability scanning at push time. Cheap (reads lockfiles, no build) and every finding carries a CVE/GHSA id and a fixed version.'
    }

    # CodeQL has no winget or choco package - verified 2026-08-04. It must be
    # downloaded and extracted by hand.
    #
    # The URL below is the BUNDLE from github/codeql-action, not the bare CLI
    # from github/codeql-cli-binaries. This distinction is load-bearing: the
    # bare CLI ships no query packs, so `<lang>-code-scanning.qls` fails to
    # resolve and every scan errors out at push time. The bundle is ~700 MB
    # (verified 2026-08-26 against v2.26.3's win64.tar.gz asset; an older note
    # here said ~1.3 GB, which does not match any asset this repo downloads)
    # because it contains every extractor and every query pack.
    #
    # Asset name is codeql-bundle-win64.tar.gz. "windows64" is a 404.
    #
    # Pinned to a specific release tag rather than releases/latest/download/,
    # matching gitleaks and osv-scanner below: verified 2026-08-26 that
    # codeql-bundle-v2.26.3 publishes codeql-bundle-win64.tar.gz.checksum.txt
    # at that same fixed tag (not only under the "latest" alias), so pinning
    # loses nothing and gains a checksum that cannot silently start pointing
    # at a different build under you.
    $tools += @{
        Id             = 'codeql'
        Name           = 'CodeQL CLI (bundle)'
        Command        = 'codeql'
        VersionArgs    = @('version', '--format=terse')
        VersionPattern = '([\d]+\.[\d]+\.[\d]+)'
        TestedVersion  = '2.26.3'
        Required       = $true
        InstallMethod  = 'manual'
        InstallSpec    = @{
            Kind           = 'targz'
            Url            = 'https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.26.3/codeql-bundle-win64.tar.gz'
            ChecksumUrl    = 'https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.26.3/codeql-bundle-win64.tar.gz.checksum.txt'
            ApproxSizeMB   = 700
            ExtractTo      = $toolRoot
            ExeFullPath    = [System.IO.Path]::Combine($codeqlHome, 'codeql.exe')
            AddToUserPath  = $codeqlHome
        }
        DocsUrl        = 'https://github.com/github/codeql-action/releases'
        Why            = 'Static analysis at push time. Also the slowest stage by far (~89% of push wait in the POC).'
    }

    # Check only, never install. Two reasons: most users already have Claude Code,
    # and npm is not necessarily on PATH (it is absent on the POC machine), so
    # an automated `npm install -g` would fail more often than it helped.
    $tools += @{
        Id             = 'claude'
        Name           = 'Claude Code CLI'
        Command        = 'claude'
        VersionArgs    = @('--version')
        VersionPattern = '([\d]+\.[\d]+\.[\d]+)'
        TestedVersion  = '2.1.220'
        Required       = $true
        InstallMethod  = 'none'
        InstallSpec    = $null
        DocsUrl        = 'https://docs.claude.com/en/docs/claude-code'
        # The native installer is listed first deliberately: npm is NOT on PATH
        # on the POC machine, and Claude Code there lives in ~\.local\bin, so
        # npm guidance would fail for the very setup it was written on.
        Why            = 'AI review of the pushed diff. Install manually: irm https://claude.ai/install.ps1 | iex  (or npm install -g @anthropic-ai/claude-code if you have npm)'
    }

    return $tools
}

function Get-LanguageToolchainRegistry {
    <#
    .SYNOPSIS
    Toolchains that do not gate the hooks but silently degrade result quality.

    .DESCRIPTION
    These are the reason this setup exists at all. CodeQL runs with
    --build-mode=none, so it never compiles anything and therefore never hard
    fails when a toolchain is absent - it just extracts less and finds less,
    with a warning buried in several hundred lines of progress output.

    The POC ran with no JDK for its entire duration and only discovered it
    afterwards, which is why every Java recall figure in the findings document
    is a floor rather than an estimate.

    Keyed by CodeQL language name.
    #>

    $toolRoot = Get-ToolRootPath
    $jdkHome  = [System.IO.Path]::Combine($toolRoot, 'jdk')

    $reg = @{}

    # No winget: same checksum-verified GitHub release pattern as gitleaks,
    # osv-scanner and CodeQL - see Install-GithubReleaseAsset. Adoptium
    # publishes to github.com, the same domain those three already need, so
    # this needed no new network allowlisting to move off winget.
    #
    # Unlike gitleaks (flat zip) the archive's root is a VERSIONED FOLDER
    # (jdk-17.0.20.1+1/bin/java.exe, verified 2026-08-26), so ExtractTo is the
    # tool's home dir, not java.exe's immediate parent - see the comment in
    # Install-GithubReleaseAsset explaining why that distinction matters.
    # Bumping the JDK means updating the version string in BOTH the Url and
    # ExeFullPath below, not just one - the folder name inside the archive
    # changes with every release.
    $reg['java'] = @(
        @{
            Id             = 'jdk'
            Name           = 'JDK 17+'
            Command        = 'java'
            VersionArgs    = @('-version')
            VersionPattern = 'version "?([\d\._]+)'
            InstallMethod  = 'manual'
            InstallSpec    = @{
                Kind          = 'zip'
                Url           = 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_x64_windows_hotspot_17.0.20.1_1.zip'
                ChecksumUrl   = 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_x64_windows_hotspot_17.0.20.1_1.zip.sha256.txt'
                ApproxSizeMB  = 182
                ExtractTo     = $jdkHome
                ExeFullPath   = [System.IO.Path]::Combine($jdkHome, 'jdk-17.0.20.1+1', 'bin', 'java.exe')
                AddToUserPath = [System.IO.Path]::Combine($jdkHome, 'jdk-17.0.20.1+1', 'bin')
                VersionArgs   = @('-version')
            }
            Impact         = 'Without a JDK, CodeQL falls back to a minimal bundled JDK and warns that some Java may be wrongly extracted. Findings become a floor, not a clean bill of health.'
        }
    )

    $reg['csharp'] = @(
        @{
            Id             = 'dotnet'
            Name           = '.NET SDK'
            Command        = 'dotnet'
            VersionArgs    = @('--version')
            VersionPattern = '([\d]+\.[\d]+\.[\d]+)'
            InstallMethod  = 'winget'
            InstallSpec    = @{ PackageId = 'Microsoft.DotNet.SDK.8' }
            Impact         = 'Without the .NET SDK, dependency and framework resolution is weaker, so dataflow through libraries is lost.'
        }
    )

    $reg['python'] = @(
        @{
            Id             = 'python-deps'
            Name           = 'Python dependencies installed'
            Command        = 'python'
            VersionArgs    = @('--version')
            VersionPattern = 'Python ([\d\.]+)'
            InstallMethod  = 'none'
            InstallSpec    = $null
            Impact         = 'Without installed dependencies, imports go unresolved and dataflow through third-party libraries is lost.'
        }
    )

    $reg['javascript'] = @(
        @{
            Id             = 'node'
            Name           = 'Node.js'
            Command        = 'node'
            VersionArgs    = @('--version')
            VersionPattern = 'v?([\d]+\.[\d]+\.[\d]+)'
            InstallMethod  = 'winget'
            InstallSpec    = @{ PackageId = 'OpenJS.NodeJS.LTS' }
            Impact         = 'Without node_modules present, TypeScript type resolution is weaker.'
        }
    )

    $reg['go'] = @(
        @{
            Id             = 'go'
            Name           = 'Go toolchain'
            Command        = 'go'
            VersionArgs    = @('version')
            VersionPattern = 'go([\d]+\.[\d]+(\.[\d]+)?)'
            InstallMethod  = 'winget'
            InstallSpec    = @{ PackageId = 'GoLang.Go' }
            Impact         = 'Improves module and dependency resolution.'
        }
    )

    $reg['rust'] = @(
        @{
            Id             = 'cargo'
            Name           = 'Cargo'
            Command        = 'cargo'
            VersionArgs    = @('--version')
            VersionPattern = 'cargo ([\d]+\.[\d]+\.[\d]+)'
            InstallMethod  = 'none'
            InstallSpec    = $null
            Impact         = 'CodeQL wants cargo metadata to resolve crates.'
        }
    )

    return $reg
}

function Get-CommandVersion {
    <#
    .SYNOPSIS
    Runs a version probe and returns @{ Found; Version; Path; Raw }.

    .DESCRIPTION
    Native stderr is folded into stdout because several probes write their
    version there - `java -version` is the notorious one. $ErrorActionPreference
    is forced to Continue for the duration so a caller running under
    "Stop" does not get a terminating error from a tool that merely printed a
    banner to stderr. That trap cost real debugging time during the POC.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$VersionArgs = @(),
        [string]$VersionPattern = '([\d]+\.[\d]+\.[\d]+)'
    )

    $out = [pscustomobject][ordered]@{
        Found   = $false
        Version = $null
        Path    = $null
        Raw     = ''
    }

    $resolved = Get-Command $Command -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandType -ne 'Alias' } |
        Select-Object -First 1

    if (-not $resolved) { return $out }

    $out.Found = $true
    if ($resolved.Path) {
        $out.Path = $resolved.Path
    } else {
        $out.Path = $resolved.Name
    }

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $Command @VersionArgs 2>&1 | Out-String
    } catch {
        $raw = ''
    } finally {
        $ErrorActionPreference = $prev
    }

    $out.Raw = $raw.Trim()
    if ($out.Raw -match $VersionPattern) {
        $out.Version = $Matches[1]
    }

    return $out
}

function Test-ToolStatus {
    <#
    .SYNOPSIS
    Evaluates one registry entry and returns a status record.

    .OUTPUTS
    status is one of:
      OK      - present, version readable
      PARTIAL - on PATH but the version probe produced nothing parseable
      MISSING - not on PATH
    #>
    param([Parameter(Mandatory = $true)]$Tool)

    $probe = Get-CommandVersion -Command $Tool.Command `
        -VersionArgs $Tool.VersionArgs `
        -VersionPattern $Tool.VersionPattern

    $status = 'MISSING'
    if ($probe.Found -and $probe.Version) {
        $status = 'OK'
    } elseif ($probe.Found) {
        $status = 'PARTIAL'
    }

    $installable = $false
    if ($Tool.InstallMethod -ne 'none') { $installable = $true }

    # pscustomobject rather than a hashtable: Format-Table cannot see dictionary
    # keys as properties, so a hashtable renders as headers with blank rows.
    return [pscustomobject][ordered]@{
        id            = $Tool.Id
        name          = $Tool.Name
        command       = $Tool.Command
        status        = $status
        version       = $probe.Version
        path          = $probe.Path
        testedVersion = $Tool.TestedVersion
        required      = [bool]$Tool.Required
        installMethod = $Tool.InstallMethod
        installable   = $installable
        docsUrl       = $Tool.DocsUrl
        why           = $Tool.Why
    }
}

function Get-AllToolStatus {
    <#
    .SYNOPSIS
    Status record for every tool in the registry, in registry order.
    #>
    $results = @()
    foreach ($tool in Get-ToolRegistry) {
        $results += Test-ToolStatus -Tool $tool
    }
    return $results
}
