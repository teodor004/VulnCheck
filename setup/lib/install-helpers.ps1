# install-helpers.ps1 - the two operations that actually change the machine.
#
# Kept out of install.ps1 so they can be tested in isolation and so doctor.ps1
# never has them in scope at all.
#
# Targets Windows PowerShell 5.1.

Set-StrictMode -Version Latest

function Get-Sha256Hex {
    <#
    .SYNOPSIS
    Lowercase hex SHA-256 of a file.

    .DESCRIPTION
    Deliberately NOT Get-FileHash. Verified 2026-08-17 on the target platform
    (Windows PowerShell 5.1.26100.8875, FullLanguage mode): Get-FileHash is not
    available even though Microsoft.PowerShell.Utility is present on disk and
    other cmdlets from the same module resolve fine. Import-Module -Force does
    not bring it back, so this is an environment restriction rather than a
    broken profile, and it cannot be worked around by importing.

    That matters because one caller uses this to verify the published checksum
    of the downloaded CodeQL bundle. Dropping the check when the cmdlet is
    missing would silently turn a verified download into an unverified one, so
    the hash moves to the .NET API instead of becoming optional.

    Returns lowercase hex to match the format published in the upstream
    .sha256sum files, so callers can compare without re-normalising.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $sha    = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $bytes = $sha.ComputeHash($stream)
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Install-CodeQLBundle {
    <#
    .SYNOPSIS
    Downloads, verifies, extracts the CodeQL bundle and adds it to user PATH.

    .DESCRIPTION
    Uses curl.exe and tar.exe from System32 rather than PowerShell cmdlets:

    - Invoke-WebRequest in PowerShell 5.1 buffers the whole response in memory
      before writing it. For a ~700 MB download that is a real problem. curl.exe
      streams to disk and prints a progress bar for free.
    - Expand-Archive does not handle .tar.gz at all. tar.exe (bsdtar) does.

    Both have shipped in Windows since 1803, and were verified present on the
    POC machine.

    Verifies the SHA256 published alongside the asset. This is a security tool
    being installed to gate a security review; taking the download on trust
    would be an odd place to stop caring.
    #>
    param(
        [Parameter(Mandatory = $true)]$Spec,
        [switch]$AllowUnverified
    )

    $extractTo = $Spec.ExtractTo
    $url       = $Spec.Url
    $exePath   = $Spec.ExeFullPath

    $curl = [System.IO.Path]::Combine($env:SystemRoot, 'System32', 'curl.exe')
    $tar  = [System.IO.Path]::Combine($env:SystemRoot, 'System32', 'tar.exe')
    foreach ($needed in @($curl, $tar)) {
        if (-not (Test-Path -LiteralPath $needed)) {
            throw "$needed not found. It ships with Windows 1803 and later; this machine cannot download or extract the bundle without it."
        }
    }

    if (-not (Test-Path -LiteralPath $extractTo)) {
        New-Item -ItemType Directory -Path $extractTo -Force | Out-Null
    }

    # Refuse to extract over an existing install rather than merging two
    # versions' files into one directory.
    $codeqlDir = [System.IO.Path]::Combine($extractTo, 'codeql')
    if (Test-Path -LiteralPath $codeqlDir) {
        throw "$codeqlDir already exists. Remove or rename it first - extracting on top of an existing bundle mixes versions."
    }

    $archive  = [System.IO.Path]::Combine($env:TEMP, 'codeql-bundle-win64.tar.gz')
    $checksum = "$url.checksum.txt"

    Write-Host "     downloading ~$($Spec.ApproxSizeMB) MB (this takes a while)..." -ForegroundColor DarkGray

    # -L follows GitHub's redirect to its asset CDN; -f turns HTTP errors into a
    # nonzero exit instead of a saved error page; -C - resumes a partial file.
    & $curl -L -f -C - --retry 3 --retry-delay 2 -o $archive $url
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed (curl exit $LASTEXITCODE). The partial file at $archive can be resumed by re-running."
    }

    Write-Host '     verifying checksum...' -ForegroundColor DarkGray
    $expected = $null
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $checksumText = & $curl -L -f -s $checksum
        $checksumOk   = ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }

    if ($checksumOk -and $checksumText) {
        # Format is "<sha256>  <filename>".
        $line = @($checksumText)[0]
        if ($line -match '([0-9a-fA-F]{64})') { $expected = $Matches[1].ToLowerInvariant() }
    }

    if ($expected) {
        $actual = Get-Sha256Hex -Path $archive
        if ($actual -ne $expected) {
            Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
            throw "Checksum mismatch. Expected $expected but got $actual. The download was deleted; do not use it."
        }
        Write-Host '     checksum OK' -ForegroundColor DarkGray
    } elseif ($AllowUnverified) {
        # A proxy blocking the checksum file is a real, seen scenario, so this
        # stays an escape hatch rather than an unconditional wall - but it must
        # be asked for explicitly (-AllowUnverifiedDownload on install.ps1), not
        # the silent default. Flagged 2026-08-26: warn-then-execute-anyway with
        # no way to say no is a fail-open path into running an unverified binary,
        # for a security tool's own bootstrap - worth catching before the
        # blocking tripled from one tool to three.
        Write-Host '     WARNING: could not fetch the published checksum. Proceeding UNVERIFIED because -AllowUnverifiedDownload was given.' -ForegroundColor Yellow
    } else {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
        throw "Could not verify the published checksum for $([System.IO.Path]::GetFileName($archive)), so it was deleted rather than installed and run unverified. Re-run with -AllowUnverifiedDownload if a proxy is known to block $checksum."
    }

    Write-Host "     extracting to $extractTo ..." -ForegroundColor DarkGray
    # The archive already contains a top-level codeql/ directory, so extracting
    # into C:\tools produces C:\tools\codeql - do not add another level.
    & $tar -xzf $archive -C $extractTo
    if ($LASTEXITCODE -ne 0) { throw "Extraction failed (tar exit $LASTEXITCODE)." }

    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "Extraction finished but $exePath is missing. The archive layout was not what was expected."
    }

    Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue

    Add-ToUserPath -Directory $Spec.AddToUserPath

    # Verify via the absolute path, because the PATH change is invisible to this
    # process and every child it spawns.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $version = & $exePath version --format=terse 2>&1
    } finally {
        $ErrorActionPreference = $prev
    }
    Write-Host "     installed CodeQL $version" -ForegroundColor DarkGray

    # The single most common misinstall: bare CLI instead of bundle. Catch it
    # here, at install time, rather than at push time three minutes in.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $null = & $exePath resolve queries 'java-code-scanning.qls' 2>&1
        $resolveOk = ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }
    if (-not $resolveOk) {
        throw 'CodeQL installed but java-code-scanning.qls does not resolve, which means this download has no query packs. Was the bare codeql-cli-binaries archive used instead of the bundle?'
    }
    Write-Host '     query packs verified' -ForegroundColor DarkGray
}

function Get-ChecksumFromFile {
    <#
    .SYNOPSIS
    Finds the SHA-256 for one filename inside a published checksums file.

    .DESCRIPTION
    gitleaks and osv-scanner both publish a single file covering every
    platform's asset ("<hash>  <filename>", one line per asset, optionally
    "<hash> *<filename>" in binary mode) rather than CodeQL's one-line-per-asset
    file. Matching by filename, not "take the first hash", is required here -
    unlike the CodeQL caller, this file has ten lines and nine of them are for
    the wrong platform.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    foreach ($line in ($Content -split "`r?`n")) {
        $line = $line.Trim()
        if (-not $line) { continue }
        if ($line -match ('^([0-9a-fA-F]{64})\s+\*?' + [regex]::Escape($FileName) + '\s*$')) {
            return $Matches[1].ToLowerInvariant()
        }
    }
    return $null
}

function Install-GithubReleaseAsset {
    <#
    .SYNOPSIS
    Downloads one asset from a GitHub release, verifies its published SHA-256,
    then either extracts it (zip) or places it directly (a bare .exe).

    .DESCRIPTION
    Replaces winget for gitleaks and osv-scanner: both ship a Windows asset
    plus a published checksum, so the same download-then-verify shape
    Install-CodeQLBundle already uses for the CodeQL bundle applies here too -
    only the archive format and the checksum file's layout differ, which is
    what $Spec.Kind selects between.

    Pinned to a specific release tag, not "latest" - a checksum verified
    against a moving target is not a real verification, it just shifts which
    silent build you trust.
    #>
    param(
        [Parameter(Mandatory = $true)]$Spec,
        [switch]$AllowUnverified
    )

    $curl = [System.IO.Path]::Combine($env:SystemRoot, 'System32', 'curl.exe')
    if (-not (Test-Path -LiteralPath $curl)) {
        throw "$curl not found. It ships with Windows 1803 and later; this machine cannot download the asset without it."
    }

    $exeFullPath = $Spec.ExeFullPath
    $destDir     = [System.IO.Path]::GetDirectoryName($exeFullPath)

    # For a flat zip (gitleaks: the .exe sits at the archive root) or a bare
    # .exe (osv-scanner: no archive at all), the exe's own parent directory IS
    # the correct extraction/placement target. For an archive whose root is a
    # versioned FOLDER (JDK: OpenJDK17U-*.zip contains jdk-17.0.20.1+1/bin/
    # java.exe), extracting to the exe's parent would double that folder -
    # Spec.ExtractTo names the directory that should contain the archive's
    # top-level entries, which for JDK is the tool's home dir, several levels
    # above $exeFullPath. Falls back to $destDir so gitleaks/osv-scanner, which
    # never set ExtractTo to anything else, need no change.
    $extractDir = if ($Spec.ExtractTo) { $Spec.ExtractTo } else { $destDir }

    # Refuse to install over an existing copy rather than mixing two versions'
    # files into one directory - the same rule Install-CodeQLBundle enforces.
    if (Test-Path -LiteralPath $exeFullPath) {
        throw "$exeFullPath already exists. Remove it first - installing on top of an existing binary mixes versions."
    }
    if ($Spec.Kind -eq 'zip') {
        if (-not (Test-Path -LiteralPath $extractDir)) {
            New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
        }
    } elseif (-not (Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    $assetName = [System.IO.Path]::GetFileName($Spec.Url)
    $download  = [System.IO.Path]::Combine($env:TEMP, $assetName)

    Write-Host "     downloading $assetName ..." -ForegroundColor DarkGray
    & $curl -L -f -C - --retry 3 --retry-delay 2 -o $download $Spec.Url
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed (curl exit $LASTEXITCODE) for $($Spec.Url). The partial file at $download can be resumed by re-running."
    }

    Write-Host '     verifying checksum...' -ForegroundColor DarkGray
    $expected = $null
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $checksumText = & $curl -L -f -s $Spec.ChecksumUrl
        $checksumOk   = ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }

    if ($checksumOk -and $checksumText) {
        $expected = Get-ChecksumFromFile -Content ([string]($checksumText -join "`n")) -FileName $assetName
    }

    if ($expected) {
        $actual = Get-Sha256Hex -Path $download
        if ($actual -ne $expected) {
            Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
            throw "Checksum mismatch for $assetName. Expected $expected but got $actual. The download was deleted; do not use it."
        }
        Write-Host '     checksum OK' -ForegroundColor DarkGray
    } elseif ($AllowUnverified) {
        Write-Host "     WARNING: could not find $assetName in the published checksum file. Proceeding UNVERIFIED because -AllowUnverifiedDownload was given." -ForegroundColor Yellow
    } else {
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
        throw "Could not verify the published checksum for $assetName, so it was deleted rather than installed and run unverified. Re-run with -AllowUnverifiedDownload if a proxy is known to block $($Spec.ChecksumUrl)."
    }

    if ($Spec.Kind -eq 'zip') {
        Write-Host "     extracting to $extractDir ..." -ForegroundColor DarkGray
        Expand-Archive -LiteralPath $download -DestinationPath $extractDir -Force
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
    } elseif ($Spec.Kind -eq 'exe') {
        # No archive - the release asset IS the executable, just not named what
        # the hooks expect it to be called on PATH (e.g. osv-scanner_windows_
        # amd64.exe, not osv-scanner.exe).
        Move-Item -LiteralPath $download -Destination $exeFullPath -Force
    } else {
        throw "Unknown Spec.Kind '$($Spec.Kind)' - expected 'zip' or 'exe'."
    }

    if (-not (Test-Path -LiteralPath $exeFullPath)) {
        throw "Install finished but $exeFullPath is missing. The archive layout was not what was expected."
    }

    Add-ToUserPath -Directory $destDir

    # Verify via the absolute path, because the PATH change is invisible to this
    # process and every child it spawns.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $version = & $exeFullPath @($Spec.VersionArgs) 2>&1 | Out-String
    } finally {
        $ErrorActionPreference = $prev
    }
    Write-Host "     installed: $($version.Trim())" -ForegroundColor DarkGray
}

function Add-ToUserPath {
    <#
    .SYNOPSIS
    Appends a directory to the persistent user PATH, if not already present.

    .DESCRIPTION
    User scope, not Machine: no elevation needed, and it only affects the person
    running setup. The POC machine's shell was non-admin.

    The change does NOT apply to the current process or any child of it. Windows
    reads environment variables at process start, so a new terminal is required.
    Callers must say so out loud.
    #>
    param([Parameter(Mandatory = $true)][string]$Directory)

    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $current) { $current = '' }

    $entries = @($current -split ';' | Where-Object { $_ })
    $already = $false
    foreach ($e in $entries) {
        if ($e.TrimEnd('\') -ieq $Directory.TrimEnd('\')) { $already = $true; break }
    }

    if ($already) {
        Write-Host "     $Directory already on user PATH" -ForegroundColor DarkGray
        return
    }

    $new = $current
    if ($new -and -not $new.EndsWith(';')) { $new += ';' }
    $new += $Directory

    [Environment]::SetEnvironmentVariable('Path', $new, 'User')
    Write-Host "     added $Directory to user PATH" -ForegroundColor DarkGray

    # Also patch this process so later verification steps in the same run work.
    $env:Path = "$env:Path;$Directory"
}

function Write-SecurityProfile {
    <#
    .SYNOPSIS
    Writes .hooks/security-profile.json, the manifest the hooks read at runtime.

    .DESCRIPTION
    This file is why the hooks can warn about degraded analysis instead of
    silently under-reporting. It records what setup found, so the hooks do not
    have to re-derive it on every push.

    UTF8 without BOM: PowerShell 5.1's Out-File -Encoding utf8 writes a BOM,
    and a BOM ahead of the opening brace breaks some JSON parsers. Written via
    .NET so the encoding is explicit rather than context-dependent - the `>`
    redirect produced UTF-16LE in a real hook run during the POC.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Profiles,
        [Parameter(Mandatory = $true)][string]$QuerySuite,
        [bool]$BlockCodeql = $false,
        [bool]$BlockClaude = $false,
        [bool]$BlockOsv = $false,
        [double]$BudgetUsd = 1.00,
        [int]$MaxTurns = 5
    )

    $langs = @()
    foreach ($p in @($Profiles)) {
        $langs += [pscustomobject][ordered]@{
            language   = $p.language
            status     = $p.status
            fileCount  = $p.fileCount
            buildModes = @($p.buildModes)
            reasons    = @($p.reasons)
        }
    }

    $obj = [pscustomobject][ordered]@{
        generatedAt   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        generatedBy   = 'setup/install.ps1'
        querySuite    = $QuerySuite
        blocking      = [pscustomobject][ordered]@{
            codeql = $BlockCodeql
            claude = $BlockClaude
            osv    = $BlockOsv
        }
        claude        = [pscustomobject][ordered]@{
            maxBudgetUsd = $BudgetUsd
            maxTurns     = $MaxTurns
            allowedTools = 'Read'
        }
        languages     = @($langs)
        note          = 'Written by setup/install.ps1. Re-run setup/doctor.ps1 after installing a toolchain so DEGRADED statuses refresh.'
    }

    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $json = ConvertTo-Json $obj -Depth 8
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}
