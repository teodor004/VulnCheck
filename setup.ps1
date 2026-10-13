# Shift-Left Security - Setup script
# Installs the setup-security-hooks and compliance-audit Claude Code skills to
# ~/.claude/skills/, AND bundles the setup/ scripts (install.ps1, doctor.ps1,
# the hook templates) inside setup-security-hooks' own folder, so the skill has
# everything it needs on first trigger - no separate "go clone VulnCheck"
# step for the common case of "I just ran this script".
#
# Layout follows the Claude Code plugin convention (plugins/<name>/skills/<skill>)
# with a git-sparse-clone-or-ZIP fallback, so the plugin can also be installed
# by any tool that understands that layout.
#
# Usage:
#   .\setup.ps1                     # auto-detects git or falls back to ZIP download

param()

# The repo the skills and setup/ scripts are fetched from.
$repoHost  = "github.com"
$repoOrg   = "teodor004"
$repoName  = "VulnCheck"
$branch    = "main"
$skillsDir = "$env:USERPROFILE\.claude\skills"
$tmpDir    = "$env:TEMP\shift-left-security-setup"
$skillsSubpath = "plugins\shift-left-security\skills"
$setupSubpath  = "setup"
# Nested inside the already-installed skill's own folder, not a separate fixed
# path: it means "re-run setup.ps1" is also "refresh the bundled setup/ copy",
# with no second update mechanism to keep in sync.
$bundledSetupDir = "$skillsDir\setup-security-hooks\setup"

Write-Host "Installing Shift-Left Security skills..." -ForegroundColor Cyan

if (-not (Test-Path $skillsDir)) { New-Item -ItemType Directory -Path $skillsDir -Force | Out-Null }
if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }

# -- Choose download method ---------------------------------------------------

$gitAvailable = $null -ne (Get-Command git -ErrorAction SilentlyContinue)

if ($gitAvailable) {
    Write-Host "Using git (sparse clone)..." -ForegroundColor Gray
    $cloneUrl = "https://$repoHost/$repoOrg/$repoName.git"
    git clone --depth 1 --branch $branch --filter=blob:none --sparse $cloneUrl $tmpDir | Out-Null
    Push-Location $tmpDir
    # Both paths in one sparse-checkout call - the skills AND the setup/
    # scripts they wrap, fetched together so they can be verified and copied
    # as one step below.
    git sparse-checkout set $skillsSubpath $setupSubpath | Out-Null
    Pop-Location
    $skillsSource = "$tmpDir\$skillsSubpath"
    $setupSource  = "$tmpDir\$setupSubpath"
}
else {
    Write-Host "git not found - using ZIP download..." -ForegroundColor Gray
    # The repo is public, so the archive needs no token. Integrity is still
    # checked below against the committed manifests, same as the git path.
    $zipPath = "$env:TEMP\$repoName.zip"
    $zipUrl  = "https://$repoHost/$repoOrg/$repoName/archive/refs/heads/$branch.zip"
    Invoke-WebRequest $zipUrl -OutFile $zipPath -UseBasicParsing
    Expand-Archive $zipPath $tmpDir -Force
    Remove-Item $zipPath -Force
    # A full-repo ZIP already contains setup/ - no second fetch needed here.
    $skillsSource = "$tmpDir\$repoName-$branch\$skillsSubpath"
    $setupSource  = "$tmpDir\$repoName-$branch\$setupSubpath"
}

# -- Verify integrity ---------------------------------------------------------
#
# CWE-494 (Download of Code Without Integrity Check). checksums.sha256 is
# committed alongside each payload it covers, so a tampered download - or a
# tampered git remote - is caught before anything gets copied somewhere it
# will be run from. setup/ gets its own manifest, checked the same way as the
# skills: it is executable PowerShell being installed onto the machine too,
# not a lesser payload just because it is not under ~/.claude/skills/.

function Test-ChecksumManifest {
    param([Parameter(Mandatory = $true)][string]$Source, [Parameter(Mandatory = $true)][string]$Label)

    $checksumFile = "$Source\checksums.sha256"
    if (-not (Test-Path $checksumFile)) {
        Write-Error "checksums.sha256 not found in the downloaded $Label payload - aborting."; exit 1
    }
    $failed = @()
    Get-Content $checksumFile | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) { return }
        $parts = $_ -split '  ', 2
        $expected = $parts[0]; $relPath = $parts[1]
        $fullPath = "$Source\$($relPath -replace '/', '\')"
        if (-not (Test-Path $fullPath)) { $failed += $relPath; return }
        $actual = (Get-FileHash $fullPath -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected) { $failed += $relPath }
    }
    if ($failed.Count -gt 0) {
        Write-Error "Integrity check FAILED for $Label - $($failed -join ', ') - aborting install."
        exit 1
    }
    Write-Host "Integrity verified: $Label." -ForegroundColor Gray
}

Test-ChecksumManifest -Source $skillsSource -Label 'skills'
Test-ChecksumManifest -Source $setupSource  -Label 'setup scripts'

# -- Install skills ------------------------------------------------------------

Get-ChildItem $skillsSource -Directory | ForEach-Object {
    $dest = "$skillsDir\$($_.Name)"
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    Copy-Item $_.FullName $dest -Recurse
    Write-Host "  Installed: $($_.Name)" -ForegroundColor Green
}

# -- Bundle setup/ inside setup-security-hooks' own folder --------------------

if (Test-Path "$skillsDir\setup-security-hooks") {
    if (Test-Path $bundledSetupDir) { Remove-Item $bundledSetupDir -Recurse -Force }
    Copy-Item $setupSource $bundledSetupDir -Recurse
    Write-Host "  Installed: setup/ scripts (bundled with setup-security-hooks)" -ForegroundColor Green
}

# Cleanup
Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done. Restart Claude Code and run /skills to verify." -ForegroundColor Green

# Deterministic, not left to the model to remember to mention: installing the
# skill changes nothing about any repo by itself. Without this, a user who
# doesn't already know to ask about it would have no reason to ever trigger
# setup-security-hooks, and the skill would sit installed but unused.
if (Test-Path "$skillsDir\setup-security-hooks") {
    Write-Host ""
    Write-Host "Next step - this installed a SKILL, not the hooks. No repo is protected yet." -ForegroundColor Cyan
    Write-Host "To turn the hooks on for a repo, open Claude Code inside it and say:" -ForegroundColor Cyan
    Write-Host "  set up the security hooks in this repo" -ForegroundColor White
    Write-Host "(that phrase triggers setup-security-hooks; asking why a push was blocked works too)." -ForegroundColor DarkGray
}
