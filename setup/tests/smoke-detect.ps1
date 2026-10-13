# Smoke test for lib/detect.ps1. Read-only: creates no CodeQL databases.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\tools.ps1')
. (Join-Path $PSScriptRoot '..\lib\detect.ps1')

$root = Get-RepoRoot -StartPath $PSScriptRoot
Write-Host "=== Repo root: $root ===" -ForegroundColor Cyan

Write-Host "=== CodeQL home: $(Get-CodeQLHome) ===" -ForegroundColor Cyan

Write-Host '=== Build modes read from extractor manifests ===' -ForegroundColor Cyan
foreach ($lang in @('java', 'go', 'cpp', 'swift', 'rust', 'python', 'csharp')) {
    $modes = Get-ExtractorBuildModes -Language $lang
    $none  = 'no'
    if ($modes -contains 'none') { $none = 'YES' }
    Write-Host ("  {0,-12} buildless={1,-4} modes=[{2}]" -f $lang, $none, ($modes -join ', '))
}

Write-Host '=== Repo language inventory (git-tracked) ===' -ForegroundColor Cyan
$inv = Get-RepoLanguageInventory -RepoRoot $root
foreach ($k in ($inv.Keys | Sort-Object)) { Write-Host ("  {0,-12} {1} files" -f $k, $inv[$k]) }

Write-Host '=== Build system markers ===' -ForegroundColor Cyan
$bm = Get-BuildSystemMarkers -RepoRoot $root
foreach ($k in ($bm.Keys | Sort-Object)) { Write-Host ("  {0,-12} {1}" -f $k, ($bm[$k] -join ', ')) }

Write-Host '=== Language profile (the headline output) ===' -ForegroundColor Cyan
$profiles = Get-LanguageProfile -RepoRoot $root
$profiles | Format-Table language, fileCount, status -AutoSize
foreach ($p in $profiles) {
    Write-Host "  [$($p.language)] status=$($p.status)"
    foreach ($r in $p.reasons) { Write-Host "     - $r" -ForegroundColor DarkGray }
    foreach ($m in $p.missingToolchain) { Write-Host "     missing: $($m.name) via $($m.installMethod) $($m.packageId)" -ForegroundColor Yellow }
}

Write-Host '=== JSON round-trip ===' -ForegroundColor Cyan
# Not piped: PowerShell 5.1's ConvertFrom-Json emits a deserialized array as a
# single pipeline object, so `@($json | ConvertFrom-Json).Count` reports 1
# regardless of how many entries there are.
#
# An empty profile list is a legitimate result, not a failure: this repository is
# PowerShell and Markdown, so it contains no CodeQL-supported source at all. Guard
# for it, because ConvertTo-Json on an empty array yields $null and
# ConvertFrom-Json then throws on a null InputObject - which reads as a detect.ps1
# fault when it is really "there was nothing to serialise".
if (@($profiles).Count -eq 0) {
    Write-Host '  no supported languages in this repo, so nothing to round-trip (this is a valid result)' -ForegroundColor DarkGray
} else {
    $json = $profiles | ConvertTo-Json -Depth 6
    $back = ConvertFrom-Json $json
    Write-Host "  profiles parsed back: $(@($back).Count)"
    if (@($back).Count -ne @($profiles).Count) { throw "JSON round-trip lost entries: $(@($back).Count) vs $(@($profiles).Count)" }
}

Write-Host '=== Dependency ecosystems and offline database ===' -ForegroundColor Cyan
$osvDb = Get-OsvDatabaseStatus -RepoRoot $root
Write-Host "  expected: [$(@($osvDb.expected) -join ', ')]"
Write-Host "  present : [$(@($osvDb.present)  -join ', ')]"
Write-Host "  missing : [$(@($osvDb.missing)  -join ', ')]"
if (@($osvDb.missing).Count -gt 0) {
    Write-Host '  (missing entries are ecosystems the osv hook would exit 127 on)' -ForegroundColor Yellow
}

Write-Host '=== Suite availability for detected languages ===' -ForegroundColor Cyan
foreach ($p in $profiles) {
    $suites = Get-AvailableQuerySuites -Language $p.language
    foreach ($k in @('code-scanning', 'security-and-quality')) {
        $s = $suites[$k]
        Write-Host ("  {0,-40} resolves={1,-5} queries={2}" -f $s.suite, $s.resolves, $s.queryCount)
    }
}

Write-Host 'SMOKE OK' -ForegroundColor Green
