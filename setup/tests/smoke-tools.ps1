# Smoke test for lib/tools.ps1. Read-only: probes tools, installs nothing.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\tools.ps1')

Write-Host '=== Tool status ===' -ForegroundColor Cyan
Get-AllToolStatus | Format-Table id, status, version, testedVersion, installMethod -AutoSize

Write-Host "=== Default tool root: $(Get-ToolRootPath) ===" -ForegroundColor Cyan

Write-Host '=== SECURITY_TOOL_ROOT override ===' -ForegroundColor Cyan
$env:SECURITY_TOOL_ROOT = 'D:\alt'
$codeql = Get-ToolRegistry | Where-Object { $_.Id -eq 'codeql' }
Write-Host "  root      : $(Get-ToolRootPath)"
Write-Host "  exe       : $($codeql.InstallSpec.ExeFullPath)"
Write-Host "  pathEntry : $($codeql.InstallSpec.AddToUserPath)"
Remove-Item Env:\SECURITY_TOOL_ROOT
Write-Host "  restored  : $(Get-ToolRootPath)"

Write-Host '=== JSON round-trip (the skill contract) ===' -ForegroundColor Cyan
$json = Get-AllToolStatus | ConvertTo-Json -Depth 4
$back = $json | ConvertFrom-Json
Write-Host "  entries parsed back: $($back.Count)"
Write-Host "  first id: $($back[0].id), status: $($back[0].status)"

Write-Host '=== Toolchain registry ===' -ForegroundColor Cyan
$tc = Get-LanguageToolchainRegistry
foreach ($lang in ($tc.Keys | Sort-Object)) {
    Write-Host "  $lang -> $(($tc[$lang] | ForEach-Object { $_.Id }) -join ', ')"
}

Write-Host 'SMOKE OK' -ForegroundColor Green
