<#
.SYNOPSIS
Exercises the setup user flow end to end without installing anything.

.DESCRIPTION
Creates throwaway git repositories under $env:TEMP and runs doctor.ps1 and
install.ps1 against them. Verifies the behaviours that matter and that are easy
to break:

  1. doctor.ps1 outside a git repo fails cleanly rather than crashing
  2. doctor.ps1 on a fresh repo reports NOT_READY with real blockers
  3. doctor.ps1 -Json is parseable and complete in every scenario
  4. install.ps1 -DryRun changes nothing at all
  5. install.ps1 actually wires a fresh repo (config, hooks, manifest)
  6. install.ps1 is idempotent - a second run plans nothing
  7. install.ps1 REFUSES to overwrite a foreign .pre-commit-config.yaml
  8. the written manifest reflects the chosen options
  9. per-language status is correct for java (degraded), go and swift (skipped)

No tool is installed and no CodeQL database is created. -SkipToolInstall is
passed everywhere, so the run is safe on any machine.
#>
[CmdletBinding()]
param([switch]$KeepArtifacts)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SetupDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Doctor   = Join-Path $SetupDir 'doctor.ps1'
$Install  = Join-Path $SetupDir 'install.ps1'

$script:Pass = 0
$script:Fail = 0
$script:Failures = @()

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ''
    Write-Host "TEST: $Name" -ForegroundColor Cyan
    try {
        & $Body
        Write-Host "  PASS" -ForegroundColor Green
        $script:Pass++
    } catch {
        Write-Host "  FAIL: $_" -ForegroundColor Red
        $script:Fail++
        $script:Failures += "$Name : $_"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ("$Expected" -ne "$Actual") { throw "$Message (expected '$Expected', got '$Actual')" }
}

function New-ScratchRepo {
    param([string]$Name, [switch]$WithJava, [switch]$WithGo, [switch]$WithSwift)

    $path = [System.IO.Path]::Combine($env:TEMP, "security-test-$Name")
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    New-Item -ItemType Directory -Path $path -Force | Out-Null

    Push-Location $path
    try {
        & git init --quiet 2>$null | Out-Null
        & git config user.email 'test@example.invalid' 2>$null | Out-Null
        & git config user.name  'Security Test'          2>$null | Out-Null

        Set-Content -LiteralPath (Join-Path $path 'README.md') -Value '# scratch'

        if ($WithJava) {
            $src = [System.IO.Path]::Combine($path, 'src', 'main', 'java')
            New-Item -ItemType Directory -Path $src -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $src 'App.java') -Value 'public class App { }'
            Set-Content -LiteralPath (Join-Path $path 'build.gradle') -Value "plugins { id 'java' }"
        }
        if ($WithGo) {
            Set-Content -LiteralPath (Join-Path $path 'main.go') -Value 'package main'
            Set-Content -LiteralPath (Join-Path $path 'go.mod')  -Value 'module scratch'
        }
        if ($WithSwift) {
            Set-Content -LiteralPath (Join-Path $path 'main.swift') -Value 'print("hi")'
        }

        & git add -A 2>$null | Out-Null
        & git commit -m 'initial' --quiet 2>$null | Out-Null
    } finally { Pop-Location }

    return $path
}

function Invoke-Doctor {
    param([string]$Repo, [switch]$Json)
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Doctor, '-RepoRoot', $Repo)
    if ($Json) { $args += '-Json' }
    $out = & powershell @args 2>&1 | Out-String
    return [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
}

function Invoke-Install {
    param([string]$Repo, [string[]]$ExtraArgs = @())
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Install,
              '-RepoRoot', $Repo, '-SkipToolInstall') + $ExtraArgs
    $out = & powershell @args 2>&1 | Out-String
    return [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
}

Write-Host '=========================================='
Write-Host ' Setup user flow test (installs nothing)'
Write-Host '=========================================='

$repos = @()

# --- 1. Not a git repo ------------------------------------------------------

Test-Case 'doctor.ps1 outside a git repository fails cleanly' {
    $tmp = [System.IO.Path]::Combine($env:TEMP, 'security-test-notarepo')
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Push-Location $tmp
    try {
        # -RepoRoot is deliberately omitted so detection has to fail on its own.
        #
        # -File, not -Command. `powershell -Command "& script.ps1"` collapses the
        # script's exit code to 1, so an earlier version of this test read 1 and
        # blamed doctor.ps1 for a defect in the harness. -File propagates the
        # real code, and is how the skill and the README invoke it anyway. The
        # child inherits this process's cwd, which is what puts it outside a repo.
        $out  = & powershell -NoProfile -ExecutionPolicy Bypass -File $Doctor 2>&1 | Out-String
        $code = $LASTEXITCODE
        Assert-Equal 2 $code 'exit code should be 2'
        Assert-True ($out -match 'Not inside a git repository') 'should say it is not in a git repo'
        Assert-True ($out -notmatch 'Exception|StackTrace') 'should not leak a raw exception'
    } finally {
        Pop-Location
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- 2. Fresh repo, nothing wired ------------------------------------------

$fresh = New-ScratchRepo -Name 'fresh' -WithJava
$repos += $fresh

Test-Case 'doctor.ps1 on an unwired repo reports NOT_READY with blockers' {
    $r = Invoke-Doctor -Repo $fresh
    Assert-Equal 2 $r.ExitCode 'exit code should be 2 (not ready)'
    Assert-True ($r.Output -match 'NOT READY') 'should report NOT READY'
    Assert-True ($r.Output -match 'pre-commit-config\.yaml is missing') 'should flag the missing config'
    Assert-True ($r.Output -match 'secret scanning will not run|No pre-commit hook shim') 'should flag the missing pre-commit shim'
    Assert-True ($r.Output -match 'setup-security-hooks|install\.ps1') 'should point at the fix'
}

Test-Case 'doctor.ps1 -Json is parseable and complete on an unwired repo' {
    $r = Invoke-Doctor -Repo $fresh -Json
    $j = ConvertFrom-Json $r.Output
    Assert-Equal 'NOT_READY' $j.readiness 'readiness'
    Assert-Equal 2 $j.exitCode 'exitCode field should match the process exit code'
    Assert-Equal 2 $r.ExitCode 'process exit code'
    Assert-True (@($j.tools).Count -ge 5) 'should report all tools'
    Assert-True (@($j.blockers).Count -ge 2) 'should list blockers'
    Assert-True ($j.hooks.wired -eq $false) 'hooks.wired should be false'
    # Every language entry must carry the fields the skill reads.
    foreach ($l in @($j.languages)) {
        Assert-True ($null -ne $l.language) 'language name present'
        Assert-True ($l.status -in @('OK','DEGRADED','NEEDS_BUILD','UNSUPPORTED')) "unexpected status '$($l.status)'"
    }
}

# --- 3. Dry run must not touch anything ------------------------------------

Test-Case 'install.ps1 -DryRun changes nothing' {
    $before = @(Get-ChildItem -LiteralPath $fresh -Recurse -Force |
        Where-Object { $_.FullName -notmatch '\\\.git\\' } |
        ForEach-Object { $_.FullName }) | Sort-Object

    $r = Invoke-Install -Repo $fresh -ExtraArgs @('-DryRun')
    Assert-Equal 0 $r.ExitCode 'dry run should exit 0'
    Assert-True ($r.Output -match 'DRY RUN') 'should announce dry run'
    Assert-True ($r.Output -match 'Nothing was changed') 'should confirm nothing changed'

    $after = @(Get-ChildItem -LiteralPath $fresh -Recurse -Force |
        Where-Object { $_.FullName -notmatch '\\\.git\\' } |
        ForEach-Object { $_.FullName }) | Sort-Object

    Assert-Equal ($before -join '|') ($after -join '|') 'file list must be unchanged'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $fresh '.pre-commit-config.yaml'))) 'config must not exist'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $fresh '.hooks'))) '.hooks must not exist'
}

# --- 4. Real install on a scratch repo -------------------------------------

Test-Case 'install.ps1 wires a fresh repo' {
    $r = Invoke-Install -Repo $fresh -ExtraArgs @('-Yes', '-Blocking', 'codeql', '-ClaudeBudgetUsd', '0.5')
    Write-Host ($r.Output -split "`n" | Select-Object -Last 25 | Out-String) -ForegroundColor DarkGray

    Assert-True (Test-Path -LiteralPath (Join-Path $fresh '.pre-commit-config.yaml')) '.pre-commit-config.yaml should exist'
    Assert-True (Test-Path -LiteralPath (Join-Path $fresh '.hooks\security-profile.json')) 'manifest should exist'
    Assert-True (Test-Path -LiteralPath (Join-Path $fresh '.hooks\codeql-check.ps1')) 'codeql hook should be copied'
    Assert-True (Test-Path -LiteralPath (Join-Path $fresh '.hooks\claude-check.ps1')) 'claude hook should be copied'
    Assert-True (Test-Path -LiteralPath (Join-Path $fresh '.hooks\osv-check.ps1')) 'osv hook should be copied'

    # cyclonedx-init.gradle is not a hook, so it is easy to leave out of the copy
    # list in install.ps1. Without it osv-check.ps1 silently degrades a Gradle repo
    # to partial coverage - a pass that covers nothing, which is the exact failure
    # this whole tool exists to prevent.
    Assert-True (Test-Path -LiteralPath (Join-Path $fresh '.hooks\cyclonedx-init.gradle')) `
        'cyclonedx-init.gradle should be copied, or Gradle repos get no dependency coverage'

    $shim = Join-Path $fresh '.git\hooks\pre-push'
    Assert-True (Test-Path -LiteralPath $shim) 'pre-push shim should be installed'

    # Regression: every planned action must actually succeed. Without this, a
    # GetNewClosure() scoping bug made `pre-commit install` report exit 1 while
    # succeeding, and the file-existence checks above still passed - the run was
    # reported as "Finished with problems" and the test went green anyway. The
    # inverse of that bug is the dangerous one: a genuinely failed winget install
    # reported as success.
    Assert-True ($r.Output -notmatch 'Finished with problems') `
        "every action must succeed; output reported failures:`n$($r.Output)"
    Assert-True ($r.Output -notmatch '\[FAIL\]') 'no action should report [FAIL]'
    Assert-True ($r.Output -match 'Applied (\d+) of \1 action') 'applied count must equal planned count'
}

Test-Case 'the Gradle init script keeps the two properties it has to keep' {
    # Both assertions below cost an afternoon to discover, and both fail silently
    # in the direction of "no dependency coverage" rather than an obvious error.
    $init = Get-Content -LiteralPath (Join-Path $fresh '.hooks\cyclonedx-init.gradle') -Raw

    # 1. The plugin must be applied by CLASS. `apply plugin: 'org.cyclonedx.bom'`
    #    throws UnknownPluginException from an init script even though the jar
    #    resolves and does contain a valid plugin descriptor: project plugin-id
    #    resolution does not search the initscript classloader.
    Assert-True ($init -match 'pluginManager\.apply\(\s*CyclonedxPlugin\s*\)') `
        'plugin must be applied by class - applying it by id fails from an init script'

    # Comments are stripped first: the script documents the broken form on purpose,
    # so matching the raw text would fail on its own explanation.
    $code = (($init -split "`n") | Where-Object { $_ -notmatch '^\s*//' }) -join "`n"
    Assert-True ($code -notmatch "apply\s+plugin:\s*'org\.cyclonedx") `
        'must not apply the plugin by id'

    # 2. The version must be pinned. Maven Central's metadata for this artifact
    #    reports 1.4.0 as latest while the plugin portal is on 3.4.1, so anything
    #    resolving "latest" gets a four-year-old plugin.
    Assert-True ($init -match "org\.cyclonedx:cyclonedx-gradle-plugin:\d+\.\d+\.\d+") `
        'plugin version must be pinned explicitly, not resolved as latest'

    Assert-True ($init -notmatch '[^\x00-\x7E]') 'init script must stay plain ASCII'
}

Test-Case 'a Gradle repo with no lockfile still primes the Maven database' {
    # The dangerous direction: if build.gradle is not mapped to an ecosystem,
    # priming skips Maven, and the first push hits osv-scanner exit 127 - which
    # writes {"results": []}, a file identical to a genuinely clean scan.
    . (Join-Path $PSScriptRoot '..\lib\tools.ps1')
    . (Join-Path $PSScriptRoot '..\lib\detect.ps1')

    $ecos = @(Get-DependencyEcosystems -RepoRoot $fresh)
    Assert-True ($ecos -contains 'Maven') `
        "a build.gradle-only repo must expect the Maven database; got [$($ecos -join ', ')]"
}

Test-Case 'the manifest records the chosen options' {
    $m = Get-Content -LiteralPath (Join-Path $fresh '.hooks\security-profile.json') -Raw | ConvertFrom-Json
    Assert-Equal 'code-scanning' $m.querySuite 'querySuite default'
    Assert-Equal $true  $m.blocking.codeql 'codeql blocking was requested'
    Assert-Equal $false $m.blocking.claude 'claude tool-error handling should stay advisory (findings still block regardless)'
    Assert-Equal 0.5 $m.claude.maxBudgetUsd 'budget'
    Assert-True (@($m.languages).Count -ge 1) 'languages recorded'
    $java = @($m.languages) | Where-Object { $_.language -eq 'java' }
    Assert-True ($null -ne $java) 'java should be recorded'
}

Test-Case 'CodeQL blocks by default when -Blocking is not passed' {
    # The goal this tooling exists for is "catch issues locally, pre-push, so
    # server-side code scanning raises fewer alerts". A non-blocking CodeQL default would
    # let the vulnerable code through and the alert would still be raised, which
    # defeats the purpose. This asserts the default explicitly, without passing
    # -Blocking, so the default cannot quietly regress to advisory.
    $defaults = New-ScratchRepo -Name 'defaults' -WithJava
    $script:repos += $defaults

    $r = Invoke-Install -Repo $defaults -ExtraArgs @('-Yes')
    Assert-True ($r.Output -notmatch 'Finished with problems') "install should succeed:`n$($r.Output)"

    $m = Get-Content -LiteralPath (Join-Path $defaults '.hooks\security-profile.json') -Raw | ConvertFrom-Json
    Assert-Equal $true  $m.blocking.codeql 'CodeQL MUST block by default'
    Assert-Equal $false $m.blocking.claude 'Claude TOOL ERRORS stay advisory by default (budget/turns/transport - undecided call); a real finding blocks regardless of this flag, see claude-check.ps1'
    Assert-Equal $true  $m.blocking.osv    'osv MUST block by default (deterministic findings, each with a fixed version)'
}

Test-Case 'manifest is UTF-8 without a BOM' {
    $bytes = [System.IO.File]::ReadAllBytes((Join-Path $fresh '.hooks\security-profile.json'))
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    Assert-True (-not $hasBom) 'manifest must not start with a UTF-8 BOM'
    Assert-True ($bytes[0] -eq [byte][char]'{') 'manifest must start with an opening brace'
}

Test-Case 'install.ps1 is idempotent' {
    $r = Invoke-Install -Repo $fresh -ExtraArgs @('-DryRun', '-Blocking', 'codeql', '-ClaudeBudgetUsd', '0.5')
    Assert-Equal 0 $r.ExitCode 'second dry run should exit 0'
    Assert-True ($r.Output -match 'already current')  'hooks should be recognised as current'
    Assert-True ($r.Output -match 'already contains the core checks') 'config should be recognised'
    # The manifest is always rewritten (it is a generated file), so the plan is
    # allowed to contain exactly that one action and nothing else.
    $planLines = @($r.Output -split "`n" | Where-Object { $_ -match '^\s+\d+\.\s+\[' })
    foreach ($line in $planLines) {
        Assert-True ($line -match 'security-profile.json') "unexpected planned action: $($line.Trim())"
    }
}

Test-Case 'doctor.ps1 now reports the repo as wired' {
    $r = Invoke-Doctor -Repo $fresh -Json
    $j = ConvertFrom-Json $r.Output
    Assert-Equal $true $j.hooks.wired 'hooks.wired'
    Assert-Equal $true $j.hooks.prePushManaged 'prePushManaged'
    Assert-Equal $true $j.repoFiles.configPresent 'configPresent'
    Assert-Equal $true $j.repoFiles.profilePresent 'profilePresent'
    Assert-True ($j.readiness -in @('READY','DEGRADED')) "readiness should no longer be NOT_READY (got $($j.readiness))"
}

# --- 5. Foreign config must not be clobbered -------------------------------

$foreign = New-ScratchRepo -Name 'foreign' -WithJava
$repos += $foreign

Test-Case 'install.ps1 refuses to overwrite a foreign .pre-commit-config.yaml' {
    $cfg = Join-Path $foreign '.pre-commit-config.yaml'
    $original = @'
repos:
  - repo: https://github.com/psf/black
    rev: 24.1.0
    hooks:
      - id: black
'@
    Set-Content -LiteralPath $cfg -Value $original

    $r = Invoke-Install -Repo $foreign -ExtraArgs @('-Yes')

    $after = Get-Content -LiteralPath $cfg -Raw
    Assert-True ($after -match 'psf/black') 'the existing config must survive untouched'
    Assert-True ($after -notmatch 'codeql-check') 'the config must not have been rewritten'
    Assert-True ($r.Output -match 'Refusing to overwrite') 'should say it refuses'
    Assert-True ($r.Output -match 'manual merge|merge the block|Merge the block') 'should tell the user to merge'
    Assert-Equal 2 $r.ExitCode 'should exit 2 because a human is needed'
}

# --- 5b. Outdated-but-ours config must be flagged, not silently kept -------

$outdated = New-ScratchRepo -Name 'outdated' -WithJava
$repos += $outdated

Test-Case 'install.ps1 flags an outdated config that is missing a newer check' {
    # The POC-era config: the three original checks, but neither the pre-push
    # gitleaks safety net nor the dependency scan. Recognised as "ours", so it is
    # correctly not overwritten - but staying quiet about the gaps would
    # reintroduce exactly the silent under-coverage this installer exists to
    # prevent. Both missing checks must be named, not just counted.
    $cfg = Join-Path $outdated '.pre-commit-config.yaml'
    $old = @'
default_install_hook_types: [pre-commit, pre-push]

repos:
  - repo: local
    hooks:
      - id: gitleaks
        name: Secrets scan
        entry: gitleaks git --pre-commit --redact --staged --verbose
        language: system
        pass_filenames: false
        stages: [pre-commit]

      - id: codeql
        name: CodeQL static analysis
        entry: powershell -ExecutionPolicy Bypass -File .hooks/codeql-check.ps1
        language: system
        pass_filenames: false
        stages: [pre-push]

      - id: claude-review
        name: Claude Code security review
        entry: powershell -ExecutionPolicy Bypass -File .hooks/claude-check.ps1
        language: system
        pass_filenames: false
        stages: [pre-push]
'@
    Set-Content -LiteralPath $cfg -Value $old

    $r = Invoke-Install -Repo $outdated -ExtraArgs @('-DryRun')
    Assert-True ($r.Output -match 'missing 2 check') 'should report the missing check count'
    Assert-True ($r.Output -match 'gitleaks-push') 'should name gitleaks-push'
    Assert-True ($r.Output -match 'osv') 'should name osv'
    Assert-True ($r.Output -match 'NOT rewritten') 'should say it did not rewrite the config'

    $after = Get-Content -LiteralPath $cfg -Raw
    Assert-True ($after -notmatch 'gitleaks-push') 'the config must not be modified'
    Assert-True ($after -notmatch 'osv-check') 'the config must not be modified'
}

Test-Case 'a current config produces no missing-check warning' {
    # The inverse: the template itself must never be reported as outdated,
    # or the warning becomes noise everyone learns to ignore.
    $current = New-ScratchRepo -Name 'current' -WithJava
    $script:repos += $current
    Copy-Item -LiteralPath (Join-Path $SetupDir 'templates\pre-commit-config.yaml') `
              -Destination (Join-Path $current '.pre-commit-config.yaml') -Force

    $r = Invoke-Install -Repo $current -ExtraArgs @('-DryRun')
    Assert-True ($r.Output -match 'already contains the core checks') 'should recognise the config'
    Assert-True ($r.Output -notmatch 'missing \d+ check') 'must NOT warn about a current config'
}

# --- 6. Go and Swift gating ------------------------------------------------

$polyglot = New-ScratchRepo -Name 'polyglot' -WithJava -WithGo -WithSwift
$repos += $polyglot

Test-Case 'go and swift are reported as skipped, not as failures' {
    $r = Invoke-Doctor -Repo $polyglot -Json
    $j = ConvertFrom-Json $r.Output

    $go = @($j.languages) | Where-Object { $_.language -eq 'go' }
    Assert-True ($null -ne $go) 'go should be detected'
    Assert-Equal 'NEEDS_BUILD' $go.status 'go cannot be analysed buildless'
    Assert-True (@($go.reasons).Count -ge 1) 'go should explain why'

    $swift = @($j.languages) | Where-Object { $_.language -eq 'swift' }
    Assert-True ($null -ne $swift) 'swift should be detected'
    Assert-True ($swift.status -in @('NEEDS_BUILD','UNSUPPORTED')) "swift status was '$($swift.status)'"

    $java = @($j.languages) | Where-Object { $_.language -eq 'java' }
    Assert-True ($java.status -in @('OK','DEGRADED')) 'java should still be analysable'

    Assert-True (@($j.blockedLanguages) -contains 'go') 'go should be listed as blocked'
}

Test-Case 'install.ps1 explains the skipped languages before installing' {
    $r = Invoke-Install -Repo $polyglot -ExtraArgs @('-DryRun')
    Assert-Equal 0 $r.ExitCode 'dry run exit'
    Assert-True ($r.Output -match 'SKIPPED') 'should say those languages are skipped'
    Assert-True ($r.Output -match 'go \(') 'should name go'
}

# --- Summary ---------------------------------------------------------------

Write-Host ''
Write-Host '=========================================='
Write-Host " PASS: $($script:Pass)   FAIL: $($script:Fail)"
Write-Host '=========================================='
if ($script:Fail -gt 0) {
    foreach ($f in $script:Failures) { Write-Host "  - $f" -ForegroundColor Red }
}

if (-not $KeepArtifacts) {
    foreach ($r in $repos) { Remove-Item -LiteralPath $r -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host 'Scratch repositories removed.' -ForegroundColor DarkGray
} else {
    Write-Host 'Scratch repositories kept:' -ForegroundColor DarkGray
    foreach ($r in $repos) { Write-Host "  $r" -ForegroundColor DarkGray }
}

if ($script:Fail -gt 0) { exit 1 }
exit 0
