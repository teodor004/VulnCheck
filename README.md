# Shift-Left Security

Four security checks that run on your machine from real git hooks, so problems
are caught before a push reaches server-side code scanning.

This repo is the **product**. `setup/install.ps1` deploys the hooks into
whatever repo you point it at.

**Windows / PowerShell only.** Measured evidence for everything below is in
[docs/FINDINGS.md](docs/FINDINGS.md) — read the verdict there before proposing
rollout beyond a demo.

## What runs, and when

| Stage | Check | Tool | Cost |
|---|---|---|---|
| `pre-commit` | Secrets, staged changes | Gitleaks | 0.5 s |
| `pre-push` | Secrets, whole working tree | Gitleaks | ~2 s |
| `pre-push` | Static analysis | CodeQL | ~171 s |
| `pre-push` | Dependency CVEs | osv-scanner (offline) | ~2–15 s |
| `pre-push` | AI review of the diff | Claude Code | ~20 s, $0.10–0.14 |

A clean push costs **~191 s**, ~89% of it CodeQL. Secrets are checked at commit
because a secret must never enter history at all; the rest run at push because
they are too slow or cost money per run.

**Secrets are scanned twice on purpose.** `git commit --no-verify` skips the
pre-commit hook completely, and a commit made that way would otherwise push an
unscanned secret. The pre-push pass re-scans the whole working tree, which
catches that. It costs ~2 s on this repo (593 KB) and scales with tree size
rather than diff size, so scanning twice costs nothing worth counting. The
~191 s total above was measured before this pass existed; add ~2 s.

One case still gets through: the pre-push pass scans **files on disk, not git
history**, so a secret committed with `--no-verify` and then deleted from the
working tree before pushing is not seen locally. Server-side secret scanning is
what catches that, which is the general shape of this whole thing — these hooks
are fast local feedback, not enforcement.

Every hook uses the same three exit codes: `0` pass, `1` a real security
finding, `2` a tool error — "I could not judge your code" is deliberately not
reported as a vulnerability.

## Install

You need **git**, **Python** (only because `pre-commit` is a pip package), and
an **authenticated Claude Code CLI** already present. Everything else is
installed for you.

```powershell
# 1. See what your machine has. Read-only, installs nothing.
powershell -ExecutionPolicy Bypass -File setup/doctor.ps1 -RepoRoot C:\path\to\target-repo

# 2. Preview the plan.
powershell -ExecutionPolicy Bypass -File setup/install.ps1 -DryRun -RepoRoot C:\path\to\target-repo

# 3. Apply.
powershell -ExecutionPolicy Bypass -File setup/install.ps1 -Yes -RepoRoot C:\path\to\target-repo
```

Step 3 installs Gitleaks, osv-scanner, and the **CodeQL bundle (~700 MB, one
time)** — each downloaded from its own pinned GitHub release and checksum-
verified against the hash published alongside it, no winget or package manager
involved; installs `pre-commit` via pip; primes the osv offline database for
the ecosystems your repo actually uses; writes `.hooks/` and
`.pre-commit-config.yaml`; and runs `pre-commit install`.

**Open a new terminal afterwards.** Windows reads PATH at process start, so this
shell cannot see newly installed tools. If `doctor.ps1` still reports something
missing right after installing it, that is why.

### Where the tools go

`install.ps1` does this for you. Do it by hand only if a download fails or you
already have a copy.

```
C:\tools\codeql\codeql.exe              <- CodeQL, from codeql-action
C:\tools\codeql\java\                   <- query packs, one folder per language
C:\tools\gitleaks\gitleaks.exe          <- Gitleaks
C:\tools\osv-scanner\osv-scanner.exe    <- osv-scanner (ships as a bare .exe upstream)
```

Each folder needs to be on your user PATH — `install.ps1` does this too; verify
with `codeql version --format=terse`, `gitleaks version`,
`osv-scanner --version`. Getting the CodeQL layout wrong is the most common
install failure:

- **Extract to `C:\tools\codeql`** and you get `C:\tools\codeql\codeql\codeql.exe`
  — a doubled folder, and nothing finds it. The bundle already contains a
  top-level `codeql/` folder, so extract to `C:\tools`, not `C:\tools\codeql`.
- **Download the wrong artifact.** You need
  [`codeql-bundle-win64.tar.gz`](https://github.com/github/codeql-action/releases)
  from **`github/codeql-action`** (~700 MB). The similarly-named
  `codeql-cli-binaries` release ships **no query packs**, so
  `java-code-scanning.qls` fails to resolve and every push errors out. If you see
  a suite-resolution error, this is why. (`codeql-bundle-windows64.tar.gz` is a
  404 — the asset is `win64`.)

Every download is pinned to a specific release tag, not `releases/latest/`, and
checked against the `.checksum.txt` / `checksums.txt` / `SHA256SUMS` file that
release publishes — a tampered download or a tampered GitHub mirror is caught
before anything is extracted or added to PATH. If a checksum cannot be fetched
(e.g. a proxy blocking that one file, not the asset itself), the install
**aborts for that tool** rather than running an unverified binary. Only
`-AllowUnverifiedDownload` downgrades that to a loud warning, and it is off by
default on purpose.

To use a different location, set `SECURITY_TOOL_ROOT` before running
`install.ps1` and everything follows it.

Useful flags: `-Blocking none|codeql|claude|both`, `-QuerySuite
code-scanning|security-and-quality`, `-ClaudeBudgetUsd`, `-IncludeToolchains`,
`-SkipToolInstall`. Run `install.ps1 -DryRun` to see the resolved plan.

### Every teammate runs one command

Cloning a repo **never** activates hooks — git never transfers `.git/hooks`, by
design, or `git clone` would be remote code execution. The hook files arrive
with the clone; activating them is one local command per person:

```powershell
pre-commit install --hook-type pre-commit --hook-type pre-push
```

Re-running `install.ps1 -Yes` does the same and is idempotent.

## Claude Code skills

Two optional skills, installed to `~/.claude/skills/` by `setup.ps1`:

- **`setup-security-hooks`** — installs and troubleshoots the hooks
  conversationally. Ask "why was my push blocked?" and it diagnoses instead of
  helping you bypass.
- **`compliance-audit`** — reviews code against public secure-coding standards
  (OWASP ASVS 5.0, NIST SSDF SP 800-218, CWE Top 25) and reports findings by
  requirement ID. A deliberate, on-demand review, separate from the quick AI
  review the push hook runs.

## Layout

```
setup/
  doctor.ps1                 read-only machine + repo profile (-Json)
  install.ps1                the installer
  lib/                       tool registry, language/lockfile detection, helpers
  templates/hooks/           CANONICAL source of the hook scripts
  tests/                     smoke + userflow tests
plugins/shift-left-security/
  skills/                    the two skills above, with a checksum manifest
setup.ps1                    installs just the skills to ~/.claude/skills/
docs/FINDINGS.md             measured POC evidence
```

Edit hooks in `setup/templates/hooks/`. A target repo's `.hooks/` is a generated
copy — `install.ps1` overwrites it.

## Known limitations

Windows only. CodeQL only tracks taint from
sources it recognises, so a local pass is narrower than "this code is safe".
Local CodeQL recall on a labelled corpus is between 10% and 57%.

**Push small, focused commits.** The AI review found 3 of 3 planted
vulnerabilities in a 44-line diff, and 0 of 1 in a 118k-token diff that was
mostly documentation — for 4× the cost. A `pass` on a large mixed diff is close
to meaningless.

**This is a filter in front of server-side code scanning, not a
replacement for it.** See [docs/FINDINGS.md](docs/FINDINGS.md).
