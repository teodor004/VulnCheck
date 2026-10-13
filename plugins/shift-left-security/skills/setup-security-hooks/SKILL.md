---
name: setup-security-hooks
description: Set up, check, or troubleshoot the local pre-commit and pre-push security checks (Gitleaks secret scanning, CodeQL static analysis, osv-scanner dependency scanning, Claude Code security review) in a git repository. Use when the user asks to install or configure the security hooks, asks why a push was blocked, mentions gitleaks, codeql or osv hooks, or asks whether their local security checks are working.
---

# Set up local security checks

Installs four checks into a git repository: Gitleaks on commit, then CodeQL,
osv-scanner and Claude Code on push. Your job is to profile the machine, ask the
few questions that cannot be inferred, run the installer, and report honestly
what happened.

The scripts hold all the logic. You are the conversation around them, not a
reimplementation of them.

## Step 0 - locate the setup folder

Check this skill's own folder first: `setup.ps1` bundles the scripts here, next
to this file, at `setup/doctor.ps1` relative to wherever this SKILL.md lives
(typically `~/.claude/skills/setup-security-hooks/setup/doctor.ps1`). This is
the common case - anyone who ran `setup.ps1` has this already, no extra step.

If it is not there, look for `setup/doctor.ps1` in the repository root next,
then ask the user where the `setup/` folder is - it is commonly a copy on disk
or a checkout of another repository, because the folder is designed to be
copied to whichever repository needs the hooks. Do not guess and do not author
your own scripts.

If none of that turns it up, this skill arrived without its bundled setup/
folder - possible if it was copied by hand, or by some other distribution
script that only knows to fetch skills (not, currently, this repo's own
setup.ps1, which fetches both together for exactly this reason). Tell the user
to get it from the source repo:

```
git clone --depth 1 https://github.com/teodor004/VulnCheck.git
```

`setup/` inside that clone is what Step 0 is looking for. Do not offer to
reconstruct the scripts from this skill's own description of them - install.ps1
and doctor.ps1 are the actual logic; this skill only narrates them.

The setup folder does **not** have to live inside the target repository. The
scripts resolve their own location, and `install.ps1` takes `-RepoRoot`, so a
`setup/` folder anywhere on disk can wire up any repository:

```
powershell -ExecutionPolicy Bypass -File <path-to-setup>\doctor.ps1 -RepoRoot <target-repo>
```

Run the commands below from the repository being set up, or pass `-RepoRoot`
explicitly. Use `-RepoRoot` whenever the setup folder is outside the target
repository - it is the difference between profiling the target and profiling
whatever repository the setup folder happens to sit in.

## Step 1 - profile, never guess

```
powershell -ExecutionPolicy Bypass -File setup/doctor.ps1 -Json
```

This is read-only and installs nothing. Its JSON is the single source of truth.
Do not infer tool presence from the file tree, from `CLAUDE.md`, or from what a
previous run reported. Do not run version commands yourself - `doctor.ps1`
already normalises them.

Exit codes: `0` ready, `1` usable but degraded, `2` not ready.

Key fields: `readiness`, `tools[]`, `languages[]` (each with `status` of `OK`,
`DEGRADED`, `NEEDS_BUILD` or `UNSUPPORTED`, plus `reasons[]`), `hooks.wired`,
`blockers[]`, `repoFiles.hooksDirIgnored`.

## Step 2 - show the user what you found

Summarise the tool table and the language table. Two things must be stated
plainly rather than buried:

- **DEGRADED languages.** Say what will be missed and why it matters: findings
  become a floor, not a clean bill of health, so a pass does not mean the code
  is clean. Include the `reasons[]` text.
- **NEEDS_BUILD or UNSUPPORTED languages.** Say those files will be skipped
  entirely, and why (Go and Swift cannot be analysed without a build; Swift
  cannot be analysed on Windows at all).

If `repoFiles.hooksDirIgnored` is true, tell the user `.hooks/` is gitignored,
so the rest of the team will not receive these hooks and nobody can review them. Do not
edit `.gitignore` yourself - that is their call.

If `readiness` is already `READY` and the user only wanted a check, stop here.

## Step 3 - ask only what cannot be inferred

Use `AskUserQuestion`. Skip any question the user has already answered in their
message, and skip questions whose answer `doctor.ps1` already determined.

1. **Blocking or advisory?** Default **`codeql`**: secrets and CodeQL findings
   block the push, the AI review only reports. Do not offer `none` as the
   recommended option - the purpose of this mechanism is that vulnerabilities do
   not reach GitHub, and an advisory default would let the code through and the
   code-scanning alert would still be raised. State the real cost honestly: a clean push
   measured ~191 s in the POC, ~89% of it CodeQL rebuilding its database. If the
   user asks for `none`, set it - it is their repo - but say plainly what it
   turns off.
2. **CodeQL query suite?** Default **code-scanning** (security only, 80 queries
   for Java). `security-and-quality` adds hygiene queries (244 for Java, ~3x)
   and in the POC 59.7% of its findings were hygiene rather than security.
3. **Claude budget per push?** Default **$1.00**. A real POC push was killed
   mid-review at a $0.20 cap on a large accumulated diff.
4. **Install missing tools now, or print the commands?** If anything is missing,
   get an explicit yes before installing. Mention the CodeQL bundle is ~700 MB.
   Gitleaks, osv-scanner, and CodeQL are each downloaded from a pinned GitHub
   release and checksum-verified - no winget, no admin rights needed.
5. **Install language toolchains too?** Only ask if a language is DEGRADED.
   These are large and optional; the hooks work without them, just with less
   visibility.

## Step 4 - install

Always dry-run first and show the user the plan:

```
powershell -ExecutionPolicy Bypass -File setup/install.ps1 -DryRun
```

Then apply with the answers from Step 3:

```
powershell -ExecutionPolicy Bypass -File setup/install.ps1 -Yes `
  -QuerySuite <code-scanning|security-and-quality> `
  -Blocking <none|codeql|claude|both> `
  -ClaudeBudgetUsd <n> `
  [-IncludeToolchains] [-SkipToolInstall] [-InstallSkill]
```

Notes that matter:

- `-Yes` skips the interactive prompt. Only pass it after the user has agreed in
  chat - it is their consent, transferred, not a way around asking.
- The CodeQL download is ~700 MB. Run it in the background and report progress
  rather than sitting idle.
- If the installer refuses to overwrite an existing `.pre-commit-config.yaml`,
  that is deliberate. Show the user the template block and offer to merge it by
  hand. Never overwrite it.
- `-InstallSkill` copies this skill to `~/.claude/skills/` so
  `/setup-security-hooks` works in every repository.

## Step 5 - verify and report

`install.ps1` re-runs `doctor.ps1` at the end. Read that output rather than
assuming success.

- Report only what `doctor.ps1` confirms. Installer output saying "installed" is
  not confirmation.
- **If PATH changed, say a new terminal is required.** Windows reads environment
  variables at process start, so this session cannot see the new PATH. If
  `doctor.ps1` still reports a tool missing right after installing it, this is
  almost certainly why - say so instead of reporting a failure.
- Finish with what will now happen on the user's next commit and next push, and
  roughly how long it will take.

## Troubleshooting mode

If the user is asking why something failed rather than asking to install, run
`doctor.ps1` and stop. Do not install anything.

- **Push blocked, output says `TOOL ERROR`** - a tooling problem, not a security
  finding. Common causes: Claude budget or turn exhaustion, CodeQL database
  creation failure, a query suite that does not resolve, osv-scanner absent from
  PATH. Check `.hooks/claude-error.log`, `.hooks/claude-result.json` and
  `.hooks/osv-results.json`.
- **Dependency scan prints a yellow SKIP saying no package sources were found** -
  not a failure and not a pass. osv-scanner reads lockfiles; `build.gradle`, a
  bare `Gemfile` and an unpinned requirements file contain no resolved versions,
  so it can extract nothing. Tell the user plainly that their dependencies were
  not scanned at all, and that the fix is to commit a lockfile
  (`gradle dependencies --write-locks`, `Gemfile.lock`, a pinned
  `requirements.txt`). Never suggest `--allow-no-lockfiles` - it converts this
  into a green pass without scanning anything.
- **Push blocked with real findings** - do not help bypass it. Read the code,
  confirm whether the finding is real, and help fix it. If it is a false
  positive, that is a conversation with a reviewer, not a `--no-verify`.
- **Hooks never fire** - check `hooks.wired` and `hooks.hooksPathOverride` in
  the JSON. A `core.hooksPath` setting silently overrides `.git/hooks`.
- **A query suite fails to resolve** - the bare `codeql-cli-binaries` download
  was installed instead of the bundle. It has no query packs. Reinstall.

## Hard rules

- Never overwrite an existing `.pre-commit-config.yaml`.
- Never install anything without an explicit yes in the conversation.
- Never edit `.gitignore` on the user's behalf.
- Never claim a tool is installed unless `doctor.ps1` says so.
- Never suggest `--no-verify` as a way past a finding. On commit it skips secret
  scanning; the pre-push pass re-scans the working tree, but a secret already
  deleted from the tree still reaches the remote in history.
- Do not rewrite the hook scripts to make a check pass.
