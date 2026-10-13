# NIST SSDF (SP 800-218 v1.1) - process checklist

The Secure Software Development Framework's practices, summarised in our own
words, with what to check in a repository and how this repo's hooks relate to
each one. Source: NIST SP 800-218 v1.1 (February 2022),
<https://csrc.nist.gov/pubs/sp/800/218/final>. Practice IDs match the standard
(v1.1 has no PW.3; it was merged into PW.4).

Use this file when the question is about the **repository, pipeline or team
practice**, not a specific code change. Each practice has several tasks in the
official text; this is a review aid, not a substitute for it.

Coverage key: **Yes** = the hooks implement part of it, **Partial** = they help
but leave gaps, **No** = outside what local hooks can do.

## PO - Prepare the Organization

| ID | Practice | What to check in a repo | Hooks |
|---|---|---|---|
| PO.1 | Define security requirements for development | A documented security baseline (e.g. an ASVS level) and where it applies | No |
| PO.2 | Implement roles and responsibilities | `CODEOWNERS`, named owners for security findings, review rules | No |
| PO.3 | Implement supporting toolchains | Security tools are versioned, installed reproducibly and integrity-checked | **Yes** - pinned, checksum-verified tool downloads |
| PO.4 | Define and use criteria for security checks | Which findings block, which only warn, and why | **Yes** - `-Blocking` profile and the 0/1/2 exit-code contract |
| PO.5 | Implement and maintain secure development environments | Least-privilege developer and CI credentials; secrets not on disk in plaintext | Partial - Gitleaks keeps secrets out of commits |

## PS - Protect the Software

| ID | Practice | What to check in a repo | Hooks |
|---|---|---|---|
| PS.1 | Protect all code from unauthorized access and tampering | Branch protection, required reviews, signed commits, no secrets in history | Partial - secret scanning at commit and push |
| PS.2 | Provide a way to verify release integrity | Published checksums or signatures for releases and installers | Partial - this repo's own installer verifies `checksums.sha256` |
| PS.3 | Archive and protect each release | Tagged releases, SBOMs, retained build provenance | Partial - osv-check generates a CycloneDX SBOM for Maven/Gradle |

## PW - Produce Well-Secured Software

| ID | Practice | What to check in a repo | Hooks |
|---|---|---|---|
| PW.1 | Design software to meet security requirements and mitigate risks | Threat model or security notes for new features | No |
| PW.2 | Review the design against requirements and risks | Design reviews recorded for security-relevant changes | No |
| PW.4 | Reuse well-secured existing software instead of duplicating it | Vetted libraries for crypto, auth, parsing; dependencies pinned via lockfiles | Partial - osv-scanner flags known-vulnerable components |
| PW.5 | Create source code using secure coding practices | A coding standard; the ASVS checklist applied in review | Partial - the AI review and `compliance-audit` |
| PW.6 | Configure build processes to improve executable security | Compiler hardening flags, reproducible builds, no debug builds shipped | No |
| PW.7 | Review and/or analyze human-readable code for vulnerabilities | Code review plus static analysis on every change | **Yes** - CodeQL and the Claude review on pre-push |
| PW.8 | Test executable code for vulnerabilities | Security tests, DAST, fuzzing where it fits | No |
| PW.9 | Configure software to have secure defaults | Debug off, least-privilege defaults, secure headers on by default | No (review with ASVS V13) |

## RV - Respond to Vulnerabilities

| ID | Practice | What to check in a repo | Hooks |
|---|---|---|---|
| RV.1 | Identify and confirm vulnerabilities on an ongoing basis | Dependency and code scanning that keeps running after release; a way to report issues (`SECURITY.md`) | Partial - only at push time; server-side scanning is still needed |
| RV.2 | Assess, prioritize and remediate vulnerabilities | Severity-based fix deadlines; findings tracked to closure | No |
| RV.3 | Analyze vulnerabilities to find root causes | Recurring finding types fed back into checks, rules or training | No |

## Reading the result

Local pre-push hooks mainly cover **PO.3, PO.4 and PW.7**, with partial help on
PS.1, PS.2, PS.3, PW.4 and RV.1. Everything else needs process, documentation
or server-side tooling. A finding here is "this practice has no evidence in the
repo", not "the code is vulnerable".
