# POC findings

Measured evidence for the four checks in this repo. Numbers here were produced
by running the real tools against a real repository, not estimated. Where a
figure is weak, it says so. Where an earlier figure was wrong, it is retracted
rather than quietly corrected.

**Target under test:** SasanLabs `VulnerableApp` — Spring Boot 2.7.18 / Gradle /
Java, 161 Java files, shipping `scanner/sast/expectedIssues.csv` with 154
hand-labelled vulnerabilities.
**Dates:** secrets/SAST/AI review 2026-08-03; dependency scanning 2026-08-17.
**Platform:** Windows 11, Windows PowerShell 5.1.

| Tool | Version |
|---|---|
| Gitleaks | 8.30.1 |
| CodeQL CLI (bundle) | 2.26.1 |
| osv-scanner | 2.4.0 |
| Claude Code CLI | 2.1.220, model Claude Sonnet 5 |
| pre-commit | 4.6.1 |
| JDK | **none installed** — see [Limitations](#limitations) |

These are the versions the POC actually measured. **2026-08-26:** `install.ps1`
was moved off winget for Gitleaks and osv-scanner (checksum-verified GitHub
release downloads instead — see README, "Where the tools go"), and CodeQL's
pinned tag was bumped to v2.26.3 in the same change. That is a newer CodeQL
than the 2.26.1 measured above; nothing here has been re-measured against it.
A patch-level CLI bump is unlikely to move the recall/precision numbers below,
but "unlikely" is not "verified" — treat this table as accurate for 2.26.1 and
re-run the measurement harnesses before citing these figures against 2.26.3.

---

## Verdict

The mechanism works. All four tools run from a real `git commit` / `git push`,
scoped correctly, and a push carrying a real vulnerability is blocked. Verified
end to end against a local bare repository, so nothing reached GitHub.

**It is not ready to be switched on for a whole team**, for one dominant reason: a
clean push costs **~191 s**, ~89% of it CodeQL rebuilding its database from
scratch every time. A mandatory 3-minute gate gets bypassed with `--no-verify`,
and a gate that is routinely bypassed is worse than no gate because it creates
false confidence.

Recommendation: **Gitleaks blocking at both stages now. CodeQL advisory at
pre-push until database caching is solved.** osv-scanner blocking (it is cheap).
Claude blocking on findings, advisory on its own failures.

This is a filter placed *in front of* server-side code scanning, not a
replacement for it. Local CodeQL recall is somewhere between 10% and 57% on a
labelled corpus — it reduces alert volume, it does not make server-side scanning
redundant.

---

## Detection quality

| Tool | Precision | False positives | Basis |
|---|---|---|---|
| Gitleaks | 100% | **0%** | 10 true-positive secrets, 17 false-positive probes |
| Claude | 100% | **0%** | 14 fixtures × 3 runs = 42 verdicts, zero disagreement |
| CodeQL | 55.9% | see note | 129 findings vs. the 154-vulnerability corpus |
| osv-scanner | 100% | 0 observed | 5 fixtures — a demonstration, not a rate |

The 17 Gitleaks negative probes are the ones that matter for adoption:
placeholders (`${AWS_KEY}`, `xxxxx`, `TODO`), documentation examples
(`AKIAIOSFODNN7EXAMPLE`), git SHAs, UUIDs, SHA-256 checksums, non-secret base64,
public keys, local H2 dev credentials. None were flagged. Gitleaks also prints
`REDACTED` rather than the key — a hook that echoes secrets to a terminal
creates a new leak path.

**Secrets are scanned at both stages.** `git commit --no-verify` skips the
pre-commit hook, so a second Gitleaks pass runs at pre-push over the whole
working tree (`gitleaks dir .`). Measured 2026-08-24 against *this* repo, not
VulnerableApp: 2.0 s, mean of 3 runs (2039 / 1979 / 2111 ms) over 593 KB, of
which Gitleaks reports 186 ms of actual scanning — the rest is process startup.
It scales with tree size, not diff size.

Residual gap, and the reason this is a mitigation rather than a fix: `dir` mode
scans **files on disk, not git history**. A secret committed with `--no-verify`
and then deleted from the working tree before pushing is still not caught
locally. Server-side secret scanning is what covers that case.

**CodeQL's "59.7% noise ratio" is not a false-positive rate.** It is the share of
findings that are hygiene (deprecated calls, unused parameters, unchecked
`NumberFormatException`) rather than security. They are largely correct; they are
just not what a security gate should block on. This is why the default query
suite is `code-scanning` (80 queries for Java) rather than
`security-and-quality` (244).

**CodeQL recall against the labelled corpus:**

| Metric | Value | Reading |
|---|---|---|
| Method-level | 10.3% (13/126) | Lower bound |
| File-level | 57.1% (12/21) | Upper bound |

The truth sits between. The gap is structural: many labelled vulnerabilities
route input through a shared helper; CodeQL flags the helper (the real sink)
while the corpus labels the caller. Neither is wrong — they count different
things. Strong: SQL injection 7/8. Weak or absent: path traversal, persistent
XSS, JWT, open redirect, command injection, LDAP injection, SSRF, IDOR.

**Treat every CodeQL recall figure as a floor, not an estimate.**

### CodeQL only tracks taint from *recognised remote sources*

Worth knowing before trusting a pass. `java/sql-injection` will not flag obvious
concatenated SQL if the tainted value arrives as a bare method parameter — it is
not a source CodeQL recognises. The same fixture caught immediately once the
input came from `HttpServletRequest.getParameter`. The Python equivalent is
`sys.argv`. A local pass means "no tainted flow from a recognised source", which
is narrower than "this code is safe".

### Claude's recall degrades sharply on large diffs

Measured 2026-08-24, and the most important caveat for anyone relying on the AI
review. The same hook and the same three fixtures were pushed twice:

| Diff | Findings | Cost | Latency | Verdict |
|---|---|---|---|---|
| 44 lines, fixtures only | **3 of 3** — IDOR, SQL injection, vulnerable dependency | $0.098 | 21.8 s | exit 1, blocked |
| ~118k tokens, mostly documentation | **0 of 1** | $0.42 | 91.6 s | exit 0, **passed** |

The large diff was a README rewrite plus a 17 KB findings document plus two file
deletions, with a 10-line IDOR inside it. The envelope confirms this was a real
miss and not a tool failure: `terminal_reason: "completed"`,
`subtype: "success"`, `is_error: false`,
`structured_output: {"verdict":"pass","findings":[]}`. The reviewer ran, cost 4×
the focused run, and reported clean.

Two consequences:

- **A `pass` on a large mixed diff is close to meaningless.** Push small,
  focused commits if you want the AI review to be worth its cost.
- **Cost does not scale with value.** The run that found nothing cost 4× the run
  that found everything, because the diff was 4× bigger.

The POC's earlier "$0.10–0.14 per push" figure holds only for focused diffs.
This was never measured during the POC — every fixture there was small and
code-only.

---

## Performance and cost

Mean of 3 runs per scenario, timed per stage:

| Stage | Clean push | Blocked push |
|---|---|---|
| Gitleaks (commit) | 0.5 s | 0.4 s |
| CodeQL | 170.9 s | 190.5 s |
| osv-scanner | ~2 s reused SBOM / ~15 s regenerated | same |
| Claude | 20.0 s | 72.8 s |
| **Total** | **191.4 s** | **263.7 s** |

These totals were measured before the pre-push Gitleaks pass was added; add ~2 s
to both.

Range: clean 178.7–199.3 s; blocked 225.7–320.2 s. Gitleaks at 0.5 s is
effectively free. **CodeQL is ~89% of the wait** and rebuilds its database every
push — there is no caching. That single fact drives the recommendation.

Claude cost per invocation: $0.017 on a small synthetic diff, $0.10–0.14 on a
real repository diff (11–95 s). At 10 pushes/day that is ~$250–350/developer/year
— small, but recurring and it scales with activity, so it should be a conscious
decision.

---

## Dependency scanning: three ways a scan passes cleanly while seeing nothing

These are the findings that matter most, because each produces a green result
that is not earned. All three were reproduced, not inferred, and all three are
defended against in `osv-check.ps1`.

**1. It reads lockfiles, not build scripts.** osv-scanner resolves *resolved
versions*. A `build.gradle`, a bare `Gemfile`, an unpinned `requirements.txt`
state none, so it sees zero packages and exits **128**. VulnerableApp is exactly
this shape — a naive integration would have reported it clean forever. The hook
prints a loud yellow `SKIPPED (NOT SCANNED, NOT A FAILURE)` and does not block:
"your dependencies are clean" and "your dependencies were never looked at" are
different claims.

**2. `--offline` with no database exits 127 and writes a clean-looking report.**
The results file contains `{"results": []}` — byte-for-byte what a genuinely
clean scan produces. Anything judging the JSON instead of the exit code reports a
pass. The hook branches on the exit code first, then cross-checks the two against
each other in *both* directions.

**3. The offline database is per ecosystem.** `--download-offline-databases`
fetches only the ecosystems seen *in that scan*. A cache primed against an
npm-only repo produces `npm/all.zip` and nothing else; point it at a Maven
project and you get failure mode 2 again, for Maven alone. The original
installer tested for "any file under the cache directory" and called that primed.
Now `Get-OsvDatabaseStatus` compares the repo's ecosystems against what is on
disk, primes only what is missing, and verifies the prime worked.

Database sizes, which is why only the repo's own ecosystems are primed: npm
210 MB, PyPI 32 MB, Maven 9.6 MB.

### JVM projects: the transitive dependency fix

Most real vulnerabilities arrive transitively, and offline osv-scanner cannot
resolve a transitive graph — upstream it delegates that to a network service.
The fix is to let the build tool do the resolution, since it is the only thing on
the machine that genuinely knows how.

- **Maven:** `cyclonedx-maven-plugin:makeAggregateBom` → CycloneDX SBOM →
  `osv-scanner --offline -L target/bom.json`. Verified: 62 vulnerability groups,
  fully offline.
- **Gradle:** same idea, but applied through an **init script**
  (`cyclonedx-init.gradle`) so `build.gradle` is never modified. No adopting team
  should have to take a diff to a build file to get a security hook.

**Measured on VulnerableApp:** 113-component SBOM, then **27 vulnerable packages
across 102 vulnerability groups**. Same repo, same hook, before this work: **0
packages, exit 128**. The profile is the point — the top findings are all
transitive and appear nowhere in `build.gradle`:

| Package | Version | Groups | In `build.gradle`? |
|---|---|---|---|
| `tomcat-embed-core` | 9.0.83 | 33 | No — via `spring-boot-starter-web` |
| `spring-webmvc` | 5.3.31 | 15 | No |
| `snakeyaml` | 1.30 | 7 | No |
| `jackson-databind` | 2.13.5 | 5 | No |
| `commons-text` | 1.8 | 1 (Text4Shell, CVSS 9.8) | Yes, literal version |

Only the last row was ever findable by reading the build script.

Four traps worth an hour each to rediscover:

- Maven Central's metadata for `cyclonedx-gradle-plugin` is **stale** (reports
  1.4.0; the Gradle plugin portal has up to 3.4.1). Pin and resolve from the portal.
- `apply plugin: 'org.cyclonedx.bom'` fails inside an init script with
  `UnknownPluginException` — plugin-*id* resolution does not search the initscript
  classloader. Apply the class: `gradle.rootProject { p -> p.pluginManager.apply(CyclonedxPlugin) }`.
  Note the lowercase `d`; `CycloneDxPlugin` does not exist.
- **`--no-daemon` is mandatory, and not for performance.** The forked daemon
  inherits the hook's stdout handle, so the pipe never reaches EOF and the hook
  hangs — observed past 600 s with no output.
- **A Java toolchain is needed even to *resolve* a configuration**, not only to
  compile. The Gradle route works only where the developer can already build the
  project. The hook detects this and reports partial coverage.

**Failure policy is asymmetric on purpose:** a failed Maven build is a hard error
(exit 2); a failed Gradle SBOM is partial coverage and does **not** block. Adding
this capability must never create a *new* blocking failure on repositories that
until now received no scan at all, and Gradle fails for ordinary environmental
reasons. Teams that prefer blocking can set `osv.gradleSbomFailureIsError: true`.

Full Dependabot parity was an explicit non-goal (2026-08-17) — partial coverage is acceptable.
No ground-truth diff against Dependabot's own alerts was ever run (`gh` CLI was
never installed), so no recall figure against Dependabot can be stated.

---

## The three exit codes

All hooks share one contract, and it is deliberately three values, not two:

| Code | Meaning |
|---|---|
| `0` | Pass |
| `1` | A real security finding |
| `2` | A tool / infrastructure error — "I could not judge your code" |

osv-scanner's own exit 127 (broken database) folds into **2**, not 1. Reporting
infrastructure faults as findings teaches developers that the red banner is
noise, which is how a real finding gets ignored later.

This was a real problem, not a hypothetical. A POC push failed with:

```json
{"terminal_reason":"budget_exhausted","subtype":"error_max_budget_usd",
 "errors":["Reached maximum budget ($0.2)"],"total_cost_usd":0.333}
```

and the output was indistinguishable from a genuine vulnerability report.

**Resolved 2026-08-24:** a Claude *finding* (exit 1) blocks the push
unconditionally — `blocking.claude` has no effect on it. That flag now governs
only the tool-error path (budget exhausted, turn limit, transport error), which
is advisory by default and remains an open call rather than a settled one.

---

## Limitations

**No JDK on the test machine.** CodeQL said so directly: *"Because there was no
JDK available on the host system, Java analysis used a minimal JDK shipped with
CodeQL. […] This means some Java may be wrongly extracted."* Gradle
dependency-graph extraction also failed. Every CodeQL recall figure above is
therefore a floor. Timing figures are unaffected.

**Claude Code is non-deterministic.** 42/42 identical verdicts is encouraging,
not a guarantee. Two behaviours were observed and fixed:

1. *Output-contract drift.* With the JSON requirement at the end of a long
   prompt, 2 of 14 cases returned conversational prose instead. Moving the
   contract to the front fixed all 14 and roughly halved cost and latency.
2. *Reasoning toward "unreachable."* Given repo read access the model can argue a
   vulnerability is unreachable and return `pass` — observed verbatim: *"Spring
   never populates it […] there's no reachable trigger path."* Locally correct,
   but "currently crashes" is not "safe."

**Retraction.** Behaviour 2 was initially recorded as an 80% detection rate for
the deployed hook. **That figure was wrong and should not be cited.** The cause
was a defect in the test fixture, not the tool — it omitted `@Autowired`, so
there genuinely was no reachable path. With a realistic controller, Claude caught
the vulnerability in 11.4 s on the first turn. The earlier 80%/50% detection
figures are retracted.

The general lesson, worth carrying into any rollout: **fixture-based harnesses
did not predict deployed behaviour.** The synthetic matrix scored 42/42 while
real-diff runs behaved differently, and the discrepancy was a fixture artefact in
both directions. Validate against real commits.

**No developer other than the author has used this.** Every developer-experience
claim is one person's assessment. Defensible for a POC; it is not validation and
should not be presented as such.

**Other known gaps:** Windows/PowerShell only (macOS dropped 2026-08-24, not
deferred). Maven test-scope dependencies are outside the
aggregate BOM. Database staleness is reported (>30 days) but not enforced.
`claude-check.ps1` sends the full diff to the model provider with no data-classification
gate. No hook retains a shared auditable record of what a review found.

**Open before any rollout beyond a demo:** CodeQL database caching (the ~171 s),
installing a JDK, deciding who pays for Claude, confirming other people can
authenticate Claude Code at all, and a trial with 2–3 real developers. The
`--no-verify` gap came off this list on 2026-08-24 — mitigated by the pre-push
Gitleaks pass, with the history-only case left to server-side scanning.

---

## Reproducing

Measurement harnesses live with the POC target repo, not here:
`measure_gitleaks.sh`, `measure_codeql.py` (SARIF vs. `expectedIssues.csv`),
`measure_claude.ps1` (`-Repeat N` for stability), `measure_endtoend.ps1`
(per-stage wall clock), `measure_osv.ps1`.

`measure_claude.ps1` extracts the prompt out of `claude-check.ps1` by regex
rather than duplicating it, so it fails loudly if the hook changes shape instead
of silently measuring a stale copy.

A moving target worth knowing about: the original osv "clean" fixture was lodash
4.17.21, chosen as the patched release. By 2026-08-17 it reported 2 vulnerability
groups because new advisories had landed. `measure_osv.ps1` failing on the clean
fixture is the intended way to learn a pinned assumption has expired — verify
before editing it away.

---

## Scope

| Goal | Asked for | Status |
|---|---|---|
| 1 — Gitleaks/CodeQL/Claude pre-push mechanism | Local mechanism, tested, findings + recommendation | Met. Verified with real `git commit` + `git push` against a local bare repo |
| 2 — Dependency scanning, on device, free | Investigate options, feasibility, demo if viable | Met with partial coverage accepted. osv-scanner `--offline` chosen |
| 3 — Packaged as a Claude Code skill | Conversational install/troubleshooting on top of the scripts | Met. `setup-security-hooks` wraps `doctor.ps1`/`install.ps1`; `setup.ps1` installs it with `setup/` bundled |

Only osv-scanner was measured for dependency scanning. Grype+Syft, OWASP
Dependency-Check and Trivy were assessed from documentation and rejected for the
pre-push slot on weight or preconditions, **not** for any known defect —
Grype+Syft is the strongest unevaluated alternative and could in principle
resolve a JVM project without invoking the build tool, which is the one
precondition the Gradle route could not remove. Snyk and Dependabot fail the
on-device constraint by construction.

**Structure** follows the Claude Code plugin convention
(`plugins/<name>/.claude-plugin/plugin.json` + `skills/<skill>/SKILL.md`,
installed by a root `setup.ps1`), plus a `checksums.sha256` integrity check on
both the skills and the bundled `setup/` scripts (CWE-494). Line endings are
pinned with `.gitattributes` (`eol=lf`) because the manifests hash bytes on disk,
and a clone with a different `core.autocrlf` would otherwise fail verification.

**Security review of the tooling itself.** The hook scripts were reviewed
against their own threat model before anything here was called done. Fixed as a
result: `claude-check.ps1` tells the model to treat text inside the reviewed diff
as data, not instructions (the diff is attacker-influenceable — OWASP LLM01,
prompt injection), and prints which model id actually answered, taken from the
response envelope's `modelUsage` rather than the ambient `ANTHROPIC_MODEL`, so
every AI verdict is traceable to a model version. Two gaps found and **not**
fixed, named rather than omitted: no data-classification gate before the diff
leaves the machine for model inference, and no retained auditable record of what
any review found. Both need a design decision rather than a unilateral default.
