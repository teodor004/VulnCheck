# compliance-audit references

Condensed, review-oriented checklists for three public standards. Each row is a
summary written for this skill, **not** the official requirement text - always
cite the official source when a finding matters.

## Applicability matrix

Load only what the code under review actually does.

| If the code involves... | Load |
|---|---|
| Any code review (always) | `cwe-top25.md` |
| HTML/XML/JSON output, SQL/NoSQL/LDAP/OS commands, templates, eval, XML parsing, deserialization, outbound URLs (SSRF) | `owasp-asvs.md` → V1 |
| Input validation, multi-step business flows, rate limits | `owasp-asvs.md` → V2 |
| Browser-facing responses, cookies, CORS, security headers | `owasp-asvs.md` → V3 |
| REST/GraphQL/WebSocket APIs | `owasp-asvs.md` → V4 |
| File upload, download, file paths built from input | `owasp-asvs.md` → V5 |
| Login, passwords, MFA, account recovery | `owasp-asvs.md` → V6 |
| Session tokens, logout, timeouts | `owasp-asvs.md` → V7 |
| Permission checks, object ownership, multi-tenancy | `owasp-asvs.md` → V8 |
| JWTs or other self-contained tokens; OAuth / OIDC | `owasp-asvs.md` → V9, V10 |
| Encryption, hashing, password storage, random values | `owasp-asvs.md` → V11 |
| TLS, certificate validation, service-to-service calls | `owasp-asvs.md` → V12 |
| Secrets, configuration, debug modes, deployment artifacts | `owasp-asvs.md` → V13 |
| Personal or sensitive data, caching, client-side storage | `owasp-asvs.md` → V14 |
| Third-party dependencies, mass assignment, type juggling, concurrency | `owasp-asvs.md` → V15 |
| Logging, audit trails, error handling | `owasp-asvs.md` → V16 |
| The repo, CI pipeline or team process (not a code change) | `nist-ssdf.md` |

For a small change (one file, one endpoint), load only the sections of each
chapter that plausibly apply.

## Sources and licences

| File | Source | Licence / terms |
|---|---|---|
| `owasp-asvs.md` | OWASP Application Security Verification Standard 5.0.0, <https://github.com/OWASP/ASVS> (requirement IDs and chapter structure from `5.0/en/`) | ASVS is © OWASP Foundation, CC BY-SA 4.0. This summary is a derivative work and is shared under the same licence: <https://creativecommons.org/licenses/by-sa/4.0/> |
| `cwe-top25.md` | 2025 CWE Top 25 Most Dangerous Software Weaknesses, <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html> | CWE™ is a trademark of The MITRE Corporation. Used under the CWE Terms of Use: <https://cwe.mitre.org/about/termsofuse.html> |
| `nist-ssdf.md` | NIST SP 800-218 v1.1, Secure Software Development Framework (Feb 2022), <https://csrc.nist.gov/pubs/sp/800/218/final> | U.S. Government work, not subject to copyright in the United States |

Checked against the sources on 2026-10-13. Standards move: re-check the IDs
above before relying on this in an audit.
