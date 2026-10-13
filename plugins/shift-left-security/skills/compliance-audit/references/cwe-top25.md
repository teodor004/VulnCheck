# 2025 CWE Top 25 - spotting them in a diff

The 2025 CWE Top 25 Most Dangerous Software Weaknesses, in rank order, with
short hints for finding each one during review. Source:
<https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>. CWE™ is a
trademark of The MITRE Corporation.

"Hook" says which pre-push check usually catches it, so the review can focus on
what the hooks miss. "CodeQL" means only with a recognised taint source, and
"AI" means the Claude review may catch it but recall drops on large diffs.

| # | CWE | Weakness | How to spot it | ASVS | Hook |
|---|---|---|---|---|---|
| 1 | CWE-79 | Cross-site scripting | Untrusted data written into HTML/JS without context-aware encoding; `innerHTML`, unescaped template output | 1.2.1, 1.2.3, 3.2.2 | CodeQL, AI |
| 2 | CWE-89 | SQL injection | Query text built by concatenation or formatting; raw ORM queries with interpolation | 1.2.4 | CodeQL, AI |
| 3 | CWE-352 | Cross-site request forgery | Cookie-authenticated state change with no CSRF token, `SameSite` or origin check; state change on GET | 3.5.1-3.5.3 | AI |
| 4 | CWE-862 | Missing authorization | A handler that changes or returns data with no permission check at all | 8.2.1, 8.3.1 | AI |
| 5 | CWE-787 | Out-of-bounds write | C/C++ writes past a buffer: unchecked indexes, `memcpy`/`strcpy` with untrusted lengths | 1.4 (L2/L3) | CodeQL (needs a build) |
| 6 | CWE-22 | Path traversal | File paths joined from user input without canonicalising and checking the base directory; zip-slip | 5.3.2 | CodeQL, AI |
| 7 | CWE-416 | Use after free | C/C++ pointer used after `free`/`delete`, or after its container reallocated | 1.4 (L2/L3) | CodeQL (needs a build) |
| 8 | CWE-125 | Out-of-bounds read | C/C++ reads past a buffer; lengths taken from input | 1.4 (L2/L3) | CodeQL (needs a build) |
| 9 | CWE-78 | OS command injection | Shell commands built from input; `shell=True`, `exec(String)`, `system()` | 1.2.5 | CodeQL, AI |
| 10 | CWE-94 | Code injection | `eval`/`exec`, expression languages (SpEL, OGNL), template engines or dynamic imports fed by input | 1.3.2, 1.3.7 | CodeQL, AI |
| 11 | CWE-120 | Classic buffer overflow | Copy without a size check: `strcpy`, `gets`, `sprintf` into a fixed buffer | 1.4 (L2/L3) | CodeQL (needs a build) |
| 12 | CWE-434 | Unrestricted file upload | Uploads accepted without type/extension checks, stored executable or under the web root | 5.2.2, 5.3.1 | AI |
| 13 | CWE-476 | NULL pointer dereference | Return values used without a null check (C/C++, also crashes in managed code) | - | CodeQL |
| 14 | CWE-121 | Stack-based buffer overflow | Fixed-size local arrays filled from input | 1.4 (L2/L3) | CodeQL (needs a build) |
| 15 | CWE-502 | Unsafe deserialization | `ObjectInputStream`, `pickle`, `yaml.load`, `BinaryFormatter` on untrusted bytes | 1.5.2 | CodeQL, AI |
| 16 | CWE-122 | Heap-based buffer overflow | Heap allocations sized from input, then over-written | 1.4 (L2/L3) | CodeQL (needs a build) |
| 17 | CWE-863 | Incorrect authorization | A check exists but tests the wrong thing: role instead of ownership, client-supplied role, inverted condition | 8.2.1-8.2.2 | AI |
| 18 | CWE-20 | Improper input validation | Values used without type, range, length or format checks | 2.2.1-2.2.2 | AI |
| 19 | CWE-284 | Improper access control | Broad class: resources reachable by the wrong principal; missing tenant isolation | 8.2, 8.4.1 | AI |
| 20 | CWE-200 | Sensitive information exposure | Stack traces, internal fields, secrets or personal data in responses or logs | 15.3.1, 16.5.1, 16.2.5 | AI |
| 21 | CWE-306 | Missing authentication for critical function | Admin, debug or management endpoints reachable without login | 8.2.1, 13.4.5 | AI |
| 22 | CWE-918 | Server-side request forgery | Server fetches a URL the user controls without an allowlist; redirects followed | 1.3.6, 15.3.2 | CodeQL, AI |
| 23 | CWE-77 | Command injection | Any interpreter command (not just the OS shell) assembled from input | 1.2.5 | CodeQL, AI |
| 24 | CWE-639 | Authorization bypass through user-controlled key (IDOR) | Object fetched by an ID from the request with no ownership/tenant check | 8.2.2 | AI |
| 25 | CWE-770 | Resource allocation without limits | No size, count or rate limits on uploads, queries, loops or allocations sized by input | 2.4.1, 5.2.1 | AI |

## Also worth a line in every review

These are outside the 2025 Top 25 but are exactly what this repo's hooks target:

| CWE | Weakness | Hook |
|---|---|---|
| CWE-798 | Hard-coded credentials | Gitleaks |
| CWE-1104 / CWE-1395 | Unmaintained or vulnerable third-party components | osv-scanner |
| CWE-327 / CWE-328 | Broken or weak crypto / hash | CodeQL, AI (ASVS 11.3, 11.4) |
| CWE-295 | Improper certificate validation | CodeQL, AI (ASVS 12.3.2) |
