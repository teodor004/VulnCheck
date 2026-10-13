# OWASP ASVS 5.0 - code review checklist

A condensed, code-review-oriented selection of OWASP ASVS 5.0.0 requirements,
**summarised in our own words**. IDs and levels match the official standard;
the wording does not - cite <https://github.com/OWASP/ASVS> (`5.0/en/`) for the
real text. Derived from ASVS (© OWASP Foundation), CC BY-SA 4.0.

`L` = the lowest ASVS level the requirement applies at (1 or 2). A Level 1
review checks the L1 rows; a Level 2 review checks both. Documentation-only
requirements (the `Vx.1` sections) and Level 3 are left out: they cannot be
judged from code.

Chapter V17 (WebRTC) is not covered.

---

## V1 Encoding and Sanitization

| ID | L | Check | Look for in code |
|---|---|---|---|
| 1.2.1 | 1 | Output to HTML/XML/HTTP headers is encoded for its exact context | String-built HTML, `innerHTML`, templates with escaping turned off (`\|safe`, `th:utext`, `dangerouslySetInnerHTML`) |
| 1.2.2 | 1 | Untrusted data put into a URL is URL-encoded for its position | `"...?q=" + input`, redirects built from parameters |
| 1.2.3 | 1 | Untrusted data put into JavaScript or JSON is escaped | Values concatenated into `<script>` blocks or hand-built JSON strings |
| 1.2.4 | 1 | Database queries are parameterised (SQL, HQL, NoSQL, Cypher) | String concatenation or formatting into a query; `Statement` instead of `PreparedStatement`; raw ORM queries with interpolation |
| 1.2.5 | 1 | OS commands do not take untrusted input unescaped | `Runtime.exec`, `subprocess(..., shell=True)`, `os.system`, `child_process.exec` with user input |
| 1.2.6-1.2.9 | 2 | LDAP, XPath, LaTeX and regex built from input are escaped or parameterised | Filters/expressions concatenated from input; `--shell-escape` |
| 1.3.1 | 1 | Rich HTML from users is sanitised with a well-known library | Home-made tag stripping; no sanitiser before rendering WYSIWYG content |
| 1.3.2 | 1 | No `eval()`-style dynamic code execution (incl. expression languages like SpEL) on untrusted data | `eval`, `exec`, `Function()`, `ScriptEngine`, SpEL/OGNL parsing user input |
| 1.3.6 | 2 | Outbound requests to user-supplied URLs are restricted to an allowlist (SSRF) | `fetch(url)`, `requests.get(user_url)`, URL from a parameter or webhook config |
| 1.3.7 | 2 | Templates are never built from untrusted input (template injection) | `Template(user_string)`, `render_template_string(input)` |
| 1.3.8 | 2 | JNDI lookups do not take untrusted input | `InitialContext.lookup(input)`, logging untrusted strings with an old Log4j |
| 1.3.10-1.3.11 | 2 | Format strings and mail headers are not built from input | `String.format(input)`, `printf(input)`, user input in SMTP headers |
| 1.5.1 | 1 | XML parsers are configured restrictively; external entities are off (XXE) | `DocumentBuilderFactory` without `disallow-doctype-decl`, `XMLInputFactory` defaults, `lxml` with `resolve_entities=True` |
| 1.5.2 | 2 | Deserialisation of untrusted data uses a type allowlist or a safe format | `ObjectInputStream.readObject`, `pickle.loads`, `yaml.load` (not `safe_load`), `BinaryFormatter` |

## V2 Validation and Business Logic

| ID | L | Check | Look for in code |
|---|---|---|---|
| 2.2.1 | 1 | Input is validated against what the business expects (allowlist, ranges, formats) | Values used straight from the request without type, length or range checks |
| 2.2.2 | 1 | Validation is enforced on the server, not only in the client | Checks only in frontend code; backend trusts the payload |
| 2.2.3 | 2 | Combinations of related fields are checked for consistency | Start date after end date accepted; discount larger than price |
| 2.3.1 | 1 | Multi-step flows run in order; steps cannot be skipped | Checkout/approval endpoints callable directly without the earlier state |
| 2.3.2-2.3.4 | 2 | Business limits are enforced, operations are transactional, scarce resources are locked | Missing transaction around a multi-write operation; check-then-act races on stock or balance |
| 2.4.1 | 2 | Anti-automation (rate limits) protects functions that could be abused at volume | No throttling on search, export, signup, password reset |

## V3 Web Frontend Security

| ID | L | Check | Look for in code |
|---|---|---|---|
| 3.2.1 | 1 | Responses cannot be rendered in the wrong context (correct Content-Type, no sniffing) | User-uploaded content served inline with a guessable type |
| 3.2.2 | 1 | Text meant as text is rendered with safe APIs (`textContent`, `createTextNode`) | `innerHTML` / `document.write` with data |
| 3.3.1 | 1 | Cookies have `Secure` (and a `__Host-`/`__Secure-` prefix) | Cookie set without `Secure` |
| 3.3.2-3.3.4 | 2 | `SameSite` set deliberately; session cookies are `HttpOnly` | Session cookie readable by JS; `SameSite=None` without reason |
| 3.4.1 | 1 | HSTS on all responses | No `Strict-Transport-Security` header |
| 3.4.2 | 1 | CORS `Access-Control-Allow-Origin` is fixed or checked against an allowlist | Origin header reflected back; `*` combined with credentials |
| 3.4.3-3.4.6 | 2 | CSP, `nosniff`, referrer policy and `frame-ancestors` are set | Missing security headers in middleware/config |
| 3.5.1-3.5.3 | 1 | Sensitive actions are CSRF-protected and never triggered by GET | State-changing GET routes; no CSRF token or origin check on cookie-authenticated POSTs |
| 3.5.5 | 2 | `postMessage` handlers check the sender's origin | `addEventListener('message', ...)` without an origin check |

## V4 API and Web Service

| ID | L | Check | Look for in code |
|---|---|---|---|
| 4.1.1 | 1 | Every response with a body has a correct Content-Type (and charset) | Handlers returning raw strings without a type |
| 4.1.3 | 2 | Headers set by a proxy/load balancer cannot be spoofed by the client | Trusting `X-Forwarded-For` / `X-User` from any source |
| 4.3.1-4.3.2 | 2 | GraphQL limits query depth/cost; introspection off in production | No depth or complexity limit; introspection enabled by default |
| 4.4.1 | 1 | WebSockets use WSS | `ws://` endpoints |

## V5 File Handling

| ID | L | Check | Look for in code |
|---|---|---|---|
| 5.2.1 | 1 | Upload size is limited | No max request/file size |
| 5.2.2 | 1 | File extension and content type match the expected type | Trusting the client-sent filename or MIME type |
| 5.2.3 | 2 | Archives are checked against a maximum uncompressed size (zip bombs) | Extracting uploads without size or entry limits |
| 5.3.1 | 1 | Uploaded files in public folders are never executed as code | Uploads saved under the web root with executable extensions |
| 5.3.2 | 1 | File paths use generated or trusted names, not user-submitted ones (path traversal) | `open(base + filename)`; `Path.join` with `../` possible; zip-slip on extraction |
| 5.4.1-5.4.2 | 2 | Download filenames from users are validated and encoded | `Content-Disposition` built from raw input |

## V6 Authentication

| ID | L | Check | Look for in code |
|---|---|---|---|
| 6.2.1, 6.2.5 | 1 | Passwords at least 8 characters (15 recommended); no composition rules | Max length limits, forced character classes |
| 6.2.2-6.2.3 | 1 | Users can change their password; change requires the current one | Change-password endpoint that skips the current password |
| 6.2.4 | 1 | New passwords are checked against a list of common passwords | No breached/common password check |
| 6.2.8 | 1 | Passwords are verified exactly as entered (no truncation or case folding) | `.lower()` or truncation before hashing |
| 6.3.1 | 1 | Credential stuffing and brute force are mitigated | No lockout, backoff or rate limit on login |
| 6.3.2 | 1 | No default accounts (`admin`, `root`, `sa`) are active | Seeded default users or credentials in code or migrations |
| 6.3.4 | 2 | There are no undocumented or weaker alternative login paths | Debug login, legacy endpoints, API keys that bypass MFA |
| 6.4.1 | 1 | Initial passwords/activation codes are random and expire | Predictable or non-expiring reset/activation codes |
| 6.4.2 | 1 | No password hints or security questions | "Secret question" recovery |
| 6.5.x | 2 | OTPs and recovery codes are single-use, random, high-entropy, short-lived | Reusable codes, `Math.random()` OTPs, no expiry |

## V7 Session Management

| ID | L | Check | Look for in code |
|---|---|---|---|
| 7.2.1 | 1 | Session tokens are verified on a trusted backend | Session state trusted from the client |
| 7.2.2-7.2.3 | 1 | Session tokens are dynamic and generated with a CSPRNG | Static API keys used as sessions; tokens from `random` / timestamps |
| 7.2.4 | 1 | A new session token is issued on login (no session fixation) | Session id kept across authentication |
| 7.3.1-7.3.2 | 2 | Idle and absolute session timeouts exist | Sessions that never expire |
| 7.4.1 | 1 | Logout/expiry really invalidates the session server-side | Logout that only deletes the cookie client-side |
| 7.4.2 | 1 | Disabling or deleting an account ends its active sessions | Disabled users keep working sessions or refresh tokens |
| 7.5.1 | 2 | Sensitive account changes require re-authentication | Email/password/MFA change with only an existing session |

## V8 Authorization

| ID | L | Check | Look for in code |
|---|---|---|---|
| 8.2.1 | 1 | Function-level access needs an explicit permission | Admin routes guarded only by "is logged in"; missing `@PreAuthorize` / middleware |
| 8.2.2 | 1 | Data-level access checks the caller owns or may access *that* object (IDOR / BOLA) | `findById(request.id)` without an owner/tenant check |
| 8.2.3 | 2 | Field-level access is restricted (no reading/writing fields the caller may not see) | Returning or accepting whole entities |
| 8.3.1 | 1 | Authorization is enforced on the server/service layer | Hiding buttons in the UI as the only control |
| 8.4.1 | 2 | Multi-tenant apps isolate tenants on every operation | Queries missing the tenant filter |

## V9 Self-contained Tokens (e.g. JWT)

| ID | L | Check | Look for in code |
|---|---|---|---|
| 9.1.1 | 1 | Token signature/MAC is verified before its content is used | `jwt.decode(..., verify=False)`, reading claims before verification |
| 9.1.2 | 1 | Only allowlisted algorithms are accepted; never `none` | Algorithm taken from the token header |
| 9.1.3 | 1 | Verification keys come from trusted, preconfigured sources | `jku`/`x5u` headers followed blindly |
| 9.2.1 | 1 | Expiry/not-before times are enforced | `exp` not checked |
| 9.2.2-9.2.3 | 2 | Token type and audience are checked | ID tokens accepted as access tokens; no `aud` check |

## V10 OAuth and OIDC

| ID | L | Check | Look for in code |
|---|---|---|---|
| 10.2.1 | 2 | OAuth clients protect the code flow against CSRF (PKCE, `state`) | No `state` or PKCE parameter |
| 10.3.1-10.3.3 | 2 | Resource servers check audience, enforce scopes/claims, and identify users by an immutable claim (`sub`) | Users identified by email from the token |
| 10.4.1-10.4.5 | 1 | Authorization servers: exact redirect-URI matching, single-use short-lived codes, only needed grants, refresh-token replay protection | Prefix/wildcard redirect matching; implicit grant enabled |
| 10.5.1-10.5.4 | 2 | OIDC clients check `nonce`, issuer and audience of ID tokens | ID token accepted without `nonce`/`iss`/`aud` checks |

## V11 Cryptography

| ID | L | Check | Look for in code |
|---|---|---|---|
| 11.2.1 | 2 | Crypto uses vetted libraries, not home-made implementations | Custom ciphers, XOR "encryption" |
| 11.3.1-11.3.2 | 1 | No ECB or weak padding; approved ciphers/modes only (e.g. AES-GCM) | `AES/ECB`, `DES`, `RC4`, PKCS#1 v1.5 encryption |
| 11.3.3 | 2 | Encrypted data is integrity-protected (authenticated encryption) | AES-CBC without a MAC |
| 11.4.1 | 1 | Only approved hash functions for cryptographic uses | MD5 or SHA-1 for signatures, HMAC or integrity |
| 11.4.2 | 2 | Passwords are stored with a slow password-hashing function (Argon2id, scrypt, bcrypt, PBKDF2) | `sha256(password)`, unsalted hashes |
| 11.5.1 | 2 | Non-guessable values come from a CSPRNG | `Math.random`, `random.random`, `java.util.Random` for tokens, IDs or codes |

## V12 Secure Communication

| ID | L | Check | Look for in code |
|---|---|---|---|
| 12.1.1 | 1 | Only TLS 1.2+ is enabled | Old protocol versions allowed in server/client config |
| 12.2.1-12.2.2 | 1 | External services use TLS with publicly trusted certificates, no fallback to plaintext | `http://` endpoints, mixed content |
| 12.3.1, 12.3.3 | 2 | Connections to databases, caches, queues and internal services are encrypted | `sslmode=disable`, plaintext internal URLs |
| 12.3.2 | 2 | TLS clients validate certificates | `verify=False`, `rejectUnauthorized: false`, trust-all `TrustManager`, `InsecureSkipVerify` |

## V13 Configuration

| ID | L | Check | Look for in code |
|---|---|---|---|
| 13.2.3 | 2 | Service credentials are never defaults | Default DB/admin passwords in config |
| 13.2.4-13.2.5 | 2 | Outbound connections are limited to an allowlist | Unrestricted egress from user-controlled targets |
| 13.3.1 | 2 | Secrets live in a secrets manager / vault, not in code or config files | Hard-coded API keys, passwords or connection strings (also CWE-798) |
| 13.3.2 | 2 | Access to secrets follows least privilege | One shared credential for everything |
| 13.4.1 | 1 | Source-control metadata (`.git`) is not deployed or served | `.git` copied into images or web roots |
| 13.4.2-13.4.5 | 2 | Debug modes, directory listing, TRACE and internal docs/monitoring are off in production | `DEBUG=True`, `app.run(debug=True)`, exposed `/actuator`, Swagger in prod |

## V14 Data Protection

| ID | L | Check | Look for in code |
|---|---|---|---|
| 14.2.1 | 1 | Sensitive data is never sent in URLs or query strings | Tokens, passwords or personal data as GET parameters |
| 14.2.2 | 2 | Sensitive responses are not cached by intermediaries | Missing `Cache-Control: no-store` on sensitive endpoints |
| 14.2.3 | 2 | Sensitive data is not sent to third parties such as trackers | Analytics calls carrying personal data |
| 14.3.1 | 1 | Authenticated data is cleared from client storage on logout | Tokens or personal data left in `localStorage` |

## V15 Secure Coding and Architecture

| ID | L | Check | Look for in code |
|---|---|---|---|
| 15.2.1 | 1 | No dependency is past its documented patch window for known vulnerabilities | Old pinned versions with known CVEs (osv-scanner covers the detection) |
| 15.2.3 | 2 | Production contains only what it needs (no test or sample code) | Test endpoints, sample apps, dev dependencies shipped |
| 15.3.1 | 1 | Responses return only the needed fields | Serialising whole entities, including password hashes or internal flags |
| 15.3.2 | 2 | Backend calls to external URLs do not follow redirects unless intended | HTTP client with redirects on for user-influenced URLs |
| 15.3.3 | 2 | Mass assignment is prevented (allowlist of bindable fields) | Binding request bodies straight onto entities (`role`, `isAdmin` settable) |
| 15.3.5-15.3.7 | 2 | Strict typing/comparisons; no prototype pollution; no HTTP parameter pollution | `==` on secrets in PHP/JS; recursive merges of user objects into plain objects |

## V16 Security Logging and Error Handling

| ID | L | Check | Look for in code |
|---|---|---|---|
| 16.2.1 | 2 | Security log entries record when, where, who and what | Log lines without user or request identifiers |
| 16.2.5 | 2 | Sensitive data is not logged in the clear | Passwords, tokens, full card numbers or personal data in log calls |
| 16.3.1-16.3.2 | 2 | Authentication attempts and failed authorization are logged | Login and permission failures that leave no trace |
| 16.3.4 | 2 | Unexpected errors and security-control failures are logged | Swallowed exceptions (`catch {}`) around security checks |
| 16.4.1 | 2 | Log output is encoded to prevent log injection | Raw user input (with newlines) written into logs |
| 16.4.2 | 2 | Logs are protected from tampering and unauthorised access | Logs writable or deletable by the application user |
| 16.5.1 | 2 | Users get generic error messages; no stack traces or internals | Exception messages or stack traces returned in responses |
| 16.5.3 | 2 | Failures fail closed (an exception never grants access) | `try { check() } catch { allow }`; default-allow on error |
