# Effectiveness benchmark

This benchmark measures scanner behavior rather than prompt compliance. Each
case is copied into a fresh Git repository and scanned three times so the
report can distinguish repeatable detection from a lucky single run.

The evaluator requires both a compatible CWE and an overlapping expected code
location. A generic CWE match elsewhere does not count. Each reported finding
can match only one expectation, so duplicate findings become false positives.
Missing or malformed scan artifacts become completion failures and false
negatives instead of disappearing from the score. When a runner status receipt
is present, a nonzero, malformed, or mismatched receipt also makes the run a
reliability failure even if partial findings exist.

Metrics include completion rate, precision, recall, F1, exact-case pass rate,
negative-control pass rate, stable detection across repeated runs, validation
coverage, attack-path coverage, code-evidence coverage, severity accuracy, and
false positives per run. Evidence coverage requires substantive proof rather
than field presence: validation needs a source-backed narrative plus a method,
witness, assertion, or counterevidence; attack paths need a realistic narrative
plus source-to-impact continuity; and code evidence needs a concrete
path-and-line anchor, source text, and explanatory reasoning. Presence and
substantive-quality flags are both retained in per-match diagnostics.

The versioned corpus currently contains thirty-five vulnerable/control pairs:
command injection, path traversal, executable file upload/content placement,
HTTP request smuggling across inconsistent gateway/backend framing,
object-level authorization, SQL injection, document-query operator injection,
server-side request forgery, unsafe deserialization, reflected XSS, XML
external entities, JWT signature-verification bypass, JWT `alg`/key-type
confusion that reinterprets an RSA public key as an HMAC secret,
attacker-controlled JWT/OIDC JWKS key origin, SAML signed-versus-consumed assertion
confusion, prototype pollution, disabled TLS certificate verification,
predictable security tokens, server-side template injection, check/use state
races, unsafe mass assignment, cookie-authenticated cross-site request forgery,
attacker-length native-memory corruption, LDAP filter injection into
directory-backed group authorization, XPath predicate injection into XML-backed
authentication, OAuth authorization-code account-linking CSRF with session
takeover, login session fixation with authenticated-session rotation as the
control, password-reset link origin poisoning with a fixed public origin as the
control, credentialed CORS secret exfiltration with an exact configured origin
allowlist as the control, cross-site WebSocket hijacking with exact handshake
Origin authorization as the control, edge/origin web-cache deception with exact
routing and explicit public-only caching as the control, GraphQL alias/batch
amplification of recovery-code verification with execution-plan and
account-scoped resolver budgets as the control, and adversarial repository instructions
that try to suppress a real finding while inducing a false one. The corpus also
includes catastrophic-backtracking regular-expression denial of service on an
unauthenticated JavaScript event-loop path, paired with bounded linear
validation, and fail-open external policy authorization that exposes signing
keys on policy errors, paired with exact-boolean fail-closed enforcement. Three
runs per case produce 210 scans in the complete corpus.

Run scans into a directory outside this repository:

```powershell
cd sdk/typescript
npm run build
node ../../benchmarks/run-benchmark.mjs `
  --results-dir C:\security-benchmarks\copilot-security `
  --auth github `
  --mode deep
```

For a quicker diagnostic slice, select paired cases and limit the repetitions:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --results-dir C:\security-benchmarks\copilot-security-smoke `
  --case javascript-command-injection `
  --case javascript-safe-command `
  --runs 1 `
  --selection-only `
  --mode standard
```

`--selection-only` writes `benchmark-selection-manifest.json` and
`benchmark-report.json` into the external results directory and enforces only
the requested cases and run count. Runner evaluation always requires a
successful, case-and-run-matched status receipt. Without `--selection-only`, a
partial slice still fails the full-manifest completion gate. Use the default
full-manifest behavior for corpus claims.

Evaluate existing results without spending Copilot credits:

```powershell
node ./bin/copilot-security.mjs benchmark `
  ../../benchmarks/manifest.json `
  --results-dir C:\security-benchmarks\copilot-security `
  --format json
```

The thresholds in `manifest.json` are effectiveness targets. Do not lower them
merely to make a regression pass. Add cases when a real false negative or false
positive is found, preserving the vulnerable and fixed variants when possible.
