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

The versioned corpus currently contains forty-seven vulnerable/control pairs:
command injection, path traversal, archive symlink/hardlink write pivots with
link rejection and root-anchored no-follow writes as the control, executable
file upload/content placement, raw-DEFLATE data amplification with actual
per-entry output, expansion-ratio, and cumulative bundle budgets as the control,
AES-GCM key/nonce reuse that reveals victim plaintext from a known plaintext
and two valid-tag ciphertexts with fresh HKDF-derived per-envelope data keys
and profile-bound AAD as the control, even though the visible nonce repeats,
HTTP request smuggling across inconsistent gateway/backend framing,
duplicate-query parameter authorization confusion where a gateway selects the
first action but a reparsing backend selects the last, with bounded strict
decode-once handling and duplicate decoded-name rejection as the control,
HTTP response splitting through a CR/LF-injected download filename with
pre-serialization control-byte rejection and RFC 5987 encoding as the control,
object-level authorization, SQL injection, document-query operator injection,
server-side request forgery, unsafe deserialization, reflected XSS, XML
external entities, JWT signature-verification bypass, JWT `alg`/key-type
confusion that reinterprets an RSA public key as an HMAC secret,
attacker-controlled JWT/OIDC JWKS key origin, signed OIDC ID-token
audience/authorized-party/nonce misbinding across sibling clients,
WebAuthn/passkey credential-to-account misbinding despite correct challenge,
RP ID, origin, and signature verification, with a one-time user-bound
transaction and credential-owner-derived session as the control, signed
payment-webhook capture/replay with freshness and atomic event-id consumption
as the control, ECDSA `(r, s)` to `(r, n-s)` signature malleability that bypasses
signature-byte replay identity with atomic signed-event-ID consumption as the
control, cross-tenant application-cache key confusion where an
identity-omitting hit bypasses a correctly tenant-scoped cold lookup with a
trusted tenant-derived cache namespace and hit ownership check as the control,
RSA-SHA256-verified SAML signed-versus-consumed assertion confusion with
one-time request, issuer, destination, audience, recipient, lifetime, and
signed-object-to-session binding as the control, prototype pollution, disabled
TLS certificate verification,
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
account-scoped resolver budgets as the control, trusted-proxy client-identity
spoofing that rotates attacker-prepended `X-Forwarded-For` hops past a recovery
budget with exact proxy trust, right-to-left chain peeling, and account-scoped
limits as the control, and adversarial repository instructions
that try to suppress a real finding while inducing a false one. The corpus also
includes catastrophic-backtracking regular-expression denial of service on an
unauthenticated JavaScript event-loop path, paired with bounded linear
validation, and fail-open external policy authorization that exposes signing
keys on policy errors, paired with exact-boolean fail-closed enforcement. It
also covers DNS-rebinding SSRF where validation and connection resolve the same
hostname separately, paired with complete answer-set validation and a
destination-pinned, redirect-free transport. Three runs per case produce 282
scans in the complete corpus.

## Comparing scanner versions or implementations

Run both scanners against exactly the same manifest, case selection, and
repetition count. Preserve each scanner's `benchmark-report.json`; do not
compare raw finding totals because duplicates, missing runs, unstable
detections, and negative-control failures would be hidden.

The Windows application's **Benchmark** tab compares two compatible version
`1.0` benchmark reports. It first requires identical case IDs, case count, and
run count. It then reports deltas for completion, precision, recall, F1,
case/negative-control pass rates, stable detection, validation, attack paths,
code evidence, severity accuracy, and false positives per run. A baseline case
that stops passing, loses true positives, gains false positives, or gains false
negatives is a regression even if the aggregate score rises.

Use a full three-run corpus report for release claims. A one-run selected pair
is useful for development but cannot establish repeatability.

Run scans into a directory outside this repository:

```powershell
cd sdk/typescript
npm run build
node ../../benchmarks/run-benchmark.mjs `
  --results-dir C:\security-benchmarks\copilot-security `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --max-attempts 2 `
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

The runner creates `benchmark-campaign.json` before the first model call. Its
identities cover the manifest and fixture bytes, exact case/run selection,
model, effort, mode, optional credit bound, authentication source, runner bytes,
Node runtime, scanner entrypoint, compiled scanner code, bundled policy, package
metadata, and dependency lock. A results directory with files but no campaign
lock is rejected. Reusing a directory with a different corpus, scanner package,
runner, authentication source, or scan policy is also rejected; use a new
directory instead of mixing results.

Resume is fail-closed. A run is skipped only after its campaign-bound receipt,
complete scanner contract, sealed artifacts, scan ID, and findings, coverage,
and manifest hashes all validate. A partial, failed, mismatched, or tampered run
is moved intact under `.benchmark-attempts/<case>/run-N/attempt-N/` before a
fresh temporary Git repository and unique scanner-visible staging output are
created. The staging path is never reused and is promoted to the canonical run
directory only after the scanner returns, which keeps retries compatible with
scanners that retain their own path registry. `--force` also preserves the
previous run rather than deleting it. `--max-attempts N`
controls fresh process attempts per invocation, `--scan-timeout-ms N` supplies
an outer process-tree deadline, and `--workers N` runs up to eight independent
case/runs concurrently. The default remains one worker.

To measure another CLI that implements the same scan/output contract, select
its Node entrypoint and keep its results in a separate campaign directory:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --results-dir C:\security-benchmarks\compatible-baseline `
  --scanner-cli C:\tools\compatible-scanner\bin\security-scanner.mjs `
  --scanner-label compatible-baseline `
  --auth auto `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

For a valid baseline/candidate comparison, both reports must have the same
`corpusId` and `scanPolicyId`. Scanner package, label, and authentication source
may differ and are intentionally captured by different `campaignId` values.
The Windows comparison reader rejects one-sided provenance, changed fixture or
manifest bytes, different case/run selections, different model policies,
different per-case expectation counts, and redistributed run counts.

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
