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
path-and-line anchor, source text, and explanatory reasoning. The scanner's
sealer replaces model-authored snippets with bytes read from the registered
repository, so benchmark evidence is derived from the claimed source range.
Presence and substantive-quality flags are both retained in per-match
diagnostics.

The versioned corpus currently contains forty-nine vulnerable/control pairs:
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
attacker-length native-memory corruption, asynchronous session use-after-free
with deterministic fixed-pool reuse and a serialized retained-lifetime control,
attacker-controlled native format strings that select an in-scope session
capability as a variadic string argument with a literal-format data-only call as
the control, LDAP filter injection into
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
destination-pinned, redirect-free transport. Three runs per case produce 294
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
  --model PROVIDER_MODEL `
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

The cross-file wrapper lane has its own strict paired manifest:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/cross-file-framework-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-cross-file `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Python cross-file lane applies the same gates to explicit relative
from-imports and includes multiline parameter-binding counterevidence:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/python-cross-file-framework-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-python-cross-file `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Python multi-hop lane inserts one public module-level service relay between
the registered Flask route and sink wrapper. It also exercises bounded
multiline relay calls:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/python-multi-hop-framework-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-python-multi-hop `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The bounded multi-hop lane adds an exported service relay between the request
caller and command or SQL sink wrapper. Its paired negatives retain the same
three-file topology while using bounded shell-free execution or native SQL
binding:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/multi-hop-framework-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-multi-hop `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
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

If the runner is interrupted after scan receipts are written but before its
selection manifest or report is committed, rerun the identical campaign command
with `--finalize-only`. This mode validates the existing campaign identity,
does not launch or preserve any scanner attempt, atomically rebuilds
`benchmark-selection-manifest.json` when selection mode is active, and
atomically replaces `benchmark-report.json` from the existing fail-closed
receipts. It cannot be combined with `--force`. This is also the safe way to
materialize an incomplete campaign report after an outer job timeout without
silently granting additional model attempts.

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

The benchmark runner accepts a different bounded lowercase document namespace
only at its sealed-result verification boundary. It normalizes namespace fields
in memory for structural schema validation, then verifies the original scan
IDs, scope, derived fingerprint identities, artifact hashes, canonical paths,
and campaign receipt without rewriting the reference output. All three contract
documents must use the same namespace. Normal scanner result loading remains
strict to this product's namespace; compatibility mode is not available through
the scan or GUI result-reader paths.

For a valid cross-provider baseline/candidate comparison, both new reports must
have campaign schema `1.1` and the same `corpusId` and `comparisonPolicyId`.
The comparison identity binds mode, effort, and any explicit AI-credit bound,
but intentionally excludes the provider model: model, scanner package, label,
authentication source, runtime, and runner remain visible and are sealed into
different exact `scanPolicyId` and `campaignId` values. This permits a Copilot
model to be measured against a reference provider's model without pretending
the model identities are equal or weakening campaign resume integrity.

The Windows comparison reader rejects one-sided or mixed-version provenance,
changed fixture or manifest bytes, different case/run selections, different
mode/effort/credit policies, different per-case expectation counts, and
redistributed run counts. Two campaign-schema `1.0` reports remain comparable
only under their legacy model-bound `scanPolicyId`; they cannot be mixed with a
`1.1` report. Two reports with no campaign provenance remain legacy-comparable,
but a provenanced report cannot be compared with an unprovenanced one.

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
