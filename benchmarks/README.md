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

## Local secret-candidate microbenchmark

`secret-candidate-manifest.json` exercises the deterministic pre-model secret
engine separately from the multi-run model benchmark. Its typed positives cover
GitHub, GitLab, Slack, Stripe, npm, PyPI, SendGrid, Google, AWS, private-key
material, and generic high-entropy credential assignment. Placeholder,
low-entropy, environment-reference, and public-key controls must remain quiet.

The manifest stores only disjoint construction fragments. The Bun regression
materializes complete values inside a private temporary repository, requires
1.0 precision and 1.0 recall, and proves no materialized value reaches the
inventory. This keeps the public scanner repository self-scannable without
embedding credential-shaped benchmark strings.

## Reachable Git secret-history microbenchmark

`secret-history-manifest.json` proves the separate history lane against a real
temporary Git repository. The regression commits fragment-materialized GitHub,
GitLab, and generic refresh credentials, creates a second blob containing the
same GitLab value, deletes every candidate from the working tree, and then
scans reachable objects through the trusted Git boundary. Placeholder and
public-key history are negative controls.

The gate requires 1.0 precision and recall, zero false positives and false
negatives, a history-only source classification, exact path/rule identity,
deduplication across multiple blob IDs, complete bounded execution, and absence
of every materialized value from both the model inventory and private redacted
report. Additional regressions prove commit-horizon behavior, immutable path
scope, explicit disabled/non-Git/unavailable states, and strict `0..2048`
depth validation.

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

The Node object-authorization lane applies perfect selected-run gates to two
same-file and two cross-file cases. Each positive carries a request-controlled
invoice ID into a single-record lookup without constraining the record to the
authenticated customer. Each negative binds the same object ID to the trusted
customer identity in the lookup itself. UUID opacity, authentication, and ORM
use are deliberately common to both sides and therefore cannot satisfy the
authorization requirement:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/node-object-authorization-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-node-object-authorization `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The ASP.NET object-authorization lane applies the same perfect gates to a real
EF Core controller/repository pair. The positive keeps `[Authorize]` but passes
the route ID directly to `DbSet.FindAsync`; the executable witness proves that
an attacker-selected key returns another customer's invoice. The control uses
the same endpoint and entity topology while binding both invoice ID and the
authenticated customer ID in one `SingleOrDefaultAsync` predicate. A second
witness proves cross-customer selection returns no entity:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/aspnet-object-authorization-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-aspnet-object-authorization `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

dotnet run --project benchmarks/witnesses/aspnet-cross-file-idor/AspnetCrossFileIdorWitness.csproj --configuration Release
dotnet run --project benchmarks/witnesses/aspnet-cross-file-safe-authorization/AspnetCrossFileSafeAuthorizationWitness.csproj --configuration Release
```

The Spring object-authorization lane applies the same perfect gates to real
Spring Boot 4.1, Spring Data JPA, Spring Security, Hibernate, and H2 fixtures.
The positive keeps endpoint authentication but sends the route invoice ID to
typed `JpaRepository.findById`; an executable `@SpringBootTest` seeds two
customers and proves cross-customer disclosure. The control declares
`findByIdAndCustomerId`, binds its second argument to the typed
`Authentication.getName()` value, and proves the same foreign invoice is
rejected while the caller's own invoice remains available:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/spring-object-authorization-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-spring-object-authorization `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-cross-file-idor/pom.xml verify
wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-cross-file-safe-authorization/pom.xml verify
```

The Spring mass-assignment lane applies perfect gates to a matched Spring Boot
4.1 MVC/JPA pair. The positive binds a submitted `administrator` property
directly onto an `@Entity Account`, crosses a typed service, and calls
`JpaRepository.save`; its real MockMvc/Hibernate/H2 witness proves the
unintended privilege bit persisted. The control retains that topology and
request but applies `@InitBinder("account")` with an exact allowed-field list;
its witness proves the intended display name persists and the submitted
privilege bit does not:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/spring-mass-assignment-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-spring-mass-assignment `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-cross-file-mass-assignment/pom.xml verify
wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-cross-file-safe-binding/pom.xml verify
```

The GitHub Actions pwn-request lane applies perfect gates to a matched
`pull_request_target` pair. Both workflows request the immutable pull-request
head SHA and contain the same later `npm` execution. The positive explicitly
sets Checkout v7's `allow-unsafe-pr-checkout: true`, retains write-capable
permissions, and exposes a mock secret-bearing environment. The negative uses
read-only permissions and leaves Checkout v7's default fork refusal active.
The host model requires trigger, untrusted ref, checkout, path, and later
execution closure rather than flagging trigger or checkout co-occurrence. The
standalone witness executes harmless attacker-controlled code only in the
positive branch and proves the protected branch stops before execution:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/github-actions-pwn-request-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-github-actions-pwn-request `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

node ../../benchmarks/witnesses/github-actions-pwn-request/PwnRequestWitness.mjs
```

The self-hosted pull-request lane applies perfect gates to a same-file
CWE-284/CWE-829 pair. Both workflows use an ordinary `pull_request` trigger,
read-only permissions, official Checkout with credential persistence disabled,
and later execute the checked-out test command. The positive selects
`[self-hosted, linux, x64]`; the negative selects `ubuntu-latest`. The host
requires exact trigger, static runner classification, checkout, workspace, and
execution closure rather than reporting `runs-on` alone. The witness proves an
untrusted job can replace a user-writable release helper seen by a later
privileged job on the reused machine, while destruction and fresh hosted
provisioning preserve the trusted helper:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/github-actions-self-hosted-pr-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-github-actions-self-hosted-pr `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

node ../../benchmarks/witnesses/github-actions-self-hosted-pr/SelfHostedPrWitness.mjs
```

The GitHub Actions artifact-poisoning lane applies perfect gates to a
cross-workflow CWE-829 pair. Both producers run on `pull_request`, check out
untrusted code with read-only permissions, and upload the same named artifact.
The positive consumer runs under `workflow_run`, binds the official download to
the exact triggering run ID, extracts into the trusted workspace, and executes
the artifact with write, OIDC, and secret access. The negative extracts beneath
`runner.temp`, parses a narrowly typed integer, and fails closed without
executing artifact content. The witness proves harmless attacker code observes
a mock privileged token only in the positive branch:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/github-actions-artifact-poisoning-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-github-actions-artifact-poisoning `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

node ../../benchmarks/witnesses/github-actions-artifact-poisoning/ArtifactPoisoningWitness.mjs
```

The reusable-workflow injection lane applies perfect gates to a cross-file
CWE-094/CWE-095/CWE-116 pair. Both callers forward an attacker-controlled issue
comment into the same declared local `workflow_call` string input. The positive
compiles that input into official `actions/github-script` source with inherited
secrets and write/OIDC permissions. The negative assigns the expression once to
an intermediate environment entry and reads it only through `process.env`. The
witness proves that direct substitution executes a harmless second JavaScript
statement while the same payload remains one inert value in the control:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/github-actions-reusable-workflow-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-github-actions-reusable-workflow-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

node ../../benchmarks/witnesses/github-actions-reusable-workflow-injection/ReusableWorkflowInjectionWitness.mjs
```

The composite-action injection lane applies the same perfect gates to a
workflow-to-action CWE-094/CWE-095/CWE-116 pair. Both callers forward an
attacker-controlled issue comment and a mock release secret into the same
literal repository-local action. Both action metadata files declare the same
inputs and `runs.using: composite`. The positive compiles the release name into
official GitHub Script source; the negative assigns the expression to that
step's environment and reads it only through `process.env`. The witness proves
that direct substitution executes a harmless second JavaScript statement while
the same payload remains one inert value in the control:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/github-actions-composite-action-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-github-actions-composite-action-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

node ../../benchmarks/witnesses/github-actions-composite-action-injection/CompositeActionInjectionWitness.mjs
```

The SSRF framework lane applies the same strict gates to Node and Python
relative-import wrappers. Its positives pass complete caller-controlled URLs
to outbound HTTP sinks. Its negative controls select only complete
server-owned URLs by exact key and disable redirects. Both sides use the same
strict request deadline and decoded-response size ceiling so the pair isolates
destination control without introducing an unrelated buffering weakness:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/ssrf-framework-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-ssrf-framework `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Axios instance SSRF lane separately measures module and client identity,
destination argument roles, and client configuration. The positive fixture
passes a complete attacker-controlled URL to an `axios.create(...)` instance;
Axios's default permits that absolute URL to override the configured
`baseURL`. The paired control accepts only exact keys into server-owned
relative paths, sets `allowAbsoluteUrls: false`, and disables redirects. The
manifest requires perfect completion, precision, recall, validation,
attack-path evidence, code evidence, severity, and negative-case performance:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/node-axios-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-node-axios-ssrf `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Go `net/http` SSRF lane measures exact standard-library import identity,
typed request accessors, URL argument roles, one same-package wrapper, request
construction, and actual dispatch. The positive passes a query-controlled
complete URL through `NewRequestWithContext` into a constructed
`http.Client.Do`. The control maps the request value to a fixed server-owned
complete URL, rejects unknown keys, and returns `http.ErrUseLastResponse` to
stop redirects. Real `httptest` services prove the positive can reach a mock
metadata endpoint and that neither a direct internal URL nor an allowed
server's redirect reaches it in the control:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-net-http-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-net-http-ssrf `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-ssrf
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-fetch
go test ./...
Pop-Location
```

The Go process-execution lane measures exact `os/exec` import identity, typed
request accessors, executable and argument roles, one same-package wrapper,
immutable complete-command selection, and construction-to-execution closure.
The positive formats the request value into the string interpreted by `sh -c`
and reaches `CombinedOutput`; the control retains the request, wrapper, shell,
flag, finisher, and attack bytes but only selects a complete server-owned
command. Each module copies its running test executable into a temporary `sh`
witness, making the exploit and control deterministic on Windows and Linux
without invoking the host shell:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-os-exec-command-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-os-exec-command-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-shell-command-injection
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-shell-command
go test ./...
Pop-Location
```

The Go `database/sql` injection lane measures exact package and receiver
identity, query-text argument positions, placeholder-value exclusion, one
same-package wrapper, and prepared-statement execution closure. The positive
formats the request value into `DB.QueryContext` query grammar and exposes an
internal record. The control passes identical metacharacters only as a bound
value to a fixed query. Deterministic standard-library drivers prove both
behaviors without a database service or third-party dependency:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-database-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-database-sql-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-sql-injection
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-sql
go test ./...
Pop-Location
```

The sqlx lane measures exact upstream import and typed DB/Tx/Conn identity,
receiver and package-helper query positions, destination-before-query
`Select`/`Get`, named-value exclusion, placeholder rebinding, and extended
statement execution closure. The positive formats the request value into a
`DB.Select` query and exposes an internal record. The matched control preserves
the same topology while passing identical bytes as one placeholder value. Both
fixtures use an offline API-compatible sqlx adapter over a deterministic
standard-library driver:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-sqlx-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-sqlx-sql-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-sqlx-sqli
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-sqlx
go test ./...
Pop-Location
```

The GORM v2 lane measures exact `gorm.io/gorm` import and `*gorm.DB` identity,
query-fragment argument roles, fluent and assigned builder propagation, and
construction-to-finisher execution closure. The traditional pair formats the
request value into `Raw` query grammar and reaches `Scan`; the generic pair
uses `gorm.G[string](db)`, retains a request-derived `Where` predicate, and
reaches context-first `Find`. Each matched control retains its handler,
wrapper, adapter, and attack bytes but places those bytes after a placeholder
in a fixed query. All four fixtures use offline signature-compatible GORM
subsets over deterministic standard-library drivers:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-gorm-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-gorm-sql-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-gorm-sqli
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-gorm
go test ./...
Pop-Location
Push-Location fixtures\go-gorm-generics-sqli
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-gorm-generics
go test ./...
Pop-Location
```

The Masterminds/Squirrel lane measures exact upstream import, builder and
runner identity, structural-versus-bound argument roles, immutable fluent and
assigned propagation, helper dispatch, materialization, preparation, and
execution closure. The positive formats the request value into a `Where`
predicate and proves `RunWith(...).Query()` exposes an internal record. The
matched control preserves the same topology and bytes but supplies them only
after a placeholder. Both fixtures use an offline signature-compatible
Squirrel subset over a deterministic standard-library driver:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-squirrel-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-squirrel-sql-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-squirrel-sqli
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-squirrel
go test ./...
Pop-Location
```

The pgx v5 lane adds exact `pgx` and `pgxpool` import and receiver identity,
context/SQL/value argument roles, fixed prepared-name execution, and typed
batch queue-to-`SendBatch` closure. It separately resolves exact local custom
`QueryRewriter` types, follows request-derived receiver fields and preserved
input SQL into the first returned value, and preserves that rewrite through
direct or batched dispatch. It rejects taint confined to returned arguments,
later `$1` values, built-in named/struct value rewriters, inert preparation,
undispatched or replaced batches, ambiguous methods, v4/fork/lookalike imports,
and untyped methods. The four fixtures use offline module replacements under
the exact public pgx v5 path and minimal API-compatible witnesses. This
preserves deterministic direct-query and custom-rewriter exploit/control
behavior without claiming that the witnesses are the PostgreSQL wire protocol:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-pgx-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-pgx-sql-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-pgx-sqli
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-pgx
go test ./...
Pop-Location
Push-Location fixtures\go-pgx-query-rewriter-sqli
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-pgx-query-rewriter
go test ./...
Pop-Location
```

The pgconn lane covers lower-level PostgreSQL APIs that high-level pgx and
`database/sql` models do not reach. It distinguishes simple-protocol `Exec`
from extended-protocol `ExecParams`, preserves the SQL position of `CopyFrom`
and `CopyTo`, follows fixed prepared names and exact statement descriptions,
and requires queued `pgconn.Batch` or `Pipeline` work to reach `ExecBatch`,
`Flush`, or `Sync`. An unsynchronized pipeline, including one closed before a
flush, is a negative control. The exact pgx v5 replacement supplies a
deterministic signature-compatible execution witness without claiming to
implement the PostgreSQL wire protocol:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-pgconn-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-pgconn-sql-injection `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-pgconn-sqli
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-pgconn
go test ./...
Pop-Location
```

The template-injection framework lane applies the same strict gates to Node
and Python relative-import wrappers. Its positives compile caller-controlled
Pug or Jinja template source. Its negative controls pass the same untrusted
display value across the same boundary but bind it only to an explicitly
constructed render-data field in a fixed server-owned template. This isolates
template grammar control from ordinary escaped data interpolation:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/template-injection-framework-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-template-injection-framework `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Java cross-file template lane exercises a constructor-injected Spring
service and the exact fourth, template-source argument of Apache Velocity
`evaluate`. Its negative control preserves the controller, receiver type,
service call, and request value, but HTML-encodes that value into
`VelocityContext` while evaluating fixed server-owned source. The explicit
encoding also prevents the control from concealing a distinct reflected-XSS
path in Velocity's non-auto-escaping output:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/java-cross-file-template-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-java-template `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Java path lane carries an annotated Spring request parameter through two
constructor-injected service boundaries into `Files.readString`. The vulnerable
fixture passes the value directly to `Path.resolve`, which permits both parent
traversal and an absolute later operand that discards the trusted root. The
negative control rejects absolute input, normalizes and checks component-aware
lexical containment, then resolves both the existing root and target with
`toRealPath` and checks real containment before opening the file. This rejects
sibling-prefix and symbolic-link pivots; a deployment where an attacker can
rename filesystem objects concurrently still needs an OS-specific handle-based
open boundary. Dependency-free JDK witnesses exercise both exploit forms,
sibling-prefix rejection, symbolic-link rejection when the host permits links,
and an allowed in-root document:

```powershell
javac -d C:\security-benchmarks\java-path-vulnerable `
  benchmarks\witnesses\java-multi-hop-path-traversal\VulnerablePathWitness.java
java -cp C:\security-benchmarks\java-path-vulnerable VulnerablePathWitness

javac -d C:\security-benchmarks\java-path-safe `
  benchmarks\witnesses\java-multi-hop-safe-path\SafePathWitness.java
java -cp C:\security-benchmarks\java-path-safe SafePathWitness
```

Run the strict live pair with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/java-multi-hop-path-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-java-multi-hop-path `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Java SSRF lane carries an annotated Spring request value through two
constructor-injected service boundaries, builds a JDK `HttpRequest` from the
complete caller-controlled URI, and sends it through a typed `HttpClient`. The
negative control retains the same topology and local request construction, but
uses the request value only as an exact key into fixed server-owned complete
URIs and requires `HttpClient.Redirect.NEVER`. Redirect rejection is not
initial-destination authorization; it is paired with fixed selection so the
control closes both boundaries. Pure-JDK witnesses bind loopback-only HTTP
servers to prove that the vulnerable URI reaches a private service while the
control rejects a complete URI before transport and still accepts the fixed
`status` key:

```powershell
javac --add-modules jdk.httpserver `
  -d C:\security-benchmarks\java-ssrf-vulnerable `
  benchmarks\witnesses\java-multi-hop-ssrf\VulnerableSsrfWitness.java
java --add-modules jdk.httpserver `
  -cp C:\security-benchmarks\java-ssrf-vulnerable VulnerableSsrfWitness

javac --add-modules jdk.httpserver `
  -d C:\security-benchmarks\java-ssrf-safe `
  benchmarks\witnesses\java-multi-hop-safe-fetch\SafeFetchWitness.java
java --add-modules jdk.httpserver `
  -cp C:\security-benchmarks\java-ssrf-safe SafeFetchWitness
```

Run the strict live pair with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/java-multi-hop-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-java-multi-hop-ssrf `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Java WebClient lane uses the same three-file Spring topology but terminates
at the first argument of reactive `WebClient.UriSpec.uri`. The host accepts
injected clients, `create()` and `builder().build()` chains, fully qualified
construction, and locally assigned request specifications only when the root
receiver is typed. Later URI-template variables are not complete-destination
control. The safe fixture maps the request key to one fixed complete `URI`,
uses a `JdkClientHttpConnector` configured with `HttpClient.Redirect.NEVER`,
releases the response body, and applies a short reactive timeout.

The executable witnesses use the actual Spring WebClient against loopback-only
HTTP servers:

```powershell
mvn --file benchmarks\witnesses\java-webclient-ssrf\pom.xml `
  compile exec:java -Dexec.mainClass=example.VulnerableWebClientWitness

mvn --file benchmarks\witnesses\java-webclient-safe-fetch\pom.xml `
  compile exec:java -Dexec.mainClass=example.SafeWebClientWitness
```

Run the strict live pair with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/java-webclient-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-java-webclient-ssrf `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The Java OkHttp lane follows the same three-file Spring topology into
`Request.Builder.url`, but emits a host hypothesis only when the exact request
is passed to a typed `OkHttpClient.newCall` and then `execute` or `enqueue`.
This execution-aware closure rejects unused request construction, `newCall`
without dispatch, unrelated URL builders, and local `Request` or
`OkHttpClient` lookalikes. The safe fixture treats input only as an exact key
into fixed complete URLs and configures both `followRedirects(false)` and
`followSslRedirects(false)`.

The executable witnesses use OkHttp 5.3.0 against loopback-only HTTP servers:

```powershell
mvn --file benchmarks\witnesses\java-okhttp-ssrf\pom.xml `
  compile exec:java -Dexec.mainClass=example.VulnerableOkHttpWitness

mvn --file benchmarks\witnesses\java-okhttp-safe-fetch\pom.xml `
  compile exec:java -Dexec.mainClass=example.SafeOkHttpWitness
```

Run the strict live pair with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/java-okhttp-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-java-okhttp-ssrf `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The ASP.NET cross-file lane applies the same strict gates to constructor-
injected controller/service flows. Its command positive reaches `cmd.exe /c`,
while its control uses a fixed executable, disables shell execution, and adds
the request value as one `ArgumentList` entry. Its SQL positive reaches the
query-text argument of `SqlCommand`, while its control binds the same value
through a typed `SqlParameter`. Dependency-free witness executables prove that
the SQL payload selects a different in-memory user in the vulnerable fixture
and remains ordinary data in the control:

```powershell
dotnet run --project benchmarks/witnesses/aspnet-cross-file-sql-injection/AspNetCrossFileSqlInjectionWitness.csproj --configuration Release
dotnet run --project benchmarks/witnesses/aspnet-cross-file-safe-sql/AspNetCrossFileSafeSqlWitness.csproj --configuration Release
```

The ASP.NET SSRF lane carries a complete `[FromQuery]` URI through the same
constructor-injected topology into `HttpClient.GetAsync`. Its control uses the
request value only as an exact key into fixed server-owned HTTPS destinations,
rejects unknown keys before transport, and disables redirects. In-memory
message handlers prove the exploit and control without issuing real network
requests:

```powershell
dotnet run --project benchmarks/witnesses/aspnet-cross-file-ssrf/AspNetCrossFileSsrfWitness.csproj --configuration Release
dotnet run --project benchmarks/witnesses/aspnet-cross-file-safe-fetch/AspNetCrossFileSafeFetchWitness.csproj --configuration Release
```

Run the strict live pair with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/aspnet-cross-file-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-aspnet-cross-file-ssrf `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The ASP.NET path lane adds a second typed service hop between the controller
and storage sink. The vulnerable fixture lets a later rooted `Path.Combine`
argument discard the configured root and lets `..` escape it. The control
rejects rooted input, resolves full root and candidate paths, and rejects any
relative result that is `..`, begins with an exact parent-directory boundary,
or remains rooted. The control assumes its content root is server-owned; a
deployment with attacker-writable links or reparse points needs a link-safe
open boundary as well. Dependency-free witnesses exercise parent traversal,
absolute reset, sibling-prefix escape, and an allowed in-root document:

```powershell
dotnet run --project benchmarks/witnesses/aspnet-multi-hop-path-traversal/AspNetMultiHopPathTraversalWitness.csproj --configuration Release
dotnet run --project benchmarks/witnesses/aspnet-multi-hop-safe-path/AspNetMultiHopSafePathWitness.csproj --configuration Release
```

Run the strict live pair with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/aspnet-multi-hop-path-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-aspnet-multi-hop-path `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

Run the live scanner lane with an inner model-turn deadline below the outer
process deadline:

The examples use twenty minutes per model turn, not per complete scan. A
baseline deep ASP.NET path campaign took 12m05s for the positive and 15m16s for
the safe control. The stricter endpoint-role closure campaign took 32m31s and
22m13s in total while no individual turn exhausted the twenty-minute deadline.
The former six-minute override forced three fresh-session timeouts per case
without any allowance, authentication, rate-limit, or classifier failure. The
scanner default remains one hour per turn, while the benchmark runner's
independent outer deadline defaults to four hours.

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/aspnet-cross-file-framework-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-aspnet-cross-file `
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
previous run rather than deleting it. Archive allocation skips occupied slots,
including duplicate legacy receipts, instead of terminating the retry loop.
Each child process is drained through adjacent `.scanner.stdout.log` and
`.scanner.stderr.log` files; console mirroring is best-effort, so terminal or CI
log disconnection does not kill the campaign. `--max-attempts N`
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
