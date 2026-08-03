# Copilot Security

Copilot Security is a repository security scanner driven by the GitHub Copilot
CLI installed on the local machine. It combines deterministic inventory and
artifact validation with threat modeling, multi-pass discovery, exploit
validation, attack-path analysis, canonical JSON, SARIF/report generation,
scan history, diff scanning, bulk scanning, and finding management.

Production scans use GitHub's official `@github/copilot-sdk` to control the
system `copilot` executable.

## Status

This is a pre-1.0, production-oriented standalone Secwest scanner. Standard
repository, path, committed-diff, and working-tree scans use a Copilot-native
plugin and runtime.
Deep mode uses repeated independent Copilot subagents and adds explicit
systems, supply-chain/configuration, business-logic, control-differential, and
compositional/temporal attack-path, and residual-miss review lenses before
centralized validation.

Every scan also receives a mandatory independent correction turn. The host
builds a bounded, prioritized residual-risk inventory from exact source
locations across common application, systems, infrastructure, and CI
languages. Overlapping hits are coalesced into bounded evidence windows, and
category and file diversity are preserved before the remaining prompt budget
is filled by risk priority. Repository-controlled excerpt bytes are
base64-encoded before entering the correction prompt, path and line ranges
remain structured, and prompt metacharacters in all host inventories are
escaped. The correction turn reopens the source, traces each signal through
attacker control and nearby guards, adds missed exploitable defects, and
rejects safe or mitigated flows. This supplements model-led discovery without
treating lexical matches or repository-written scanner instructions as
findings or control flow.

The immutable host inventory omits conventional generated and dependency
trees, including .NET `bin`/`obj`, Node `node_modules`, and common build,
coverage, fixture, example, test, and vendor directories. Explicit path and
diff scope remains authoritative; ignored generated output cannot silently
stand in for reviewed application source.

The residual pass also applies typed framework data-flow models for Node HTTP,
Python web, Spring/servlet, and ASP.NET command-execution, raw-SQL, and
server-side request-forgery boundaries, plus Node and Python server-side
request forgery and server-side template injection. Each applicable
row identifies an exact source line, sink line, CWE family, and nearby
candidate controls. For Java, the host resolves uniquely named service types
from controller fields, confines calls to parsed public or protected method
bodies, and preserves annotated Spring or servlet-assigned request values
through the exact call argument and wrapper parameter. For C#, the host
likewise resolves one uniquely named class, record, or struct from an ASP.NET
controller field or static receiver, binds the exact service-call argument to
the public, protected, or internal wrapper parameter, and preserves either an
annotated bound parameter or an assigned `HttpRequest` field through
`ProcessStartInfo`/`Process.Start`, the query-text argument of `SqlCommand`,
`FromSqlRaw`, or `ExecuteSqlRaw`, or a complete outbound `HttpClient` request
URI. For Node/TypeScript
relative-module wrappers, the host can
emit bounded one-hop and two-hop cross-file chains. For Python, it can resolve
either one direct wrapper or exactly one public module-level relay through
explicit relative from-imports, bind each exact positional argument, and
inspect bounded multiline relay and sink calls, including DB-API binding and
outbound HTTP calls. A two-hop row contains the exact caller import and
argument, relay parameter, relay import and argument, sink-wrapper parameter,
and sink that references that parameter. Language strings and comments are
masked before structural source, sink, and call matching. These rows remain
hypotheses: the correction turn must prove runtime same-value flow through
every recorded file and reject unused imports, fixed arguments, intervening
reassignment, out-of-function calls, unreachable wrappers, text that only
resembles code, and API co-occurrence. Argument vectors without a shell,
native SQL parameter binding, exact parsed-host or fixed-destination
allowlists, redirect rejection, connection-address validation or pinning, and
fixed template source with explicit render-data binding count only when they
apply to the same value, are context-correct, and dominate the sink. A URL or
hostname substring check is not classified as an exact-host control. Output
escaping does not sanitize attacker-controlled template grammar, while a fixed
template that receives untrusted data only as a named context field is not
template-source injection. That distinction does not itself prove XSS safety:
a non-auto-escaping engine still requires context-appropriate output encoding.

The correction turn also receives a deterministic reconciliation of
`in_scope_files.txt` against the draft coverage document. This catches omitted
files even when they contain no known lexical risk signal. The host repeats the
same reconciliation while sealing: an unreviewed inventory path is added as
explicit deferred work and coverage is downgraded to `partial`, so a
model-written `complete` claim cannot conceal a coverage gap.

The immutable scope is created before Copilot starts. A trusted host helper
walks the disposable repository snapshot for repository/path scans or resolves
the exact changed-file set for diff scans, writes zero-preview rank metadata,
`in_scope_files.txt`, and `deep_review_input.jsonl`, and records the SHA-256 of
all three. The host also writes an exact JSON inventory of repository
`SECURITY.md` paths. Copilot must consume these files without regenerating,
narrowing, reordering, or modifying them; empty inventories are authoritative.
The host verifies every digest before preparation and again before sealing.
It also sandwiches a SHA-256 comparison of every model-visible file between
authoritative registered-target checks before model execution, before contract
preparation, and before completion. A concurrent checkout mutation therefore
fails the scan instead of associating reviewed bytes with a different target
snapshot.
This removes model-selected scope and avoids unreliable model-side Git,
ripgrep, Python, or policy-glob execution.

The host separately audits every draft finding before that correction turn.
It lists missing CWE assignments, absent, unanchored, out-of-range, or
repository-ungrounded code evidence, weak validation, weak attack paths,
unknown code-evidence references, and validation or attack-path dispositions
that contradict reportability. Common draft line aliases are accepted only
when the claimed path and line resolve inside the registered repository. Every
`rootCause`, `validation`, and `attackPath` evidence reference must name an ID
in that finding's `codeEvidence` catalog; artifact paths belong in coverage
receipts instead. Copilot must either repair each row from repository evidence
or remove it from `findings.json` and close coverage accurately. Equivalent
broken-control field names are accepted when their contents are substantive.
This prevents a structurally valid but evidentially empty finding—or one whose
attack path points only at unrelated artifacts—from silently surviving the
model-to-contract boundary.

During deterministic sealing, every accepted code-evidence excerpt is read
again from the registered repository at its claimed path and line range. The
repository bytes replace model-authored snippet text; missing, escaping,
oversized, binary, empty, or out-of-range evidence is removed and cannot be
used as proof. Draft JSON parsing tolerates an optional UTF-8 BOM so a valid
PowerShell-authored artifact does not trigger an otherwise needless full scan
retry.

After the correction turn, the host rebuilds both the coverage-gap and
finding-quality inventories from the files Copilot actually wrote. If any gap
remains, Copilot receives one bounded repair turn containing only the
outstanding host inventories. The host then audits the files again and fails
closed instead of reporting completion when a gap persists or the closure
state cannot be read. The first correction turn's existing artifact-recovery
path remains available for a transport failure after all drafts were written;
an unsuccessful deterministic closure audit does not use that escape hatch.
The coverage audit includes synthetic `coverage.deferred[index]` rows as well
as immutable repository paths, so an orphan or speculative deferral cannot
appear only during sealing and unexpectedly downgrade an otherwise closed scan.
The model is never required to author `report.md`: after the structured drafts
pass closure, the host renders the Markdown report deterministically, hashes
that exact projection into the manifest, writes it atomically, and seals the
canonical artifact set. A missing model-written report therefore cannot turn
an otherwise valid scan into a late I/O failure.

Recoverable Copilot model-call failures are retried by the CLI inside the
existing turn, with a fixed two-retry ceiling. Explicit safety-classifier,
content-filter, Responsible AI, and policy-violation refusals receive a
separate six-retry native budget even when the provider labels them terminal.
If the provider still refuses, the host makes up to two additional prompt
replays with progressively narrower authorized defensive framing. These
replays preserve the original scan contract and existing correct drafts, use
idempotent writes, forbid external targeting and weaponization, and apply to
the initial, quality-gate, and final repair turns.

The retry classifier is deliberately narrow: ordinary uses of words such as
`policy`, `blocked`, `unsafe`, authentication errors, tool failures, transport
failures, and scanner safety-limit diagnostics do not trigger prompt replay.
Persistent safety refusal fails with a fixed diagnostic after three total
prompt attempts rather than being reported as a successful or clean scan.
Startup and session creation are cancellation-aware, and a partially started
CLI runtime is gracefully stopped or force-stopped before the original error
is returned. Each model turn has an independent host-enforced one-hour
wall-clock deadline; expiry aborts the Copilot session instead of waiting for
the SDK's maximum process lifetime. Set
`COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS` to a whole number from `60000` through
`86400000` when a shorter benchmark bound or a longer deep-scan turn is needed.
Keep this inner deadline below an outer benchmark or service process deadline
so the scanner can perform its own bounded recovery first. If a deadline or
recognized transport interruption occurs after all three draft artifacts
exist, the scanner stops replaying the full scan and hands the drafts to the
deterministic workbench. The workbench must normalize, validate, and seal them
before the result can succeed; missing drafts still start a fresh isolated
session.

Model turns occasionally leave complete flow-style object literals instead of
strict JSON. Before workbench sealing, the host may normalize only bounded,
regular, non-symlink draft files as data. The parser does not evaluate draft
content, rejects aliases, duplicate keys, empty files, non-object roots, and
ambiguous syntax, and stages every repair before replacing any draft. Existing
strict JSON is not rewritten. A normalized draft still has to pass the same
canonical schemas, repository evidence grounding, coverage reconciliation, and
seal checks; normalization cannot make an invalid security result acceptable.

A hard model-turn deadline or recognized transport interruption starts a new,
isolated Copilot CLI session over the same disposable analysis snapshot and
immutable host worklist. Direct scans allow three sessions by default. Set
`--max-session-attempts N`, or SDK `maxSessionAttempts`, from `1` through `5`;
`1` disables fresh-session recovery. Authentication, authorization, scanner
contract, sandbox, cancellation, cost-limit, and exhausted safety-classifier
failures remain terminal. Recovery never trusts conversational state or a
prior session's files: the new session must re-consume the inventory, treat
existing artifacts as possibly partial drafts, reopen repository evidence,
and pass the same deterministic host audits before sealing. Session shutdown
is bounded so a hung disconnect cannot prevent the next attempt. Streamed and
persisted token usage is accumulated across all attempt roots and their
subagents, so scanner-owned cost enforcement cannot be reset by recovery.

## Requirements

- GitHub Copilot CLI, installed and signed in (`copilot login`)
- Node.js 22.13+, 24, or 26
- Python 3.10+ (`tomli` is also needed on Python 3.10)
- Git

The scanner uses the installed CLI found on `PATH`. Set `COPILOT_CLI_PATH` or
the SDK `copilotPath` option to select another executable.

## Scan history

`copilot-security scans compare BEFORE_SCAN_ID AFTER_SCAN_ID` automatically
matches findings by root cause, reuses saved matches, and identifies new,
persisting, reopened, resolved, or unknown findings. Missing findings remain
unknown when the later scan is incomplete or their original location was not
reviewed.

## Build and run

```powershell
cd sdk/typescript
npx --yes pnpm@11.9.0 install
npx --yes pnpm@11.9.0 run build
node ./bin/copilot-security.mjs scan C:\path\to\repository --auth github
```

Common scan forms:

```powershell
# Whole repository
node ./bin/copilot-security.mjs scan C:\code\project

# Selected paths
node ./bin/copilot-security.mjs scan C:\code\project --path src --path server

# Committed diff
node ./bin/copilot-security.mjs scan C:\code\project --diff origin/main

# Staged and unstaged changes
node ./bin/copilot-security.mjs scan C:\code\project --working-tree

# Repeated independent discovery with centralized validation
node ./bin/copilot-security.mjs scan C:\code\project --mode deep

# Use CodeQL, Semgrep, Sonar, Trivy, OSV-Scanner, or other SARIF 2.1.0
# results as untrusted candidates for independent Copilot validation
node ./bin/copilot-security.mjs scan C:\code\project `
  --seed-sarif C:\analysis\codeql.sarif `
  --seed-sarif C:\analysis\trivy.sarif

# Map absolute SARIF paths produced from a different checkout root
node ./bin/copilot-security.mjs scan C:\code\project `
  --seed-sarif C:\analysis\results.sarif `
  --sarif-source-root C:\build\original-checkout
```

### Hybrid SARIF candidate review

`--seed-sarif` accepts repeatable SARIF 2.1.0 files and turns their
unsuppressed, repository-located results into candidate rows. It supports
primary locations and source-to-sink code-flow locations, extracts CWE and
severity hints, maps an optional original checkout root, validates every path
and line against the current repository, records source SHA-256 provenance,
and gives every imported candidate the scanner's normal validation and attack
path workflow. Imported alerts do not bypass native inventory, independent
discovery, residual-miss review, or final evidence requirements.

SARIF is treated as hostile input. The normalizer rejects symlinked inputs,
path traversal, locations outside the repository, malformed or oversized
documents, and excessive result/location counts. It intentionally discards
result messages, snippets, fixes, fingerprints, arbitrary properties, and
embedded source so an upstream analyzer cannot inject instructions or leak a
detected secret into the model context. Suppressed and absent results are not
seeded, and ignored counts remain visible in the provenance artifact. Seed
files and their source root are preserved in the launch recipe so history
reruns use the same inputs.

See [`docs/scanner-landscape.md`](docs/scanner-landscape.md) for the design
comparison and improvement backlog derived from other mature scanners.

The dedicated `benchmarks/sarif-seed-manifest.json` campaign pairs a real
command-injection seed with a deliberately noisy safe-process-execution seed.
It tests recall gain and false-positive rejection while its SARIF messages and
fingerprints contain hostile text and fake secrets that must never reach scan
artifacts or model context:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/sarif-seed-manifest.json `
  --results-dir C:\security-benchmarks\sarif-seeds `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The strict `benchmarks/framework-model-manifest.json` campaign exercises the
initial typed model pack with one command-injection positive, one shell-free
negative, one SQL-injection positive, and one parameter-bound SQL negative:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/framework-model-manifest.json `
  --results-dir C:\security-benchmarks\framework-models `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Python relative-import lane measures cross-file command and SQL wrappers
against shell-free and multiline parameter-bound negative controls:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/python-cross-file-framework-manifest.json `
  --results-dir C:\security-benchmarks\python-cross-file `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Python multi-hop lane adds one public service relay and keeps the same
strict positive, safe, reassignment, fixed-argument, and text-only controls:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/python-multi-hop-framework-manifest.json `
  --results-dir C:\security-benchmarks\python-multi-hop `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The SSRF framework lane pairs Node and Python cross-file absolute-URL flows
with fixed complete-URL selection and redirect-free negative controls:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/ssrf-framework-manifest.json `
  --results-dir C:\security-benchmarks\ssrf-framework `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The template-injection framework lane pairs Node/Pug and Python/Jinja
cross-file template-source flows with fixed-template, explicit-render-data
negative controls:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/template-injection-framework-manifest.json `
  --results-dir C:\security-benchmarks\template-injection-framework `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Java lane pairs a constructor-injected Spring service that evaluates the
request value as Apache Velocity template source with the same controller and
service topology using a fixed template plus explicitly HTML-encoded
`VelocityContext` data:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/java-cross-file-template-manifest.json `
  --results-dir C:\security-benchmarks\java-cross-file-template `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The ASP.NET lane pairs constructor-injected controller/service flows for
command and SQL injection with the same topologies using a fixed shell-free
executable plus `ArgumentList`, or fixed SQL plus a typed `SqlParameter`:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/aspnet-cross-file-framework-manifest.json `
  --results-dir C:\security-benchmarks\aspnet-cross-file-framework `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The separate ASP.NET SSRF lane passes a complete attacker-controlled URI to
`HttpClient.GetAsync`; its negative control treats the request value only as
an exact key into a server-owned map of complete HTTPS destinations and
disables redirects. Dependency-free transport witnesses prove both behaviors
without sending traffic to the real network:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/aspnet-cross-file-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\aspnet-cross-file-ssrf `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The ASP.NET path lane follows a request value across two uniquely typed
service boundaries into `Path.Combine` and `File.ReadAllTextAsync`. Its
negative control rejects rooted input, canonicalizes the configured root and
candidate, and proves exact relative containment before the file operation.
Executable witnesses cover parent traversal, absolute-path reset,
sibling-prefix bypass, and a legitimate in-root read:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/aspnet-multi-hop-path-manifest.json `
  --results-dir C:\security-benchmarks\aspnet-multi-hop-path `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

Use `--model` and `--effort` to select a Copilot model and reasoning effort.
The default is `gpt-5.6-sol` with `xhigh` effort.
`--model auto` delegates model selection to Copilot and does not send a
reasoning-effort override because Copilot rejects reasoning effort for the
automatic model.
The scanner imposes no AI-credit or request allowance by default. Usage values
in results are consumption telemetry, not a remaining balance. Use
`--max-ai-credits N` only when you want Copilot to enforce an optional native
session limit across the root session and its subagents; Copilot CLI requires
an explicit limit of at least 30 credits. Service-side transient rate limits
remain separate from billing or plan allowance and use the scanner's bounded
reconnect path. A configured native AI-credit limit is applied independently
to every fresh session; scanner-owned `--max-cost` accounting remains
cumulative across all fresh sessions.

### Isolated scanner state

Copilot Security keeps its state under `~/.copilot-security` by default. Set
`COPILOT_SECURITY_HOME` to choose a different absolute scanner-owned root. Its
private runtime subdirectory is named `copilot-security-home`.

Scanner artifacts, locks, configuration, temporary directories, and output
roots remain outside every other scanner's state tree. `COPILOT_HOME` is read
only to obtain the user's existing Copilot CLI authentication. File-backed
credentials are copied into the isolated runtime when needed. For operating
system credential stores, the scanner imports only Copilot's non-secret active
account selector (`host` and `login`) so the isolated CLI chooses the same
Copilot user instead of silently falling back to a different `gh` account. It
does not copy tokens, trusted folders, settings, experiments, sessions, or
other ambient state, and it preserves an account explicitly selected in the
scanner home. The deprecated `COPILOT_SECURITY_STATE_DIR` alias selects this
scanner's state root only. This separation lets multiple scanners run
concurrently without sharing mutable state.

## Native Windows application

The repository includes a native WPF `.NET 8` desktop application in
[`apps/windows`](apps/windows). It exposes whole-repository, scoped path,
committed-diff, and working-tree scans; standard/deep modes; model and effort
selection; optional cost and credit bounds; live progress and process-tree
cancellation; findings, validation, attack paths, reports, private scan
history, diagnostics, corpus evaluation, and baseline/candidate effectiveness
comparison.
The New scan tab also accepts repeatable SARIF seed files and an optional
original SARIF source root, using the same hardened normalization and
independent-review contract as the CLI and SDK.

The desktop application remains a client of this standalone scanner. It does
not duplicate prompts or model orchestration, invoke a command shell, share
another scanner's state, or read credentials. Before findings are displayed it
recomputes the sealed manifest digests for the findings and coverage artifacts.

```powershell
dotnet run `
  --project apps/windows/CopilotSecurity.Core.Tests/CopilotSecurity.Core.Tests.csproj `
  --configuration Release

dotnet run `
  --project apps/windows/CopilotSecurity.Gui/CopilotSecurity.Gui.csproj `
  --configuration Release
```

See [`apps/windows/README.md`](apps/windows/README.md) for the architecture,
trust boundaries, publication command, benchmark comparison workflow, and
failure/recovery behavior.

## Effectiveness benchmark

`benchmarks/manifest.json` defines paired vulnerable and fixed fixtures for
command injection, path traversal, archive symlink/hardlink write pivots,
decompression bombs with actual-output and cumulative expansion budgets,
object-level authorization, SQL injection,
server-side request forgery, unsafe deserialization, reflected XSS, XML
external entities, JWT signature-verification bypass, attacker-controlled
JWT `alg`/key-type confusion that reuses an RSA public key as an HMAC secret,
attacker-controlled JWT/OIDC JWKS key origin, signed OIDC ID-token
audience/authorized-party/nonce misbinding across sibling clients, signed
payment-webhook replay despite correct HMAC verification, ECDSA signature
malleability that bypasses signature-byte idempotency while the signature and
freshness checks succeed, cross-tenant
application-cache key confusion despite correctly scoped cold repository
lookups, prototype pollution, RSA-SHA256-verified SAML signed-versus-consumed
assertion confusion across one-time request and session creation, disabled TLS certificate
verification, predictable security tokens, server-side template injection,
check/use state races, unsafe mass assignment, cookie-authenticated cross-site
request forgery,
attacker-length native-memory corruption, deterministic asynchronous-session
use-after-free with privileged callback redirection, document-query operator injection,
executable file upload/content placement, cross-proxy/backend HTTP request
smuggling, duplicate-query parameter authorization confusion where a gateway
checks the first action but a backend executes the last, CR/LF response-header
injection that makes a gateway honor an
attacker-injected internal redirect, LDAP filter injection into directory-backed
group authorization,
XPath predicate injection into XML-backed authentication, OAuth account-linking
CSRF leading to account takeover, WebAuthn/passkey credential-to-account
misbinding where an attacker's valid credential creates a victim session, login session fixation, password-reset link
origin poisoning, credentialed CORS secret exfiltration, and adversarial
repository instructions. The corpus also covers cross-site WebSocket hijacking
of cookie-authenticated bidirectional channels and edge/origin web-cache
deception that exposes authenticated responses across requests. It additionally
covers GraphQL alias/batch amplification of recovery-code verification across
the HTTP-request, execution-plan, resolver, and account-state boundaries,
trusted-proxy client-identity spoofing where attacker-prepended
`X-Forwarded-For` hops bypass recovery-code attempt budgets,
fail-open external authorization on policy exceptions and malformed decisions,
DNS-rebinding SSRF across validation and connection-time resolution, plus
catastrophic-backtracking regular-expression denial of service with a bounded
linear validator as the control. It now includes AES-GCM key/nonce reuse that
recovers victim plaintext from a chosen plaintext and two public ciphertexts,
paired with fresh per-envelope HKDF data keys and profile-bound authenticated
data even though the visible nonce repeats. Each of the 98 cases is scanned
three times, producing 294 scans that measure both accuracy and model variance.
Interrupted benchmark finalization is recoverable without another model call:
repeat the identical runner command with `--finalize-only` to atomically rebuild
the selected manifest and report from the sealed campaign receipts.
The evaluator uses one-to-one CWE-plus-location
matching, counts duplicate reports as false positives, and records missing scan
artifacts as completion failures.

```powershell
# Evaluate existing outputs
node ./bin/copilot-security.mjs benchmark `
  ../../benchmarks/manifest.json `
  --results-dir C:\security-benchmarks\copilot-security `
  --format json

# Build fresh isolated Git repositories and scan the complete corpus
node ../../benchmarks/run-benchmark.mjs `
  --results-dir C:\security-benchmarks\copilot-security `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --max-attempts 2 `
  --mode deep

# Run the strict cross-file wrapper diagnostic
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

# Run the strict three-file relay diagnostic
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

# Run the strict Node/Python SSRF framework diagnostic
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

# Run the strict Node/Python template-source-injection diagnostic
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

Evaluation requires successful campaign-bound runner receipts by default, so a
manifest cannot relabel an unsealed or interrupted result as completed. Use
`--no-require-status` only when deliberately evaluating manually imported
compatible/cross-provider findings that have no runner receipt; reports from
that compatibility mode do not prove scanner-process completion.

Use repeatable `--case <id>` options, `--runs 1`, and `--selection-only` for a
quick paired vulnerable/control diagnostic with its own durable report. Omit
`--selection-only` when a partial run should intentionally exercise the
full-corpus completion gate.

Every fresh run directory receives an immutable `benchmark-campaign.json`
before scanning. It binds corpus and fixture bytes, selection, exact provider
model and scan policy, runtime, runner, authentication source, and the effective
scanner package. Resume verifies the complete
sealed scan and its campaign receipt before skipping; failed or partial attempts
are preserved under `.benchmark-attempts` and retried from a fresh Git fixture.
Every scanner invocation also receives a unique staging output path that is
promoted to the canonical run directory only after the process returns. This
prevents a stateful scanner's internal path registry from turning a real retry
into an "existing scan" collision. Archived attempt slots remain monotonic even
when recovery encounters an older duplicate receipt. Scanner stdout and stderr
are drained into per-attempt logs and mirrored only on a best-effort basis, so a
closed terminal cannot abort a long scan or erase its diagnostic evidence.
Model-authored contract drafts may contain one UTF-8 byte-order mark; the
workbench removes it at the unsealed-draft boundary and records recovery before
canonical sealing. Invalid UTF-8, non-finite numbers, malformed structure, and
post-seal mutations remain fatal.
Use `--workers N` for bounded concurrency, `--max-attempts N` for process-level
retries, `--scan-timeout-ms N` for an outer process-tree deadline, and
`--scanner-cli PATH --scanner-label NAME` to produce a separate compatible
baseline campaign. Comparable version `1.1` reports must share `corpusId` and
`comparisonPolicyId`.
Version `1.1` campaigns additionally expose a provider-neutral
`comparisonPolicyId`; cross-provider reports compare on that identity so models
may differ while mode, effort, explicit credit bounds, corpus bytes, selection,
expectations, and repetition counts remain identical. Exact model identity
continues to affect `scanPolicyId` and `campaignId`, so resuming or mixing runs
cannot silently change providers.

The measured gates cover completion, precision, recall, F1, exact-case and
negative-control passes, repeated-run stability, validation, attack paths,
code evidence, severity accuracy, and false positives per run. Validation,
attack-path, and code-evidence rates reject nonempty placeholder objects and
require substantive source-to-impact proof. See
[`benchmarks/README.md`](benchmarks/README.md).

## Container

The customer container includes both `copilot-security` and the official
`@github/copilot` CLI. It keeps the inherited noninteractive CSV bulk-scan
contract. The Compose service runs as an unprivileged user with dropped Linux
capabilities, `no-new-privileges`, and the inherited seccomp profile.

```bash
docker build -t copilot-security:local .
docker run --rm copilot-security:local --version

mkdir -p results state
printf 'id,repository,revision\n' > repositories.csv
GH_TOKEN=... docker compose run --rm copilot-security
```

The Compose interface uses `COPILOT_SECURITY_IMAGE`,
`COPILOT_SECURITY_USER`, `COPILOT_SECURITY_CSV`,
`COPILOT_SECURITY_RESULTS`, `COPILOT_SECURITY_STATE`, and
`COPILOT_SECURITY_GIT_HOST`. `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, and
`GITHUB_TOKEN` are accepted for noninteractive Copilot and GitHub access.

## Authentication

`--auth github` uses the login stored by the Copilot CLI and ignores ambient
token variables. `--auth token` requires one of:

- `COPILOT_GITHUB_TOKEN`
- `GH_TOKEN`
- `GITHUB_TOKEN`

`--auth auto` uses a token when one is present and otherwise uses the stored
Copilot login. Token values are passed to the child Copilot process through the
SDK's dedicated authentication channel after the scanner removes the public
token aliases from its allowlisted environment. Token-authenticated sessions
disable every model shell tool, preventing child tools from inheriting or
printing the credential. Token values are never copied into scan artifacts.

## TypeScript

```ts
import { CopilotSecurity } from "@secwest/copilot-security";

const scanner = new CopilotSecurity({
  copilotPath: "C:\\path\\to\\copilot.exe", // optional
  copilotOverrides: {
    model: "gpt-5.6-sol",
    reasoning_effort: "xhigh",
  },
});

try {
  const result = await scanner.run("C:\\code\\project", {
    auth: "github",
    mode: "standard",
    outputDir: "C:\\security-results\\project",
  });
  console.log(result.reportPath);
} finally {
  await scanner.close();
}
```

`CopilotSecurity`, `CopilotSecurityConfig`, and `copilotOverrides` are the
canonical SDK names. Scanner-owned environment variables use the
`COPILOT_SECURITY_*` prefix.

## Safety

Scans are report-only. The scanning prompt forbids modifying the target
repository, publishing findings, opening issues, committing, pushing, or
contacting third parties. Scan output must be outside the target repository and
its enclosing Git worktree. Run only against repositories you are authorized
to assess.

### Model execution boundary

The model never operates on the authoritative checkout. Before session
creation, the host copies the repository and installed plugin into a unique
disposable analysis workspace. Symbolic links, junctions, and special files
are not recreated; their repository-relative paths and link targets are
recorded in `links.json` for security review. The model receives an empty
disposable scanner-state directory rather than the workbench database or
authoritative `COPILOT_SECURITY_HOME`. Scoped scans stage only requested paths,
and dependency stores are omitted unless explicitly selected. Registered
target-state checks surround host byte-for-byte verification of every staged
inventory file, closing setup and completion races against mutable checkouts.

The Copilot process receives an allowlisted environment instead of the ambient
process environment. Unrelated secrets and executable-injection variables are
removed, `PATH` is rebuilt from trusted executable directories, the tool
sandbox denies outbound and local network access, Git/GitHub credential
forwarding and permission bypass are disabled, and URL, MCP, memory,
extension, and out-of-profile permission requests are rejected. Reads are
limited to the disposable repository/plugin and scan artifacts; writes are
limited to the disposable workspace and exclusive scan directory. Every shell
completion must carry positive native `sandboxApplied` telemetry or the host
aborts the session. Sessions using an environment token expose no shell tools;
stored-credential sessions retain the sandboxed shell profile.

Windows native sandboxing is currently a public-preview defense, not the sole
security boundary. Current preview builds can give sandboxed child-native
processes an unusable working directory. The production workflow therefore
uses Copilot built-in file tools for exact host-worklist repository reads,
permits PowerShell only for scan-directory draft artifacts in stored-credential
sessions, disables shell tools entirely for token-authenticated sessions, and
forbids model-side Python, Git, ripgrep, and plugin helpers. The disposable snapshot,
omitted-link manifest, stripped environment, category-scoped permission
handler, immutable host inventories, deterministic contract audit, and final
artifact sealing remain independent controls if the native preview regresses.
See GitHub's [local sandbox settings documentation](https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/configuring-local-sandbox-settings)
and the current [MXC security notice](https://github.com/microsoft/mxc).

## License

Copyright and license terms are in [LICENSE](LICENSE).
