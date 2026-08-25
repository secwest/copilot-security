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

The residual pass also applies typed framework data-flow models for Node HTTP
and exact GitHub Copilot SDK trusted-instruction boundaries,
Python web, Spring/servlet, and ASP.NET command execution, raw SQL, filesystem
paths, server-side request forgery, and object authorization; a separate Go
`net/http` model covers server-side request forgery, a typed Go filesystem
model covers request-controlled read, open, write, delete, metadata, link,
move, root-selection, walk, and response-file paths through exact
standard-library APIs, an execution-aware Go `text/template` model covers
request-controlled template source through `Parse` into `Execute` or
`ExecuteTemplate`, while typed
`os/exec`, `execabs`, `os.StartProcess`, and `syscall` models cover executable,
shell, interpreter, remote, and option-sensitive command paths through constructors,
manual `Cmd` fields, and direct dispatch, and typed `database/sql`, `sqlx`, GORM v2,
Masterminds/Squirrel, `pgx/v5`, `pgxpool`, and low-level `pgconn` models cover
request-to-query grammar and deferred database dispatch;
and Node, Python, and Spring models cover server-side template injection. Each applicable
row identifies an exact source line, sink line, CWE family, and nearby
candidate controls. The Python host pass also models request bodies reaching
standard-library `pickle.load` or `pickle.loads`, NumPy `load` with literal
`allow_pickle=True`, as well as PyYAML
`unsafe_load` or `load` with an explicit `Loader`, `UnsafeLoader`,
`CLoader`, or `CUnsafeLoader`. It proves the exact `yaml` receiver or named
import and stream argument, follows relative wrappers, and rejects `safe_load`,
safe or full loaders, absent or dynamic loaders, fixed YAML, reassignment,
local `yaml` module shadows, and comment/string lookalikes. The correction pass
treats this exact non-shadowed API and remote stream as reportable CWE-502
object/state integrity evidence even when deployment metadata is unavailable.
It records runtime-module and constructor uncertainty as validation limitations
and requires a bounded constructor or gadget witness before escalating to code
execution, filesystem, network, credential, or availability impact.
For pickle, the host proves the exact non-shadowed standard-library receiver or
named import, argument zero, and relative-wrapper path. It rejects `dumps`,
fixed or wrong-role data, star expansion, reassignment, member replacement,
local `pickle` shadows, and text lookalikes. Because the pickle virtual machine
can invoke serialized callables through `GLOBAL`/`STACK_GLOBAL` and `REDUCE`, a
request-controlled pickle stream is itself a CWE-502 code-execution boundary;
no separately installed gadget library is required. Validation must still use
a bounded non-destructive callable witness and report only the demonstrated
process effect. A secret-keyed integrity check over the exact serialized bytes
before loading is strong counterevidence; checksums, embedded keys, post-load
authentication, return-value validation, and exception handling do not stop
instructions that execute during unpickling. JSON remains the preferred format
for untrusted data.
For NumPy, the host accepts only a live non-shadowed `numpy.load` binding,
request control of its file argument, and literal `allow_pickle=True`. It
rejects NumPy's safe default, explicit `allow_pickle=False`, dynamic flags,
fixed or wrong-role input, star expansion, reassignment, local `numpy`
shadows, and text lookalikes. Validation requires an object-dtype `.npy`
payload and exact Python/NumPy versions: numeric-only arrays do not establish
pickle execution, and an `.npz` archive must actually access its lazy member.
The paired witness proves bounded `__reduce__` callable execution while the
otherwise identical `allow_pickle=False` control fails closed before the
callable runs.
For Java, the host resolves uniquely named service types
from controller fields, confines calls to parsed public or protected method
bodies, and preserves annotated Spring or servlet-assigned request values
through the exact call argument and wrapper parameter. Java can follow one
direct service wrapper or up to two additional uniquely typed service relays
before a typed sink. For C#, the host likewise resolves one uniquely named
class, record, or struct from an ASP.NET
controller field or static receiver, binds the exact service-call argument to
the public, protected, or internal wrapper parameter, and preserves either an
annotated bound parameter or an assigned `HttpRequest` field through
`ProcessStartInfo`/`Process.Start`, the query-text argument of `SqlCommand`,
`FromSqlRaw`, or `ExecuteSqlRaw`, or a complete outbound `HttpClient` request
URI. C# follows the same one-to-three service-boundary ceiling and exact
positional identity at every call. Exact Razor Pages sources also include public HTTP-verb handler parameters
on official `PageModel` subclasses and public writable `[BindProperty]` or
`[BindProperties]` properties, with GET/HEAD property binding gated by
`SupportsGet = true`; service parameters, `[NonHandler]`, `[BindNever]`, local
framework shadows, reassignment, ambiguous or ninth inheritance edges, and
unbound properties fail closed. For Node/TypeScript, Axios sinks require a real package binding or bounded
non-reassigned `axios.create(...)` instance and preserve only the URL argument
or request-config `url` property, never a POST/PUT/PATCH body. A fixed
`baseURL` is not treated as confinement while Axios can still accept an
attacker-controlled absolute URL; disabling absolute override, selecting a
server-owned destination, rejecting redirects, and validating relative paths
remain separate control leads. Node/TypeScript object-authorization rows
preserve a request-controlled record identifier into the exact single-record
lookup argument and retain only same-query principal/owner filtering or a
post-lookup check on that returned object as control leads. Authentication,
UUID opacity, ORM use, or unrelated owner text is not classified as object
authorization. Node/TypeScript Mongoose selector-injection rows require an
official `mongoose` binding, a unique Model created through that exact
unmodified binding, request flow into argument zero of a documented
filter-bearing Model operation, and proof that the Query is consumed through
`await`, an async returned thenable, `exec`, `then`, or `catch`. Update,
replacement, projection, and options values are not filters. Exact `$eq` and
official `mongoose.sanitizeFilter` boundaries are retained as counterevidence;
same-named local helpers, casting, `strictQuery`, `runValidators`,
`requireFilter`, authentication, and result limiting are not treated as
selector sanitization. Separate Mongoose update-document rows trace only
argument one of executed Model `updateOne`, `updateMany`, `findOneAndUpdate`,
and `findByIdAndUpdate` calls. Attacker-controlled operators and pipelines are
reviewed as CWE-943 query-language injection, while field-only over-posting is
reviewed as CWE-915 mass assignment. Only a tainted scalar beneath a fixed
server-owned `$set` field is retained as strong counterevidence; complete
objects beneath `$set`, computed keys, spreads, `sanitizeFilter`, casting,
strict mode, and update validators do not establish a universal update
boundary. GitHub Copilot SDK prompt-injection rows require an exact named
`CopilotClient` import from `@github/copilot-sdk`, one constructed and
non-reassigned client, and `createSession` or `resumeSession`. They preserve
request data only when it reaches `systemMessage` content, customize-section
content or a known-section transform, inference-visible custom-agent prompts or
descriptions, or tool descriptions. Ordinary `session.send` and `sendAndWait`
prompt data stays in the user-message channel and is a negative control.
Content under an unknown customize-section name remains risky because the SDK
falls back to appended instructions. The model follows up to two exact
relative-module wrappers and eight local value aliases, then fails closed on
ambiguous bindings, reassignment, content ignored by a section action,
completion-UI-only command descriptions, or a ninth alias. ASP.NET
object-authorization rows preserve a `[FromRoute]`,
`[FromQuery]`, or request-derived identifier through a uniquely typed
repository boundary into a typed EF Core `DbSet` or `DbContext` single-record
lookup. `[Authorize]`, authentication, EF tracking, and opaque primary keys are
not object controls. The host retains a same-query owner, tenant, or customer
predicate only when it is bound to an authenticated-principal-shaped value, or
an `IAuthorizationService.AuthorizeAsync(User, returnedEntity, policy)` call
only when its exact result is enforced fail-closed before the protected effect.
Spring object-authorization rows preserve an annotated or servlet-derived
identifier through one to three uniquely typed service boundaries into an
official Spring Data `CrudRepository` or `JpaRepository` `findById` lookup or
an explicitly declared owner-qualified derived query. Endpoint authentication,
role-only `@PreAuthorize`, opaque IDs, and repository identity are not object
controls. The host retains a query control only when the same lookup binds its
owner-like dimension to a typed Spring Security `Authentication`, Java
`Principal`, or official `SecurityContextHolder` value. It retains
`@PostAuthorize` only for a Spring-managed read method when pre/post method
security is active, the expression authorizes the returned object's owner
against `authentication.name`, and no write occurs before the decision.
Spring mass-assignment rows preserve an official `@ModelAttribute` JPA domain
object from a state-changing controller through one to three uniquely typed
service boundaries into the exact `CrudRepository` or `JpaRepository` `save`
argument. The domain type must resolve to one unique official JPA entity.
`@Valid`, authentication, role checks, denylisted fields, and repository use
are not binding controls. An attribute-applicable official `@InitBinder` using
`WebDataBinder.setAllowedFields`, or constructor-only
`setDeclarativeBinding(true)`, is retained as a control lead; dedicated DTO
projection remains reviewer counterevidence rather than being broadened into
the entity flow.
GitHub Actions rows preserve an exact `pull_request_target` trigger into an
explicit fork pull-request checkout and then into a later command or local
action that executes from the same workspace path. A privileged trigger,
checkout step, or install command alone is insufficient. The host retains
effective token permissions, secret or OIDC exposure, persisted checkout
credentials, immutable commit selection, review/environment gates, and
Checkout v7's default refusal of unsafe fork checkouts as distinct control and
impact leads. Malformed workflows, trusted/base checkouts, overwritten or
unrelated paths, and fixed non-loading commands are rejected before review.
Self-hosted pull-request rows require a pull-request-capable event, an explicit
self-hosted label, statically classified custom label, or runner group, an
official untrusted checkout, and later command or local-action execution from
the same workspace. Current standard GitHub-hosted Ubuntu, macOS, and Windows
labels plus recognized BuildJet and Warp hosted labels are excluded; fully
dynamic runner expressions are deferred. Ordinary `pull_request` rows do not
invent secret or write-token access. Other events retain exact authority and
control evidence, but immutable refs, read-only tokens, disabled credential
persistence, labels, and environments do not by themselves prevent persistence
on the host. Review must prove actual customer-controlled scheduling and runner
lifecycle; a proven freshly destroyed single-job JIT runner is strong
counterevidence.
Kubernetes configuration rows require a complete same-container host-authority
chain rather than a loose YAML keyword match. The parser accepts exact current
`Pod`, `ReplicationController`, `apps/v1` controller, `batch/v1` `Job`, and
`batch/v1` `CronJob` shapes, including multi-document files and Kubernetes
`List` objects. A row requires one Linux container or init/ephemeral container
with boolean `securityContext.privileged: true`, one uniquely named `hostPath`
volume rooted at a sensitive node path, and a matching absolute read-write
`volumeMount` on that same container. The record preserves workload identity,
container section/name, normalized host path, mount path, volume identity, and
exact source/sink lines. Read-only mounts, isolated volumes, `hostUsers: false`,
Windows workloads, safe subpaths, dynamic subpath expressions, mismatched or
duplicate names, wrong API/kind pairs, aliases, duplicate YAML keys, malformed
documents, and non-YAML lookalikes fail closed. Correction still has to prove
the rendered workload is admitted and deployed plus a concrete attacker path
to the container; dangerous host authority alone does not invent remote node or
cluster compromise.
Kubernetes RBAC rows separately preserve a complete cluster-wide authority
grant: an exact `rbac.authorization.k8s.io/v1` `ClusterRoleBinding`, the
built-in `cluster-admin` `ClusterRole`, and one intrinsic broad principal. The
initial high-confidence set covers `system:anonymous`,
`system:unauthenticated`, `system:authenticated`, and
`system:serviceaccounts`; named administrator groups, individual service
accounts, namespace-scoped service-account groups, `RoleBinding` objects, and
similarly named roles remain negative. Review must verify rendering,
deployment, effective RBAC authorization, and the exact credential or
anonymous reachability boundary. A manifest proves the authority grant, not an
internet-reachable API or a compromised workload.
CloudFormation IAM rows preserve a complete same-role public-administrator
chain in strict YAML 1.2 or JSON. A row requires an exact `AWS::IAM::Role`, an
unrestricted `Allow` trust statement whose `Principal` is `*` or whose AWS
principal contains `*`, an `sts:AssumeRole`, `sts:*`, or `*` action, and either
the exact AWS-managed `AdministratorAccess` policy or an unrestricted inline
`Action: "*"`/`Resource: "*"` grant. An absent permissions boundary and the
`AdministratorAccess` policy used as a boundary are both unbounded. A nonempty
or dynamic trust condition, any other static or dynamic permissions boundary,
a specific principal, narrower authority, intrinsic value at a modeled
boundary, aliases, duplicate keys, malformed input, or a non-template shape
fails closed. The record retains logical role identity, optional deployed role
name, trust and permission forms, conditions, boundary state, CWE-269/CWE-284,
and exact source/sink lines. Review must still prove synthesis or transform
output, repository-visible stack selection, overlays, effective controls, and
same- or cross-account permission semantics. The complete static chain is a
reportable IaC defect with unchanged deployment and caller permission stated as
preconditions; absence of live account telemetry or attacker credentials is
uncertainty, not suppression evidence. Only positive evidence that rendering,
deployment, or an effective control removes the chain closes it. SCP/session/
explicit denies, drift, current role state, and the least concrete administrator
effect calibrate confidence and impact; a template does not prove anonymous
internet access, active deployment, valid credentials, or a successful role
session.
Cross-workflow artifact rows preserve an unprivileged `pull_request` checkout
and official artifact upload into a named `workflow_run` consumer, require an
official download bound to `github.event.workflow_run.id`, and emit only when
the downloaded path is later executed under the privileged consumer. Workflow
and artifact names, action identity, step order, extraction paths, trusted
cleanup, permissions, secrets, and OIDC remain explicit. Producer success,
read-only producer permissions, and artifact transport digests do not make
pull-request bytes trusted; extraction outside the workspace plus fail-closed
typed-data parsing is strong counterevidence when artifact content is never
executed.
Reusable-workflow script-injection rows preserve an externally influenced
default-branch trigger, exact caller event field, local workflow target,
forwarded `with` name, declared `workflow_call` string input, and the called
`run` or official `actions/github-script` source that recompiles the same value.
Direct `${{ inputs.NAME }}` substitution and input-derived `${{ env.NAME }}`
substitution are code generation even when quoted inside the generated script.
Assigning the expression to an intermediate environment entry and reading it
only through native shell syntax or `process.env` remains data-only
counterevidence. Caller/callee permission intersection, forwarded secrets,
OIDC, environment gates, and runner reachability remain separate impact and
control evidence.
Composite-action script-injection rows preserve the same externally influenced
event-field identity through an exact workflow-step `with` entry, literal
repository-local action directory, one unambiguous `action.yml` or
`action.yaml`, declared metadata input, `runs.using: composite`, and a runnable
`run` or official `actions/github-script` source. Direct input substitution and
same-step input-derived `${{ env.NAME }}` re-expansion are code generation;
assigning the input to that step's environment and reading it only through the
shell's native variable syntax or `process.env` remains data-only. The model
rejects parent traversal, remote or dynamic targets, ambiguous or invalid
metadata, shell-less commands, ordinary action inputs, script-action lookalikes,
cross-step environment assumptions, and secret evidence that exists only in a
YAML comment. Effective caller permissions, explicitly forwarded and consumed
secrets, OIDC, review/environment gates, and runner reachability remain separate
impact and control evidence.
Same-workflow script-injection rows bind each supported workflow trigger to
its exact attacker-controlled event fields and require that value to reach a
`run` script or a code-bearing input from the current exact CodeQL/zizmor
action map. Bounded value flow includes direct dot or single-quoted bracket
contexts, parentheses, `toJSON`, `fromJSON`, `format`, `join`, reachable
short-circuit results, and workflow/job/step `${{ env.NAME }}` re-expansion.
Comparisons, predicates, fixed or unreachable results, native shell or
`process.env` consumption, unknown action inputs, lookalikes, and dynamic
action revisions are rejected. Ordinary `pull_request` rows retain code
execution without inventing secret or write-token impact; other triggers keep
exact permissions, structurally available secrets, review gates, deployment
environments, and runner reachability as separate evidence.
For Node/TypeScript relative-module wrappers, the host can emit bounded
one-to-three-hop cross-file chains. For Python, it can resolve one direct
wrapper or up to two public module-level relays through
explicit relative from-imports, bind each exact positional argument, and
inspect bounded multiline relay and sink calls, including DB-API binding and
outbound HTTP calls. A multi-hop row contains every exact caller/relay import
and argument, each relay parameter, the sink-wrapper parameter, and the sink
that references that parameter. Language strings and comments are
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
Direct model write requests to all four host-owned inventory files are denied.
The host verifies every digest before preparation and again before sealing,
and both completion phases pass the original `in_scope_files.txt` SHA-256 to
the trusted finalizer for an independent check immediately before it reads the
inventory.
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
exist, the scanner stops replaying the full scan and starts a fresh isolated
session in `draft_quality_correction`. That session receives newly computed
host gap inventories and resumes the mandatory correction and deterministic
re-audit series. If the configured session budget is exhausted, the remaining
drafts still have to pass deterministic workbench normalization, validation,
and sealing before any partial result can survive; missing drafts use ordinary
fresh-session scan recovery.

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
prior session's artifact claims: an ordinary replacement must re-consume the
inventory, while draft-quality recovery treats existing artifacts as untrusted
drafts and consumes freshly computed host gap inventories. Successful built-in
file views remain valid host telemetry across sessions over the same immutable
snapshot; unfinished tool calls are cleared at every session boundary, and
shell reads, labels, receipts, or summaries cannot replace direct-view
evidence. Every path still passes the same deterministic host audits before
sealing. Session shutdown is bounded so a hung disconnect cannot prevent the
next attempt. Streamed and persisted token usage is accumulated across all
attempt roots and their subagents, so scanner-owned cost enforcement cannot be
reset by recovery.

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

# Apply an expiring, justified local fingerprint baseline
node ./bin/copilot-security.mjs scan C:\code\project `
  --secret-baseline C:\security-policy\project-secrets.json

# Inspect more reachable Git history for credentials deleted from the tree
node ./bin/copilot-security.mjs scan C:\code\project `
  --secret-history-depth 512

# Disable reachable-history inspection while retaining the current-tree pass
node ./bin/copilot-security.mjs scan C:\code\project `
  --secret-history-depth 0
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

The launch recipe also binds the exact normalized candidate count, candidate
JSONL SHA-256, and ordered source-document digests. At completion, the trusted
host reconciles every reserved seed identity against the enriched ledger and
fails closed on a missing, duplicate, invented, out-of-scope, identity-mutated,
or incompletely validated row. It then writes and manifest-seals
`artifacts/03_coverage/external_sarif_seed_coverage.json`, with one terminal
`reportable`, `rejected`, `deferred`, or `out_of_scope` record per normalized
seed. Deferred seeds force partial coverage. CLI and GUI completion warnings
show the four counts; SDK results expose the receipt through
`externalSarifSeedCoveragePath`.

See [`docs/scanner-landscape.md`](docs/scanner-landscape.md) for the design
comparison and improvement backlog derived from other mature scanners.

### Local secret candidates

Before Copilot starts, the trusted host scans bounded working-tree plaintext
and, by default, unique plaintext blobs reachable from the newest 128 Git
commits for typed credential forms and high-entropy credential assignments. A
credential deleted from the current checkout therefore remains visible while
it is retained in reachable history. Candidate bytes
never enter the detector's prompt inventory, report, baseline, diagnostics, or
errors. The model receives only an active rule, exact location, redacted shape,
repository-scoped keyed HMAC, and bounded immutable blob IDs for historical
provenance; repeated appearances of the same rule/path/value are deduplicated.
Justified unexpired exact-match baselines are removed locally, while expired
entries become active automatically. Redacted reports, the random key, and
per-repository default baselines live only beneath
`COPILOT_SECURITY_HOME/copilot-security-home/secret-scanner`.

Use `--secret-baseline PATH`, SDK `secretBaselinePath`, or the Windows/Linux GUI
to select a strict schema 1.0 baseline. Invalid, linked, duplicate, missing, or
unbounded baseline input fails before Copilot is invoked. Use
`--secret-history-depth N`, SDK `secretHistoryDepth`, or the GUI history field
to select `0` through `2048` commits. Git execution uses the host-resolved
trusted executable, disables lazy object fetching, strips ambient `GIT_*`
control variables, reads objects without checkout, and reports every resource
or availability cutoff as incomplete rather than a clean history result. See
[`docs/secret-scanning.md`](docs/secret-scanning.md) for rule coverage, the
baseline schema, key isolation, privacy limits, and benchmark procedure.

The dedicated `benchmarks/sarif-seed-manifest.json` campaign pairs a real
command-injection seed with a deliberately noisy safe-process-execution seed.
It tests recall gain and false-positive rejection while its SARIF messages and
fingerprints contain hostile text and fake secrets that must never reach scan
artifacts or model context. Each case additionally requires an exact sealed
seed-coverage receipt: the positive must close as reportable and the negative
as rejected, with no deferred or out-of-scope seed:

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

The Python multi-hop lane adds public gateway and service relays and keeps the
same strict positive, safe, reassignment, fixed-argument, and text-only
controls:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/python-multi-hop-framework-manifest.json `
  --results-dir C:\security-benchmarks\python-multi-hop `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Node object-authorization lane pairs same-file and cross-file invoice
lookups that use only a request-controlled record ID with controls that bind
the same ID to the authenticated customer in the repository query. It gates
CWE-639/CWE-862 detection, validation, attack-path evidence, code evidence,
severity, and both negative cases at perfect selected-run thresholds:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/node-object-authorization-manifest.json `
  --results-dir C:\security-benchmarks\node-object-authorization `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The ASP.NET object-authorization lane uses real EF Core 8 fixtures and
executable witnesses. The positive passes a route-controlled primary key to
`DbSet.FindAsync` under `[Authorize]` and returns another customer's invoice;
the control preserves the same topology but constrains one
`SingleOrDefaultAsync` predicate by the customer ID derived from the current
principal:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/aspnet-object-authorization-manifest.json `
  --results-dir C:\security-benchmarks\aspnet-object-authorization `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Spring object-authorization lane uses real Spring Boot, Spring Data JPA,
Spring Security, Hibernate, and H2 components. Its positive keeps an
authenticated endpoint while passing a route-controlled primary key to
`JpaRepository.findById`; its executable witness proves one customer can read
another customer's invoice. The control binds that key and the typed
`Authentication.getName()` value in one declared derived query and proves the
cross-customer selection fails:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/spring-object-authorization-manifest.json `
  --results-dir C:\security-benchmarks\spring-object-authorization `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Spring mass-assignment lane uses the same Boot 4.1, Spring MVC, Spring
Data JPA, Hibernate, and H2 stack. Its positive posts an unintended
`administrator=true` form property onto an `@ModelAttribute Account` and
persists the same entity through a typed service. Its matched control scopes a
`WebDataBinder` allowlist to `account`; the runtime witness proves the display
name persists while the administrative flag remains false:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/spring-mass-assignment-manifest.json `
  --results-dir C:\security-benchmarks\spring-mass-assignment `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-cross-file-mass-assignment/pom.xml verify
wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-cross-file-safe-binding/pom.xml verify
```

The GitHub Actions lane pairs two `pull_request_target` workflows that select
the pull request's immutable head SHA and then execute `npm` in the checked-out
workspace. The positive explicitly opts Checkout v7 back into unsafe fork
checkout while retaining a write-capable token and secret-bearing environment;
the control keeps Checkout v7's default fork protection and read-only token.
The executable witness proves harmless attacker-controlled code can observe a
mock secret only in the opted-out case:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/github-actions-pwn-request-manifest.json `
  --results-dir C:\security-benchmarks\github-actions-pwn-request `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

node benchmarks/witnesses/github-actions-pwn-request/PwnRequestWitness.mjs
```

The self-hosted pull-request lane pairs an ordinary pull-request job on a
reusable self-hosted runner with the same job on `ubuntu-latest`. Both use
read-only permissions, disable Checkout credential persistence, and execute
the checked-out test command. The positive remains dangerous because the
untrusted job can persist in user-writable runner state and affect a later
privileged job; the hosted control starts that later job on a fresh machine:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/github-actions-self-hosted-pr-manifest.json `
  --results-dir C:\security-benchmarks\github-actions-self-hosted-pr `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

node benchmarks/witnesses/github-actions-self-hosted-pr/SelfHostedPrWitness.mjs
```

The Kubernetes host-authority lane pairs a privileged Linux Deployment that
mounts the node root read-write with a matched workload that uses a pod user
namespace, disables privileged mode, and replaces the host bind with an
isolated `emptyDir`. The perfect gate requires exact workload/container/volume
provenance, validation, attack-path and code evidence, high or critical
severity, stable detection, and zero false positives:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/kubernetes-privileged-hostpath-manifest.json `
  --results-dir C:\security-benchmarks\kubernetes-privileged-hostpath `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Kubernetes RBAC lane pairs the documented strongly discouraged grant of
the built-in `cluster-admin` role to every service account with a
source-identical binding to one named administrator group. It requires exact
principal and immutable role-reference evidence, a concrete credential or
anonymous path, high or critical severity, and zero false positives:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/kubernetes-cluster-admin-binding-manifest.json `
  --results-dir C:\security-benchmarks\kubernetes-cluster-admin-binding `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The CloudFormation IAM lane pairs a public wildcard trust plus unbounded
administrator permission on one role with a source-identical role trusted only
to one AWS account. It requires exact trust, role, policy, condition and
permissions-boundary evidence, conditional deployment, effective caller-side
`sts:AssumeRole` authorization, high or critical severity, and zero false
positives. Its semantic gate rejects unqualified session-issuance or "any AWS
principal is sufficient" claims even when structural validation and attack-
path fields are otherwise substantive:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/cloudformation-public-admin-role-manifest.json `
  --results-dir C:\security-benchmarks\cloudformation-public-admin-role `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The artifact-poisoning lane pairs an unprivileged pull-request producer with a
privileged `workflow_run` consumer. The positive downloads the producer's
`release-input` artifact from the exact triggering run into the trusted
workspace and executes it with write/OIDC/secret access. The control follows
GitHub's documented design: extract beneath `runner.temp`, parse a narrowly
typed integer, and fail closed without executing artifact bytes:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/github-actions-artifact-poisoning-manifest.json `
  --results-dir C:\security-benchmarks\github-actions-artifact-poisoning `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

node benchmarks/witnesses/github-actions-artifact-poisoning/ArtifactPoisoningWitness.mjs
```

The reusable-workflow injection lane forwards the same issue-comment body into
a declared local `workflow_call` string input. The positive substitutes it
directly into `actions/github-script` source under inherited secrets and
write/OIDC permissions. The control transfers it once into an environment
entry and reads it only through `process.env`, so the identical injection
payload remains inert:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/github-actions-reusable-workflow-injection-manifest.json `
  --results-dir C:\security-benchmarks\github-actions-reusable-workflow-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

node benchmarks/witnesses/github-actions-reusable-workflow-injection/ReusableWorkflowInjectionWitness.mjs
```

The composite-action injection lane forwards the same issue-comment body into
a declared input of one literal repository-local composite action. The positive
substitutes it directly into official `actions/github-script` source while the
caller grants write/OIDC permissions and explicitly forwards a release secret.
The control maps the same input into the GitHub Script step's environment and
reads it only through `process.env`, so the identical payload remains inert:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/github-actions-composite-action-injection-manifest.json `
  --results-dir C:\security-benchmarks\github-actions-composite-action-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

node benchmarks/witnesses/github-actions-composite-action-injection/CompositeActionInjectionWitness.mjs
```

The same-workflow injection lane places a pull-request title directly into an
official GitHub Script program under write/OIDC permissions and an explicit
mock release-token environment. The matched control transfers the identical
title bytes into an intermediate environment entry and reads only
`process.env.TITLE`. The witness proves that direct expression substitution
creates a second JavaScript statement while the environment value remains one
inert string:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/github-actions-workflow-script-injection-manifest.json `
  --results-dir C:\security-benchmarks\github-actions-workflow-script-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

node benchmarks/witnesses/github-actions-workflow-script-injection/WorkflowScriptInjectionWitness.mjs
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

The Axios instance lane isolates client identity and destination-argument
semantics. Its positive passes an absolute request value through a relative
module wrapper into an `axios.create(...)` client whose nominal `baseURL` is
overridden under Axios defaults. Its negative maps the same request shape to
server-owned relative paths, sets `allowAbsoluteUrls: false`, and disables
redirects:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/node-axios-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\node-axios-ssrf `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Go lane requires the exact standard-library `net/http` binding and a typed
`*http.Request` source. Its positive carries a query-controlled complete URL
through one same-package wrapper into `NewRequestWithContext` and a constructed
`http.Client.Do`; request construction without dispatch is not a sink. The
control accepts only an exact key into a fixed server-owned destination map and
returns `http.ErrUseLastResponse` from `CheckRedirect`. Real `httptest`
loopback tests prove both the initial-request exploit and redirect containment:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-net-http-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\go-net-http-ssrf `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-ssrf
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-fetch
go test ./...
Pop-Location
```

The Go filesystem-path lane requires exact `net/http`, `os`, legacy
`io/ioutil`, `path/filepath`, or file-serving import identities and a typed
`*http.Request` source. It preserves request values through one unique
same-package string wrapper and path construction into exact read, open,
write, delete, metadata, link, move, walk, and HTTP file-response arguments.
Request control of an `OpenRoot` or `OpenInRoot` root argument is reported as
filesystem-root selection; rooting does not help when the root is untrusted.
`filepath.Join`, `Clean`, `Abs`, `Rel`, and `EvalSymlinks` remain visible
evidence rather than universal sanitizers; lexical normalization is not
containment or authorization. Immutable server-owned file selection is a
deterministic barrier. Root-scoped `os.OpenInRoot`, `os.OpenRoot`, and
`os.Root` operations are treated as strong control evidence, subject to the
target platform, link/mount/race analysis, and a patched runtime. In
particular, affected Unix deployments need Go 1.25.12 or 1.26.5 or newer for
GO-2026-4970/CVE-2026-39822. A paired cross-platform witness proves that
`filepath.Join` plus `os.ReadFile` discloses a sibling signing-key file while
the same payload is rejected by `os.OpenInRoot` and an allowed document still
loads:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-http-filesystem-path-manifest.json `
  --results-dir C:\security-benchmarks\go-http-filesystem-path `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-path-traversal
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-rooted-file
go test ./...
Pop-Location
```

The Go template-source lane requires exact `net/http` and `text/template`
identity and preserves typed request data through one unique same-package
string wrapper, `Template.Parse` argument zero, and the same non-reassigned
parsed object into `Execute` or `ExecuteTemplate`. Parsing without execution is
not reported. A fixed server-owned template with the request value supplied
only as execution data is the negative boundary; HTML escaping is not a
template-grammar sanitizer because brace-delimited directives remain active.
The host records `FuncMap` and execution-data capability evidence so review can
prove the reachable secret, method, filesystem, network, process, state, or
resource effect. The paired fixtures prove a registered function discloses a
signing key in the positive and that a fixed `html/template` renders the same
payload as escaped inert data in the control:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-http-template-injection-manifest.json `
  --results-dir C:\security-benchmarks\go-http-template-injection `
  --runs 1 --selection-only `
  --auth github --model PROVIDER_MODEL --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-template-injection
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-template-data
go test ./...
Pop-Location
```

The Go object-authorization lane requires exact `net/http` and
`database/sql` identities, a typed request-derived object key, a fixed SQL
object predicate, and a concrete protected effect. Single-row reads close only
after `QueryRow` data is scanned and disclosed. Collection reads require the
same returned `Rows` to reach `Next`, `Scan`, and disclosure of scanned data;
direct `UPDATE` and `DELETE` executions are immediate state effects. Prepared
mutations require a fixed statement created by `Prepare` or `PrepareContext`
to reach `Stmt.Exec` or `Stmt.ExecContext` through the exact non-reassigned,
not-yet-closed statement or its proven alias. Mutations on an exact `Tx` remain
provisional until that same transaction reaches a non-deferred top-level
`Commit`; a dominating `Rollback`, missing commit, commit before execution,
or commit confined to a nested conditional does not prove durable state change.
Authentication and bound
parameters alone are not
authorization. The host retains a same-query owner/tenant/account predicate
only when its value is derived from the authenticated request context, and it
retains a fail-closed post-lookup ownership comparison only when it dominates
the response. The paired offline driver witnesses prove that an attacker can
read a victim invoice through the unscoped lookup and that the context-bound
account predicate blocks the same cross-account request while preserving an
owned-object read. A second pair proves the same boundary for a multi-row
project invoice listing. A third pair proves that an unscoped prepared DELETE
can remove a victim-owned invoice while a context-principal predicate blocks
the same attack and still permits deletion of an owned invoice. A fourth pair
proves the transaction boundary with a driver that stages changes until commit.
A fifth pair covers the common DB-prepared-statement transfer path: exact
`Tx.Stmt`/`Tx.StmtContext` source and returned statement identities retain the
fixed SQL predicate, execution stays provisional, and only the destination
transaction's commit closes the durable effect. Its control preserves that
entire topology while adding only a context-principal account predicate. A
sixth pair closes a direct transaction through a uniquely resolved typed
same-package helper, retaining both the caller boundary and the helper's exact
`Commit` path and line. A seventh pair adds a typed coordinator that aliases
and forwards the transaction to a leaf helper. The host resolves up to 32 exact
helper boundaries, rejects cycles and ambiguous outcomes, and records every
forwarding call plus the real leaf finalizer. An eighth pair crosses two
imported internal packages whose identities are derived from the repository's
exact `go.mod` module path; renamed imports, exported targets, and transaction
arguments must all agree. A ninth pair obtains the exact transaction through
two imported factory packages before executing and committing the mutation.
Factory summaries require a unique typed `*sql.DB` or `*sql.Conn` input, an
exact first `*sql.Tx` return, a direct-return or assigned-then-return leaf
`Begin`/`BeginTx`, and the same authoritative module/import rules. Each control
changes only the authenticated account predicate. A tenth pair captures both
the application factory and finalizer as local function values, while each
imported helper captures its leaf function in turn. Resolution accepts at most
eight exact, top-level, single-assignment aliases and retains every binding as
evidence; shadowing, reassignment, nested assignment, cycles, ambiguity, and a
ninth alias fail closed. An eleventh pair carries the object identifier and
authenticated principal through an exact handler-to-service-to-repository
chain spanning two imported local packages. Object-wrapper summaries compose
through at most 32 uniquely resolved same-package or cross-package boundaries,
retain every argument, parameter, and local alias as evidence, and remap the
principal position at every edge. The deepest enclosing `go.mod`, exact import
path and alias, exported unique target, top-level call shape, and exact string
parameter flow must all agree. Duplicate routes or modules, cycles, package or
function shadowing, nested, deferred, or goroutine calls, multi-name
assignments, immutable map selection, reassignment to a fixed value, and a
thirty-third boundary fail closed. A twelfth pair replaces both outer function
wrappers with methods. The handler binds one imported concrete service receiver;
the service binds one imported repository implementation to an explicitly
declared local interface. Exact `T` versus `*T` method sets, receiver type and
module identity, interface method membership, and at most eight receiver aliases
are preserved as evidence. Unbound interface parameters, nil pointer variables,
inexact constructor returns, promoted methods, method values, nested or unknown
reassignment, duplicate receiver methods, and a ninth alias fail closed:
A thirteenth pair obtains the service through an exact same-package or imported
constructor and traverses a named concrete value field to the repository method.
The constructor must return its single exact local struct result directly or
through at most eight top-level aliases, and the call must satisfy its ordinary
or variadic arity. Field chains retain each declaration's own package/import
identity and stop after eight fields. A fourteenth pair injects an exact
repository instance into a pointer or interface field through a keyed
constructor composite. Constructor summaries bind each field to its exact
parameter or direct concrete expression; call sites carry that instance through
aliases, enumerate valid interface implementations, and retain only the
implementation selected by the concrete argument and Go method set. Missing
fields, unbound arguments, parameter reassignment, wrong static types,
pointer-method calls on interface-held values, embedded, anonymous, generic,
duplicate, missing, or ambiguous fields; constructor parameters returned as the
result; nested or multiple returns; shadowed constructor names; a ninth
constructor alias; and a ninth field fail closed.
A fifteenth pair carries the selected implementation through a nested pointer
layer created inside the constructor composite while the same composite also
initializes unrelated scalar fields. Keyed composites recurse only through
exact repository-local struct or basic-interface fields, preserve every nested
assignment as separate evidence, accept ordinary trailing commas, and share the
eight-field selector bound. A constructor assignment or return may span at most
thirteen structural lines; a fourteenth line, positional composite, unresolved
nested receiver, wrong nested type, or reassigned referenced parameter fails
closed. Scalar initialization is ignored because it neither proves nor
invalidates receiver identity.
A sixteenth pair assembles the same nested receiver graph with exact top-level
field writes after constructing an empty service. Constructor state follows
direct selectors and explicit pointer dereferences through the existing bounded
aliases: pointer aliases share field state, while value aliases copy it. Every
accepted write records `go-method-receiver-constructor-field-write` at its real
line, the latest linear overwrite wins, and only the returned instance is
materialized. Eight writes and thirteen structural lines per write are accepted;
a ninth write, fourteenth line, conditional write, nested selector path, invalid
dereference, unresolved value, or parameter reassignment fails closed.
A seventeenth pair initializes the parent pointer layer first and injects the
repository later through a nested selector. Constructor values now retain a
recursive field-state tree and an independent origin for every node. A nested
write requires every parent to be a materialized keyed composite, may traverse
at most eight fields, and replaces only the exact leaf. Shallow copies share
pointer-field state while recursively copied concrete value fields remain
independent. Missing parents, conditional writes, wrong field or implementation
types, reassigned leaf parameters, a ninth selector field, and unresolved
dynamic parent state fail closed.
An eighteenth pair writes the same nested repository field through two
pre-existing aliases on the explicit arms of one top-level branch chain. The
host clones the complete constructor alias graph for every arm, preserves shared
pointer nodes across shallow value copies, applies at most eight writes per
executable path, and joins only structurally identical complete states. Two
through four write origins remain separate evidence. A mandatory final `else`
makes every path explicit. Each arm may contain at most sixteen
structural lines and only exact field writes on already-proven aliases.
One-sided or divergent writes, different returned objects, branch-local
assignment, nested control flow, early returns, unequal write budgets, a fifth
arm, a missing final `else`, a seventeenth arm line, and ambiguity fail closed.
A nineteenth pair obtains the constructor's parent pointer object from an
exact receiverless helper in another file of the same package. Helper summaries
accept a matching keyed composite directly, through at most eight exact aliases,
or through at most eight exact helper calls. Bare parameters are substituted at
their real constructor use line, while helper call, internal alias, composite,
return, constructor binding, nested write, and receiver evidence retain their
own paths and lines. Duplicate or shadowed helpers, cycles, a ninth call, pointer
or value result mismatch, parameter reassignment, positional composites,
transformed parameters, nested or multiple returns, and dynamic state fail
closed.
A twentieth pair imports the parent allocator from another package in the same
authoritative Go module. Qualified helper calls require an exact ordinary import
alias, an exported function, a uniquely resolved local-module path, and an
unshadowed package binding. Materialized composites retain the helper package's
type identity across constructor substitution, while selectors into that parent
must obey Go's exported-type and exported-field rules. Multiline constructor
fields retain the helper expression's actual line. Function values, wrong or
external module paths, unexported helpers, types, or fields, duplicate targets,
and mismatched defining-package identity fail closed under the shared eight-call
bound.
A twenty-first pair moves repository injection into that imported helper. The
factory allocates an empty parent, aliases its pointer, writes the selected
repository through the alias, and returns the original pointer. Helper writes
must be top-level, linear, declared-field assignments on a live result alias;
pointer aliases share state while direct fields on value aliases use independent
snapshots. Nested writes require every exact materialized parent, and
explicit dereference requires a pointer. Conditional writes outside the exact
all-path shape described below, missing parents or fields, transformed
parameters, invalid value dereferences, and ninth writes or selector fields fail
closed.
A twenty-second pair exercises Go's shallow value-copy rule inside the imported
helper. The returned layer is a value containing a pointer holder. Writes
through copied layer values share that exact holder, even across deeper concrete
value fields or a parent returned by another helper; replacing the pointer on
one copy detaches only that copy. The call, allocation, every copy alias, nested
write, return, constructor field, and receiver retain separate evidence.
A twenty-third pair places the shared-pointer repository write on both explicit
arms of one top-level helper branch, using a different value copy on each arm.
The host clones the complete materialized helper graph for each path,
preserves all alias and nested pointer identities inside that path, and joins
only structurally identical states with the same one-to-one node-sharing
topology. Evidence from both aliases and both write origins is retained. Each
arm accepts only writes through aliases proven before the branch, with at most
eight writes per path and sixteen structural lines.
One-sided or divergent state, pointer-slot replacement on different copies,
concrete-value isolation, branch-local assignments, nested control flow,
unequal write budgets, and over-budget paths fail closed. A twenty-fourth pair
extends the same imported helper proof through `if / else if / else`: three
shallow value copies write one shared holder on three explicit paths, and the
host retains all three write origins. Exact chains accept two through four arms
and require a final `else`; a fifth arm or incomplete chain fails closed. A
twenty-fifth pair expresses the same all-path helper initialization as an exact
`switch`. Each `case` and the mandatory final `default` reuses the bounded world
replay and identity-topology join. Two through four arms are accepted;
`fallthrough`, labelled or non-terminal `break`, missing or non-final `default`,
empty or divergent arms, nested control flow, and a fifth arm fail closed. A
twenty-sixth pair uses the common expressionless `switch` form and ends each arm
with an explicit unlabelled `break`. The scanner treats only that final statement
as Go's redundant case terminator, preserves all three write origins, and applies
the same complete-state, topology, and resource checks. A twenty-seventh pair
uses the common initializer-bound expression switch
`switch selected := label; selected`. The initializer must short-declare one
fresh guard from one exact built-in scalar parameter, and the guard must be the
switch expression without appearing in any arm body. Calls, composite or
non-scalar sources, mismatched guards, parameter or prior-local shadowing, and
any non-terminal or labelled `break` remain fail closed. A twenty-eighth pair
exercises both exact `switch repository.(type)` and
`switch selected := repository.(type)` recognition through an imported helper.
The source must be one uniquely resolved interface parameter. A named guard
must be fresh and may only be consumed by a leading `_ = selected` no-op; every
value-bearing use remains rejected. A twenty-ninth pair carries the interface
parameter through two exact local aliases before the switch. The scanner
follows as many as eight top-level, single-name, value-preserving assignments
while killing overwritten names. A ninth hop, transformation, selector,
multiple assignment, nested or conditional binding, scalar, shadowed or
ambiguous source, malformed guard, missing final default, or divergent arm
fails closed under the existing complete-state, topology, and resource checks.
A thirtieth pair converts the exact interface parameter to an empty interface
before carrying it through a local alias and entering the same bounded type
switch. Both `interface{}(repository)` and the predeclared
`any(repository)` spelling preserve the dynamic value. The latter is admitted
only when the enclosing module does not select a language version before Go
1.18 and `any` is not shadowed by a package declaration in any same-package
file, the current file's explicit or effective import name, a parameter,
receiver, named result, or preceding local declaration. Conversion assignments
consume the same eight-hop alias budget. Nested calls or conversions,
selectors, composite arguments, shadowed `any`, and a
ninth local edge remain fail closed. Constructor-helper discovery also ignores
unqualified call-shaped expressions unless a same-package function is actually
declared, preventing built-ins and type conversions from erasing otherwise
complete helper-boundary evidence. A thirty-first pair converts the exact
source to a distinct named basic interface before one further alias and the
same bounded type switch. The target must resolve uniquely after lexical
shadow checks. Identical interfaces and named empty interfaces are admitted;
otherwise both descriptors must belong to the same package and the source
method set must contain every target method with an exact signature. Qualified
local-module empty-interface targets are also supported. The conversion keeps
the original dynamic value while replacing only its tracked static interface
descriptor. Signature mismatch, a broader target, embedded or constraint
interfaces, unresolved import identity, cross-package nonempty method sets,
nested input, local type or value shadowing, and a ninth edge fail closed.
A thirty-second pair replaces textual signature equality with bounded canonical
Go type identities. Method parameter and result names are erased, grouped names
are expanded, `byte`/`rune` aliases are normalized, and qualified types resolve
through each declaring file's import aliases to their import paths. Local named
types include their package identity, while unexported method identity also
includes its declaring package. This admits exact same-package cross-file and
cross-package exported basic-interface conversions even when parameter names and
import aliases differ. It rejects missing or duplicate import identities,
dot/blank imports, unresolved external implicit aliases, different imported or
result types, cross-package unexported methods, malformed or unsupported types,
and every existing ambiguity and depth failure. The executable pair places the
target interface in a separate `contracts` package and proves both the unscoped
deletion and its principal-bound control.
A thirty-third pair expands named embedded basic interfaces before comparing
method sets. Same-package and qualified local-module embeddings resolve through
unique interface declarations, may nest through eight edges, and merge at most
64 canonical methods. Exported method identity follows its name; unexported
method identity also retains the package which declared it. Repeated diamond
methods are accepted only with identical signatures. Cycles, a ninth edge,
conflicting signatures, duplicate declarations, unresolved or external
embeddings, non-interface type terms, constraints, incomplete imports, and
oversized method sets fail closed. The executable pair composes the source
within `parent`, composes the target through an aliased `capabilities` import,
and proves the unscoped deletion and account-bound control through the same
type-switch join.
A thirty-fourth pair carries the same proof through exact Go type aliases.
Direct and grouped non-generic aliases can name method-signature types,
same-package embedded elements, imported capability contracts, constructor
parameters and fields, and the final conversion target. Each alias is resolved
in its declaration's own package/import context through at most eight local
module declarations. Alias identity is substituted exactly, including proven
empty-interface aliases, while defined types remain distinct. Cycles, a ninth
edge, generic declarations, duplicate alias or alias/interface names, qualified
unexported aliases, pointers, incomplete imports, unresolved or external
targets, and aliases ending at non-interface types fail closed. The executable
pair proves the unscoped deletion and the otherwise identical account-bound
control across all of those alias-bearing proof paths.
A thirty-fifth pair resolves methods promoted through local embedded concrete
structs. The selector search is breadth-first: a direct method or field hides
deeper candidates, and more than one candidate at the shallowest depth is
ambiguous. Embedding `T` versus `*T` preserves Go's distinct value and pointer
method sets, while an addressable concrete call may use the language's implicit
address operation. Every traversed embedded field is retained as evidence and
embedded pointer fields must have exact constructor provenance. The resolver
accepts at most eight promotion edges and rejects cycles, a ninth edge,
unresolved or external embedded types, embedded interfaces, generic forms,
visibility violations, duplicate methods, and ambiguous selectors. The
executable exploit reaches an unscoped repository deletion through two promoted
fields; its matched control keeps the same topology and adds only the
authenticated account predicate.

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-http-object-authorization-manifest.json `
  --results-dir C:\security-benchmarks\go-http-object-authorization `
  --runs 1 --selection-only `
  --auth github --model PROVIDER_MODEL --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-list-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-list-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-prepared-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-prepared-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-transaction-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-transaction-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-transaction-stmt-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-transaction-stmt-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-helper-transaction-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-helper-transaction-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-helper-chain-transaction-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-helper-chain-transaction-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-helper-transaction-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-helper-transaction-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-transaction-factory-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-transaction-factory-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-transaction-function-value-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-transaction-function-value-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-wrapper-chain-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-wrapper-chain-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-method-interface-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-method-interface-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-constructor-field-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-constructor-field-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-constructor-interface-field-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-constructor-interface-field-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-nested-constructor-interface-field-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-nested-constructor-interface-field-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-constructor-field-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-constructor-field-write-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-constructor-nested-field-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-constructor-nested-field-write-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-constructor-branch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-constructor-branch-write-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-constructor-helper-parent-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-constructor-helper-parent-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-constructor-helper-parent-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-constructor-helper-parent-delete-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-constructor-helper-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-constructor-helper-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-value-copy-pointer-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-value-copy-pointer-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-branch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-branch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-multi-branch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-multi-branch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-switch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-expressionless-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-expressionless-switch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-initialized-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-initialized-switch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-aliased-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-aliased-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-empty-interface-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-empty-interface-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-named-interface-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-named-interface-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-imported-helper-cross-package-interface-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-imported-helper-cross-package-interface-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-embedded-interface-type-switch-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-embedded-interface-type-switch-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-type-alias-interface-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-type-alias-interface-authorization
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-promoted-method-delete-idor
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-package-safe-promoted-method-authorization
go test ./...
Pop-Location
```

The Go process-execution lane requires exact standard-library `os/exec`, `os`,
or `syscall` bindings, or the exact `golang.org/x/sys/execabs` binding, plus a
typed `*http.Request` source. It keeps construction separate from execution: a
risky `Command`, `CommandContext`, or manually populated `Cmd` must reach
`Run`, `Start`, `Output`, or `CombinedOutput` on the same non-reassigned
object. `os.StartProcess` and `syscall.Exec`, `ForkExec`, and `StartProcess`
are instead immediate dispatchers with exact executable and argv positions.
The model follows `Path`, complete `Args` replacement, exact `Args[index]`
mutation, local slice literals and aliases, and zero-value or `new(exec.Cmd)`
construction. It distinguishes attacker-selected executables, shell or
interpreter command grammar, Windows batch-file arguments, interpreter script
paths, fixed-host SSH commands, and option-sensitive Git/rsync arguments from
ordinary direct argument vectors. `Args[0]` is process-visible argv data, not
the executable selected by `Cmd.Path` or a low-level dispatcher's first
argument. Immutable complete-command selection and a preceding `--` for
supported tools are deterministic barriers. Two paired cross-platform fixture
sets install their test executable as an isolated temporary shell witness,
proving constructor and manual-field grammar injection plus fixed-command
isolation without invoking the host shell:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-os-exec-command-injection-manifest.json `
  --results-dir C:\security-benchmarks\go-os-exec-command-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-shell-command-injection
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-shell-command
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-manual-cmd-shell-injection
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-manual-cmd-shell-command
go test ./...
Pop-Location
```

The Go SQL lane requires exact standard-library imports and a typed
`*sql.DB`, `*sql.Tx`, or `*sql.Conn` query receiver. Its positive formats a
request value into the query-text argument of `DB.QueryContext`; the matched
control keeps query text fixed and passes the same bytes only as a placeholder
value. A tainted `Prepare*` call is retained only when the resulting statement
later executes. Standard-library driver witnesses prove both grammar injection
and bound-value isolation without requiring a network database:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-database-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\go-database-sql-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-sql-injection
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-sql
go test ./...
Pop-Location
```

The sqlx lane separately requires the exact `github.com/jmoiron/sqlx` import
and a proven DB, Tx, or Conn handle. It preserves destination-before-query
`Select`/`Get`, receiver and package helper signatures, named bindings,
placeholder rebinding, and extended statement execution. The positive exposes
an internal record through request-derived `DB.Select` grammar; the matched
offline control keeps the same bytes in one bound value:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-sqlx-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\go-sqlx-sql-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-sqlx-sqli
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-sqlx
go test ./...
Pop-Location
```

The GORM v2 lane requires the exact `gorm.io/gorm` import and a proven
`*gorm.DB`. It distinguishes query construction from execution across both the
traditional API and `gorm.G[T](db)`: request data in `Raw`, `Where`, `Order`,
`Table`, and other documented fragment positions is retained only when the same
fluent or assigned builder reaches a real finisher. The generic model preserves
context-first signatures, `Count` column grammar, exact typed interfaces,
`JoinBuilder`/`PreloadBuilder` callback clauses, and `gorm.Expr` in constructor
options or `Set` assignments. Generic join targets and preload associations are
typed metadata, and `Build` only materializes a DryRun statement. Fixed
templates with request data only in later placeholder arguments remain
controls. Four offline modules prove traditional `Raw(...).Scan(...)` and
generic `Where(...).Find(ctx)` exploits plus their matched bound-value controls
without a database service or dependency download:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-gorm-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\go-gorm-sql-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-gorm-sqli
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-gorm
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-gorm-generics-sqli
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-gorm-generics
go test ./...
Pop-Location
```

The Squirrel lane requires the exact `github.com/Masterminds/squirrel` import,
a typed immutable builder or `Sqlizer`, and a proven Squirrel or
`database/sql` runner. It treats structural strings in constructors, joins,
columns, grouping, ordering, prefixes, suffixes, `Expr`, `ConcatExpr`,
`Alias`, and `Case` as query grammar while keeping placeholder arguments,
`Values`, `Set` values, and `Where`/`Having` map or `Eq` values as data.
`RunWith` alone is inert: the same builder must reach an execution method, an
exact package helper, or materialized SQL that later reaches typed database or
prepared-statement execution. `DebugSqlizer` output is retained only when it
is actually executed. The matched offline modules prove both an injected
`Where(...).RunWith(...).Query()` predicate and bound-value isolation without
a database service or dependency download:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-squirrel-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\go-squirrel-sql-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-squirrel-sqli
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-squirrel
go test ./...
Pop-Location
```

The pgx lane separately requires exact `github.com/jackc/pgx/v5` or
`pgxpool` imports and typed connection, transaction, or pool receivers. Its
direct operations preserve context, SQL text, and later values/options at
their documented positions. Manual preparation closes only through the same
receiver and a fixed statement name; `Batch.Queue` closes only when the exact
typed batch reaches `SendBatch`. Custom `QueryRewriter` implementations are
resolved only through the exact interface signature and one local struct type.
The model follows request-derived receiver fields into the first returned SQL
value across `Exec`, `Query`, `QueryRow`, and dispatched batches, while a fixed
first return with the same data only in returned arguments is rejected. The
matched offline modules use the exact pgx v5 module path and API-compatible
deterministic witnesses so both direct and rewriter exploit/control pairs run
without PostgreSQL or dependency downloads:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-pgx-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\go-pgx-sql-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-pgx-sqli
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-pgx
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-pgx-query-rewriter-sqli
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-pgx-query-rewriter
go test ./...
Pop-Location
```

The low-level pgconn lane is separate because its execution semantics differ
materially from high-level pgx. It recognizes exact `*pgconn.PgConn` receivers,
including `pgx.Conn.PgConn()` escape hatches; preserves `Exec`, `ExecParams`,
`CopyFrom`, and `CopyTo` SQL positions; closes prepared SQL through a fixed name
or the exact returned `StatementDescription`; and requires queued `pgconn.Batch`
and `Pipeline` commands to reach `ExecBatch`, `Flush`, or `Sync`. Parameter byte
slices and COPY streams remain data. Unsynchronized pipeline sends and
`Pipeline.Close` are not treated as execution. The matched fixtures prove
simple-protocol grammar injection and extended-protocol parameter isolation:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/go-pgconn-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\go-pgconn-sql-injection `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep

Push-Location benchmarks\fixtures\go-cross-file-pgconn-sqli
go test ./...
Pop-Location
Push-Location benchmarks\fixtures\go-cross-file-safe-pgconn
go test ./...
Pop-Location
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

The Spring path lane carries an annotated request parameter across three
constructor-injected Java services into `Files.readString`. Its negative
control rejects absolute input, proves component-aware lexical containment,
resolves both the existing root and target through `toRealPath`, and rejects a
real target outside the real root. Pure-JDK witnesses cover parent traversal,
absolute reset, sibling-prefix confusion, symlink escape, and an allowed
in-root document. Two additional matched pairs prove that neither exact
`java.io.File.getName()` nor exact `java.nio.file.Path.getFileName()` rejects
the parent name `..`; each control rejects the exact reduced parent before the
same sink while preserving an allowed name:

The `Path` specialization follows Java compilation-unit identity rather than
simple spelling. An exact `java.nio.file.Path` or `Paths` import remains
authoritative over a top-level lookalike in the same package, while
`java.nio.file.*` is rejected when such a same-package type exists. Nested and
different-package names do not suppress the JDK binding. Exact and wildcard
static imports of `Path.of` and `Paths.get` are supported only when no local
method, qualified lookalike call, or competing same-name static import can own
the call. Fully qualified factories remain independent of every simple-name
shadow.

Both basename specializations also follow exact local helper returns. Every
helper must have one unoverloaded symbol, exact official `String`/`File` or
`String`/`Path` input and return types, a straight-line single return, and exact
fixed arity, argument position, and value identity. Same-file calls may be
bare, `this`-qualified, or owner-qualified. Cross-file calls must remain in the
nearest Maven project or conventional Gradle project/module, resolve exactly
one top-level owner through the same package, an exact single-type import, or a
fully qualified name, and invoke an accessible static method. Cross-package
calls additionally require a public top-level type and public method. Gradle
Groovy and Kotlin build scripts and settings files are exact boundary markers;
the deepest ancestor wins, isolating sibling modules and nested composite
builds. A conventional caller module may also read a helper from one direct
module named by a literal `api`, `implementation`, `compileOnly`, or
`compileOnlyApi` `project(":path")` dependency in its own top-level
`dependencies` block. The project path must be included by one unique nearest
settings build and map to the standard physical directory with exactly one
`build.gradle` or `build.gradle.kts`; dependency direction is preserved.
Likewise, a conventional Maven reactor caller may read one direct sibling
whose exact literal `groupId`, `artifactId`, and `version` match a unique
reactor module. The dependency must be in the caller's top-level
`dependencies`, use the default/`compile` or `provided` scope, use the
default/`jar` type without a classifier, and keep both endpoints under
`src/main/java`. Literal nested module paths and exact local-parent
`groupId`/`version` inheritance are supported; `dependencyManagement` alone
does not establish an edge.
Wildcard custom imports, duplicate owners across the caller's visible modules,
undeclared siblings, test/runtime-only or transitive dependencies, variables,
nonstandard production source sets, custom project directories/build filenames,
composite includes, Maven property/interpolation or managed-only declarations,
non-JAR/classified dependencies, ambiguous or overlapping reactor ownership,
ambiguous settings/build ownership, inaccessible or instance methods, branches,
transformations, reassignment, helper chains,
foreign receivers, and lookalike types fail closed. Evidence names the helper
return while a parent rejection
must still dominate the caller-side result before the sink. The four Spring
basename fixtures cross this compilation-unit boundary, so the strict
executable benchmark exercises it independently of the adversarial unit matrix.

The basename controls are branch-sensitive. An exact comparison contributes a
parent-rejection lead only when the equality is not negated or conditionally
conjoined, its matching branch itself unconditionally returns or throws, that
abrupt completion is not caught before the sink, and the guard shares the
sink's lexical block path. A logging-only check, optional nested check, or
unrelated nearby `return`/`throw` remains an incomplete boundary. The positive
`Path.getFileName()` fixture deliberately contains the exact `..` comparison,
logs it, and then remains exploitable; the matched control terminates the exact
branch.

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/java-multi-hop-path-manifest.json `
  --results-dir C:\security-benchmarks\java-multi-hop-path `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Spring SSRF lane carries an annotated request parameter across the same
two uniquely typed Java services into the complete URI of a JDK `HttpRequest`
sent by `HttpClient`. Its negative control treats the request value only as an
exact key into fixed server-owned complete destinations and requires
`HttpClient.Redirect.NEVER`. Pure-JDK loopback witnesses prove that the
vulnerable complete URI reaches a private service while the control rejects it
before transport:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/java-multi-hop-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\java-multi-hop-ssrf `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The Spring WebClient lane carries the same annotated value through two typed
service boundaries into the first argument of reactive `WebClient.uri`. Its
control maps the request value to a fixed complete `URI` and configures the
underlying JDK connector with `HttpClient.Redirect.NEVER`. Executable witnesses
use the actual WebClient and loopback-only services to prove both behaviors:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/java-webclient-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\java-webclient-ssrf `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

The OkHttp lane requires more than a suspicious builder call: the annotated
value must reach `Request.Builder.url`, the resulting typed `Request` must be
passed to a typed `OkHttpClient.newCall`, and that call must actually be
executed or enqueued. Inert builders, prepared-but-unexecuted calls, local
lookalike types, and component-only `HttpUrl.Builder` operations are negative
controls. Its safe pair selects one fixed complete URL by exact server-owned
key and disables both HTTP and HTTPS redirect following:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/java-okhttp-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\java-okhttp-ssrf `
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

The separate Razor Pages SQL lane proves that an unannotated named handler
parameter is remotely model bound, preserves it through the typed service, and
contrasts concatenated query grammar with the same value carried only by a
typed parameter. Both halves are executable without an external database:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/aspnet-razor-page-sql-manifest.json `
  --results-dir C:\security-benchmarks\aspnet-razor-page-sql `
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

The ASP.NET path lane follows a request value across three uniquely typed
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

The standalone Node/Python filesystem-path lane follows an HTTP request value
across three exact relative-import boundaries into official Node `fs` or Python
`builtins`/`os`/`shutil` path positions. Its controls preserve the same
four-file topology but select one complete server-owned path from a fixed map.
The host distinguishes path arguments from file contents and encodings, accepts
documented source and destination roles for copy/move/link/rename operations,
and rejects aliases bound to local lookalikes or foreign Python modules:

```powershell
node benchmarks/run-benchmark.mjs `
  --manifest benchmarks/filesystem-path-framework-manifest.json `
  --results-dir C:\security-benchmarks\filesystem-path-framework `
  --runs 1 --selection-only `
  --auth github --model gpt-5.6-terra --effort high --mode deep
```

Use `--model` and `--effort` to select a Copilot model and reasoning effort.
The default is Copilot's `auto` model selection. The configured `xhigh` effort
is retained for explicit models and is deliberately not sent for `auto`, because
Copilot rejects reasoning-effort overrides when it selects the model.
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

## Native desktop applications

The repository includes a native WPF `.NET 8` Windows application in
[`apps/windows`](apps/windows) and an Avalonia `.NET 8` Linux application in
[`apps/linux`](apps/linux). They expose whole-repository, scoped path,
committed-diff, and working-tree scans; standard/deep modes; model and effort
selection; optional cost and credit bounds; live progress and process-tree
cancellation; findings, validation, attack paths, reports, private scan
history, diagnostics, corpus evaluation, and baseline/candidate effectiveness
comparison.
The New scan tab also accepts repeatable SARIF seed files and an optional
original SARIF source root, using the same hardened normalization and
independent-review contract as the CLI and SDK. It also accepts the same
expiring secret-fingerprint baseline as the CLI without placing credential
bytes in GUI settings or command output.

Both desktop applications remain clients of this standalone scanner. They do
not duplicate prompts or model orchestration, invoke a command shell, share
another scanner's state, or read credentials. Before findings are displayed it
recomputes the sealed manifest digests for the findings and coverage artifacts.
The shared platform-neutral desktop layer keeps command construction, process
supervision, artifact acceptance, history, and benchmark behavior identical.
Linux preferences and generated history use Linux-specific paths below the
same scanner-owned `copilot-security-home`, so WSL and Windows can run without
overwriting one another.

```powershell
dotnet run `
  --project apps/windows/CopilotSecurity.Core.Tests/CopilotSecurity.Core.Tests.csproj `
  --configuration Release

dotnet run `
  --project apps/windows/CopilotSecurity.Gui/CopilotSecurity.Gui.csproj `
  --configuration Release
```

On Linux or WSL:

```bash
dotnet run --project apps/linux/CopilotSecurity.Gui.Tests/CopilotSecurity.Gui.Tests.csproj \
  --configuration Release
dotnet run --project apps/linux/CopilotSecurity.Gui/CopilotSecurity.Gui.csproj \
  --configuration Release
```

See [`apps/windows/README.md`](apps/windows/README.md) and
[`apps/linux/README.md`](apps/linux/README.md) for architecture, trust
boundaries, publication and installation commands, benchmark comparison, and
failure/recovery behavior.

## Effectiveness benchmark

`benchmarks/manifest.json` defines paired vulnerable and fixed fixtures for
command injection, path traversal, archive symlink/hardlink write pivots,
decompression bombs with actual-output and cumulative expansion budgets,
object-level authorization, SQL injection,
server-side request forgery, unsafe deserialization including a matched PyYAML
UnsafeLoader/safe-load wrapper pair and exact NumPy, Joblib, and PyTorch model
loaders, reflected XSS, XML
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
data even though the visible nonce repeats. The package-backed availability
lanes now include persistent `socket.io-parser` zero-attachment state: the
affected fixture retains every later binary frame, while the source-identical
repaired fixture rejects the impossible packet before retaining state. A second
pair exercises the ordinary public `socket.io` Server surface with identical
4.8.3 application source and parent dependency: only the npm-locked transitive
parser changes from vulnerable 4.2.6 to repaired 4.2.7. The newest pair carries
a request-controlled numeric ID size through three wrappers into
`nanoid/non-secure` 5.1.15; its source-identical 5.1.16 twin proves that the
negative-size decrement loop terminates after the repair. The newest
industrial-protocol pair starts an official `OPCUAServer` with exact
`node-opcua` 2.165.0 or 2.168.0 dependency proof. A bounded real-package
witness shows that the affected build retains the first of 50,001 unique
nonces, while the repaired build evicts it at its 50,000-entry ceiling. A
second node-opcua pair configures a real application `userManager`: 2.165.2
accepts one encrypted username token under two different session nonces and
passes a forged empty password to the manager, while source-identical 2.166.0
rejects both nonce violations before the manager is called. The newest pair
uses an official Auth.js middleware wrapper and changes only `next-auth`
5.0.0-beta.31 to 5.0.0-beta.32. A real provider-configuration error becomes a
truthy auth object and permits the unauthenticated request on beta.31, while
the repaired version maps it to `null` and denies it. The current JSONata pair
then carries a request-controlled expression through three wrappers into a
compiled expression's `evaluate()` call. Exact 2.2.0 recovers the host
`Function` constructor in a bounded witness, while source-identical 2.2.1
rejects the chain before host access. The LiquidJS pair carries a remote
template through the same wrapper depth into official `parseAndRender`: exact
10.25.7 resolves inherited `valueOf` as a filter and returns only the host
`process.version`, while source-identical 10.26.0 uses null-prototype filter
and tag registries and returns `false`. The Velocity.js pair carries a remote
template through the same wrapper depth into official `render`: exact 2.1.6
follows inherited `constructor.constructor` to the host `Function` constructor,
while source-identical 2.1.7 blocks the property read with its shared prototype
guard. The Shescape pair carries a remote value through the same wrapper depth,
escapes it for `cmd.exe`, and follows the exact result into official Node
process dispatch: 3.0.0 leaves CMD parentheses raw, while source-identical 3.0.1
caret-escapes both. The decompression pair carries an uploaded archive through
the same wrapper depth into official `@xhmikosr/decompress`: exact 10.2.0
allows a bounded entry writer to cross into a sibling-prefix directory, while
source-identical 10.2.1 rejects the destination and also repairs escaping link
targets and special mode bits. The latest node-tar pair then carries a
remote compressed archive through three wrappers into `tar.list`: exact 7.5.18
processes a bounded 1017.97:1 gzip expansion, while source-identical 7.5.19
aborts at its new default 1000:1 cumulative ratio guard. The vm2 pair carries
remote code through the same wrapper depth into an official `VM.run`: exact
3.11.5 recovers only the host `process.version` with a bounded non-shell
witness, while source-identical 3.11.6 blocks the dangerous-prototype chain.
The scanner separately recognizes `NodeVM.run` with wildcard builtins only
when `os` or `dns` remains exposed. The Sequelize Oracle pair carries a remote
predicate through three wrappers into an official model query: exact 6.37.3
emits a bounded injected predicate from the real query generator without a
database connection, while source-identical 6.37.4 rejects the same value.
The pickle corpus separately covers direct `pickle.loads` and the two-stage
`pickle.Unpickler(file).load()` object flow, with JSON controls and a bounded
fixture-local callable witness for both call shapes. The shell-quote pair carries a remote operator through three wrappers into an
explicit object token, official `quote()`, and a real POSIX shell dispatch:
exact 1.8.3 preserves a line terminator and executes only the harmless `pwd`
second line in `/tmp`, while source-identical 1.8.4 rejects the token before
serialization. The NumPy pair holds the upload, relative wrapper, package,
object-dtype payload, request and decoded-byte budgets, header and format
checks, rank and element limits, and witness constant while changing only
`allow_pickle=True` to `False`. The Joblib pair likewise preserves its model
upload, relative `parse_model` wrapper, byte budget, exact dependency/runtime
record, serialized artifact, and harmless in-process witness while replacing
only pickle-backed `joblib.load` with `json.load` at the unsafe boundary. The
PyTorch pair preserves the same bounded upload, wrapper, patched 2.13 CPU
runtime, and malicious checkpoint while changing only explicit
`weights_only=False` to `weights_only=True`. Its host model separately proves
full-unpickler opt-in, a custom pickle module, a pre-2.6 default under an exact
pin, or an advisory-affected weights-only version instead of treating every
`torch.load` spelling as exploitable. The lxml pairs keep their Flask upload,
relative wrapper, XML payload, and fixture-local marker identical while
changing only `lxml==6.0.2` to `lxml==6.1.1`; the former discloses the marker
through the affected external-entity default and the latter rejects it. One
pair requires eager `iterparse` consumption. The other requires a constructed
`ETCompatXMLParser` (or its `XMLTreeBuilder` alias) to reach the actual `XML`,
`fromstring`, `fromstringlist`, or `parse` parser argument without conflating
ordinary `XMLParser`. Each of the 222 cases in 111 exploit/control pairs is
scanned three times, producing 666 scans that measure both accuracy and model
variance.
Exact dependency evidence also respects the API lifetime: PyTorch 1.13.0 is
the first supported `weights_only` boundary, so an exact older pin suppresses
keyword-mode findings that could not reach the modeled loader branch.
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

# Run the strict GitHub Copilot SDK trusted-instruction diagnostic
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/node-copilot-prompt-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-prompt-injection `
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
