# `@secwest/copilot-security`

TypeScript SDK and CLI for the Copilot CLI-backed security scanner. See the
[repository README](../../README.md) for setup, usage, authentication, safety,
and attribution.

The package is ESM-only and provides:

- `copilot-security` CLI
- `CopilotSecurity` SDK class
- repository, path, committed-diff, and working-tree targets
- standard and deep multi-pass modes
- deterministic scan artifacts, Markdown report, SARIF, exports, history,
  reruns, comparison, bulk scans, and finding feedback
- host-rendered and atomically sealed `report.md` output; the model authors only
  structured drafts, and exact finding evidence references are re-audited
  against each finding's `codeEvidence` IDs before completion
- host-reconciled per-file coverage that preserves omitted inventory paths as
  deferred work instead of accepting a false complete claim
- pre-session host-generated and SHA-256-verified repository, review, and
  `SECURITY.md` path inventories; the model cannot choose, narrow, or rewrite
  scan scope, and conventional generated trees such as .NET `bin`/`obj` are
  omitted before ranking
- deterministic pre-model typed and entropy secret candidates across bounded
  working-tree plaintext and reachable Git blobs, with no plaintext in detector
  prompts or reports, repository-scoped keyed fingerprints, revision
  deduplication, private local audit JSONL, and exact expiring justified
  baselines
- registered-target checks surrounding staged-file SHA-256 comparisons before
  model execution and final sealing, so checkout races fail closed
- a disposable repository/plugin snapshot that omits links and special files,
  plus an allowlisted model environment, category-scoped permissions, disabled
  tool network/credential forwarding, and mandatory positive native-sandbox
  telemetry for every stored-credential shell completion; token-authenticated
  sessions remove public token aliases and expose no shell tools
- typed host-generated Node HTTP, Python web, Spring/servlet, and ASP.NET
  command/SQL/SSRF/filesystem-path data-flow hypotheses, including JDK
  `HttpClient`, Spring `RestTemplate`, reactive Spring `WebClient`, and
  module-bound Axios clients and instances; Axios preserves only the URL
  argument or request-config `url` property and keeps request bodies out of
  destination flow. A separate Go model requires the exact standard-library
  `net/http` import and a typed `*http.Request` source, preserves only complete
  URL arguments, and requires a request built by `NewRequest*` to reach a
  proven typed or constructed `Client.Do`. It follows at most one unique
  same-package string wrapper and rejects body-only flow, untyped receivers,
  inert construction, reassignment, and import lookalikes. A typed Go SQL
  model separately preserves request input into the exact query-text position
  of standard-library `DB`, `Tx`, and `Conn` operations. Placeholder and
  `sql.Named` values remain data; tainted `Prepare*` text requires later
  statement execution; and inferred handles, same-file receiver fields, one
  unique package wrapper, fixed query selection, and reassignment are explicit.
  A separate sqlx model requires the exact `github.com/jmoiron/sqlx` import and
  proven DB, Tx, or Conn identity. It preserves destination-before-query
  `Select`/`Get` signatures, receiver and package helpers, named binding,
  placeholder rebinding, and `Stmt`/`NamedStmt` execution closure. Fixed SQL
  with request data only in positional or named values remains a negative
  control; forks, arbitrary Queryer/Execer implementations, inert preparation,
  and reassigned statements are rejected.
  A separate GORM v2 model requires the exact `gorm.io/gorm` import and proven
  `*gorm.DB` identity. It preserves the first grammar argument of `Raw`,
  `Where`, `Not`, `Or`, `Select`, `Distinct`, `Table`, `Group`, `Having`,
  `Order`, `Joins`, and `InnerJoins`, but reports those deferred builders only
  after a same-chain or assigned finisher. It separately models immediate
  `Exec`, `Pluck` identifiers, inline finisher conditions, and the first
  `gorm.Expr` argument while excluding later placeholder values. Unexecuted or
  reassigned builders, forks and legacy imports, untyped methods, fixed fragment
  maps, and ambiguous wrappers are rejected.
  A separate Masterminds/Squirrel model requires the exact upstream import,
  typed builders or `Sqlizer` values, and proven Squirrel or `database/sql`
  runners. It preserves structural constructor and method arguments across
  immutable fluent and assigned builders, nested `Expr`/`ConcatExpr`/`Alias`/
  `Case` values, exact package helpers, and `ToSql`/`MustSql` or
  `DebugSqlizer` materialization. Deferred builders must reach a real execution
  method, and materialized or prepared query text must later execute. Bound
  placeholder, `Values`, `Set`, map, and `Eq` values; runnerless builders;
  unrelated `Rows.Scan`; lookalikes; arbitrary runners; reassignment; and
  ambiguous wrappers are rejected.
  A separate pgx v5 model requires exact `pgx` or `pgxpool` imports and typed
  Conn, Tx, or Pool receivers. It preserves the context/SQL/value split,
  follows fixed prepared names on the same receiver, and reports queued SQL
  only after the same typed batch reaches `SendBatch`. It also resolves one
  exact local custom `QueryRewriter`, tracks receiver fields or preserved input
  SQL into the first returned value, and carries queued rewrites through
  `SendBatch`; taint confined to the returned argument slice stays data. Pgx v4
  and import lookalikes, later bound values, ambiguous or inexact rewriters,
  inert preparation, and undispatched or reassigned batches are rejected.
  A separate low-level pgconn model proves exact `PgConn`, `Batch`, `Pipeline`,
  and `StatementDescription` identities. It preserves raw, extended-protocol,
  and COPY SQL positions; requires prepared execution, `ExecBatch`, `Flush`, or
  `Sync` closure; excludes parameter bytes and COPY streams; and treats
  unsynchronized sends plus `Pipeline.Close` as inert.
  Node
  object-authorization hypotheses preserve the exact
  request-controlled record lookup and principal-bound owner filtering or
  post-lookup policy leads without treating authentication or opaque IDs as
  authorization. ASP.NET object-authorization hypotheses preserve bound route
  or query identifiers into typed EF Core single-record lookups and retain only
  exact principal-bound predicates or enforced resource-authorization leads;
  `[Authorize]` alone is not a resource control. Spring object-authorization
  hypotheses preserve bound request identifiers into typed Spring Data
  `findById` or declared owner-qualified derived queries. They retain only an
  exact typed-principal query binding or active `@PostAuthorize` ownership
  policy on a Spring-managed read method; authentication and role-only method
  checks are not resource controls. Spring MVC/JPA mass-assignment hypotheses
  require an official state-changing controller, an official
  `@ModelAttribute` whose type is the uniquely resolved persisted JPA entity,
  and the exact same object reaching typed `CrudRepository` or
  `JpaRepository.save`. Applicable official allowed-field and constructor-only
  binders are control leads; `@Valid`, authentication, denylists, DTOs, fixed
  entities, and shadow framework types do not silently satisfy that proof.
  GitHub Actions hypotheses require the complete same-job chain from
  `pull_request_target`, through an explicit pull-request head checkout, to a
  later workspace command or local action on the matching path. Effective
  token permissions, secret/OIDC exposure, persisted credentials, immutable
  selection, review/environment gates, and Checkout v7 fork protection remain
  separate review evidence; a trigger, checkout, or execution step alone does
  not create the hypothesis.
  Self-hosted pull-request hypotheses require a pull-request-capable trigger,
  a literal self-hosted label, static custom label, or runner group, an
  official untrusted checkout, and later execution from the matching workspace.
  Current standard GitHub-hosted and recognized BuildJet/Warp labels are
  excluded, while fully dynamic runner selection is deferred. Ordinary
  `pull_request` rows do not invent secret or write-token authority. Review
  must confirm the runner is customer controlled and whether its workspace,
  service identity, network access, Docker socket, tool caches, or later jobs
  survive the untrusted job; a proven freshly destroyed single-job JIT runner
  is strong persistence counterevidence.
  Cross-workflow artifact-poisoning hypotheses require a named pull-request
  producer, untrusted checkout, official upload name/path, matching privileged
  `workflow_run`, official triggering-run download, extraction path, and later
  execution closure. Producer success and transport integrity are not trust;
  isolated extraction plus strict typed-data parsing is counterevidence only
  when artifact content is never executed.
  Reusable-workflow injection hypotheses require an externally influenced
  default-branch event field, exact local workflow call and forwarded name,
  declared `workflow_call` string input, and direct interpolation into `run` or
  official `actions/github-script` source. Input-derived `${{ env.NAME }}`
  re-expansion remains unsafe; native shell or `process.env` use keeps the
  intermediate environment value as data. Effective caller/callee permissions,
  forwarded secrets, OIDC, and environment gates remain explicit.
  Composite-action injection hypotheses require the exact attacker-controlled
  caller field, workflow-step input, literal local action directory, one valid
  metadata descriptor, declared input, composite runtime, and generated shell
  or official GitHub Script source. Same-step `${{ env.NAME }}` re-expansion
  remains unsafe, while native shell or `process.env` consumption keeps an
  intermediate environment value as data. Descriptor ambiguity, parent
  traversal, invalid metadata, shell-less commands, cross-step environment
  assumptions, ordinary action inputs, lookalikes, and comment-only secret
  evidence are rejected; effective permissions and explicitly forwarded and
  consumed secrets remain explicit.
  Same-workflow injection hypotheses couple each supported event to exact
  attacker-controlled context fields and require the value to reach `run` or
  an exact known action code-input. The bounded evaluator follows direct dot
  and single-quoted bracket contexts, parentheses, `toJSON`, `fromJSON`,
  `format`, `join`, reachable `&&`/`||` results, and workflow/job/step
  `${{ env.NAME }}` re-expansion. It rejects predicates, fixed or unreachable
  values, native shell and `process.env` consumption, unknown action inputs,
  lookalikes, and dynamic revisions. Ordinary `pull_request` code execution
  does not invent secret or write-token impact; other event rows retain exact
  permission, secret, review, and environment evidence.
  Models include exact
  source/sink lines and nearby negative controls for the mandatory residual
  correction turn, plus bounded one-hop or
  two-hop C# controller/service summaries,
  one-hop or two-hop Java controller/service summaries, and one-hop or two-hop
  relative-import/call/parameter summaries for Node/TypeScript and Python
  wrappers; language strings and comments are masked before structural
  matching
- bounded native Copilot model-call retries plus six concise, idempotent
  defensive recovery prompts for explicit safety-classifier refusals, without
  replaying the original blocked text, and cancellation-safe cleanup of
  partially initialized CLI sessions
- up to three isolated Copilot sessions by default after hard model-turn
  deadlines or recognized transport interruptions, with untrusted-draft
  recovery over the same immutable snapshot, bounded disconnects, and
  cumulative root/subagent cost accounting across attempts
- bounded, data-only normalization of complete flow-style model drafts before
  deterministic sealing; aliases, duplicate keys, ambiguous syntax, symlinks,
  and non-object roots remain terminal, and canonical schemas still decide
  acceptance
- cancellation and streamed Copilot usage/subagent events

```ts
import { CopilotSecurity } from "@secwest/copilot-security";

await using scanner = new CopilotSecurity({
  copilotOverrides: {
    model: "gpt-5.6-sol",
    reasoning_effort: "xhigh",
  },
});

const result = await scanner.run("/path/to/repository", {
  auth: "github",
  outputDir: "/path/outside/repository/results",
  seedSarifPaths: ["/path/to/codeql.sarif", "/path/to/trivy.sarif"],
  sarifSourceRoot: "/original/build/checkout",
  secretBaselinePath: "/security/project-secret-baseline.json",
  secretHistoryDepth: 512,
});

console.log(result.reportPath);
```

`seedSarifPaths` imports SARIF 2.1.0 results only as untrusted candidate hints.
The host strips imported messages, snippets, fixes, fingerprints, properties,
and embedded content; validates paths and line ranges against the repository;
and requires Copilot to independently prove or reject each in-scope seed.
`sarifSourceRoot` remaps absolute paths emitted from another checkout. Omit it
when SARIF paths are repository-relative or were produced from the repository
being scanned.

`secretBaselinePath` selects an optional strict schema 1.0 file containing only
opaque local HMAC fingerprints, exact rule/path identity, a justification, and
a canonical UTC expiry. The host rejects malformed or linked baselines before
Copilot starts. Without this option, it creates a per-repository empty baseline
beneath `COPILOT_SECURITY_HOME/copilot-security-home/secret-scanner`; candidate
bytes never enter the detector inventory, report, baseline, error, or
diagnostic channel.

`secretHistoryDepth` selects how many newest commits across reachable refs are
examined for credentials absent from the current tree. It defaults to `128`,
accepts `0` through `2048`, and uses `0` to disable history while preserving
the current-tree pass. Historical rows expose only redacted metadata and a
bounded list of immutable Git blob IDs. The scanner uses a host-resolved Git
executable, strips ambient Git control variables, disables lazy fetching, and
never checks historical content into the working tree.

Configuration:

| Option                              | Meaning                                                               |
| ----------------------------------- | --------------------------------------------------------------------- |
| `copilotPath`                       | System Copilot CLI executable; otherwise `COPILOT_CLI_PATH` or `PATH` |
| `copilotOverrides.model`            | Copilot model, default `auto`                                         |
| `copilotOverrides.reasoning_effort` | `low`, `medium`, `high`, or `xhigh`                                   |
| `pluginPath`                        | Alternate Copilot Security plugin directory or ZIP                    |
| `pythonPath`                        | Python interpreter used by deterministic helpers                      |

Scan authentication accepts `"auto"`, `"github"`, or `"token"`. Output
directories must be outside the scanned repository and any enclosing Git
worktree. The scanner does not impose a credit or request allowance by default.
Usage values in scan results describe consumption, not remaining entitlement.
`maxAiCredits` opts into Copilot's native per-session AI-credit limit and
includes subagent use; Copilot CLI requires an explicit limit of at least `30`.
`maxSessionAttempts` accepts `1` through `5` and defaults to `3`; `1` disables
fresh-session recovery. Only scanner-owned model-turn deadlines and recognized
transport interruptions open a new session. Authentication, authorization,
contract, sandbox, cancellation, cost-limit, and exhausted safety-filter
failures remain terminal. A new session receives the original scan contract,
re-consumes the immutable host inventory, and treats existing artifacts as
untrusted partial drafts. Direct writes to host-owned inventory files are
denied, and the original in-scope inventory digest is verified independently
by both completion phases. Native AI-credit limits apply per fresh session;
scanner-owned cost tracking is cumulative across all attempt roots and their
subagents.
Scanner-owned state is isolated under `COPILOT_SECURITY_HOME` (default:
`~/.copilot-security`). `COPILOT_HOME` is read only as the source of existing
Copilot CLI authentication; a private copy is prepared under the scanner-owned
`copilot-security-home` runtime directory. The deprecated
`COPILOT_SECURITY_STATE_DIR` alias selects this scanner's state root only.

During a scan, Copilot sees only an expendable repository/plugin copy and an
empty staged scanner-state directory. Repository links and special files are
represented in a link manifest instead of being recreated. The trusted host
generates immutable worklists and repository-policy paths before model
execution and verifies their digests before completion. Registered-target
checks surround SHA-256 comparisons of every authoritative and staged inventory
file before model execution, preparation, and completion. Model-side Python,
Git, ripgrep, and plugin helpers are prohibited; deterministic helpers run in
the trusted host, while the model uses built-in file tools for exact worklist
paths and writes drafts only beneath the exclusive scan directory. This also
works around current Windows native-sandbox preview limitations without
treating the preview sandbox as the only security boundary.

### Runtime environment

| Variable                            | Purpose                                                                                      |
| ----------------------------------- | -------------------------------------------------------------------------------------------- |
| `COPILOT_SECURITY_HOME`             | Scanner-owned state, locks, configuration, runtime copy, and default results root            |
| `COPILOT_CLI_PATH`                  | Absolute path to the installed GitHub Copilot CLI                                            |
| `COPILOT_HOME`                      | Source location for existing Copilot CLI authentication; never used as mutable scanner state |
| `COPILOT_GITHUB_TOKEN`              | Highest-precedence noninteractive GitHub token                                               |
| `GH_TOKEN`                          | GitHub CLI-compatible token fallback                                                         |
| `GITHUB_TOKEN`                      | Generic GitHub token fallback                                                                |
| `GH_HOST`                           | GitHub Enterprise host used for repository discovery                                         |
| `PYTHON`                            | Python interpreter for deterministic contract and workbench helpers                          |
| `COPILOT_SECURITY_NO_UPDATE_NOTICE` | Disable the interactive package update notice                                                |
| `NO_COLOR`                          | Disable terminal styling                                                                     |
| `CI`                                | Select noninteractive behavior                                                               |

The default native Copilot configuration is equivalent to:

```toml
model = "auto"
model_reasoning_effort = "xhigh"

[features]
plugins = true
goals = true

[features.multi_agent_v2]
enabled = true
max_concurrent_threads_per_session = 9
```

Deep discovery computes bounded parallelism from the machine and Copilot
capacity. With 12 available processors its deterministic defaults are
`workers = 6`, `subagents = 3`, `stop_after_no_new = 6`, and
`max_discovery_runs = 60`. These are execution bounds, not substitutes for the
per-file and per-candidate closure requirements.

## Scan history and comparisons

`copilot-security scans compare BEFORE_SCAN_ID AFTER_SCAN_ID` automatically
matches findings by root cause, reuses saved matches, and reports findings as
new, persisting, reopened, resolved, or unknown. Missing findings are not
treated as resolved when the later scan is incomplete or does not cover their
original scope.

## Benchmarking scanner effectiveness

Use the read-only `benchmark` command to compare completed scan directories
with versioned ground truth:

```bash
copilot-security benchmark ./benchmarks/manifest.json \
  --results-dir /absolute/path/to/benchmark-results \
  --format json
```

The command exits `1` when a case or configured threshold fails. It matches
findings one-to-one by CWE and code location, treats duplicates as false
positives, measures repeated-run stability and negative controls, and includes
completion, validation, attack-path, evidence, and severity metrics. Use
`--no-enforce` to produce a report without enforcing the gates. Successful
campaign-bound runner receipts are required by default. The explicit
`--no-require-status` compatibility mode accepts manually imported or
cross-provider findings without claiming that their scanner process completed.
