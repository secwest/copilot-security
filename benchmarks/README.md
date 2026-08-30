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

Cases with `seedSarif` may declare `expectedSeedCoverage` totals for `total`,
`inScope`, `reportable`, `rejected`, `deferred`, and `outOfScope`. The evaluator
requires internally consistent totals, validates every reserved seed entry in
the host-generated closure receipt, requires canonical coverage to reference
it, and verifies its exact SHA-256 in the sealed scan manifest. A missing,
malformed, mismatched, duplicated, or unsealed receipt makes the run incomplete
even when its findings happen to match. `sarif-seed-manifest.json` uses this
gate to require its vulnerable seed to close as reportable and its noisy safe
seed to close as rejected.

The evaluator accepts both the current explicit `id`/`locations` expectation
shape and the committed specialized manifests' original
`title`/`path`/`line` shape. Legacy expectations receive deterministic
per-case identities, and every original metric name maps to its current
`min*` gate. A manifest may not define both names for one metric. This keeps
sealed historical campaigns evaluable without weakening malformed-manifest or
conflicting-policy rejection.

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

## Coverage-closure orchestration microbenchmark

`coverage-closure-orchestration-benchmark.json` preserves the sealed
implementation-checkpoint self-scan baseline of 491 reconciled surfaces, 17
reviewed surfaces, and 474 explicit coverage gaps. It does not claim that a
synthetic run is another observed self-scan. Instead, its deterministic
scenarios score the fresh-session scheduler at the same gap scale.

The completion scenario must reduce 474 gaps to zero within three of five
available sessions, invoke broad discovery exactly once, use targeted closure
prompts thereafter, improve the closure rate by at least 0.96, and reach a 1.0
final closure rate. Its paired exhaustion control keeps all 474 gaps through
three sessions and must terminate with `ScanClosureIncompleteError`; it may not
convert the zero-finding draft into complete coverage. The regression combines
these scenarios with host file-view tracking tests that preserve successful
views and discard unfinished tool calls across session boundaries.

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

## Unicode source-display-control benchmark

`source-bidi-authorization-manifest.json` isolates source-review spoofing from
ordinary right-to-left language content. The positive fixture contains exact
RLO and isolate controls in a JavaScript comment and logically grants deletion
to a non-admin who does not own the document. Its runtime witness proves that
authorization result. The negative control contains Arabic and Hebrew prose,
uses no explicit direction controls, and enforces the intended admin-or-owner
policy.

The focused manifest requires perfect three-run precision, recall, stability,
location and severity accuracy, substantive validation and attack path, and
grounded code evidence. Deterministic regression separately checks exact
code-point metadata, base64 prompt isolation, pairing semantics, bounded
control-flood behavior, and ordinary-prose silence. Run it with:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/source-bidi-authorization-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-source-bidi
```

## Terraform public administration ingress benchmark

`terraform-aws-public-admin-ingress-manifest.json` isolates literal AWS
security-group authorization from deployment and host exploitability. The
positive fixture admits `0.0.0.0/0` to TCP port 22; the topology-identical
control changes only the source to `10.0.0.0/8`. The focused gate requires
perfect three-run precision, recall, stability, location, severity, validation,
attack-path, and code-evidence scores. Validation must distinguish the source
declaration from rendered-plan selection, apply state, security-group
attachment, network reachability, a listening service, authentication, and
concrete impact.

Deterministic regression separately covers inline, legacy, and current AWS
provider resource shapes, IPv4 and IPv6 public sources, literal port ranges,
provider-specific all-protocol syntax, malformed and computed controls,
comments, heredocs, and parser resource bounds. Run the focused model benchmark
with:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/terraform-aws-public-admin-ingress-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-terraform-admin-ingress
```

## PHP PDO and MySQLi SQL-injection benchmark

`php-pdo-sql-injection-manifest.json` adds the canonical corpus's first PHP
pair. Both fixtures retain the same HTTP source, typed PDO receiver, query
preparation, execution, and returned-row path. The positive interpolates the
request value before `prepare`; the control uses a fixed placeholder and passes
the value only through `execute` parameter data. The focused perfect gate
requires the report to distinguish tainted SQL grammar from parameter data and
to validate route deployment, receiver identity, driver behavior, database
privileges, affected rows, returned data, and concrete impact.

Deterministic regression also covers direct PDO execution, object and
procedural MySQLi, `filter_input`, concatenation, interpolation, formatting,
heredoc, typed receiver and scope identity, inert preparation, reassignment,
fixed scalar and literal selection, manual escaping evidence, malformed input,
and bounded hostile nesting/token volume. Run it with:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/php-pdo-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-php-sql
```

## Ruby on Rails command-injection benchmark

`ruby-rails-command-injection-manifest.json` adds the canonical corpus's first
Ruby pair. Both fixtures retain the same Rails parameter source, Open3 process
API, captured output, status handling, and rendered response. The positive
interpolates the request value into Open3's one-string command form; the control
uses a fixed executable and format with the request value only as a separate
argument. Their native witnesses use an environment marker to demonstrate
shell expansion without filesystem, network, credential, persistence, or
privilege effects.

Deterministic regression additionally covers Kernel, Process, IO, and Open3
call shapes; POSIX, CMD, and PowerShell command-string flags; backticks and
`%x`; Rails parameter variants; assignment and interpolation flow; fixed argv,
numeric conversion, method shadowing, reassignment, test/non-controller
exclusion, Shellwords control evidence, CRLF provenance, and lexer resource
bounds. Run the focused model benchmark with:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/ruby-rails-command-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-ruby-command
```

## Kotlin Ktor delegated-command benchmark

`kotlin-ktor-command-injection-manifest.json` now holds eighteen strict cases.
Alongside direct shell, mutable command-list, inline pipeline, builder-factory,
command-helper, and `ProcessBuilder` delegation boundaries, its newest pair
preserves a typed Ktor Resource, `Runtime.getRuntime().exec(arrayOf("env",
"--", ...))`, process execution, captured output, and HTTP response. In the
positive, the Resource value occupies `env`'s delegated executable position.
The control fixes `printf` in that position and passes the same value later as
one ordinary argument.

The deterministic model follows recognized `env` options, option arguments,
`NAME=VALUE` assignments, and `--`; recursively classifies the first remaining
operand as an executable; carries nested shell/interpreter semantics through
that boundary; and distinguishes tainted `-S`/`--split-string` command text.
Regression also rejects assignment-only calls, tainted `--unset` operands,
fixed delegated executables, unknown failing options, and fixed split commands
whose later values remain argv. Both native witnesses substitute only fixed,
harmless `printf` values, start one short-lived process, and perform no network
or file I/O. Runtime-specific regression additionally distinguishes the
tokenized `exec(String)` overload from explicit array elements, tracks exact
retained runtime instances and mutable arrays, and rejects local/imported
lookalikes and unsupported `List` call shapes. Run the strict benchmark with:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/kotlin-ktor-command-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-kotlin-command
```

## Rust Axum and Actix Web command-injection benchmark

`rust-axum-command-injection-manifest.json` adds the canonical corpus's first
Rust pair. Both fixtures retain the Axum query extractor,
`std::process::Command` builder, captured output, and returned response. The
positive formats request data into the command-string position after `sh -c`;
the control selects a fixed executable and passes the same data only as a
literal argument. Their standard-library witnesses expand a fixed inert
environment marker only in the shell case and perform no filesystem, network,
credential, persistence, or privilege operation.

Deterministic regression additionally covers Axum Query, Path, Form, and Json
extractors; Actix Web extractors; direct, grouped, module, fully qualified, and
aliased imports; tuple bindings; local assignments and `format!`; chained and
mutable process builders; `arg` and `args`; POSIX, CMD, PowerShell, interpreter,
Windows batch, `raw_arg`, and executable-selection boundaries; fixed argv,
numeric normalization, reassignment, inert construction, local lookalikes,
escape/control evidence, LF/CRLF provenance, malformed source, and lexer
resource bounds.

`rust-tokio-command-injection-manifest.json` adds a second strict pair for the
official Tokio process builder. Both fixtures pin Tokio 1.53.1 with Cargo lock
format v3, retain the same Axum source, `output().await`, captured stdout, and
response topology, and differ only at the command/data boundary. The positive
formats the request value into `sh -c`; the control gives it to fixed `printf`
as one literal argument. The witnesses use a current-thread Tokio runtime and
expand only a fixed inert environment marker. Regression covers direct,
aliased, grouped, nested-grouped, module, and fully qualified Tokio identities,
assigned and fluent builders, local-module and foreign-crate shadows, inert
construction, unavailable Tokio `exec`, and the current fact that `status()`
and `output()` spawn before returning their Future. Run the focused model
benchmarks with:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/rust-axum-command-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-rust-command

node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/rust-tokio-command-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-rust-tokio-command
```

Run the Tokio witnesses on Linux or WSL with:

```bash
RUST_COMMAND_MARKER=rust-tokio-expanded cargo run --quiet --locked \
  --manifest-path ../../benchmarks/fixtures/rust-axum-tokio-shell-command-injection/Cargo.toml \
  --example witness
RUST_COMMAND_MARKER=rust-tokio-expanded cargo run --quiet --locked \
  --manifest-path ../../benchmarks/fixtures/rust-axum-tokio-argv-command/Cargo.toml \
  --example witness
```

## Spring Java command-state benchmark

`spring-java-command-injection-manifest.json` replaces constructor-proximity
reasoning with an exact Spring-handler process boundary. Its positive preserves
the currently missed fluent shape reported by Semgrep: an unassigned builder,
an intervening fluent call, a later `command("/bin/bash", "-l", "-c", target)`
replacement, and `start()`. The topology-matched control fixes `printf` and
keeps the request value in one ordinary argv element. Both Java 21 witnesses
start one bounded process and perform no file, network, credential,
persistence, or privilege operation. A second pair starts from an initially
benign retained builder, obtains and aliases the actual list returned by
`ProcessBuilder.command()`, and rebuilds the effective command with `clear`
plus `add`. Its positive installs `sh -c`; its matched control preserves the
same live-list mutations but installs fixed `printf` argv. A third matched pair
starts from a caller-owned `ArrayList`, passes its exact identity through the
documented no-copy `ProcessBuilder(List)` boundary, and mutates a retained
caller alias after binding. The positive rebuilds `sh -c`; the control rebuilds
ordinary `printf` argv. Regression distinguishes resizable `ArrayList`,
fixed-size `Arrays.asList`, and unmodifiable `List.of` operations. A fourth
pair retains an exact mutable `LinkedList` through `ProcessBuilder(List)` and
uses `Collections.addAll` for the command transition. The positive supplies
`sh`, `-c`, and the request value; the control supplies `printf`, `%s`, and the
same value. Regression also covers import lookalikes, empty-varargs no-ops,
and Java 21 sequenced-list end mutations. A fifth pair starts with an
already-sized caller-owned `ArrayList` retained by the builder and replaces its
three-element prefix through `Collections.copy`; the control performs the same
copy but installs ordinary `printf` argv. Regression also distinguishes exact
prefix copying and full-list `Collections.fill` from size-changing mutations,
including too-small, fixed-size, unmodifiable, empty, and lookalike cases. Run
the strict benchmark with:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/spring-java-command-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-spring-java-command
```

## Spring R2DBC SQL-injection benchmark

`java-r2dbc-sql-injection-manifest.json` applies perfect three-run gates to a
real Spring 7.0.8 `DatabaseClient` pair. Both fixtures carry the same annotated
username through a typed controller-to-query wrapper and consume the same
`fetch().one()` Publisher against an in-memory H2 R2DBC database. The positive
interpolates the value into SQL grammar and proves an unauthorized
administrator-row read; the control changes only the boundary to fixed SQL and
`bind`, where the identical hostile value returns no row.

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/java-r2dbc-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-java-r2dbc `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-r2dbc-databaseclient-sql-injection/pom.xml verify
wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-r2dbc-databaseclient-bound-parameter/pom.xml verify
```

## Java R2DBC SPI SQL-injection benchmark

`java-r2dbc-spi-sql-injection-manifest.json` applies the same perfect
three-run gates to the lower-level official R2DBC SPI. The positive carries an
annotated username through a typed controller-to-query wrapper, interpolates
it into the sole `Connection.createStatement(String)` SQL-grammar argument,
and returns `Statement.execute()` for reactive consumption. Its private H2
witness proves the predicate change reads the seeded administrator row. The
matched control keeps SQL fixed and supplies the identical hostile bytes only
through `Statement.bind`, producing no row.

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/java-r2dbc-spi-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-java-r2dbc-spi `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-r2dbc-spi-statement-sql-injection/pom.xml verify
wsl.exe -d Ubuntu -- mvn --batch-mode --no-transfer-progress --file /mnt/c/Users/dr/Documents/copilot-security/benchmarks/fixtures/java-r2dbc-spi-statement-bound-parameter/pom.xml verify
```

## Python asyncpg SQL-injection benchmark

`python-asyncpg-sql-injection-manifest.json` applies perfect three-run gates to
an official asyncpg/FastAPI wrapper path. The positive carries a FastAPI query
parameter through `accounts.lookup`, copies the constructed SQL, and awaits
`Connection.fetch(query_copy)`. Its topology-matched control keeps fixed `$1`
SQL and supplies the identical hostile bytes only as the later bound value.
Both identical recording witnesses are deliberately socket-free: they prove
the query-grammar versus protocol-value boundary, not PostgreSQL impact.

The same strict manifest also contains a source-retention pair. Both fixtures
carry Python 3.12 PEP 695 syntax, a variation selector, `%s`, a zero-width
joiner, a combining mark, and a soft hyphen. The positive must retain the exact
SQL-grammar edge at `src/accounts.py:11`; the otherwise identical `$1` control
must remain negative. This catches both silent source loss and false positives
caused merely by unusual valid source text.

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/python-asyncpg-sql-injection-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-python-asyncpg `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

python ../../benchmarks/fixtures/python-asyncpg-sql-injection/examples/witness.py
python ../../benchmarks/fixtures/python-asyncpg-bound-parameter/examples/witness.py
python ../../benchmarks/fixtures/python-asyncpg-unicode-source-sql-injection/examples/witness.py
python ../../benchmarks/fixtures/python-asyncpg-unicode-source-bound-parameter/examples/witness.py
```

## Node MCP tool-handler security benchmark

`node-mcp-tool-security-manifest.json` measures tool input across nineteen
distinct modeled boundaries and nineteen matched pairs under perfect selected-run
gates. The command pair uses
the real stable `@modelcontextprotocol/server` 2.0.0 API: the exploit carries a
tool field through an arrow helper into `child_process.exec`, while its
topology-matched control uses a fixed `process.execPath` and an explicit `--`.
The argument pair keeps that fixed Node runtime on both sides: the exploit puts
tool data in the runtime option region, while the control places the same data
after `--`. A second argument pair preserves `process.execPath` through one
stable module-scope alias; the exploit keeps tool data in Node's option region,
while its topology-matched control retains the alias and places every untrusted
argument after `--`. Reassignment, shadows, alias chains, and ambiguous nested
aliases remain negative model cases. A third argument pair obtains the runtime
from an exact official `node:process` binding and preserves it through one
stable alias; the exploit omits `--`, while the control places all tool values
after it. ESM default, namespace, and named `execPath` (including combined ESM
declarations), CommonJS namespace and destructured `execPath`, and TypeScript
import-equals forms are covered;
unprefixed package lookalikes, mutation, computed access, chains, and ambiguous
nested aliases remain negative cases. An additional argument pair fixes the
forked module while placing tool input in `child_process.fork`'s exact
object-literal `execArgv` array. Its matched control keeps `execArgv` fixed and
passes the identical option-looking value only as an ordinary module argument.
The detector rejects dynamic or aliased options, spreads, computed or duplicate
`execArgv` properties, replaced fork bindings, and unsupported overloads rather
than inventing provenance. Two further fork pairs separately model argument
zero as the executable child module and exact object-literal `options.execPath`
as the child executable. Their controls fix or allowlist the module and pin the
executable to `process.execPath`, preserving the identical module- or
executable-looking value only as ordinary child data. The module row reports
CWE-829 without overclaiming attacker code placement; the executable row
reports CWE-78 without confusing program selection with argument injection.
Two execution-context pairs then cover indirect redirection. One preserves a
fixed relative child entry point while tool input selects `options.cwd`; its
file-URL control includes a same-named alternate child but proves the fixed
module still runs. The other places tool input in exact
`options.env.NODE_OPTIONS` under the default Node runtime; its control passes
the same option-looking text through a non-special environment key. The model
accepts a preceding `process.env` spread whose value is overwritten by the
explicit final `NODE_OPTIONS`, but rejects following spreads, computed or
duplicate relevant properties, dynamic options, and unknown custom runtimes.
Another pair applies that same exact runtime-environment boundary to non-shell
`spawn`, `spawnSync`, `execFile`, and `execFileSync` calls whose executable is
proved to be Node. Its control keeps `NODE_OPTIONS` fixed and preserves the
same option-looking value only as ordinary environment data. The executable-
search pair instead holds a bare command literal fixed while tool input reaches
exact `options.env.PATH`, reporting CWE-426 only for command lookup. Its control
pins PATH to the current Node executable directory and uses the tool value only
as a non-special environment field. Shell-enabled calls, path-qualified
executables, options aliases, unsupported overloads, and ambiguous properties
remain negative.
The code-evaluation pair carries an expression through a same-file
helper into direct JavaScript `eval`; its control preserves expression input,
the helper, arithmetic results, and the MCP response while an explicit numeric
`+`/`*` grammar never evaluates the tool string as source. A second
code-evaluation pair closes the compile/execute lifecycle: the exploit compiles
tool input with `Function` and invokes the retained result, while the stronger
control retains a compiled-Function invocation but parses tool input into
numeric and allowlisted-operator data for fixed source. The Worker pair requires
tool-derived JavaScript to reach `new Worker(..., { eval: true })` and actual
worker startup; its control keeps the evaluated Worker lifecycle but passes
only structured-cloned numeric/operator data to fixed server-owned source. One
SQLite pair sends tool-derived grammar to `DatabaseSync.exec`; its control uses
fixed SQL and a `StatementSync` bound parameter. A second SQLite pair requires
tool-derived grammar in `DatabaseSync.prepare` and subsequent execution of that
exact returned statement through `get`; its control preserves both lifecycle
steps but binds the same value outside SQL grammar. The regular-expression
pair compiles a tool pattern through a same-file helper and executes it with
`test` against a separately bounded tool-supplied match subject; its control
preserves both schemas, helper, subject, and response while a fixed-pattern map
selects only operator-owned regular-expression literals. The SSRF pair carries
a tool URL through a helper into global `fetch`; its control fixes a disposable
loopback origin before loading the server and places tool data only in the
request body. The path pair passes a tool-selected name through a same-file
helper to the path argument of
`node:fs/promises.writeFile`; its control uses the same API and helper topology
but fixes the file URL and confines both tool values to file contents.

Each fixture pins exact dependencies and supplies a bounded witness. The
process witnesses emit only inert fixed text or Node's version string. The
code-evaluation witnesses use fixed side-effect-free arithmetic and object
values. The regular-expression witnesses use only short fixed anchors,
alternation, and invalid syntax; they never execute catastrophic-backtracking or
load-generating patterns. The network witnesses use a
random-port loopback listener, close it in all paths, and never contact an
external or metadata address. The filesystem witnesses create and remove only
fresh temporary trees containing synthetic marker data. Both SQLite pairs use
only in-memory databases and fixed inert rows. The fork pairs use only the
inert `--stack-trace-limit=77` runtime option and private IPC; it never loads an
external module or enables an inspector. The execution-context witnesses add
only checked-in inert child modules and one checked-in preload that sets an
in-memory marker. The new process witnesses either load that same inert preload
or prove PATH participation through a bounded `ENOENT`; no attacker executable
is created or run. Node CI executes all thirty-eight witnesses on Windows and
Linux. Run the focused scanner benchmark with:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/node-mcp-tool-security-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-node-mcp-tools
```

The versioned corpus currently contains 175 vulnerable/control pairs:
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
server-side request forgery, unsafe deserialization including a
standard-library `pickle.loads`/JSON relative-wrapper pair and a separate
`pickle.Unpickler(file).load()`/JSON request-stream pair with a bounded
fixture-local `__reduce__` callable witness, a NumPy object-array
`allow_pickle=True`/`False` upload pair, a pickle-backed `joblib.load`/JSON
model-upload pair, and a version-sensitive PyTorch full-unpickler/patched
weights-only checkpoint pair, a source-identical lxml 6.0.2/6.1.1
`iterparse` external-entity pair, a second source-identical pair that supplies
an affected-default `ETCompatXMLParser` to `fromstring`, plus a PyYAML
`UnsafeLoader`/`safe_load`, and a Python 3.12 standard-library tarfile pair
that contrasts the pre-3.14 fully trusted default with `filter="data"` plus
bounded member/type/name/expanded-byte preflight, plus a Hydra
1.3.3/1.3.4 untrusted-configuration pair that distinguishes attacker-selected
`_target_` invocation from fixed application-owned target configuration, a
SymPy default-namespace/restricted-namespace pair, and a
`python-statemachine` 3.1.2/3.2.0 pair that requires the same processor to
parse remote SCXML and then start while distinguishing the repaired restricted
default from explicit `trusted=True`,
relative-wrapper pair, reflected XSS, XML
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
signed-object-to-session binding as the control, prototype pollution including
an HTTP value crossing three module boundaries into two nested computed object
keys, paired with nested `Map` storage as the prototype-safe control,
setter-triggering shallow `Object.assign()` from an HTTP object, paired with an
exact null-prototype target, disabled
TLS certificate verification,
predictable security tokens, server-side template injection including typed Go
`text/template` source-to-execution closure with registered-function capability
proof and fixed escaped execution-data control, check/use state
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
destination-pinned, redirect-free transport, IPv6-transition SSRF where an
IPv4-only private-address guard accepts IPv4-mapped IPv6, NAT64, and 6to4
encodings with complete transition canonicalization as the control, plus GitHub Copilot SDK
trusted-instruction injection where request data crosses two relative-module
wrappers into `systemMessage.content`, paired with the same data sent only as
an ordinary `sendAndWait` prompt, plus an unannotated Razor Page handler
parameter that crosses a typed service boundary into SQL grammar, paired with
the same handler topology and a typed `SqlParameter`, plus Mongoose document
selector injection where an object-valued Express field crosses three module
boundaries into a Model query filter, paired with an exact `$eq` literal-value
boundary, plus Mongoose update-document injection where an Express patch
crosses the same topology and selects `$unset` to remove an MFA secret, paired
with one scalar beneath a fixed server-owned `$set` field, plus Mongoose
`bulkWrite()` update-operator injection and replacement-document mass
assignment across the same topology, each paired with its exact fixed update
or document boundary, plus Mongoose aggregation-pipeline injection that uses
`$lookup` to cross a collection boundary or `$merge` to overwrite protected
account state, paired with fixed `$match`, projection, mutation, and write
destinations, plus later `Aggregate.append()` mutation that exposes a signing
key through attacker-selected `$lookup` and projection stages, paired with an
exact `$eq` match value and fixed public projection, plus a request object
crossing three wrappers into a recursively traversed Lodash merge source
under an exact vulnerable runtime pin, paired with the same call and a
patched pin, plus the same topology under an ordinary semver range whose
fresh npm lockfile resolves either vulnerable or patched Lodash, plus a
separately versioned standalone `lodash.merge` callable pinned to vulnerable
4.6.1 and paired with its patched 4.6.2 boundary. The standalone package must
carry its own manifest or lockfile proof; a declaration for core `lodash`
cannot authorize it, or vice versa. A further package-isolated pair covers the
direct `merge-deep` callable at vulnerable 3.0.2 and its patched 3.0.3
boundary. A fourth package-isolated pair covers only literal recursive
`extend(true, target, ...sources)` calls at vulnerable 3.0.1 and its patched
3.0.2 boundary; omitted, false, or dynamic deep flags remain negative. A
fifth package-isolated pair covers the always-recursive direct `deep-extend`
callable at vulnerable 0.5.0 and its patched 0.5.1 property-read boundary. No
declaration for one merge family can authorize another. A sixth pair covers
literal-recursive `just-extend` 4.0.0 and its 4.0.1 own-destination-property
boundary; this deliberately follows the upstream repair and CodeQL rather
than the reviewed advisory's stale claim that 4.0.0 was already patched.
A seventh package-isolated pair covers always-recursive `merge-options` 1.0.0
and its patched 1.0.1 boundary. Every argument is a source because this API
returns a new merged object rather than mutating argument zero. An eighth pair
covers literal-recursive `node.extend` at the disjoint vulnerable 2.0.0 release
and patched 2.0.1 boundary; the model also covers releases below 1.1.7 while
keeping the intervening and later safe versions negative. A ninth pair covers
always-recursive `assign-deep` 0.4.7 and its completed 0.4.8 repair. This pair
deliberately exceeds CodeQL's older below-0.4.7 model: the later reviewed
advisory also covers 0.4.7 and exactly 1.0.0 because blocking only `__proto__`
left `constructor.prototype` traversal reachable. The newest pair carries a
remote brace pattern through three wrappers into `brace-expansion` 5.0.8 and
pairs it with source-identical 5.0.9, measuring whether result and character
bounds apply while padded sequences and comma alternatives are constructed.
The next pair exercises persistent `socket.io-parser` state through its direct
Decoder API. The latest pair reaches the same state through the public
`socket.io` Server: application source and `socket.io@4.8.3` stay identical,
while declaration-consistent npm locks select parser 4.2.6 or 4.2.7. The newest
pair carries a remote negative size through three wrappers into
`nanoid/non-secure` 5.1.15 and pairs it with source-identical 5.1.16. The lxml
pair then proves that eagerly consumed `iterparse` under one exact 6.0.2 pin
retains local external-entity access while source-identical 6.1.1 rejects the
same fixture-local `SYSTEM` entity. Its ET-compatible companion proves the
separate constructor default and requires that the exact constructed parser
actually reach the parse call; ordinary `XMLParser` and construction alone
remain negative. The tarfile pair adds exact uploaded-`fileobj` flow, retained
`TarFile` receiver identity, runtime-default semantics, and a matched control
that closes both traversal and decompression-exhaustion paths. The Next.js
dynamic-route pair then holds a concrete middleware denial, Pages Router SSR
lookup, and standalone deployment harness constant while changing only
15.5.15 to 15.5.16. Its real-package differential preserves ordinary-request
counterevidence and proves the wrapped route-module `nxtPslug` normalization
boundary changed by the repair. The Plate media pair then keeps the serialized
document path, component registration, parser/gate, and iframe sink identical
while changing only `@platejs/media` 53.0.1 to 53.1.4. On both Windows and
native Ubuntu, the affected real hook retains the inert `javascript:` URL and
the repaired hook returns no embed. The Defuddle pair then preserves remote
HTML, an official relative wrapper, and the HTML render boundary while changing
only 0.19.0 to 0.19.1. Its network-disabled witness reparses one synthetic X
article and observes one inert event-handler attribute only on the affected
release. The Pickem pair then maps fetched release text into exact picker display
fields and changes only `pickem` 1.0.6 to 1.0.7. Its public-formatter witness is
noninteractive and never prints raw terminal control bytes: the affected package
retains OSC, BEL, DEL, C1, and an inert clipboard marker, while the repaired
package removes them and preserves the selected value. The LogTape pair keeps
the formatted application, exported request handler, connected category/sink
topology, loopback UDP witness, and `@logtape/logtape` 2.1.5 core identical
while changing only `@logtape/syslog` 2.1.4 to 2.1.5. It never prints raw
control-bearing data: the affected datagram retains the injected newline, while
the repaired datagram contains `#010` and no newline. The Nx self-hosted-cache
pair then preserves its operational CI configuration, task, workspace, and
loopback-only gzip-tar witness while changing only Nx 22.7.6 to 22.7.7. The
affected release writes an inert sentinel outside its per-hash cache directory
but inside the disposable root; the repaired release does not. Three runs per
case are also applied to the Undici SOCKS5 pair, which keeps a remote first
origin, later credentialed origin, shared agent, and bounded loopback witness
constant while changing only 7.27.2 to 7.28.0. The affected build routes both
requests to the first origin; the repaired build creates one pool per origin.
The Echo pair then preserves an operational middleware-protected wildcard
route, root static handler, and inert `httptest` marker while changing only
Echo 4.15.2 to 4.15.3. A direct request is denied on both builds; the encoded
separator discloses the marker only on the affected build, while the repair
returns 404. The Traefik pair preserves the file provider, public rewrite,
authenticated sibling, shared backend, and loopback witness while changing
only 3.7.6 to 3.7.7. A direct protected request is denied on both builds; only
the affected build forwards `/api../admin` onto the backend-normalized marker.
The complete corpus now produces 840 scans across 140 exploit/control pairs.
The added
industrial-protocol pair starts the same official
`OPCUAServer` surface on both sides: 2.165.0 retains every unique nonempty
client nonce in a process-global object, while 2.168.0 enforces TTL and size
eviction. A second node-opcua pair exercises encrypted username-token
authentication with an explicit application user manager: 2.165.2 accepts a
token replay across distinct session nonces, while 2.166.0 verifies the token's
trailing nonce before calling the manager.
The newest application-authentication pair keeps Auth.js source identical and
changes only `next-auth` 5.0.0-beta.31 to 5.0.0-beta.32. Under a real provider
configuration error, beta.31 exposes the JSON error body as a truthy
`request.auth` value and a bare existence gate permits the request; beta.32
maps the non-successful session response to `null` and the same gate denies it.

`node-logtape-syslog-injection-manifest.json` isolates
[GHSA-8h6h-x5pq-56fq / CVE-2026-54511](https://github.com/dahlia/logtape/security/advisories/GHSA-8h6h-x5pq-56fq)
under perfect three-run gates. The positive requires exact production
provenance, official stable bindings, explicitly enabled structured data, a
connected sink and matching logger category, a remote record property,
CWE-93/CWE-117, high severity, substantive evidence, and exact line-23
location. The source-identical 2.1.5 control must remain empty. Its witness uses
one inert marker and one disposable loopback UDP receiver, prints only byte
indexes and booleans, and proves decimal C0 escaping at the real package
boundary.

`node-contentful-mcp-management-token-host-redirect-manifest.json` isolates
[GHSA-2xhg-73j7-rrgx / CVE-2026-53957](https://github.com/contentful/contentful-mcp-server/security/advisories/GHSA-2xhg-73j7-rrgx)
under perfect gates. The positive requires an operational root-package launch,
exact affected production provenance, CWE-918/CWE-441, validation, attack-path
analysis, code evidence, high severity, and exact line-1 location. The
source-identical control changes only `@contentful/mcp-server` 1.7.15 to 1.7.19
and must remain empty. The non-network witness loads the real installed job-tool
shapes with a fake token: affected tools 0.4.1 admit `host`, `proxy`,
`rawProxy`, `headers`, and `config` for both export and import, while repaired
0.4.5 admits none. The stronger witness uses two random loopback TLS endpoints
and child-process-only trust. Affected code routes the fake Bearer token only to
the argument-controlled endpoint; repaired code routes it only to the
operator-configured endpoint. It never contacts Contentful or uses a real token
or space, and removes its certificate, key, trust state, export directory, and
generated error log.

`python-asyncssh-scp-download-path-traversal-manifest.json` isolates
[GHSA-2wxc-x7rj-hg8f / CVE-2026-54591](https://github.com/ronf/asyncssh/security/advisories/GHSA-2wxc-x7rj-hg8f)
under perfect gates. The positive requires a live official `asyncssh.scp`
binding, a remote source tuple or host-path source, a proven local destination,
an exact affected production pin, CWE-22, validation, attack-path analysis,
code evidence, high severity, and the exact call location. The source-identical
control changes only AsyncSSH 2.23.0 to 2.23.1 and must remain empty. Its
real-package witness starts an in-process SSH server on a random loopback port,
sends one inert marker through a `C ../escaped-marker.txt` response, and keeps
both the requested child and escaped file inside one automatically removed
temporary root. Version 2.23.0 writes outside the requested child; 2.23.1
raises `Invalid filename` and creates no escaped file. The witness never uses a
home, startup, SSH configuration, authorization, executable, credential, or
persistent path. The benchmark records the repair's residual limitation as
well: SCP can still overwrite server-selected names inside the destination, so
SFTP remains the preferred protocol.

`python-chainlit-mcp-stdio-command-injection-manifest.json` isolates
[GHSA-w3fx-mc44-mf6j / CVE-2026-45018](https://github.com/advisories/GHSA-w3fx-mc44-mf6j)
under perfect gates. The positive requires a non-shadowed top-level official
Chainlit application import, an exact stable 2.4.0–2.11.1 production pin,
parsed MCP-enabled `.chainlit/config.toml`, legacy stdio capability, CWE-78,
validation, attack-path analysis, code evidence, critical severity, and exact
line-1 location. The source-identical control changes only Chainlit 2.11.1 to
2.12.0 and must remain empty. Fourteen evidence groups are required separately
in validation and attack path, covering the advisory, application,
configuration, executable policy, affected pin, client request, validator,
spawn chain, reachability uncertainty, non-executing witness, repaired release,
residual process risk, and taxonomy. Its Ubuntu Python 3.12.3 witness calls only
the affected pure validator with fixed inert text and records parsed argv with
`executed:false`; no returned value reaches a process API. The repaired package
has no validator and rejects legacy `stdio`/`fullCommand` request fields with
`ValidationError`. Both isolated package trees are removed after the
differential.

`go-echo-static-encoded-separator-manifest.json` isolates the application-level
[GHSA-vfp3-v2gw-7wfq / CVE-2026-55677](https://github.com/labstack/echo/security/advisories/GHSA-vfp3-v2gw-7wfq)
topology under perfect gates. The positive must retain the official Echo
instance, middleware-protected non-root group, wildcard GET route, root
`Static`/`StaticFS` handler, operational server start, exact affected `go.mod`
proof, CWE-22, validation, attack-path analysis, code evidence, high severity,
and exact line-24 location. The source-identical control changes only 4.15.2 to
4.15.3 and must remain empty. Its real-package witness uses no listener or real
secret: `httptest` requests an inert marker inside a test-owned temporary root,
proves the direct route is denied on both builds, and distinguishes affected
200 disclosure from repaired 404 rejection.

`traefik-replacepathregex-manifest.json` isolates the
[GHSA-cxjq-mrr5-89rv](https://github.com/traefik/traefik/security/advisories/GHSA-cxjq-mrr5-89rv)
route boundary under perfect three-run gates. The positive must retain the
exact official affected image, file-provider mount, public separator-free
rewrite, authenticated sibling, shared service and entry point, CWE-22,
validation, attack-path analysis, code evidence, high severity, and an exact
sink location. Three source-identical exploit/control pairs cover a mounted
YAML filename at `dynamic.yml:15`, operational Docker labels at
`compose.yml:29`, and a mounted directory that merges TOML routers, YAML
middlewares, and a TOML service at `dynamic/middlewares.yml:4`. Each control
changes only 3.7.6 to 3.7.7 and must remain empty. The binary witnesses bind
Traefik and the inert backend only to ephemeral loopback ports, prove the
direct route is denied, and distinguish vulnerable marker forwarding from
repaired rejection without a real credential or external service. The Docker
label witness uses an isolated Compose project and cleans all project
resources.

`node-mongoose-nosql-manifest.json` isolates the Mongoose selector boundary
under perfect single-run gates. The positive must retain the HTTP source, all
nine ordered import/call/parameter propagators, the exact filter position,
CWE-943, validation, attack-path analysis, and code evidence. The paired
control keeps the same four-file topology and query operation but wraps the
request value in `$eq`. Deterministic regressions resolve official default,
namespace, named-model, and CommonJS bindings; distinguish filters from update
and options data; require query consumption; retain exact
`mongoose.sanitizeFilter`; and reject Model, factory, and sanitizer lookalikes,
reassignment, malformed receiver factories, and inert synchronous returns.
The executable witness evaluates representative MongoDB operator semantics:
the vulnerable selector selects the administrator record, while the control
rejects the operator object and retains literal lookup.

`node-mongoose-update-manifest.json` isolates the Mongoose update-document
boundary under the same perfect gates. The positive retains the HTTP source,
all nine ordered import/call/parameter propagators, exact update position,
CWE-943 and CWE-915 review choices, validation, attack-path analysis, and code
evidence. Its control preserves the four-file topology but maps only
`displayName` beneath a fixed `$set` field. Deterministic regressions distinguish
update data from filters and options, require exact Model identity and query
consumption, and reject replacements, one-argument calls, Model lookalikes,
computed fields, spreads, complete objects beneath `$set`, and validators as a
universal control. The executable witnesses prove MFA-secret deletion in the
operator path and MFA preservation plus legitimate display-name change in the
fixed-field path.

`node-mongoose-bulk-write-manifest.json` isolates the complete documented
Mongoose bulk operation-array grammar under perfect gates. Its two positives
retain the HTTP source, all nine ordered propagators, the exact `bulkWrite()`
call, both CWE review choices, validation, attack-path analysis, and code
evidence. One proves nested `updateOne.update` operator control; the other
proves `replaceOne.replacement` mass assignment. Their controls preserve the
topology but use one scalar beneath a fixed server-owned `$set` field or a
fixed literal replacement projection. Deterministic regressions separately
trace insert documents; update, delete, and replacement filters; update
documents; replacement documents; whole operation arrays; dynamic elements;
and operation or specification spreads. They reject bulk options,
`arrayFilters`, fixed-only calls, Model lookalikes, and reassignment. The four
executable witnesses prove MFA deletion and role/MFA replacement on the
vulnerable paths, and protected-field preservation plus legitimate
display-name changes on the controls.

`node-mongoose-aggregate-manifest.json` isolates Mongoose aggregation read and
write grammar under perfect gates. Its three positives retain the HTTP source,
all nine ordered propagators, the exact lazy `Model.aggregate()` execution,
validation, attack-path analysis, and code evidence. One supplies a complete
pipeline whose `$lookup` and projection expose a signing-key collection; the
other supplies attacker-selected stages before a fixed `$merge`, using `$set`
to replace role and MFA state; the third appends attacker-selected `$lookup`
and projection stages to an assigned Aggregate before later execution.
Their controls preserve the four-file topology while binding one scalar through
a fixed `$match` field and exact `$eq`; the read control fixes the public
projection, and the write control also fixes the mutation, destination,
identity key, and merge policy. Deterministic regressions distinguish complete
pipelines, dynamic or spread stages, filters, cross-collection reads, input
before a fixed write, write stages, appended stages, and append-before-write
ordering; require exact official Model and Aggregate receiver identity plus
consumption of the lazy Aggregate; reject options-only, inert, lookalike,
reassigned, inspection-only, append-after-execution, and different-receiver
execution cases; and credit only direct or exact-`$eq` fixed-match values. Six
executable witnesses prove secret disclosure and protected-state replacement
on the vulnerable paths, and operator rejection, public projection,
protected-state retention, and fixed destination on the controls.

`node-prototype-pollution-manifest.json` isolates remote nested-key prototype
pollution under perfect gates. The positive retains the Express body source,
all nine ordered import/call/parameter propagators across three relative-module
boundaries, the exact two-key assignment at `src/storage.js:4`, CWE-1321,
validation, attack-path analysis, and code evidence. Its matched control keeps
the same route and relay topology but represents both attacker-selected keys
with nested `Map` instances. Deterministic regressions require source flow into
two dynamic key positions and reject request data used only as the assigned
value, one-level writes, a fixed first key, comparisons, compound assignments,
`Map.get`/`Map.set`, and code-shaped strings. They also prove that an unrelated
assignment earlier on the same line cannot hide a later exact sink. The
executable witnesses demonstrate inherited `Object.prototype` authorization
state on the vulnerable path and ordinary retained `__proto__` data with no
prototype mutation on the control.

`node-object-assign-prototype-manifest.json` isolates shallow built-in copy
semantics under perfect gates. The positive retains the Express body source,
all nine ordered propagators, and only the source-argument position of exact
`Object.assign()` at `src/storage.js:4`; an own JSON `__proto__` property
replaces the ordinary options target's prototype and supplies an inherited
authorization flag. Its control keeps the same topology and call but uses an
exact `Object.create(null)` target, so the key remains own data and is retained
as `null-prototype-assignment-target` counterevidence. Deterministic regressions
accept direct, aliased, and later source arguments while rejecting remote data
used only as the target, shadowed or reassigned built-ins, lookalike methods,
object spread, and code-shaped strings. The witnesses separately prove target
prototype replacement without claiming global `Object.prototype` mutation,
and safe null-prototype retention of both defaults and hostile key data.

`node-lodash-prototype-merge-manifest.json` isolates recursive third-party
merge semantics under perfect gates. Its positives retain the Express body
source, all nine ordered propagators, an exact source operand at
`src/storage.js:4`, CWE-1321, validation, attack-path analysis, and code
evidence. Core Lodash uses either a nearest runtime `package.json` pin of
4.17.10 or `^4.17.0` plus an adjacent npm v3 lockfile that repeats the root
declaration and resolves 4.17.10. Further isolated pairs cover standalone
`lodash.merge`, `merge-deep`, literal-recursive `extend`, and always-recursive
`deep-extend`, plus literal-recursive `just-extend`, each with its own patched
boundary and dependency-free witness. The `just-extend` control measures the
upstream fix's global `Object.prototype` boundary through a fresh object while
preserving target-local prototype replacement as separate review evidence. A
further pair covers `merge-options`, including its argument-zero source
semantics and patched own-data-property definition. The final pair covers the
direct `node.extend` callable, its below-1.1.7 plus exact-2.0.0 vulnerable
ranges, literal deep flag, package-isolated dependency proof, and the shared
1.1.7/2.0.1 own-property repair. The final pair covers direct `assign-deep`,
the later reviewed below-0.4.8 plus exact-1.0.0 vulnerable union, its primitive
target shift, and the completed 0.4.8/1.0.1 dangerous-key repair. This is a
measured improvement over CodeQL's older below-0.4.7 package model.
The next pair covers `merge.recursive`, the complete later-reviewed range below
2.1.1, its optional clone-boolean call form, and the nested dangerous-key bypass
left in both 1.2.1 and 2.1.0. The matched 2.1.1 control repeats the same
pre-existing nested destination and proves that validation now also runs in the
recursive helper. This extends CodeQL's older below-1.2.1 package boundary.
Matched controls preserve each call and topology while selecting a patched
version.
Deterministic regressions accept official default, namespace, CommonJS,
destructured, subpath, and optional runtime bindings, plus fresh npm v2/v3
resolution and shrinkwrap precedence. They reject patched resolution,
lockfile-free ranges, stale or v1 locks, missing installed entries, tags,
aliases, workspace declarations, development-only declarations, target-only
data, lookalikes, receiver or member reassignment, code-shaped strings,
malformed JSON, and oversized metadata. Dependency-free witnesses isolate
`constructor.prototype` traversal and the patched dangerous-key boundary
without installing a vulnerable package.

`node-lodash-prototype-deletion-manifest.json` measures Lodash's distinct
`unset`/`omit` deletion primitive rather than folding it into recursive merge.
The positive sends an Express JSON path through the same three relative-import
wrappers to core `lodash/unset.js` under the incomplete 4.17.23 repair. An
array-wrapped `__proto__` segment survives the string-only guard, reaches
`Object.prototype`, deletes `toString`, and breaks later object coercion. The
matched control pins current 4.18.1, which normalizes every segment and rejects
non-terminal magic-property traversal. Deterministic regressions cover core
Lodash receivers and named, destructured, or subpath methods; `lodash-es`;
RequireJS/AMD receivers backed by `lodash-amd`; and the directly callable
`lodash.unset` package. They preserve `unset` argument one and every `omit`
path operand after the target, distinguish pre-fix string paths from the
4.17.23 nested-array bypass, retain exact versus fresh npm v2/v3 lock
provenance, and reject patched or pre-API releases, target-only data, read-only
methods, reassignment, shadowing, unsafe metadata, and the separately published
`lodash.omit` package. Dependency-free witnesses prove both deletion plus
cleanup and the completed pre-access guard.

`node-immutable-prototype-replacement-manifest.json` measures Immutable.js
plain-object prototype replacement without mislabeling it as global pollution.
The positive sends an Express JSON profile update through three relative-import
wrappers into 5.1.4 `mergeDeep`; copying an own `__proto__` key makes `admin` an
inherited property of the returned profile and changes the authorization branch
while leaving `Object.prototype` unchanged. The topology-identical 5.1.5
control measures the shared magic-key repair. Deterministic regressions cover
named, aliased, destructured, namespace, interoperable default, CommonJS, and
direct-member bindings; all functional merge, set, and update surfaces; direct
and locally retained `Map`/`fromJS` conversions; the 3.8.3, 4.3.8, and 5.1.5
repair boundaries; and exact versus fresh npm v2/v3 lock provenance. They retain
argument zero for copying functional merges, exclude merger callbacks, preserve
key/path positions, and admit remote values only under a literal magic key.
Patched or unavailable API branches, safe fixed-key values, wrong/read-only
packages and methods, unconnected same-line expressions, reassignment,
shadowing, development-only declarations, lockfile-free ranges, inconsistent or
v1 locks, and stale metadata remain negative. Dependency-free witnesses prove
the inherited authorization effect, own-property absence, global-prototype
invariance, and repaired rejection.

`node-axios-prototype-gadget-chain-manifest.json` measures a cross-component
prototype-pollution attack path rather than another isolated sink. The positive
sends an Express JSON object through three wrappers into Lodash 4.17.10,
installs an object-valued `Object.prototype.proxy`, and then reaches an Axios
1.17.0 instance. Its ordinary immutable-style request interceptor returns
`{ ...config }`, changing Axios's initially null-prototype configuration back
into a normal object before a protected outbound request and exposing the
inherited proxy gadget. The matched control retains the source, wrappers,
merge, interceptor, and request topology while pinning Lodash 4.17.11 and Axios
1.18.0, closing both prerequisites. Deterministic regressions cover the direct
Axios 0.19.0–0.31.0 and 1.0.0–1.15.1 stages; the interceptor-rematerialization
0.31.1–0.32.x and 1.15.2–1.17.x stages; ESM, namespace, and CommonJS bindings;
root and created instances; spread and `Object.assign` copies; exact and fresh
npm v2/v3 lock proof; identity interceptors; own `proxy:false` boundaries;
reassignment, shadowing, development-only and wrong-package declarations;
local-only prototype replacement; repaired upstream primitives; and candidate
density. Dependency-free witnesses prove the object-valued global write,
null-prototype loss, inherited proxy selection, protected request material,
both repairs, and cleanup. Live isolated loopback matrices separately confirm
that the attacker proxy receives the absolute URL and authorization material on
1.15.1 directly and on 1.17.0 after a plain-object interceptor, while 1.15.2's
direct path, identity interception, own post-hardening `proxy:false`, 1.18.0,
1.19.0, and patched Lodash remain on the intended target. On the pre-hardening
stage, `proxy:false` prevents routing but can still leave inherited validator
denial of service, so it is recorded as counterevidence rather than automatic
suppression.

`node-tmp-path-traversal-manifest.json` measures a current package/API/option
boundary that generic filesystem sinks miss. The positive sends an Express
query prefix through three relative-import wrappers into `tmp.fileSync` 0.2.5;
the `../` component escapes the intended temporary root before protected export
content is written through the returned descriptor. The topology-identical
0.2.6 control retains the source, creator, option, and write while measuring the
upstream relative-component rejection. Deterministic regressions cover default,
namespace, TypeScript import-equals, named and destructured creators, direct
CommonJS members, and CommonJS receivers; asynchronous and synchronous file and
directory creation; `prefix`, `postfix`, `template`, `dir`, and unresolved
option spreads; exact and fresh declaration-consistent npm v2/v3 proof;
candidate basename and allowlist controls; cross-file wrappers; and dense call
sites. Patched, development-only, wrong-package, wrong-method, fixed-option,
fully overwritten spread, reassigned, shadowed, lockfile-free, inconsistent,
and v1-lock cases remain negative. Dependency-free witnesses reproduce actual
directory escape and protected-content placement without claiming a chosen
filename overwrite, then prove the repaired prefix rejection. A separate live
matrix confirms both prefix traversal and the older sibling-prefix `dir`
containment bypass under 0.2.5 and their rejection under 0.2.6.

`node-nodemailer-raw-access-manifest.json` measures the application-level
policy bypass in GHSA-p6gq-j5cr-w38f rather than treating dependency presence as
reachability. The positive carries one attacker-controlled message object
through three relative-import wrappers into a Nodemailer 9.0.0 transporter;
that same proven object supplies both message-level `raw` and `to`, while the
transporter explicitly sets `disableFileAccess` and `disableUrlAccess`. The
source-identical 9.0.1 control measures the repair that threads both flags into
the raw root MIME node. Regressions cover default, namespace, TypeScript
import-equals, named and destructured factories, CommonJS receivers and direct
members, inline require, transporter-level and message-level policies, separate
file and URL effects, exact and fresh npm v2/v3 resolution, and multi-hop
dependency provenance. Ordinary attachments, fixed raw data or recipients,
split uncorrelated source parameters, replaceable object spreads, missing or
false flags, patched, development-only, wrong-package, lockfile-free,
inconsistent, reassigned, shadowed, lookalike, non-sendMail, and test-only cases
remain negative. Package-backed witnesses use only a benign temporary sentinel
and loopback listener: 9.0.0 delivers both sentinel bodies while its ordinary
attachment control fails with `EFILEACCESS`; 9.0.1 rejects the raw variants
with `EFILEACCESS` and `EURLACCESS`.

`node-brace-expansion-dos-manifest.json` measures reachable synchronous work,
not a dependency alert. The positive carries one Express query pattern through
three relative-import wrappers into the official named `expand` API on 5.0.8;
the source-identical 5.0.9 control measures cumulative limits inside padded
sequence and comma-alternative construction. Deterministic regressions cover
callable CommonJS/default releases 1.x and 2.x, default ESM plus CommonJS
`.default` releases 3.x and 4.x, named `expand` release 5.x, every repaired
branch boundary, exact and fresh declaration-consistent npm v2/v3 proof,
candidate literal `max` plus `maxLength` evidence, wrapper flow, and dependency
provenance. Fixed patterns, unavailable major-line APIs, patched,
development-only, wrong-package, lockfile-free, inconsistent/v1-lock,
reassigned, member-replaced, shadowed, lookalike, and test-only cases remain
negative. Spread-bearing option objects receive no control credit, while an
explicit spread-free literal bound pair remains incomplete-control evidence.
The package-backed witness uses a bounded padded sequence: affected 5.0.8 and
repaired 5.0.9 return byte-identical 3,996,999-character output, while the
patched release avoids generating the discarded 100,000-element intermediate
sequence.

`node-nanoid-size-dos-manifest.json` measures the two reviewed generator-loop
causes without turning package presence into a finding. The canonical positive
carries a numeric request size through three wrappers into
`nanoid/non-secure.nanoid` 5.1.15; the source-identical 5.1.16 control changes
only the package repair boundary. A kill-bounded child witness requires 5.1.15
to remain CPU-bound and 5.1.16 to return the empty string. Deterministic
regressions separately cover the main package's `customAlphabet` and
`customRandom` zero-default factory defect, the Node-specific 3.3.17 and 5.1.6
repairs, the non-secure 3.3.16 and 5.1.16 repairs, official ESM, namespace,
TypeScript import-equals, CommonJS and direct bindings, exact and fresh npm
lock proof, and a typed cross-file path. Main-package `nanoid`, a zero passed
only to a positive-default generator, uninvoked factories, fixed values,
patched or development-only packages, unresolved ranges, replacement,
shadowing, and test/example paths remain negative. The zero-default control
requires both integer validation and a positive bound because `NaN` also
collapses the factory's random step to zero.

`node-opcua-nonce-cache-dos-manifest.json` measures the unauthenticated
process-global nonce retention reviewed in GHSA-6wvw-vrw4-363w. The positive
constructs and starts the official `OPCUAServer` under exact production
`node-opcua` 2.165.0 proof; the source-identical control changes only that
dependency to 2.168.0. Deterministic regressions cover named and aliased ESM,
namespace, TypeScript import-equals, CommonJS receiver, destructure, and direct
member bindings, same-file startup, an exported server instance started across
a relative import, exact declarations, and fresh npm v2/v3 resolution. Client
use, unstarted construction, post-review releases, wrong or development-only
packages, unresolved ranges, inconsistent or v1 locks, reassignment, member
replacement, wrapper shadowing, local lookalikes, and test/example paths remain
negative. The bounded real-package witness inserts 50,001 unique 32-byte
nonempty nonces and replays the first: 2.165.0 still recognizes it, whereas
2.168.0 has evicted it at the 50,000-entry ceiling. This proves the storage
repair without deliberately exhausting memory or starting a network listener.

`node-opcua-username-token-nonce-bypass-manifest.json` measures the missing
cryptographic binding reviewed in GHSA-mq36-523m-x7vv. The positive constructs
and starts an official `OPCUAServer` with a usable application `userManager`
under exact `node-opcua` 2.165.2 proof; the source-identical control changes
only the dependency to 2.166.0. Deterministic regressions cover named and
aliased ESM, namespace, TypeScript import-equals, CommonJS receiver,
destructure, and direct-member bindings; literal, referenced, and factory-built
user managers; same-file and exported-instance startup; exact declarations;
and fresh npm v2/v3 resolution. Default deny-all, null, empty, or
certificate-only managers, literal `SecurityPolicy.None`-only endpoints,
dynamic unproved policy arrays, client-only or unstarted code, repaired or
development-only packages, unresolved ranges, inconsistent/v1 locks,
reassignment, member replacement, wrapper shadowing, and tests/examples remain
negative. The bounded witness encrypts a password plus nonce A once. Version
2.165.2 calls the manager and accepts that ciphertext under both nonce A and
nonce B; it also turns a four-byte forged blob into an empty password. Version
2.166.0 accepts only the correctly bound token and rejects both invalid forms
before the manager. The empty-password branch establishes an authentication
bypass only when the deployed manager accepts that credential; the general
replay condition does not depend on such behavior.

`node-authjs-configuration-error-manifest.json` measures the Auth.js v5
server-configuration fail-open reviewed in GHSA-8fpg-xm3f-6cx3. The positive
uses an official stable `next-auth` default factory, its generated `auth`
wrapper across a relative import, and a concrete private-route decision based
only on `!!request.auth` under exact 5.0.0-beta.31 proof. The source-identical
control changes only the dependency to 5.0.0-beta.32. Deterministic regressions
cover default aliases, namespace-default, TypeScript import-equals, CommonJS
default/member forms, generated-wrapper aliases, relative and unambiguous root
aliases, deployed `callbacks.authorized` proxy/middleware exports, inline
destructuring, derived booleans, and direct `auth()` results.
They accept exact prereleases and fresh declaration-consistent npm v2/v3
locks, while rejecting repaired or v4 releases, wrong or development-only
packages, unresolved ranges, ambiguous aliases, reassignment, local
lookalikes, test/example code, log-only use, and concrete session-property
checks. The published-package witness induces an OIDC endpoint-configuration
error without a listener or outbound request: beta.31 supplies a truthy
`{message}` object and permits the request, while beta.32 supplies `null` and
denies it.

`node-jsonata-expression-rce-manifest.json` measures the application-level
reachability missing from dependency-only JSONata alerts for
GHSA-66mm-25pp-rfff, GHSA-2943-5xfg-gq5f, and GHSA-8gq3-vp5j-2grp. The
positive sends an Express query expression through three relative-import
wrappers into the official JSONata compiler and requires the returned compiled
expression to reach `evaluate()` under exact 2.2.0 production proof. The
source-identical control changes only JSONata to 2.2.1, the first v2 release
that closes all three reviewed sandbox-escape chains. Regressions cover stable
default aliases, namespace-default, TypeScript import-equals, CommonJS and
direct-require callables, one-hop compiler aliases, immediate and retained
compiled expressions, multiline calls, both repaired release lines, and fresh
declaration-consistent npm v2/v3 locks. Package-only, compile-only, trusted
static expressions, request data used only as evaluation input, named and
CommonJS-default guesses, replaced compiler or evaluation capabilities,
development-only packages, unresolved ranges, stale/v1 locks, test/example
code, and repaired or prerelease versions remain negative. The bounded witness
returns only `process.version`: 2.2.0 recovers the host `Function` constructor,
whereas 2.2.1 rejects the same expression with `T1006`.

`node-urllib-cross-origin-credential-leak-manifest.json` measures the exact
application lifecycle behind
[GHSA-hq3h-g68c-hp78 / CVE-2026-55553](https://github.com/advisories/GHSA-hq3h-g68c-hp78),
not merely an affected urllib dependency. The positive carries an inbound
authorization value through three relative-import wrappers into a standard
credential header on an official urllib 4.9.0 request. Redirects remain
enabled at their default ten-hop limit. The source-identical control changes
only urllib to 4.9.1, which follows the redirect but removes the credential
before crossing the origin boundary. Regressions cover named and aliased,
default, namespace, TypeScript import-equals, CommonJS receiver/destructured,
and direct-require `request`/`curl` forms; `Authorization`, `Cookie`,
`Proxy-Authorization`, `auth`, and `digestAuth`; both affected release lines;
and fresh declaration-consistent npm v2/v3 locks. Repaired and prerelease
versions, development-only or wrong packages, unresolved/stale/v1 metadata,
fixed credentials, custom auth-like headers, local lookalikes, reassignment,
member replacement, and 3.x/4.x calls that disable redirects or stream remain
negative. The 2.x regression deliberately retains `maxRedirects: 0` because
that implementation replaces zero with its default ten. The shared witness
uses two ephemeral loopback listeners and an inert bounded token: 4.9.0 sends
the token to the second origin, while 4.9.1 reaches it without the header.

`node-rhinostone-swig-template-traversal-manifest.json` measures the complete
application boundary behind
[GHSA-2mf3-mr2r-r4vf](https://github.com/advisories/GHSA-2mf3-mr2r-r4vf).
The positive carries an Express query value through three relative-import
wrappers into the `partial` local of a trusted template. Its dynamic `include`
is rendered by an official `@rhinostone/swig` 2.7.0 instance whose filesystem
loader has an explicit root. The source-identical control changes only the
runtime to 2.7.2, which rejects the same outside-root target. Regressions cover
the Swig, Django, Jinja2, and Twig frontends; default, namespace, TypeScript
import-equals, CommonJS, receiver-alias, engine-alias, constructor, and default
instance forms; `include`, `extends`, `import`, and `from`; exact production
proof; the affected rooted route; patched but unconfined loaders; and the
documented `allowOutsideRoot` opt-out. Literal or mismatched template targets,
trusted locals, repaired rooted defaults, compile-only flows, wrong or
development-only packages, unresolved versions, local lookalikes,
reassignment, member replacement, and tests/examples remain negative. The
bounded witness reads only the fixture-local sentinel immediately outside the
template root: 2.7.0 renders it, while 2.7.2 throws before reading it.

`node-intlify-flat-json-prototype-pollution-manifest.json` measures the
application-reachable boundary behind
[GHSA-p2ph-7g93-hw3m / CVE-2025-27597](https://github.com/advisories/GHSA-p2ph-7g93-hw3m).
The positive carries a request-body message object through three relative
wrappers into official Vue I18n 9.14.2 `createI18n()` configuration with
literal `flatJson: true`. The source-identical control changes only Vue I18n to
9.14.3, which rejects an exact `__proto__` segment before prototype traversal.
Regressions cover the direct `@intlify/message-resolver` transformer, explicit
`@intlify/core` and `@intlify/core-base` ESM browser bundles that export it,
Vue I18n, its core package, and Petite Vue I18n; named, aliased, namespace,
TypeScript import-equals, CommonJS, direct-require, and stable-alias bindings;
initial messages and configured locale setters; every reviewed 9.x, 10.x, and
11.x branch boundary; and exact or declaration-consistent npm v2/v3 production
proof. Repaired and out-of-range prereleases, root core imports without the
export, custom initial message resolvers, disabled or dynamic `flatJson`,
spread or duplicate options, fixed messages, development-only or wrong
packages, stale/v1 metadata, lookalikes, reassignment, member replacement, and
tests/examples remain negative. The disposable-process witness uses one inert
unique property, opens no listener or socket, and deletes the property in
`finally`: 9.14.2 creates the inherited value, while 9.14.3 throws `unsafe key`
and leaves `Object.prototype` unchanged.

`node-deepseek-mcp-http-session-authorization-manifest.json` measures the
HTTP-only cross-session authorization boundary in
[GHSA-fh3r-g96v-f578 / CVE-2026-55604](https://github.com/arikusi/deepseek-mcp-server/security/advisories/GHSA-fh3r-g96v-f578).
The positive uses a production top-level launcher that assigns literal
`TRANSPORT=http` before dynamically starting exact
`@arikusi/deepseek-mcp-server` 1.6.0. The source-identical control changes only
the runtime to 1.7.0. Regressions cover top-level dot and bracket environment
assignment, bounded start/serve/server/mcp script forms for POSIX and Windows,
the full stable 1.4.2-through-1.6.x interval, exact and declaration-consistent
npm v2/v3 proof, and fail-closed rejection of stdio, overwritten or dynamic
transport, nested and static launchers, arbitrary or echo-only scripts,
subpath lookalikes, development-only packages, prereleases, stale/v1 locks,
and tests/examples. The real-package witness opens no listener and contacts no
API: 1.6.0 returns the same singleton to two simulated client flows, exposing
the victim key and inert message marker, while 1.7.0 returns distinct stores
that remain empty even when both clients choose the same `session_id`.

`node-sequelize-oracle-sql-injection-manifest.json` measures the conjunction
that dependency and generic raw-SQL scanners cannot establish for
[GHSA-v8fg-2rw7-q452 / CVE-2026-69240](https://github.com/advisories/GHSA-v8fg-2rw7-q452):
an affected production Sequelize resolution, a statically proven Oracle
dialect, an exact model created by that instance, and remote data reaching
`where` in an executed ORM operation. The positive carries an Express query
value through three relative-import wrappers into `Student.findOne` under
exact 6.37.3 proof. The source-identical control changes only Sequelize and its
lock to 6.37.4. Regressions cover official named/aliased, default, namespace,
TypeScript import-equals, CommonJS destructured/direct constructors; static
Oracle URIs; resolved and shorthand options; six executed model operations;
the stable repaired boundary; exact and modern lock provenance; reassignment,
member replacement, wrong-dialect, wrong-position, fixed-value, path, and
metadata negatives. The shared witness loads no Oracle driver and contacts no
database: 6.37.3 emits the bounded `OR 1=1--` predicate, while 6.37.4 rejects
the identical value with `Invalid SQL function call.`

`node-liquidjs-template-rce-manifest.json` measures application reachability
for [GHSA-gf2q-c269-pqgc / CVE-2026-45618](https://github.com/advisories/GHSA-gf2q-c269-pqgc),
not merely an affected LiquidJS dependency. The positive sends an Express
query template through three relative-import wrappers into official
`parseAndRender` under exact 10.25.7 production proof. The source-identical
control changes only `liquidjs` to 10.26.0, whose null-prototype filter and tag
registries prevent inherited `Object.prototype` names from becoming template
capabilities. Regressions cover official named and aliased constructors;
namespace/default and TypeScript import-equals receivers; CommonJS
destructures, receivers, and direct members; stable one-hop constructor and
instance aliases; immediate parse-and-render calls; retained and nested
parse-to-render closures on the same instance; synchronous variants; and
fresh declaration-consistent npm v2/v3 locks. Trusted fixed templates with
remote context, package-only and parse-only use, different-instance rendering,
local lookalikes, replaced or reassigned capabilities, development-only
packages, unresolved/stale/v1 metadata, test/example code, 10.26.0+, and
prereleases remain negative. The shared witness never invokes a shell,
listener, filesystem API, or network API: 10.25.7 returns only
`process.version` through inherited `valueOf` filter resolution, while 10.26.0
returns `false` for the identical template.

`node-shescape-cmd-injection-manifest.json` measures application reachability
for [GHSA-w4hw-qcx7-56pr / CVE-2026-73414](https://github.com/advisories/GHSA-w4hw-qcx7-56pr),
not merely an affected Shescape dependency or incomplete local escaping code.
The positive sends an Express query value through three relative-import
wrappers into official Shescape 3.0.0 configured for `cmd.exe`; the exact
escaped result reaches an official Node child-process command-string dispatch.
The source-identical control changes only `shescape` to 3.0.1, which
caret-escapes both CMD parentheses. Regressions cover named and aliased
constructors; namespace and TypeScript import-equals receivers; CommonJS
destructures, receivers, and direct members; official stateless `escape` and
`escapeAll`; stable constructor, instance, process, command, and argument
aliases; direct nested and multiline dispatch; `exec`, `execSync`, `spawn`,
`spawnSync`, and shell-enabled `execFile` forms; both affected release branches;
and fresh declaration-consistent npm v2/v3 locks. Non-CMD shells, fixed or
unused input, safe shell-free argv dispatch, missing final shell options,
patched/prerelease versions, wrong or development-only packages, unresolved or
stale metadata, mutated options or values, lookalikes, replaced capabilities,
and test/example paths remain negative. The shared witness executes only the
advisory's benign `echo y` sentinel on Windows. Linux imports the installed
package's published Windows CMD escape function and checks the exact string
boundary without invoking a shell.

`node-shell-quote-object-token-command-injection-manifest.json` measures
application reachability for
[GHSA-w7jw-789q-3m8p / CVE-2026-9277](https://github.com/advisories/GHSA-w7jw-789q-3m8p),
not merely an affected `shell-quote` dependency. The positive sends an Express
query value through three relative-import wrappers, assigns it to the exact
`op` property of an object token, passes that token to official `quote()`, and
dispatches the exact serialized result through official `execSync` under
1.8.3 production proof. The source-identical control changes only
`shell-quote` and its lock to 1.8.4. Regressions cover named and aliased,
namespace/default, TypeScript import-equals, CommonJS destructured/receiver/
direct-member, inline `require()`, and stable one-hop bindings; direct object
construction and `parse()` environment callbacks; `exec`/`execSync`, explicit
POSIX interpreter `-c`/`-lc`, and shell-enabled `spawn`/`execFile` dispatch;
the exact affected range; and fresh declaration-consistent npm v2/v3 locks.
Ordinary strings, fixed operators, glob/comment objects, parse-only use,
unused output, shell-free argv execution, unsupported flags, repaired or
prerelease versions, wrong/development-only packages, unresolved/stale/v1
metadata, lookalikes, reassignment, replaced capabilities, and test/example
paths remain negative. The shared witness is side-effect-free: Ubuntu/WSL runs
only `pwd` through `/bin/sh -c` in `/tmp`, where 1.8.3 executes the retained
second line and 1.8.4 rejects the token; Windows checks serialization only.

`node-decompress-archive-escape-manifest.json` measures application
reachability for
[GHSA-mp2f-45pm-3cg9 / CVE-2026-53486](https://github.com/advisories/GHSA-mp2f-45pm-3cg9),
not merely an affected archive dependency. The positive sends an Express body
through three relative-import wrappers into official `@xhmikosr/decompress`
10.2.0 with a concrete destination. The source-identical control changes only
the package to 10.2.1. Regressions cover both maintained affected branches,
unpatched upstream `decompress` 4.2.1, official default/namespace/TypeScript/
CommonJS forms, one-hop aliases, multiline calls, exact manifests, and fresh
declaration-consistent npm v2/v3 locks. Parse-only overloads, omitted or
non-string destinations, repaired releases, ambiguous package identities,
wrong or development-only packages, stale metadata, shadows, reassignment,
replaced capabilities, and test/example paths remain negative. The bounded
custom-plugin witness writes only into a newly created temporary sibling and
cleans it. A second fixture using the repair commit's real tar archive proves
the default parser's symlink-to-sibling write on affected releases and
rejection on repaired releases.

`node-velocity-template-rce-manifest.json` measures application reachability
for [GHSA-7gfh-x38p-prh3 / CVE-2026-73649](https://github.com/advisories/GHSA-7gfh-x38p-prh3),
not merely an affected Velocity.js dependency. The positive sends an Express
query template through three relative-import wrappers into official `render`
under exact 2.1.6 production proof. The source-identical control changes only
`velocityjs` to 2.1.7, whose shared guard rejects dangerous property reads in
references, indexes, methods, and assignments. Regressions cover official
named and aliased `render`, `parse`, and `Compile` bindings; namespace/default
and TypeScript import-equals receivers; CommonJS destructures, receivers, and
direct members; direct-require rendering; stable one-hop aliases; direct
rendering and complete parse-to-Compile-to-render paths; multiline calls; and
fresh declaration-consistent npm v2/v3 locks. Trusted fixed templates with
remote context, package-only use, parse-only and compile-without-render flows,
local lookalikes, default-call guesses, replaced or reassigned capabilities,
development-only packages, unresolved/stale/v1 metadata, test/example code,
2.1.7+, and prereleases remain negative. The shared witness never invokes a
shell, listener, filesystem API, or network API: 2.1.6 returns only
`process.version` through `constructor.constructor`, while 2.1.7 leaves the
final `$r` reference unresolved.

`node-vm2-sandbox-escape-manifest.json` measures application reachability for
[GHSA-cfcw-xp6x-25gj / CVE-2026-47698](https://github.com/advisories/GHSA-cfcw-xp6x-25gj)
rather than treating vm2 package membership as proof of host compromise. The
positive carries an Express body field through three relative-import wrappers
into an official `VM.run` under exact 3.11.5 production proof. The
source-identical control changes only vm2 to 3.11.6. Regressions cover named
and aliased constructors, namespace/default and TypeScript import-equals
receivers, CommonJS destructures/receivers/direct members, one-hop constructor
aliases, assigned and immediate instances, `VMScript` source preservation,
exact and fresh declaration-consistent npm v2/v3 locks, and same-file or
multi-hop reachability. A second precision model covers
[GHSA-m5w8-4gq2-6f8x](https://github.com/advisories/GHSA-m5w8-4gq2-6f8x)
only when attacker code reaches `NodeVM.run` with a statically proven wildcard
builtin allowlist and either `os` or `dns` remains exposed. Complete
`-os`/`-dns` cutouts, demonstrably inert literal replacements for both modules,
package-only
use, trusted code, NodeVM without wildcard builtins, local lookalikes,
reassigned or replaced capabilities, unresolved/development-only/stale/v1
dependency evidence, tests/examples, repaired versions, and prereleases remain
negative. The bounded witness recovers only `process.version`: 3.11.5 crosses
the host-prototype boundary, while 3.11.6 stops the same chain without a shell,
filesystem access, network request, listener, or process-state mutation.

`node-tar-decompression-dos-manifest.json` measures application reachability
for [GHSA-23hp-3jrh-7fpw / CVE-2026-59873](https://github.com/advisories/GHSA-23hp-3jrh-7fpw).
The positive sends an uploaded compressed archive path through three
relative-import wrappers into the official `tar.list` parser under exact
7.5.18 production proof. The source-identical control changes only `tar` to
7.5.19, whose parser defaults cumulative `maxDecompressionRatio` to 1000.
Regressions cover namespace/default and TypeScript receivers, named aliases,
CommonJS destructuring, direct requires, `t`/`list`/`x`/`extract` plus streaming
`Parse`/`Unpack`, file and request-stream sources, operation-specific sink
provenance, exact and fresh npm v2/v3 locks, simple-range consistency,
reassignment, replaced members, wrapper shadows, wrong or development-only
packages, fixed inputs, create APIs, and patched/prerelease releases. The same
bounded witness constructs an 8,390,144-byte tar whose gzip form is 8,242
bytes: 7.5.18 processes the 1017.97:1 expansion, while 7.5.19 aborts at an
observed ratio of 1001.88 before the complete archive is parsed. No payload is
extracted.

`node-keystone-negative-take-bypass-manifest.json` measures the configured
limit bypass in [GHSA-cqmq-8755-7xvh / CVE-2026-63421](https://github.com/advisories/GHSA-cqmq-8755-7xvh).
The positive exports a Keystone 6.5.2 configuration with a queryable list and
`graphql.maxTake: 3`; the source-identical control changes only
`@keystone-6/core` to 6.5.3. Regressions cover named aliases,
namespace/default and TypeScript import-equals receivers, CommonJS destructures
and receivers, direct requires, exported configuration aliases and wrappers,
relative list modules, list-option aliases, exact and fresh npm v2/v3 runtime
proof, factory reassignment, receiver-member replacement, local lookalikes,
unexported configurations, unresolved or nonpositive limits, query omission,
and statically deny-all query access. The bounded witness calls Keystone's real
GraphQL resolver through its public context API with an in-memory Prisma test
double and no listener or database: 6.5.2 passes `-5` to Prisma and returns five
rows, while 6.5.3 returns `KS_LIMITS_EXCEEDED` before Prisma.

`node-postcss-source-map-traversal-manifest.json` measures PostCSS's implicit
previous-source-map file load. The positive sends an Express CSS body through
three relative-import wrappers into `postcss([]).process` 8.5.17 with an
ordinary fixed `from` path; a hostile final `sourceMappingURL` traverses to an
external `.map`, and returned `result.map` exposes its `sourcesContent`. The
topology-identical 8.5.18 control measures the upstream same-directory
containment check. Exact regressions cover root and named parse bindings,
default/namespace/CommonJS roots, direct CommonJS parse, processor variables,
parse and process operations, exact and fresh npm v2/v3 resolution, and typed
cross-file flow. Exact `map: false` and `map: { prev: false }`, patched or
development-only versions, fixed CSS, wrong packages, reassignment, shadowing,
lockfile-free ranges, inconsistent locks, and v1 locks remain negative. The
review boundary requires a final non-inline `.map` annotation, an external or
absolute resolved path, a valid source map, and a concrete `result.map` or
`sourcesContent` disclosure channel; it does not promote a file load into code
execution or claim non-`.map` reads on 8.5.12 through 8.5.17. Dependency-free
witnesses reproduce the disclosure and repaired containment, while an isolated
real-package matrix confirms vulnerable 8.5.17, patched 8.5.18, `map: false`,
and the repaired release's explicit `unsafeMap: true` opt-out.

`node-js-toml-prototype-pollution-manifest.json` broadens the measured parser
surface beyond recursive merge helpers. Its positive sends an Express TOML body
through three relative-import wrappers into the official `js-toml.load(text)`
API under an exact 1.0.1 runtime pin. The hostile `[__proto__]` table reuses
`Object.prototype`, and the following assignment becomes inherited
authorization state on a fresh object. The matched 1.0.2 control preserves the
source, call, and topology while measuring the upstream repair: null-prototype
root, inline-table, array-of-tables, and nested objects retain hostile names as
data without reaching built-in prototypes. Deterministic regressions accept
named, aliased, destructured, namespace, CommonJS receiver, and direct-member
bindings plus exact 0.x/1.0.0/1.0.1 pins and fresh npm v2/v3 vulnerable lock
resolution. They reject 1.0.2+, default-import guesses, wrong members or
packages, argument-position confusion, absent sources, reassignment and
shadowing, development-only declarations, lockfile-free ranges, patched or
inconsistent resolution, and v1 locks. The dependency-free witness proves both
the vulnerable inherited-object effect and the patched null-prototype invariant.

`node-copilot-prompt-injection-manifest.json` isolates that SDK boundary under
perfect single-run gates. The positive must retain the HTTP source, all six
ordered import/call/parameter propagators, exact trusted-content sink,
CWE-1427, validation, attack-path analysis, and code evidence. The paired
control keeps the same three-file topology and fixed system message but passes
request values only through the user-message channel. Deterministic regressions
cover all current trusted fields, ESM aliases, CommonJS destructuring,
unknown-section fallback, `resumeSession`, exact acceptance through eight
value aliases, and rejection of wrong/default/namespace imports, reassignment,
a ninth alias, fixed or unrelated fields, comments, and string-only
pseudo-flows.

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

The IPv6-transition SSRF lane specializes an already proven Node
request-to-outbound-URL path when the sink wrapper applies a fail-closed
private-address guard that understands only dotted-quad IPv4. The positive
retains the exact request, relative import, wrapper parameter, parsed host,
guard, and `fetch` sink. The executable witness demonstrates independent
bypasses through IPv4-mapped IPv6, NAT64, and 6to4 literals. The paired control
preserves the topology but canonicalizes all three families before applying
the private IPv4 policy. A mapped-only normalizer remains positive; unrelated
host checks, log-only branches, comments, and non-dominating guards are
rejected:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/node-ipv6-transition-ssrf-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-node-ipv6-transition-ssrf `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

node ../../benchmarks/witnesses/javascript-ipv6-transition-ssrf/Ipv6TransitionSsrfWitness.mjs
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

The Go filesystem-path lane measures exact standard-library import identity,
typed request accessors, path argument roles, one same-package wrapper, and
the distinction between path construction and rooted filesystem access. The
first positive joins a query value beneath a public directory and passes the
result to `os.ReadFile`; its executable witness reads a sibling signing-key
file. Its matched control keeps the request, wrapper, directory layout, attack
bytes, and allowed-file behavior but uses `os.OpenInRoot`, which rejects the
escape. The second positive computes `filepath.Rel` and then rejoins its result
without rejecting `..`; its witness proves the supposedly relative path still
reads the sibling secret. The matched lexical control rejects both an exact
`..` result and `..` followed by `os.PathSeparator`, then proves the public
document remains readable. `Join`, `Clean`, `Abs`, `Rel`, and `EvalSymlinks` do
not erase the host hypothesis. `Rel` remains tainted construction; the scanner
records a `relative-parent-boundary-rejection` candidate only when the same
result receives both separator-aware checks before the sink. The quality gate
must still prove dominance and fail-closed behavior. Request control of an
`OpenRoot` or `OpenInRoot` root is a separate root-selection finding. Review
must separately prove lexical
boundaries, links, mounts, races, authorization, and runtime patch level;
affected Unix `os.Root` users
need Go 1.25.12 or 1.26.5 or newer for GO-2026-4970/CVE-2026-39822:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-http-filesystem-path-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-http-filesystem-path `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-path-traversal
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-rooted-file
go test ./...
Pop-Location
Push-Location fixtures\go-relative-path-traversal
go test ./...
Pop-Location
Push-Location fixtures\go-relative-safe-containment
go test ./...
Pop-Location
```

The Go process-execution lane measures exact `os/exec`, `execabs`, `os`, and
`syscall` import identity, typed request accessors, executable and argv roles,
one same-package wrapper, immutable complete-command selection, and the
difference between deferred `Cmd` execution and immediate low-level dispatch.
One positive uses `CommandContext`; the other populates a manual `Cmd` through
`Path` plus a complete `Args` field assignment. Both format the request value
into the string interpreted after `sh -c` and reach `CombinedOutput`. Their
controls retain the request, wrapper, shell, flag, finisher, and attack bytes
but only select a complete server-owned command. Each module copies its running
test executable into a temporary `sh` witness, making both exploit/control
pairs deterministic on Windows and Linux without invoking the host shell:

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
Push-Location fixtures\go-cross-file-manual-cmd-shell-injection
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-manual-cmd-shell-command
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

The Go HTTP object-authorization lane measures a different boundary from SQL
injection: the SQL remains fixed and parameterized, but an attacker-controlled
object ID can select another principal's record or collection. The first
positive fixture carries a path value through one same-package wrapper into an
ID-only `QueryRow`, then scans and returns the victim secret. Its control adds
an account predicate bound to a principal obtained from the request context.
The second pair uses `QueryContext`, the returned `Rows`, `Next`, `Scan`, and
response disclosure to prove and block a victim-project invoice listing.
The third pair prepares a fixed DELETE and later executes the exact returned
`Stmt`; its control adds a context-principal account predicate. Deterministic
standard-library drivers prove both cross-account disclosures and the
unauthorized prepared deletion. A fourth pair stages deletion on an exact `Tx`
and applies it only at `Commit`, proving durable victim impact and a committed
principal-scoped control. A fifth pair prepares fixed SQL on the DB, transfers
the exact statement into a transaction with `Tx.StmtContext`, executes the
returned clone, and commits; its matched control adds only the authenticated
account predicate. A sixth pair finalizes a direct transaction mutation through
a uniquely resolved typed same-package commit helper and preserves the helper's
actual commit path; its control adds only the authenticated account predicate.
The seventh pair adds a typed coordinator that aliases and forwards the exact
transaction to a leaf commit helper, preserving both helper boundaries and the
real commit location; its control changes only the account predicate. The suite
adds an eighth pair whose application imports a typed coordinator from one
internal package and reaches the real commit through a second internal package.
The host derives both identities from `go.mod`, exact import aliases, and
exported functions; the control again changes only the account predicate. A
ninth pair obtains the transaction through an imported coordinator and leaf
factory before mutation and commit. The exact typed DB/Conn input, first Tx
return, module path, import aliases, helper chain, and leaf `BeginTx` are all
preserved; its control again changes only the account predicate. A tenth pair
captures the imported factory and finalizer in application function values,
and both helpers capture their leaf operations the same way. Each exact local
binding and helper boundary remains visible in the evidence path; its control
again changes only the account predicate. An eleventh pair carries both the
path-selected object ID and the context-derived account through an exact
handler-to-service-to-repository chain spanning two imported local packages.
The host preserves every call, string parameter, and object alias, and remaps
the principal position across every boundary. Its control again changes only
the account predicate. A twelfth pair calls an imported concrete service method,
which binds one imported repository implementation to a local interface before
calling its method. Exact receiver construction and interface binding remain
visible in the evidence; the control again changes only the account predicate.
A thirteenth pair obtains the imported service from an exact constructor and
traverses its named concrete repository value field before calling the sink
method. Exact constructor call, internal return aliases, return location,
receiver binding, field declaration, object aliases, and principal positions
remain visible; the control again changes only the account predicate. The suite
adds a fourteenth pair whose constructor stores one of two valid repository
implementations in an interface field. Exact constructor-parameter mapping,
call-site instance identity, implementation narrowing, field dispatch, object
aliases, and principal positions remain visible; the control again changes only
the account predicate. A fifteenth pair nests that constructor-selected
implementation beneath a pointer layer while initializing unrelated scalar
fields in a normal multiline trailing-comma composite. Nested instance
assignments and field declarations remain distinct in the evidence; the control
again changes only the account predicate. A sixteenth pair constructs an empty
service and then writes the nested layer through a pointer alias. Exact
post-construction state, pointer alias sharing, scalar writes, nested interface
identity, and the distinct field-write evidence line remain visible; the control
again changes only the account predicate. A seventeenth pair creates the pointer
layer first and injects the selected repository through a later nested selector.
The recursive constructor-state tree retains separate parent-creation and leaf-
write lines, shallow pointer sharing, deep concrete-value copying, and exact
implementation replacement; the control again changes only the account
predicate. An eighteenth pair writes the same nested repository field on both
arms of one explicit constructor `if`/`else`, using two aliases of the returned
pointer. The host clones each complete alias graph, preserves shallow pointer
sharing, joins only structurally identical post-branch states, and retains both
write lines as evidence; the control again changes only the account predicate.
The suite adds a nineteenth pair whose constructor obtains its pointer parent
from an exact same-package helper in another file before injecting the selected
repository through a nested write. The helper's composite, alias, return, call,
constructor binding, and field-write locations remain distinct evidence; its
control again changes only the account predicate. A twentieth pair moves that
allocator into another package in the same Go module. Exact import aliases,
exported callable/type/field visibility, defining-package composite identity,
the shared helper-depth bound, and the multiline field's actual source line are
preserved; its control again changes only the account predicate. A twenty-first
pair moves repository injection into the imported helper: it allocates an empty
parent, aliases the pointer, writes the selected repository, and returns the
original alias. Exact linear writes, nested parent existence, pointer sharing,
direct value-field copying, explicit dereference, and the eight-write bound are
enforced. A twenty-second pair copies a value layer containing a pointer holder,
writes the repository through the copy, and returns the original value. Exact
shallow sharing survives deeper concrete value fields and nested helper results,
while pointer overwrite detaches only the selected copy. Its control again
changes only the account predicate. A twenty-third pair writes the same shared
holder through different value copies on the two explicit arms of a helper
`if`/`else`. Each branch runs against an identity-preserving clone of the fully
materialized helper graph, and only identical complete post-branch states with
the same one-to-one node-sharing topology join.
Evidence from both branch aliases and both write origins is retained. Concrete
value isolation, pointer-slot replacement on different copies, divergent
implementations, branch-local assignments, nested control flow, unequal write
counts, a ninth write, and a seventeenth branch line fail closed. Its control
again changes only the account predicate. A twenty-fourth pair generalizes the
imported helper join to one exact `if / else if / else` chain. Three shallow
value copies write the same shared pointer holder on three paths; the host
retains all three origins and joins only complete, identity-compatible state.
A mandatory final `else`, two-through-four-arm bound, equal nonzero write
counts, and the existing per-path budgets make the accepted paths explicit; a
fifth arm, missing final arm, or divergent state fails closed. Its control again
changes only the account predicate. A twenty-fifth pair expresses the same
imported-helper all-path proof
with an exact `switch`: two named cases and a mandatory final `default` write
through three shallow copies sharing one pointer holder. The common bounded
world replay retains all three origins and requires complete state and topology
convergence. Missing or non-final `default`, `fallthrough`, labelled or
non-terminal `break`, empty or divergent arms, nested control, a fifth arm, and
over-budget paths fail closed.
Its control again changes only the account predicate. A twenty-sixth pair uses
an expressionless `switch` whose three arms end with explicit unlabelled
`break` statements. The scanner trims only that redundant terminal statement,
then applies the same complete-world replay and identity-topology join. Switch
general initializers, type switches, labelled or non-terminal breaks, and all
existing divergence and resource failures remain rejected. Its control again
changes only the account predicate. A twenty-seventh pair binds a fresh switch
guard directly from an exact built-in scalar parameter before selecting among
the same three all-path writes. The guard must be the switch expression and may
not appear in an arm body; call results, non-scalar sources, mismatched guards,
parameter or prior-local shadowing, and other initializer forms fail closed. Its
control again changes only the account predicate. A twenty-eighth pair admits
exact type switches whose source is one uniquely resolved interface parameter.
Both unbound and fresh guard-bound forms reuse the same all-path replay. A named
guard may appear only in a leading blank assignment such as `_ = selected`,
which satisfies Go's compiler without changing tracked state; all value-bearing
uses reject the join. Scalar, selector, conversion, shadowed, and ambiguous
sources remain rejected. Its control again changes only the account predicate.
A twenty-ninth pair threads the interface source through two exact local aliases
before the type switch. The scanner follows up to eight top-level, single-name,
value-preserving assignments and invalidates overwritten names; a ninth hop,
transformation, selector, multiple assignment, nested or conditional binding,
or concrete replacement fails closed. Its control again changes only the
account predicate. A thirtieth pair converts the exact interface source to the
empty interface before one further local alias and the type switch. Exact
`interface{}` conversion is unconditional; predeclared `any` requires Go 1.18
or later when the enclosing module declares a version and must remain unshadowed
across the package, current file imports, function signature, and preceding
local scope. Conversion assignments share the eight-edge alias budget. Nested
calls, selectors, composites, shadowed imports or
declarations, and pre-1.18 modules fail closed. Its control again changes only
the account predicate. A thirty-first pair converts the source to a distinct
named basic interface with an identical method signature, carries that value
through one local alias, and enters the same all-path type switch. The target
must resolve uniquely without lexical shadowing. Identical and named-empty
interfaces are admitted directly; nonempty distinct targets require an exact
same-package method-set subset with matching signatures. Broader or mismatched
targets, embedded or constraint interfaces, unresolved or cross-package
nonempty signatures, nested inputs, local type or value shadowing, and a ninth
edge fail closed. Its control again changes only the account predicate. The
thirty-second pair places the target interface in a separate local-module
package and intentionally changes import aliases plus parameter and result
names. Bounded canonical type identities erase parameter names, expand grouped
names, resolve qualified types to import paths, normalize predeclared aliases,
and retain package identity for local types and unexported methods. Exact
exported cross-package method sets are admitted; ambiguous, duplicate, dot,
blank, unresolved, or differently bound imports, result/type mismatches, and
cross-package unexported methods fail closed. Its control again changes only
the account predicate. A thirty-third pair composes the source contract from a
same-package embedded interface and the target contract from an aliased
interface in another local-module package. The scanner resolves unique named
basic interfaces, recursively expands at most eight embedding edges, merges at
most 64 canonical methods, retains declaring-package identity for unexported
methods, and permits identical diamond duplicates. Cycles, a ninth edge,
signature conflicts, duplicate declarations, unresolved external or
non-interface terms, and incomplete import identity fail closed. Its control
again changes only the account predicate. A thirty-fourth pair carries method
signature types, embedded source and target contracts, constructor parameter
and field types, and the conversion target through exact local Go aliases.
Direct and grouped non-generic declarations resolve in their own file/import/
package context through at most eight same-package or qualified local-module
aliases. Defined types remain distinct. Cycles, a ninth edge, generic or
duplicate aliases, alias/interface collisions, unexported qualified names,
pointers, incomplete imports, unresolved or external endpoints, and
non-interface targets fail closed. Its control preserves the complete alias
topology and again changes only the account predicate. A thirty-fifth pair
crosses two local concrete embedded fields before invoking the repository's
promoted deletion method. Exact breadth-first selector depth, same-depth
uniqueness, package visibility, value-versus-pointer method sets, constructor
state, and every promoted field are preserved. Cycles, a ninth edge, external,
unresolved, interface, or generic embeddings, duplicate methods, pointer/value
mismatches, and ambiguous shallow selectors fail closed. Its control preserves
the promotion graph and again changes only the account predicate. The suite
proves all thirty-five blocked attacks and successful owned-object, owned-collection,
prepared-mutation, direct-transaction, and
transferred-statement, direct-helper, same-package-chain, and cross-package-chain
transaction behavior, plus cross-package transaction creation and exact
function-value, object-wrapper, concrete-method, exact local-interface,
constructor/concrete-field, constructor-injected interface, and nested
constructor-interface and constructor-field-write dispatch, including nested
post-construction injection, exact all-path constructor joins, cross-file
constructor parent helpers, imported local-module parent helpers, and imported
constructor-helper field writes, shallow value-copy pointers, and exact helper
two-way, multi-way, expression-switch, expressionless-switch,
initializer-bound-switch, direct interface-type-switch, and bounded aliased
interface-type-switch, exact empty-interface-conversion, and exact named-basic-
interface-conversion, canonical cross-package-interface-conversion,
same-package plus imported embedded-interface-conversion, and exact
type-alias-interface branch joins, plus exact concrete promoted-method dispatch,
without a database service:

```powershell
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/go-http-object-authorization-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-go-http-object-authorization `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep

Push-Location fixtures\go-cross-file-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-list-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-list-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-prepared-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-prepared-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-transaction-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-transaction-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-transaction-stmt-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-transaction-stmt-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-helper-transaction-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-helper-transaction-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-helper-chain-transaction-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-file-safe-helper-chain-transaction-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-helper-transaction-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-helper-transaction-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-transaction-factory-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-transaction-factory-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-transaction-function-value-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-transaction-function-value-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-wrapper-chain-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-wrapper-chain-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-method-interface-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-method-interface-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-constructor-field-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-constructor-field-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-constructor-interface-field-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-constructor-interface-field-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-nested-constructor-interface-field-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-nested-constructor-interface-field-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-constructor-field-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-constructor-field-write-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-constructor-nested-field-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-constructor-nested-field-write-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-constructor-branch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-constructor-branch-write-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-constructor-helper-parent-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-constructor-helper-parent-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-constructor-helper-parent-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-constructor-helper-parent-delete-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-constructor-helper-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-constructor-helper-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-value-copy-pointer-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-value-copy-pointer-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-branch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-branch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-multi-branch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-multi-branch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-switch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-expressionless-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-expressionless-switch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-initialized-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-initialized-switch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-aliased-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-aliased-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-empty-interface-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-empty-interface-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-named-interface-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-named-interface-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-imported-helper-cross-package-interface-type-switch-write-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-imported-helper-cross-package-interface-type-switch-write-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-embedded-interface-type-switch-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-embedded-interface-type-switch-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-type-alias-interface-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-type-alias-interface-authorization
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-promoted-method-delete-idor
go test ./...
Pop-Location
Push-Location fixtures\go-cross-package-safe-promoted-method-authorization
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

The Java path lane carries an annotated Spring request parameter through three
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

The same manifest also contains a second matched pair for
`java.io.File.getName()`. Basename reduction removes ordinary parent prefixes
but preserves the exact value `..`, so the reduced result can still select the
trusted root's parent. The negative control rejects that exact reduced component
before the sink. Its witnesses prove the parent escape, rejection of both `..`
and `nested/..`, and continued access to an allowed basename. Both Spring
fixtures call a package-access static helper in a separate compilation unit.

A third pair applies the same adversarial boundary to exact
`java.nio.file.Path.of`/`Paths.get` construction followed by
`Path.getFileName()`. The last lexical name element remains `..`; a bare
`getFileName` or `getNameCount` call is therefore not accepted as a control.
The matched control compares the same reduced `Path` with exact `Path.of("..")`
before the sink. Its witnesses prove runtime parent escape, exact and nested
parent rejection, and continued access to an allowed name. Both Spring fixtures
use the same project-local cross-file helper boundary, exercising helper-file
reduction evidence and caller-side guard recognition together.

Cross-file summaries remain deliberately narrower than Java compilation. The
caller and helper must share the nearest Maven project or conventional Gradle
project/module; the top-level owner must be unique and resolve through the same
package, one exact single-type import, or its fully qualified name; and the
method must be static and accessible. Exact `build.gradle`, `build.gradle.kts`,
`settings.gradle`, and `settings.gradle.kts` ancestors partition Gradle modules
and nested composite builds, with the deepest marker winning. A direct
cross-module call is admitted only when the caller's own top-level
`dependencies` block contains a literal compile-classpath `api`,
`implementation`, `compileOnly`, or `compileOnlyApi` `project(":path")` edge,
one unique nearest settings build includes that project path, and its
conventional physical directory has exactly one standard build file. Calls
across Maven reactor modules are admitted only for one direct top-level
dependency whose literal `groupId`, `artifactId`, and `version` resolve to a
unique reactor sibling, whose scope is absent/`compile`/`provided`, whose type
is absent/`jar` with no classifier, and whose caller and helper remain under
conventional `src/main/java`. Exact local-parent coordinate inheritance and
literal nested module paths are supported; `dependencyManagement` alone is
not a dependency edge. Calls
across packages additionally require a public top-level type and public method.
Exact official types, an unoverloaded symbol, a straight-line return, fixed
arity, argument position, and value identity remain mandatory. Wildcard custom
imports, duplicate owners across visible modules, undeclared or
reverse-direction siblings, test/runtime-only or transitive configurations,
dynamic Gradle paths or Maven coordinates, managed-only Maven declarations,
classified/non-JAR artifacts, nonstandard production source sets, custom
project-directory/build-file mappings, composite builds, inaccessible or
instance methods, transformations, overlapping reactors, and ambiguity fail
closed.

The deterministic identity gate implements Java's compilation-unit import
precedence. A single-type `Path` or `Paths` import remains exact even when
another compilation unit in the same package declares that simple name; an
on-demand `java.nio.file.*` import is suppressed by the same-package top-level
type. Nested and different-package lookalikes do not suppress the JDK type.
Exact and on-demand static imports of `Path.of` or `Paths.get` are accepted only
without a local method declaration, qualified lookalike call, or competing
same-name static import. Focused negative controls exercise each ambiguity.

Control-flow identity is equally strict. The host credits the exact parent
comparison only when its true branch itself completes abruptly with an
unconditional `return` or `throw` and the check shares the sink's lexical block
path. Negation, `&&`/`||` composition, optional nesting, a caught exception, a
logging-only branch, and an unrelated nearby abrupt statement are rejected as
controls. The vulnerable fixture includes the last adversarial shape: it logs
the exact parent value and has a separate null-state throw before the read, but
its witness still reads the parent secret. The safe fixture rejects the exact
same value in the matching branch.

```powershell
javac -d C:\security-benchmarks\java-path-vulnerable `
  benchmarks\witnesses\java-multi-hop-path-traversal\VulnerablePathWitness.java
java -cp C:\security-benchmarks\java-path-vulnerable VulnerablePathWitness

javac -d C:\security-benchmarks\java-path-safe `
  benchmarks\witnesses\java-multi-hop-safe-path\SafePathWitness.java
java -cp C:\security-benchmarks\java-path-safe SafePathWitness

javac -d C:\security-benchmarks\java-file-name-vulnerable `
  benchmarks\witnesses\java-file-getname-path-traversal\VulnerableFileGetNameWitness.java
java -cp C:\security-benchmarks\java-file-name-vulnerable VulnerableFileGetNameWitness

javac -d C:\security-benchmarks\java-file-name-safe `
  benchmarks\witnesses\java-file-getname-safe-path\SafeFileGetNameWitness.java
java -cp C:\security-benchmarks\java-file-name-safe SafeFileGetNameWitness

javac -d C:\security-benchmarks\java-path-file-name-vulnerable `
  benchmarks\witnesses\java-path-getfilename-path-traversal\VulnerablePathGetFileNameWitness.java
java -cp C:\security-benchmarks\java-path-file-name-vulnerable VulnerablePathGetFileNameWitness

javac -d C:\security-benchmarks\java-path-file-name-safe `
  benchmarks\witnesses\java-path-getfilename-safe-path\SafePathGetFileNameWitness.java
java -cp C:\security-benchmarks\java-path-file-name-safe SafePathGetFileNameWitness
```

Run all six strict cases with:

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

The Razor Pages SQL lane closes the separate model-binding boundary introduced
by `PageModel` handlers. Its positive uses the unannotated `filter` parameter
of named `OnGetLookupAsync`, crosses the same constructor-injected service
boundary, and selects an unauthorized in-memory row through concatenated query
grammar. The control preserves the handler, service, input bytes, and intended
lookup but binds `filter` through a typed `SqlParameter`:

```powershell
dotnet run --project benchmarks/witnesses/aspnet-razor-page-sql-injection/AspnetRazorPageSqlInjectionWitness.csproj --configuration Release
dotnet run --project benchmarks/witnesses/aspnet-razor-page-safe-sql/AspnetRazorPageSafeSqlWitness.csproj --configuration Release
```

Run the strict pair with `aspnet-razor-page-sql-manifest.json`. Its gates require
perfect single-run completion, precision, recall, validation, attack-path,
code-evidence, severity, stability, and negative-control results.

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

The ASP.NET path lane carries the request through three typed service
boundaries between the controller and storage sink. The vulnerable fixture
lets a later rooted `Path.Combine`
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

The Node/Python filesystem-path lane carries one request value through route,
gateway, service, and storage modules. The vulnerable fixtures pass it to the
documented path position of an exact `node:fs/promises` `readFile` binding or
the unshadowed Python `open` builtin and can read the committed parent witness.
The matched controls accept only a server-owned key mapped to a fixed complete
document path. Request data used only as `writeFile` contents or an `open`
encoding is not a path sink. Official aliases, Node namespace/default/CommonJS
receivers, both source and destination copy positions, Python module aliases,
and local/import shadow rejection are covered by deterministic regressions.

Run the strict four-case lane with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/filesystem-path-framework-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-filesystem-path `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The fixture data is itself executable: each vulnerable storage module returns
its language-specific private witness for `../private/deployment-secret.txt`,
while each control rejects that key and still returns the public `welcome`
document. These witnesses exercise actual Node and Linux Python filesystem
semantics without network access or third-party services.

`node-sails-action2-path-manifest.json` adds a strict framework-source pair to
the same exact Node filesystem sink discipline. The positive exports an
Action2 object from `api/controllers`, declares `filename`, binds an explicit
route, and carries `inputs.filename` through multiline `path.join` into
`readFileSync`. The control retains the route, declaration, handler, and
traversal-shaped input but reads the fixed `cover-256.jpg` path. Helpers,
machine-shaped files outside `api/controllers`, undeclared properties,
reassignment, assigned exports, destructuring, function/arrow properties, and
bracket access have direct regression coverage. Concrete findings must prove
the recorded exact custom route or literal blueprint action-route enablement
rather than assuming exposure from a filename.

Run the strict Sails pair with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/node-sails-action2-path-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-sails-action2-path `
  --runs 1 `
  --selection-only `
  --auth github `
  --model gpt-5.6-terra `
  --effort high `
  --workers 2 `
  --mode deep
```

The dependency-free witnesses run with `npm run witness` in each fixture. The
positive reads only its checked-in victim marker; the control proves the same
parent-segment string cannot influence the fixed path. Neither writes or uses
the network.

`node-sails-action2-wrapper-path-manifest.json` extends that source across one
exact relative module call. The controller's declared input reaches the
exported `readThumbnail` parameter and then the same exact Node filesystem path
position. The positive must preserve the custom route, controller property,
relative import, call argument, wrapper parameter, path construction, and sink;
the twin keeps the route and wrapper topology but selects one fixed thumbnail.
Direct regressions also require literal `blueprints.actions: true` for implicit
action routes, reject the documented false default plus false, dynamic,
unrelated, and ambiguous configurations, reject Action2-shaped helpers, and
preserve a two-relative-relay path.

Run the strict routed-wrapper pair with:

```powershell
$env:COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS = '1200000'
node ../../benchmarks/run-benchmark.mjs `
  --manifest ../../benchmarks/node-sails-action2-wrapper-path-manifest.json `
  --results-dir C:\security-benchmarks\copilot-security-sails-action2-wrapper `
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
from-imports and includes multiline parameter-binding counterevidence. Its ten
exploit/control pairs distinguish exact list indexes, dictionary keys, fresh
`types.SimpleNamespace` fields, and generated standard-library dataclass fields
from container- or object-wide taint, plus exact FastAPI/Pydantic request-body
fields from class variables and an exact FastAPI redirect location from a
fixed-local control. The object and dataclass exploits
overwrite and select `command.value`, while their matched controls store the
same hostile value only in `command.audit` and retain the same real
`shell=True` sink. Direct attribute assignment, constant-name `setattr`, dot
selection, and constant-name `getattr` are covered under receiver-sensitive,
field-sensitive, last-write-wins state. The dataclass case additionally
requires an exact non-shadowed `dataclasses.dataclass` decorator, a field-only
class body, declared fields, and complete keyword construction. Defaults,
inheritance, methods, positional or incomplete construction, dynamic fields,
arbitrary objects, alias escape, and ambiguous mutations fail closed. Native
witnesses create only disposable temporary markers. The FastAPI pair uses a
real pinned TestClient request; the positive reads the declared body string
`payload.name`, while the control reads `payload.fixed_command`, an exact
`ClassVar[str]` excluded from the JSON body. Exact official framework imports,
POST/PUT/PATCH/DELETE routes, a field-only `BaseModel`, stable parameters, and
one selected string field are required. GET, dependency/query parameters,
validators/configuration, dynamic `Field` declarations, non-string or private
fields, shadows, mutation, whole-model escape, and ambiguous selection fail
closed. The redirect exploit binds an official
`Annotated[str, Query()]` value to `RedirectResponse(url=...)`; its TestClient
witness disables redirect following and proves only the selected `Location`.
The control encodes the same hostile absolute URL beneath `/continue?next=`.
The redirect model rejects ambiguous Query configuration, extra metadata,
non-string or reassigned parameters, package shadows, replaced response
bindings, duplicate URL roles, and star expansion. It deliberately keeps
`"/" + value` reportable because a leading slash in the value can produce
`//attacker.example`:

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

The Python multi-hop lane inserts public gateway and service relays between the
registered Flask route and sink wrapper. It also exercises bounded multiline
relay calls:

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

The bounded multi-hop lane adds exported gateway and service relays between the
request caller and command or SQL sink wrapper. Its paired negatives retain the
same four-file topology while using bounded shell-free execution or native SQL
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

The runner holds an exclusive `.benchmark-runner.lock` for the complete
campaign operation, including `--finalize-only`. Do not start a second command
against the same results directory: a live owner is reported with its PID and
start time before either process can alter campaign or run output. This matters
after terminal, automation, or CI timeouts because losing the host command does
not prove that its descendant process tree stopped. Check the reported PID or
wait for the first runner instead of deleting a live lock.

If the recorded PID is no longer alive, the next runner verifies that the
bounded, regular lock record is stable, moves it intact under
`.benchmark-runner-locks/`, and acquires a fresh token before continuing.
Malformed, oversized, symbolic-link, permission-denied, or otherwise
unverifiable ownership evidence fails closed and is not removed automatically.
Normal and process-exit cleanup compare the complete ownership record, so a
late cleanup cannot remove another process's replacement lock. Stale archives
are operational evidence and may remain beside `benchmark-campaign.json`.

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
