# Scanner landscape and improvement roadmap

This document records ideas worth adopting from mature security scanners and
the constraints for integrating them without turning Copilot Security into an
unverifiable alert aggregator. It is a living engineering backlog, not a claim
that dissimilar products can be reduced to one score.

## Design principles extracted from other scanners

| Scanner or ecosystem                                                                                                         | Useful design                                                                                                                                                                               | Copilot Security application                                                                                                                                                                    |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)                          | A result is stronger when it explains a source-to-sink path rather than naming only a suspicious line.                                                                                      | Preserve SARIF code-flow locations as source/evidence/sink hints, then independently validate the exact data flow and controls.                                                                 |
| [CodeQL data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)                 | Local and global flow have different precision, performance, and completeness tradeoffs.                                                                                                    | Keep deterministic full-file inventory separate from expensive cross-file/deep passes; report deferred closure rather than silently narrowing scope.                                            |
| [CodeQL custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-cpp/)            | Framework-specific source, sink, summary, barrier, and threat models extend coverage beyond built-in libraries.                                                                             | Emit bounded typed framework hypotheses with exact source/sink lines and context-specific control leads while keeping repository excerpts base64-encoded and requiring independent proof.       |
| [CodeQL C# custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-csharp/)      | C# model packs identify exact callable signatures and argument access paths for sources, summaries, sinks, barriers, and threat models; `SqlCommand` argument zero is a canonical SQL sink. | Resolve exact ASP.NET controller/service argument positions into bounded host hypotheses, preserve type binding and query-text argument roles, and retain parameter binding as counterevidence. |
| [Semgrep taint rules](https://semgrep.dev/docs/writing-rules/glossary)                                                       | Explicit sources, sinks, propagators, and sanitizers make taint assumptions reviewable; cross-file and per-file analysis have distinct guarantees.                                          | Preserve model provenance and demand source/control/sink closure for imported candidates. Build regression fixtures for custom propagators and sanitizers.                                      |
| [Sonar security rules](https://docs.sonarsource.com/sonarqube-server/user-guide/rules/security-related-rules)                | Taint vulnerabilities and review-required security hotspots are different evidence classes. Sonar also supports custom sources, sanitizers, validators, and sinks.                          | Treat all imported results as candidates, not findings. Validation decides reportable, rejected, or deferred; a hotspot cannot inherit vulnerability status merely from its producer.           |
| [OSV-Scanner](https://google.github.io/osv-scanner/usage/) and [call analysis](https://google.github.io/osv-scanner/output/) | Extract dependencies deterministically, match authoritative advisories, and use call information to distinguish called from apparently unused vulnerable code.                              | Add deterministic SBOM/lockfile inventory and advisory ingestion, then use Copilot for repository-specific reachability, compensating controls, and remediation boundary analysis.              |
| [Trivy repository scanning](https://www.trivy.dev/docs/latest/guide/target/repository/)                                      | One repository pass can cover vulnerable dependencies, misconfiguration, secrets, and licenses.                                                                                             | Accept these result families through SARIF now; later add opt-in local adapters while keeping each family’s evidence and completion semantics distinct.                                         |
| [Trivy SARIF reporting](https://trivy.dev/docs/latest/configuration/reporting/)                                              | SARIF 2.1.0 is a practical interchange format across vulnerability, misconfiguration, secret, and license scanners.                                                                         | Implement repeatable `--seed-sarif` intake rather than tool-specific parsers. Preserve normalized provenance and never copy a producer’s conclusion into canonical findings.                    |
| [Trivy secret scanning](https://www.trivy.dev/docs/latest/guide/scanner/secret/)                                             | Built-in and custom rules, allow rules, path bounds, and explicit skip behavior reduce secret-scanning cost and noise.                                                                      | Future deterministic secret discovery must redact values before model access, preserve only local fingerprints, distinguish test fixtures, and make exclusions auditable.                       |
| [Gitleaks](https://github.com/gitleaks/gitleaks)                                                                             | Full redaction, stable fingerprints, baselines, and scoped allowlists make high-volume secret findings manageable.                                                                          | Extend false-positive feedback with expiring, justified fingerprint baselines; never persist or display raw secret material by default.                                                         |
| [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)           | Stable rule IDs, relative paths, locations, severity/precision metadata, and partial fingerprints support interoperable alert tracking.                                                     | Normalize relative paths and rule metadata, but hash source documents locally and omit imported fingerprints because they may contain arbitrary or sensitive producer data.                     |

## Implemented: hardened SARIF seed ingestion

The CLI and SDK accept repeatable `--seed-sarif` / `seedSarifPaths` inputs. The
Windows GUI exposes the same capability. An optional `--sarif-source-root`
maps absolute artifact paths produced from a separate checkout.

The host performs these steps before Copilot sees any imported candidate:

1. Require regular, non-symlink SARIF 2.1.0 files and bounded file, run,
   result, and location counts.
2. Parse strict UTF-8 JSON and reject malformed run or tool structures.
3. Ignore suppressed and baseline-absent results.
4. Map only primary and code-flow locations that resolve to regular files
   inside the current repository, with valid positive line ranges.
5. Extract bounded tool, rule, CWE, severity, and source-to-sink hints.
6. Deliberately omit result messages, source snippets, fixes, fingerprints,
   arbitrary properties, and embedded source. This prevents prompt injection
   and stops secret-scanner matches from becoming model input.
7. Store only normalized candidate JSONL plus source name, SHA-256 digest,
   counts, and tool provenance under the isolated scan artifact tree.
8. Merge every in-scope seed into the normal candidate ledger and require the
   same independent validation and attack-path closure as native discovery.

`benchmarks/sarif-seed-manifest.json` is the initial ensemble lane. Its
positive case should retain a seeded command injection; its negative case
feeds a high-severity false-positive process-execution seed that must be
rejected. Both source SARIF files contain hostile messages and fake credential
text, allowing artifact inspection to prove that the host removed those fields
before model execution.

The import does not execute another analyzer, trust imported severity, or
claim that a seeded tool completed its own coverage. Native inventory,
multi-pass discovery, residual-miss review, negative controls, deterministic
contract validation, and sealed outputs remain mandatory.

## Implemented: typed framework data-flow hypotheses

The mandatory host residual pass now has an initial provider-neutral model pack
for Node HTTP, Python web, Spring/servlet, and ASP.NET command execution and raw
SQL, plus Node and Python server-side request forgery and server-side template
injection. Same-file models activate
when their language, request-source syntax, and concrete runtime or sink API are
present in one bounded source file. The bounded Java cross-file layer resolves
unique service types from controller fields, parses public and protected method
bodies, and preserves exact annotated-parameter or servlet-assignment flow into
the service wrapper. The bounded C# layer applies the same unique-type and
exact-argument discipline to class, record, or struct receivers; public,
protected, or internal controller and service methods; ASP.NET bound parameters
or assigned request fields; and `ProcessStartInfo`/`Process.Start` or raw SQL
query-text sinks. Bounded Node/TypeScript and Python cross-file layers
additionally resolve explicit repository-relative imports
into exported or public module-level wrappers and preserve the exact
argument-to-parameter position. Node/TypeScript follows either one direct
wrapper or exactly one exported relay before the sink wrapper. Python follows
either one direct relative from-import or exactly one public module-level relay
and parses bounded complete relay and sink calls so multiline forwarding,
parameter binding, and outbound request calls remain visible. The host masks
language string and comment contents before structural matching while retaining
exact JavaScript template and Python f-string expressions only for
sink-parameter reference checks, and emits:

- a stable model id and language;
- the exact modeled source kind and line;
- the exact modeled sink kind, line, and CWE family;
- nearby candidate controls such as argument-vector construction, no-shell
  execution, SQL parameter binding, typed query construction, or bounded
  allowlists;
- separately base64-encoded source and sink evidence windows.
- for cross-file rows, every ordered relative import, caller, argument
  position, exported parameter declaration, wrapper, and sink path/line.

This is deliberately a high-recall hypothesis, not a taint verdict. The
quality-gate prompt requires same-value tracing across assignments, wrappers,
parsers, and transformations. A candidate control must apply to the same value,
be correct for the consuming interpreter, and dominate the sink. API
co-occurrence, annotations, and unused request values must be rejected.

`benchmarks/framework-model-manifest.json` pairs command and SQL positives with
shell-free and parameter-bound negatives. Its thresholds require perfect
completion, precision, recall, evidence, validation, attack-path, severity, and
negative-case performance for the selected single-run diagnostic.

`benchmarks/cross-file-framework-manifest.json` applies the same gates to
request values that cross imported command and SQL wrapper boundaries. Its
negative cases prove that a fixed shell-free executable and native SQL
parameter binding remain safe across the same module boundary.

`benchmarks/multi-hop-framework-manifest.json` applies the gates to three-file
caller-to-relay-to-sink chains. Fixed arguments, relay reassignment, calls
outside the exported relay, comments, and string examples are deterministic
negative controls rather than propagators.

`benchmarks/python-cross-file-framework-manifest.json` applies the same strict
gates to Flask request values crossing relative Python imports into command and
SQL wrappers. The negative cases preserve fixed shell-free execution and
multiline DB-API parameter binding. Deterministic tests also reject fixed
arguments, reassignment after request input, ambiguous absolute imports,
comments, and string-only pseudo-calls. The SQL expectation accepts medium
severity because the fixture proves unauthorized row selection but deliberately
does not invent authentication, write, sensitive-column, or deployment impact.

`benchmarks/python-multi-hop-framework-manifest.json` adds a public Python
service relay between each registered Flask route and its command or SQL sink
wrapper. The host emits all six ordered import, call-argument, and parameter
propagators. Paired negatives prove shell-free argument-vector execution and
native SQL parameter binding remain safe, while deterministic controls reject
fixed relay arguments, relay reassignment, calls outside the relay, private
relays, absolute imports, and docstring pseudo-flows.

`benchmarks/ssrf-framework-manifest.json` applies the same strict gates to Node
and Python relative-import HTTP wrappers. Positive cases expose complete
caller-controlled URLs to `fetch` or `requests`; negative cases map the
untrusted label to one of a bounded set of complete server-owned URLs and
disable redirects. Both sides impose the same request deadline and decoded-body
ceiling, keeping upstream resource exhaustion from confounding the SSRF result.
The model records exact parsed-host membership, fixed
destination selection, redirect rejection, and address validation or pinning
only as candidate controls requiring same-value and dominance proof. It does
not label URL or hostname substring checks as exact-host controls, following
the bypass boundary documented by CodeQL's
[incomplete URL substring sanitization](https://codeql.github.com/codeql-query-help/javascript/js-incomplete-url-substring-sanitization/)
guidance. The sink family follows the path-query treatment in CodeQL's
[JavaScript SSRF query](https://codeql.github.com/codeql-query-help/javascript/js-request-forgery/)
and Python's separate full/partial SSRF flow model.

`benchmarks/template-injection-framework-manifest.json` adds strict Node/Pug
and Python/Jinja template-source injection lanes. Positive request values cross
a relative import into `pug.compile` or `render_template_string`. Negative
controls preserve the same request and wrapper topology while compiling only a
fixed server-owned template and passing the untrusted value through an explicit
escaped render-data field. This follows CodeQL's high-precision distinction
between attacker-controlled template grammar and fixed-template data binding
for [Java server-side template injection](https://codeql.github.com/codeql-query-help/java/java-server-side-template-injection/)
and [JavaScript code/template injection](https://codeql.github.com/codeql-query-help/javascript/js-code-injection/).
The host retains fixed-template and sandbox leads as candidate controls, while
the correction gate must prove exact sink argument roles and sandbox dominance.

`benchmarks/java-cross-file-template-manifest.json` extends the strict lane to
constructor-injected Spring services. The positive carries an annotated request
parameter into the fourth, template-source argument of Apache Velocity
`evaluate`; the negative keeps the same type binding and service call while
HTML-encoding the request value into `VelocityContext` and evaluating fixed
source. The encoding is necessary because fixed source disproves SSTI but raw
Velocity context data can still produce reflected XSS.
This follows CodeQL's high-precision, interprocedural
[Java server-side template-injection query](https://codeql.github.com/codeql-query-help/java/java-server-side-template-injection/),
which assigns the family security severity 9.3 and treats fixed template source
as the principal counterexample. The shared Java method-flow layer also feeds
the existing Spring command and raw-SQL models.

`benchmarks/aspnet-cross-file-framework-manifest.json` adds strict ASP.NET
command and raw-SQL lanes. The command positive carries a `[FromQuery]` value
through a constructor-injected service into the `cmd.exe /c` grammar; its
control starts a fixed executable with `UseShellExecute=false` and preserves
the value as one `ArgumentList` entry. The SQL positive carries the request
value into the first, query-text argument of `SqlCommand`; its control keeps
the query fixed and binds a bounded typed `SqlParameter`. The host masks C#
comments and string contents, rejects fixed or reassigned caller arguments and
duplicate simple service types, and emits exact type, call-argument, and
wrapper-parameter propagators. This follows CodeQL's high-precision
[C# command-line injection path query](https://codeql.github.com/codeql-query-help/csharp/cs-command-line-injection/)
and its documented
[C# `SqlCommand` sink model](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-csharp/).

## Prioritized next improvements

1. **Expand typed framework security models.** Extend bounded summaries beyond
   two Node/TypeScript or Python relative-import hops; extend Java beyond one
   uniquely typed service boundary; extend ASP.NET beyond one uniquely typed
   service boundary; add framework-specific authorization models, ASP.NET
   template models, broader
   outbound-client and partial-URL SSRF models,
   manifest-derived activation evidence,
   and signed or hashed external model packs. Benchmark every extension against
   paired positive and negative fixtures.
2. **Dependency and advisory reachability.** Build deterministic lockfile/SBOM
   extraction, accept OSV identifiers and fixed-version facts, and require a
   repository call/use path or explicit deployment exposure before escalating
   severity. Preserve uncalled/unknown rather than equating both with safe.
3. **Local secret candidate engine.** Run deterministic pattern and entropy
   checks without sending secret bytes to Copilot. Persist a keyed local
   fingerprint, rule, path, line, and redacted shape only. Support expiring
   justified baselines and negative-control fixtures.
4. **Configuration and IaC model packs.** Add deterministic parsers and typed
   checks for high-value Docker, Kubernetes, Terraform, CI, and cloud policy
   surfaces, then ask Copilot to evaluate deployment reachability and
   compensating controls.
5. **Seed-coverage receipts.** Make imported-candidate closure a workbench
   contract field, not only a ledger invariant, so a future host can prove the
   exact imported count that was reportable, rejected, deferred, or out of
   scope without relying on prose.
6. **Ensemble benchmark lanes.** Run native-only and native-plus-seed campaigns
   over the same selected manifest. Gate the integration on improved recall or
   completion without precision, evidence, validation, attack-path, stability,
   or negative-control regressions.
7. **Optional analyzer adapters.** Provide opt-in command adapters that invoke
   a locally installed analyzer with argument arrays, resource/time bounds,
   no shell, no network by default, and SARIF-only handoff. Keep analyzer
   installation and licensing outside the core scanner.

## Benchmark acceptance criteria

An integration is useful only when its comparative campaign demonstrates all
of the following:

- no decline in completion rate or negative-control pass rate;
- no precision or duplicate-rate regression outside configured tolerance;
- statistically useful recall or first-attempt recall improvement;
- every new true positive retains concrete code evidence, independent
  validation, and attack-path closure;
- imported false positives receive explicit rejected dispositions rather than
  disappearing during merge;
- repeated runs remain stable enough that improvement is not one lucky model
  sample; and
- source provenance, selection policy, model, scanner revision, and seed
  digests are recorded so the campaign can be reproduced.
