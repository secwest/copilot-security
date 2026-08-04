# Scanner landscape and improvement roadmap

This document records ideas worth adopting from mature security scanners and
the constraints for integrating them without turning Copilot Security into an
unverifiable alert aggregator. It is a living engineering backlog, not a claim
that dissimilar products can be reduced to one score.

## Design principles extracted from other scanners

| Scanner or ecosystem                                                                                                                                                                                                                                                                                                                                                                                       | Useful design                                                                                                                                                                                                                                                                                                                   | Copilot Security application                                                                                                                                                                                                                                                                     |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)                                                                                                                                                                                                                                                                                                        | A result is stronger when it explains a source-to-sink path rather than naming only a suspicious line.                                                                                                                                                                                                                          | Preserve SARIF code-flow locations as source/evidence/sink hints, then independently validate the exact data flow and controls.                                                                                                                                                                  |
| [CodeQL data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)                                                                                                                                                                                                                                                                                               | Local and global flow have different precision, performance, and completeness tradeoffs.                                                                                                                                                                                                                                        | Keep deterministic full-file inventory separate from expensive cross-file/deep passes; report deferred closure rather than silently narrowing scope.                                                                                                                                             |
| [CodeQL custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-cpp/)                                                                                                                                                                                                                                                                                          | Framework-specific source, sink, summary, barrier, and threat models extend coverage beyond built-in libraries.                                                                                                                                                                                                                 | Emit bounded typed framework hypotheses with exact source/sink lines and context-specific control leads while keeping repository excerpts base64-encoded and requiring independent proof.                                                                                                        |
| [OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), and [Prisma single-record filters](https://docs.prisma.io/docs/orm/reference/prisma-client-reference)                                                                                                                         | Object authorization requires permission for the exact requested action on the exact object selected by a client-controlled key. Authentication and opaque IDs are insufficient; single-record filters may add non-unique permission dimensions.                                                                                | Preserve the request object reference into the lookup argument, retain principal-bound owner/tenant filtering or a dominating check on the returned object as control leads, and require the reviewer to prove disclosure/mutation plus missing permission.                                      |
| [CodeQL Java custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-java-and-kotlin/)                                                                                                                                                                                                                                                                         | Java model packs identify typed sources, sinks, summaries, and barriers at exact callable and argument positions.                                                                                                                                                                                                               | Resolve exact Spring/servlet request values and uniquely typed service calls before proposing a Java framework flow; reject ambiguous receiver types instead of guessing.                                                                                                                        |
| [CodeQL Java SSRF](https://codeql.github.com/codeql-query-help/java/java-ssrf/), [Spring WebClient](https://docs.spring.io/spring-framework/reference/web/webflux-webclient.html), [OkHttp calls](https://square.github.io/okhttp/5.x/okhttp/okhttp3/-ok-http-client/), and [JDK redirect policy](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Redirect.html) | High-precision Java SSRF analysis tracks request data into outbound clients; WebClient delegates transport behavior to its configured connector; OkHttp separates request construction, call preparation, and dispatch; server-owned authorized URLs are preferred, and redirect policy applies only after the initial request. | Track Spring/servlet values across typed Java services into JDK `HttpClient`, `RestTemplate`, reactive `WebClient`, and executed OkHttp requests, while keeping fixed complete destination selection, connector redirect rejection, dispatch, and address pinning as distinct proof obligations. |
| [CodeQL JavaScript request forgery](https://codeql.github.com/codeql-query-help/javascript/js-request-forgery/) and [Axios request configuration](https://axios-http.com/docs/req_config)                                                                                                                                                                                                                  | JavaScript SSRF includes attacker control of outbound URLs. Axios prepends `baseURL` to relative URLs, permits absolute URLs to override it by default, and exposes separate absolute-override and redirect controls.                                                                                                           | Prove the `axios` package binding or non-reassigned created client, track only the URL argument/configuration property, and keep fixed selection, authority confinement, relative-path validation, redirects, and address pinning as separate proof obligations.                                 |
| [CodeQL Java partial path traversal](https://codeql.github.com/codeql-query-help/java/java-partial-path-traversal/) and [Oracle path operations](https://docs.oracle.com/javase/tutorial/essential/io/pathOps.html)                                                                                                                                                                                        | Java path security depends on component-aware containment and real filesystem semantics: normalization is syntactic, absolute resolution can replace the base, and string prefixes admit sibling names.                                                                                                                         | Track Java web input into typed JDK filesystem APIs, retain absolute rejection, `Path.startsWith`, normalization, and `toRealPath` as separate proof leads, and require parent, absolute-reset, sibling, and link witnesses.                                                                     |
| [CodeQL C# custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-csharp/)                                                                                                                                                                                                                                                                                    | C# model packs identify exact callable signatures and argument access paths for sources, summaries, sinks, barriers, and threat models; `SqlCommand` argument zero is a canonical SQL sink.                                                                                                                                     | Resolve exact ASP.NET controller/service argument positions into bounded host hypotheses, preserve type binding and query-text argument roles, and retain parameter binding as counterevidence.                                                                                                  |
| [CodeQL missing function-level access control](https://codeql.github.com/codeql-query-help/csharp/cs-web-missing-function-level-access-control/), [ASP.NET Core resource authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resource-based), and [EF Core `FindAsync`](https://learn.microsoft.com/en-us/ef/core/change-tracking/entity-entries#find-and-findasync)       | Function-level authorization is a useful medium-precision signal, but ASP.NET documents that declarative authorization occurs before resource loading and is insufficient for resource decisions. EF Core primary-key lookup selects one entity without an ownership predicate.                                                 | Keep endpoint authorization out of the object-control set; preserve a bound request ID into a typed EF lookup and retain only a principal-bound query predicate or enforced `AuthorizeAsync(User, exactEntity, policy)` result as resource-level control evidence.                               |
| [CodeQL C# path injection](https://codeql.github.com/codeql-query-help/csharp/cs-path-injection/) and [.NET CA3003](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3003)                                                                                                                                                                                              | High-precision web-request-to-filesystem path analysis must preserve path construction and distinguish exact allowlists or canonical containment from normalization alone.                                                                                                                                                      | Track ASP.NET input across uniquely typed services into `System.IO` paths, retain rooted-input and canonical-relative controls, and require witnesses for parent, absolute-reset, and sibling-prefix cases.                                                                                      |
| [Semgrep taint rules](https://semgrep.dev/docs/writing-rules/glossary)                                                                                                                                                                                                                                                                                                                                     | Explicit sources, sinks, propagators, and sanitizers make taint assumptions reviewable; cross-file and per-file analysis have distinct guarantees.                                                                                                                                                                              | Preserve model provenance and demand source/control/sink closure for imported candidates. Build regression fixtures for custom propagators and sanitizers.                                                                                                                                       |
| [Sonar security rules](https://docs.sonarsource.com/sonarqube-server/user-guide/rules/security-related-rules)                                                                                                                                                                                                                                                                                              | Taint vulnerabilities and review-required security hotspots are different evidence classes. Sonar also supports custom sources, sanitizers, validators, and sinks.                                                                                                                                                              | Treat all imported results as candidates, not findings. Validation decides reportable, rejected, or deferred; a hotspot cannot inherit vulnerability status merely from its producer.                                                                                                            |
| [OSV-Scanner](https://google.github.io/osv-scanner/usage/) and [call analysis](https://google.github.io/osv-scanner/output/)                                                                                                                                                                                                                                                                               | Extract dependencies deterministically, match authoritative advisories, and use call information to distinguish called from apparently unused vulnerable code.                                                                                                                                                                  | Add deterministic SBOM/lockfile inventory and advisory ingestion, then use Copilot for repository-specific reachability, compensating controls, and remediation boundary analysis.                                                                                                               |
| [Trivy repository scanning](https://www.trivy.dev/docs/latest/guide/target/repository/)                                                                                                                                                                                                                                                                                                                    | One repository pass can cover vulnerable dependencies, misconfiguration, secrets, and licenses.                                                                                                                                                                                                                                 | Accept these result families through SARIF now; later add opt-in local adapters while keeping each family’s evidence and completion semantics distinct.                                                                                                                                          |
| [Trivy SARIF reporting](https://trivy.dev/docs/latest/configuration/reporting/)                                                                                                                                                                                                                                                                                                                            | SARIF 2.1.0 is a practical interchange format across vulnerability, misconfiguration, secret, and license scanners.                                                                                                                                                                                                             | Implement repeatable `--seed-sarif` intake rather than tool-specific parsers. Preserve normalized provenance and never copy a producer’s conclusion into canonical findings.                                                                                                                     |
| [Trivy secret scanning](https://www.trivy.dev/docs/latest/guide/scanner/secret/)                                                                                                                                                                                                                                                                                                                           | Built-in and custom rules, allow rules, path bounds, and explicit skip behavior reduce secret-scanning cost and noise.                                                                                                                                                                                                          | Future deterministic secret discovery must redact values before model access, preserve only local fingerprints, distinguish test fixtures, and make exclusions auditable.                                                                                                                        |
| [Gitleaks](https://github.com/gitleaks/gitleaks)                                                                                                                                                                                                                                                                                                                                                           | Git-patch history scanning, full redaction, stable fingerprints, baselines, and scoped allowlists make high-volume secret findings manageable.                                                                                                                                                                                  | Scan bounded reachable Git blobs locally through a trusted executable, deduplicate revision occurrences, use expiring justified keyed baselines, and never persist or display raw secret material.                                                                                               |
| [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)                                                                                                                                                                                                                                                                                         | Stable rule IDs, relative paths, locations, severity/precision metadata, and partial fingerprints support interoperable alert tracking.                                                                                                                                                                                         | Normalize relative paths and rule metadata, but hash source documents locally and omit imported fingerprints because they may contain arbitrary or sensitive producer data.                                                                                                                      |

## Implemented: bounded reachable-Git secret history

Gitleaks scans Git patches, GitHub scans all branches in repository history,
and TruffleHog treats version history plus deduplication metadata as a distinct
secret source. Copilot Security now covers the same deleted-credential class
without installing or trusting another analyzer and without copying raw values
into model context.

The host resolves Git outside the protected repository, strips ambient
`GIT_*` controls, disables global/system configuration, replacement objects,
lazy object fetching, pagers, and optional locks, and never checks out a
historical tree. It enumerates the newest bounded reachable commit set across
refs, maps safe repository-relative object paths, batch-checks type and size,
and then batch-reads only bounded nonbinary blobs. Unique blob contents are
scanned once. Repeated rule/path/value identities aggregate up to eight opaque
blob IDs while retaining the full bounded object count; the HMAC identity and
expiring exact baseline remain shared with the working-tree lane.

The default horizon is 128 commits, `0` disables history, and 2048 is the hard
maximum. Independent caps cover enumeration bytes, objects, blobs, blob bytes,
total content, candidate occurrences, command time, and retained provenance.
Every cutoff, missing trusted Git executable, malformed object response, or
unavailable reachable object produces an explicit partial/error history state
and sets overall truncation, so it cannot support a clean history-wide claim.
Non-Git directories remain a distinct complete `not_git_repository` state.

Historical candidate rows contain `source=git_history`, exact path and line in
the blob, redacted shape, repository-scoped keyed fingerprint, and bounded
immutable object IDs. The quality prompt forbids `git show`, `cat-file`, patch
logs, or source views merely to recover candidate bytes and forbids claiming
the credential is live without separate safe validation. Operators receive
revocation and reachable-history cleanup guidance instead of the value.

`benchmarks/secret-history-manifest.json` commits and deletes three positive
credential families and two controls in a private temporary repository. It
requires perfect precision/recall, revision deduplication, history-only
classification, and zero candidate-byte occurrence in both inventory and
report. Separate regressions prove horizon, exact scoped-path, disabled,
non-Git, unavailable-Git, and numeric-bound behavior.

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
for Node HTTP, Python web, Spring/servlet, and ASP.NET command execution, raw
SQL, server-side request forgery, filesystem path injection, and Node plus
ASP.NET object authorization, plus Node and Python server-side request forgery
and server-side template injection. Same-file models activate
when their language, request-source syntax, and concrete runtime or sink API are
present in one bounded source file. The bounded Java cross-file layer resolves
unique service types from controller fields, parses public and protected method
bodies, and preserves exact annotated-parameter or servlet-assignment flow into
either one direct service wrapper or exactly one additional uniquely typed
service relay. It records both receiver type bindings and exact argument and
parameter positions, including bounded local URI, request-object, and path
assignments into typed JDK filesystem, JDK `HttpClient`, Spring
`RestTemplate`, reactive `WebClient.UriSpec.uri`, or OkHttp
`Request.Builder.url` sinks. The WebClient model
resolves typed root clients through fluent chains or request-spec aliases and
keeps later fixed-template variables separate from the destination argument.
The OkHttp model additionally binds the built `Request` to a typed
`OkHttpClient.newCall` and requires `execute` or `enqueue`, so request
construction and call preparation alone do not become findings.
The bounded C# layer applies the same unique-type and
exact-argument discipline to class, record, or struct receivers; public,
protected, or internal controller and service methods; ASP.NET bound parameters
or assigned request fields; and `ProcessStartInfo`/`Process.Start`, raw SQL
query-text, complete `HttpClient` request-URI, or typed `System.IO` path sinks.
The C# layer now follows either one direct service wrapper or exactly one
additional uniquely typed service relay and records both type bindings and
argument positions. Bounded Node/TypeScript and Python cross-file layers
additionally resolve explicit repository-relative imports
into exported or public module-level wrappers and preserve the exact
argument-to-parameter position. Node/TypeScript follows either one direct
wrapper or exactly one exported relay before the sink wrapper. Axios calls are
accepted only through a real package binding or bounded non-reassigned
`axios.create(...)` instance, and only the URL argument or request-config
`url` property participates in destination flow. This avoids both literal
receiver false negatives and generic `.get`/`.post` or body-only false
positives. Python follows
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

Wrapper and relay summaries are enumerated across the complete bounded host
snapshot before reachability and final candidate selection, preventing a large
prefix of unrelated wrappers from hiding later Java, C#, JavaScript, or Python
sinks. The C# path model also reads the nearest project and applicable MSBuild
property metadata for `ImplicitUsings`, plus project-wide global usings, while
preserving local `File`/`FileStream` shadow rejection.

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

`benchmarks/node-object-authorization-manifest.json` applies perfect gates to
the existing same-file invoice IDOR/control pair and a new relative-module
repository pair. The host preserves the exact request object reference,
wrapper argument, wrapper parameter, and record lookup. A principal-bound
owner/tenant/account/customer/user/organization/workspace filter in the same
query or a bounded post-lookup check on the returned object is retained only as
counterevidence for independent review. Fixed and unused IDs, reassignment,
attacker-controlled owner filters, unrelated principal text, random UUIDs,
authentication alone, comments, and strings do not close authorization.
Bounded multiline exported declarations and calls keep ordinary formatter
output visible across every Node framework model.

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

`benchmarks/node-axios-ssrf-manifest.json` isolates Axios receiver identity and
destination argument roles. The positive carries an absolute request value
through a relative-module wrapper into a created client: its fixed `baseURL`
does not prevent the absolute URL from overriding the authority under Axios's
default configuration. The negative selects a server-owned relative path by
exact key, sets `allowAbsoluteUrls: false`, and disables redirects. Regression
controls reject local shadows, body-only POST flow, reassigned instances, and
comment-only imports or configuration. Absolute-URL rejection is retained as
an authority control rather than being promoted into relative-path traversal
or endpoint-authorization proof.

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

`benchmarks/java-multi-hop-path-manifest.json` adds a strict three-file Spring
path lane. The positive carries an annotated request value across a controller,
service, and store into typed `java.nio.file.Files.readString`; untrusted parent
components or an absolute later `Path.resolve` operand can escape the configured
root. The negative preserves the topology while rejecting absolute input,
checking normalized component-aware containment, resolving the existing root
and target through `toRealPath`, and checking real containment before the read.
Pure-JDK witnesses prove parent traversal, absolute-root reset, sibling-prefix
rejection, symbolic-link rejection where supported, and an allowed in-root
read. This follows CodeQL's [Java partial path-traversal query](https://codeql.github.com/codeql-query-help/java/java-partial-path-traversal/)
and Oracle's [path-operations semantics](https://docs.oracle.com/javase/tutorial/essential/io/pathOps.html).
The host treats these operations as candidate evidence, not automatic safety:
normalization cannot resolve links, string prefix checks are not component
checks, and link-capable or concurrently mutable roots require stronger
filesystem-boundary proof.

`benchmarks/java-multi-hop-ssrf-manifest.json` adds a strict three-file Spring
outbound-request lane. The positive carries an annotated request value through
a controller, service, and transport, constructs a JDK `HttpRequest` from the
complete caller-controlled URI, and sends it through a typed `HttpClient`. The
negative preserves the topology and request construction but uses the request
value only as an exact key into fixed server-owned complete destinations and
requires `HttpClient.Redirect.NEVER`. Pure-JDK loopback witnesses prove that
the positive reaches a private service while the control rejects the complete
URI before transport and still permits the fixed key. This follows CodeQL's
high-precision, default-suite [Java SSRF query](https://codeql.github.com/codeql-query-help/java/java-ssrf/),
which assigns security severity 9.1 and recommends server-owned authorized
URLs, plus the JDK's documented [redirect-policy boundary](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Redirect.html).
The host records redirect rejection only as a candidate control: it does not
authorize the initial destination or close DNS rebinding, proxies, connection
reuse, final socket addressing, or Host/TLS identity.

`benchmarks/java-webclient-ssrf-manifest.json` extends the strict Java SSRF
lane to Spring's reactive `WebClient`. The positive carries the annotated
request value through the same controller, service, and transport topology into
the first `UriSpec.uri` argument. The negative preserves that topology but maps
the value to one fixed complete URI, configures a `JdkClientHttpConnector` with
`HttpClient.Redirect.NEVER`, releases the response body, and applies a short
reactive timeout. Maven-executed loopback witnesses exercise the actual
WebClient. This follows Spring's documented
[`WebClient` transport abstraction](https://docs.spring.io/spring-framework/reference/web/webflux-webclient.html)
and [`UriSpec` absolute-URI boundary](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/reactive/function/client/WebClient.UriSpec.html).
The host treats redirect policy as connector evidence, not initial-destination
authorization, and requires exact authority tracing rather than flagging later
variables applied to a fixed URI template.

`benchmarks/java-okhttp-ssrf-manifest.json` adds an execution-aware OkHttp
lane. The positive carries the same annotated value through two typed service
boundaries into `Request.Builder.url`, binds that exact request to a typed
`OkHttpClient.newCall`, and executes it. The negative maps the request value to
one server-owned complete URL by exact key and disables both HTTP and HTTPS
redirect following. OkHttp 5.3.0 loopback witnesses prove that the vulnerable
complete URL reaches a private service while the control rejects it before
request construction. The model covers imported and fully qualified request
types, fluent and builder-alias construction, and inline execution. It rejects
inert builders, calls prepared without `execute` or `enqueue`, unrelated URL
builders, reassigned input, and locally shadowed `Request` or `OkHttpClient`
types. This follows OkHttp's documented separation between
[`Request.Builder.url`](https://square.github.io/okhttp/3.x/okhttp/okhttp3/class-use/Request.Builder.html),
[`newCall`](https://square.github.io/okhttp/5.x/okhttp/okhttp3/-ok-http-client/),
and execution, plus CodeQL's recommendation to select server-owned authorized
URLs. Redirect rejection remains response-policy evidence rather than
authorization of the initial destination, and custom DNS remains only a lead
until final address and connection binding are proven.

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

`benchmarks/aspnet-object-authorization-manifest.json` adds a strict EF Core
resource-authorization pair. The positive carries a `[FromRoute]` invoice ID
through a uniquely resolved repository into a typed `DbSet.FindAsync` lookup;
the controller's `[Authorize]` attribute deliberately remains common
counterexample evidence rather than a resource control. The negative preserves
the same route, repository, database entity, and runtime provider while adding
the authenticated customer ID to the exact `SingleOrDefaultAsync` predicate.
Real EF Core InMemory witnesses prove cross-customer disclosure in the positive
and rejection in the control. Focused regressions also require an exact
`IAuthorizationService` receiver, exact returned entity argument, a checked
`Succeeded` result, and a fail-closed denial branch before retaining imperative
resource authorization. Untyped lookalikes, local EF shadows, fixed or
reassigned identifiers, attacker-owned customer filters, `[Authorize]`, wrong
resources, ignored policy results, comments, and strings remain negative cases.

`benchmarks/aspnet-cross-file-ssrf-manifest.json` adds a strict outbound-client
pair. The positive sends an ASP.NET query parameter as the complete URI to
`HttpClient.GetAsync`; its request deadline and response ceiling isolate SSRF
from resource exhaustion without changing destination control. The negative
uses the same controller/service topology but accepts only an exact key into a
server-owned map of complete HTTPS URIs and disables redirects. In-memory
`HttpMessageHandler` witnesses prove that the positive reaches a link-local
attacker URI while the control rejects that same string before transport. This
adopts CodeQL's high-precision distinction between attacker-controlled URL
authority and fixed destination selection from its
[JavaScript SSRF path query](https://codeql.github.com/codeql-query-help/javascript/js-request-forgery/),
and preserves .NET's documented default redirect behavior from
[HttpClientHandler.AllowAutoRedirect](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.allowautoredirect).

`benchmarks/aspnet-multi-hop-path-manifest.json` adds a strict three-file path
lane. The positive carries `[FromQuery]` data through a controller, facade, and
storage service into `Path.Combine` and `File.ReadAllTextAsync`; both parent
components and a rooted later argument escape the configured content root.
The negative preserves that topology but rejects rooted input, resolves the
root and candidate with `Path.GetFullPath`, and uses `Path.GetRelativePath` to
reject an exact parent-directory boundary rather than relying on a vulnerable
bare string prefix. Witnesses prove parent traversal, rooted reset,
sibling-prefix rejection, and an allowed in-root read. This follows CodeQL's
high-precision [C# path-injection query](https://codeql.github.com/codeql-query-help/csharp/cs-path-injection/),
Microsoft's HTTP-to-file-operation model in
[CA3003](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3003),
and the documented rule that a rooted later argument causes
[`Path.Combine`](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine)
to discard earlier components. Lexical containment is recorded as
counterevidence only under a server-owned content-root assumption; writable
links, junctions, reparse points, and rename races remain a separate boundary.

`benchmarks/aspnet-template-framework-manifest.json` adds a typed ASP.NET
Scriban lane where the positive carries `[FromBody]` data through a uniquely
resolved constructor-injected service into the first `Template.Parse`
argument and subsequent `Render` dispatch. Inert parsing is rejected. The
executable witness renders `{{ api_key }}` and proves disclosure
of a server-owned model value. The matching control preserves the controller,
service, secret-bearing render model, and attacker delimiter text, but parses
only fixed server-owned source; the delimiter remains ordinary render data and
the secret is not disclosed. The model rejects the optional source-file-name
argument, reassignment, local `Template` shadows, missing Scriban imports, and
comment or string examples. This extends CodeQL's high-precision
[Java template-injection distinction](https://codeql.github.com/codeql-query-help/java/java-server-side-template-injection/)
between attacker-controlled template code and a fixed template to a C# engine
boundary that the documented C# query set does not presently list. The sink
shape and render semantics follow Scriban's
[official package and API documentation](https://www.nuget.org/packages/Scriban/),
with fixtures pinned to non-vulnerable Scriban 7.2.5.

`benchmarks/aspnet-razorlight-template-framework-manifest.json` extends the
same strict ASP.NET lane to RazorLight runtime compilation. The typed model
requires a proven `IRazorLightEngine` or `RazorLightEngine` receiver and treats
only `CompileRenderStringAsync`'s second `content` argument as template source.
The first template key and third model argument retain their distinct roles,
including when C# named arguments are reordered. `CompileRenderAsync(key,
model)` resolves a project-owned template and is deliberately excluded. The
positive fixture compiles attacker `@Model.ApiKey` source and the executable
witness proves disclosure of a server-owned model property. The matched
control compiles fixed source and passes that same text only as `Model.Name`,
where it remains ordinary encoded data. The model also rejects reassignment,
untyped receivers, local engine shadows, incomplete builders, and comment or
string lookalikes. Argument order and runtime-compilation behavior follow the
[official RazorLight interface and documentation](https://github.com/toddams/RazorLight/blob/master/src/RazorLight/IRazorLightEngine.cs),
with fixtures pinned to the official RazorLight 2.3.1 package and explicit
patched .NET 8 dependency floors for its legacy caching and JSON transitives.

## Prioritized next improvements

1. **Expand typed framework security models.** Extend bounded summaries beyond
   two Node/TypeScript or Python relative-import hops; extend Java and ASP.NET
   beyond two uniquely typed service boundaries;
   extend framework-specific authorization models beyond the bounded Node and
   ASP.NET object-reference lanes, add ASP.NET template engines
   beyond the typed Scriban and RazorLight lanes,
   outbound-client APIs beyond JDK `HttpClient`, Spring `RestTemplate`,
   Spring `WebClient`, OkHttp, Axios, and .NET `HttpClient`, partial-URL SSRF models,
   manifest-derived activation evidence,
   and signed or hashed external model packs. Benchmark every extension against
   paired positive and negative fixtures.
2. **Dependency and advisory reachability.** Build deterministic lockfile/SBOM
   extraction, accept OSV identifiers and fixed-version facts, and require a
   repository call/use path or explicit deployment exposure before escalating
   severity. Preserve uncalled/unknown rather than equating both with safe.
3. **Local secret candidate engine — shipped.** Deterministic typed-pattern and
   entropy checks now run before Copilot, persist only repository-scoped keyed
   fingerprints and redacted structural evidence, enforce exact expiring
   justified baselines, and gate a fragment-materialized positive/negative
   corpus at perfect precision and recall. Bounded reachable-Git object scanning
   now finds deleted credentials, deduplicates revision provenance, and has its
   own real-history exploit/control gate. Next extensions should add audited
   custom-rule packs and separately authorized issuer verification without
   weakening the no-plaintext persistence or no-implicit-network contracts.
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
