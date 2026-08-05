# Scanner landscape and improvement roadmap

This document records ideas worth adopting from mature security scanners and
the constraints for integrating them without turning Copilot Security into an
unverifiable alert aggregator. It is a living engineering backlog, not a claim
that dissimilar products can be reduced to one score.

## Design principles extracted from other scanners

| Scanner or ecosystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Useful design                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Copilot Security application                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)                                                                                                                                                                                                                                                                                                                                                                                                                                          | A result is stronger when it explains a source-to-sink path rather than naming only a suspicious line.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Preserve SARIF code-flow locations as source/evidence/sink hints, then independently validate the exact data flow and controls.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| [CodeQL data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)                                                                                                                                                                                                                                                                                                                                                                                                                                 | Local and global flow have different precision, performance, and completeness tradeoffs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Keep deterministic full-file inventory separate from expensive cross-file/deep passes; report deferred closure rather than silently narrowing scope.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [CodeQL custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-cpp/)                                                                                                                                                                                                                                                                                                                                                                                                                            | Framework-specific source, sink, summary, barrier, and threat models extend coverage beyond built-in libraries.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Emit bounded typed framework hypotheses with exact source/sink lines and context-specific control leads while keeping repository excerpts base64-encoded and requiring independent proof.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [CodeQL untrusted checkout](https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-high/), [GitHub secure `pull_request_target`](https://docs.github.com/en/actions/reference/security/secure-use), and [OpenSSF Dangerous-Workflow](https://github.com/ossf/scorecard/blob/main/docs/checks.md#dangerous-workflow)                                                                                                                                                                                                  | Privileged pull-request workflows become exploitable when attacker-controlled fork contents are fetched and later executed with privileged resources. Trigger-plus-checkout detection is useful but coarse; checkout version, path, ref, permissions, and execution order change the conclusion.                                                                                                                                                                                                                                                                                                | Parse workflow YAML, require exact same-job trigger-to-untrusted-checkout-to-matching-workspace-execution closure, and retain Checkout v7 fork refusal, immutable SHA, effective permissions, credentials, secrets/OIDC, and approval gates as separate proof obligations.                                                                                                                                                                                                                                                                                                                                                                                                 |
| [OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), and [Prisma single-record filters](https://docs.prisma.io/docs/orm/reference/prisma-client-reference)                                                                                                                                                                                                                                                           | Object authorization requires permission for the exact requested action on the exact object selected by a client-controlled key. Authentication and opaque IDs are insufficient; single-record filters may add non-unique permission dimensions.                                                                                                                                                                                                                                                                                                                                                | Preserve the request object reference into the lookup argument, retain principal-bound owner/tenant filtering or a dominating check on the returned object as control leads, and require the reviewer to prove disclosure/mutation plus missing permission.                                                                                                                                                                                                                                                                                                                                                                                                                |
| [CodeQL Java custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-java-and-kotlin/)                                                                                                                                                                                                                                                                                                                                                                                                           | Java model packs identify typed sources, sinks, summaries, and barriers at exact callable and argument positions.                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Resolve exact Spring/servlet request values and uniquely typed service calls before proposing a Java framework flow; reject ambiguous receiver types instead of guessing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [Spring Data reserved query methods](https://docs.spring.io/spring-data/jpa/reference/data-commons/repositories/query-methods-details.html), [`CrudRepository.findById`](https://docs.spring.io/spring-data/commons/docs/3.3.5/api/org/springframework/data/repository/CrudRepository.html), and [Spring Security method authorization](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)                                                                                                         | `findById` selects by the repository identifier. Derived query names add property predicates. Spring method security is inactive until explicitly enabled, and `@PostAuthorize` can protect a returned object after a read but is unsafe as a post-write boundary.                                                                                                                                                                                                                                                                                                                              | Preserve a request ID into a typed official Spring Data lookup; retain only a typed-principal owner predicate or active exact return-object ownership policy on a Spring-managed read method, while rejecting role-only, inactive, shadow, or post-write annotations.                                                                                                                                                                                                                                                                                                                                                                                                      |
| [Spring MVC model binding](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-data-binding.html), [`@ModelAttribute`](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/modelattrib-method-args.html), [`@InitBinder`](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-initbinder.html), and [`CrudRepository.save`](https://docs.spring.io/spring-data/commons/docs/3.3.5/api/org/springframework/data/repository/CrudRepository.html)                  | Spring binds request values through constructor and property binding by default, warns against domain-object binding, recommends allowed fields for property binding, and persists an entity passed to `save`.                                                                                                                                                                                                                                                                                                                                                                                  | Preserve the exact official `@ModelAttribute` JPA entity through typed services into `save`; retain only an applicable official allowed-field or constructor-only binder as a deterministic control lead, and keep DTO projection and sensitive-property impact for reviewer validation.                                                                                                                                                                                                                                                                                                                                                                                   |
| [CodeQL Java SSRF](https://codeql.github.com/codeql-query-help/java/java-ssrf/), [Spring WebClient](https://docs.spring.io/spring-framework/reference/web/webflux-webclient.html), [OkHttp calls](https://square.github.io/okhttp/5.x/okhttp/okhttp3/-ok-http-client/), and [JDK redirect policy](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Redirect.html)                                                                                                                                   | High-precision Java SSRF analysis tracks request data into outbound clients; WebClient delegates transport behavior to its configured connector; OkHttp separates request construction, call preparation, and dispatch; server-owned authorized URLs are preferred, and redirect policy applies only after the initial request.                                                                                                                                                                                                                                                                 | Track Spring/servlet values across typed Java services into JDK `HttpClient`, `RestTemplate`, reactive `WebClient`, and executed OkHttp requests, while keeping fixed complete destination selection, connector redirect rejection, dispatch, and address pinning as distinct proof obligations.                                                                                                                                                                                                                                                                                                                                                                           |
| [CodeQL JavaScript request forgery](https://codeql.github.com/codeql-query-help/javascript/js-request-forgery/) and [Axios request configuration](https://axios-http.com/docs/req_config)                                                                                                                                                                                                                                                                                                                                                    | JavaScript SSRF includes attacker control of outbound URLs. Axios prepends `baseURL` to relative URLs, permits absolute URLs to override it by default, and exposes separate absolute-override and redirect controls.                                                                                                                                                                                                                                                                                                                                                                           | Prove the `axios` package binding or non-reassigned created client, track only the URL argument/configuration property, and keep fixed selection, authority confinement, relative-path validation, redirects, and address pinning as separate proof obligations.                                                                                                                                                                                                                                                                                                                                                                                                           |
| [CodeQL Go request forgery](https://codeql.github.com/codeql-query-help/go/go-request-forgery/), [Go `net/http` package](https://pkg.go.dev/net/http), and [Go client dispatch source](https://go.dev/src/net/http/client.go)                                                                                                                                                                                                                                                                                                                | The high-precision Go query tracks request data into outbound HTTP. The standard library separates request construction from package/client dispatch, and `CheckRedirect` governs redirect following rather than authorizing the initial URL.                                                                                                                                                                                                                                                                                                                                                   | Require an exact `net/http` binding and typed request source; preserve complete URL argument roles, require constructed requests to close through `Client.Do`, and keep fixed selection, redirects, DNS, socket binding, proxying, and TLS identity as separate proof obligations.                                                                                                                                                                                                                                                                                                                                                                                         |
| [CodeQL Go command injection](https://codeql.github.com/codeql-query-help/go/go-command-injection/), [Go `os/exec`](https://pkg.go.dev/os/exec), [Go `os.StartProcess`](https://pkg.go.dev/os#StartProcess), [Go `syscall`](https://pkg.go.dev/syscall), [CodeQL's `os/exec` model](https://github.com/github/codeql/blob/main/go/ql/lib/ext/os.exec.model.yml), [gosec G204](https://github.com/securego/gosec/blob/master/rules/subproc.go), and [gosec G702](https://github.com/securego/gosec/blob/master/analyzers/commandinjection.go) | Go constructs an argument vector rather than invoking a shell automatically, but executable names, explicit shell/interpreter command strings, script paths, remote commands, and option-sensitive tools can still provide execution. `Cmd.Path` selects the program; nonempty `Cmd.Args` includes process-visible `Args[0]`. CodeQL's shipped model starts at `Command`/`CommandContext`. Gosec covers low-level `os`/`syscall` dispatch but G204 flags unresolved values at construction and G702 treats the calls as general taint sinks.                                                    | Require exact imports, typed request sources, executable/argv positions, and object identity. Distinguish executable, command-string, script, remote-command, and ordinary data arguments; preserve immutable command and `--` barriers; close constructor and manual-field state through execution; and model low-level APIs as immediate dispatch without treating argv zero as executable selection.                                                                                                                                                                                                                                                                    |
| [CodeQL Go path injection](https://codeql.github.com/codeql-query-help/go/go-path-injection/), [Go `path/filepath`](https://pkg.go.dev/path/filepath), [Go `os.Root`](https://pkg.go.dev/os#Root), [GO-2026-4970](https://pkg.go.dev/vuln/GO-2026-4970), [gosec G304](https://github.com/securego/gosec/blob/master/rules/readfile.go), and [gosec G703](https://github.com/securego/gosec/blob/master/analyzers/pathtraversal.go)                                                                                                           | CodeQL's high-precision query covers untrusted filesystem paths and recommends relative containment or component validation. Gosec G304 focuses on common open/read/create calls; G703 is broader but classifies several normalization/resolution helpers as sanitizers. Go documents that `Join` cleans and can escape a base, `IsLocal` is lexical and does not account for links, and root APIs depend on runtime/platform correctness. GO-2026-4970 demonstrates that even rooted APIs need patch-level scrutiny.                                                                           | Require exact request, import, API, and argument roles; retain normalization and resolution as evidence rather than universal barriers; model read/write/delete/move/link/metadata/root-selection/walk/response effects; accept immutable selection and proven trusted-root access as counterevidence; and separately validate symlinks, mounts, races, authorization, platform behavior, and affected runtime versions.                                                                                                                                                                                                                                                   |
| [Go `text/template`](https://pkg.go.dev/text/template), [Go template source](https://go.dev/src/text/template/template.go), [gosec G708](https://github.com/securego/gosec/blob/master/analyzers/ssti.go), and [CodeQL Go query index](https://codeql.github.com/codeql-query-help/go/)                                                                                                                                                                                                                                                      | `Template.Parse` interprets template grammar and `Funcs` installs functions used during execution. The current CodeQL Go index has no SSTI query. Gosec G708 finds tainted parse source but does not require later execution, combines fixed-template HTTP rendering/XSS with SSTI, and lists HTML escaping as a sanitizer even though brace directives remain active.                                                                                                                                                                                                                          | Require exact `text/template` identity, source argument zero, parsed-object identity, and `Execute`/`ExecuteTemplate` closure; keep fixed source plus request-only execution data as counterevidence; do not treat HTML escaping as a grammar barrier; and retain exact `FuncMap`, execution data, output, method, secret, side-effect, and resource capabilities for impact validation.                                                                                                                                                                                                                                                                                   |
| [CodeQL Go SQL injection](https://codeql.github.com/codeql-query-help/go/go-sql-injection/), [Go `database/sql`](https://pkg.go.dev/database/sql), and [gosec rules](https://github.com/securego/gosec/blob/master/RULES.md)                                                                                                                                                                                                                                                                                                                 | CodeQL's high-precision default query traces request data into database query grammar. Go documents exact query parameters and later placeholder arguments; gosec separately covers formatted/concatenated construction and taint rule G701.                                                                                                                                                                                                                                                                                                                                                    | Prove the standard-library binding and DB/Tx/Conn receiver, preserve query-text positions, exclude bound values, require prepared statements to execute, and keep driver behavior, structural identifiers, privileges, tenant predicates, and read/write impact distinct.                                                                                                                                                                                                                                                                                                                                                                                                  |
| [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [Go `database/sql`](https://pkg.go.dev/database/sql), [CodeQL Go query index](https://codeql.github.com/codeql-query-help/go/), and [gosec rules](https://github.com/securego/gosec/blob/master/RULES.md)                                                                                                                                                                                      | OWASP requires authorization for every endpoint that receives an object ID and acts on the selected object; its shop-revenue listing example is explicitly collection-shaped. The current CodeQL Go index and published gosec rule list do not expose a dedicated object-level authorization query. Go's standard library makes fixed query arguments, `QueryRow`/`Scan`, `Query`/`Rows.Next`/`Rows.Scan`, direct mutation dispatch, the separate `Prepare` to `Stmt.Exec` lifecycle, and transaction commit versus rollback observable.                                                        | Require an exact typed request-to-object-predicate path and actual single-row disclosure, same-cursor collection iteration/disclosure, direct mutation, exact prepared-statement mutation dispatch, or same-transaction durable commit; retain same-query security predicates only when bound to a context-derived principal; retain fail-closed returned-owner checks only before the protected effect; and reject authentication-only, unrelated Rows/statements/transactions, closed/replaced/unexecuted statements, uncommitted or rolled-back mutations, attacker-controlled owner filters, opaque IDs, parameterization-only, lookalike APIs, and generic responses. |
| [`sqlx`](https://pkg.go.dev/github.com/jmoiron/sqlx), [CodeQL Go library models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-go/), and [gosec SQL taint sinks](https://github.com/securego/gosec/blob/master/analyzers/sqlinjection.go)                                                                                                                                                                                                                                                             | Sqlx retains `database/sql` while adding destination-before-query `Select`/`Get`, named binding, package-level Queryer/Execer helpers, placeholder rebinding, extended statements, and transaction statement transfer. The inspected gosec sink table names standard-library DB/Tx operations and has no explicit sqlx call signatures.                                                                                                                                                                                                                                                         | Prove the exact upstream import and DB/Tx/Conn handle; preserve every helper's query position; keep positional/named values out of grammar; propagate tainted SQL through Rebind/Named; and require prepared or transferred statements to execute before review.                                                                                                                                                                                                                                                                                                                                                                                                           |
| [GORM v2 security](https://gorm.io/docs/security.html), [`gorm.io/gorm` API](https://pkg.go.dev/gorm.io/gorm), and [CodeQL's GORM model](https://github.com/github/codeql/blob/main/go/ql/lib/ext/gorm.io.gorm.model.yml)                                                                                                                                                                                                                                                                                                                    | GORM safely binds later placeholder values but accepts raw SQL or structural fragments in `Raw`, `Exec`, `Where`, `Order`, `Table`, inline conditions, `Pluck`, and `gorm.Expr`. Its newer `gorm.G[T]` API changes method families and places context before immediate SQL or results; typed join/preload callbacks can add clauses. Most chain methods build state, while finishers dispatch it. The inspected CodeQL extension models `DB` methods but not generic interfaces, context-first signatures, or callback closure.                                                                 | Prove exact v2 import, `*gorm.DB`, generic constructor, and typed interface identity; preserve grammar versus value positions and fluent object identity; require deferred fragments to reach a finisher; model generic callbacks and `gorm.Expr`; reject inert `Build`; and retain DryRun, dialect, allowlists, privileges, tenancy, and concrete impact separately.                                                                                                                                                                                                                                                                                                      |
| [Masterminds/Squirrel](https://github.com/Masterminds/squirrel), [Squirrel builder source](https://github.com/Masterminds/squirrel/blob/master/select.go), [CodeQL's Squirrel model](https://github.com/github/codeql/blob/main/go/ql/lib/ext/github.com.masterminds.squirrel.model.yml), and [gosec SQL taint sinks](https://github.com/securego/gosec/blob/master/analyzers/sqlinjection.go)                                                                                                                                               | Squirrel builds immutable SQL values, binds later arguments and map/`Eq` values, attaches a runner through `RunWith`, executes through builder or package helpers, and can materialize through `ToSql`/`MustSql`. Upstream explicitly warns that executing `DebugSqlizer` output containing untrusted data is insecure. The visible CodeQL extension covers many structural argument positions, including legacy package identities, but does not express the complete builder/runner/materialized execution closure; the current gosec sink table names only `database/sql` DB and Tx methods. | Require the exact modern import, typed builder/Sqlizer and runner identity, every variadic structural argument, safe value-container separation, immutable reassignment state, actual builder/helper execution, materialized/prepared dispatch, and executed `DebugSqlizer` output while rejecting unrelated same-named methods.                                                                                                                                                                                                                                                                                                                                           |
| [pgx v5](https://pkg.go.dev/github.com/jackc/pgx/v5), [pgxpool](https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool), [CodeQL Go library models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-go/), and [Semgrep's pgx rule](https://github.com/semgrep/semgrep-rules/blob/40b8c63f75dc7c22c8a77482d73bfb864b146f7e/go/lang/security/audit/sqli/pgx-sqli.yaml)                                                                                                                                        | Pgx v5 places context before SQL and later positional values/options, automatically prepares ordinary queries, names manual preparations, dispatches queued batches through `SendBatch`, and executes the first SQL value returned by a leading custom `QueryRewriter`. The community Semgrep rule is low-confidence and construction-oriented.                                                                                                                                                                                                                                                 | Prove exact v5 package and Conn/Tx/Pool identity, exclude later and returned values, close manual preparation and batches through execution, resolve exact custom rewriter method/type/field/first-return flow, and preserve protocol, privilege, and concrete-impact review.                                                                                                                                                                                                                                                                                                                                                                                              |
| [pgconn](https://pkg.go.dev/github.com/jackc/pgx/v5/pgconn), [pgconn v5.10 source](https://github.com/jackc/pgx/blob/v5.10.0/pgconn/pgconn.go), [CodeQL Go SQL customization](https://github.com/github/codeql/blob/main/go/ql/lib/semmle/go/security/SqlInjectionCustomizations.qll), and [gosec SQL taint sinks](https://github.com/securego/gosec/blob/master/analyzers/sqlinjection.go)                                                                                                                                                  | PgConn exposes simple-protocol multi-statement `Exec`, single-command extended `ExecParams`, raw COPY commands, prepared descriptions, deferred batches, and pipelines that transmit only at `Flush` or `Sync`. Gosec's current sink table is limited to `database/sql`; the visible CodeQL customization uses its generic SQL query abstraction rather than an explicit pgconn pipeline closure.                                                                                                                                                                                               | Prove exact PgConn/Batch/Pipeline identity and argument roles; close preparation through a fixed name or exact statement description; require `ExecBatch`, `Flush`, or `Sync`; reject parameter bytes, COPY streams, unsynchronized sends, and `Pipeline.Close` as query execution.                                                                                                                                                                                                                                                                                                                                                                                        |
| [CodeQL Java partial path traversal](https://codeql.github.com/codeql-query-help/java/java-partial-path-traversal/) and [Oracle path operations](https://docs.oracle.com/javase/tutorial/essential/io/pathOps.html)                                                                                                                                                                                                                                                                                                                          | Java path security depends on component-aware containment and real filesystem semantics: normalization is syntactic, absolute resolution can replace the base, and string prefixes admit sibling names.                                                                                                                                                                                                                                                                                                                                                                                         | Track Java web input into typed JDK filesystem APIs, retain absolute rejection, `Path.startsWith`, normalization, and `toRealPath` as separate proof leads, and require parent, absolute-reset, sibling, and link witnesses.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| [CodeQL C# custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-csharp/)                                                                                                                                                                                                                                                                                                                                                                                                                      | C# model packs identify exact callable signatures and argument access paths for sources, summaries, sinks, barriers, and threat models; `SqlCommand` argument zero is a canonical SQL sink.                                                                                                                                                                                                                                                                                                                                                                                                     | Resolve exact ASP.NET controller/service argument positions into bounded host hypotheses, preserve type binding and query-text argument roles, and retain parameter binding as counterevidence.                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| [CodeQL missing function-level access control](https://codeql.github.com/codeql-query-help/csharp/cs-web-missing-function-level-access-control/), [ASP.NET Core resource authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resource-based), and [EF Core `FindAsync`](https://learn.microsoft.com/en-us/ef/core/change-tracking/entity-entries#find-and-findasync)                                                                                                                                         | Function-level authorization is a useful medium-precision signal, but ASP.NET documents that declarative authorization occurs before resource loading and is insufficient for resource decisions. EF Core primary-key lookup selects one entity without an ownership predicate.                                                                                                                                                                                                                                                                                                                 | Keep endpoint authorization out of the object-control set; preserve a bound request ID into a typed EF lookup and retain only a principal-bound query predicate or enforced `AuthorizeAsync(User, exactEntity, policy)` result as resource-level control evidence.                                                                                                                                                                                                                                                                                                                                                                                                         |
| [CodeQL C# path injection](https://codeql.github.com/codeql-query-help/csharp/cs-path-injection/) and [.NET CA3003](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3003)                                                                                                                                                                                                                                                                                                                                | High-precision web-request-to-filesystem path analysis must preserve path construction and distinguish exact allowlists or canonical containment from normalization alone.                                                                                                                                                                                                                                                                                                                                                                                                                      | Track ASP.NET input across uniquely typed services into `System.IO` paths, retain rooted-input and canonical-relative controls, and require witnesses for parent, absolute-reset, and sibling-prefix cases.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| [Semgrep taint rules](https://semgrep.dev/docs/writing-rules/glossary)                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Explicit sources, sinks, propagators, and sanitizers make taint assumptions reviewable; cross-file and per-file analysis have distinct guarantees.                                                                                                                                                                                                                                                                                                                                                                                                                                              | Preserve model provenance and demand source/control/sink closure for imported candidates. Build regression fixtures for custom propagators and sanitizers.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [Sonar security rules](https://docs.sonarsource.com/sonarqube-server/user-guide/rules/security-related-rules)                                                                                                                                                                                                                                                                                                                                                                                                                                | Taint vulnerabilities and review-required security hotspots are different evidence classes. Sonar also supports custom sources, sanitizers, validators, and sinks.                                                                                                                                                                                                                                                                                                                                                                                                                              | Treat all imported results as candidates, not findings. Validation decides reportable, rejected, or deferred; a hotspot cannot inherit vulnerability status merely from its producer.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [OSV-Scanner](https://google.github.io/osv-scanner/usage/) and [call analysis](https://google.github.io/osv-scanner/output/)                                                                                                                                                                                                                                                                                                                                                                                                                 | Extract dependencies deterministically, match authoritative advisories, and use call information to distinguish called from apparently unused vulnerable code.                                                                                                                                                                                                                                                                                                                                                                                                                                  | Add deterministic SBOM/lockfile inventory and advisory ingestion, then use Copilot for repository-specific reachability, compensating controls, and remediation boundary analysis.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| [Trivy repository scanning](https://www.trivy.dev/docs/latest/guide/target/repository/)                                                                                                                                                                                                                                                                                                                                                                                                                                                      | One repository pass can cover vulnerable dependencies, misconfiguration, secrets, and licenses.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Accept these result families through SARIF now; later add opt-in local adapters while keeping each family’s evidence and completion semantics distinct.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| [Trivy SARIF reporting](https://trivy.dev/docs/latest/configuration/reporting/)                                                                                                                                                                                                                                                                                                                                                                                                                                                              | SARIF 2.1.0 is a practical interchange format across vulnerability, misconfiguration, secret, and license scanners.                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Implement repeatable `--seed-sarif` intake rather than tool-specific parsers. Preserve normalized provenance and never copy a producer’s conclusion into canonical findings.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| [Trivy secret scanning](https://www.trivy.dev/docs/latest/guide/scanner/secret/)                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Built-in and custom rules, allow rules, path bounds, and explicit skip behavior reduce secret-scanning cost and noise.                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Future deterministic secret discovery must redact values before model access, preserve only local fingerprints, distinguish test fixtures, and make exclusions auditable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [Gitleaks](https://github.com/gitleaks/gitleaks)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Git-patch history scanning, full redaction, stable fingerprints, baselines, and scoped allowlists make high-volume secret findings manageable.                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Scan bounded reachable Git blobs locally through a trusted executable, deduplicate revision occurrences, use expiring justified keyed baselines, and never persist or display raw secret material.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)                                                                                                                                                                                                                                                                                                                                                                                                                           | Stable rule IDs, relative paths, locations, severity/precision metadata, and partial fingerprints support interoperable alert tracking.                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Normalize relative paths and rule metadata, but hash source documents locally and omit imported fingerprints because they may contain arbitrary or sensitive producer data.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

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

`benchmarks/go-net-http-ssrf-manifest.json` adds the first strict Go outbound
client lane. The positive reads a complete URL from a typed `*http.Request`,
passes it through one unique same-package string wrapper, constructs an
`http.Request` with `NewRequestWithContext`, and dispatches it through a
locally constructed `http.Client.Do`. The matched control uses the request
value only as an exact key into a server-owned map of complete destinations
and returns `http.ErrUseLastResponse` from `CheckRedirect`. `httptest`
loopback witnesses prove that the positive reaches a mock metadata service,
while the control rejects a direct internal URL and prevents an allowed
server's redirect from reaching that service. This follows CodeQL's
high-precision, default-suite [Go request-forgery query](https://codeql.github.com/codeql-query-help/go/go-request-forgery/)
and the standard library's separation of [`NewRequest` construction from
client dispatch](https://go.dev/src/net/http/client.go). Redirect rejection is
retained only as candidate evidence because it cannot authorize the initial
destination or prove DNS, proxy, final socket, Host, or TLS identity. The
bounded host model deliberately stops after one same-package wrapper;
cross-package/module summaries, method receivers, client factories, custom
`RoundTripper`, request cloning, partial URL construction, and package-wide
map-mutation proof remain future work.

`benchmarks/go-os-exec-command-injection-manifest.json` adds a strict Go
process-execution lane. One positive carries an indexed HTTP value through one
unique same-package wrapper, formats it into the command string following
`sh -c`, and closes `CommandContext` construction through `CombinedOutput`.
The second uses the same path but assigns a complete slice to a manually
constructed `Cmd.Args` before the same execution closure. Matched controls
retain the request, wrapper, exact `os/exec` import, shell, flag, execution
method, and attack bytes but use the value only to select a complete immutable
server-owned command. All four modules copy their running Go test executable
to a temporary `sh` path and activate a bounded command witness, so both
exploit/control pairs execute deterministically on Windows and Linux without
trusting or invoking the host shell.

The host model distinguishes attacker-controlled executable selection; POSIX,
Windows, PowerShell, batch-file, and language-interpreter command grammar;
interpreter script selection; fixed-host SSH remote commands; and option-sensitive remote
Git and rsync arguments. Fixed executable direct argument vectors are not
treated as shell strings. Exact `--` placement blocks the modeled Git/rsync
option path, and immutable map selection blocks dynamic shell grammar. A risky
`Command`, `CommandContext`, composite, zero-value, or `new(exec.Cmd)` state is
retained only until the same non-reassigned command reaches `Run`, `Start`,
`Output`, or `CombinedOutput`; construction, pipe setup, `LookPath`, and
unrelated same-named methods are inert. Manual `Path`, complete `Args`, and
exact `Args[index]` writes are tracked with local slice literals, aliases, and
exact element mutation. `Args[0]` is excluded from executable selection.
`os.StartProcess` and `syscall.Exec`, `ForkExec`, and `StartProcess` are modeled
at their immediate dispatch sites using the same exact program and argv roles.
Exact aliases and execabs are supported, while import lookalikes, dot or
duplicate imports, reassignment, ambiguous wrappers, and comment/string
examples are rejected. This preserves the source and argument distinctions in
[CodeQL's high-precision Go command-injection query](https://codeql.github.com/codeql-query-help/go/go-command-injection/),
adds explicit construction-to-execution closure and low-level dispatch, and
avoids gosec G204's broad construction-time treatment of unresolved arguments.
Remaining work includes nested `env`/`sudo`/`timeout` command selection,
variadic and branch-built slices, composite `Args` identifiers, cross-package
and multiple wrapper hops, receiver fields and factories, PATH/environment
mutation, working-directory and credential inheritance, Windows CreateProcess
command-line APIs, and platform-specific deployment evidence.

`benchmarks/go-http-filesystem-path-manifest.json` adds a strict Go
request-to-filesystem lane. The positive carries an HTTP query value through
one unique same-package wrapper, joins it beneath a public directory, and
passes the result to `os.ReadFile`. Its cross-platform test proves a `..`
payload reads a sibling signing-key witness. The matched control preserves the
request, wrapper, payload, directory layout, and allowed-file behavior but
opens through `os.OpenInRoot`, which rejects the escape.

The host model requires exact default or aliased standard-library imports and
the documented argument position for `os`, legacy `io/ioutil`,
`path/filepath.Walk*`, and `net/http.ServeFile*` operations. It distinguishes
read, open, write, delete, metadata, source/destination move and link, root
selection, walk root, and response-file effects. Query, form, path, and header sources can
flow directly, through assignment and `filepath` construction, or through one
unique same-package string wrapper. Reassignment, immutable map selection,
lookalike/dot/duplicate imports, ambiguous wrappers, and comment/string
examples are rejected. Unlike the inspected gosec G703 implementation, the
model does not treat `Clean`, `Abs`, `Rel`, or `EvalSymlinks` as universal
sanitizers: Go documents lexical transformations separately from filesystem
containment, and `IsLocal` explicitly does not account for symbolic links.
Root-scoped names under a fixed trusted root are retained as strong
counterevidence, while request control of the root itself is reported.
Reviewer guidance requires root identity, authorization, platform,
link/mount/race behavior, and patch-level proof. GO-2026-4970/CVE-2026-39822
requires affected Unix deployments to use at least Go 1.25.12 or 1.26.5.
Remaining work includes typed `os.Root` receiver-state summaries, multiple and
cross-package wrappers, interfaces and methods, branch-sensitive flow,
archive/upload extraction, `embed.FS` and third-party virtual filesystems,
Windows volume and reparse-point depth, and deployment permission evidence.

`benchmarks/go-http-template-injection-manifest.json` adds a strict Go
template-source lane. The positive carries an HTTP query value through one
unique same-package string wrapper into argument zero of
`text/template.Template.Parse`, registers a `FuncMap`, and executes the same
parsed object. Its cross-platform test proves `{{readSigningKey}}` invokes the
server function and discloses the fixture signing key. The matched control
preserves the source, wrapper, payload, renderer, and response but parses a
fixed `html/template` and supplies the request only as data, proving the
directive remains literal, script markup is escaped, and the key is not
disclosed.

The host requires exact default or aliased standard-library identity, typed
query/form/path/header sources, source argument zero, and `Execute` or
`ExecuteTemplate` closure on the same non-reassigned parsed object. It follows
separate builders, direct chains, parsed-object aliases, one wrapper, and fixed
immutable source selection. It rejects inert parsing, fixed source, package
lookalikes, `html/template`, duplicate imports, local shadows, ambiguous
wrappers, reassignment, comments, and strings. Unlike the inspected gosec G708
configuration, it does not classify HTML escaping as a source sanitizer and
does not merge fixed-template XSS into CWE-1336. Capability evidence records
registered functions and execution data for concrete impact review. Remaining
work includes `ParseFiles`/`ParseFS` archive or tenant content provenance,
associated template sets, receiver methods and fields, cross-package and
multi-hop summaries, branch-sensitive identity, and bounded recursion analysis.

`benchmarks/go-database-sql-injection-manifest.json` adds a strict Go query-
grammar lane. The positive takes an indexed HTTP query value through one
same-package function, formats it into SQL source, and dispatches it at the
exact `DB.QueryContext` query position. The control preserves that topology but
uses a fixed server-owned query and supplies the request value only as a
placeholder argument. Standard-library `database/sql/driver` witnesses prove
that an injected predicate exposes an internal record in the positive while
the same metacharacters remain inert data in the control. The host also models
typed or inferred DB/Tx/Conn handles, same-file receiver fields, and
preparation followed by statement execution; it rejects `Stmt` value
arguments, inert preparation, type lookalikes, and another function's local
receiver declarations. This combines CodeQL's high-precision, default-suite
[Go SQL-injection query](https://codeql.github.com/codeql-query-help/go/go-sql-injection/),
the standard library's documented separation of [query text and placeholder
arguments](https://pkg.go.dev/database/sql), and gosec's complementary
[G201/G202/G701 construction and taint rules](https://github.com/securego/gosec/blob/master/RULES.md).
Cross-file methods, interfaces, driver-specific APIs, query builders, ORMs,
stored procedures, and deployment database-role evidence remain future work.

`benchmarks/go-http-object-authorization-manifest.json` adds a strict Go
object-level authorization lane. Its SQL is fixed and parameterized: the
positive vulnerability is that a path-selected invoice is looked up by object
ID alone, scanned, and disclosed through a same-package wrapper. An offline
`database/sql/driver` witness proves an attacker can read the victim signing
key. A second positive uses `QueryContext`, `Rows.Next`, `Rows.Scan`, and
response disclosure to expose every invoice in a victim project. The matched
controls add an account predicate whose value comes from the authenticated
request context; their witnesses prove both cross-account reads fail while the
attacker's own object and collection remain available. The typed host requires
exact `net/http` and `database/sql` identities, object-key placeholder roles,
DB/Tx/Conn receivers, and either `QueryRow` scan-to-response closure, exact
`Query`/`QueryContext` Rows-to-Next-to-Scan-to-response closure, or an executed
update/delete. It records context-principal query binding and dominating
post-lookup ownership checks as counterevidence without treating authentication,
opaque IDs, parameterized SQL, principal-named parameters, or attacker-provided
owner filters as authorization. Fixed mutations prepared on a DB and transferred
through exact `Tx.Stmt` or `Tx.StmtContext` source/result identities retain the
original predicate but become reportable only after the destination transaction
commits. The original statement remains a separate identity; ignored results,
context/source argument confusion, closed or replaced statements, transfers
between distinct transactions, rollback, and missing durable closure are
negative cases. A fifth executable pair proves both the unscoped committed
deletion and the context-principal control with an offline driver. The host also
summarizes one uniquely resolved same-package finalizer function only when an
exact typed transaction parameter reaches exactly one function-level commit or
rollback. Unlike a name heuristic, this keeps caller transaction identity,
argument position, nesting, ordering, definition ambiguity, and the helper's
actual evidence path. A sixth executable pair proves the helper-committed
positive and principal-scoped control. The summary now composes through up to 32
exact same-package helper boundaries. Each edge must pass the same typed
transaction parameter or a proven local alias into the uniquely resolved next
function; cycles, reassignment, nesting, defer, multiple reachable outcomes, and
over-depth graphs fail closed. Evidence retains each internal delegation and the
real leaf `Commit`. A seventh executable pair proves this multi-helper positive
and principal-scoped control. Finalizer edges may now cross local package and
nested-module boundaries only when the deepest enclosing `go.mod`, exact module
import path, ordinary import alias, exported function, unique local definition,
and transaction argument all agree. Package alias shadowing, dot and blank
imports, missing modules, external lookalikes, duplicate local module identities,
and unexported targets fail closed. An eighth executable pair crosses two
internal packages and proves both the unscoped durable deletion and matched
principal control. Transaction creation now receives the same exact treatment:
a bounded local factory chain must carry a typed `*sql.DB` or `*sql.Conn` into
the real `Begin`/`BeginTx`, return `*sql.Tx` first, and expose the unchanged
result through a direct return or one assigned-then-return identity. Evidence
retains every factory boundary and leaf begin path. DB/Conn method mismatch,
wrong or transformed results, nesting, reassignment, cycles, alias shadowing,
ambiguous modules or definitions, interfaces, and methods fail closed. A ninth
executable pair crosses two imported factory packages and proves both the
durable unscoped deletion and its principal-bound control. Exact local function
values now compose with both factory and finalizer summaries through at most
eight top-level, single-name, single-assignment bindings. Each capture is
evidence, qualified imports bind at capture time, and shadowing, reassignment,
nesting, multi-name assignment, unknown targets, cycles, or a ninth binding fail
closed. A tenth executable pair crosses application and internal-package
function values on both creation and finalization paths and proves the durable
unscoped deletion plus its principal-bound control. This
directly
implements OWASP API1:2023's
[exact-object authorization requirement](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
for a standard-library Go boundary that the current [CodeQL Go query
index](https://codeql.github.com/codeql-query-help/go/) and published [gosec
rule list](https://github.com/securego/gosec/blob/master/RULES.md) do not expose
as a dedicated query. General cross-package object wrappers, nested and
multi-result-set loops, joins, composite keys, row mappers, policy services,
sqlc, ORMs, branch-
sensitive dominance, and deployment authorization remain future work.

This bounded application-function summary follows the same precision principle
as CodeQL's distinction between local flow and explicitly modeled
interprocedural flow summaries: the summary expands a proven semantic boundary,
not every similarly named call. It remains deliberately narrower than whole-
program call-graph and control-flow analysis; interface dispatch, function
parameters, method values and factories, named-result-only returns, recursive
transaction helpers, replace-only packages without source inventory, and
dynamically selected creation or finalization callbacks remain future work.

`benchmarks/go-sqlx-sql-injection-manifest.json` adds a strict sqlx lane. The
positive carries an HTTP query value through one unique same-package wrapper,
formats it into SQL, and reaches destination-before-query `DB.Select`; the
matched control keeps query grammar fixed and passes identical attack bytes
only as a placeholder value. Offline local replacement modules retain the
exact public sqlx path and an API-compatible adapter over `database/sql`, so
both behaviors execute without a dependency download or database service. The
host models typed and inferred DB/Tx/Conn receivers, exact receiver and package
helper query positions, named execution, Rebind/Named propagation, extended
preparation, transaction statement transfer, and execution closure. It rejects
arbitrary Queryer/Execer implementations, forks and import lookalikes, later
positional or named values, fixed or reassigned queries, inert or replaced
statements, duplicate wrappers, and comment/string examples. This applies
CodeQL's exact callable/access-path modeling discipline to signatures absent
from the inspected gosec `database/sql` sink table. Cross-package and multi-hop
summaries, sqlc, builders, other ORMs, stored procedures, driver dialect metadata,
and deployment database-role evidence remain future work.

`benchmarks/go-gorm-sql-injection-manifest.json` adds a strict modern GORM
lane. One positive carries an HTTP query value through one unique same-package
wrapper, formats it into SQL, and retains that grammar across traditional
`Raw` until `Scan` executes it. A second uses `gorm.G[string](db)`, retains a
request-derived `Where` predicate, and executes through context-first `Find`.
Each matched control preserves its handler, wrapper, `*gorm.DB`, attack bytes,
and deterministic driver but keeps query text fixed and supplies the bytes only
as a placeholder value. Exact local replacement modules provide minimal
signature-compatible `gorm.io/gorm` subsets, so all four behaviors execute
offline without claiming to reproduce all ORM semantics.
The host models exact default or aliased imports, typed parameters and fields,
`gorm.Open`, derived sessions and transactions, same-line or multiline fluent
chains, assigned builders, documented fragment positions, immediate `Exec`,
inline finisher conditions, `Pluck` identifiers, `gorm.Expr` query text, fixed
fragment-map selection, and one unique wrapper. It rejects legacy, fork,
suffix-lookalike, dot, duplicate, and untyped identities; later bound values;
unexecuted or reassigned builders; fixed selections; ambiguous wrappers; and
comment/string examples. The generic extension additionally proves exact
`gorm.G[T]` construction, typed generic receiver interfaces, context-first
`Exec`, deferred `Raw`, generic clauses and `Count`, `JoinBuilder` and
`PreloadBuilder` callbacks, expression-bearing options and `Set`, and inert
`Build`, without importing traditional inline-condition signatures. This adds
generic coverage and explicit construction-to-finisher closure beyond the
traditional `DB` argument positions in [CodeQL's visible GORM model](https://github.com/github/codeql/blob/main/go/ql/lib/ext/gorm.io.gorm.model.yml)
and follows GORM's official distinction between [safe placeholders and
injectable SQL fragments](https://gorm.io/docs/security.html). Cross-package and
multi-hop wrappers, custom clauses and plugin callbacks beyond the exact generic
builders, `Scopes`, branch-sensitive DryRun dominance, other ORMs and builders,
dialect metadata, and deployment database-role evidence remain future work.

`benchmarks/go-squirrel-sql-injection-manifest.json` adds a strict modern
Masterminds/Squirrel lane. The positive carries an indexed HTTP query value
through one unique same-package wrapper, formats it into a predicate, and
retains that grammar until `RunWith(db).Query()` executes the immutable
builder. The control preserves the handler, wrapper, exact import, builder,
runner, attack bytes, and deterministic driver but keeps the predicate fixed
and supplies the input only as one placeholder value. Exact local replacement
modules implement a signature-compatible Squirrel subset, so both behaviors
execute offline without claiming full library emulation.

The host models all builder families, `StatementBuilder` child construction,
typed parameters and fields, exact Squirrel runners and standard-library DB,
Tx, or Conn handles, cache/wrapper constructors, aliases, fluent and assigned
immutable builders, every variadic structural argument, map and `Eq` value
containers, `Expr`, `ConcatExpr`, `Alias`, `Case`, nested `Sqlizer` values,
exact package helpers, and one unique wrapper. `RunWith` must lead to builder
execution; `ToSql` and `MustSql` must reach typed direct or prepared execution;
and `DebugSqlizer` becomes a sink only when its interpolated output executes.
The model rejects forks and legacy/lookalike imports, dot or duplicate imports,
unproven runners, untyped or unrelated same-named methods, bound values,
unexecuted or reassigned state, fixed selections, ambiguous wrappers, and
comment/string examples. This adds object and execution closure around the
argument positions in [CodeQL's visible Squirrel model](https://github.com/github/codeql/blob/main/go/ql/lib/ext/github.com.masterminds.squirrel.model.yml),
follows upstream's [builder and `DebugSqlizer` contracts](https://github.com/Masterminds/squirrel/blob/master/squirrel.go),
and extends beyond the current [gosec `database/sql` sink table](https://github.com/securego/gosec/blob/master/analyzers/sqlinjection.go).
Cross-package and multiple wrapper hops, branch-sensitive merging, arbitrary
runner factories, package-wide immutable state, other builder libraries,
stored procedures, dialect metadata, and deployment database-role evidence
remain future work.

`benchmarks/go-pgx-sql-injection-manifest.json` adds a strict pgx v5 lane.
The first positive carries an indexed HTTP query value through one same-package
function into the SQL argument of a typed `pgxpool.Pool.Query`; its control
keeps SQL fixed and supplies the same bytes only after `$1`. The second positive
places a form value in a custom rewriter field whose exact `RewriteQuery`
implementation returns formatted SQL; its control returns fixed SQL first and
the same field only in `[]any`. Offline local module replacements retain the
exact public pgx v5 path and documented signatures while deterministically
proving grammar injection exposes an internal record and both value boundaries
do not. The host also models explicit and inferred pgx Conn/Tx/Pool handles,
same-file fields, fixed prepared names executed on the same receiver, typed
batches closed through `SendBatch`, exact custom value/pointer rewriter methods,
leading pgx options, preserved input SQL, receiver-field construction and
reassignment, and the first returned SQL expression.
It rejects v4, fork and suffix lookalikes, dot or duplicate imports, untyped
methods, later values and named/struct argument rewriters, dynamic or replaced
prepared names, a different execution receiver, inert preparation,
undispatched or replaced batches, and fixed query selection. This extends the
official [pgx query and preparation contracts](https://pkg.go.dev/github.com/jackc/pgx/v5),
[pgxpool method signatures](https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool),
and exact-callable modeling from [CodeQL's Go extension guidance](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-go/)
beyond the construction-only, low-confidence community
[Semgrep pgx rule](https://github.com/semgrep/semgrep-rules/blob/40b8c63f75dc7c22c8a77482d73bfb864b146f7e/go/lang/security/audit/sqli/pgx-sqli.yaml).
Cross-package rewriter types, constructor-returned or interface-held rewriters,
multi-hop helper methods inside rewrites, pgx v4, sqlc wrappers, builders,
other ORMs, and deployment database-role evidence remain future work.

`benchmarks/go-pgconn-sql-injection-manifest.json` adds the low-level protocol
lane. The positive carries an indexed HTTP query value through one unique
same-package wrapper into simple-protocol `PgConn.Exec`, where the deterministic
witness proves an injected predicate exposes an internal record. The matched
control retains the same request and wrapper topology but passes the bytes only
as `ExecParams` parameter data, proving that they remain one extended-protocol
value. The host separately preserves `Exec` and `ExecParams` SQL positions,
`CopyFrom` and `CopyTo` commands, fixed prepared names, returned
`StatementDescription` identity, `pgconn.Batch` queue-to-`ExecBatch` closure,
and Pipeline queue-to-`Flush` or `Sync` closure. It rejects parameter bytes,
COPY streams, dynamic names, different preparation receivers, unused
preparations, replaced batches or pipelines, unsynchronized sends, and
`Pipeline.Close` as execution. Upstream source confirms that `Exec` permits
multiple statements, `ExecParams` accepts one command, `Sync` flushes queued
requests, and `Close` errors on unsynchronized work. This fills an explicit gap
in gosec's current `database/sql`-only taint sink table and goes beyond the
legacy construction-oriented Semgrep pgx rule. `ExecStatement` values created
outside the bounded function, cross-package and multi-hop wrappers, arbitrary
connection factories, direct frontend protocol messages, and database-role
deployment evidence remain future work.

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

`benchmarks/spring-object-authorization-manifest.json` adds the corresponding
strict Spring Data resource-authorization pair. The positive carries an
annotated route ID through a uniquely resolved service into official typed
`JpaRepository.findById`; endpoint authentication is deliberately common to
both sides and does not close the object decision. The negative declares
`findByIdAndCustomerId` and binds the owner dimension to a real Spring Security
`Authentication.getName()` value in the same query. H2-backed Spring Boot
witnesses prove cross-customer disclosure and rejection against the real ORM
topology. Focused regressions reject untyped repositories, local Spring Data
and security annotation shadows, fixed or reassigned IDs, attacker-provided
owner values, role-only policies, inactive method security, and
`@PostAuthorize` after a write. Active return-object ownership policy is kept
only on an official Spring-managed read method with enabled pre/post
interception.

`benchmarks/spring-mass-assignment-manifest.json` adds a strict Spring MVC/JPA
CWE-915 pair. The positive binds request form fields directly onto the unique
official JPA `Account` entity and preserves that same typed object through a
service into `JpaRepository.save`. The negative uses the identical route,
entity, service, repository, Hibernate, H2, and submitted privilege field, but
an attribute-scoped official `WebDataBinder.setAllowedFields` excludes it.
MockMvc witnesses prove unintended administrative persistence in the positive
and intended-field-only persistence in the control. Focused regressions cover
same-file, one-service, and two-service paths, fully qualified framework types,
constructor-only declarative binding, binder attribute scope, disabled
binding, DTO projection, reassignment, GET handlers, local shadows, entity and
repository type mismatches, and ambiguous service identities. Denylists remain
review evidence rather than a complete host control because Spring recommends
allowed fields and documents denylist fragility.

`benchmarks/github-actions-pwn-request-manifest.json` adds a strict CWE-829
privileged-workflow pair. The host parses only exact workflow paths, rejects
malformed or duplicate-key YAML, and requires `pull_request_target`, an
explicit pull-request head checkout, and a later command or local action whose
workspace overlaps the tainted checkout path. A later trusted checkout of that
path clears the host hypothesis. The positive deliberately opts Checkout v7
into unsafe fork checkout and exposes privileged resources; the negative
retains Checkout v7's default refusal and read-only permissions. The runtime
witness proves harmless attacker code observes only a mock secret in the
positive case. Focused regressions cover trigger and ref variants, immutable
versus mutable refs, repository identity, checkout version and opt-out,
working-directory and local-action paths, trusted overwrite, token and
credential controls, review/environment leads, malformed YAML, aliases, and
non-workflow paths.

`benchmarks/github-actions-self-hosted-pr-manifest.json` adds a strict
CWE-284/CWE-829 persistent-runner pair grounded in
[GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use),
the [CodeQL self-hosted pull-request query](https://codeql.github.com/codeql-query-help/actions/actions-pr-on-self-hosted-runner/),
and [CodeQL 2.26.0's hosted-label update](https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.26.0/).
GitHub warns that self-hosted runners do not have the ephemeral clean-machine
guarantee of GitHub-hosted runners and can be persistently compromised by
untrusted workflow code. The host model goes beyond a `runs-on` report: it
requires a pull-request-capable event, statically classified self-hosted or
custom runner selection, official untrusted checkout, matching workspace, and
later command or local-action execution. It excludes CodeQL's current standard
GitHub-hosted label patterns plus BuildJet and Warp hosted labels, rejects fully
dynamic scheduling, and does not infer upstream pull-request provenance for a
`workflow_run` checkout. Ordinary `pull_request` rows remain free of invented
secret and write-token categories. The paired witness proves persistence into
a later privileged job on a reused machine and proves isolation when the
pull-request machine is destroyed before a fresh hosted job.

`benchmarks/github-actions-artifact-poisoning-manifest.json` adds a strict
cross-workflow CWE-829 pair based on the
[CodeQL very-high-precision artifact-poisoning query](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/)
and [GitHub's current triggering-workflow artifact guidance](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#using-data-from-the-triggering-workflow).
The producer must have an exact `pull_request` trigger, official untrusted
checkout, and later official upload whose literal path remains inside that
checkout. The consumer must name the producer under `workflow_run`, download
the same artifact through the official action bound to
`github.event.workflow_run.id`, and later execute from the extracted path. The
host preserves workflow/artifact identity, action pins, step order,
all-artifact subdirectories, effective working directories, permissions,
secrets/OIDC, and cleanup state. A clean trusted checkout clears taint;
`clean:false` does not. The paired witness proves workspace replacement and
mock-token observation, while the control follows GitHub's current
`runner.temp` plus fail-closed typed-data pattern. This improves on a generic
`workflow_run` or download warning by requiring complete cross-file identity
and execution closure. Regressions reject name and run mismatches, missing
tokens, unrelated paths, non-PR producers, lookalike actions, data-only
consumers, malformed/duplicate/aliased YAML, and non-workflow paths.

`benchmarks/github-actions-reusable-workflow-injection-manifest.json` adds a
strict cross-file CWE-094/CWE-095/CWE-116 pair grounded in
[GitHub's script-injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections),
[reusable-workflow input contract](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows),
and the [CodeQL very-high-precision Actions code-injection query](https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/).
The caller must run from an exact externally influenced default-branch event,
forward one exact attacker-controlled event field to an exact local workflow
path, and bind it to a matching declared `workflow_call` string input. The
called workflow must then interpolate that input, or an input-derived workflow
`env` expression, into a `run` script or official `actions/github-script`
source. The host preserves trigger, call, input, declaration, environment
alias, sink, permission, secret, OIDC, and control provenance across both YAML
documents. The matched control follows GitHub's recommended intermediate-env
boundary and consumes the value only through `process.env`; its executable
witness proves the same payload stays inert. This adds exact cross-file closure
beyond a same-document expression match while rejecting remote targets,
fixed/boolean-transformed values, undeclared or non-string inputs, ordinary
action arguments, lookalike script actions, native environment reads, and
malformed/duplicate/aliased YAML.

`benchmarks/github-actions-composite-action-injection-manifest.json` extends
that expression-compilation boundary through an exact literal repository-local
action call. The workflow must forward one supported attacker-controlled event
field under one exact input name; exactly one `action.yml` or `action.yaml`
must declare that input and `runs.using: composite`; and a runnable composite
step must interpolate the value into `run` or official GitHub Script source.
Same-step environment transfer followed by native shell or `process.env` use
is the matched control, while later `${{ env.NAME }}` expansion remains code
generation. Descriptor ambiguity, invalid metadata, parent traversal, remote
or dynamic targets, shell-less commands, cross-step environment assumptions,
ordinary action inputs, lookalikes, and comment-only secret evidence are
rejected. The executable witness proves direct substitution observes only a
mock forwarded token while the identical environment value stays inert.

`benchmarks/github-actions-workflow-script-injection-manifest.json` adds the
same-file CWE-094/CWE-095/CWE-116 boundary grounded in
[GitHub's script-injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections),
the [CodeQL very-high-precision Actions code-injection query](https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/),
and zizmor's current CodeQL-derived action-input sink map. The host couples
each supported trigger to exact attacker-controlled fields and follows direct
dot or single-quoted bracket contexts, parentheses, value-preserving
`toJSON`/`fromJSON`/`format`/`join`, reachable short-circuit results, and
workflow/job/step environment aliases only when `${{ env.NAME }}` is later
re-expanded into source. It rejects boolean predicates, comparisons, fixed or
unreachable results, native environment reads, trigger/field mismatches,
unknown action inputs, lookalikes, dynamic revisions, and invalid YAML.
`pull_request` rows preserve code execution but deliberately omit secret and
write-token impact normally removed from fork runs; other event rows require
exact effective permissions and structural secret/token use. The paired
GitHub Script witness proves the direct title substitution creates a second
statement that observes a mock token, while the identical intermediate
environment value logs as one inert string.

Current GitHub cache rules informed the model boundary rather than becoming a
new broad alert. GitHub now makes `pull_request_target`, `issue_comment`, and
`workflow_run` cache access read-only in the default-branch scope, and keeps
`pull_request` writes in the merge-ref scope. A generic low-trust cache-save
rule would therefore report platform-blocked flows. Future cache models must
prove a presently writable cache scope, attacker-controlled cached bytes, a
matching consumer key/version/path, and later trusted execution.

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
   extend framework-specific authorization models beyond the bounded Node,
   Spring Data, and ASP.NET object-reference lanes, add ASP.NET template engines
   beyond the typed Scriban and RazorLight lanes,
   outbound-client APIs beyond JDK `HttpClient`, Spring `RestTemplate`,
   Spring `WebClient`, OkHttp, Axios, .NET `HttpClient`, and Go `net/http`;
   deepen Go HTTP and SQL lanes beyond one same-package wrapper; extend the
   shipped `database/sql`, sqlx, pgx, and pgconn lanes into sqlc wrappers,
   builders, and ORMs; add
   partial-URL SSRF models,
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
4. **Configuration and IaC model packs — six CI lanes shipped.** Deterministic
   YAML models now prove both same-job privileged-trigger/untrusted-checkout
   execution, ordinary pull-request execution on a persistent self-hosted
   runner, cross-workflow pull-request artifact poisoning, and reusable-
   workflow, local composite-action, and direct same-workflow script injection
   against paired
   witnesses, including Checkout v7 protection, triggering-run binding,
   extraction paths, cleanup, runner classification and lifecycle, typed-data
   isolation, descriptor and input identity, step scope, and
   expression-compilation timing. Extend the same evidence discipline to
   cross-file runner-group policy and `workflow_run` provenance,
   current-semantics cache poisoning, nested reusable-workflow and
   composite-action chains,
   Docker, Kubernetes, Terraform, and cloud policy surfaces, then ask Copilot
   to evaluate deployment reachability and compensating controls.
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
