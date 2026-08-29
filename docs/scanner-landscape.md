# Scanner landscape and improvement roadmap

This document records ideas worth adopting from mature security scanners and
the constraints for integrating them without turning Copilot Security into an
unverifiable alert aggregator. It is a living engineering backlog, not a claim
that dissimilar products can be reduced to one score.

The latest comparator adoption is CodeQL's July 2026
[`Sails Action2 inputs as remote sources`](https://github.com/github/codeql/pull/22142)
repair for a demonstrated `js/path-injection` false negative. Copilot Security
now applies the same declared-input/controller/export boundary to exact Node
filesystem path positions, adds overwritten-value and ambiguous-shape controls,
and extends the source through exact relative wrapper and two-relay paths. It
also goes beyond the source-only comparator by requiring a custom route target
or literal blueprint action-route enablement before emitting the source. The
documented blueprint action-route default is false. Two read-only exploit/
control pairs gate same-file and cross-file behavior while route, helper,
reassignment, fixed-path, and ambiguous-configuration controls constrain noise.

The preceding comparator gap was Pickem
[GHSA-8qx3-8gm5-9cj2](https://github.com/calebogden/pickem-oss/security/advisories/GHSA-8qx3-8gm5-9cj2).
Package presence and a picker call are not yet a reachable terminal-control
path: remote collection data must be projected into an exact rendered item
field and reach the official default formatter. The
[v1.0.7 repair](https://github.com/calebogden/pickem-oss/releases/tag/v1.0.7)
sanitizes display text at render boundaries, covering bare C0/C1/DEL bytes in
addition to escape-sequence forms while preserving returned values. Current
authenticated CodeQL and Semgrep rule-source searches contain no Pickem package
or advisory match. Copilot Security therefore records the complete remote-
collection/display-projection/binding/render/provenance chain and uses a
noninteractive real-package byte differential before any terminal-policy or
realized clipboard-impact claim.

## Design principles extracted from other scanners

| Scanner or ecosystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Useful design                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Copilot Security application                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CodeQL Sails Action2 source model](https://github.com/github/codeql/pull/22142), [original false-negative report](https://github.com/github/codeql/issues/21773), [Sails Action2 documentation](https://sailsjs.com/documentation/concepts/actions-and-controllers), and [blueprint configuration](https://sailsjs.com/documentation/reference/configuration/sails-config-blueprints)                                                                                                                                                                                                                                                                                                                                                              | Framework-normalized request data may no longer resemble `req.params` or `req.query`. The useful source boundary is structural: an exported action below `api/controllers`, an object-valued declared `inputs` property, and the matching first `fn` parameter. The same machine specification is also used by helpers, and implicit action routes default to false, so a name-only `inputs.foo` rule is unsound and an action file alone does not prove exposure.                                                                                                                                                                                          | Extend exact Node filesystem path tracking with only routed declared Action2 inputs, including exact relative wrapper and two-relay paths. Require a literal custom route target or `blueprints.actions: true`; preserve helper/machine paths, undeclared or computed properties, spreads, ambiguous exports, unsupported handlers, overwritten values, false/dynamic/unrelated route configuration, and fixed paths as controls. Gate scanner output and runtime effect with matched fixed-thumbnail witnesses.                                                                                                                                                                                                                                                                    |
| [Pickem advisory GHSA-8qx3-8gm5-9cj2](https://github.com/calebogden/pickem-oss/security/advisories/GHSA-8qx3-8gm5-9cj2), [v1.0.7 repair release](https://github.com/calebogden/pickem-oss/releases/tag/v1.0.7), and current authenticated [CodeQL](https://github.com/github/codeql) / [Semgrep rules](https://github.com/semgrep/semgrep-rules) source searches                                                                                                                                                                                                                                                                                                                                                                        | The affected package rendered hostile item fields without complete control-byte neutralization, but application risk still depends on remote item provenance, exact display-field projection, default formatter reachability, and terminal policy. Current public rule sources have no exact package/advisory model.                                                                                                                                                                                                                                                                                                                              | Require exact affected production provenance, a stable official Pickem binding, request or fetched JSON, an exact map projection into `label`, `description`, or `group`, and an actual picker call. Keep value-only, sanitized, custom-format, reassigned, trusted, and fixed-package paths negative; validate the public formatter with inert markers and print only booleans or escaped JSON.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [Defuddle advisory GHSA-jg4p-g6xj-4qmf](https://github.com/kepano/defuddle/security/advisories/GHSA-jg4p-g6xj-4qmf), [extractor-output repair](https://github.com/kepano/defuddle/commit/baf2eaef61d334ef595b28c89e5c5e89e52daf7f), and current authenticated [CodeQL](https://github.com/github/codeql) / [Semgrep rules](https://github.com/semgrep/semgrep-rules) source searches                                                                                                                                                                                                                                                                                                                                                    | The affected package interpolates hostile site attributes into returned HTML, but application risk still depends on remote input, the official parser path, an unmodified `content` result, and downstream HTML interpretation. The repair combines sink escaping with centralized DOM sanitization, while current public rule sources have no exact package/advisory model.                                                                                                                                                                                                                                                                      | Require exact affected production provenance, a stable official `defuddle/node` binding, an exported relative wrapper, request or fetched HTML, and the same response content at an explicit HTML response, `innerHTML`, React raw-HTML, or Web `Response` boundary. Keep parsing-only, non-HTML, sanitized, reassigned, and fixed-package paths negative; validate by reparsing one inert marker without executing it.                                                                                                                                                                                                                                                                                                                                                                                                |
| [Plate advisory GHSA-qj6x-xx2h-8hvv](https://github.com/udecode/plate/security/advisories/GHSA-qj6x-xx2h-8hvv), [metadata fast-path repair](https://github.com/udecode/plate/commit/6214914ca811adf22d0ad503154494216eed68ba), and current authenticated [CodeQL](https://github.com/github/codeql) / [Semgrep rules](https://github.com/semgrep/semgrep-rules) source searches                                                                                                                                                                                                                                                                                                                                                         | The affected package can preserve a stored URL only when serialized provider metadata takes the hook's early return; whether that becomes XSS depends on application-owned editor state flow, media registration, parser configuration, provider gating, and iframe rendering. Current public rule sources have no exact package/hook model.                                                                                                                                                                                                                                                                                                      | Require remote serialized state, an exported prop and exact Plate value edge, official stable plugin/hook bindings, nonempty parsers, an `isVideo` gate, the same `embed.url` iframe sink, script-capable sandbox state, and exact affected runtime provenance. Keep fixed packages and every missing edge as controls; validate the real affected/repaired hook first, then require a disposable browser and bounded message sentinel before assigning browser impact.                                                                                                                                                                                                                                                                                                                                                |
| [Next.js advisory GHSA-492v-c6pp-mqqv](https://github.com/vercel/next.js/security/advisories/GHSA-492v-c6pp-mqqv), [route-wrapper repair](https://github.com/vercel/next.js/commit/87080764c96f5416decccd43f4c434545fd5d4e1), and current authenticated [CodeQL](https://github.com/github/codeql) / [Semgrep rules](https://github.com/semgrep/semgrep-rules) source searches                                                                                                                                                                                                                                                                                                                                                          | A dependency advisory is insufficient because the vulnerable value crosses two views of one request: middleware sees the visible pathname, while an affected routing handoff can prepare a different dynamic page parameter. The repair explicitly distinguishes trusted proxy normalization from ordinary requests already wrapped by Next. Current public rule sources have no exact advisory/internal-key model.                                                                                                                                                                                                                               | Require a concrete middleware/proxy denial, covering matcher, one matching App/Pages dynamic segment, real server-side data access, absent route-local authorization, and exact affected runtime provenance. Preserve ordinary standalone behavior as counterevidence and validate the real route-module handoff against the repaired version before claiming exploitability or impact.                                                                                                                                                                                                                                                                                                                                                                                                                                |
| [DeepSeek MCP advisory GHSA-fh3r-g96v-f578](https://github.com/arikusi/deepseek-mcp-server/security/advisories/GHSA-fh3r-g96v-f578), [1.7.0 isolation repair](https://github.com/arikusi/deepseek-mcp-server/commit/9fd514292d23d59ca1434b01f019aca6ef4356f9), and current authenticated [CodeQL](https://github.com/github/codeql) / [Semgrep rules](https://github.com/semgrep/semgrep-rules) source searches                                                                                                                                                                                                                                                                                                                         | Dependency version is insufficient when the vulnerable state exists only in one transport. The decisive application facts are multi-client HTTP operation, a process-global store, and caller-controlled session keys; stdio is a real negative control rather than a weaker deployment. Current public rule sources have no exact package model.                                                                                                                                                                                                                                                                                                 | Require exact affected production provenance plus literal `TRANSPORT=http` and a top-level dynamic package launch or bounded operational npm command. Keep static-import ordering, nested launchers, overwritten transport, arbitrary scripts, development-only metadata, and 1.7.0 negative. Validate store identity and one inert cross-client marker without starting a listener or contacting the upstream API.                                                                                                                                                                                                                                                                                                                                                                                                    |
| [Microsoft Prompty advisory GHSA-w28w-gp39-m4p6](https://github.com/microsoft/prompty/security/advisories/GHSA-w28w-gp39-m4p6), [Prompty fix PR 404](https://github.com/microsoft/prompty/pull/404), and current authenticated [CodeQL](https://github.com/github/codeql) / [Semgrep rules](https://github.com/semgrep/semgrep-rules) source searches                                                                                                                                                                                                                                                                                                                                                                                   | The package advisory identifies critical Nunjucks member-traversal RCE in untrusted or LLM-generated `.prompty` bodies, while the fix changes runtime member lookup, input sanitation, and function-call policy. Current CodeQL and Semgrep rule sources have no package, renderer, or advisory match. A dependency alert therefore misses application reachability, while a generic `render` match confuses template code with ordinary data inputs and alternative renderers.                                                                                                                                                                   | Bind exact affected `@prompty/core` provenance and official Nunjucks or public pipeline capabilities; require remote grammar in the explicit template position or exact `Prompty.instructions` followed by render/prepare/invoke; preserve aliases and three relative wrappers. Keep Mustache, trusted templates with untrusted inputs, construction-only paths, path-only invoke, replaced bindings, ambiguous provenance, and 0.1.5/2.0.0-beta.5 repairs as deterministic controls. Validate with a bounded host-version witness and do not promote deployment impact from package membership alone.                                                                                                                                                                                                                 |
| [datamodel-code-generator advisory GHSA-5578-w22f-pfx9](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-5578-w22f-pfx9), [GitHub advisory](https://github.com/advisories/GHSA-5578-w22f-pfx9), and current authenticated [CodeQL](https://github.com/github/codeql) / [Semgrep rules](https://github.com/semgrep/semgrep-rules) source searches                                                                                                                                                                                                                                                                                                                                                           | A package advisory identifies the unsafe schema-extension-to-import-rendering primitive, but generation and execution are separate application stages. Current CodeQL and Semgrep rule sources have no match for the package, module, or `x-python-import` extension, so a package-only dependency alert would miss reachability while a raw `generate` match would overstate impact.                                                                                                                                                                                                                                                             | Model the official versioned generator plus exact request schema edge, then require either same-path `output` to `runpy.run_path` continuity or returned-source to built-in `exec` continuity. Keep repaired 0.64.0, path mismatch/reassignment, non-schema input, shadows, and generation-without-execution as executable negative controls; require a bounded real-package differential before promoting impact.                                                                                                                                                                                                                                                                                                                                                                                                     |
| [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | A result is stronger when it explains a source-to-sink path rather than naming only a suspicious line.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Preserve SARIF code-flow locations as source/evidence/sink hints, then independently validate the exact data flow and controls.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| [CodeQL data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Local and global flow have different precision, performance, and completeness tradeoffs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Keep deterministic full-file inventory separate from expensive cross-file/deep passes; report deferred closure rather than silently narrowing scope.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| [CodeQL custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-cpp/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Framework-specific source, sink, summary, barrier, and threat models extend coverage beyond built-in libraries.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Emit bounded typed framework hypotheses with exact source/sink lines and context-specific control leads while keeping repository excerpts base64-encoded and requiring independent proof.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| [CodeQL JavaScript system prompt injection](https://codeql.github.com/codeql-query-help/javascript/js-system-prompt-injection/) and the [GitHub Copilot SDK session types](https://github.com/github/copilot-sdk/blob/main/nodejs/src/types.ts)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Untrusted text becomes materially more dangerous when it enters a higher-priority instruction channel. The SDK exposes that boundary through system-message modes and sections as well as custom-agent and tool metadata; ordinary sent prompts remain user messages, while command descriptions are completion-UI metadata.                                                                                                                                                                                                                                                                                                                      | Bind the exact official client and session call, preserve only content-bearing trusted fields, treat unknown-section content according to its append fallback, and retain ordinary `send`/`sendAndWait` prompt data as a negative control. Require downstream capability and unintended-operation proof before assigning impact.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [CodeQL untrusted checkout](https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-high/), [GitHub secure `pull_request_target`](https://docs.github.com/en/actions/reference/security/secure-use), and [OpenSSF Dangerous-Workflow](https://github.com/ossf/scorecard/blob/main/docs/checks.md#dangerous-workflow)                                                                                                                                                                                                                                                                                                                                                                                             | Privileged pull-request workflows become exploitable when attacker-controlled fork contents are fetched and later executed with privileged resources. Trigger-plus-checkout detection is useful but coarse; checkout version, path, ref, permissions, and execution order change the conclusion.                                                                                                                                                                                                                                                                                                                                                  | Parse workflow YAML, require exact same-job trigger-to-untrusted-checkout-to-matching-workspace-execution closure, and retain Checkout v7 fork refusal, immutable SHA, effective permissions, credentials, secrets/OIDC, and approval gates as separate proof obligations.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| [OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), and [Prisma single-record filters](https://docs.prisma.io/docs/orm/reference/prisma-client-reference)                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Object authorization requires permission for the exact requested action on the exact object selected by a client-controlled key. Authentication and opaque IDs are insufficient; single-record filters may add non-unique permission dimensions.                                                                                                                                                                                                                                                                                                                                                                                                  | Preserve the request object reference into the lookup argument, retain principal-bound owner/tenant filtering or a dominating check on the returned object as control leads, and require the reviewer to prove disclosure/mutation plus missing permission.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| [CodeQL Java custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-java-and-kotlin/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Java model packs identify typed sources, sinks, summaries, and barriers at exact callable and argument positions.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Resolve exact Spring/servlet request values and uniquely typed service calls before proposing a Java framework flow; reject ambiguous receiver types instead of guessing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| [Spring Data reserved query methods](https://docs.spring.io/spring-data/jpa/reference/data-commons/repositories/query-methods-details.html), [`CrudRepository.findById`](https://docs.spring.io/spring-data/commons/docs/3.3.5/api/org/springframework/data/repository/CrudRepository.html), and [Spring Security method authorization](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)                                                                                                                                                                                                                                                                                                    | `findById` selects by the repository identifier. Derived query names add property predicates. Spring method security is inactive until explicitly enabled, and `@PostAuthorize` can protect a returned object after a read but is unsafe as a post-write boundary.                                                                                                                                                                                                                                                                                                                                                                                | Preserve a request ID into a typed official Spring Data lookup; retain only a typed-principal owner predicate or active exact return-object ownership policy on a Spring-managed read method, while rejecting role-only, inactive, shadow, or post-write annotations.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [Spring MVC model binding](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-data-binding.html), [`@ModelAttribute`](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/modelattrib-method-args.html), [`@InitBinder`](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-initbinder.html), and [`CrudRepository.save`](https://docs.spring.io/spring-data/commons/docs/3.3.5/api/org/springframework/data/repository/CrudRepository.html)                                                                                                                                                                                                             | Spring binds request values through constructor and property binding by default, warns against domain-object binding, recommends allowed fields for property binding, and persists an entity passed to `save`.                                                                                                                                                                                                                                                                                                                                                                                                                                    | Preserve the exact official `@ModelAttribute` JPA entity through typed services into `save`; retain only an applicable official allowed-field or constructor-only binder as a deterministic control lead, and keep DTO projection and sensitive-property impact for reviewer validation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| [CodeQL Java SSRF](https://codeql.github.com/codeql-query-help/java/java-ssrf/), [Spring WebClient](https://docs.spring.io/spring-framework/reference/web/webflux-webclient.html), [OkHttp calls](https://square.github.io/okhttp/5.x/okhttp/okhttp3/-ok-http-client/), and [JDK redirect policy](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Redirect.html)                                                                                                                                                                                                                                                                                                                              | High-precision Java SSRF analysis tracks request data into outbound clients; WebClient delegates transport behavior to its configured connector; OkHttp separates request construction, call preparation, and dispatch; server-owned authorized URLs are preferred, and redirect policy applies only after the initial request.                                                                                                                                                                                                                                                                                                                   | Track Spring/servlet values across typed Java services into JDK `HttpClient`, `RestTemplate`, reactive `WebClient`, and executed OkHttp requests, while keeping fixed complete destination selection, connector redirect rejection, dispatch, and address pinning as distinct proof obligations.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [CodeQL JavaScript request forgery](https://codeql.github.com/codeql-query-help/javascript/js-request-forgery/) and [Axios request configuration](https://axios-http.com/docs/req_config)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | JavaScript SSRF includes attacker control of outbound URLs. Axios prepends `baseURL` to relative URLs, permits absolute URLs to override it by default, and exposes separate absolute-override and redirect controls.                                                                                                                                                                                                                                                                                                                                                                                                                             | Prove the `axios` package binding or non-reassigned created client, track only the URL argument/configuration property, and keep fixed selection, authority confinement, relative-path validation, redirects, and address pinning as separate proof obligations.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [CodeQL experimental IPv6-transition SSRF guard query](https://github.com/github/codeql/blob/main/javascript/ql/src/experimental/Security/CWE-918/SsrfIpv6TransitionIncompleteGuard.ql), [CodeQL JavaScript SSRF](https://codeql.github.com/codeql-query-help/javascript/js-request-forgery/), and [RFC 4291 IPv4-compatible address forms](https://www.rfc-editor.org/rfc/rfc4291)                                                                                                                                                                                                                                                                                                                                                     | Dotted-quad private-address guards can miss IPv4 embedded in IPv4-mapped IPv6, NAT64, and 6to4 representations. The experimental query locates validator-shaped functions and known guard packages, but a one-prefix workaround or co-occurring guard does not prove the actual outbound value is safe.                                                                                                                                                                                                                                                                                                                                           | Start from an exact request-to-outbound-URL model, bind the guard to the same parsed host in the sink wrapper, require a fail-closed IPv4-only branch, and retain all three transition families as separate witnesses. Suppress the specialization only when the consumed host is completely canonicalized before the address policy; continue to validate parser acceptance, DNS, connection pinning, redirects, proxy behavior, and the concrete internal effect.                                                                                                                                                                                                                                                                                                                                                    |
| [CodeQL Go request forgery](https://codeql.github.com/codeql-query-help/go/go-request-forgery/), [Go `net/http` package](https://pkg.go.dev/net/http), and [Go client dispatch source](https://go.dev/src/net/http/client.go)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | The high-precision Go query tracks request data into outbound HTTP. The standard library separates request construction from package/client dispatch, and `CheckRedirect` governs redirect following rather than authorizing the initial URL.                                                                                                                                                                                                                                                                                                                                                                                                     | Require an exact `net/http` binding and typed request source; preserve complete URL argument roles, require constructed requests to close through `Client.Do`, and keep fixed selection, redirects, DNS, socket binding, proxying, and TLS identity as separate proof obligations.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| [Ktor type-safe routing](https://ktor.io/docs/server-resources.html), [Kotlin functions](https://kotlinlang.org/docs/functions.html), [JDK `ProcessBuilder`](https://docs.oracle.com/en/java/javase/26/docs/api/java.base/java/lang/ProcessBuilder.html), and [CodeQL Java/Kotlin command-line injection](https://codeql.github.com/codeql-query-help/java/java-command-line-injection/)                                                                                                                                                                                                                                                                                                                                                | Ktor Resources deserializes path and query data into an annotated handler value. Kotlin supports top-level functions and expression bodies. `ProcessBuilder` keeps an ordered command that can be replaced after construction. A list passed to the constructor or `command(List)`, and the list returned by `command()`, remains live rather than being copied. `startPipeline` starts one process for each builder in its supplied list, including inline builders; retained command and builder-list mutations therefore affect the effective launch. A program-and-argument list does not imply a shell.                                      | Bind only exact Ktor call or typed-resource sources and exact JDK builder identities; follow shared command-list and pipeline-list identity, builder/list aliases, replacement, indexed writes, `set`, `add`, `removeAt`, clear/rebuild order, and uniquely named same-file single-expression factories or single-command mutators into exact `start` or `startPipeline` execution; reject arbitrary wrappers, overloads, named/default-argument ambiguity, member/extension dispatch, callbacks, and nontrivial bodies; detach old command views after replacement; distinguish executable selection and explicit command-language positions from ordinary argv; and preserve annotation, route import, helper call, builder identity, pipeline assembly, mutation, reassignment, and execution as proof obligations. |
| [CodeQL Go command injection](https://codeql.github.com/codeql-query-help/go/go-command-injection/), [Go `os/exec`](https://pkg.go.dev/os/exec), [Go `os.StartProcess`](https://pkg.go.dev/os#StartProcess), [Go `syscall`](https://pkg.go.dev/syscall), [CodeQL's `os/exec` model](https://github.com/github/codeql/blob/main/go/ql/lib/ext/os.exec.model.yml), [gosec G204](https://github.com/securego/gosec/blob/master/rules/subproc.go), and [gosec G702](https://github.com/securego/gosec/blob/master/analyzers/commandinjection.go)                                                                                                                                                                                            | Go constructs an argument vector rather than invoking a shell automatically, but executable names, explicit shell/interpreter command strings, script paths, remote commands, and option-sensitive tools can still provide execution. `Cmd.Path` selects the program; nonempty `Cmd.Args` includes process-visible `Args[0]`. CodeQL's shipped model starts at `Command`/`CommandContext`. Gosec covers low-level `os`/`syscall` dispatch but G204 flags unresolved values at construction and G702 treats the calls as general taint sinks.                                                                                                      | Require exact imports, typed request sources, executable/argv positions, and object identity. Distinguish executable, command-string, script, remote-command, and ordinary data arguments; preserve immutable command and `--` barriers; close constructor and manual-field state through execution; and model low-level APIs as immediate dispatch without treating argv zero as executable selection.                                                                                                                                                                                                                                                                                                                                                                                                                |
| [CodeQL Go path injection](https://codeql.github.com/codeql-query-help/go/go-path-injection/), [Go `path/filepath`](https://pkg.go.dev/path/filepath), [Go `os.Root`](https://pkg.go.dev/os#Root), [GO-2026-4970](https://pkg.go.dev/vuln/GO-2026-4970), [gosec G304](https://github.com/securego/gosec/blob/master/rules/readfile.go), and [gosec G703](https://github.com/securego/gosec/blob/master/analyzers/pathtraversal.go)                                                                                                                                                                                                                                                                                                      | CodeQL's high-precision query covers untrusted filesystem paths and recommends relative containment or component validation. Gosec G304 focuses on common open/read/create calls; G703 is broader but classifies several normalization/resolution helpers as sanitizers. Go documents that `Join` cleans and can escape a base, `IsLocal` is lexical and does not account for links, and root APIs depend on runtime/platform correctness. GO-2026-4970 demonstrates that even rooted APIs need patch-level scrutiny.                                                                                                                             | Require exact request, import, API, and argument roles; retain normalization and resolution as evidence rather than universal barriers; model read/write/delete/move/link/metadata/root-selection/walk/response effects; accept immutable selection and proven trusted-root access as counterevidence; and separately validate symlinks, mounts, races, authorization, platform behavior, and affected runtime versions.                                                                                                                                                                                                                                                                                                                                                                                               |
| [Go `text/template`](https://pkg.go.dev/text/template), [Go template source](https://go.dev/src/text/template/template.go), [gosec G708](https://github.com/securego/gosec/blob/master/analyzers/ssti.go), and [CodeQL Go query index](https://codeql.github.com/codeql-query-help/go/)                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `Template.Parse` interprets template grammar and `Funcs` installs functions used during execution. The current CodeQL Go index has no SSTI query. Gosec G708 finds tainted parse source but does not require later execution, combines fixed-template HTTP rendering/XSS with SSTI, and lists HTML escaping as a sanitizer even though brace directives remain active.                                                                                                                                                                                                                                                                            | Require exact `text/template` identity, source argument zero, parsed-object identity, and `Execute`/`ExecuteTemplate` closure; keep fixed source plus request-only execution data as counterevidence; do not treat HTML escaping as a grammar barrier; and retain exact `FuncMap`, execution data, output, method, secret, side-effect, and resource capabilities for impact validation.                                                                                                                                                                                                                                                                                                                                                                                                                               |
| [CodeQL Go SQL injection](https://codeql.github.com/codeql-query-help/go/go-sql-injection/), [Go `database/sql`](https://pkg.go.dev/database/sql), and [gosec rules](https://github.com/securego/gosec/blob/master/RULES.md)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | CodeQL's high-precision default query traces request data into database query grammar. Go documents exact query parameters and later placeholder arguments; gosec separately covers formatted/concatenated construction and taint rule G701.                                                                                                                                                                                                                                                                                                                                                                                                      | Prove the standard-library binding and DB/Tx/Conn receiver, preserve query-text positions, exclude bound values, require prepared statements to execute, and keep driver behavior, structural identifiers, privileges, tenant predicates, and read/write impact distinct.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [Go `database/sql`](https://pkg.go.dev/database/sql), [Go method sets](https://go.dev/ref/spec#Method_sets), [Go struct types](https://go.dev/ref/spec#Struct_types), [Go selectors](https://go.dev/ref/spec#Selectors), [CodeQL Go data flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-go/), [CodeQL Go library](https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-go/), [Semgrep analysis scope](https://semgrep.dev/docs/writing-rules/glossary), and [gosec rules](https://github.com/securego/gosec/blob/master/RULES.md) | OWASP requires authorization for every endpoint that receives an object ID and acts on the selected object; its shop-revenue listing example is explicitly collection-shaped. Go defines different method sets for `T`, `*T`, and interfaces, and selector validity depends on the exact field/method chain. CodeQL's call graph distinguishes the declared interface target from possible concrete runtime callees. Semgrep documents per-file Community Edition and cross-file/cross-function proprietary analysis. The current CodeQL Go query index and published gosec rule list do not expose a dedicated object-level authorization query. | Require an exact typed request-to-object-predicate path and actual protected disclosure or durable mutation. Compose bounded unique function or concrete-method paths with explicit constructor, receiver, concrete-field, interface binding, call, parameter, alias, and principal evidence; retain same-query security predicates only for the exact context-derived principal; and reject unbound or ambiguous dispatch, authentication-only, over-depth graphs, unrelated object state, opaque IDs, parameterization-only, lookalike APIs, and generic responses.                                                                                                                                                                                                                                                  |
| [`sqlx`](https://pkg.go.dev/github.com/jmoiron/sqlx), [CodeQL Go library models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-go/), and [gosec SQL taint sinks](https://github.com/securego/gosec/blob/master/analyzers/sqlinjection.go)                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Sqlx retains `database/sql` while adding destination-before-query `Select`/`Get`, named binding, package-level Queryer/Execer helpers, placeholder rebinding, extended statements, and transaction statement transfer. The inspected gosec sink table names standard-library DB/Tx operations and has no explicit sqlx call signatures.                                                                                                                                                                                                                                                                                                           | Prove the exact upstream import and DB/Tx/Conn handle; preserve every helper's query position; keep positional/named values out of grammar; propagate tainted SQL through Rebind/Named; and require prepared or transferred statements to execute before review.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [GORM v2 security](https://gorm.io/docs/security.html), [`gorm.io/gorm` API](https://pkg.go.dev/gorm.io/gorm), and [CodeQL's GORM model](https://github.com/github/codeql/blob/main/go/ql/lib/ext/gorm.io.gorm.model.yml)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | GORM safely binds later placeholder values but accepts raw SQL or structural fragments in `Raw`, `Exec`, `Where`, `Order`, `Table`, inline conditions, `Pluck`, and `gorm.Expr`. Its newer `gorm.G[T]` API changes method families and places context before immediate SQL or results; typed join/preload callbacks can add clauses. Most chain methods build state, while finishers dispatch it. The inspected CodeQL extension models `DB` methods but not generic interfaces, context-first signatures, or callback closure.                                                                                                                   | Prove exact v2 import, `*gorm.DB`, generic constructor, and typed interface identity; preserve grammar versus value positions and fluent object identity; require deferred fragments to reach a finisher; model generic callbacks and `gorm.Expr`; reject inert `Build`; and retain DryRun, dialect, allowlists, privileges, tenancy, and concrete impact separately.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [Masterminds/Squirrel](https://github.com/Masterminds/squirrel), [Squirrel builder source](https://github.com/Masterminds/squirrel/blob/master/select.go), [CodeQL's Squirrel model](https://github.com/github/codeql/blob/main/go/ql/lib/ext/github.com.masterminds.squirrel.model.yml), and [gosec SQL taint sinks](https://github.com/securego/gosec/blob/master/analyzers/sqlinjection.go)                                                                                                                                                                                                                                                                                                                                          | Squirrel builds immutable SQL values, binds later arguments and map/`Eq` values, attaches a runner through `RunWith`, executes through builder or package helpers, and can materialize through `ToSql`/`MustSql`. Upstream explicitly warns that executing `DebugSqlizer` output containing untrusted data is insecure. The visible CodeQL extension covers many structural argument positions, including legacy package identities, but does not express the complete builder/runner/materialized execution closure; the current gosec sink table names only `database/sql` DB and Tx methods.                                                   | Require the exact modern import, typed builder/Sqlizer and runner identity, every variadic structural argument, safe value-container separation, immutable reassignment state, actual builder/helper execution, materialized/prepared dispatch, and executed `DebugSqlizer` output while rejecting unrelated same-named methods.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [pgx v5](https://pkg.go.dev/github.com/jackc/pgx/v5), [pgxpool](https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool), [CodeQL Go library models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-go/), and [Semgrep's pgx rule](https://github.com/semgrep/semgrep-rules/blob/40b8c63f75dc7c22c8a77482d73bfb864b146f7e/go/lang/security/audit/sqli/pgx-sqli.yaml)                                                                                                                                                                                                                                                                                                                                   | Pgx v5 places context before SQL and later positional values/options, automatically prepares ordinary queries, names manual preparations, dispatches queued batches through `SendBatch`, and executes the first SQL value returned by a leading custom `QueryRewriter`. The community Semgrep rule is low-confidence and construction-oriented.                                                                                                                                                                                                                                                                                                   | Prove exact v5 package and Conn/Tx/Pool identity, exclude later and returned values, close manual preparation and batches through execution, resolve exact custom rewriter method/type/field/first-return flow, and preserve protocol, privilege, and concrete-impact review.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| [pgconn](https://pkg.go.dev/github.com/jackc/pgx/v5/pgconn), [pgconn v5.10 source](https://github.com/jackc/pgx/blob/v5.10.0/pgconn/pgconn.go), [CodeQL Go SQL customization](https://github.com/github/codeql/blob/main/go/ql/lib/semmle/go/security/SqlInjectionCustomizations.qll), and [gosec SQL taint sinks](https://github.com/securego/gosec/blob/master/analyzers/sqlinjection.go)                                                                                                                                                                                                                                                                                                                                             | PgConn exposes simple-protocol multi-statement `Exec`, single-command extended `ExecParams`, raw COPY commands, prepared descriptions, deferred batches, and pipelines that transmit only at `Flush` or `Sync`. Gosec's current sink table is limited to `database/sql`; the visible CodeQL customization uses its generic SQL query abstraction rather than an explicit pgconn pipeline closure.                                                                                                                                                                                                                                                 | Prove exact PgConn/Batch/Pipeline identity and argument roles; close preparation through a fixed name or exact statement description; require `ExecBatch`, `Flush`, or `Sync`; reject parameter bytes, COPY streams, unsynchronized sends, and `Pipeline.Close` as query execution.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| [CodeQL Java partial path traversal](https://codeql.github.com/codeql-query-help/java/java-partial-path-traversal/) and [Oracle path operations](https://docs.oracle.com/javase/tutorial/essential/io/pathOps.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Java path security depends on component-aware containment and real filesystem semantics: normalization is syntactic, absolute resolution can replace the base, and string prefixes admit sibling names.                                                                                                                                                                                                                                                                                                                                                                                                                                           | Track Java web input into typed JDK filesystem APIs, retain absolute rejection, `Path.startsWith`, normalization, and `toRealPath` as separate proof leads, and require parent, absolute-reset, sibling, and link witnesses.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| [CodeQL C# custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-csharp/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | C# model packs identify exact callable signatures and argument access paths for sources, summaries, sinks, barriers, and threat models; `SqlCommand` argument zero is a canonical SQL sink.                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Resolve exact ASP.NET controller/service argument positions into bounded host hypotheses, preserve type binding and query-text argument roles, and retain parameter binding as counterevidence.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| [CodeQL CLI 2.26.0 Razor Pages source addition](https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.26.0/), [CodeQL Razor framework model](https://github.com/github/codeql/blob/bfc7a8b6ba4ac0ab54dd02ef4d86802b04077a8a/csharp/ql/lib/semmle/code/csharp/frameworks/Razor.qll), and [ASP.NET Core model binding](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/model-binding)                                                                                                                                                                                                                                                                                                                     | Razor Page handler parameters are remote-flow sources without controller-style source attributes. Public `PageModel` properties bind only when opted in, and GET property binding additionally requires `SupportsGet`; service inputs and non-handlers are distinct framework roles.                                                                                                                                                                                                                                                                                                                                                              | Require exact official `PageModel` inheritance through a bounded unique local graph, public HTTP-verb handlers, parameter-to-sink reachability, and service/opt-out exclusions. Improve beyond the upstream handler-parameter addition by preserving exact `[BindProperty]`/`[BindProperties]` property flow, GET semantics, reassignment, local shadow rejection, typed wrappers, executable controls, and all six ASP.NET sink families.                                                                                                                                                                                                                                                                                                                                                                             |
| [CodeQL missing function-level access control](https://codeql.github.com/codeql-query-help/csharp/cs-web-missing-function-level-access-control/), [ASP.NET Core resource authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resource-based), and [EF Core `FindAsync`](https://learn.microsoft.com/en-us/ef/core/change-tracking/entity-entries#find-and-findasync)                                                                                                                                                                                                                                                                                                                                    | Function-level authorization is a useful medium-precision signal, but ASP.NET documents that declarative authorization occurs before resource loading and is insufficient for resource decisions. EF Core primary-key lookup selects one entity without an ownership predicate.                                                                                                                                                                                                                                                                                                                                                                   | Keep endpoint authorization out of the object-control set; preserve a bound request ID into a typed EF lookup and retain only a principal-bound query predicate or enforced `AuthorizeAsync(User, exactEntity, policy)` result as resource-level control evidence.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| [CodeQL C# path injection](https://codeql.github.com/codeql-query-help/csharp/cs-path-injection/) and [.NET CA3003](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3003)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | High-precision web-request-to-filesystem path analysis must preserve path construction and distinguish exact allowlists or canonical containment from normalization alone.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Track ASP.NET input across uniquely typed services into `System.IO` paths, retain rooted-input and canonical-relative controls, and require witnesses for parent, absolute-reset, and sibling-prefix cases.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| [Semgrep taint rules](https://semgrep.dev/docs/writing-rules/glossary)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Explicit sources, sinks, propagators, and sanitizers make taint assumptions reviewable; cross-file and per-file analysis have distinct guarantees.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Preserve model provenance and demand source/control/sink closure for imported candidates. Build regression fixtures for custom propagators and sanitizers.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| [Sonar security rules](https://docs.sonarsource.com/sonarqube-server/user-guide/rules/security-related-rules)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Taint vulnerabilities and review-required security hotspots are different evidence classes. Sonar also supports custom sources, sanitizers, validators, and sinks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Treat all imported results as candidates, not findings. Validation decides reportable, rejected, or deferred; a hotspot cannot inherit vulnerability status merely from its producer.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [OSV-Scanner](https://google.github.io/osv-scanner/usage/) and [call analysis](https://google.github.io/osv-scanner/output/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Extract dependencies deterministically, match authoritative advisories, and use call information to distinguish called from apparently unused vulnerable code.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Add deterministic SBOM/lockfile inventory and advisory ingestion, then use Copilot for repository-specific reachability, compensating controls, and remediation boundary analysis.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| [Trivy repository scanning](https://www.trivy.dev/docs/latest/guide/target/repository/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | One repository pass can cover vulnerable dependencies, misconfiguration, secrets, and licenses.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Accept these result families through SARIF now; later add opt-in local adapters while keeping each family’s evidence and completion semantics distinct.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| [Trivy SARIF reporting](https://trivy.dev/docs/latest/configuration/reporting/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | SARIF 2.1.0 is a practical interchange format across vulnerability, misconfiguration, secret, and license scanners.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Implement repeatable `--seed-sarif` intake rather than tool-specific parsers. Preserve normalized provenance and never copy a producer’s conclusion into canonical findings.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| [Trivy secret scanning](https://www.trivy.dev/docs/latest/guide/scanner/secret/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Built-in and custom rules, allow rules, path bounds, and explicit skip behavior reduce secret-scanning cost and noise.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Future deterministic secret discovery must redact values before model access, preserve only local fingerprints, distinguish test fixtures, and make exclusions auditable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| [Gitleaks](https://github.com/gitleaks/gitleaks)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Git-patch history scanning, full redaction, stable fingerprints, baselines, and scoped allowlists make high-volume secret findings manageable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Scan bounded reachable Git blobs locally through a trusted executable, deduplicate revision occurrences, use expiring justified keyed baselines, and never persist or display raw secret material.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Stable rule IDs, relative paths, locations, severity/precision metadata, and partial fingerprints support interoperable alert tracking.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Normalize relative paths and rule metadata, but hash source documents locally and omit imported fingerprints because they may contain arbitrary or sensitive producer data.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

## Implemented: shell-quote object-token sanitizer-bypass reachability

GHSA-w7jw-789q-3m8p demonstrates why an escaping-library alert is neither a
generic command-injection finding nor sufficient evidence by itself. The
affected serializer fails only for an attacker-shaped object token whose `op`
contains a line terminator. The quoted result must then reach a command-string
boundary or a real POSIX interpreter; ordinary string quoting and shell-free
argument-vector execution remain safe from this defect.

Copilot Security closes that conjunction as one auditable path. It proves an
official `shell-quote` binding and affected production resolution, exact
object-token construction either directly or from a `parse()` environment
callback, propagation of the serialized result, and official Node process
dispatch with an actual POSIX shell. The paired 1.8.3/1.8.4 fixture runs only
`pwd` in `/tmp` on Ubuntu/WSL and checks serialization without shell execution
on Windows. Comment and glob objects were tested separately and deliberately
excluded because they do not preserve the advisory's attacker value.

Current public CodeQL source contains no advisory or CVE reference; its
inspected `shell-quote` examples parse into shell-free `execFileSync` argument
vectors. Public Semgrep rules contain no advisory, CVE, or package reference.
The first comparison-scanner search found no advisory or CVE and one package
reference before GitHub throttled later queries, while local snapshots predate
the advisory. These results establish the searched boundary, not a permanent
claim about remote scanner coverage. Review remains effect-bounded: the model
establishes CWE-77/CWE-78 command execution reachability, but filesystem,
network, credential, persistence, or privilege impact requires separate
evidence of the injected command and execution identity.

## Implemented: reachable Sequelize Oracle escaping advisory model

GHSA-v8fg-2rw7-q452 is a useful example of the gap between dependency
inventory, generic SQL taint, and application exploitability. The vulnerable
code is inside Sequelize's ordinary value escaping, so the application can use
an ORM object predicate rather than visibly concatenating SQL. At the same
time, package presence is too broad: the injection requires an Oracle dialect,
an affected production resolution, attacker control of a value that actually
enters a model query, and a deployed database path that accepts and executes
the generated syntax.

Copilot Security now closes those conditions as one auditable path. It binds an
official Sequelize constructor to the exact Oracle-configured instance, the
instance to a model produced by `define`, remote data to `where`, and the model
to an executed ORM operation. Dependency and dialect evidence remain separate
propagators. The paired 6.37.3/6.37.4 fixtures reproduce the real query
generator without loading an Oracle driver or contacting a database: the
affected package emits the injected predicate and the repaired package rejects
the same value. Following Sonar's hotspot distinction, generated injectable SQL
establishes CWE-89 candidate evidence but does not automatically inherit a
claim of data theft, tampering, authentication bypass, or database-host
execution; those impacts require deployed-driver, privilege, row-policy, and
concrete-effect validation.

The public CodeQL and Semgrep source searches completed before GitHub search
throttling showed no matching advisory/CVE model, while the available local
comparison-scanner snapshots also contain no matching term but predate the
advisory. The implementation therefore records the comparison boundary rather
than overstating remote-head coverage.

## Implemented: reachable archive-writer advisory models

Dependency scanners correctly identify known-vulnerable archive packages, but
package presence alone cannot establish whether remote archive bytes reach an
extracting API, whether a destination is supplied, or which filesystem
primitive and downstream impact are reachable. Copilot Security now combines
exact production resolution with source-to-extraction closure for
`@xhmikosr/decompress` and unmaintained upstream `decompress`. It distinguishes
parse-only overloads from extraction, carries the exact affected version into
the path, and asks reviewers to validate entry traversal, sibling-prefix
confusion, hardlinks, symlinks, link-pivot writes, and special mode bits
separately. This applies the call-analysis idea used by OSV-Scanner while
retaining CodeQL-style path evidence and Sonar's distinction between a proven
vulnerability and a review-required impact hotspot.

The source-identical 10.2.0/10.2.1 pair and bounded installed-package witnesses
make both reachability and repair executable. Exact searches found no matching
application model in the reviewed public CodeQL or Semgrep sources or in the
comparison scanner, so this lane complements rather than duplicates generic
path traversal and dependency alerting. Findings cannot infer overwrite of a
valuable file, persistence, execution, or privilege escalation without an
independently evidenced writable target and consumer.

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
9. Bind the exact normalized candidate bytes and ordered source digests into
   the immutable launch recipe. At completion, reconcile every reserved seed
   identity against the ledger and fail on missing, duplicate, invented,
   out-of-scope, identity-mutated, or incomplete rows.
10. Generate a deterministic, manifest-sealed closure receipt with exact
    `reportable`, `rejected`, `deferred`, and `out_of_scope` totals and one
    terminal record per seed. Deferred seeds force partial completeness.

`benchmarks/sarif-seed-manifest.json` is the initial ensemble lane. Its
positive case should retain a seeded command injection; its negative case
feeds a high-severity false-positive process-execution seed that must be
rejected. Both source SARIF files contain hostile messages and fake credential
text, allowing artifact inspection to prove that the host removed those fields
before model execution. The benchmark now gates the receipt itself: each case
must have the expected closure totals, unique reserved instances, a canonical
coverage reference, and the receipt's exact digest in the sealed manifest.

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
one direct service wrapper or up to two additional uniquely typed service
relays. It records every receiver type binding and exact argument and parameter
position, including bounded local URI, request-object, and path
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
The C# layer now follows one direct service wrapper or up to two additional
uniquely typed service relays and records every type binding and argument
position. Bounded Node/TypeScript and Python cross-file layers
additionally resolve explicit repository-relative imports
into exported or public module-level wrappers and preserve the exact
argument-to-parameter position. Node/TypeScript follows either one direct
wrapper or up to two exported relays before the sink wrapper. Axios calls are
accepted only through a real package binding or bounded non-reassigned
`axios.create(...)` instance, and only the URL argument or request-config
`url` property participates in destination flow. This avoids both literal
receiver false negatives and generic `.get`/`.post` or body-only false
positives. Python follows one direct relative from-import or up to two public
module-level relays and parses bounded complete relay and sink calls so multiline forwarding,
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

### GitHub Copilot SDK trusted-instruction boundary

The typed Node lane now recognizes an exact named `CopilotClient` binding from
`@github/copilot-sdk` and a uniquely constructed non-reassigned receiver at
`createSession` or `resumeSession`. It extracts only model-visible trusted text:
top-level system-message content, customize-section content and known-section
transforms, inference-visible custom-agent prompts/descriptions, and tool
descriptions. Command descriptions are completion-UI metadata and are excluded.
Content under an unknown customize-section name is retained because the SDK
falls back to appending it as additional instructions. A fixed trusted
configuration with attacker text only in the later `send` or `sendAndWait`
prompt is rejected because that text remains in the user-message channel.

The parser follows named object/array entries and eight local value aliases,
then reuses the existing exact relative-import summaries for up to two wrapper
boundaries. It accepts named ESM aliases and CommonJS destructuring, but rejects
default/namespace guesses, lookalike packages, duplicate or reassigned clients,
client parameters, unrelated same-named methods, a ninth alias, inert fields,
content ignored by `remove`/`preserve`, non-inferred agent descriptions,
command descriptions, and comments or string examples. This conservative binding loses some unusual
construction styles but prevents generic `.createSession` calls and words such
as `prompt` or `description` from becoming findings.

`benchmarks/node-copilot-prompt-injection-manifest.json` pairs a six-propagator
three-file exploit with the same topology using only the ordinary user-message
channel. Perfect single-run gates require CWE-1427, repository-grounded code
evidence, validation, attack-path continuity, stable severity, and zero control
findings. Focused regressions separately exercise every trusted field,
`resumeSession`, unknown-section fallback, import styles, exact alias bounds,
allowlist counterevidence, and adversarial binding failures.

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
request-to-filesystem lane. One positive carries an HTTP query value through
one unique same-package wrapper, joins it beneath a public directory, and
passes the result to `os.ReadFile`. Its cross-platform test proves a `..`
payload reads a sibling signing-key witness. Its matched control preserves the
request, wrapper, payload, directory layout, and allowed-file behavior but
opens through `os.OpenInRoot`, which rejects the escape. A second pair captures
the [CodeQL 2.26.2 correction that `filepath.Rel` is not a path-injection
sanitizer](https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.26.2/).
The exploit rejoins an unchecked `Rel` result and reads the same class of
sibling secret. The control rejects an exact `..` and a `..` prefix followed by
the platform `os.PathSeparator`, while preserving allowed-file behavior.

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
`Rel` remains a tainted construction propagator. An exact
`relative-parent-boundary-rejection` candidate requires equality with `..` and
a `strings.HasPrefix` check against `".." + string(os.PathSeparator)` on the
same derived variable; either half, another variable, or a post-sink check is
rejected. It remains reviewer evidence until control flow proves that the check
dominates the exact sink and fails closed.
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
unscoped deletion plus its principal-bound control. An eleventh pair carries
the object key and authenticated principal through a handler, imported service,
and imported repository. The object-wrapper graph composes up to 32 exact
same-package or cross-package boundaries and retains each call, string
parameter, and object alias. Principal parameter positions are remapped at
every edge, so only the exact context-derived account can preserve the
same-query control. The deepest `go.mod`, exact local-module import and alias,
exported unique target, and top-level argument flow must agree. Duplicate
routes to one sink, duplicate module identities, ambiguity, cycles, package or
function shadowing, nested, deferred, or goroutine calls, multi-name
assignments, fixed-map selection, object replacement, the thirty-third edge,
and composition beyond 4,096 candidate paths fail closed. The executable
positive proves a victim deletion; the matched control keeps the complete
wrapper topology and proves the victim survives while an owned deletion still
succeeds. A twelfth pair calls an imported concrete service method and then a
repository method through a local interface value initialized from one exact
imported implementation. The method graph preserves `T` versus `*T`, receiver
parameters, direct construction, up to eight receiver aliases, interface method
membership, the interface-to-concrete binding, and every object and principal
position. Unbound interface parameters, nil pointer variables, unresolved or
ambiguous promotion, method values, dynamic callbacks, nested or
unknown reassignment, duplicate receiver methods, pointer methods on an
interface-held concrete value, and a ninth alias fail closed. Its executable
positive proves victim deletion; the matched principal-scoped control proves
the victim survives and an owned deletion still succeeds. A thirteenth pair
obtains the imported service from an exact constructor, retains a constructor-
local alias and return boundary, and traverses a named concrete repository
value field before the second method. Constructors require one unique
same-package or exact local-module function, one matching local struct result,
an exact ordinary or minimum variadic argument count, and one direct composite
return or alias chain of at most eight bindings.
Concrete field chains retain every declaration and its per-file import identity
and stop after eight fields. Returned parameters, nested or multiple returns,
constructor function values or shadowing, and unresolved, interface-promoted,
generic, duplicate, missing, or ambiguous fields fail closed. Its positive deletes the
victim; its control keeps the complete constructor/field topology and proves the
victim survives while an owned deletion succeeds. A fourteenth pair injects one
of two valid repository implementations through a constructor parameter into an
interface field. The host maps keyed constructor fields to exact parameters or
direct concrete expressions, carries instance identity through call-site aliases,
enumerates valid method implementations, and narrows the summary to the concrete
argument and its Go method set. Missing initialization, unbound interface values,
constructor-parameter reassignment, wrong concrete field types, and value
instances lacking a required pointer method fail closed. The positive proves
that only the selected repository sink is reached; the control preserves the
multiple-implementation topology and adds only the authenticated account
predicate. A fifteenth pair places that selected implementation inside a nested
pointer layer and initializes unrelated scalar fields in the same ordinary
multiline composite. The host recursively materializes only exact local
struct/interface instance fields, accepts trailing-comma formatting, retains
each nested assignment, and stops at the existing eight-field selector and new
thirteen-line statement bounds. A fourteenth statement line, unresolved nested
receiver, wrong inner type, referenced-parameter reassignment, or unsatisfied
method set fails closed; scalar fields do not erase an otherwise exact receiver
path. The positive proves the nested selected sink deletes, and the control
preserves the topology while adding only principal scope. A sixteenth pair
constructs an empty service and writes its nested pointer layer afterward
through an alias. The host models exact top-level linear writes, shares pointer
state, copies value state, records the real write line, accepts ordinary
multiline composites, and bounds both aliases and writes at eight. Conditional,
invalid-dereference, unresolved, over-bound, and parameter-reassigned writes
fail closed. The positive reaches only the selected implementation; the control
adds only principal scope. A seventeenth pair builds the parent pointer layer
before injecting its repository through a later nested selector. The host keeps
a recursive constructor-state tree with a distinct origin per field, requires
every parent to be a materialized exact keyed composite, shares pointer fields
across shallow value copies, recursively copies concrete value fields, and
replaces only the written leaf. Missing or dynamic parents, wrong types,
conditional writes, and a ninth selector field fail closed. The positive reaches
only the injected primary implementation; the control again adds only principal
scope. An eighteenth pair exercises one explicit top-level constructor branch
whose arms write the same nested field through different aliases of
the returned pointer. The host clones the complete alias and shared-value graph
per arm, applies the existing eight-write bound per executable path, retains up
to four write origins, and joins only identical complete states. Chains require
a final `else`; arms are limited to sixteen structural lines and exact field
writes on pre-existing aliases.
One-sided or divergent state, different objects, branch-local assignments,
nested control flow, early returns, unequal write budgets, a fifth arm, missing
final `else`, and a seventeenth arm line fail closed. The positive reaches only
the joined primary implementation; the control again adds only principal scope.
A nineteenth pair
materializes the constructor's parent pointer from one exact receiverless
same-package helper in a separate file. The host follows a matching keyed
composite through bounded aliases or helper calls, substitutes only bare
non-reassigned parameters, and preserves call, creation, alias, return, binding,
write, and receiver evidence at their actual paths and lines. Duplicate or
shadowed helpers, cycles, ninth calls, result pointer/value mismatch,
transformed parameters, positional composites, nested or multiple returns, and
dynamic state fail closed. The positive reaches only the injected primary
implementation; the control again adds only principal scope. A twentieth pair
moves the allocator into another package under the same authoritative local Go
module. The host requires the exact import path and ordinary alias, exported
helper, type, and traversed field, unshadowed package identity, and a unique
local definition. The helper composite retains its defining-package identity
through constructor substitution and shares the eight-call bound with local
helpers. Multiline constructor fields retain the qualified helper expression's
actual line. Wrong or external module paths, function values, unexported or
duplicate targets, and package/type mismatches fail closed. The positive reaches
only the imported-parent-selected primary implementation; the control again
adds only principal scope. A twenty-first pair moves the repository injection
inside that imported helper. The host preserves pointer-alias sharing and
direct value-field copying, requires exact top-level linear writes and every
nested parent, checks field and pointer identity at each selector, and records
the writer alias and field-write line independently. Conditional writes,
other than the exact all-path shape described below, invalid dereferences,
missing parents or fields, transformed parameters, and ninth writes fail closed.
A twenty-second pair exercises a shallow value copy:
concrete fields copy recursively while a nested pointer holder preserves exact
identity across copies and deeper value fields. Replacing that pointer detaches
only the selected copy. Complete helper-boundary evidence follows the shared
node. The positive reaches only the helper-copy-selected primary
implementation; its control again adds only principal scope. A twenty-third
pair places the same nested write on both explicit arms of a top-level helper
`if`/`else`, using different value copies that share the holder. Each branch
executes against a complete identity-preserving graph clone. The host joins only
structurally identical post-branch states under a bidirectional node mapping and
merges both alias chains and both write origins as evidence. Concrete-value
isolation, asymmetric sharing, pointer-slot replacement, divergent
implementations, branch-local assignments, nested control flow,
unequal write counts, a ninth write, and a seventeenth arm line fail closed. The
positive reaches only the all-path primary implementation; its control again
adds only principal scope. A twenty-fourth pair exercises an imported helper
`if / else if / else` chain. Three shallow value copies write the same shared
holder on three explicit paths, and the scanner preserves all three write
origins while enforcing complete-state and one-to-one identity convergence.
Exact chains accept two through four arms and require a final `else`; a fifth
arm, incomplete chain, unequal writes, or divergent state fails closed. This
is followed by a twenty-fifth pair using an exact `switch` with two named cases
and a mandatory final `default`. The same bounded world replay retains all three
write origins and requires complete-state and one-to-one identity convergence.
Missing or non-final `default`, `fallthrough`, labelled or non-terminal `break`,
empty or divergent arms, nested control, a fifth arm, and over-budget paths fail
closed. A twenty-sixth pair uses an expressionless `switch` whose three arms end
with explicit unlabelled `break` statements. Only an exact final break is treated
as Go's redundant case terminator; the same bounded world replay retains all
three write origins and requires complete-state and one-to-one identity
convergence. General initializers and type switches, labelled or non-terminal
breaks, and all existing divergence and resource failures remain fail closed. A
twenty-seventh pair uses `switch selected := label; selected` to exercise one
bounded initializer. The guard must be a fresh short-declared name sourced
directly from an exact built-in scalar parameter, must be the switch expression,
and cannot appear in an arm body. Call results, composite or non-scalar sources,
mismatched guards, parameter or prior-local shadowing, and all other initializer
forms remain rejected. The same complete-world replay retains all three write
origins and requires identity-compatible convergence. A twenty-eighth pair
covers exact type switches sourced directly from one uniquely resolved
interface parameter. Both unbound and fresh guard-bound spellings are admitted;
a named guard can be consumed only by an exact leading blank assignment and
cannot affect the tracked graph. Scalar, selector, conversion, shadowed, and
ambiguous sources, or any value-bearing guard use, fail closed. A twenty-ninth
pair carries the interface source through two exact local aliases. The host
follows up to eight top-level, single-name, value-preserving assignments,
invalidates overwritten names, and rejects a ninth hop, transformation,
selector, multiple assignment, concrete replacement, or nested/conditional
binding. A thirtieth pair admits an exact empty-interface conversion either
inline or through one of those bounded locals. Literal `interface{}` cannot be
shadowed. The `any` spelling additionally requires a compatible module language
version and proof that no same-package declaration, current-file import,
parameter, receiver, named result, or preceding local declaration shadows the
predeclared alias. Effective local import package names are resolved before the
path basename fallback. Unqualified call-shaped constructor-helper expressions
must now name an actual same-package function, so conversions and built-ins do
not truncate helper call, alias, write, and return evidence. A thirty-first pair
adds exact named basic-interface conversions. The target name must resolve
uniquely after lexical shadow checks. Identical and named-empty interfaces are
admitted; a distinct nonempty target requires a same-package basic interface
whose every method and canonical signature is present in the source method
set. The tracked alias changes static interface identity while preserving the
original parameter and dynamic value. Nested calls or conversions, selectors,
composite arguments, broader or signature-mismatched targets, constraint
interfaces, unresolved or cross-package nonempty signatures,
shadowed targets, shadowed `any`, pre-1.18 modules, and a ninth assignment edge
remain rejected. A thirty-second pair closes that cross-package boundary with
bounded canonical Go identities. Parameter and result names are discarded,
grouped declarations are expanded, imported named types bind to import paths
instead of file-local aliases, local named types retain package identity, and
unexported methods retain their declaring-package identity. Exact exported
method sets can therefore match across files and local-module packages while
different aliases, result types, package types, cross-package unexported
methods, duplicate or unresolved imports, dot/blank imports, and unsupported
type grammar fail closed. The same complete-world and topology proof is
retained. A thirty-third pair expands named embedded basic interfaces before
that comparison. One unqualified same-package declaration or one qualified
local-module declaration is resolved per edge, with eight edges and 64 merged
canonical methods as hard limits. Diamond duplicates require identical
signatures, and lower-case method identity retains its declaring package.
Cycles, conflicts, ambiguity, a ninth edge, external or non-interface terms,
and incomplete imports fail closed. A thirty-fourth pair follows exact
[Go alias declarations](https://go.dev/ref/spec#Alias_declarations) through
the same proof. Direct and grouped non-generic aliases may identify method
signature types, embedded contracts, constructor parameters and fields, type
switch sources, and conversion targets. One shared eight-edge resolver uses
each declaration's own package/import context and preserves the aliased type's
identity. Defined types are not collapsed. Generic, cyclic, duplicate,
ambiguous, unexported qualified, unresolved, external, pointer, over-depth, or
non-interface endpoints fail closed. This closes a compatibility-package
false negative without adopting a broad name-equivalence heuristic. It
follows the [Go conversion and assignability rules](https://go.dev/ref/spec#Conversions),
which preserve representation for this conversion family. It directly
implements OWASP API1:2023's exact object check across aliased contracts. A
thirty-fifth pair follows local concrete embedded fields using the official
[selector depth rules](https://go.dev/ref/spec#Selectors) and
[promoted method-set rules](https://go.dev/ref/spec#Struct_types). The host
searches breadth-first, accepts exactly one method at the shallowest depth,
distinguishes value and pointer method sets for interface satisfaction, applies
addressability only to ordinary concrete calls, retains every promotion edge,
and requires exact construction of embedded pointer fields. Direct fields or
methods hide deeper names. Same-depth collisions, cycles, a ninth edge,
unresolved or external types, embedded interfaces, generic forms, visibility
violations, and duplicate methods fail closed. The exploit reaches an unscoped
database deletion through two promoted fields; the control preserves that path
and binds the same predicate to the authenticated account. This directly
implements OWASP API1:2023's
[exact-object authorization requirement](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
for a standard-library Go boundary that the current [CodeQL Go query
index](https://codeql.github.com/codeql-query-help/go/) and published [gosec
rule list](https://github.com/securego/gosec/blob/master/RULES.md) do not expose
as a dedicated query. CodeQL's [official Go data-flow documentation](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-go/)
defines recursive `localFlow` over zero or more value-flow steps and distinguishes
it from configurable global interprocedural flow, while its
[Go library documentation](https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-go/)
describes call-graph target resolution; Semgrep documents explicit taint
propagators plus [separate per-file and cross-file analysis modes](https://semgrep.dev/docs/writing-rules/glossary).
This host's differentiator is therefore not the existence of interprocedural
analysis, but a standalone deterministic proof path with explicit bounded
failure semantics and executable object/principal controls. External-module
and parameter-transforming helpers, nested helper branches, five-or-more-arm
chains and switches, side-effecting or composite initializers, type switches
over selectors, unresolved named or nested conversions, transformed, composite,
field-held, package-held, or branch-joined aliases, or value-bearing guards,
one-arm conditionals
proven from pre-state, loop-sensitive writes,
unbound interfaces, embedded promotion, function-value object wrappers, nested and
multi-result-set loops, joins, composite keys, row mappers, policy services,
sqlc, ORMs, general dominance and nested joins, and deployment authorization remain
future work.

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

`benchmarks/java-multi-hop-path-manifest.json` adds a strict four-file Spring
path lane. The positive carries an annotated request value across a controller,
facade, service, and store into typed `java.nio.file.Files.readString`;
untrusted parent components or an absolute later `Path.resolve` operand can
escape the configured root. The negative preserves the topology while
rejecting absolute input, checking normalized component-aware containment,
resolving the existing root and target through `toRealPath`, and checking real
containment before the read.
Pure-JDK witnesses prove parent traversal, absolute-root reset, sibling-prefix
rejection, symbolic-link rejection where supported, and an allowed in-root
read. This follows CodeQL's [Java partial path-traversal query](https://codeql.github.com/codeql-query-help/java/java-partial-path-traversal/)
and Oracle's [path-operations semantics](https://docs.oracle.com/javase/tutorial/essential/io/pathOps.html).
The host treats these operations as candidate evidence, not automatic safety:
normalization cannot resolve links, string prefix checks are not component
checks, and link-capable or concurrently mutable roots require stronger
filesystem-boundary proof.

The same manifest now includes a second exploit/control pair derived from the
[CodeQL 2.26.2 correction](https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.26.2/).
The positive applies exact `java.io.File.getName()` basename reduction before
the typed read. The JDK [`File.getName()` contract](<https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/io/File.html#getName()>)
still permits `new File("..").getName()` to return `..`, so that reduction is
not parent-component rejection. Its matched control rejects the exact reduced
parent value before the operation. The specialization requires an existing
Spring path proof, exact `java.io.File` identity, and exact result reachability;
a local `File` lookalike, another object's `getName`, a reassigned result, a test
or dedicated `examples` directory, weak logging, another variable, or a
post-sink rejection fails closed. Even the exact rejection remains reviewer evidence because links,
junctions, mounts, attacker-writable directories, races, platform semantics,
tenant boundaries, and object authorization are separate questions.

The specialization now follows a bounded local helper return as well. This
borrows the explicit input-to-return summary idea from CodeQL's
[Java/Kotlin library modeling](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-java-and-kotlin/),
but keeps a stricter host boundary because no compiler database is available:
one unoverloaded symbol, official parameter/return types, one straight-line
return, and exact fixed arity, argument position, and value identity. Same-file
calls may be bare, `this`-qualified, or exact-owner calls. Cross-file calls must
stay in the nearest Maven project or conventional Gradle project/module,
resolve one top-level owner through the same package, an exact single-type
import, or a fully qualified name, and invoke an accessible static method;
cross-package use also requires a public top-level type and method. Exact
Gradle Groovy/Kotlin build scripts and settings files partition ordinary
modules and nested composite builds, with the deepest ancestor winning. This
prevents an unrelated sibling duplicate from suppressing a real local summary
and prevents an undeclared sibling helper from supplying a call target. Direct
Gradle compile-classpath project edges are recovered only from literal
top-level declarations under one unique conventional settings build. Direct
Maven reactor edges are recovered only when literal module membership, exact
effective coordinates (including verified local-parent inheritance), a unique
top-level dependency, compile/provided scope, ordinary JAR identity, and
conventional production source roots all agree. Dependency management,
properties, transitive paths, classifiers, overlapping reactors, and custom or
dynamic layouts remain outside the bounded proof. That conservative policy reflects the owner, accessibility,
applicability, arity, and overload work required by
[JLS 15.12](https://docs.oracle.com/javase/specs/jls/se21/html/jls-15.html#jls-15.12).
Wildcard custom imports, duplicate owners, nested projects, inaccessible or
instance methods, branches, transformations, reassignment, helper chains,
arbitrary receivers, and lookalike types are rejected. Reduction evidence
points to the helper file while any parent rejection remains caller-side. Both
Java basename benchmark pairs now cross this compilation-unit boundary in
their Spring fixtures; their dependency-free JDK witnesses retain the same
runtime exploit/control proofs.

The third pair closes the analogous `java.nio.file.Path.getFileName()` gap.
Oracle [defines `getFileName`](<https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Path.html#getFileName()>)
as returning the farthest lexical name element;
the executable witness confirms that `Path.of("..").getFileName()` remains
exact `..` and escapes when resolved beneath a trusted root. The host requires
exact imported or fully qualified `Path.of`/`Paths.get` identity, exact request
reachability into that factory or a typed `Path` parameter, exact receiver or
direct reduction, and exact result reachability to the existing typed sink. It
now applies the Java 21 [shadowing rules](https://docs.oracle.com/javase/specs/jls/se21/html/jls-6.html#jls-6.4.1)
across compilation units in the same package: a single-type import is
authoritative, while an on-demand import loses to a same-package top-level
`Path` or `Paths`. This approaches the resolved type and method identity exposed
by [CodeQL's Java type model](https://codeql.github.com/docs/codeql-language-guides/types-in-java/),
while remaining conservative without a compiler database. Nested and
different-package names do not suppress the official binding. Exact and
on-demand static `Path.of`/`Paths.get` imports are eligible only without a local
method, qualified lookalike call, or competing same-name static import. It
removes the previous generic `getFileName`/`getNameCount` candidate control and
records only exact pre-sink equality with `Path.of("..")` or `Paths.get("..")`
as a parent-rejection lead. That equality is now branch-sensitive: its matching
branch must itself return or throw unconditionally, the condition cannot be
negated or conditionally conjoined, the completion cannot be caught before the
sink, and the guard must share the sink's lexical block path. This bounded
control rule follows Java's distinction between normal and abrupt statement
completion in [JLS Chapter 14](https://docs.oracle.com/javase/specs/jls/se21/html/jls-14.html)
and the guard/dominance relation exposed by CodeQL's Java
[Guards](https://codeql.github.com/codeql-standard-libraries/java/semmle/code/java/controlflow/Guards.qll/module.Guards.html)
and [Dominance](https://codeql.github.com/codeql-standard-libraries/java/semmle/code/java/controlflow/Dominance.qll/module.Dominance.html)
libraries. The host deliberately fails closed rather than claiming a complete
compiler CFG. Local `Path`/`Paths` lookalikes, another object's
method, fixed factory input, cleared results, unrelated parallel reductions,
tests, logging, optional nesting, unrelated nearby throws, substring checks,
and post-sink checks fail closed. Provider,
zero-element/null, volume, separator, link, mount, writable-directory, race,
tenant, object, and concrete-effect proof remains independent.

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

`benchmarks/aspnet-multi-hop-path-manifest.json` adds a strict four-file path
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

1. **Expand typed framework security models.** Extend Node/TypeScript, Python,
   Java, and ASP.NET beyond their current three exact import or service
   boundaries only with measured false-negative evidence;
   extend the shipped routed Sails Action2 declared-input path source beyond
   its current exact relative wrapper and two-relay boundaries or into other
   sink families only with matched route/helper and fixed-operation controls;
   extend framework-specific authorization models beyond the bounded Node,
   Spring Data, and ASP.NET object-reference lanes, add ASP.NET template engines
   beyond the typed Scriban and RazorLight lanes,
   outbound-client APIs beyond JDK `HttpClient`, Spring `RestTemplate`,
   Spring `WebClient`, OkHttp, Axios, .NET `HttpClient`, and Go `net/http`;
   deepen the remaining Go SSRF, filesystem, template, process, and SQL lanes
   beyond their current wrapper bounds; extend Go object authorization through
   initialized pointer/interface receiver fields, constructor parameter and
   helper summaries, multi-implementation interface call graphs, policy
   services, sqlc, and ORMs;
   extend the shipped `database/sql`, sqlx, pgx, and pgconn lanes into sqlc wrappers,
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
5. **Seed-coverage receipts — shipped.** Imported-candidate closure is now a
   workbench-bound, deterministic, manifest-sealed contract. The host proves
   the exact normalized input digest and one terminal `reportable`, `rejected`,
   `deferred`, or `out_of_scope` record per seed; the dedicated benchmark gates
   these counts and the seal. Extend this evidence to future local analyzer
   adapters without weakening the current fail-closed identity rules.
6. **Ensemble benchmark lanes.** Run native-only and native-plus-seed campaigns
   over the same selected manifest. Gate the integration on improved recall or
   completion without precision, evidence, validation, attack-path, stability,
   or negative-control regressions.
7. **Optional analyzer adapters.** Provide opt-in command adapters that invoke
   a locally installed analyzer with argument arrays, resource/time bounds,
   no shell, no network by default, and SARIF-only handoff. Keep analyzer
   installation and licensing outside the core scanner.

## Implemented: correlated Nodemailer raw-message policy bypass

The reviewed [Nodemailer raw-root advisory](https://github.com/nodemailer/nodemailer/security/advisories/GHSA-p6gq-j5cr-w38f)
provides a useful example of why dependency and sink recognition are not enough.
Nodemailer through 9.0.0 omits its documented file/URL deny flags only while
constructing a message-level `raw` root. The official
[CodeQL email-client model](https://github.com/github/codeql/blob/main/javascript/ql/lib/semmle/javascript/EmailClients.qll)
recognizes Nodemailer delivery but exposes text, HTML, addressing, and subject
fields rather than `raw` or the deny-policy boundary. Authenticated current
source searches found no `disableFileAccess` implementation in CodeQL, no
Nodemailer model in the public Semgrep rules, and no Nodemailer model in the
reference scanner.

Copilot Security therefore adds a narrow application model instead of a
package alert. It requires exact vulnerable production resolution, official
factory and transporter identity, literal enabled policy, one proven remote
message object supplying both `raw` and `to`, and exact `sendMail` consumption.
It preserves distinct file-disclosure and full-response-SSRF taxonomies and
keeps uncorrelated parameters negative. The paired 9.0.0/9.0.1 benchmark and
real temporary-file/loopback witnesses verify both effects, the ordinary
attachment policy control, the repaired errors, source identity, and cleanup
on Windows and Linux. The next useful improvement is explicit two-track
correlation so independently propagated raw and recipient values can be
accepted only when both paths close at the same call.

## Implemented: persistent Socket.IO parser state reachability

The reviewed [Socket.IO parser zero-attachment advisory](https://github.com/advisories/GHSA-2m8v-j782-fhvr)
describes a pre-callback memory-retention defect in `socket.io-parser`. An
affected decoder accepts and emits a binary packet declaring zero attachments,
but leaves its reconstructor alive. Every later binary frame is appended before
the completion comparison, so the buffer count can never return to zero.
Official CodeQL has no `socket.io-parser` or `maxAttachments` reference; its
Socket.IO models begin at server/client event objects after parsing. Current
public Semgrep rules and the reviewed reference scanner also have no matching
model. Dependency-only scanners can identify an affected package, but cannot
prove that remote frames reach a persistent decoder instance.

Copilot Security therefore requires the complete path: an exact affected
production resolution, an official Decoder binding, a module-scope persistent
instance, and remote input at that instance's unmodified `add` method. It
rejects request-local decoders because their state cannot retain later frames,
as well as patched branches, fixed packets, Encoder calls, unresolved or
development dependencies, reassignment, replaced members, shadows, and tests.
The source-identical 4.2.6/4.2.7 pair and real package witnesses validate all
three upstream repair branches. In the accepted bounded witness, 4.2.6 retains
2,048 distinct 4 KiB frames (8 MiB), while 4.2.7 rejects the initial
`50-["evt"]` packet with `Illegal attachments` and retains nothing on both
Windows and Linux. `maxAttachments` does not repair the invalid zero-count
state; upgrade is the supported remedy.

## Implemented: exact brace-expansion work-amplification reachability

The reviewed [brace-expansion intermediate-array advisory](https://github.com/advisories/GHSA-rgw5-rvv9-x895)
closes two availability paths that bypassed the package's earlier cumulative
output-length check: comma alternatives could accumulate an unbounded
intermediate array, and padded numeric sequences could perform maximum-element
work without the intended `maxLength` constraint. Official CodeQL currently
contains six `brace-expansion` references, all attribution for adapted regular-
expression tests, and no `EXPANSION_MAX_LENGTH` reference. Current public
Semgrep rules contain neither string. The reviewed reference scanner recognizes
only its repaired lockfile version and has no application model.

Copilot Security binds the advisory to an actual request-to-expansion path and
the export contract of the installed major line: callable 1.x/2.x,
default/`.default` 3.x/4.x, or named/`.expand` 5.x. It rejects wrong APIs,
unresolved or nonproduction dependencies, fixed data, replaced bindings,
shadows, and tests. Explicit literal `max` and `maxLength` values remain visible
as incomplete control evidence rather than suppressing a bypass finding. The
5.0.8/5.0.9 source-identical benchmark and bounded witness prove the same 999
outputs and 3,996,999 characters while measuring 1,769.885 ms versus 25.389 ms.
This adds a reachable CWE-400/CWE-407 path that dependency-only scanning cannot
establish and that generic regular-expression complexity rules do not express.

## Implemented: operation-specific node-tar decompression reachability

The reviewed [node-tar decompression advisory](https://github.com/advisories/GHSA-23hp-3jrh-7fpw)
describes unbounded cumulative output from a small gzip, brotli, or zstd input.
The pre-repair `maxReadSize` option bounds only individual read chunks. Version
7.5.19 instead counts compressed and decompressed bytes inside the parser and
defaults the allowed ratio to 1000. Authenticated source searches found no
advisory or `maxDecompressionRatio` model in CodeQL, public Semgrep rules, or
the reference scanner.

Copilot Security combines affected production resolution with actual remote
archive reachability through the official `t`/`list`/`x`/`extract`/`Parse` and
`Unpack` APIs. It distinguishes listing, parsing, and extraction so validation
cannot turn parser CPU or throughput pressure into an unsupported disk-impact
claim. Patched releases, fixed archives, non-consuming create APIs, stale or
development dependency evidence, binding replacement, and wrapper shadows are
negative. A source-identical 7.5.18/7.5.19 pair and bounded installed-package
witness prove the 1017.97:1 completion-versus-abort boundary. The same work also
tightens shared npm lock proof so simple caret and tilde declarations cannot
resolve below their declared minimum.

## Implemented: exported Keystone list-limit reachability

The reviewed [Keystone negative-take advisory](https://github.com/advisories/GHSA-cqmq-8755-7xvh)
describes a signed-pagination error in `@keystone-6/core` through 6.5.2. The
resolver compares a requested `take` directly with `graphql.maxTake`, allowing
a negative magnitude greater than the configured limit. Version 6.5.3 applies
the limit to `Math.abs(take ?? Infinity)`. Authenticated source searches found
no advisory identifier, `maxTake`, or `@keystone-6/core` application model in
CodeQL, public Semgrep rules, or the comparison scanner repository.

Copilot Security binds affected production resolution to an official list with
a finite positive limit inside a default/CommonJS-exported Keystone runtime
configuration. It resolves named, namespace, TypeScript, CommonJS, direct, and
relative-list forms while rejecting inert package presence, unexported configs,
patched or unresolved versions, replaced bindings, nonpositive limits, omitted
queries, and statically deny-all access. Dynamic access rules and infrastructure
budgets remain validation questions rather than being credited as repairs. A
source-identical 6.5.2/6.5.3 pair and installed-package public-context witness
prove that `take: -5` crosses `maxTake: 3` only on the affected build, without a
listener or database.

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
