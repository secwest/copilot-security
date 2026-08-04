# Framework Data-Flow Models

Use these models as typed discovery hypotheses, never as findings. A model
becomes reportable only when repository evidence proves that the same
attacker-controlled value reaches the modeled sink through the identified
propagators and that no context-correct control dominates the sink.

The SDK's mandatory residual pass emits schema `1.2` `frameworkModel` records
with exact source and sink paths/lines, scope, propagators, and candidate
controls. Those records are host-authored metadata; their base64 source
excerpts remain untrusted repository evidence.

Within the host's bounded repository snapshot, wrapper and relay summaries are
enumerated before source reachability and final candidate selection. A large
set of unrelated wrappers must not silently hide a later reachable sink.

For Node/TypeScript, `scope: "cross-file-wrapper"` is emitted only when the
host can resolve a repository-relative ESM/CommonJS import to an exported
function, match the call's exact argument position to the exported parameter,
and see that parameter referenced on the dangerous sink line. The record
preserves the import, call, and declaration as propagators. This is a bounded
syntactic summary, not proof of runtime reachability, alias equivalence, or
exploitability. Reopen both files and disprove intervening reassignment,
shadowing, dead code, alternate exports, runtime dispatch, and dominating
controls before reporting.

For Python, the same scope is emitted only for an explicit relative
`from .module import symbol` boundary resolved to a repository `.py` module or
package initializer and a public module-level function. The host binds the
call's exact positional argument to the wrapper parameter and parses a bounded
complete sink call, including multiline DB-API parameter binding and f-string
expressions. Python comments and ordinary string contents cannot create
imports, calls, sources, or sink references. Reject absolute imports whose
runtime module identity is ambiguous, fixed arguments, request values
reassigned before the call, private or nested wrappers, and text-only examples.
This is still a syntactic summary; decorators, monkey patching, re-exports,
dynamic imports, keyword remapping, and arbitrary transformations require
manual closure.

For C#, the same scope is emitted only when the host resolves one unique
class, record, or struct owner for a controller field or static receiver,
parses public, protected, or internal controller and service methods, binds the
call's exact positional argument to the wrapper parameter, and sees that
parameter in the modeled sink expression. The ordered propagators preserve the
declared receiver type, call argument, and wrapper parameter. ASP.NET bound
parameter attributes and local assignments from `HttpRequest` fields are
supported, including bounded multiline calls and zero-parameter controller
methods. Reject duplicate simple type names, unresolved receivers, fixed or
reassigned arguments, parameters unused by the sink, and C# comments or string
examples that merely name an API.

For C#, `scope: "cross-file-multi-hop-wrapper"` extends that same discipline by
exactly one additional uniquely typed service relay. The host requires both
owner types to resolve to one source file, matches both positional arguments,
rejects reassignment before either call, and records both receiver bindings,
calls, and wrapper parameters in order. It does not infer interface dispatch,
dependency-injection registrations, named arguments, callbacks, or a third
service hop.

For Java, `scope: "cross-file-multi-hop-wrapper"` now applies the same exact
two-boundary contract to public or protected methods. Both simple owner types
must resolve to one `.java` source file, each call must preserve the exact
positional parameter without reassignment, and the final wrapper parameter
must reach the typed sink through either the sink expression or bounded local
Java assignments. The host records both Java receiver
bindings, calls, and wrapper declarations in order. It rejects duplicate type
names, local filesystem or outbound-client type shadows, fixed arguments,
text-only calls, and a third service hop; it does not infer interfaces, framework registrations,
overload resolution, named Kotlin arguments, callbacks, or reflection.

`scope: "cross-file-multi-hop-wrapper"` is the same bounded syntax extended by
exactly one exported JavaScript/TypeScript or public module-level Python relay.
Its propagators are ordered as caller import and argument, relay parameter,
relay import and argument, then sink-wrapper parameter. The host requires the
relay argument to be the exact unreassigned relay parameter and ignores
downstream calls outside the relay. Python relays require explicit relative
from-imports and exact positional forwarding; bounded multiline calls are
parsed, but keyword remapping remains outside the summary. Language strings
and comments are masked before structural matching; template and formatted-
string expressions remain visible only for exact parameter reference checks.
This is not general interprocedural taint analysis and does not cover a third
import hop, dynamic dispatch, re-export graphs, callbacks, or arbitrary
transformations.

## Model Tuple

For each applicable model preserve:

- activation: the imported runtime, driver, framework, or concrete API;
- source: the exact request field, bound argument, header, cookie, body,
  parameter, route value, or stored cross-boundary value;
- propagators: assignments, coercions, parsers, DTOs, helper arguments,
  template values, query builders, and wrapper return values carrying the same
  value;
- control: the closest allowlist, shape/type validator, context-specific
  encoder, argument-vector construction, parameter binder, authorization
  check, or missing guard;
- sink: the exact dangerous argument and callsite;
- outcome: the command, query, object, record, privilege, file, or process the
  attacker can influence;
- counterevidence: the strongest nearby safe sibling or negative control.

Do not call generic validation a sanitizer without proving its accepted
language excludes the dangerous syntax for the sink. Do not call escaping
context-correct without matching it to the command shell, SQL dialect, LDAP
filter, XPath expression, HTML/JavaScript context, path component, or other
interpreter that consumes the value.

## Initial Model Pack

### Node HTTP command execution — CWE-78

- Sources: Express/Fastify-style `req` or `request` body, cookie, file,
  header, parameter, and query fields; Koa `ctx` request fields; Next URL
  search parameters.
- Sinks: `child_process.exec`/`execSync`, or `spawn`/`spawnSync` with an
  explicitly enabled shell.
- Strong counterevidence: a fixed executable with an argument vector and no
  shell, plus type/length/grammar validation appropriate to that executable.

### Node HTTP raw SQL — CWE-89

- Sources: the same Node HTTP request surfaces.
- Sinks: raw query/execute calls in common SQL clients and unsafe Prisma raw
  APIs.
- Strong counterevidence: driver-native parameters or a typed query builder
  that keeps the attacker value out of SQL identifiers and syntax. A tagged
  template is safe only when the selected API binds interpolations rather than
  concatenating them.

### Node HTTP server-side request forgery — CWE-918

- Sources: the same Node HTTP request surfaces.
- Sinks: complete or partial outbound request URLs passed to `fetch`, common
  `axios`/`got` methods, Node `http`/`https`, Undici, or an activated HTTP
  client wrapper.
- Strong counterevidence: selection of one complete server-owned URL by exact
  key with redirects disabled, or a parsed exact-host allowlist combined with
  complete A/AAAA validation, connection-address pinning, preserved Host/TLS
  identity, and redirect revalidation or rejection. `new URL` alone is not a
  sanitizer: an attacker-controlled absolute first argument overrides its
  base. URL or hostname substring checks are bypassable and never count as
  exact-host validation.

### Node HTTP server-side template injection — CWE-1336

- Sources: the same Node HTTP request surfaces.
- Sinks: attacker-controlled template source passed to Pug, Handlebars, EJS,
  Nunjucks, Mustache, doT, or Lodash template compilation/evaluation APIs.
- Strong counterevidence: a fixed server-owned template whose untrusted value
  is supplied only through an explicitly constructed render-data field. Output
  escaping protects a data context; it does not sanitize attacker-controlled
  template grammar. A sandbox counts only when its callable, member, and global
  restrictions dominate the exact compilation and render path.
- Severity: a directly reachable HTTP source flowing into unsandboxed,
  general-purpose Pug template-source compilation or rendering is high
  severity even when deployment privileges, secrets, or runtime exploitation
  are outside static scope. Lower severity only when a proven sandbox, isolated
  renderer, constrained engine, or other dominating control materially limits
  impact on the same path.

### Python web command execution — CWE-78

- Sources: Flask/Django-style request collections and JSON, plus FastAPI bound
  body, cookie, form, header, path, and query parameters.
- Sinks: `os.system`/`os.popen`, or subprocess APIs with `shell=True`.
- Strong counterevidence: a fixed executable and argument list with no shell,
  or context-correct shell quoting when use of a shell is unavoidable and the
  entire grammar is otherwise fixed.

### Python web raw SQL — CWE-89

- Sources: Flask/Django request collections and FastAPI bound parameters.
- Sinks: DB-API/SQLAlchemy/Django raw `execute`, `executemany`,
  `executescript`, and `raw` paths.
- Strong counterevidence: native bound parameters or ORM expressions that do
  not permit request-controlled identifiers, operators, clauses, or raw
  fragments.

### Python web server-side request forgery — CWE-918

- Sources: Flask/Django request collections and FastAPI bound parameters.
- Sinks: outbound URL arguments to `requests`, HTTPX, urllib/urlopen, or an
  activated client/session wrapper.
- Strong counterevidence: selection of one complete server-owned URL by exact
  key with redirects disabled, or parsed exact-host validation plus complete
  address validation and connection pinning. `urljoin` is only safe when the
  attacker cannot supply a scheme-relative or absolute destination; parsing a
  URL without constraining the consumed host is not validation.

### Python web server-side template injection — CWE-1336

- Sources: Flask/Django request collections and FastAPI bound parameters.
- Sinks: attacker-controlled template source passed to Flask/Jinja
  `render_template_string`, Jinja/Django/Mako `Template`, or environment
  `from_string` compilation.
- Strong counterevidence: a fixed server-owned template with the untrusted
  value supplied only as a named render-context field. Autoescaping applies to
  data interpolation, not attacker-controlled template code. A Jinja sandbox
  is a lead rather than a verdict until its attribute, callable, and global
  restrictions are proven on the same environment and sink.
- Severity: a directly reachable HTTP source flowing into unsandboxed,
  general-purpose Jinja template-source compilation or rendering is high
  severity even when deployment privileges, secrets, or runtime exploitation
  are outside static scope. Lower severity only when a proven sandbox, isolated
  renderer, constrained engine, or other dominating control materially limits
  impact on the same path.
- Keep XSS separate from template-source injection. Jinja's
  `select_autoescape` defaults `default_for_string` to `true`; consequently,
  `select_autoescape(default=True)` also escapes unnamed `from_string`
  templates. A fixed HTML template, that autoescape policy, and a value passed
  only as `render(name=value)` are strong XSS counterevidence unless the path
  disables autoescape, applies `|safe`/`Markup`, concatenates into HTML, or
  otherwise bypasses the escaping context.

### Spring/servlet command execution — CWE-78

- Sources: `@RequestParam`, `@PathVariable`, `@RequestBody`,
  `@RequestHeader`, `@CookieValue`, and servlet request accessors.
- Sinks: `Runtime.exec` and `ProcessBuilder`.
- Strong counterevidence: a fixed executable and structured arguments with a
  strict, bounded allowlist for any attacker-selected operation.

### Spring/servlet raw SQL — CWE-89

- Sources: Spring-bound and servlet request values.
- Sinks: native-query, statement, `JdbcTemplate`, and related raw execution
  APIs.
- Strong counterevidence: `PreparedStatement`, named parameters, or equivalent
  binding. Values cannot safely parameterize SQL identifiers or keywords;
  those need an exact allowlist and server-owned mapping.

### Spring/servlet server-side template injection — CWE-1336

- Sources: Spring-bound request parameters and servlet request accessors.
- Sinks: attacker-controlled template source passed to Apache Velocity
  `evaluate`, Jinjava `render`, Handlebars `compile`, or Pebble
  `getLiteralTemplate`.
- Preserve engine argument roles. Apache Velocity's template-source string is
  the fourth `evaluate` argument after context, writer, and log tag. A request
  value stored only in `VelocityContext`, combined with fixed server-owned
  fourth-argument source, is strong SSTI counterevidence. It is not XSS
  counterevidence unless the rendered output context has proven encoding or a
  dominating equivalent control; Velocity does not provide general HTML
  auto-escaping.
- For cross-file rows, verify the receiver's unique declared Java type, exact
  public service method, argument position, wrapper parameter, and final engine
  argument. Duplicate simple class names, unresolved receiver types, values
  reassigned before the service call, and text-only API examples do not prove a
  flow.
- A directly reachable Spring or servlet source flowing into unsandboxed
  general-purpose Velocity template-source evaluation is high severity. Lower
  it only when a proven sandbox, isolated renderer, constrained engine, or
  other dominating control limits the same path.

### Spring/servlet server-side request forgery — CWE-918

- Sources: Spring-bound request parameters and servlet request accessors.
- Sinks: request objects or complete URI values passed to typed JDK
  `HttpClient.send`/`sendAsync`, typed Spring `RestTemplate` operations, or the
  first destination argument of typed reactive `WebClient.UriSpec.uri` calls.
- Preserve both uniquely resolved Java service types, exact arguments and
  parameters, and bounded local URI/request assignments. A local class that
  shadows `HttpClient`, `RestTemplate`, or `WebClient` is not an outbound HTTP
  sink. For WebClient request-spec aliases, reopen the typed root client and
  the request-producing method before accepting the `uri` receiver.
- `URI.create`, `new URI`, `HttpRequest.newBuilder`, parsing, and encoding do
  not authorize a destination. A WebClient `baseUrl` does not make an absolute
  attacker URI safe. Later variables applied to a fixed URI template are not
  complete-authority control. `HttpClient.Redirect.NEVER` or Reactor Netty
  `followRedirect(false)` rejects automatic redirect following but does not
  constrain the initial request URI; inspect the configured
  `ClientHttpConnector` for the actual transport behavior.
- Strong counterevidence is exact request-key selection from fixed,
  server-owned complete destinations plus redirect rejection. URL substring,
  suffix, scheme-only, or userinfo-insensitive checks are not host
  authorization.
- A parsed host allowlist still requires every DNS A/AAAA answer,
  connection-time resolution and pool reuse, proxies, the final socket address,
  and Host/TLS identity to remain bound or revalidated. Otherwise DNS rebinding
  and redirect pivots remain open.

### Spring/servlet filesystem path injection — CWE-22

- Sources: Spring-bound request parameters and servlet request accessors.
- Sinks: typed `java.nio.file.Files` read, write, copy, move, delete, channel,
  and stream operations, plus imported or fully qualified `java.io`
  `FileInputStream`, `FileOutputStream`, `FileReader`, `FileWriter`, and
  `RandomAccessFile` construction.
- Preserve both uniquely resolved Java service types, exact call arguments,
  wrapper parameters, and the final path argument. A local class that shadows
  `Files` or a `java.io` sink type is not a JDK sink.
- `Path.resolve` does not retain the trusted root when its later operand is
  absolute. `Path.normalize` is syntactic and does not resolve filesystem
  links. A bare `String.startsWith` check can admit a sibling directory prefix;
  component-aware `Path.startsWith` avoids that specific confusion.
- Strong counterevidence is an exact server-owned file map or a dominating
  boundary that rejects absolute input, normalizes under the intended root,
  checks component-aware lexical containment, resolves the existing root and
  target through `toRealPath`, and proves the real target remains beneath the
  real root before the operation. Reassess symbolic links, mount points,
  attacker-writable directories, `SecureDirectoryStream` availability, and
  rename races separately.

### ASP.NET process execution — CWE-78

- Sources: `[FromBody]`, `[FromForm]`, `[FromHeader]`, `[FromQuery]`,
  `[FromRoute]`, and `HttpRequest` fields.
- Sinks: `Process.Start` and `ProcessStartInfo`.
- Strong counterevidence: a fixed executable, `ArgumentList`,
  `UseShellExecute = false`, and operation-specific validation.
- For cross-file rows, preserve the exact receiver type, service-call argument
  position, wrapper parameter, executable, and command-line grammar. A request
  value incorporated into `cmd.exe /c`, PowerShell `-Command`, or an equivalent
  interpreter string is not made safe by passing through `ProcessStartInfo`.

### ASP.NET raw SQL — CWE-89

- Sources: ASP.NET-bound parameters and request fields.
- Sinks: `FromSqlRaw`, `ExecuteSqlRaw`, and `SqlCommand` construction.
- Strong counterevidence: interpolated APIs that bind values correctly,
  `DbParameter`/`SqlParameter`, or an exact server-owned mapping for dynamic
  identifiers.
- For `SqlCommand`, preserve the first constructor argument as query text. A
  request value referenced only by a typed parameter binding is
  counterevidence, not raw SQL flow; values still cannot parameterize
  identifiers or clauses.

### ASP.NET server-side template injection — CWE-1336

- Sources: ASP.NET-bound parameters and request fields.
- Sinks: the first template-source argument to the real Scriban
  `Template.Parse` API when that parsed template reaches `Render` or
  `RenderAsync`, and the second `content` argument of a typed RazorLight
  `IRazorLightEngine.CompileRenderStringAsync` call. Parsing without rendering
  is inert for Scriban; RazorLight's string API compiles and renders in the
  same call. Require the corresponding import or fully qualified type and
  reject local engine lookalikes.
- Preserve the uniquely resolved C# service type, controller argument,
  wrapper parameter, bounded local aliases, and exact first parse argument.
  The optional second source-file-name argument and parser options are not
  template source.
- For RazorLight, preserve the template key, content, and model roles. The key
  is the first argument, runtime template content is the second, and the model
  is the third. Resolve a named `content` argument by semantic name even when
  named arguments are reordered. `CompileRenderAsync(key, model)` resolves a
  project template and is not the direct string-source sink.
- Strong counterevidence is fixed server-owned template source parsed once,
  with attacker-controlled values supplied only through the resulting
  template's render model. The same applies to a fixed RazorLight content
  string with attacker values supplied only as model properties. Model strings
  are data and are not recursively compiled merely because they contain
  template delimiters.
- `TemplateContext`, `ScriptObject`, syntax validation, output encoding, and
  source-file metadata, RazorLight template keys or view bags do not make
  attacker-controlled template source safe.
  A restricted member filter or isolated context is a candidate control only
  after proving it dominates the same parsed template and removes the
  demonstrated capability.
- Classify a proven path as CWE-1336. Validate the actual exposed objects,
  callable members, secret disclosure, code-like behavior, or resource impact
  instead of assuming that every template grammar has identical power.

### ASP.NET server-side request forgery — CWE-918

- Sources: ASP.NET-bound parameters and request fields.
- Sinks: complete request-URI arguments to `HttpClient` convenience methods,
  including `GetAsync`, `GetStringAsync`, and the corresponding verb helpers.
- Strong counterevidence: an exact request value used only as a key into a
  bounded server-owned map of complete destinations, redirect rejection, and
  correct address validation plus connection pinning when hostnames remain
  configurable.
- `Uri` parsing, `BaseAddress`, timeouts, response ceilings, and
  `AllowAutoRedirect = false` do not constrain an arbitrary initial absolute
  URI. Hostname substring or suffix checks are not exact authority checks.
- Reopen proxies, every DNS A/AAAA answer, connection-time re-resolution,
  pooled connections, the actual socket destination, and Host/TLS identity.
  Redirect rejection closes only the redirect leg; it does not authorize the
  first destination.

### ASP.NET filesystem path injection — CWE-22

- Sources: ASP.NET-bound parameters and request fields.
- Sinks: path arguments to typed `System.IO.File` operations and `FileStream`
  construction, including reads, writes, creates, moves, copies, and deletes.
- Unqualified `File` and `FileStream` calls may be typed by a file-local using,
  a project-wide global using, or the nearest `.csproj`/applicable MSBuild
  property file with `ImplicitUsings` enabled. Local type shadows and projects
  that disable implicit usings remain negative evidence.
- `Path.Combine` and `Path.Join` construct strings; they do not establish
  containment. A rooted later `Path.Combine` operand can discard the trusted
  prefix, parent components can escape it, and normalization alone does not
  authorize the result.
- Strong lexical counterevidence: exact selection from a server-owned file map,
  or rooted-input rejection followed by canonical root/candidate resolution
  and an exact relative-to-root boundary check that dominates the file
  operation. A bare root string-prefix comparison can accept a sibling path.
- Reopen platform separators, drive and UNC forms, alternate data or device
  syntax where applicable, attacker-writable parent directories, symlinks,
  junctions, reparse points, rename races, and the exact read/write/delete
  effect. Lexical containment is not link-safe containment.

### Go HTTP object-level authorization — CWE-639 and CWE-862

- Source: query, form, path, or header data from an exact typed
  `*net/http.Request`, directly or through one unique same-package string
  wrapper.
- Protected effect: the request-derived identifier occupies an object-key
  equality predicate in fixed SQL executed by an exact typed `*database/sql.DB`,
  `*database/sql.Tx`, or `*database/sql.Conn`. A single-row read requires
  `QueryRow`, `Scan`, and disclosure of scanned data. A collection read
  requires exact `Query`/`QueryContext`, the same returned `Rows`, `Next`,
  `Scan`, and disclosure; `UPDATE` or `DELETE` through `Exec` is an immediate
  mutation effect. A mutation through a prepared statement requires the exact
  `Prepare`/`PrepareContext` result and later `Stmt.Exec`/`Stmt.ExecContext`.
  If that statement is prepared on a transaction, or an existing DB statement
  is transferred by exact `Tx.Stmt`/`Tx.StmtContext` source and result
  identities or an exact same-expression transfer/execution chain, keep the
  effect provisional until the same transaction reaches
  a non-deferred function-level `Commit`. Reject rollback, missing or premature
  commit, nested or deferred commit, finalization before execution, ignored
  transfer results, closed or replaced statements, and cross-transaction
  transfer.
- Authentication, middleware, opaque IDs, parameterized SQL, and a principal-
  named parameter do not authorize the selected object. Verify the exact
  placeholder-to-argument mapping, wrapper argument, object or collection,
  `Rows` identity, action, and denial path.
- Strong counterevidence: the same query also binds an owner, tenant, account,
  organization, user, or workspace predicate to a principal derived from the
  request context, or a fail-closed comparison of returned ownership data to
  that context principal dominates every disclosure. A request header or
  query value used as the owner filter is attacker controlled and is not a
  control.
- Reject dynamic or ambiguous query construction, fixed or reassigned object
  identifiers, immutable server-owned object selection, untyped database
  lookalikes, generic responses that do not expose selected data, and checks
  performed after disclosure or mutation.
- For a transferred statement, preserve the original prepare line, exact
  source statement, returned transaction statement, object predicate,
  execution arguments, transaction identity, and commit line. `StmtContext`'s
  context controls preparation rather than execution; it is neither the source
  statement nor proof of authorization. Confirm commit success and driver or
  database behavior before claiming durable impact.

### Go HTTP server-side template injection — CWE-1336

- Source: query, form, path, or header data from an exact typed
  `*net/http.Request`, directly or through one unique same-package string
  wrapper.
- Grammar boundary: argument zero to `(*text/template.Template).Parse` on an
  object created by the exact standard-library package. The parsed object must
  subsequently reach `Execute` or `ExecuteTemplate`; parsing without execution
  is inert.
- Preserve object identity through builder and parsed-template aliases and
  clear it on replacement. Require exact import identity; `html/template`,
  package lookalikes, duplicate or dot imports, local shadows, ambiguous
  wrappers, comments, and strings are not equivalent evidence.
- Strong counterevidence: a fixed server-owned template or immutable map of
  complete template sources with request data supplied only as execution data.
  Autoescaping addresses output contexts, not attacker-controlled template
  grammar. `html.EscapeString` leaves Go's brace-delimited directives active
  and is not an SSTI sanitizer.
- Inspect every registered `FuncMap` function and the exact value passed as
  execution data. Prove which functions, exported methods, secrets, files,
  network or process capabilities, state changes, recursion, or resource
  effects are reachable rather than assuming all template environments have
  identical impact.

## Closure Rules

- Trace across wrappers and files when the source and sink are separated.
- For cross-file wrapper rows, verify the resolved runtime module/export and
  exact argument-to-parameter position; reject unused imports, fixed arguments,
  source values overwritten before the call, shadowed symbols, and unreachable
  wrappers.
- For Python rows, verify package execution makes the relative import valid and
  preserve the distinction between a formatted SQL/shell expression and a
  driver-bound or shell-free multiline call.
- Preserve the exact argument position or object field accepted by the sink.
- Verify framework parsing and runtime types; JSON objects, arrays, dotted
  keys, and operator objects may survive a nominal string conversion in some
  stacks but not others.
- A source and sink in one file are not proof that they are connected.
- A safe sibling does not suppress a vulnerable callsite, and a vulnerable
  sibling does not make a parameterized or shell-free callsite vulnerable.
- For SSRF, distinguish full URL authority control from a bounded path segment.
  Reopen redirect behavior, proxy selection, DNS resolution, every A/AAAA
  answer, connection-pool reuse, the actual socket destination, and Host/TLS
  identity. A hostname allowlist without address validation and connection
  pinning does not close DNS rebinding.
- For filesystem paths, preserve the complete source-to-path chain and prove
  containment at the operation that consumes it. Treat exact server-owned
  selection or canonical relative containment as counterevidence only when it
  dominates that operation; separately close link and rename boundaries.
- For template injection, preserve the template engine's exact argument roles.
  Prove the attacker value becomes template source, grammar, or an evaluated
  expression. Classify that broken control as CWE-1336 rather than substituting
  generic code-injection CWE-94. A fixed template plus an untrusted context value is not SSTI;
  template-name selection and whole-object template-context injection are
  separate families that need their own source, sink, and impact proof.
- When a candidate is rejected, record the exact dominating control and why it
  is context-correct for that sink.
