# Framework Data-Flow Models

Use these models as typed discovery hypotheses, never as findings. A model
becomes reportable only when repository evidence proves that the same
attacker-controlled value reaches the modeled sink through the identified
propagators and that no context-correct control dominates the sink.

The SDK's mandatory residual pass emits schema `1.2` `frameworkModel` records
with exact source and sink paths/lines, scope, propagators, and candidate
controls. Those records are host-authored metadata; their base64 source
excerpts remain untrusted repository evidence.

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
- For template injection, preserve the template engine's exact argument roles.
  Prove the attacker value becomes template source, grammar, or an evaluated
  expression. Classify that broken control as CWE-1336 rather than substituting
  generic code-injection CWE-94. A fixed template plus an untrusted context value is not SSTI;
  template-name selection and whole-object template-context injection are
  separate families that need their own source, sink, and impact proof.
- When a candidate is rejected, record the exact dominating control and why it
  is context-correct for that sink.
