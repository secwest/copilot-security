# Validation Guidance

Use this guidance when validating candidate security findings.

## Instance-Preserving Validation

Validation does not choose whether the scan is diff-scoped or repository-wide. Use the scope and candidate set provided by the user, discovery report, or top-level security scan workflow. When validation is invoked directly for one named bug, validate that bug only unless the user explicitly provides multiple instances or asks for sibling expansion.

When validation is part of a top-level repository-wide security scan, treat discovery notes, coverage ledgers, and repeated source/sink/control patterns as validation input even if they are not yet numbered as final findings. The ledger is a coverage artifact: preserve rows that are not_applicable, suppressed, deferred, or reportable, and continue bounded high-impact sibling checks needed to complete that provided ledger. This is preserving repository-wide scan scope, not independently expanding a standalone validation request.

For large repository-wide scans, validation should preserve coverage as well as proof depth. Once a candidate has a complete source, closest control, sink, and impact tuple, prefer static trace plus existing tests and deploy/config evidence over lengthy environment bring-up when runtime reproduction needs unavailable internal services, secrets, service meshes, cloud accounts, or production data. Missing runtime setup is a proof-gap note, not counterevidence and not a suppression reason.

If discovery, user scope, or an advisory/tag seed names a specific package, class family, or root-control family, validation must close that exact row. A same-family finding in a neighboring route, parser, deserializer, or auth flow can be used as supporting evidence, but it is not counterevidence for the seeded row. If the seeded row survives, preserve its exact root-control file:line into attack-path analysis and final-report inputs.

Advisory-derived candidate files, functions, or hunks are not findings by themselves, but they are validation obligations for advisory-led repository-wide scans. Validate them against the checked-out local code, then close each exact seed row as `reportable`, `suppressed`, `not_applicable`, or `deferred` with local evidence. If the seed file was opened only during search, still give it an explicit closure row rather than leaving it only in logs.

When the checked-out code still contains a seeded construct, keep that seed row alive until validation decides its local proof tuple. Mark it `reportable` only when local repository evidence independently supports the same source, broken control, sink or security impact, and realistic preconditions; otherwise mark it `deferred` or `suppressed` with the exact missing proof or counterevidence. A stricter deployment assumption, missing downstream application configuration, or a neighboring stronger finding is a precondition or proof gap to state, not counterevidence by itself.

When a high-impact candidate is blocked only by a missing downstream consumer, workflow caller, policy exception, or artifact provenance fact, run one bounded adjacency pass over the most likely evidence sources before suppressing it: generated clients/specs, workflow callers, deploy/policy config, storage or ACL definitions, and package importers. If that pass still leaves the proof gap, keep the row `deferred` rather than treating the gap as counterevidence.

When the input contains multiple candidate instances, preserve that instance inventory:

- validate each candidate instance independently enough to decide whether that exact file/line should survive
- do not collapse multiple candidate instances into one validated finding solely because they share a vulnerability family
- for repeated instances provided by discovery or the security scan workflow, validate a representative exploit path once when feasible, then analytically validate each sibling instance by checking the same proof tuple: attacker-controlled source, missing or incomplete closest control, dangerous sink, and impact
- for repeated vulnerable templates, query builders, parser operations, auth/object endpoints, or shared-helper callers, preserve each independently vulnerable file and sink/control line as a surviving instance when the proof tuple applies. Grouping is acceptable for readability only after every affected instance has its own surviving finding entry or explicit suppressed/deferred row.
- if discovery hands validation a broad family candidate with multiple concrete sink, parser, helper, API-mode, or protected-action lines, expand it into child closure rows before deciding survival. One representative PoC may support the family, but each child still needs its own file/line, source or protected boundary, closest control, sink or action, disposition, and counterevidence.
- when one route or helper exposes multiple same-family operations such as `execute`/`executemany`/`executescript`, `pickle.load`/`pickle.loads`/`yaml.load`/`yaml.load_all`, separate path/file helpers, insert/select/delete/update query builders, or unauthenticated create/delete/reset/admin/job actions, validate or suppress each independently triggerable operation rather than carrying only one representative row.
- treat shared or generated wrappers as reachability evidence during validation. Do not let a proved wrapper path replace the child sink/control/protected-action rows that determine whether each concrete instance survives.
- after a repeated high-impact pattern has one strong proof tuple, stop deepening that one proof unless extra runtime work would materially change reportability, severity, or confidence. Spend the next validation effort on sibling ledger rows and suppress only with exact per-instance counterevidence.
- when a sibling is safe, suppress that exact instance with the specific control that makes it safe
- keep a table of `candidate id`, `file:line`, `family`, `validation method`, `closest control`, `survives`, and `confidence`
- prefer exact source/sink line evidence over broad prose, because downstream validation, attack-path analysis, and final report assembly depend on precise affected locations
- for wrapper-to-shared-sink findings, validate reachability through the wrapper while preserving the underlying parser, deserializer, path/archive, expression, or auth/authz sink/control line as an affected location when that line implements the broken security behavior
- for parser, deserializer, and object-construction findings, validate the concrete codec, converter, deserializer, resolver, or container handler that performs recursive parsing, type resolution, conversion, class filtering, or object construction. A broad parser/config proof does not close a concrete registered handler unless the handler's own root-control line is included or exactly suppressed.
- for file-format object-model helper rows, first decide whether malformed or adversarial input plausibly reaches the helper and whether the missing type, size, shape, recursion, numeric, or conversion guard creates crash, denial-of-service, parser-confusion, authorization-bypass, or other concrete security impact. If those pieces are absent, suppress or defer the row with exact evidence; if present, preserve the helper line as the root control even when an edge parser/filter finding also survives.
- when equivalent class filters, allowlists, denylists, blacklists, whitelists, or resolver controls are duplicated across runtime packages, validate or suppress the runtime/exported implementation separately. A transport callsite or nested helper proves reachability, but the reusable resolver line remains affected when it implements the broken security behavior.
- if validation shows one route or helper has multiple distinct high-impact proof tuples, keep them separately addressable instead of replacing one with another. A proved command-injection path does not validate away a separate SSRF, XML parser, path/file, XSS/template, or authz/state-change path in the same flow.
- when suppressing XML/parser/deserializer candidates, name the exact complete control that defeats that parser path. Partial hardening or a safe sibling parser does not suppress a different default factory, converter, validator, transformer, unmarshal, or parse call.
- for XML parser/converter candidates, verify hardening fails closed on the exact parser instance. `FEATURE_SECURE_PROCESSING` by itself, swallowed/logged `setFeature` failures, caller-supplied parser factories/readers, or missing entity/DTD resolver controls leave the row alive unless exact runtime evidence proves external entities and DTDs cannot be processed.
- for command/action runner candidates, validate each argument type and execution mode independently. Treat API/webhook-supplied values as attacker-controlled even when the frontend widget would normally constrain them, and do not suppress shell injection until the exact typecheck/escape path for that argument type is proven safe before template rendering and shell wrapping.
- for SSRF/download/webhook/callback candidates, validate the exact destination source, URL parser, allow/deny/filter config, redirect behavior, and network client sink. Do not suppress because the outbound request is a documented feature, because operators can configure filters, because filters are empty by default, or because validation happens before redirects; those facts are preconditions or partial controls unless the final requested destination is constrained on the exact path.
- for resource-serving/path traversal candidates, validate the exact allowlist, path matcher, URL decoding, canonicalization, and resource-selection control used by that handler. A newer safe resource handler or resolver does not suppress a legacy/deprecated/exported handler with a different control line. For restore/import/export/admin-looking routes, also validate the exact global middleware and decorator semantics before assuming the path is authenticated; optional or conditional login wrappers are not enough when the route is reachable without auth in default or no-password deployments.
- for restore/import/export, backup/restore, archive extraction, file copy/move, download/open, and key/config fetch candidates, validate the exact destination-selection, canonicalization, branch-local transform, and filesystem effect for that operation. A nearby auth bypass, secret leak, or configuration flaw is a separate row, not suppression or replacement for the path/file row.
- for archive extraction and restore/import candidates, suppression requires exact proof that each untrusted member path is normalized and contained before the extraction or write occurs. Do not suppress with a generic claim that a library helper is safe, or with later top-level file filtering, UUID/manifest gates, copytree/import allowlists, recursive promotion into an approved root, or post-extraction scanning after attacker-controlled paths have already been materialized. Reason explicitly about symlink, hardlink, metadata, and imported-subtree behavior whenever extracted content is later copied or promoted. Do not require the write to escape the overall app/datastore root; writes into trusted config, peer-object directories, shared roots, or imported subtrees inside that root still count as arbitrary file impact.
- for archive symlink and hardlink pivots, execute an ordered archive when
  feasible: first materialize a link with a target outside or elsewhere within
  the trusted root, then extract a regular member whose lexically contained
  name traverses that link. Record the archive entry names/types/link targets,
  target interpretation base, path-component identities before each write,
  final opened object, and overwritten or disclosed protected data. Separately
  test a pre-existing link in the extraction tree. The negative control must
  reject link entries and/or use root-directory-handle-relative no-follow
  traversal for every component and final file while a legitimate nested file
  still succeeds.
- for decompression-bomb and data-amplification candidates, use a valid bounded
  compressed payload that expands far beyond its input and record compressed
  bytes, declared size, actual output, expansion ratio, peak retained output,
  entry count, per-entry totals, cumulative compressed-input/decoder-work and
  expanded-output/retention totals, nesting, concurrency, decoder behavior, and
  the affected memory/disk/worker/service capacity. Test lying size metadata,
  many individually acceptable or zero-output entries, nested containers,
  malformed input,
  and one legitimate bounded input. Suppression requires an actual output cap
  enforced during streaming or decompression, cumulative input-work and
  pre-retention output accounting, relevant nesting/concurrency bounds,
  fail-closed errors, and a
  usable negative control; input size or untrusted metadata alone is not enough.
- for authenticated-encryption nonce/IV-reuse candidates, record algorithm and
  mode, exact key identity/scope, the two nonce values, ciphertexts, tags, AAD,
  and plaintext lengths. Use a bounded same-key pair and show actual victim
  plaintext recovery, keystream equality, or a verified forgery rather than
  inferring exploitation from a constant alone. Confirm both original tags and
  legitimate decrypts when applicable: valid tags do not repair GCM key/nonce
  reuse. Test fresh messages, restart/worker/tenant/counter-rollback paths, key
  rotation, metadata substitution, and tampering. Suppression requires
  key-scoped pair uniqueness through cryptographic nonces, independently
  derived per-message data keys, or an atomic persistent counter; fail-closed
  tag verification before plaintext use; and AAD binding for security-relevant
  envelope metadata.
- for archive-member traversal, static evidence can be enough to survive when uploaded package/archive bytes reach a member-name decode/filter/join/write sequence and no exact containment check runs before the write. Missing optional parser libraries or lack of a full archive harness should lower confidence or become an explicit deferred proof gap, not silently suppress or replace the row with an adjacent same-family file traversal.
- deprecation, opt-in registration, or documentation warning that an API can be dangerous is a precondition, not counterevidence, for framework/library runtime code when the instance has a plausible cross-boundary source and runtime/deployment path. Suppress only if repository evidence proves the intended restricted/control mode defeats the exact attack; do not suppress a bypass of the restricted mode because an unrestricted mode is documented as dangerous.
- when suppressing auth/authz candidates, name the exact permission, authentication, tenant/object, or state-transition check on that endpoint. A credential-helper issue elsewhere does not replace a public webhook/status/API endpoint that reads protected data or triggers protected work.
- for stateful authentication protocols, validate the transition from pre-authentication or pre-upgrade state to credentialed identity: principal/credential/token installation, rebind or reauthentication call, issuer/callback assignment, and validated object versus consumed object. Missing rebinding or incomplete state checks remain reportable when attacker-controlled protocol state can authenticate or bind the wrong identity.
- for login session-fixation candidates, use separate attacker and victim clients. Have the attacker create or learn one anonymous session identifier, cause the victim to present that exact identifier, complete legitimate victim authentication, then retry a protected request from the attacker with the original identifier. Record the pre-login ID, post-login Set-Cookie value, store record, installed principal, old-record invalidation, and protected response. Suppress when the identifier cannot realistically be known or fixed by the attacker, or successful authentication atomically invalidates the old session and issues a fresh unpredictable identifier before protected use. Cookie flags and credential validity alone are not rotation controls.
- for self-service update candidates, compare the attacker-controlled request object and persisted object field by field for security-sensitive identity, trust-state, tenant, role/group, MFA, and account-recovery properties. Do not suppress because one alias is checked, such as primary email, when a related scalar or collection alias can still be changed.
- when the provided candidate set is repository-wide, validate high-impact candidates first and spend validation effort in this order: command/code execution, unsafe deserialization, SSTI/template execution, SQL/NoSQL/query injection, SSRF/callback/file/network impact, path traversal/arbitrary file read or write, unsafe upload, and authz/tenant/object bypass with privilege or protected-object impact
- do not let low-severity data/config findings consume validation budget before the high-impact queue is exhausted
- do not let one difficult build or service setup consume the budget needed to validate sibling high-impact candidates from the coverage ledger. If setup becomes disproportionate, switch to code trace plus existing tests/config evidence for that candidate and continue the ledger.
- suppressions must close the specific row they suppress. A missing downstream caller, deployment fact, import path, or artifact-provenance fact is a reason to run the bounded adjacency pass or mark the row `deferred`, not proof that the candidate is safe.

Use class-specific proof tuples:

- authz/tenant/object/state change: attacker path + missing/wrong guard + protected object/comparison/state transition
- bulk object binding/mass assignment: attacker-controlled request fields +
  effective DTO/schema/serializer/ORM writable-field set + persisted
  security-sensitive role, tenant, owner, identity, verification, recovery,
  billing, workflow, or trust-state field + later privileged reader or state
  transition. Suppression requires an exact allowlist or equivalent binding
  control that excludes the claimed field; authentication, ownership of the
  edited object, or a repository comment is not field-level counterevidence.
- browser CSRF: security-relevant state-changing route + credential the victim
  browser attaches cross-site + exact cross-site-sendable method, content type,
  parser, and request shape + SameSite cookie behavior + Origin/Referer, Fetch
  Metadata, or anti-CSRF token semantics + realistic victim interaction and
  protected-action impact. Authentication, POST, an intended JSON content
  type, or CORS response policy alone is not a categorical defense. Suppression
  requires proof that the exact request cannot carry ambient credentials, is
  rejected before the state change by an enforced origin/fetch-metadata
  predicate, or requires an unpredictable token bound to the victim session or
  request and compared correctly.
- credentialed CORS response exposure: exact attacker origin + a browser or
  faithful browser simulator issuing a credentialed fetch + proof that the
  relevant cookie, HTTP authentication, or client certificate attaches under
  the real Domain, SameSite, schemeful-site, and third-party-cookie rules +
  preflight when required and the actual protected request + the actual
  response's `Access-Control-Allow-Origin` and
  `Access-Control-Allow-Credentials` values + attacker JavaScript reading a
  sensitive body and, for secrets, exercising the disclosed capability. Test
  same-site sibling/subdomain, `null`, suffix lookalike, scheme, and port
  variants, then prove one exact trusted origin still succeeds. The negative
  control must reject the attacker before sensitive-data retrieval, omit an
  attacker-matching allow-origin header, prevent attacker JavaScript from
  reading the body, and preserve legitimate trusted-origin access. Do not infer
  exposure from CORS header/library names, preflight alone, or a server-side 200;
  wildcard allow-origin plus credentials is browser-blocked for credentialed
  reads. Public data, no browser-attachable credential, an exact serialized
  origin allowlist, or an unexposed actual response is counterevidence. CORS
  governs response readability, not whether a request executes, so evaluate a
  state-changing request without readable output separately as CSRF.
- cross-site WebSocket hijacking: exact attacker page and browser-generated
  Origin + real browser/headless reproduction or a faithful WebSocket handshake
  simulator + proof that the victim cookie or HTTP credential attaches under
  the deployed Domain, SameSite, Secure, schemeful-site, and third-party-cookie
  rules + accepted HTTP upgrade and authenticated session + exact attacker
  message + attacker JavaScript reading the server reply or causing a protected
  action + demonstrated use of any disclosed key or token. Record the handshake
  response/close code, registered handlers, and message transcript. Test
  wholly cross-site and controlled same-site sibling origins as applicable,
  plus `null`, suffix, scheme, and port variants; then prove the exact trusted
  origin still connects. The negative control must reject before session lookup
  and message-handler registration or require an unpredictable session-bound
  connection token unavailable to the attacker, emit no sensitive message, and
  preserve the legitimate client flow. CORS/preflight, HttpOnly, TLS,
  authentication, or a WebSocket framework name is not suppression. Do not
  report anonymous public channels, bearer-only/server-only credentials the
  browser cannot attach, or non-browser Origin spoofing without access to a
  victim credential as cross-site hijacking.
- DNS-rebinding SSRF: attacker-controlled HTTPS hostname + an initial A/AAAA
  answer set accepted as public + a later resolver invocation by the HTTP
  client, proxy, redirect handler, pool, or transport + a private, loopback,
  link-local, metadata, or otherwise forbidden connection address + a
  meaningful internal response or state change. Record every lookup and answer,
  URL and redirect hop, final socket destination, Host header, TLS server name,
  response, and credential or internal effect. The negative control must reject
  direct private, mixed, malformed, unsupported-family, and empty answers,
  resolve once, pin an approved address into the actual connection while
  retaining logical Host/TLS identity, reject or fully revalidate redirects,
  and preserve a legitimate public fetch. A hostname check, public first
  answer, disabled redirect, or private-address helper alone does not close a
  validation/use mismatch.
- web cache deception: start from a cold shared cache and use separate victim
  and attacker clients. First prove the attacker cannot retrieve the protected
  object without credentials. Request an attacker-chosen deceptive URL as the
  victim, recording the edge-visible path and cache key, origin-visible path
  and selected route, attached credential, response body and cache directives,
  cache miss, and storage decision. Then repeat the identical URL without
  credentials and prove a cache hit returns the same victim secret or sensitive
  object without another origin call; demonstrate meaningful use of a disclosed
  key or data when relevant. Exercise extension suffix, extra segment,
  semicolon/path-parameter, encoded separator/dot, query, case, trailing, and
  double-decoding variants supported by the topology. The negative control must
  show exact consistent route handling and/or that private, no-store,
  authenticated, Set-Cookie, or non-explicitly-public responses are never
  shared, while a legitimate public object still produces a cache hit. Do not
  report a cache or route pattern without the cold-cache denial, victim
  population, credential-free hit, and identity-preserving response witness.
- application authorization-cache isolation: two valid authenticated
  principals or tenants + one colliding logical resource/key + cold-cache
  authoritative lookups proving each principal receives only its own object +
  the exact cache key and namespace + first-principal population + second-
  principal hit that bypasses the authoritative lookup + the wrong sensitive
  object or protected decision. Record repository/policy call counts so the
  hit-path bypass is explicit. The negative control must derive every
  authorization-relevant key component from trusted session or policy context,
  keep the principals' entries distinct, verify tenant/owner or decision
  binding on hits, preserve a legitimate same-principal hit, and exercise
  invalidation when permissions or ownership can change. Do not infer a leak
  from a shared cache or omitted-looking field without the cross-principal
  collision and wrong-object/decision witness.
- GraphQL operation amplification: one exact HTTP/WebSocket/RPC envelope +
  parsed and fully expanded execution plan showing aliases, fragments, nested
  selections, batch entries, persisted-document substitution, list cardinality,
  and directives + the actual count of security-sensitive resolver/service
  invocations + the transport-, client-, account-, principal-, tenant-, and
  operation-scoped budget state before and after each invocation + a protected
  result. For authentication, MFA, recovery, invitation, or token issuance,
  show that attempts which would be rejected as separate requests execute in
  one accepted document and yield a session, reset capability, credential, or
  privileged state transition; quantify the resulting effective search space
  and achievable request/operation rate. For payments, messaging, exports, and
  resource abuse, show the multiplied downstream effects and attacker cost.
  The negative control must reject the amplified plan before any protected
  resolver runs or charge its complete cost, then independently enforce an
  atomic account/principal/tenant/operation budget at the resolver or service
  boundary so cross-client distribution also fails. Prove an allowed bounded
  public batch still works. Do not report aliases, batching, introspection, a
  complexity plugin name, or a request limiter without the request-to-resolver
  mismatch and concrete security effect.
- forwarded client-identity/proxy-trust bypass: one fixed actual client and
  transport peer + exact observed forwarding chain after each ingress append or
  overwrite + trusted proxy set and hop order + canonical parser result + the
  client/account/principal security key before and after each request + enough
  rotated attacker-prepended hops to exceed the intended attempt budget and
  reach a recovery, login/MFA, fraud, abuse, allowlist, or protected-operation
  effect. The negative control must ignore forwarding metadata from untrusted
  peers, reject malformed or ambiguous addresses, peel only exact trusted hops
  from the right, bind all spoof variants from one actual client to one key, and
  enforce an independent atomic account/principal budget where distribution
  matters. Header presence, `trust proxy`, or an apparent first/last selection
  alone is inconclusive without the deployed append/overwrite topology and
  bypass witness.
- regular-expression denial of service: attacker-controlled text or pattern +
  the exact regex, flags, engine, and evaluation API + an adversarial
  near-match that demonstrates superlinear or catastrophic work + the shared
  event loop, worker, parser, protocol negotiation, or service capacity it
  blocks. Run the witness only inside a bounded worker, subprocess, VM
  deadline, engine diagnostic, or deterministic complexity harness; record the
  input length and timeout/operation result without hanging the scan. The
  negative control must preserve intended legitimate matches and ordinary
  rejections while using a strict pre-evaluation length bound, linear parser,
  guaranteed linear-time engine, or structurally unambiguous expression.
  Reject syntax-only claims and cases whose exact engine, input cap, isolation,
  or upstream validation makes the expensive path unreachable or immaterial.
- external authorization fail-open: authenticated or otherwise identified
  low-privilege subject + attacker-selectable action/resource/tenant/context +
  policy/entitlement/sidecar/plugin/cache call + exception, timeout,
  cancellation, malformed/empty result, stale fallback, or retry exhaustion +
  permissive initial state, swallowed failure, truthy coercion, unbound cached
  decision, or default allow + protected data or action. Exercise explicit deny,
  the exact failure, malformed response, and legitimate allow through the same
  handler. Record policy call inputs, return/throw behavior, final decision,
  protected-operation arguments, response, and whether the sink ran. The
  negative control must begin without permission, require one exact
  subject/action/resource-bound affirmative decision, produce no protected
  effect on every failure, and preserve legitimate authorized behavior.
- login session fixation: attacker-known or attacker-injectable
  pre-authentication session identifier + victim adoption of that identifier +
  successful credential transition that preserves or promotes the same
  identifier + subsequent attacker reuse that resolves to the victim principal
  and reaches a protected object or action. The negative control must show a
  distinct unpredictable post-authentication identifier, atomic invalidation of
  the old record, successful access with only the new identifier, and failure
  with both attacker and victim pre-authentication identifiers.
- password-reset/verification/magic-link origin poisoning: attacker-controlled
  request authority or forwarded authority/protocol accepted through the real
  proxy trust path + a secret-bearing absolute URL delivered by the legitimate
  mail/message channel + victim navigation to the attacker origin + captured
  token redeemed at the canonical completion endpoint + resulting password,
  login, identity-link, invitation, or verification change. Send the exact
  malicious `Host`, `Forwarded`, `X-Forwarded-Host`, and protocol variants the
  deployment accepts; capture the delivered URL, simulate the victim follow,
  extract the token, and exercise the real protected transition. Token entropy,
  digest storage, expiry, and one-time consumption are controls against other
  attacks, not disclosure to the wrong origin. The negative control must keep
  every malicious authority variant on the configured canonical origin, prove
  the attacker receives no token or security capability, allow a legitimate
  victim flow, and reject wrong and replayed tokens. Suppression also requires
  evidence that proxies overwrite/canonicalize untrusted authority or that a
  fixed/strictly allowlisted public origin is used before URL construction and
  cannot open-redirect the secret.
- native memory corruption: attacker-controlled bytes, length, index, pointer,
  object state, or scheduling action + exact allocation/object extent and
  lifetime + integer types, units, wrap/signedness, terminator/metadata space,
  and source availability + first out-of-bounds read/write, use-after-lifetime,
  double free, invalid cast, or overlapping operation + corrupted/read object,
  control data, secret, crash, or execution effect. Suppression requires
  callsite-complete proof of checked arithmetic, correct source and destination
  bounds in the same units, reserved metadata/terminator space, and valid
  ownership/lifetime; a bounded-function name or compiler hardening flag alone
  is not proof.
- document-query/NoSQL operator injection: attacker-controlled parsed key,
  primitive, array, object, selector document, aggregation stage, projection,
  sort, update operator, or expression + exact parser/schema/coercion runtime
  type + driver/ODM selector or operator semantics + selected/read/updated/
  deleted object + authentication, authorization, tenant, confidentiality,
  integrity, or availability effect. Object-literal syntax is not proof of
  parameterization. Suppression requires a pre-query primitive-type or exact
  schema/shape/key/operator allowlist that excludes every operator and coercion
  needed by the witness, plus proof that the driver does not reinterpret the
  surviving value.
- LDAP filter injection: attacker-controlled request, federated/session claim,
  stored tenant value, UID, DN, CN, or group value + its exact rendered filter
  assertion and effective RFC 4515 filter AST + directory matching semantics
  for presence/substring operators, nested boolean expressions, multi-valued
  attributes, and any extensible match + the selected identity/group and later
  authentication, role, session, or protected action. Execute the exploit and
  negative controls through the same parser, directory query, and
  authorization path, recording the input, rendered filter, matched entry, and
  resulting privilege. Suppression requires context-correct RFC 4515 assertion
  escaping or a typed builder for every attacker-influenced assertion plus any
  required server-owned canonical principal binding. DN escaping, generic
  encoding, rejecting all special characters, or an API name alone is not
  proof; include a legitimate literal-special-character control to distinguish
  escaped data from an LDAP wildcard/operator.
- XPath/XQuery injection: attacker-controlled request, form, RPC,
  federated/session claim, or stored value + the exact rendered expression and
  effective parser AST under the deployed XPath/XQuery version and library +
  boolean precedence, predicates, unions, axes, functions, namespaces,
  variables, and type coercion + the selected node set + later authentication,
  tenant, role, session, confidentiality, integrity, or protected-action
  effect. Execute the exploit and negative controls through the same expression
  parser, XML query, node selection, and security decision, recording the input,
  rendered expression, selected node, and resulting privilege. Suppression
  requires native variable/parameter binding or a context-correct expression
  builder that proves attacker values remain scalar data. XML/HTML encoding,
  ad hoc quote replacement, a static-expression sibling, or an API name alone
  is not proof.
- OAuth/OIDC authorization-code transaction or account-linking CSRF: attacker
  initiation under the attacker's external identity + exact authorization
  request, code, `state`, OIDC nonce, PKCE challenge/verifier, issuer/client,
  redirect URI, and callback browser session + server-side transaction lookup,
  expiry, one-time consumption, and session/account/operation binding + code
  exchange and verified external subject + resulting local-account link,
  session, credential change, consent, or protected action. A missing `state`
  check alone is not a validated security outcome. For account linking, prove
  that a code or transaction created for the attacker can be submitted by the
  authenticated victim, linked to the victim's local account, and then used by
  the attacker to sign in as that victim. Suppression requires an unpredictable
  one-time transaction bound to the initiating browser session, local account,
  and operation; fixed issuer/client/redirect URI; transaction-bound S256 PKCE;
  and use of the transaction-bound account rather than callback-controlled or
  merely current-session identity.
- injection/path traversal/header/open redirect: attacker-controlled bytes + sanitizer/canonicalization/allowlist result + dangerous sink/context
- untrusted upload/content placement: attacker-controlled filename, metadata,
  and bytes + multipart/parser and size limits + effective byte transforms +
  temporary and final destination after rename/canonicalization + overwrite and
  permission behavior + downstream static server, browser origin, plugin/
  extension loader, startup hook, configuration reader, archive importer,
  media/document processor, or interpreter + concrete active-content,
  overwrite, parser, configuration, privilege, or code-execution effect.
  Suppression requires controls that defeat the exact downstream consumer, not
  a MIME/extension check alone; parsing into a bounded allowlisted data model,
  canonical re-encoding, a server-generated name, and a non-served,
  non-executable destination together form strong counterevidence.
- HTTP request smuggling/desynchronization: one exact attacker-controlled byte
  sequence + every reachable proxy/gateway/server/backend parser and protocol
  translation + each hop's duplicate-header normalization, effective
  `Content-Length`/`Transfer-Encoding`, message boundary, consumed and leftover
  bytes, route, principal, connection reuse, and forwarding behavior + a second
  or differently interpreted request that bypasses authorization/routing,
  poisons another request/response, reaches a protected action, or crosses a
  trust boundary. Suppression requires equivalent parsing at every reachable
  hop or first-hop rejection and canonical single-message forwarding; a
  standards citation, one parser's behavior, or closing the connection after
  forwarding ambiguous bytes is not enough.
- XSS/template/SSTI: attacker-controlled value + escaping/template context + browser/server-side template execution sink
- server-side template source: attacker-controlled request, stored, tenant, configuration, or error text + compilation or parsing as template/expression source + exact sandbox/global/object-capability/recursion controls + reachable read, expression, code-execution, or secret-exposure effect. A fixed template receiving untrusted variables is a negative control unless those variables are reparsed or evaluated as source; autoescaping controls output encoding, not server-side expression execution.
- recursive placeholder/template injection: request, tenant/client metadata, stored configuration, or error value + placeholder/template helper that recursively expands, re-parses, or evaluates resolved values + missing escape/non-recursive guard + XSS, expression execution, credential exfiltration, or code execution impact
- predictable security value: attacker-relevant token, session identifier, invitation, nonce, temporary credential, API key, reset/verification code, or security selection + generator and all truncation/encoding transforms + effective entropy and exposure/lifetime + storage/comparison and attempt controls + concrete impersonation, replay, forgery, or boundary-bypass effect. A non-cryptographic generator name alone is not proof; quantify the feasible attacker work and suppress values that protect no boundary or have an effective independent control.
- check/use or state race: security decision over a specific file, record, version, principal, amount, destination, permission, or state + attacker-reachable conflicting mutation + a real interleaving boundary + later use of a different or re-resolved value/object without an atomic predicate, lock, version check, stable handle, or immutable snapshot + concrete confidentiality, integrity, authorization, or availability impact. Repeated reads or asynchronous syntax alone are not proof.
- deserialization/code execution: attacker-controlled serialized/code/template bytes + unsafe loader/evaluator + execution or object-construction effect
- deserializer wrapper denylist/allowlist control: attacker-controlled, stored, plugin, remoting, import, or persisted-state serialized input + shared wrapper that accepts type tags or default object construction + missing/misordered deny entry, allowlist gap, converter-priority gap, or unsafe class-loader/default-converter behavior + object construction, crash, code execution, or privilege-boundary impact
- concrete deserializer/codec control: attacker-controlled serialized or structured input + registered codec/converter/deserializer/container handler that recursively parses, resolves types, filters classes, converts values, or constructs objects + missing validation, unsafe fallback, fail-open filter, or unbounded traversal + code execution, object construction, parser confusion, denial of service, or privilege-boundary impact
- SSRF/callback: attacker-controlled destination + destination control bypass + network/read/side-effect impact
- SSRF optional-filter/redirect control: attacker-controlled download/webhook/callback URL + optional, empty-by-default, regex-only, pre-request-only, or redirect-following destination control + internal/LAN/cloud metadata/file-backed fetch or server-side callback side effect
- auth/token/assertion/protocol control: attacker-controlled token, assertion, protocol metadata, or version value + exact validator/control semantics + mismatch between validated value and trusted value, incomplete canonicalization/equality, unchecked parsing, or missing binding + authentication, authorization, or protocol-security impact
- stateful auth protocol transition: attacker-controlled credentials, principal, token, issuer, assertion, server response, or protocol metadata + state transition after TLS upgrade, bind, redirect, callback, assertion validation, or identity-provider response + missing rebind/reauthentication, stale identity reuse, incomplete issuer/callback binding, or validated-vs-consumed mismatch + authentication bypass or identity confusion impact
- JWT/JWS algorithm and key-type confusion: attacker-controlled compact token and
  protected `alg` + verifier support for symmetric and asymmetric algorithms or
  a token-selected verification branch + one configured key representation that
  crosses algorithm families, especially published RSA/EC/OKP public-key bytes
  reused as an HMAC secret + a real attacker-computed MAC/signature accepted as
  trusted claims + installed identity or protected action. The negative control
  must pin the algorithm before key selection, require a compatible runtime key
  type, invoke only the intended asymmetric or symmetric primitive, accept a
  legitimate token, and reject the confused-algorithm forgery, tampering,
  unknown key, and wrong key type.
- JWT/JWS/OIDC remote key origin: attacker-controlled compact token and protected
  header + `jku`, `x5u`, embedded key, issuer discovery, or other attacker-derived
  verification-key source + actual JWKS/certificate URL and redirect/cache path +
  selected `kid`, key metadata, algorithm, and signature result + forged trusted
  issuer/audience/subject/role claims + installed session or privilege. A valid
  signature is not counterevidence when the attacker supplied its trust root.
  Suppression requires a trusted issuer-to-key-source mapping, one compatible
  key, fixed algorithm, complete claim/lifetime/nonce binding, and continuity
  through principal creation.
- OIDC ID-token client and transaction binding: a compact ID token with a valid
  signature from the configured issuer but issued to a sibling client + the
  exact initiating target-app browser session, callback `state`, and requested
  nonce + scalar/array `aud`, optional or conflicting `azp`, token nonce,
  lifetime, and subject + the relying party's validation decisions + installation
  of that subject into the attacker's target-app session. Prove a concrete
  cross-client token acquisition or replay path and wrong-subject session; a
  missing check by itself is insufficient. The paired control must accept a
  legitimate target-client token and reject wrong-audience, multi-audience with
  absent or foreign `azp`, missing or cross-session nonce, wrong state, wrong
  issuer, expired, invalid-signature, and replay cases before principal
  installation. Callback `state`, signature validity, and trusted issuer are
  counterevidence only for their own bindings, not substitutes for `aud`, `azp`,
  or nonce validation.
- Signed webhook capture-replay: exact raw request bytes + signature header and
  signed timestamp + provider-authentication result + parsed event/delivery ID,
  account/object, amount/action, and protected effect + a second delivery of the
  unchanged valid request. Prove that both deliveries repeat the effect even
  though tampering or a wrong secret fails. The paired control must accept one
  fresh legitimate delivery, reject timestamps outside a bounded past/future
  window, reject body/signature changes, and atomically consume the signed event
  ID with the mutation so concurrent or sequential duplicates are harmless.
  A valid HMAC authenticates bytes but does not prove freshness or one-time
  execution. A non-atomic `has`/effect/`add` sequence is not sufficient replay
  protection when multiple workers or deliveries can race.
- ECDSA/DSA signature-malleability replay: one exact signed event or operation +
  its valid `(r, s)` signature + a mathematically equivalent valid `(r, n-s)`
  representation + the verification result for both + each derived replay,
  deduplication, cache, or idempotency key + repeated protected effect. The
  paired control must accept legitimate delivery, reject tampering/wrong keys
  and stale requests, and make both valid representations resolve atomically to
  one signed semantic event/operation ID. Accepting high-S and low-S signatures
  is not itself a finding; the exploit requires a representation-sensitive
  security decision. Conversely, freshness and correct signature verification
  do not close replay identity derived from malleable signature bytes.
- OAuth/OIDC authorization-code callback binding: attacker-controlled code,
  `state`, issuer response, redirect parameters, or browser session + initiation
  transaction and PKCE material + exact lookup, consume, exchange, and identity
  installation/linking semantics + wrong-subject session or account takeover.
  Suppression requires exact transaction-to-session/account/operation binding,
  one-time use and expiry, fixed issuer/client/redirect URI, and verifier
  continuity through exchange and the final security decision.
- SAML/XML assertion binding: attacker-controlled response or assertion set + protocol/signature validation of one object + later use, clone, serialization, or storage of a different assertion/document node + authentication/session/token impact. Multi-object preconditions should be stated, but suppression needs exact evidence that the same object is cryptographically and semantically bound to the consumed object.
- SSO/SAML response validator: attacker-controlled SSO response containing one or more assertions + response/assertion validator code that selects, indexes, clones, serializes, or returns an assertion + mismatch between the signed/validated assertion and the assertion later consumed by the session/token path, or missing recipient/audience/destination/ACS binding + authentication or authorization bypass impact. A generic claims-authorizer or service-method authorization finding does not validate or suppress this row.
- found-valid selection mismatch: attacker-controlled list or set of tokens/assertions/identities + validator loop or `foundValid*` flag proves one element while later fixed-index, first/last, clone, serialization, or lookup consumes another element + authentication, authorization, or protocol-state impact. Suppression needs evidence that the consumed object is the same object already validated.
- SAML signed-byte-to-session binding: attacker-controlled federated response +
  unique signature reference/ID resolution + exact canonical bytes covered by
  the verified signature + claims parsed from those same bytes + issuer,
  audience, recipient, destination/ACS, subject-confirmation, lifetime, and
  replay checks + the exact subject/role installed in the session. A valid
  signature over one assertion does not validate sibling objects or fields
  copied before/after verification. Suppression requires object identity and
  semantic binding through principal creation, not merely a successful
  cryptographic API call.
- XML parser/converter hardening: attacker-controlled XML/SVG/XSLT/SAX/DOM/StAX input + parser factory, converter, transformer, or resolver setup + fail-open feature configuration, missing entity/DTD controls, caller-supplied parser path, or secure-processing-only hardening + XXE, SSRF, file read, parser injection, or denial-of-service impact
- query/parser injection: attacker-controlled bytes + query/selector/parser API that receives syntax or operators rather than bound values + semantic change, parser error, row-set change, write amplification, or bypassable post-query guard + read, write, authz, integrity, or availability impact. A later business check limits confidence or impact only after proving it checks the same trusted object and defeats syntax control for that exact instance.
- resource handler path control: attacker-controlled URL/path/resource name + allowlist/path-matcher/decoder/canonicalizer/resource-selection control + mismatch, pre-decode/post-decode gap, legacy handler behavior, or unsafe resolver fallback + arbitrary file read/write, path traversal, or unauthorized resource access impact
- shared deserialization control: attacker-controlled or privilege-bearing serialized/config/import/plugin/remoting input + shared loader or converter/allowlist/denylist behavior + unsafe object construction or incomplete control + affected callsites or unresolved cross-boundary reuse
- protocol/version parser: attacker-controlled protocol metadata + missing complete format enforcement before split/parse/compare + parse exception, wrong ordering, or feature-gate bypass + protocol-security impact
- protocol/version regression seed: CVE/advisory/security-test context points at protocol compatibility, version comparison, negotiation, or feature gating + checked-out utility/comparator parses attacker-controlled protocol metadata with `split`, numeric conversion, regex partial validation, or unchecked component access + malformed or adversarial metadata can crash negotiation, bypass a protocol gate, select the wrong feature path, or downgrade/disable a security-relevant behavior. Missing runtime harness is a confidence limit when the local parser/control/impact tuple is visible.
- file-format object model DoS/corruption: untrusted document/archive/message parsed into first-party object model + low-level array/dictionary/node/helper method that performs unchecked element conversion, recursion, numeric parsing, or unbounded iteration without validating attacker-controlled structure + crash, denial of service, parser confusion, or security-control bypass impact
- file-format primitive helper: untrusted PDF/XML/YAML/archive/message/image/font/protocol structure + helper such as `to*Array`, `toList`, `getObject`, numeric conversion, parser/iterator, size-based allocation, unchecked cast, collection-to-array conversion, or loop over attacker-controlled nodes + missing type/size/shape validation + crash, denial of service, parser confusion, or security-control bypass impact. Central object-model helpers should be validated even when an edge parser/filter finding already survives.
- advisory-seeded parser/file-format DoS: advisory, release note, fix hunk, or security test identifies a malformed-input crash or resource-exhaustion regression + checked-out source shows untrusted file/message parsing reaches the exact helper + the helper performs unchecked cast, size-based allocation, recursive traversal, numeric conversion, or loop over attacker-controlled structure. A runtime harness improves confidence, but checked-out code plus existing tests or deterministic code reasoning can be enough to mark the row `reportable` when no exact countercontrol exists.
- deterministic parser/helper availability: untrusted remote, protocol, document, archive, or package input + missing helper guard produces a deterministic exception, unchecked cast, unchecked numeric parse, recursion, allocation, or loop failure + repeated trigger can abort request processing, parser execution, security negotiation, or service availability. Treat as security-relevant unless exact recovery or equivalent prevalidation defeats this instance.
- branch-specific operation control: request-selected operation or fallback branch + branch-local split/filter/canonicalize/type-resolution/object-binding line transforms attacker-controlled path/value differently from the shared path + shared evaluator, binder, or security-sensitive mutation sink. Validate the branch line, not only the common helper.
- self-service object/profile update authz: authenticated or externally controlled identity + update guard over protected profile/account/tenant fields + missing immutable-field, collection-alias, or subject/object binding check + account takeover, identity confusion, privilege escalation, or protected-object mutation impact
- secret/data exposure/session config: secret or sensitive source + exposure/storage/log/client boundary + missing protection; validate after high-impact classes unless this directly enables code execution, injection, privilege escalation, auth bypass, or sensitive cross-boundary impact
- agent/MCP: untrusted instruction/data source + privileged tool/action boundary + action, code execution, or exfiltration effect

## Validation Checklist

Use this checklist to keep validation close to the prompt contract:

- Build the rubric before validating, using up to five concrete criteria grounded in the candidate and the surrounding code.
- Include a realistic-interface criterion when the code exposes an HTTP, CLI, message, file, or other user-reachable interface.
- Prefer precise, bounded steps over broad scans.
- For non-compiled stacks, prefer minimal targeted code understanding and only the smallest set of files needed.
- For compiled stacks, prefer stronger evidence in this order when feasible:
  - crash
  - valgrind or ASan
  - debugger trace
  - focused unit or integration test
  - realistic interface reproduction
  - code understanding
- If the code exposes a realistic interface, attempt validation through that interface before concluding when feasible.
- For SAML/federated assertion candidates, retain the signed fixture bytes or
  payload and signature, record reference and object identities at each step,
  and test an unsigned privileged sibling before or after a valid low-privilege
  assertion. Use a reference-selected, verified-payload-derived session plus
  wrong-audience, wrong-recipient, expired, duplicate-ID, and replay cases as
  negative controls when feasible.
- For JWT/JWS algorithm-confusion candidates, create a real asymmetric key pair
  and compact token when feasible. Publish only the public verification key,
  sign a legitimate token with the private key, then use the public-key bytes as
  the MAC secret for a token-selected symmetric algorithm. Record the protected
  headers, exact key bytes and runtime types, selected branches and primitives,
  signature/MAC outcomes, accepted claims, and protected effect. Use a
  pinned-algorithm verifier plus legitimate, tampered, unknown-key, and
  incompatible-key-type tokens as controls.
- For JWT/OIDC remote-key candidates, create a real attacker key pair and compact
  signed token when feasible. Record the token header, requested key URL,
  redirects, returned key set, selected key, signature outcome, accepted claims,
  and session. Use a header-supplied attacker JWKS as the exploit witness and a
  fixed trusted-issuer JWKS plus wrong issuer/audience, expired token, replayed
  nonce, duplicate `kid`, incompatible algorithm/key type, and tampered payload
  as negative controls.
- For OAuth/OIDC authorization-code or account-linking candidates, execute two
  browser-session flows when feasible. Obtain a real code for the attacker's
  external subject, submit its callback from the victim's authenticated session,
  and record the initiation transaction, state/nonce, PKCE material, exchange,
  linked local account, and a later external login. The negative control should
  reject attacker state in the victim session before exchange, accept a
  legitimate matching session transaction, reject a wrong verifier, and reject
  replay after one-time consumption.
- For recovery, verification, invitation, and magic-link origin candidates,
  execute the request through the closest reachable proxy/application path with
  malicious authority and forwarded-authority headers. Preserve ingress
  normalization, the exact outbound link, attacker-side request/capture, token,
  canonical completion request, and resulting account state. Repeat against a
  fixed-origin or strict canonical-allowlist control, verify the attacker sees
  no secret, then complete one legitimate flow and reject wrong/replayed tokens.
- For HTTP request-smuggling candidates, save the literal request bytes and a
  per-hop framing table with normalized headers, message boundaries, residual
  bytes, routing/authorization decisions, connection reuse, and the protected
  effect. Reproduce the same bytes against the closest reachable parser pair
  and an ambiguity-rejecting negative control when feasible.
- For HTTP response-header injection or response splitting, save the exact
  attacker input before and after URL/form/metadata decoding, raw serialized
  response bytes, parsed header/body boundaries at every downstream proxy,
  gateway, cache, or browser, and the resulting protected effect. Demonstrate
  the same ordinary response without control bytes, then use a negative control
  that rejects CR/LF and all response-field control characters before
  serialization while preserving a legitimate quoted or RFC 5987 encoded
  value. Do not validate from a `setHeader`, `Location`, or
  `Content-Disposition` call alone: prove which injected header or second
  response a real consumer honors and what secret, session, cache entry,
  policy, route, or protected object changes as a result.
- Keep commands short, non-interactive, and scoped to the touched files or the minimum referenced paths.
- If validation fails, record what was attempted, why it was inconclusive, and what proof gap remains.
- Save any PoCs, logs, or crafted inputs under that finding's validation artifacts path from `../../../references/scan-artifacts.md`.
- When multiple instances are provided, keep each candidate individually marked as survived, suppressed, or uncertain; do not silently omit candidates from the final validation report.
- For a single standalone validation request, do not infer repository-wide or sibling scope unless the user explicitly asks for expansion or provides a multi-instance candidate list.
- For a top-level repository-wide security scan, do not narrow validation to one representative finding when discovery supplied a coverage ledger or repeated pattern family.
- For repository-wide candidate sets, do not drop low-severity but real instances solely because they are low severity, but validate and report them only after the high-impact queue unless they directly amplify a serious issue.
- Use nearby safe paths as negative controls when feasible, but do not let the existence of a safe sibling suppress vulnerable siblings.
- Along with the PoC and artifacts, include a small readme explaining how to rebuild or use the PoC to test against the real target.
- If ASan, valgrind, debugger, or other logs prove the vulnerability with high certainty, include them as validation artifacts.

## Confidence Guidance

Calibrate confidence from the strongest evidence actually obtained, not the scariness of the bug class.

- `1.0` for a reproduced crashing PoC with a successful validation result
- `0.9+` for valgrind or ASan reproduction with a successful validation result
- `0.8+` for a debugger trace that successfully demonstrates the vulnerability path
- `0.3+` for code understanding with a defensible success or failure conclusion
- `0.0` when counterevidence clearly defeats the suspected vulnerability
