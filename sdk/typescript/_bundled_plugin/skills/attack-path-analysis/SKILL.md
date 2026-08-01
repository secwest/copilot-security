---
name: attack-path-analysis
description: Use when Copilot is already in the attack-path-analysis phase of a security scan or the user explicitly asks to trace a security finding from source to sink and calibrate severity. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Attack Path Analysis

## Objective

Turn validated or still-plausible findings into explicit attacker stories, structured attack-path analysis facts, severity calibration, and a final reportability decision grounded in the threat model.

## Artifact Resolution

The path references in this skill are the default locations for this phase.
If the user explicitly provides a different path for a required input or output, use the user-provided path instead of the corresponding default path referenced in this skill.
If a required input is still missing, stop and ask the user for it before continuing.
Use the shared scan artifact path conventions in `../../references/scan-artifacts.md`.

### Compact Standard-Scan Mode

When `/security-scan` explicitly invokes this skill in compact standard-scan mode, load the per-scan threat model and the enriched `<discovery_dir>/candidate_ledger.jsonl`. Analyze, in one invocation, every row whose validation disposition is `reportable` or `deferred`. Add one nested `attack_path` record to each row that enters the phase, using the compact record shape in `../../references/scan-artifacts.md`, while preserving every discovery and validation field and the original row order.

In this mode, the nested record replaces the per-finding attack-path report and receipt. Rewrite the ledger atomically. Keep attack-path facts, counterevidence, severity calibration, and policy adjustment as separate reasoning steps even though their output is compact. All reachability, instance-preservation, and evidence requirements still apply; only the artifact packaging changes.

## Workflow

1. Load the per-scan threat model path from `../../references/scan-artifacts.md` as the repo-specific threat-model source of truth. Start from this along with the potential findings. Both inputs are required for this workflow.
   - For repository-wide and scoped-path scans, include validation closure rows marked `reportable` or `survives: yes` even if they were not assigned polished candidate numbers during discovery.
2. Determine whether the affected code is in scope for the repository threat model and whether it belongs to a product surface or production workflow.
3. Build a factual attack path using repository evidence only:
   - service mapping
   - exposure and entry points
   - identity, privilege, and trust boundaries
   - secrets handling and sensitive-data flow
   - reachability
   - existing controls and mitigations
4. Before finalizing scope or reportability-driving facts, identify the strongest repository counterevidence against the key scoping fields and explain why it is or is not dispositive.
5. Calibrate impact and likelihood from the repository evidence.
6. Apply a separate final policy-adjustment pass mechanically using those facts and the calibrated severity.
7. Record final policy decision `ignore` explicitly. Outside compact standard-scan mode, drop it from the surviving finding set; in compact mode, retain the ledger row for coverage mapping.
8. In compact standard-scan mode, add the nested `attack_path` record to every candidate that entered the phase and atomically replace the ledger.
9. Outside compact standard-scan mode, save that finding's visible attack-path report and append one attack-path receipt per candidate id at the default paths from `../../references/scan-artifacts.md`. The receipt must record the candidate id, attack-path reportability decision, attack-path facts or exact proof gap, and attack-path artifact/report reference for that candidate finding.

## Scope and Attack Path Checklist

Use this checklist before finalizing the attack-path facts or policy decision:

- Determine whether the finding is actually a real security vulnerability rather than a correctness bug or false positive.
- Determine whether the affected code belongs to a product surface or production workflow.
- Map the relevant service, component, or workflow context from repository evidence.
- Establish exposure and entry points from repository evidence such as listeners, ingress, load balancers, service ports, manifests, routing, or network policy.
- Establish identities, privileges, and trust boundaries that matter for the path.
- Establish whether sensitive data, secrets references, or privileged control paths are involved.
- Determine whether a realistic attacker can actually reach and use the issue from an in-scope attack surface.
- For multi-stage or temporal findings, enumerate each required attacker action
  and repository-backed transition in execution order. Identify which actor can
  mutate state, which component checks it, the scheduling/queue/transaction or
  request boundary that creates the interleaving, which component consumes it,
  and whether the same identity, version, destination, or object remains bound
  across the chain.
- For security-token findings, state the effective search space, observable or
  inferable generator state, token lifetime, number of attempts, rate limits,
  and the protected action. Do not equate use of a particular random API with a
  practical account or privilege compromise.
- For template findings, state whether the attacker controls template source or
  only template data, which expression/object capabilities the environment
  exposes, and the exact demonstrated or source-supported effect. Do not infer
  code execution merely from output injection.
- For mass-assignment findings, preserve the request-controlled field, the
  effective binder/DTO/schema/ORM writable-field decision, persistence, and the
  later privileged reader or state transition. State the attacker's starting
  identity and the exact privilege, tenant, ownership, recovery, billing, or
  trust-state delta. Do not infer exploitability from a bulk-binding API name
  when an exact field allowlist excludes the claimed security-sensitive field.
- For CSRF findings, preserve the attacking origin, victim interaction, exact
  browser request shape, automatically attached credential, server parser,
  route and state transition, and resulting security impact. Record SameSite,
  Origin/Referer, Fetch Metadata, token generation and binding, and token
  comparison as separate controls. Do not infer account takeover from a
  cosmetic action, or suppression from POST, JSON, CORS, or authentication
  without proving how the exact browser request is blocked.
- For credentialed CORS response-exposure findings, preserve the exact attacker
  origin, browser credential mode and cookie/site policy, automatically attached
  credential, preflight when required, protected route, actual-response
  allow-origin and allow-credentials values, sensitive body, proof that attacker
  JavaScript can read it, and any subsequent use of a disclosed key, token, PII,
  tenant data, or control-plane state. A server-side 200, preflight success, or
  CORS header/library name is not browser-read proof. Record exact-origin parsing
  and equality, rejection timing, trusted-origin success, `Vary: Origin`, and
  sibling, `null`, suffix, scheme, and port variants as separate controls. Do not
  claim credentialed exposure from wildcard allow-origin plus credentials, which
  browsers block, or from bearer-only/server-only credentials an attacker site
  cannot make the browser attach. Analyze an unreadable state change as CSRF
  instead.
- For cross-site WebSocket-hijacking findings, preserve the attacker page,
  exact browser-generated Origin, `ws:`/`wss:` endpoint, cookie Domain/SameSite/
  Secure and third-party policy, automatically attached victim credential,
  upgrade route, Origin or connection-token decision, authenticated session,
  registered message handler, attacker message, readable server reply or
  protected action, and any downstream use of disclosed data or credentials.
  Separate wholly cross-site from same-site sibling reachability. CORS headers,
  preflight, HttpOnly, TLS, authentication, or server acceptance alone is not
  proof of either exploitation or suppression. Require an attacker-readable
  channel transcript or exact state transition. Record rejection before session
  lookup and handler registration, exact serialized-origin equality,
  unpredictable session-bound connection tokens, trusted-origin success, and
  `null`/sibling/suffix/scheme/port variants as distinct controls.
- For DNS-rebinding SSRF findings, preserve the attacker-controlled URL and DNS
  authority, every validation and connection-time A/AAAA answer, address-family
  and special-range classification, redirect and proxy behavior, final socket
  destination, Host header, TLS server name, request path, internal response,
  returned credential or protected operation, and subsequent use. Show the
  public answer passes the check while a later private/link-local answer becomes
  the peer; direct private rejection alone is not counterevidence. Resolve-once
  complete-answer validation, address-pinned connection, unchanged Host/TLS
  identity, no later hostname lookup, and redirect rejection or per-hop
  revalidation are distinct counterevidence.
- For web-cache-deception findings, preserve the attacker-chosen URL and exact
  bytes as parsed at every edge, proxy, framework, and origin hop; the cache key
  and cacheability decision; victim credential attachment; origin route and
  authenticated response; response directives such as `private`, `no-store`,
  `Vary`, `Set-Cookie`, and surrogate controls; storage in a shared cache; and a
  later credential-free attacker hit that returns the same sensitive object.
  Model this as a temporal two-client path: prove the attacker cannot retrieve
  the object from a cold cache, the victim request populates it, the later hit
  bypasses the origin, and the disclosed secret or data has meaningful use.
  Exercise extension suffixes, extra path segments, path parameters, encoded
  separators/dots, query variants, case, trailing syntax, and multiple decoding
  where the deployed components differ. A cache header, middleware, CDN rule,
  route wildcard, or static-looking extension alone is not proof. Record exact
  routing plus explicit public-only caching, honored private/no-store controls,
  authenticated-request bypass, Set-Cookie rejection, or correctly
  identity-partitioned keys as distinct counterevidence.
- For application authorization-cache findings, preserve both authenticated
  principals/tenants, the server-derived identity context, colliding logical
  resource ID, exact cache namespace and key components, cold authoritative
  lookup results, cached object's tenant/owner/sensitivity, population request,
  later cross-principal hit, skipped repository/policy authorization call, and
  disclosed object or unauthorized protected decision. Model this as a
  temporal two-principal path even when both requests use the same ordinary
  route. A global cache or compact key alone is not proof: demonstrate that the
  authoritative miss path is correctly scoped but the hit path returns a value
  authorized for someone else. Record trusted identity-partitioned keys,
  tenant/owner validation on hits, permission-change invalidation, and
  same-principal cache success as distinct counterevidence.
- For GraphQL operation-amplification findings, preserve the raw request or
  subscription message, parsed document, operation and variables, aliases,
  fragments, directives, nested selections, list cardinality, HTTP batch or
  persisted-document resolution, fully expanded execution plan, transport and
  operation costs, and each security-sensitive resolver and downstream service
  invocation. Compare request-level, client-level, account/principal/tenant-
  level, and operation-level budget keys and updates. For authentication, MFA,
  recovery, invitation, or token issuance, quantify the intended and effective
  attempts and prove the amplified call yields a session, reset capability,
  credential, or protected transition which separate requests cannot reach.
  For other effects, preserve every multiplied payment, message, export, job,
  or resource allocation and its business impact. A GraphQL endpoint, alias,
  batch, introspection setting, or missing complexity plugin alone is not
  proof. Bounded expanded plans, cost charging before execution, at most one
  high-risk mutation where appropriate, and atomic resolver/service-layer
  principal or account quotas are distinct counterevidence; demonstrate benign
  bounded batching through the same safe path.
- For forwarded client-identity and proxy-trust findings, preserve the direct
  socket peer, exact raw forwarding header, each proxy/CDN append or overwrite,
  trusted-hop configuration, right-to-left or vulnerable first-hop selection,
  canonicalized client address, and the rate-limit/lockout/fraud/allowlist key.
  Hold the real client constant while rotating only attacker-prepended hops,
  quantify intended versus effective attempts, and prove the extra attempt
  yields a recovery capability, authenticated session, authorization bypass,
  fraud/abuse action, or other protected effect. A spoofable log field or header
  alone is not a security path. Record untrusted-peer header ignoring, exact
  ingress trust, canonical bounded parsing, right-to-left peeling, and atomic
  account/principal budgets as separate counterevidence.
- For regular-expression denial-of-service findings, preserve the remote,
  protocol, document, stored, or tenant-controlled input; exact pattern and
  flags; engine and evaluation API; adversarial near-match and its length;
  observed deadline, operation growth, or engine diagnostic; and the shared
  event loop, request worker, parser, or negotiation capacity that becomes
  unavailable. Separate pattern-controlled injection from fixed-pattern
  catastrophic backtracking, and explain why request, parser, proxy, or schema
  bounds do not defeat the witness before evaluation. Record legitimate match,
  ordinary rejection, bounded length, linear parser/engine, worker isolation,
  and concurrency controls as distinct counterevidence. A nested quantifier,
  regex API, or slow local microbenchmark alone does not establish a remotely
  exploitable service-level path.
- For external authorization fail-open findings, preserve the caller identity,
  attacker-selected action/resource/tenant/context, complete request to the
  policy or entitlement boundary, explicit-deny behavior, exact exception/
  timeout/malformed response, default and final decision values with runtime
  types, catch/fallback/cache/circuit-breaker path, and the protected operation
  and returned or mutated asset. Demonstrate that explicit deny works yet the
  failure outcome alone reaches the sink, and compare a legitimate allow.
  Separate availability-only failure from authorization bypass. Fail-closed
  unavailable/forbidden handling, exact affirmative semantics, no sink call,
  and decision binding to the consumed subject/action/resource are distinct
  counterevidence.
- For native-memory findings, preserve the attacker-controlled bytes, length,
  index, pointer, object state, or scheduling action; the allocation and exact
  source/destination object extents in consistent units; integer wrap,
  signedness, terminator/metadata space, ownership, and lifetime; the first
  invalid read/write/free/cast; and the corrupted object, control data, secret,
  crash, or execution outcome. Distinguish a demonstrated adjacent-field or
  control-flow overwrite from generic undefined behavior, and do not infer code
  execution when the repository proves only a bounded crash.
- For format-string findings, show the exact untrusted value entering the
  format-grammar parameter, the conversion or positional/width syntax, the
  corresponding variadic argument types and order, and the resulting read,
  write, disclosure, corruption, crash, or control effect at the reachable
  sink. Distinguish a demonstrated secret or memory effect from a merely odd
  log message, and treat a fixed literal format with untrusted data in a
  matching value argument as counterevidence.
- For temporal-memory findings, show the event order explicitly: object and
  privilege at registration, retained aliases, disconnect/error/destructor or
  pool-release path, missing cancellation/join/ownership transfer, attacker-
  controlled timing or replacement allocation, same-address/type reuse when
  required, first stale dereference, and the exact new recipient, capability,
  secret, control target, or crash. Distinguish a proven stale-object data or
  callback substitution from generic allocator speculation. Cancellation before
  release or retained/ref-counted ownership is counterevidence only when all
  teardown and completion races are covered.
  Anchor the ability to overlap operations to a concrete thread/task/process,
  signal/interrupt, scheduler/executor, reentrant callback, documented caller
  contract, or runtime witness. Separately callable C functions and deferred or
  asynchronous terminology do not prove preemption between adjacent
  expressions. If the attack path must assume an unstated concurrent caller,
  mark it unproved and do not report it as a high-confidence vulnerability.
- For document-query and NoSQL findings, preserve the attacking JSON/form/RPC
  shape and parsed runtime types; selector keys, values, operator documents,
  aggregation stages, or expressions; schema/DTO/ODM coercion and sanitization;
  driver query semantics; the exact selected/read/updated/deleted account,
  tenant, or object; and the later session, authorization, or protected action.
  Do not infer authentication bypass merely because `$ne` appears, or suppress
  an operator object because the query uses an object literal. Prove the exact
  witness against the effective driver semantics and nearest primitive/schema
  control.
- For LDAP filter findings, preserve the attacker-controlled request,
  SSO/federated claim, session field, or stored value; its placement and
  context-specific escaping in the rendered RFC 4515 filter; the effective
  filter AST including presence/substring and boolean operators; the exact
  directory entry selected under multi-valued attribute semantics; and the
  resulting bind, group membership, role mapping, application session, or
  protected action. Distinguish LDAP filter-assertion escaping from DN escaping.
  Do not infer authorization bypass from interpolation or an LDAP API alone,
  and do not suppress when the attacker can reshape the filter despite a later
  group-name check. Prove the witness and a legitimate literal-special-character
  negative control through the same directory and authorization path.
- For XPath/XQuery findings, preserve the attacker-controlled input; its exact
  placement or variable binding in the expression; the effective parser AST,
  boolean precedence, predicates, union/axis/function behavior, namespace and
  type coercion; the selected XML node set; and the resulting account, tenant,
  role, session, secret, mutation, or protected action. Do not infer a security
  bypass from string interpolation or an XML query API alone, and do not treat
  XML/HTML escaping as XPath expression safety. Prove the same payload changes
  the vulnerable AST and selected node while remaining scalar data under the
  nearest variable-bound negative control.
- For untrusted upload and content-placement findings, preserve the exact
  attacker-controlled filename, metadata, and bytes; multipart/parser limits;
  temporary and final paths after decoding, renaming, and canonicalization;
  overwrite and permission behavior; and the later static server, browser,
  plugin/extension loader, startup hook, configuration reader, archive
  importer, media/document processor, or interpreter. Prove that the same
  stored object reaches that consumer and the resulting script execution,
  active-content origin, configuration change, overwrite, parser exploit, or
  other protected effect. MIME or extension checks alone are not suppression;
  parse-and-re-encode plus storage outside every active consumer can be.
- For archive symlink and hardlink findings, preserve the ordered archive
  entries, link name and target, target interpretation base, extraction root,
  lexical member checks, materialized link, later regular member, filesystem
  resolution at every path component, final opened object, and protected
  overwrite or disclosure. Prove the link is followed on the deployed
  extraction path; link-related symbols or a suspicious target alone are not
  reportable. Link-entry rejection, root-handle-relative no-follow traversal of
  every component and final file, a pre-existing-link rejection control, and a
  legitimate nested extraction are distinct counterevidence.
- For decompression-bomb and data-amplification findings, preserve the remote or
  tenant-controlled compressed bytes; container/codec; compressed, declared,
  and actual expanded sizes; ratio; entry and nesting structure; decoder call;
  streaming/allocation behavior; entry count; per-entry limits; cumulative
  compressed-input/decoder-work and expanded-output/retention budgets;
  concurrency and request budgets; retained memory or disk; and the shared
  worker, parser, event-loop,
  disk, or service capacity made unavailable. Validate with a bounded witness
  and a legitimate input. Codec symbols, high ratios, or absent metadata checks
  alone are not reportable without reachable resource impact; actual-output
  caps plus cumulative input-work and pre-retention output accounting and
  relevant nesting/concurrency controls are counterevidence.
- For authenticated-encryption nonce/IV-reuse findings, preserve the exact
  algorithm and mode, key identifier/derivation/scope, first and second nonce,
  plaintext and ciphertext lengths, authentication tags, AAD, envelope
  publication or attacker observation, restart/worker/tenant/rollback path, and
  recovered plaintext or accepted forgery. Prove the same key/nonce pair, not
  merely a repeated nonce under different keys. A valid tag is not
  counterevidence for GCM reuse. Fresh key-scoped random nonces, independently
  derived per-message data keys, or atomically persistent nonrepeating
  counters, fail-closed verification before plaintext release, metadata AAD,
  and a successful legitimate decrypt are distinct counterevidence.
- For HTTP request-smuggling and desynchronization findings, preserve the exact
  raw bytes, ingress protocol, proxy/gateway/server/backend versions and
  configuration, duplicate-header normalization, effective framing decision,
  consumed and residual bytes, connection pooling/reuse, route and principal at
  each hop, and the downstream protected request or response. Prove the same
  bytes are accepted across the deployment chain and that the parser
  disagreement bypasses a control or affects another request. A conflicting
  header pair without per-hop boundaries and impact is not reportable; exact
  first-hop rejection or canonical one-message forwarding is counterevidence.
- For duplicate-parameter authorization-confusion findings, preserve the exact
  raw query/form/body bytes, ordered decoded name/value pairs, encoding aliases,
  and every gateway, middleware, framework, signature, authorization, router,
  and backend interpretation. Show the security-relevant value selected at the
  check, the different value selected at use, the principal and resource, and
  the resulting protected effect. Reverse duplicate order or remove the extra
  parameter to demonstrate the differential rather than an unrelated missing
  permission check. Duplicate acceptance, a parser-name mismatch, or differing
  generic library defaults without a changed security decision is not
  reportable. Strict bounded decoding once, duplicate decoded-key rejection,
  immutable canonical-object propagation, and downstream authorization of the
  same action are counterevidence.
- For HTTP response-header injection and response-splitting findings, preserve
  the attacker-controlled value and decoding path, exact raw response bytes,
  injected header or second response, downstream proxy/gateway/cache/browser
  interpretation, deployment configuration, and the secret, session, cache,
  redirect, internal route, or protected object affected. Prove the consumer
  honors the injected field; a raw interpolation, header name, or CR/LF-capable
  helper without an effect is not reportable. Rejection of all response-field
  control bytes before serialization, context-correct quoting/encoding, and a
  legitimate-value success path are distinct counterevidence.
- For SAML/federated signed-object findings, preserve the exact response and
  signature bytes, reference URI/ID, ID uniqueness, canonicalized byte range,
  verified assertion object, returned/cloned object, claims source, issuer,
  audience, recipient, destination/ACS, subject confirmation, lifetime, replay
  state, and the final session subject and privileges. Prove an unsigned or
  differently bound object becomes trusted despite a valid signature over
  another object. A signature success without that object-continuity proof is
  not enough; claims derived only from the unique verified payload with complete
  semantic and replay binding are counterevidence.
- For JWT/JWS/OIDC remote-key findings, preserve the compact token, protected
  header, `alg`, `kid`, `jku`/`x5u` or embedded key, configured issuer and
  metadata, final JWKS/certificate URL after redirects, cache scope, all matching
  keys and their type/use/algorithm, signature result, accepted claims,
  nonce/replay state, and installed principal. Prove the attacker can cause
  their own key to become the trust root for a token that receives protected
  identity or privileges. Signature success alone is not a control; a trusted
  issuer-pinned key source and end-to-end claim binding are counterevidence.
- For JWT/JWS algorithm-confusion findings, preserve the legitimate asymmetric
  token and the forged compact token, decoded `alg` and `kid`, published public
  key bytes, runtime key representation, signature-versus-MAC branch, exact
  cryptographic primitive and result, accepted claims, and protected identity or
  action. Prove the attacker can compute the accepted forgery without the
  private key by reinterpreting public verification material or otherwise
  crossing algorithm/key families. A verifier that pins the algorithm before
  key lookup, requires a compatible key object, invokes only the intended
  primitive, accepts a legitimate token, and rejects the same forgery is
  counterevidence.
- For OIDC ID-token client-binding findings, preserve the target and sibling
  client registrations; attacker and victim browser sessions; target initiation
  state and nonce; the sibling-client flow through which a valid victim token is
  exposed to the attacker; compact token and signature result; issuer, scalar or
  array `aud`, `azp`, nonce, subject, and lifetime; every relying-party claim
  check; and the final target-app session identity. Prove the attacker can pair
  their own valid target callback state with a victim token issued to another
  client and receive the victim's target-app session. A trusted signature,
  issuer, expiry, or callback state alone does not close audience or nonce
  substitution. Exact target-client audience and authorized-party validation,
  one-time session-transaction nonce equality, replay rejection, and continuity
  through principal installation are counterevidence.
- For WebAuthn/passkey credential-account-binding findings, preserve two
  registered principals and credentials; the victim-targeted initiation and
  fresh challenge; transaction expiry and one-time state; RP ID, origin,
  authenticator flags and sign counter where applicable; the attacker-owned
  credential ID, owner and `userHandle`; successful signature verification; and
  the final session principal. Prove that the attacker can sign with only their
  own credential yet receive a session for the victim. Exact RP/origin and
  signature checks authenticate the credential but do not bind it to a
  separately selected username. A user-bound transaction with an allowed-
  credential set, owner equality, complete assertion verification, replay
  rejection, and credential-owner-derived session identity is counterevidence.
- For signed-webhook replay findings, preserve how the attacker captures or can
  resend one legitimate request; the exact raw body, signature header, signed
  timestamp, and event ID; successful provider authentication; missing or
  ineffective freshness; missing, late, or non-atomic event consumption; the
  account/object and amount/action selected from authenticated bytes; and each
  repeated financial or state-changing effect. Distinguish signature forgery
  from capture-replay: a correct HMAC is expected in the exploit. Strong
  counterevidence requires a bounded signed-timestamp window and atomic unique
  event-ID consumption in the same transaction as the protected mutation, with
  one legitimate delivery succeeding and duplicates remaining harmless.
- For ECDSA/DSA signature-malleability replay findings, preserve the curve and
  signature encoding, exact signed bytes, original `(r, s)` signature,
  attacker-derived valid twin such as `(r, n-s)`, successful verification of
  both, distinct representation-derived replay/idempotency keys, event identity,
  and each financial or state-changing effect. Do not call the twin a forgery:
  the control failure is using a non-unique signature representation as
  security identity. Strong counterevidence is atomic signed-event identity or
  complete canonicalization before every representation-sensitive decision,
  plus legitimate, invalid-signature, tamper, stale, and duplicate controls.
- For OAuth/OIDC authorization-code login and account-linking findings, preserve
  both attacker and victim browser sessions; the initiation account and
  operation; authorization request; code, `state`, nonce, redirect URI, PKCE
  challenge and verifier; server-side transaction lookup and consumption; code
  exchange; verified external issuer/subject; local account selected for
  linking; and later session or external login. For account takeover, prove the
  attacker can obtain a code for their own external identity, make the victim
  submit it while authenticated, bind that identity to the victim's local
  account, and later sign in as the victim. Do not infer takeover from a missing
  `state` parameter or callback API alone. A one-time unpredictable
  session/account/operation-bound transaction, fixed issuer/client/redirect URI,
  transaction-bound S256 PKCE, and transaction-account identity installation
  are strong counterevidence.
- For login session-fixation findings, preserve two clients and the exact
  identifier across attacker anonymous-session creation or injection, victim
  cookie adoption, credential verification, session-store promotion or
  replacement, post-login Set-Cookie, and attacker replay to a protected
  endpoint. Account takeover requires that the replayed attacker-known
  identifier resolves to the victim principal after login. Distinguish this
  from harmless pre-authentication state continuity when the authenticated ID is
  fresh and the old record is atomically invalidated.
- For password-reset, verification, invitation, or magic-link origin findings,
  preserve the public ingress/proxy topology, raw and normalized `Host`/
  `Forwarded`/`X-Forwarded-*` values, server-side authority selection, exact
  secret-bearing absolute URL, legitimate outbound message, victim navigation,
  attacker capture, canonical completion request, token consumption, and final
  password/session/identity/trust-state change. Account takeover requires proof
  that attacker-selected authority survives the actual trust policy and yields
  a capability the attacker can redeem; header names or a URL builder alone are
  not enough. A fixed configured public origin, strict canonicalization before
  URL construction, no secret-bearing open redirect, and a negative control in
  which the attacker receives no token are strong counterevidence. Do not treat
  strong entropy, expiry, hashing at rest, or one-time use as counterevidence to
  disclosure of the live token.
- Identify the strongest repository counterevidence against the scoping and reportability-driving fields before finalizing them.
- Lower confidence or keep fields unknown when repository evidence is incomplete; do not automatically suppress a finding solely because deployment evidence is missing.

## Counterevidence Checklist

For the most interpretive fields, explicitly ask what repository evidence suggests the opposite and why it does or does not defeat the finding:

- In-Scope Status According to the Threat Model
- Vector
- Auth Scope
- Exposure
- Cross-Boundary Behavior
- Preconditions
- Impact Surface

Look specifically for repository evidence that the path is:

- out of scope
- internal-only
- admin-only
- not cross-boundary
- not attacker-reachable
- not meaningfully reportable

## Severity and Policy Checklist

Apply severity and policy calibration using `references/severity-policy.md`.

## Output Contract

In compact standard-scan mode, use the nested record defined in `../../references/scan-artifacts.md`. Every validation row with disposition `reportable` or `deferred` must receive exactly one attack-path decision. The record is the phase closure for this mode; do not also create a narrative report or receipt.

Outside compact standard-scan mode, use the following report contract.

For each surviving finding include:

- title
- candidate id, instance key, and ledger row id when provided
- affected lines from validation, preserving labeled entrypoint/wrapper, root_control, sink, and concrete_implementation locations
- attack path steps
- rendered attack-path facts
- counterevidence summary and challenges
- severity calibration
- final policy decision
- enough reasoning that a later reader can understand why the finding survived or was suppressed

Render attack-path facts using `references/attack-path-facts.md`.

## Hard Rules

- Prefer repository evidence first, but use network connectivity when it materially helps confirm deployment context, reachable surfaces, or other reportability-relevant facts.
- Do not invent attack chains that the code does not support.
- Do not compress a multi-component chain into a generic source-to-sink claim.
  Preserve the intermediate stored state, callback, redirect, queue, mutable
  record, or privileged worker that makes the exploit possible, and distinguish
  a proved chain from a plausible but unverified adjacency.
- Do not leave candidate coverage implicit. In compact standard-scan mode, every candidate that reaches attack-path analysis must receive a nested `attack_path` record, even when the final policy decision is `ignore` or `deferred`. In other modes, every such candidate must leave an attack-path receipt in its candidate-ledger path from `../../references/scan-artifacts.md`.
- Do not drop exact affected locations while converting validated findings into attack paths. Repository-wide seeded/root-control rows that survive validation must keep their root-control file:line even when a wrapper, route, or transport is easier to explain.
- Do not skip a reportable validation row because a neighboring same-family finding has a cleaner story. Either produce attack-path facts for that exact row or make an explicit final policy decision with repository counterevidence.
- Missing public-ingress evidence is not by itself dispositive counterevidence.
- Keep attack-path analysis, severity calibration, and final policy suppression as separate sub-stages.
- Use the final policy-adjustment matrix mechanically rather than re-arguing severity from scratch after the facts are set.
- Outside compact standard-scan mode, save a final visible report for each candidate finding using that finding's attack-path analysis report path from `../../references/scan-artifacts.md`. Compact standard scans use the nested phase record instead.

-- Considerations for attack path --

- A bug matters if evidence shows an attacker could exploit it.
- The attack surface should generally be one that is plausibly exposed to end users / external actors (or another actor explicitly in scope in the threat model).
