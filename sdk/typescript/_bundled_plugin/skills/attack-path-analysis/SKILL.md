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
- For native-memory findings, preserve the attacker-controlled bytes, length,
  index, pointer, object state, or scheduling action; the allocation and exact
  source/destination object extents in consistent units; integer wrap,
  signedness, terminator/metadata space, ownership, and lifetime; the first
  invalid read/write/free/cast; and the corrupted object, control data, secret,
  crash, or execution outcome. Distinguish a demonstrated adjacent-field or
  control-flow overwrite from generic undefined behavior, and do not infer code
  execution when the repository proves only a bounded crash.
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
- For HTTP request-smuggling and desynchronization findings, preserve the exact
  raw bytes, ingress protocol, proxy/gateway/server/backend versions and
  configuration, duplicate-header normalization, effective framing decision,
  consumed and residual bytes, connection pooling/reuse, route and principal at
  each hop, and the downstream protected request or response. Prove the same
  bytes are accepted across the deployment chain and that the parser
  disagreement bypasses a control or affects another request. A conflicting
  header pair without per-hop boundaries and impact is not reportable; exact
  first-hop rejection or canonical one-message forwarding is counterevidence.
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
