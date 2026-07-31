# Severity and Policy Guidance

Use this guidance after attack-path facts, reachability, and counterevidence are established.

-- Considerations for severity / criticality re-rating --

- For `high` and above, the impact must be materially security-relevant (for example: account takeover, auth bypass, meaningful privilege escalation, significant sensitive data exposure/exfiltration, credible RCE, or similarly severe compromise), not simply a bug or strange behavior
- For a finding to remain `high` or `critical`, the exploitation path and impact should be clear enough that a professional security reviewer would not need a long speculative argument to justify it.
- Do **not** treat ordinary code bugs as high/critical security issues just because they are bugs or because the scanner labeled them that way.
- Do **not** keep `critical` based on contrived, highly speculative, or edge-case-only exploit stories unless the threat model explicitly supports those conditions. Critical DEMANDS attention implying an immediate likely threat.
- Do **not** keep `high`/`critical` for strange configurations or odd codebase behaviors unless there is clear evidence that an in-scope attacker can realistically exploit them for major impact.
- Do **not** rely on unusual operator mistakes, internal-only access, or non-attacker-reachable code paths to justify severe external impact unless the repository threat model says those actors/paths are in scope.
- If the issue is a real bug but not actually a security vulnerability, classify it as `ignore` (or, if you have to, `low`) for criticality purposes.
- If it is actually provable that there is no bug at all (the description is entirely wrong or made up and you actually got that real proof that it is so), then label it as `ignore` for criticality to mark a false-positive.

Non-exhaustive examples of vulnerabilities that often support `critical` when evidenced in code and context:

- Credible RCE or arbitrary code execution (command injection, LFI exec, trivial memory corruption exploits, etc.). Requires actual proof that attacker input causes this from an in-scope attack surface.
- Real XSS with meaningful proven impact (for example session/token theft, account compromise, privileged action execution, etc)
- Account takeover or strong authentication bypass, especially if it is 0-click
- Missing authorization checks / authorization bypass / tenant-boundary break (trivial IDOR, easy to swap out org or use ids with no authz, etc)
- Severe sensitive data leak (LFI, path traversal, bad scoping of file downloads, access to data without authorization, trivial side-channels) with realistic attacker access (proof the attacker can read secrets, PII, signing keys, credential stores, private keys, classified or highly confidential information (model weights etc))
- Trivial memory corruption exploits with known exploit patterns which require little effort to exploit
- SQL or other Database or query injection with clear proof of path from attacker input from in-scope attack surface and impact of the injection (leaks sensitive data, inserts dangerous records)
- Document-query or NoSQL operator injection that demonstrably selects another
  account or tenant, bypasses authentication or authorization, exposes
  sensitive records, or performs unauthorized update/deletion. Severity follows
  the selected object's privilege and data impact; a `$` token, object-valued
  request field, or document-query API without accepted operator semantics and
  a protected outcome is not sufficient.
- LDAP filter injection that demonstrably bypasses authentication, selects a
  privileged group or principal, or installs an unauthorized role/session can
  be `high` or `critical` according to the resulting privilege and blast
  radius. Interpolation, an LDAP API, a wildcard, or missing escaping without a
  proven attacker-controlled filter-semantic change and protected outcome is
  not sufficient.
- XPath or XQuery injection that demonstrably selects a privileged account,
  crosses a tenant or authorization boundary, exposes high-value secrets, or
  installs an unauthorized role/session can be `high` or `critical` according
  to the resulting privilege and blast radius. Expression interpolation,
  quotes, boolean keywords, or an XML-query API without a proven AST change,
  selected node, and protected outcome is not sufficient.
- Sandbox, container, VM, browser, or interpreter escape that breaks an intended isolation boundary
- Server-side template injection when it leads to RCE or leaking of secrets, with actual proof that the templating library can be exploited to do this (RCE escape or secrets/credentials in scope) and that this can be reached from an in-scope attack surface
- Arbitrary file write in executable, startup, config, or firmware paths with a realistic path to persistence or code execution. Requires proof that an attacker can actually trigger this from in-scope attack surface.
- Untrusted upload or content placement that writes attacker-controlled bytes
  into an automatically loaded plugin/extension, startup, interpreter,
  executable, or equivalent privileged content root and demonstrably produces
  code execution or compromise. A writable directory, upload API, filename
  extension, or MIME value without the downstream consumer and effect is not
  sufficient.
- HTTP request smuggling that demonstrably crosses a broadly exposed gateway or
  proxy boundary and yields unauthenticated privileged execution, cross-tenant
  compromise, credential/session capture, or reliable poisoning of many users.
  Critical requires the exact multi-hop parser disagreement and severe effect,
  not merely conflicting framing headers or a theoretical desynchronization.
- SAML/SSO signature wrapping or signed-object confusion that allows an
  unauthenticated attacker to install an arbitrary administrative, cross-tenant,
  or control-plane identity despite a valid signature being checked elsewhere
  in the response. Critical requires proof of the exact verified-versus-consumed
  object mismatch and resulting principal, not merely incomplete SAML hygiene.
- JWT/JWS/OIDC key-origin confusion that lets an unauthenticated attacker make
  their own remote or embedded key authoritative, forge a trusted administrative
  or cross-tenant identity, and install that principal. Critical requires the
  exact token, attacker-controlled key-origin path, successful verification, and
  compromise-equivalent identity impact.
- JWT/JWS algorithm/key-type confusion that lets an unauthenticated attacker
  forge an administrative, cross-tenant, signing, billing, or control-plane
  identity without the private key and obtain compromise-equivalent access.
  Critical requires the exact compact token, public or mismatched key material,
  selected signature/MAC branch, successful cryptographic check, accepted
  claims, and high-value protected effect.
- OAuth/OIDC authorization-code or account-linking transaction confusion that
  lets an attacker bind their external identity to an administrator,
  cross-tenant, billing, or otherwise high-value victim account and subsequently
  authenticate as that victim. Critical requires the exact attacker initiation,
  victim-session callback, missing or bypassed transaction/PKCE binding,
  resulting external-identity link, and successful later attacker login—not
  merely an absent `state` parameter.
- OIDC ID-token client or nonce misbinding that lets an attacker replay a
  correctly signed high-value victim token issued by the trusted provider to a
  sibling client and obtain the victim's target-app session. Critical requires
  the exact sibling-client token acquisition path, target callback transaction,
  accepted `aud`/`azp`/nonce mismatch, installed victim principal, and
  compromise-equivalent access—not merely an omitted claim check.
- Signed webhook replay that lets a remote attacker repeat a correctly
  authenticated event to cause unbounded crown-jewel financial transfers,
  administrative changes, cross-tenant effects, or safety-critical actions.
  Critical requires one exact captured body/signature/timestamp/event-ID tuple,
  successful repeated protected effects, realistic replay access, and impact
  equivalent to broad compromise—not merely missing idempotency terminology.
- Session fixation that lets a remote attacker preserve an attacker-known
  pre-authentication identifier through an administrator, cross-tenant,
  billing, or otherwise high-value victim login and reuse it for
  compromise-equivalent authenticated access. Critical requires the exact
  fixation mechanism, unchanged identifier or store alias, installed victim
  principal, and successful attacker replay.
- Account-recovery or identity-link origin poisoning that discloses a live
  secret-bearing link to an attacker and yields administrator, cross-tenant,
  billing, control-plane, or otherwise high-value account takeover. Critical
  requires the exact externally controllable authority through the deployed
  proxy/trust path, legitimate message, victim navigation, attacker token
  capture, canonical redemption, and compromise-equivalent account change.
- Credentialed CORS exposure of crown-jewel administrative, cloud, cross-tenant,
  or control-plane credentials or state that attacker JavaScript can read and
  use for broad compromise. Critical requires the exact attacker origin,
  browser-attached victim credential, actual-response CORS policy, readable
  sensitive body, and compromise-equivalent downstream use.
- Cross-site WebSocket hijacking that gives attacker JavaScript a victim's
  administrative, cloud, cross-tenant, or control-plane channel and demonstrates
  crown-jewel secret disclosure or compromise-equivalent privileged actions.
  Critical requires the exact browser handshake, ambient victim credential,
  accepted attacker Origin, message/action transcript, and downstream impact.
- Web cache deception that stores a victim's administrative, cloud,
  cross-tenant, or control-plane response under an attacker-fetchable shared
  key and demonstrates compromise-equivalent use. Critical requires a cold
  attacker denial, exact deceptive URL, credentialed victim population,
  edge/origin interpretation and cache decision, later credential-free hit
  returning the same crown-jewel object without an origin call, and downstream
  impact.
- Application authorization-cache key confusion that returns administrative,
  cloud, signing, billing, cross-tenant, or control-plane objects or allow
  decisions across authenticated principals and enables compromise-equivalent
  use. Critical requires different cold scoped results, the exact colliding
  identity-omitting key, first-principal population, second-principal hit that
  skips authorization, the same crown-jewel object or decision, and downstream
  impact.
- GraphQL operation amplification that converts one accepted transport request
  into enough authentication, MFA, recovery, invitation, token-issuance, or
  similarly privileged resolver operations to compromise an administrator,
  control-plane, cloud, cross-tenant, or otherwise crown-jewel account.
  Critical requires the exact expanded execution plan, actual resolver/service
  invocation count, bypassed effective budget, issued security capability or
  installed principal, and compromise-equivalent downstream action.
- Logic flaws that allow irreversible or broad compromise of integrity at scale, such as unauthenticated deletion of other users' data, cross-tenant tampering with sensitive records, or unauthorized modification of security-critical configuration, when the impact is clearly demonstrated and severe enough to be compromise-equivalent; when there is actual proof that this logic can be exercised from in-scope attack-surface.
- etc, other bugs not listed which follow this level of critical severity and impact; with actual proof that these bugs are reachable from in-scope attack-surface.

Non-exhaustive examples of vulnerabilities that often support `high` when evidenced in code and context:

- Server Side Request Forgery where there is actual proof that (1) an attacker can control the URL or final connected address from in-scope attack-surface and (2) local/LAN/cloud services can be reached with meaningful impact. DNS rebinding supports `high` when a public validation answer and later private/link-local connection are proved and expose credentials, protected internal data, or a security-sensitive operation. Be careful with reporting webhooks unless there is clear proof that they are dangerous, but do not treat a product-intended webhook/download/callback feature, direct-private-address rejection, a public preflight lookup, or an optional operator allow/deny list as suppression evidence when attacker-controlled destinations can still reach internal, metadata, file-backed, redirect, or side-effecting targets.
- Exploitable memory corruption with clear, major impact or ease of exploitation
- Arbitrary file read that exposes less-sensitive user data or source code (if you have actual proof it reveals env secrets, then it is critical)
- Arbitrary file write in executable, startup, config, or firmware paths with a realistic path to persistence or code execution
- CSRF when it enables important state-changing actions such as credential changes, permission changes, payment / billing changes, or security-setting changes with realistic victim interaction. Evaluate actual browser request behavior, credential attachment, cookie policy, preflight requirements, server parsing, and effective anti-CSRF controls; an HTTP method or JSON content type alone is not a categorical defense.
- Credentialed CORS exposure of ordinary but meaningful API keys, session
  tokens, account data, PII, or tenant data when attacker JavaScript can
  reliably read the victim's authenticated response. Severity follows the
  sensitivity, privileges, population, and demonstrated use of the disclosed
  material; reserve critical for compromise-equivalent administrative,
  cross-tenant, cloud, or control-plane impact.
- Cross-site WebSocket hijacking that exposes meaningful API keys, session
  material, PII, account or tenant data, or security-relevant authenticated
  actions to attacker JavaScript. High requires realistic browser credential
  attachment, accepted attacker Origin, and a readable message or protected
  effect; severity follows data sensitivity, privilege, and blast radius.
- Web cache deception that reliably exposes meaningful API keys, session
  material, PII, account data, or tenant data through a shared cache. High
  requires the exact cross-request sequence, a credentialed victim response
  stored under an attacker-reusable key, and a later credential-free hit;
  severity follows the sensitivity, privileges, affected population, cache
  lifetime, and demonstrated use of the disclosed material.
- Application authorization-cache key confusion that reliably returns one
  authenticated principal's or tenant's sensitive object or protected allow
  decision to another. High requires two valid principals, different cold
  authoritative results for one colliding logical resource ID, the exact
  identity-omitting key, a cross-principal hit that skips the scoped lookup,
  and meaningful confidentiality or integrity impact. Critical requires broad
  or compromise-equivalent administrative, cloud, signing, billing, or
  cross-tenant impact rather than one ordinary low-sensitivity record.
- GraphQL alias, fragment, nesting, batch, or persisted-document amplification
  that bypasses an intended authentication, MFA, recovery, invitation,
  payment, messaging, export, or other security-sensitive operation budget and
  demonstrably yields account takeover, unauthorized value transfer, meaningful
  protected data, or a comparably serious state transition. High requires the
  exact request-to-expanded-resolver multiplier, practical effective attempts
  or effects, missing/bypassable account or principal quota, and successful
  protected outcome; a theoretical increase in calls is not enough.
- Regular-expression denial of service that lets a low-cost unauthenticated or
  broadly reachable input monopolize a shared event loop, request worker,
  parser, protocol negotiation, or comparable finite service capacity.
  `high` requires the exact pattern/input near-match, bounded runtime or
  complexity proof, realistic repeated-request economics, ineffective or
  absent pre-evaluation bounds/isolation, and material multi-user availability
  impact. Use `medium` when the affected capacity or reachability is narrower
  but the superlinear behavior and service impact remain concrete.
- External authentication or authorization failure that defaults to or
  preserves allow and thereby exposes signing keys, administrative or
  cross-tenant data, identity controls, billing, deployment, or other
  compromise-equivalent operations. `critical` requires an exact low-privilege
  subject, policy exception/timeout/malformed response, resulting affirmative
  decision, protected sink invocation, and demonstrated crown-jewel effect.
- Hardcoded or default credentials that are valid, reachable, and provide meaningful access warranting `high`, even when that access is not broad or privileged enough for `critical`.
- Cryptographic failures that allow signature forgery, token forgery, trusted artifact forgery, secure-channel bypass, or decryption of highly sensitive data in a way that directly enables compromise, with actual proof that these attacks are practical and can be carried out from an in-scope attack surface.
- Supply-chain or update-channel compromise that allows malicious code or malicious trusted artifacts to be delivered to users, servers, agents, or endpoints, including signing bypass or package source substitution with real impact. This should focus on actual supply-chain risk and risk around CI actions, not just "does npm report outdated packages"
- Authorization bypass, IDOR, or privilege escalation that exposes or modifies meaningful sensitive data or privileged functionality, but is narrower in scope, limited to a smaller set of objects, limited to same-tenant boundaries, or otherwise less catastrophic than the critical cases above.
- Mass assignment or unsafe object binding that lets a realistically
  authenticated or unauthenticated attacker persist a security-sensitive role,
  permission, tenant, owner, identity, verification, recovery, billing, or
  trust-state field that later grants meaningful privileged access or protected
  state transitions. Severity follows the proven privilege and blast-radius
  delta; a bulk-binding API name without an effective writable privileged field
  is not sufficient.
- HTTP request smuggling that reliably bypasses gateway authorization, routing,
  or header normalization to reach meaningful protected functionality, or that
  poisons another user's request/response, when the exact bytes, parser
  boundaries, and deployed connection-reuse path are proved.
- SAML/federated assertion binding failures that reliably authenticate the wrong
  subject, role, tenant, issuer, audience, or recipient and produce meaningful
  unauthorized access, with the signature reference, consumed claims, and
  installed session identity demonstrated.
- JWT/JWS/OIDC verification that accepts an attacker-origin key through `jku`,
  `x5u`, embedded material, untrusted discovery, redirect, cache confusion, or
  ambiguous `kid` selection and thereby produces meaningful unauthorized access,
  with the selected key and installed identity demonstrated.
- JWT/JWS algorithm/key-type confusion that reliably accepts an
  attacker-computable token under a trusted key identifier and produces
  meaningful unauthorized access, with the selected algorithm, key
  reinterpretation, verification result, claims, and protected effect
  demonstrated.
- OIDC ID-token audience, authorized-party, or nonce misbinding that reliably
  accepts a correctly signed victim token issued to a sibling client and
  installs that victim in an attacker-owned target session. High requires the
  exact cross-client token path, target transaction, accepted claim mismatch,
  and resulting meaningful account access, plus a legitimate matching-token
  control.
- Signed webhook or callback replay that reliably repeats a meaningful payment,
  credit, entitlement, fulfillment, credential, or other protected mutation
  despite correct provider authentication. High requires the exact signed
  request, accepted stale or duplicate delivery, repeated effect, tamper/wrong-
  key rejection, legitimate first-delivery control, and evidence that freshness
  or atomic event consumption does not prevent the replay.
- External authorization fail-open that reliably converts a policy exception,
  timeout, malformed/empty result, stale fallback, or retry exhaustion into
  meaningful unauthorized access. High requires the exact policy inputs,
  failure outcome, default/final decision, protected operation, explicit-deny
  control, and legitimate-allow control; severity follows the asset,
  privilege delta, reachability, and blast radius.
- OAuth/OIDC login or account-linking CSRF that reliably authenticates the
  victim as the wrong subject, links an attacker-controlled external identity to
  a victim account, changes consent or credentials, or otherwise crosses a
  meaningful identity boundary with realistic browser interaction.
- Session fixation that reliably lets an attacker reuse a fixed
  pre-authentication identifier after victim login to obtain meaningful
  authenticated account access.
- Password-reset, verification, invitation, or magic-link origin poisoning that
  reliably discloses a live capability and produces meaningful ordinary account
  takeover or identity/trust-state change. Severity follows the proven account
  privilege, tenant boundary, victim interaction, and blast radius.
- XXE with clear proof that an attacker can control the XML document through in-scope attack-surface and that the XML engine is vulnerable to XXE
- etc, other bugs not listed which follow this level of high severity and impact; with actual proof that these bugs are reachable from in-scope attack-surface.
- Dangerous upload / file handling issues that enable stored active content, trusted-origin script execution, or meaningful content-type confusion with real security impact; with actual proof that both the upload and access are reachable through in-scope attack-surface.
- Deserialization, SSTI, plugin abuse, macro / template abuse, or interpreter abuse where dangerous primitives are clearly reachable and impactful, but code execution or compromise is not fully proven to the standard needed for critical.

Strong factors that often push a plausible `high` up to `critical`:

- Unauthenticated or near-unauthenticated reachability from the internet or other broad in-scope surfaces.
- 0-click or extremely low-friction exploitation.
- Cross-tenant / cross-boundary impact rather than same-user or same-tenant impact.
- Direct compromise of signing, identity, control-plane, or cloud credentials.
- Realistic persistence, mass exploitation, wormability, or compromise of many victims at once.
- Clear proof of code execution, full account takeover, or crown-jewel secret access rather than only a plausible path.

Examples that usually should not remain `high`/`critical` without very strong proof of it leading to the class of vulnerabilities above:

- Generic correctness/reliability bugs
- Strange edge cases with unclear attacker value
- Low-impact information leaks
- Internal-only defects without attacker reachability
- The report shows a bug class in isolation, but not a realistic exploit path.
- The issue requires the attacker to already have privileged, admin, root, console, shell, or code-execution access.
- "Could maybe matter if chained with many assumptions" arguments
- Self-XSS without a victim or meaningful boundary crossing, or XSS whose actual origin, browser reachability, and impact do not justify `high`/`critical`. An `alert` proof demonstrates JavaScript execution and is not evidence against reflected XSS.
- SQLi or other injection claims with no demonstrated attacker control, no shown sink reachability, or only speculative impact.
- CSRF on low-impact actions, cosmetic actions, logout, preferences, or actions requiring unrealistic victim behavior.
- CORS reports based only on middleware/header names, permissive preflight, a
  server-side 200, or origin reflection without proving browser-attached
  credentials and attacker-JavaScript readability of a sensitive actual
  response. Also suppress a claimed credentialed read when the only policy is
  wildcard allow-origin plus credentials (browser-blocked), the response is
  public/nonsensitive, credentials are bearer-only or server-only and not
  browser-attachable, an exact origin allowlist rejects the attacker before
  sensitive retrieval, or the actual response is not exposed. Evaluate any
  independent state-changing effect as CSRF.
- WebSocket-hijacking reports based only on a WebSocket library, upgrade route,
  missing generic middleware, authentication, or absent CORS headers without
  proving browser attachment of a victim credential, acceptance of the exact
  attacker Origin, and an attacker-readable sensitive message or meaningful
  protected action. Suppress anonymous public channels, browser-unattachable
  bearer/server credentials, exact Origin rejection before session/handler
  setup, an effective unpredictable session-bound connection token, or cookie
  policy that blocks every realistic attacker origin. A low-value ping,
  presence indicator, or cosmetic action does not support high severity.
- Web-cache-deception reports based only on cache APIs, response headers,
  static-looking suffixes, broad routes, or theoretical parser differences
  without proving a deployed shared cache, victim credentials, a sensitive
  origin response, storage under the exact attacker-fetchable key, and a later
  credential-free hit. Suppress private browser caches, public/nonsensitive
  objects, cold-cache misses that remain misses, exact-route rejection,
  correctly honored private/no-store or authenticated/Set-Cookie bypass, and
  correctly identity-partitioned cache entries.
- Application authorization-cache reports based only on a global cache, short
  key, cache hit before a repository call, tenant fields elsewhere, or
  theoretical key collision. Suppress unless two authenticated principals'
  cold authoritative results differ and one can receive the other's sensitive
  object or protected decision on a hit. Trusted identity-partitioned keys,
  tenant/owner verification before use, permission-change invalidation, and
  same-principal hit behavior are strong counterevidence.
- DNS-rebinding or SSRF reports based only on a hostname, resolver call,
  private-address helper, URL parser, or theoretical DNS change without proving
  a second effective lookup, forbidden connected address, and meaningful
  response or side effect. Suppress when every answer is checked, the approved
  address is pinned into the actual socket connection with correct Host/TLS
  identity, no later component re-resolves it, and redirects are rejected or
  revalidated at every hop while legitimate public traffic still works.
- GraphQL reports based only on aliases, fragments, batching, introspection,
  persisted queries, nested fields, a request limiter, or a missing named
  complexity plugin without proving the fully expanded protected resolver
  count, effective budget mismatch, and concrete security effect. Suppress
  bounded plans whose complete cost is charged before execution, high-risk
  operations limited to one where appropriate, atomic account/principal/tenant
  quotas enforced at the resolver or service boundary, and benign public
  batching that cannot reach the claimed effect.
- Open redirect, clickjacking, user enumeration, rate-limit weakness, banner leakage, version disclosure, directory listing, stack traces, internal hostnames, or basic error-message leakage, unless they are shown as part of a serious exploit chain.
- Memory corruption that is theoretical, non-triggerable from in-scope input, or not plausibly exploitable in the target environment.
- Request-smuggling claims based only on `Content-Length` and
  `Transfer-Encoding` appearing together, without proving divergent reachable
  parsers, accepted bytes, connection reuse or residual-byte handling, and a
  concrete protected effect.
- SAML/SSO reports based only on multiple assertions, index access, or a missing
  optional check without proving which exact bytes were signed, which object was
  consumed, which semantic binding failed, and what unauthorized principal or
  action resulted.
- JWT/JWKS reports based only on the presence of `kid`, `jku`, `x5u`, remote key
  fetching, dynamic issuer support, or a missing optional metadata check without
  proving attacker control of the accepted verification-key origin and a forged
  principal or protected action.
- JWT algorithm-confusion reports based only on support for more than one
  algorithm, a header-controlled `alg`, HMAC/RSA API names, or missing library
  options without proving a cross-family key reinterpretation, accepted
  attacker-computable token, and protected identity or action.
- OIDC ID-token reports based only on absent `aud`, `azp`, or nonce checks,
  generic claim parsing, or a signed-token API without proving an attacker can
  obtain a valid victim token for another client, pair it with a target
  transaction, and receive the wrong target-app principal. Suppress exact
  target-client audience/authorized-party validation, one-time session-bound
  nonce and state, replay rejection, and successful legitimate-token behavior.
- Signed-webhook reports based only on a signature API, timestamp field, missing
  named middleware, or generic duplicate-delivery concern without replaying an
  exact valid request into a repeated protected effect. Suppress when the exact
  raw body is authenticated, the signed timestamp has a bounded past/future
  window, the event identity and target are strictly bound, and atomic unique
  event consumption shares the transaction with the mutation so sequential and
  concurrent duplicates are harmless while legitimate delivery succeeds.
- OAuth/OIDC callback reports based only on missing `state`, nonce, or PKCE,
  parameter names, or a generic callback route without proving transaction
  substitution, browser-session/account misbinding, and a resulting wrong
  identity, account link, or protected action.
- Session-management reports based only on a pre-authentication session,
  unchanged non-security state, missing framework API name, or cookie flags
  without proving attacker knowledge or injection, identifier survival across
  authentication, and successful replay as the victim.
- Recovery-link reports based only on a `Host`, `Forwarded`,
  `X-Forwarded-Host`, forwarded-protocol, URL-builder, or reset-token symbol
  without proving accepted attacker control through the actual proxy/trust
  topology, a resulting secret-bearing attacker-origin URL, victim disclosure,
  and successful security action. Fixed deployment origins, strict canonical
  allowlists before URL construction, and trusted-proxy canonicalization are
  strong counterevidence; strong token entropy or one-time use alone is not.
- Missing headers, cookie flags, CSP weaknesses, TLS observations, or crypto hygiene issues without a concrete exploit path and meaningful demonstrated impact.
- Reports that effectively say "this could be dangerous if combined with something else" but do not show the something else.
- Denial of service that is transient, single-user, self-targeting, easy to mitigate, requires disproportionate attacker resources, or does not create severe and realistic business / safety impact.
- Regular-expression reports based only on a nested quantifier, ambiguous
  alternation, dynamic `RegExp`, unbounded input, or a slow development-machine
  timing without the exact engine, adversarial near-match, effective upstream
  bounds, shared-capacity path, and realistic attacker-to-defender cost ratio.
- Fail-open reports based only on a `catch`, remote policy call, default value,
  error log, circuit breaker, or unavailable dependency without proving the
  exact failure produces permission and reaches a protected operation. Suppress
  handlers that begin without permission, require an exact affirmative result,
  bind it to the consumed subject/action/resource, and invoke no protected sink
  on failures.
- Authz findings that require already having the same privilege as the victim, or only expose trivial metadata.
- Bugs that already require admin/root/shell access unless the privilege-escalation delta itself is the issue being reported.
- Arbitrary file read limited to public files, low-sensitivity files, or source fragments with no realistic security consequence.

High/Critical acceptance checklist (all should be true, unless the threat model strongly justifies an exception):

- In-scope component
- Realistic attacker
- Reasonable in-scope attack surface
- Credible exploitation path (not simply speculation)
- Major security impact
- Would likely be accepted as `high`/`critical` (not informational/low) in serious audit or bug bounty triage by a major auditing firm who puts their reputation on the line.

## Severity and Policy Checklist

Apply severity adjustment only after scope, reachability, and counterevidence are established. Do not reopen discovery here.

Start from the candidate's original severity hypothesis, then adjust it using the repository-evidenced facts from this phase.

Severity adjustment guidance:

- Keep `critical` only when the attack path, reachability, and impact are all clear enough that the finding would demand immediate attention.
- Keep `high` only when there is a realistic in-scope attacker path and major security impact without a long speculative chain.
- Downgrade when the path is real but constrained to narrower objects, same-tenant impact, internal-only surfaces, or other materially limiting conditions.
- Reduce severity when the path is localhost-only, self-only, highly constrained, dependent on unrealistic preconditions, or already requires privileged access unless the privilege-escalation delta is the issue.
- Dangerous sink, scary bug class, or sensitive code area alone is not enough to preserve high severity.
- If the issue is a real bug but not meaningfully reportable as a security problem in context, set the final policy decision to `ignore`.
- Do not discard an otherwise reportable finding solely because its impact or likelihood is `low`; downgrade its severity instead.

Final policy-adjustment guidance:

- Apply hard suppression first:
  - self-only impact -> `ignore`
  - unachievable or highly unrealistic preconditions -> `ignore`
  - privileged-only, operator-only, developer-only, physical-access-only, or protected-write-path preconditions -> `ignore`, unless the privilege-escalation delta itself is the issue
- Then weight likelihood using the established network scope:
  - `remote` usually supports high likelihood when the attacker position is realistic and in scope
  - `local_network` usually supports medium likelihood unless the evidence is stronger or weaker
  - `localhost` usually supports low likelihood unless a lower-privileged attacker can realistically reach that listener
  - `none` does not increase likelihood based on exposure
- Then decide reportability using the existing facts:
  - if repository evidence does not establish a realistic lower-privileged in-scope attacker path, set `ignore`
  - if the path is internal-only, developer-only, operator-only, localhost-only, privileged-local, or otherwise not meaningfully reportable in context, set `ignore`

Do not suppress solely because the surface is private or internal when repository evidence still shows a meaningful authorization, trust-boundary, identity, or security-control regression in a real product or production-service workflow. In those cases, internal exposure should usually reduce likelihood or confidence rather than force `ignore`.

Use missing deployment or ingress evidence to lower confidence or keep fields unknown when appropriate; do not automatically defeat an otherwise well-evidenced finding on that basis alone.

Severity calibration and final policy-adjustment matrix:

- `impact=high`:
  - `likelihood=high` -> `critical` only when the critical criteria above are satisfied; otherwise `high`
  - `likelihood=medium` -> `medium`
  - `likelihood=low` -> `low`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `medium`
- `impact=medium`:
  - `likelihood=high` -> `medium`
  - `likelihood=medium` -> `low`
  - `likelihood=low` -> `low`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `low`
- `impact=low`:
  - `likelihood=high` -> `low`
  - `likelihood=medium` -> `low`
  - `likelihood=low` -> `low`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `low`
- `impact=ignore`:
  - all likelihoods -> `ignore`
- `impact=unknown`:
  - `likelihood=high` -> `medium`
  - `likelihood=medium` -> `low`
  - `likelihood=low` -> `low`
  - `likelihood=ignore` -> `ignore`
  - `likelihood=unknown` -> `low`

Priority mapping after final severity:

- `critical` -> `P0`
- `high` -> `P1`
- `medium` -> `P2`
- `low` -> `P3`

Use this mapping after the final policy-adjustment pass determines the final reportable severity. Do not assign a priority to findings whose final policy decision is `ignore`.

Once the facts are set, use the severity calibration and final policy-adjustment matrix mechanically. Do not re-argue severity from scratch afterward.
