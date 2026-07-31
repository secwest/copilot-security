# Threat Model Guidance

Use this guidance during threat model generation.

## Threat Model Generation Checklist

Do not restate this checklist in the final threat model output.

- Start at the repository root and use the minimum hops needed to understand the repository's real-world purpose before narrowing into critical components.
- Keep this phase at repository scope unless the user explicitly asks for a narrower target-scoped threat model.
- Ignore any reviewed commit, diff, changed files, changed directories, commit title, and scan target during threat model generation unless the user explicitly asks for narrower scope.
- Distinguish primary product or runtime code from developer-only, test-only, documentation-only, example, prototype, or one-off tooling paths.
- Identify the primary product or runtime surfaces the repository actually exposes.
- Identify the main trust boundaries and which actors sit on each side of them.
- Explicitly separate attacker-controlled, operator-controlled, and developer-controlled inputs.
- Describe common vulnerability classes that are relevant in this repository context rather than findings about the current diff.
- Call out mitigations, robustness measures, and security controls already present in the repository when they materially affect severity or scope.
- Explain when attacker stories are realistic, when they are out of scope, and when the repository's real-world usage makes a vulnerability class less important.
- Note unique security considerations for the codebase, for example:
  - outbound URL and DNS trust across A/AAAA answer sets, public/private/special-range classification, validation-time versus connection-time resolution, proxies, redirects, connection pools, address pinning, Host and TLS identity, final socket destinations, cloud metadata and internal services, and legitimate public traffic
  - external authentication and authorization policy/entitlement decisions across initial defaults, explicit deny, exception, timeout, cancellation, malformed or empty response, retry exhaustion, stale cache, circuit breaker, fallback, exact-allow semantics, protected effects, and binding between the authorized and consumed subject/action/resource
  - authn/authz, session management including login fixation and authenticated-session rotation, password-reset, verification, invitation, and magic-login link origin binding across request authority, forwarded headers, proxy trust, configured public origins, outbound messages, victim navigation, and security-action completion, forwarded client identity across the direct peer, proxy append/overwrite topology, exact trusted-hop sets, canonical address syntax, right-to-left peeling, and client/account/principal security budgets, OAuth/OIDC authorization-code state, nonce, PKCE, callback-session, redirect-URI, and account-linking transaction binding, signed OIDC ID-token audience/authorized-party/nonce/client-session binding across sibling clients, JWT/JWS/OIDC algorithm-to-key-family and signature-versus-MAC binding including public-key-as-HMAC confusion, remote-key, issuer-to-JWKS, key-cache, claim, nonce, and replay binding, SAML/federated signed-object and issuer/audience/recipient/replay binding, CSRF, credentialed CORS response authorization across exact origins, browser credential attachment, actual-response headers, attacker-JavaScript readability, and sensitive-data or secret use, cookie-authenticated WebSocket handshake Origin authorization, accepted bidirectional channels, attacker-readable messages, and privileged actions, web-cache deception and shared-cache isolation across cache keys, credential boundaries, response directives, and edge/origin route normalization, application authorization-cache isolation across trusted principal/tenant/role/resource key dimensions, authoritative misses, hit-path ownership checks, permission changes, TTLs, and invalidation, GraphQL aliases/fragments/nesting/batches/persisted documents, execution-plan expansion, resolver fan-out, complexity charging, and atomic account/principal/tenant budgets for security-sensitive operations, regular-expression catastrophic backtracking across attacker-controlled near-matches, actual engine complexity, input bounds, and shared event-loop/worker/parser capacity, XSS, SSRF, SQL/document-query operator injection, LDAP filter and directory group/role authorization binding, XPath/XQuery expression and selected-node authentication/authorization binding, untrusted upload/content placement and its serving or execution roots, HTTP framing/parser agreement across proxies, gateways, protocol translators, and backends, bulk object binding and mass assignment, tenant boundaries, rate limits, and secret handling for web applications
  - signed webhook and callback trust across exact raw-body authentication, signed timestamps, bounded past/future freshness, capture-replay, event/delivery identity, atomic idempotency, duplicate and concurrent delivery, selected account/object, and repeated financial or state-changing effects
  - ECDSA/DSA signature representation and malleability across high-S/low-S or equivalent valid encodings, replay/deduplication/cache/audit/idempotency keys, signed semantic event or operation identity, atomic consumption, and repeated protected effects
  - archive extraction and restore/import trust across member names, symlink and hardlink targets, relative-target bases, entry ordering, pre-existing destination links, recursive promotion, root-directory-handle-relative no-follow traversal, final opened objects, and protected overwrite or disclosure effects
  - compressed-data trust across archive, package, document, protocol, media, backup, and import codecs; compressed, declared, and actual sizes; expansion ratios; entry-count and per-item limits; cumulative compressed-input/decoder-work and expanded-output/retention budgets; nested, request, and concurrency budgets; streaming versus whole-buffer allocation; retained memory/disk; and shared worker/service availability
  - authenticated-encryption trust across algorithm/mode, exact key identity and scope, nonce/IV derivation and key-scoped uniqueness across messages, restarts, workers, tenants, rollback, backups, and rotation, ciphertext/tag exposure, security-metadata AAD, tag verification before plaintext use, and confidentiality or forgery impact
  - duplicate query/form/body parameter trust across raw bytes, percent and character decoding, repeated decoded names, first/last/array/merge/rejection semantics in gateways, middleware, frameworks, signature and authorization checks, routers, and downstream consumers; checked-versus-used value binding; canonical decode-once propagation; and protected effects
  - HTTP response-header trust across untrusted redirect, filename, cookie, metadata, and proxy-derived values; decoding and normalization; CR/LF and control-byte boundaries; context-appropriate quoting and encoding; raw serializers; proxy, gateway, cache, and browser consumers; internal redirect/sendfile controls; and concrete downstream disclosure, session, redirect, cache, policy, or response-splitting effects
  - untrusted byte streams, parser and protocol lengths, allocation arithmetic, object bounds, ownership/lifetime, concurrency, privilege, and exploit mitigations for native or unsafe-language components
  - key management, privacy assumptions, ACLs/RBAC, PII handling, and auditability for cryptography or privacy-sensitive systems
  - public interfaces, embedding assumptions, safe-by-default behavior, footguns, and secure usage patterns for libraries or frameworks
  - production/runtime code paths versus CI, build, or local developer tooling
- Explain when a vulnerability class would be critical, high, medium, or low in this repository and give a couple of concrete examples at each level.
- If a vulnerability class requires attacker control that does not exist in the repo's real-world usage, say so in the severity calibration discussion.
- When possible, point to specific files, components, or controls that ground the threat model.

## Output Contract

When generating a threat model, structure it in Markdown with these sections:

- Overview
- Threat Model, Trust Boundaries, and Assumptions
- Attack Surface, Mitigations, and Attacker Stories
- Severity Calibration (Critical, High, Medium, Low)

The threat model should help a security researcher understand the codebase and its likely security-relevant failure modes. It should be detailed, repository-scoped, and suitable for reuse across unrelated diffs in the same repo.

Within those sections, make sure the output covers:

- repository overview and intended real-world usage
- trust boundaries and assumptions
- attacker stories and out-of-scope attacker stories
- attack surfaces and existing mitigations
- which vulnerability classes matter most in context
- which vulnerability classes are less severe or out of scope in context
- severity calibration with concrete examples at each level
- references to concrete files or controls when those materially ground the model
