# Standard Repository Or Scoped-Path Review

Use this procedure for a standard repository or scoped-path scan. Review every file, collect candidates in one ledger, then validate and check reachability in two compact passes over that ledger. Do not use ranking or multi-stage queues from deep scans.

## Framework Data-Flow Models

During detection, classify framework-aware paths as exact source,
propagator, closest control, sink argument, and outcome tuples. Apply the
host-provided Node HTTP, Python web, Spring/servlet, and ASP.NET command and raw
SQL models when their concrete runtime or API is present. A source and sink in
the same file are only a hypothesis: prove that the same attacker-controlled
value reaches the sink across wrappers and transformations. Treat argument
vectors without a shell and native SQL parameter binding as strong negative
controls only when they apply to the same value and dominate the sink. Generic
validation, escaping for another interpreter, framework annotations, and API
names alone are neither sanitizers nor findings. The mandatory residual pass
will provide exact typed model rows for any high-risk paths the first pass may
have missed; close every such row explicitly.

## File Inventory And Progress

The trusted host creates `COPILOT_SECURITY_INVENTORY_PATH` and
`COPILOT_SECURITY_REVIEW_WORKLIST` before model execution. Consume every row
without recreating, overwriting, appending to, deleting, narrowing, or
reordering either file. Use Copilot's built-in file tools with the exact
repository-relative paths. On Windows do not use shell/native tools for
repository enumeration or reads, and do not change directories; the native
sandbox preview may give child shells an unusable working directory.

Keep repository-relative paths in artifacts. Do not skip a file just because it is educational, an example, a demo, a fixture, or a test. Include it when it contains runnable behavior such as a route, parser, or template. List binary or generated files that could not be reviewed. Because every file is reviewed, do not create ranking or deep-review worklists.

For an app scan, keep `reviewItemsTotal` at zero while building the file list. Then publish the file count, review files in batches, and update `reviewItemsCompleted` after each batch.

## Discover And Combine Once

Review every listed file from start to finish. Read nearby code when needed to understand it. Look for unsafe command execution, SQL and document-query selector/operator injection, LDAP filter construction and directory group/role authorization binding, XPath/XQuery expression construction and selected-node authentication/authorization binding, unsafe parsing, XSS, browser-ambient credential CSRF on meaningful state changes, credentialed CORS origin authorization from exact attacker origin and browser-attached credentials through actual-response headers to attacker-JavaScript readability of secrets or sensitive data, cookie-authenticated WebSocket upgrade Origin authorization through accepted channels, message handlers, attacker-readable replies, and protected actions, web-cache deception across edge/shared-cache keys, extension and status cacheability, credential boundaries, private/no-store/Set-Cookie response handling, and origin rewrite/path-info/normalization disagreement, server-side application authorization-cache key isolation across authenticated principal/tenant/role/resource dimensions, hit-path ownership checks, permission changes, and invalidation, GraphQL aliases/fragments/nesting/batches/persisted documents that multiply security-sensitive resolver calls behind one transport envelope and bypass request-level limits or account/principal/tenant operation budgets, forwarded client identity across direct peers, exact trusted proxies, append/overwrite topology, canonical hop parsing, right-to-left peeling, and client/account/principal budgets, regular-expression catastrophic backtracking across fixed or dynamic patterns, attacker-controlled near-matches, actual engine behavior, pre-evaluation input bounds, and shared event-loop/worker/parser availability, login session fixation and authenticated-session rotation, password-reset, verification, invitation, and magic-login absolute URL origin binding across request/forwarded authority, proxy trust, configured public origins, outbound messages, victim navigation, and completion actions, OAuth/OIDC authorization-code state, nonce, PKCE, callback-session, redirect-URI, and account-linking transaction misbinding, signed OIDC ID-token audience/authorized-party/nonce/client-session misbinding across sibling clients even when signature and issuer checks pass, JWT/JWS token-selected algorithm and key-family confusion including asymmetric public keys reused as HMAC secrets, signature-versus-MAC selection, token-controlled remote-key URLs, and unpinned JWKS/key origins, signed-versus-consumed SAML/federated identity mismatches, attacker-controlled network requests, unsafe file access, untrusted upload/content placement and its downstream serving, loading, parsing, or execution roots, inconsistent HTTP request framing across proxies/gateways/backends, duplicate query/form/body parameter interpretation across gateways, middleware, signature or authorization checks, frameworks, and downstream consumers, missing permission checks, native memory bounds and lifetime violations, and request-controlled bulk object binding or mass assignment into persisted or privileged state. For CORS, distinguish read authorization from CSRF, test same-site siblings and exact serialized-origin controls, and do not infer a credentialed browser read from preflight, headers, or wildcard-plus-credentials alone. For WebSockets, CORS and preflight are irrelevant: trace browser cookie attachment and Origin through upgrade acceptance, session binding, the exact bidirectional message or action, and exact-origin or session-bound-token controls. For web caches, trace one exact attacker URL through a cold miss, credentialed victim population, origin route interpretation, response directives, shared storage, and a later credential-free hit; compare exact routing and explicit public-only caching as controls. For application authorization caches, prove two principals' cold scoped results differ, then show one principal's population causes a wrong-object or wrong-decision hit for the other; compare trusted identity-partitioned keys, hit validation, and permission-change invalidation as controls. For GraphQL, compare the transport request count with the fully expanded execution plan and each downstream protected operation; require bounded depth/selection/complexity and batch size plus atomic resolver/service-layer quotas for high-risk operations, while treating benign bounded batching as a negative control rather than a vulnerability. For proxy-derived client identity, begin at the socket peer, trust headers only from exact configured hops, peel from the right, and prove one fixed client can or cannot rotate prepended hops past a security budget. For duplicate parameters, preserve the raw ordered input and each component's decoded first/last/array/merge result; require the security check and protected consumer to select different attacker-controlled values, and compare a strict decode-once duplicate-rejecting canonical path. For regex complexity, preserve the exact pattern, runtime engine, adversarial near-match, input length, evaluation context, and shared resource; use bounded witnesses and compare legitimate behavior with a linear, unambiguous, or strictly bounded control instead of inferring ReDoS from syntax alone. For OIDC ID tokens, pair a valid sibling-client victim token with an attacker-owned target callback and trace `aud`, `azp`, nonce, state, and installed principal; require exact target-client and session-transaction binding, not only signature and issuer checks. For JWT/JWS, trace the protected `alg` through allowlisting, key lookup, runtime key construction, and the exact verify/MAC primitive; require a pinned algorithm and compatible key type, and treat a legitimate token as the safe-path control. Do not ignore a clear bug because another issue seems more important.

For native format strings, distinguish the exact format-grammar parameter from
data parameters, preserve conversion syntax and variadic argument types/order,
and require a concrete read, write, disclosure, corruption, or crash effect. A
fixed literal format with untrusted content supplied only as matching data is a
control, not a finding; a printf-family or logging API name proves nothing by
itself.

For WebAuthn/passkey authentication, enumerate initiation and completion routes,
transaction and challenge stores, registrations, credential lookup, RP/origin
policy, authenticator verification, and session creation. Trace the requested
account through the allowed credential set to the verified credential owner and
the principal installed in the session. Exercise a victim-targeted transaction
with an attacker-owned valid credential; exact RP/origin/signature checks alone
do not close account binding. Compare a short-lived one-time user-bound
transaction, owner equality, complete assertion verification, replay rejection,
and credential-owner-derived session identity as the control.

For archive extraction and restore/import paths, trace member names separately
from symlink and hardlink targets, their relative-target base, archive ordering,
pre-existing destination links, every materialized path component, and the
later regular-member write or copy. Exercise link-then-file and pre-existing-
link pivots. Member-name containment alone is insufficient; compare link
rejection and root-directory-handle-relative no-follow traversal of every
component and final file while preserving a legitimate nested extraction.

For decompression and data-amplification paths, trace untrusted compressed bytes
through the concrete codec into actual expanded output and retained memory or
disk. Compare compressed, declared, and observed sizes; expansion ratio;
entry-count and per-entry limits; cumulative compressed-input/decoder-work and
expanded-output/retention budgets; nested, request, and concurrency budgets;
streaming versus whole-buffer allocation; and shared worker/service impact. Do
not accept
input-size or header-only checks as output bounds. Require a bounded valid bomb
witness plus a legitimate input, and recognize output caps enforced during
decoding with cumulative input-work and pre-retention output accounting as
counterevidence.

For authenticated encryption, trace each plaintext through algorithm and mode,
exact key identity and scope, nonce/IV construction, ciphertext and tag
publication, AAD, verification, and plaintext use. Test key-scoped nonce
uniqueness across messages, restarts, workers, tenants, counter rollback,
backups, and key rotation. Require a bounded same-key witness that recovers
plaintext or produces an accepted forgery; a constant nonce or valid tag alone
is not complete proof. Compare fresh cryptographic nonces, independently
derived per-message data keys, or atomically persistent nonrepeating counters,
metadata AAD, fail-closed verification before plaintext release, and a
legitimate encrypt/decrypt path.

For HTTP response headers, trace untrusted redirect targets, filenames,
cookies, metadata, proxy-derived values, and custom fields through all decoding,
CR/LF and control-byte checks, quoting/encoding, framework or raw serialization,
and downstream proxy, gateway, cache, and browser interpretation. Require exact
serialized bytes plus a protected effect such as internal-resource disclosure,
cookie/redirect manipulation, cache poisoning, or a second response. Compare
control-byte rejection before serialization and a legitimate encoded value as
the negative control; a response-header API or interpolation alone is not proof.

For signed webhooks and callbacks, trace the exact raw body, signature header,
signed timestamp, event/delivery ID, parsed account/object and amount/action,
and protected effect. Replay one unchanged legitimate request at least twice.
Require a bounded past/future freshness window and atomic one-time event-ID
consumption in the same transaction as the protected mutation; a valid HMAC or
signature and rejection of tampered bytes do not prevent capture-replay.

For ECDSA/DSA-signed operations, trace signature representation through every
replay, deduplication, cache, audit, uniqueness, and idempotency decision. Submit
one legitimate signature and its mathematically equivalent valid twin such as
P-256 `(r, n-s)` over identical bytes. Require both to resolve to one atomically
consumed signed semantic event/operation ID, or prove canonicalization precedes
every representation-sensitive use. Acceptance of both signatures alone is
safe; distinct signature-byte keys that repeat a protected effect are not.

For external authorization and entitlement decisions, exercise explicit deny,
the exact exception or timeout, malformed/empty response, and legitimate allow
through the same handler. Preserve initial and final decision values and types,
catch/fallback/cache behavior, the policy subject/action/resource, the consumed
subject/action/resource, and whether the protected sink ran. An explicit deny
test does not close a failure-only bypass; conversely, do not report a remote
policy call or `catch` when every failure produces unavailable or forbidden,
permission begins unset, one exact bound affirmative decision is required, and
no protected effect occurs.

For hostname-based outbound requests, enumerate validation, proxy, HTTP-client,
redirect, pool, and transport DNS lookups and compare every checked A/AAAA
answer with the final socket destination. Exercise a public validation answer
followed by a private/link-local connection answer, direct private and mixed
answers, empty/malformed/unsupported-family answers, legitimate public traffic,
and every redirect policy. A private-address check followed by hostname-based
`fetch` or `get` is not closure when it re-resolves. Strong counterevidence
resolves once, validates the complete set, pins an approved address into the
actual connection while preserving Host/TLS identity, and rejects or fully
revalidates each redirect.

Do not stop reviewing a file after finding one bug.

Write candidates directly to `<discovery_dir>/candidate_ledger.jsonl`. Use one
JSON object per line and assign each row a unique, stable `candidate_id` based
on its root-control path, line, CWE family, and instance. Do not invoke Python,
Git, ripgrep, or `normalize_candidates.py` from the model sandbox. The trusted
host validates and canonicalizes the completed artifacts.

When `COPILOT_SECURITY_SARIF_SEEDS` is set, review that exact file once and
merge each independently reviewed in-scope row into the candidate ledger with
a unique candidate ID. The host already normalized it to this candidate schema and
removed imported messages, snippets, fixes, fingerprints, properties, and
embedded content. Preserve each row's `instance` so external seeds do not
collapse into native candidates before independent validation. Do not treat
their tool name, rule, severity, summary, or code-flow hint as proof.
For a scoped-path scan, include only seed rows with an exact location in the
immutable inventory; malformed rows fail closed.
Preserve the seed's exact `instance`, CWE list, and normalized locations.
Process every in-scope reserved `sarif-seed-NNNNN` instance exactly once; do
not insert an out-of-scope seed or invent another reserved instance. The host
will reject missing, duplicate, identity-mutated, or unbound reserved rows. It
also derives and seals
`artifacts/03_coverage/external_sarif_seed_coverage.json` from the immutable
seed input and final ledger. Never author or modify that host-owned receipt.

Each discovery candidate row initially uses these fields:

- `candidate_id`: a unique stable `candidate-<descriptive-id>` string.
- `cwe_ids`: an array of `CWE-<positive integer>` strings, which may be empty.
- `locations`: an array of repository-relative `path`, positive `start_line`, optional `end_line`, and `role`. The role is one of `entrypoint`, `entrypoint/wrapper`, `source`, `root_control`, `sink`, `concrete_implementation`, or `evidence`. At least one location must be in `in_scope_files.txt`; supporting locations may be elsewhere in the repository.
- `summary` and `evidence`: concise text describing the possible bug and the code path.
- optional `context`: concise text that may help the review.
- optional `instance`: a short label for separate bugs that share the same locations, such as different request parameters or operations.

Merge equivalent discoveries by CWE ids, locations, and optional instance before writing. Preserve distinct instances and do not infer a validation status from discovery alone. `candidate_ledger.jsonl` is the sole durable candidate artifact for a standard scan. Do not create one ledger or report per candidate, validation or attack-path queues, duplicate reports, or repeated receipts.

After discovery, freeze every discovery field, including `candidate_id`,
`locations`, and `instance`. The two compact phase passes below may only add
their nested records. Rewrite the ledger atomically and preserve its row order.

## Validate And Check Reachability

Run `/validation` once over the complete ledger in compact standard-scan mode. It must add a `validation` record to every row and preserve separate bugs, including bugs reachable through different routes or code paths. Do not dismiss a real bug just because the code is a demo, test, or only runs locally.

Then run `/attack-path-analysis` once in compact standard-scan mode over validation rows with disposition `reportable` or `deferred`. It must add an `attack_path` record to every row that enters the phase, preserve exact affected locations, and use the threat model to decide realistic reachability and severity. A neighboring finding does not close the current candidate.

For an imported seed, a `reportable` or `deferred` validation without its own
attack-path decision is incomplete. A `suppressed` or `not_applicable`
validation closes the seed as rejected and may omit attack-path analysis or
use only an `ignore` decision. Do not convert a deferred validation directly
to a reportable attack-path decision; resolve the validation evidence first.

Build canonical findings and coverage from the file list and enriched candidate decisions using the ordered mapping in `../../../references/final-report.md`. Include all relevant code locations in each finding.
