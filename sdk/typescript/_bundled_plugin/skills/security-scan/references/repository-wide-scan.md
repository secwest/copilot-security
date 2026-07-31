# Standard Repository Or Scoped-Path Review

Use this procedure for a standard repository or scoped-path scan. Review every file, collect candidates in one ledger, then validate and check reachability in two compact passes over that ledger. Do not use ranking or multi-stage queues from deep scans.

## File Inventory And Progress

Create the file list before review:

```text
mkdir -p "<discovery_dir>"
(cd "<repo_root>" && rg --files --hidden --glob '!.git/**' -- "<scope>" | LC_ALL=C sort) > "<discovery_dir>/in_scope_files.txt"
```

Keep repository-relative paths in artifacts. Do not skip a file just because it is educational, an example, a demo, a fixture, or a test. Include it when it contains runnable behavior such as a route, parser, or template. List binary or generated files that could not be reviewed. Because every file is reviewed, do not create ranking or deep-review worklists.

For an app scan, keep `reviewItemsTotal` at zero while building the file list. Then publish the file count, review files in batches, and update `reviewItemsCompleted` after each batch.

## Discover And Combine Once

Review every listed file from start to finish. Read nearby code when needed to understand it. Look for unsafe command execution, SQL and document-query selector/operator injection, LDAP filter construction and directory group/role authorization binding, XPath/XQuery expression construction and selected-node authentication/authorization binding, unsafe parsing, XSS, browser-ambient credential CSRF on meaningful state changes, credentialed CORS origin authorization from exact attacker origin and browser-attached credentials through actual-response headers to attacker-JavaScript readability of secrets or sensitive data, cookie-authenticated WebSocket upgrade Origin authorization through accepted channels, message handlers, attacker-readable replies, and protected actions, web-cache deception across edge/shared-cache keys, extension and status cacheability, credential boundaries, private/no-store/Set-Cookie response handling, and origin rewrite/path-info/normalization disagreement, GraphQL aliases/fragments/nesting/batches/persisted documents that multiply security-sensitive resolver calls behind one transport envelope and bypass request-level limits or account/principal/tenant operation budgets, regular-expression catastrophic backtracking across fixed or dynamic patterns, attacker-controlled near-matches, actual engine behavior, pre-evaluation input bounds, and shared event-loop/worker/parser availability, login session fixation and authenticated-session rotation, password-reset, verification, invitation, and magic-login absolute URL origin binding across request/forwarded authority, proxy trust, configured public origins, outbound messages, victim navigation, and completion actions, OAuth/OIDC authorization-code state, nonce, PKCE, callback-session, redirect-URI, and account-linking transaction misbinding, JWT/JWS token-selected algorithm and key-family confusion including asymmetric public keys reused as HMAC secrets, signature-versus-MAC selection, token-controlled remote-key URLs, and unpinned JWKS/key origins, signed-versus-consumed SAML/federated identity mismatches, attacker-controlled network requests, unsafe file access, untrusted upload/content placement and its downstream serving, loading, parsing, or execution roots, inconsistent HTTP request framing across proxies/gateways/backends, missing permission checks, native memory bounds and lifetime violations, and request-controlled bulk object binding or mass assignment into persisted or privileged state. For CORS, distinguish read authorization from CSRF, test same-site siblings and exact serialized-origin controls, and do not infer a credentialed browser read from preflight, headers, or wildcard-plus-credentials alone. For WebSockets, CORS and preflight are irrelevant: trace browser cookie attachment and Origin through upgrade acceptance, session binding, the exact bidirectional message or action, and exact-origin or session-bound-token controls. For web caches, trace one exact attacker URL through a cold miss, credentialed victim population, origin route interpretation, response directives, shared storage, and a later credential-free hit; compare exact routing and explicit public-only caching as controls. For GraphQL, compare the transport request count with the fully expanded execution plan and each downstream protected operation; require bounded depth/selection/complexity and batch size plus atomic resolver/service-layer quotas for high-risk operations, while treating benign bounded batching as a negative control rather than a vulnerability. For regex complexity, preserve the exact pattern, runtime engine, adversarial near-match, input length, evaluation context, and shared resource; use bounded witnesses and compare legitimate behavior with a linear, unambiguous, or strictly bounded control instead of inferring ReDoS from syntax alone. For JWT/JWS, trace the protected `alg` through allowlisting, key lookup, runtime key construction, and the exact verify/MAC primitive; require a pinned algorithm and compatible key type, and treat a legitimate token as the safe-path control. Do not ignore a clear bug because another issue seems more important.

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

Write raw candidates to one or more temporary JSONL files, then combine them:

```text
<python_command> <plugin_dir>/scripts/normalize_candidates.py --input <candidate-source> [<candidate-source> ...] --out <discovery_dir>/candidate_ledger.jsonl --repo-root <repo_root> --in-scope-files <discovery_dir>/in_scope_files.txt
```

Each raw candidate row uses only these fields:

- `cwe_ids`: an array of `CWE-<positive integer>` strings, which may be empty.
- `locations`: an array of repository-relative `path`, positive `start_line`, optional `end_line`, and `role`. The role is one of `entrypoint`, `entrypoint/wrapper`, `source`, `root_control`, `sink`, `concrete_implementation`, or `evidence`. At least one location must be in `in_scope_files.txt`; supporting locations may be elsewhere in the repository.
- `summary` and `evidence`: concise text describing the possible bug and the code path.
- optional `context`: concise text that may help the review.
- optional `instance`: a short label for separate bugs that share the same locations, such as different request parameters or operations.

The combiner validates this shape and merges rows with the same CWE ids, locations, and optional instance. It preserves their text and writes deterministic rows with a stable `candidate_id`. It does not infer a status or decide whether a candidate is a bug. `candidate_ledger.jsonl` is the sole durable candidate artifact for a standard scan. Do not create one ledger or report per candidate, validation or attack-path queues, duplicate reports, or repeated receipts.

After normalization, freeze every discovery field, including `candidate_id`, `locations`, and `instance`. The two compact phase passes below may only add their nested records. Rewrite the ledger atomically and preserve its row order. Never feed an enriched ledger back through `normalize_candidates.py`; that script accepts raw discovery rows only.

## Validate And Check Reachability

Run `/validation` once over the complete ledger in compact standard-scan mode. It must add a `validation` record to every row and preserve separate bugs, including bugs reachable through different routes or code paths. Do not dismiss a real bug just because the code is a demo, test, or only runs locally.

Then run `/attack-path-analysis` once in compact standard-scan mode over validation rows with disposition `reportable` or `deferred`. It must add an `attack_path` record to every row that enters the phase, preserve exact affected locations, and use the threat model to decide realistic reachability and severity. A neighboring finding does not close the current candidate.

Build canonical findings and coverage from the file list and enriched candidate decisions using the ordered mapping in `../../../references/final-report.md`. Include all relevant code locations in each finding.
