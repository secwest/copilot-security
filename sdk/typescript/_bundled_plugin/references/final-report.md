# Final Report and Copilot Review Directives

Use this guidance when authoring canonical report semantics and returning the generated Copilot Security report and review directives.

## Final Outputs

The final readable output is a deterministic projection of `scan-manifest.json`, `findings.json`, and `coverage.json`:

- primary readable markdown report at the final scan report path from `scan-artifacts.md`
- optional detailed vulnerability write-ups under `findings/<slug>/`, linked from the primary report through `finding.writeup.reportPath`
- optional structural hardening guidance under `hardening/`, linked from the primary report through `scan.hardening.portfolioPath`

When writing `findings.json` alongside this readable output, populate the optional structured details in `finding-detail-fields.md` from the same validated evidence. Do not parse the rendered report back into finding data.

Use `report.md` as the primary readable entry point. Explain report-relevant artifact paths in the report itself, especially in `Scope`, `Reviewed Surfaces`, and `Open Questions And Follow Up`.

In the final response, link the generated markdown report path as the primary readable artifact.

Every scan mode uses the same final report pipeline. The model authors canonical JSON only; it must not author, repair, or treat an existing `report.md` as input. For an app-backed running scan, author `scan-manifest.json` as an unsealed draft and omit `scan.sealedAt` and `scan.artifacts`; finalization owns the exact workbench timestamps, seal, artifact digests, and derived finding identities. `complete-scan` invokes finalization, which validates and enriches the canonical JSON, seals the canonical JSON and evidence artifacts, then deterministically generates and validates `report.md` as an unsealed downstream projection. Missing report prose must be added to the structured canonical fields rather than recovered from a separately authored report.

When `complete_copilot_security_scan` is available, use it to complete the scan. In Copilot CLI or another terminal/chat host without that tool, run `python <plugin_dir>/scripts/finalize_scan_contract.py --scan-dir <scan_dir> --source-root <repo_root>` after writing the completed canonical JSON. Do not mark the scan goal complete until this command succeeds and the generated markdown report exists.

Before completion, verify on disk that the workflow-owned `scan-manifest.json`, `findings.json`, and `coverage.json` exist and contain the completed canonical JSON. Completion is finalization only: it validates and seals already-authored canonical artifacts and generates `report.md`; it does not create missing artifacts or run skipped scan phases.

If any required scan phase, canonical-artifact write, or on-disk existence check fails before completion, stop the current response and surface the exact workflow blocker. Do not call completion with missing artifacts, return a final report or no-findings result, satisfy a structured output schema, or emit benchmark JSON. Leave the durable scan available for a later continuation instead of canceling or failing it solely because canonical assembly is blocked.

If `complete_copilot_security_scan` or the terminal/chat finalizer fails, stop the current response and surface the exact MCP or finalizer error. Do not retry completion in the same response, return a final report or no-findings result, satisfy a structured output schema, or emit benchmark JSON. Leave the durable scan available for a later continuation instead of canceling or failing it solely because completion failed.

Canonical report semantics live in these fields:

- `scan-manifest.json`: `scan.scope` and `scan.threatModel`
- `findings.json`: each finding's `summary`, `codeEvidence`, `rootCause`, `validation`, `attackPath.dataflow`, `attackPath.reachability`, `severity.rationale`, `severity.changeConditions`, `remediation`, `remediationTests`, and `preventiveControls`
- `findings.json`: optional `writeup.reportPath` for a derived, unsealed detailed vulnerability report written under `findings/<slug>/<slug>.md`
- `scan-manifest.json`: optional `scan.hardening.portfolioPath` for the derived, unsealed design portfolio at `hardening/hardening.md`
- `coverage.json`: `surfaces` including `riskArea` and `notes`, plus `openQuestions`

For a whole-repository Deep scan, keep `coverage.inventoryStrategy` as `repository`; repeated discovery is workflow metadata, not a different inventory strategy.

Older v1 producers may omit the new optional fields. Finalization uses explicit JSON-derived fallback text in that case; it never reads a pre-existing report to fill gaps.

When `scan.hardening.portfolioPath` is present, include a short `## Structural Hardening` section linking the portfolio. Keep individual proposal links and the full option analysis in `hardening/hardening.md` rather than copying them into the primary scan report. The portfolio is design guidance, not evidence that any finding has been remediated.

When there are no reportable findings, include a short `No findings` section that explains why nothing survived discovery or the later reportability gates. For repository-wide and scoped-path scans with a coverage ledger, still include `Reviewed Surfaces` so checked, rejected, not-applicable, and follow-up-needed surfaces remain auditable.

When there are reportable findings, render them as readable markdown findings rather than raw JSON or a dumped schema object.
Order findings from highest severity to lowest severity: `critical`, then `high`, then `medium`, then `low`.

Use a separate finding entry for each independently attackable source/control/sink instance. Do not combine sibling routes, templates, query builders, parser operations, auth/object-access endpoints, or shared-helper callers into one representative finding solely for readability; if grouping helps, add a short grouped summary after the individual finding entries.

If validation or attack-path analysis provides a broad family row with multiple independently triggerable sink, parser, helper, API-mode, or protected-action lines, split it into child final findings before writing the report. Multiple affected lines inside one finding are appropriate for one inseparable proof tuple, such as a wrapper plus its shared sink, but not as a substitute for separate findings when sibling operations can be triggered independently.

Set the finding category and CWE from the primary broken control. Do not add secondary support-impact CWEs, such as data exposure or missing authentication, to an injection/RCE/path/file/parser finding merely because they make exploitation worse; mention those impacts in prose or emit a separate finding if that secondary control is independently vulnerable.

Examples that should normally become separate final findings include SQL API modes such as `execute`, `executemany`, and `executescript`; deserializer variants such as `pickle.load`, `pickle.loads`, `yaml.load`, and `yaml.load_all`; distinct path/file helper calls; SSRF modes with different destination controls; and missing-auth protected actions such as create, delete, reset, admin, and job-trigger endpoints.

For a standard repository or scoped-path scan, assemble the canonical JSON from the enriched `<discovery_dir>/candidate_ledger.jsonl`. Map each nested `validation` record into the finding's validation fields, map its confidence and rationale into top-level `confidence.level` and `confidence.rationale`, and map each nested `attack_path` record into dataflow, reachability, severity, and change conditions.

Apply row outcomes in this order: validation disposition `reportable` plus attack-path decision `reportable` becomes a finding with its distinct instance and all relevant entrypoint, root-control, sink, and supporting locations; otherwise, a `deferred` result from either phase becomes `needs_follow_up` coverage and a `coverage.deferred` entry using the recorded uncertainty or proof gap; otherwise, validation disposition `not_applicable` becomes `not_applicable` coverage; otherwise, validation disposition `suppressed` or attack-path decision `ignore` becomes `rejected` coverage. A missing required phase record leaves the candidate unresolved and prevents complete coverage. Do not require phase receipts, per-candidate narratives, or another reconciliation pass.

Diff, deep, and resumed legacy scans may still provide per-candidate ledgers, validation closure tables, and repository coverage ledgers. When those artifacts exist, retain their traceability: start from reportable/surviving rows, preserve exact affected locations, and map suppressed, not-applicable, or deferred rows to public-facing coverage outcomes. Do not silently drop a seeded row because a same-family neighbor survived.

## Report Structure

Use this report structure:

`# Security Review: <repo_or_target_name>`

`## Scope`

Populate `scan.scope` with in-scope context, artifacts reviewed, runtime or test status, validation mode, and explicit limitations. Include/exclude paths and coverage fields supply the remaining projected scope content. If the threat model was generated during Phase 1 rather than provided by the user, say that in canonical scope context. Do not call generated threat-model material an external input.

After the scope bullets, include a compact `### Scan Summary` table when the scan has findings or repository-wide coverage. Use columns `Field` and `Value`. Include the count of reportable findings, severity mix, confidence mix, coverage, and validation mode when those values are known. Keep artifact paths below this table.

`## Threat Model`

Populate `scan.threatModel` from the completed threat-model analysis. The detailed `<context_dir>/threat_model.md` may remain supporting evidence, but finalization reads only the canonical threat-model object when projecting this section.

`## Findings`

Start this section with the findings summary table.

For Deep Security Scan outputs, group the summary table by `extensions.candidateId` and use columns `Findings`, `Reports`, `Severity`, `Confidence`, and `Detailed write-up`. `deep_repository` scans always use this presentation. Scoped-path deep outputs use it when the reportable child findings carry the deep-scan identifiers described below; ordinary scoped standard scans keep the standard table. Emit one table row per reportable canonical DSS finding. `Findings` contains the vulnerability title without duplicated trailing report or provenance annotations. `Reports` lists every child finding's unique `extensions.reportId`, with each id linking to that child's detailed summary section. For compatibility with older deep-scan artifacts, fall back to `extensions.ledgerRowId`; when a ledger row produced multiple reports, use each child's unique trailing title annotation or instance identity rather than displaying duplicate labels. `Detailed write-up` lists the corresponding `writeup.reportPath` link for every child report. Preserve every child report as its own detailed section below the grouped table. When child reports have different severity or confidence levels, list every distinct level in the grouped row. In the scan summary, distinguish the number of reportable DSS findings from the number of child report instances. For every other scan mode, preserve the standard columns `Finding`, `Severity`, `Confidence`, and `Detailed write-up`, with the finding title linking to the detailed summary section.

After the summary table, include a compact `### Confidence Scale` table with columns `Label` and `Meaning`:

- `high`: direct source, configuration, or runtime evidence supports the finding, with no material unresolved reachability or exploitability blocker.
- `medium`: source evidence supports a plausible issue, but runtime behavior, deployment configuration, role reachability, type constraints, or exploit reliability still need proof.
- `low`: weak or incomplete evidence; include only when the user explicitly wants follow-up candidates in the final report.

When a finding records `writeup.reportPath`, link the detailed report from the findings summary and do not duplicate the complete finding inline. The linked write-up is a derived, unsealed readable output; the canonical finding remains the source of truth for adapters and regeneration. Findings without a write-up continue to use the inline format below for compatibility.

Render each inline finding as:

`### [<number>] <title>`

For each finding include a compact two-column metadata table immediately below the heading. Use columns `Field` and `Value`. Include these rows:

- `Severity`: `critical|high|medium|low`
- `Confidence`: `high|medium|low` or a short calibrated confidence label
- `Confidence rationale`: one sentence explaining why the confidence label is calibrated that way, grounded in the validation method, direct evidence, and missing proof if any
- `Category`: concrete vulnerability class
- `CWE`: id and name list, or `none`
- `Affected lines`: path:line-range list

Use a concrete category such as `Authorization bypass / IDOR`, `Path traversal`, `SQL injection`, `XXE`, `Open redirect`, or `Hardcoded credentials`. Do not use generic placeholders such as `security scan finding`.

For standard scan modes, the summary table should link each finding title to its detailed finding section with an intra-document markdown anchor. For the Deep Security Scan grouped presentation, the report id in the `Reports` column owns that link instead. Keep the displayed vulnerability title and report id aligned with the corresponding detailed heading. Use the explicit finding anchor emitted by the deterministic projection.
The summary table and the detailed finding sections must use the same descending severity order: all `critical` findings first, then `high`, then `medium`, then `low`. Renumber findings after sorting so the table order, detailed headings, and anchors match.

Affected lines must include the root broken control or dangerous sink line when that line is identifiable, not only the public wrapper, route, or caller that makes it reachable. For wrapper-to-shared-helper findings, list both the reachable wrapper/entrypoint and the underlying parser, deserializer, path/archive helper, expression evaluator, or auth/authz control line. If a seeded file, class, package, or hunk shares the surviving proof tuple, keep that seed anchor in affected lines instead of replacing it with a broader sibling-only location. If the bug is caused by unsafe transformation or selection before the sink, include the split, parse, canonicalization, normalization, comparison, regex, object-selection, or object-binding line where the control fails. For parser, XML, deserialization, and object-construction findings, include the concrete codec, converter, deserializer, parser feature setup, resolver, class filter, or container handler line when that line performs recursive parsing, type resolution, object conversion, class filtering, or fail-open hardening. For central file-format object models, include low-level helper lines such as `to*Array`, `toList`, `getObject`, numeric conversion, iterator, size-based allocation, unchecked cast, or collection-to-array loops when those helpers are the broken malformed-input control. For recursive placeholder/template findings, include the helper/parser setup line that enables recursive expansion or expression evaluation, not only the later resolver or render call. For resource-serving findings, include the allowlist, path-matcher, URL decoding, canonicalization, or resource-selection line that decides whether the attacker-selected resource is allowed. For stateful authentication protocol findings, include the principal/credential/token/issuer installation, rebind/reauthentication, or validated-vs-consumed object-selection line that creates the auth bypass. For SSO/SAML/federation findings, include the response/assertion selection, signed-object lookup, cloned/returned assertion, subject, audience, recipient, destination, ACS URL, or issuer-binding line that determines which identity object is trusted. For polymorphic or request-selected handler, operation, converter, filter, validator, or strategy families, include the concrete subclass/implementation line that transforms, validates, canonicalizes, selects, or reinterprets attacker input before a shared sink/control, including specialized helper methods and branch predicates inside the concrete class when they perform or enable the unsafe transform. If a special-case branch such as append, wildcard, fallback, copy/move `from`, default-value, or type-resolution handling bypasses or narrows validation, include that branch-local root-control line even when a shared helper is also affected. If the finding text says a shared flaw affects "all", "every", or "any" concrete operation, codec, converter, handler, validator, filter, or resolver, the affected lines must include the concrete implementations identified during discovery or validation; do not rely on "and related classes" prose for independently reachable root-control lines. If equivalent resolver/filter controls are duplicated across core, server, client, remoting, plugin, or import packages, include the runtime/exported implementation that enforces the broken control. For repeated vulnerable templates, routes, query builders, parser operations, or auth/object-access endpoints, keep each independently vulnerable file and line as its own affected instance; do not hide sibling instances as extra context on one representative finding when they can be attacked independently. The Copilot review directive should point at the tightest root-cause line unless the wrapper or concrete implementation line is the actual broken control.

For archive symlink or hardlink traversal findings, affected lines must include
the link-entry type and target selection, member-name containment that fails to
bind the target, link materialization, later regular-member write/open/copy, and
final protected filesystem effect when those lines are distinct. The write-up
must preserve ordered entry names/types/targets, target interpretation base,
extraction root, each resolved path component, final opened object, and
overwritten or disclosed asset. Link-related APIs alone are not an exploit
witness; record link-entry rejection, root-handle-relative no-follow traversal,
pre-existing-link rejection, and legitimate nested extraction when present.

For decompression-bomb and data-amplification findings, affected lines must
include the attacker-controlled compressed input boundary, decoder call,
missing or bypassed entry-count, cumulative compressed-input/decoder-work,
expanded-output/retention, or nesting budget, retained output, and shared
resource effect when distinct. Record codec/container, compressed and
declared sizes, actual expanded bytes, ratio, entry count/nesting/concurrency,
streaming or allocation behavior, memory/disk/worker outcome, bounded witness,
and legitimate-input control. A decoder API or large ratio alone is not proof.

For authenticated-encryption nonce/IV-reuse findings, affected lines must
include nonce construction, the same-key encryption call, and ciphertext/tag
publication or protected plaintext use when distinct. Record algorithm/mode,
key identity and scope, both nonces, plaintext and ciphertext lengths, tags,
AAD, attacker observation path, restart/worker/tenant/rollback conditions, and
the bounded recovered-plaintext or accepted-forgery witness. A constant nonce
or valid tag alone is not complete proof; demonstrate key/nonce reuse and its
confidentiality or integrity effect, plus fresh-nonce or independently derived
per-message-key and legitimate-decrypt controls.

For OIDC ID-token client-binding findings, affected lines must include the
trusted signature/issuer acceptance boundary, the incomplete `aud`/`azp`/nonce
validation, and the final local-principal or session installation when those
lines are distinct. The write-up must preserve the sibling and target client
identities, target callback state and nonce, exact signed victim-token claims,
and resulting attacker-owned target session; a missing claim check alone is not
an exploit witness.

For WebAuthn/passkey credential-to-account misbinding findings, affected lines
must include the successful assertion-verification boundary, credential/account
selection or missing owner binding, and wrong-principal session installation
when those lines are distinct. Preserve the victim-targeted transaction, exact
fresh challenge/RP ID/origin, attacker-owned credential and registered owner,
valid signature result, and victim session. Use category
`webauthn-credential-account-misbinding` with CWE-287 and CWE-304. A WebAuthn API,
username parameter, or missing owner check without a cross-account session is
not an exploit witness.

For signed-webhook replay findings, affected lines must include the raw-body
signature and signed-timestamp acceptance boundary, the missing or ineffective
freshness/event-consumption control, and the financial or state-changing sink
when those lines are distinct. The write-up must preserve one exact legitimate
body/signature/timestamp/event-ID tuple, its first accepted effect, the repeated
effect from an unchanged second delivery, and tamper or wrong-key controls. A
valid HMAC is expected and does not by itself rebut capture-replay.

For ECDSA/DSA signature-malleability replay findings, affected lines must
include successful signature verification, the signature-byte-derived replay,
deduplication, cache, or idempotency key, and the protected mutation when those
lines are distinct. The write-up must preserve one exact signed event, its
original `(r, s)` signature, the valid transformed twin such as `(r, n-s)`, both
verification results, distinct security keys, and repeated effects. Use the
concrete category `signature-malleability-replay` with CWE-294 and CWE-347. Do
not describe acceptance of both valid representations as a forgery or finding
when a signed semantic event ID is atomically consumed once.

For forwarded client-identity or proxy-trust findings, affected lines must
include the direct-peer/forwarding-header trust decision, selected hop and
canonicalized client identity, security-budget key/update, and protected
recovery/login/MFA/fraud/abuse effect when those lines are distinct. The
write-up must hold the real client constant, preserve the deployed proxy append
or overwrite topology and raw chain, rotate only attacker-controlled prepended
hops, show the resulting distinct security keys and intended/effective attempt
counts, and prove the extra attempt reaches the protected effect. Use the
concrete category `proxy-client-identity-rate-limit-bypass` with CWE-345 and
CWE-307. Do not report forwarding headers or trust-proxy configuration alone
when exact trusted-hop right-to-left peeling, canonical bounded parsing,
untrusted-peer header ignoring, and account/principal budgets defeat the path.

For duplicate-parameter authorization-confusion findings, affected lines must
include the first security-relevant parse and authorization/signature/validation
decision, forwarding or reparsing boundary, downstream value selection, and
protected action when those lines are distinct. The write-up must preserve the
exact raw query/form/body, ordered decoded pairs, each component's selection
semantics, checked and used values, principal/resource, reversed-order and
single-value controls, and unauthorized effect. Use the concrete category
`duplicate-parameter-authorization-confusion` with CWE-436 and CWE-863. Do not
report parser presence or duplicate acceptance alone when bounded strict
decode-once handling rejects duplicate decoded names and propagates the same
authorized canonical object through the protected consumer.

For application authorization-cache findings, affected lines must include the
trusted authenticated principal or tenant extraction, exact cache-key
construction, hit return, authoritative scoped lookup, and cache population
when those lines are distinct. The write-up must preserve two principals'
different cold results for one logical resource ID, the first population, the
second principal's wrong-object or wrong-decision hit, and proof that the hit
skips the scoped authorization lookup. A shared cache or compact key alone is
not an exploit witness; record identity-partitioned keys, hit validation, and
permission-change invalidation when present.

For HTTP response-header injection or response-splitting findings, affected
lines must include the untrusted value extraction or decoding, missing
control-byte boundary, response-field construction or raw serialization, and
the downstream proxy/gateway/cache/browser decision that creates the protected
effect when those lines are distinct. The write-up must preserve exact raw
response bytes, the injected header or second response, deployment consumer,
and disclosed secret, session change, redirect, cache entry, internal route, or
protected object. A response-header API or possible CR/LF alone is not an
exploit witness; record pre-serialization control-byte rejection,
context-appropriate quoting or RFC 5987 encoding, and legitimate-value success
when present.

For external authorization fail-open findings, affected lines must include the
permissive initial/default decision, policy or entitlement call, exception/
timeout/malformed-response handling, final allow comparison, and protected sink
when those lines are distinct. The write-up must state the exact subject,
action, and resource authorized and consumed, and must distinguish policy
availability failure from the authorization bypass produced by the fallback.

For DNS-rebinding SSRF findings, affected lines must include the
attacker-controlled URL/hostname, validation-time resolution and address-set
decision, any later HTTP-client/proxy/pool resolution, and final connection
sink when those occur on distinct lines or files. The write-up must distinguish
the logical URL, Host header, and TLS server name from the connected address,
record redirect behavior, and state which private/internal service, credential,
data, or protected operation the rebound connection reaches.

Then render these subsections under each finding:

- `#### Summary`
  - Explain why the issue matters, what the vulnerable path is, and why the current controls are insufficient.
  - Wrap code identifiers, RPC names, functions, types, fields, parameters, configuration keys, and literal values in single backticks.
- `#### Root Cause`
  - State the violated security invariant and explain exactly how the implementation breaks it.
  - Walk the vulnerable call stack from the code that accepts or decodes user-controlled input through each meaningful call or transformation to the missing control, dangerous operation, and security-relevant consumer. Do not begin at the sink when an earlier input boundary is known.
  - Give every displayed `codeEvidence` item a role and an explanation that names the carried value and the next callee or state transition. Order `rootCause.evidenceRefs` from input to outcome, with any `expected_control` comparison after the vulnerable stack.
  - Show the smallest complete snippets needed for that walkthrough. Omit incidental helpers, but do not skip a call boundary whose behavior is necessary to understand how attacker input reaches the broken invariant.
  - Do not emit generic prose that only repeats an affected `path:line` already present in the metadata table.
- `#### Validation`
  - Include method, checklist items, evidence, and remaining uncertainty.
  - Pair each important validation claim with actual source in `validation.evidenceRefs`; a list of file names and line numbers is not sufficient evidence for the readable finding.
- `#### Dataflow`
  - Show the technical source-to-sink path inside the code, such as request parameter -> controller -> service/helper -> dangerous sink -> response or side effect.
- `#### Reachability`
  - Explain who can realistically trigger the dataflow, from what boundary, under what preconditions, and what attacker outcome follows. Fold any attack-path facts into this prose or compact bullets instead of emitting a separate `Attack Path Facts` section.
  - Use `attackPath.evidenceRefs` for the few code transitions that establish attacker input, the missing control, and the resulting sink or state change. Keep this shorter than Validation.
- `#### Severity`
  - State the final severity and then explain the rationale.
  - Treat likelihood and impact as inputs to the final severity, not as separate report labels.
  - The rationale should fold in reachability: attacker role, exposed entry point, exploit steps, required feature flags/config, runtime/deployment assumptions, and any counterevidence or blockers.
  - The rationale should explain the concrete security consequence using repository evidence: data exposed, integrity boundary broken, credential/control-plane effect, code execution path, or why impact is narrower.
  - Include one concise sentence explaining what specific additional evidence would raise or lower the severity.
  - Avoid circular phrasing such as `this is high because it is high severity`, `maps to high`, or `high-severity issue`.
- `#### Remediation`
  - Give concrete minimal fixes, tests, and preventive controls.

For repository-wide and scoped-path scans with a coverage ledger, include a concise `## Reviewed Surfaces` section after the findings. This section summarizes what was inspected, what came out of each reviewed surface, and seeded/root-control rows that were suppressed, not applicable, or deferred so an auditor can see why they did not become findings. Use a table with `Surface`, `Risk Area`, `Outcome`, and `Notes`.

Recommended outcomes:

- `Reported`: became a final finding.
- `No issue found`: reviewed and no credible issue survived.
- `Rejected`: plausible-looking candidate was ruled out with specific counterevidence.
- `Not applicable`: the risk class does not apply to that surface.
- `Needs follow-up`: plausible but not fully closed because of a concrete blocker or proof gap.

Write the same content, or a slightly more detailed version, to `<coverage_dir>/reviewed_surfaces.md`.

For broad scans where the completed coverage is useful for triage but too large for high-precision review, include a concise `## Open Questions And Follow Up` section near the end of the report. Use concrete, copyable prompt ideas that narrow the next review to individual commits from the current scan. Do not include this section for precise scans where the requested scope was already sufficient.

Follow-up prompts should be tailored to the actual scan results:

- use exact commit SHAs, PR numbers, short titles, file paths, or component names from the report
- focus each prompt on the specific boundary that made the commit worth follow-up, such as auth, plugin/MCP exposure, artifact downloads, signed URLs, or gateway routing
- avoid generic placeholders

Each finding should make it easy for an application security engineer or software engineer to answer:

- what changed or what path is vulnerable
- what attacker-controlled input or trust boundary matters
- what direct evidence supports the claim
- what counterevidence or uncertainty remains
- why the severity landed where it did
- what the smallest safe fix is

Include the final markdown report path in the response so the user can find the readable report easily.

After a completed scan:

- If the scan found reportable issues, ask whether the user wants to export the findings as JSON, SARIF, or CSV, generate patches, or track selected findings. Name the highest-priority finding.
- Offer tracking only when `/track-findings` can use an available destination, such as Linear, Jira, or GitHub Issues. Name the destination in the question.
- If the report names a specific follow-up, ask whether the user wants to investigate it.
- If the scan found nothing and has no specific follow-up, do not add a generic question.
- Wait for the user's answer before exporting findings, generating patches, tracking findings, or starting another scan.

## Copilot Review Directives

For Copilot app rendering, emit one `::code-comment{...}` directive per surviving finding in the final response. The markdown report and review directives should agree on title, file, line range, and core explanation.

Map the final report severity to Copilot directive priority only when emitting the directive:

- `critical` -> `P0`, `priority=0`
- `high` -> `P1`, `priority=1`
- `medium` -> `P2`, `priority=2`
- `low` -> `P3`, `priority=3`

For each reportable finding, emit a Copilot review directive in this form:

`::code-comment{title="[P1] Example title" body="One-paragraph review explanation." file="/absolute/path/to/file" start=10 end=12 priority=1 confidence=0.55}`

Directive requirements:

- `title`, `body`, and `file` are required
- `title` should include the mapped Copilot directive priority, formatted like `[P1] Example title`
- `file` should be an absolute path
- `start` and `end` should be tight 1-based line numbers
- `priority` should match the mapped Copilot directive priority
- `confidence` should be numeric when available
- emit one directive per finding and none when there are no findings
- inline Markdown code spans are allowed and encouraged for short identifiers, flags, function names, and config keys, such as `git -c`, `--config`, and `diff.external`
- do not put double quote characters inside quoted attribute values, including escaped quotes like `\"`; rewrite quoted command examples without quotes or leave them only in the markdown report
