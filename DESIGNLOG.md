# Design log

This log records consequential implementation decisions, their evidence, and the tradeoffs that future scanner work must preserve.

## 2026-08-03 — Prove direct review and repair serialization without inferred conclusions

**Decision.** Permit up to three closure-repair turns after the independent quality correction, with a deterministic host re-audit after every turn. Feed each repair only the current gap inventories and stop as soon as both inventories close. Require `coverage.json` to be a single parsed object with exact inventory paths and canonical scalar dispositions; broad rewrites use a serializer, parse-and-set verification, and atomic replacement rather than repeated textual edits. In addition, require host-observed proof of a successful built-in `view` for every exact immutable inventory path before its coverage surface can close.

**Why.** A packaged production-code self-scan directly opened every one of its 88 immutable inventory paths and completed all six discovery passes, but its final bounded repair used line-oriented shell edits against JSON. The resulting document had valid-looking content followed by trailing bytes, a misspelled path, and nested object-valued dispositions. One repair turn was too brittle for an otherwise recoverable serialization defect, while accepting the backup's `status: "present"` values would have manufactured 88 security conclusions that the contract did not contain.

**Evidence.** The first session completed 61 assistant turns and 150 successful tools, with one correctly denied read outside the scanner profile. It resolved `auto` to `gpt-5-mini`, reported zero premium requests, recorded 27.110705 AIU-equivalent usage, and had no session, authentication, quota, credit-limit, or safety-classifier error. Copilot viewed all 88 exact production paths; the deterministic auditor converted malformed coverage into 88 gaps and prevented a false successful result. A second packaged run then demonstrated the inverse weakness: the final contract claimed complete coverage with 88 canonical `rejected` surfaces, but the SDK receipt proved 0 direct production-file views. That session completed 41 assistant turns and 42 successful tools with one correctly denied out-of-scope read, zero premium requests, no session error, and 15.390385 AIU-equivalent usage. Its successful exit is negative acceptance evidence: canonical model-authored rows alone did not prove review.

**Regression evidence.** Tests prove first- and later-attempt closure, use of the newest host inventory, exhaustion of all three repairs, invalid-bound rejection, transport-cause preservation, serialization guidance, and hostile-inventory containment. They also prove that only successful built-in repository views enter the host-owned review set: failed views, shell calls, MCP tools named `view`, and out-of-root paths do not. A closed canonical surface without matching host evidence becomes `missing_direct_file_review`; the same surface closes after its exact view succeeds. The complete suite passes 670 tests and 5,949 assertions.

**Liveness evidence and refinement.** Enforcing direct review on the same 88-file production scope raised observed coverage from 0/88 to 88/88, but the model replayed almost the entire inventory before successive artifact operations. The one-hour external acceptance ceiling stopped the run after 68 assistant turns, 2,681 built-in views, 2,694 successful tools, and 27.919905 AIU-equivalent; it recorded zero premium requests and no session error. Thirteen grep failures came from Copilot CLI 1.0.78-3 attempting an obsolete 1.0.77 bundled-ripgrep path. The remaining coverage draft used `path` rather than the required `label`, so the host retained 88 gaps. This is safe but not production-efficient. Correction inventories now expose `directFileReviewObserved`: a true value directs a structural coverage repair without a reread, while false still requires a successful built-in view. Scanner skills make the initial inventory pass read-once across tool calls and compaction and explicitly forbid substituting `path` for `label`.

**Scoped acceptance and mode binding.** A packaged five-file production scan reduced replay to 28 views total and proved all five exact paths, but final sealing rejected repository mode where the selected target required `scoped_path`. Per-file closure alone cannot prove target semantics, so the trusted host now supplies the exact expected mode in the runtime map and initial prompt. The closure inventory independently compares it and emits a synthetic `coverage.mode` row with exact expected and actual values; this structural row never requests repository rereads. Repeating the identical packaged scan completed in 8m53s after repair 1/3: 5/5 exact direct views, 19 total views, 35 assistant turns, 36 successful tools, one correctly denied out-of-scope read, zero premium requests, no session error, and 10.880370 AIU-equivalent. Coverage was complete `scoped_path` with zero deferred work or closure gaps. All 10 sealed artifact hashes reproduced and SARIF was nonempty. The complete suite passes 670 tests and 5,949 assertions.

**Safety boundary.** Extra turns improve recovery, not trust. The host never maps `present`, descriptive prose, missing dispositions, object values, or misspelled paths to `no_issue_found`. It never creates model evidence or coverage decisions. Direct-review evidence comes only from successful Copilot SDK tool-completion events for the built-in file viewer, normalized beneath the staged repository, and resets on each fresh session. Every repair remains finite, the exact same deterministic gates run after each attempt, and unreadable, unreviewed, or incomplete state still fails the scan.

**Consequence.** A structurally damaged draft can receive more than one chance to become auditable without replaying the expensive discovery phase or weakening acceptance. Future increases to the repair budget must remain capped and evidence-driven; they must not become an unbounded loop or a substitute for deterministic artifact validation.

## 2026-08-03 — Model OkHttp SSRF at dispatch, not request construction

**Decision.** Treat an OkHttp URL flow as executable SSRF evidence only when a typed `Request` reaches a typed `OkHttpClient.newCall(...)` and the resulting call is executed or enqueued. Support direct chaining and a prepared typed `Call`, while rejecting intervening reassignment and statement-boundary leakage.

**Why.** A request object or `newCall` value can be constructed and never sent. Matching those intermediate states inflated recall at the expense of findings that a developer could not reproduce. Dispatch is the security boundary that turns attacker-controlled URL data into an outbound request.

**Evidence.** The regression corpus includes imported and fully qualified APIs, aliases, inline construction, direct client construction, later execution, inert construction, unexecuted calls, unrelated `execute` methods, separated builders, local type shadows, and input/call reassignment. Vulnerable and safe Maven witnesses exercise OkHttp 5.3.0 against a loopback server.

**Consequence.** This bounded model intentionally misses highly dynamic dispatch that cannot be tied to the request with local typed evidence; the AI review pass remains responsible for those cases. Future extensions should add explicit data-flow evidence rather than relax the dispatch requirement.

## 2026-08-03 — Share behavior, isolate platform presentation and state

**Decision.** Move scanner orchestration and GUI state into a platform-neutral .NET 8 project. Keep WPF and the Linux presentation shell separate, and inject a small immutable platform profile for executable discovery, settings, path comparison, scan history, and benchmark output names.

**Why.** Duplicating the orchestration in two GUIs would cause security-sensitive drift in command construction, cancellation, sealed-artifact acceptance, and benchmark handling. Sharing presentation code would instead couple Linux to Windows-only assemblies. A narrow platform profile preserves one behavioral implementation without erasing native UI differences.

**Isolation.** Both applications use the scanner's `COPILOT_SECURITY_HOME` contract and `copilot-security-home` runtime directory. Linux GUI preferences and generated history use Linux-specific names, while Windows retains its established paths. Neither profile reads or writes another scanner's runtime names.

**Failure behavior.** Executable discovery accepts only actual runnable files; Linux additionally requires an execute bit. A relative `XDG_CONFIG_HOME` is invalid under the XDG convention and is ignored in favor of the user's `.config` directory, avoiding a startup crash or a working-directory-relative settings file.

## 2026-08-03 — Use a native Linux presentation with headless and X11 gates

**Decision.** Implement the Linux interface in Avalonia 12 on .NET 8, while keeping every scanner-affecting operation in the shared desktop/core projects. Publish a self-contained `linux-x64` directory and package it with conventional freedesktop metadata rather than requiring a system .NET installation.

**Why.** Avalonia provides one Linux-native control tree that can run under X11, WSLg, and a headless test platform. A self-contained directory is larger than a framework-dependent executable but produces a predictable operator experience and permits the runtime patch to be pinned, audited, and deliberately upgraded.

**Verification boundary.** The project declares `linux-x64` as its runtime identity so direct, transitive test, and self-contained publish restores all validate against the same committed lock graph. The non-graphical smoke mode validates platform/state contracts without loading graphics. The headless test loads the complete XAML tree and verifies tabs, data grids, commands, bindings, report surface, and state paths. CI then starts the published binary under `xvfb-run`, covering native Linux loading separately from headless rendering.

**Packaging boundary.** The installer refuses an incomplete payload before writing system paths. It copies only the published application and fixed launcher/desktop/icon files. Scanner state and preferences remain per-user and are never installed below `/opt` or copied from Windows.

**Standalone payload.** The release archive also carries the inspected npm scanner package plus production dependencies resolved from the committed pnpm lockfile on Linux. The GUI looks for this adjacent `scanner/bin/copilot-security.mjs` first and falls back to the source-checkout layout only for development. The scanner code is immutable application content; its mutable state still lives exclusively below the per-user scanner home.

## 2026-08-03 — Default to Copilot model negotiation

**Decision.** New CLI and GUI configurations use `model="auto"`. Explicit models remain selectable and benchmark manifests continue to record the exact effective scan policy. When `auto` is selected, the SDK session omits the reasoning-effort override as required by Copilot CLI.

**Evidence.** Native Linux Copilot CLI 1.0.77, authenticated as the same `secwest` GitHub account, rejected a fixed `gpt-5.6-terra` request as unavailable and immediately completed the same request with `auto`. No credit, quota, rate-limit, or authentication error occurred.

**Consequence.** Default scans follow the model set available to the authenticated Copilot account and survive provider catalog changes. Reproducible benchmark campaigns should continue to select and record an explicit available model when cross-run model identity is part of the comparison policy.

## 2026-08-03 — Make the model protocol independent of shell expansion

**Decision.** Attach an allow-listed JSON object containing exact non-secret host runtime values to every initial, correction, and closure turn. The object is framed as immutable operational data, JSON-escapes control characters, escapes prompt-tag metacharacters, excludes unknown scanner-prefixed values and secrets, and directs the model to use decoded strings directly with built-in file tools. Shell access remains optional and must not be used merely to discover paths.

**Why.** A native Ubuntu live scan received only literal `$COPILOT_SECURITY_*` references. Copilot attempted to resolve them with `bash`, but its sandboxed shell could not start before `bubblewrap` was installed. It then tried to create artifacts in the read-only repository snapshot and the scanner correctly failed closed with no canonical drafts and four coverage gaps. Environment variables are still useful to trusted processes, but asking the model to expand them creates an unnecessary platform dependency.

**Evidence.** After exact values were added, the same deep OkHttp scan used built-in file operations to create and reopen `scan-manifest.json`, `findings.json`, `coverage.json`, and 18 discovery artifacts and receipts beneath the authorized Linux scan directory. Host reconciliation reported zero coverage gaps. The session recorded 48 successful sandboxed tool completions and no session error. Tests cover Windows and POSIX paths, hostile closing-tag text, newlines, quotes, unrelated secrets, and unknown scanner-prefixed values.

**Consequence.** Linux installations should still provide `bubblewrap` because Copilot may legitimately use its sandboxed shell for bounded analysis, but artifact correctness no longer depends on it. The prompt map must remain an explicit allow-list; never replace it with serialization of the whole process environment.

## 2026-08-03 — Validate evidence references semantically

**Decision.** Treat a data-flow endpoint or nested validation/attack-path reference as valid when it exactly names an ID in that finding's `codeEvidence` array, regardless of the ID's display length. Recursively reject every unknown value under `evidenceRefs`, while allowing prose in the separate validation `evidence` field.

**Why.** The live Linux scan produced a grounded CWE-918 finding with source `e1`, sink `e2`, exact repository snippets, validation steps, reachability, broken controls, and counterevidence. The deterministic gate nevertheless rejected `e1` and `e2` because its generic prose heuristic required strings of at least three characters and inspected only top-level references. Length is appropriate for narrative substance, not referential integrity.

**Evidence.** The preserved finding originally returned `missing_validation_evidence`, `incomplete_attack_path_dataflow`, and `missing_attack_path_evidence_refs`. The revised gate re-audits the same bytes with no gap. A dedicated regression covers short source/sink IDs in validation evidence, nested steps, and data-flow endpoints; the existing unknown-reference case continues to fail.

**Consequence.** Future quality gates must distinguish prose-quality checks from identifier-resolution checks. Evidence IDs are meaningful only through exact membership in the local finding graph; artifact paths, dangling IDs, empty arrays, and merely long strings must never receive equivalent credit.

## 2026-08-03 — Recover exact coverage aliases without guessing

**Decision.** When a model-authored coverage surface omits or corrupts `disposition`, accept `outcome` or `status` only if its value is an exact member of the canonical coverage-disposition set. Prefer `outcome` over `status`, preserve an already-valid `disposition`, and continue to force `needs_follow_up` plus partial coverage for every absent, descriptive, or otherwise ambiguous value.

**Why.** The first acceptance scan from the inspected Linux release tarball found and fully traced the intended multi-hop OkHttp SSRF, but the model wrote `status: "no_issue_found"` for `pom.xml` without the schema-required duplicate `disposition`. Treating that exact canonical value as unknowable created a false incompleteness result after successful review. Broad natural-language mapping would have hidden genuinely unresolved surfaces, so recovery remains deliberately narrow.

**Evidence.** The 4m11s native WSL run sealed hashed findings, coverage, report, discovery, and validation artifacts and exported SARIF. Its only incomplete surface had the exact canonical status and a real discovery receipt; no deferred row, missing inventory path, quota failure, refusal, or session error existed. Integration regressions reproduce that non-finding metadata shape: exact `no_issue_found` closes complete coverage, while `looks clean` remains `needs_follow_up` and partial. The corrected tarball then completed the same deep fixture in a fresh WSL directory with complete coverage, no deferred work, one high-confidence CWE-918 finding, and zero deterministic quality gaps. Recomputed hashes matched all five manifest records, and the nonempty SARIF/report outputs were present. The complete suite passes 666 tests and 5,918 assertions.

**Consequence.** This is a syntax recovery, not a security conclusion. The finalizer may normalize an exact canonical duplicate field, but it must never translate prose such as “looks clean” into a closed review or use an alias to override a valid canonical `disposition`.

**Follow-up evidence.** The successful session still recorded eight failed creates against absent artifact parents and three failed views of not-yet-created JSON files before recovering to 38 successful sandboxed tool calls. The fixed parent-directory problem is addressed by the host preparation decision below; required root drafts remain model-owned and intentionally absent until authored.

## 2026-08-03 — Prepare directories, never evidence

**Decision.** Before model execution, the trusted host creates a fixed private directory skeleton for context, six stable deep-discovery pass IDs, coverage, validation, reconciliation, attack-path, and findings artifacts. The host does not create `scan-manifest.json`, `findings.json`, `coverage.json`, `report.md`, receipts, ledgers, or finding evidence.

**Why.** Copilot's built-in file creation tool writes files but does not create missing parents. The accepted WSL session spent eight failed operations trying to write legitimate threat-model, pass-receipt, validation, and attack-path files beneath documented parents. Depending on a shell `mkdir` fallback made artifact production less portable and wasted model turns.

**Safety boundary.** Output validation supplies a fresh private canonical directory, archives a prior scan before reuse, and rejects nonempty or symlink output roots. Host preparation uses only a compile-time list beneath that directory. Empty prepared directories are not included in the sealed artifact manifest and cannot satisfy required-file, receipt, evidence, coverage, or quality gates.

**Evidence.** The runtime regression verifies all fixed directories on the real inventory-preparation path and separately proves that all four required root drafts remain absent. The focused runtime suite passes 13 tests and 65 assertions; the complete scanner suite passes 666 tests and 5,918 assertions.
