# Design log

This log records consequential implementation decisions, their evidence, and the tradeoffs that future scanner work must preserve.

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
