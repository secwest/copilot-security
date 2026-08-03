# Changelog

All notable scanner, application, benchmark, and operational changes are recorded here. The project is under active development; entries remain in **Unreleased** until a version is tagged.

## Unreleased

### Scanner effectiveness

- Added execution-aware Java OkHttp SSRF modeling for imported and fully qualified clients, request-builder aliases, inline requests, directly constructed clients, and prepared `Call` values that are later executed or enqueued.
- Rejected inert request construction, unexecuted `newCall` values, unrelated execution statements, reassigned calls and inputs, unrelated builders, and local type shadows to keep OkHttp coverage precise.
- Added vulnerable and safe OkHttp benchmark fixtures, executable Maven witnesses using OkHttp 5.3.0, a strict benchmark manifest, regression tests, scanner guidance, and Java CI coverage.

### Resilience

- Kept the OkHttp typed fallback bounded to a confirmed request-construction-to-network-dispatch path so incomplete or ambiguous code does not become a synthetic finding.
- Made Linux and Windows scan turns independent of shell environment expansion by attaching an allow-listed, JSON-escaped map of exact non-secret host paths to the initial, quality-correction, and closure-repair prompts. Built-in file tools now own repository reads and draft-artifact writes on every platform.
- Hardened runtime-value prompt framing against control characters, tag-like strings, unknown scanner-prefixed values, and unrelated secrets, and added regressions proving exact POSIX and Windows path delivery without path-driven prompt structure.
- Corrected finding-quality closure to recognize canonical short `codeEvidence` IDs in validation evidence, data-flow endpoints, and nested attack-path steps while recursively rejecting unknown `evidenceRefs`. This removes a false failure without relaxing repository grounding, CWE, reachability, counterevidence, or broken-control gates.
- Extracted the scanner GUI's commands, durable settings, process control, progress, scan history, artifact loading, benchmark comparison, and diagnostics into a platform-neutral .NET 8 desktop layer while preserving the existing Windows application contract.
- Added explicit Windows and Linux platform profiles. Linux uses executable names without Windows suffixes, XDG-compatible settings, case-sensitive path identity, and separate `gui-linux-runs` and `gui-linux-benchmarks` directories beneath `copilot-security-home`.
- Added desktop regression tests for platform defaults, runtime-home isolation, durable settings, and the absence of implicit executable fallbacks.

### Linux desktop application

- Added a native Avalonia .NET 8 Linux GUI with the Windows application's scan modes, scopes, model/auth/cost controls, candidate inputs, progress, cancellation, findings, attack paths, report, durable history, benchmark execution/comparison, and diagnostics.
- Added validated findings/report export, native Linux file pickers, executable-bit-aware discovery, fail-closed UI-dispatch shutdown, non-graphical startup validation, and a headless full-window regression test.
- Added locked NuGet dependency graphs with a project-level `linux-x64` runtime identity, self-contained publication, X11 startup validation, a freedesktop launcher/desktop entry/icon, a guarded installer, and a retained CI package.
- Bundled the inspected, lockfile-resolved production scanner and Linux dependencies beside the packaged GUI, with installed-file discovery preferring that immutable payload before development-checkout discovery.
- Changed fresh scanner and GUI configurations to Copilot-native `auto` model selection after native Linux CLI verification proved the account was authorized but did not expose the previous fixed model names. Explicit model selections remain available, and reasoning effort is omitted automatically only for `auto`.
- Added `bubblewrap` to the documented/CI Linux prerequisites for Copilot's native sandboxed shell fallback, while keeping scanning functional through built-in file tools when shell access is unavailable. Disabled Avalonia and .NET build telemetry in CI and documented the reproducible local-build settings.
- Documented native library prerequisites and WSLg build, smoke-test, UI-test, packaging, installation, state-isolation, and recovery procedures.

### Operational verification

- Installed and verified native Linux Node.js 22.23.1, Copilot CLI 1.0.77, GitHub CLI authentication, and `bubblewrap` 0.9.0 in Ubuntu 24.04 WSL 2 without using Windows-mounted runtime shims.
- Verified that a native Copilot request succeeds with `auto`, while an unavailable explicit model fails as a catalog mismatch rather than an allowance error. A live deep scanner run resolved to `gpt-5-mini`, reported zero premium requests, completed 38 model turns and 48 successful sandboxed tool operations, and returned no session, authentication, quota, credit-limit, or rate-limit error.
- Demonstrated the Linux orchestration improvement on the intentionally vulnerable multi-hop OkHttp fixture: the pre-fix run could not create canonical drafts and retained four coverage gaps; the exact-path run created all drafts, closed coverage to zero gaps, and produced the expected high-confidence CWE-918 finding. Re-auditing that preserved finding with the corrected semantic evidence gate returns zero quality gaps.
- Revalidated the native WSL package with a non-graphical smoke test and a real WSLg window open/close test, plus 7/7 core tests, 3/3 shared-desktop tests, 2/2 headless Linux UI tests, and clean Windows and Linux GUI builds.
