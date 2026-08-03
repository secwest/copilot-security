# Changelog

All notable scanner, application, benchmark, and operational changes are recorded here. The project is under active development; entries remain in **Unreleased** until a version is tagged.

## Unreleased

### Scanner effectiveness

- Added execution-aware Java OkHttp SSRF modeling for imported and fully qualified clients, request-builder aliases, inline requests, directly constructed clients, and prepared `Call` values that are later executed or enqueued.
- Rejected inert request construction, unexecuted `newCall` values, unrelated execution statements, reassigned calls and inputs, unrelated builders, and local type shadows to keep OkHttp coverage precise.
- Added vulnerable and safe OkHttp benchmark fixtures, executable Maven witnesses using OkHttp 5.3.0, a strict benchmark manifest, regression tests, scanner guidance, and Java CI coverage.

### Resilience

- Kept the OkHttp typed fallback bounded to a confirmed request-construction-to-network-dispatch path so incomplete or ambiguous code does not become a synthetic finding.
- Extracted the scanner GUI's commands, durable settings, process control, progress, scan history, artifact loading, benchmark comparison, and diagnostics into a platform-neutral .NET 8 desktop layer while preserving the existing Windows application contract.
- Added explicit Windows and Linux platform profiles. Linux uses executable names without Windows suffixes, XDG-compatible settings, case-sensitive path identity, and separate `gui-linux-runs` and `gui-linux-benchmarks` directories beneath `copilot-security-home`.
- Added desktop regression tests for platform defaults, runtime-home isolation, durable settings, and the absence of implicit executable fallbacks.
