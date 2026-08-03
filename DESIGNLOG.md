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
