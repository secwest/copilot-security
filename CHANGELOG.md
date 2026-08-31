# Changelog

All notable scanner, application, benchmark, and operational changes are recorded here. The project is under active development; entries remain in **Unreleased** until a version is tagged.

## Unreleased

### Scanner effectiveness

- Closed a measured Flask open-redirect false negative. The unchanged model
  ignored an attacker-selected GET query field read through the official
  `request.values` collection before `flask.redirect`; all 43 preceding Flask
  tests passed and only the new case failed, with 320 assertions.
- Added a distinct `flask-request-values-string` source and
  `flask-request-values-read` provenance for exact `.get` and literal-subscript
  access through the stable official request binding. The source preserves
  Flask's combined query/form semantics without applying the form-only route
  gate, because query arguments populate `values` on every reachable route.
- Added four accepted access/route forms, eight dynamic, ambiguous, unsupported,
  or rebound controls, and a Flask 3.1.3/Werkzeug 3.1.8 executable pair. The
  exploit emits the hostile GET query value as Location; the topology-matched
  control permits only immutable tuple members and otherwise selects
  `/account`. Both witnesses disable redirect following and perform no external
  I/O. The canonical corpus advances to 204 pairs, 408 cases, and 1,224 repeated
  scan positions.
- The dedicated Flask lane passes 47 tests with 354 assertions; the adjacent
  Flask, canonical, Rust bookkeeping, and Python-datamodel lane passes 81 tests
  with 3,281 assertions. Both exact-version witnesses reproduce the hostile
  query-to-Location and allowlisted-control differential.
- The full managed suite exercises 2,197 tests across 218 files: 2,164 pass, 31
  are intentional platform or integration skips, and only the two established
  managed-sandbox Git-metadata and Windows-ACL checks fail. Their unchanged
  native rerun passes 48/48 tests with 242 assertions; the aggregate executes
  17,205 assertions. Generated-model drift, TypeScript, the clean production
  build, formatting, and the live production dependency audit are green, with
  no known vulnerabilities.
- A whole-repository self-scan retains exactly one
  `flask-request-values-string` CWE-601 row at the exploit and no row at the
  topology-matched allowlisted control. Two SDK-root self-scans are
  byte-identical at 256 rows, 259,242 bytes, and SHA-256
  `5d9443f1e440e664c3d4b099c4eae2610a5d03e3019781319e42b7981b30a970`;
  86 rows cover production source across 17 category signals.
- Two independently built 299-entry npm archives are byte-identical at
  2,499,986 bytes with SHA-256
  `79db9f39969c24d0b5d020acfe89c582b5dfc4bacd722d5b6718f9e18f839f3b`.
  Two fresh 67-package consumers validate the public API, executable CLI, and
  all 79 bundled plugin files. Windows builds with zero warnings/errors, passes
  7/7 core and 3/3 shared tests, and survives a verified hidden startup; its
  346,796-byte executable has SHA-256
  `da74330cff4354451f318c15efee0040bf545847da34ac90b74f9e16b8f37096`.
  Ubuntu/WSL builds with zero warnings/errors; 7/7 core, 3/3 shared, and 2/2
  Linux UI tests pass, followed by non-graphical and X11/Xvfb startup. The
  72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
  All disposable package, consumer, and publish trees were removed after
  verification. Hosted and immutable-checkpoint evidence follows after the
  implementation commit.
- Closed a measured Flask open-redirect false negative. The unchanged model
  discarded a request query value wrapped by the live Python built-in
  `str(object)` before `flask.redirect`; 39 preceding Flask tests passed and
  only the new case failed, with 283 assertions.
- Added one bounded string-conversion taint edge for a single positional
  argument through the live bare built-in, unchanged `builtins.str`, an aliased
  official module, or a direct/aliased official import. The conversion is an
  explicit provenance step and composes with the existing same-value immutable
  allowlist proof. String conversion is never treated as URL validation.
- Hardened Python built-in liveness for lexical scope. Parameters, local
  definitions, imports, or assignments anywhere in the handler—including
  after the call—prevent built-in attribution; custom imports, rebound official
  aliases, and qualified lookalikes also remain unproved. Existing datamodel
  `compile`/`exec` behavior remains green.
- Added five live-binding forms, eight fixed custom-shadow/rebinding controls,
  and a Flask 3.1.3/Werkzeug 3.1.8 executable pair. The exploit emits the
  hostile absolute URL after `str`; the topology-matched control performs the
  same conversion but redirects only immutable tuple members and otherwise
  selects `/account`. Both no-follow witnesses perform no external I/O. The
  canonical corpus advances to 203 pairs, 406 cases, and 1,218 repeated scan
  positions.
- Focused Flask, canonical, and Rust bookkeeping acceptance passes 68 tests
  with 3,185 assertions; the adjacent datamodel built-in lane passes 9 tests
  with 46 assertions. Full local acceptance runs 2,193 tests across 218 files:
  2,160 pass, 31 are intentional platform/integration skips, and only the two
  established managed-sandbox permission checks fail. Their native rerun
  passes 48/48 tests and 242 assertions; the aggregate executes 17,155
  assertions. Generated-model drift, TypeScript, build, formatting, both
  exact-version witnesses, and the live production dependency audit are clean.
- Two independently built 299-entry npm packages are byte-identical at
  2,499,173 bytes with SHA-256
  `b933f2631e084417e6f2b5c22ce70e14bc041274cc2d2f716c045d7a3509e50a`;
  a fresh 67-package installation validates the public API, CLI, and all 79
  bundled plugin files. A bounded whole-repository self-scan emits 256 review
  rows from fixtures, tests, and documentation, zero production-source rows,
  and no spurious Flask open-redirect row.
- Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared
  tests, and passes a verified hidden startup. Its 346,796-byte executable has
  SHA-256
  `d95025f9cf3cd913df7957dd17adb4511d186ec76f61d802ced345f08312f38f`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, followed by non-graphical and real
  X11/Xvfb startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
  All disposable package and platform-publish trees were removed after
  inspection.
- Exact implementation checkpoint
  `7a843dd9dda93a06c6c5ba3b261ae47d0021724e` has a 3,806,304-byte tracked
  source archive with SHA-256
  `1411daa482a50e75c2e3fe7e6c9ab4fea5365b481163a39e49b73d097e0f4984`.
  All 11 hosted workflow families pass on the first attempt: Node
  `33381752420` (92/92 jobs), container `33381752517`, Windows GUI
  `33381752454`, Linux GUI `33381752476`, .NET `33381752513`, Go
  `33381752418`, Java `33381752503`, Kotlin `33381752407`, PHP `33381752455`,
  Ruby `33381752522`, and Rust `33381752439`. GitHub reports the repository
  public with default branch `main`.
- Closed a measured Flask open-redirect false positive. The previous model
  reported a request-derived redirect guarded by exact positive membership in
  an immutable server-owned tuple; the baseline was 35 prior tests passing,
  the new safe control failing, and 240 assertions.
- Added a bounded allowlist proof that suppresses only direct, dominating
  `target in ALLOWED_REDIRECTS` guards over the exact redirect value when one
  stable uppercase binding is assigned exactly once to a top-level tuple of at
  least two literal strings. Negative membership, mutable/dynamic/rebound or
  function-local data, compound or non-dominating conditions, different
  values, nested sinks, and unsupported tuple shapes remain reportable.
- Added 14 adversarial allowlist variants and a Flask 3.1.3 / Werkzeug 3.1.8
  executable pair. The inverted `not in` exploit emits the selected absolute
  Location while the positive-membership control selects `/account`; both
  TestClient witnesses disable redirect following and perform no external I/O.
  The strict
  `python-flask-static-allowlist-open-redirect-manifest.json` requires polarity,
  immutable policy, source, sink, fallback, and CWE-601 evidence. The canonical
  corpus advances to 202 pairs, 404 cases, and 1,212 repeated scan positions.
- Focused Flask, canonical, and Rust bookkeeping acceptance passes 64 tests
  with 3,137 assertions. Full local acceptance runs 2,189 tests across 218
  files: 2,156 pass, 31 intentional platform/integration skips, and only the
  established two managed-sandbox permission failures. Both affected files
  pass natively at 48/48 tests and 242 assertions. The aggregate executes
  17,107 assertions. Generated models, TypeScript, build, formatting, both
  witnesses, and the live production audit are clean.
- Two independently built 299-entry npm packages are byte-identical at
  2,462,770 bytes with SHA-256
  `6f317e42744cbf63234e8a241559fec951885ca8684a0c8e9de2ff7330cf6d0a`;
  a fresh 67-package install validates the public API, CLI, and all 79 bundled
  plugin files.
- Windows builds with zero warnings/errors and passes 7/7 core and 3/3 shared
  tests. Two hidden startup checks reach the idle UI loop and terminate under
  harness control; the 346,796-byte executable has SHA-256
  `31a6eabdb82d6aa37f08038a45597a7860724800f4c2a832000432819bffea4d`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, followed by non-graphical and real
  X11/Xvfb startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- Exact implementation checkpoint
  `56e1753a98ab9491c7f786fe5476bb8596885b93` has a 3,799,444-byte tracked
  source archive with SHA-256
  `5cce40e4562a29242c4a1846776c53d3bdfc57c9fde5eefcd2b67c44faebd0ca`.
  All 11 hosted workflow families pass on the first attempt: Node
  `33372117244` (92/92 jobs), container `33372117185`, Windows GUI
  `33372117205`, Linux GUI `33372117207`, .NET `33372117174`, Go
  `33372117258`, Java `33372117189`, Kotlin `33372117214`, PHP `33372117176`,
  Ruby `33372117216`, and Rust `33372117177`.
- Closed two measured cross-file Flask nested-Blueprint false negatives. A
  child imported into a parent Blueprint and mounted either on a same-file
  application or through a second relative import into `create_app` emitted no
  rows while all 30 previous Flask tests passed; the measured lane was 30 pass,
  2 fail, and 205 assertions.
- Added a bounded one-edge cross-file nesting proof. It requires an exact
  relative child import, stable official top-level parent Blueprint, exact
  child-to-parent mount, and exactly one final parent mount either on a
  same-file official application or through one further exact relative import
  into an undecorated named factory that directly returns its application.
  Arbitrary recursive package traversal is not performed.
- Added 16 fail-closed controls for absolute/wildcard imports, child or parent
  rebinding, non-Blueprint parents, replaced members, conditional, dynamic,
  unsupported, duplicate, absent, or ambiguous mounts, a second nesting edge,
  missing factory returns, and unstable final imports.
- Added a three-module Flask 3.1.3 / Werkzeug 3.1.8 exploit/control pair and
  strict
  `python-flask-cross-file-nested-blueprint-factory-open-redirect-manifest.json`.
  No-follow witnesses prove both registration-prefix overrides, the effective
  `/root/child/continue` route, and attacker-origin selections one and zero
  without external I/O. The canonical corpus advances to 201 pairs, 402 cases,
  and 1,206 repeated scan positions.
- Focused Flask, canonical, and Rust bookkeeping acceptance passes 60 tests
  with 3,081 assertions. Full local acceptance runs 2,185 tests across 218
  files: 2,152 pass, 31 intentional platform/integration skips, and only the
  same two managed-sandbox permission failures. Both affected files pass
  natively at 48/48 tests and 242 assertions. The aggregate executes 17,051
  assertions. Generated-model drift, TypeScript, build, formatting, both
  witnesses, and the live production audit are clean.
- Two independently built 299-entry npm packages are byte-identical at
  2,495,704 bytes with SHA-256
  `d4b47d0ac0ac38b2cb9d11023672181fd12cbb13c88f40d383b8ebf6de9dbffe`;
  a fresh 67-package install validates the public API, CLI, and all 79 bundled
  plugin files.
- Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared
  tests, and passes a verified hidden startup. Its 346,796-byte executable has
  SHA-256
  `0b04a3a9356f8eafab8954940519911567c425f3f6ce8ff143533f4630242d5a`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, followed by non-graphical and real
  X11/Xvfb startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- Exact implementation checkpoint
  `09678fc358b8c4775ba085c6a3ac7e6453204f26` has a 3,793,776-byte tracked
  source archive with SHA-256
  `070fe4d67b2afd909c527942b4c9c8fc7be2b0ee3a4b81e32200e479f0556bfc`.
  All 11 hosted workflow families pass on the first attempt: Node
  `33364332193` (92/92 jobs), container `33364332119`, Windows GUI
  `33364332084`, Linux GUI `33364332152`, .NET `33364332145`, Go
  `33364332127`, Java `33364332220`, Kotlin `33364332160`, PHP `33364332129`,
  Ruby `33364332146`, and Rust `33364332080`. The repository remains public on
  default branch `main`.
- Closed two measured same-file Flask application-factory false negatives. An
  official Blueprint mounted directly inside `create_app` and an official child
  Blueprint mounted on a parent whose final application mount occurred inside
  `create_app` each emitted zero rows while the previous 25 Flask tests passed;
  the measured lane was 25 pass, 2 fail, and 178 assertions.
- Added shared exact same-file application-mount evidence for direct and nested
  Blueprint routes. A factory mount requires an undecorated top-level
  `create_app`/`make_app`, direct-suite official Flask construction and mount,
  one later direct `return app`, stable Blueprint/application bindings, and no
  replaced registration member.
- Added 12 fail-closed factory controls covering renamed/decorated factories,
  indirect mounts, missing or different returns, application and Blueprint
  rebinding, member replacement, duplicate mounts, construction after mount,
  dynamic prefixes, and unsupported options.
- Added a Flask 3.1.3 / Werkzeug 3.1.8 nested-Blueprint factory pair and strict
  `python-flask-nested-blueprint-factory-open-redirect-manifest.json`. The
  witnesses prove that registration-time `/root` overrides the parent
  constructor prefix, yielding `/root/child/continue`, and record attacker-
  origin selections one and zero without external I/O. The canonical corpus
  advances to 200 pairs, 400 cases, and 1,200 repeated scan positions.
- Focused Flask, canonical, and Rust bookkeeping acceptance passes 55 tests
  with 3,036 assertions. Full local acceptance runs 2,180 tests across 218
  files: 2,147 pass, 31 intentional platform/integration skips, and only the
  same two managed-sandbox permission failures. Both affected files pass
  natively at 48/48 tests and 242 assertions. The aggregate executes 17,006
  assertions.
- Exact implementation checkpoint
  `68f470055f4cd9c0e7e2e6df49af8d37e6a57bd2` has a 3,788,109-byte tracked
  source archive with SHA-256
  `0f52baa87e02030772f821df5f8b91d1781a65b8205476d9590dca2ba3d31b5b`.
  Two independently built 299-entry npm packages are byte-identical at
  2,494,642 bytes with SHA-256
  `3c24c5d060907ce04aaef7c64ed7121137926444c2bf4b9710761dd9355efe76`;
  a fresh 67-package install validates the public API, CLI, and all 79 bundled
  plugin files.
- Windows GUI acceptance builds with zero warnings/errors, passes 7/7 core and
  3/3 shared tests, and passes a verified hidden startup. Its 346,796-byte
  executable has SHA-256
  `a8edf3f35c0578e44f00257734961f2a78b5b86b52acc2d417bc2354a34a0939`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, followed by non-graphical and real
  X11/Xvfb startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- A tracked-only extraction of the exact checkpoint passes deep/xhigh dry-run
  preflight with three fresh-session attempts, `gpt-5.6-terra`, scanner-owned
  output, no `GH_TOKEN`, and stored-credential selection. It starts no model
  runtime and creates no output or persistent scanner-state directory; this is
  not evidence of a completed or clean self-scan.
- All 11 hosted workflow families pass at `68f4700`: Node `33358327904`
  (92/92 jobs), container `33358327915`, Windows GUI `33358327869`, Linux GUI
  `33358327980`, .NET `33358327884`, Go `33358327909`, Java `33358327893`,
  Kotlin `33358327887`, PHP `33358327907`, Ruby `33358327900`, and Rust
  `33358327873`.
- Closed a measured one-level Flask nested-Blueprint false negative. Before the
  host change, Flask's documented child-to-parent-to-application registration
  shape emitted zero rows while all 20 previous Flask regressions passed with
  144 assertions.
- Added exact `flask-blueprint-nesting` evidence. The host accepts one ordered
  same-file chain only when a completed child route is mounted once on a
  distinct stable official parent Blueprint and that parent is mounted once on
  the same stable official application. Each registration edge may have no
  options or one literal `url_prefix`.
- Added fail-closed controls for unmounted or non-Blueprint parents, rebound
  child/parent/application bindings, replaced registration members, dynamic or
  unsupported options, conditional or duplicate mounts, wrong ordering, self-
  nesting, and recursive or second-level nesting.
- Added a source-matched Flask 3.1.3 / Werkzeug 3.1.8 nested-Blueprint
  exploit/control pair and strict
  `python-flask-nested-blueprint-open-redirect-manifest.json`. No-follow
  TestClient witnesses prove the full `/parent/child/continue` route and
  attacker-origin selections of one and zero without external I/O. The
  canonical corpus advances to 199 pairs, 398 cases, and 1,194 repeated scan
  positions.
- Focused Flask, canonical, and Rust bookkeeping acceptance passes 50 tests
  with 2,998 assertions. Full local acceptance runs 2,175 tests across 218
  files: 2,142 pass, 31 intentional platform/integration skips, and only the
  two expected managed-sandbox permission failures. Both affected files pass
  natively at 48/48 tests and 242 assertions. The aggregate executes 16,968
  assertions. Package, GUI, and hosted evidence follows the implementation
  checkpoint.
- Exact implementation checkpoint
  `dea99c61f16dd691f4a4cf9708306ec616e5b5d8` has a 3,783,103-byte tracked
  source archive with SHA-256
  `9bfc1cc0aead5cd2c76328bab1feac28304612ece8db47581fe17caab7032f77`.
  Two independent 299-entry npm packages are byte-identical at 2,492,555 bytes
  with SHA-256
  `14dbfa4e417bd79c426ee25a59dc319b0c3a666c4476db756ae4a1304c88d4fe`;
  a fresh 67-package install validates the public API, CLI, and all 79 bundled
  plugin files.
- Windows GUI acceptance builds with zero warnings/errors, passes 7/7 core and
  3/3 shared tests, and passes a verified hidden startup. Its 346,796-byte
  executable has SHA-256
  `248fa766f3a62a2dd82a6ab94e156d91157bcb88b5430c04df56169025a589b8`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, as do non-graphical and X11/Xvfb
  startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- A tracked-only extraction of the exact checkpoint passes deep/xhigh dry-run
  preflight with three fresh-session attempts, `gpt-5.6-terra`, scanner-owned
  output, no `GH_TOKEN`, and stored-credential selection. It starts no model
  runtime and creates no output or persistent scanner-state directory; this is
  not evidence of a completed or clean self-scan.
- All 11 hosted workflow families pass at `dea99c6`: Node `33354547654`
  (92/92 jobs), container `33354547649`, Windows GUI `33354547602`, Linux GUI
  `33354547699`, .NET `33354547620`, Go `33354547633`, Java `33354547650`,
  Kotlin `33354547603`, PHP `33354547679`, Ruby `33354547623`, and Rust
  `33354547666`.
- Closed a measured Flask application-factory false negative. Before the host
  change, the maintained `create_app` pattern—official Blueprint in one module,
  `from . import redirects`, exact `app.register_blueprint(redirects.bp)`, and
  direct `return app` in the package factory—emitted zero rows while all 15
  previous Flask regressions passed with 103 assertions.
- Added typed `relative-python-blueprint-symbol-import` and
  `relative-python-blueprint-module-import` evidence. Cross-file reachability
  resolves one explicit relative import to the exact Blueprint source and
  exported binding, then requires either a stable top-level official Flask
  application or an undecorated top-level `create_app`/`make_app` that
  constructs, mounts, and directly returns the same stable application.
- Added exact literal `url_prefix` support for same-file and cross-file mounts.
  Absolute, wildcard, dynamic, unresolved, or rebound imports; renamed or
  decorated factories; missing or different returns; conditionally nested,
  multiply mounted, expanded, dynamic-prefix, or other configured mounts; and
  replaced Blueprint or application members remain fail-closed controls.
- Added a source-matched Flask 3.1.3 / Werkzeug 3.1.8 cross-file application-
  factory exploit/control pair and strict
  `python-flask-cross-file-blueprint-open-redirect-manifest.json`. No-follow
  TestClient witnesses prove attacker-origin selections of one and zero without
  external I/O. The canonical corpus advances to 198 pairs, 396 cases, and
  1,188 repeated scan positions.
- Focused acceptance passes 45 Flask, canonical, and Rust bookkeeping tests
  with 2,954 assertions. Types, build, formatting, the clean production
  dependency audit, and both exact-version witnesses pass.
- Full local acceptance runs 2,170 tests across 218 files: 2,137 pass, 31
  intentional platform/integration skips, and only two expected managed-
  sandbox failures. Both affected files pass natively at 48/48 tests and 242
  assertions. The aggregate executes 16,924 assertions.
- Exact implementation checkpoint
  `cc14b5b273630cb908ccbc0e0d04cf4af16a17f2` has a 3,776,498-byte tracked
  source archive with SHA-256
  `67d0f615da5b1fb18211edee206b611c460eb9f0dbebfd9f3b9ff5b4cf232f03`.
  Two independent 299-entry npm packages are byte-identical at 2,489,721
  bytes with SHA-256
  `45ce9207d1003570878adebbbad487b6718818f4fa26d9e474e86defa9135650`;
  a fresh 67-package install validates the public API, CLI, and all 79 bundled
  plugin files.
- Windows GUI acceptance builds with zero warnings/errors, passes 7/7 core and
  3/3 shared tests, and publishes a 346,796-byte executable with SHA-256
  `065a30a1e86415e641dcf6bb51a67e0bf5c7b8451fc7d94e2c09fb5c8af6a81b`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, as do non-graphical and X11/Xvfb
  startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- A clean tracked-only clone of the exact checkpoint passes deep/xhigh dry-run
  preflight with three fresh-session attempts, scanner-owned output, no
  `GH_TOKEN`, and stored-credential account selection. The dry run starts no
  model runtime, creates no persistent scanner-state directory, and is not
  evidence of a completed or clean self-scan.
- All 11 hosted workflow families pass at `cc14b5b`: Node `33349893432`
  (92/92 jobs), container `33349893498`, Windows GUI `33349893540`, Linux GUI
  `33349893435`, .NET `33349893445`, Go `33349893408`, Java `33349893486`,
  Kotlin `33349893473`, PHP `33349893412`, Ruby `33349893476`, and Rust
  `33349893405`.
- Closed a measured Flask Blueprint false negative. Before the host change, an
  exact official `Blueprint` GET route mounted by a later exact
  `app.register_blueprint(bp)` emitted zero rows while all eleven previous Flask
  regressions passed. The typed model now binds the declaration to the live
  application mount instead of treating every Blueprint as reachable.
- Added separate `flask-official-blueprint-factory` and
  `flask-blueprint-registration` evidence while retaining the official Flask
  application factory, exact route method, request-field, redirect, and
  Location edges. The model requires top-level same-file constructors and one
  later exact registration of the same stable Blueprint on the same stable
  official application.
- Added fail-closed registration controls for unmounted, dynamically mounted,
  scoped, rebound, member-replaced, multiply mounted, nested-only, shadowed, and
  non-Flask application cases. Configured or expanded registration calls remain
  unsupported rather than being guessed reachable.
- Added a source-matched Flask 3.1.3 / Werkzeug 3.1.8 registered-Blueprint
  exploit/control pair and strict
  `python-flask-blueprint-open-redirect-manifest.json`. No-follow TestClient
  witnesses prove attacker-origin selections of one and zero without external
  I/O. The canonical corpus advances to 197 pairs, 394 cases, and 1,182 repeated
  scan positions.
- Focused acceptance passes 40 Flask, canonical, and Rust bookkeeping tests
  with 2,902 assertions. Both exact-version Blueprint witnesses pass.
- Exact implementation checkpoint
  `3733581ed0f41c552fa7123aebfc90fdc193741c` has a 3,768,555-byte tracked
  source archive with SHA-256
  `c9e2b76045657d5cef7c0a07fb646d75834f82f34503a81905c1fdfb1d23096a`.
  Two independent 299-entry npm packages are byte-identical at 2,480,477 bytes
  with SHA-256
  `f522514891c5f80e61586994993f5faf986e63cd24671aea3bbf967423c94bfe`;
  a fresh 67-package install validates the public API, CLI, and all 79 bundled
  plugin files. The production high-severity dependency audit is clean.
- Full local acceptance runs 2,165 tests across 218 files: 2,132 pass, 31
  intentional platform/integration skips, and only two expected managed-sandbox
  failures. Both affected files pass natively at 48/48 tests and 242 assertions.
  All Python lanes pass 232 tests with eight intentional skips and 1,526
  assertions; formatting, types, and build pass.
- Windows GUI acceptance builds with zero warnings/errors, passes 7/7 core and
  3/3 shared tests, and publishes a 346,796-byte executable with SHA-256
  `022f2cf49049ed87546ee3a3ea25d095d9e491cd2e88e0705541f37103416ad0`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, as do non-graphical and X11/Xvfb
  startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- A tracked-only clone of the exact checkpoint passes deep/xhigh dry-run
  preflight with three fresh-session attempts, scanner-owned output, no
  `GH_TOKEN`, and stored Copilot credentials. This was deliberately a dry run,
  so it is not evidence of a completed model scan or a clean self-scan.
- All 11 hosted workflow families pass at `3733581`: Node `33343372972`
  (92/92 jobs), container `33343372989`, Windows GUI `33343373001`, Linux GUI
  `33343372983`, .NET `33343372996`, Go `33343372965`, Java `33343372963`,
  Kotlin `33343372947`, PHP `33343372956`, Ruby `33343372944`, and Rust
  `33343372975`.
- Closed a measured Flask form-redirect false negative. Before the host change,
  an official `@app.post` handler whose `request.form.get("next")` value reached
  `flask.redirect` emitted zero rows while all eight previous Flask regressions
  passed. The typed model now accepts literal `.get(...)` and subscript reads
  from the stable official form collection.
- Added exact route-method control instead of treating every Flask handler as
  form-capable. Form evidence requires `app.post`, `app.put`, `app.patch`, or an
  exact static literal `methods` list/tuple containing POST, PUT, or PATCH.
  Default routes, GET, DELETE, empty collections, dynamic values, expanded
  arguments, unstable bindings, and unsupported request collections fail
  closed. Query-string evidence remains independent of the route method.
- Added distinct `flask-request-form-string`, `flask-route-form-method`, and
  `flask-request-form-read` evidence. The reviewer must name the exact route
  method, form field, redirect-to-Location edge, origin switch, missing control,
  and CWE-601.
- Added a source-matched Flask 3.1.3 / Werkzeug 3.1.8 POST exploit/control pair
  and strict `python-flask-post-open-redirect-manifest.json`. No-follow
  TestClient witnesses prove attacker-origin selections of one and zero without
  external I/O. The canonical corpus advances to 196 pairs, 392 cases, and
  1,176 repeated scan positions.
- Initial focused acceptance passes 36 Flask, canonical, and Rust bookkeeping
  tests with 2,867 assertions; generated-model and TypeScript checks pass. Both
  exact-version POST witnesses pass. Full aggregate, package, GUI, hosted, and
  immutable-checkpoint evidence follows after the implementation checkpoint.
- Exact implementation checkpoint
  `5de7c8f8889f9378b25f2bc8ffa47379d11f3b7f` has a 3,764,407-byte tracked
  source archive with SHA-256
  `a0c3ac643de3fcfcbde8d472f31545e9096093d6b290558ba0a61adda0dd4127`.
  Two independent 299-entry npm packages are byte-identical at 2,479,253 bytes
  with SHA-256
  `fec56a0e02aaf379a85179b2b5615f70ca2e20f6aa0c7fb64aac12a279d5e0fd`;
  a fresh 67-package install validates the public API, CLI, and all 79 bundled
  plugin files. The production high-severity dependency audit is clean.
- Full local acceptance runs 2,161 tests across 218 files: 2,128 pass, 31
  intentional platform/integration skips, and only two expected managed-sandbox
  failures. Both affected files pass natively at 48/48 tests and 242 assertions.
  All Python lanes pass 228 tests with eight intentional skips and 1,502
  assertions; the focused Flask/canonical/bookkeeping lane passes 36/36 tests
  with 2,867 assertions. Formatting, generated models, types, and build pass.
- Windows GUI acceptance builds with zero warnings/errors, passes 7/7 core and
  3/3 shared tests, and publishes a 346,796-byte executable with SHA-256
  `20259e7ee90d076286dfbd1727e2cc45fee427a5fc50a53ecc8c232c9e1a72e8`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, as do non-graphical and X11/Xvfb
  startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- All 11 hosted workflow families pass at `5de7c8f`: Node `33339341739`
  (92/92 jobs), container `33339341735`, Windows GUI `33339341705`, Linux GUI
  `33339341736`, Java `33339341699`, .NET `33339341783`, Go `33339341721`,
  Kotlin `33339341757`, Rust `33339341752`, PHP `33339341704`, and Ruby
  `33339341700`.
- An isolated tracked-only deep self-scan dry-run binds the clean exact
  implementation SHA, scanner-owned external output path, xhigh effort, and
  three-session recovery budget. Removing ambient `GH_TOKEN` correctly selects
  stored Copilot credentials. No production Copilot call was made and no scan
  finding or completion claim is inferred from preflight.
- Closed a measured Django form-redirect false negative. Before the host change,
  a registered function view reading `request.POST` produced zero findings while
  all sixteen prior Django regressions passed. The typed model now accepts exact
  `request.POST.get(...)` and subscript reads in registered function views and
  exact `post(self, request, ...)` class handlers.
- Extended class dispatch without broad request-name matching. A direct official
  `View` may expose one exact GET and one exact POST handler through the same
  no-argument `as_view()` registration. Form data is reachable only from the
  POST handler under default dispatch; query data remains available in either
  handler. Duplicate or replaced POST methods, a POST collection in `get()`,
  request reassignment, lifecycle overrides, decorators, shadows, and ambiguous
  routing remain negative.
- Closed the paired function-view false positive for exact stable
  `django.views.decorators.http.require_GET`, `require_safe`, and static
  `require_http_methods` collections that omit POST. A real `require_POST`
  decorator remains positive; an exact empty static collection is correctly
  treated as deny-all, while shadowed, rebound, lookalike, or dynamic method
  controls receive no trust.
- Added distinct `django-request-form-string`, `django-post-request-parameter`,
  and `django-request-post-read` evidence plus reviewer requirements that name
  the form field, exact POST handler, redirect-to-Location edge, origin switch,
  missing control, and CWE-601.
- Added a source-matched Django 6.1 POST class-view exploit/control pair and a
  strict `python-django-post-open-redirect-manifest.json`. Offline TestClient
  witnesses prove attacker-origin selections of one and zero without following
  the redirect or performing external I/O. The canonical corpus advances to 195
  exploit/control pairs, 390 cases, and 1,170 repeated scan positions.
- Focused acceptance passes 44 Django, canonical, and Rust bookkeeping tests
  with 2,903 assertions; generated-model and TypeScript checks pass. The
  new real Django 6.1 exploit/control witnesses also pass in an isolated
  environment, which is removed after validation.
- The 2,158-test TypeScript aggregate records 2,125 passes, 31 intentional
  platform/environment skips, and only the two expected managed-sandbox
  denials in benchmark Git setup and scanner-home transport. Native reruns of
  both complete affected files pass 48/48 with 242 assertions. The final
  deny-all method-decorator precision regression then passes in the complete
  19-test Django file (125 assertions), alongside a clean generated-model and
  TypeScript recheck.
- Exact implementation checkpoint
  `ac373b807fbfbe091357fae82f243c8d8d802e12` has a 5,963,412-byte tracked
  source archive with SHA-256
  `a1b032ccd047a5a856e57e359ccae6b80706c95e6264d26df96383c543a3e1a6`.
  Its two independent 299-entry npm packages are byte-identical at 2,477,744
  bytes with SHA-256
  `29edd56e9fda984cf54d11dd5caf907cc950815e1562ffd860122726104c8982`;
  a fresh 67-package install validates the public API, CLI, and all 79 bundled
  plugin files. The production high-severity dependency audit is clean.
- Windows GUI acceptance builds with zero warnings/errors, passes 7/7 core and
  3/3 shared tests, and publishes a 346,796-byte executable with SHA-256
  `c6a6e8ac4e6266c6c2104c8e50d4ebeaccdea8b68d82091844545e62ec9e5562`.
  Ubuntu/WSL locked restore and build also have zero warnings/errors; 7/7 core,
  3/3 shared, and 2/2 Linux UI tests pass, as do non-graphical and X11/Xvfb
  startup. The 72,568-byte Linux executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- All 11 hosted workflow families pass at `ac373b8`: Node `33335556000`
  (92/92 jobs), container `33335556028`, Windows GUI `33335555992`, Linux GUI
  `33335556012`, Java `33335556007`, .NET `33335555991`, Go `33335556003`,
  Kotlin `33335555986`, Rust `33335555984`, PHP `33335555987`, and Ruby
  `33335555985`. The repository is public on default branch `main`.
- An isolated deep self-scan dry-run validates the exact tracked target,
  scanner-owned output path, xhigh effort, and three-session recovery budget.
  Removing the ambient `GH_TOKEN` correctly selects stored Copilot credentials
  instead of token authentication. The production self-scan itself remains
  pending because the execution safety layer denied external Copilot source
  egress; no self-scan finding or completion claim is inferred from preflight.
- Closed a separately measured Django class-based-view false negative: the
  unchanged scanner emitted zero rows for an official `django.views.View`
  subclass registered through `ContinueView.as_view()`, while the typed model
  now emits the expected `python-django-open-redirect` row from
  `get(self, request)`.
- Added fail-closed class-dispatch proof for one direct official `View` base,
  an exact no-argument `as_view()` URL registration, one undecorated GET
  handler, its second request parameter, and stable class/import/member state.
  Multiple inheritance, decorators, duplicate definitions, configured
  `as_view`, `setup`/`dispatch` overrides, defaulted or reassigned request
  parameters, local Django shadows, and replaced `as_view` or `get` members
  remain negative. The existing official host-and-scheme guard suppression also
  applies inside class handlers.
- Added a strict Django 6.1 class-view exploit/control pair and offline
  no-follow witnesses. The canonical corpus advances to 194 exploit/control
  pairs, 388 cases, and 1,164 repeated scan positions. The focused class-view,
  canonical-count, and TypeScript compilation lanes pass 23 tests and 144
  assertions before full acceptance.
- Final scanner acceptance at exact implementation checkpoint
  `1e77620c9c3f714ff370539b8d607372e134d81e` runs all 2,155 TypeScript
  tests in 844.63 seconds: 2,122 pass, 31 intentional environment/platform
  cases skip, and the two managed-sandbox Git/Windows-ACL denials pass in a
  native rerun of their complete six-test and 42-test files (48/48, 242
  assertions). Generated-model drift, formatting, TypeScript, the clean build,
  and the production high-severity dependency audit are green.
- Two scans of an isolated exact-checkpoint tracked tree are byte-identical at
  the 256-row cap: 627,964 bytes with SHA-256
  `fa8304167b0e18c8a62b80f6a9d7e8abc0449fa46bc8ed4bcc0f779b3813a0da`.
  Exactly one new row retains the class-view source at `src/views.py:7`, sink
  at `src/views.py:9`, CWE-601, and all nine View/route/query/Location
  propagators; the topology-matched safe twin emits no Django row. The
  5,949,888-byte exact tracked ZIP has SHA-256
  `0d0ba56f61520198f0345906ed9f150703b7241c66553d0af22c69a149e05da1`.
- Two production package builds are byte-identical. Strict inspection validates
  the 299-entry, 2,442,805-byte archive with SHA-256
  `e5d6ed4a01109cd6567358a6dd9f3711ef62d12d1112bc19ed2af78281595a7d`;
  a fresh 67-package install validates the public import, CLI, and all 79
  bundled plugin files. The exact Django 6.1 exploit/control witnesses pass in
  an isolated environment.
- Windows GUI acceptance builds with zero warnings/errors, passes 7/7 core and
  3/3 shared tests, and publishes a 346,796-byte executable with SHA-256
  `93513ea1f20bcfd0f718651195aaaa65239d34f66556224eb203a74b6d264da0`.
  Ubuntu/WSL builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and
  2/2 Linux UI tests, passes non-graphical and X11/Xvfb startup, and publishes
  a 72,568-byte executable with SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- All 11 exact-checkpoint workflow families pass: Node `33329023218` (92/92
  jobs), container `33329023217`, Windows GUI `33329023180`, Linux GUI
  `33329023185`, Java `33329023197`, .NET `33329023216`, Go `33329023204`,
  Kotlin `33329023109`, Rust `33329023171`, PHP `33329023228`, and Ruby
  `33329023239`. The repository remains public on default branch `main`.
- Added a fail-closed `python-django-open-redirect` model for CWE-601. It
  requires an official `django.urls.path` or `re_path` call inside the sole
  balanced `urlpatterns` list, an exact same-file or relative-imported function
  view, one literal `request.GET` field, and an official
  `django.shortcuts.redirect` or `django.http` redirect-response Location sink.
  Direct, qualified, aliased, response-class, named-target, subscript, multiple-
  route, and relative-wrapper forms retain typed evidence.
- Closed a measured Django false negative for `"/" + target`, which can form a
  scheme-relative attacker authority. A non-root local prefix and an enclosing
  official `url_has_allowed_host_and_scheme` check over the exact value with a
  static host set suppress the path. Unregistered and class-based views,
  dynamic or ambiguous routing, local shadows, rebound symbols, non-query
  collections, opaque transformations, and unknown arguments fail closed.
- Added a strict Django 6.1 exploit/control pair. The no-follow test-client
  witness resolves the exploit Location to `attacker.invalid`, while the
  topology-matched encoded-local control remains below `/continue/?next=`;
  neither performs an external request. The canonical corpus advances to 193
  pairs, 386 cases, and 1,158 repeated scan positions. The focused Django,
  Flask, FastAPI, Rust bookkeeping, and canonical lane passes 56 tests and
  2,950 assertions.
- Final acceptance at implementation checkpoint
  `b0d09b8e4fdf1e1dd5110f4fc697705bc05bb435` runs all 2,149 TypeScript tests:
  2,116 pass, 31 intentional environment/platform cases skip, and the two
  sandbox-denied Git/Windows-ACL cases pass in native reruns of their complete
  six-test and 42-test files. Generated-model drift, formatting, TypeScript, a
  clean build, and the production advisory audit are green.
- Two exact-checkpoint self-inventories are byte-identical at the 256-row cap:
  626,847 bytes with SHA-256
  `7d7e0d86fa67ff1d61ee990af6a73f6a8b7b830d509038b7a02698215c4b7865`.
  Each uniquely retains the Django source at `src/views.py:5`, redirect sink at
  `src/views.py:7`, and CWE-601; the fixed-local twin is absent. The
  21,739,520-byte tracked archive has SHA-256
  `9f65a721453c04f396b6b39790a53bd7cfaf36a3ec69a81d83fa65051a5a2868`.
- Two production package builds are byte-identical. Strict inspection validates
  the 299-entry, 2,471,910-byte archive with SHA-256
  `4a8253b1f73ce27e9da065ead7ee5f1f36b458de7cdf1501960a08d11b79e942`;
  a fresh 67-package install validates the public import, CLI, and all 79
  bundled plugin files. Windows and Ubuntu WSL builds have zero warnings or
  errors; each passes the seven core and three shared tests, and Linux also
  passes both headless/UI-smoke tests. All temporary archives are removed.
- All eleven exact-source workflow families pass: Node `33324067745` passes 92
  jobs including the Django witnesses; container `33324067792`, .NET
  `33324067774`, Go `33324067760`, Java `33324067666`, Kotlin `33324067684`,
  Linux GUI `33324067690`, PHP `33324067709`, Ruby `33324067688`, Rust
  `33324067755`, and Windows GUI `33324067708` also pass. GitHub reports the
  repository public on default branch `main`.
- Added a fail-closed `python-flask-open-redirect` model for CWE-601. It
  requires an official `flask.Flask` application, one literal route, an exact
  stable `flask.request.args` query-field read, and an official
  `flask.redirect` Location sink. Same-file aliases and one relative wrapper
  retain structured factory, route, request, field, redirect, and Location
  evidence.
- Closed a reproduced root-prefix false negative. The unchanged scanner emitted
  no row for `"/" + target`; the implemented model preserves it because a
  target beginning with slash forms `//host`. This is stricter than CodeQL's
  current URL-redirection string-concatenation sanitizer, which treats the
  right operand as sanitized whenever the left operand controls the prefix.
- Preserved fail-closed precision for local Flask shadows, rebound request,
  redirect, application, and route members, Blueprint-only registration,
  multiple or dynamic decorators, star or unknown redirect arguments,
  non-query request collections, opaque transformations, and multiple
  unresolved query sources. A non-root fixed local prefix remains a control.
- Added a pinned Flask 3.1.3 / Werkzeug 3.1.8 exploit/control pair. With
  `follow_redirects=False`, the exploit emits
  `//attacker.invalid/capture` and the encoded control remains below
  `/continue?next=`; neither witness performs an external request. The
  canonical corpus advances to 192 pairs, 384 cases, and 1,152 repeated scan
  positions.
- Focused Flask, FastAPI, and canonical acceptance passes 39 tests and 2,827
  assertions. Generated-model drift, TypeScript, formatting, and a clean
  production build pass.
- The authoritative native Windows aggregate passes 2,108 tests and 16,641
  assertions, skips 31 intentional platform/environment cases, and reports no
  failures across 2,139 tests in 217 files. The initial sandboxed soak exposed
  only stale-build, private-ACL, and 191-pair bookkeeping conditions; a fresh
  build, the 192-pair update, and the required native ACL boundary clear all
  seven without changing product expectations.
- Two compiled inventories of the 3,968-file exact implementation archive at
  checkpoint `7347faacf59c74a9a8612915f96a4f57f98dec07` are byte-identical.
  They take 42,619.554 and 21,958.991 milliseconds, reach the 256-row cap with
  only structured rows, total 626,362 bytes, and have SHA-256
  `63c6085a11989f5b6db7e811b03c605347e2dd25338fdfeb2a15d77aef642ae1`.
  Exactly one Flask row retains request source line 7, redirect sink line 9,
  CWE-601, and six ordered framework and Location transitions; the fixed-local
  twin is absent. The 21,657,600-byte tracked archive has SHA-256
  `d8e8b2eb6a276c7623f4204800592d020a0d6c8a3e1cf5a826e97322cb3c2eea`.
- Two production package builds are byte-identical. Strict inspection validates
  the 299-entry, 2,462,222-byte archive with SHA-256
  `34956d772552b3fc84da34e11ed7a04faf22bde48dcf75f79d3b2f4ac20fc426`;
  an isolated 67-package installation validates the public import, executable
  CLI, and all 79 bundled plugin files. The production high-severity advisory
  audit reports no known vulnerabilities.
- All eleven exact-source workflow families pass at the implementation
  checkpoint. Node CI run `33319844821` passes all 92 jobs, including the new
  Flask exploit/control witnesses; container `33319844756`, .NET `33319844779`,
  Go `33319844774`, Java `33319844810`, Kotlin `33319844811`, Linux GUI
  `33319844902`, PHP `33319844727`, Ruby `33319844828`, Rust `33319844808`, and
  Windows GUI `33319844822` also pass. GitHub reports the repository public on
  default branch `main`.
- Closed a reproduced shared false negative for balanced multiline FastAPI
  path-operation decorators. The unchanged host passed its 12 existing direct-
  return redirect checks but emitted no finding for the new executable case.
  Route evidence now spans a comment- and string-aware balanced decorator call
  bounded to 32 physical lines while preserving the first `@app.get(` or
  `@app.post(` line as exact provenance.
- Kept the expansion fail closed. FastAPI evidence still requires exactly one
  official path-operation decorator; unbalanced calls, additional decorators,
  wildcard options, duplicate roles, local framework shadows, and unrelated
  preceding decorated handlers cannot broaden a finding. The shared route
  boundary improves both the direct-return CWE-601 model and cross-file
  FastAPI/Pydantic request-body-to-shell flows.
- Converted the existing response-class exploit/control fixture pair to
  ordinary multiline decorator syntax, so the canonical corpus remains 191
  pairs, 382 cases, and 1,146 repeated positions while continuously exercising
  the repaired parser. Its pinned WSL TestClient witness records attacker-
  origin selections `1` and `0` on FastAPI 0.116.1, Starlette 0.47.3, Pydantic
  2.11.7, and HTTPX 0.28.1 without following the redirect or contacting an
  external origin.
- Focused acceptance passes 24 tests and 191 assertions; the complete 19-file
  Python lane passes 198 tests and 1,299 assertions with eight intentional
  platform skips; and the focused plus Pydantic plus canonical gate passes 42
  tests and 2,868 assertions. The authoritative native aggregate passes 2,100
  tests and 16,585 assertions, skips 31 intentional platform/environment cases,
  and has no failures across 2,131 tests in 216 files. Formatting, generated-
  model drift, TypeScript, the clean production build, and the production high-
  severity advisory audit are green.
- Two compiled inventories of the 3,956-file exact implementation archive at
  checkpoint `12e6b0b2d53d47f601e16bf170ec011cf9e0aa2f` are byte-identical.
  Each reaches the 256-row cap, is 625,837 bytes, and has SHA-256
  `31827ab6aefe37195f5fea1049ec5a1c8157710c22a048872dfd0de859334292`.
  Exactly one response-class row retains the multiline route at line 10,
  request source at line 15, direct-return sink at line 17, and CWE-601; the
  fixed-local twin is absent. The 21,596,160-byte tracked archive has SHA-256
  `b770ae65570a017b6bbbb9b39619b112c1f3056ab4c1e0304255579caf8fc813`.
- Two production package builds are byte-identical. Strict inspection validates
  the 299-entry, 2,421,669-byte archive with SHA-256
  `290f78c26e72bd2c820643a6ed9d91f7c47ff3f4f2b00eb5d745fbc80f235fdb`;
  an isolated 75-package installation validates the public import, executable
  CLI, and all 79 bundled plugin files. A release-only provenance assertion
  rejects the local pack because it correctly omits registry `gitHead`; hosted
  exact-head workflows supply that evidence. Temporary archives, package
  outputs, installs, and dependency junctions were removed after validation.
- All eleven exact-source workflow families pass at the implementation
  checkpoint. Node CI run `33315078040` passes all 92 jobs, including the
  multiline FastAPI witness; container `33315078152`, .NET `33315078064`, Go
  `33315078104`, Java `33315078093`, Kotlin `33315078151`, Linux GUI
  `33315078092`, PHP `33315078134`, Ruby `33315078118`, Rust `33315078075`, and
  Windows GUI `33315078130` also pass. The public default `main` branch hosts
  the exact implementation checkpoint.
- Closed FastAPI's documented `response_class=RedirectResponse` direct-return
  gap under the existing typed CWE-601 model. The new sink requires an exact
  official FastAPI or Starlette response binding in the route decorator's sole
  `response_class=` role and an unconditional top-level handler return that
  preserves exactly one supported string query parameter. It emits distinct
  response-class binding and FastAPI-to-`Location` propagators.
- Preserved fail-closed precision for the new form. Wrong or rebound response
  classes, local framework shadows, duplicate response-class roles, wildcard
  route options, configured or ambiguous Query metadata, guarded nested
  returns, opaque helper/sanitizer calls, fixed local destinations, and
  multiple controlled parameters remain negative. Root-only `"/" + value`
  remains reportable because it can form `//host`.
- Added a separate source-matched TestClient pair on FastAPI 0.116.1, Starlette
  0.47.3, Pydantic 2.11.7, and HTTPX 0.28.1. With redirect following disabled,
  the direct return selects the inert attacker origin once while the encoded
  fixed-local control selects it zero times. The dedicated strict manifest now
  contains both constructor and response-class pairs; the canonical corpus
  advances to 191 pairs, 382 cases, and 1,146 repeated scan positions.
- The authoritative Windows aggregate exercises 2,129 tests: 2,091 pass, 31
  intentional platform/environment cases skip, and seven initially fail. One
  failure is the deliberately stale 190-pair invariant and passes at 191/382.
  Five campaign tests first reject stale built output; rebuilding restores four
  and leaves only the managed temporary-Git boundary. That case and the managed
  private-ACL denial both pass in an unchanged native 48-test, 242-assertion
  rerun. The effective product result is 2,098 passes and no failures. The
  complete 19-file Python lane separately passes 196 tests and 1,285 assertions
  with eight expected platform skips.
- Two compiled inventories of the 3,956-file exact implementation archive at
  checkpoint `a2d3847799175b3f8e3ed71b05444696255ad421` are byte-identical.
  Each reaches the 256-row cap with 256 structured records, is 626,013 bytes,
  and has SHA-256
  `202db65ff5ac8e1cf16f32b443c2ce6d5ef6aba5497128882eeef78034c4f76a`.
  Exactly one response-class redirect row retains the request source at
  `src/server.py:11`, direct-return sink at line 13, CWE-601, and all seven
  ordered framework, Query, response-class, and Location transitions; its
  fixed-local twin is absent.
- Two production package builds are byte-identical. Strict inspection validates
  the 299-entry, 2,454,697-byte archive with SHA-256
  `f33c7358e1906e01d35e04b680f4eeee9b58d0a50d9239029ff0046fbbde281a`;
  an isolated 67-package installation validates the public import, executable
  CLI, and all 79 bundled plugin files. The production high-severity advisory
  audit reports no known vulnerabilities.
- All eleven exact-source workflow families pass. Node CI run `33312264502`
  passes all 92 jobs, including the updated FastAPI exploit/control witness;
  container `33312264470`, .NET `33312264494`, Go `33312264521`, Java
  `33312264495`, Kotlin `33312264487`, Linux GUI `33312264473`, PHP
  `33312264486`, Ruby `33312264503`, Rust `33312264520`, and Windows GUI
  `33312264466` also pass. The repository is public on default branch `main`,
  whose hosted head is the exact implementation checkpoint.
- Added a fail-closed `python-fastapi-open-redirect` host model for CWE-601.
  One stable official FastAPI path operation and string query parameter must
  reach the positional or named URL of an exact non-shadowed FastAPI or
  Starlette `RedirectResponse`. Structured evidence retains the route, exact
  `str` / `Annotated[str, Query()]` / legacy `str = Query()` boundary,
  request-parameter flow, official response binding, URL argument, and HTTP
  `Location` assignment through same-file aliases, relative wrappers, and
  bounded multi-hop relays.
- Kept origin-control handling deliberately conservative. A fixed local prefix
  longer than `/` suppresses the model when the remote value is nested beneath
  it; root-only `"/" + value` remains reportable because a leading slash can
  form `//host`. Configured or ambiguous Query calls, extra Annotated metadata,
  non-string, duplicated, or reassigned parameters, multiple candidate request
  strings, star-expanded or duplicate URL roles, local `fastapi` or `starlette`
  packages, rebound responses, and lookalikes remain negative. Dotted local-
  module shadow checks now correctly inspect package prefixes, strengthening
  all typed Python models.
- Added a pinned FastAPI/Starlette/HTTPX TestClient differential. The unchanged
  pre-change host emitted zero structured rows for both fixtures. The new host
  emits exactly one CWE-601 row for the absolute attacker-origin selection and
  none when the identical URL is percent-encoded beneath `/continue?next=`.
  The witness disables redirect following and contacts no external origin;
  native Ubuntu/WSL records attacker-origin selections `1` and `0`.
- Added a strict dedicated manifest, canonical three-run cases, model-specific
  validation and attack-path requirements, reviewer correction guidance, and a
  hosted witness. The canonical corpus advances to 190 exploit/control pairs,
  380 cases, and 1,140 repeated scan positions; the focused Python framework
  corpus advances to 20 cases split 10/10. Initial Windows acceptance passes
  8 redirect tests with 52 assertions, 17/18 Python framework tests with one
  intentional witness skip and 265 assertions, and all 192 runnable tests with
  1,253 assertions across the complete 19-file Python model lane. The
  authoritative Windows aggregate records 2,092 passes, 31 intentional skips,
  and two managed-sandbox permission failures across 2,125 tests and 16,522
  assertions; a native 48-test, 242-assertion rerun passes both denied files,
  yielding 2,094 passing outcomes and no product failures. Generated-model
  drift, TypeScript, and the clean production build are green.
- Two compiled inventories of the immutable 3,946-file implementation archive
  at checkpoint `8dfe36f2cba0a31b6aba4c68bed7df0c4f80390e` are byte-
  identical. Each reaches the 256-row cap with 256 structured records, is
  624,998 bytes, and has SHA-256
  `f0238cb2713be74054442e8e78070a7fd5c4e7f5e65a1e55324fa1f3df11eb24`.
  Exactly one FastAPI redirect row retains the request parameter at
  `src/server.py:11`, relative wrapper call, sink at `src/redirects.py:5`,
  CWE-601, and all ten ordered route, Query, Annotated, import, call, parameter,
  response-binding, and Location propagators; the fixed-local twin is absent.
  The 21,534,720-byte archive has SHA-256
  `8c0b0d110575f303b7634c1e098e2ea82fc76abd88d52be0d9bc69689087b088`
  and was removed after verification. A first 371-file subdirectory archive
  was explicitly rejected when the required fixture row was absent.
- Strict package inspection validates a 2,452,901-byte npm archive with SHA-256
  `e10464405f313b4470117c3d5f50748e526d3975beb9af16c1541f1905786702`.
  An isolated installation adds 67 packages and validates the public import,
  executable CLI, and all 79 bundled plugin files. The production high-severity
  advisory audit reports no known vulnerabilities; the archive and isolated
  installation are removed after validation.
- Hosted acceptance for checkpoint `8dfe36f` is green across all 11 workflow
  families: Node CI `33308699091` completes all 92 jobs, including the new
  FastAPI request-body and open-redirect witnesses; PHP `33308699054`, Go
  `33308699115`, Ruby `33308699064`, Rust `33308699093`, .NET `33308699104`,
  Windows GUI `33308699123`, container `33308699117`, Kotlin `33308699074`,
  Linux GUI `33308699062`, and Java `33308699079` also succeed. The exact
  implementation checkpoint is published on the public `secwest/copilot-security`
  `main` branch.
- Closed the documented embedded and legacy FastAPI Pydantic request-body gap.
  The exact endpoint model now accepts `Annotated[Model, Body(embed=True)]`,
  literal `embed=False`, and legacy `Model = Body()` / `Body(...)` equivalents
  while preserving the same declared request-controlled field through bounded
  Python wrappers into shell grammar.
- Added a shared fail-closed `Body` call contract. Only zero arguments, an
  optional leading required ellipsis, and one literal `embed=True` or
  `embed=False` keyword qualify. Query/dependency metadata, extra Annotated
  metadata, aliases and other Body options, positional, dynamic, or duplicate
  embed values, arbitrary defaults, shadows, missing/ambiguous imports, and
  rebound bindings remain negative.
- Structured evidence now distinguishes `fastapi-embedded-body-shape` and
  `fastapi-legacy-body-default`. Host quality closure and the Copilot reviewer
  must retain the exact embedded JSON envelope or legacy default syntax in
  both validation and attack-path prose.
- Added a pinned FastAPI TestClient exploit/control pair whose nested JSON
  produces temporary-marker values `1` and `0`. The unchanged pre-change host
  emitted zero structured rows for both; the new host emits exactly one for
  the vulnerable field and none for the topology-matched `ClassVar` control.
  The canonical corpus advances to 189 exploit/control pairs, 378 cases, and
  1,134 repeated scan positions; the focused Python relative-import corpus is
  18 cases split 9/9.
- Focused Windows regression passes 45 tests and 3,003 assertions with one
  intentional POSIX-witness skip; native Ubuntu/WSL passes all 46 tests and
  3,019 assertions. The authoritative Windows aggregate records 2,083 passes,
  31 intentional skips, two managed-sandbox permission denials, and one stale
  corpus-count assertion across 2,117 tests and 16,447 assertions. After
  correcting the count to 189 pairs, a native 55-test, 299-assertion rerun
  passes that guard and both denied Git/Windows-ACL files, yielding 2,086
  passing outcomes and no product failures.
- The validated 299-entry npm archive is 2,446,494 bytes with SHA-256
  `3b2326dac6616d602e9cf05fd307222c18d73234488420e6e1edf22d870383e4`.
  Strict inspection and isolated Windows and Ubuntu installs validate the
  public import, executable CLI, and all 79 bundled plugin files. Generated-
  model drift, formatting, TypeScript, the clean production build, and the
  production dependency audit are clean.
- Two compiled inventories of the immutable 3,932-file implementation archive
  at checkpoint `aaaa7da9656255020f792873f929b2950f57c848` are byte-identical.
  Each reaches the 256-row cap, is 623,886 bytes, and has SHA-256
  `3946b2f1327f59f5e3d822e9f2d34326ff4c17b8c4333b8ae2b4ccf66a80a79a`.
  Exactly one row retains the embedded-body shape, official Annotated and Body
  bindings, Pydantic model/string field, relative model and command-wrapper
  imports, `payload.name`, `shell=True`, and CWE-78; the `ClassVar` control is
  absent. The 21,463,040-byte source archive has SHA-256
  `581b0843e07cb47fc00e7bd56bdd57d0ac560314037c3906fa3e5c03c714192a`.
- All eleven hosted workflow families pass exact implementation checkpoint
  `aaaa7da`: Node `33304028467` (92/92 jobs, including direct, Annotated, and
  embedded pinned FastAPI witnesses), container `33304028423`, Windows GUI
  `33304028430`, Linux GUI `33304028341`, Java `33304028398`, Kotlin
  `33304028417`, .NET `33304028345`, Go `33304028355`, Rust `33304028342`,
  Ruby `33304028407`, and PHP `33304028395`. The repository remains public on
  default branch `main`.
- Closed the documented FastAPI `Annotated[Model, Body()]` request-body gap.
  Exact official `typing` or `typing_extensions.Annotated` and `fastapi` or
  `fastapi.params.Body` bindings now preserve the selected Pydantic string
  field through same-file, relative-wrapper, and bounded multi-hop Python sink
  models. Direct, aliased, and module-qualified forms are covered.
- Kept the new boundary fail closed: query and dependency metadata, extra
  metadata, `Body` arguments, defaults, missing or ambiguous imports, binding
  replacement, repository-local `typing`, `typing_extensions`, or `fastapi`
  shadows, and lookalike helpers do not qualify. Structured evidence records
  both the official `Annotated` and `Body` bindings, and quality closure must
  name the exact annotated body boundary.
- Added a real pinned TestClient exploit/control pair, 14 new adversarial
  metadata/binding negatives, hosted witness coverage, and direct corpus
  assertions. The canonical corpus advances to 188 exploit/control pairs, 376
  cases, and 1,128 repeated scan positions; the focused Python relative-import
  corpus advances to 16 cases split evenly between positives and controls.
- Local acceptance closes with 2,082 passes, 31 intentional skips, and two
  managed-sandbox permission denials across 2,115 tests and 16,413 assertions;
  the two denied Git/Windows-ACL cases pass in a 48-test, 242-assertion native
  rerun, yielding 2,084 passing outcomes and no product failures. Ubuntu/WSL
  passes all 51 focused tests and 3,040 assertions. The pinned TestClient
  witnesses record temporary-marker values `1` and `0`.
- The validated npm archive contains 299 entries, is 2,445,031 bytes, and has
  SHA-256
  `3844c3da3bfeced90836d8f8a0578b43969e9860f6c370ce56a566018d573d8a`.
  Strict archive inspection plus isolated Windows and Ubuntu installations
  validate the public import, CLI, and all 79 bundled plugin files. Generated-
  model drift, formatting, TypeScript checking, the production build, and the
  production advisory audit are clean.
- Two compiled inventories of the immutable 3,918-file implementation archive
  at checkpoint `1cdf97a70e90406e716d9803ae9992808d70b2b0` are byte-
  identical. Each reaches the 256-row cap, is 621,677 bytes, and has SHA-256
  `f9510f76d4c995bde2475b0b6dcdec7e290514a39fe720d7f195c09b81006ac6`.
  Exactly one row retains the official Annotated and Body bindings, Pydantic
  model/string field, relative model and command-wrapper imports,
  `payload.name`, `shell=True`, and CWE-78; the `ClassVar` control is absent.
  The 21,411,840-byte source archive has SHA-256
  `1e78ed3131ac85e2087206d57e487d8cfd0818fd9db2bbf93a01b5397b102199`.
- All eleven hosted workflow families pass exact implementation checkpoint
  `1cdf97a`: Node `33300495470` (92/92 jobs, including the direct-and-Annotated
  pinned FastAPI witness), container `33300495506`, Windows GUI `33300495473`,
  Linux GUI `33300495462`, Java `33300495474`, Kotlin `33300495471`, .NET
  `33300495417`, Go `33300495421`, Rust `33300495502`, Ruby `33300495493`, and
  PHP `33300495456`. The repository remains public on default branch `main`.
- Closed a reproduced FastAPI/Pydantic request-body command-injection false
  negative. An exact JSON body field on a `pydantic.BaseModel` now crosses a
  same-file, relative-wrapper, or bounded multi-hop Python flow into shell
  grammar as a structured `python-web-command` row. The topology-matched
  control selects a `ClassVar` that Pydantic excludes from request-body fields
  and emits no structured row.
- Added a fail-closed FastAPI/Pydantic boundary: exact non-shadowed
  `FastAPI`/`APIRouter` factories; POST, PUT, PATCH, or DELETE route decorators;
  direct model-typed body parameters; exact stable `BaseModel` identity; and
  one selected declared `str` or optional-`str` field. GET routes, dependency
  or query injection, arbitrary or multiply inherited classes, methods,
  validators, model configuration, dynamic `Field` declarations, private,
  non-string, or `ClassVar` fields, local module shadows, reassignment,
  mutation, whole-model escape, dynamic `getattr`, multiple selected fields,
  and models above the 64-field/128-line cap fail closed.
- Added an executable FastAPI TestClient exploit/control pair and a dedicated
  adversarial regression matrix. Reviewer closure now requires the official
  request-body route, exact Pydantic model and field, stable parameter,
  wrapper path, shell boundary, CWE-78, and the absence of `ClassVar`,
  validator, mutation, or escape confusion. The canonical corpus advances to
  187 exploit/control pairs, 374 cases, and 1,122 repeated scan positions.
- Completed the authoritative native Windows suite with 2,081 passes, 31
  intentional platform/environment skips, zero failures, and 16,369 assertions
  across 2,112 tests and 215 files in 836.43 seconds. The focused Ubuntu/WSL
  lane passes all 30 tests and 357 assertions; the real pinned TestClient
  witnesses independently record temporary-marker values `1` and `0`.
  Formatting, generated-model drift, TypeScript checking, the production
  build, and the high-severity production advisory audit are clean.
- The validated npm archive contains 299 entries, is 2,443,615 bytes, and has
  SHA-256
  `17fa925b4dc738bf2c22100257dfeb36aebcb9a307b31b0c997ba9d66309922e`.
  Strict archive inspection plus isolated Windows and Ubuntu installations
  validate the public import, CLI, and all 79 bundled plugin files.
- Two compiled inventories of the immutable 3,904-file implementation archive
  at checkpoint `5d604c2e89de130396277794d9d494b128dfa7b0` are byte-identical.
  Each reaches the 256-row cap, is 619,632 bytes, and has SHA-256
  `2f2da111999e27600df6f31b10ec56f78650a3db6ad1c0b3ade62c4a6ad7888e`.
  Exactly one row records the new FastAPI route, Pydantic model/string field,
  relative model and wrapper imports, `payload.name` read, `shell=True` sink,
  and CWE-78; the `ClassVar` control is absent. The 21,360,640-byte exact-
  commit archive has SHA-256
  `53b7e2babae6bf709919761632c9526627fc2d2794b6c32919d4717a82c75623`.
- All eleven hosted workflow families pass exact implementation checkpoint
  `5d604c2`: Node `33297071160` (92/92 jobs, including the new pinned FastAPI
  witness), container `33297071141`, Windows GUI `33297071172`, Linux GUI
  `33297071161`, Java `33297071144`, Kotlin `33297071164`, .NET
  `33297071157`, Go `33297071128`, Rust `33297071134`, Ruby `33297071139`,
  and PHP `33297071189`. The repository remains public on default branch
  `main`.
- Closed a reproduced Python cross-file command-injection false negative where
  a Flask request crossed a relative wrapper, entered a declared field of a
  standard-library generated dataclass, was selected through dot or
  constant-name `getattr`, and reached `subprocess.run(..., shell=True)`. The
  pre-change production inventory emitted only lexical process leads; the
  rebuilt scanner emits exactly one structured `python-web-command` row for
  the vulnerable fixture and none for its same-object, different-field control.
- Added a bounded generated-dataclass field model without broadening arbitrary
  Python objects. The accepted shape requires one exact, non-shadowed
  `dataclasses.dataclass` decorator; one field-only class with 1–64 unique,
  ordinary annotated fields and no bases, defaults, methods, or additional
  decorators; and complete, exact keyword construction. Receiver-sensitive,
  field-sensitive, last-write-wins state supports constructor fields, direct
  assignment, constant-name `setattr`, dot selection, and constant-name
  `getattr`. Positional, incomplete, duplicate, or unknown arguments;
  `ClassVar`, `InitVar`, `KW_ONLY`, defaults, inheritance, configured or frozen
  decorators, local-module shadowing, class replacement or monkeypatching,
  undeclared fields, alias or helper escape, dynamic names, ambiguous writes,
  and later safe overwrite fail closed.
- Hardened the existing `SimpleNamespace` identity check so a repository-local
  `types.py` or `types/__init__.py` cannot masquerade as the standard-library
  module. Reviewer guidance now requires exact generated-dataclass evidence and
  explicitly rejects Pysa-style whole-object broadening as proof of a selected
  field.
- Added an executable dataclass exploit/control pair, bringing the canonical
  corpus to 186 pairs, 372 cases, and 1,116 repeated scan positions. Both
  fixtures retain the Flask source, relative import, declared dataclass fields,
  complete keyword construction, local selection, hostile bytes, and real
  shell sink. Only the positive writes those bytes to `command.value`; the
  control writes them to `command.audit`. Ubuntu/WSL witnesses record temporary
  marker values `1` and `0`. The focused Windows lane passes 112 tests and
  3,983 assertions with three intentional platform/permission skips; the same
  four-file lane passes all 115 tests and 4,002 assertions on Ubuntu/WSL.
- Completed the authoritative native Windows suite with 2,076 passes, 31
  intentional platform/environment skips, zero failures, and 16,306 assertions
  across 2,107 tests and 214 files in 807.87 seconds. Formatting,
  generated-model drift, TypeScript checking, the clean production build, and
  the high-severity production advisory audit are green with no known
  vulnerabilities.
- The validated npm archive contains 299 entries, is 2,399,022 bytes, and has
  SHA-256
  `03bdc619615d52d514892dc44b7d396f3e15e75044894f36924882687ffc50b1`.
  Strict archive inspection plus isolated Windows and Ubuntu installations
  validate the public import, CLI, and all 79 bundled plugin files.
- Two compiled inventories of the 3,889-file tracked-only archive at exact
  implementation checkpoint
  `c4c9b24da1f15f66c1d7395660d23047192a88a3` complete in 21,215.379 and
  19,817.632 milliseconds. Both reach the 256-row cap, are byte-identical at
  618,138 bytes, and have SHA-256
  `db1b4ad1e074059e8d0fb3017c4f8930ab4a430adda0395dab43646a4f7ee848`.
  Exactly one row retains the new fixture's Flask source at `server.py:10`,
  relative wrapper chain, `python-dataclass-attribute-assignment` for
  `command.value` at `runner.py:13`, shell sink at line 15, and CWE-78; the
  topology-matched safe control is absent. The 5,822,526-byte exact-commit
  archive has SHA-256
  `21a211de40a828c4897368742bff637d55b39dba483309738d3f4ba866825a51`.
- All eleven hosted workflow families pass exact implementation checkpoint
  `c4c9b24`: Node `33292707290` (91/91 jobs), container `33292707267`, Windows
  GUI `33292707315`, Linux GUI `33292707279`, Java `33292707281`, Kotlin
  `33292707303`, .NET `33292707309`, Go `33292707280`, Rust `33292707291`, Ruby
  `33292707277`, and PHP `33292707345`. The repository remains public on
  default branch `main`; disposable package and exact-commit self-scan
  artifacts are removed.
- Closed a reproduced Python cross-file command-injection false negative where
  a Flask request crossed a relative wrapper, was written to a fresh
  `types.SimpleNamespace` field, selected through dot or constant-name
  `getattr`, and passed to `subprocess.run(..., shell=True)`. Before this
  increment the compiled scanner emitted only a generic lexical process lead;
  it now emits one structured `python-web-command` row with the exact request,
  wrapper, field write, selected receiver and field, sink, and CWE-78.
- Added bounded, receiver-sensitive field state for the exact standard-library
  `SimpleNamespace` binding. Empty and keyword constructors, direct attribute
  assignment, and constant-name `setattr` are modeled with last-write-wins
  semantics across at most 64 fields and 64 transitions. Positional mappings,
  arbitrary classes, dynamic or special fields, unknown methods, augmented,
  annotated, deleted, tuple, or ambiguous writes, receiver replacement with an
  unknown object, binding or parameter reassignment, and alias/helper escape
  fail closed. A value in another receiver or field, or one removed by a later
  safe overwrite, cannot taint the selected field.
- Added a permanent executable object-field exploit/control pair and strict
  validation and attack-path requirements. Both fixtures retain the Flask
  source, relative import, fresh namespace, hostile bytes, field operations,
  and real shell sink; only the positive selects the hostile `command.value`.
  Ubuntu/WSL records temporary-marker values `1` and `0`. The focused Windows
  lane passes 39 tests and 2,845 assertions with one intentional POSIX witness
  skip; Ubuntu/WSL passes the Python, canonical, inventory, and fixed-count lane
  with 112 tests and 3,934 assertions and no failures. The canonical corpus now
  contains 185 pairs, 370 cases, and 1,110 repeated scan positions.
- Completed the authoritative native Windows suite with 2,073 passes, 31
  intentional platform/environment skips, zero failures, and 16,240 assertions
  across 2,104 tests and 214 files in 815.13 seconds. The managed-sandbox run
  was stopped after its known Git-fixture child-process access denial; the
  correctly permissioned complete run passed that test and every later test.
  Formatting, generated-model drift, TypeScript, the clean production build,
  and the high-severity production advisory audit are green with no known
  vulnerabilities.
- The validated npm archive contains 299 entries, is 2,394,366 bytes, and has
  SHA-256
  `368f18557abc9910b76dbe55f50517bf07707810836fb755c8cd2308a2c45a77`.
  Strict archive inspection plus isolated Windows and Ubuntu installations
  validate the public import, CLI, and all 79 bundled plugin files.
- Two compiled inventories of the 3,877-file tracked-only archive at exact
  implementation checkpoint
  `431fcb17806541a3f425b3981e3c4a9eb765ff15` complete in 20,223.153 and
  20,510.579 milliseconds. Both reach the 256-row cap, are byte-identical at
  617,628 bytes, and have SHA-256
  `7dcd21d77c337b3f2bdc32c55a8e7c8772e770f1eeca37c423a92f0808934cd4`.
  Exactly one row retains the new fixture's Flask source at `server.py:10`,
  relative wrapper chain, `python-object-attribute-assignment` for
  `command.value` at `runner.py:7`, shell sink at line 9, and CWE-78; the
  topology-matched safe control is absent. The disposable tree and archive are
  removed.
- All eleven hosted workflow families pass exact implementation checkpoint
  `431fcb1`: Node `33288798187` (91/91 jobs), container `33288798141`, Windows
  GUI `33288798229`, Linux GUI `33288798154`, Java `33288798298`, Kotlin
  `33288798205`, .NET `33288798134`, Go `33288798164`, Rust `33288798150`, Ruby
  `33288798184`, and PHP `33288798139`. The repository remains public on
  default branch `main`.
- Closed a reproduced Python cross-file command-injection false negative where
  a Flask request value was stored under a constant dictionary key and later
  selected through bracket, `get`, or `pop` syntax as the command passed to
  `subprocess.run(..., shell=True)`. The bounded host model reconstructs exact
  dictionary literals and empty `dict()`, direct constant-key assignments,
  literal `dict.update`, Python 3.9 `|=`, and `setdefault`, including duplicate
  and later-write semantics across at most 64 keys and 64 transitions.
- Improved mapping precision beyond container-wide taint. A row is retained
  only when the wrapper parameter reaches the exact constant key selected by
  the shell sink after bounded value and sink-alias resolution. Direct
  assignment, update, and `|=` overwrite; `setdefault` preserves an existing
  key. Dynamic or escaped keys, comprehensions, unpacking, keyword-form dict
  construction, nonliteral updates, unknown methods, helper or alias escape,
  pre-storage parameter reassignment, and ambiguous mutations fail closed.
  Comments and strings are structurally inert, and hostile data in an
  unselected or subsequently overwritten value does not taint another key.
- Added a permanent executable `dict.update` exploit/control pair. Both retain
  the Flask source, relative wrapper, dictionary update, hostile bytes, and a
  real `shell=True` sink. The exploit overwrites and selects `preview`; the
  control updates only `audit` and selects a fixed `preview`. Ubuntu/WSL records
  temporary-marker values `1` and `0`, respectively. The focused Python,
  canonical, and fixed-count lane passes 36 tests with 2,781 assertions and one
  intentional Windows POSIX-witness skip; native Ubuntu/WSL passes the widened
  Python, canonical, residual-risk, and fixed-count lane with 109 tests, 3,866
  assertions, and no skips. The canonical corpus now contains 184 pairs, 368
  cases, and 1,104 repeated positions.
- Completed the authoritative Windows acceptance pass with 2,070 tests and
  16,176 assertions passing across 214 files in 783.71 seconds, 31 intentional
  platform/environment skips, and zero failures. An initial direct Bun run used
  Bun's 5-second default instead of the repository's 30-second test harness and
  also preceded the production rebuild; its seven failures all pass after the
  clean build under the authoritative harness, including 24 isolated tests and
  192 assertions. No deadline or assertion was weakened.
- Formatting, generated-model drift, TypeScript, the clean production build,
  and the high-severity production advisory audit pass with no known
  vulnerabilities. The validated npm archive has 299 entries, is 2,386,490
  bytes, and has SHA-256
  `3990be977a24eea2e74cdc673b25b3cfe2754b85212666be2fd45558ea97590f`.
  Isolated Windows and Ubuntu installations validate the public import, CLI,
  and all 79 bundled plugin files.
- Two independent compiled inventories of the 3,865-file tracked-only archive
  at exact implementation checkpoint
  `2edc0571ab3a9a6b84e1082a293589f802afc39d` are byte-identical at the
  256-row cap: 617,203 bytes and SHA-256
  `52dfb19047df358ddb722d67aecd43fecc844fb5db4dd21c54a1a78709c9dd3c`.
  Exactly one row retains the new fixture's Flask request source, relative
  wrapper call, `python-dict-update-element` for `commands["preview"]`, final
  `shell=True` sink, and CWE-78; the topology-matched safe control is absent.
- All eleven hosted workflow families pass exact implementation checkpoint
  `2edc057`: Node `33284772599` (91/91 jobs), container `33284772628`, Windows
  GUI `33284772603`, Linux GUI `33284772594`, Java `33284772577`, Kotlin
  `33284772659`, .NET `33284772649`, Go `33284772597`, Rust `33284772625`,
  Ruby `33284772672`, and PHP `33284772634`.
- Closed a reproduced Python cross-file command-injection false negative where
  a Flask request value entered an initially empty list through `append`,
  `extend`, `insert`, or `+=` and only the selected indexed element later
  reached `subprocess.run(..., shell=True)`. The host now records the exact
  mutation and selected index as a typed propagator while rejecting dynamic
  indexes, nonempty or unknown collections, wrong-element flows, parameter or
  collection reassignment, later mutation, comments, strings, and literal argv
  with `shell=False`.
- Improved beyond the collection flow added by CodeQL's August 2026
  [Python list-content repair](https://github.com/github/codeql/pull/22310):
  that change added `extend` and `insert` beside existing `append` coverage and
  explicitly retained `+=` as an unresolved limitation. Copilot Security models
  bounded literal `+=` as well, and requires validation and attack-path fields
  to name the list operation, constant selected element, exact shell boundary,
  and absence of an intervening overwrite.
- Added a topology-matched executable exploit/control pair. Both fixtures keep
  the Flask source, relative import, hostile payload, empty-list initialization,
  and `+=`; the positive selects `commands[0]` as a shell string while the
  control passes the same value only as literal argv to fixed `printf` with
  `shell=False`. Ubuntu/WSL proves marker creation only on the vulnerable side.
  The focused model and canonical lanes pass 32 tests and 2,717 assertions on
  Windows with the one intentional POSIX witness skip. The canonical corpus now
  contains 183 pairs, 366 cases, and 1,098 repeated positions.
- Completed the authoritative Windows acceptance pass with 2,066 tests and
  16,112 assertions passing across 214 files in 785.00 seconds, 31 intentional
  platform/environment skips, and zero failures. The first aggregate run
  exposed an unrelated native format-string executable killed at its old
  10-second deadline under load; it passed alone in 2.36 seconds, so the
  executable allowance is now 30 seconds and the enclosing test allowance 180
  seconds. The complete rerun passes, while retaining the same exit-status and
  output assertions. Ubuntu/WSL passes all 105 applicable Python list-flow,
  canonical-corpus, residual-risk, and Tokio tests with 3,798 assertions and no
  skips, including the live exploit/control differential.
- Formatting, generated-model drift, TypeScript, and the clean production build
  pass. Windows and Ubuntu validate the same 299-entry, 2,413,314-byte npm
  archive with SHA-256
  `1cf828978a95528162dd1cac450bfb50b843937b586037d8fb5a43cc1b151b4f`
  through isolated installation, public import, CLI execution, and all 79
  bundled plugin files. The production dependency audit reports no known
  vulnerabilities. Independent compiled self-inventories of a disposable
  tracked-only archive at exact implementation checkpoint
  `40ab9a7f20963952f17b190a7e95dc1aca7952f6` are byte-identical at the 256-row
  cap: 616,777 bytes and SHA-256
  `9e48bfd1fb0e53b8b7f018765b41fc79c7a435ca87e478be5afef864ecc51fc4`.
- All eleven hosted workflow families pass exact implementation checkpoint
  `40ab9a7`: Node `33280747436` (91/91 jobs), container `33280747437`, Windows
  GUI `33280747410`, Linux GUI `33280747448`, Java `33280747520`, Kotlin
  `33280747415`, .NET `33280747488`, Go `33280747455`, Rust `33280747399`,
  Ruby `33280747406`, and PHP `33280747456`.
- Closed the remaining scan-relevant filesystem swallow found by a
  repository-wide ingestion audit. External SARIF enrichment now treats only
  an exact `ENOENT` as an expected stale/deleted artifact location. Permission,
  device, and transient metadata failures raise a path-specific
  `SourceDiscoveryError` instead of silently discarding an analyzer seed and
  making reduced coverage look clean.
- Preserved interoperability for SARIF produced against a changing checkout:
  a genuinely absent referenced file remains an ignored result, while an
  unobservable file fails the scan as incomplete. The cross-platform control
  adds an absent location beside a valid seed; an unprivileged Ubuntu/WSL
  fault-injection test removes traversal permission from a referenced source
  directory and verifies the typed `inspect` failure. The focused Windows lane
  passes 10 tests with two intentional platform skips and the Linux lane passes
  all 12 tests with 35 assertions.
- Completed the authoritative Windows acceptance pass with 2,062 tests and
  16,056 assertions passing across 214 files in 713.50 seconds, 30 intentional
  platform/environment skips, and zero failures. A restricted-sandbox pass
  separately confirmed 2,060 tests before its two expected owner/profile
  constraints; both pass in the authoritative real-user lane. The release
  archive retains 299 entries, validates isolated public import, CLI execution,
  and all 79 bundled plugin files, and is 2,376,862 bytes with SHA-256
  `8e417b502778c6b52e886c9d2cece6b312ae9eb4740a49053f7b85f27fe8c4c3`.
  The production dependency audit reports no known vulnerabilities.
- Two independent compiled inventories of a tracked-only archive at exact
  implementation checkpoint `6268852fdfc1895f9a0233e5bbe4409284585913`
  are byte-identical at the 256-row cap: 616,394 bytes and SHA-256
  `340f05b263eb3ae24dc72935ae50a397ea121f96e47b029e1bdf82347560a971`.
  This intentionally matches the preceding saturated whole-repository result:
  SARIF ingestion code and regressions do not enter production-path model
  candidates.
- All eleven hosted workflow families pass exact implementation checkpoint
  `6268852`: Node `33276634454` (91/91 jobs), container `33276634445`, Windows
  GUI `33276634450`, Linux GUI `33276634443`, Java `33276634447`, Kotlin
  `33276634462`, .NET `33276634451`, Go `33276634440`, Rust `33276634442`,
  Ruby `33276634455`, and PHP `33276634471`.
- Closed a clean-looking partial-scan failure mode in deterministic source
  discovery. Repository directory enumeration and reads of selected source
  files now fail closed with a bounded, path-specific incomplete-scan error
  instead of silently producing an empty or reduced residual-risk inventory.
  Missing selected current-tree secret-scanning inputs and enumeration,
  metadata, canonicalization, or read failures likewise remain fatal through
  the existing secret-scanner boundary. An exact path already absent when a
  positive Git-history scan starts remains eligible as history-only input; a
  file that disappears after inspection still fails closed. Intentional exclusions for symlinks,
  non-files, oversized files, generated trees, binary data, and out-of-root
  canonical paths remain unchanged.
- Preserved source-discovery incompleteness through both orchestration swallow
  points: the optional residual-inventory fallback may still tolerate an
  unrelated model-building failure, but never a `SourceDiscoveryError`, and a
  correction turn may no longer treat that error as recoverable merely because
  draft artifacts exist. Operations are classified as `enumerate`, `inspect`,
  `canonicalize`, or `read`; repository-controlled path text is normalized,
  JSON-delimited, and capped at 512 code points in the error message.
- Reproduced the old behavior under an unprivileged Ubuntu/WSL account: a
  mode-`000` source directory containing a valid modeled sink completed with
  zero bytes and zero rows. The revised scanner instead rejects incomplete
  coverage, and the Linux-only residual and secret regressions pass alongside
  missing-selected-file, Unicode-source, and orchestration propagation tests.
- Audited this boundary after CodeQL's August 2026
  [silent Python file-loss repair](https://github.com/github/codeql/pull/22443).
  Copilot Security does not use that Rust/Python escape bridge, but now carries
  a strict source-retention pair containing Python 3.12 PEP 695 syntax, a
  variation selector, `%s`, zero-width joiner, combining mark, and soft hyphen.
  The vulnerable FastAPI-to-asyncpg fixture emits one exact SQL-grammar edge at
  `src/accounts.py:11`; its otherwise identical `$1` bound-parameter control
  emits none. The canonical benchmark advances to 182 pairs, 364 cases, and
  1,092 repeated positions.
- Completed the authoritative source-completeness acceptance pass at exact
  implementation checkpoint `799e50e40948e17b3d2cf5d4110b190760df7bb0`.
  The real-user Windows suite passes 2,062 tests and 16,056 assertions across
  214 files in 788.29 seconds, with 29 intentional platform/environment skips
  and zero failures. The Linux-applicable residual, secret, history, asyncpg,
  canonical, and Tokio lane passes all 119 tests and 3,835 assertions,
  including both mode-`000` regressions.
- Two independent compiled inventories of a tracked-only exact-head archive
  are byte-identical at the 256-row cap: 616,394 bytes and SHA-256
  `340f05b263eb3ae24dc72935ae50a397ea121f96e47b029e1bdf82347560a971`.
  Windows and Ubuntu validate the same 299-entry, 2,408,542-byte npm archive
  with SHA-256
  `ce8fe898c2ad09744e4cb67e39c50597c4d97f3cd2716c933ec6c38abf6474b9`
  through strict inspection, isolated installation, public import, CLI
  execution, and all 79 bundled plugin files. The production advisory audit
  reports no known vulnerabilities.
- All eleven hosted workflow families pass exact implementation checkpoint
  `799e50e`: Node `33272818126`, container `33272818116`, Windows GUI
  `33272818154`, Linux GUI `33272818132`, Java `33272818106`, Kotlin
  `33272818145`, .NET `33272818110`, Go `33272818115`, Rust `33272818118`,
  Ruby `33272818138`, and PHP `33272818107`. All 91 Node jobs pass.
- Extended the exact Rust web command model from `std::process::Command` to
  current `tokio::process::Command`. Direct, aliased, grouped, nested-grouped,
  module-qualified, and fully qualified Tokio bindings now retain the runtime
  identity through chained or assigned builders and exact `arg`/`args` state
  into `spawn`, `status`, or `output`. Local `tokio` modules, foreign crates
  aliased as `tokio`, unavailable Tokio `exec`, inert builders, and ordinary
  fixed-executable argv remain negative.
- Improved on CodeQL's merged August 2026 Rust command-injection model rather
  than copying its broad sink map. CodeQL marks `Command::new`, `arg`, and
  `args` for both runtimes and its tests alert on a remote ordinary `grep`
  argument, even though its help recommends separate arguments to avoid shell
  interpretation. Copilot Security still requires actual process dispatch and
  distinguishes executable selection or shell/interpreter/batch/raw grammar
  from literal argv. It also records Tokio's current implementation detail:
  `status()` and `output()` call `spawn()` before returning their Future, so a
  missing `await` is not treated as execution prevention.
- Added a strict Tokio 1.53.1 Axum exploit/control pair with Cargo-v3 locks
  compatible with Rust/Cargo 1.75. The positive formats the query value into
  `sh -c`; the identical control passes it as one argument to fixed `printf`.
  Both Windows compilation and the Ubuntu/WSL marker differential pass, the
  previous compiled scanner emits zero Tokio rows, and the new host emits one
  exact line-15 positive with no control row. The focused Rust and canonical
  lanes pass 43 tests and 2,756 assertions. The canonical benchmark advances
  to 181 pairs, 362 cases, and 1,086 repeated positions.
- Completed the authoritative Tokio acceptance pass. The full Windows suite
  passes 2,056 tests and 16,010 assertions across 214 files, with 27 intentional
  platform/environment skips and zero failures. Ubuntu/WSL passes all 113
  selected Rust, framework, residual-risk, and canonical tests with 3,834
  assertions. An initial aggregate run exposed an older asyncpg test that
  assumed its pair would remain last forever; its canonical registration check
  is now ID-located and append-safe. Hosted Windows Node 22 then exposed two
  fixture assertions that compared raw LF text after a CRLF checkout; all text
  fixtures in that test now pass through explicit newline normalization.
- Two inventories of exact corrective checkpoint `d11a5f4` are byte-identical
  at 256 structured rows, 615,647 bytes, and SHA-256
  `d32e6e93637c5cb540d1f7bdbca088f7eb5431959ffb6b761d14efed04e21b3c`.
  The saturated whole-repository inventory is unchanged, as expected because
  production-path filtering excludes benchmark fixtures. A separate exact
  fixture-root scan emits one line-15 Tokio shell row with source, formatting,
  execution, and CWE-78/CWE-88 evidence; the literal-argv control emits none.
- Windows and WSL validate the same Linux-generated 299-entry,
  2,374,484-byte package with SHA-256
  `95a7c9b5440ddb8caec3cc4ec8fc6932278c7e88429887194bc50ef071b18ed7`
  through strict archive inspection, isolated installation, public import,
  CLI execution, and all 79 bundled plugin files. Repacking exact corrective
  head `d11a5f4` is byte-identical. Formatting, generated-model drift,
  TypeScript, the clean build, and the production high-severity audit pass.
- All eleven hosted workflow families pass exact corrective checkpoint
  `d11a5f4`: Node `33267512070`, container `33267511996`, Windows GUI
  `33267512065`, Linux GUI `33267512152`, Java `33267512074`, Kotlin
  `33267512035`, .NET `33267512055`, Go `33267512013`, Rust `33267512063`,
  Ruby `33267512059`, and PHP `33267512079`. All 91 Node jobs pass. The Rust
  family runs both the prior synchronous witness and the locked Tokio compile
  and marker-differential job.
- Added execution-aware Python `asyncpg` SQL-injection discovery for every
  query-bearing current API boundary: `copy_from_query`, `cursor`, `execute`,
  `executemany`, `fetch`, `fetchmany`, `fetchrow`, `fetchval`, and `prepare`.
  The model requires a live official `Connection` or compatible `Pool`, exact
  grammar-bearing query/command argument, and `await` or async cursor
  consumption. It follows copied query variables, direct or aliased
  `connect`/`create_pool` factories, acquired connections, context managers,
  FastAPI `Annotated` parameters, and one- or two-relay Python wrappers.
- Closed false-positive paths beyond the pending Semgrep asyncpg taint-rule
  repair: later protocol-bound values, unawaited coroutine creation, invalid
  Pool `cursor`/`prepare` calls, local modules and lookalikes, reassigned
  imports/factory/method/receiver bindings, starred or malformed calls, and
  fixed SQL remain negative. The scanner covers the official underscored
  `copy_from_query` spelling and `fetchmany`, neither covered by that comparator
  proposal. Host re-audit now requires source, receiver, argument role,
  execution, PostgreSQL/protocol behavior, `$1` counterevidence, database
  authority, concrete impact, and CWE-89 in both validation and attack path.
- Added a perfect-gate asyncpg exploit/control benchmark. The prior compiled
  scanner emits zero specialized rows; the new model emits one exact
  FastAPI-to-copied-query-to-awaited-`Connection.fetch` row at
  `src/accounts.py:11` and none for its topology-matched `$1` control. Identical
  socket-free witnesses prove only first-query-argument mutation versus later
  protocol-value separation and explicitly do not claim a PostgreSQL exploit.
  The focused lane passes 9 tests and 37 assertions on Windows. The canonical
  benchmark advances to 180 pairs, 360 cases, and 1,080 repeated positions.
- Two inventories of exact asyncpg implementation checkpoint
  `c1028fa88c24709b2e5be16d62498d06a5133055` are byte-identical at 256
  structured rows, 615,647 bytes, and SHA-256
  `d32e6e93637c5cb540d1f7bdbca088f7eb5431959ffb6b761d14efed04e21b3c`.
  Exactly one asyncpg row identifies the vulnerable fixture at line 11 and the
  bound control remains absent from the saturated whole-repository inventory.
- The widened Windows model lane passes 177 tests and 3,407 assertions with
  seven expected symlink skips; WSL passes all 33 selected tests with 2,656
  assertions and both Python witnesses. The complete managed Windows suite
  selects 2,073 tests: 2,044 pass, 27 intentionally skip, and only the two
  established temporary-Git and private-home ACL operations are denied by the
  sandbox. The exact two affected files pass unchanged outside that boundary:
  48 tests and 242 assertions. Formatting, generated-model drift, TypeScript,
  the clean build, and the production dependency audit are green.
- Windows and WSL both validate the same Linux-generated 299-entry,
  2,372,709-byte package with SHA-256
  `03552a8d7f93d41905b4f7a2e17ce22924245ca5668f25c74de3c0d87839995b`
  through isolated installation, public import, CLI execution, and all 79
  bundled plugin files; the generated archive is removed afterward.
- Corrected the canonical paired-fixture list formatting after every hosted
  core platform completed its tests but rejected the same unformatted
  `benchmark.test.ts` block. The Prettier-only change retains all 18 benchmark
  tests and 2,556 assertions; generated-model drift, TypeScript, and the clean
  build pass again before the corrective checkpoint.
- All eleven hosted workflow families pass corrective checkpoint `5289134`:
  Node `33261879992`, container `33261880000`, Windows GUI `33261879987`,
  Linux GUI `33261880049`, Java `33261879990`, Kotlin `33261879983`, .NET
  `33261880036`, Go `33261880017`, Rust `33261880105`, Ruby `33261879965`,
  and PHP `33261880064`. All 91 Node jobs pass; every core Windows, macOS, and
  Ubuntu job passes formatting, build, package inspection, and isolated CLI
  smoke after its complete scanner suite.
- Added a lower-level Java R2DBC SPI SQL model for all six official grammar
  boundaries: `Connection.createStatement`, `Batch.add`, the three
  savepoint-name operations, and `Statement.returnGeneratedValues`. Exact
  `io.r2dbc.spi` receiver proof, argument arity, fluent or assigned execution,
  and returned/subscribed Publisher evidence replace name-only matching.
- Closed realistic Java shapes beyond the comparator signature pack. The host
  distinguishes `Statement.add()` from `Batch.add(String)`, sees fluent
  `Connection.createBatch().add(...).execute()` and
  `createStatement(...).returnGeneratedValues(...).execute()` chains, retains
  multiple grammar boundaries on one line, follows local SQL variables, and
  resolves constructor-initialized final SPI fields without confusing an
  out-of-scope constructor parameter for the live receiver. Local/competing
  types, wrong arity, inert operations, mutable reassignment, unconsumed
  savepoint Publishers, and fixed SQL with request data only in `bind` remain
  negative.
- Added a strict executable R2DBC SPI exploit/control pair. The prior compiled
  scanner emits zero specialized rows for both fixtures; the new scanner emits
  one exact CWE-89 controller-to-`Connection.createStatement` path at line 17
  and none for the bound twin. Both Java 21/H2 R2DBC witnesses pass under WSL,
  proving the positive reads the seeded administrator row and the identical
  bound payload returns no row. The canonical benchmark advances to 179 pairs,
  358 cases, and 1,074 repeated positions.
- Exact-checkpoint self-review of
  `172fd2110e9a55673fd0c126d67fd16d922e605d` is byte-identical across two
  runs at 256 structured rows, 615,203 bytes, and SHA-256
  `6516fc7896cedbeb84d63fb10380031d972da1bc3ee32fe2452b5c8baa5a50b5`.
  The new SPI exploit survives the global cap with its exact sink and the bound
  control remains absent. The widened Windows lane passes 129 tests with 3,790
  assertions and one expected symlink skip; WSL passes all 62 selected tests
  with 2,727 assertions, including the known 101.6-second `/mnt/c`
  whole-repository saturation check.
- Formatting, generated-model drift, TypeScript, the clean build, both Maven
  witnesses, and the production dependency audit pass. Windows and WSL both
  validate the same Linux-generated 299-entry, 2,362,017-byte package with
  SHA-256
  `9e97dcf6ab3c50d412173eaf86effb16e9578facfbbed30c3f2a2f8b1bd361f1`
  through isolated installation, public import, CLI execution, and all 79
  bundled plugin files; the generated archive is removed afterward.
- All eleven hosted workflow families pass for the exact implementation
  checkpoint: Node `33256439091`, container `33256439137`, Windows GUI
  `33256439233`, Linux GUI `33256439131`, Java `33256439112`, Kotlin
  `33256439138`, .NET `33256439103`, Go `33256439099`, Rust `33256439243`,
  Ruby `33256439205`, and PHP `33256439093`. All 91 Node jobs pass, including
  complete suites and package validation on Windows, macOS, and the supported
  Ubuntu Node matrix.
- Added high-confidence Spring R2DBC SQL-injection discovery for the official
  `org.springframework.r2dbc.core.DatabaseClient`. The host traces Spring or
  servlet input only into the `sql` grammar argument, unwraps a simple
  `Supplier<String>` lambda, requires `fetch`, `then`, `map`, `flatMap`,
  `mapValue`, or `mapProperties`, and retains that execution-stage transition
  as structured evidence across same-file, one-wrapper, and two-relay Java
  paths.
- Kept the model fail closed on local or competing `DatabaseClient` types,
  receiver reassignment, wrong arity, malformed Supplier shapes, inert `sql`
  specifications, and request values used only by `bind` or `bindNull`. The
  quality gate separately requires reactive consumption, driver/dialect and
  statement behavior, database authority, tenant/object authorization, and a
  concrete read, write, or availability effect before accepting CWE-89.
- Added a real Spring 7.0.8/R2DBC H2 exploit-control pair. The positive changes
  a query predicate and reads the seeded administrator row; the matched control
  passes the identical payload only as a bound value and returns no row. Both
  `mvn verify` witnesses pass under Ubuntu/WSL. The prior compiled scanner emits
  zero specialized rows for both fixtures; the new focused lane passes 8 tests
  and 25 assertions. The canonical benchmark advances to 178 pairs, 356 cases,
  and 1,068 repeated positions.
- Corrected typed Java wrapper resolution after exact-checkpoint self-review
  found that sibling Maven applications with the same simple class name could
  suppress both flows as repository-global ambiguity. Direct and bounded
  multi-hop Java graphs now resolve one owner only within the caller's nearest
  Maven/Gradle project plus exact declared project dependencies. A sibling
  exploit/control regression and a whole-repository cap regression preserve
  the R2DBC positive while excluding the bound control; the affected Windows
  lane passes 107 tests and 2,961 assertions.
- Two inventories of exact repair checkpoint
  `7ae5fd60c318c1a1e40aff5468adeb39f41db9e5` are byte-identical at 256
  structured rows, 614,431 bytes, and SHA-256
  `71bba544bbd1fd4d0fa4cd9069626d568b3392149e0cc3a407de22efe5dc991a`.
  Exactly one row retains the vulnerable R2DBC controller-to-SQL path and the
  bound twin retains none. Windows and WSL each validate the same 299-entry,
  2,384,043-byte package with SHA-256
  `2a01d7868264072b7a22bfcf683dff2756f2892c5552de9b8cb2eddf469f52a7`
  through two fresh installs, public import, CLI execution, and all 79 bundled
  plugin files; the generated archive is removed afterward.
- All eleven hosted workflow families pass at repair checkpoint `7ae5fd6`:
  Node `33252379667`, container `33252379632`, Windows GUI `33252379630`,
  Linux GUI `33252379643`, Java `33252379666`, Kotlin `33252379674`, .NET
  `33252379680`, Go `33252379684`, Rust `33252379668`, Ruby `33252379677`,
  and PHP `33252379651`. All 91 Node jobs pass, including the complete scanner
  suite and package inspection/smoke on Windows, macOS, and supported Node
  releases on Ubuntu.
- Completed pre-checkpoint product acceptance. The managed Windows aggregate
  selects 2,051 tests: 2,022 pass, 27 intentionally skip, and only the two
  established temporary-Git and private-ACL operations are denied; their exact
  native rerun passes 2/2 with seven assertions. The focused Windows and WSL
  lanes each pass 30 tests and 2,578 assertions. Formatting, generated-model
  drift, TypeScript, the clean build, and the production audit pass. Windows
  and Linux each validate the same 299-entry package through a fresh install,
  public import, CLI execution, and all 79 bundled plugin files.
- Closed the routed Sails.js Action2 cross-file false negative measured by the
  new executable fixture: the previous compiled scanner emitted zero Node path
  rows when a declared controller input crossed one relative module call. The
  host now carries that source through one exact exported wrapper or two exact
  relative relays, preserving every import, call argument, parameter, and
  official Node filesystem sink position.
- Tightened Sails source reachability beyond the source-only comparator. A
  controller input is emitted only when an exact custom route targets that
  action or the nearest app has literal `blueprints.actions: true`; the official
  default is false. Direct and object-valued routes plus direct and object-valued
  configuration exports are supported. Missing, false, dynamic, unrelated, or
  ambiguous exposure, helpers, machines, undeclared values, reassignment, and
  fixed complete paths remain negative.
- Added a second strict three-run Sails exploit/control pair. The positive reads
  only a checked-in inert marker through the real wrapper; the topology-matched
  control ignores the same traversal-shaped input and reads a fixed thumbnail.
  The canonical benchmark advances to 177 pairs, 354 cases, and 1,062 repeated
  positions. Four additional Ubuntu/Windows witness jobs expand the expected
  hosted Node matrix to 91 jobs.
- Completed local routed-wrapper acceptance. The focused Windows lane passes 94
  tests and 3,644 assertions with one intentional symlink skip; WSL passes all
  95 tests and 3,645 assertions, and both hosts pass both executable witnesses.
  The managed aggregate selects 2,045 tests: 2,016 pass, 27 intentionally skip,
  and only the two established temporary-Git and private-ACL operations are
  denied; their exact native reruns pass 2/2 with seven assertions. Formatting,
  generated-model drift, TypeScript, the clean build, and the production audit
  pass.
- Two compiled inventories of exact implementation checkpoint
  `c6ff1836041bf0f48d452a60c409e016d3c5f38c` are byte-identical at 256 records,
  587,051 bytes, and SHA-256
  `c416874bd0aaa662344779fcf7fa83368c141f319d4a99bd112ba13654054185`.
  The 245 structured records include exactly the original same-file and new
  wrapper Sails rows; the fixed wrapper emits none. Windows and Linux validate
  the same 299-entry, 2,379,258-byte package with SHA-256
  `20beb699c62923f899cd892a1166157fab2fe001992e42eecc45d35db2048189`,
  fresh public import, CLI execution, and all 79 bundled plugin files.
- All eleven hosted workflow families pass at implementation checkpoint
  `c6ff183`: Node `33247742943`, container `33247742932`, Linux GUI
  `33247742994`, Windows GUI `33247742976`, Go `33247743005`, Java
  `33247742968`, Kotlin `33247742929`, .NET `33247742971`, Rust `33247742962`,
  Ruby `33247742939`, and PHP `33247742977`. All 91 Node jobs pass, including
  the original and wrapper Sails exploit/control witnesses on Ubuntu and
  Windows.
- Closed the Sails.js Action2 request-source false negative for Node filesystem
  paths. Exported action objects under `api/controllers` now treat only reads
  of properties declared by the same object-valued `inputs` block from the
  `fn` handler's first parameter as `sails-action2-declared-input`. The source
  reaches only exact official `node:fs` path positions and retains the existing
  CWE-22 path model, controls, and finding-quality obligations.
- Kept the model fail closed on helper and machine modules, files outside
  `api/controllers`, undeclared or computed input properties, spread or
  ambiguous action objects, multiple exports, unsupported handler shapes,
  and values overwritten before the sink. Direct, assigned-export, ordinary
  parameter, destructured-alias, function-property, arrow-property, bracket,
  multiline, and bounded straight-line propagation forms are covered. Exact
  custom-route or enabled-blueprint evidence is now a deterministic host gate;
  environment overrides and deployed policy remain reviewer obligations.
- Added a strict three-run exploit/control benchmark and executable Windows/
  Linux witnesses. The positive's declared `filename` crosses `path.join` into
  `readFileSync` and reads only a checked-in inert marker outside the thumbnail
  directory. The topology-matched control receives the same traversal-shaped
  value but reads one fixed server-owned thumbnail. The canonical benchmark
  advances to 176 pairs, 352 cases, and 1,056 repeated positions; Node CI adds
  four dedicated Sails witness jobs.
- Completed local Sails acceptance. The focused model and benchmark lane passes
  25 tests with 2,557 assertions on both Windows and native WSL. The managed
  Windows aggregate selects 2,043 tests across 210 files: 2,013 pass and 27
  intentionally skip; its two established Git/ACL sandbox cases pass 48/48
  with native Windows access, and an unrelated candidate-cap stress test that
  timed out under aggregate load passes 8/8 alone in 27.66 seconds. Formatting,
  generated-model drift, TypeScript, the clean build, both executable
  witnesses, and the production advisory audit pass.
- Two compiled repository self-inventories are byte-identical at 256 records,
  585,125 bytes, and SHA-256
  `159f2d148694e8436a673475e9f288b4b2afddef0e9c732c5a8158030f7b678a`;
  exactly one structured Sails Action2 record survives the repository cap.
  Windows and Linux package checks each validate 299 entries, fresh installed
  public import, CLI execution, and all 79 bundled-plugin files. The final
  Linux-native archive is 2,375,997 bytes with SHA-256
  `1a9fbc434a268bf100028d2e8f587ed22ada5a11158b65d06561cc3c92a2eecd`.
- All eleven hosted workflow families pass at Sails implementation checkpoint
  `2a7f6f02b53376c8c270aef512f23e4e36201066`: Node `33244376872`,
  container `33244376875`, Linux GUI `33244376917`, Windows GUI
  `33244376903`, Go `33244376887`, Java `33244376893`, Kotlin
  `33244376881`, .NET `33244376891`, Rust `33244376912`, Ruby
  `33244376898`, and PHP `33244376920`. All 87 Node jobs pass, including the
  four Sails exploit/control witnesses on Ubuntu and Windows.
- Closed two process-environment blind spots in official MCP tool-input flows.
  Exact `options.env.NODE_OPTIONS` now reaches the existing argument-injection
  model for non-shell `spawn`, `spawnSync`, `execFile`, and `execFileSync`
  calls when the target is proved to be `process.execPath` or an exact official
  `node:process` binding. Tool-controlled exact `options.env.PATH` now emits
  `node-mcp-tool-untrusted-executable-search` with CWE-426 when those APIs use
  a fixed bare executable name. This covers runtime-option interpretation and
  executable lookup even though the command, argv, and shell setting remain
  fixed.
- Kept both models role- and identity-sensitive. NODE_OPTIONS requires a
  proved Node runtime; PATH requires a nonempty bare literal without a path,
  drive, URL, or dot-segment qualifier. Both require exact supported overloads
  and exact options/environment objects, permit a preceding environment spread
  only when an explicit relevant property wins, and reject following spreads,
  computed or duplicate target properties, options aliases, shell-enabled
  launches, replaced bindings, and ambiguous executable identity. PATH is not
  described as command source, and attacker code execution requires separate
  evidence of an attacker-writable directory and a shadow executable.
- Added two frozen MCP SDK 2.0.0/Zod 4.4.3 exploit/control pairs. The bounded
  NODE_OPTIONS witness loads only a checked-in inert preload; its control keeps
  the same text in a non-special environment field. The PATH witness supplies
  an empty search path and observes `ENOENT` without executing any program; its
  control pins PATH to the current Node directory and runs only that Node
  executable. All four pass on Windows and WSL. The focused model/benchmark
  gate passes 95 tests and 3,539 assertions on each platform. The strict MCP lane now contains 38 cases
  across 19 pairs; the canonical corpus contains 175 pairs, 350 cases, and
  1,050 repeated positions. Hosted Node CI schedules all 38 MCP witnesses on
  Ubuntu and Windows, expanding the expected matrix from 75 to 83 jobs.
- Completed local process-environment acceptance. The managed Windows
  aggregate selects 2,041 tests across 210 files: 2,012 pass, 27 intentionally
  skip, and only the established temporary-Git and private-Windows-ACL cases
  fail at their host boundaries. Their exact native rerun passes 48/48 with
  242 assertions. The focused Windows and WSL model/benchmark lanes each pass
  95 tests with 3,539 assertions. Formatting, generated-model drift,
  TypeScript, the clean production build, and the whitespace audit pass, and
  the production advisory audit reports no known vulnerabilities.
- Two compiled repository-root inventories complete in 20.014 and 21.333
  seconds and are byte-identical at 256 rows, 584,350 bytes, 243 structured
  records, 13 lexical leads, and SHA-256
  `d6e35ce2196ec63e445da0449fb56dae7672f160e768901c34c5857e2548fc89`.
  Direct compiled fixture inspection retains exactly the NODE_OPTIONS and PATH
  models and no structured row for either control. Windows and WSL strict
  package inspection each validate 299 entries, fresh installed public import,
  CLI execution, and all 79 bundled-plugin files. The Windows archive is
  2,337,999 bytes with SHA-256
  `9ebd1b613cd36c822fccfd5c4527b0f18f204e381cb9f923b8b0ab357c65d7d3`;
  the Linux-native executable-mode archive is 2,337,993 bytes with SHA-256
  `c95c43e7e4c897e53544c2361047003f33900894f8c3554dca8212fef450e7be`.
  Linux correctly rejects the Windows-mode archive before the native package
  is built, preventing a cross-platform launcher-permission false pass.
- All eleven hosted workflow families pass at implementation checkpoint
  `090b9fb6e8157f717be038203b3a39dd5d347b33`: Node `33240769402`,
  container `33240769388`, Linux GUI `33240769407`, Windows GUI
  `33240769419`, Go `33240769396`, Java `33240769410`, Kotlin
  `33240769398`, .NET `33240769395`, Rust `33240769405`, Ruby
  `33240769420`, and PHP `33240769397`. All 83 Node jobs pass with zero
  failures, including the NODE_OPTIONS positive/control and executable-search
  positive/control witnesses on both Ubuntu and Windows.
- Closed two indirect `child_process.fork` execution-context gaps for official
  MCP tool-input flows. A fixed non-absolute `modulePath` combined with
  tool-controlled exact `options.cwd` now emits
  `mcp-tool-fork-relative-cwd` as
  `node-mcp-tool-untrusted-module-load` with CWE-426/CWE-829. Exact
  `options.env.NODE_OPTIONS` under fork's default Node executable or a proved
  `process.execPath` now emits `mcp-tool-fork-node-options` as
  `node-mcp-tool-argument-injection` with CWE-88/CWE-94. These paths expose
  fixed-looking calls whose child code can still be redirected without
  tainting `modulePath`, `execPath`, or `execArgv` directly.
- Kept both context models role- and identity-sensitive. Absolute paths, file
  URLs, fixed working directories, ordinary environment values, fixed
  `NODE_OPTIONS`, and unknown custom executables remain controls. Exact
  options objects are required; aliases, unsupported overloads, computed or
  duplicate relevant properties, and ambiguous executable identity suppress
  the structured row. An inner `env` literal may spread `process.env` before
  an explicit `NODE_OPTIONS` because the latter wins, but a following spread
  remains ambiguous. Explicit Node-runtime bindings retain their exact
  `node:process` and runtime-alias provenance.
- Added two frozen MCP SDK 2.0.0/Zod 4.4.3 exploit/control pairs. The cwd
  witness selects one checked-in inert child through a relative entry point;
  its file-URL control includes a same-named alternate child in the selected
  directory and still runs the fixed module. The `NODE_OPTIONS` witness loads
  one checked-in inert preload that sets only an in-memory child marker; its
  control preserves the same option-looking bytes in a non-special
  environment variable. All four witnesses pass on Windows and WSL without a
  shell, external code, network, credentials, persistence, or privileged
  effects. The focused model/benchmark gate passes 93 tests and 3,416
  assertions. The strict MCP lane now contains 34 cases across 17 pairs; the
  canonical corpus contains 173 pairs, 346 cases, and 1,038 repeated
  positions. Hosted Node CI schedules all 34 MCP witnesses on Ubuntu and
  Windows, expanding the matrix from 67 to 75 jobs.
- Completed fork execution-context acceptance at implementation checkpoint
  `3bfd9f45dd78da9014cf3cc667606551f2a0e68a`. The managed Windows aggregate
  selects 2,039 tests across 210 files: 2,010 pass, 27 intentionally skip, and
  only the established temporary-Git and private-Windows-ACL permission cases
  fail at their host boundaries; the exact two-file native rerun passes 48/48
  with 242 assertions. The focused Windows and WSL model/benchmark lane passes
  93 tests with 3,416 assertions on each platform. Independent compiled
  inventory checks retain exactly the cwd and NODE_OPTIONS structured rows and
  no structured row for either topology-matched control.
- Two compiled repository-root inventories complete in 20.318 and 19.632
  seconds and are byte-identical at 256 rows, 584,350 bytes, 243 structured
  records, 13 lexical leads, and SHA-256
  `d6e35ce2196ec63e445da0449fb56dae7672f160e768901c34c5857e2548fc89`.
  The production audit reports no known vulnerabilities. Strict Windows and
  WSL package inspection validates the same 299-entry archive, executable CLI,
  public import, and all 79 bundled-plugin files through fresh isolated
  installs; the 2,366,525-byte archive has SHA-256
  `cc037b1eb31e5e57eb03205cad2924c40951b8e9d49f371e5d758740a3a1c06f`.
- All eleven exact-implementation hosted workflows pass: Node `33236439739`,
  container `33236439742`, Linux GUI `33236439754`, Windows GUI `33236439774`,
  Go `33236439772`, Java `33236439755`, Kotlin `33236439831`, .NET
  `33236439725`, Rust `33236439740`, Ruby `33236439744`, and PHP
  `33236439727`. All 75 Node jobs pass, including the eight new cwd,
  absolute-module, NODE_OPTIONS, and ordinary-environment-data witnesses on
  Ubuntu and Windows.
- Made `child_process.fork` role-aware for official MCP tool-input flows.
  Argument zero now emits `node-mcp-tool-untrusted-module-load` at the exact
  `fork:modulePath[0]` boundary with CWE-829, while exact object-literal
  `options.execPath` emits command/executable selection at
  `fork:options.execPath` with CWE-78. Existing `options.execArgv` remains
  CWE-88/CWE-94 interpreter-option injection, and ordinary `args` remain
  module data. One call can retain all independently tainted roles instead of
  collapsing them into one generic command row.
- Added exact shorthand-property support for `{ execPath }` and preserved
  fail-closed rejection of dynamic or aliased options objects, nonliteral
  module-argument lists, spreads, computed or duplicate properties,
  unsupported overloads, replaced bindings or namespace members, and
  lookalike modules. Host-enforced finding closure now requires the exact
  module or executable role plus its fixed/allowlisted-module or fixed
  `process.execPath` matched control in both validation and attack-path text.
- Added two frozen MCP SDK 2.0.0/Zod 4.4.3 exploit/control pairs. The bounded
  module witness selects only a checked-in inert child; the executable witness
  supplies only the current Node binary. Both pairs pass on Windows and WSL
  without a shell, dynamic code, filesystem writes, network access,
  credentials, persistence, or an external executable. The focused model and
  benchmark regression passes 91 tests and 3,306 assertions on each platform.
  The strict MCP lane now contains 30 cases across 15 matched pairs; the
  canonical corpus contains 171 pairs, 342 cases, and 1,026 repeated
  positions. Hosted Node CI now schedules all 30 MCP witnesses on Ubuntu and
  Windows, expanding the matrix from 59 to 67 jobs.
- Completed full acceptance at implementation revision
  `7d4d9e9e65b5f62072bce93cd33e469ad73d18fe`. The managed Windows suite
  selects 2,037 tests across 210 files: 2,008 pass, 27 intentionally skip, and
  only the two established Git-metadata and Windows-ACL cases fail closed;
  their exact native rerun passes 48/48 with 242 assertions. Two compiled
  root inventories complete in 20.291 and 19.664 seconds and are
  byte-identical at 256 rows, 584,350 bytes, 243 structured records, 13
  lexical leads, and SHA-256
  `d6e35ce2196ec63e445da0449fb56dae7672f160e768901c34c5857e2548fc89`.
  The production audit is clean. Strict package inspection and a fresh
  isolated installation validate 299 entries, the public import, CLI, and all
  79 bundled-plugin files; the 2,330,647-byte archive has SHA-256
  `8ed24e72635536b6f75ac9428aa3943a383ee27390c73b79a52c9b8520468203`.
  All eleven hosted workflow families pass: Node `33233377811`, container
  `33233377810`, Linux GUI `33233377877`, Windows GUI `33233377818`, Go
  `33233377808`, Java `33233377876`, Kotlin `33233377812`, .NET
  `33233377809`, Rust `33233377805`, Ruby `33233377806`, and PHP
  `33233377842`. All 67 Node jobs pass, including the eight new fork-role
  witnesses across Ubuntu and Windows.
- Closed a deterministic MCP argument-injection false negative for
  tool-controlled entries in `child_process.fork(..., { execArgv: [...] })`.
  The model proves a live official `node:child_process` or `child_process`
  fork binding, an exact supported two- or three-argument overload, and an
  exact object-literal `execArgv` array while preserving the fixed module as
  counterevidence. It emits `mcp-tool-fork-exec-argv` with the exact
  `fork:options.execArgv[index]` sink and CWE-88/CWE-94, while ordinary fork
  arguments remain data rather than generic command-injection findings.
- Kept fork inference fail closed: dynamic or aliased options, nonliteral
  argument arrays, spreads, computed or duplicate `execArgv` properties,
  non-array values, replaced or shadowed bindings and namespace members,
  lookalike modules, and unsupported overloads suppress structured inference.
  A literal `--` within `execArgv` is not accepted as the matched repair,
  because later Node options can still change module selection. Finding
  correction requires both validation and attack-path fields to repeat the
  exact `fork:options.execArgv` edge and the fixed-`execArgv`/ordinary-module-
  argument control.
- Added a frozen MCP SDK 2.0.0/Zod 4.4.3 exploit/control pair with a reachable
  stdio launcher, fixed child module, same-file helper, private IPC, bounded
  timeout, and an inert `--stack-trace-limit=77` witness. Both witnesses pass
  on Windows and WSL without shell, external modules, inspector, filesystem,
  network, credentials, persistence, or attacker code. The focused Windows
  and WSL lanes each pass 88 tests and 3,210 assertions. The strict MCP lane now contains 26 cases
  across 13 matched pairs, and the canonical corpus contains 169 pairs, 338
  cases, and 1,014 repeated positions.
- The complete managed-shell Windows suite selects 2,034 tests across 210
  files: 2,005 pass, 27 intentionally skip, and the two established
  host-permission cases fail closed; their exact native rerun passes 48/48 with
  242 assertions. Formatting, generated-model drift, TypeScript, the clean
  production build, and the production advisory audit are green. Two compiled
  root self-inventories complete in 19.213 and 20.078 seconds and remain
  byte-identical at 256 rows, 584,350 bytes, 243 structured records, 13 lexical
  leads, and SHA-256
  `d6e35ce2196ec63e445da0449fb56dae7672f160e768901c34c5857e2548fc89`.
  Strict package inspection and a fresh isolated install validate the public
  import, CLI, all 79 bundled-plugin files, and a 299-entry, 2,359,970-byte
  archive with SHA-256
  `88c4fd26468fc70c580cac864f687f66710e35836f0bcfadee1c4b7fa56b996e`.
  All eleven hosted workflow families pass at implementation revision
  `57db2c5b70df2391f8d53fa87feda81040aad1a0`: Node `33230452192`,
  container `33230452188`, Linux GUI `33230452176`, Windows GUI
  `33230452202`, Go `33230452163`, Java `33230452179`, Kotlin
  `33230452172`, .NET `33230452162`, Rust `33230452165`, Ruby
  `33230452238`, and PHP `33230452169`. All 59 Node jobs pass, including
  the fork `execArgv` exploit and ordinary-module-argument control on both
  Ubuntu and Windows.
- Closed the remaining deterministic MCP Node interpreter-option false
  negative when the runtime comes from an exact official `node:process`
  binding. The detector now proves ESM default, namespace, and named
  `execPath` imports, including combined default-plus-named or namespace ESM
  declarations; CommonJS namespace and destructured `execPath` requires; and
  TypeScript import-equals bindings, either directly or through one stable
  runtime alias. Positive rows preserve separate exact process-binding and
  runtime-alias provenance edges.
- Kept imported-runtime inference fail closed: only the unambiguous
  `node:process` built-in specifier is accepted. The unprefixed `process`
  package, other modules, local shadows, binding or member mutation, computed
  access, duplicate bindings, destructuring assignment, reflective mutation,
  alias chains, and nested ambiguous aliases suppress the row. Finding-quality
  correction requires both validation and attack-path fields to repeat the
  exact imported binding or explicitly identify the official `node:process`
  binding, independently of any runtime alias and the Node option boundary.
- Added a frozen MCP SDK 2.0.0/Zod 4.4.3 exploit/control pair with a reachable
  stdio launcher, default `node:process` import, module-scope runtime alias, and
  one same-file helper. The exploit proves that inert `--version` is consumed
  in Node's option region; the control inserts exact `--` and preserves the
  same values as data. Both witnesses and the 85-test/3,144-assertion focused
  lane pass on Windows and WSL. The strict MCP lane now contains 24 cases
  across 12 matched pairs, and the canonical corpus contains 168 pairs, 336
  cases, and 1,008 repeated positions.
- The complete managed-shell Windows suite selects 2,031 tests across 210
  files: 2,002 pass, 27 intentionally skip, and two host-permission cases fail
  closed. The exact permission-sensitive files pass 48/48 with host access.
  Generated-model drift, TypeScript, and build checks are clean.
- The compiled exploit emits exactly one
  `node-mcp-tool-argument-injection` row at `src/server.mjs:12`, with
  `execFile:argv[2]`, CWE-88/CWE-94, registration,
  `nodeProcess<-node:process`, `runtime=nodeProcess.execPath`, and same-file
  helper evidence; the independently rooted exact-`--` control emits no row.
  Two root self-inventories complete in 20.074 and 20.144 seconds and are
  byte-identical at 256 rows, 584,350 bytes, 243 structured records, 13 lexical
  leads, and SHA-256
  `d6e35ce2196ec63e445da0449fb56dae7672f160e768901c34c5857e2548fc89`.
  Production audit reports no known vulnerability. The rebuilt 299-entry,
  2,355,981-byte package at SHA-256
  `bbf920709c8f2597899c0768389e9016d76dc28a6403a0848e2bec91781754bd`
  passes isolated install, public import, CLI, and all 79 bundled-plugin checks.
  All eleven hosted workflow families pass at implementation revision
  `f5edfe61d3a1017bdf39195cd1577b09c9234986`: Node `33226781592`,
  container `33226781570`, Linux GUI `33226781584`, Windows GUI
  `33226781586`, Go `33226781569`, Java `33226781583`, Kotlin
  `33226781575`, .NET `33226781600`, Rust `33226781589`, Ruby
  `33226781576`, and PHP `33226781573`. All 55 Node jobs pass, including the
  imported-runtime exploit and exact-`--` control on both Ubuntu and Windows.
- Closed a deterministic MCP argument-injection false negative when a fixed
  Node executable is preserved through one stable local or module-scope alias,
  such as `const runtime = process.execPath`, before tool-controlled values
  enter `execFile(runtime, argv)`. The detector now records the exact
  `runtime=process.execPath` edge and still requires an exact `--`
  end-of-options element before every tainted option-region argument. Generic
  fixed-executable/argv guidance remains valid for ordinary programs, while
  the Node interpreter's own option parser receives explicit treatment.
- Kept runtime-alias inference fail closed: a local `process` shadow,
  `process` or `process.execPath` replacement, deletion or reflective mutation,
  alias reassignment or destructuring, multiple declarations, alias chains,
  nested ambiguous declarations, computed/global process expressions, and
  unsupported runtime forms suppress the structured row. Finding-quality
  correction now requires both validation and attack-path fields to repeat the
  recorded runtime-alias symbol and independently explain the Node option
  region and end-of-options boundary.
- Added a topology-matched MCP SDK 2.0.0/Zod 4.4.3 executable pair with a
  reachable stdio launcher, frozen dependency locks, one same-file helper, and
  bounded inert values. The exploit proves that `--version` is consumed as a
  Node option through the aliased runtime; the control inserts exact `--` and
  proves that `--version`, `--help`, and the fixed marker remain ordinary
  program data. Both witnesses pass under Windows Node 24.15.0 and WSL Node
  22.23.1 without shell, filesystem, network, credential, persistence, or
  attacker-code effects. The strict MCP lane now contains 22 cases across 11
  matched pairs, and the canonical corpus contains 167 pairs, 334 cases, and
  1,002 repeated positions.
- The compiled exploit inventory contains one exact
  `node-mcp-tool-argument-injection` row at `src/server.mjs:11`, with
  `execFile:argv[2]`, CWE-88/CWE-94, registration, helper, and
  `runtime=process.execPath` propagators; the independently rooted control has
  no structured argument-injection row. Two complete product-root inventories
  are byte-identical at 256 rows, 584,350 bytes, 243 structured records, 13
  lexical leads, and SHA-256
  `d6e35ce2196ec63e445da0449fb56dae7672f160e768901c34c5857e2548fc89`,
  completing in 19.114 and 19.082 seconds.
- Focused Windows acceptance passes 82 tests and 3,061 assertions; native WSL
  passes the 64-test/648-assertion MCP model lane and both new witnesses. The
  clean complete Windows suite selects 2,028 tests across 210 files: 1,999 pass
  and 27 intentionally skip under the managed shell, while its two
  permission-sensitive cases pass in an exact 48/48 host-permission rerun.
  Formatting, generated-model drift, TypeScript, build, and production audit
  are clean. The rebuilt 299-entry, 2,353,336-byte package at SHA-256
  `79b36a83b30fa5126e13795e7523a2fb4669938d312a50a6ffb1dd1d252f2d8e`
  passes isolated install, public import, CLI, and all 79 bundled-plugin
  checks. All eleven hosted workflow families pass at implementation revision
  `3a3ded79b08393d5657fe10b46e35f195a806a6f`: Node `33221929778`,
  container `33221929807`, Linux GUI `33221929867`, Windows GUI
  `33221929747`, Go `33221929866`, Java `33221929761`, Kotlin
  `33221929812`, .NET `33221929861`, Rust `33221929805`, Ruby
  `33221929848`, and PHP `33221929817`. The Node run includes successful
  Ubuntu and Windows jobs for both the aliased-runtime exploit and its exact
  end-of-options control.
- Closed a deterministic MCP SQL-injection false negative for tool-controlled
  SQL compiled by the official built-in `node:sqlite`
  `DatabaseSync.prepare` API and then executed through the exact returned
  `StatementSync` with `all`, `get`, `iterate`, or `run`. The model now emits
  separate preparation and execution edges, supports immediate execution,
  declarations including `using`/`await using`, later `let`/`var` assignment,
  one stable statement alias, and same-file helper propagation. Preparation
  without execution and tool values bound into fixed placeholder SQL remain
  negative controls.
- Kept prepared-SQL discovery fail closed on database or statement
  reassignment, instance or prototype method replacement, pre-execution
  closure/disposal, shadowed or unsupported statement flows, and ambiguous
  database identity. Corrected an adjacent lifecycle bug found during
  self-review: closing one independent `DatabaseSync` instance no longer
  suppresses a sink on another instance, while closing an alias of the same
  database still does. Model-specific quality gates now require both the exact
  `prepare` edge and the exact `StatementSync` execution edge and forbid
  inferring `exec`-style stacked-statement behavior from `prepare`.
- Added an exact MCP SDK 2.0.0/Zod 4.4.3 exploit/control pair using only an
  in-memory database. The exploit passes interpolated tool input to
  `database.prepare` and proves an unauthorized internal-role lookup when the
  returned statement executes; its topology-matched control keeps SQL fixed
  and binds the identical value through `statement.get(name)`. Both witnesses
  pass on Windows Node 24.15.0 and WSL Node 22.23.1. The strict MCP lane now
  contains 20 cases across ten matched pairs, and the canonical corpus contains
  166 pairs, 332 cases, and 996 repeated positions.
- The compiled detector emits one exact `node-mcp-tool-sql-injection`/CWE-89
  row for the independently rooted exploit, with `database.prepare:sql[0]`
  and `statement.get:prepared-sql[0]` edges, and no structured row for the
  bound-parameter control. Two product-root self-inventories complete in
  20.068 and 19.161 seconds and are byte-identical at 584,350 bytes and SHA-256
  `d6e35ce2196ec63e445da0449fb56dae7672f160e768901c34c5857e2548fc89`,
  matching the previous accepted 256-row checkpoint. The root inventory
  correctly contains no MCP fixture row because benchmark trees remain outside
  production model ownership.
- Focused Windows acceptance passes 79 tests and 3,021 assertions; the wider
  model, canonical benchmark, and residual-risk lane passes 146 tests and
  4,084 assertions with one intentional symlink skip; and native WSL passes
  the focused 79-test/3,021-assertion lane. The clean complete Windows suite
  selects 2,025 tests across 210 files: 1,996 pass and 27 intentionally skip in
  the managed shell, while the two host-permission cases blocked there pass in
  an exact 48/48 native-ACL rerun. Generated models, TypeScript, formatting,
  build, and production audit are clean. A 299-entry, 2,351,834-byte archive
  with SHA-256
  `1436bccff878d919e80621cbd77890863b692337e21491af3ee12153d6485538`
  passes isolated install, public-import, CLI, and all 79 bundled-plugin checks.
  All eleven hosted workflow families pass at implementation revision
  `f675b257d1c667112d24fc454195cf7aeb00b0e5`: Node `33217653997`,
  container `33217654074`, Linux GUI `33217654009`, Windows GUI
  `33217654024`, Go `33217654055`, Java `33217654056`, Kotlin
  `33217654025`, .NET `33217654069`, Rust `33217654083`, Ruby
  `33217654022`, and PHP `33217654071`.
- Expanded deterministic residual discovery from 2,000 files/8 MiB to 8,192
  files/32 MiB after self-review showed that the file ceiling was applied
  during directory traversal before final path sorting. Added `.pnpm-store` to
  the generated-tree denylist so a workspace-local package cache cannot consume
  source budget or enter model prompts. The 256-row final cap and its
  framework-kind, category, and path-diversity reservation remain unchanged.
  A regression creates 2,048 ordinary source files, an ignored package-cache
  decoy, and a lexically late MCP/SQLite sink; the structured CWE-89 row must
  survive. The expanded Windows model/benchmark/inventory lane passes 141 tests
  and 4,005 assertions with one intentional symlink skip, and the new native
  WSL boundary passes with four assertions. The rebuilt 299-entry,
  2,348,280-byte archive has SHA-256
  `56c490c33467ec8930d8b60ddf93adb60a97a6435f9c3cb0bdf2be6182244d7d`
  and passes isolated Windows and WSL public-import, CLI, and 79-file bundled
  plugin validation. At public revision
  `0a8472d0510e07e79ba8b50bb3ab06813ffbb5b8`, two exact-head inventories
  complete in 20.55 and 19.41 seconds and are byte-identical: 256 rows and
  584,350 bytes, with 243 structured records and 13 lexical leads at SHA-256
  `d6e35ce2196ec63e445da0449fb56dae7672f160e768901c34c5857e2548fc89`.
  The production-path owner intentionally excludes benchmark fixtures, so the
  root inventory emits no MCP SQLite row; the independently rooted matched
  pair remains the positive/negative proof. All eleven hosted workflow families
  pass at that implementation revision: Node `33211464346`, container
  `33211464323`, Linux GUI `33211464275`, Windows GUI `33211464368`, Go
  `33211464536`, Java `33211464288`, Kotlin `33211464260`, .NET `33211464311`,
  Rust `33211464328`, Ruby `33211464258`, and PHP `33211464379`.
- Added deterministic `node-mcp-tool-sql-injection` coverage for exact MCP tool
  input reaching argument zero of the official built-in `node:sqlite`
  `DatabaseSync.exec` API. Named, aliased, namespace, default, CommonJS, and
  TypeScript import-equals bindings are supported, along with a stable database
  alias and same-file helper propagation. The row preserves the MCP source,
  schema, helper edge, database construction, SQL execution, and CWE-89 sink.
- Kept the SQLite model fail closed on `sqlite3` and local lookalikes,
  constructor options, callback-local or ambiguous construction, reassigned
  constructors and receivers, replaced prototype or instance methods, and a
  database closed before execution. Fixed SQL with the same tool value passed
  through `StatementSync` bound parameters remains a strong negative control.
  Model-specific validation and attack-path gates independently require the
  exact MCP, built-in SQLite, SQL-grammar, parameterization, and concrete
  integrity or confidentiality boundaries.
- Added a reachable MCP SDK 2.0.0/Zod 4.4.3 exploit/control pair backed by an
  in-memory `DatabaseSync`. The bounded exploit witness proves that one fixed
  value changes SQL structure and inserts a second inert row; the control binds
  that identical value as one SQL scalar and inserts one literal row. Both
  witnesses pass on Windows Node 24.15.0 and WSL Node 22.23.1 without
  filesystem, network, subprocess, credential, or persistent-database effects.
  The strict MCP lane now contains 18 cases across nine matched pairs, and the
  canonical corpus contains 165 pairs, 330 cases, and 990 repeated positions.
- Bound the specialized and canonical Worker and SQLite ground-truth locations
  to their deterministic framework rows, and corrected the canonical Worker
  sink from stale line 9 to the actual line-12 constructor. Focused Windows
  acceptance passes 74 tests and 2,941 assertions; native WSL passes 141 tests
  and 4,001 assertions. The complete Windows aggregate passes 1,992 tests and
  15,140 assertions across 210 files, with 27 intentional platform/environment
  skips and no unresolved failures after the clean-build and native-ACL lane.
  Formatting, generated-model drift, TypeScript checking, and the production
  build are clean.
- Production audit reports no known vulnerabilities. A 299-entry,
  2,348,253-byte npm archive with SHA-256
  `c276d1d2bb300cb5ca4ef020b4e744a1834b1978884d72f90587e9890125ebfc`
  passes isolated Windows and WSL public-import, executable-CLI, and all
  79-bundled-plugin checks. Independently rooted fixtures emit one exact CWE-89
  row at `src/server.mjs:19` for the exploit and none for the prepared/bound
  control.
- Kept exhausted host-proven coverage or finding-quality closure terminal after
  deterministic draft preparation. Validated partial evidence remains
  recoverable, but it can no longer be converted into a completed scan, clean
  result, or successful benchmark receipt. Outer benchmark and service retry
  policies now receive the typed closure failure and can start a genuinely
  fresh scanner attempt.
- Corrected the Worker benchmark expectation from stale line 9 to the actual
  line-12 `new Worker(expression, { eval: true })` execution sink. A direct
  regression binds the manifest location to the deterministic framework row,
  preventing future fixture drift from turning a true detection into a
  misleading semantic failure.
- Strengthened Worker-specific field-local closure so validation and attack
  path each have to name an official `worker_threads`/`new Worker` constructor
  boundary and explicitly state code execution or code injection. General
  Worker/evaluation prose and CWE-94 alone no longer satisfy those two proof
  obligations.
- Accepted live campaign
  `a2402dced948e29fdd993a9c4df207a6dac68ca467a94ef4b3570317ee86dc16`
  at public implementation revision
  `ac58ca7e16bd61768c7dda750c24a81b5db1c7bd`. Both stored-credential
  `gpt-5.6-terra` high-effort deep scans complete on attempt one: the reachable
  Worker-eval case produces one high CWE-94/CWE-95 finding in 6m17s and the
  fixed-source/structured-clone control produces none in 3m58s. Completion,
  precision, recall, F1, case and negative-case pass, stable detection,
  validation, attack path, code evidence, and severity are all 1.0, with zero
  false positives or negatives. Finalize-only revalidation accepts the sealed
  receipts without another model call.
- The accepted campaign consumes 2,168,768 input, 1,905,473 cached, and 50,410
  output tokens at an estimated $2.0552345. One positive excerpt is benignly
  re-anchored from immutable repository bytes. Across all six deep scans in the
  three Worker campaigns there is no allowance, credit-limit, authentication,
  authorization, rate-limit, classifier-refusal, transport, timeout, or retry
  event; the configured account imposed no observed credit ceiling.
- Final implementation acceptance passes 1,987 tests and 15,074 assertions
  across 210 files in 495.04 seconds, with 27 intentional Windows/platform
  skips and zero failures. Production audit reports no known vulnerabilities.
  A 299-entry, 2,343,423-byte npm archive with SHA-256
  `e1ff376d91b32a83f2124470eddd00bc0d4091d975949bcaccd6e3cca2be453b`
  passes isolated Windows and WSL public-import, executable-CLI, and all
  79-bundled-plugin checks.
- Exact-head tracked-only self-review covers 3,594 files from a 20,039,680-byte
  Git archive with SHA-256
  `37f892b42c09484dd3fe4c08d683ba8f40442c0eeedd89fda9ef7f511274cff9`.
  Two production inventories are byte-identical at 256 rows and 551,013 bytes,
  with 204 structured and 52 lexical records and SHA-256
  `744969455b26d83168e1932a69936a170eb853acfb242adf7696a6531d498a7b`.
  Independently rooted runs twice emit exactly one structured Worker row at
  `src/server.mjs:12` for the exploit and no structured row for the control.
- All eleven hosted workflow families pass at the same implementation revision:
  Node `33201380299`, container `33201380334`, Windows GUI `33201380323`,
  Linux GUI `33201380288`, Java `33201380332`, Kotlin `33201380295`, .NET
  `33201380270`, Go `33201380271`, Rust `33201380281`, Ruby `33201380292`,
  and PHP `33201380327`. GitHub reports the repository public on default branch
  `main`.
- Added deterministic MCP code-injection coverage for tool input reaching
  argument zero of the exact Node `worker_threads` or `node:worker_threads`
  `Worker` constructor with an object-literal `eval: true` option. The model
  supports named aliases, namespace imports, CommonJS destructuring, and
  TypeScript import-equals, including same-file helpers. It records distinct
  construction and worker-startup evidence because Node executes the string
  once the worker comes online.
- Kept the Worker model fail closed on calls without `new`, omitted, false,
  dynamic, duplicated, spread, or computed eval options, input used only as
  `workerData`, wrong modules, local and parameter shadows, and replaced direct
  or namespace bindings. Worker-specific field-local gates require both
  validation and attack path to name the official binding, argument-zero code
  edge, literal eval mode, and startup execution; generic Function lifecycle
  prose is rejected.
- Added a reachable official MCP SDK 2.0.0/Zod 4.4.3 exploit/control pair. The
  exploit starts a worker from the tool expression. The topology-matched
  control retains Worker eval mode but fixes all source, parses an explicit
  two-operand arithmetic grammar, and transfers only numbers plus an
  allowlisted operator through structured-cloned `workerData`. Both bounded
  Windows and WSL witnesses return `42`; the control rejects JavaScript object
  syntax. The strict MCP lane advances to sixteen cases, and the canonical
  corpus to 164 pairs, 328 cases, and 984 repeated positions.
- Focused Windows and native WSL acceptance each pass 51 tests and 490
  assertions with zero failures, including four official Worker binding forms,
  helper propagation, adversarial false-positive controls, exact manifest
  integration, and Worker-specific quality-gate closure. TypeScript checking
  passes on both hosts.

- Added deterministic compile-to-execution lifecycle coverage for MCP tool input
  that reaches the live global `Function` constructor or exact `node:vm`
  `compileFunction`, `Script`, or `SourceTextModule` bindings. Bare compilation
  remains negative; findings require invocation, a `Script.runIn*` call, or a
  complete module link/instantiate/evaluate lifecycle. The model rejects
  shadows, wrong modules, replaced imports or members, overwritten compiled
  values, replaced execution methods, unawaited legacy linking, and incomplete
  module state transitions. Existing immediate `vm.runIn*` coverage now also
  fails closed after binding or member replacement.
- Preserved construction and module-lifecycle propagators across same-file
  helper summaries, and strengthened field-local quality gates so validation
  and attack path separately name the compilation API, explicit execution
  step, and module linking or instantiation where applicable. Correction
  guidance permits only fixed side-effect-free arithmetic and distinguishes
  compilation from execution using Node's documented lifecycle.
- Added a real MCP TypeScript SDK 2.0.0 exploit/control pair. The exploit puts
  the `expression` property into `Function` source and invokes the retained
  result. The stronger control still invokes a compiled `Function`, but its
  source is fixed and an explicit arithmetic grammar passes only numbers and an
  allowlisted operator as data. Both bounded witnesses pass. The strict MCP
  corpus now contains fourteen cases and witnesses; the canonical corpus
  contains 163 pairs, 326 cases, and 978 repeated scan positions.
- Corrected the new Function-constructor benchmark's ground-truth location from
  stale line 10 to the actual retained-result execution at line 8. The first
  live campaign found exactly the intended high CWE-94 lifecycle defect and
  kept the fixed-grammar control clean, but the old anchor counted that true
  finding as both unexpected and missed. A manifest regression now binds the
  specialized expectation to the execution line, and the canonical corpus uses
  the same anchor.
- Strengthened that pair after a corrected live rerun exposed a separate fixture
  flaw: registration alone was followed only by trusted direct witness calls,
  with no connected transport in the complete source inventory. Both twins now
  launch the registered server through the official MCP 2.0.0
  `StdioServerTransport`; the evaluator remains their only security-relevant
  delta. Regression tests pin the common start script and launcher, and both
  Windows and WSL witnesses remain clean and bounded.
- Accepted live campaign
  `2dfe83e47c92ce6de9947e80482d840adeea8b4a17715fd6c8dc3f56acab8b21`
  at public revision `89c12e6563dc6e11a30be10fe64be121fb128016`.
  Both reachable deep/high cases complete on attempt one with complete coverage:
  the exploit produces one high CWE-94 finding, and the fixed-grammar control
  produces none. Completion, precision, recall, F1, case and negative-case pass,
  stable detection, validation, attack path, code evidence, and severity are all
  1.0 with zero false positives or negatives. Finalize-only revalidation accepts
  the same sealed receipts, and no allowance, authentication, rate-limit,
  classifier, transport, timeout, or retry event occurs.
- The implementation checkpoint passes the authoritative 1,983-test Windows
  suite with 14,991 assertions across 210 files, 27 intentional skips, and zero
  failures. The post-counterexample focused Windows and WSL lanes each pass 65
  tests and 2,798 assertions; both reachable package-backed witnesses pass.
  Production dependency audit reports no known vulnerability.
- Exact-head tracked-only self-review of 3,582 files is byte-stable across two
  production inventories: 256 rows, 553,659 bytes, 206 structured and 50 lexical
  records, SHA-256
  `51ff34c0e0170f88555497de26ea9367ef7025cc76d085880ec134100acae79b`.
  Independently rooted scans emit one exact lifecycle row for the exploit and no
  structured row for the control, twice identically. A 299-entry, 2,310,421-byte
  Linux release archive with SHA-256
  `ba4777fa4021288f5e3e9fc1d304324ccd543cd77c3d846e4fc05d1343ed9da4`
  passes isolated Linux and Windows import, executable CLI, and all 79 bundled
  plugin checks.
- All eleven hosted workflow families pass at exact reachability revision
  `89c12e6563dc6e11a30be10fe64be121fb128016`: Node `33192877968`,
  Windows GUI `33192877902`, Linux GUI `33192877994`, container `33192877934`,
  Java `33192878044`, Kotlin `33192877916`, .NET `33192877889`, Go
  `33192877942`, Rust `33192877925`, Ruby `33192877911`, and PHP `33192877945`.
- Added deterministic `node-mcp-tool-regex-injection` coverage for official MCP
  TypeScript SDK tool input used as argument zero of the live global `RegExp`
  and then actually executed through `test` or `exec`. The bounded source model
  preserves local assignment and same-file helper provenance, emits
  CWE-400/CWE-730, and rejects constructor-only code, tool input used only as
  flags or test data, fixed expressions, shadows, reassignment, and replaced
  expression methods.
- Added a field-local finding-quality contract and correction guidance. Both
  validation and attack path must name the MCP caller, exact property and schema
  limitation, construction, execution, match-subject provenance and work bound,
  pattern-grammar boundary, CWE pair, and concrete synchronous Node event-loop
  effect. Small fixed server-owned subjects are counterevidence. Validation
  permits only short fixed metacharacter examples and the matched safe control;
  catastrophic or load-generating expressions are explicitly forbidden.
- Added real `@modelcontextprotocol/server` 2.0.0 exploit/control fixtures. The
  exploit carries the `pattern` property through `searchText` into constructed
  and executed regular-expression syntax over an independently supplied text
  subject capped at 4,096 characters. The topology-matched control keeps the
  SDK, both schemas, tool, helper, subject, and response while mapping fixed
  names to operator-owned literals. The strict MCP corpus now contains twelve
  cases and twelve cross-platform witnesses; the canonical corpus contains 162
  pairs, 324 cases, and 972 repeated scan positions.
- Focused Windows and native WSL lanes each pass 59 tests and 2,726 assertions,
  both executable witnesses, generated-model drift, and TypeScript checking.
  The authoritative native Windows suite passes 1,977 tests and 14,923
  assertions across 210 files in 496.94 seconds, with 27 intentional platform or
  integration skips and zero failures.
- Preserved failed live campaign
  `2e7279a06889e5490dc3526f41632a40f8d8d999404dca55d540a5c83be15e0d`
  as a benchmark counterexample. The scanner correctly rejected the first
  fixture because its pattern ran over only three short fixed strings, yielding
  one benchmark false negative but no reportable security impact. The corrected
  pair adds the independently supplied bounded subject, and the stricter host
  quality gate now requires subject/work amplification evidence so harmless
  dynamic regular expressions do not become availability findings.
- Preserved corrected campaign
  `c6452f14a702bb7bb329c8e8078b81a52e4dcdc2a826cd1c1223ba27c8360519`
  as a second ground-truth counterexample. It found the exact workload-backed
  defect and kept the fixed-pattern control clean, but the manifest counted the
  medium CWE-1333 report as unexpected because it accepted only high/critical
  CWE-400/CWE-730. The corpus now accepts CWE-1333 as the specific uncontrolled
  search-pattern class and medium severity when deployment exposure remains
  unknown, while its field-specific workload, shared-event-loop, evidence, and
  negative-control gates remain mandatory.
- Final exact-revision campaign
  `dba2cf8001efda9f58fab6767b87eca48a51c1551b582cb96a807e0765419c0c`
  closes the counterexample loop at public commit
  `88367a1e3edeb55348b22d8ff6fc9bb9a77851a2`. Both deep high-effort scans
  complete on attempt one with complete coverage. The exploit produces one
  medium CWE-1333 finding that independently traces MCP registration, both
  bounded input properties, the `searchText` helper, pattern construction,
  synchronous execution, nonlinear work, and the shared Node event loop; the
  fixed-pattern control produces no finding. All strict completion, precision,
  recall, F1, case, negative-case, stability, validation, attack-path,
  code-evidence, severity, and semantic gates equal one, with zero false
  positives or false negatives. A finalize-only rebuild verifies the same
  campaign, corpus, comparison-policy, scanner, package, source, fixture, and
  sealed artifact hashes. The two runs consume 3,087,003 input, 2,682,221
  cached, and 51,655 output tokens over 664,626 ms of cumulative worker time;
  no authentication, allowance, rate-limit, classifier, transport, timeout, or
  retry event occurs.
- Exact-checkpoint self-review is byte-for-byte stable. Two compiled scans of
  the 3,570-file tracked-only archive emit 256 rows, 555,898 bytes, and SHA-256
  `3a7dc85e52b995f7a1e4cd8fe86f71d7b25c404d3fd16f3302c5eb5e366fd675`
  in 27,578.952 and 10,627.158 ms. Independently rooting the archived exploit
  emits one complete MCP regex model at execution line 8 plus one generic
  complexity lead; repeated output is 2,331 bytes with SHA-256
  `c45ed172cc1efd2b389049094c1ca5275aef583a38fd5b2104b4f480822250e5`.
  The matched control emits the empty SHA-256 on both passes. Strict Windows
  and Ubuntu/WSL consumers validate the same 299-entry, 2,333,795-byte package
  with SHA-256
  `00f22a1c99301b7d20aa96449bd4bb5b1bd1894c504fc6a36946d07471bf5826`,
  including the public import, executable CLI, and all 79 bundled plugin
  files. The local pack correctly omits registry publish-time `gitHead`; its
  standard contract passes, and exact hosted checkout supplies provenance.
  The production advisory audit is clean.
- All eleven exact-head workflow families pass at `88367a1`: Node
  `33182642390`, Windows GUI `33182642395`, Linux GUI `33182642391`, container
  `33182642452`, Java `33182642367`, Kotlin `33182642349`, .NET `33182642397`,
  Go `33182642369`, Rust `33182642384`, Ruby `33182642365`, and PHP
  `33182642363`. The Node matrix includes all twelve bounded MCP witnesses on
  Windows and Ubuntu. The repository remains public on default branch `main`.
- Added deterministic `node-mcp-tool-code-injection` coverage for official MCP
  TypeScript SDK tool input reaching actual JavaScript execution. The model
  accepts only the live unshadowed global `eval` or exact named, namespace,
  default, CommonJS, and TypeScript import-equals bindings of `vm`/`node:vm`
  `runInContext`, `runInNewContext`, and `runInThisContext`. It preserves local
  assignment and same-file helper provenance, emits CWE-94/CWE-95, and rejects
  fixed code, wrong modules, evaluator parameters and declarations, overwritten
  input, tests, comments, strings, and unrelated member calls that borrow an
  imported identifier's spelling.
- Kept execution closure stricter than constructor-only rules. `Function`,
  `vm.compileFunction`, `new vm.Script`, and `new vm.SourceTextModule` do not
  produce an execution finding until a later model proves invocation or
  evaluation. A dedicated field-local quality gate requires both validation
  and attack path to identify the MCP caller, input schema limitation, exact
  evaluator, JavaScript-source boundary, CWE, and concrete in-process effect;
  the correction prompt permits only fixed side-effect-free arithmetic.
- Added a real `@modelcontextprotocol/server` 2.0.0 exploit/control pair. The
  exploit passes an expression through `evaluateExpression` to direct `eval`;
  its witness evaluates only fixed inert arithmetic and object values. The
  topology-matched control preserves the schema, tool, helper, arithmetic
  result, and response while an explicit numeric `+`/`*` grammar rejects the
  object expression without dynamic evaluation. Both Windows and native WSL
  witnesses pass.
  The strict MCP manifest now contains ten cases, hosted Node CI includes ten
  Windows/Linux witnesses, and the canonical corpus contains 161 pairs, 322
  cases, and 966 repeated scan positions. Focused Windows and native WSL lanes
  each pass 54 tests and 2,677 assertions with TypeScript clean.
- Full local acceptance passes 1,970 tests and 14,869 assertions across 210
  files in 552.75 seconds, with 27 intentional platform or integration skips.
  The managed Windows process denied the nested-Git and private-ACL boundary
  tests; the unchanged native rerun passes all 48 tests and 242 assertions.
  Generated-model drift, formatting, TypeScript, the clean production build,
  and the production advisory audit are green. Compiled inventory emits exactly
  one structured code-evaluation row for the exploit and none for its parser
  control. Isolated Windows and native WSL consumers validate the public import,
  executable CLI, and all 79 bundled plugin files.
- Final evidence at exact implementation checkpoint
  `4d4d4a454006357cd942a4444ba81f9d4d0e8211` is green. Two compiled reviews
  of a root-level tracked archive take 29,042.671 and 10,597.841 ms and produce
  256 byte-identical rows, 557,948 bytes, and SHA-256
  `d90bcb95b7bfe0557e9e7d5ce122a295fb3a986b333ea553e3514634744dceab`.
  The repository review intentionally excludes benchmark fixture paths from
  the MCP application model; independently rooting the exact archived pair
  produces one line-7 code-evaluation row with the complete source, sink,
  helper, and CWE contract for the exploit and none for the control. Their
  repeated inventories are byte-identical with SHA-256 values
  `54ea1d682728ae83b02fc90cce9ac9091b779cbbb8c574909fc36fa003476e8b`
  and `37386a2cb61f160da8c53c479371049904e1e00a711d187d72ffc46f9cf0a43c`.
  Strict inspection validates a 299-entry, 2,299,273-byte npm archive with
  SHA-256
  `8c8e04e224fca3d1e0c1355462adc1bfdf9ccb965d299ffdfa7ad8529541d82b`.
  Live campaign
  `3720809396b82d0a25f427516b9602f347ffeaef7a27bb99e7ceca1032efcfab`
  completes both deep high-effort cases on attempt one: one true positive, a
  clean parser control, zero false positives or false negatives, and every
  strict completion, precision, recall, F1, negative-case, stability,
  validation, attack-path, code-evidence, and severity rate equal to one.
  Recomputed findings, coverage, and manifest hashes match both sealed run
  receipts. No authentication, allowance, rate-limit, classifier, transport,
  timeout, or retry event occurs. All eleven exact-source workflows pass, and
  the repository remains public on default branch `main`.
- Promoted a live benchmark counterexample into deterministic coverage. The
  first six-case MCP filesystem campaign at public revision
  `f16dc15e8d87f4cedf7b8259252d1c904edf09b5` completed every deep scan on
  attempt one with complete coverage and no authentication, allowance,
  rate-limit, classifier, timeout, or retry event. The new path exploit passed
  every evidence and semantic gate and its fixed-file control remained clean,
  but the campaign correctly found that the supposed command argv control was
  still vulnerable to Node interpreter-option injection. A bounded local
  check confirmed `--version` and `--help` were consumed as runtime options,
  and a fixed `--eval` spelling replaced the intended inert script. The SSRF
  finding was correct but omitted required schema-control and MCP-caller terms
  from its field-local validation and attack path. Campaign
  `a54b3338e3e1eba8b76d6a95ad40e077620a72858cf3c5d4f6a54f4ddb2edb3b`
  therefore failed honestly at 0.75 precision and 1.0 recall rather than
  suppressing the counterexample.
- The first three-case remediation campaign at public implementation revision
  `23b081f0ae6b7122934daa87303f372c7b735069` completed the new argument
  exploit, its end-of-options control, and the SSRF semantic regression on
  attempt one with complete coverage and no authentication, allowance,
  rate-limit, classifier, timeout, or retry event. Detection was exact at two
  true positives, zero false positives, precision/recall/F1 1.0, and a clean
  negative control. The strict report gate still failed honestly: argument
  validation used the bare `--` token without spelling out the option-region
  consequence, and the SSRF attack path omitted the modeled `loadUrl` helper
  hop. Campaign
  `ea7ac6bf5f3c91b682f932dd2ca7055c0dfa283b2a5d6abc7f6807f9fe7dc6b0`
  consumed 4,109,128 input, 3,311,616 cached, and 83,497 output tokens over 14
  minutes 9 seconds of cumulative worker time and about 9 minutes 22 seconds
  of wall time.
- Hardened the host-owned MCP finding-quality audit rather than weakening the
  corpus. A bare `--` no longer satisfies interpreter-option explanation by
  itself, and every recorded `mcp-tool-helper-call` now contributes its exact
  symbol as a dynamic validation and attack-path requirement. The correction
  prompt requires field-local option-region wording and exact same-file helper
  provenance. Focused Windows and native WSL lanes each pass 49 tests and 2,622
  assertions after this second-order correction; TypeScript and a clean
  production build pass on Windows.
- Exact-revision campaign
  `77aba49e309013f79ff7c324f25d1d5558f774adfa500126d260a57deabb9fbe`
  confirms the correction at public commit
  `59a17928c10b6f5195d3c5ffb69a2b7a3a5797cb`. The argument-injection and
  SSRF positives both completed on attempt one with one high finding, complete
  coverage, and accepted field-local validation, attack path, code evidence,
  severity, and content semantics. The selected campaign passes every perfect
  gate: two true positives, zero false positives or misses, and 1.0 precision,
  recall, F1, case pass, stability, validation, attack-path, code-evidence, and
  severity rates. It consumed 2,737,904 input, 2,046,464 cached, and 69,580
  output tokens over 10 minutes 21 seconds of cumulative worker time and about
  5 minutes 53 seconds of wall time, with no classifier, allowance,
  rate-limit, authentication, timeout, or retry event.
- Added `node-mcp-tool-argument-injection` with schema 1.2 source, sink,
  helper, registration, and control provenance plus CWE-88/CWE-94. Exact
  `execFile` or `spawn` calls using `process.execPath` now split literal argv,
  locate the tool-controlled element, and require an exact `--`
  end-of-options element before it. Fixed executables remain strong
  shell-injection counterevidence, but no longer erase interpreter-option
  injection. New field-local quality requirements force both validation and
  attack path to name the MCP caller, schema-only control, Node runtime,
  option region, end-of-options boundary, and concrete interpreter effect.
- Corrected the original argv control by inserting `--` and extending its
  witness with dash-prefixed inputs. Added a separate real
  `@modelcontextprotocol/server` 2.0.0 argument-injection/control pair: the
  positive consumes only inert `--version`, while the control proves ordinary,
  `--version`, and `--help` strings remain script data. The strict MCP manifest
  now has eight cases, Node CI runs eight witnesses on Windows and Linux, and
  the canonical corpus has 160 pairs, 320 cases, and 960 repeated scan
  positions.
- The remediation-focused Windows and native WSL lanes each pass 49 tests and
  2,620 assertions. The full managed Windows aggregate exercises 1,994 tests:
  1,965 pass, 27 intentional platform/integration skips remain, and two are
  denied only at the nested-Git and private-Windows-ACL host boundaries. The
  complete two-file native rerun passes all 48 permission-sensitive tests and
  242 assertions. Formatting, generated-model drift, TypeScript, production
  build, and the production advisory audit are green; no known production
  vulnerabilities were reported.
- Isolated Windows and native WSL package consumers validate public import,
  CLI execution, and all 79 bundled plugin files. Both archives contain 299
  entries. The 2,295,107-byte Windows archive has SHA-1
  `8ce4f983b6b35d9824d10be65d49b7dd617ebc1f` and SHA-256
  `d855338f684bc6d20cc540a1912b3bddc4a8ba7059a671a2f022a72fe9fb12cd`;
  the 2,295,118-byte WSL archive has SHA-1
  `fe3464cce2812b4e6c6253259ef1d8235c1686cd` and SHA-256
  `7b97f65eaab77497dcc57c0d04f8a0684110384884a71213291b48db3fa05b76`.
- Two production-build inventories of a 3,540-file tracked-only archive of
  public filesystem checkpoint `f16dc15e8d87f4cedf7b8259252d1c904edf09b5`
  complete in 10,202.859 and 10,556.737 ms and are byte-identical at the
  256-row cap, 559,541 bytes, and SHA-256
  `cc1c59d537047fefae3343046f4904a29c602c813b1d35c2e51e1cf0340eb397`.
  The 5,411,477-byte archive has SHA-256
  `43ab8f1899879690781bd756167cb084a6813d099df828e747feb55d71f9b67d`.
  An independently rooted path fixture emits exactly one structured MCP path
  row at `src/server.mjs:12` with tool-input source line 25,
  `writeFile:path[0]`, CWE-22/CWE-73, and helper provenance; its fixed twin
  emits no MCP path row.
- Two production-build inventories of the 3,550-file tracked-only public
  interpreter-option checkpoint
  `23b081f0ae6b7122934daa87303f372c7b735069` complete in 10,329.532 and
  9,923.145 ms and are byte-identical at the 256-row cap, 557,948 bytes, and
  SHA-256
  `d90bcb95b7bfe0557e9e7d5ce122a295fb3a986b333ea553e3514634744dceab`.
  The 5,423,185-byte archive has SHA-256
  `2f8531b73739d0eb0402bfe602ce737108753e618de58265c4d9f45dacaf4476`.
  An independently rooted exploit emits one structured
  `node-mcp-tool-argument-injection` row at `server.mjs:9`, sourced from tool
  input line 27, with `execFile:argv[2]`, CWE-88/CWE-94, registration, and
  `runCommand` helper provenance. The independently rooted `--` control emits
  no structured row.
- The final field-local provenance checkpoint
  `59a17928c10b6f5195d3c5ffb69a2b7a3a5797cb` retains 3,550 tracked files.
  Its 5,425,222-byte tracked-only archive has SHA-256
  `1d2b4a043a450337d4e0ae41e955d2e2ac79c3825e2fbe4abed60d82a5d3d2e3`.
  Two inventories complete in 10,182.611 and 10,458.618 ms and remain
  byte-identical at 256 rows, 557,948 bytes, 210 structured rows, 46 lexical
  rows, and SHA-256
  `d90bcb95b7bfe0557e9e7d5ce122a295fb3a986b333ea553e3514634744dceab`.
  The exact independently rooted exploit/control sources still produce one
  structured interpreter-option row versus zero.
- All eleven hosted workflows pass at exact correction commit
  `59a17928c10b6f5195d3c5ffb69a2b7a3a5797cb`. Node run `33169917602`
  completes 23 jobs across supported Windows, Ubuntu, and macOS runtimes,
  package checks, and all eight MCP witnesses on Windows and Ubuntu. Windows
  GUI `33169917654`, Linux GUI `33169917700`, container `33169917715`, .NET
  `33169917616`, Go `33169917609`, Java `33169917642`, Kotlin `33169917691`,
  PHP `33169917659`, Ruby `33169917640`, and Rust `33169917606` also complete
  successfully with no failed workflow.
- Extended the standalone JavaScript/TypeScript MCP tool-handler model from
  process and network capabilities to Node filesystem authority. Exact
  `node:fs`, `node:fs/promises`, legacy `fs`, and `fs/promises` named,
  namespace, default, CommonJS, TypeScript import-equals, and `fs.promises`
  bindings now trace client-controlled tool input to every modeled path-bearing
  argument, including both source and destination paths for copy, rename, link,
  and symlink operations.
- Added `node-mcp-tool-path-traversal` schema 1.2 evidence with CWE-22/CWE-73,
  same-file helper-local propagation, filesystem-specific validation and
  attack-path closure, and a 75-case method/argument-position regression table.
  File contents, flags, modes, encodings, callbacks, fixed paths, local
  lookalikes, overwritten values, and unrelated helper arguments remain
  negative. `path.join` and `path.resolve` construction stays reviewable until
  an allowlist or boundary-safe canonical containment design proves it safe.
- Added a real `@modelcontextprotocol/server` 2.0.0 exploit/control pair with
  identical schema-bearing registration, two-input helper, `writeFile` effect,
  options, and response topology. The exploit demonstrates only a one-level
  escape inside a fresh disposable temporary tree; the control fixes the file
  URL and keeps an attacker-looking path string in file contents. Both
  witnesses pass on Windows and native Ubuntu/WSL. This checkpoint initially
  advanced the strict manifest to six cases and the canonical corpus to 159
  pairs, 318 cases, and 954 repeated scan positions; the later
  interpreter-option remediation above advances those counts again.
- Completed authoritative Windows acceptance for the MCP filesystem increment:
  1,964 tests pass with 27 intentional platform/integration skips, no failure,
  and 14,787 assertions across 210 files in 477.45 seconds. Focused Windows and
  native Ubuntu/WSL gates each pass 46 tests and 2,589 assertions. Formatting,
  generated-model drift, TypeScript checking, a clean production build, and
  the production dependency audit are green; the audit reports no known
  vulnerabilities.
- Validated independently packed Windows and native Ubuntu archives through
  isolated installation, public import, CLI execution, and all 79 bundled
  plugin files. Both contain 299 entries. The 2,292,791-byte Windows archive
  has SHA-1 `bd88c776384f626730e9ecd8dadf21ce94893bc5` and SHA-256
  `7bb1534fb7d1e53a101c6a9841d84bde2c297ecac417dfe5e393b77c16202858`;
  the 2,292,804-byte native Ubuntu archive has SHA-1
  `cc341599a33513bdfeee72d9e2bbdd60d2fb3a11` and SHA-256
  `4aee804faca6645295825b515bacd03c8ded2c29ed1ae3b09ab4b2a3a81bd8ea`.
- Added a standalone JavaScript/TypeScript MCP tool-handler model for the
  stable `@modelcontextprotocol/server` API and the legacy
  `@modelcontextprotocol/sdk/server/mcp.js` API. Exact `McpServer`
  registrations, schema-bearing v2 `registerTool` callbacks, schema-bearing
  v1 `tool` callbacks, destructured and object callback inputs, local
  assignments, same-file function/arrow/function-expression helpers, ESM and
  CommonJS bindings, and server aliases now feed command-injection and SSRF
  candidates into deterministic discovery.
- Distinguished shell command strings, shell-enabled spawn, interpreter
  commands, and attacker-selected executables from fixed executable plus
  separate argv data. Network modeling covers global and imported `fetch`,
  Undici, Node HTTP/HTTPS, and Axios destinations while excluding body-only
  data, same-host paths, fixed destinations, fixed argv, reassigned inputs,
  schema-less context callbacks, tests, comments, strings, shadows, and SDK or
  process lookalikes.
- Added host-enforced MCP-specific validation and attack-path proof
  obligations, bounded loopback validation guidance, a strict four-case
  specialized manifest, and four real `@modelcontextprotocol/server` 2.0.0
  fixtures. Exploit witnesses demonstrate only inert process output or a
  disposable loopback request; matched controls prove argv and fixed-origin
  boundaries. The canonical corpus now has 158 vulnerable/control pairs, 316
  cases, and 948 repeated scan positions. Node CI executes every witness on
  Windows and Linux.
- Completed authoritative Windows acceptance for the MCP tool-handler
  increment: 1,957 tests pass with 27 intentional platform/integration skips,
  no failure, and 14,591 assertions across 210 files in 490.11 seconds.
  Formatting, generated-model drift, TypeScript checking, the clean production
  build, and the production dependency audit are clean; the audit reports no
  known vulnerabilities. Focused Windows and native Ubuntu gates each pass 39
  tests and 2,393 assertions, and all four package-backed witnesses pass on
  both systems.
- Validated independently packed Windows and native Ubuntu archives through
  isolated installation, public import, CLI execution, and all 79 bundled
  plugin files. Both contain 299 entries. The 2,321,304-byte Windows archive
  has SHA-1 `201cafc71ec8bb7797ae2a548feb2467ff3f3aed` and SHA-256
  `3f0185a430fae0a0a29f03580f1e2d100a02dd690d5461f2f468115fed344005`;
  the 2,290,059-byte native Ubuntu archive has SHA-1
  `29e11293445ee11c15e7cb61296302c1752bd9a4` and SHA-256
  `85f0973ba936b4786ee1ef8ef2040de047fcc34c42396e3c33073e1e6236b1df`.
- Ran all four MCP exploit/control cases through strict live deep Copilot
  scanning at exact public implementation revision
  `e83a3ab7093e4769e8d9e74ed6dd68b8a1cc0c51`, with two workers and the
  bounded ten-attempt recovery policy. Every case completed on attempt one
  with complete coverage and no authentication, allowance, rate-limit,
  classifier, timeout, or retry event. The command exploit produced one
  critical finding, the SSRF exploit produced one high finding, and both
  matched controls remained clean. Precision, recall, F1, case accuracy,
  negative accuracy, stable detection, validation, attack path, code evidence,
  severity, and completion are all `1`, with zero false positives and false
  negatives. Campaign
  `08542e73eb4a7e7c70b6416ab8db038159782698c1ac5e1f0961e0b0a795d09b`
  used 9,034,043 input tokens, including 7,969,610 cached tokens, and 175,618
  output tokens in 37 minutes 58.812 seconds of cumulative worker time and 20
  minutes 48.933 seconds of campaign wall time.
- Two deterministic production-build residual inventories of a 3,530-file
  tracked-only archive of that exact revision are byte-identical at the
  256-record cap and 562,434 bytes, with SHA-256
  `e2ab8f32cd775358a89f5d30fcb437919285ef1a9dfcd9a7526612de84d4c0d5`.
  The archive SHA-256 is
  `2b89641c9e3a92859d0681e9c1a23b6f5edfd7f147ca497165db47f2072c82f3`.
  An independently rooted SDK inventory emits no MCP tool-handler row. The
  command and SSRF exploit fixtures each emit exactly their intended row at
  sink lines 9 and 7 respectively, while the matched argv and fixed-origin
  controls emit none.
- All eleven hosted workflow families pass the exact implementation revision:
  Node `33158601288`, container `33158601429`, Java `33158601213`, Kotlin
  `33158601263`, .NET `33158601242`, Go `33158601294`, Rust `33158601371`,
  Ruby `33158601280`, PHP `33158601190`, Windows GUI `33158601244`, and Linux
  GUI `33158601316`.
- Extended exact Java command-vector mutation through
  `java.util.Collections.copy` and `Collections.fill`. Copy overwrites only
  the destination prefix and rejects a source larger than the destination;
  fill replaces every existing element. Both preserve size, work on known
  mutable and fixed-size lists, treat empty operations as no-ops, and fail
  closed for nonempty unmodifiable, unresolved, malformed, or lookalike calls.
- Added adversarial coverage for caller aliases, live `builder.command()`
  destinations, inline and named sources, fixed-size lists, too-small
  destinations, unmodifiable lists, exact repairs, empty operations, and
  imported lookalikes. A fifth Spring 7.0.9/Java 21 pair preserves
  caller-owned `ArrayList` identity through `ProcessBuilder(List)` and copies
  either `sh -c` or fixed `printf` argv into the retained command. The focused
  manifest now has ten strict cases, and the canonical corpus has 156 pairs,
  312 cases, and 936 repeated scan positions.
- Completed authoritative Windows acceptance for the static rewrite increment:
  1,936 tests pass with 27 intentional platform/integration skips, no failure,
  and 14,490 assertions across 209 files in 514.66 seconds. Formatting,
  generated-model drift, TypeScript checking, a clean production build, and
  the production dependency audit are clean; the audit reports no known
  vulnerabilities. Focused native Ubuntu gates pass 118 tests and 3,501
  assertions, and both Java 21 Maven witnesses pass.
- Validated independently packed Windows and POSIX-strict Ubuntu archives
  through isolated installation, public import, CLI execution, and all 79
  bundled plugin files. The 295-entry, 2,265,788-byte Windows archive has
  SHA-1 `56776c8fedd5b596016f2af7689a989989d8d157` and SHA-256
  `e885cf9510a4b233874262760d17e12b3708635606de199804ba1cab2791f8f2`;
  the 295-entry, 2,265,816-byte native Ubuntu archive has SHA-1
  `54667c3e5636cc76f55b8f6fa306326babf26203` and SHA-256
  `a5252c2fd6cab03c82e7ad9b3ee37a7d693b235562f0fe23930ba23bf62fc392`.
- Ran the new copy exploit/control pair through strict live deep Copilot
  scanning at exact public implementation revision
  `5fd98134b558f76f088ae192a714ddc236a25098`, with two workers and the
  bounded ten-attempt recovery policy. Both cases completed on attempt one
  with complete coverage and no authentication, allowance, rate-limit,
  classifier, timeout, or retry event. The exploit produced one critical
  validated finding and the topology-matched argv control produced none, so
  precision, recall, F1, case accuracy, negative accuracy, stable detection,
  validation, attack path, code evidence, severity, and completion are all
  `1`, with zero false positives and false negatives. Campaign
  `6a0108841ea0f9df03561c4c547e2302e3e9c673ad6c3ef786a3b2de81ccd66f`
  used 4,090,209 input tokens, including 3,034,221 cached tokens, and 138,474
  output tokens in 14 minutes 37 seconds of cumulative scanner time.
- Two deterministic production-build residual inventories of a 3,507-file
  tracked-only archive of that exact revision are byte-identical at the
  256-record cap and 564,069 bytes, with SHA-256
  `8c2dde78157d113b130c384db986f03647a3586a02e06a3bd265a5703ba16488`.
  The archive SHA-256 is
  `1eeb737cc951eef9f1cdc8358986f537051660e15e4e679eaa4ab05b11c560e7`.
  An independently rooted SDK inventory emits no Spring Java command row;
  the exploit emits exactly one at sink line 20, sourced at line 14, with
  command-list-mutation, caller-list-binding, and process-execution
  provenance, while the matched argv control emits none.
- All eleven hosted workflow families pass the exact implementation revision:
  Node `33152938924`, container `33152938885`, Java `33152938954`, Kotlin
  `33152938961`, .NET `33152938917`, Go `33152938948`, Rust `33152938899`,
  Ruby `33152938895`, PHP `33152938936`, Windows GUI `33152938903`, and Linux
  GUI `33152938943`.
- Extended caller-owned Java command state to exact imported and fully
  qualified `java.util.LinkedList` construction, including independent
  collection-copy construction. The model now handles Java 21
  `List.addFirst`/`addLast`/`removeFirst`/`removeLast` operations without losing
  ordered command identity.
- Added exact `java.util.Collections.addAll` mutation through command-list
  aliases and `ProcessBuilder.command()` getter expressions. Non-empty calls
  append each vararg through the destination's capability; empty calls are
  proven no-ops; fixed-size and unmodifiable failures, invalid constructors,
  unresolved operations, and local or imported lookalikes fail closed.
- Strengthened Java correction and finding-quality guidance with `LinkedList`,
  static bulk mutation, and sequenced-list evidence. A fourth Spring
  7.0.9/Java 21 pair preserves a caller-owned linked list, no-copy builder
  binding, static mutation, execution, timeout, stdout, and response topology
  while contrasting `sh -c` with fixed `printf` argv. Both native Ubuntu
  witnesses pass. The specialized manifest now has eight strict cases, and
  the canonical corpus has 155 pairs, 310 cases, and 930 repeated scan
  positions.
- Completed authoritative Windows acceptance for the static/sequenced-list
  increment: 1,934 tests pass with 27 intentional platform/integration skips,
  no failure, and 14,459 assertions across 209 files in 506.01 seconds.
  Formatting, generated-model drift, TypeScript checking, a clean production
  build, and the production dependency audit are clean; the audit reports no
  known vulnerabilities. Focused native Ubuntu gates pass 116 tests and 3,470
  assertions, and both new Java 21 Maven witnesses pass.
- Validated independently packed Windows and POSIX-strict Ubuntu archives
  through isolated installation, public import, CLI execution, and all 79
  bundled plugin files. The 295-entry, 2,264,401-byte Windows archive has
  SHA-1 `4643279b18f0dd5ed53780eba3eb53b0c06ad4e8` and SHA-256
  `912d9f7d296aa5690a2b2089908ed647fe96b24afbc4643e9baccc4e3bca04a4`;
  the native Ubuntu archive has 295 entries, is 2,264,425 bytes, and has SHA-1
  `589f52a2f98012f1f12a601a06ff3ab06a0137b2`.
- Ran the new exploit/control pair through strict live deep Copilot scanning
  with two concurrent workers and bounded ten-attempt retry policy. Both scans
  completed on attempt one with complete coverage and no authentication,
  allowance, rate-limit, or classifier failure. The exploit produced one
  critical validated finding and the control produced none: precision, recall,
  F1, case accuracy, negative accuracy, validation, attack-path, code-evidence,
  severity, and stability scores are all `1`, with zero false positives and
  false negatives. Campaign
  `b6771b03f26c2e1d4424b75833b49619a6c0228567b95d1e363b61a464171fda`
  used 5,807,967 input tokens, including 5,136,361 cached tokens, and 101,618
  output tokens across 22 minutes 42 seconds of wall-clock scan time.
- Repeated the canonical pair three times at exact public implementation
  revision `b4d6b201d5874836d083a6a720e18e1c9bd55619`. All six deep scans
  completed on attempt one with complete coverage: the exploit was detected
  in all three runs and the control remained clean in all three. Campaign
  `fd65882ed35a11a42dda843ac4cbab3c20c39791c1841176b7ec05e03e0926df`
  has three true positives, zero false positives or false negatives, and `1`
  for every strict quality and stability metric. Two concurrent workers used
  8,427,865 input tokens, including 6,803,429 cached tokens, and 186,043 output
  tokens in 22 minutes 8 seconds of wall time; no authentication, allowance,
  rate-limit, or classifier event occurred.
- Two deterministic residual reviews of a 3,499-file tracked-only archive of
  that exact revision are byte-identical at the 256-record cap and 561,804
  bytes, with SHA-256
  `e4bc7a98a3fb5e3f0da9591860bcfd338460f34518092c5126ea36ddbe438231`.
  The archive SHA-256 is
  `78a2dff76ec77d7a14ca89fbbff6abcdc4c94db07120a2f642012144833c452c`.
  The independently rooted SDK emits no Spring Java command row; the exploit
  emits exactly one at line 19 with mutation, caller-list-binding, and process
  execution provenance, while the matched argv control emits none.
- All eleven hosted workflow families pass the exact implementation revision:
  Node `33149476632`, container `33149476660`, Java `33149476717`, Kotlin
  `33149476675`, .NET `33149476641`, Go `33149476646`, Rust `33149476677`,
  Ruby `33149476630`, PHP `33149476628`, Windows GUI `33149476689`, and Linux
  GUI `33149476692`.
- Preserved caller-owned Java command-list identity through the documented
  no-copy `ProcessBuilder(List)` and `ProcessBuilder.command(List)` boundaries.
  Local `ArrayList` values and aliases now share one command-vector state with
  every bound builder until replacement; copied `ArrayList` values receive a
  distinct vector, and later builder replacement detaches the earlier caller
  list. Tainted post-binding changes can no longer disappear into an anonymous
  argument-array snapshot.
- Added collection capability semantics to the Spring Java process model.
  Resizable `ArrayList` supports `set`, `add`, exact `addAll`, indexed
  insertion/removal, and `clear`; fixed-size `Arrays.asList` supports `set` but
  rejects size-changing
  operations; unmodifiable `List.of` rejects every mutation. Unsupported,
  impossible, immutable, and fixed-size-changing operations fail closed, while
  exact repairs and detached-list mutations remain negative controls.
- Added `java-caller-command-list-binding` provenance, matching validation and
  attack-path obligations, and correction guidance for caller-owned no-copy
  lists and their capabilities. A third Spring 7.0.9/Java 21 exploit/control
  pair executes the same `ArrayList`, alias, process, timeout, stdout, and
  response topology; only `sh -c` versus fixed `printf` argv differs. Both
  native Ubuntu witnesses pass. The specialized manifest now has six strict
  cases, and the canonical corpus has 154 pairs, 308 cases, and 924 repeated
  scan positions.
- Completed authoritative Windows acceptance for the caller-list increment:
  1,931 tests pass with 27 intentional platform/integration skips, no failure,
  and 14,425 assertions across 209 files in 499.64 seconds. Formatting,
  generated-model drift, TypeScript checking, a clean production build, and
  the production dependency audit are clean; the audit reports no known
  vulnerabilities. Focused Linux compiler and scanner gates pass 112 tests and
  3,431 assertions, and both Java 21 Maven witnesses pass.
- Validated the 295-entry package on Windows and POSIX-strict Ubuntu through
  isolated installation, public import, CLI execution, and all 79 bundled
  plugin files. The 2,292,693-byte archive has SHA-1
  `6005d7768d8afad49aa57b513b22ade3b7770685` and SHA-256
  `7e2032655bd1eb8d5b6cbc0fa911fec66a060b5c41b1f5d14b3d5d82901eeac2`.
- Repeated deterministic residual review against a disposable tracked-only
  archive of public revision `0c38212172411f7f9bd538c1f21676b2226f9140`.
  Both whole-repository inventories are byte-identical at the 256-record cap
  and 559,742 bytes, with SHA-256
  `d07c41289099cca745829c42157d28a8e09a9f5133d0162cc06b40b4538c3fa2`.
  The independently rooted SDK inventory emits no Spring Java command row;
  the caller-list exploit emits exactly one at line 22 with mutation,
  caller-list-binding, and process-execution provenance, while the matched
  argv control emits none.
- All eleven hosted workflow families pass the exact implementation revision:
  Node `33144720489`, container `33144720531`, Java `33144720477`, Kotlin
  `33144720492`, .NET `33144720484`, Go `33144720527`, Rust `33144720511`,
  Ruby `33144720509`, PHP `33144720516`, Windows GUI `33144720490`, and Linux
  GUI `33144720491`.
- Extended the exact Spring Java command model through the documented live
  identity of `ProcessBuilder.command()`. Direct and aliased `set`, `add`,
  indexed insertion, `remove`, and `clear` now update the effective command;
  builder aliases share state, while a later `command(...)` replacement
  detaches previously returned list views. Impossible indices, unresolved
  operands, exceptional shapes, and unsupported mutators fail closed instead
  of preserving stale dangerous state.
- Added `java-command-list-mutation` provenance and variant-specific Java
  finding-quality obligations. Validation and attack-path fields must now
  identify the exact shell, interpreter, split-command, or executable-selection
  boundary; live-list rows must additionally explain the getter/mutation edge,
  and delegated `env` or `Runtime.exec` rows must retain those dispatch edges.
  The correction prompt distinguishes the zero-argument getter from command
  replacement and requires bounded mutation and detachment reasoning.
- Added a topology-matched Spring 7.0.9/Java 21 live-command-list pair. Both
  fixtures obtain and alias the getter's actual list, clear and rebuild it,
  start the process, capture stdout, and enforce a two-second timeout. Only the
  positive reconstructs `sh -c`; the control reconstructs fixed `printf` argv
  and preserves metacharacters as one literal argument. Both Maven witnesses
  pass on Ubuntu, and the focused Windows and Ubuntu lanes pass 39 tests and
  2,338 assertions. The canonical corpus now contains 153 pairs, 306 cases,
  and 918 repeated scan positions.
- Completed authoritative Windows acceptance for the live-list increment:
  1,924 tests pass with 27 intentional platform/integration skips, no failure,
  and 14,387 assertions across 209 files in 494.85 seconds. Formatting,
  generated-model drift, TypeScript checking, a clean production build, and
  the production dependency audit are clean; the audit reports no known
  vulnerabilities.
- Validated the 295-entry package on Windows and POSIX-strict Ubuntu through
  isolated installation, public import, CLI execution, and all 79 bundled
  plugin files. The 2,290,494-byte archive has SHA-1
  `cacf9314b9f84a8aff628eca11ae9d1883b1c3ee` and SHA-256
  `9f58862bf67501e77db79ab04589a7b90303cc857b5454626968866d2070086f`.
- Repeated deterministic residual review against a disposable tracked-only
  archive of public revision `f7106087e0d4c4fa0b5088decad013035fb318e6`.
  Both whole-repository inventories are byte-identical at the 256-record cap
  and 557,503 bytes, with SHA-256
  `d44274164d835c59b55dafc80f15a32fedeb9826485dd8cd45901259ab5ca0c7`.
  The independently rooted SDK inventory emits no Spring Java command row;
  the exploit fixture emits exactly one at line 21 with live-list mutation and
  process-execution provenance, while the matched argv control emits none.
- All eleven hosted workflow families pass the exact implementation revision:
  Node `33141073732`, container `33141073725`, Java `33141073874`, Kotlin
  `33141073801`, .NET `33141073731`, Go `33141073733`, Rust `33141073755`,
  Ruby `33141073739`, PHP `33141073745`, Windows GUI `33141073727`, and Linux
  GUI `33141073807`. The Node matrix covers Ubuntu Node 22, 24, 24.0.0, 26,
  and 26.0.0 plus macOS and Windows Node 22.
- Replaced the Java side of the broad `spring-http-command` proximity model
  for production Spring sources with `spring-java-command-injection`, an exact
  same-handler process model. It requires a supported Spring request-binding
  annotation and route mapping, follows Java assignment and concatenation,
  resolves constructor, fluent, and later `ProcessBuilder.command(...)` state,
  and requires actual `start()` or `Runtime.exec(...)` execution. The Kotlin
  and legacy loose-source fallback remains available outside the exact model's
  ownership boundary.
- Added exact Java command-position classification for executable selection,
  POSIX shells including intervening login flags, CMD, PowerShell, interpreter
  code flags, Windows batch consumers, `Runtime.exec(String)` tokenization,
  inline `String[]` command vectors, and POSIX `env` delegation. Ordinary argv,
  inert builders, overwritten dangerous state, non-routes, generated/test
  sources, and local/imported platform lookalikes remain negative controls.
- Made unqualified `List.of(...)` and `Arrays.asList(...)` command vectors
  conditional on an unshadowed `java.util` import; fully qualified factories
  remain exact. Project-local collection lookalikes now fail closed instead of
  being mistaken for a tainted executable.
- Added a topology-matched Spring 7.0.9/Java 21 fluent-builder exploit/control
  pair with bounded Maven witnesses and a perfect-gate specialized manifest.
  The canonical corpus now has 152 pairs, 304 cases, and 912 repeated scan
  positions. The dedicated model passes 16 tests and 59 assertions. The
  six-file adjacent lane passes 149 tests and 3,846 assertions on Ubuntu; on
  Windows it passes 148 tests and 3,845 assertions with one intentional
  symlink-capability skip.
- Added both Spring command fixtures to the hosted Java 21 Maven cache and
  verification lane. Local Ubuntu/WSL execution compiles each application and
  passes its one-test bounded process witness with no failure, error, or skip.
- Completed authoritative Windows acceptance for this increment: 1,919 tests
  pass with 27 intentional platform/integration skips, no failure, and 14,356
  assertions across 209 files in 501.60 seconds. Formatting, generated-model
  drift, TypeScript checking, a clean production build, and the production
  dependency audit are clean; the audit reports no known vulnerabilities.
- Validated the 295-entry package on Windows and POSIX-strict Ubuntu through
  isolated installation, public import, CLI execution, and all 79 bundled
  plugin files. The 2,285,786-byte archive has SHA-1
  `57fd1c4ff722fcb87e5bbbbdeae53db2ad6cf9bf` and SHA-256
  `071b3238396fae8ce4e1cac8a38b0ac00dc9495e10d30193433ae4b9ac9449ae`.
- Repeated deterministic residual review against a disposable tracked-only
  archive of public revision `8a61ea2016896584cd54ae74cf52afef82464960`.
  Both inventories are byte-identical at the 256-record cap and 555,117 bytes,
  with SHA-256
  `b91960e118d2d86f89080fb343ad08870aa8e768029fefc9e90f4e3b365628ef`.
  Scanner and test source emit no Java/Spring command row; independently
  rooting the exploit fixture emits exactly one shell-command row at
  `ProcessBuilder.start`, while the matched argv control emits none.
- All eleven hosted workflow families pass the exact implementation revision:
  Node `33137966098`, container `33137966111`, Java `33137966005`, Kotlin
  `33137966113`, .NET `33137966079`, Go `33137966084`, Rust `33137966100`,
  Ruby `33137966089`, PHP `33137966138`, Windows GUI `33137966136`, and Linux
  GUI `33137966021`.
- Extended Kotlin `Runtime.exec` command-vector recovery through exact
  `listOf`, `mutableListOf`, and `arrayListOf` values converted with
  `Collection.toTypedArray()`. Direct, fully qualified, retained, and aliased
  collection shapes preserve element positions and snapshot semantics;
  mutation of the resulting array remains live, while later mutation of the
  source list does not rewrite the already-created array. Local collection
  factories and `toTypedArray` extensions remain negative.
- Added `kotlin-runtime-array-conversion` attack-path provenance and made
  finding-quality closure require the conversion in both validation and
  attack-path prose when it lies on the recorded tainted path. The correction
  prompt now distinguishes list snapshots, later source-list changes, and live
  mutations of the converted command array.
- Preserved exact aliased string shapes while classifying POSIX `env` options
  and assignments. Aliased `--split-string=...`, `--unset=...`, and fixed-name
  `NAME=VALUE` operands retain their grammar, while reassignment and
  attacker-controlled prefixes invalidate the shape instead of suppressing a
  candidate.
- Added a topology-matched typed-resource `Runtime.exec` converted-list
  exploit/control pair with harmless native witnesses. Both Kotlin 2.2.20/Ktor
  3.5.2 fixtures compile and pass on Java 21 under Ubuntu/WSL. The specialized
  Kotlin manifest now has 18 cases; the canonical corpus has 151 pairs, 302
  cases, and 906 repeated scan positions. Focused Kotlin and canonical gates
  pass 50 tests and 2,641 assertions; formatting, generated-model drift, and
  TypeScript checks are clean.
- Completed exact-source acceptance for revision
  `d690f9238ecebe63aa260c5e5be4909c12e3d280`. The rebuilt Windows suite
  passes 1,903 tests and 14,286 assertions across 208 files in 497.60 seconds,
  with 27 intentional platform/integration skips and no failure. Ubuntu/WSL
  passes 163 tests and 3,908 assertions across the focused Kotlin, canonical
  corpus, residual-inventory, Copilot transport, and package-provenance lanes
  in 19.20 seconds, with one Windows-launcher skip and no failure. The
  production dependency audit reports no known vulnerabilities.
- Validated the exact-head package on Windows and Ubuntu. POSIX-strict and
  Windows inspection accept all 291 entries, and isolated installs validate
  the public import, executable CLI, and all 79 bundled plugin files. The
  archive occupied 2,261,617 packed and 11,679,982 unpacked bytes, retained
  `-rwxr-xr-x` on `bin/copilot-security.mjs`, and had SHA-1
  `09924fad29e2af35997ab66579c4185b60c6172a` and SHA-256
  `4155baa7d9f1132b93cb73c7f189e54016071d00f1527f47a57a2b12113deaa9`.
  The validated archive was removed.
- Repeated deterministic self-review against a disposable tracked-only archive
  of the exact revision. Both inventories are byte-identical at the 256-record
  cap and 552,767 bytes, with SHA-256
  `dd5e1b7418249e6586321677ee737f542b35b78fbb57aa1c31e7ade666e7a23f`.
  Scanner and test source emit no Kotlin command or Runtime row. Independently
  rooting the build at the converted-list exploit produces exactly one row
  with runtime, conversion, and delegated-launcher provenance; its matched
  argv control produces none. The temporary archive and inventories were
  removed.
- All eleven hosted workflow families pass the exact implementation revision:
  Node `33133856990`, container `33133856944`, Kotlin `33133857042`, Java
  `33133856817`, .NET `33133856971`, Go `33133857034`, Rust `33133856861`,
  Ruby `33133856855`, PHP `33133856821`, Windows GUI `33133856956`, and Linux
  GUI `33133856880`.
- Extended the deterministic Kotlin/Ktor process model to exact
  `java.lang.Runtime.exec` boundaries. The tokenized `exec(String)` overload is
  a split-command sink; `exec(arrayOf(...))` preserves explicit command-vector
  positions and reuses executable, shell, interpreter, batch, and delegated
  `env` classification. Direct, imported-alias, fully qualified, and retained
  runtime instances are recognized, as are exact array aliases and mutations.
  Local/imported lookalikes, unsupported `List` call shapes, fixed commands,
  and request values used only as ordinary argv remain negative.
- Added a topology-matched typed-resource `Runtime.exec`/`env` exploit-control
  pair pinned to Ktor 3.5.2, Kotlin 2.2.20, and Java 21. Both harmless witnesses
  compile and pass on Ubuntu/WSL with one test and no failure, error, or skip
  apiece. The specialized Kotlin manifest now has 16 cases; the canonical
  corpus has 150 pairs, 300 cases, and 900 repeated scan positions. Focused
  Kotlin and canonical regression passes 48 tests and 2,579 assertions with no
  failure.
- Made finding-quality closure require the real `Runtime.exec` edge in both
  validation and attack-path fields. A regression proves that correct Ktor,
  `env`, executable-selection, response, and witness prose still cannot close
  a runtime row until both fields name the runtime launch boundary. The quality
  correction prompt now distinguishes tokenized strings from explicit arrays
  and explicitly rejects the claim that ordinary array argv is shell grammar.
- Completed exact-source native acceptance for revision
  `e9ac09d463cd86b0b6ba95ba798cd6804d548575`. Windows passes 1,901 tests
  and 14,224 assertions across 208 files in 515.91 seconds, with 27 intentional
  platform/integration skips and no failures. Ubuntu/WSL passes 161 tests and
  3,846 assertions across the focused Kotlin, canonical corpus,
  residual-inventory, Copilot transport, and package-provenance lanes in 20.01
  seconds, with one Windows-launcher skip and no failure. The production
  dependency audit reports no known vulnerabilities.
- Built the exact-head package under Ubuntu and validated it on both operating
  systems. POSIX-strict and Windows inspection accept all 291 entries, and two
  isolated installs per operating system validate the public import,
  executable CLI, and all 79 bundled plugin files. The archive occupied
  2,259,669 packed and 11,884,544 unpacked bytes, retained `-rwxr-xr-x` on
  `bin/copilot-security.mjs`, and had SHA-1
  `54683acc3e965f38ff54bb2ae0c8c180e9a6ada8` and SHA-256
  `583f843788cb2e2eb5388fd10042e50e8b32a7af183dbaf28d1a4870d014b604`.
  The validated archive was removed.
- Repeated deterministic self-review against a disposable tracked-only archive
  of the exact revision. Both inventories are byte-identical at the 256-record
  cap and 552,767 bytes, with SHA-256
  `dd5e1b7418249e6586321677ee737f542b35b78fbb57aa1c31e7ade666e7a23f`.
  Scanner and test source emit no Kotlin command or Runtime row. Independently
  rooting the scanner at the new exploit produces exactly one Runtime framework
  row; its topology-matched argv control produces none. The temporary archive
  and inventories were removed.
- All eleven hosted workflow families pass the exact implementation revision:
  Node `33131671387`, container `33131671489`, Kotlin `33131671488`, Java
  `33131671447`, .NET `33131671476`, Go `33131671438`, Rust `33131671524`,
  Ruby `33131671501`, PHP `33131671478`, Windows GUI `33131671499`, and Linux
  GUI `33131671442`.
- Extended the deterministic Kotlin/JVM process model through POSIX `env`
  delegation. After recognized fixed options and `NAME=VALUE` assignments, the
  first remaining operand is recursively analyzed as the executable; nested
  shell and interpreter grammar retains its original sink kind and adjusted
  argument position. Tainted `-S`/`--split-string` command text has a distinct
  `kotlin-process-split-command` sink, while option arguments, assignment-only
  calls, unknown failing options, fixed delegated executables, and later argv
  remain negative. The new `kotlin-process-delegated-launcher` propagator
  records the exact `env` boundary.
- Added a topology-matched Ktor typed-resource `env` executable-selection and
  fixed-`printf` argv pair, each pinned to Ktor 3.5.2, Kotlin 2.2.20, Java 21,
  and a one-process fixed-string witness. The specialized Kotlin manifest now
  has 14 cases; the canonical corpus has 149 pairs, 298 cases, and 894 repeated
  scan positions. Focused Kotlin and canonical regression passes 45 tests and
  2,521 assertions with no failure. Both new Maven witnesses compile and pass
  on Ubuntu/WSL with one test, no failure, error, or skip apiece.
- Made Kotlin finding-quality closure sink-aware. Common Ktor source,
  `ProcessBuilder`, execution, response, and evidence obligations remain
  shared, while shell, interpreter, `env -S`, executable-selection,
  delegating-launcher, factory, and mutator semantics are required only for the
  variant actually recorded. A regression proves that generic process prose
  cannot close an `env` row until validation names executable selection and a
  delegating launcher and the attack path names executable selection and the
  delegated executable.
- Completed exact-source acceptance for delegated `env` handling. The rebuilt
  Windows suite passes 1,898 tests and 14,166 assertions across 208 files in
  475.85 seconds, with 27 intentional platform/integration skips and no
  failures. Ubuntu/WSL passes 158 tests and 3,788 assertions across the focused
  Kotlin, canonical corpus, residual-inventory, Copilot transport, and package
  provenance lanes, with one Windows-launcher skip and no failure. The
  production dependency audit reports no known vulnerabilities.
- Built the package from public revision
  `5c67fdc62f46c365438394c9417d56a8f2b0df46`. Windows and POSIX-strict
  inspection validate all 291 entries, and two isolated installs on each
  operating system validate the public import, executable CLI, and all 79
  bundled plugin files. The archive occupied 2,256,002 packed and 11,858,432
  unpacked bytes, retained `-rwxr-xr-x` on `bin/copilot-security.mjs`, and had
  SHA-1 `3df883b58a5105b6606981480a370c1e09680ed6` and SHA-256
  `3bebb4015b127e588173c00dc7c0c7ca532c69a4b790eb1c00b0313c661b0c43`.
  The validated archive was removed.
- Repeated deterministic self-review against a disposable tracked-only archive
  of revision `5c67fdc62f46c365438394c9417d56a8f2b0df46`. Both bounded inventories
  are byte-identical at the 256-record cap and 553,364 bytes, with SHA-256
  `e0e02c0a5fd199ecf86d809957031322d5796e158a639fd726a70acaf1ffefcd`.
  Independently rooting the scanner at the new exploit produces exactly one
  framework row carrying delegated-launcher and executable-selection evidence;
  the topology-matched argv control produces none. The temporary archive and
  inventories were removed.
- All eleven hosted workflow families pass exact implementation revision
  `5c67fdc62f46c365438394c9417d56a8f2b0df46`: Node `33129523493`,
  container `33129523472`, Kotlin `33129523509`, Java `33129523483`, .NET
  `33129523467`, Go `33129523465`, Rust `33129523461`, Ruby `33129523481`,
  PHP `33129523514`, Windows GUI `33129523503`, and Linux GUI
  `33129523448`.
- Extended `kotlin-ktor-command-injection` across two bounded same-file helper
  boundaries. A uniquely named top-level factory with an explicit exact
  `ProcessBuilder` return type may now contribute a direct constructor and
  optional fluent `command(...)` to a later `start()`. A uniquely named
  top-level mutator with exactly one typed `ProcessBuilder` parameter and one
  `builder.command(...)` statement may replace the live command before launch.
  Caller arguments are substituted positionally into the helper command, so
  request taint, literal argv, shell/interpreter placement, and safe later
  replacement retain their existing meaning. New
  `kotlin-process-builder-factory`, `kotlin-process-command-helper`, and
  `kotlin-process-helper-call` propagators make the interprocedural edge
  explicit in deterministic findings and reviewer evidence.
- Kept helper inference deliberately fail-closed. Overloaded names,
  named/default-argument calls, wrong arity, member or extension dispatch,
  callbacks, dynamic resolution, multiple returns, side effects, and
  nontrivial bodies do not produce summaries. A safe helper replacement can
  remove an earlier dangerous command, while a later direct safe `command(...)`
  replacement clears obsolete helper provenance. This adds useful
  interprocedural reach without turning an unresolved Kotlin call into a sink.
- Added topology-matched typed-resource factory and command-mutator
  exploit/control pairs. The four Ktor 3.5.2/Kotlin 2.2.20 applications compile
  on Java 21 under Ubuntu and their fixed-string witnesses each pass with one
  short-lived process, no network, file, credential, or persistence effect.
  The specialized Kotlin manifest now has 12 cases and the canonical corpus has
  148 pairs, 296 cases, and 888 repeated scan positions. Focused Kotlin plus
  canonical regression passes 41 tests and 2,464 assertions with no failure.
- Completed rebuilt native and cross-platform acceptance for the helper-summary
  increment. The authoritative Windows suite passes 1,894 tests and 14,109
  assertions across 208 files in 498.84 seconds, with 27 intentional
  platform/integration skips and no failures. Ubuntu/WSL passes 154 tests and
  3,731 assertions across the focused Kotlin, canonical corpus,
  residual-inventory, Copilot transport, and package-provenance lanes, with one
  Windows-launcher skip and no failure. Formatting, generated-model drift,
  TypeScript checking, the production build, and the production advisory audit
  are clean; the audit reports no known vulnerabilities.
- Ran deep/xhigh four-case Copilot campaign
  `0a4c8f61351c4e0f4ea6ac64b61b9e279c82c6347800891985129da9e6f84307`
  against both new helper pairs with stored GitHub authentication, two bounded
  workers, six available fresh attempts, a 30-minute process-tree deadline, and
  no artificial credit ceiling. Every case completed on attempt one with status
  0, complete coverage, no timeout, and no classifier, quota, rate-limit, or
  authentication failure. The factory exploit produced one critical finding in
  10m11s, its argv control produced none in 3m23s, the command-helper exploit
  produced one high finding in 6m23s, and its argv control produced none in
  5m59s. Precision, recall, F1, stability, validation, attack-path,
  code-evidence, severity, and negative-case metrics were all 1.0.
- Refused to count the first campaign as a complete pass because its factory
  finding flattened `diagnosticProcess(commandLine).start()` into a nonexistent
  direct constructor/start expression. Validation and attack-path fields omitted
  the same-file factory edge even though code evidence contained it, leaving
  case pass rate at 0.75. Finding-quality closure now derives extra field-local
  groups from `kotlin-process-builder-factory` and
  `kotlin-process-command-helper` propagators and includes the exact helper
  symbol. The untouched sealed finding is consequently diagnosed with precise
  `diagnosticProcess` validation and attack-path gaps. `Ktor resource` and
  `shell program` are accepted as exact semantic equivalents where the finding
  already proved those concepts. Focused regression now passes 42 tests and
  2,469 assertions.
- Ran provenance-bound correction campaign
  `f2f8412e138516e64936f7980662be6a649feedfdd050f1573e4729e3c18bfe3`
  against the factory exploit at quality-gate revision
  `2684694f9b7ee193d33f503f6a002b833e167ec1`. The scan completed on attempt
  one with status 0, no timeout, complete coverage, and one high finding in
  6m32s. Validation now explicitly names the typed Ktor resource,
  `commandLine`, `diagnosticProcess` builder factory, `ProcessBuilder`, and
  `sh -c`; the attack path preserves the resource value, factory call, exact
  constructor arguments, process start, and returned stdout. Its initial
  evaluation missed only the exact phrase `child shell`, despite using that
  phrase to describe the command-language boundary. Adding that narrow synonym
  and re-evaluating the untouched sealed bytes accepts the case with every
  metric at 1.0 and no missing validation or attack-path group. Both immutable
  campaigns remain outside the repository as positive and negative acceptance
  evidence.
- Completed final combined native acceptance after the helper-aware quality and
  evaluator corrections. Windows passes 1,895 tests and 14,114 assertions
  across 208 files in 494.37 seconds, with 27 intentional
  platform/integration skips and no failures. Ubuntu/WSL passes 155 tests and
  3,736 assertions across the focused Kotlin, canonical corpus,
  residual-inventory, Copilot transport, and package-provenance lanes, with one
  Windows-launcher skip and no failure.
- Built the final package from exact public revision
  `44cb6e3fe3a0402f7c3c7e0c3a05f4e43a38b323` with the documented Ubuntu
  `pnpm pack` path. Windows and POSIX-strict inspection validate all 291 archive
  entries and two isolated installs on each operating system validate the
  public import, executable CLI, and all 79 bundled plugin files. The archive
  occupied 2,252,340 packed and 11,619,605 unpacked bytes, retained
  `-rwxr-xr-x` on `bin/copilot-security.mjs`, and had SHA-1
  `3bfd82e403cc4345957638a9a53acfb750e1995c` and SHA-256
  `fb3b52ef3606508d9a01f71df32d0a4a3e62e44f53eb8c69c1cf4a7ce6427f9b`.
  The local archive appropriately lacks registry publish-time `gitHead`; hosted
  exact-head workflows provide revision provenance. The validated archive was
  removed.
- Repeated deterministic self-review against a disposable tracked-only archive
  of exact revision `44cb6e3fe3a0402f7c3c7e0c3a05f4e43a38b323`. Both inventories are
  byte-identical at 256 rows and 553,364 bytes with SHA-256
  `e0e02c0a5fd199ecf86d809957031322d5796e158a639fd726a70acaf1ffefcd` and
  contain no Kotlin command-injection row from scanner or test code.
  Independently rooting the same build at each new factory/mutator exploit and
  argv control produces exactly 1/0 and 1/0 Kotlin rows. The disposable archive
  and inventories were removed.
- All eleven hosted workflow families pass implementation revision
  `4792c82eb7e111d9b60b41ca88ab1d11545fbf9f`: Node `33123927139`,
  container `33123927134`, Kotlin `33123927113`, Java `33123927159`, .NET
  `33123927125`, Go `33123927186`, Rust `33123927137`, Ruby `33123927133`,
  PHP `33123927120`, Windows GUI `33123927136`, and Linux GUI
  `33123927160`. All eleven also pass helper-quality revision
  `2684694f9b7ee193d33f503f6a002b833e167ec1`: Node `33125991771`,
  container `33125991731`, Kotlin `33125991737`, Java `33125991797`, .NET
  `33125991748`, Go `33125991885`, Rust `33125991747`, Ruby `33125991758`,
  PHP `33125991707`, Windows GUI `33125991776`, and Linux GUI
  `33125991887`.
- All eleven hosted workflow families pass final exact-source revision
  `44cb6e3fe3a0402f7c3c7e0c3a05f4e43a38b323`: Node `33127231770`,
  container `33127231782`, Kotlin `33127231781`, Java `33127231877`, .NET
  `33127231774`, Go `33127231976`, Rust `33127231854`, Ruby `33127231823`,
  PHP `33127231765`, Windows GUI `33127231799`, and Linux GUI
  `33127231846`. The repository remains public at
  `https://github.com/secwest/copilot-security` with default branch `main`.
- All ten path-applicable hosted workflow families pass acceptance-only
  revision `01787f425108d228961b6f11f5a56d4b7296e6da`: Node `33127954581`,
  Kotlin `33127954442`, Java `33127954530`, .NET `33127954391`, Go
  `33127954468`, Rust `33127954437`, Ruby `33127954460`, PHP `33127954385`,
  Windows GUI `33127954395`, and Linux GUI `33127954502`. The container
  workflow was not triggered by that documentation-only revision.
- Closed hosted verification of prior acceptance revision
  `754f12f549dfa36b221b5e1df4451fe964493011`: Node `33121285236`,
  container `33121285223`, Kotlin `33121285286`, Java `33121285279`, .NET
  `33121285315`, Go `33121285230`, Rust `33121285226`, Ruby `33121285313`,
  PHP `33121285283`, Windows GUI `33121285222`, and Linux GUI `33121285243`
  all completed successfully.
- Extended `kotlin-ktor-command-injection` through exact
  `ProcessBuilder.startPipeline(List<ProcessBuilder>)` assembly. Inline builders
  inside `listOf`, `mutableListOf`, and `arrayListOf`, retained builder-list
  variables, builder-list aliases, and fluent inline `command(...)` replacement
  now reach pipeline execution. The former identifier-anywhere approximation
  was removed, so arbitrary wrappers that merely mention a known builder no
  longer count as a pipeline.
- Preserved live pipeline-list state and order. Constant indexed writes, `set`,
  append/indexed `add`, `removeAt`, and `clear` update the builders that will
  actually execute; aliases share the same list; replacement or removal can
  eliminate an earlier risk; and deterministically invalid indices abort the
  straight-line route before launch. New
  `kotlin-process-pipeline-list-mutation` and
  `kotlin-process-pipeline-assembly` propagators retain those edges in attack
  paths without weakening executable-selection, shell/interpreter, or ordinary
  argv distinctions.
- Added a topology-matched typed-resource inline-pipeline exploit/control pair,
  expanding the perfect-gate Kotlin manifest to eight cases and the canonical
  corpus to 146 pairs, 292 cases, and 876 repeated scan positions. Both Ktor
  3.5.2/Kotlin 2.2.20 applications compile and their fixed-string Java 21
  witnesses pass on Ubuntu using only two short-lived processes. Deterministic
  review emits one shell finding at the exact `startPipeline` call and no
  finding for fixed `printf` argv. Focused Kotlin plus canonical tests pass 39
  tests and 2,400 assertions, and TypeScript checking is clean. The manifest's
  validation vocabulary now accepts the precise phrase `inline pipeline`, so a
  finding that explicitly describes an inline pipeline element or assembly is
  not rejected merely because it omits the equivalent wording `inline builder`
  or `pipeline list`.
- Completed rebuilt native and cross-platform acceptance. The authoritative
  Windows suite passes 1,892 tests and 14,044 assertions across 208 files in
  483.08 seconds, with 27 intentional platform/integration skips and no
  failures. A pre-build run was rejected because five benchmark-runner tests
  correctly stopped at the stale-runtime guard; after rebuilding `dist`, all
  six recovery tests pass alone and the complete suite passes. Ubuntu/WSL
  passes 152 tests and 3,666 assertions across the focused Kotlin, canonical
  corpus, residual-inventory, Copilot transport, and package-provenance lanes,
  with one Windows-launcher skip and no failure. Formatting, generated-model
  drift, TypeScript checking, the production build, and the production
  advisory audit are clean.
- Validated an Ubuntu-produced 291-entry npm archive through strict inspection
  and two isolated installs on each of Windows and Linux. Every install proves
  the public API, executable CLI, and all 79 bundled plugin files. The archive
  occupied 2,243,305 packed and 11,567,078 unpacked bytes, retained
  `-rwxr-xr-x` on `bin/copilot-security.mjs`, and had SHA-1
  `6d9e1a5f246c4415ee0eb1b5bed1788196086220` and SHA-256
  `7a4aff551ea28dac598c6c4e7f0f545c99419f2ff60731f1fffd6c4bc86b2c8c`.
  The exact archive and temporary self-scan tree were removed after
  acceptance.
- Verified deterministic self-scan behavior against an isolated tracked-only
  archive of revision `8a5dbd11f6135922043b566891b551349382486d`.
  Two inventories are byte-identical at 256 rows and 553,364 bytes with
  SHA-256
  `e0e02c0a5fd199ecf86d809957031322d5796e158a639fd726a70acaf1ffefcd`
  and contain no Kotlin command-injection row from scanner or test code.
  Rooting the same build at the archived inline-pipeline exploit and argv
  control produces exactly one and zero Kotlin rows respectively.
- Ran provenance-bound deep/xhigh Copilot campaign
  `e927657629a46ca5debc3e6e9f59bb00fda6f704b9f5d6f35a1246953b23509a`
  against the inline-pipeline pair with stored GitHub credentials, six bounded
  available attempts, a 30-minute process-tree deadline, and no artificial
  credit ceiling. Both cases completed on attempt one with status 0 and no
  timeout: the positive took 257,309 ms and produced one high finding with
  complete coverage after two deterministic endpoint-role alignments; the
  control took 395,676 ms and produced no finding with complete coverage. The
  first report had perfect completion, precision, recall, F1, stability,
  validation, attack-path, code-evidence, severity, and negative-case metrics,
  but failed the positive case's exact validation-wording gate because the
  sealed finding said `inline pipeline assembly` rather than one of three
  narrower synonyms. Re-evaluating the untouched sealed artifacts with the
  corrected vocabulary accepts both cases with no missing validation terms.
  The durable original campaign remains outside the repository at
  `C:\security-benchmarks\copilot-security-kotlin-inline-pipeline-8a5dbd1`.
- All eleven hosted workflow families pass implementation revision
  `8a5dbd11f6135922043b566891b551349382486d`: Node `33118228836`,
  container `33118228863`, Kotlin `33118228879`, Java `33118228789`,
  .NET `33118228820`, Go `33118228818`, Rust `33118228843`, Ruby
  `33118228799`, PHP `33118228811`, Windows GUI `33118228807`, and Linux
  GUI `33118228810`.
- Extended `kotlin-ktor-command-injection` through the JDK's live command-list
  boundary. The model now preserves shared list identity when a collection is
  passed to `ProcessBuilder(List)` or `command(List)`, follows the mutable view
  returned by `command()`, and follows exact builder and list aliases. Ordered
  indexed writes, `set`, append/indexed `add`, `removeAt`, and `clear` now
  update the effective command seen by `start()` and `startPipeline()`.
  Replacing the builder command detaches older list views, deterministic
  out-of-bounds mutations terminate the straight-line route before execution,
  and later overwrites or clear/rebuild sequences can remove an earlier risk.
- Added explicit `kotlin-process-command-replacement` and
  `kotlin-command-list-mutation` attack-path propagators plus reviewer guidance
  for shared identity, mutation order, detachment, builder aliases, and hard
  ordinary-argv counterevidence. Regression-first tests reproduced both the
  former false negative for a live-list write and the former false positive
  after a safe clear/rebuild. The focused Kotlin and canonical lane now passes
  37 tests and 2,354 assertions. The perfect-gate Kotlin manifest expands to
  six cases, and the canonical corpus to 145 exploit/control pairs, 290 cases,
  and 870 repeated scan positions.
- Added buildable Ktor 3.5.2/Kotlin 2.2.20/Java 21 live-list exploit and control
  applications. The positive uses constructor list sharing, a retained
  `command()` view, `set`, and a builder alias to install shell grammar. The
  topology-matched control starts with attacker-influenced shell state but
  clears and rebuilds the same live list as fixed `printf` argv. Both native
  Ubuntu witnesses pass using only an inert environment marker, their generated
  Maven targets were removed, and hosted Kotlin CI now compiles and executes
  all six Ktor fixtures.
- Completed native, cross-platform, and package acceptance. The authoritative
  Windows suite passes 1,890 tests and 13,999 assertions across 208 files in
  474.61 seconds, with 27 intentional platform/integration skips and zero
  failures. One unrelated native format-string witness failed once in the first
  complete run, then passed alone and in five consecutive stress runs before
  the all-green authoritative rerun. Native Ubuntu passes the 150-test,
  3,621-assertion focused scanner/model/orchestration/package lane with one
  Windows-only skip. Formatting, generated models, TypeScript, the clean build,
  and the high-severity production audit are clean.
- Validated an Ubuntu-produced 291-entry npm archive through strict inspection
  and two isolated installs on each of Linux and Windows. Every install proves
  the public API, executable CLI, and all 79 bundled plugin files. The archive
  is 2,239,222 bytes packed and 11,538,669 bytes unpacked, preserves the
  `-rwxr-xr-x` launcher, and has SHA-256
  `5c2dd192a075eeeac064e2fea72db5343cce2079061e966051bfa41494aaf85e`.
  The reproducible archive and extraction directories were removed after
  validation.
- Verified deterministic self-scan behavior against an isolated tracked-only
  archive of implementation revision
  `643d1e4e053d5ee67d47c30e6bf7a286fd017d52`. Two inventories are
  byte-identical at 256 rows and 553,241 bytes with SHA-256
  `e6c77ef922a7f91cc6276b884ba905eba745e05090e9241dcd277a2f303ef7c2`
  and contain zero Kotlin command-injection rows. Rooting the same scanner at
  the archived live-list exploit and control fixtures produces exactly one
  and zero Kotlin rows respectively. The exact temporary archive, extraction,
  and self-scan tree were removed after verification.
- Ran a provenance-bound deep/xhigh Copilot campaign against the new live-list
  pair with stored credentials, six bounded available attempts, a 30-minute
  process-tree deadline, and no artificial credit ceiling. Campaign
  `94002c15d327e5511343633dce81bc80fb18af7560909838ac066100a39cdfc5`
  binds revision `643d1e4e053d5ee67d47c30e6bf7a286fd017d52` and completed both
  cases on attempt one. The positive completed in 234,429 ms with one critical
  finding, complete coverage, and three host-reanchored code excerpts; the
  clear/rebuild argv control completed in 301,021 ms with zero findings and
  complete coverage. Completion, precision, recall, F1, case and negative-case
  pass, stability, validation, attack-path, code-evidence, and severity rates
  are all 1.0 with zero false positives or false negatives. Retained logs
  contain no quota, credit, classifier, authentication, transport, reconnect,
  timeout, or retry marker. Sealed results remain outside the repository at
  `C:\security-benchmarks\copilot-security-kotlin-live-list-643d1e4`.
- All eleven hosted workflow families pass at exact implementation revision
  `643d1e4e053d5ee67d47c30e6bf7a286fd017d52`: Node `33114303879`,
  container `33114303826`, Kotlin `33114303657`, Java `33114303877`,
  .NET `33114303742`, Go `33114303971`, Rust `33114303815`, Ruby
  `33114303843`, PHP `33114303792`, Windows GUI `33114303887`, and Linux
  GUI `33114303678`. The Node matrix passes Node 22/24/26 on Ubuntu plus
  macOS and Windows, including the complete regression suite, type checking,
  formatting, production build, package inspection, and runtime smoke tests.
- Extended `kotlin-ktor-command-injection` through two previously unmodeled
  Kotlin/JDK boundaries: typed Ktor Resources handlers and mutable
  `ProcessBuilder.command(...)` state. Exact `io.ktor.server.resources` route
  imports plus an exact imported, aliased, or fully qualified
  `io.ktor.resources.Resource` annotation seed the explicit or implicit typed
  handler parameter. The same-file flow then follows resource properties into
  the effective command after vararg or fixed-collection replacement. Named
  builders now close through `startPipeline(...)` as well as `start()`.
- Preserved effective-state and command/data false-positive barriers. A safe
  constructor later replaced with attacker-influenced shell grammar is
  reportable; an unsafe-looking constructor later replaced with a fixed
  ordinary executable and distinct untrusted argv is not. Local annotations,
  unannotated handler types, wrong Resources imports, inert builders, and
  non-executed replacement remain hard negatives. Reviewer guidance and
  field-local evidence gates now require the typed resource property, command
  replacement, and actual execution method when those edges are present.
- Added a second topology-matched Ktor exploit/control pair and expanded the
  perfect-gate Kotlin manifest to four cases. Both real applications compile
  with Kotlin 2.2.20, Ktor 3.5.2, the serialization compiler plugin, and Java
  21 under Ubuntu. Their native tests prove that the effective shell command
  expands only an inert environment marker while the effective `printf` argv
  command does not. Focused Windows regressions pass 16 tests and 140
  assertions, including exact identities, multiline handler parameters,
  vararg/list replacements, state reversal, and `startPipeline`. Generated
  Maven targets were removed. The canonical corpus now contains 144 pairs,
  288 cases, and 864 repeated scan positions.
- Ran the complete acceptance matrix at revision
  `8fc33386ede7767f35af67544d3db3dbc8231709`. The authoritative native
  Windows suite passes 1,887 tests and 13,945 assertions across 208 files in
  473.78 seconds, with 27 intentional platform/integration skips and zero
  failures. The focused Ubuntu host/inventory/package lane passes 84 tests and
  2,514 assertions with one Windows-launcher skip; the 34-test, 2,300-assertion
  Kotlin plus canonical benchmark lane is identical on Windows and Ubuntu.
  Both Maven applications and native witnesses pass on Ubuntu. All eleven
  hosted workflows pass, including Kotlin, Windows GUI, and Linux GUI; the
  Kotlin run is
  `https://github.com/secwest/copilot-security/actions/runs/33104335972`.
- Verified release and self-scan provenance. Formatting, generated-model
  drift, TypeScript checking, the production build, and the high-severity
  production dependency audit are clean. An Ubuntu-produced 291-entry npm
  archive is 2,204,931 bytes packed and 11,508,231 bytes unpacked, has SHA-256
  `73cad7125423e94450b6a1538d2171fcf9fe80ac8c8986e8e75d1c6f038c5d84`,
  retains the POSIX executable launcher mode, and passes strict Windows and
  Linux inspection plus isolated 67-package Windows and 75-package Linux
  installs, public API, CLI, and all 79 bundled plugin files. A tracked-only
  self-scan is byte-identical twice at 256 rows and 554,239 bytes with SHA-256
  `d3c8bb8b0a90794e3f39cc400e925fb1d122587d2d81cb2b2f540cd76ed34722`;
  scanner and test trees emit no Kotlin row, while separately rooted new
  positive/control fixtures emit exactly one and zero. Disposable Maven,
  package, extraction, and self-scan artifacts were removed.
- Ran a new provenance-bound deep/xhigh Copilot campaign against the typed
  resource pair with stored credentials, six bounded available attempts, a
  30-minute process-tree deadline, and no artificial credit ceiling. Campaign
  `d722ae8729b6a839b18de2baaaed94f2ca8bfbe77722d9907b17af5078853d0d`
  completed both cases on attempt one. The positive completed in 654,249 ms
  with one critical finding, complete coverage, and two host-reanchored code
  excerpts; the control completed in 613,247 ms with zero findings and
  complete coverage. Completion, precision, recall, F1, case and negative-case
  pass, stability, validation, attack-path, code-evidence, and severity rates
  are all 1.0 with zero false positives or false negatives. No quota, credit,
  classifier, authentication, transport, reconnect, or retry event occurred.
  Sealed results remain outside the repository at
  `C:\security-benchmarks\copilot-security-kotlin-resource-8fc3338`.
- Added the canonical corpus's first native Kotlin/Ktor model,
  `kotlin-ktor-command-injection`. A bounded Kotlin lexer and route-lambda
  dataflow pass follows exact Ktor query, path, header, query-string, and body
  sources through local assignment, string interpolation, and concatenation
  into an exact imported or fully qualified `java.lang.ProcessBuilder`. It
  requires `start()` on the same non-reassigned builder and supports imported
  aliases, literal program/flag variables, vararg and `listOf`/`arrayOf`
  constructors, and multiline builder chains.
- Preserved the JVM command/data boundary to reduce command-injection false
  positives. Attacker-selected executables, POSIX shell `-c`, CMD `/c` or `/k`,
  PowerShell/pwsh command strings, interpreter code flags, and Windows batch
  consumers are retained. A fixed ordinary executable with request data only
  in a distinct operating-system argument is a hard negative. Inert builders,
  builder reassignment, numeric normalization, tests/examples/fixtures, local
  lookalikes, missing Ktor identity, malformed source, and excessive token or
  nesting volume fail closed. Validation expressions remain candidate controls
  until dominance and command-language correctness are proved.
- Added a topology-matched Ktor exploit/control pair, perfect-gate focused
  manifest, exact host finding-field requirements, and read-only hosted Kotlin
  workflow. Both applications compile with Kotlin 2.2.20 and Ktor 3.5.2 on
  Java 21 in Ubuntu; the positive native test expands only an inert environment
  marker through `sh -c`, while the control passes the same marker spelling to
  `printf` as literal argv and does not expand it. The generated Maven targets
  were removed. The canonical corpus now contains 143 pairs, 286 cases, and
  858 repeated scan positions. The focused model and canonical benchmark pass
  30 tests and 2,247 assertions; the broader prompt, residual-inventory,
  packaging-provenance, and timeout lane passes 107 tests and 3,329 assertions
  with one intentional platform skip and no failures. Benchmark source
  anchoring now accepts bounded conventional nested layouts such as
  `src/main/kotlin` instead of requiring a file directly under `src`.
- Ran a provenance-bound deep Copilot benchmark against both Kotlin cases with
  xhigh effort, stored credentials, six available fresh attempts, and no
  artificial credit ceiling. Campaign
  `45c66e91d688c25f03987f6bdfc7ea2350afaf6ba748477dbf9bbaaaff4ca4ef`
  binds revision `e01cde71e37eac85d3d412c07457a483f1bea84f` and completed
  both scans on attempt one. The shell case produced exactly one critical
  finding with complete coverage after deterministic re-anchoring of five
  excerpts; the literal-argv control produced none with complete coverage.
  Completion, precision, recall, F1, case and negative-control pass rates,
  stable detection, validation, attack path, code evidence, and severity
  accuracy are all 1.0 with zero false positives. No quota, credit,
  classifier, authentication, transport, or retry event occurred. Sealed
  results remain outside the repository at
  `C:\security-benchmarks\copilot-security-kotlin-ktor-e01cde7`.
- Final Kotlin acceptance passes 1,883 Windows tests and 13,892 assertions
  across 208 files in 508.63 seconds, with 27 intentional platform/integration
  skips and zero failures. The focused Linux lane passes 97 tests and 3,307
  assertions with no failures or skips. A tracked-files-only self-scan is
  byte-identical across two runs (256 rows, 554,239 bytes, SHA-256
  `d3c8bb8b0a90794e3f39cc400e925fb1d122587d2d81cb2b2f540cd76ed34722`),
  produces no Kotlin row from scanner production or test trees, and produces
  exactly one vulnerable and zero safe rows when the archived fixtures are
  scanned at their own roots. Formatting, TypeScript checking, the production
  build, and the high-severity production dependency audit are clean. A fresh
  291-entry, 2,199,580-byte npm archive (11,487,538 bytes unpacked) with
  SHA-256
  `61859f3c0bf52a90aa9c920e588a45290ef9fe2bd2e9e635bc4da249ec0304cf`
  passes strict inspection and an isolated 67-package install, including the
  public API, CLI, and all 79 bundled plugin files. All eleven hosted workflows
  pass at the exact revision. Disposable package and self-scan artifacts were
  removed; the provenance-bound live benchmark was intentionally retained.
- Added the canonical corpus's first Rust model,
  `rust-web-command-injection`. A bounded Rust lexer and same-function dataflow
  pass follows exact Axum and Actix Web Query, Path, Form, and Json extractors
  through tuple bindings, local assignment, `format!`, concatenation, and
  escape candidates into exact `std::process::Command` builders. It requires
  actual `output`, `status`, `spawn`, or imported Unix `exec` dispatch on the
  same non-reassigned builder and supports direct, grouped, module-qualified,
  fully qualified, and aliased standard-library imports.
- Modeled Rust's documented command/data boundary instead of reporting every
  process argument. Attacker-selected executables, POSIX shell `-c`, CMD `/c`
  or `/k`, PowerShell/pwsh command strings, interpreter code flags, Windows
  batch consumers, and exact Windows `raw_arg` are retained; a fixed ordinary
  executable whose request value stays in a separate `arg`/`args` element is a
  hard negative. Literal shell and flag variables are resolved. Inert
  construction, fixed commands, numeric normalization, builder reassignment,
  test/example/fixture paths, local lookalikes, malformed source, and excessive
  token or nesting volume fail closed. Regexes, literal matches, deadlines, and
  shell-escape calls remain contextual candidate controls rather than automatic
  suppression.
- Added a strict Axum exploit/control pair, perfect-gate focused manifest, and
  read-only hosted Rust workflow, advancing the canonical corpus to 142 pairs,
  284 cases, and 852 repeated scan positions. Native Rust 1.75.0 under Ubuntu
  compiles both standard-library witnesses and produces
  `shell_expanded_marker=1` versus `shell_expanded_marker=0`; the temporary
  binaries and directory were removed.
- Added deterministic Rust finding-field closure to the host quality gate after
  live scans showed that correct detection alone did not reliably preserve the
  exact extractor, `format!` propagation, `Command::new` builder, shell
  boundary, and stdout-to-response edge in both validation and attack-path
  fields. Incomplete Rust findings now emit exact field-local missing groups
  and must pass bounded correction before sealing. A paired regression proves
  that an otherwise substantive finding is rejected until every required
  source-backed group is present. Focused Windows regression passes 15 tests
  and 115 assertions; the final native Ubuntu Rust/host-gate/residual lane
  passes 82 tests and 1,175 assertions with no skips or failures.
- Ran a provenance-bound deep Copilot benchmark against both Rust cases with
  xhigh effort, stored native credentials, six available fresh attempts, and
  no artificial credit ceiling. Final campaign
  `3c275b1c275ae2ebadcca6b1c9e0aa570a947f454e6f47eade708e2bb8e1439c`
  binds revision `addf52248d521145961701f2be11949f7d36c49a` and completed both
  scans on attempt one. The shell case produced exactly one high finding with
  complete coverage; the argv control produced none. Every perfect gate
  passed: completion, precision, recall, F1, case and negative-control pass
  rates, stable detection, validation, attack path, code evidence, severity
  accuracy, and zero false positives. Sealed results remain outside the
  repository at
  `C:\security-benchmarks\copilot-security-rust-command-addf522`.
- Final Rust acceptance passes 1,871 Windows tests and 13,783 assertions across
  207 files in 559.43 seconds, with 27 intentional platform/integration skips
  and zero failures. A tracked-files-only self-scan is byte-identical across
  two passes (256 rows, 554,097 bytes, SHA-256
  `a64907b710fc86454600e253388d601a55f0750a183dd165e4f72d978ff66bc5`),
  produces no Rust row from production or test trees, and produces exactly one
  vulnerable and zero safe rows when the archived fixtures are scanned at
  their own roots. Formatting, TypeScript checking, the production build, and
  the high-severity production dependency audit are clean. A fresh 287-entry,
  2,182,889-byte npm archive (11,394,287 bytes unpacked) with SHA-256
  `eee303bef16649a24cbec1fda027a427a9d5bcb298dd034b366e7a694ac31590`
  passes strict inspection and an isolated 67-package install, including the
  public API, CLI, and all 79 bundled plugin files. All ten hosted workflows
  pass at the exact revision: the Node 22/24/26 Ubuntu matrix, macOS, Windows,
  Rust, Ruby, PHP, Go, Java, .NET, container, and both GUI platforms.
  Disposable package and tracked-archive self-scan artifacts were removed;
  provenance-bound live benchmark campaigns were intentionally retained.
- Added the canonical corpus's first Ruby model,
  `ruby-rails-command-injection`. A bounded Ruby-aware lexer and Rails
  controller-method dataflow pass follows `params` and request parameter maps
  through local assignment, interpolation, and concatenation into Kernel,
  Process, IO, and required Open3 process APIs, including ordinary Ruby
  parentheses-free calls, backticks, `%x`, and explicit POSIX, CMD, and
  PowerShell command-string forms. It distinguishes one-string shell grammar
  and attacker-selected executables from a fixed executable whose untrusted
  value remains a separate argument.
- Kept the host signal deliberately narrower than a keyword match. Open3
  requires an exact same-file `require`, Rails scope requires an exact
  controller inheritance and method, locally shadowed core methods are
  rejected, and test, non-Ruby, malformed, disconnected, reassigned, fixed,
  and numerically normalized flows remain negative. `Shellwords.escape` and
  `shellescape` are retained as Bourne-shell-specific candidate controls for
  contextual validation rather than treated as universal suppression. The
  pass caps nesting at 128, tokens at 131,072, records at 64, and each excerpt
  line at 2,048 Unicode characters.
- Added a strict Rails/Open3 exploit-control pair and focused perfect-gate
  manifest, advancing the full corpus to 141 pairs, 282 cases, and 846 repeated
  scan positions. The pair keeps the Rails parameter source, Open3 API, output
  capture, status handling, and rendered response fixed; only the positive
  embeds data in a one-string command, while the control uses fixed executable
  and argv boundaries. Native Ruby 3.2.3 parses all four source/witness files
  and produces `shell_expanded_marker=1` versus
  `shell_expanded_marker=0` without file, network, credential, persistence, or
  privilege effects. A new read-only `ruby-fixture-ci` workflow repeats that
  boundary on hosted Ubuntu. Focused Windows tests pass 12 cases and 104
  assertions; the adjacent native Ubuntu canonical/residual lane passes 97
  tests and 3,291 assertions. The authoritative Windows suite passes 1,856
  tests and 13,657 assertions across 206 files in 532.57 seconds, with 27
  intentional platform/integration skips and zero failures. Formatting,
  generated-model drift, TypeScript, production build, and the high-severity
  production dependency audit are clean. A fresh 283-entry, 2,186,440-byte npm
  archive with SHA-256
  `f242c4b1e88acf39ae2c0e3ace255b7053085afb5e87b89f59c3900eca75733d`
  passes strict inspection and two isolated installs, including the public API,
  CLI, and all 79 bundled plugin files; the disposable archive is removed.
  The first hosted Windows Node run found one test-only line-ending assumption:
  Git checked the control witness out with CRLF while its content assertion
  required LF. The assertion now canonicalizes CRLF before comparing the Ruby
  argv shape; source/sink provenance already has a separate byte-level CRLF
  regression.
- Ran a provenance-bound deep Copilot benchmark against one repetition of both
  Ruby cases. Campaign `999c678379c7f0e8122eaa8ed9135a2afe0c119a5ca5439a30671e8cc4259c7e`
  completed both scans on their first attempt using stored native credentials:
  the vulnerable case produced exactly one high finding with complete coverage,
  and the argv control produced none. Every perfect gate passed: completion,
  precision, recall, F1, case and negative-control pass rates, stable detection,
  validation, attack-path and code-evidence coverage, severity accuracy, and
  zero false positives. The sealed external results are retained under
  `C:\security-benchmarks\copilot-security-ruby-command-450ac020`.
- Hardened Windows package verification after a later documentation-only hosted
  run installed all 75 isolated-consumer packages at the exact 180-second child
  deadline and was then terminated. Windows package smoke commands now retain a
  hard but less timing-sensitive five-minute deadline, the parent remains
  bounded 30 seconds later, and the Node job budget is 30 minutes so strict
  inspection and the independent smoke install can both finish on a cold or
  slow registry path. Linux and macOS retain their two-minute child deadline.
- Added the canonical corpus's first PHP model,
  `php-pdo-mysqli-sql-injection`. A bounded PHP-aware lexer and same-scope
  dataflow pass follows `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, selected
  attacker-controlled `$_SERVER` keys, and `filter_input` through assignments,
  interpolation, concatenation, formatting, and heredoc into typed PDO or
  MySQLi execution. It covers direct object and procedural query APIs plus the
  subtle case where tainted SQL is prepared and only later executed; inert
  preparation, untyped lookalikes, and parameter data remain negative.
- Modeled command/data separation instead of treating every `prepare` call as
  safe. Fixed placeholder templates with request values supplied only as
  execute-time parameters, validated numeric/boolean scalars, fixed literal
  selections, reassignments, fixed queries, disconnected scopes, non-code
  HTML/comments/strings, and non-attacker server variables stay negative.
  Database-specific escaping is retained as validation evidence because its
  correctness depends on the exact connection, character set, and SQL lexical
  context. The pass recognizes PHP attributes and `.phtml`, bounds nesting at
  128, tokens at 131,072, records at 64, and each excerpt line at 2,048 Unicode
  characters.
- Added a strict PDO exploit/control pair and focused perfect-gate manifest,
  advancing the full corpus to 140 pairs, 280 cases, and 840 repeated scan
  positions. Both fixtures keep the same source, PDO receiver, preparation,
  execution, and result topology; the positive interpolates before preparation
  while the control supplies the same bytes only as placeholder data. Native
  PHP 8.3.6 parses all four source/witness files. Their in-memory SQLite
  witnesses return `injected_rows=2` and `parameterized_rows=0` respectively.
  A new least-privilege `php-fixture-ci` workflow makes this executable boundary
  a hosted regression. Focused Windows tests pass 14 cases and 96 assertions,
  including byte-identical LF/CRLF provenance;
  the adjacent canonical and residual-risk lane passes 98 tests and 3,271
  assertions with one intentional Windows symlink skip, while native Ubuntu
  passes all 99 tests and 3,272 assertions. The authoritative Windows suite
  passes 1,844 tests and 13,542 assertions across 205 files in 557.03 seconds,
  with 27 intentional platform/integration skips and zero failures. Formatting,
  generated-model drift, TypeScript, the production build, and the high-severity
  production dependency audit are clean. A fresh 279-entry, 2,166,045-byte npm
  archive with SHA-256
  `5226d9fddd1ffe49457e648fbef7a043630f90e66b0abd1f7a95267e797fbb69`
  passes strict inspection and two isolated installs, including the public API,
  CLI, and all 79 bundled plugin files; the disposable archive is removed.
- Added the scanner's first native Terraform model,
  `terraform-aws-public-admin-ingress`. A bounded fail-closed HCL lexer and
  structural parser recognizes literal `aws_security_group` inline ingress,
  legacy `aws_security_group_rule`, and current
  `aws_vpc_security_group_ingress_rule` resources only when `0.0.0.0/0` or
  `::/0` reaches SSH port 22 or RDP port 3389 under TCP, UDP, or the exact AWS
  all-protocol sentinel. It preserves resource, rule shape, CIDR, protocol,
  port range, and line provenance while leaving module expansion, deployment,
  attachment, routing, listening services, authentication, and realized impact
  to explicit validation.
- Kept the Terraform lane narrower and more evidence-oriented than a generic
  public-ingress linter. Private CIDRs, public non-administration ports, egress,
  computed or interpolated values, dynamic blocks, malformed HCL, duplicate
  attributes, lookalike resources, protocol-shape errors, comments, strings,
  and heredocs stay negative. The modern standalone rule's omitted ports for
  protocol `-1` are distinguished from the legacy and inline `0/0` form.
  Token count and parse depth are bounded against hostile configuration files.
- Added a topology-identical public/restricted Terraform benchmark pair to a
  focused perfect-gate manifest and the full 139-pair corpus. Windows and native
  Ubuntu focused tests each pass 9 cases and 50 assertions, including all three
  provider resource shapes, IPv4 and IPv6, range and all-protocol semantics,
  exact provenance, prompt guidance, negative controls, trailing commas,
  heredoc isolation, and adversarial token/depth limits. The authoritative
  Windows suite passes 1,830 tests and 13,435 assertions across 204 files in
  522.54 seconds, with 27 intentional platform/integration skips and zero
  failures. Formatting, generated-model drift, TypeScript, the production
  build, and the high-severity production dependency audit are clean. A fresh
  275-entry, 2,141,550-byte npm archive with SHA-256
  `03ee8831d9168a1504c767cf083dfc1a6cdc1acefc655fb38a2d67f2d64f74ec`
  passes strict inspection and two isolated installs, including the public API,
  CLI, and all 79 bundled plugin files; temporary package artifacts are removed.
- Added a bounded deterministic source-display-control pass based on Unicode's
  source-code handling guidance and GCC's bidirectional-character diagnostics.
  It emits exact code-point, line, column, pairing, context-hint, and
  syntax-adjacency metadata for U+202A-202E and U+2066-2069, plus U+061C and
  U+200E/F when a directional mark touches ASCII syntax. Unpaired controls,
  overrides, and cross-line pairs rank above balanced same-line embeddings;
  ordinary Arabic or Hebrew text without explicit controls remains quiet.
  Excerpts stay base64-framed so an invisible control cannot reorder the model
  prompt itself.
- Hardened the new pass against hostile control floods. A file retains bounded
  head, tail, and override/syntax-adjacent samples, carries the exact total and
  retained counts, marks pairing unknown when sampling prevents an exact
  conclusion, and bounds every excerpt line. Linear scanning and a fixed-size
  tail ring avoid per-control shifting and quadratic column calculation.
- Added a strict Trojan Source authorization benchmark pair to both the full
  138-pair corpus and a focused perfect-gate manifest. The positive fixture
  uses an RLO and isolate sequence to disguise an unconditional non-admin
  grant; the negative fixture contains ordinary Arabic and Hebrew prose with a
  correct admin-or-owner policy. Runtime witnesses prove the authorization
  difference. Focused Windows regression passes 28 tests and 2,136 assertions,
  including exact candidate metadata, raw-control prompt isolation, pairing,
  nested-isolate behavior, false-positive resistance, a 6,001-control flood,
  manifest gates, and both executable outcomes; native Ubuntu passes the same
  28 cases. The authoritative native Windows suite passes 1,821 tests and
  13,374 assertions across 203 files in 560.17 seconds, with 27 intentional
  platform/integration skips and zero failures. The production dependency
  audit reports no known vulnerability. A fresh 271-entry npm archive passes
  the strict file contract, clean install, public import, CLI, and 79-file
  bundled-plugin smoke test; its 2,124,756 bytes hash to
  `52dfc0676c98fd712c39abd0453af9d97a0a66ac96de51b7c5e59e83902ecafd`.
- A fresh tracked-only self-scan of exact remediation checkpoint
  `8e991945847ef77b3958341222c2a6481dabe072` now closes all 494 immutable
  inventory surfaces with zero deferrals and zero findings, confirming that
  both the privileged-installer defect and synthetic benchmark-secret false
  positive are gone. The uncapped stored-credential run uses `xhigh` effort
  and completes in 88 minutes 17 seconds after 37,395,246 input tokens
  (32,209,213 cached) and 674,409 output tokens. Its first draft transport ends
  at 61 minutes 24 seconds; bounded recovery starts fresh session 2 of 5 and
  completes without an allowance, authentication, classifier, or additional
  transport failure. Scan `3ef8adc8-85f4-4461-8f29-7ec57b97fff9` is completed
  and host-sealed at the same exact timestamp, all three canonical artifact
  hashes independently reproduce, and the deterministic report exists.
- Followed up a low-severity hardening lead that quality correction correctly
  excluded from the canonical vulnerability set because it lacked a concrete
  adverse effect. Scan-history terminal rendering removed ANSI plus C0/C1
  controls but retained Unicode bidirectional embeddings, overrides, isolates,
  marks, and Unicode line separators in operator-visible repository, finding,
  path, and reason fields. The shared renderer now replaces those display
  controls before wrapping, coloring, or alignment, preventing visual
  reordering and injected line boundaries without stripping ordinary Unicode.
- Host finalization now removes model-authored top-level regular files and
  symlinks that resemble alternate results before it publishes the canonical
  seal. The live recovery session left an unsealed `findings-repaired.json`
  beside the authoritative zero-finding result; although neither the manifest
  nor report referenced it, its shape was plausibly authoritative. Cleanup is
  confined to the private unsealed scan root, preserves the four canonical
  files and every artifact/export/finding directory, unlinks rather than
  follows links, and fails before sealing on an unsafe entry or cleanup race.
  Revalidation of an already sealed scan does not remove later user sidecars.
  Focused Windows tests pass 92 cases and 544 assertions; native Ubuntu proves
  both bidi neutralization and external-target-preserving symlink cleanup. The
  final authoritative Windows suite passes 1,811 tests and 13,321 assertions
  across 201 files in 536.16 seconds, with 27 intentional platform/integration
  skips and zero failures. The high-severity production dependency audit finds
  no known vulnerability. An isolated 267-entry npm archive installs cleanly
  and passes its public import, CLI, and 79-file bundled-plugin contract; the
  2,114,267-byte tarball has SHA-256
  `694ac990778bd0805589a4909ea3fec204558e05987b7c870b819d89f50d034e`.
- A fresh uncapped stored-credential self-scan of exact checkpoint
  `f175c68ca707bc97a397654856b23ff85d91f307` now seals successfully after
  20 minutes 24 seconds with complete 495-of-495 inventory coverage, zero
  deferrals, and two high-severity findings. It processes 8,139,483 input
  tokens (7,116,839 cached) and 131,192 output tokens with no allowance,
  authentication, transport, or classifier failure. The manifest is completed,
  `sealedAt` exactly equals the workbench `completedAt`, five artifacts are
  digest-bound, and the deterministic report exists. This live-validates the
  host-seal ownership fix; the preceding complete-but-unsealed output remains
  correctly classified as a failed partial run.
- Confirmed and narrowed the self-scan's privileged Linux installer finding.
  The relevant attacker is a local process able to mutate a user-owned
  extracted archive during a `sudo` installation, not a malicious package
  author who already controls `install.sh`. The installer now uses a fixed
  trusted tool path, serializes installation, freezes the extraction into a
  private root-owned staging tree without preserving user ownership, rejects
  special files, strips elevated/world-writable mode bits, and permits only
  existing relative package-manager links that resolve inside the staged
  scanner `node_modules`. It prepares launcher and desktop assets as regular
  temporary files, rejects link-shaped destinations, atomically swaps the
  application directory, and restores the previous application on failure.
  Linux CI now injects an `/etc/passwd` link pivot into the unpacked release,
  requires rejection with the target digest unchanged, installs the unmodified
  archive, and runs the installed GUI smoke test. ShellCheck and native Ubuntu
  POSIX syntax validation are clean.
- Rejected the other self-scan finding as a demonstrated scanner false
  positive. The reported benchmark value was the exact synthetic literal
  `signing-key-material`; the model promoted redacted generic-entropy metadata
  despite recording benchmark context, medium entropy, and no external
  validity proof. Generic secret discovery now excludes only an anchored set of
  complete semantic placeholder literals such as `signing-key-material`, while
  retaining arbitrary high-entropy values. The placeholder is a committed
  negative benchmark case. Focused secret discovery and its perfect-gate corpus
  pass 7 tests and 58 assertions, and strict TypeScript remains green.
- Added bounded automatic fresh-session coverage closure. When the trusted host
  still proves missing direct file reviews or finding-quality gaps after a
  session's correction turns, the scanner now spends the remaining shared
  `--max-session-attempts` budget on isolated closure sessions instead of
  immediately recovering a partial result. Closure sessions skip broad
  repository discovery, preserve only successful host-observed built-in file
  views, clear unfinished tool calls, consume freshly recomputed gap
  inventories, and inspect the exact remaining paths. Transport failure inside
  correction remains transport-classified, while authentication,
  authorization, cancellation, cost limits, scanner contract failures,
  nonretryable provider errors, and exhausted safety recovery remain terminal.
  The total budget remains bounded from one through five sessions and defaults
  to three, so retries cannot create an independent unbounded loop.
- Preserved fail-closed closure identity across the Copilot event boundary.
  Retry events expose only the sanitized `closure_incomplete` reason and
  `coverage_closure` phase; terminal events carry validated nonnegative gap
  counts without provider response text. The API reconstructs
  `ScanClosureIncompleteError`, reports exact residual coverage and
  finding-quality counts, and may preserve deterministically validated partial
  artifacts without promoting zero findings or partial coverage to clearance.
  The CLI now distinguishes targeted closure from transport and full-scan
  recovery in live progress output, and its session-budget help covers both
  transport recovery and host-proven closure.
- Added `coverage-closure-orchestration-benchmark.json`. Its observed baseline
  records the preceding exact-checkpoint self-scan's 491 reconciled surfaces,
  17 reviewed surfaces, and 474 explicit gaps. Separate deterministic synthetic
  scenarios require the scheduler to reduce 474 gaps to zero within three of
  five sessions with no broad discovery replay, while a paired no-progress
  control must exhaust three sessions as incomplete and preserve a partial
  result. The benchmark requires a final closure rate of 1.0, at least 0.96
  closure gain, no more than five total sessions, and zero broad replays after
  the first scan; it does not misrepresent synthetic data as another observed
  self-scan.
- Added regression coverage for successful closure, budget exhaustion,
  transport interruption during closure, nonretryable provider failure,
  sanitized retry events, reconstructed terminal error identity, recovery
  warnings, CLI progress, and benchmark thresholds. Focused Windows and native
  Ubuntu runs each pass 149 tests with one intentional platform skip and no
  failures. The authoritative native Windows suite passes 1,807 tests and
  13,297 assertions across 201 files in 591.69 seconds, with 27 intentional
  platform/integration skips and zero failures. Formatting, generated-model
  drift, TypeScript, the production build, Windows and Linux focused behavior,
  and the high-severity production dependency audit are green.
- The first exact-checkpoint live acceptance run exposed a second closure edge:
  Copilot produced one closed `no_issue_found` surface for all 493 immutable
  inventory paths, no deferred items, and no host path or finding-quality gap,
  but retained an unexplained `completeness: partial` label. The run therefore
  remained safely non-clearing after 23 minutes 59 seconds and 13,389,405 input
  tokens (11,296,056 cached) plus 171,630 output tokens; it encountered no
  credit-limit or classifier refusal. Added
  `unresolved_coverage_completeness` to the deterministic closure inventory.
  It is emitted only when all other path, direct-view, mode, disposition, and
  deferred-work gaps are closed but the draft still says partial or unknown.
  Correction must then set `complete` or add a concrete path-bound deferred
  item for a plausible reportable defect; an unexplained label can no longer
  bypass same-session correction and fresh-session closure. Focused Windows
  and native Ubuntu runs each pass 111 tests with one intentional platform
  skip, 1,287 assertions, and no failures after this change.
- A second uncapped stored-credential self-scan of exact corrected checkpoint
  `bd80e6ae3cf26b012fa1c25d4cc8f690e9e9cab5` reaches complete 493-of-493
  inventory closure and reports two high-severity self-findings after 33 minutes
  19 seconds. It processes 26,798,043 input tokens (23,198,529 cached) and
  253,328 output tokens with no allowance, authentication, transport, or
  classifier failure. The first draft covered only 240 paths while claiming
  complete; same-session host correction expanded it to all 493, repaired both
  finding evidence sets, and produced a successful complete scan. No fresh
  session was necessary, so live evidence complements—but does not replace—the
  deterministic multi-session scheduler benchmark.
- Confirmed and fixed the self-scan's coverage-contract finding. Standalone
  compact-draft recovery no longer turns `needs_follow_up` documentation or
  metadata surfaces into `no_issue_found` by matching free-text notes such as
  “documentation reviewed.” Those rows and their path-bound deferrals now stay
  partial until an evidence-producing scan correction closes them. Explicit
  canonical outcomes remain recoverable, and finding-backed surfaces may still
  reconcile to `reported`.
- Re-audited the self-scan's benchmark-fixture Git-filter finding. The report
  missed an existing earlier control: fixture hashing already rejects any
  `.git` repository metadata before copy, so the stated direct pull-request
  attack path was not reachable. Added a second post-copy `.git` control-path
  rejection immediately before repository initialization to close mutation
  between hashing and copying and to preserve defense in depth. The regression
  uses an inert marker configuration and proves that neither a fixture filter
  nor the scanner runs. The clean Windows remediation lane passes 197 tests,
  one intentional skip, and 1,777 assertions. Native Ubuntu passes 191 tests,
  one intentional launcher skip, and 1,738 assertions, with its copied-tree
  guard case passing separately; the combined nested-runner file exceeds its
  pre-existing 25-second child timeout on `/mnt/c`, so it is not counted as a
  scanner failure.
- Added the missing strict-TypeScript declaration for the standalone
  `fixture-security.mjs` benchmark helper and included both the implementation
  and declaration in the container package stage's explicit benchmark-helper
  copy list. Native Windows and Ubuntu WSL now both resolve the post-copy
  control-path guard under `moduleResolution: bundler`; this closes the Linux
  Node and container CI portability failures without changing benchmark runtime
  behavior. The authoritative post-remediation Windows suite passes 1,808 tests
  and 13,305 assertions across 201 files in 590.41 seconds, with 27 intentional
  platform/integration skips and zero failures.
- The post-remediation tracked-only self-scan of exact runtime checkpoint
  `0c8acb9549b19b076e1cccb75533440c8e372274` produced a complete 494-of-494
  coverage draft with no deferrals and no surviving findings, but correctly
  exited nonzero instead of publishing clearance when host finalization failed.
  The model had omitted the host-owned `sealedAt` field but included two
  placeholder `scan.artifacts` rows. Finalization incorrectly treated any
  artifact array as proof of an existing seal, then rejected the absent seal
  timestamp. Sealed-state detection now requires the host-owned timestamp;
  unsealed model artifact rows are discarded and rebuilt from the final bytes,
  while manifests that actually carry a seal remain subject to strict digest
  validation. A live-shape regression proves placeholder zero digests are
  replaced, `sealedAt` equals the workbench completion, and the derived report
  is sealed. The full Windows recovery file passes 84 tests and 481 assertions;
  the isolated native Ubuntu regression also passes.
- Added `python-chainlit-mcp-stdio-command-injection`, an exact Python model
  for
  [GHSA-w3fx-mc44-mf6j / CVE-2026-45018](https://github.com/advisories/GHSA-w3fx-mc44-mf6j).
  It requires a non-shadowed top-level official Chainlit application import,
  one nearest exact stable production `chainlit` pin from 2.4.0 through
  2.11.1, and one nearest parsed `.chainlit/config.toml` with MCP enabled and
  legacy stdio not disabled. The stdio policy must omit
  `allowed_executables`—which the affected validator interpreted as allow
  all—or contain a reviewed command-capable shell, runtime, or package runner.
  Ranges, missing or duplicate pins, prereleases, repaired 2.12.0+, malformed
  TOML, disabled MCP or stdio, empty or non-command-capable allowlists, local
  shadows, indented imports, tests, examples, package-only repositories, and
  text lookalikes fail closed. Structured evidence records the application,
  exact dependency, configuration, client-controlled `POST /mcp`
  `fullCommand`, `shlex.split` executable-only check, and
  `StdioServerParameters -> stdio_client` spawn chain. Eight focused tests
  exercise 43 assertions on Windows and 45 on Ubuntu, including fail-closed
  dependency and configuration symlinks.
- Added a source-identical Chainlit 2.11.1/2.12.0 benchmark pair with Python
  3.12.3 runtime evidence, critical/CWE-78 ground truth at `src/app.py:1`,
  fourteen field-local validation and attack-path evidence groups, four
  explicit overclaim guards, and perfect three-run canonical gates. The corpus
  advances to 137 pairs, 274 cases, and 822 scans. A real-package Ubuntu
  witness invokes only the affected release's pure validator with fixed inert
  text and records `npx` plus its arguments with `executed:false`; it never
  passes the result to a process, shell, stdio, filesystem, network, or
  credential API. The 2.12.0 control proves that the validator is absent and
  the legacy `stdio`/`fullCommand` request raises `ValidationError`, also with
  `executed:false`. Review guidance separates the advisory's package primitive
  from deployment, authentication, session, proxy, privilege, containment,
  executable-semantics, and resource-limit evidence, and preserves residual
  risk from developer-configured stdio processes and concurrent sessions.
- Accepted exact Chainlit implementation checkpoint
  `ad948d76805c4868582b02febe16e34f5ebc6aaa`. The authoritative native
  Windows suite passes 1,800 tests and 13,242 assertions across 200 files in
  537.83 seconds, with 27 intentional platform/integration skips and no
  failures. The focused-plus-canonical lanes pass 25 tests/2,126 assertions on
  Windows with one intentional symlink skip and all 26 tests/2,128 assertions
  on native Ubuntu/WSL. The wider Windows focused, residual-risk, and canonical
  lane passes 91 tests/3,182 assertions with two intentional skips. Generated
  output, formatting, TypeScript, the production build, and the high-severity
  production dependency audit are green. Two compiled inventories of a
  tracked-only exact-commit archive are byte-identical at 256 rows, 552,649
  bytes, and SHA-256
  `7f5b9fa2b9cdefa842a728dacb9a130a9d5bba55ef8f1972ab2f2db3ac5d68cd`;
  201 rows carry structured evidence, 55 are lexical leads, and 250 are
  fixture paths. Exactly one row retains the affected Chainlit fixture at
  `src/app.py:1` with all seven propagators; the source-identical 2.12.0
  control is absent. Strict Windows and native Linux inspection validates a
  267-entry, 2,111,003-byte npm archive with SHA-256
  `d0f0882f281195247fc293c6383cdb1f1aae40fb865f25af67e00cdaff9b0457`.
  Fresh isolated installs add 67 packages on Windows and 75 on Linux and
  validate the public import, executable CLI, and all 79 bundled plugin files.
  The Windows GUI builds without warnings, passes 7/7 core and 3/3 shared
  desktop tests, survives a hidden startup probe, and publishes a 346,796-byte
  single-file executable with SHA-256
  `a393896769829c24a31cfa4348c86188489f63faa18a4c0ba8a008c2449dad50`.
  Native Ubuntu repeats the 7/7 and 3/3 suites, passes 2/2 Linux interface tests
  plus non-graphical and Xvfb startup, and publishes a 72,568-byte executable
  with SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
  A real uncapped stored-credential Copilot self-scan processes 4,187,566 input
  tokens (3,687,900 cached) and 31,312 output tokens in 6 minutes 22 seconds.
  The response stream ends after producing valid artifacts, which the
  deterministic workbench recovers and seals. It reports zero surviving
  findings but correctly exits nonzero with partial coverage: only 17 of 491
  reconciled surfaces have review closure, while 474 inventory paths remain
  explicit `needs_follow_up` items. Zero findings in that run is therefore not
  security clearance. All seven hosted families pass the exact implementation
  SHA: Node `33041570009` with all Windows, macOS, and Linux matrix jobs;
  container `33041570031`; .NET `33041570022`; Go `33041570076`; Java
  `33041569982`; Windows GUI `33041569983`; and Linux GUI `33041569977`.
- Added `python-asyncssh-scp-download-path-traversal`, an exact Python model for
  [GHSA-2wxc-x7rj-hg8f / CVE-2026-54591](https://github.com/ronf/asyncssh/security/advisories/GHSA-2wxc-x7rj-hg8f).
  It requires a live non-shadowed official `asyncssh.scp` binding, a proven
  remote-to-local download using a remote source tuple or literal host-path,
  a literal local string or `Path` destination, and one nearest exact stable
  production `asyncssh<=2.23.0` pin. Uploads, remote destinations,
  local-to-local calls, ranges, missing or duplicate pins, prereleases,
  repaired 2.23.1+, local shadows, replaced bindings or members,
  wrapper-parameter shadows, star expansion, test/example code, package-only
  repositories, and text lookalikes fail closed. Structured evidence records
  the binding, exact dependency, source direction, destination, server-owned
  SCP `C`/`D` filename fields, and the internal write chain from
  `_parse_cd_args` through `posixpath.join` to `_recv_file`/`open(wb)`. Eight
  focused tests exercise 42 assertions with one intentional Windows symlink
  skip.
- Added a source-identical AsyncSSH 2.23.0/2.23.1 benchmark pair with
  Python 3.12.3 runtime evidence, high/CWE-22 ground truth at
  `src/downloader.py:9`, field-local validation and attack-path requirements,
  and perfect three-run canonical gates. The corpus advances to 136 pairs, 272
  cases, and 816 scans. A real-package Ubuntu witness starts an in-process SSH
  server on a random loopback port and confines the requested child plus escaped
  marker to one automatically removed temporary root. Version 2.23.0 writes the
  inert marker through `C ../escaped-marker.txt`; version 2.23.1 raises
  `SFTPBadMessage: Invalid filename` and writes nothing outside the requested
  child. No home, startup, SSH configuration, authorization, executable,
  credential, or persistent path is used. The reviewer contract preserves the
  repair's residual limitation—SCP can still overwrite server-selected names
  inside the destination—and recommends SFTP.
- Accepted exact AsyncSSH implementation checkpoint
  `45895c7b94f2f09d7a766c13d81a235c31064ee8`. The authoritative native
  Windows suite passes 1,793 tests and 13,188 assertions across 199 files in
  557.97 seconds, with 26 intentional platform/environment skips and no
  failures. The focused model, residual-risk, and canonical lanes pass 73
  tests and 1,098 assertions on Windows with two intentional skips and all 75
  tests and 1,100 assertions on native Ubuntu/WSL. Generated-model drift,
  formatting, TypeScript, the clean production build, and the high-severity
  production audit are green. Two production-build inventories of a
  tracked-only exact-commit archive complete in 32,110.134 and 14,371.002
  milliseconds and are byte-identical at 256 rows, 550,240 bytes, and SHA-256
  `d960e3a488baf8e066500137072d2b907dced49cb82feaadcd3994dc74551e13`;
  200 rows carry structured framework evidence, 56 are lexical leads, and 249
  are fixture paths. Exactly one AsyncSSH row retains the affected fixture at
  `src/downloader.py:9`, all six binding/version/direction/destination/protocol/
  write-chain propagators, and CWE-22; the source-identical 2.23.1 control is
  absent. Strict inspection validates a 267-entry, 2,103,015-byte npm archive
  with SHA-256
  `04baad81c6082c339a4728f281c0550bb56b9e63b5957991448506f4462cff7c`;
  a fresh isolated install adds 67 packages and validates the public import,
  executable CLI, and all 79 bundled plugin files. A release-only `gitHead`
  assertion correctly rejects the local pack because npm registry provenance
  is not synthesized locally; the unchanged local contract passes after a
  native rerun is allowed to use npm's user cache. The first exact-head hosted
  Node matrix exposed one Windows-only fixture assertion: GitHub's checkout
  materialized `requirements.txt` with CRLF while the test compared an LF
  string. The scanner and all semantic assertions passed on every host. The
  test now normalizes only line endings before checking the two exact pins,
  preserving the byte-for-byte source-pair comparison and version boundary.
  All seven hosted families pass test-portability closure checkpoint
  `d24142c96782196901c952749939d59ea8771a7b`: Node `33038252883` with all
  seven Windows, macOS, and Linux jobs; Go `33038252834`; Java `33038252930`;
  .NET `33038252899`; container `33038252889`; Windows GUI `33038252893`;
  and Linux GUI `33038252864`. The exact-commit archive and snapshot, package,
  two self-scan reports, and isolated package consumer were removed after
  acceptance.
- Added `node-contentful-mcp-management-token-host-redirect`, an exact
  operational model for
  [GHSA-2xhg-73j7-rrgx / CVE-2026-53957](https://github.com/contentful/contentful-mcp-server/security/advisories/GHSA-2xhg-73j7-rrgx).
  It requires a top-level official root-package import or bounded operational
  npm script plus exact affected production provenance for
  `@contentful/mcp-server` before 1.7.19. Dependency membership, subpath or
  nested imports, arbitrary scripts, echo/lookalike commands, repaired or
  prerelease versions, development-only packages, unlocked ranges, stale or
  inconsistent modern locks, and npm v1 locks fail closed. Seven focused tests
  cover the version boundary, module and script launch families, exact evidence,
  modern lock proof, adversarial negatives, and field-local review guidance.
- Added a source-identical Contentful 1.7.15/1.7.19 benchmark pair with exact
  npm v3 locks, high/CWE-918+CWE-441 ground truth at `src/launcher.mjs:1`, and
  perfect three-run gates. The corpus advances to 135 pairs, 270 cases, and 810
  scans. Real installed input-shape witnesses report that server/tools
  1.7.15/0.4.1 admit `host`, `proxy`, `rawProxy`, `headers`, and `config` for
  both migration tools, while 1.7.19/0.4.5 admit none. An identical two-endpoint
  TLS witness uses a fake token and child-process-only trust: affected code
  sends one authorized request to the argument-controlled endpoint and none to
  the configured endpoint; repaired code sends one to the configured endpoint
  and none to the argument-controlled endpoint. No Contentful host, real token,
  or real space is used; certificate, key, trust, export, and error-log
  artifacts are removed after each run.
- Accepted exact Contentful implementation checkpoint
  `fdf1873453ba317d8f6e1ddb0f41d17773153e71` on Windows and tracked-only native
  Ubuntu/WSL. Both platforms pass generated-model verification, TypeScript,
  formatting, and the 25-test focused-plus-canonical lane with 2,097
  assertions; Ubuntu also reproduces both real installed-package witnesses.
  The strict 267-entry, 2,095,517-byte npm archive has SHA-256
  `4b81e35b7d17b88c71bc407bba9180ab672d7e84c842d81fb3ebc9730127bc2a`;
  inspection and isolated installation validate the public import, CLI, and all
  79 bundled plugin files, and the high-severity production audit is clean. Two
  production-build scans of a tracked-only archive complete in 24,570.383 and
  15,538.839 milliseconds and are byte-identical at 256 rows, 548,353 bytes,
  and SHA-256
  `3a45e0b0c93cedd82b01b5fe4d881124d31639c43f9cc769e0af3069eb86e9b7`.
  All 199 structured rows precede 57 lexical leads. Exactly one Contentful row
  retains the affected fixture at `src/launcher.mjs:1`; the source-identical
  repaired control is absent. Package, self-scan, WSL dependency, certificate,
  trust, export, and error-log artifacts were removed afterward. All seven
  hosted families pass that exact SHA: Node `32998739818` with all seven
  Windows, macOS, and Linux matrix jobs; Go `32998742451`; .NET `32998745587`;
  Java `32998748789`; Windows GUI `32998751947`; Linux GUI `32998754593`; and
  container `32998757081`.
- Corrected the SunEditor regression corpus's package-version assertions to
  use index-signature-safe access. The Node and container hosted lanes exposed
  `TS4111` under the pinned Linux TypeScript toolchain even though the scanner
  model, benchmark execution, and Windows checks passed. The correction is
  test-only and preserves all 2,105 focused-plus-canonical assertions. Exact
  checkpoint `bcf25476583d7e05e1c21e8d42a3ba3452bfe524` passes a clean
  tracked-only Ubuntu/WSL install, generated-model verification, typecheck,
  formatting, and the 25-test focused-plus-canonical lane. All seven hosted
  families also pass on that SHA: Node `32994131557` (7/7 Windows, macOS, and
  Linux matrix jobs), Go `32994135095`, .NET `32994138312`, Java `32994141457`,
  Windows GUI `32994144407`, Linux GUI `32994147806`, and container
  `32994150866`. The disposable WSL archive and native dependency tree were
  removed after verification.
- Added `node-suneditor-embed-external-script-xss`, an exact production model
  for
  [GHSA-w93q-cq9w-58p7 / CVE-2026-54606](https://github.com/advisories/GHSA-w93q-cq9w-58p7).
  It requires SunEditor through affected 3.1.3, an official stable create
  binding, an official Embed binding keyed as `embed` in the real plugin object
  or the complete official aggregate, a literal embed toolbar entry, and remote
  request content at the initial editor value or stable instance's
  `setContents` boundary. Exact 3.1.4+, prereleases, unlocked ranges,
  development-only or wrong packages, invalid plugin arrays, disconnected or
  missing plugins/buttons, trusted content, unrelated remote options,
  unexported entry points, lookalikes, and reassigned bindings, members, or
  editor instances fail closed. Seven focused tests and 55 assertions cover
  affected boundaries, fresh npm v3 lock proof, five official import families,
  both content boundaries, and adversarial controls.
- Added a source-identical SunEditor 3.1.3/3.1.4 benchmark pair with exact npm
  locks, high/CWE-79 ground truth at `src/editor.js:5`, and perfect three-run
  evidence gates. The corpus advances to 134 pairs, 268 cases, and 804 scans;
  the specialized plus canonical lane passes 25 tests and 2,105 assertions on
  both Windows and native Ubuntu/WSL. Exact installed-package checks report the
  3.1.4 default-deny script gate only in the repaired build. A disposable Edge
  differential binds a random `127.0.0.1` port and submits identical inert
  iframe-plus-script bytes through the official initialized Embed instance:
  3.1.3 returns submitted=true, requests the loopback script once, and sets the
  in-memory sentinel once; 3.1.4 returns submitted=false, makes zero script
  requests, and leaves the sentinel unset. Generated installs, browser
  profiles, and capture files were removed after verification.
- Accepted exact SunEditor implementation checkpoint
  `5049600aac9510971e527ca4dd8007906ce354f1` as a distributable scanner. Its
  strict npm archive contains 267 entries and 2,090,763 bytes with SHA-256
  `5053d9d06f0ea2f6cc61975069c0b9b0b134fc91a0957b5bb06af96bc4b07fdf`;
  isolated installation validates the public import, CLI, and all 79 bundled
  plugin files, and the high-severity production audit reports no known
  vulnerabilities. Two production-build inventories of a tracked-only archive
  complete in 15,040.279 and 15,340.177 milliseconds and are byte-identical at
  256 rows, 547,663 bytes, and SHA-256
  `9121aa09e7e2fb91d5fabf35e318f75ddf39bf4e68b8f033807663f7ff2269cf`.
  All 198 structured rows precede 58 lexical leads. Exactly one SunEditor row
  retains the affected fixture at `src/editor.js:5`; the source-identical 3.1.4
  control is absent. Package and self-scan artifacts were removed afterward.
- Added `node-logtape-syslog-structured-data-injection`, an exact
  production-provenance model for
  [GHSA-8h6h-x5pq-56fq / CVE-2026-54511](https://github.com/dahlia/logtape/security/advisories/GHSA-8h6h-x5pq-56fq).
  It requires an affected `@logtape/syslog` release, official stable
  `getSyslogSink`, `configure`, and `getLogger` bindings, literal
  `includeStructuredData: true`, a sink connected through the matching logger
  category, and request-controlled structured-data values or names in the
  record-properties argument. Exact repaired releases, unproved ranges,
  development-only or wrong packages, disabled or dynamic configuration,
  disconnected topologies, message-only data, trusted properties, transformed
  values, unexported request handlers, and lookalikes remain negative. The
  formatted production configuration can span a bounded 64-line call window
  without weakening the topology gates. The focused regression lane now passes
  eight tests and 71 assertions across all
  reviewed vulnerable branches, repaired boundaries, modern lock provenance,
  value and key injection, root-category inheritance, and adversarial controls.
- Added model-specific reviewer requirements for bounded loopback UDP/TCP byte
  capture, source-identical repaired comparison, escaped output, downstream
  parser and framing evidence, CWE-93/CWE-117 discipline, and conservative
  impact claims. Raw control-bearing records must never be printed or sent to a
  real collector.
- Added a strict source-identical 2.1.4/2.1.5 exploit/control pair with exact
  npm locks, high/CWE-93+CWE-117 ground truth at `src/audit.js:23`, and perfect
  three-run evidence gates. The corpus advances to 133 pairs, 266 cases, and
  798 scans. The LogTape and canonical lane passes 26 tests and 2,110
  assertions. Real installed-package UDP witnesses bind only `127.0.0.1`, emit
  one inert marker, and report byte indexes: 2.1.4 captured 167 bytes with a
  newline at index 98 and no `#010`; 2.1.5 captured 170 bytes with no newline
  and the decimal escape present. Both captured one datagram and retained the
  marker. Generated fixture `node_modules` trees were removed after the run.
- Completed local acceptance for exact benchmark checkpoint
  `0d8e41a438c3df941852aaeea17a142f6fd59875`. Windows and native Ubuntu/WSL
  both pass the 26-test LogTape/canonical lane with 2,110 assertions, and the
  installed-package UDP differential returns identical 2.1.4/2.1.5 byte facts
  on both platforms. The full managed Windows Bun 1.3.14 aggregate exercises
  1,797 tests across 196 files in 605.62 seconds: 1,770 pass, 25 intentional
  platform skips remain, and only the established child-Git provenance and
  private `copilot-security-home` ACL cases fail under the managed host. Their
  exact native rerun passes 2/2 with seven assertions; the aggregate records
  13,016 assertions.
- The strict 267-entry, 2,085,415-byte local npm archive has SHA-256
  `3514ea9ebeea6cfc4f958f10a3b504316db6826a114eff26005f4faee96efc17`
  and passes archive inspection plus two isolated installation checks of the
  public import, CLI, and all 79 bundled-plugin files. The production advisory
  audit reports no known vulnerabilities. Two production-build inventories of
  a tracked-only archive of the exact checkpoint complete in 23,334.738 and
  15,607.766 milliseconds and emit 256 byte-identical rows, 550,439 bytes, and
  SHA-256
  `cf4b095123a4ac87e7789a2b90c027ae8fb738ce1caf848848f36be3b38d12a2`.
  All 197 structured rows survive ahead of 59 lexical leads; 247 rows are
  fixture paths and nine are not. Exactly one LogTape row retains the affected
  fixture topology while the source-identical 2.1.5 control remains absent.
  Package, self-scan, and real-runtime dependency artifacts were removed after
  verification.
- Completed the hosted acceptance matrix for the LogTape scanner checkpoint.
  Node (`32985953331`), Go (`32986015950`), .NET (`32986478961`), Java
  (`32986478963`), and Windows GUI (`32986479000`) passed on the exact
  implementation commit. The retry-control commit changes no scanner or
  fixture source; its manually dispatched Linux GUI run (`32986968743`) passed
  all package, core, desktop, headless, publish, non-graphical/X11 startup, and
  artifact checks in 2m30s, while container run `32987171001` passed all
  customer-context, image, bundled-scanner, hardened Compose, discovery, and
  credential checks in 2m16s. The superseded Linux and container attempts
  executed zero steps and are classified only as runner allocation failures.
- Extended the Traefik file-provider model from one YAML filename to exact
  YAML or TOML filename and directory configurations. Directory providers bind
  an exact Compose mount and merge routers, middlewares, and services from
  immediate top-level `.yml`, `.yaml`, and `.toml` children, preserving each
  source and sink location and accepting explicit `@file` references. Malformed
  supported siblings, duplicate cross-file resource names, nested or adjacent
  paths, ambiguous filename/directory commands, unsupported extensions, and
  cross-provider references fail closed. The focused suite now passes 12 groups
  and 144 assertions. Added a third source-identical Traefik exploit/control
  pair that changes only 3.7.6 to 3.7.7 while splitting TOML routers, YAML
  middlewares, and a TOML service across one mounted directory. Its strict
  specialized and canonical expectations require one high/CWE-22 finding at
  `dynamic/middlewares.yml:4` and none on the repaired fixture. The corpus
  advances to 132 pairs, 264 cases, and 792 scans; Windows and native Ubuntu/WSL
  both pass the combined focused and canonical lane's 30 tests and 2,186
  assertions. A real-binary WSL witness extracted the exact executables from
  cached official image IDs
  `21a3d8369637` and `1cb3845d7a05`: 3.7.6 kept direct HTTP 401, forwarded raw
  `/../admin` to normalized `/admin`, and returned the inert marker with 200;
  3.7.7 kept direct 401, returned 400, and recorded no crafted backend hit.
  Both temporary binaries and extraction containers were removed.
- Completed acceptance for exact benchmark checkpoint
  `3519cd663be19c9acd92c17971e360bf02d35384`. The full managed Windows Bun
  1.3.14 aggregate exercises 1,789 tests across 195 files in 607.23 seconds:
  1,762 pass, 25 intentional platform skips remain, and only the established
  child-Git provenance and private `copilot-security-home` ACL cases fail under
  the managed host. Their exact native rerun passes 2/2 with seven assertions;
  the aggregate records 12,934 assertions. Windows and native Ubuntu/WSL both
  pass the 30-test Traefik/canonical lane with 2,186 assertions. All seven
  hosted workflows pass: Go `32983317559`, Windows GUI `32983317601`, Java
  `32983317691`, .NET `32983317588`, container `32983317608`, Linux GUI
  `32983317710`, and Node `32983317684`.
- The strict 267-entry, 2,048,439-byte npm archive has SHA-256
  `5c3473b2338e07b9406b383a1e246d11d2c4f621b1e1ab431bd7d398a1bf6cc3`
  and passes archive inspection plus two isolated installation checks of the
  public import, CLI, and all 79 bundled-plugin files. The production advisory
  audit reports no known vulnerabilities. Two production-build inventories of
  a tracked-only archive of the exact checkpoint complete in 31,692.479 and
  15,990.594 milliseconds and emit 256 byte-identical rows, 548,306 bytes, and
  SHA-256
  `61a67743dbcdbd303f34d9b65595361bd21023791ac47be8e89d25ca36b116dd`.
  All 196 structured rows survive ahead of 60 lexical leads; 246 rows are
  fixture paths and ten are not. Exactly three Traefik positives retain the
  affected filename, Docker-label, and split-directory topologies, while all
  three source-identical 3.7.7 controls remain absent. Package, self-scan, and
  real-runtime temporary artifacts were removed after verification.
- Added a source-identical Docker-provider Traefik exploit/control pair that
  changes only the proxy image from 3.7.6 to 3.7.7. The operational Compose
  topology keeps the proxy entry point loopback-published, the inert backend
  unexposed, explicit container enablement, a canonical read-only Docker socket
  bind, escaped replacement labels, inline BasicAuth, and an exact backend
  port. Its strict specialized and canonical expectations require one
  `compose.yml:29` high/CWE-22 finding on the affected fixture and none on the
  repaired fixture. The corpus advances to 131 pairs, 262 cases, and 786 scans.
  A source-identical real-Compose witness now selects a unique project and
  ephemeral loopback port, verifies the exact in-container release, waits for
  both the auth boundary and backend, records bounded backend paths, and tears
  down containers, networks, and volumes even after failure. WSL Docker 29.1.3
  reproduces the 3.7.6 raw `/../cps-benchmark-admin` to normalized
  `/cps-benchmark-admin` marker hit with HTTP 200; 3.7.7 returns HTTP 400 with
  no crafted backend hit. Both retain direct HTTP 401 and leave no project
  resources. Fixture-specific router, middleware, service, and route names
  avoid collisions with ordinary daemon-wide Docker-provider discovery.
- Completed final acceptance for exact checkpoint
  `77d3d6408fac3da1e76f965e22f8d6d5e1ef3ed9`. The full Windows aggregate
  exercises 1,788 tests across 195 files in 635.34 seconds: 1,761 pass, 25
  intentionally skip, and only the established managed-host child-Git and
  private scanner-home ACL cases fail. Their native rerun passes 2/2 with seven
  assertions; the full aggregate records 12,880 assertions. Windows and native
  Ubuntu/WSL both pass the 29-test Traefik/canonical lane with 2,132 assertions.
  All seven hosted workflows pass: Node `32977873933`, container `32977873804`,
  Windows GUI `32977873796`, Linux GUI `32977873806`, Go `32977873843`, Java
  `32977873902`, and .NET `32977873957`.
- Two production-build inventories of a tracked-only archive of that exact
  checkpoint complete in 31,100.745 and 14,195.887 ms and produce 256
  byte-identical rows, 546,161 bytes, and SHA-256
  `b25ee70c4539f8ec075524a51eab2051f5b6df1bba2c71eafe05b373911c36bd`.
  All 195 structured rows survive ahead of 61 lexical leads; 246 rows are
  fixture paths and ten are not. Exactly two Traefik positives retain the file
  and Docker-label affected fixtures, exact source/sink lines, CWE-22, and
  3.7.6 provenance; both 3.7.7 controls remain absent. The strict 267-entry,
  2,071,489-byte npm archive has SHA-256
  `37658bca179eb08db0f9b78dbc425a5404dac6bf72c3f5df7247b17a2ba73170`
  and passes isolated public import, CLI, and all 79 bundled-plugin checks. The
  production advisory audit reports no known vulnerabilities. Package and
  self-scan artifacts were removed after verification.
- Corrected the Traefik v3 lower bound to the official 3.6.0 introduction.
  Releases 3.0.0 through 3.5.x now remain negative instead of inheriting the
  affected 3.6 branch, and the focused release matrix and reviewer contract
  preserve that false-positive boundary.
- Extended the Traefik model to Docker-provider Compose labels, the common
  application-owned configuration surface documented by Traefik. Exact
  sequence and mapping labels bind one enabled backend container's public and
  protected routers, middleware references, effective `ReplacePathRegex`,
  concrete auth, entry point, service, and load-balancer port to an affected
  proxy with `--providers.docker=true` and the Docker socket mounted. Disabled
  containers, `exposedByDefault=false` without explicit enablement, provider
  constraints, remote endpoints, Swarm mode, lookalike enablement,
  cross-provider middleware references, duplicate or unresolved-interpolation
  labels, unproved auth files, invalid ports, safe replacements, and repaired
  releases remain negative.
- Added the first `traefik-replacepathregex-auth-bypass` implementation for
  [GHSA-cxjq-mrr5-89rv](https://github.com/traefik/traefik/security/advisories/GHSA-cxjq-mrr5-89rv).
  The cross-file configuration model binds an exact affected official Traefik
  Compose image and mounted file provider to a public `PathPrefix`, the exact
  separator-free `ReplacePathRegex` traversal shape, and an authenticated
  sibling router on the same entry point and defined backend. Repaired or
  prerelease images, mismatched providers/mounts, duplicate or aliased YAML,
  safe regex/replacement shapes, public authentication, empty protected auth,
  undefined or different services, and disjoint entry points fail closed.
- Preserved vulnerable writable-mount coverage: exact short and long Compose
  bind syntax now accepts read-only, explicit read-write, and default modes,
  since provider-file writability is not a prerequisite for the routing flaw.
  Source locations are resolved within the correct YAML service, router, and
  middleware blocks so decoy keys cannot corrupt finding evidence. Test,
  example, and vendor configuration trees remain excluded.
- Added field-local validation and impact rules plus focused release,
  topology, provenance, YAML-integrity, authentication, and mount regressions.
  Current CodeQL and Semgrep rule repositories contain no match for either the
  advisory ID or `ReplacePathRegex`. A source-identical executable benchmark
  pair and real-binary differential follow this implementation checkpoint.
- Added the source-identical Traefik 3.7.6/3.7.7 exploit/control pair, strict
  three-run specialized manifest, canonical registration, fixture integrity
  checks, and a dependency-free loopback witness. The affected official binary
  denied direct `/admin`, forwarded crafted `/api../admin` as `/../admin`, and
  reached the inert backend marker at normalized `/admin` with HTTP 200. The
  repaired binary denied the direct route and returned HTTP 400 with no backend
  hit. Official checksum manifests matched SHA-256
  `3bf0555714961fe01d8e07c3899788fe6564da75374db5775ea9ad7d18b71a5d`
  for 3.7.6 and
  `5c8ff19144683f862c04e8ac01893e8cd94a3519d3d9ca3e6fbd0a7de73261ba`
  for 3.7.7. Ten focused tests pass with 65 assertions; the canonical corpus
  advances to 130 exploit/control pairs and 780 scans, with its 18 structural
  tests and 2,006 assertions passing.
- Completed Traefik acceptance at exact checkpoint
  `37e949288322d714a2f1c5996516e262ea424de8`. The full managed Windows Bun
  1.3.14 run exercises all 1,787 tests across 195 files: 1,760 pass, 25
  intentional skips remain, and only the two established Git/Windows-ACL host
  boundaries fail inside the managed sandbox; their native rerun passes 2/2
  tests and 7 assertions. The aggregate records 12,819 assertions in 625.64
  seconds. Native Ubuntu/WSL passes the focused Traefik and canonical lane with
  28 tests and 2,071 assertions. Generated models, TypeScript, the production
  build, formatting, the installed-package contract, and the production
  advisory audit are clean.
- Two compiled scans of a disposable exact-commit archive take 31,972.627 and
  15,297.327 milliseconds and produce 256 byte-identical rows, 543,066 bytes,
  and SHA-256
  `8b3ad02982368129ff324101a1976f24c4e1b9e91a76b8bfe86b9fe03d006b12`.
  All 194 structured records survive ahead of 62 lexical leads, with 246
  fixture and 10 non-fixture rows. Exactly one Traefik row retains public source
  `dynamic.yml:3`, rewrite sink `dynamic.yml:15`, protected sibling line 8,
  affected Compose image line 3, CWE-22, and exact 3.7.6 provenance; the 3.7.7
  twin is absent. The 267-entry, 2,061,495-byte npm archive has SHA-256
  `b58928e692468872693a4a1189b3cf96d23ac746e9a3bcb523243facdcc3f8bb`
  and validates the public import, CLI, and all 79 bundled plugin files. All
  seven exact-head workflows pass: Node `32970804925`, Go `32970804800`,
  Windows GUI `32970804831`, .NET `32970804875`, Java `32970804789`, container
  `32970804784`, and Linux GUI `32970804824`. Disposable exact-commit scan data,
  package archives, and real-binary caches are removed after acceptance.
- Added `go-echo-static-encoded-separator-auth-bypass` for
  [GHSA-vfp3-v2gw-7wfq / CVE-2026-55677](https://github.com/labstack/echo/security/advisories/GHSA-vfp3-v2gw-7wfq).
  The model requires an official stable Echo instance, a middleware-protected
  non-root group with an active wildcard GET route, a root `Static` or
  `StaticFS` handler on the same instance, an actual server start, stable
  instance/group bindings, and nearest exact non-replaced affected `go.mod`
  provenance. It covers the unpatched legacy module through 3.3.10, v4 before
  4.15.3, and v5 before 5.2.0. Dependency membership, repaired/prerelease or
  replaced versions, local lookalikes, incomplete/non-GET/non-wildcard route
  policy, non-root static mounts, separate or reassigned instances, missing
  activation, and tests/examples fail closed.
- Added source-identical Echo 4.15.2/4.15.3 fixtures, complete Go sums, a strict
  specialized manifest, canonical registration, field-local correction
  guidance, and adversarial regressions for v3/v4/v5 boundaries, aliased
  imports, both static APIs, inline and `Use` middleware, nearest modules,
  mutation, replacement, and incomplete topology controls. The real-package
  witness uses `httptest` and one inert marker inside a test-owned temporary
  static root: a direct request is denied on both builds, 4.15.2 returns the
  marker for the encoded-separator request, and 4.15.3 returns 404. The
  canonical corpus advances to 129 exploit/control pairs, 258 cases, and 774
  repeated scans.
- Closed full acceptance at implementation checkpoint `1057897` and package
  correction `f8e5f30`. The complete Windows aggregate exercised 1,777 tests:
  1,750 passed, 25 intentionally skipped, and only the two known managed-host
  ACL/child-process boundaries failed; their exact native rerun passed 2/2.
  The final Go/canonical lane passed 393 tests plus one platform skip on Windows
  and 394/394 on Ubuntu/WSL. Both hosts reproduced affected 200 marker
  disclosure and repaired 404 rejection. Two exact-head repository inventories
  are byte-identical at 256 rows and retain exactly one affected Echo row while
  excluding the repaired twin.
- Added the compiled `go-echo-risk` artifacts to strict npm package inspection
  after the first hosted Linux/container builds correctly rejected the new
  unlisted module. Fresh 263-entry Windows and POSIX archives now pass strict
  inspection and installed-consumer smoke. Windows and Linux GUIs pass their
  complete local build, test, publish, and startup matrices, and all seven
  exact-head hosted workflow families pass. Generated-model drift, formatting,
  TypeScript, production build, and the high-severity production audit are
  clean.
- Added `node-undici-socks5-cross-origin-routing` for
  [GHSA-hm92-r4w5-c3mj / CVE-2026-6734](https://github.com/nodejs/undici/security/advisories/GHSA-hm92-r4w5-c3mj).
  The model requires one official stable `Socks5ProxyAgent`, a request-controlled
  first destination, a later standard credential-bearing request through the
  same explicit or global dispatcher, correct call ordering, stable bindings,
  and exact affected production provenance in Undici 7.23.0 through 7.27.x or
  8.0.0 through 8.1.x. Repaired/prerelease versions, development-only or stale
  metadata, fixed first destinations, missing or custom headers, separate or
  reassigned agents, overwritten global dispatchers, local lookalikes, and
  tests/examples fail closed.
- Added source-identical Undici 7.27.2/7.28.0 fixtures, exact npm locks, a
  strict specialized manifest, canonical registration, field-local correction
  guidance, and adversarial regressions across both release windows, modern
  lock proof, named/aliased/namespace/CommonJS bindings, explicit and global
  dispatch, ordering, credentials, agent identity, mutation, and provenance.
  A bounded real-package differential uses two loopback HTTP origins, one
  loopback-only SOCKS5 proxy, and an inert authorization marker: 7.27.2 sends
  both requests to the first origin, while 7.28.0 sends the second request to
  its intended origin. The canonical corpus advances to 128 exploit/control
  pairs, 256 cases, and 768 repeated scans.
- Exact implementation checkpoint
  `52be9d450c769eed259c0d41671f6d87bc0adf3f` passes the focused model lane
  with nine tests and 43 assertions, the adjacent Windows lane with 115 passes,
  one intentional platform skip, and 3,177 assertions, and the corresponding
  Ubuntu/WSL lane with 116 passes and 3,178 assertions. Both systems reproduce
  the loopback-only 7.27.2/7.28.0 witness boundary. The complete Windows Bun
  aggregate records 1,740 passes, 25 intentional skips, and 12,692 assertions
  across 1,767 tests and 193 files in 606.70 seconds. Its only two failures are
  the established managed child-Git and private-Windows-ACL boundaries; their
  exact native rerun passes 2/2 tests and seven assertions. Generated-model
  drift, formatting, TypeScript, the clean production build, and the production
  advisory audit are green.
- Strict inspection accepts a 259-entry, 2,039,028-byte npm archive with
  SHA-256
  `17a47234b38c77e3f51e7b4f00c53b709bcb0350e1e3544f5301c213ce44f47d`.
  Fresh Windows and Ubuntu consumers add 67 and 75 packages and validate the
  public SDK import, executable CLI, and all 79 bundled plugin files. Windows
  builds with zero warnings or errors, passes 7/7 core and 3/3 shared tests,
  survives bounded hidden startup, and publishes a 346,796-byte executable with
  SHA-256
  `a6630a86308d4b50dcb29856f7c870fab8483a7fa17471206cfbe8867390c939`.
  Ubuntu/WSL performs locked restores, builds with zero warnings or errors,
  passes 7/7 core, 3/3 shared, and 2/2 Linux UI tests, and passes non-graphical
  plus real X11/Xvfb startup. Its self-contained 72,568-byte executable has
  SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- Two production-build inventories of a tracked-only archive of that exact
  checkpoint complete in 31,036.171 and 15,682.558 ms and produce 256
  byte-identical rows, 542,005 bytes, and SHA-256
  `5e8e323fb7907fa3a4922a93399b3f9ec6255d01406444d2d425cd1806a348ab`.
  All 192 structured rows survive ahead of 64 lexical leads; 241 rows are
  fixture paths and 15 are not. Exactly one Undici record binds the remote first
  request at `src/server.js:6` to the credentialed second request at line 7,
  retains CWE-346 and exact
  `undici@7.27.2:manifest-exact:single-cross-origin-socks5-pool` provenance,
  and excludes the source-identical 7.28.0 control. All seven exact-checkpoint
  workflows pass: Node `32960600167`, Windows GUI `32960600187`, Linux GUI
  `32960600250`, container `32960600218`, Go `32960600249`, Java
  `32960600146`, and .NET `32960600220`.
- Added `node-nx-self-hosted-cache-archive-escape`, an operational
  configuration-, task-execution-, provider-, and exact build-dependency model
  for
  [GHSA-vp3h-ghgh-jr7g / CVE-2026-71476](https://github.com/nrwl/nx/security/advisories/GHSA-vp3h-ghgh-jr7g).
  The built-in HTTP surface reports only when a nonempty
  `NX_SELF_HOSTED_REMOTE_CACHE_SERVER` assignment and a cache-consuming Nx task
  share an operational file under stable affected Nx 20.8.0 through 22.7.6 or
  23.0.0 through 23.0.1 provenance. Administrative commands, local cache, Nx
  Cloud, fixed/prerelease versions, unproved or stale locks, and explicit cache
  bypasses fail closed.
- Added coverage for all eight separately versioned `@nx/*-cache` and
  `@nx/powerpack-*-cache` packages named by the advisory. Provider packages
  require their matching `nx.json` object; shared-filesystem packages require a
  CI task path. These remain findings under fixed core Nx because their own
  extractors are deprecated and unpatched. `nx.json` and bounded `.env` files
  now participate in source discovery, and Nx build dependencies correctly
  accept exact dev-dependency or declaration-consistent npm v2/v3 lock proof.
- Added source-identical Nx 22.7.6/22.7.7 fixtures, exact npm locks, a strict
  specialized manifest, canonical registration, field-local correction
  guidance, and adversarial regression coverage for version windows, five task
  forms, cache-disable controls, provider configuration, shared-filesystem CI,
  and fixed-core/unpatched-provider coexistence. A loopback-only real-package
  differential confines every write to a disposable root: 22.7.6 writes one
  inert sentinel outside its per-hash cache directory, while 22.7.7 rejects or
  contains the identical gzip tar. The canonical corpus advances to 127
  exploit/control pairs, 254 cases, and 762 repeated scans.
- Exact implementation checkpoint
  `4a77487e86754e5af05e13b93c1f437822b55775` passes the focused Nx,
  framework, and canonical lane with 43 tests and 2,123 assertions on Windows
  and 2,122 assertions on Ubuntu/WSL. The complete Windows Bun aggregate records
  1,731 passes, 25 intentional skips, and 12,638 assertions across 1,758 tests
  and 192 files in 686.81 seconds; its only two failures are the established
  managed child-Git and private-Windows-ACL boundaries, whose exact native
  reruns pass 2/2 tests and seven assertions. Generated-model drift, formatting,
  TypeScript, the clean production build, and the production advisory audit are
  green.
- Strict inspection accepts a 259-entry, 2,030,344-byte npm archive with
  SHA-256
  `7017c58d90d60574966260b5e3046e3c79abb1a1f23c9e10468fa42097377cc2`.
  Fresh Windows and Ubuntu consumers add 67 and 75 packages and validate the
  public SDK import, executable CLI, and all 79 bundled plugin files. Windows
  builds without warnings or errors, passes 7/7 core and 3/3 shared tests,
  survives hidden startup, and publishes a 346,796-byte executable with
  SHA-256
  `df65e451da9a243fb9e710fc02b45a75ec11e6c945f936f747dfe76340d44446`.
  Ubuntu/WSL performs locked restores, builds without warnings or errors,
  passes 7/7 core, 3/3 shared, and 2/2 Linux UI tests, and passes non-graphical
  plus real X11/Xvfb startup. Its self-contained 72,568-byte executable has
  SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- Two production-build inventories of a tracked-only archive of that exact
  checkpoint complete in 37,719.902 and 18,208.277 ms and produce 256
  byte-identical rows, 540,451 bytes, and SHA-256
  `42cced376a319a661e8c306e71d26c9e148d81cc8dfce8194766998c93cf4c12`.
  All 191 structured rows survive ahead of 65 lexical leads; 241 rows are
  fixture paths and 15 are not. Exactly one Nx row retains the line-7
  self-hosted cache configuration, line-10 cache-consuming task, CWE-22/CWE-59,
  and exact `nx@22.7.6:manifest-exact:unconfined-http-cache-tar-extraction`
  provenance; the source-identical 22.7.7 control is absent. All seven
  exact-checkpoint workflows pass: Node `32956856745`, Windows GUI
  `32956856714`, Linux GUI `32956856565`, container `32956856591`, Go
  `32956856599`, Java `32956856743`, and .NET `32956856769`. GitHub reports the
  repository public on default branch `main`.
- Added `node-pickem-terminal-control-injection`, an exact production-version,
  official-binding, remote-collection, display-projection, and terminal-render
  model for
  [GHSA-8qx3-8gm5-9cj2](https://github.com/calebogden/pickem-oss/security/advisories/GHSA-8qx3-8gm5-9cj2).
  It reports CWE-150 only when request or fetched JSON is mapped from one remote
  item into `label`, `description`, or `group` and that collection reaches an
  official stable `pickem` or `pickem.checkbox` call under exact affected
  production provenance. Fixed/prerelease versions, package-only presence,
  development or wrong packages, unproved/stale/inconsistent/v1 locks, trusted
  arrays, value-only flow, neutralized text, custom formatters, reassignment,
  local lookalikes, and incomplete topologies fail closed.
- Added source-identical 1.0.6/1.0.7 fixtures, exact npm locks, a strict
  specialized manifest, canonical registration, model-specific correction
  guidance, and adversarial regressions for official ESM, namespace,
  TypeScript/CommonJS bindings, request/fetch sources, checkbox and display-field
  variants, version/provenance edges, sanitization, mutation, and topology
  controls. The public `createFormatter` witness opens no TTY and never prints
  raw rendered data: 1.0.6 retains OSC, BEL, DEL, C1, and one inert clipboard
  marker, while 1.0.7 removes all five and preserves the selected value. The
  canonical corpus advances to 126 exploit/control pairs, 252 cases, and 756
  repeated scans.
- The focused Pickem/framework/canonical lane passes 42 tests and 2,106
  assertions on Windows and native Ubuntu/WSL. The complete Windows Bun
  aggregate passes 1,722 tests, skips 25 intentional platform/environment cases,
  and records 12,552 assertions; its only two failures across 1,749 tests and
  191 files are the known managed child-Git and private-Windows-ACL host
  boundaries. Exact native reruns pass 2/2 tests and seven assertions. Formatting,
  generated-model drift, TypeScript, and the clean production build are green.
- Exact implementation checkpoint
  `f7699499f72a1aa309592ab75240e9bddd63fc0e` passes the production advisory
  audit with no known vulnerabilities. Strict inspection accepts a 259-entry,
  2,021,712-byte npm archive with SHA-256
  `72f05e72986f68f5df08df6a9851aa65df9b09802829a0f2313012bb194cad37`;
  fresh Windows and Ubuntu installs add 67 and 75 packages and validate the
  public SDK import, executable CLI, and all 79 bundled plugin files. Windows
  builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests,
  survives hidden startup, and publishes a 346,796-byte executable with SHA-256
  `34917a868fbdd5f2d95c7f7b33f0152ef35dd0228c7152209c921ff560977411`.
  Ubuntu/WSL performs locked restores, builds with zero warnings/errors, passes
  7/7 core, 3/3 shared, and 2/2 Linux UI tests, and passes non-graphical plus
  real X11/Xvfb startup; its 72,568-byte executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- Two production-build inventories of a tracked-only archive of the exact
  checkpoint complete in 32,422.082 and 14,790.882 ms and produce 256
  byte-identical rows, 539,915 bytes, and SHA-256
  `d151b5be935b949db11cdd5eee0142afc07a370f25317fb9e7aa8807886cc3bf`;
  240 rows are fixture paths and 16 are not. Exactly one Pickem row survives:
  fetched JSON line 4 reaches label projection line 7 and picker line 11 with
  CWE-150, five ordered propagators, and
  `pickem@1.0.6:manifest-exact:unsanitized-terminal-display` provenance; the
  source-identical 1.0.7 control is absent. All seven exact-checkpoint workflows
  pass: Node `32952531990`, Windows GUI `32952531970`, Linux GUI `32952532106`,
  container `32952532017`, Go `32952531983`, Java `32952531976`, and .NET
  `32952532023`. GitHub reports the repository public on default branch `main`,
  and generated package, GUI, witness, and tracked-archive artifacts are removed.

- Added `node-defuddle-extractor-html-xss`, an exact production-provenance,
  official-binding, relative-wrapper, remote-input, returned-property, and HTML
  execution-boundary model for
  [GHSA-jg4p-g6xj-4qmf / CVE-2026-61824](https://github.com/kepano/defuddle/security/advisories/GHSA-jg4p-g6xj-4qmf).
  It reports CWE-79 only when request or fetched HTML reaches argument zero of
  the official `defuddle/node` `Defuddle` API through an exported relative
  wrapper and that exact response's `content` reaches an explicit HTML
  response, DOM `innerHTML`, React `dangerouslySetInnerHTML`, or Web `Response`
  boundary. Patched/prerelease versions, package-only presence, development or
  wrong packages, unproved/stale/inconsistent/v1 locks, trusted literals,
  non-HTML output, sanitization, reassignment, local lookalikes, and incomplete
  wrappers fail closed.
- Added source-identical 0.19.0/0.19.1 fixtures, exact npm locks, a strict
  specialized manifest, canonical registration, model-specific correction
  guidance, and adversarial regressions across official ESM, namespace,
  TypeScript/CommonJS-compatible bindings, request/fetch sources, four render
  boundaries, modern lock provenance, and an adversarial matrix of missing or
  controlled topologies.
  A network-disabled real-package witness reparses a synthetic X article:
  published 0.19.0 emits one inert sentinel `onerror` attribute, while 0.19.1
  emits none. It never executes the attribute. The canonical corpus advances
  to 125 exploit/control pairs, 250 cases, and 750 repeated scans.
- Exact implementation checkpoint
  `06f0bf086733736034beecb40cc0803d0995972b` passes the complete Windows
  Bun aggregate with 1,714 passes, 25 intentional skips, 12,472 assertions,
  and two managed-sandbox-only failures across 1,741 tests and 190 files in
  646.06 seconds. Exact native reruns of those child-Git and private-ACL
  boundaries pass 2/2 tests and seven assertions. The focused Defuddle,
  framework-dataflow, framework-model, and canonical lane passes 42 tests and
  2,090 assertions on both Windows and Ubuntu/WSL. Both hosts reproduce the
  real 0.19.0 event-attribute output and 0.19.1 rejection without network
  access. Generated-model drift, formatting, TypeScript, clean build, and the
  production advisory audit are green.
- Strict inspection accepts a 259-entry, 1,988,285-byte npm archive with
  SHA-256
  `ee7da1d952126f48ca904ff1ebaa4dc02e8d11bb4ea8017e719879c379d74355`;
  two isolated installs validate the public SDK import, executable CLI, and
  all 79 bundled plugin files. Windows builds without warnings or errors,
  passes 7/7 core and 3/3 shared tests plus hidden startup, and publishes a
  346,796-byte executable with SHA-256
  `a2f51604757dd0902bf85bb198f00f60cb9d862052ddd5e5bc412edac6d2a689`.
  Ubuntu/WSL performs locked restores, builds without warnings or errors,
  passes 7/7 core, 3/3 shared, and 2/2 Linux interface tests plus non-graphical
  and Xvfb startup, and publishes a 72,568-byte executable with SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
- Two compiled inventories of a private tracked-only archive complete in
  31,714.436 and 15,632.411 ms and produce 256 byte-identical rows, 538,362
  bytes, and SHA-256
  `51e79e65326112417c41f24e25766c192dfdf1a6a608d368481c4617f2d9f313`.
  They retain 189 structured records, 240 fixture rows, and exactly one
  Defuddle path from request-body source line 4 through the official wrapper
  and parser to HTML sink line 7 with exact
  `defuddle@0.19.0:manifest-exact:unsanitized-site-extractor-output`
  provenance; the 0.19.1 control is absent. All seven exact-checkpoint hosted
  workflows pass: Node `32948233605`, Windows GUI `32948233653`, Linux GUI
  `32948233656`, container `32948233728`, Go `32948233597`, Java
  `32948233723`, and .NET `32948233914`. The repository remains public on
  default branch `main`, and all generated acceptance artifacts are removed.

- Added `node-plate-media-embed-metadata-xss`, an exact provenance-,
  component-registration-, parser-, provider-gate-, iframe-, and cross-file
  dataflow-aware CWE-79 model for
  [GHSA-qj6x-xx2h-8hvv / CVE-2026-55596](https://github.com/udecode/plate/security/advisories/GHSA-qj6x-xx2h-8hvv).
  It requires fetched JSON or an HTTP request body to reach a `Plate` value or
  `initialValue` through an exported component prop, an official
  `MediaEmbedPlugin.withComponent` registration, official `useMediaState` with
  nonempty URL parsers and an `isVideo` fail-closed gate, the same `embed.url`
  reaching a script-capable iframe, and exact affected production
  `@platejs/media` 53.0.0 through 53.1.3 provenance.
- Added source-identical 53.0.1/53.1.4 fixtures, a strict specialized
  manifest, canonical corpus registration, field-local correction guidance,
  and adversarial regressions for version edges, npm v2/v3 provenance,
  official ESM/TypeScript/CommonJS binding forms, hook-result shapes,
  `value`/`initialValue`, request-body sources, missing topology edges,
  script-blocking sandboxes, local lookalikes, reassignment, sanitization, and
  trusted static values. The source matcher now anchors the component use
  before testing mutation ranges, so JSX attributes cannot masquerade as
  JavaScript assignments or let a prior reassignment hide inside lookahead.
- Added a bounded real-package differential witness that executes no attacker
  URL, opens no listener, and contacts no external service. On both Windows and
  native Ubuntu, published 53.0.1 retains the inert `javascript:` URL with
  `provider=vimeo` and `isVideo=true`; published 53.1.4 returns no embed and
  `isVideo=false`. Browser-context execution, document write authority, CSP,
  session privilege, and concrete impact remain mandatory validation evidence.
  The canonical corpus advances to 124 exploit/control pairs, 248 cases, and
  744 repeated scans.

- Added `node-nextjs-dynamic-route-param-authorization-bypass`, an exact
  route-, gate-, data-access-, provenance-, and version-aware CWE-288 model for
  [GHSA-492v-c6pp-mqqv / CVE-2026-44574](https://github.com/vercel/next.js/security/advisories/GHSA-492v-c6pp-mqqv).
  It requires an official middleware or proxy that denies one concrete dynamic
  path, a covering matcher when configured, exactly one matching App or Pages
  Router segment, that parameter entering a server-side data operation, no
  route-local authorization control, and affected production `next` provenance:
  15.4.0 through 15.5.15 or 16.0.0 through 16.2.4.
- Added exact App/Pages route parsing, route-group support, direct/bracket and
  destructured-alias parameter tracking, balanced multiline call attribution,
  middleware pathname aliases and reversed comparisons, proxy support, and
  401/403/login denial recognition. Static/multi-parameter/display-only routes,
  reassigned aliases, local auth/session/cookie/header/permission checks,
  unrelated matchers or denied paths, missing `next/server`, incomplete denials,
  prereleases, repaired versions, development-only or wrong packages,
  lockfile-free ranges, and stale/inconsistent/v1 locks fail closed.
- Added source-identical 15.5.15/15.5.16 Pages Router fixtures, a strict
  specialized manifest, canonical corpus registration, field-local validation
  guidance, and an adversarial regression matrix. The real-package witness
  builds and starts both standalone servers on disposable loopback ports. It
  preserves the observed counterevidence that ordinary requests resolve the
  visible `public` segment first, then exercises the exact wrapped route-module
  handoff changed by upstream: 15.5.15 prepares `secret` from external
  `nxtPslug`, while 15.5.16 filters it and retains the route placeholder. The
  canonical corpus advances to 123 exploit/control pairs, 246 cases, and 738
  repeated scans.

- Added `node-deepseek-mcp-http-cross-session-authorization-bypass`, an exact
  deployment-, transport-, launch-, provenance-, and version-aware CWE-639
  model for
  [GHSA-fh3r-g96v-f578 / CVE-2026-55604](https://github.com/arikusi/deepseek-mcp-server/security/advisories/GHSA-fh3r-g96v-f578).
  It requires affected production `@arikusi/deepseek-mcp-server` 1.4.2 through
  1.6.x plus literal HTTP selection and an actual top-level dynamic launch or
  bounded start/serve/server/mcp script. STDIO, static-import ordering, nested
  or test launchers, overwritten/dynamic transport, arbitrary or echo-only
  scripts, prereleases, dev-only/wrong packages, unresolved ranges,
  stale/inconsistent/v1 locks, and 1.7.0 or later fail closed.
- Added source-identical 1.6.0/1.7.0 fixtures, a strict specialized manifest,
  canonical corpus registration, field-local validation guidance, and an
  adversarial regression matrix for JavaScript and POSIX/Windows npm launch
  forms. Exact declarations and fresh declaration-consistent npm v2/v3 locks
  are accepted. The canonical corpus advances to 122 exploit/control pairs,
  244 cases, and 732 repeated scans.
- Added a bounded real-package differential witness that opens no listener and
  contacts no API. Two simulated client flows share the 1.6.0 singleton,
  allowing the second to enumerate one victim key and retrieve one inert
  message marker. Explicit 1.7.0 stores remain independent even with a
  colliding caller-selected `session_id`. Both branches clear their state in
  `finally`.

- Added `node-http-intlify-flat-json-prototype-pollution`, an exact
  provenance-, binding-, configuration-, operation-, and dataflow-aware
  CWE-1321 model for
  [GHSA-p2ph-7g93-hw3m / CVE-2025-27597](https://github.com/intlify/vue-i18n/security/advisories/GHSA-p2ph-7g93-hw3m).
  It follows HTTP data through relative wrappers into the public
  `@intlify/message-resolver.handleFlatJson` transformer, the explicit Intlify
  core browser bundles that export it, official `createI18n({ flatJson: true,
messages })` initialization, and `setLocaleMessage` or `mergeLocaleMessage`
  on a stable configured global object.
- Preserved the advisory's branch-specific ranges for all six package names:
  the Intlify core/resolver packages from 9.1.0 through 9.1.10; Vue I18n from
  9.1.0 below 9.14.3, 10.0.0-alpha.1 below 10.0.6, and 11.0.0-beta.0 below
  11.1.2; Vue I18n core from 9.2.0 across those upper branches; and Petite Vue
  I18n from 10.0.0 below 10.0.6 and 11.0.0-beta.0 below 11.1.2. Exact
  production declarations and fresh declaration-consistent npm v2/v3 locks
  are accepted; repaired or earlier prereleases, dev-only/wrong packages,
  unresolved ranges, stale/inconsistent/v1 locks, and root core imports that
  do not export the transformer are negative.
- Added source-identical Vue I18n 9.14.2/9.14.3 fixtures, a strict specialized
  manifest, canonical corpus registration, field-local validation guidance,
  and an adversarial regression matrix. Literal `flatJson: true`, exact remote
  message/setter position, stable official identity, and runtime provenance
  are mandatory. False/dynamic flags, spreads, duplicate keys, custom initial
  resolvers, fixed data, lookalikes, reassignment, replaced members, and
  tests/examples fail closed. The bounded real-package witness uses one inert
  unique prototype property in a disposable process and always removes it:
  9.14.2 creates the inherited value; 9.14.3 throws `unsafe key: __proto__` and
  leaves the prototype unchanged. The canonical corpus advances to 121
  exploit/control pairs, 242 cases, and 726 repeated scans.

### Reliability and platform hardening

- Added manual dispatch to the Node, Go, .NET, Java, and Windows GUI workflows,
  completing the recovery surface already present in the container and Linux
  GUI lanes. Every hosted acceptance family can now be rerun at an exact branch
  head when a local push credential suppresses workflow creation or GitHub
  fails before assigning a runner; automatic push and pull-request coverage is
  unchanged.
- Added a manual dispatch entry point to the hosted Linux GUI workflow so an
  operator can retry a zero-step GitHub-hosted runner allocation failure
  without changing scanner source or manufacturing an unrelated commit. The
  ordinary `push` and `pull_request` acceptance triggers remain unchanged.
- Made the Windows scan-local file backend compatible with hardened and
  sandboxed profile ancestors that permit traversal but deny directory
  attribute handles. Ancestor locks now request the minimum zero-access Win32
  metadata handle, retain every openable ancestor without delete sharing, and
  tolerate `ERROR_ACCESS_DENIED` only above the canonical scan root. The scan
  root and every accessible descendant remain locked and identity-checked;
  reparse points, changed roots, non-regular leaves, and unsafe replacements
  still fail closed.
- Added a Windows backend regression that asserts the minimal handle access and
  exercises verified read, atomic replacement, and exact-handle deletion. This
  also restores immutable-inventory finalization beneath restricted home
  directory ACLs instead of masking later recovery diagnostics with a generic
  unreadable-inventory error.

### Validation and distribution

- Exact implementation checkpoint
  `fa70abb387a42a137919710de194c642ce04237a` passes the hosted Windows Bun
  1.3.14 suite with 1,701 passes, 25 intentional skips, zero failures, and
  12,357 assertions across 188 files and 1,726 total tests in 469.17 seconds.
  The managed local aggregate passes 1,699 cases before denying a child Git
  metadata read and Windows credential-home ACL replacement; exactly those two
  permission-dependent tests pass with seven assertions under their required
  host permissions. The focused Windows and Ubuntu/WSL model, dataflow,
  framework, and canonical benchmark lane passes 41 tests and 2,037 assertions
  on each host, and both hosts reproduce the deployment-sensitive real-package
  15.5.15/15.5.16 boundary. Generated-model drift, formatting, TypeScript, the
  production build, and the high-severity production dependency audit are
  green.
- Two compiled inventories of an immutable archive of that checkpoint complete
  in 30,724.650 and 15,203.680 ms and are byte-identical at 256 rows, 535,547
  bytes, and SHA-256
  `259dc29da0cb09589f67c6fcd065cc0ec228daf218e4aef28a5e0ef2bbc344d7`.
  They retain 187 framework rows ahead of 69 lexical leads, with 238 fixture
  and 18 non-fixture paths. Exactly one CWE-288 Next.js row joins the line-4
  visible-path denial to the line-11 data access with exact 15.5.15 provenance;
  the 15.5.16 control is absent. A previous-archive comparison proves that the
  apparent one-row structured reduction removes only two late shell examples
  embedded in a scanner regression test at the unchanged 8 MiB input bound;
  no production row or model family is displaced.
- Two exact-source npm packages are byte-identical at 259 entries and 1,991,766
  bytes with SHA-256
  `a6a8de2e68daba3f3bc80c65ddc26609300ef5fbebcc11f9d4f3018d36ff055c`;
  strict inspection and two fresh installs validate the public SDK import,
  executable CLI, and all 79 bundled plugin files. Windows passes 7/7 core and
  3/3 shared tests, publishes a 346,796-byte executable, and survives hidden
  startup. Ubuntu/WSL passes 7/7 core, 3/3 shared, and 2/2 Linux GUI tests,
  publishes a 72,568-byte executable, and passes both non-graphical and Xvfb
  window startup. All seven exact-source hosted workflow families pass, and
  GitHub reports the repository public on default branch `main`.

- Exact implementation checkpoint
  `86a1ece2468cd236a42654587da8af6911bdffc8` passes the authoritative
  Windows Bun 1.3.14 suite with 1,694 passes, 25 intentional
  platform/environment skips, zero failures, and 12,309 assertions across 187
  files and 1,719 total tests in 568.82 seconds. The focused Windows and
  Ubuntu/WSL model, dataflow, and canonical benchmark lane passes 39 tests and
  2,010 assertions on each host. Both hosts also reproduce the bounded real
  1.6.0 cross-session read and the isolated 1.7.0 control.
- Two compiled inventories of a disposable Git archive of that exact
  checkpoint complete in 31,511.777 and 33,465.482 ms and are byte-identical
  at 256 rows, 535,196 bytes, and SHA-256
  `5307a1046e9db4777a6f898a52979c28849f42d6355ecff0c551b44cfca11f8a`.
  Structured-first selection retains all 188 framework rows ahead of 68
  lexical leads; 236 rows are fixture paths and 20 are not. Exactly one
  DeepSeek MCP row retains HTTP launch configuration at
  `src/launcher.mjs:1`, the vulnerable process-global store sink at line 3,
  CWE-639, and exact
  `@arikusi/deepseek-mcp-server@1.6.0:manifest-exact:process-global-session-store`
  provenance. The source-identical 1.7.0 control is absent.
- Generated-model drift, formatting, TypeScript, the production build, and the
  production advisory audit are green. Two exact-source npm packages are
  byte-identical at 259 entries and 1,956,583 bytes with SHA-256
  `5e40673df3b5281ea67bdcfe782a5d71a99b0611b017a5540e63fa38757786ea`;
  both isolated installs validate the public SDK import, executable CLI, and
  all 79 bundled plugin files. Windows GUI core/shared tests pass 7/7 and 3/3,
  its bounded hidden startup survives, and its 346,796-byte executable has
  SHA-256
  `6da28a6cc2fe55226e7e371e022cf4b6e15804a7aa70028a53e1dc6703243578`.
  Ubuntu/WSL passes 7/7 core, 3/3 shared, and 2/2 Linux GUI tests plus both
  startup modes; its 72,568-byte executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
  All seven exact-source workflow families pass: Node `32930320668`, container
  `32930320652`, Windows GUI `32930320688`, Linux GUI `32930320666`, Java
  `32930320663`, .NET `32930320631`, and Go `32930320632`. GitHub reports the
  repository public on default branch `main`.

- Exact implementation checkpoint
  `68df325d2ada7e688de5031918103c56599b2631` passes the post-build Windows Bun
  1.3.14 suite with 1,687 tests, 12,267 assertions, 25 intentional
  platform/environment skips, and zero failures across 186 files in 648.99
  seconds. The isolated recovery suite passes 83/83 tests and the new Windows
  backend test passes its real verified-read/atomic-write/delete round trip.
  The focused Ubuntu/WSL model, dataflow, and canonical benchmark lane passes
  40 tests and 2,005 assertions, and both hosts reproduce the bounded
  Vue I18n 9.14.2 prototype write and 9.14.3 rejection.
- Two compiled inventories of a disposable archive of that exact checkpoint
  complete in 28,020.143 and 14,915.281 ms and are byte-identical at 256 rows,
  533,915 bytes, and SHA-256
  `a4a6365664b5e41d08b3085bc12f2f0d5e862f56a57334af3a8531704d1e6237`.
  All 187 structured rows survive ahead of 69 lexical leads. Exactly one
  Intlify row retains request source `src/server.js:4`, transformer sink
  `src/i18n.js:4`, CWE-1321, nine ordered wrapper transitions, exact
  `vue-i18n@9.14.2:manifest-exact:create-i18n-messages` provenance, and the
  `flatJson:true` configuration proof; the source-identical 9.14.3 control is
  absent.
- Generated-model drift, formatting, TypeScript, the production build, and the
  production advisory audit are green. Strict inspection validates a
  259-entry, 1,950,207-byte npm archive at SHA-256
  `a19c0f4f1f4431ff5b00106098f97d30e555c0dc43a2b0d23fd7ddf31dd6d214`;
  two isolated installs validate the public SDK import, CLI, and all 79 bundled
  plugin files. Windows GUI core/shared tests pass 7/7 and 3/3, hidden startup
  survives, and its 346,796-byte executable has SHA-256
  `3586e31fd9ae7278db7d624b3dbc59faed4cbbf460a819ff889f99784dc9de7e`.
  Ubuntu/WSL passes 7/7 core, 3/3 shared, and 2/2 Linux GUI tests plus both
  startup modes; its 72,568-byte executable has SHA-256
  `7e29d642169a6c218c249216c6c10648307aea88faf636b69ac25741104b4adf`.
  All seven exact-source workflow families pass: Node `32928158512`, container
  `32928158506`, Windows GUI `32928158537`, Linux GUI `32928158521`, Java
  `32928158545`, .NET `32928158526`, and Go `32928158567`. The repository is
  public on default branch `main`, and all disposable acceptance artifacts are
  removed.

### Scanner effectiveness

- Added `node-http-rhinostone-swig-template-path-traversal`, an exact
  provenance-, renderer-, loader-configuration-, template-, and locals-flow
  aware CWE-22 model for
  [GHSA-2mf3-mr2r-r4vf](https://github.com/gina-io/swig/security/advisories/GHSA-2mf3-mr2r-r4vf).
  It follows HTTP data across relative wrappers into the exact unquoted
  variable used by `include`, `extends`, `import`, or `from` in the referenced
  trusted template, and requires that template to be rendered through an
  official Rhinostone Swig family `renderFile` surface with exact production
  dependency proof.
- Modeled the loader boundary instead of treating the repaired package version
  as sufficient evidence. A rooted loader remains eligible below 2.7.1; a
  loader without a configured root remains reviewable on repaired releases
  because the containment check has no root to enforce; and the documented
  `allowOutsideRoot` third argument remains reviewable because it explicitly
  restores outside-root resolution. A rooted 2.7.1+ default is negative. The
  model covers the Swig, Django, Jinja2, and Twig frontends; constructor and
  default instances; default, namespace, TypeScript import-equals, CommonJS,
  receiver-alias, and engine-alias forms; same-file and multi-hop flows; and
  template discovery for HTML and Twig files.
- Added source-identical `@rhinostone/swig` 2.7.0/2.7.2 fixtures, a strict
  specialized manifest, canonical corpus registration, model-specific field
  evidence, and review guidance. The bounded Windows witness reads only a
  fixture sentinel immediately outside the configured template root: 2.7.0
  renders it and 2.7.2 rejects the identical target. Literal or mismatched
  template targets, trusted locals, repaired rooted defaults, wrong or
  development-only packages, unresolved ranges, local lookalikes,
  reassignment, member replacement, and tests/examples remain negative.
  Current authenticated searches find no advisory or package-specific rule in
  `github/codeql` or `semgrep/semgrep-rules`. The canonical corpus advances to
  120 exploit/control pairs, 240 cases, and 720 repeated scans.
- Final Swig acceptance passes 1,678 native Windows tests with 25
  platform-specific skips, zero failures, and 12,216 assertions across 184
  files in 583.64 seconds. The post-hardening Ubuntu/WSL gate passes 26 focused
  tests and 1,919 assertions; its real-package witnesses reproduce the bounded
  outside-root read on 2.7.0 and the repaired rejection on 2.7.2. Formatting,
  generated-model/type consistency, and the production dependency audit are
  clean. A fresh 259-entry, 1,961,337-byte package at SHA-256
  `edd82139ae04e01c2568d3f04a3a4fc8261d1da8b90c771367bb3a3057baaa18`
  passes structural inspection and two isolated installed-runtime checks of
  the public SDK import, CLI, and all 79 bundled plugin files. Exact-commit
  self-scan and reproducible-package evidence follows after the implementation
  commit.
- Exact implementation checkpoint
  `71d194509e4a5d43a77e7ee4cd30e6aff26b82ee` is fully accepted. Two
  tracked-only archive self-inventories are byte-identical at 256 rows and
  531,422 bytes with SHA-256
  `c09a9722dc9baa81df1f6db0629fb41eaa24135e468dbe9be14d6b1d4294d5e5`;
  186 rows are structured and 70 lexical. Exactly one Swig row retains the
  source at `src/server.js:4`, sink at `src/renderer.js:9`, CWE-22, six ordered
  import/call/parameter transitions, exact
  `@rhinostone/swig@2.7.0:manifest-exact:affected-rooted` proof, and
  `include:partial` template proof. The 2.7.2 control remains absent. Two
  exact-source npm packages are byte-identical at 259 entries and 1,960,247
  bytes with SHA-256
  `6cb786344d40441f505fd22a23ded9c4cf4fd5e777afd6a16ee537a5fb0a6d49`;
  isolated inspection again validates the public SDK import, CLI, and all 79
  bundled plugin files. All seven hosted workflow families pass: Node
  `32921770724`, Windows GUI `32921770709`, Linux GUI `32921770745`, container
  `32921770710`, Go `32921770725`, .NET `32921770746`, and Java `32921770777`.
- Added `node-http-urllib-cross-origin-credential-leak`, an exact
  provenance-, API-, credential-, and redirect-lifecycle-aware CWE-201/CWE-522
  model for
  [GHSA-hq3h-g68c-hp78 / CVE-2026-55553](https://github.com/node-modules/urllib/security/advisories/GHSA-hq3h-g68c-hp78).
  It follows inbound credential data across relative wrappers into official
  named, aliased, default, namespace, TypeScript import-equals, CommonJS,
  direct-require, and `HttpClient` `request`/`curl` surfaces. Findings require
  exact affected production provenance through urllib 2.44.0 or from 3.0.0
  through 4.9.0, a standard `Authorization`, `Cookie`,
  `Proxy-Authorization`, `auth`, or `digestAuth` field, and redirect behavior
  that remains enabled.
- Extended official `HttpClient`/`HttpClient2` coverage through constructor
  `defaultArgs`, including aliases and separately declared client/default
  objects. The model follows inherited `auth` and `digestAuth`, models per-call
  override precedence for credentials and redirect/stream controls, and also
  follows inherited standard headers on urllib 2.x. It deliberately does not
  treat 3.x/4.x `defaultArgs.headers` as transmitted because those branches
  build request headers from the original per-call options, while inherited
  auth fields are applied after the options merge.
- Preserved branch-specific runtime semantics instead of treating every
  redirect option alike. On 3.x/4.x, `followRedirect: false`, nonpositive
  static limits, and active request/response streaming suppress the row; false
  or null stream options and nullish redirect limits preserve the default
  path. On 2.x, numeric zero and false are replaced by the default ten and
  remain vulnerable, while a negative or quoted-zero limit disables the
  redirect. Dynamic limits fail closed. Versions 2.44.1 and 4.9.1, prereleases,
  custom auth-like headers, fixed credentials, local lookalikes, reassignment,
  member replacement, wrong or development-only packages, unresolved ranges,
  inconsistent/v1 locks, tests, and examples remain negative.
- Added source-identical four-file urllib 4.9.0/4.9.1 fixtures, a perfect-gate
  specialized manifest, canonical corpus registration, strict field-evidence
  requirements, and reviewer guidance that separates demonstrated credential
  disclosure from SSRF, code execution, or privilege claims. Two ephemeral
  loopback listeners prove on both Windows and Ubuntu/WSL that 4.9.0 forwards
  the inert authorization token across the origin boundary and 4.9.1 follows
  the same redirect without it. The focused native gate passes 24 tests and
  1,904 assertions; Ubuntu/WSL passes the same 24 tests and 1,904 assertions,
  including constructor-default inheritance and override cases.
  The corpus advances to 119 exploit/control pairs, 238 cases, and 714 repeated
  scans. Current authenticated source searches found no advisory-specific
  rule in `github/codeql` or `semgrep/semgrep-rules`; their `urllib` matches are
  Python models rather than this Node package lifecycle.
- Raised the bounded temporal-memory native witness timeout from 10 to 30
  seconds after a loaded full-suite Windows run terminated the otherwise
  passing executable at 10.6 seconds. The enclosing test remains capped at 120
  seconds; isolated witnesses still finish in roughly two seconds, so hangs
  remain fail-closed while scheduler pressure no longer creates a false
  regression.
- Final native Windows acceptance passes 1,670 tests with 25 platform skips,
  zero failures, and 12,182 assertions across 183 files in 593.24 seconds.
  The production dependency audit reports no known vulnerabilities. The final
  pre-commit package checker validates the public import, CLI, and all 79
  bundled plugin files in a 259-entry, 1,952,415-byte tarball with SHA-256
  `6b409d913cbfc103ea78c4fb2ea20cf92be9ae2b97e572c8d4d8afeac6c09b31`.
- Independently rebuilt exact commit
  `300d045f3dd45345d74332bb48328e009e66af12` from `git archive`. Two full
  inventory passes are byte-identical: 256 rows and 532,009 bytes at SHA-256
  `bb2ca991eceb8a45558e24f08952104406a024df2de03e98f19ba3ef0a767171`,
  with 188 structured and 68 lexical rows. Exactly one urllib finding joins
  the benchmark request source to the affected 4.9.0 request through ten
  provenance/flow records; the 4.9.1 control remains absent.
- Two exact-commit package builds are byte-identical at 259 entries,
  1,951,255 bytes, and SHA-256
  `e56350e9e002164a58d6f5b0e2b5987f78774b855c3b632b8d37bee3d19fb470`;
  the isolated checker again validates the import, CLI, and 79 plugin files.
  The exact-commit tar differs from the Windows-checkout pre-commit tar only
  in CRLF/LF representation across 28 bundled text files: all 28 become equal
  after newline normalization, and the remaining 231 entries are byte-equal.
- All seven push workflows succeed for exact implementation commit `300d045`:
  `node-ci` 32917519608, `windows-gui-ci` 32917519603,
  `linux-gui-ci` 32917519605, `container-ci` 32917519803,
  `dotnet-fixture-ci` 32917519645, `java-fixture-ci` 32917519653, and
  `go-fixture-ci` 32917519711. The Node workflow covers its seven-job
  Windows/macOS/Ubuntu and Node 22/24/26 matrix through tests, formatting,
  build, package inspection, and runtime smoke tests.
- Added `node-http-kysely-mysql-ddl-sql-injection`, an exact provenance-,
  dialect-, argument-, and lifecycle-aware CWE-89 model for
  [GHSA-8cpq-38p9-67gx / CVE-2026-33468](https://github.com/kysely-org/kysely/security/advisories/GHSA-8cpq-38p9-67gx).
  It requires request data in argument two of an official three-argument
  `Kysely` `schema.createIndex(...).where(lhs, operator, value)` chain, a live
  official `MysqlDialect`, actual `compile()` or `execute()`, and exact
  affected production provenance through 0.28.13. Named and aliased ESM,
  namespace, TypeScript import-equals, CommonJS, and stable schema aliases are
  covered across same-file and three-relative-wrapper flows.
- Preserved the advisory-specific false-positive boundary. Kysely 0.28.14 and
  later, prereleases, non-MySQL or unresolved dialects, ordinary parameterized
  DML, fixed values, request data only in the left operand or operator, builder
  construction without compilation/execution, local lookalikes, reassigned
  instances or schema aliases, wrong or development-only packages,
  lockfile-free ranges, inconsistent or v1 locks, tests, and examples fail
  closed. Raw `sql.lit` and `sql.raw` are excluded because their documented
  unchecked-input contract is distinct from this versioned DDL compiler flaw.
- Added topology-identical four-file fixtures pinned to Kysely 0.28.13 and
  0.28.14, a perfect-gate specialized manifest, main-corpus registration, and
  a database-free real-package witness. The affected package compiles the
  bounded `\\' OR 1=1 --` value with one MySQL backslash before the quote; the
  repaired package emits two. The witness opens no connection or socket and
  changes no external state. The canonical corpus advances to 118
  exploit/control pairs, 236 cases, and 708 repeated scans.
- Current authenticated source searches found no `kysely`, advisory ID, or
  Kysely DDL literal match in `github/codeql` or `semgrep/semgrep-rules`.
  Focused native acceptance passes 24 tests and 1,893 assertions across the
  exact model and full corpus contract; the broader focused matrix passes 50
  tests and 2,003 assertions, and WSL passes 42 tests and 1,976 assertions.
  Full Windows regression passes 1,664 tests with 25 platform/integration
  skips, zero failures, and 12,151 assertions across 182 files. Both
  real-package witnesses, generated-model checks, TypeScript, formatting, the
  clean build, and the production dependency audit are green. The strict npm
  package check validates 259 entries, public import, CLI startup, and all 79
  bundled plugin files; the pre-commit tarball is 1,917,201 bytes with SHA-256
  `80f4f27922440dc6ff1b456cf3274e7ebca75e8c6b9d10f3bc21c471400aa241`.
- Final acceptance for the Kysely MySQL DDL model is green at exact
  implementation checkpoint `650cc29d61d5d2b94279613420dc01b48feb40c2`.
  Two compiled inventories of a disposable repository-root archive take
  17,223.331 and 16,026.728 milliseconds and produce 256 byte-identical rows,
  529,269 bytes, and SHA-256
  `d941e79efd02be37a1a1a15b73fcee6c03158a52ba63731c870b3ed4512d9d6b`.
  All 187 structured rows survive ahead of 69 lexical leads; 233 rows are in
  benchmark fixtures and 23 are not. Exactly one Kysely row retains the HTTP
  source at `src/server.js:4`, compilation sink at `src/storage.js:17`,
  CWE-89, nine ordered relative-wrapper transitions, exact
  `kysely@0.28.13` provenance, and the official MySQL dialect edge; the
  source-identical 0.28.14 control is absent. The exact-commit npm archive is
  byte-identical to the pre-commit package and passes the same strict install
  checks. All seven exact-source workflow families pass: Node `32911252669`,
  container `32911252735`, Windows GUI `32911252716`, Linux GUI `32911252767`,
  Java `32911252692`, .NET `32911252770`, and Go `32911252751`. The repository
  remains public on default branch `main`.
- Added `node-http-prompty-nunjucks-template-rce`, an exact provenance- and
  lifecycle-aware CWE-94/CWE-1336 model for request-controlled template grammar
  reaching Microsoft Prompty's official TypeScript Nunjucks renderer under
  [GHSA-w28w-gp39-m4p6 / CVE-2026-73299](https://github.com/microsoft/prompty/security/advisories/GHSA-w28w-gp39-m4p6).
  The model covers both the legacy line through 0.1.4 and the 2.0 preview line
  through 2.0.0-beta.4. It binds named, aliased, namespace, TypeScript
  import-equals, and CommonJS `@prompty/core` capabilities; follows stable
  constructor, module-member, and renderer-instance aliases; and recognizes
  both explicit `NunjucksRenderer.render(agent, template, inputs)` and the
  public `render`/`prepare`/`invoke` pipeline when the exact
  `Prompty.instructions` value is remote-controlled.
- Preserved the execution and repair boundaries. Dependency presence,
  construction without execution, trusted template literals with request data
  used only as render inputs, Mustache rendering, path-only `invoke` calls,
  local lookalikes, reassigned or replaced constructors/renderers/functions,
  development-only declarations, lockfile-free ranges, inconsistent or v1
  locks, malformed previews, tests, and examples fail closed. Exact 0.1.5 and
  2.0.0-beta.5-or-later releases are negative because the repaired Nunjucks
  path sanitizes inputs, performs own-data-only member lookup, rejects
  `__proto__`, `constructor`, and `prototype`, and prohibits template calls.
- Added topology-identical four-file Express fixtures pinned to
  `@prompty/core` 2.0.0-beta.4 and 2.0.0-beta.5, a perfect-gate specialized
  manifest, main-corpus registration, and a real-package non-shell witness.
  The affected package evaluates the bounded template
  `{{ range.constructor("return process.version")() }}` and returns only the
  local Node version; the repaired package rejects `constructor` access before
  invocation. The canonical corpus advances to 117 exploit/control pairs, 234
  cases, and 702 repeated scans.
- Current authenticated source searches found no `@prompty/core`,
  `NunjucksRenderer`, or GHSA-specific match in `github/codeql` or
  `semgrep/semgrep-rules`. Focused native Windows acceptance passes 42 tests
  and 1,952 assertions across the new model, adjacent LiquidJS lifecycle
  model, same-file and multi-hop framework lanes, and canonical corpus; exact
  TypeScript/generated-model checks are also green.
- Final local acceptance is green at immutable implementation revision
  `ad7d4933c97f325950c8426b7872d8aa4158b069`. After a clean production
  build, the authoritative native Windows Bun suite passes 1,658 tests and
  12,119 assertions across 181 files, with 25 intentional skips and zero
  failures in 615.00 seconds. The compact authoritative WSL lane passes 33
  tests and 1,920 assertions across four files in 6.00 seconds. Production
  dependency audit reports no known vulnerabilities.
- Two compiled inventories of a disposable repository-root archive take
  15,154.982 and 15,952.777 milliseconds and produce 256 byte-identical rows
  totaling 527,158 bytes with SHA-256
  `e9a34442f667f65efca97efbcbc5db9e42e8ccaa7c726f617c688723f82609e0`.
  All 186 structured records survive ahead of 70 lexical leads, with 232
  fixture and 24 non-fixture rows. Exactly one Prompty record retains source
  `src/server.js:8`, sink `src/renderer.js:6`, CWE-94/CWE-1336, nine ordered
  wrapper/import transitions, and exact beta.4 dependency provenance; the
  topology-identical beta.5 control is absent.
- Strict inspection validates a 259-entry, 1,909,482-byte npm archive with
  SHA-256
  `39a150979817b1833f0a3c8ef551ff3b4296e82b23101df1dee193d52d96d918`.
  Its isolated consumer installs 67 production packages and validates the
  public import, executable CLI, and all 79 bundled plugin files.
- All seven exact-source workflow families pass: Node `32906598888`, container
  `32906598804`, Windows GUI `32906598931`, Linux GUI `32906598895`, Go
  `32906598802`, Java `32906598811`, and .NET `32906599208`. GitHub reports the
  repository public on default branch `main`. The disposable exact-commit
  archive, npm archive, and isolated consumer are removed after acceptance.
- Added `python-web-datamodel-codegen-import-injection`, a version- and
  lifecycle-aware CWE-94/CWE-95 model for request-controlled OpenAPI or JSON
  Schema data reaching the official `datamodel_code_generator.generate` API
  under [GHSA-5578-w22f-pfx9 / CVE-2026-55415](https://github.com/advisories/GHSA-5578-w22f-pfx9).
  A finding requires one exact production pin in the affected
  `>=0.11.6,<=0.63.0` range, a live official generator binding, an exact
  schema argument, and actual execution of the generated Python: either the
  same `output=` path reaches official `runpy.run_path`, or the exact returned
  source reaches live built-in `exec`, optionally through live built-in
  `compile`. The sink is anchored at generated-module execution rather than
  generation alone.
- Preserved the fixed and lifecycle controls. Version 0.64.0 and later,
  versions below 0.11.6, ranges, prereleases, missing or duplicate pins,
  literal non-schema input types, local `datamodel_code_generator` or `runpy`
  shadows, replaced bindings or members, wrapper-parameter shadows, unrelated
  scopes, star expansion, fixed schemas, output-path mismatch or reassignment,
  output mode followed by `exec` of the generator's `None` return, generation
  without execution, execution without official generation, comments,
  strings, and lookalikes fail closed. Candidate discovery is derived from a
  complete generator-to-executor lifecycle, so dense unrelated `exec` calls
  cannot consume the 64-candidate budget.
- Added topology-identical Flask fixtures pinned to CPython 3.12.3 and
  `datamodel-code-generator` 0.63.0/0.64.0, a perfect-gate specialized
  manifest, main-corpus registration, and a bounded real-package witness. The
  affected release renders a newline-bearing `x-python-import` value through
  `Import.from_full_path` and `Imports.create_line`; `runpy.run_path` captures
  the harmless fixed `print(6 * 7)` output as 42. The repaired release raises
  `Error` during import-path validation before writing a module. The witness
  uses only an automatically removed temporary directory and in-memory
  standard-output capture—no command, network, credential, persistence, or
  destructive operation. Twelve evidence groups are independently mandatory
  in validation and attack path. The canonical corpus advances to 116
  exploit/control pairs, 232 cases, and 696 repeated scans.
- Authenticated searches of current `github/codeql` and
  `semgrep/semgrep-rules` source found no match for
  `datamodel-code-generator`, `datamodel_code_generator`, or
  `x-python-import`. Nine focused groups pass 46 assertions across the exact
  benchmark pair, import and executor aliases, file and returned-source
  lifecycles, built-in `compile`, same-file and two-relay flow, dense decoys,
  field-local evidence closure, prompt guidance, and a strict negative matrix.
- Final acceptance is green at immutable implementation revision
  `1d3303b6d21950da9f4cc4afd084a610736d284b`. After a clean production
  build, the authoritative native Windows Bun 1.3.14 suite passes 1,649 tests
  and 12,084 assertions across 180 files with 25 intentional platform or
  environment skips, zero failures, and a 582.04-second runtime. The focused
  native Ubuntu/WSL model, canonical corpus, Python cross-file and multi-hop,
  adjacent typed-model, framework-dataflow, and residual-risk lane passes all
  149 tests and 3,233 assertions. Generated-model drift, repository
  formatting, TypeScript compilation, the clean production build, and the
  production high-severity audit are green with no known vulnerabilities.
- Strict package inspection accepts the fresh 259-entry, 1,927,885-byte npm
  archive with SHA-256
  `c96a78e6d89706f7913fff6c94fbc47e3ca0ab3a550c07fe6322b29b7680f742`.
  Two isolated consumers each install 67 production packages and validate the
  public import, executable CLI, and all 79 bundled plugin files. Two
  inventories of a disposable exact-commit archive take 20,354.484 and
  15,859.490 milliseconds and produce 256 byte-identical rows totaling
  524,932 bytes with SHA-256
  `67eb897f367f435a929d24b3a6b624158da0cc8dbff1c44cabd81f57a661d8ba`;
  all 185 structured rows survive and exactly one is the new affected model.
  The real CPython 3.12.3 package differential records the bounded affected
  `42` output and repaired pre-write `Error` control.
- All seven exact-revision workflows pass: Node `32901920374`, container
  `32901920413`, Windows GUI `32901920388`, Linux GUI `32901920403`, Go
  `32901920467`, Java `32901920324`, and .NET `32901920370`. GitHub reports
  the repository public on default branch `main`. The disposable Windows and
  WSL witness environments, exact-commit archive, package archive, and
  isolated consumers were removed after acceptance.
- Added `python-web-statemachine-unsafe-scxml-eval`, a version- and
  lifecycle-aware CWE-95 model for request-controlled SCXML reaching the
  official `statemachine.io.scxml.processor.SCXMLProcessor`. Under the
  GHSA-v4jc-pm6r-3vj8 / CVE-2026-47103 affected range
  `python-statemachine>=3.0.0,<3.2.0`, a finding requires one exact production
  pin, construction of an official processor, `parse_scxml` receiving the
  remote document, and a later `start()` on the same live receiver. The row is
  anchored at `start()`, where initial-state entry actually invokes the
  datamodel callback, rather than at parsing alone.
- Preserved the repaired and deliberate opt-in boundaries. Version 3.2.0 or
  later with the default or explicit `trusted=False` is negative because its
  restricted AST evaluator rejects calls, builtins, dunder/private access,
  comprehensions, and script execution. An explicit literal
  `SCXMLProcessor(trusted=True)` or positional `True` remains reportable for a
  remote document because the package intentionally restores full Python
  `eval`/`exec` in that mode. Stable versions below 3.0, ranges, prereleases,
  missing or duplicate pins, unofficial package re-exports, local
  `statemachine.py` or `statemachine/` shadows, replaced bindings or
  parse/start members, receiver reassignment, cross-function receiver
  confusion, parse-only and wrong-receiver lifecycles, star expansion, fixed
  documents, and text lookalikes fail closed.
- Added topology-identical Flask fixtures pinned to CPython 3.12.3 and
  `python-statemachine` 3.1.2/3.2.0, a perfect-gate specialized manifest, and
  a bounded arithmetic witness. The affected package lets an SCXML `<data
expr>` resolve `__import__` and ask `builtins.eval` to evaluate only `6 * 7`,
  producing 42. The repaired default raises `InvalidDefinition` for that
  capability probe while ordinary `6 * 7` still produces 42. No command,
  file, network, credential, persistence, or destructive operation is used.
  Eleven evidence groups are independently mandatory in validation and attack
  path, and the canonical corpus advances to 115 exploit/control pairs, 230
  cases, and 690 repeated scans.
- Authenticated searches of current `github/codeql` and
  `semgrep/semgrep-rules` source found no match for the advisory, CVE, package,
  `SCXMLProcessor`, or `parse_scxml_file`. Official 3.1.2 and 3.2.0 package
  execution confirms the affected callback chain and the repaired evaluator
  boundary. Nine focused groups currently pass 44 assertions with one
  intentional Windows symlink skip across exact imports, parenthesized and
  one-hop aliases, affected defaults, repaired trusted opt-in, same-file and
  multi-hop flow, dense unrelated `start()` calls, field-local evidence
  closure, regular-file dependency provenance, and the strict negative matrix.
  The full Python model lane passes 127 tests and 683 assertions with four
  intentional Windows symlink skips.
- Final local acceptance is green at immutable implementation revision
  `002d3e8ca02abd4f69c867178897fa0c427fbd82`. After a clean production
  build, the authoritative native Windows Bun 1.3.14 suite passes 1,640 tests
  and 12,026 assertions across 179 files with 25 intentional environment or
  platform skips, zero failures, and a 609.22-second runtime. The focused
  Ubuntu/WSL StateMachine, canonical corpus, Python cross-file and multi-hop,
  framework-dataflow, residual-risk, and Copilot adapter lane passes 152 tests
  and 3,241 assertions with one Windows-launcher skip and zero failures.
  Generated-model drift, formatting, TypeScript compilation, and a clean
  production build pass. The production high-severity audit reports no known
  vulnerabilities.
- Strict package inspection accepts the fresh 259-entry npm archive at
  SHA-256
  `c8a44308d1b6b5b1ae0da14890caafed060d6c4dbae7b07c5fc87f67e95c98a4`.
  Two clean consumers each install 67 production packages and validate the
  public import, executable CLI, and all 79 bundled plugin files. The real
  CPython 3.12.3 package witness confirms that 3.1.2 reaches the bounded
  capability sentinel and returns 42 while 3.2.0 raises `InvalidDefinition`
  for that probe and still evaluates ordinary arithmetic to 42.
- Two inventories of an exact-commit repository-root archive are
  byte-identical at 256 rows and 522,460 bytes, SHA-256
  `45b76fd78ad6549c7922004e23baa6245833a8ef930abfc94912ab2cbf422766`,
  in 35,578.623 and 15,733.205 milliseconds. Exactly one StateMachine row
  identifies the affected fixture at `src/loader.py:9`; the restricted control
  and production scanner source emit no StateMachine row. Two independent
  inventories of the publishable SDK archive are also identical at 256 rows
  and 242,315 bytes, SHA-256
  `7b951f07c7b8026fbe102c9a14d5f486efb5e11f6dc01b2d9ac8873c3965174f`.
  A focused compiled inventory independently returns one affected row and zero
  control rows.
- Sealed campaign
  `af4b3aaf2e0f06f4ff29c755de057f66f2cbf67c20181a3635593e010d204486`
  binds the implementation revision, manifest SHA-256
  `3cd8e442450b25e25798f4a6b640e9c123a049239cd79e335cf89699b1194dc3`,
  exact fixture hashes, corpus, comparison and scan policies, runner, scanner
  CLI, and packaged scanner to stored GitHub authentication,
  `gpt-5.6-terra`, high effort, deep mode, two workers, three bounded outer
  attempts, and no artificial credit ceiling. Both cases complete on attempt
  one with complete coverage. The affected case emits exactly one high CWE-95
  finding in 4m50s; the 3.2.0 restricted-evaluator control emits zero findings
  in 5m00s. Completion, precision, recall, F1, case and negative-case pass,
  stability, validation, attack path, code evidence, and severity are all 1.0,
  with zero false positives per run. A finalize-only replay reproduces the
  same campaign and sealed evaluation without invoking Copilot.
- The two live scans use 2,349,968 input, 2,085,019 cached, and 52,329 output
  tokens at an estimated $2.133760375. The host re-anchors two code-evidence
  excerpts from immutable repository bytes before sealing the positive
  finding; no model, process, or campaign retry occurs. Bounded campaign output
  contains no allowance, quota, credit-limit, rate-limit, classifier-refusal,
  reconnect, timeout, transport, authentication, or authorization failure.
- All seven hosted workflow families pass on acceptance head
  `41ee1c37c95e4fc7065e453e7aa1736ab0d54552`: Node `32897953405`,
  container `32898015237`, Windows GUI `32897953447`, Linux GUI
  `32897953455`, Go `32897953391`, Java `32897953314`, and .NET
  `32897953426`. The container workflow was dispatched explicitly because its
  push path filter correctly excludes a documentation-only acceptance commit;
  its recorded head is the same exact revision. GitHub reports the repository
  public on default branch `main`.
- Added `python-web-sympy-unsafe-parse-expr`, a primitive-wide CWE-94/CWE-95
  model for request-controlled strings reaching the official
  `sympy.parsing.sympy_parser.parse_expr` evaluator without a provably
  restricted namespace. It resolves module, parser-module, direct, aliased,
  parenthesized, function-local, and one-hop callable-alias bindings; preserves
  same-file, one-wrapper, and two-relay flows; records the exact expression
  argument and intrinsic `stringify_expr -> compile -> eval_expr -> eval`
  chain; and extends the same-file trace to 64 lines within the containing
  function so realistic validation and normalization do not hide the source.
- Kept the model fail closed at identity, namespace, and flow boundaries.
  Repository-local `sympy.py` or `sympy/` shadows, import/member replacement,
  wrapper-parameter and cross-function shadows, star expansion, fixed strings,
  comments, and lookalikes do not emit. `evaluate=False`, regex or AST checks,
  length limits, exception handling, authentication, `global_dict=None`, and
  an empty global dictionary without an explicit empty `__builtins__` mapping
  are not misclassified as sandboxes. The negative boundary requires an
  application-owned `{"__builtins__": {}}` global dictionary plus a literal
  local allowlist made only from reviewed mathematical SymPy identifiers;
  dynamic, request-controlled, or capability-bearing namespaces remain
  reviewable findings.
- Added topology-matched Flask fixtures pinned to Python 3.12.3 and SymPy
  1.14.0, a perfect-gate specialized manifest, and a bounded arithmetic
  witness. The affected default namespace resolves `__import__` and evaluates
  only the fixed expression `6 * 7` to 42. The control raises `NameError` for
  the same capability probe while ordinary `6 * 7` still returns 42. The
  witness launches no shell, touches no file or credential, opens no network
  connection, persists nothing, and performs no destructive action. Ten
  independent evidence groups are mandatory in both validation and attack
  path, and four forbidden claims prevent simplification-mode, universal-call,
  shell-witness, and deployment-proof overstatement. The canonical corpus now
  contains 114 exploit/control pairs, 228 cases, and 684 repeated scans.
- Tested the generalized primitive against the exact upstream application that
  motivated it. Official Qwed tag `v5.1.1` at
  `edb0c90b16df9afefd8795e2707c126ab92858d9` emits one exact same-file row from
  `request.get("expression")` at `src/qwed_new/api/main.py:463` through its
  cosmetic normalization to `parse_expr` at line 504. Current repaired Qwed
  7.1.0 at `4f0f4f05f2998889aed386e34f6a14e469d1ef2d` emits zero SymPy rows. This
  upstream differential exposed and closed the old 12-line same-file tracing
  limit without widening other typed-sink models. Authenticated searches of
  current public CodeQL and Semgrep rule source found no `parse_expr` model.
  The disposable upstream clone and WSL witness environment were removed after
  verification.
- Twelve focused SymPy groups plus the canonical corpus lane pass 30 tests and
  1,874 assertions on Windows. The wider Python typed-model, cross-file,
  multi-hop, and residual-inventory lane passes 184 tests with five intentional
  Windows-only skips. The separate elevated native transport lane passes all
  39 tests and 179 assertions, including creation and verification of the
  private `copilot-security-home` ACL. Generated-model drift and TypeScript
  compilation are clean.
- Final local acceptance is green at implementation revision
  `ada24aab2760bffdc205cf56f04f97f006acd73b`. After a clean production build,
  the authoritative native Windows suite passes 1,632 tests and 11,971
  assertions across 178 files with 24 intentional environment/platform skips,
  zero failures, and a 569.09-second runtime. The focused Ubuntu/WSL SymPy,
  Python cross-file, Python multi-hop, canonical benchmark, and Copilot adapter
  lane passes 74 tests and 2,115 assertions with one Windows-launcher skip and
  zero failures. Generated-model drift, formatting, TypeScript checking, and
  the clean build pass. The production high-severity audit reports no known
  vulnerabilities.
- Strict package inspection accepts the fresh 259-entry npm archive. Two clean
  install-smoke passes each add 67 production packages and validate the public
  import, executable CLI, and all 79 bundled plugin files. The isolated package
  and exact-commit self-review directories were verified beneath the system
  temporary root and removed after evidence capture.
- Sealed campaign
  `fa8711193f1444f805040af9d0c5c251f8c541bb1f8b8636007dda3a9a786148`
  binds implementation revision
  `ada24aab2760bffdc205cf56f04f97f006acd73b`, manifest SHA-256
  `f972cae431bfef9d71b8d779e8a39e9aab7badbf46bb76f964de9d242e93c3f2`,
  exact fixture hashes, comparison policy, runner, scanner CLI, and packaged
  scanner to stored GitHub authentication, `gpt-5.6-terra`, high effort, deep
  mode, two workers, three bounded outer attempts, and no artificial credit
  ceiling. Both cases complete on attempt one with complete coverage. The
  affected case emits exactly one high CWE-94/CWE-95 finding in 4m59s; the
  restricted-namespace control emits zero findings in 10m44s. Completion,
  precision, recall, F1, case and negative-case pass, stability, validation,
  attack path, code evidence, and severity are all 1.0, with zero false
  positives per run. A finalize-only replay reproduces the same campaign and
  sealed evaluation without invoking Copilot.
- The two live scans use 3,840,923 input, 3,437,207 cached, and 84,412 output
  tokens at an estimated $3.386957375. The host re-anchors two excerpts and
  aligns two endpoint roles from immutable repository bytes before sealing the
  positive finding; no model or process retry occurs. Bounded campaign output
  contains no allowance, quota, credit-limit, rate-limit, classifier-refusal,
  reconnect, timeout, transport, authentication, or authorization failure.
  Two whole-repository inventories of the exact implementation archive are
  byte-identical at 256 rows and 523,955 bytes, SHA-256
  `c3be5ffc4d4cc86f0da64d856cfff373826df6107e89e44191cbc684e69f3e0a`.
  Exactly one row identifies the affected SymPy fixture at `src/parser.py:7`;
  the restricted control and production scanner source emit no SymPy row.
- All seven hosted workflow families pass on the same implementation revision:
  Node `32885914255`, container `32885914187`, Windows GUI `32885914173`,
  Linux GUI `32885914194`, Go `32885914170`, Java `32885914172`, and .NET
  `32885914287`. GitHub reports the repository public on default branch `main`.
- Added `python-web-hydra-unsafe-instantiate`, a version-aware CWE-94/CWE-470
  model for remote Hydra object-instantiation configuration under
  GHSA-2cp2-2r3c-7p7r / CVE-2026-68508. It resolves the official
  `hydra.utils.instantiate` and `call` APIs through module, utility, direct,
  aliased, parenthesized, and one-hop callable-alias bindings; preserves
  same-file, one-wrapper, and two-relay request flows; and requires one nearest
  exact production `hydra-core<=1.3.3` pin. Each row records the official
  binding, exact config or `_target_` edge, dependency proof, dynamic dotpath
  resolution, and configured callable invocation.
- Kept the model fail closed at its identity and version boundaries. Stable
  1.3.4 or later, ranges, development versions, duplicate or missing pins,
  symlinked requirements, local `hydra.py` or `hydra/` shadows, import/member
  replacement, wrapper-parameter shadowing, cross-function callable aliases,
  fixed application-owned targets, wrong keyword roles, star expansion, and
  string/comment lookalikes do not emit. Candidate discovery begins with the
  proven Hydra binding, so dense unrelated `.instantiate()` calls cannot
  consume the bounded sink budget. The shared Python expression resolver now
  retains bounded multiline dictionary, list, tuple, and call assignments;
  a regression-discovered scalar-alias overread is prevented by limiting a
  non-container opening parenthesis to the assignment's first line.
- Added topology-identical Flask fixtures pinned to Python 3.12.3 and
  `hydra-core` 1.3.3/1.3.4, plus a perfect-gate specialized manifest. Their
  bounded, non-shell witness supplies `builtins.eval` only the fixed arithmetic
  expression `6 * 7`: 1.3.3 returns 42, while 1.3.4 raises
  `InstantiationException` before invocation. The witness performs no network,
  filesystem write, process mutation, persistence, or credential access. Ten
  independent evidence groups are mandatory in both validation and attack
  path, and four forbidden claims prevent package-presence, ordinary-data,
  complete-boundary, and deployment-proof overstatement. The canonical corpus
  now contains 113 exploit/control pairs, 226 cases, and 678 repeated scans.
- Compared the increment with the reviewed GitHub advisory, Hydra's official
  instantiate documentation, the 1.3.4 release and target blocklist, and the
  1.4 trusted call-site `_target_whitelist` upgrade guidance. The 1.3.4
  blocklist is retained as the exact advisory control but not represented as a
  complete security boundary. Authenticated searches found no corresponding
  `hydra.utils.instantiate` model in the current public CodeQL or Semgrep rule
  repositories, so this scanner adds exact call identity, affected dependency
  proof, cross-file source flow, executable paired evidence, and field-local
  report closure rather than a package or call-name heuristic.
- Twelve focused Hydra groups and the corpus lane pass 30 tests and 1,865
  assertions on both Windows and Ubuntu/WSL; Linux executes the real symlink
  provenance rejection. The complete Python model lane passes 107 tests and
  591 assertions with four intentional Windows-only skips. The authoritative
  native Windows suite passes 1,620 tests and 11,912 assertions across 177
  files with 24 intentional environment/platform skips, zero failures, and a
  658.21-second runtime. Formatting, generated-model drift, TypeScript
  compilation, the clean production build, and the high-severity production
  audit pass with no known vulnerabilities. Strict package inspection accepts
  a fresh 259-entry, 1,903,475-byte archive with SHA-256
  `a13dc2cb004a1d92831544b9dff133129aaa5397b0a0679949be3527ed995a66`;
  two isolated installs each add 67 packages and validate public import, CLI
  behavior, and all 79 bundled plugin files. The unique package staging
  directory was removed after evidence capture.
- Sealed live campaign
  `ca24307ff087c589f2ae9142f3db6550c8d56389f249e7244328840e14cc5035`
  binds implementation revision
  `587d096a1afa1030c2f3a7611aab3d7f2b5e9591`, the exact specialized
  manifest and fixtures, comparison policy, runner, scanner CLI, packaged
  scanner, stored GitHub authentication, `gpt-5.6-terra`, high effort, deep
  mode, and two workers with no artificial credit ceiling. Both cases complete
  on attempt one with complete coverage. The 1.3.3 case emits exactly one high
  CWE-94/CWE-470 finding in 9m56s; the 1.3.4 control emits zero findings in
  4m19s. Completion, precision, recall, F1, case and negative-case pass,
  stability, validation, attack path, code evidence, and severity are all 1.0,
  with zero false positives per run. A finalize-only replay verifies the same
  sealed receipts without a model call.
- The two campaign scans use 3,929,339 input, 3,553,238 cached, and 69,000
  output tokens at an estimated $3.098068875. The host re-anchors one excerpt
  and aligns one endpoint role from repository bytes before sealing the
  positive finding; no model retry is needed. Bounded logs contain no
  allowance, quota, credit-limit, rate-limit, classifier-refusal, reconnect,
  timeout, transport, authentication, or authorization failure. Exact-commit
  deterministic self-review is byte-for-byte stable across two runs at 256
  rows and 522,247 bytes, SHA-256
  `a35433dedad30d4d8f921180e16e98995f420a0766a907092a7b31bf59979609`.
  Its only Hydra row is the intentional 1.3.3 fixture; the 1.3.4 control and
  production scanner code emit none.
- Raised the Windows-capable Node workflow test-step deadline from 10 to 15
  minutes after the exact implementation workflow killed the otherwise-green
  1,620-test Windows lane at the old deadline. The measured authoritative local
  run is 10m58s, while all Linux and macOS matrix jobs completed successfully;
  the wider bound preserves the same commands and assertions instead of
  splitting or weakening the suite.
- All seven hosted workflow families pass on correction revision
  `0681f170a20552898bb8472833741fe265ad3c6d`: Node `32880004422`, manually
  dispatched exact-head container `32881145835`, Windows GUI `32880004311`,
  Linux GUI `32880004337`, Go `32880004335`, Java `32880004317`, and .NET
  `32880004338`. The corrected Windows Node test completes in 8m39s and its
  complete job in 11m33s, including build, package inspection, and installed-
  runtime smoke. The earlier 10-minute cancellation remains visible as the
  trigger for the bounded operational fix.
- Added `python-web-tarfile-unsafe-extraction`, a Python-standard-library
  CWE-22 model for remote tar archive extraction outside the intended
  destination. It resolves live `tarfile.open` and `TarFile` bindings across
  module, aliased, direct, and bounded parenthesized imports; binds only the
  `fileobj` input of a readable archive to the exact retained `TarFile`
  receiver; and requires a later `extract` or `extractall` operation. Same-file,
  one-wrapper, and two-relay request flows retain explicit binding, open,
  runtime, filter, extraction, and intrinsic member-path-write provenance.
- Made omitted-filter semantics runtime exact. One nearest regular
  `.python-version` or `runtime.txt` must contain one stable `X.Y.Z` pin.
  Omitted or `None` filters are unsafe below Python 3.14 and suppressed at
  3.14 or later; literal or official `fully_trusted` filters remain findings
  on supported Python 3.12+ releases. Literal `data` or `tar`, official
  `data_filter` or `tar_filter`, and exact safe instance or class
  `extraction_filter` assignments are negative controls. Missing, ranged,
  malformed, duplicate, shadowed, symlinked, or ambiguous evidence fails
  closed, as do write modes, filename-only input, fixed streams, destination-
  only request flow, star expansion, binding replacement, receiver
  reassignment, unrelated scopes, local package shadows, and text lookalikes.
- Added topology-matched Flask unsafe/default and hardened `filter="data"`
  fixtures with a perfect-gate specialized benchmark. Their bounded witness creates one
  in-memory tar member named `../escaped-marker.txt`, operates only in a new
  temporary directory, and uses neither network nor shell. Under Python
  3.12.3 in Ubuntu/WSL, the unsafe default writes the fixture marker outside
  the selected destination; the data-filter control raises
  `OutsideDestinationError` and writes nothing. The control also enforces 32
  members, 1 MiB per member, 2 MiB total expanded data, regular file/directory
  types, and unique case-folded names before extraction. The canonical corpus now
  contains 112 exploit/control pairs, 224 cases, and 672 repeated scans.
- Added fourteen tarfile regression groups covering all accepted binding and
  receiver forms, `extract` and `extractall`, multiline and positional
  `fileobj` calls, one-hop aliases, two relative relays, the Python 3.14
  default transition, nearest runtime boundaries, literal and official
  filters, instance and class overrides, dense candidate decoys, shadows,
  reassignment, wrong argument roles, and ten independent evidence groups in
  both validation and attack path. The focused Windows lane passes 31 tests
  and 1,866 assertions with one intentional POSIX-only skip; Ubuntu/WSL
  passes all 32 tests and 1,867 assertions. A test-discovered exact-value
  parser defect is fixed: quoted `mode=` and `filter=` values are now compared
  before structural string erasure.
- Compared the model against Python's 3.12 and current `tarfile` documentation
  and CodeQL's medium-precision `py/tarslip` query guidance. The scanner adds
  exact remote `fileobj` flow, official receiver identity, runtime/default and
  override semantics, cross-file propagation, executable matched evidence,
  and field-local report closure instead of treating archive extraction or a
  path spelling alone as a verdict.
- Final local acceptance is green. The authoritative native Windows suite
  passes 1,608 tests and 11,852 assertions across 176 files with 24 intentional
  environment/platform skips, zero failures, and a 687.10-second runtime.
  Formatting, generated-model drift, TypeScript compilation, the clean build,
  and the high-severity production audit pass with no known vulnerabilities.
  Strict inspection validates a fresh 259-entry, 1,897,637-byte package with
  SHA-256
  `86e91e9e606beca7f844c8dd973c3be0eb690b7a7218e76c2035447f76a809f3`;
  an isolated install adds 67 packages and validates public import, CLI
  behavior, and all 79 bundled plugin files. The unique package staging
  directory is removed after evidence capture.
- The first sealed live campaign correctly reported the expected traversal in
  the unsafe fixture, but also found a distinct high CWE-409/CWE-400
  decompression/resource-exhaustion flaw in the initial data-filter control.
  That control limited only compressed request bytes while `r:*` and
  `extractall` left expanded bytes, member count, individual size, and
  extraction work unbounded. The result is retained as valid scanner evidence;
  the benchmark was hardened rather than suppressing the finding or weakening
  its zero-false-positive gate.
- Fresh sealed campaign
  `730a523dd61c335277874beb75a7de4ce1d28ccfa068f8574cd858ef4645aea3`
  binds hardened source revision
  `c80e03d993bcddf5f6f4d61ef0a33fa767420af7`, the exact manifest, fixtures,
  comparison policy, scanner CLI, and packaged scanner to `gpt-5.6-terra`,
  high effort, deep mode, and stored GitHub authentication. Both scans
  completed on attempt one with complete coverage. The positive emitted the
  one expected high CWE-22 finding in 4m31s; the hardened control emitted zero
  findings in 4m05s. Completion, precision, recall, F1, case and negative-case
  pass, stability, validation, attack path, code evidence, and severity are
  all 1.0, with zero false positives per run. The two scans used 1,565,351
  input, 1,315,410 cached, and 44,868 output tokens at an estimated
  $1.782881875. A finalize-only replay reproduced the same campaign and
  receipts without a model call. No retry, authentication, allowance, quota,
  credit, rate-limit, classifier-refusal, reconnect, timeout, or transport
  event occurred.
- Deterministic self-review of the hardened revision is byte-for-byte stable:
  two runs each emit 256 rows and 520,096 bytes with SHA-256
  `2a888db147a5bfd36064081b7c510dba5e8d3f9cc120262fa526d9fa5ec05c91`.
  Exactly one tarfile row identifies the positive benchmark; the hardened
  control and production scanner code emit none. All seven hosted workflows
  pass for the same source revision: Node `32870741290`, container
  `32870741422`, Windows GUI `32870741382`, Linux GUI `32870741347`, Go
  `32870741387`, Java `32870741376`, and .NET `32870741453`.
- Added `python-web-lxml-etcompat-xxe`, a version-aware CWE-611 model that
  completes the second parser surface in CVE-2026-41066/GHSA-vfmq-68hx-4jfw.
  It resolves live official `ETCompatXMLParser` and `XMLTreeBuilder`
  constructors plus `XML`, `fromstring`, `fromstringlist`, and `parse` calls
  across module, receiver, direct, aliased, and bounded parenthesized imports.
  A finding requires request-controlled XML, an exact constructed
  ET-compatible parser supplied in parser argument one or `parser=`, and
  either literal `resolve_entities=True` or the affected omitted default under
  one nearest exact `lxml<6.1.0` `requirements.txt` pin. Ordinary
  `XMLParser`, parser construction without use, patched or unproved defaults,
  safe or dynamic modes, positional constructor arguments, unrelated
  function scopes, local lookalikes, package shadows, reassignment, wrong-role
  input, and star expansion fail closed.
- Added source-identical Flask `lxml==6.0.2` and `lxml==6.1.1` ET-compatible
  parser fixtures and a perfect-gate specialized benchmark. On Python 3.12.3
  under Linux/WSL, the affected fixture returns
  `fixture-local-etcompat-marker` through its local `file:` `SYSTEM` entity;
  the patched control raises `XMLSyntaxError` and returns no marker. The
  witness uses no network or shell and reads no non-fixture path. The canonical
  corpus now contains 111 exploit/control pairs, 222 cases, and 666 repeated
  scans.
- Added seventeen ET-compatible parser regression groups covering every
  supported constructor and parse binding, positional and keyword parser use,
  multiline construction, explicit and version-derived modes, nearest
  dependency boundaries, one-hop and two-relay aliases, function-scope
  isolation, dense-call candidate budgets, import invalidation, shadows,
  lookalikes, wrong argument roles, and ten independent semantic evidence
  groups in both validation and attack path. A test-discovered expression
  resolver defect that let an identifier-only assignment absorb a later call
  is closed, and the existing `iterparse` wrapper-summary discovery now also
  derives candidates from exact imports instead of spellings.
- Compared the new model with the official advisory and lxml 6.0.2/6.1.0
  `parser.pxi` implementations. Those primary sources prove that
  `ETCompatXMLParser` and its `XMLTreeBuilder` alias retained the external-
  entity default until 6.1.0, independently of the earlier ordinary
  `XMLParser` default change. Public CodeQL Python XXE guidance establishes
  the generic category but does not encode this ET-compatible version/API
  split. The scanner adds exact constructor-to-parser-use flow, bounded alias
  resolution, dependency scope, executable paired evidence, and field-local
  report closure.
- Final local acceptance is green. Focused Windows tests pass 34 tests and
  1,852 assertions with one intentional POSIX-only skip; Ubuntu/WSL passes all
  35 tests and 1,853 assertions. The authoritative unrestricted Windows suite
  passes 1,595 tests and 11,779 assertions across 175 files with 23 intentional
  environment/platform skips, zero failures, and a 605.80-second runtime.
  Formatting, generated-model drift, TypeScript compilation, the clean build,
  and the high-severity production audit pass. Strict inspection validates a
  fresh 259-entry, 1,885,663-byte package with SHA-256
  `c0b1c28853fb39fad842127d72f93bba3d0860f82bc037c4793bd49f915983ea`;
  an isolated install adds 67 packages and validates public import, CLI
  behavior, and all 79 bundled plugin files. The unique package probe and
  fixture bytecode are removed after evidence capture.
- Sealed live campaign
  `eda3157f75440e149292731e2556daacae111b6a562304103c0ac354d808605e`
  binds the specialized manifest and fixture hashes, scanner CLI/package
  hashes, comparison policy, and source revision
  `787e83e4ce736d1bc378ea2f242d1247a8532570` to `gpt-5.6-terra`, high
  effort, deep mode, and stored GitHub authentication. The patched 6.1.1
  control succeeds on attempt one in 450,022 ms with zero findings and
  complete coverage, using 1,482,200 input/1,295,684 cached/33,064 output
  tokens at $1.398251 recorded cost. The affected 6.0.2 case rejects its first
  draft because one finding-quality and four coverage gaps remain after the
  bounded correction turn, then succeeds in a fresh attempt in 424,429 ms
  with one high CWE-611 finding and complete coverage. Host recovery
  re-anchors two code excerpts from repository bytes; the accepted run uses
  1,628,180 input/1,493,089 cached/37,373 output tokens at $1.355991 recorded
  cost. Accepted runs total 3,110,380 input, 2,788,773 cached, and 70,437
  output tokens at $2.754242; the rejected attempt did not emit usage or cost,
  so it is not included in that accounting. All twelve strict metrics pass at
  1.0 except the required zero false positives per run, and finalize-only
  replay verifies the sealed receipts and artifact hashes without another
  model call. The sole retry is deterministic content-closure recovery; logs
  contain no authentication, session, timeout, quota, credit-limit, or
  classifier-refusal error. All seven implementation-source workflow families
  pass: Node `32861983964`, container `32861983978`, Windows GUI `32861984047`,
  Linux GUI `32861983983`, Java `32861984084`, .NET `32861983998`, and Go
  `32861983986`. GitHub reports the repository public on default branch `main`.
- Added `python-web-lxml-iterparse-xxe`, a version-aware request-to-parser
  model for CWE-611 and CVE-2026-41066/GHSA-vfmq-68hx-4jfw. It resolves live
  official `lxml.etree.iterparse` module, receiver, direct, aliased, and
  parenthesized imports; requires request control of argument zero or
  `source=`; and requires actual iterator consumption through inline
  iteration or eager `list`/`tuple` materialization. It emits for explicit
  `resolve_entities=True` on any otherwise proven runtime, or for an omitted
  mode under one exact nearest `lxml<6.1.0` `requirements.txt` pin. The 6.1.0
  patched default, safe explicit modes, unpinned or ranged version guesses,
  duplicate or out-of-boundary pins, unconsumed iterators, wrong-role or fixed
  sources, star expansion, dynamic flags, local package shadows, reassignment,
  and text lookalikes remain negative.
- Added source-identical Flask `lxml==6.0.2` and `lxml==6.1.1` fixtures and a
  strict specialized benchmark. On Python 3.12.3 under Linux/WSL, the affected
  fixture eagerly consumes `iterparse` and discloses only its fixture-local
  marker, while the patched control raises `XMLSyntaxError` without returning
  the marker. No witness accesses the network, launches a shell, or reads a
  non-fixture file. The canonical corpus now contains 110 exploit/control
  pairs, 220 cases, and 660 repeated scans.
- Added thirteen lxml regression groups covering every accepted binding form,
  positional and keyword sources, explicit and version-derived modes, the
  exact 6.1 boundary, iterator-consumption closure, two-relay flow, dependency
  scope and symlink rejection, import invalidation, wrong-role and safe-mode
  controls, and ten independent semantic evidence groups in both validation
  and attack-path fields. A dense 80-call decoy regression also proves that an
  arbitrary direct alias remains discoverable after the bounded candidate
  budget. The focused Windows lane passes 30 tests and 1,839 assertions with
  one intentional POSIX-only skip; Ubuntu/WSL passes all 31 tests and 1,840
  assertions. The authoritative unrestricted Windows suite passes 1,579 tests
  and 11,709 assertions across 174 files with 22 intentional
  environment/platform skips, zero failures, and a 574.46-second runtime.
- Compared the model with current primary sources. The lxml advisory records
  the affected default and the 6.1.0 change to `resolve_entities='internal'`;
  current lxml API documentation preserves the distinction between entity
  resolution and `no_network`; and CodeQL's high-precision Python XXE guidance
  establishes the CWE-611 category. The scanner adds exact application flow,
  iterator execution, dependency-bound version semantics, executable paired
  evidence, and field-local report closure rather than treating package
  presence or an import as a vulnerability.
- Formatting, generated-model drift, TypeScript compilation, the clean
  production build, and the production dependency audit pass. A
  fresh 259-entry, 1,877,025-byte package with SHA-256
  `4e80e19605bfa573f4fb7ad3a81ad7a83bee40c71056ff97680693e3d74d0afd`
  passes strict archive inspection, a fresh 67-package isolated install,
  public import, CLI behavior, and all 79 bundled plugin-file checks. The
  unique package probe is removed after recording this acceptance evidence.
- The sealed first-attempt live campaign
  `8242ce452acbd49b49edfa0ffa791877a66612140ed5132ef105d6136805cef6`
  binds the strict lxml pair to source revision
  `09c4a7747b78afb349e305c96524d40899ae5c9e`, the exact scanner and manifest
  hashes, `gpt-5.6-terra`, high effort, deep mode, and stored GitHub
  authentication. The affected 6.0.2 case completes in 367,891 ms with one
  high finding, complete coverage, 1,013,919 input/894,470 cached/25,485
  output tokens, and $0.979140625 recorded cost. The source-identical 6.1.1
  control completes in 416,696 ms with zero findings, complete coverage,
  1,667,768 input/1,451,493 cached/38,488 output tokens, and $1.615667
  recorded cost. All twelve strict metrics are 1.0 except the required zero
  false positives per run, and finalize-only replay re-verifies every sealed
  receipt and artifact hash. Neither case retries, times out, nor reports an
  authentication, session, quota, credit-limit, or classifier-refusal error.
  All seven exact-source workflow families pass: Node `32857049691`, container
  `32857049575`, Windows GUI `32857049629`, Linux GUI `32857049673`, Java
  `32857049666`, .NET `32857049597`, and Go `32857049641`. The repository
  remains public on default branch `main`.
- Added `python-web-torch-unsafe-load`, a typed request-to-PyTorch checkpoint
  model for CWE-502. It resolves only live official `torch.load` receiver or
  named bindings, the artifact in argument zero or `f=`, and bounded relative
  wrappers. It emits only for explicit `weights_only=False`, a custom
  `pickle_module` without an explicit safe mode, an omitted flag under an exact
  pre-2.6 `requirements.txt` pin, or `weights_only=True` under an exact version
  affected by GHSA-63cw-57p8-fm3p. Modern unpinned defaults, patched explicit
  weights-only loads, exact pre-1.13 pins whose runtime does not implement the
  keyword, dynamic modes, wrong-role or fixed inputs, star expansion,
  `torch.save`, local shadows, reassignment, and text lookalikes remain
  negative.
- Added bounded, symlink-rejecting nearest Python `requirements.txt` snapshots
  for exact package provenance without admitting dependency files into lexical
  risk discovery. Ambiguous duplicate pins, ranges, nested boundary files, and
  missing versions fail closed rather than being interpreted as advisory
  evidence.
- Added a topology-identical Flask checkpoint pair and strict benchmark. The
  official `torch==2.13.0+cpu` witness on Python 3.12.3 proves that the positive
  explicit full unpickler invokes only fixture-local `effects.mark`, while
  changing only to `weights_only=True` raises `UnpicklingError` with the marker
  unset. Ten focused groups cover aliases, `f=`, all four unsafe modes, exact
  version boundaries, same-file and two-relay flow, import invalidation,
  negative controls, and independent validation/attack-path closure. The
  canonical corpus now contains 109 exploit/control pairs, 218 cases, and 654
  repeated scans.
- The authoritative native Windows suite with the PyTorch model passes 1,566
  tests and 11,634 assertions across 173 files, with 20 intentional
  environment/platform skips and zero failures in 630.41 seconds. After that
  aggregate, the final manifest-coherence, requirements-symlink, and exact
  1.12.1/1.13.0 API-boundary assertions pass in a 29-test native Windows gate
  with one intentional symlink skip and 1,827 assertions; WSL passes all 30
  tests and 1,828 assertions.
- Generated-model drift, formatting, TypeScript, the clean production build,
  and the high-severity production advisory audit are clean. A fresh 259-entry,
  1,871,846-byte package with SHA-256
  `d70cbc3a29d38896813a06de8bd7fbfdcf8dbd57c32f5a1d97690c3f7948f754`
  passed two isolated 67-package installs, public import, CLI, and all 79
  bundled-plugin file checks; its unique temporary directory was removed.
- Compared the extension with current primary sources. PyTorch documents that
  `torch.load` uses an unpickler and must not consume untrusted data, while its
  security policy prefers Safetensors for untrusted models. The current
  weights-only advisory affects releases through 2.9.1 and is repaired in
  2.10.0. CodeQL supplies a high-precision generic Python unsafe-deserialization
  query, and Semgrep's community repository still tracks broader ML-loader
  coverage as an open request. This model adds exact application reachability,
  binding invalidation, version-gated modes, executable control evidence, and
  field-local report closure rather than claiming that the primitive is
  unknown elsewhere.
- Ran the sealed PyTorch exploit/control campaign against the pushed
  `f321ba4d8cc18cad99bbb5407ba48973cdad9043` revision with authenticated
  Copilot CLI, `gpt-5.6-terra`, high effort, deep mode, two workers, and up to
  three fresh attempts. Both cases completed on attempt one: the vulnerable
  fixture produced one accepted high-severity finding, the patched
  weights-only control produced none, and all strict completion, precision,
  recall, F1, case, stability, validation, attack-path, code-evidence, and
  severity metrics equal 1 with zero false positives or negatives. Campaign
  `8282e25aefbd054e06d1e3a9b598b7329a824396ab8c1bd6b146cb2465709bfd`
  also exercised successful repository-byte excerpt re-anchoring and observed
  no allowance-exhaustion or classifier-refusal event.
- Closed hosted verification for the same source checkpoint. `node-ci` run
  `32849767656` passes Ubuntu Node 22, 24, 24.0.0, 26, and 26.0.0, Windows
  Node 22, and macOS Node 22, including full tests, formatting, build, package
  inspection, and installed-runtime smoke checks. Container run `32849767711`,
  Go fixture run `32849767649`, Java fixture run `32849767685`, .NET fixture
  run `32849767754`, Windows GUI run `32849767653`, and Linux GUI run
  `32849767689` also pass.
- Added `python-web-joblib-unsafe-load`, a typed Python request-to-Joblib
  deserialization model for CWE-502. It accepts only a live non-shadowed
  `import joblib` receiver or named `from joblib import load` binding and
  request control of argument zero or `filename=` across bounded relative
  wrappers. Fixed and wrong-role values, star expansion, `joblib.dump`, local
  module/package shadows, reassigned imports or members, and text lookalikes
  remain negative.
- Added a bounded Flask model-upload/JSON control pair, fixture-local
  `__reduce__` marker witness, and strict specialized benchmark. Both fixtures
  preserve the route, upload stream, `parse_model` wrapper, byte budget,
  dependency pin, runtime contract, witness, and malicious Joblib artifact;
  only `joblib.load` versus `json.load` differs at the trust boundary. The
  canonical corpus now contains 108 exploit/control pairs, 216 cases, and 648
  repeated scans.
- Executed the pinned witness on Python 3.14.5/Windows and Python 3.12.3/Linux,
  both with Joblib 1.5.3. Each positive invokes the harmless in-process marker;
  each JSON control rejects the same serialized bytes with the marker unset.
  Windows and WSL focused regression lanes each pass 46 tests and 1,939
  assertions with no failures.
- Two independent inventories of the positive fixture are byte-identical and
  emit one CWE-502 row from `src/server.py:11` to `src/parser.py:13`, with the
  relative import/call/parameter chain, exact Joblib binding, and intrinsic
  pickle-callable boundary retained as five propagators. The JSON control emits
  no Joblib row.
- Compared the model against current primary scanner sources. CodeQL now has a
  first-party `JoblibLoadCall` decoder model for argument zero or `filename`.
  Trail of Bits' public Semgrep rule excludes only literal-string calls, while
  Semgrep's broader ML-loader rule is still an open proposal. This scanner adds
  request-to-sink reachability, relative-wrapper evidence, exact import
  invalidation, local-shadow rejection, field-scoped correction requirements,
  and an executable false-positive control rather than claiming a library-level
  detection gap.
- Diagnostic campaign
  `cd3b48aa3cb7e22e00bbbcd5df46872375dbbb45dec69160abe4ea7f9773052a`
  on immutable checkpoint `9a2da9d307802f6d19a553562cf33cdaa6073321`
  authenticated from stored Copilot credentials with no account, allowance,
  quota, rate-limit, classifier, authentication, or transport failure. The
  JSON control completed on attempt one with zero findings. The positive's
  first draft failed closed on one finding-quality and five coverage gaps; its
  automatic retry produced one high CWE-502 finding with complete structural
  coverage. Precision, recall, F1, stability, validation, attack-path,
  code-evidence, severity, and negative-control rates were all 1.0 with zero
  false positives or false negatives.
- Kept that campaign diagnostic at a 0.5 case-pass rate because both validation
  and attack path omitted seven required Joblib fact groups despite retaining
  the correct source, sink, wrapper path, and finding. The missing facts were
  the `parse_model` wrapper, argument-zero/file-object role, pickle-backed
  protocol, observed `effects.mark` process effect, both tested Python
  versions, and Joblib 1.5.3. The report also incorrectly described the review
  as static-only even though the fixture contains bounded executable evidence.
- Added deterministic host-side, model-specific report closure. The finding
  quality re-audit now correlates a draft finding with the exact modeled Joblib
  sink from the host residual-risk inventory and independently requires all ten
  semantic evidence groups in validation and attack path. Its JSONL diagnostic
  returns the exact missing alternative groups to bounded correction; facts in
  another field cannot substitute, and fixture runtime evidence cannot be
  promoted to a deployment claim. Re-auditing the sealed failed finding
  reproduces its exact seven omitted groups in each field.
- Campaign
  `89c2822204217f3696237b32d9995e0aa5a4d2a5fc767f9248c2d640ff9d8de3`
  deliberately remains diagnostic: source revision
  `9ff3f627dae5f45e9637dcfb4e108af192ce3233` was checked out, but the live CLI
  receipt retained the prior package hash
  `d9d55f901ce580e7aaba2e9bee2880e9c0e4c49fbecc4ad92ac8a353f54fbab0`
  because `dist` had not been rebuilt after the source-only checkpoint. Its
  positive and control still detected correctly, but the stale executable
  omitted five Joblib evidence groups and failed acceptance. Running the
  current source directly against that sealed finding reproduced the exact
  five validation and attack-path gaps, identifying build provenance rather
  than correlation logic as the integration fault.
- Rebuilt campaign
  `b039e5ea8188ef83e17d38a9c12014106643b78fe93afcf31411f25af0778d95`
  is bound to the same revision and new package hash
  `d184bad8d187cb873f21bf6bc5e949515e06d856e146111f47347a17c85c70da`.
  Both deep scans authenticated from stored Copilot credentials and completed
  on attempt one with no account, allowance, quota, rate-limit, classifier,
  authentication, or transport failure. The positive emitted one high CWE-502
  finding with every required fact in both fields; the JSON control emitted no
  findings. All completion, precision, recall, F1, case-pass, negative-pass,
  stability, validation, attack-path, code-evidence, and severity metrics are
  1.0 with zero false positives and zero false negatives. Total estimated cost
  was $1.540957375.
- The benchmark runner now fails before campaign creation when local TypeScript
  source is newer than, or lacks, its compiled JavaScript counterpart. This
  bounds the source walk, rejects symbolic links, and gives an exact build
  command, preventing a source revision from being paired with stale ignored
  `dist` bytes in future live evidence.
- The widened Windows provenance, recovery, Joblib, residual-risk, and Copilot
  orchestration lane passes 135 tests and 1,396 assertions with one intentional
  symlink skip. The WSL Joblib, closure, campaign-provenance, residual-risk, and
  Copilot lanes also pass; the freshness check takes 0.58 seconds on the
  Windows-mounted source tree. A separate extended diagnostic completed all
  five nested runner-recovery cases under WSL, where process startup across
  `/mnt/c` exceeds that Windows-calibrated test's 25-second child timeout.
  Production scanner and campaign deadlines are unchanged.
- The authoritative native Windows suite on the committed provenance checkpoint
  passes 1,556 tests and 11,574 assertions across 172 files, with 20 intentional
  environment/platform skips and zero failures in 622.05 seconds.
- Added `python-web-numpy-allow-pickle-load`, a typed Python web-to-NumPy
  object-array deserialization model for CWE-502. It requires an exact live
  `import numpy` receiver or named `from numpy import load` binding, request
  control of the file argument, and literal `allow_pickle=True`. It follows
  bounded relative wrappers while rejecting the safe default,
  `allow_pickle=False`, dynamic flags, fixed and wrong-role values, star
  expansion, reassignment, member replacement, repository-local NumPy shadows,
  and text lookalikes.
- Added a topology-identical Flask upload pair and strict benchmark. Its
  object-dtype `.npy` witness on Python 3.14.5 and NumPy 2.5.2 invokes only a
  fixture-local in-memory marker with `allow_pickle=True`; the otherwise
  identical `allow_pickle=False` control raises `ValueError` and leaves the
  marker unset. Direct, named, parenthesized, positional, keyword, cross-file,
  two-relay, invalidated-binding, wrong-role, and false-control regressions are
  covered. The canonical corpus advances to 107 exploit/control pairs, 214
  cases, and 642 repeated scans.
- The NumPy correction gate requires exact Python and NumPy versions, a
  complete object-dtype `.npy` payload, the explicit flag, wrapper chain,
  unpickling and bounded callable effect in both validation and attack-path
  evidence. It rejects numeric-only arrays, lazy `.npz` archives that are never
  indexed, package/import presence, `numpy.save`, default loading, and the
  fail-closed control as execution evidence.
- First live campaign
  `72a1864d3d72d579948eed8d48341991d81fb7154491e2b21b2e5788db661e80`
  authenticated from stored Copilot credentials and completed both deep scans
  on attempt one with no allowance, quota, rate-limit, classifier,
  authentication, or transport error. The positive produced one critical
  CWE-502 finding with complete coverage and the exact upload-to-NumPy path.
  The negative produced no deserialization finding, but correctly found a
  separate medium CWE-400: the original pair had no request, decoded-byte,
  shape, element-count, or work bound. That is a valid benchmark-confounder,
  not a scanner false positive. Evaluation of the positive was additionally
  invalidated when its expected line moved during the still-running campaign;
  results from this campaign are retained only as diagnostic evidence.
- Hardened both NumPy fixtures identically with Flask's complete-request limit
  plus independent stream-byte, header-size, format-version, rank, element
  count, and dtype checks before `numpy.load`. The only parser difference
  remains literal `allow_pickle=True` versus `False`; the bounded object-array
  witness still executes only in the positive.
- Diagnostic campaign
  `277c69851f7961baeea043f1aa5f8280571a46b9ecf2ba5cc617bf55a5dccc86`
  on immutable checkpoint `86ac235fb4e6965c74f0225fedf8e9b7f8a545a5`
  confirmed the corrected topology. Both deep scans completed on attempt one
  with stored Copilot credentials and no provider failure. The positive
  produced one critical CWE-502 finding with complete coverage; the bounded
  `allow_pickle=False` control produced zero findings with complete coverage.
  Precision, recall, F1, stability, validation, attack-path, code-evidence,
  severity, and negative-control rates were all 1.0, with no false positive or
  false negative. Acceptance remained intentionally failed at a 0.5 case-pass
  rate because validation omitted the exact tested Python and NumPy versions,
  while attack-path prose omitted `parse_array`, explicit `numpy.load`, and
  `__reduce__`/callable dispatch even though the underlying finding retained
  the correct source, sink, and effect.
- Added a source-identical `RUNTIME.md` contract for both NumPy cases recording
  the executable witness matrix: Python 3.12.3 on Linux and Python 3.14.5 on
  Windows, both with NumPy 2.5.2. Correction guidance distinguishes that
  fixture evidence from deployment proof. Validation and attack path must now
  each independently preserve the exact runtime matrix and full upload →
  `parse_array` → `numpy.load(..., allow_pickle=True)` → object-dtype `.npy` →
  `__reduce__` callable → process-effect chain. Evidence elsewhere in a report
  cannot satisfy an omitted field-local step.
- Campaign
  `f0abd2474ae3c4b0e8ccea770a44a70d55ca70335710b716f7056877c5aef173`
  on checkpoint `689033c4112c1edcb9b2272077c3d63fcdb26933` again
  completed both deep scans on attempt one with stored Copilot credentials and
  no account, allowance, quota, rate-limit, classifier, authentication, or
  transport failure. The positive produced one high CWE-502 finding with
  complete coverage in 6m16s; the control produced zero findings with complete
  coverage in 5m21s. The total estimated cost was $2.97711025. Every structural
  and classification metric was 1.0 with zero false positives or false
  negatives. Its report contained all ten required facts in validation and
  attack path, but the literal evaluator rejected the exact alias `np.load`,
  the concrete in-process `src.effects.mark` effect, and coordinated version
  wording such as “Python 3.12.3 and 3.14.5.”
- Corrected the NumPy semantic alternatives without weakening any required
  fact. `np.load` is now equivalent to its proven `numpy.load` binding;
  `effects.mark` or an observable harmless effect is equivalent to the generic
  process-effect label; and both exact Python numbers may be expressed in one
  coordinated phrase. Re-evaluating the immutable findings with receipt
  enforcement intentionally disabled passes every threshold, proving the
  change repairs evaluator spelling rather than scanner output. A new
  receipt-bound campaign remains required for final live acceptance.
- Receipt-bound campaign
  `108ea03d172a173cc913229c4fcb18bcf44b7bc655cb75e7f22b4adaea38c04e`
  on checkpoint `13e1f85ab710ac405107b7416d13748b266e6fec` passes every
  threshold. Both deep scans completed on attempt one with stored Copilot
  credentials and no account, credit, allowance, quota, rate-limit,
  classifier, authentication, or transport failure. The unsafe case produced
  one high CWE-502 finding with complete coverage in 6m06s; the bounded
  `allow_pickle=False` control produced zero findings with complete coverage
  in 4m41s. Precision, recall, F1, case pass, negative-case pass, stability,
  validation, attack path, code evidence, severity, and completion are all
  1.0, false positives per run are zero, and total estimated cost is
  $3.581733125. Fresh receipts bind the exact revision, manifest hash, scanner
  package, and both fixture digests.
- Final NumPy acceptance is green. The authoritative native Windows suite on
  documentation head `b094cacab7d4053e2acfcf9fdbd575f5de364d1d` passes
  1,546 tests and 11,512 assertions across 171 files in 570.55 seconds, with 20
  intentional platform/environment skips and zero failures. A managed-sandbox
  diagnostic was stopped after it denied Windows ACL hardening and immutable
  workbench inventory access; the unchanged unrestricted rerun passes those
  exact lanes and the complete suite. Generated models, formatting,
  TypeScript, production build, and the high-severity production audit are
  clean with no known vulnerabilities.
- Two inventories of an immutable whole-repository Git archive are
  byte-identical at 256 rows and 587,921 bytes, SHA-256
  `03c42368bd3e38d5d5ec3aecb2e8775207b62541e8826882abd82cd176c14b63`.
  Exactly one NumPy row survives the global cap: request source
  `benchmarks/fixtures/python-numpy-allow-pickle/src/server.py:11`, sink
  `src/parser.py:31`, CWE-502, and the six relative-wrapper, binding, explicit
  opt-in, and intrinsic-unpickling propagators. The false control emits no row.
- Windows and WSL packages each contain 259 entries and pass strict tar
  inspection, two isolated installations, public import, CLI, and all 79
  bundled plugin files. The Windows archive installs 67 packages and is
  1,861,671 bytes with SHA-256
  `a508b62fd01810239ef4db2190014d58bd634b665990513a9ffbd8781b94d1df`;
  the WSL archive installs 75 packages and is 1,837,653 bytes with SHA-256
  `a5643a3519f7546f2514cf4786eb4449f898ee5408b77e066aac7c479fb83f06`.
- All seven implementation-checkpoint workflows pass: Node `32835367417`,
  container `32835367422`, Windows GUI `32835367470`, Linux GUI `32835367468`,
  Java `32835367432`, .NET `32835367421`, and Go `32835367413`. The six
  workflows selected for documentation head `b094cac` also pass: Node
  `32836047715`, Windows GUI `32836047667`, Linux GUI `32836047689`, Java
  `32836047713`, .NET `32836047683`, and Go `32836047704`.
- Live campaign
  `c6fb9c92bed2214f45681dde76518cbc72c2c65850dc1e673b33e16247e494f3`
  on checkpoint `4cb88e175bb0d06a8ebc400579b54b623f8ba2e4` completed both
  deep scans on attempt one with stored Copilot credentials and no allowance,
  quota, rate-limit, classifier, authentication, or transport failure. The
  unsafe case produced one critical CWE-502 finding with complete coverage;
  the JSON control produced zero findings with complete coverage. Precision,
  recall, F1, stability, validation, attack-path, code-evidence, severity, and
  negative-control metrics were all 1.0 with zero false positives or false
  negatives. Its sole failed threshold was field-scoped semantics: validation
  used the exact Python spelling `request.stream`, while the attack path named
  `decoder.load()` and pickle loading but omitted the preceding `Unpickler`
  constructor. The semantic gate now accepts `request.stream` as equivalent to
  “request stream,” while correction guidance requires validation and attack
  path to each retain request/file source, constructor argument, instance, and
  later dispatch. The constructor requirement remains strict.
- Corrected campaign
  `4516f838395104dcd4452b6ed47875a9a77b53d6c447304b661d51575038ca62`
  on checkpoint `49e3126299409e85fefee3ea7a6f0b2b4013afb7` passes every
  threshold. Both deep scans again completed on attempt one with no account,
  allowance, quota, rate-limit, classifier, authentication, or transport
  failure. The unsafe case produced one critical CWE-502 finding with complete
  coverage in 5m15s; its attack path now explicitly preserves
  `request.stream` → `pickle.Unpickler(document)` → retained decoder →
  zero-argument `decoder.load()` → `GLOBAL`/`REDUCE` callable execution. The
  JSON control produced zero findings with complete coverage in 3m53s. Every
  metric is 1.0, with zero false positives or false negatives and a total
  estimated cost of $2.988318375. Deterministic finalization safely re-anchored
  one code-evidence excerpt from repository bytes before sealing the positive.
- Preserved exact framework sink-kind diversity at the 256-record
  whole-repository ceiling. Selection now reserves one ranked record for every
  distinct framework-model ID and sink kind before repeated rows can consume
  the remaining capacity. A 261-file saturation regression proves that both
  `pickle.loads` and the later-ranked `pickle.Unpickler(...).load()` flow remain
  available to the model while the inventory stays bounded at 256 rows.
- Corrected the self-scan acceptance procedure to archive and scan from the Git
  repository root. The earlier replay archive was unintentionally rooted at
  `sdk/typescript`, so it correctly contained no executable Python fixture and
  could not establish a pickle-family false negative. The whole-repository
  replay now includes the real exploit/control corpus and retains both exact
  pickle sink kinds at the hard inventory limit.
- The focused native WSL lane passes 97 tests and 2,874 assertions. The
  authoritative Windows lane passes 1,538 tests and 11,444 assertions across
  170 files with 20 intentional platform/environment skips, zero failures, and
  a 610.64-second runtime. Formatting, generated-model drift, TypeScript, and
  the clean production build remain green after the global selector change.
- Extended `python-web-pickle-unsafe-load` across the standard-library
  `pickle.Unpickler(file).load()` boundary. The host now links request control
  at constructor argument zero to a later zero-argument `load()` on the same
  non-reassigned instance, including named/receiver imports and bounded local
  aliases. It records separate binding, constructor-file, instance-alias,
  dispatch, and intrinsic-execution evidence. Inert construction, fixed input,
  wrong argument roles, import/constructor/instance/member replacement, local
  module shadows, and unproved or restrictive subclasses remain negative.
- Added a Flask request-stream `Unpickler`/JSON pair, a bounded in-memory
  callable witness, a strict specialized manifest, and adversarial direct,
  assigned, aliased, invalidated, inert, and restrictive-subclass regressions.
  The correction gate now requires the model to preserve constructor file,
  retained instance or aliases, and later load dispatch instead of collapsing
  construction into execution. The canonical corpus advances to 106
  exploit/control pairs, 212 cases, and 636 repeated scans.
- The final focused Windows and WSL lanes each pass 30 tests and 1,817
  assertions. On both Python 3.14.5 and Python 3.12.3 the positive invokes only
  the fixture-local in-memory marker and returns its dictionary, while JSON
  rejects the same protocol-4 bytes and leaves the marker unset. The
  authoritative native Windows suite passes 1,537 tests and 11,442 assertions
  across 170 files with 20 intentional platform/environment skips, zero
  failures, and a 560.78-second runtime. An initial managed-sandbox diagnostic
  denied Git, Windows ACL, PDF-worker, and immutable-inventory operations; the
  unchanged authorized run closes all 78 environmental failures. Formatting,
  generated-model drift, TypeScript, and the clean production build pass.
- Added `python-web-pickle-unsafe-load`, a typed Python web-to-standard-library
  pickle model for CWE-502. It requires an exact live `import pickle` receiver
  or named `from pickle import load/loads` binding, traces only argument zero,
  and follows the existing bounded relative-wrapper graph. It rejects local
  module shadows, receiver/function reassignment, member replacement, wrapper
  parameter shadowing, keyword-only and star-expanded inputs, fixed data,
  `dumps`, safe lookalikes, and comments or strings. Direct, named, aliased,
  parenthesized, file-stream, cross-file, and two-relay paths are covered.
- The pickle correction gate now requires exact remote-byte provenance and the
  standard-library binding, explains intrinsic callable execution through
  `GLOBAL`/`STACK_GLOBAL` and `REDUCE`, and preserves a source-to-process attack
  path. Post-load authentication or validation, discarded results,
  `try`/`except`, encoding, and compression are not execution barriers. A
  secret-keyed integrity check over the exact bytes before unpickling is strong
  counterevidence; a checksum, embedded key, or verification after loading is
  not. Stronger filesystem, network, credential, persistence, or privilege
  claims still require their own evidence.
- Added a topology-identical Flask `pickle.loads`/`json.loads` fixture pair, a
  strict specialized manifest, and eight adversarial regression groups with 42
  assertions. The source-identical witness serializes only a fixture-local
  harmless callable whose single effect is an in-memory marker: pickle invokes
  it before returning, while JSON rejects the same bytes and leaves the marker
  unset. The witness passes on Windows Python 3.14.5 and WSL Python 3.12.3 and
  performs no shell, network, listener, or file-write action. The pair advances
  the canonical corpus to 105 exploit/control pairs, 210 cases, and 630
  repeated scans. The initial widened Windows lane passes 119 tests and 3,008
  assertions with one intentional platform skip; the same WSL lane passes all
  120 tests and 3,009 assertions. The authoritative Windows suite passes 1,533
  tests and 11,394 assertions across 170 files, with 20 intentional
  environment/platform skips and zero failures in 557.46 seconds.
- Final acceptance for the pickle model is green. Formatting,
  generated-model drift, TypeScript, the clean production build, and
  `pnpm audit --prod --audit-level high` pass with no known vulnerabilities.
  Two compiled self-inventories take 15,935.037 and 16,578.093 ms and produce
  256 byte-identical rows totaling 584,985 bytes with SHA-256
  `7dfae52dc7383b76711fef3fc73ca1003a0124e81538e95095224d9322786684`.
  They retain the new cross-file pickle row with five exact propagators and the
  older same-file pickle fixture, while both JSON controls and production
  source remain clean. Strict Windows and WSL inspection validates the same
  259-entry, 1,854,553-byte npm archive with SHA-256
  `a9a6d81172126a26d9efaf9ab484b4927a16759b4180dbe8e78c03d33e4f5fbf`;
  two isolated installs on each host validate the public import, executable
  CLI, and all 79 bundled plugin files. The temporary archive is removed.
- Live campaign
  `e4f0eec1b0a9a517324f4f6235835e8fea903dfcf32171a99fdef4e8d2794fba`
  against implementation checkpoint
  `61854de9f33175f71c649223baf296202bb7ae57` completed both deep scans on
  attempt one with no authentication, allowance, quota, rate-limit,
  classifier, or transport failure. The unsafe case produced one source-backed
  high CWE-502 finding with complete coverage in 5m19s; the source-identical
  JSON control produced zero findings with complete coverage in 2m41s. Total
  estimated cost was $2.115233875. Precision, recall, F1, completion,
  case/negative pass, stable detection, validation, attack-path, code-evidence,
  and severity gates are all 1.0, with zero false positives or false negatives.
  Initial evaluation exposed a benchmark spelling defect: the sealed
  validation repeatedly said `standard-library`, while its alternatives
  accepted only the equivalent unhyphenated phrase. Both specialized and
  canonical gates now accept either exact spelling, and a regression preserves
  that semantic equivalence; re-evaluation of the immutable receipts passes
  every gate without another model call.
- Added `python-web-pyyaml-unsafe-load`, a typed Python web-to-PyYAML
  deserialization model for CWE-502. It requires an exact `import yaml`
  receiver or named `from yaml import` binding, accepts ordinary and
  parenthesized aliases, traces only the `stream`/argument-zero value, and
  follows the existing bounded relative-wrapper graph. Reportable host rows are
  limited to explicit `unsafe_load` or `load` with `Loader`, `UnsafeLoader`,
  `CLoader`, or `CUnsafeLoader`. `safe_load`, `SafeLoader`, `CSafeLoader`,
  `full_load`, `FullLoader`, missing or dynamic loaders, fixed YAML, request data
  in another argument, reassignment, member replacement, local import shadows,
  comments, strings, and unrelated nested `yaml` modules remain negative. The
  correction pass treats the exact non-shadowed PyYAML-specific API and remote
  stream as source-backed CWE-502 object/state integrity evidence even when
  deployment metadata is outside the sealed scope. Runtime-module and
  constructor uncertainty remain explicit validation limitations, and stronger
  execution, filesystem, network, credential, or availability impact requires
  a bounded non-destructive constructor/gadget witness; the host row alone
  never becomes an automatic remote-code-execution claim.
- Added a topology-identical Flask `UnsafeLoader`/`safe_load` fixture pair, a
  strict semantic specialized manifest, and adversarial regression coverage for
  module/named aliases, positional and keyword stream and loader roles,
  multiline imports, safe/full/unproved loaders, fixed and unrelated inputs,
  shadowing, reassignment, member replacement, and presentation-only text. The
  source-identical Python witness uses only the harmless `!!python/tuple` tag:
  PyYAML 6.0.1 with `UnsafeLoader` constructs a tuple, while `safe_load` rejects
  the same bytes with `ConstructorError`; neither path starts a listener, makes
  a network request, invokes a shell, or writes a file. The initial focused lane
  passes eight tests and 53 assertions, including a two-relay terminal-binding
  path. The pair also advances the canonical corpus to 104 exploit/control
  pairs, 208 cases, and 624 repeated scans.
- Final local acceptance for the PyYAML model is green. The authoritative
  Windows Bun suite passes 1,525 tests and 11,332 assertions across 169 files in
  569.92 seconds, with 20 intentional platform/environment skips and zero
  failures. WSL passes the focused PyYAML, Python cross-file, Python multi-hop,
  and canonical benchmark lane with 32 tests and 1,832 assertions. Generated
  model drift, repository formatting, TypeScript, the production build, and
  `pnpm audit --prod --audit-level high` are green with no known
  vulnerabilities. Two compiled self-inventories take 16,872.064 and
  16,113.658 ms and produce 256 byte-identical rows totaling 583,378 bytes with
  SHA-256 `aef2238821366bb8e3b908cb5fb9bcdf8afe82a63c9d8231758161ae2e63ca92`.
  Exactly one PyYAML row remains at the unsafe fixture's `src/parser.py:5`, with
  `cross-file-wrapper` scope and `pyyaml-load-with-unsafeloader` sink; the safe
  control and production sources have no PyYAML row. Strict Windows and WSL
  inspection validates the same 259-entry, 1,850,906-byte npm archive with
  SHA-256 `2d10f411533bf65858a96b4d5632a8227b1c6c26ba9a45bc41d365808b8b7e56`;
  isolated installs validate the public import, executable CLI, and all 79
  bundled plugin files. Temporary archives and isolated installs are removed
  after acceptance.
- Exact-source live campaign
  `945b070b3559c64279828bf4ec90e3e17d6a598a79fb615eb3f723f84bf0602b`
  against checkpoint `8ab9f694cd5047f76e4a625e732af5b489e9cc76`
  supplied an actionable false-negative: the safe control stayed clean, but the
  unsafe case was rejected solely because deployed-module and concrete-gadget
  proof were absent from the three-file sealed scope. The two completed scans
  had zero false positives and no authentication, quota, credit, or classifier
  failure, but recall and F1 were zero at a total cost of $1.626461125. The
  quality gate now treats the exact host-proven non-shadowed PyYAML unsafe API
  and remote stream as sufficient for a CWE-502 object/state integrity finding,
  records unavailable runtime proof as a limitation, and retains the bounded
  witness requirement before any stronger impact claim.
- A second exact-source campaign on corrected checkpoint
  `3f9b0d859ac1993596e6ac089befc93084e2838a` recovered one high
  unsafe-case finding on attempt one and kept the source-identical `safe_load`
  control clean, yielding perfect structural precision, recall, F1, stability,
  evidence, validation, attack-path, severity, and false-positive metrics. Its
  stricter field-scoped semantic gate exposed two wording variants: validation
  used `POST body`, while the attack path used `Python-specific constructor`
  rather than the narrower benchmark literals. The benchmark now recognizes
  these exact equivalent phrases, and correction guidance explicitly requires
  the request/YAML boundary in validation and Python construction outcome in
  the attack path. It does not relax CWE, location, substantive-field,
  safe-control, or impact-overclaim gates; severity calibration is addressed by
  the next campaign.
- Final-candidate campaign
  `71fcc965504a51e68508a1bf947f172b43a24b1a3df67194f62ad0ee130f22a2`
  on `f99a720e0aa59237ed865bcf614c5447bd6b7b62` passes every
  structural and field-scoped semantic gate, emits one unsafe-case finding and
  no safe-control finding, but exposes severity calibration as the sole failed
  threshold. The model selected medium after explicitly declining to infer a
  runtime gadget or stronger effect. The benchmark now accepts medium for the
  proven object/state-integrity boundary as well as high or critical when
  independently justified; it still rejects low/informational output and does
  not credit an unproved stronger impact.
- Final exact-source campaign
  `d514ac9c160af504ee551f33ee9e16f03de7aad0ef8172ddb6893d9d701ba1e1`
  on calibrated checkpoint `f2a9c951e9995d2bd3fd85a3348e05bb6c8d8c52`
  passes every gate. The unsafe case produces one medium CWE-502 finding with
  substantive validation, attack path, and exact source/sink evidence; the
  source-identical `safe_load` case produces none. Completion, precision,
  recall, F1, case pass, negative-case pass, stability, validation, attack-path,
  code-evidence, severity, and semantic acceptance are all 1.0, with zero false
  positives and false negatives. Both scans complete on attempt one for a total
  cost of $2.291457125, with no authentication, quota, credit-limit, or
  safety-classifier error. All seven exact-checkpoint workflow families pass:
  Node `32816357391`, Windows GUI `32816357532`, Linux GUI `32816357459`,
  container `32816357383`, Java `32816357426`, .NET `32816357385`, and Go
  `32816357392`.
- Added `cloudformation-public-admin-role`, the first native CloudFormation IAM
  authority model. It joins one exact `AWS::IAM::Role`, an unrestricted
  wildcard AWS-principal `Allow` for `sts:AssumeRole`, and either the exact
  AWS-managed `AdministratorAccess` policy or an unrestricted inline wildcard
  action/resource grant on that same role. The structured row preserves logical
  and optional deployed role identity, trust action and condition state,
  permission form, permissions-boundary state, CWE-269/CWE-284, and exact
  source/sink lines across strict YAML 1.2, JSON, and `.template` inputs,
  including CloudFormation shorthand intrinsic tags outside the modeled static
  boundaries. Empty conditions and an `AdministratorAccess` boundary remain
  correctly unbounded. Nonempty or dynamic conditions, other static or dynamic
  boundaries, specific principals, narrower permissions, ambiguous aliases,
  duplicate keys, malformed documents, unresolved modeled intrinsics, and non-
  templates fail closed. Correction separately proves rendered deployment,
  transforms and generated templates, drift, caller reachability, same- versus
  cross-account semantics, effective SCP/session/explicit denies, and the least
  concrete administrator effect without inventing anonymous access or valid
  credentials. Fallback repository discovery content-prefilters bounded JSON
  and `.template` candidates for both `Resources` and `AWS::IAM::Role` instead
  of adding every JSON metadata or lock file to the general source budget; this
  preserves existing package-boundary and candidate-cap coverage.
- Added the paired perfect-gate
  `cloudformation-public-admin-role-manifest.json` benchmark. The positive uses
  a wildcard trust and exact AdministratorAccess attachment; the source-
  identical control changes only the principal to one AWS account. Eight
  focused groups cover exact structured provenance, YAML/JSON/template input,
  intrinsic tags and partitions, managed and inline permission forms,
  conditions and permissions boundaries, narrower authority, parser ambiguity,
  non-template rejection, and correction guidance. The focused plus canonical
  lane passes 26 tests and 1,748 assertions on native Windows and Ubuntu/WSL.
  The canonical corpus now contains 103 exploit/control pairs, 206 cases, and
  618 repeated scans.
- Final local and hosted acceptance for the CloudFormation model is green at
  exact implementation checkpoint `77546af1ad18746790e4fb3c5d3f90c2f1f285fb`.
  The authoritative Windows Bun 1.3.14 suite passes 1,516 tests and 11,252
  assertions across 168 files in 581.48 seconds, with 20 intentional platform/
  environment skips and zero failures. The first full run correctly exposed
  that indiscriminately ingesting JSON displaced three prior framework rows and
  weakened an oversized npm-boundary control; the format-specific discovery
  correction restores both regressions, and the exact failing suites pass on
  Windows and Ubuntu/WSL. Generated-model drift, formatting, TypeScript, the
  clean production build, and the production high-severity audit are green with
  no known vulnerabilities. Two inventories of an immutable exact-commit
  archive produce 256 byte-identical rows totaling 582,834 bytes with SHA-256
  `48516b803c7ba2299c4afa62354bca85fbf79cc43b1f21c47012c8040ec037a8`.
  Exactly one CloudFormation row retains the wildcard trust at line 13, the
  same role and assume action, and AdministratorAccess sink at line 17; its
  specific-principal control is absent. Both prior Kubernetes rows remain and
  their controls are absent. Windows and Ubuntu/WSL strictly inspect the same
  POSIX-built 259-entry, 1,817,596-byte npm archive with SHA-256
  `1a8adc2cfa77bea33edf7b38cfea311bcd3c7718369626313f85a8f5792fd5a6`;
  isolated consumers install 67 and 75 packages respectively and validate the
  public import, executable CLI, new `cloudformation-risk` distribution module,
  and all 79 bundled plugin files. All exact-source workflows succeed: Node
  `32806856391`, container `32806856370`, Windows GUI `32806856344`, Linux GUI
  `32806856384`, Java `32806856341`, .NET `32806856380`, and Go `32806856368`.
  The package archive, immutable source snapshot, inventories, and isolated
  installs are removed after acceptance.
- A first live CloudFormation campaign exposed a validation false negative,
  rather than a model-service failure. Campaign
  `c540268ea0c49f75e7b1a4aac598d4b528e41308c62e115e126fc479e921d499`
  completed both cases on their first attempts without refusal, retry, rate
  limit, or transport recovery. The specific-principal control correctly
  produced zero findings, but the vulnerable case also produced zero even
  though all six independent discovery passes called the joined policy
  reportable. Central validation incorrectly treated absent live AWS deployment
  telemetry and an attacker credential in the repository as counterevidence.
  The host quality gate and bundled validation guidance now make the declared
  IaC defect/reportability boundary explicit: exact unsafe trust and authority
  are reportable with unchanged deployment and caller permission recorded as
  preconditions; missing live telemetry calibrates confidence and wording, and
  only positive exclusion, rejection, replacement, or effective-control
  evidence suppresses the row. The same rule requires an attacker-controlled
  external AWS principal with caller-side `sts:AssumeRole`, while continuing to
  forbid anonymous-access, active-session, or critical-compromise claims without
  runtime proof. The failed baseline used 2,869,984 input tokens (2,583,325
  cached), 47,314 output tokens, and estimated cost $2.251245625 over 4m31s and
  remains isolated for comparison.
- A second live campaign, `f8be18fa5cd43c2acd0eef46f9c6f9ac86b0b2107fe1cf82c2ab5b660a5688c4`,
  proved the reportability correction: the vulnerable case produced one high-
  severity finding and the specific-principal control produced none, both on
  attempt one without refusal or transport recovery. The then-current
  structural gate reported perfect precision, recall, F1, validation, attack-
  path, code-evidence, severity, stability, and negative-control metrics.
  Manual artifact review still found an important reachability overclaim: the
  attack-path ledger called operating any AWS principal the only precondition
  and described session issuance as unconditional, omitting cross-account
  caller-side authorization. Benchmark expectations now support bounded,
  case-insensitive whole-finding, validation-scoped, and attack-path-scoped
  alternative groups plus forbidden literals; the evaluator reports exact
  missing groups and present overclaims and never executes manifest regexes.
  Re-evaluating that preserved campaign now fails the vulnerable case for a
  missing validation caller-permission group, missing attack-path caller and
  deployment groups, and three unqualified outcome phrases. The quality gate and packaged guidance also
  require unchanged deployment plus effective caller-side `sts:AssumeRole` in
  both validation uncertainty and attack-path serialization. The combined generic
  benchmark and CloudFormation lanes pass 26 tests and 1,748 assertions.
- Campaign `ff9bc508799c3db3d4b9ae0c3d9100f6c2c9eca6b794671db084d9646da1790e`
  then produced the intended semantics: one conditional critical finding and
  zero control findings on attempt one, with explicit unchanged-deployment and
  caller-side authorization preconditions in both validation and attack-path
  objects and none of the forbidden overclaims. Deterministic completion also
  re-anchored three model-written excerpts to exact repository bytes. The two
  scans used 2,521,686 input tokens (2,258,391 cached), 40,156 output tokens,
  and estimated cost $1.989648375 over about 4m10s, with no refusal, retry,
  limit, authentication, or transport event. This campaign exposed an
  acceptance-process issue: its runner loaded the preceding compiled evaluator
  while the source had just gained field-scoped gates. Exact-source evaluation
  verified the finding but showed that literal matching should ignore Markdown
  code backticks and admit the precise phrase "role is deployed unchanged."
  Semantic normalization now removes Markdown code delimiters as presentation,
  and the manifest includes the exact caller-authorization and deployment
  variants. The fresh manifest-bound acceptance is recorded below.
- Exact manifest-bound campaign
  `e8d629966465d373da2516e3ab72f1dfe50f2d3ebc5ec11bf979d2a4f975b37d`
  at source `17b27d8e5f53ddae5c96d6651f4aa4015b248218` passes the final
  gate. The vulnerable case reports one conditional critical CWE-269/CWE-284
  finding at the wildcard trust, `sts:AssumeRole`, and AdministratorAccess
  lines; the specific-principal control reports none. Both completed on attempt
  one with complete coverage. All structural rates are 1.0, false positives and
  misses are zero, and the semantic match has empty whole-finding, validation,
  attack-path, and forbidden-text failure lists. Direct ledger review confirms
  unchanged deployment and effective external caller-side authorization in
  validation and attack-path preconditions, conditional session wording, and
  no anonymous, active-deployment, successful-session, target-account, or
  organization-wide claim. The two scans used 3,847,786 input tokens (3,462,660
  cached), 54,043 output tokens, and estimated cost $2.879669375 over 4m29s,
  without refusal, retry, rate-limit, authentication, transport, or allowance
  error. The accepted artifacts remain isolated under
  `C:\security-benchmarks\cloudformation-public-admin-role-semantic-final-17b27d8`.
- Final regression and release-shape acceptance is green. The authoritative
  elevated Windows Bun 1.3.14 suite passes 1,517 tests and 11,268 assertions
  across 168 files in 557.07 seconds, with 20 intentional platform/environment
  skips and zero failures. An initial managed-sandbox run was stopped after it
  consistently denied its temporary Git, Windows ACL, PDF worker, and Python
  workbench fixtures; every affected test passes with its required access.
  Generated-model drift, formatting, TypeScript, clean build, and the production
  high-severity audit are clean with no known vulnerabilities. Windows and
  WSL-built archives each contain 259 entries totaling 9,255,964 unpacked bytes
  and pass strict inspection plus two isolated installs, public import, CLI,
  and all 79 bundled plugin files. The Windows archive is 1,823,031 bytes,
  SHA-1 `56522b551fa630ea8b4d262ff137c04dab1ca199`, integrity
  `sha512-YAezvRTXGglhuXOd5AJlUVrPL4gpOv4KxuZE2ikjqeRpuHY65ZO3Vufxkceg1tkVcVqApY9xtNpUhtJD+xVYhg==`,
  and SHA-256 `142e9eeeb799c3b71fd517a67fb770decf65d2f1f05512820b6134efbc2561f1`.
  The POSIX archive is 1,823,011 bytes, SHA-1
  `f051226487bf0e2d5817e913a9e679e86e494e58`, integrity
  `sha512-eSNuEDewm9h6yleS29bLg3MwcvGuTILd9y0AEpwd2lrBkMtAiZCOJWk21JLzhoEJqhMKA+kP45RmVMmWe3Ubsw==`,
  and SHA-256 `69581e3e0095cad31426cdb583a262c8ab70b61be0a134b1ab928f2a3ff3727f`.
  Exact implementation commit `17b27d8` passes Node `32810193083`, container
  `32810193122`, Windows GUI `32810193063`, Linux GUI `32810193071`, Java
  `32810193089`, .NET `32810193080`, and Go `32810193073`. Documentation-only
  acceptance commit `212382d` also passes its six applicable path-filtered
  workflows. Local archives and isolated installs are removed after acceptance.
- Added `kubernetes-cluster-admin-broad-subject`, the second native Kubernetes
  infrastructure-as-code model. It requires an exact
  `rbac.authorization.k8s.io/v1` `ClusterRoleBinding`, an immutable exact
  reference to the built-in `cluster-admin` `ClusterRole`, and one documented
  intrinsic catch-all principal: `system:anonymous`,
  `system:unauthenticated`, `system:authenticated`, or
  `system:serviceaccounts`. The structured row preserves binding, role,
  principal, cluster scope, CWE-269/CWE-284, and exact source/sink lines. Named
  administrator groups, individual service accounts, namespace-scoped service-
  account groups, RoleBindings, similar role names, wrong API shapes,
  namespaces on cluster-scoped objects or User/Group subjects, duplicate
  subject identities, aliases, duplicate keys, malformed YAML, and non-YAML
  lookalikes fail closed. Correction separately proves rendered deployment,
  effective RBAC authorization, credential or anonymous reachability, and the
  least concrete unauthorized cluster action without inventing a public API or
  compromised workload.
- Added the paired perfect-gate
  `kubernetes-cluster-admin-binding-manifest.json` benchmark. The positive uses
  Kubernetes' documented strongly discouraged binding of `cluster-admin` to
  every service account; the source-identical control uses one named platform
  administrator group. Seven focused groups pass 36 assertions across all four
  supported broad principals, exact line identity, multi-document/List parsing,
  narrower scopes and subjects, immutable role references, parser ambiguity,
  and correction guidance. The combined Kubernetes and canonical lane passes
  31 tests and 1,768 assertions on both native Windows and Ubuntu/WSL. The
  canonical corpus now contains 102 exploit/control pairs, 204 cases, and 612
  repeated scans.
- Final acceptance for the broad-principal RBAC model is green at exact
  implementation checkpoint `140ead32297a8deaf4fe99fb4d490db6ce1e83b2`.
  The authoritative Windows suite passes 1,508 tests and 11,210 assertions
  across 167 files in 594.96 seconds, with 20 intentional
  platform/environment skips and zero failures. Generated-model drift,
  formatting, TypeScript, the clean production build, and the production audit
  pass with no known vulnerabilities. Two inventories of an immutable archive
  of that commit produce 256 byte-identical rows totaling 581,530 bytes with
  SHA-256
  `ac1d024e3486aa3f80fa49c066b12acae2690c5ed831f36bb69d7d7aa8ae6281`;
  exactly one RBAC row retains the vulnerable all-service-account binding and
  exactly one prior hostPath row remains, while both matched controls are
  absent. Windows and Ubuntu/WSL strictly inspect the same POSIX-built
  255-entry, 1,804,936-byte npm archive with SHA-256
  `51ef028caad7dca0b75315a0ca15d694fabd45af6aa34bf3ce2e52fc6e4e4caa`;
  isolated consumers install 67 and 75 packages respectively and validate the
  public import, installed CLI, executable mode, and all 79 bundled plugin
  files. All seven exact-source workflow families succeed: Node `32803416155`,
  container `32803416113`, Windows GUI `32803416227`, Linux GUI `32803416168`,
  Java `32803416140`, .NET `32803416156`, and Go `32803416115`. Disposable
  archives, snapshots, and isolated installs are removed after acceptance.
- A live first-attempt Copilot deep benchmark of the RBAC pair passes every
  perfect gate with campaign ID
  `f01cac642bc942aa0f073eaa9f7787234a6a290dc4e468fa8b4d1dd2a9c23fae`.
  The vulnerable binding produces exactly one high-severity true positive with
  substantive validation, attack-path and code evidence; the named-group
  control produces zero findings. Completion, precision, recall, F1, case and
  negative-case pass rates, stable detection, validation, attack-path,
  code-evidence, and severity accuracy are all 1.0 with zero false positives.
  The parallel campaign completes in 3m52s without retry or refusal, consuming
  1,959,466 input tokens (1,693,549 cached), 37,064 output tokens, and an
  estimated $1.80694350. The isolated receipts remain under
  `C:\security-benchmarks\kubernetes-cluster-admin-binding-140ead3` for
  comparison runs.
- Added the first native Kubernetes infrastructure-as-code model,
  `kubernetes-privileged-sensitive-hostpath`. It joins one exact deployable
  workload shape, one exact privileged Linux container or init/ephemeral
  container, one uniquely named sensitive `hostPath` volume, and that same
  container's absolute read-write mount. The structured row carries workload,
  namespace, container section/name, normalized host path, mount path, volume
  identity, CWE-250/CWE-732, and exact source/sink provenance. It supports
  current Pod, ReplicationController, apps/v1 controller, batch/v1 Job and
  CronJob layouts, multi-document YAML, and Kubernetes List objects. Read-only
  mounts, isolated volumes, pod user namespaces, Windows workloads, safe or
  dynamic subpaths, mismatched or duplicate identities, wrong API/kind pairs,
  aliases, duplicate keys, malformed documents, and non-YAML lookalikes fail
  closed. The correction rule separately requires rendered deployment,
  admission and exemption proof, a realistic attacker prerequisite, and a
  concrete host effect instead of inventing remote node or cluster compromise.
  This improves on separate privileged-container and mounted-hostPath warnings
  by preserving the complete same-container authority path for review.
- Added the paired perfect-gate
  `kubernetes-privileged-hostpath-manifest.json` benchmark. The positive is an
  apps/v1 Deployment whose pinned container mounts the node root read-write
  while privileged. The matched control opts into `hostUsers: false`, disables
  privileged mode, and uses `emptyDir`. Seven focused groups pass 42 assertions
  across workload shapes, all three container sections, multi-document/List
  parsing, exact line identity, subpaths, typed booleans, Windows and user
  namespace controls, ambiguity, malformed YAML, prompt guidance, and canonical
  gate shape. The combined focused and canonical lane passes 24 tests and 1,721
  assertions on both native Windows and Ubuntu/WSL. Two native self-inventories
  are byte-identical at 256 rows with SHA-256
  `51c2c9907f8e8a5bc2e0c1c355616a2cea830afbfe0754d456529048062c6844`;
  the new structured row survives the global cap and only the vulnerable
  fixture is retained. The canonical corpus now contains 101 exploit/control
  pairs, 202 cases, and 606 repeated scans.
- Final local acceptance for the Kubernetes authority-path model is green. The
  authoritative Windows suite passes 1,501 tests and 11,163 assertions across
  166 files in 705.07 seconds, with 20 intentional platform/environment skips
  and zero failures. Generated-model drift, repository formatting, TypeScript
  checking, and the clean production build pass; the production dependency
  audit reports no known vulnerabilities. Windows and Ubuntu/WSL strictly
  inspect the same POSIX-built 255-entry, 1,800,859-byte npm archive with
  SHA-256
  `63f03c3a436d5fbf1baf752af50ab670e219fff1a8b2c9f18cb1b68cd75798b5`;
  isolated consumers install 67 and 75 packages respectively and validate the
  public import, installed CLI, and all 79 bundled plugin files. The strict
  package checker now explicitly accounts for the new `kubernetes-risk`
  distribution module. It rejected the otherwise valid Windows-produced
  archive because that producer flattened the CLI mode to 0644; the accepted
  WSL-produced archive preserves 0755, preventing a Linux packaging regression
  from being hidden by Windows-only validation.
- Complete-draft transport recovery now resumes the mandatory host-audited
  quality gate in a fresh isolated Copilot session before deterministic
  finalization. A timeout or sanitized transport interruption whose session
  already wrote all three bounded draft artifacts enters a dedicated
  `draft_quality_correction` phase within the existing one-to-five-session
  budget; it does not replay the full repository scan. The replacement session
  receives freshly computed residual-risk, secret-candidate, coverage-gap, and
  finding-quality inventories, and every correction remains subject to the
  existing deterministic re-audit and bounded repair series. Successful
  built-in file views accumulate across isolated sessions, while unfinished
  tool calls are cleared at each boundary so a reused tool-call ID cannot
  manufacture direct-review evidence. Authentication, authorization, safety,
  sandbox, contract, cancellation, and unrelated model failures remain
  non-retryable. SDK observers and the CLI expose the sanitized correction
  phase without forwarding provider error text. A deterministic recovery
  benchmark proves that one completed first-session view remains valid, a
  stale completion closes nothing, and exact replacement-session views reduce
  the remaining coverage gaps from two to zero.
- Final local acceptance for fresh-session draft correction is green. The
  authoritative Windows suite passes 1,494 tests and 11,110 assertions across
  165 files in 647.36 seconds, with 20 intentional platform/environment skips
  and zero failures. The changed orchestration/API/CLI lane passes 142 tests
  and 1,378 assertions on Windows with one intentional skip and passes the
  corresponding WSL/Linux lane with only its Windows-launcher skip. Generated
  models, full formatting, TypeScript, and the clean production build pass;
  the production audit reports no known vulnerabilities. Strict Windows and
  Linux inspection accepts the same 251-entry, 1,810,430-byte npm archive with
  SHA-256
  `e994930f48909f8153e5cdc4e4a63fada70deaab425c2376c0dfa39d98ab39e9`;
  isolated consumers install 67 and 75 packages respectively and validate the
  public import, CLI, and all 79 bundled plugin files. The archive and isolated
  installs are removed after acceptance.
- Exact-commit hosted acceptance is green for
  `bc97e5e4bde3f9d8c6637113d38f6b63ef8c2b55`: Node `32796785950`, container
  `32796785902`, Windows GUI `32796785918`, Linux GUI `32796785931`, Java
  `32796785883`, .NET `32796785929`, and Go `32796785893` all succeed. The Node
  workflow covers Windows Node 22, macOS Node 22, and Linux Node 22, 24, 24.0.0,
  26, and 26.0.0.
- Hardened two environment-heavy Windows test deadlock guards after a later
  documentation-head run completed 1,492 assertions-clean tests but timed out
  waiting for hosted Python startup and private credential-home setup. The
  Python subprocess guard is now 120 seconds with a 150-second enclosing test;
  the credential-home integration test allows 180 seconds. Scanner production
  deadlines, retry limits, assertions, and failure handling are unchanged. The
  affected native Windows files pass 119 tests and 1,317 assertions with one
  intentional platform skip and zero failures. The same audit exposed a
  separate WSL mounted-filesystem integration whose clean TypeScript build can
  exceed its old 30-second outer guard; it now has a 90-second build guard and
  180-second test guard plus explicit child-process error assertions. The full
  WSL CLI file passes all 81 tests and 1,148 assertions, including the 60.97s
  split-package case.
- Added deterministic external-SARIF seed-coverage receipts. Seeded scans now
  bind the exact normalized candidate count and JSONL SHA-256 plus ordered
  source digests into the trusted workbench recipe; reject partial, malformed,
  or noncanonical bindings before model execution; and reconcile every
  reserved seed identity against the final enriched ledger. Completion fails
  on missing, duplicate, invented, out-of-scope, identity-mutated, or
  incompletely validated rows. The host writes a manifest-sealed
  `external_sarif_seed_coverage.json` receipt with one `reportable`, `rejected`,
  `deferred`, or `out_of_scope` disposition per input seed, adds canonical
  coverage and deferred-work records, and reports exact closure counts to CLI
  and GUI consumers. The TypeScript SDK exposes the receipt path. The dedicated
  SARIF ensemble benchmark now gates exact closure totals, unique instances,
  the coverage reference, and the receipt's sealed digest, so a matching
  finding alone cannot hide lost imported candidates or a false-positive seed.
- Hardened those receipts for real deep and diff scan artifacts. Finalization
  now reconciles the canonical compact row and a bounded set of exact merged
  representations emitted by multi-pass scans, including camel-case identity
  fields, nested imported-seed records, and separate validation and attack-path
  ledgers. It still requires an exact reserved instance/CWE/location identity,
  rejects conflicting aliases and ambiguous representations, requires
  substantive attack-path evidence for reportable or deferred seeds, and adds
  every supporting closure ledger to canonical coverage and the manifest seal.
  The bundled deep/diff instructions now specify one canonical imported-seed
  row and exact closure-ledger filenames to reduce output variance.
- Live Copilot deep scans now pass both dedicated external-SARIF controls on
  their first attempt with the hardened finalizer. The vulnerable command case
  seals one reportable seed and one true positive with no false positives or
  negatives. The source-identical safe `execFile` case seals one rejected seed,
  emits no finding, and passes every completion, negative-case, precision,
  recall, validation, attack-path, evidence, severity, stability, and
  false-positive gate at 1.0 (zero false positives).
- Final exact-state acceptance for deep-ledger compatibility is green. The
  authoritative Windows suite passes 1,490 tests and 11,086 assertions across
  165 files in 582.78 seconds, with 20 intentional platform/environment skips
  and zero failures. Windows and Ubuntu/WSL each pass all 100 recovery and
  benchmark tests with 2,144 assertions and no skips. Formatting,
  generated-model drift, TypeScript checking, the clean production build, and
  the production audit are green with no known vulnerabilities. Strict Windows
  and Linux inspection accepts the same 251-entry, 1,808,822-byte npm archive
  with SHA-256
  `0840d319146ee7cd89c6d917a6e7e1dce20e7f103969739c832f950ddb0f7b5e`;
  isolated consumers validate the public import, CLI, and all 79 bundled plugin
  files.
- Exact-commit hosted acceptance is green for `1f5181421ec589fbacb8b5ac8afd191ff0380076`:
  Node `32792460240`, container `32792460282`, Windows GUI `32792460242`,
  Linux GUI `32792460254`, Java `32792460241`, .NET `32792460302`, and Go
  `32792460232` all succeed. A deep self-scan of an immutable archive of that
  commit also exercises late transport recovery successfully: Copilot's stream
  ends after draft creation, the deterministic workbench validates and seals
  the artifacts, and no finding survives. It correctly reports partial rather
  than overstating coverage because 415 of 417 inventory paths lack exact
  per-file closure. This exposes the next effectiveness target: recovered
  complete drafts must still receive bounded coverage correction, potentially
  in a fresh session, before completeness can be claimed. The scan takes 16m
  25s and records 15,329,102 input tokens (13,367,459 cached), 136,262 output
  tokens, and estimated cost $11.513870375.
- Local acceptance for the seed-coverage contract is green. The authoritative
  Windows suite passes 1,482 tests and 11,059 assertions across 165 files in
  559.22 seconds, with 20 intentional platform/environment skips and zero
  failures. Ubuntu/WSL passes all 107 changed-contract, benchmark, SDK, and
  recovery tests with 2,155 assertions and no skips. Generated-model drift,
  formatting, TypeScript, the clean production build, and the production audit
  pass with no known vulnerabilities. Strict Windows and Linux inspection of
  the same 251-entry, 1,806,132-byte npm archive with SHA-256
  `ac2d79b5b73287a21426a48e827b90ade21fe17883067c20c88f8d32baa52746`
  validates isolated public imports, the CLI, and all 79 bundled plugin files.
  Windows and Linux both pass 7 core and 3 shared desktop tests; Linux also
  passes 2 Avalonia tests. The hidden Windows startup, Linux non-graphical
  startup, and real X11/Xvfb window startup pass. Generated archives and GUI
  publications are removed after acceptance.
- Added `node-http-shell-quote-object-token-command-injection` for [GHSA-w7jw-789q-3m8p / CVE-2026-9277](https://github.com/advisories/GHSA-w7jw-789q-3m8p). The model requires attacker-controlled HTTP data to become an explicit `shell-quote` object token with an `op` property, official `quote()` serialization through either direct token construction or a `parse()` environment callback returning that token, exact propagation of the non-reassigned serialized result into an official Node child-process API that actually invokes a POSIX command interpreter, and nearest exact production or fresh declaration-consistent npm v2/v3 proof from 1.1.0 through 1.8.3. It supports named and aliased imports, namespace/default receivers, TypeScript import-equals, CommonJS destructured/receiver/direct-member forms, direct `require()` calls, stable one-hop aliases, `exec`/`execSync`, explicit `sh`/`bash`/`dash`/`zsh`/`ksh` `-c` or `-lc` dispatch, shell-enabled `spawn`/`execFile`, and same-file or relative-import multi-hop reachability. Ordinary string tokens, parser output without an attacker-shaped environment return, glob/comment objects, fixed operators, unused serialization, shell-free argv execution, wrong interpreter flags, repaired/prerelease versions, wrong or development-only packages, unresolved/stale/inconsistent/v1 metadata, local lookalikes, reassignment, replaced members, and tests/examples remain negative. Source-identical fixtures change only `shell-quote` 1.8.3 to 1.8.4. Their harmless witness uses only `pwd` under `/bin/sh` in `/tmp`: 1.8.3 preserves a line terminator and executes the second shell line, while 1.8.4 rejects the identical object token before serialization; Windows checks the same serialization boundary without invoking a shell. Eight focused groups pass 29 assertions, and the strict pair advances the canonical benchmark to 100 exploit/control pairs, 200 cases, and 600 repeated scans.
- Final acceptance for the shell-quote object-token model is green at exact implementation checkpoint `ed7abdaf2ca73f1a5a03bc6d6d5112bcf65979bc`. The hosted Windows Bun 1.3.14 suite passes 1,466 tests and 11,000 assertions across 165 files in 477.59 seconds with 20 intentional platform/environment skips and zero failures; Ubuntu Node 22 passes 1,482 tests and 11,076 assertions with four skips and zero failures in 373.93 seconds. A managed local aggregate exercises all 1,486 cases but denies 60 cases only at the established Git, private-ACL, PDF-worker, and immutable-inventory host boundaries; the exact four-file native rerun passes 108 tests and 611 assertions with two intentional skips and no failures. Windows and Ubuntu focused lanes pass 51 tests/1,820 assertions and 38 tests/1,754 assertions respectively, and both preserve the real 1.8.3/1.8.4 witness boundary. Generated-model drift, formatting, TypeScript, the production build, and the production advisory audit are green. Two compiled inventories of a disposable exact-commit archive take 16,134.337 and 15,865.762 ms and produce 256 byte-identical rows, 579,059 bytes, and SHA-256 `e6993ceaf052613feef2c36100a7e79933df96ceb76e222a8e39db2606d71159`; all 173 structured records survive ahead of 83 lexical leads, with 225 fixture and 31 non-fixture rows. Exactly one shell-quote row retains source `src/server.js:7`, final process sink `src/runner.js:6`, CWE-77/CWE-78, nine ordered import/wrapper transitions, and exact `shell-quote@1.8.3:manifest-exact:direct-object-token` provenance, while the source-identical 1.8.4 twin is absent. Strict inspection validates a 251-entry, 1,797,122-byte npm archive with SHA-256 `d10c113310aa599062685b8cd81409e95886417366d05a1154ba618cbffcee16`; an isolated install validates the public import, CLI, and all 79 bundled plugin files. Windows GUI core/shared tests pass 7/7 and 3/3, hidden startup passes, and its 346,796-byte publish has SHA-256 `7a15a6a649b373543ef0fbc2c4d8c4ae6d2ce8d412fdb3282daf24b4325559e2`; Ubuntu/WSL core/shared/Linux tests pass 7/7, 3/3, and 2/2, both startup modes pass, and its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-source workflow families pass: Node `32778676340`, container `32778676455`, Windows GUI `32778676437`, Linux GUI `32778676371`, Java `32778676469`, .NET `32778676467`, and Go `32778676348`. The repository remains public on default branch `main`, and fixture installs, research packages, package archives, GUI publications, exact-commit archives, and self-scan reports are removed.
- Added `node-http-sequelize-oracle-sql-injection` for [GHSA-v8fg-2rw7-q452 / CVE-2026-69240](https://github.com/advisories/GHSA-v8fg-2rw7-q452). The model requires attacker-controlled HTTP data inside the `where` property of an executed official Sequelize `count`, `destroy`, `findAll`, `findAndCountAll`, `findOne`, or `update`; an exact model created by a non-reassigned Sequelize instance whose dialect statically resolves to Oracle or whose connection URI is a static Oracle URI; and nearest exact production or fresh declaration-consistent npm v2/v3 proof below 6.37.4. It supports named and aliased constructors, default and namespace bindings, TypeScript import-equals, CommonJS destructured/direct forms, resolved configuration objects and shorthand dialect properties, same-file and relative-import multi-hop reachability, and separate dependency and dialect propagators. Sequelize 6.37.4+, prereleases, non-Oracle or dynamic dialects, wrong or development-only packages, lockfile-free ranges, stale/inconsistent/v1 locks, package-only use, fixed predicates, request data outside `where`, local lookalikes, shadows, reassignment, replaced `define` or ORM members, and tests/examples remain negative. Source-identical fixtures change only Sequelize 6.37.3 to 6.37.4. Their inert real-package witness substitutes only the Oracle driver object, contacts no database, and proves that 6.37.3 emits `OR 1=1--` outside the intended value while 6.37.4 rejects the identical input with `Invalid SQL function call.` Eight focused groups pass 27 assertions, and the strict pair advances the canonical benchmark to 99 exploit/control pairs, 198 cases, and 594 repeated scans.
- Final acceptance for the Sequelize Oracle model is green at exact implementation checkpoint `7e6f7fa889dc3da2d24a9b7c7c19bec95096ec80`. The authoritative native suite passes 1,458 tests and 10,958 assertions across 164 files in 515.26 seconds, with 20 intentional platform/environment skips and zero failures. Ubuntu/WSL passes the focused model, framework-dataflow, and canonical lane with 38 tests and 1,741 assertions; both hosts reproduce the real 6.37.3 generated predicate and the 6.37.4 rejection without a database. Generated-model drift, formatting, TypeScript, the clean production build, and `pnpm audit --prod --audit-level high` are green. Two compiled inventories of a disposable repository-root archive take 35,969.942 and 14,594.544 ms and produce 256 byte-identical rows totaling 576,703 bytes with SHA-256 `064c3284256837911658b958aa12658532847569695cc79e463cec902a8a04a8`; all 172 structured records survive ahead of 84 lexical leads, with 225 fixture and 31 non-fixture rows. Exactly one Sequelize Oracle row retains source `src/server.js:7`, sink `src/storage.js:14`, CWE-89, eleven ordered import/wrapper/dependency/dialect transitions, exact `sequelize@6.37.3` provenance, and `dialect:oracle`; the source-identical 6.37.4 twin is absent. The 251-entry, 1,789,328-byte npm archive has SHA-256 `5c3eecb0b083ddefaf5353f5a8b03429b42a59188d1a1da8985f95518ea7f0eb` and passes isolated public-import, CLI, and 79-file bundled-plugin checks. Windows GUI core/shared tests pass 7/7 and 3/3, and its 346,796-byte publish has SHA-256 `f0349662f3247c599b96a7ed1805f503e316021e1905cf7655991d662a250420`; Ubuntu/WSL core/shared/Linux tests pass 7/7, 3/3, and 2/2, non-graphical plus X11/Xvfb startup pass, and its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-source workflow families pass: Node `32772500708`, container `32772500610`, Windows GUI `32772500695`, Linux GUI `32772500692`, Java `32772500730`, .NET `32772500698`, and Go `32772500699`. The repository remains public on default branch `main`, and fixture installs, package archives, GUI publications, research packages, exact-commit archives, and self-scan reports are removed.
- Added `node-http-decompress-archive-escape` for [GHSA-mp2f-45pm-3cg9 / CVE-2026-53486](https://github.com/advisories/GHSA-mp2f-45pm-3cg9). The model requires attacker-controlled HTTP archive bytes to reach an official `@xhmikosr/decompress` or upstream `decompress` call with a concrete string destination and exact affected production provenance. It recognizes the maintained 10.x range below 10.2.1, the maintained 11.x range from 11.0.0 below 11.1.3, and unpatched upstream `decompress` through 4.2.1; supports default, named-default, namespace-default, TypeScript import-equals, CommonJS callable/default/destructured-default, direct-require, one-hop alias, and multiline forms; and preserves same-file and relative-import multi-hop source paths. Repaired releases, prereleases, wrong or development-only packages, lockfile-free ranges, stale/inconsistent/v1 locks, package ambiguity, parse-only overloads, omitted or non-string destinations, fixed input, local lookalikes, shadowing, reassignment, replaced members, and tests/examples remain negative. Source-identical fixtures change only `@xhmikosr/decompress` 10.2.0 to 10.2.1. A bounded custom-plugin witness proves the sibling-prefix write on Windows and Linux without touching existing files; the repair commit's exact tar fixture independently proves the default-parser symlink-pivot boundary on Ubuntu/WSL. Seven focused groups pass 31 assertions, and the strict pair advances the canonical benchmark to 98 exploit/control pairs, 196 cases, and 588 repeated scans.
- Final acceptance for the decompression archive model is green at exact implementation checkpoint `f9c3e3a1077ddf626d2e9dc99c40de83bb5abad6`. The managed Windows aggregate exercises all 1,470 cases: 1,390 pass, 20 intentional platform/environment skips remain, and 60 cases are denied only at four host boundaries covering Git fixture ownership, private Windows ACLs, PDF-worker module access, and immutable scan-inventory finalization. The exact four-file native rerun passes 108 tests and 611 assertions with two intentional symlink/permission skips and zero failures. The adjacent Windows archive/framework/canonical lane passes 62 tests and 1,842 assertions; Ubuntu/WSL passes the focused model, framework-dataflow, and canonical lane with 37 tests and 1,734 assertions. Generated-model drift, formatting, TypeScript, the clean production build, and `pnpm audit --prod --audit-level high` are green. Two inventories of a disposable exact-commit archive take 14,721.169 and 15,262.138 ms and produce 256 byte-identical rows totaling 573,037 bytes with SHA-256 `9f2c8ee50c73f937094cfd2893b80000ee1a1a317836862c4b712ab3c380e23d`; all 169 structured records survive ahead of 87 lexical leads, with 225 fixture and 31 non-fixture rows. Exactly one decompression row retains source `src/server.js:10`, sink `src/storage.js:6`, CWE-22/CWE-59/CWE-732, nine ordered wrapper/import transitions, and exact `@xhmikosr/decompress@10.2.0` provenance, while the source-identical 10.2.1 twin is absent. All seven exact-source workflow families pass: Node `32765170480`, container `32765170354`, Windows GUI `32765170965`, Linux GUI `32765170474`, Java `32765170548`, .NET `32765170444`, and Go `32765170469`. The repository is public on default branch `main`, and all fixture installs, research packages, exact-commit archives, and self-scan trees are removed.
- Added `node-http-shescape-cmd-injection` for [GHSA-w4hw-qcx7-56pr / CVE-2026-73414](https://github.com/advisories/GHSA-w4hw-qcx7-56pr). The model requires attacker-controlled HTTP data in argument zero of official Shescape `escape`/`escapeAll`, Shescape options resolving to `shell: true` or `cmd`/`cmd.exe`, exact propagation of the non-reassigned escaped result into an official Node `exec`, `execSync`, `spawn`, `spawnSync`, shell-enabled `execFile`, or shell-enabled `execFileSync` command/argument position, CMD options at final dispatch, and nearest exact production or fresh declaration-consistent npm v2/v3 proof in the affected stable ranges below 2.1.14 or exactly 3.0.0. It supports named and aliased constructors, namespace and TypeScript import-equals receivers, CommonJS destructures/receivers/direct members, stable constructor/instance/process aliases, official `shescape/stateless` bindings, `escapeAll`, multiline and direct nested dispatch, transitive command/argument aliases, and same-file or relative-import multi-hop reachability. Versions 2.1.14 and 3.0.1+, prereleases, non-CMD shells, package-only or unused escaping, fixed input, ordinary shell-free argv dispatch, missing final shell options, wrong or development-only packages, lockfile-free ranges, stale/inconsistent/v1 locks, option or escaped-value mutation, local lookalikes, shadowing, reassignment, replaced capabilities, and tests/examples remain negative. Source-identical fixtures change only Shescape 3.0.0 to 3.0.1. On Windows Node 24.15.0, the advisory's fixed `x) else if a==a (echo y` input reaches only the benign `echo y` branch on 3.0.0; 3.0.1 caret-escapes both parentheses and emits no output. On Ubuntu/WSL Node 22.23.1, the same published internal Windows CMD escape function proves the exact string boundary without invoking a shell. Seven focused groups pass 30 assertions, and the strict pair advances the canonical benchmark to 97 exploit/control pairs, 194 cases, and 582 repeated scans.
- Final acceptance for the Shescape CMD model is green at exact implementation checkpoint `31cf7e3ce7737c43cb3da242925e0fcbbc277e7a`. The hosted Windows Bun 1.3.14 suite passes 1,443 tests and 10,880 assertions across 162 files with 20 intentional platform/environment skips, zero failures, and a 455.24-second runtime; Ubuntu Node 22 passes 1,459 tests and 10,956 assertions with four skips and zero failures in 267.54 seconds. A managed local aggregate exercised all 1,463 cases but denied Git ownership, Windows ACL, PDF-worker, and immutable-inventory fixture operations; the exact four-file host-permission rerun passes 108 tests with two intentional skips and no failures. The adjacent Windows lane passes 65 tests and 1,829 assertions, and Ubuntu/WSL passes the focused Shescape, benchmark, and dataflow lane with 37 tests and 1,722 assertions. Generated-model drift, formatting, TypeScript, the clean production build, and `pnpm audit --prod --audit-level high` are green. Two scans of a disposable exact-commit archive take 59,973.094 and 17,408.310 ms and produce 256 byte-identical rows totaling 568,498 bytes with SHA-256 `0125e143309db46d2f93c63c139e09b7201f75c827053c3da345fc6f221f78b6`; 168 are structured framework records, 88 are lexical leads, 224 are fixture paths, and 32 are non-fixture paths. Exactly one Shescape row retains source `src/server.js:7`, final dispatch `src/runner.js:10`, CWE-78/CWE-116, ten ordered propagators, and exact `shescape@3.0.0` provenance, while the source-identical 3.0.1 twin is absent. All seven exact-source workflows pass: Node `32760319981`, container `32760320081`, Windows GUI `32760319960`, Linux GUI `32760319993`, Java `32760319963`, .NET `32760319988`, and Go `32760320059`. The repository remains public on default branch `main`; disposable archives, reports, fixture installs, and research packages are removed after acceptance.
- Added `node-http-liquidjs-template-rce` for [GHSA-gf2q-c269-pqgc / CVE-2026-45618](https://github.com/advisories/GHSA-gf2q-c269-pqgc). The model requires attacker-controlled HTTP data in argument zero of an official LiquidJS `parseAndRender`/`parseAndRenderSync` call, or in `parse` whose exact token result reaches `render`/`renderSync` on the same stable official instance, plus nearest exact production or fresh declaration-consistent npm v2/v3 proof below 10.26.0. It supports named and aliased constructors, namespace/default and TypeScript import-equals receivers, CommonJS destructures/receivers/direct members, stable one-hop constructor and instance aliases, retained and immediate parse/render paths, and same-file or relative-import multi-hop reachability. Version 10.26.0+, prereleases, wrong or development-only packages, lockfile-free ranges, stale/inconsistent/v1 locks, package-only use, trusted templates with remote context only, parse-only or different-instance render flows, local lookalikes, shadowing, reassignment, replaced capabilities, and tests/examples remain negative. Source-identical fixtures change only LiquidJS 10.25.7 to 10.26.0. Their bounded witness never invokes a shell, listener, filesystem API, or network API: on Windows Node 24.15.0 and Ubuntu/WSL Node 22.23.1, 10.25.7 traverses the inherited `valueOf` filter capability and returns only `process.version`, while 10.26.0 returns `false` after moving filter and tag registries to null-prototype objects. Nine focused groups pass 32 assertions. Whole-repository review found that the 128-row limit was saturated; simply doubling it still allowed generic lexical leads to compete with structured source-to-sink records. The aligned global, per-file, cross-file, and multi-hop ceilings are now 256, and final selection reserves structured framework records before filling the remaining bounded capacity with category and path diversity. The exact-checkpoint self-inventory retains all 165 structured rows, including LiquidJS, plus 91 lexical leads in 608,739 bytes. The strict pair advances the canonical benchmark to 96 exploit/control pairs, 192 cases, and 576 repeated scans.
- Final acceptance for the LiquidJS model and structured-first retention correction is green at exact implementation checkpoint `516b561d997f72ee147fbfbf87a45433168a2c7c`. The authoritative native Windows Bun 1.3.14 suite passes 1,436 tests and 10,837 assertions across 161 files with 20 intentional environment/platform skips, zero failures, and a 491.13-second runtime. An initial managed run's Git, ACL, PDF-worker, and host-inventory denials all pass in a 108-test native rerun; an attempted native aggregate with the disposable exact-commit archive still nested beneath the repository was stopped when duplicate fixture paths invalidated repository-cap expectations, and the clean restarted aggregate supplies the accepted result. Ubuntu/WSL passes the focused LiquidJS, inventory, and canonical-benchmark lane with 91 tests and 2,706 assertions and no skips. Generated-model drift, formatting, TypeScript, the clean production build, and `pnpm audit --prod --audit-level high` are green. Two scans of a disposable archive of the exact checkpoint take 61,901.396 and 15,656.300 ms and produce 256 byte-identical rows totaling 608,739 bytes with SHA-256 `ea1d91d90c2eccb0ed3138a6da1293ef1608bec2196dd73e8fb9f547d9cb26e4`; 225 rows are fixture paths, 31 are production-source paths, and all 165 structured framework rows survive. Exactly one LiquidJS row retains source `src/server.js:8`, sink `src/renderer.js:6`, CWE-94, ten ordered propagators, and exact `liquidjs@10.25.7` provenance, while the source-identical 10.26.0 twin is absent. All seven exact-source workflows pass: Node `32753841917`, container `32753841865`, Windows GUI `32753841933`, Linux GUI `32753841848`, Java `32753841909`, .NET `32753841877`, and Go `32753841858`. The repository remains public on default branch `main`; disposable archives, isolated installs, research packages, and partial reports are removed after acceptance.
- Added `node-http-velocity-template-rce` for [GHSA-7gfh-x38p-prh3 / CVE-2026-73649](https://github.com/advisories/GHSA-7gfh-x38p-prh3). The model requires attacker-controlled HTTP data in argument zero of official Velocity.js `render`, or in official `parse` whose AST reaches official `Compile` and then `render`, plus nearest exact production or fresh declaration-consistent npm v2/v3 proof through 2.1.6. It supports named and aliased exports, namespace/default and TypeScript import-equals receivers, CommonJS destructures/receivers/direct members, direct-require rendering, stable one-hop aliases, retained and immediate compile paths, multiline calls, and same-file or relative-import multi-hop reachability. Version 2.1.7+, prereleases, wrong or development-only packages, lockfile-free ranges, stale/inconsistent/v1 locks, package-only use, trusted templates with remote context only, parse-only or Compile-without-render flows, local lookalikes, default-call guesses, shadowing, binding/AST/template reassignment, replaced members, and tests/examples remain negative. Source-identical fixtures change only Velocity.js 2.1.6 to 2.1.7. Their self-checking witness never invokes a shell, listener, filesystem API, or network API: on Windows Node 24.15.0 and Ubuntu/WSL Node 22.23.1, 2.1.6 follows inherited `constructor.constructor` and returns only `process.version`, while 2.1.7 leaves `$r` unresolved. Nine focused tests pass 31 assertions. Exact-commit self-review then showed that the 96-row global inventory ceiling let the new valid fixture displace an existing production-source signal even though the byte budget was almost entirely unused. The ceiling now matches the existing 128-row cross-file and multi-hop bounds; file, candidate, per-file, and 8 MiB inventory limits remain unchanged. The strict pair advances the canonical benchmark to 95 exploit/control pairs, 190 cases, and 570 repeated scans.
- Final acceptance for the Velocity.js model and inventory-retention correction is green at exact source checkpoint `b83f62fe32afbd66e5602676eb034f14bda65a34`. The authoritative native Windows Bun 1.3.14 suite passes 1,427 tests and 10,794 assertions across 160 files with 20 intentional platform/environment skips, zero failures, and a 394.48-second runtime. Focused capacity, Velocity.js, and canonical-benchmark coverage passes 90 tests and 2,693 assertions with one intentional symlink skip; adjacent JSONata/vm2 coverage, generated-model drift, formatting, TypeScript, the clean production build, and `pnpm audit --prod --audit-level high` are green. Two inventories of a disposable exact-commit archive take 12,726.665 and 13,012.667 ms and produce 128 byte-identical rows totaling 327,664 bytes with SHA-256 `c97472cc0d5a67b899d77b3d244d16941d1379b3a8cb22ec0fa0ab8da7acaae9`; 117 rows are fixture paths and 11 are production-source paths. Exactly one Velocity.js row retains source `src/server.js:8`, sink `src/renderer.js:4`, CWE-94, ten ordered propagators, and exact `velocityjs@2.1.6` provenance, while the source-identical 2.1.7 twin is absent. Strict Windows and Ubuntu/WSL inspection validates the same 251-entry npm archive with SHA-256 `f014ff63b0575a2f76f1f4af255e9eda85de36dcbc3d60ec554b9c1a73bf58d8`; fresh installs validate public import, executable CLI, and all 79 bundled files. Windows WPF and Ubuntu/WSL Avalonia Release builds complete with zero warnings or errors; Windows passes 7/7 core and 3/3 shared tests, while Linux passes 7/7 core, 3/3 shared, and 2/2 headless tests. All seven exact-source workflows pass: Node `32748045375`, container `32748045376`, Windows GUI `32748045300`, Linux GUI `32748045380`, Java `32748045478`, .NET `32748045326`, and Go `32748045310`. The repository is public on default branch `main`; generated archives, isolated consumers, exact-commit self-scan data, and test reports are removed after acceptance.
- Added `node-http-vm2-host-proto-sandbox-escape` for [GHSA-cfcw-xp6x-25gj / CVE-2026-47698](https://github.com/advisories/GHSA-cfcw-xp6x-25gj) and `node-http-vm2-wildcard-builtin-host-exposure` for [GHSA-m5w8-4gq2-6f8x](https://github.com/advisories/GHSA-m5w8-4gq2-6f8x). The first model requires attacker-controlled HTTP data to reach an official `VM.run`; the second requires the same reachability into `NodeVM.run` plus a statically resolved `builtin: ["*"]` configuration that leaves `os` or `dns` exposed. Both require nearest exact production or fresh declaration-consistent npm v2/v3 proof through vm2 3.11.5. Named and aliased imports, namespace/default and TypeScript import-equals receivers, CommonJS destructures/receivers/direct members, stable one-hop constructor aliases, retained and immediate instances, source-preserving `VMScript`, and same-file or multi-hop wrappers are supported. Version 3.11.6+, prereleases, wrong or development-only packages, lockfile-free ranges, stale/inconsistent/v1 locks, package-only or trusted-code use, NodeVM without wildcard builtins, complete `-os`/`-dns` cutouts, demonstrably inert literal replacements for both modules, unknown local lookalikes, shadowing, reassigned constructors/instances, replaced `run` methods, and tests/examples remain negative. Unknown replacement identifiers do not suppress review. The cross-file and multi-hop output ceilings rise from 64 to 128 after the whole-repository regression proved that late model families could otherwise be silently omitted; file and byte ingestion bounds remain unchanged. Source-identical fixtures change only vm2 3.11.5 to 3.11.6. Their bounded dual witness never invokes a shell or host-mutating API: on Windows Node 24.15.0 and Ubuntu/WSL Node 22.23.1, 3.11.5 recovers only `process.version` through the dangerous host-prototype chain and reads only `os.hostname()` through wildcard NodeVM, while 3.11.6 blocks the first and denies `os`. Nine focused Windows and WSL tests pass 31 assertions. The strict pair advances the canonical benchmark to 94 exploit/control pairs, 188 cases, and 564 repeated scans.
- Final acceptance for the vm2 sandbox-boundary models is green at exact implementation checkpoint `450a2eb9fa072bb5bead82a95b26b2b10bb1b742`. The authoritative Windows Bun 1.3.14 suite passes 1,418 tests and 10,752 assertions across 159 files with 20 intentional platform/environment skips, zero failures, and a 374.08-second runtime. Generated-model drift, repository formatting, TypeScript, the clean production build, the focused Windows and WSL lane, both exact-package witnesses, and `pnpm audit --prod --audit-level high` are green. Two compiled inventories of a disposable exact-commit archive take 30,581.468 and 12,028.033 ms and produce 96 byte-identical rows totaling 249,667 bytes with SHA-256 `f046c49dc44d38d3a412264dc875b06becff816874f7fcea3d9a719dbbdf4515`; 95 rows are fixture paths. The single vm2 row retains source `src/server.js:8`, sink `src/sandbox.js:5`, CWE-94/CWE-693, ten ordered dataflow/dependency propagators, and exact vm2 3.11.5 provenance, while the source-identical 3.11.6 twin is absent. Strict inspection validates a 251-entry, 1,759,566-byte npm archive with SHA-256 `da5ec27cf059fa353113356805620b49a1739f83e6d61428dafd93e321979c61`; one fresh Windows install adds 67 packages and two fresh Ubuntu Node 22.23.1 installs add 75 packages each, with public import, executable CLI, and all 79 bundled plugin files validated every time. Windows builds without warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `c18bbc7c73dbade52d339f997c9b89272cd230859eec2c3ad1189b859204a439`. Ubuntu/WSL locked restores and builds without warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass: Node `32739060455`, Windows GUI `32739060411`, Linux GUI `32739060359`, container `32739060378`, .NET `32739060350`, Go `32739060382`, and Java `32739060328`. The repository remains public on default branch `main`; generated archives, isolated consumers, exact-commit self-scan data, and test reports are removed after acceptance.
- Added `node-keystone-graphql-negative-take-bypass` for [GHSA-cqmq-8755-7xvh / CVE-2026-63421](https://github.com/advisories/GHSA-cqmq-8755-7xvh). The model requires an official `@keystone-6/core` `config` factory whose result reaches a default/CommonJS runtime export, a same-file or relative-imported lists object, an official queryable `list` with a finite positive integer `graphql.maxTake`, and nearest exact production or fresh declaration-consistent npm v2/v3 proof through 6.5.2. It supports named aliases, namespace/default and TypeScript import-equals receivers, CommonJS destructures/receivers, direct requires, exported configuration aliases and wrappers, relative list aliases, and referenced list options. Version 6.5.3+, prereleases, wrong or development-only packages, lockfile-free ranges, stale/inconsistent/v1 locks, unexported configurations, local lookalikes, reassigned factories, replaced receiver members, unresolved or nonpositive limits, query-omitted lists, and statically deny-all query access remain negative. Dynamic access controls remain reviewer-visible instead of being mistaken for a response-size bound. Source-identical fixtures change only 6.5.2 to 6.5.3. Their bounded real-package witness uses Keystone's public GraphQL context and an in-memory Prisma boundary without a listener or database: 6.5.2 passes `take: -5` through `maxTake: 3` and returns five rows, while 6.5.3 returns `KS_LIMITS_EXCEEDED` before Prisma. Five focused groups pass 22 assertions; the canonical benchmark advances to 93 exploit/control pairs, 186 cases, and 558 repeated scans.
- Final acceptance for the Keystone negative-take model is green at exact implementation checkpoint `38dd54e57a637b10f170514b8a2b861a6f839d48`. The authoritative Windows Bun 1.3.14 suite passes 1,409 tests and 10,710 assertions across 158 files with 20 intentional platform/environment skips, zero failures, and a 401.32-second runtime. Ubuntu/WSL Node 22.23.1 and Bun 1.3.14 pass the focused model/canonical lane with 21 tests and 1,609 assertions. Generated-model drift, repository formatting, TypeScript, a clean production build, and `pnpm audit --prod --audit-level high` are green with no known vulnerabilities. Fresh exact-package installs reproduce the 6.5.2 five-row bypass and the 6.5.3 `KS_LIMITS_EXCEEDED` control on both Windows and Ubuntu, then are removed. Two compiled inventories of a disposable exact-commit archive take 29,009.398 and 11,559.843 ms and produce 96 byte-identical rows totaling 246,222 bytes with SHA-256 `6ee66fcfc16fd1de3ee047c8e62236d8beb525b63229ee8f30b1f5995b2de214`; the single Keystone row retains source `src/keystone.js:4`, sink `src/schema.js:8`, CWE-20/CWE-770, and exact 6.5.2 provenance, while the 6.5.3 twin is absent. Strict package inspection validates a 251-entry archive with SHA-256 `18c1ac9fc54f0bcd6a54c437b545080964ed03f436aa204cda8b36a93a66d398`; an isolated install adds 67 packages and validates the public import, CLI, and all 79 bundled plugin files. Windows builds without warnings/errors and passes 7/7 core plus 3/3 shared tests. Ubuntu/WSL builds without warnings/errors and passes 7/7 core, 3/3 shared, and 2/2 Linux GUI tests. All seven exact-head workflows pass: Node `32733473591`, Windows GUI `32733473628`, Linux GUI `32733473611`, container `32733473531`, .NET `32733473579`, Go `32733473563`, and Java `32733473528`. Temporary archives, isolated installs, WSL witness directories, and self-scan trees are removed after acceptance.
- Added `node-http-tar-decompression-dos` for [GHSA-23hp-3jrh-7fpw / CVE-2026-59873](https://github.com/advisories/GHSA-23hp-3jrh-7fpw). The application model requires an official `tar` `t`/`list`/`x`/`extract`/`Parse`/`Unpack` binding, remote compressed-archive flow through an options file or dynamic options object or a directly piped request stream, and nearest exact production or fresh npm v2/v3 lock proof through 7.5.18. It distinguishes list, parse, and extract sinks under CWE-770; carries exact dependency provenance; supports namespace/default and TypeScript receivers, named aliases, CommonJS receivers/destructures, and direct requires; and follows the established same-file and relative-import wrapper graph. Version 7.5.19+, prereleases, fixed archives, create APIs, package-only use, wrong or development-only packages, lockfile-free ranges, stale/v1 locks, receiver reassignment, member replacement, wrapper shadows, and local lookalikes remain negative. `maxReadSize`, `maxDepth`, and upload-byte limits do not suppress the row because they do not bound cumulative expansion; explicit ratio/output/entry budgets remain reviewer-visible control leads. The shared npm lock verifier now rejects exact/caret/tilde resolutions below their declared minimum, removing stale-lock false positives across package-aware models while leaving complex registry ranges on the existing fail-safe path. Source-identical four-file fixtures change only `tar` 7.5.18 to 7.5.19. Their bounded real-package witness creates an 8,390,144-byte tar compressed to 8,242 bytes: 7.5.18 processes the 1017.97:1 archive, while 7.5.19 aborts at 1001.88 against its default 1000 ratio. The older linkpath negative control now pins 7.5.21 rather than 7.5.11 so it retains the original link repair while closing this and the later member-selection defect; this prevents a genuinely reachable cross-advisory finding from masquerading as a benchmark false positive. The strict pair advances the canonical corpus to 92 exploit/control pairs, 184 cases, and 552 repeated scans.
- Final acceptance for the node-tar decompression model is green at exact cross-advisory checkpoint `d989da6fd43da0b79655ed30072bd883ee7eb0b6`, following implementation checkpoint `30bb9bf9561ff5385f8d5c8c3de15785fb1b57fd`. The exact-head hosted Node matrix runs 1,424 tests across 157 files on every supported OS/runtime job: Windows passes 1,404 tests and 10,679 assertions with 20 intentional platform/environment skips and zero failures in 379.86 seconds, while Ubuntu Node 22 passes 1,420 tests and 10,755 assertions with four skips and zero failures in 254.18 seconds. The local authoritative pre-isolation suite passes 1,404 tests and 10,676 assertions with the same 20 skips and zero failures in 379.15 seconds; the final isolation-only delta is then covered by focused 33-test Windows and WSL lanes plus the exact-head hosted matrix. Generated-model drift, formatting, TypeScript, the production build, and `pnpm audit --prod --audit-level high` are green with no known vulnerabilities. Two compiled inventories of a disposable exact-HEAD archive take 15,671.349 and 11,508.399 ms and produce 96 byte-identical rows totaling 245,283 bytes with SHA-256 `5ee6ad5a84038fccab402764ffe8d186f758868562a507537240a7c21293adb3`; 94 rows are fixture paths. Exactly two decompression rows are legitimate: the dedicated 7.5.18 list fixture and the pre-existing 7.5.10 linkpath extraction fixture. Both the 7.5.19 decompression control and upgraded 7.5.21 linkpath control are absent. Strict package inspection validates a 251-entry, 1,737,587-byte npm archive with SHA-256 `3f99d91e335eeefe075465c3584c1e8ee21c5997472e32f510741c435a7304bc`; two isolated Windows installs add 67 packages each and validate the public import, CLI, and all 79 bundled plugin files. Windows builds without warnings or errors, passes 7/7 core and 3/3 shared tests, survives a hidden three-second startup, and publishes a 346,796-byte executable with SHA-256 `0e81411928b0a03d61078169679e5941bab31ee726a8b98f447584d09f3cf25c`. Ubuntu/WSL locked restores and builds without warnings or errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on their first run: Node `32728583530`, Windows GUI `32728583414`, Linux GUI `32728583461`, container `32728583481`, .NET `32728583599`, Go `32728583480`, and Java `32728583591`. Exact-commit archives, isolated installs, witness packages, and GUI publications are removed after acceptance.
- Added `node-http-jsonata-expression-rce` for [GHSA-66mm-25pp-rfff / CVE-2026-77415](https://github.com/advisories/GHSA-66mm-25pp-rfff), [GHSA-2943-5xfg-gq5f / CVE-2026-77414](https://github.com/advisories/GHSA-2943-5xfg-gq5f), and [GHSA-8gq3-vp5j-2grp / CVE-2026-77413](https://github.com/advisories/GHSA-8gq3-vp5j-2grp). The application model requires an official JSONata compiler, remote input in compiler argument zero, the returned compiled expression actually reaching `evaluate()`, and nearest exact production or fresh declaration-consistent npm v2/v3 proof in the complete reviewed union below 1.8.8 or from 2.0.0 through 2.2.0. It follows default aliases, namespace-default, TypeScript import-equals, CommonJS and direct-require callables, stable one-hop compiler aliases, immediate and retained compiled expressions, multiline calls, and same-file or multi-hop relative-import reachability. It reports the actual evaluation line with CWE-94 and exact dependency provenance. Patched, prerelease, wrong or development-only packages, lockfile-free ranges, inconsistent or v1 locks, package-only and compile-only use, trusted static expressions with remote evaluation data, unavailable import guesses, local lookalikes, shadowing, compiler/compiled-expression reassignment, member replacement, and tests/examples remain negative. Source-identical four-file fixtures change only 2.2.0 to 2.2.1. Their non-shell witness returns only `process.version`: 2.2.0 recovers the host `Function` constructor, while 2.2.1 rejects the same expression with `T1006`. The perfect-gate pair advances the canonical corpus to 91 exploit/control pairs, 182 cases, and 546 repeated scans.
- Final acceptance for the JSONata expression model is green at exact implementation checkpoint `c6ab68b6e43d7956d83bcbd48b3b603d9e9ad482`. The authoritative Bun 1.3.14 suite passes 1,398 tests and 10,636 assertions across 156 files with 20 intentional environment/platform skips, zero failures, and a 426.20-second runtime. An initial managed-sandbox pass was discarded after native Git, Windows ACL, and immutable workbench-inventory operations were denied; the unchanged authorized native pass closes every affected case. Generated-model drift, repository formatting, TypeScript, a clean production build, the production high-severity audit, and both Windows and Ubuntu/WSL JSONata witnesses are green. Two compiled inventories of a clean exact-HEAD archive take 29,810.659 and 11,471.329 ms and produce 96 byte-identical rows totaling 243,517 bytes with SHA-256 `4c0b7070e2d18458142f5bfc30c75ae69f311bdf40d1754b1129850b78edae05`; 93 rows are fixture paths. The only JSONata row retains source `src/server.js:8`, evaluation sink `src/storage.js:6`, CWE-94, and `jsonata@2.2.0:manifest-exact:expression-sandbox-escape`, while the source-identical 2.2.1 twin is absent. Strict package inspection validates a 251-entry, 1,734,247-byte npm archive with SHA-256 `6a4455161c419315c75c109e5eff6cedc0023975b50dcd713ded1f5e5861ef53`; two isolated Windows installs add 67 packages each and validate the public import, CLI, and all 79 bundled plugin files. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `3d8061b89973d5637c800cc3466dd5faffa2b5bf3dd573ded6f1666b3d13a63f`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on their first run: Node `32722627978`, Windows GUI `32722628054`, Linux GUI `32722627970`, container `32722628038`, .NET `32722628149`, Go `32722628236`, and Java `32722628016`. Generated fixture installs, npm caches, exact-commit archives, the packed artifact, and application publications are removed after acceptance.
- Added `node-authjs-configuration-error-fail-open` for [GHSA-8fpg-xm3f-6cx3 / CVE-2026-73421](https://github.com/advisories/GHSA-8fpg-xm3f-6cx3). The model requires an official stable `next-auth` factory, its generated non-reassigned `auth` wrapper, a concrete middleware/route allow-or-deny consequence based only on the auth object's existence, and nearest exact production prerelease or fresh declaration-consistent npm v2/v3 proof from 5.0.0-beta.0 through 5.0.0-beta.31. It follows default aliases, namespace-default and TypeScript import-equals receivers, CommonJS defaults and exported members, generated-wrapper aliases, relative imports, uniquely resolved `@/` or `~/` imports, deployed `callbacks.authorized` decisions through proxy/middleware exports, inline/destructured callbacks, derived booleans, and direct `auth()` results. Version 5.0.0-beta.32 or later, v4, wrong or development-only packages, lockfile-free ranges, inconsistent or v1 locks, ambiguous aliases, reassignment, undeployed callbacks, local lookalikes, inert logging, enrichment-only use, tests/examples, and concrete `auth.user`, stable identifier, role, or permission checks remain negative. The shared Node dependency prover now accepts canonical exact SemVer prereleases and safely locked prerelease ranges, expanding future advisory coverage without accepting registry URLs, workspace protocols, or unlocked ranges. Source-identical fixtures change only beta.31 to beta.32. Their published-package witness induces a real missing-provider-endpoint configuration error without opening a listener or making an outbound request: beta.31 passes a truthy `{message}` body to the callback and returns 204, while beta.32 passes `null` and returns 401. Nine focused groups pass 36 assertions. The perfect-gate pair advances the canonical corpus to 90 exploit/control pairs, 180 cases, and 540 repeated scans.
- Final acceptance for the Auth.js configuration-error model is green at exact implementation checkpoint `cd70d9fdf3593aee6e2bbafb62f03a5185597a0f`. The authoritative Bun 1.3.14 suite passes 1,390 tests and 10,595 assertions across 155 files with 20 intentional environment/platform skips, zero failures, and a 360.39-second runtime. Generated-model drift, formatting, TypeScript, the clean production build, the high-severity production audit, and the real beta.31/beta.32 witnesses on Windows and Ubuntu/WSL are clean. Two compiled inventories of a clean exact-HEAD archive take 31,748.603 and 11,600.654 ms and produce 96 byte-identical rows totaling 241,719 bytes with SHA-256 `ded03793bc5be9cb870749038650cabc440a6ceadd1029a2597aee90e99ffa7d`; 92 rows are fixture paths. The new positive uniquely retains source `benchmarks/fixtures/node-authjs-configuration-error-fail-open/src/middleware.ts:4`, sink line 5, CWE-636/CWE-285, and `next-auth@5.0.0-beta.31:manifest-exact:truthy-configuration-error-auth-object` provenance, while the source-identical beta.32 twin is absent. Strict package inspection validates a 251-entry, 1,706,702-byte npm archive with SHA-256 `2a5bdf0473e475fe15c446b743e6535997f09f1b56bdb31f2ad6199c09b8745b`; three isolated Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with the public import, CLI, and all 79 bundled plugin files validated every time. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `618ba3e6774197d4c1bf329d028c46ce9a3712e3ea2ffbfbfc460c18efa0c653`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on their first run: Node `32718222612`, Windows GUI `32718222660`, Linux GUI `32718222578`, container `32718222618`, .NET `32718222615`, Go `32718222595`, and Java `32718222658`. Fixture instructions now name Bun, the runtime used for the package oracle.
- Added `node-opcua-server-username-token-nonce-bypass` for [GHSA-mq36-523m-x7vv / CVE-2026-54155](https://github.com/advisories/GHSA-mq36-523m-x7vv). The model requires an official `OPCUAServer` construction with an explicit usable application `userManager`, an encrypted username-token policy, the same non-reassigned instance reaching `start()`, and nearest exact production or fresh declaration-consistent npm v2/v3 proof. Published source inspection establishes that aggregate/server releases 2.165.0, 2.165.1, and 2.165.2 all decrypt `UserNameIdentityToken.password` without verifying its trailing session nonce; 2.166.0 introduces the nonce comparison and is the repaired boundary. Named and aliased ESM, namespace, TypeScript import-equals, CommonJS receiver/destructure/direct-member, same-file startup, and an exported instance started through a relative import are supported. Default deny-all, null, empty, or certificate-only managers, literal `SecurityPolicy.None`-only endpoints, dynamic unproved policy arrays, package-only or client-only use, inert construction, repaired/development-only/wrong packages, lockfile-free ranges, inconsistent/v1 locks, reassignment, member replacement, wrapper shadows, local lookalikes, and tests/examples remain negative. Source-identical exact-lock fixtures change only 2.165.2 to 2.166.0. Their real-package witness generates an ephemeral RSA key and encrypts a correct password plus nonce A once: 2.165.2 accepts the same ciphertext in sessions A and B and passes a four-byte forged blob to an empty-password-compatible manager, whereas 2.166.0 accepts only session A and rejects both nonce violations before the manager is called. Empty-password authentication impact is reported only when the deployed manager accepts it; the general replay path is kept distinct. Windows Node and Ubuntu/WSL Node reproduce identical vulnerable and repaired results. Eight focused groups pass 53 assertions, and the adjacent/canonical lane passes 31 tests and 1,655 assertions. The perfect-gate pair advances the canonical corpus to 89 exploit/control pairs, 178 cases, and 534 repeated scans.
- Final acceptance for the node-opcua username-token model is green at exact implementation checkpoint `4a0e6abd3b888c0bd95bd44889e69100b55c502c`. The authoritative Bun 1.3.14 suite passes 1,381 tests and 10,548 assertions across 154 files with 20 intentional environment/platform skips, zero failures, and a 341.04-second runtime. Generated-model drift, formatting, TypeScript, the clean production build, both Windows and Ubuntu real-package witnesses, and the high-severity production audit are clean. Two compiled inventories of a clean exact-HEAD archive produce 96 byte-identical rows totaling 240,432 bytes with SHA-256 `335ec260d3b66a6fd3d9c0fa3e4e2f1294c64b000f33ba678c35b2d70caebc25`; exactly one username-token row retains source `benchmarks/fixtures/node-opcua-server-replayable-username-token/src/server.mjs:11`, sink line 8, CWE-347, and `node-opcua@2.165.2:manifest-exact:username-token-missing-nonce-binding` provenance, while the source-identical 2.166.0 twin is absent. Strict package inspection validates a 251-entry, 1,709,475-byte npm archive with SHA-256 `479c2fd1ef8413f72d7c1f271067230295f2247471f92574548ac68aee98f377`; three isolated Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with the public import, CLI, and all 79 bundled plugin files validated every time. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `963acd82201a7d796f0ab1347564502513dc47e694f5d859eeacd20a7dbd0206`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on their first run: Node `32713523593`, Windows GUI `32713523567`, Linux GUI `32713523638`, container `32713523595`, .NET `32713523615`, Go `32713523602`, and Java `32713523597`.
- Added `node-opcua-server-nonce-cache-dos` for [GHSA-6wvw-vrw4-363w / CVE-2026-54156](https://github.com/advisories/GHSA-6wvw-vrw4-363w). The model requires an official `OPCUAServer` construction that reaches `start()` under nearest exact production or fresh declaration-consistent npm v2/v3 proof in the reviewed `node-opcua <=2.165.0` range; it does not turn dependency presence, client-only use, or inert construction into a finding. Named and aliased ESM, namespace, TypeScript import-equals, CommonJS receiver/destructure/direct-member, same-file startup, and an exported instance started through a relative import are supported. Post-review versions, wrong or development-only packages, lockfile-free ranges, inconsistent/v1 locks, invalid higher-precedence shrinkwraps, reassigned bindings or instances, replaced `OPCUAServer` or `start` members, wrapper shadows, local lookalikes, and tests/examples remain negative. Exact 2.165.0 package evidence stores every nonempty nonce in a process-global object; 2.168.0 replaces it with timestamped entries, a four-hour TTL, and a 50,000-entry ceiling. Source-identical fixtures change only the aggregate package version. A bounded witness inserts 50,001 unique 32-byte nonces and replays the first: Windows Node and Ubuntu/WSL Node both show 2.165.0 retaining it and 2.168.0 evicting it, without starting a listener or attempting memory exhaustion. Seven focused groups pass 59 assertions; the widened Windows lane passes 117 tests and 1,439 assertions with one intentional symlink skip, and the focused Ubuntu/WSL lane passes 26 tests and 230 assertions. The strict pair advances the canonical corpus to 88 exploit/control pairs, 176 cases, and 528 repeated scans.
- Final acceptance for the node-opcua nonce-cache model is green at exact implementation checkpoint `05ad9dc9ac3b4428e2bacd9542120c8a40109b9d`. The authoritative Bun 1.3.14 suite passes 1,373 tests and 10,484 assertions across 153 files with 20 intentional environment/platform skips, zero failures, and a 324.65-second runtime. Generated-model drift, formatting, TypeScript, the clean production build, both bounded witnesses, and the high-severity production audit are clean. Two compiled inventories of a private exact-HEAD archive take 10,774.839 and 10,780.323 ms and produce 96 byte-identical rows totaling 239,691 bytes with SHA-256 `3d74e231f40ccaa39d2323379367b169b70750399a505e51c6f0a05120452c5d`; 92 rows are fixture paths. The new positive uniquely retains source `src/server.mjs:6`, sink `src/server.mjs:3`, CWE-770/CWE-400, and `node-opcua@2.165.0:manifest-exact:unbounded-session-nonce-cache` provenance, while the source-identical 2.168.0 twin is absent. Strict package inspection validates a 251-entry, 1,705,466-byte npm archive with SHA-256 `341e86c22b0255d442c246ba2dc7870dd8fcf45a728d96b9a7814c3c44be67b4`; three isolated Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `5be3cc27b77041d2e5298568a3438332c2a750cc92bcfa791e53fb18333fbe29`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass: Node `32708433373`, Windows GUI `32708433359`, Linux GUI `32708433350`, container `32708433332`, .NET `32708433391`, Go `32708433370`, and Java `32708433434`.
- Added `node-http-nanoid-size-dos` for [GHSA-28wg-ghj8-5hjv / CVE-2026-67214](https://github.com/advisories/GHSA-28wg-ghj8-5hjv) and [GHSA-2v37-7h3g-55p8 / CVE-2026-67213](https://github.com/advisories/GHSA-2v37-7h3g-55p8). The model distinguishes two executable causes instead of treating package presence as a finding: a remotely controlled negative size reaching the callable 1.x/2.x or named 3.x+ `nanoid/non-secure` API before 3.3.16 or 5.1.16, including every 4.x release, and a remotely controlled zero or non-integer default size reaching a 3.x+ main-package `customAlphabet`/`customRandom` factory before the Node-entry repair at 3.3.17 or 5.1.6. It resolves official legacy callable/default exports, named aliases, namespaces, TypeScript import-equals, CommonJS receivers, destructures, direct members, assigned factories, and immediately invoked ESM/CommonJS factories while rejecting call shapes unavailable on the proven major; requires exact production or fresh declaration-consistent npm v2/v3 evidence; preserves same-file and typed cross-file wrapper reachability; and records CWE-835/CWE-400 with exact dependency provenance. Repaired releases, development-only or wrong packages, unresolved ranges, stale/v1 locks, invalid higher-precedence shrinkwraps, fixed input, main-package `nanoid`, non-invoked or replaced factories, identifier/member reassignment, wrapper shadows, tests/examples, and safe per-call overrides remain negative. The default-size branch requires an actual generator call that uses the factory default: `customAlphabet("abc", remote)(12)` is excluded, as is `customAlphabet("abc")(0)`, which is not the reviewed zero-default loop. A negative-size guard must terminate the path before the sink; a zero-default guard must prove both integer input and a positive bound so `NaN` cannot retain a zero work step. Source-identical four-file 5.1.15/5.1.16 fixtures carry one request size through three wrappers. Bounded real-package witnesses reproduce the 5.1.15 infinite loop and normal 5.1.16 empty result on Windows Node and Ubuntu/WSL Node without hanging the test runner. Ten focused groups pass 92 assertions; the widened Windows lane passes 114 tests and 2,882 assertions with one intentional platform skip, and the clean WSL lane passes 33 tests and 1,678 assertions. Formatting, generated-model drift, and TypeScript are clean. The strict pair advances the canonical corpus to 87 exploit/control pairs, 174 cases, and 522 repeated scans; generated installs and the isolated research tree are removed.
- Final acceptance for the nanoid availability model is green at exact implementation checkpoint `83b650766e30fdeb2b2d99fb67f1ae3cf3db1dcb`. The authoritative Bun 1.3.14 suite passes 1,366 tests and 10,414 assertions across 152 files with 20 intentional environment/platform skips, zero failures, and a 360.97-second runtime. Generated-model drift, formatting, TypeScript, the clean production build, both package witnesses, and the high-severity production audit are clean. Two compiled inventories of a private exact-HEAD archive take 25,725.901 and 11,064.664 ms and produce 96 byte-identical rows totaling 239,094 bytes with SHA-256 `aabada18798ad2378460ee4d85bf49b245da70ea05f4b1511d33d0629fe51c9a`; 92 rows are fixture paths. The new positive uniquely retains source `src/server.mjs:4`, sink `src/storage.mjs:4`, CWE-835/CWE-400, ten propagators, and exact `nanoid@5.1.15` runtime provenance, while the source-identical 5.1.16 twin is absent. Strict package inspection validates a 251-entry, 1,699,985-byte npm archive with SHA-256 `293b5779d42a9a36a328ddb50c056cd79d34205becce6f8ce55d7ec044a0c3ee`; three isolated Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is removed. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `5c217ff5db9d1d231a1d109cb7ce6e08b809c59586001a8d6c40fd9891fc4cdb`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass: Node `32703837882`, Windows GUI `32703837786`, Linux GUI `32703837929`, container `32703837835`, .NET `32703837863`, Go `32703837810`, and Java `32703837792`.
- Added `node-socketio-server-transitive-parser-dos`, extending GHSA-2m8v-j782-fhvr / CVE-2026-69185 coverage from applications that import `socket.io-parser` directly to the normal public `socket.io` server surface. The model requires an official named, aliased, namespace, TypeScript import-equals, CommonJS constructor, callable CommonJS, or direct callable binding; a server actually exposed through a numeric port or an attached HTTP server that listens; default parser selection; a direct production `socket.io` dependency; and a declaration-consistent npm v2/v3 lock or shrinkwrap proving both the installed parent and the transitive `socket.io-parser` selected by its own dependency range. It supports hoisted and nested child installs and the callable 2.x server API, but rejects package-only presence, repaired children, absent/legacy/inconsistent locks, child versions outside the parent's range, higher-precedence invalid shrinkwraps, custom/dynamic/spread-capable parser options, non-listening targets, unexposed construction, wrong/development-only packages, reassigned bindings, instances, or attachment targets, replaced `Server` or `_parser` members, and test/example paths. Parent version is deliberately not a proxy for safety: source- and parent-identical `socket.io@4.8.3` fixtures resolve either vulnerable parser 4.2.6 or repaired parser 4.2.7. A real Engine.IO/WebSocket witness sends `450-["evt"]` and then bounded distinct binary frames. Windows Node 24.15.0 and Ubuntu/WSL Node 22.23.1 both show 4.2.6 retaining all 512 4 KiB frames (2,097,152 bytes), while 4.2.7 retains none and closes the client through the server parser-error path. The perfect-gate benchmark requires high severity, exact CWE-400/CWE-20/CWE-754, validation, attack path, code evidence, stable detection, and zero false positives. The widened Windows lane passes 121 tests and 2,891 assertions with one intentional POSIX-symlink skip; Ubuntu/WSL passes all 122 tests and 2,892 assertions. The exact implementation commit's authoritative Bun 1.3.14 suite passes 1,356 tests and 10,311 assertions across 151 files with 20 intentional environment/platform skips, zero failures, and a 305.83-second runtime. The strict pair advances the canonical corpus to 86 exploit/control pairs, 172 cases, and 516 repeated scans.
- Final acceptance for the transitive Socket.IO server parser model is green at exact implementation checkpoint `1f6acfffd31965a204ea2dc406fb705951361cf1`. Generated-model drift, formatting, TypeScript, the clean production build, and the high-severity production audit are clean. Two compiled inventories of an isolated tracked-head archive take 25,386.308 and 10,870.209 ms and produce 96 byte-identical rows totaling 237,264 bytes with SHA-256 `446c16ebb95e166f4354c195cfba34e115aa2a0efd1619955418cdd24255dfdf`; 92 rows are fixture paths. The new positive uniquely retains source `src/server.mjs:6`, sink `src/server.mjs:5`, CWE-400/CWE-20/CWE-754, and separate exact parent and transitive-child dependency propagators, while the source- and parent-identical 4.2.7 twin is absent. Strict package inspection validates a 251-entry, 1,688,794-byte npm archive with SHA-256 `d95bf869b508c2fe26276f106a9146e1f522f3ed87bd2b72951960859688e472`; three isolated Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is removed. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `ff521487cbb8950678e652afd2048bf89cb222aac99b27250f210fc96ca807bf`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass: Node `32699988190`, Windows GUI `32699988187`, Linux GUI `32699988144`, container `32699988218`, .NET `32699988212`, Go `32699988250`, and Java `32699988232`.
- Added `node-http-socketio-parser-zero-attachment-dos` for high-severity GHSA-2m8v-j782-fhvr / CVE-2026-69185. The model requires remote request or socket packet data in `Decoder.add`, an official `socket.io-parser` Decoder binding, a module-scope persistent decoder, and nearest exact production or fresh declaration-consistent npm v2/v3 proof in one of the complete affected branches: below 3.3.6, 3.4.0 through 3.4.4, or 4.0.0 through 4.2.6. It resolves named and aliased imports, namespace and interoperable default receivers, TypeScript import-equals, CommonJS receivers, destructures, and direct members. Versions 3.3.6, 3.4.5, and 4.2.7 or later, package-only presence, wrong/development-only packages, lockfile-free ranges, inconsistent/v1 locks, Encoder use, fixed input, request-local decoders, identifier or member replacement, wrapper shadows, and test/example paths remain negative. Reviewer guidance preserves the exact `50-["evt"]` state transition, rejects `maxAttachments` as a repair for the zero-count invariant, and limits impact to demonstrated CWE-400 memory exhaustion with CWE-20/CWE-754 input and exceptional-condition weaknesses. Official CodeQL models Socket.IO server/client event sources but not this pre-callback parser state defect; authenticated source searches found no `socket.io-parser` or `maxAttachments` support in current CodeQL or public Semgrep rules, and the reference scanner has no matching model. A real-package matrix validates all three repair branches. Source-identical four-file 4.2.6/4.2.7 fixtures retain request source `server.js:7`, persistent sink `storage.js:6`, exact runtime provenance, and bounded witnesses. On both Windows Node 24.15.0 and Ubuntu/WSL Node 22.23.1, 4.2.6 emits the crafted packet and retains 2,048 distinct 4 KiB frames (8,388,608 bytes), while 4.2.7 throws `Illegal attachments`, emits nothing, and retains zero frames. Seven direct groups plus the canonical corpus pass 23 tests and 1,560 assertions. The strict pair advances the corpus to 85 exploit/control pairs and 510 repeated scans; generated installs and the isolated research tree are removed.
- Final acceptance for the Socket.IO parser state model is green at exact implementation checkpoint `2ee7f413aaf94171ce5f497bbcae90e98733e393`. The authoritative Bun 1.3.14 suite passes 1,349 tests and 10,235 assertions across 150 files with 20 intentional environment/platform skips, zero failures, and a 317.93-second runtime. The focused Windows and Ubuntu/WSL lanes each pass 145 tests and 2,949 assertions with one platform-specific skip. Generated-model drift, formatting, TypeScript, the clean production build, both cross-platform witnesses, and the high-severity production audit are clean. Two compiled inventories of the exact tracked-head archive take 28,605.295 and 11,458.682 ms and produce 96 byte-identical rows totaling 236,314 bytes with SHA-256 `fdf81dbc99d2d5c5da5f9ed5f0a88678577180a217d912e7d557716540681727`; 92 rows are fixture paths. The new positive uniquely retains source `server.js:7`, sink `storage.js:6`, CWE-400/CWE-20/CWE-754, ten propagators, and exact `socket.io-parser@4.2.6` runtime provenance, while the 4.2.7 twin is absent. Strict package inspection validates a 251-entry, 1,678,983-byte npm archive with SHA-256 `6806e82f499f212924a6399ddacdbb288b0384abfc3c5578d68e531a2f145b1e`; three isolated Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is removed. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `44778cd24af95482636af8fca97c99a237baf91d2b2727e2d506a70c4173ebbc`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass: Node `32696402540`, Windows GUI `32696402589`, Linux GUI `32696402571`, container `32696402609`, .NET `32696402531`, Go `32696402602`, and Java `32696402617`.
- Added `node-http-brace-expansion-dos` for high-severity GHSA-rgw5-rvv9-x895 / CVE-2026-69152, the intermediate-array and padded-sequence resource-exhaustion paths that bypass the earlier output-length limit. The model requires nearest exact production or fresh declaration-consistent npm v2/v3 proof in `<1.1.18`, `>=2.0.0 <2.1.4`, `>=3.0.0 <3.0.6`, every 4.x release, or `>=5.0.0 <5.0.9`; a remote request value must reach the exact API exported by that major line. It resolves 1.x/2.x callable CommonJS/default bindings, 3.x/4.x default ESM or CommonJS `.default`, and 5.x named/CommonJS `.expand`, including aliases, namespaces, TypeScript import-equals, destructures, direct members, and inline requires. Repaired releases, package-only presence, wrong-major APIs, lockfile-free ranges, inconsistent/v1 or development-only metadata, fixed inputs, reassigned identifiers or members, wrapper shadows, wrong packages, and test/example paths remain negative. Literal positive `max` plus `maxLength` options are retained as candidate work-bound evidence, not suppression, because the reviewed defect bypasses the prior cumulative-output control; spread-bearing options receive no control credit. Official CodeQL currently has six `brace-expansion` references that are only adapted regex-test attribution and no `EXPANSION_MAX_LENGTH` reference; current public Semgrep rules have neither, while the reference scanner sees only a repaired lockfile dependency and has no application model. A real-package matrix across 1.x, 2.x, 3.x, 4.x, and 5.x confirms the export boundaries. On the bounded 4,011-byte padded witness, 5.0.8 and 5.0.9 return the same 999 values and 3,996,999 output characters with identical SHA-256 `81c8707f87bfc8296e30d5a462fce26265b195b5db6df1160ba7da477f61f8c2`, but take 1,769.885 ms and 25.389 ms respectively. Source-identical four-file 5.0.8/5.0.9 fixtures retain request source `server.js:7`, sink `storage.js:4`, ten dataflow/dependency propagators, and bounded executable witnesses. Seven direct regression groups pass 79 assertions, and the strict pair advances the canonical corpus to 84 exploit/control pairs and 504 repeated scans.
- Final acceptance for the brace-expansion availability model is green at exact implementation checkpoint `1e59d8d48f5ae2079b94cb6d010f545a0b53a004`. The authoritative Bun 1.3.14 suite passes 1,342 tests and 10,163 assertions across 149 files with 20 intentional environment/platform skips, zero failures, and a 384.58-second runtime. The corrected focused lane passes 96 tests and 2,694 assertions with one Windows-only symlink skip; native Ubuntu/WSL passes all 97 tests and 2,695 assertions. Generated-model drift, formatting, TypeScript, the production build, both executable witnesses, and the high-severity production audit are clean. Two compiled inventories of a private root-level tracked archive take 11,029 and 10,475 ms and produce 96 byte-identical rows totaling 234,777 bytes with SHA-256 `e75e365ca41f0413f86cd75ada477b91826a2a492225a01c9831f96426501ca8`; 92 rows are benchmark-fixture paths. The new positive uniquely retains source `server.js:7`, sink `storage.js:4`, CWE-400/CWE-407, ten propagators, and exact `brace-expansion@5.0.8` runtime provenance, while the 5.0.9 twin is absent. Strict package inspection validates a 251-entry, 1,675,454-byte npm archive with SHA-256 `11d48c6ad675ff1b3f5a8834936789b327dddb41549b327a039044899860884a`; three isolated Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is removed. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `916f955afb64067136ae6f71bb3335c06c4254b7b7198e81650742d0486902f9`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass: Node `32694265037`, Windows GUI `32694265091`, Linux GUI `32694265008`, container `32694265040`, .NET `32694265051`, Go `32694264991`, and Java `32694265083`.
- Added `node-http-nodemailer-raw-access-policy-bypass` for reviewed high-severity GHSA-p6gq-j5cr-w38f. The model requires nearest exact production or fresh declaration-consistent npm v2/v3 proof through 9.0.0, an official non-reassigned `nodemailer` `createTransport` binding and transporter, literal `disableFileAccess: true` and/or `disableUrlAccess: true` on that transporter or message, one proven request-controlled message object supplying both message-level `raw` and attacker-selected `to`, and the exact `sendMail` call. Effect-specific provenance retains CWE-73/CWE-200 for file access and CWE-918/CWE-200 for URL access; a combined row is emitted only when both deny policies are configured. Nodemailer 9.0.1 or later, package-only presence, ordinary attachments or text/HTML content, split uncorrelated sources, missing/false policies, fixed raw data or recipient, replaceable object spreads, wrong or development-only packages, lockfile-free ranges, inconsistent/v1 locks, reassigned/shadowed/lookalike factories or transporters, non-`sendMail` APIs, and test/example paths remain negative. Official CodeQL recognizes Nodemailer mail sending but models only text, HTML, recipient, sender, and subject; it has no `raw` or access-policy model. Current public Semgrep rules and the reference scanner have no Nodemailer model. A safely removed real-package matrix confirms 9.0.0 delivers temporary-file and loopback-response sentinel bytes through `raw` while the ordinary attachment control fails with `EFILEACCESS`; 9.0.1 rejects the two raw cases with `EFILEACCESS` and `EURLACCESS`. Source-identical four-file fixtures preserve one complete request message through three wrappers, the exact sink at `mailer.js:11`, both broken policy controls at line 3, and explicit runtime-dependency provenance. Seven direct groups and the canonical integrity lane pass 23 tests and 1,505 assertions on Windows. Both package-backed witnesses pass on Windows Node 24.15.0 and Ubuntu/WSL Node 22.23.1 and remove their installs. The strict pair advances the corpus to 83 exploit/control pairs and 498 repeated scans; formatting and TypeScript are clean.
- Final acceptance for the Nodemailer raw access-policy model is green at exact implementation checkpoint `7c5048519c8afe881f556cefdd7b513b6858529d`. The authoritative Bun suite passes 1,335 tests and 10,073 assertions across 148 files with 20 intentional environment/platform skips, zero failures, and a 374.66-second runtime. Generated-model drift, formatting, TypeScript, the production build, the executable witnesses, and the high-severity production audit are clean. Two compiled inventories of a private root-level tracked archive take 22,356 and 11,226 ms and produce 96 byte-identical rows totaling 232,438 bytes with SHA-256 `73bdd9cf4af6990b6ce36cc7335b2863c5feeee2e0ff3b8092b7579ffb13e44b`; 92 rows are benchmark-fixture paths. The new positive uniquely retains source `server.js:8`, sink `mailer.js:11`, CWE-73/CWE-918/CWE-200, ten propagators, and both line-3 deny policies, while the source-identical 9.0.1 twin is absent and the earlier fast-uri path-policy sentinel remains. Strict package inspection validates a 251-entry, 1,671,451-byte npm archive with SHA-256 `b0740a4acde58003d134bd128779c4c80665d1cff84791fb62861f86133acc27`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is removed. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `6923ca96870c5586a2687a22bfcb9b318fa1d98932362475651c0f92e5e26c8c`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on attempt one: Node `32692359103`, Windows GUI `32692359146`, Linux GUI `32692359135`, container `32692359096`, .NET `32692359161`, Go `32692359291`, and Java `32692359143`.
- Added `node-path-fast-uri-encoded-dot-segment-policy-bypass`, a separate CWE-22 specialization over proven multi-hop Node filesystem dataflow for `fast-uri` GHSA-q3j6-qgpj-74h6 / CVE-2026-6321. The model requires exact production or fresh declaration-consistent npm v2/v3 evidence through 2.4.0 or from 3.0.0 through 3.1.0; one remote wrapper parameter must pass a fail-closed `startsWith` check against a fixed canonical non-root HTTP(S) subtree and then reach the exact official `fast-uri.parse(fast-uri.normalize(value)).path` chain inside an exact official `node:path` `join`/`resolve` rooted by a fixed server value before an exact Node filesystem path argument. Version 2.4.1 and 3.1.1 controls, wrong or development-only packages, lockfile-free ranges, inconsistent/v1 locks, positive or log-only checks, a different checked value, root-only or noncanonical prefixes, missing normalize/parse-path stages, WHATWG URL reparsing, unrooted paths, reassigned/shadowed or local lookalike bindings, fixed inputs, and test/example sinks remain negative. An isolated real-package matrix confirms that 2.4.0/3.1.0 collapse `public/%2e%2e/admin` into `admin`, while 2.4.1/3.1.1 preserve `public/%2E%2E/admin`; all temporary packages were removed. The first proposed witness was deliberately rejected after runtime testing showed that later WHATWG URL parsing re-collapses the repaired encoding and therefore cannot form a version-only control. Source-identical four-file 3.1.0/3.1.1 fixtures instead keep parsing inside `fast-uri` before a rooted filesystem write, retain request source `server.js:7`, sink `storage.js:10`, ten dataflow/dependency propagators, and an exact line-9 broken control only on the vulnerable side. Both package-backed witnesses pass and remove their ignored installs. Eight direct regression groups plus the canonical lane pass 24 tests and 1,522 assertions on Windows; the widened fast-uri/filesystem/corpus lane passes 38 tests and 1,618 assertions on native Ubuntu/WSL. The strict pair advances the canonical corpus to 82 exploit/control pairs and 492 repeated scans. Formatting and TypeScript compilation are clean. Reviewer guidance explicitly keeps this protected-path defect separate from the accepted `fast-uri` SSRF model and requires proof of the final decoded protected resource and effect.
- Final acceptance for the encoded dot-segment path model is green at exact implementation checkpoint `016e00203881901fcf8a3273e5dca5bffe963182`. The authoritative Bun suite passes 1,328 tests and 10,034 assertions across 147 files with 20 intentional environment/platform skips and zero failures in 343.10 seconds. Generated-model drift, formatting, TypeScript, the production build, both package-backed witnesses, and the high-severity production audit are clean. Two compiled inventories of a private root-level tracked archive take 10,438 and 10,593 ms and produce 96 byte-identical rows totaling 229,707 bytes with SHA-256 `18beae855686b54c58ea5218040bb3c6e1b7c6d76df5b1c08be72dab5580d160`; 92 rows are benchmark-fixture paths. The new positive uniquely retains source `server.js:7`, sink `storage.js:10`, CWE-22, ten propagators, and its line-9 broken control, while the source-identical 3.1.1 twin is absent and the earlier fast-uri host-policy sentinel remains. Strict package inspection validates a 251-entry, 1,665,344-byte npm archive with SHA-256 `f9daf27b787b8bdf42ab8a3df35e694d71618e6ae99957726293ccc4c5f81912`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is removed. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `b9a007cea916f728abc53a95ae3940dfdf33febad9fa4be207f53608ae1a809a`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on attempt one: Node `32690289684`, Windows GUI `32690289708`, Linux GUI `32690289689`, container `32690289678`, .NET `32690289699`, Go `32690289725`, and Java `32690289703`.
- Added `node-ssrf-fast-uri-host-policy-confusion`, a cause-aware specialization of proven Node SSRF dataflow for two reachable parser-versus-network-consumer disagreements in the five-advisory `fast-uri` repair sequence. The `authority-introducer` cause requires an official `resolve(base, remote)` result to pass a `parse(resolved).host` allowlist for the same fixed base later supplied to WHATWG `new URL(remote, base)`; exact production or fresh declaration-consistent npm v2/v3 evidence is eligible below 2.4.4, from 3.0.0 through 3.1.4, and from 4.0.0 through 4.1.1. The separate `literal-backslash` cause requires `parse(remote).host` to pass a fail-closed allowlist before the original value reaches the outbound consumer; its exact ranges are 2.3.1–2.4.2, 3.0.0–3.1.3, and 4.0.0–4.1.0. Repaired releases, wrong or development-only packages, lockfile-free ranges, inconsistent/v1 locks, reassigned bindings, another value or base, mismatched allowlist host, log-only checks, and test/example paths remain negative. Reviewer guidance distinguishes the additional percent-encoded-authority and failed-IDN host causes without treating package presence as proof, and explicitly keeps the encoded dot-segment path-traversal advisory in its own filesystem-policy contract. Current official CodeQL and Semgrep sources contain no `fast-uri` package or advisory model. A real 2.x/3.x/4.x package matrix confirmed every published repair boundary and was removed. Source-identical four-file 4.1.1/4.1.2 fixtures preserve request source `server.js:7`, outbound sink `storage.js:9`, ten dataflow/dependency propagators, and natively executable default-receiver API use. Windows and Ubuntu/WSL witnesses reproduce the policy/network split and repaired rejection. Nine direct regression groups plus the canonical integrity lane pass 25 tests and 1,517 assertions on each host. The strict pair advances the canonical corpus to 81 exploit/control pairs and 486 repeated scans. Formatting and TypeScript compilation are clean; the authoritative suite passes 1,320 tests and 9,965 assertions across 146 files with 20 intentional environment/platform skips and no failures in 345.17 seconds.
- Final acceptance for the `fast-uri` host-policy model is green at exact implementation checkpoint `15914d70ae119c64c3e2fe5b10eb05e54576000f`. Two compiled reviews of a private root-level tracked archive take 28,098 and 12,311 ms and produce 96 byte-identical rows totaling 227,446 bytes with SHA-256 `c5173f8537e0c177898e2c9615035ff3a6c8934fdf3af374a1815dc35061590b`; 92 rows are benchmark-fixture paths. The positive uniquely retains source `server.js:7`, sink `storage.js:9`, CWE-918/CWE-436, ten propagators, and its exact line-8 vulnerable guard, while the source-identical 4.1.2 twin is absent and the preceding `ip-address` sentinel remains. Strict inspection validates a reproducible 251-entry, 1,659,227-byte npm archive with SHA-256 `d178e529fcb23b661952abcbbea9bf5128549fc9cbfcec555302049589224b5d`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive and staging directories are removed. The production build, generated-model drift check, and high-severity production audit are green with no known vulnerabilities. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives hidden startup, and publishes a 346,796-byte executable with SHA-256 `782e83368c9e1959ec54ccf55320a974fb38d15a7e03234b65841e75e214f030`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on attempt one: Node `32688821280`, Windows GUI `32688821288`, Linux GUI `32688821282`, container `32688821293`, .NET `32688821314`, Go `32688821275`, and Java `32688821276`.
- Added `node-ssrf-ip-address-leading-zero-guard-bypass` for GHSA-mwp4-54f8-5fhr / CVE-2026-69192, a parser-versus-network-consumer disagreement that generic SSRF and dependency-only signals do not prove reachable. Exact production or fresh declaration-consistent npm v2/v3 evidence from the first published 3.2.0 release through 10.3.0 is eligible; 10.3.1 rejects multi-digit IPv4 octets beginning with zero before classification. The model requires remote URL or host flow through the existing SSRF dataflow, an official named/CommonJS/namespace/import-equals `Address4` or legacy `v4.Address` binding from exactly `ip-address`, a fail-closed private-range decision over the same consumed host, and the original value at the outbound sink. Modern `isPrivate`/`isLoopback`/`isLinkLocal`/`isCGNAT` classifiers are accepted only from 10.2.0; legacy releases require `isInSubnet` against `10.0.0.0/8`. Repaired or unpublished releases, wrong or development-only packages, lockfile-free ranges, stale locks, default-import lookalikes, reassignment, log-only or wrong-value checks, test/example paths, and flows with an earlier fail-closed leading-zero-octet rejection remain negative. A real package/API matrix confirms the historical and modern export boundaries, while Node WHATWG URL parsing and native Ubuntu resolution both map `012.0.0.1` to `10.0.0.1` even though 10.3.0's decimal parser canonicalizes it as public `12.0.0.1`; all temporary packages were removed. Current official CodeQL and Semgrep source searches contain no `Address4` model or `ip-address` rule. Source-identical four-file 10.3.0/10.3.1 fixtures preserve request source `server.js:7`, outbound sink `storage.js:7`, and ten dependency/dataflow propagators. A strict specialized manifest and eight direct regression groups advance the canonical corpus to 80 exploit/control pairs and 480 repeated scans. Windows and native Ubuntu/WSL focused lanes each pass 44 tests and 1,572 assertions. Formatting, generated-model drift, TypeScript, the clean production build, both witnesses, and the production advisory audit are green; the authoritative Windows suite passes 1,311 tests and 9,892 assertions across 145 files with 20 intentional environment/platform skips and no failures in 299.55 seconds.
- Final acceptance for the `ip-address` broken-control model is green at exact implementation checkpoint `f9591250d92cfc122ff565421623a5c2674b6560`. Two compiled reviews of a private root-level tracked archive take 27,129 and 12,190 ms and produce 96 byte-identical rows totaling 225,437 bytes with SHA-256 `91567e60f588bb24fb166194ffb6ae800ab8f1c447aed4f5adc8d41bf638c557`; 92 rows are benchmark-fixture paths. The new positive uniquely retains source `server.js:7`, sink `storage.js:7`, CWE-918/CWE-20, ten propagators, and its exact line-6 vulnerable guard, while the source-identical 10.3.1 twin is absent. Strict inspection validates a 251-entry, 1,651,283-byte npm archive with SHA-256 `60441a41825c58244a5b95db1d4b92931bae5340e4bcca4037e6fb26913b1c23`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is safely removed. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives the hidden startup smoke, and publishes a 346,796-byte executable with SHA-256 `76c98517ee0357f261c62f1373b27d928582c0097581ef3ed84f20b8a3b1d59e`. Ubuntu/WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on attempt one: Node `32686792282`, Windows GUI `32686791881`, Linux GUI `32686792042`, container `32686791905`, .NET `32686791912`, Go `32686792405`, and Java `32686791880`.
- Extended `node-http-js-yaml-parser-dos` with the distinct default-schema `!!omap` quadratic-time path that remained in js-yaml 3.15.0 and 4.3.0 after their merge-key limit shipped. Releases 3.15.1 and 4.3.1 replace a growing `Array#indexOf` duplicate-key scan with constant-time own-key tracking. Older 3.x/4.x releases retain the existing `quadratic-merge` provenance because that source-identical remote loader path already proves an independently exploitable parser stall; 5.0.0 through 5.2.0 retain the stronger existing `exponential-flow` provenance, which subsumes their schema-gated omap weakness, and 5.2.1 remains flow-pair-only. This adds the two unique false-negative boundaries without duplicating rows. Official default/namespace, TypeScript import-equals, named or aliased, and CommonJS loader bindings remain subject to exact production or fresh declaration-consistent npm v2/v3 proof and remote argument-zero flow. A safely removed real Node 24.15.0 matrix measured the same 697,787-byte, 40,000-entry document at 1,398.628/1,402.917 ms on 3.15.0/4.3.0 versus 76.870/89.273 ms on 3.15.1/4.3.1; doubling from 20,000 entries caused about 4.5x affected-release work but only about 1.5x to 1.8x repaired-release work. Authenticated official-source searches find no `resolveYamlOmap`, `omapTag`, or `YAML11_SCHEMA` coverage in either CodeQL or Semgrep rules. A topology-identical 4.3.0/4.3.1 pair preserves source `server.js:7`, sink `storage.js:4`, and nine propagators, while bounded dependency-free witnesses prove quadratic versus linear lookup work. The specialized manifest now has two perfect-gate pairs, and the canonical corpus advances to 79 exploit/control pairs and 474 repeated scans. The widened parser/archive/framework/residual/corpus lane passes 115 tests and 2,644 assertions with one intentional Windows symlink skip; native Ubuntu/WSL passes all 116 tests and 2,645 assertions. Formatting, generated-model drift, TypeScript, the clean production build, both new witnesses, and the production advisory audit are green.
- Final acceptance for the js-yaml ordered-map coverage passes 1,303 tests and 9,844 assertions across 144 files with 20 intentional environment/platform skips and no failures in 319.40 seconds at exact implementation checkpoint `87ce13e4ef7980e5b48371751b56b534c6d41ced`. Two compiled reviews of a private exact tracked-head archive take 24,029 and 11,120 ms and retain 96 byte-identical rows totaling 221,968 bytes with SHA-256 `09b9b4bbfebf0e7347e57f690028f3acbf47b8a89f1ecb7837256ac0b1d096d3`; 92 are benchmark-fixture rows. The new omap positive retains source `server.js:7`, sink `storage.js:4`, `vulnerable-js-yaml-load-quadratic-omap-dos`, CWE-400/CWE-407, and nine propagators, while its 4.3.1 twin is absent; the exponential-flow, node-tar member-recursion and linkpath, Fastify, `extract-zip`, PostCSS, and `tmp` sentinels remain intact. Strict inspection validates a 251-entry, 1,647,475-byte npm archive with SHA-256 `9b3b03736c75b551a10909ad29f5b1d9ee78be33f4dc097845ac8762fb4628ac`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is safely removed. Windows locked restores and builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives a hidden three-second startup smoke, and publishes a 346,796-byte executable with SHA-256 `86e96e4beddaf600c420fac8d8a4c3501260b08f49d2b16069ce19205e0b2fd0`. WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass on attempt one: Node `32684725987`, Windows GUI `32684725967`, Linux GUI `32684725966`, container `32684726063`, .NET `32684725986`, Go `32684725990`, and Java `32684726052`.
- Added `node-http-js-yaml-parser-dos` as a version-aware application model for two distinct high-severity parser-complexity defects that dependency alerts and historical unsafe-deserialization rules do not prove reachable. The quadratic merge-chain path covers `js-yaml` 3.0.0 through 3.14.x and 4.0.0 through 4.2.x; the exponential nested flow-pair path covers 5.0.0 through 5.2.1. Versions 3.15.0/4.3.0 cap total merge-key work, and 5.2.2 reuses already parsed flow-key events instead of recursively reparsing them. Official default/namespace and TypeScript import-equals receivers, named or aliased loaders, CommonJS receivers/destructures/direct members, and direct require calls require exact production or fresh declaration-consistent npm v2/v3 proof. Remote request data must reach argument zero of `load`/`loadAll`, or the 3.x-only `safeLoad`/`safeLoadAll`; fixed YAML, pre-3 and repaired releases, unsupported APIs, wrong/development-only packages, lockfile-free ranges, inconsistent/v1 locks, reassignment, and wrapper shadowing remain negative. `maxDepth: 100`, request body limits, and ordinary `try/catch` are not misclassified as synchronous CPU preemption. Real isolated package matrices show a 155-byte depth-22 payload taking 1,306.564 ms on 5.2.1 versus 2.493 ms on 5.2.2, and a 57,448-byte 1,500-link merge chain taking 211.232 ms on 4.2.0 versus a fail-closed 6.068 ms on 4.3.0; all temporary packages were removed. Official CodeQL source contains seven `js-yaml` references only in its historical CWE-502 unsafe-deserialization model and examples, with no `maxTotalMergeKeys` coverage; the public Semgrep rules contain no `js-yaml` or `maxTotalMergeKeys` reference. Topology-identical four-file 5.2.1/5.2.2 fixtures preserve source `server.js:7`, sink `storage.js:4`, and nine propagators; dependency-free witnesses reproduce exponential versus linear work without hanging the suite. Six direct regression groups and a perfect-gate specialized manifest advance the canonical corpus to 78 exploit/control pairs and 468 repeated scans. The widened parser/framework/residual/Copilot-port/corpus lane passes on Windows and native Ubuntu/WSL with 148 tests, 2,779 assertions, one intentional host-specific skip, and no failures on each host. The authoritative suite passes 1,303 tests and 9,814 assertions across 144 files with 20 intentional environment/platform skips and no failures in 302.91 seconds.
- Final acceptance for the js-yaml parser-complexity model is green at exact implementation checkpoint `7bcb74cdcb6943f34b63f755413796551be8d402`. Formatting, generated-model drift, TypeScript, the clean production build, and the production advisory audit pass. Two compiled reviews of a private exact tracked-head archive take 24,114 and 10,689 ms and retain 96 byte-identical rows totaling 220,519 bytes with SHA-256 `9f66eb22e7c474390a2be71dcb0f1231b997606e69888c6ece9e13eb4d7a0526`; 92 are benchmark-fixture rows. The new js-yaml positive retains source `server.js:7`, sink `storage.js:4`, `vulnerable-js-yaml-load-exponential-flow-dos`, CWE-400/CWE-407, and nine propagators, while its 5.2.2 twin is absent; the node-tar member-recursion and linkpath, Fastify, `extract-zip`, PostCSS, and `tmp` sentinels remain intact. Strict inspection validates a 251-entry, 1,647,201-byte npm archive with SHA-256 `30ab076ba5a1adf1a9a5767ef14edc4b03818ab1d31c58adaff7b06431cd924a`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is safely removed. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives a hidden three-second startup smoke, and publishes a 346,796-byte executable with SHA-256 `2663923998feb87c1641872de822831aa4b6a2f07a3d723bdbd85e480cb8dd41`. WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass without retries: Node `32683750659`, Windows GUI `32683750691`, Linux GUI `32683750672`, container `32683750750`, .NET `32683750702`, Go `32683750709`, and Java `32683750759`.
- Added `node-http-tar-member-selection-recursion` for GHSA-r292-9mhp-454m / CVE-2026-73566, a distinct pre-entry availability path not covered by the scanner's node-tar linkpath model or CodeQL's experimental decompression-volume model. Official namespace/default and TypeScript import-equals receivers, named or aliased `t`/`list`/`x`/`extract` callables, CommonJS receivers/destructures, and direct require members require exact production or fresh declaration-consistent npm v2/v3 proof through 7.5.20. Remote request/upload data must select the options `file` or stream directly into the operation, and the call must supply a non-empty member list. Version 7.5.21, fixed archives, omitted/empty selections, create APIs, `sync: true`, wrong/development-only packages, lockfile-free ranges, inconsistent/v1 locks, reassignment, and wrapper shadowing remain negative. `maxDepth`, `maxReadSize`, and ordinary `try/catch` are deliberately not credited: `filesFilter/mapHas` recurses before entry-depth checks, consumes path segments rather than output bytes, and raises outside the awaited promise on async/stream paths. Reviewer guidance requires GNU `L` or PAX `x` metadata, accepted body size, slash depth, member selection, asynchronous/stream execution, runtime stack behavior, an uncaught `RangeError`, and process termination, and limits impact to CWE-674 availability. The official 7.5.21 repair caps the parent walk at 100 levels. Current Semgrep source has no node-tar rule; CodeQL's experimental node-tar decompression rule covers only `x`/`extract`, `maxReadSize`, and decompressed volume rather than list/member-filter recursion. Topology-identical four-file 7.5.20/7.5.21 fixtures preserve source `server.js:7`, sink `storage.js:4`, and nine propagators; dependency-free witnesses reproduce child-process stack exhaustion and the bounded repair. Five direct regression groups pass, and the widened model, prior linkpath model, canonical corpus, residual-inventory, and Copilot-port slice passes on Windows and native Ubuntu/WSL with 127 tests, 2,662 assertions, one intentional platform-specific skip, and no failures on each platform. The canonical corpus advances to 77 exploit/control pairs and 462 repeated scans.
- Final acceptance for the node-tar member-selection recursion model passes 1,297 tests and 9,762 assertions across 143 files with 20 intentional environment/platform skips and no failures in 321.48 seconds. Formatting, generated-model drift, TypeScript, the clean production build, and the production advisory audit are green. Two compiled reviews of an exact tracked-head archive take 23,595 and 10,545 ms and retain 96 byte-identical rows totaling 218,881 bytes with SHA-256 `acb056ba5f1d894ffbfdf4d1637e695a009fdb9e9bf5f4b0cfe8030ba797a253`; 92 are fixture rows. The new node-tar positive retains source `server.js:7`, sink `storage.js:4`, CWE-674, and nine propagators, while its 7.5.21 twin is absent; the prior node-tar linkpath, Fastify, `extract-zip`, PostCSS, and `tmp` sentinels remain intact. Strict inspection validates a 251-entry, 1,644,677-byte archive with SHA-256 `1343ba27a7812b4810d4e0ba311e6afd6d943e8c3263d7f5b13ea7a06930236`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is safely removed after validation. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives a hidden three-second startup smoke, and publishes a 346,796-byte executable with SHA-256 `842456249e6ea6298cac0ebf6d98028a9a8c1bb8e8d22b08efa5f11ec9f25234`. WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `e61a06a00af4baa53352277ab31467fe076d956f`: Node `32682152144`, Windows GUI `32682152153`, Linux GUI `32682152117`, container `32682152109`, .NET `32682152098`, Go `32682152125`, and Java `32682152124`.
- Added `node-http-tar-linkpath-traversal` to consolidate the complete reviewed 2026 node-tar link-target repair sequence rather than stopping at its first partial patch: absolute Link/SymbolicLink targets through 7.5.2, parent-segment hardlinks through 7.5.6, symlink-chain hardlinks through 7.5.7, drive-relative hardlinks through 7.5.9, and drive-relative symlinks through 7.5.10. Version 7.5.11 is the first boundary that closes all five reviewed variants. Official namespace/default and TypeScript import-equals receivers, named or aliased `x`/`extract` callables, CommonJS receivers/destructures, and direct require members require an exact production declaration or fresh declaration-consistent npm v2/v3 lock. A request/upload path must reach the options `file`, a remote dynamic options object, or an HTTP request stream must pipe directly into extraction; package presence, fixed archives, create/list APIs, wrong packages, development-only declarations, lockfile-free ranges, inconsistent/v1 locks, reassignment, and wrapper shadowing remain negative. `preservePaths: false` is not misclassified as protection on affected versions. An exact `filter` that rejects both `Link` and `SymbolicLink` suppresses the row, while a one-type or ambiguous filter is retained as candidate evidence. Reviewer guidance requires the effective header type/linkpath, entry order, platform/drive semantics, extraction root, on-disk resolution, privileges, resulting external inode/link, and a concrete later read or write before claiming CWE-22/CWE-59 impact; execution, persistence, or privilege escalation still require a consumed executable or configuration target. Authenticated official CodeQL and Semgrep source searches find no `node-tar` or `tar.extract` package model. A safely removed real WSL alias matrix proves 7.5.10 creates `a/b/l -> ../../../secret.txt` and a later write changes the external secret, while 7.5.11 creates no link and preserves it. Topology-identical four-file fixtures preserve request source `server.js:7`, extraction sink `storage.js:4`, and nine propagators across the established cross-file path; dependency-free witnesses reproduce the drive-relative validation disagreement. Six direct regression groups and a perfect-gate specialized manifest advance the canonical corpus to 76 exploit/control pairs and 456 repeated scans. The widened node-tar, extract-zip, generic archive-link, hardened plugin ZIP, residual-inventory, and corpus slice passes on Windows with 99 tests, 2,520 assertions, one intentional POSIX-only skip, and no failures, and on native Ubuntu/WSL with all 100 tests and 2,521 assertions passing.
- Final acceptance for the consolidated node-tar model passes 1,292 tests and 9,732 assertions across 142 files with 20 intentional environment/platform skips and no failures in 352.88 seconds. Formatting, generated-model drift, TypeScript, a clean production build, the widened Windows and WSL lanes, and `pnpm audit --prod --audit-level high` are green with no known vulnerabilities. Two compiled reviews of an exact tracked-head archive take 23,540 and 10,724 ms and retain 96 byte-identical rows totaling 217,058 bytes with SHA-256 `004827ff2d1e7f7e6eb9e14051a0b3ff9865ac183ed1720552f7cc9a4dd8e8d8`; 92 are fixture rows. The new node-tar positive uniquely retains source `server.js:7`, sink `storage.js:4`, CWE-22 plus CWE-59, and nine propagators, while its 7.5.11 twin is absent; the Fastify positive still retains line 5/8, the `extract-zip` positive retains line 7/4 and nine propagators, their repaired twins are absent, and the PostCSS and `tmp` sentinels remain present. Strict inspection validates a 251-entry, 1,642,551-byte archive with SHA-256 `2e47026c7e98070e7b0aeab466629f34688de25551a250a83c3eccf87769e7de`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The reproducible archive is safely removed after validation. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives a hidden three-second startup smoke, and publishes a 346,796-byte executable with SHA-256 `9e2bf1d68e5cc061236e5794779e6a318286549d5f390b7b24fdde8eb338ec21`. WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `9b6fd06ab2b494433e73183fe7bf201372139c87`: Node `32680156577`, Windows GUI `32680156569`, Linux GUI `32680156542`, container `32680156562`, .NET `32680156590`, Go `32680156566`, and Java `32680156564`.
- Added `node-http-fastify-static-route-guard-bypass` for reviewed GHSA-83w8-p2f5-377r / CVE-2026-15074, a package/version/router-normalization boundary absent from current public CodeQL and Semgrep rule sources. Official default ESM, TypeScript import-equals, CommonJS binding, and direct-require registration forms require an exact Fastify instance, a configured static root, nearest exact production or fresh declaration-consistent npm v2/v3 proof through vulnerable `@fastify/static` 10.1.0, and a distinct protected wildcard route on the same instance with concrete authentication, authorization, 401, or 403 behavior. A vulnerable dependency or intentionally public static root alone is not retained. Version 10.1.1 and later, wrong packages or receivers, development-only declarations, missing roots, lockfile-free ranges, inconsistent/v1 locks, reassignment, wrapper shadowing, unguarded routes, `serve: false`, and `wildcard: false` remain negative; `allowedPath` is preserved as review evidence rather than guessed safe. Reviewer guidance requires a raw or encoded non-leading parent segment to miss the protected route, reach the static catch-all, normalize to an existing protected file beneath the configured root, and disclose concrete response bytes without overstating the path as arbitrary traversal outside the root or a write/execution primitive. A safely removed loopback matrix proves Fastify 5.12.1 plus 10.1.0 denies direct `/deep/secret.txt` at 401 but serves the same protected bytes at 200 through raw and `%2e%2e` bypasses; 10.1.1 retains the direct 401 and rejects both bypasses at 403. Source-identical fixtures differ only in the package version, preserve guard `server.js:5` and registration `server.js:8`, and have dependency-free raw-path witnesses. Six direct regression groups and a perfect-gate specialized manifest advance the canonical corpus to 75 pairs and 450 repeated scans. Formatting, generated-model drift, TypeScript, both witnesses, the model suite, and the canonical corpus gate pass on Windows and native Ubuntu/WSL with 22 tests, 1,410 assertions, and no failures on each platform.
- Final acceptance for the Fastify Static route-guard model passes 1,286 tests and 9,698 assertions across 141 files with 20 intentional environment/platform skips and no failures in 334.91 seconds. Formatting, generated-model drift, TypeScript, a clean production build, both focused host lanes, and the production advisory audit are green with no known vulnerabilities. Two compiled reviews of an exact tracked-head archive take 24,034 and 11,357 ms and retain 96 byte-identical rows totaling 215,506 bytes with SHA-256 `d3ba4d6fc26f3a88d6a041453f778e907db1d80ebdfcb0b4ce16e1b88e31fbc7`; 92 are fixture rows. The new Fastify positive retains protected guard `server.js:5`, vulnerable registration `server.js:8`, and CWE-22, its 10.1.1 twin is absent, and the exact `extract-zip`, PostCSS, and `tmp` regression paths remain intact. Strict inspection validates a 251-entry, 1,638,948-byte archive with SHA-1 `1a0b60013e9a88c0324a31c6011a2ae82baaa681` and SHA-256 `aa7ab03126e17bcbb92c70c046532516f0652cf703ebf3e6d71b6a9fe908daec`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is safely removed after validation. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, survives a hidden native startup smoke, and publishes a 346,796-byte executable with SHA-256 `c93b26b8df7b074a6643809c53d75a933e299926dcc7a2f0d15d8c77e2fcb17f`. WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `f50403db0e23ffe969904f7dc5c0c3f1a080e818`: Node `32678066278`, Windows GUI `32678066238`, Linux GUI `32678066242`, container `32678066303`, .NET `32678066297`, Go `32678066268`, and Java `32678066280`.
- Added `node-http-extract-zip-symlink-traversal` so the scanner detects the same newly disclosed boundary that triggered removal of its former archive wrapper. Official default ESM, TypeScript import-equals, CommonJS callable, and direct-require forms bind only to exact production `extract-zip` declarations or fresh declaration-consistent npm v2/v3 lock resolutions. Every published release through 2.0.1 is treated as vulnerable; the audit service's unpublished 2.0.2 is retained only as a future negative boundary. Remote upload/request data must reach archive argument zero and argument one must provide extraction options. Wrong or development-only packages, fixed archives, missing destinations, lockfile-free ranges, inconsistent/v1 locks, reassignment, and wrapper shadowing remain negative. An exact `onEntry` callback that masks `externalFileAttributes` to Unix type `0o120000` and throws before extraction suppresses the row; callbacks that merely observe or return the entry do not. Reviewer guidance distinguishes member-name containment from symlink-target containment and requires archive mode, link payload, platform, privileges, final location, later dereference, and a concrete disclosure or integrity effect before escalating beyond CWE-22. A topology-identical four-file Express exploit/control pair pins the same affected 2.0.1 package and preserves source `server.js:7`, sink `storage.js:4`, and nine propagators; only the exact pre-extraction throw differs. Dependency-free witnesses reproduce external target resolution and fail-closed link rejection. Six direct regression groups and a perfect-gate specialized manifest advance the canonical corpus to 74 pairs and 444 repeated scans. Formatting, generated-model drift, TypeScript, both witnesses, and the adjacent archive, path, PostCSS, and residual-inventory slice pass on Windows with 90 tests, 1,137 assertions, one intentional symlink skip, and no failures, and on native Ubuntu/WSL with all 91 tests and 1,138 assertions passing.
- Final acceptance for the package-aware `extract-zip` model passes 1,280 tests and 9,666 assertions across 140 files with 20 intentional environment/platform skips and no failures in 319.95 seconds. Formatting, generated-model drift, TypeScript, a clean production build, both platform-focused lanes, and the live production advisory audit are green with no known vulnerabilities. Two compiled reviews of an exact tracked-head archive take 23,978 and 10,739 ms and retain 96 byte-identical rows totaling 215,314 bytes with SHA-256 `0af1c172ce8378fb297b3fa2385c5408cb20fade9b58e7740e29803095393ac6`; 92 are fixture rows. The new positive retains source `server.js:7`, sink `storage.js:4`, CWE-22, and nine propagators, its exact guarded twin is absent, and the PostCSS and `tmp` paths remain intact. Strict inspection validates a 251-entry, 1,633,512-byte archive with SHA-1 `0e4ae6345f24cc1a32a2a6b717a1381d1f021e43` and SHA-256 `5e10314bd186e0e61386a2a39a7f8f94d86b2ccf64ef0c70f3bdf4924f598e3a`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is safely removed after validation. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `67822dc24fa7d6a18cc5efb64b77832a4681df3f1247e11a4da5b95ed68cad34`. WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `f83fed64cd99e699b7314621ce61396251215c1d`: Node `32676497284`, Windows GUI `32676497318`, Linux GUI `32676497337`, container `32676497330`, .NET `32676497319`, Go `32676497290`, and Java `32676497271`.
- Removed the advisory-affected `extract-zip` 2.0.1 wrapper after production audit began reporting GHSA-jmr9-qjv8-65gv / CVE-2026-56876 and confirmed that the registry has no 2.0.2 repair to install. Plugin archives now use `yauzl` 3.4.0 only as a bounded decompression primitive behind scanner-owned policy. The scanner reads one immutable regular-file snapshot, rejects archives over 256 MiB, and completes raw-central-directory plus decoded-entry validation before writing any member. ZIP64, oversized central directories, raw backslashes, traversal and drive-qualified names, case-insensitive duplicates, file/child conflicts, symlinks and other special files, encrypted or unsupported entries, per-entry and aggregate expansion excess, mutable input races, and malformed directory payloads fail closed. Extraction skips metadata junk, creates only private directories and exclusive regular files, enforces decoded sizes, supports cancellation, rechecks every CRC-32, and removes staging output on any failure. New cross-platform regressions prove valid installation, the advisory's relative symlink-target shape without partial extraction or external modification, parent/backslash traversal rejection, and file-child conflict rejection. Focused Windows and native WSL runs each pass 16 tests and 78 assertions; generated-model drift, TypeScript, production build, and a fresh production advisory audit also pass with no known vulnerabilities.
- Added `node-http-postcss-source-map-traversal` for reviewed GHSA-r28c-9q8g-f849, a package/version/implicit-file-load boundary absent from current public CodeQL and Semgrep security rules. Official root, named parse, processor, ESM, TypeScript import-equals, and CommonJS bindings require nearest exact production or fresh declaration-consistent npm v2/v3 proof through vulnerable PostCSS 8.5.17; 8.5.18 and later are repaired by same-directory containment. Remote CSS must reach argument zero of `parse` or `process`. Exact `map: false` or `map: { prev: false }`, patched and development-only versions, fixed CSS, wrong packages, reassignment, wrapper shadowing, lockfile-free ranges, inconsistent/v1 locks, and stale metadata remain negative. Reviewer guidance requires a final non-inline `.map` annotation, traversal or absolute resolution outside `dirname(from)`, a valid loaded source map, and a concrete `result.map`/`sourcesContent` disclosure path without claiming non-`.map` reads, code execution, or confidentiality impact when output is not exposed. A safely removed real-package matrix proves 8.5.17 disclosure, 8.5.18 rejection, vulnerable-version `map: false` protection, and the repaired release's explicit `unsafeMap: true` opt-out. Topology-identical four-file Express fixtures preserve source `server.js:8`, sink `storage.js:5`, and nine propagators; dependency-free witnesses prove external protected-map disclosure and repaired containment. Five direct regression groups and a strict specialized manifest advance the canonical corpus to 73 pairs and 438 repeated scans.
- Final acceptance for the PostCSS model and the intervening plugin-archive security repair passes 1,274 tests and 9,633 assertions across 139 files with 20 intentional environment/platform skips and no failures in 311.37 seconds. Formatting, generated-model drift, TypeScript, clean production build, focused Windows and native WSL archive regressions, and the production advisory audit are green. Two corrected full-repository reviews of an exact tracked-head archive take 20,516 and 10,315 ms and retain 96 byte-identical rows totaling 212,721 bytes with SHA-256 `7aee83dfb79bf8a8bdcb2f9df339037e862865e3f23916914af0d98c7d255a8b`; 92 are fixture rows, the PostCSS and `tmp` positives preserve source `server.js:8`, sink `storage.js:5`, CWE-22, and nine propagators, and their repaired twins remain absent. An initial harness attempt archived only the current Git subdirectory and was explicitly discarded before evidence was recorded; root-level archive construction plus required fixture/model assertions prevent recurrence. Strict inspection validates a 251-entry, 1,629,795-byte archive with SHA-1 `1fd4819d0b6aeeed50b04a943fb044a54445d56b` and SHA-256 `1bf815aa3f629f8046d2b2db7bd9e02832017c29af11380175142f921deeb2af`; three fresh Windows installs add 67 packages each and two Ubuntu Node 22.23.1 installs add 75 each, with public import, CLI behavior, and all 79 bundled plugin files validated every time. The archive is safely removed after validation. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `3dd8e5dd2dd728ba9ee00939099bfb949acd2d3ab2c1108ae433735d6195b2e5`; publication uses the repository-pinned audited NuGet feed after the new .NET 10 SDK initially found no configured source for .NET 8 runtime packs. WSL locked restores and builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact-head workflows pass without retries at checkpoint `f0dd3f248f923e86fc915e54a44793e1b95abc79`: Node `32674631773`, Windows GUI `32674631925`, Linux GUI `32674631841`, container `32674631894`, .NET `32674631827`, Go `32674631800`, and Java `32674631799`.
- Added `node-http-tmp-path-traversal` for the 2026 `tmp` package boundary that generic filesystem and Zip Slip rules do not express. Official default, namespace, TypeScript import-equals, named/aliased/destructured creator, direct CommonJS member, and CommonJS receiver bindings require nearest exact production or fresh declaration-consistent npm v2/v3 lock proof below the repaired 0.2.6 release. Only `file`, `fileSync`, `dir`, and `dirSync` establish creation; `tmpName` alone is excluded. Remote flow is retained only from `prefix`, `postfix`, `template`, `dir`, a dynamic options object, or an object spread that can still supply one of those fields. Fully overwritten spreads, unrelated options such as `keep`/`mode`, fixed values, 0.2.6+, wrong or development-only packages, wrong methods, reassignment, member replacement, wrapper shadowing, lockfile-free ranges, inconsistent/v1 locks, and stale metadata remain negative. Candidate basename and strict allowlist controls are preserved without being promoted to conclusions. Authenticated current-source searches find no `node-tmp` model in CodeQL or public Semgrep; CodeQL's lone `tmp.fileSync` hit is a CWE-377 example, while its high-precision Zip Slip query models archive-entry paths rather than package option construction. A safely removed real-package matrix proves both `../` prefix escape and the older sibling-prefix `dir` containment bypass under 0.2.5, and their distinct rejection paths under 0.2.6. Topology-identical four-file Express fixtures preserve source `server.js:8`, sink `storage.js:5`, and nine propagators; dependency-free witnesses prove escaped protected-content placement and repaired rejection without overstating random-suffix creation as chosen-file overwrite. Eight direct regressions and a strict specialized manifest advance the canonical corpus to 72 pairs and 432 repeated scans. Formatting, generated-model drift, TypeScript, both witnesses, and the widened path/cross-file/inventory/corpus slice pass on Windows with 96 tests, 2,482 assertions, one intentional symlink skip, and no failures, and on native Ubuntu Bun 1.3.14 with all 97 tests and 2,483 assertions passing.
- Final acceptance for the `tmp` path-traversal increment passes 1,266 tests and 9,596 assertions across 137 files with 20 intentional environment/platform skips and no failures in 378.91 seconds. Formatting, generated-model drift, TypeScript, clean production build, both witnesses, structured benchmark files, and the production advisory audit pass with no known vulnerabilities. Two fresh compiled reviews of an exact tracked-head snapshot take 18,990 and 12,656 ms and retain 96 byte-identical rows totaling 210,764 bytes with SHA-256 `0bddb45541009be5b6bce6f16eaa6bca806747765b12cbced35949ab05b11ced`; the new row preserves source `server.js:8`, sink `storage.js:5`, CWE-22, exact creator provenance, and nine propagators, its repaired twin is absent, and all twenty prior package-aware parser, expression, merge, mutation, deletion, replacement, and attack-chain paths remain retained at the bounded cap. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,621,720-byte archive had SHA-1 `847d243c8be0494c96ee637377b829779f15b6d6` and SHA-256 `7993b7f307ed7a7691045dea6e64de2a22ef6d6ef3396e49baefee2134d3e577`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `9f45bf80675e8c47e20277306c96642477399aa4444ee159e44536d35259e6ed`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `0bda1bc7eda330a2188cf2f5507217387b428a34`: Node `31189673713`, Windows GUI `31189673750`, Linux GUI `31189675200`, container `31189676388`, .NET `31189673722`, Go `31189674752`, and Java `31189673499`.
- Widened Axios gadget-chain acceptance passes the new chain, prior Axios SSRF, full package-aware merge family, Lodash deletion, Immutable.js replacement, `object-path`, `dset`, `flat`, `jsonpath-plus`, `js-toml`, and the 71-pair canonical corpus on both supported scanner hosts. Windows passes 95 tests and 1,756 assertions with one intentional symlink skip and no failures across 11 files in 115.59 seconds. Native Ubuntu WSL Bun 1.3.14 passes all 96 tests and 1,757 assertions with no skips or failures across the same 11 files in 437.41 seconds. Formatting, TypeScript, both dependency-free witnesses, exact vulnerable/patched topology, the chain-to-primitive consolidation invariant, and structured benchmark files remain green.
- Added the cross-component `node-http-axios-prototype-gadget-chain` model, which synthesizes a remotely reachable object-valued global prototype write with a later official Axios request in the same exact runtime package boundary. Eligible upstream proof is deliberately narrower than generic CWE-1321 co-occurrence: version-aware recursive merge, `js-toml`, `flat.unflatten`, or `dset/merge` value flow must already prove that an attacker controls the object installed on shared prototype state; deletion-only paths, local returned-object replacement, `Object.assign` target replacement, and path-only fixed-value writes are excluded. Axios 0.19.0–0.31.0 and 1.0.0–1.15.1 retain a direct inherited-config/validator stage. Axios 0.31.1–0.32.x and 1.15.2–1.17.x require a same-receiver request interceptor whose top-level `{...config}` or `Object.assign({}, config)` copy reintroduces `Object.prototype`; 0.33.0 and 1.18.0 close that bypass. Exact declarations and fresh consistent npm v2/v3 locks preserve distinct Axios sink provenance. Official root/instance ESM, namespace, import-equals, and CommonJS bindings, reassignment/shadowing barriers, identity interceptors, returned or preserved own `proxy:false`, development-only dependencies, package/workspace separation, and repaired upstream primitives remain precise. A chain row records the original request source and wrappers, exact pollution state write, Axios manifest proof, interceptor rematerialization, shared `Object.prototype.proxy` state, final gadget sink, CWE-1321 plus CWE-441, and bounded controls; it subsumes only its exact lower-value primitive row so the 96-row repository cap retains all prior package-aware paths. An isolated live loopback matrix confirms Lodash 4.17.10 `constructor.prototype` pollution routes authorization-bearing requests through the attacker proxy on Axios 1.15.1 directly and 1.17.0 after spread or `Object.assign` interception. Axios 1.15.2's direct path, a 1.17.0 identity interceptor, preserved own `proxy:false`, Axios 1.18.0/1.19.0, and Lodash 4.17.11 remain on the intended target; pre-hardening `proxy:false` prevents routing but still reaches an inherited-validator `TypeError`, so it is counterevidence rather than automatic suppression. A topology-identical Lodash 4.17.10/Axios 1.17.0 exploit and Lodash 4.17.11/Axios 1.18.0 control, dependency-free transition witnesses, strict evidence gates, seven direct regressions, and three-run integration bring the canonical corpus to 71 pairs and 426 scans. The focused Windows chain, prior Axios SSRF, full package-aware merge, and canonical corpus subset passes 39 tests and 1,541 assertions with one intentional symlink skip and no failures in 15.13 seconds; formatting, TypeScript, both witnesses, and structured benchmark files are green.
- Final acceptance for the Axios prototype-gadget-chain increment passes 1,258 tests and 9,558 assertions across 136 files with 20 intentional environment/platform skips and no failures in 382.82 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two fresh compiled self-reviews take 13,633 and 13,410 ms and retain 96 byte-identical rows totaling 208,914 bytes with SHA-256 `c5082867b093fd5e94b46a7b06a7f06af71527736d599ab6e8b4afc4a8a093ab`; the exact chain preserves source `server.js:12`, sink `server.js:13`, both CWEs, exact interceptor-gadget provenance, and 13 propagators, its repaired twin is absent, and all nineteen prior package-aware parser, expression, merge, mutation, deletion, and replacement paths remain retained. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,617,620-byte archive had SHA-1 `41e13b2606643c6f4057652c0a1abf4029a50c6d` and SHA-256 `05325ea8e1ecbecff937481195b17dfc6c53c9109f3f801d73b98fc8cf4bed9d`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `1b9f6baffeaf4d1f9a713109075a344853e2837f389c2557795667a41bec3a17`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `42f5215f8140813b41df23ae3237d8b4a6f5ebfd`: Node `31184775915`, Windows GUI `31184775594`, Linux GUI `31184775565`, container `31184775559`, .NET `31184775541`, Go `31184775474`, and Java `31184775574`.
- Added the standalone `node-http-immutable-prototype-replacement` model for remotely controlled plain objects and keys reaching exact Immutable.js conversion, merge, set, or update APIs. Official named, aliased, destructured, namespace, interoperable default, CommonJS receiver, and direct-member bindings are tied to nearest exact runtime or fresh declaration-consistent npm v2/v3 lock evidence. `Map(input).toObject()`, `Map(input).toJS()`, `fromJS(input).toJS()`/`toObject()`, and locally retained conversions are vulnerable below 3.8.3, on 4.x below 4.3.8, and on 5.x below 5.1.5. On the modeled 4.x/5.x functional surface, `merge`/`mergeDeep` retain every operand because argument zero is copied into a new returned object; `mergeWith`/`mergeDeepWith` exclude only the merger callback; and `set`, `setIn`, `update`, and `updateIn` retain hostile collection or key/path positions without treating a remote value under a fixed safe key as pollution. Patched branches, the unavailable 3.x functional shape, wrong or read-only APIs/packages, unrelated same-line sources or conversions, reassignment, shadowing, development-only declarations, lockfile-free ranges, inconsistent/v1 locks, and stale metadata remain negative. A topology-identical 5.1.4 exploit/5.1.5 control pair measures an own `__proto__` key replacing only the returned profile's prototype, inherited `admin` authorization, absence of an own field, and unchanged global `Object.prototype`. Dependency-free witnesses, strict CWE-1321 evidence gates, seven direct regressions, package-local cap retention after forty unrelated calls, and three-run integration bring the canonical corpus to 70 pairs and 420 scans. Formatting, generated-model drift, TypeScript, both witnesses, the prior Lodash deletion, `object-path`, `dset`, `flat`, `jsonpath-plus`, and `js-toml` suites, and the corpus gate pass on Windows in 92.14 seconds and native Ubuntu WSL Bun 1.3.14 in 371.78 seconds with 66 tests, 1,518 assertions, and no failures on each platform; the positive preserves source `server.js:8`, sink `storage.js:4`, exact `mergeDeep` provenance, CWE-1321, and nine propagators while the patched twin remains absent.
- Final acceptance for the Immutable.js prototype-replacement increment passes 1,251 tests and 9,515 assertions across 135 files with 20 intentional environment/platform skips and no failures in 377.29 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two fresh compiled self-reviews take 12,368 and 11,952 ms and retain 96 byte-identical rows totaling 206,342 bytes with SHA-256 `709766145a01151359fc4b521736d8fde1e90eadd68474f8b9ceb0d8952c12bc`; the new returned-object replacement path and all eighteen prior package-aware parser, expression, merge, mutation, and deletion rows preserve source line 8, sink line 4, exact sink provenance, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,609,210-byte archive had SHA-1 `2a6d4261e78360d779e6bb64555382e8b559bb0d` and SHA-256 `1b4cc1d006ef0725343195674047d5a16a9995b47c3416beece312657a1f8a82`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `81e65172792d2bf26d60b5e17f8cb0864c5d250aa87594039c6765f293d0d15f`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `5aa00dd18d25401f7505b594a1220294d4cea1a2`: Node `31178914486`, Windows GUI `31178914553`, Linux GUI `31178914309`, container `31178914641`, .NET `31178914488`, Go `31178914385`, and Java `31178914374`.
- Added the standalone `node-http-lodash-prototype-deletion` model for request-derived paths passed to the exact `unset` or `omit` deletion APIs across core `lodash`, `lodash-es`, RequireJS/AMD receivers backed by `lodash-amd`, core/ES subpaths, and the directly callable `lodash.unset` package. Nearest exact runtime or fresh declaration-consistent npm v2/v3 lock proof preserves package, method, repair-stage, and lock-resolved sink provenance. Core/ES/AMD 4.x and `lodash.unset` 4.x are retained below the complete 4.18.0 repair: releases through 4.17.22 accept ordinary dangerous strings, while the incomplete 4.17.23 guard still accepts array-wrapped magic segments and primitive-root traversal. `unset` retains only argument one; `omit` retains every path operand after the target and requires validation of its additional nesting semantics. Patched or pre-API releases, request data used only as the target, read-only and wrong APIs, the separately published non-affected `lodash.omit` package, unsupported import shapes, receiver/member reassignment, wrapper shadowing, development-only declarations, lockfile-free ranges, inconsistent/v1 locks, and stale metadata remain negative. A topology-identical core-Lodash 4.17.23 exploit/current 4.18.1 control pair measures nested-array deletion of `Object.prototype.toString`, later object-coercion failure, cleanup, and the completed segment-normalization guard. Dependency-free witnesses, strict CWE-1321 evidence gates, seven direct regressions, package-local cap retention after forty unrelated calls, and three-run integration bring the canonical corpus to 69 pairs and 414 scans. Formatting, generated-model drift, TypeScript, both witnesses, the prior `object-path`, `dset`, `flat`, `jsonpath-plus`, and `js-toml` suites, and the corpus gate pass on Windows and native Ubuntu WSL Bun 1.3.14 with 59 tests, 1,475 assertions, and no failures on each platform; the positive preserves source `server.js:8`, sink `storage.js:4`, exact array-path `unset` provenance, CWE-1321, and nine propagators while the patched twin remains absent.
- Final acceptance for the Lodash prototype-deletion increment passes 1,244 tests and 9,472 assertions across 134 files with 20 intentional environment/platform skips and no failures in 364.75 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two fresh compiled self-reviews take 13,118 and 12,337 ms and retain 96 byte-identical rows totaling 204,391 bytes with SHA-256 `950f30de2ce5ae659d30d72b87ee2f4b8c99f1fe9cf02d3f01e6f5bd8b5c7c3b`; the new deletion path and all seventeen prior package-aware parser, expression, merge, and mutation rows preserve source line 8, sink line 4, exact sink provenance, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,604,673-byte archive had SHA-1 `35966d23241556935ab4b4d63af00fcdd4b38d6a` and SHA-256 `4f684c5043e3285fe454c7936ab1ddcdffa22169bd29550a984d7ca15e3daafd`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `10decfc0b22bcbeb8d04ff85fd6ae760f44e6412ef6b531946e5ac8e9554216b`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `6582c3bad0ce8c5357a1c5ca2310fd8237ce15c7`: Node `31174940910`, Windows GUI `31174940966`, Linux GUI `31174940911`, container `31174940907`, .NET `31174940925`, Go `31174940877`, and Java `31174940914`.
- Added the standalone `node-http-object-path-prototype-pollution` model across the package's three reviewed repair stages and full mode-sensitive mutating surface. Before 0.11.0, the base instance retains remote path flow through `set` on earlier 0.x lines and through the established 0.10.0 `set`, `ensureExists`, `push`, and `insert` APIs. From 0.11.0, only `withInheritedProps` or a literal `create({includeInheritedProps:true})` instance is eligible: `set` and `ensureExists` remain vulnerable through the 0.11.5 nested-array type-confusion bypass and are repaired in 0.11.6, while `del`, `empty`, `push`, and `insert` remain vulnerable through 0.11.7 and are repaired in 0.11.8. CommonJS and interoperable default receivers, direct or destructured method bindings, inherited aliases, literal configured instances, and callable object-bound APIs are tracked with exact argument shifts: unbound path argument one versus bound path argument zero. Exact-manifest and fresh declaration-consistent npm v2/v3 lock proof retain distinct legacy/inherited and method-specific sink kinds. The 0.11.0+ default instance, pre-inherited `del`/`empty`, false/missing/dynamic inherited configuration, repaired method/version combinations, request data used only as target or value, read-only APIs, namespace guesses, wrong APIs/packages, absent sources, reassignment or shadowing, development-only declarations, lockfile-free ranges, inconsistent/v1 locks, and stale metadata remain negative. A topology-identical 0.11.7 exploit/0.11.8 control pair measures inherited deletion of `Object.prototype.toString` and concrete later coercion failure versus the completed magic-property access guard. Dependency-free witnesses, strict CWE-1321 evidence gates, eight direct regressions, package-local cap retention after forty unrelated calls, and three-run integration bring the canonical corpus to 68 pairs and 408 scans. Formatting, generated-model drift, TypeScript, both witnesses, the prior `dset`, `flat`, `jsonpath-plus`, and `js-toml` suites, and the corpus gate pass on Windows and native Ubuntu WSL Bun 1.3.14 with 52 tests, 1,431 assertions, and no failures on each platform; the positive preserves source `server.js:8`, sink `storage.js:4`, CWE-1321, exact inherited-`del` provenance, and nine propagators while the patched twin remains absent.
- Final acceptance for the `object-path` increment passes 1,237 tests and 9,428 assertions across 133 files with 20 intentional environment/platform skips and no failures in 376.88 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two fresh compiled self-reviews take 14,807 and 14,458 ms and retain 96 byte-identical rows totaling 202,750 bytes with SHA-256 `c654ffee7f5635207102f86d4b11c13fc26175d8efda6fa13e5d904522e38435`; the new inherited object-path deletion path and all sixteen prior package-aware parser/expression/merge paths preserve source line 8, sink line 4, exact sink provenance, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,600,145-byte archive had SHA-1 `7888a162f380fdc0212fe1289333335248180c8d` and SHA-256 `96c826e14d10c86e5ea95bad35f8f5029fc1a88371af9ab62c01346d5f2512a9`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `31044aaf597a5b2fe6513c3cb57378ca9c7db6afc31716e2c5a723b6e1c792fe`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `2f35564f6c598565874b94b9187ab2e25bf8cf8b`: Node `31170619011`, Windows GUI `31170619033`, Linux GUI `31170619015`, container `31170618947`, .NET `31170619046`, Go `31170618962`, and Java `31170619925`.
- Added the standalone `node-http-dset-prototype-pollution` model for remote paths passed to the exact `dset(target, path, value)` API and remote merge values passed only to the historical vulnerable `dset/merge` API. Official v1/v2 default and CommonJS callable exports, v3 named/aliased/destructured functions, namespace and CommonJS receivers, direct require members, and the v3.1+ merge entry point are version-gated to their real published shapes. Exact-manifest and fresh declaration-consistent npm v2/v3 lock provenance remain distinct. Path flow in argument one is retained below the complete 3.1.4 repair boundary, including the nested-array implicit-coercion bypass that survives the earlier 2.1.0 string/flat-array guard through 3.1.3; merge-value flow in argument two is retained only for 3.1.0 and 3.1.1, before the 3.1.2 recursive-merge guard. This corrects the oldest reviewed advisory's stale structured cutoff, which excludes live-vulnerable 2.0.1, and unifies all three historical advisories under executable package behavior. Strict per-position source resolution rejects request data used only as the target, main-package value, or unrelated same-line expression; repaired versions, unavailable export shapes, wrong APIs/packages, absent sources, reassignment or shadowing, development-only declarations, lockfile-free ranges, inconsistent/v1 locks, and stale metadata remain negative. A topology-identical 3.1.3 exploit/3.1.4 control pair measures the nested-array `__proto__` bypass and completed pre-guard coercion. Dependency-free witnesses also reproduce the 3.1.1/3.1.2 merge-value boundary, strict CWE-1321 evidence gates, eight direct regressions, package-local cap retention after forty unrelated calls, and three-run integration bring the canonical corpus to 67 pairs and 402 scans. Formatting, generated-model drift, TypeScript, both witnesses, the prior `flat`, `jsonpath-plus`, and `js-toml` suites, and the corpus gate pass on Windows and native Ubuntu WSL Bun 1.3.14 with 44 tests, 1,392 assertions, and no failures on each platform; the positive preserves source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators while the patched twin remains absent.
- Final acceptance for the `dset` increment passes 1,229 tests and 9,389 assertions across 132 files with 20 intentional environment/platform skips and no failures in 346.50 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two fresh compiled self-reviews take 12,453 and 10,922 ms and retain 96 byte-identical rows totaling 201,395 bytes with SHA-256 `1894b5bfd27ead9c3f80eb6eeaea6136e35f7a995caee56b6eaf349359c68fa1`; the new dset path and all fifteen prior package-aware parser/expression/merge paths preserve source line 8, sink line 4, exact sink provenance, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,592,752-byte archive had SHA-1 `b1885f8b3d5afe92d97bb34df1a63f07da9984cf` and SHA-256 `79598e44cfec965e2f94da9c6623016bd22e28b763d11685d4bcb7d350bc692e`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `3b91ecdd28e6ff2e3d42407b58738de6f78db1893b7c778eb744d5b3445e0f69`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `6b6c2a9b1e08ed43266301a8e5021dbca7941ccd`: Node `31167171201`, Windows GUI `31167171791`, Linux GUI `31167170503`, container `31167170681`, .NET `31167171231`, Go `31167172536`, and Java `31167171154`.
- Added the standalone `node-http-flat-unflatten-prototype-pollution` model for remote objects passed to the exact `flat.unflatten(original, options)` API through named/aliased/destructured bindings, historical default or namespace receivers, CommonJS receivers, and direct require members. Exact-manifest and fresh npm v2/v3 lock provenance cover the complete published vulnerable union: 0.x/1.x below 1.6.2, 2.0.0/2.0.1, 3.0.0, 4.0.0/4.1.0, and 5.0.0, with distinct direct and lock-resolved sink kinds. This improves on the reviewed advisory's impossible machine-readable 4.x repair boundary at unpublished 4.0.2: npm published neither 4.0.1 nor 4.0.2, while upstream references, npm deprecation metadata, and isolated live execution prove 4.1.0 vulnerable and 4.1.1 repaired. Every repaired branch, `flatten` calls, wrong APIs/packages/argument positions, absent sources, reassignment or shadowing, development-only declarations, lockfile-free ranges, inconsistent/v1 locks, and stale metadata remain negative. A topology-identical 4.1.0 exploit/4.1.1 control pair measures delimited `__proto__` traversal into `Object.prototype` and the completed per-segment guard. Dependency-free witnesses, strict CWE-1321 evidence gates, seven direct regressions, package-local cap retention after forty unrelated calls, and three-run integration bring the canonical corpus to 66 pairs and 396 scans. Formatting, generated-model drift, TypeScript, production build, both witnesses, both prior package-parser model suites, and the corpus gate pass on Windows and native Ubuntu WSL Bun 1.3.14 with 36 tests, 1,356 assertions, and no failures on each platform; the positive preserves source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators while the patched twin remains absent.
- Final acceptance for the `flat.unflatten` increment passes 1,221 tests and 9,353 assertions across 131 files with 20 intentional environment/platform skips and no failures in 320.19 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 11,898 and 12,092 ms and retain 96 byte-identical rows totaling 203,608 bytes with SHA-256 `29a5e09e4e40d67e2234c701b5212605b0f7119b1394a8b2e10695481d4c9766`; the new expander path and all fourteen prior package-aware parser/expression/merge paths preserve source line 8, sink line 4, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,588,050-byte archive had SHA-1 `2ac6358c4e256ecb1a16fea572f3147af5a17be1` and SHA-256 `5e766adbc71cd886a143a47bdf0a0e5a31300a5b6cba830b92d7228014176fb2`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `67ae7913a5c37511b5a0124695ddad19a71bd97e4e77af60eeeccd7de3aab7fa`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `6457ebf2d84b050b95503f4b5005b2926079617d`: Node `31163169501`, Windows GUI `31163169539`, Linux GUI `31163169513`, container `31163169561`, .NET `31163169526`, Go `31163169595`, and Java `31163169635`.
- Added the standalone `node-http-jsonpath-plus-code-injection` model for remotely controlled JSONPath expressions passed through official `jsonpath-plus` named/aliased/destructured bindings, namespace or CommonJS receivers, direct require members, object options, positional calls, and constructor calls. Default, `true`, `undefined`, and explicit `safe` evaluation require nearest exact runtime or fresh npm v2/v3 lock proof below the complete upstream 10.4.0 repair boundary, extending coverage past reviewed advisories that stop at 10.3.0; explicit `eval: "native"` is a version-independent code-execution sink, while `eval: false` and unproved custom evaluators are hard negatives. Distinct exact, lock-resolved, and native sink provenance survives same-file and cross-file wrapper propagation. Patched safe evaluation, default-import or wrong-member guesses, wrong packages, request data used only as JSON input, reassignment or shadowing, development-only metadata, lockfile-free ranges, inconsistent/v1 locks, and stale metadata remain negative. A topology-identical 10.3.0 exploit/10.4.0 control pair measures the later `__lookupGetter__` / recovered-`Function` bypass and its completed repair; dependency-free witnesses, strict CWE-94 evidence gates, seven direct regressions, package-local candidate-cap retention, and three-run integration bring the canonical corpus to 65 pairs and 390 scans. A per-inventory nearest-runtime-dependency cache eliminates repeated manifest traversal without persisting across immutable source snapshots: the Windows repository-retention path returned from 54.49 seconds to 13.99 seconds while preserving prior `js-toml` results. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass on Windows and native Ubuntu WSL Bun 1.3.14 with 29 tests, 1,322 assertions, and no failures on each platform; the positive preserves source `server.js:8`, sink `storage.js:4`, CWE-94, and nine propagators while the patched twin remains absent.
- Final acceptance for the `jsonpath-plus` expression-injection increment passes 1,214 tests and 9,319 assertions across 130 files with 20 intentional environment/platform skips and no failures in 326.76 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 12,129 and 11,950 ms and retain 96 byte-identical rows totaling 201,586 bytes with SHA-256 `4851547a97fd700b5cf9045614c07237e4cc77158108404f658d88714ebf8f67`; the new CWE-94 expression path and all thirteen prior package-aware parser/merge paths preserve source line 8, sink line 4, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,586,822-byte archive had SHA-1 `ae10a1d126eb2f3eb0b310ad6f547b40588cbc58` and SHA-256 `cdb3f65c23d19c02dcc0d4f3b07e4e79d86da3bc07724a11d7a872c31e528d78`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `d9a389697029caa43106d44c606fe011614188f558b8254b03def99afff72589`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass without retries at checkpoint `4f35d287048683795e08bef82a583ad8f90aa365`: Node `31160335629`, Windows GUI `31160335204`, Linux GUI `31160335182`, container `31160335189`, .NET `31160335186`, Go `31160336042`, and Java `31160337536`.
- Added the standalone `node-http-js-toml-prototype-pollution` model for untrusted text passed to the official `js-toml.load(text)` parser with a nearest runtime dependency below the reviewed 1.0.2 repair boundary. Official named/aliased/destructured bindings, namespace and CommonJS receivers, and direct `require("js-toml").load` bindings are supported with exact-manifest or fresh npm v2/v3 lock-resolved provenance and distinct `vulnerable-js-toml-load` / `lock-resolved-vulnerable-js-toml-load` sink kinds. Package-specific activation avoids scanning unrelated call-heavy files, while a 64-candidate package-local bound retains a valid `load` after forty unrelated calls. Patched 1.0.2+, default-import guesses, wrong functions or packages, nonzero argument flow, missing sources, reassignment or shadowing, development-only declarations, lockfile-free ranges, inconsistent or v1 locks, and stale metadata remain negative. A topology-identical 1.0.1 exploit/1.0.2 control pair measures the real repair: vulnerable ordinary parser objects let a `[__proto__]` table reuse `Object.prototype`, while 1.0.2 creates null-prototype root and nested objects. Dependency-free vulnerable/patched witnesses, concrete-impact reviewer guidance, six direct model regressions, strict specialized cases, repository-cap retention, and three-run main integration bring the canonical corpus to 64 pairs and 384 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass on Windows and native Ubuntu WSL Bun 1.3.14 with 22 tests, no failures, and 1,289 assertions on each platform; the positive preserves source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators while the patched twin remains absent.
- Final acceptance for the `js-toml` parser increment passes 1,207 tests and 9,286 assertions across 129 files with 20 intentional environment/platform skips and no failures in 318.08 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 12,083 and 10,848 ms and retain 96 byte-identical rows totaling 237,921 bytes with SHA-256 `91a01b9e1c7cace2498a258036e83b6bac9a3dbfd254bf45ca8355194c3e5ec0`; the new parser path and all twelve prior exact/lock/standalone merge-family paths preserve source line 8, sink line 4, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The safely removed 1,584,336-byte archive had SHA-1 `7c85c66b574f279dfc7cbcc2415e14746a720dc5` and SHA-256 `596b6548d6a18886b4b7e818845109d6f77470589d82a7bb6320e9802e8de7ff`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `ce9f56b7689313d5afbda05985dc934879dbd9aa2206d531cac81334451ddba5`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass at checkpoint `0b42d32d6e66e669eee219f023c4e1454d7ff7bb`: Node `31156940324`, Windows GUI `31156939818`, Linux GUI `31156940193`, container `31156939958`, .NET `31156939758`, Go `31156942544`, and Java `31156939717`.
- Extended `node-http-prototype-merge` to the exact `merge` package's always-recursive `.recursive` API across the complete later-reviewed vulnerable range below 2.1.1. This deliberately improves on CodeQL's older below-1.2.1 package boundary by retaining vulnerable 1.2.1 and 2.1.0. Official default, namespace, CommonJS receiver, named/destructured `recursive`, and direct `require("merge").recursive` bindings are supported with package-isolated nearest exact or fresh npm-lock-resolved runtime provenance; optional leading clone booleans preserve argument-one source extraction. Patched 2.1.1+, shallow `merge(...)`, target-only or absent remote sources, wrong-package declarations, receiver or member reassignment, stale metadata, and patched lock resolutions remain negative. A topology-identical 2.1.0 exploit/2.1.1 control pair proves the real nested bypass: 2.1.0 filters `__proto__`, `constructor`, and `prototype` only in its outer loop, so a dangerous key beneath a benign key and pre-existing nested destination reaches `Object.prototype`; 2.1.1 repeats the filter inside the recursive helper. Dependency-free upstream-semantics witnesses, adversarial version/API/binding cases, perfect-gate specialized cases, whole-repository cap retention, and three-run integration bring the canonical benchmark to 63 pairs and 378 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass on Windows with 32 tests, one intentional symlink skip, no failures, and 1,421 assertions; native WSL Bun 1.3.14 passes all 33 focused tests and 1,422 assertions, including the POSIX lock-symlink rejection.
- Final acceptance for the `merge.recursive` increment passes 1,201 tests and 9,254 assertions across 128 files with 20 intentional environment/platform skips and no failures in 290.82 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 13,067 and 11,896 ms and retain 96 byte-identical rows totaling 272,980 bytes with SHA-256 `0f43c887ee6a41c2a8c6d32fedbecf9cea3e9ee7df0d60d28f4b0394b969a73b`; all twelve core-exact, core-lock, standalone-Lodash, `merge-deep`, `extend`, `deep-extend`, `just-extend`, `merge-options`, `node.extend`, `assign-deep`, `mixin-deep`, and `merge.recursive` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs with 80 packages each and two Ubuntu Node 22.23.1 installs with 88 packages each validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,582,679-byte archive had SHA-1 `86676583e10836a43091edd9cda3e5d87ba38c00` and SHA-256 `3f90c6a5c4a50ec49c6728abcd4bc0495a6648e21e47552c3fa4e6e17d5859e3`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `735f6eaacb344fdf5c6160d7f863306cc6d7d387125890ab8c59206b9fa6a4d2`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass at checkpoint `d4cce33494dd3ff871852f85b8a361d3cb14ce83`: Node run `31153303764`, Windows GUI `31153303770`, Linux GUI `31153303803`, container `31153303775`, .NET fixture `31153303772`, Go fixture `31153303780`, and Java fixture `31153303808`. The first Node run's Windows matrix job alone reached the native format-string benchmark's 45-second GCC startup deadline with empty output after 1,200 other passes; its failed-job-only rerun passed the full test, format, build, pack, inspection, and runtime-smoke sequence at the unchanged exact head, identifying transient hosted compiler latency rather than a source defect.
- Extended `node-http-prototype-merge` to the always-recursive direct callable exported by `mixin-deep`, preserving GitHub's complete reviewed vulnerable union below 1.3.2 plus exactly 2.0.0 while adding package-isolated exact and npm-lock-resolved provenance. The model requires remote data after the destination and deliberately does not inherit `assign-deep`'s primitive-target argument shift: `mixinDeep(0, request.body)` still treats the request value as a source and can traverse a built-in prototype. Patched 1.3.2 through later 1.x releases, 2.0.1+, target-only or absent source data, wrong-package declarations, namespace/named import guesses, reassignment, stale metadata, and patched lock resolutions remain negative. Reviewer guidance distinguishes advisory membership from exploit proof: published dependency-free 2.0.0 accepts the canonical parser-produced `constructor.prototype` payload, while 1.x review must also validate the installed `is-extendable` / `is-plain-object` predicate because a fresh 1.3.1 dependency graph rejects that particular JSON shape before recursion. A topology-identical 2.0.0 exploit/2.0.1 control pair, dependency-free upstream-semantics witnesses, adversarial disjoint-range/API cases, perfect-gate specialized cases, whole-repository cap retention, and three-run integration bring the canonical benchmark to 62 pairs and 372 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass on Windows with 31 tests, one intentional symlink skip, no failures, and 1,394 assertions; native WSL Bun 1.3.14 passes all 32 focused tests and 1,395 assertions, including the POSIX lock-symlink rejection.
- Final acceptance for the `mixin-deep` increment passes 1,200 tests and 9,227 assertions across 128 files with 20 intentional environment/platform skips and no failures in 290.27 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 12,607 and 11,599 ms and retain 96 byte-identical rows totaling 195,613 bytes with SHA-256 `c55cd43ac4691507846394dd05663c841ae4f7ee369b2b7ac651dc2624e32c75`; all eleven core-exact, core-lock, standalone-Lodash, `merge-deep`, `extend`, `deep-extend`, `just-extend`, `merge-options`, `node.extend`, `assign-deep`, and `mixin-deep` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,564,467-byte archive had SHA-1 `c8e0510b8feaef1c0f5ed2660a7d35ea6e82dbba` and SHA-256 `e56f065040a9f3342dffcfb1086abaf7e40f114b30f734ba9f18ca8521861d26`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `c5c2783a9f2fd44e10c01c511253a31b0b69f4aab1656066456741832e8c7260`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass at checkpoint `d35fc576f0eaedd9a057aa19ca933f6c6dbc662a`: Node run `31150833335`, Windows GUI `31150833359`, Linux GUI `31150833350`, container `31150833388`, .NET fixture `31150833364`, Go fixture `31150833340`, and Java fixture `31150833337`.
- Extended `node-http-prototype-merge` to the always-recursive direct callable exported by `assign-deep`, using the complete reviewed vulnerable union below 0.4.8 plus exactly 1.0.0. This deliberately improves on CodeQL's older below-0.4.7 model by retaining vulnerable 0.4.7 and 1.0.0. The model requires package-isolated nearest exact or npm-lock-resolved runtime evidence and remote data in a source operand after the destination; an obviously primitive first operand shifts the next operand into the destination, matching upstream behavior and avoiding a false positive. Patched 0.4.8, the 0.5.x gap, 1.0.1+, target-only or primitive-shifted data, wrong-package declarations, namespace/named import guesses, reassignment, stale metadata, and patched lock resolutions remain negative. Exact and lock-resolved findings retain distinct `assign-deep` sink provenance. Reviewer guidance preserves the strict-runtime mutation-before-throw ordering and requires an application error boundary or other concrete later effect instead of treating a late read-only assignment failure as rollback. A matched 0.4.7 exploit/0.4.8 control pair, dependency-free upstream-semantics witnesses, adversarial disjoint-range and API cases, perfect-gate specialized cases, whole-repository cap retention, and three-run integration bring the canonical benchmark to 61 pairs and 366 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass on Windows with 30 tests, one intentional symlink skip, no failures, and 1,368 assertions; native WSL Bun 1.3.14 passes all 31 focused tests and 1,369 assertions, including the POSIX lock-symlink rejection.
- Final acceptance for the `assign-deep` increment passes 1,199 tests and 9,201 assertions across 128 files with 20 intentional environment/platform skips and no failures in 286.94 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 12,802 and 12,168 ms and retain 96 byte-identical rows totaling 193,689 bytes with SHA-256 `c3848730247416892dd2403dc8b39ff8697b8e6df1d43ec02d4f7f007a29c380`; all ten core-exact, core-lock, standalone-Lodash, `merge-deep`, `extend`, `deep-extend`, `just-extend`, `merge-options`, `node.extend`, and `assign-deep` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,580,833-byte archive had SHA-1 `b1d2efd756bb587b0dd52e7a897bc56c93c9d35f` and SHA-256 `8aab43b62e27bcd3bfc0db90c46660ab5a301fb31d1952232be7277f5a24969e`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `2fb0fef49666729c989701fa39ea7add9677f49d33c667e72a578fd62df35363`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass at checkpoint `725fd5f17ac6ada9073d475bb621dba25c58f0ce`: Node run `31148479407`, Windows GUI `31148479574`, Linux GUI `31148479604`, container `31148479545`, .NET fixture `31148479414`, Go fixture `31148479514`, and Java fixture `31148479391`.
- Extended `node-http-prototype-merge` to the direct callable exported by `node.extend`, preserving the reviewed and CodeQL disjoint vulnerable sets below 1.1.7 and exactly 2.0.0. The model requires a matching nearest exact or npm-lock-resolved runtime dependency, the literal recursive form `extend(true, target, ...sources)`, and remote data after both the deep flag and target. Patched 1.1.7 through later 1.x releases, 2.0.1+, shallow/false/dynamic mode, target-only flow, wrong-package declarations, namespace/named import guesses, reassignment, stale metadata, and patched lock resolutions remain negative. Exact and lock-resolved findings retain distinct `node.extend` sink provenance. A topology-identical 2.0.0 exploit/2.0.1 control pair, dependency-free upstream-semantics witnesses, disjoint-range adversarial cases, reviewer guidance, perfect-gate specialized cases, whole-repository cap retention, and three-run integration bring the canonical benchmark to 60 pairs and 360 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass on Windows with 29 tests, one intentional symlink skip, no failures, and 1,341 assertions; native WSL Bun 1.3.14 passes all 30 focused tests and 1,342 assertions, including the POSIX lock-symlink rejection.
- Final acceptance for the `node.extend` increment passes 1,198 tests and 9,174 assertions across 128 files with 20 intentional environment/platform skips and no failures in 292.42 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 12,003 and 10,961 ms and retain 96 byte-identical rows totaling 231,430 bytes with SHA-256 `210d3df14836a4e0c30b2e9645cb334839cf17c0b7ff151bfd5310c834d3690b`; all nine core-exact, core-lock, standalone-Lodash, `merge-deep`, `extend`, `deep-extend`, `just-extend`, `merge-options`, and `node.extend` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,579,651-byte archive had SHA-1 `550e408ce0bd802fc32a16b3ec685ddecccd43fc` and SHA-256 `20b39e3b8778c210084f6bef29791b198c7c540c1782d700ed6fee88ab955eea`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `68f7a9729c88cbe83f4a6e50e1f1532a4adf78481a99f4c54757df9e9ecc6264`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass at checkpoint `312a91254a4d40befba11e097b2d4e98b2ad129d`: Node run `31145392820`, Windows GUI `31145392841`, Linux GUI rerun `31145392877`, container `31145392847`, .NET fixture `31145392839`, Go fixture `31145392867`, and Java fixture `31145392818`. The first Linux attempt passed package/build/test/publish/non-graphical steps but hit the 20-second X11 watchdog; its unchanged exact-head failed-job rerun passed the complete job in 2m20s, matching local X11 acceptance and identifying a hosted liveness flake rather than a source defect.
- Extended `node-http-prototype-merge` to the always-recursive direct callable exported by `merge-options`, with package-isolated exact and npm-lock runtime proof below the reviewed and upstream-patched 1.0.1 boundary. Unlike target-mutating merge APIs, `mergeOptions(option1, ...options)` treats every argument—including argument zero—as a source and returns a new object. Patched 1.0.1+, zero-argument calls, wrong-package declarations, namespace/named import guesses, reassignment, stale metadata, and patched lock resolutions remain negative. Exact and lock-resolved findings retain distinct `merge-options` sink provenance. A topology-identical 1.0.0 exploit/1.0.1 control pair, dependency-free upstream-semantics witnesses, adversarial argument-position/package/version/API cases, perfect-gate specialized cases, whole-repository cap retention, and three-run integration bring the canonical benchmark to 59 pairs and 354 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass with 28 tests, one intentional Windows symlink skip, no failures, and 1,316 assertions; native WSL Bun 1.3.14 passes all 29 focused tests and 1,317 assertions, including the POSIX lock-symlink rejection.
- Final acceptance for the `merge-options` increment passes 1,197 tests and 9,149 assertions across 128 files with 20 intentional environment/platform skips and no failures in 305.31 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 12,711 and 12,791 ms and retain 96 byte-identical rows totaling 240,902 bytes with SHA-256 `e5fa882e460322d0b2160d5a80af7e1586f8f7c473945a8e5f711945fd13f8db`; all eight core-exact, core-lock, standalone-Lodash, `merge-deep`, `extend`, `deep-extend`, `just-extend`, and `merge-options` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,579,072-byte archive had SHA-1 `34e6099578394ee6e6fda73861a12296a3c88daf` and SHA-256 `456c0e3a76c3ff25e49e6a5d9db5c50fa10d2d6d21aea681935803b9b3ab2df2`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `a02b8577ce4e2d989c14e31fefaaacfae31557e3f25b1e9861592e4ccf937b48`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass at checkpoint `f507c5cd104bc23522d90401522acf8d82f22f83`: Node run `31143355192`, Windows GUI `31143355130`, Linux GUI `31143355174`, container `31143355126`, .NET fixture `31143355154`, Go fixture `31143355112`, and Java fixture `31143355113`.
- Extended `node-http-prototype-merge` to literal-recursive calls of the direct `just-extend` default/CommonJS callable, using the upstream and CodeQL boundary below 4.0.1 rather than GitHub's reviewed advisory's stale claim that 4.0.0 was patched. Exact and npm-lock-resolved runtime proof retain distinct package-specific sink provenance. The model requires `extend(true, target, ...sources)` and remote data after both the deep flag and target; 4.0.1+, shallow/false/dynamic mode, target-only flow, package mismatch, namespace/named import guesses, reassignment, and unsafe metadata remain negative. A topology-identical 4.0.0 exploit/4.0.1 control pair measures the repaired global `Object.prototype` traversal through a fresh policy object, while its dependency-free control explicitly preserves target-local prototype replacement as separate review evidence. Adversarial exact/lock/API tests, perfect-gate cases, whole-repository cap retention, and three-run corpus integration bring the canonical benchmark to 58 pairs and 348 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass with 27 tests, one intentional Windows symlink skip, no failures, and 1,292 assertions; native WSL Bun 1.3.14 passes all 28 focused tests and 1,293 assertions, including the POSIX lock-symlink rejection.
- Final acceptance for the `just-extend` increment passes 1,196 tests and 9,125 assertions across 128 files with 20 intentional environment/platform skips and no failures in 283.79 seconds. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 13,891 and 13,459 ms and retain 96 byte-identical rows totaling 259,211 bytes with SHA-256 `561f39b21064c29ff36084de28c71d10418d6dc03a47598099348a8928c117b6`; all seven core-exact, core-lock, standalone-Lodash, `merge-deep`, `extend`, `deep-extend`, and `just-extend` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,578,440-byte archive had SHA-1 `138bdb600ec667fb5fe6e3c73c08676370609ef2` and SHA-256 `8f5252c60ecfa670f01d4ad9438135a3bf29acb7d8b4e4fa181dc40ea9c75ab2`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `720dd710611434c0c1e7db309fddb7d0caa3ed033149fa93da8f6f5c025499f8`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus real X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven exact implementation-head workflows pass at checkpoint `b07fdd8f1a342365d769e356d71ba2aaeaf7ed52`: Node run `31141499691`, Windows GUI `31141499891`, Linux GUI `31141499458`, container `31141499838`, .NET fixture `31141499357`, Go fixture `31141499983`, and Java fixture `31141499524`.
- Hardened Linux real-window smoke termination after hosted run `31138697718` passed package inspection, locked restore, build, all 12 core/shared/Linux tests, publish, and non-graphical startup but again reached the unchanged 20-second X11 watchdog after the window opened. The exact `--ui-smoke-test` path still attempts window close and explicit Avalonia lifetime shutdown first, then uses a five-second process-level fallback armed only by the real `Opened` event; ordinary GUI execution is unchanged, and a window that never opens still fails the external watchdog. The headless test injects and observes the fallback callback without terminating its process. Locked WSL build and 2/2 Linux tests pass, followed by five consecutive real X11/Xvfb runs under the unchanged 20-second timeout.
- Hosted `linux-gui-ci` run `31139671854` accepts the bounded smoke fallback at repair checkpoint `badfbfc93521f7ee4a51254e7ce9dfdaf1609f9a`: the formerly timing-out real X11 step passes, installable archive assembly and retention complete, and the full job succeeds in 2 minutes 9 seconds.
- Extended `node-http-prototype-merge` to the always-recursive direct callable exported by `deep-extend`, with an isolated critical-vulnerability boundary below 0.5.1. Default imports and CommonJS assignments qualify only with matching nearest runtime manifest or fresh npm v2/v3 lock evidence and remote data in a source operand after the target. Patched 0.5.1+, wrong-package declarations, namespace/named import guesses, reassignment, target-only flow, and patched lock resolutions remain negative. Exact and lock-resolved findings retain distinct `deep-extend` sink provenance. Package/version selection and sink provenance now use exhaustive typed dispatch instead of a growing nested conditional, preserving independent ranges for all six merge identities. A topology-identical four-file 0.5.0 exploit/0.5.1 control pair, dependency-free upstream-semantics witnesses, perfect-gate specialized cases, repository-cap retention, adversarial package/version/API tests, and three-run corpus integration bring the canonical benchmark to 57 pairs and 342 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass with 26 tests, one intentional Windows symlink skip, 0 failures, and 1,268 assertions.
- Final local acceptance for the `deep-extend` increment passes 1,195 tests and 9,101 assertions across 128 files with 20 intentional environment/platform skips and no failures in 281.78 seconds. Formatting, generated-model drift, TypeScript, the clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 13,488 and 11,815 ms and retain 96 byte-identical rows totaling 257,908 bytes with SHA-256 `fc96dc917e0225086a138e664a7de328e17475ac2b0d5ac4e01426ac063b1a8f`; all six core-exact, core-lock, standalone-Lodash, `merge-deep`, `extend`, and `deep-extend` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,559,031-byte archive had SHA-1 `869278622c609834bd12b9597aac685b1618b3db` and SHA-256 `b172f7386c905c06cd7083f2962caef07d1bfea4e478a64987ed32500cbbcf68`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `54fe0fdde2c5d7705c704c981e57af043279ee4ca0c0c24fd092d11495329f0f`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, passes non-graphical plus X11/Xvfb startup, and passes all 11 focused model tests including the POSIX lock-symlink boundary; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Exact scanner checkpoint `40986ecd3772d9a46ca9a3a08adfdcfdd6f53b62` and GUI liveness repair `badfbfc93521f7ee4a51254e7ce9dfdaf1609f9a` are pushed.
- Hosted acceptance is complete across the scanner and GUI-only repair checkpoints: Node run `31139671868`, Windows GUI `31139671887`, repaired Linux GUI `31139671854`, .NET fixture `31139671860`, Go fixture `31139671852`, and Java fixture `31139672083` pass at `badfbfc93521f7ee4a51254e7ce9dfdaf1609f9a`; container run `31138697775` passes the unchanged scanner/package content at `40986ecd3772d9a46ca9a3a08adfdcfdd6f53b62`.
- Extended `node-http-prototype-merge` to the standalone `extend` package with package-isolated exact and npm-lock version proof across both reviewed affected ranges: 1.1.3 through 2.0.1 and 3.0.0 through 3.0.1. Only direct default/CommonJS calls whose first argument is the literal `true` qualify, and request data must reach a source operand after the deep flag and target. Patched 2.0.2/3.0.2 releases, later minor lines, the pre-affected 1.1.2 boundary, omitted/false/dynamic deep mode, target-only flow, namespace/named imports, reassignment, wrong-package declarations, and patched lock resolutions remain negative. Exact and lock-resolved findings use distinct `extend` sink provenance. A topology-identical four-file 3.0.1 exploit/3.0.2 control pair, dependency-free historical/patched witnesses, perfect-gate specialized cases, repository-cap retention, and three-run corpus integration bring the canonical benchmark to 56 pairs and 336 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass with 25 tests, one intentional Windows symlink skip, 0 failures, and 1,246 assertions.
- Final local acceptance for the `extend` increment passes 1,194 tests and 9,079 assertions across 128 files with 20 intentional environment/platform skips and no failures in 310.89 seconds. Formatting, generated-model drift, TypeScript, the clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 13,191 and 11,299 ms and retain 96 byte-identical rows totaling 256,330 bytes with SHA-256 `44a42bec153df2490b68fcf553fe02fd47ec39f395b5d83118fa6484f6fa6185`; all five core-exact, core-lock, standalone-Lodash, `merge-deep`, and `extend` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry archive; three fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,557,436-byte archive had SHA-1 `41fbb2ad7586789e0a53696ce91fa551428ad873` and SHA-256 `67795ff1acf2f8f80c67ca72e8225e9c9b7cdcd51059442424dba10080c6bc23`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `6e8c85314fefe2176d7c2e0a03cfb5734d2efd246518503235ec80c9462b9f94`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, passes non-graphical plus X11/Xvfb startup, and passes the formerly skipped POSIX lock-symlink boundary in a 10/10 focused test run; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Exact implementation checkpoint `9cd50e02047a46b73d2d2af282afc3d60bf77ba6` is pushed.
- All seven hosted workflows pass at exact `extend` implementation checkpoint `9cd50e02047a46b73d2d2af282afc3d60bf77ba6`: Node run `31136636109`, Windows GUI `31136636758`, Linux GUI `31136636043`, container `31136635642`, .NET fixture `31136636541`, Go fixture `31136636501`, and Java fixture `31136635701`.
- Hosted `linux-gui-ci` run `31135258027` confirms the deterministic UI-smoke repair: the formerly timing-out real X11 step passes under the unchanged 20-second watchdog, the installable archive is assembled and retained, and the complete job succeeds in 2 minutes 23 seconds at repair checkpoint `193571271d1bd595256514e9dcbaa2cb04b33707`.
- Made Linux X11 UI-smoke shutdown deterministic after hosted `linux-gui-ci` run `31134089022` passed package inspection, locked restore, build, core/shared/headless tests, publish, and non-graphical startup but timed out waiting for the opened Avalonia window to terminate. UI-smoke mode now uses explicit lifetime shutdown, posts close after the real `Opened` event, disposes the window, and guarantees `Shutdown(0)` in `finally`; the external 20-second watchdog is unchanged. The headless Linux test now exercises the same configured close/shutdown callback and verifies both shutdown request and hidden window state. Locked WSL build and 2/2 Linux tests pass, and the published binary completes five consecutive real X11/Xvfb UI-smoke runs within the unchanged timeout.
- Extended `node-http-prototype-merge` to the direct callable exported by `merge-deep`, with an isolated critical-vulnerability boundary below 3.0.3. Default imports and CommonJS assignments qualify only with matching nearest runtime manifest or fresh npm v2/v3 lock evidence; 3.0.3+, wrong-package declarations, namespace/named import guesses, reassignment, and target-only flow are rejected. Exact and lock-resolved findings retain distinct `merge-deep` sink provenance. A topology-identical four-file 3.0.2 exploit/3.0.3 control pair, dependency-free witnesses, perfect-gate specialized cases, repository-cap retention, adversarial package/version/API tests, and three-run corpus integration bring the canonical benchmark to 55 pairs and 330 scans. The first integrated run was rejected because changed wrapper names made the new nine-hop path structurally valid but not byte-for-byte equal to the established topology; the fixtures were corrected rather than weakening the assertion. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass with 24 tests, one intentional Windows skip, 0 failures, and 1,223 assertions.
- Final local acceptance for the `merge-deep` increment passes 1,193 tests and 9,056 assertions across 128 files with 20 intentional environment/platform skips and no failures in 277.50 seconds. Formatting, generated-model drift, TypeScript, the clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 13,120 and 11,851 ms and retain 96 byte-identical rows totaling 253,758 bytes with SHA-256 `d1796ef728e7ef45355b8daee6c5217a4d0e61c06e099ec07368ee64f493cd64`; all four core-exact, core-lock, standalone-Lodash, and `merge-deep` rows preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while every patched twin remains absent. Strict inspection validates a 251-entry npm archive; three fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,576,120-byte archive had SHA-1 `8bb4a8939d68ae0057dbc7f26360ec4a7f3fd18b` and SHA-256 `abfa4e35021750e44278b82a77ac0366d8e1b4f4ebfa854dc2cfeabb1dc93e0b`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `33d1657c6775bc00ebedc9138a336aa8e4f25ce4a5adadc19df645bfd26df916`. WSL performs locked restores, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, passes non-graphical plus X11/Xvfb startup, and rejects a symlinked vulnerable `merge-deep` lockfile; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Exact implementation checkpoint `8680a3b88bb51ebb2ebf7629638ae1b13fab9024` is pushed.
- Hosted acceptance for standalone `lodash.merge` implementation checkpoint `f0bc9c1d2d9dd52a2a7b4551089c6f7b3e69856e` is complete: Node, Windows GUI, Linux GUI, container, .NET fixture, Go fixture, and Java fixture workflows all pass. The repository remains public.
- Extended `node-http-prototype-merge` to the separately versioned standalone `lodash.merge` package while preserving package-specific proof. Direct default imports and CommonJS callable bindings qualify only when the matching nearest runtime dependency resolves below 4.6.2; patched 4.6.2+, unsupported namespace/named imports, reassignment, target-only flow, and declarations for core `lodash` are rejected. Exact and npm-lockfile proof retain distinct standalone sink identities, and neither package can authorize the other's import. A topology-identical four-file 4.6.1 exploit/4.6.2 control pair, dependency-free witnesses, perfect-gate specialized cases, three-run corpus cases, repository-cap retention, and adversarial exact/lock/package-isolation coverage bring the canonical corpus to 54 pairs and 324 scans. Formatting, generated-model drift, TypeScript, both witnesses, and the focused model/corpus gate pass; the gate has 23 passing tests, one intentional Windows skip for the POSIX lock-symlink boundary, no failures, and 1,201 assertions.
- Final local acceptance for the standalone `lodash.merge` increment passes 1,192 tests and 9,034 assertions across 128 files with 20 intentional environment/platform skips and no failures in 269.00 seconds. Formatting, generated-model drift, TypeScript, the clean production build, and the production advisory audit pass with no known vulnerabilities. Two compiled self-reviews take 13,252 and 11,288 ms and retain 96 byte-identical rows totaling 251,959 bytes with SHA-256 `5a29b51f5c5004b8609e9f6fa773df3c52d0045214bc8a532c1eac9cb702e850`; the standalone 4.6.1 fixture preserves source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while the 4.6.2 control remains absent. Strict inspection validates a 251-entry npm archive; four fresh Windows installs and two Ubuntu Node 22.23.1 installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,575,633-byte archive had SHA-1 `c047c2f032478eec29d5b1c093ea61cd31e2f235` and SHA-256 `a82abf6f891c344d2613b192b6f3c9dd5e823379489c5301ba296ba02da41300`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `caa5326a295a087e26c95ff15d7370d545399cf4308732ed0320174f29c04d8c`. WSL performs locked restores under a Linux-only path, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, passes non-graphical plus X11/Xvfb startup, and separately rejects a symlinked vulnerable npm lockfile; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Exact implementation checkpoint `f0bc9c1d2d9dd52a2a7b4551089c6f7b3e69856e` is pushed.
- Corrected-cutoff acceptance passes the complete authoritative suite with 1,191 tests, 20 intentional skips, 0 failures, and 9,012 assertions across 128 files in 280.97 seconds. A clean compiled self-review retains both vulnerable 4.17.10 fixtures and excludes the 4.17.11/4.17.21 boundaries; repeated passes take 14,883 and 12,198 ms, produce 96 byte-identical rows totaling 248,883 bytes, and have SHA-256 `a14586585da6c04971f8f2721c1d75d2f9fd19ba3d83042fff11ee4021207b03`. Formatting, generated-model drift, TypeScript, and clean build pass. This exact rerun replaces the vulnerable-version portion of the earlier 4.17.11 acceptance claim.
- Corrected the core `lodash.merge` vulnerability cutoff from versions below 4.17.12 to versions below 4.17.11. Lodash's own changelog says 4.17.11 ensured `_.merge` no longer augments `Object.prototype`, and CodeQL's current high-precision query help describes the primitive as vulnerable prior to 4.17.11; 4.17.12 is a broader package-upgrade recommendation and was too coarse for this exact call model. Both exact-pin and lock-resolved exploit fixtures now use 4.17.10, while exact and resolved 4.17.11 are sharp boundary negatives alongside 4.17.21. This supersedes the vulnerable-version interpretation in the preceding acceptance record without invalidating its orchestration, metadata, package, GUI, or platform evidence. The focused model plus complete corpus contract pass 22 tests and 1,179 assertions with one intentional POSIX symlink skip; TypeScript and generated-model checks pass. Corrected implementation checkpoint `3f74f5ad3a124442c79d721e83af485a97cc0592` is pushed.
- Final local acceptance for npm lockfile-resolved Lodash proof passes 1,191 tests and 9,012 assertions across 128 files with 20 intentional environment/platform skips and no failures in 300.36 seconds. The added skip is the POSIX-only lock-symlink test, which separately passes against the compiled scanner under WSL Node 22.23.1. Formatting, generated-model drift, TypeScript, clean production build, and the production advisory audit are clean. Repeated compiled self-review takes 13,455 and 11,993 ms and retains 96 byte-identical rows totaling 248,691 bytes with SHA-256 `37fad0b7dfd11aeb385ba26a2f11035f7443ae80e4ed9bcbb923319acabd793f`; both vulnerable Lodash fixtures preserve source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators with distinct exact/lock provenance, while both patched twins remain absent. Strict inspection validates a 251-entry, 1,574,935-byte npm archive; three fresh Windows installs and Ubuntu Node 22.23.1 validate public import, CLI behavior, and all 79 bundled plugin files. The removed archive had SHA-1 `f6cb66e9b2b008f0aef00e549d2117e987ce9272` and SHA-256 `ca3f334f40726d46b93305486ff4b2a373cf2cf68d7cf005e5a7fcf025334a3f`. Windows builds with zero warnings/errors, passes 7/7 core and 3/3 shared tests, and publishes a 346,796-byte executable with SHA-256 `59bfac3e4fed206d2d7ef65d18e10206d2314d88fb5c957060e65d0844e2bde8`. WSL performs locked restores under a Linux-only path, builds with zero warnings/errors, passes 7/7 core, 3/3 shared, and 2/2 Linux tests, and passes non-graphical plus X11/Xvfb startup; its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Initial sandboxed package inspection and Windows publication were rejected only when npm/NuGet could not reach their normal cache/advisory boundaries; unchanged elevated reruns passed. Exact accepted checkpoint `1bb704b8a203ed66f142ac544a6e4abfd63bd1ef` has no hosted runs while GitHub reports an Actions major outage and throttled push/PR triggers; the repository remains public.
- Extended `node-http-prototype-merge` from exact manifest pins to high-precision npm lockfile proof for ordinary registry semver ranges. The nearest runtime `package.json` declaration must be repeated byte-for-byte in `packages[""]` of adjacent npm lockfile version 2 or 3, and `packages["node_modules/lodash"].version` must be an exact vulnerable version below 4.17.11. `npm-shrinkwrap.json` takes precedence over `package-lock.json`; stale, v1, missing-installed-entry, patched, malformed, oversized, NUL-containing, or symlinked locks fail closed, as do tags, aliases, workspaces, paths, Git sources, development-only declarations, and lockfile-free ranges. Lock metadata is kept outside executable-source discovery and bounded independently to 128 files, 4 MiB per file, and 16 MiB total. Exact manifest pins remain accepted without a lockfile. An unreadable, oversized, or symlinked child manifest now stops package-boundary lookup instead of inheriting an ancestor's dependency evidence.
- Added a topology-identical lock-resolved Lodash exploit/control pair to the perfect-gate specialized benchmark and three-run main corpus. Both use `lodash: ^4.17.0`; npm v3 evidence resolves the exploit to 4.17.10 and the control to patched 4.17.21. Dependency-free witnesses preserve historical `constructor.prototype` impact without installing a vulnerable package. The canonical main manifest now has 53 exploit/control pairs and 318 scans; its README's stale larger count was corrected against the executable pairing assertion. Adversarial coverage accepts npm v2/v3 caret, comparator, and wildcard declarations and verifies shrinkwrap precedence while rejecting stale roots, v1 locks, patched resolution, absent installed packages, non-registry specifications, invalid higher-precedence shrinkwrap, malformed/oversized metadata, and unsafe child-boundary fallback. A POSIX lane separately rejects symlinked lock evidence.
- Fixed the cap-level collision exposed by the new pair without increasing the 96-row prompt budget. Exact-manifest and npm-lockfile findings now retain distinct `vulnerable-lodash-recursive-merge` and `lock-resolved-vulnerable-lodash-recursive-merge` sink provenance. The initial whole-repository run retained only the lexically earlier lock-resolved fixture; the corrected diversity categories retain both vulnerable package boundaries and exclude both patched twins. The focused Windows lane passes 6 tests and 32 assertions with one intentional POSIX symlink skip; the adjacent prototype and complete-manifest slice passes 27 tests and 1,200 assertions. Formatting, generated-model drift, and TypeScript checking pass. Implementation checkpoint `3e34ac540ce782221b613d585e63ba2321e7cd3f` is pushed.
- Remediated newly published high-severity PDF.js advisory [GHSA-hq66-cqwq-w95j / CVE-2026-16633](https://github.com/advisories/GHSA-hq66-cqwq-w95j) by upgrading the exact `pdfjs-dist` runtime pin from 5.6.205 to the patched 6.2.108 release and refreshing its optional canvas dependency graph. The advisory affects PDF.js from 5.6.83 before 6.2.108 and permits attacker-controlled JavaScript in the hosting origin when a malicious PDF is opened with scripting enabled and no blocking CSP. The scanner already uses a memory-limited worker with `isEvalSupported: false` for knowledge-base text extraction, but dependency remediation removes reliance on configuration as the sole boundary. Supply-chain lockfile policy passes, the production audit reports no known vulnerabilities, TypeScript and clean build pass, and the patched parser passes all six active PDF/DOCX knowledge-base tests under the normal acceptance boundary; two symlink/permission tests remain intentionally platform-skipped. The first post-upgrade test attempt under the managed execution sandbox was rejected because that sandbox denied Bun permission to load the newly downloaded JavaScript/native modules; an elevated rerun passed without changing code or weakening production policy.
- Final local acceptance for the version-aware Lodash merge and PDF.js remediation increment passes 1,190 tests and 8,990 assertions across 128 files with 19 intentional environment/platform skips and no failures in 306.61 seconds. Formatting, generated-model drift, TypeScript checking, the clean production build, patched PDF/DOCX extraction, and the production advisory audit pass. Repeated compiled self-review takes 12,255 and 12,487 ms and retains 96 byte-identical rows totaling 245,933 bytes with SHA-256 `2f0acf30b3855e29176cea1aa65d6cd187a559f2b527e507fba28dd6e16dc968`; exactly one vulnerable-Lodash row survives with source `server.js:8`, sink `storage.js:4`, CWE-1321, and nine propagators, while the patched twin remains absent. Strict inspection validates a 251-entry npm archive; three isolated Windows installs and one Ubuntu Node 22.23.1 install validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,571,972-byte archive had SHA-1 `bf2113cbb66e22d456ddf102461e77781f2ffa7b` and SHA-256 `ddc7442ad91e6a280e69d189088863a73913e373df682360a7dbcc0f677ed3a0`. Windows builds with zero warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `de2e03feda4ff3437e6aa0bc4be275c8df9683c4b74c3deea85782c3c51509ec`. WSL Ubuntu performs locked restores under a Linux-only path, builds with zero warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus real X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Exact pushed checkpoint `9cd2d09837f48c843c9adc4564d90e96f3422e6a` has no hosted runs because GitHub Actions remains in a major outage and push/PR webhook triggers remain throttled; the public repository and local acceptance are unaffected.
- Added an exact Node/TypeScript `node-http-prototype-merge` model for HTTP-derived objects reaching source operands of the official Lodash recursive merge API under a nearest runtime `package.json` pinned to a vulnerable exact version below 4.17.12. The host loads manifests as bounded metadata rather than source candidates, with separate 512-file and 2 MiB limits; it accepts official default, namespace, CommonJS, destructured, `lodash/merge`, and optional-runtime bindings while rejecting patched or ranged versions, development-only declarations, missing or malformed manifests, conflicting runtime declarations, target-only data, package lookalikes, reassigned receivers or merge members, and code-shaped comments or strings. Exact sources retain the existing three-boundary relative-module graph, nine propagators, `vulnerable-lodash-recursive-merge` sink identity, and CWE-1321. Reviewer guidance requires concrete recursive `__proto__` or `constructor.prototype` traversal and impact instead of inferring global pollution from a method name. A four-file Express vulnerable/patched pair, perfect-gate specialized manifest, dependency-free historical-semantics witnesses, main three-run corpus integration, whole-repository cap regression, and adversarial binding/version/position matrix cover the contract. The focused lane passes 5 tests and 21 assertions; the Lodash, shallow-copy, nested-key, and complete benchmark-manifest lanes pass 31 tests and 1,201 assertions with formatting, generated-model drift, TypeScript checking, and all four prototype witnesses clean. The main corpus now contains 81 exploit/control pairs and 516 scans. Exact code checkpoint `aa407ea643305169bcc01408adfe26999a21a0f7` is pushed.
- Added an exact Node/TypeScript `node-http-prototype-copy` model for HTTP-derived objects copied through source arguments of the built-in `Object.assign()`. It masks comments and literals, parses bounded multiline calls, rejects remote data used only as the target, and fails closed when `Object` is shadowed or `Object.assign` is reassigned; lookalike methods, object spread, and source-free calls remain outside the contract. The model preserves CWE-1321 while telling the reviewer to distinguish shallow per-target prototype replacement through the inherited `__proto__` setter from recursive merge that can modify `Object.prototype`. An exact `Object.create(null)` target is retained as `null-prototype-assignment-target` counterevidence without treating arbitrary copied own fields as authorized. A four-file Express exploit/control pair, perfect-gate specialized manifest, three-run corpus integration, runtime witnesses, direct/alias/later-source argument matrix, and receiver negatives cover the boundary. The initial cap result was rejected because category seeding retained only the safe null-prototype row; the exact established-boundary comparator now ranks that control behind its unmitigated sibling while retaining both through category diversity. The red baseline passed manifest shape and failed the other 3 tests with 11 assertions; the strengthened model passes 5 tests and 23 assertions, while the copy, nested-key, corpus, and adjacent Mongoose prioritization lanes pass 47 tests and 1,323 assertions with both witnesses, formatting, generated-model, and TypeScript gates clean.
- Final local acceptance for the shallow-copy increment passes 1,185 tests and 8,958 assertions across 127 files with 19 intentional environment/platform skips and no failures. Formatting, generated-model drift, TypeScript checking, the clean production build, and the production advisory audit pass. Repeated compiled self-review takes 12,193 and 11,661 ms, retains 96 byte-identical rows totaling 246,323 bytes with SHA-256 `b077f1cc5045b160ea6fd496463bb35bcfd8fb769bf2a3fc132894a1999b0a09`, and preserves both `Object.assign` rows in dangerous-then-controlled order with exact lines and nine propagators. Strict inspection validates a 251-entry npm archive; three isolated Windows installations and one supported Ubuntu Node 22.23.1 installation validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,564,635-byte archive had SHA-1 `e46ad99b0300e44ec2b72da9cb5b284b5964f862` and SHA-256 `7aa2d8ccbdae406deea3ae054783b16451e3263b86bf9ace65f68f0c1e30d7f9`. Windows builds with zero warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `797859fbc18e67a56e2dcf895f7e15f2c38f175d2db5b7d51f38d244cfe13267`. WSL Ubuntu performs locked restores under a Linux-only path, builds with zero warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable retains SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Exact pushed code checkpoint `b6e1b8f9868fa66e2ab2eff1b101283184721aec` has no hosted run because GitHub Actions remains in a major outage and most push webhooks are not triggering workflows; hosted absence remains external availability rather than a product result.
- Added an exact Node/TypeScript `node-http-prototype-pollution` model for HTTP-derived data that reaches two nested computed property-name positions. The host masks comments and literals, examines every plain assignment on the candidate line, follows the established bounded three-boundary relative-module graph, and resolves source provenance from key expressions only: request data confined to the assigned value, a single dynamic key, a fixed namespace, comparisons, compound assignments, `Map` operations, and code-shaped strings remain excluded. Findings retain the exact source, nine ordered propagators, sink line, `nested-computed-property-write` identity, and CWE-1321. Reviewer guidance now requires concrete prototype reachability and impact, treats nested `Map` storage as strong counterevidence, and distinguishes null-prototype dictionaries, constant prefixes, and fail-closed key validation from unrelated merge semantics. A strict four-file Express exploit/control pair, perfect-gate specialized manifest, executable witnesses, main three-run corpus integration, whole-repository cap regression, and adversarial position matrix cover the new boundary. The red baseline passed only manifest shape and failed the three missing behavior/guidance assertions; the focused model passes 5 tests and 21 assertions, while the model, corpus, multi-hop, and adjacent framework lanes together pass 39 tests and 1,218 assertions, TypeScript checking, and both witnesses.
- Final local acceptance for the prototype-pollution increment passes 1,180 tests and 8,923 assertions across 126 files with 19 intentional environment/platform skips and no failures. Formatting, generated-model drift, TypeScript checking, the clean production build, and the production advisory audit pass. Repeated compiled self-review takes 12,849 and 12,640 ms, retains 96 byte-identical rows totaling 242,422 bytes with SHA-256 `a0bbe579ac49e438a69b1a03fc9615c206a9ed2e6ef0247e24b5d753c89ec34f`, and preserves the new source-at-`server.js:8` to sink-at-`storage.js:4` row with nine propagators and no controls while excluding the `Map` twin. Strict inspection validates a 251-entry npm archive; three isolated Windows installations and one supported Ubuntu Node 22.23.1 installation validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,561,574-byte archive had SHA-1 `c594cf58472a4a0ef27ff4e5ee8af89788198a00` and SHA-256 `28e2eb33b048feef65cd44bc65179be9fce6ccf9298f00dcc8b895eff6d7bb2c`. Windows builds with zero warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `4047af42434f851341bcc1b7ee6359e82ac6514dca52d9b37c45fb9ad7fc5c58`. WSL Ubuntu performs locked restores under a Linux-only path, builds with zero warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Exact pushed code checkpoint `59eefc780965ffcd5a91e1917232ad14af5881a2` has no hosted run because GitHub Actions remains in a major outage; GitHub reports that push and pull-request webhooks are heavily throttled and many events are not triggering workflows, so the absence is recorded as external availability rather than a product result.
- Extended the exact Mongoose aggregation model through documented `Aggregate.append()` mutation without treating `append` itself as execution. The host accepts a single stage object, one stage array, or multiple stage arguments only on the exact Aggregate returned by a proven `Model.aggregate()` call, attributes the finding to the appended stage line, and requires that the mutation precede a later `await`, async return, `exec`, `then`, `catch`, `finally`, or `cursor` consumption. Assigned receivers remain bounded to the same exported wrapper and fail closed on reassignment; append after the only execution, inspection-only use, unrelated same-named methods, and execution of a different receiver are rejected. Appended read, cross-collection, dynamic, and write stages receive origin-specific sink kinds while pipeline-wide `$merge`/`$out` ordering preserves CWE-915 on earlier dynamic grammar. The strict manifest now includes a third four-file exploit/control pair: attacker-selected appended `$lookup` and projection stages expose a signing key, while exact `$eq` beneath a fixed `$match` plus a fixed public projection remains reviewable with counterevidence. The red baseline passed 5 tests and failed 3 with 67 assertions because append rows and reviewer guidance were absent; the strengthened checkpoint passes 9 tests and 78 assertions, TypeScript checking, both executable witnesses, documented argument-form coverage, write-impact classification, and receiver-exact negative controls.
- Final local acceptance for the append increment passes 1,175 tests and 8,891 assertions across 125 files with 19 intentional environment/platform skips and no failures. Formatting, generated-model drift, TypeScript checking, clean production build, and the production advisory audit pass. Repeated compiled self-review takes 13,268 and 12,783 ms, retains 96 byte-identical rows totaling 242,966 bytes with SHA-256 `7d2566b22e5c78485042c5c82df1414c142fd49457f68a5cf7f341f222b3d28b`, and preserves all six initial/appended read/write exploit/control rows under the unchanged cap. Strict inspection validates a 251-entry npm archive; three isolated Windows installations and one supported Ubuntu Node 22.23.1 installation validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,558,170-byte archive had SHA-1 `b7b5c9171f2e6a5e9b30272292f09a4660778c38` and SHA-256 `f6c5c2bc51c74909ac443651113a16d6e69794fe1e91f5921cdf8283a017eae0`. Windows builds with zero warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `b9d42cabd58597cfbba24decf7cad66dfff9080bf9d27eb10649d4d542549b83`. WSL Ubuntu performs locked restores under a Linux-only path, builds with zero warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. Exact pushed code checkpoint `7c4822d17d48ec0560139d4112fcb86d0862b348` has no hosted run because GitHub Actions remains in a major outage; GitHub's official incident says workflow runs are failing, delayed, or timing out, so the absence is recorded as external availability rather than a product result.
- Added an exact Node/TypeScript Mongoose `Model.aggregate()` model that reuses official factory and non-reassigned Model proof, traces only pipeline argument zero, and requires consumption of Mongoose's lazy Aggregate through `await`, an async return, `exec`, `then`, `catch`, `finally`, or `cursor`. Complete pipelines, dynamic or spread stages, `$match`/`$redact`, `$lookup`/`$graphLookup`/`$unionWith`, and `$merge`/`$out` receive position-specific review metadata. Aggregate options, inert construction and inspection, local lookalikes, reassigned Models, and fixed stages without request flow remain excluded. Dynamic pipeline and write-stage structure carry CWE-943 plus CWE-915; read/query stages carry CWE-943.
- Added `node-mongoose-aggregate-manifest.json` with two four-file Express route → gateway → service → storage exploit/control pairs under perfect gates. One exploit uses attacker-selected `$lookup` and projection stages to expose a signing key; the other supplies attacker-selected `$set` stages before a fixed `$merge` and replaces role plus MFA state. Their controls retain all nine ordered propagators while fixing `$match` grammar through exact `$eq`, public projection, mutation fields, write destination, identity key, and merge policy. Only exact-`$eq` values beneath a fixed `$match` field receive counterevidence; direct request values, computed fields, spreads, `$regex`, cross-collection names, write destinations, and arbitrary expressions do not. The strict red run passed only manifest shape and failed four absent-model tests; the strengthened checkpoint covers async returns, multiline chains, assigned consumption and reassignment, passes TypeScript checking, 23 adjacent Mongoose tests and 169 assertions, and passes all four executable witnesses.
- Fixed a whole-repository cap-level false negative found by compiled self-review. The stable 96-row inventory initially retained only the lexically first generic dynamic-pipeline exploit and first fixed-match control, pruning the equally real `$merge` exploit and safe-write twin because each pair shared its sink category. Aggregate positions now retain whether the surrounding literal pipeline contains `$merge` or `$out`, yielding distinct input-before-write and filter-before-write sink kinds without changing the exact source position or CWE semantics. A whole-repository regression requires all four read/write exploit/control rows to survive the cap; the exploit fixture keeps its write destination fixed so the classification follows visible code rather than a benchmark name. Corrected compiled passes take 12,808 and 12,258 ms, retain 96 byte-identical rows with SHA-256 `871320aec642aafccb503f95afdf9ef5a5bf76152b815c4742ab6b586d88ee13`, and preserve all four rows in dangerous-read, dangerous-write, controlled-read, controlled-write order.
- Final local acceptance for the aggregation increment passes 1,172 tests and 8,875 assertions across 125 files with 19 intentional environment/platform skips and no failures. Formatting, generated-model drift, TypeScript checking, the clean production build, and the production advisory audit pass with no known vulnerabilities. Strict archive inspection validates 251 entries; three isolated Windows installs and one supported Ubuntu Node 22.23.1 install validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,554,638-byte archive had SHA-1 `f1744b80d2eed6782e9ac56fa14f889510c0535c` and SHA-256 `45588f94736c6d5343763726f7e78aefcabcf903814c65071beb5f1904fd1c80`. Windows builds with zero warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `258ce6d416fe6e7e9b4eb6e2168bb19a5c97372fd16d4b49c6dddcd626a31247`. WSL Ubuntu performs locked restores under a Linux-only `PATH`, builds with zero warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added an exact Node/TypeScript Mongoose `bulkWrite()` model that reuses official factory and non-reassigned Model identity while parsing the documented nested operation array. It traces `insertOne.document`; the filter and update positions of `updateOne` and `updateMany`; delete filters; and the filter and replacement positions of `replaceOne`. A directly tainted operation array, dynamic element, operation spread, or operation-specification spread remains reviewable. Bulk options, collation, `arrayFilters`, fixed unrelated fields, local lookalikes, and reassigned Models are excluded. Unlike lazy Query APIs, `bulkWrite()` dispatch is recognized at the call boundary without requiring `exec` or `await`.
- Added `node-mongoose-bulk-write-manifest.json` with two four-file Express route → gateway → service → storage exploit/control pairs under perfect gates. One exploit supplies `$unset` through `updateOne.update` and removes MFA; the other supplies a complete `replaceOne.replacement` and overwrites role plus MFA. Their controls retain the same nine propagators but use either one scalar beneath a fixed server-owned `$set` field or a fixed literal replacement projection. Deterministic regression covers all documented data-bearing nested positions, whole-array and spread control, exact filter/update/document counterevidence, and unrelated-position rejection. The strict red run passed only manifest shape and failed four absent-model tests; the first green checkpoint passes 16 adjacent Mongoose tests and 104 assertions, TypeScript checking, and all four executable witnesses.
- Fixed a cap-level false negative exposed by the first compiled self-review. The byte-stable 96-row inventory retained the unsafe replacement and both controlled fixtures but pruned the unsafe bulk update because both dangerous paths shared one generic sink category. Bulk rows now carry position-specific filter, update, insert, replacement, or whole-array sink kinds and exact CWE sets, and only the established bulk fixed-update and fixed-document controls rank behind unmitigated siblings. A new adversarial regression starts both controlled paths lexically first but requires both dangerous operation kinds first. The corrected compiled passes take 12,959 and 12,624 ms, retain 96 byte-identical rows with SHA-256 `5e9b13c9d0debb73983a1ff7d80ae6e5aa6362797f575565feeab98c7311f9c8`, and contain all four bulk fixtures in unsafe-then-controlled order.
- Final local acceptance for the bulk-write increment passes 1,166 tests and 8,813 assertions across 124 files with 19 intentional environment/platform skips and no failures. A first 1,161-pass attempt was rejected because a concurrently launched clean build removed `dist/benchmark-campaign.js` while four benchmark-runner subprocess tests imported it; the serial exact-head rerun after a complete build passes. Formatting, generated-model drift, TypeScript checking, the clean production build, and the production advisory audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; two isolated Windows installs and one supported Ubuntu Node 22.23.1 install validate public import, CLI behavior, and all 79 bundled plugin files. Ubuntu Node 18.19.1 was correctly rejected because it is below the declared Node 22/24/26 engine lines. The removed 1,533,451-byte archive had SHA-1 `c692f5c6f58518c1c6648b66129f490ab0b14b44` and SHA-256 `a32f4d459fa41c163e44912500af45c4bd7cdc28d5d80c855f5ac597480c858c`. Windows builds with zero warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `58528f73e9d24b5a9009813da107abe46a0a5a7fd5408821d097fd18f9ee31ef`. WSL Ubuntu performs locked restores under a Linux-only `PATH`, builds with zero warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`. All seven public workflows pass at exact code checkpoint `6fd59b2f21c27ea7d37ec8a30d92798d67c9b5b3`.
- Added a separate exact Node/TypeScript Mongoose update-document model for CWE-943 operator/query-language injection and CWE-915 field-only mass assignment. The host resolves only official Mongoose-created Models, extracts argument one from executed `updateOne`, `updateMany`, `findOneAndUpdate`, and `findByIdAndUpdate` Model calls, and preserves that value through the existing three-boundary relative-import graph. Filter-only, options-only, replacement, one-argument overload, lookalike, reassigned, and inert-query cases remain outside the model.
- Added `node-mongoose-update-manifest.json` and an executable four-file Express route → gateway → service → storage exploit/control pair under perfect completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, negative-control, and zero-false-positive gates. The exploit proves that an attacker-selected `$unset` removes an MFA secret. The control maps one request scalar beneath a fixed server-owned `$set` field and preserves MFA. Deterministic regression retains all nine propagators, exact sink position, both CWE classifications, and only that fixed-field control; it rejects complete objects beneath `$set`, computed keys, update spreads, filter/options taint, replacement APIs, one-argument calls, local lookalikes, inert queries, and `runValidators` as a universal defense. The final focused checkpoint passes 6 tests and 32 assertions, both executable witnesses, and TypeScript checking.
- Fixed a whole-repository false-negative exposed by compiled self-review: the 96-row diversity cap initially retained the controlled Mongoose update twin but pruned the unmitigated operator path because the control contributed one extra category and sorted first by path. Equal-priority rows with the exact `fixed-update-field-value-boundary` now rank after their unmitigated sibling while category diversity still retains the control. A first broad candidate-control-count rule was rejected after it reordered GORM, pgconn, and Java path evidence; the final rule is deliberately limited to this proven fixed update boundary. Regression requires the dangerous row to precede its controlled twin and retains every historical ordering contract.
- Final local acceptance for the Mongoose update increment passes 1,160 tests and 8,769 assertions across 123 files with 19 intentional environment/platform skips and no failures. Two compiled self-inventory passes take 13,254 and 12,407 ms, retain 96 byte-identical rows with SHA-256 `1b21c3c5a9e770db2b337bf520d53f9868324333a77ffa1f7c14aff23a66139e`, and contain both exact update rows in dangerous-then-controlled order. Formatting, generated-model drift, TypeScript checking, clean production build, and the production advisory audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; three isolated Windows/Linux installs validate public import, CLI behavior, and all 79 bundled plugin files. The final 1,544,434-byte archive has SHA-1 `40971c8d3ee856702930ac3435ee4d20fbaa05f2` and SHA-256 `6a1015d85f026efca7044d49476d968a16ef5bff1faef5c15439bf46c829af27` before removal. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `921e75e15d360df15fe0d84d81cce14580d24523fd4eebf7cdc343558d3a7309`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added an exact Node/TypeScript Mongoose selector-injection framework model for CWE-943. The host resolves official default, namespace, named `model`, and CommonJS bindings; proves each candidate model was created by that still-unmodified binding; traces only argument zero of documented filter-bearing query operations; and requires query consumption through `await`, an async returned thenable, `exec`, `then`, or `catch`. Request data used only as update, replacement, projection, options, comments, or logging is excluded, as are local lookalikes, receiver calls that are not `.model()`, reassigned factories or models, and inert queries.
- Added `node-mongoose-nosql-manifest.json` and an executable four-file Express route → gateway → service → storage exploit/control pair under perfect single-run completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, negative-control, and zero-false-positive gates. The exploit proves that `{ $ne: null }` selects the administrator document; the matched control wraps the same request value in `$eq`, rejects the operator object, and preserves literal lookup. Deterministic regression preserves all nine import/call/parameter propagators, exact sink position and official binding shapes, recognizes only exact `mongoose.sanitizeFilter`, and rejects update/options-only flows, local sanitization lookalikes, malformed factories, reassignment, unrelated `$eq` clauses, cross-file sanitizer lookalikes, and unexecuted returns. The strengthened focused checkpoint passes 5 tests and 31 assertions plus both live witnesses and TypeScript checking.
- Rejected and corrected the first Mongoose self-review performance result. Although it was byte-stable, two compiled passes took 33,966 and 32,009 ms. CPU profiling identified repeated immutable JavaScript masking and wrapper discovery as the dominant cost. Snapshot-scoped weak caches plus one structural pass per file reduced the final pair to 12,424 and 12,271 ms—about 2.7 times faster than the rejected build and materially faster than the preceding scanner's 19–22 second envelope. The optimized passes retain 96 byte-identical rows and SHA-256 `73cdbd3b376a4866ff6c119f6370a64908def3adb8c7f7656675a0ed99ed4fee`; their only two Mongoose rows are the committed exploit and `$eq` control fixtures. The residual-inventory lane passes 65 tests and 1,052 assertions with one intentional platform skip.
- Final local acceptance for the Mongoose and inventory-cache increment passes 1,154 tests and 8,737 assertions across 122 files with 19 intentional environment/platform skips and no failures. Formatting, generated-model drift, TypeScript checking, the clean production build, and the production advisory audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; three isolated Windows/Linux installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,541,238-byte archive had SHA-1 `4b82e1f13fb7055e7038fe559d82e701c27b16a3` and SHA-256 `1de79f567bf8586c1e5cc67adf8777bff835775b13682c65e22c6e76ed94ba34`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `aa14cc0e68a317cdf4b6b8c7e0ce4244464f307a5fbf7ee0464a0b045c685372`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added exact Node/TypeScript and Python filesystem-path framework models. Node recognition resolves official `fs`, `node:fs`, and promises imports through named aliases, namespace/default receivers, CommonJS receivers and destructuring, and direct `require` calls; Python recognition resolves the unshadowed `open` builtin plus exact `builtins`, `os`, and `shutil` module or named aliases. Each operation traces only its documented path positions, including both source and destination for copy, move, link, symlink, and rename families, so request-controlled file contents and encoding arguments do not become path findings. Local lookalikes, foreign imports, parameter shadows, and reassigned bindings fail closed.
- Added the paired `filesystem-path-framework-manifest.json` lane and four executable route → gateway → service → storage fixtures. The two CWE-22 positives prove parent-file disclosure through three exact import boundaries; their matched controls preserve topology and sink behavior while mapping one server-owned key to a fixed complete path. The strict lane requires perfect completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, negative-control behavior, and zero false positives. Deterministic regressions also distinguish Python `pathlib.Path` from FastAPI `Path` without an official import and no longer mistake JavaScript equality comparisons for parameter reassignment.
- Expanded the model quality gate with language-specific filesystem validation: canonicalization and absolute-path checks are not universal containment, Node `path.isAbsolute` alone is insufficient, Python `os.path.commonprefix` is not component-aware, and link, junction, mount, writable-ancestor, rename-race, permission, authorization, and concrete filesystem effects remain separate proof obligations. Node and WSL Python executable witnesses confirm both traversal disclosures and fixed-map rejection while retaining legitimate document reads.
- Fixed and measured the initial exact-binding performance regression before acceptance. Candidate prefiltering plus per-source-array weak binding caches reduced compiled full-SDK inventory from 70–75 seconds to 19–22 seconds per pass while preserving 96 byte-identical rows, zero self filesystem-path rows, and SHA-256 `23822919ec67fc4302c030d55a29c3097227139b11fdc91fadbb84d73f26e249`. The final authoritative suite passes 1,149 tests and 8,706 assertions across 121 files with 19 intentional environment/integration skips and no failures. Formatting, generated-model drift, TypeScript checking, the clean production build, and the pnpm production audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; three isolated Windows/Linux installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,518,640-byte archive had SHA-1 `f328aa0a1b2bf2ed5173c833e51dcfabed7bd2e4` and SHA-256 `3260a0e7faa4d616ec78982371af383cd106c1f1be9d1050efc6488861b84040`.
- Extended exact Node/TypeScript and Python relative-import summaries to three call/parameter hops. The host now composes up to two exported or public module-level relays before a terminal sink wrapper, preserves every resolved import, positional call argument, wrapper parameter, candidate control, and sink in order, and applies the improvement to all existing Node and Python framework-model families.
- Kept the deeper import graph fail-closed: every edge must resolve to an explicit repository-relative module and exact exported symbol, every forwarded value must remain the same positional parameter without reassignment, repeated files and malformed chains are rejected, and a fourth import hop remains outside the model. The strict command and SQL exploit/control corpora now use four source files and three import boundaries in both languages. The red baseline lost exactly the two new three-hop command expectations; after composition, seven focused tests pass 59 assertions, including outer-relay reassignment, repeated-file cycles, and over-depth Node and Python controls.
- The widened Node/Python framework and residual-inventory matrix passes 122 tests and 1,409 assertions with one intentional platform skip. The authoritative suite passes 1,144 tests and 8,674 assertions across 120 files with 19 intentional environment/integration skips and no failures. Compiled self-review is byte-identical across repeated runs at 96 rows; each vulnerable real fixture emits one exact nine-propagator model, both shell-free controls remain outside the dangerous model, and each parameterized SQL control retains exactly one binding lead. Formatting, generated models, types, the clean production build, and the production audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; three isolated Windows/Linux installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,522,403-byte archive had SHA-1 `444816fbfd4e8dbce2821e28b6125cfab0aedb4d` and SHA-256 `8cfc4b83f459af9b313950968a8aacc4374805177065581dd7af40ff88894960`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `40cd6f979a159568b44b875c7c59d1a3b867fe530b2a8350918288a2023dac52`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Extended the exact typed Java and C# framework summary graph to three service boundaries. Every existing Java and C# sink family can now preserve a request value across controller → facade → service → terminal-wrapper topologies while retaining every receiver binding, positional call argument, wrapper parameter, candidate control, and final sink in source-to-sink order. Their unique-type identity remains separate from the Node/TypeScript and Python relative-import contract.
- Kept the additional relay layer fail-closed: each receiver owner must remain unique, arity and argument position must match exactly, the forwarded parameter cannot be reassigned before any recorded call, repeated file paths and malformed chains are rejected, and a fourth service boundary remains outside the model. The paired real Java and ASP.NET filesystem fixtures now contain four source files and three uniquely typed injected boundaries; adversarial regressions cover outer-facade reassignment and over-depth Java and C# chains. The focused suites pass 33 tests and 184 assertions.
- All thirteen Java/.NET framework and inventory suites pass 160 tests and 1,538 assertions with one intentional platform skip; the authoritative suite passes 1,142 tests and 8,662 assertions across 120 files with 19 intentional environment/integration skips and no failures. Deterministic self-review remains 96 rows with neither path model. Both Java and ASP.NET fixture pairs compile and all four executable witnesses retain exact exploit/control behavior. Formatting, generated models, types, clean build, and the production audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; three isolated Windows/Linux installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,521,835-byte archive had SHA-1 `28e7701e8aae1e058e219657fd0355cd7bf65983` and SHA-256 `45c7b17d1308ec4fb95db28e7ed03d635e6353e822f5562ca5e3f5af3ab4f312`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `9bdc6f0469793dccd1c6b76ff7da235d592c0ef656d57bd42b1c74c594ac2d96`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added exact conventional Maven reactor dependency resolution to the Java `File.getName()` and `Path.getFileName()` cross-file helper specializations. A caller may now consume one direct sibling when a literal top-level dependency's exact `groupId`, `artifactId`, and `version` resolve to one uniquely owned reactor module; its scope is absent, `compile`, or `provided`; its type is absent or `jar` with no classifier; and both source endpoints use conventional `src/main/java`. Exact Maven model version 4.0.0, literal nested module paths, standard namespace-bearing POMs, default and safe literal local-parent paths, and exact inherited group/version coordinates are supported without executing Maven.
- Kept Maven recovery fail-closed and edge-local. `dependencyManagement`, test/runtime/system/import scopes, property/interpolated coordinates, version mismatch, classified or non-JAR artifacts, transitive and reverse-direction reachability, undeclared siblings, duplicate visible owners, nonstandard source roots, malformed dependencies, ambiguous coordinates, invalid/cyclic module trees, and overlapping reactor ownership do not create edges. A malformed or dynamic dependency entry removes only that unproved edge rather than suppressing independent exact reactor relationships. The adversarial regression retains seventeen broad Spring path rows, admits only default-scope, `compile`, and `provided` direct positives across both basename APIs, and exercises multi-level literal parent resolution plus every major negative boundary.
- The focused Java path lane passes 26 tests and 154 assertions; a widened six-suite Java/framework/inventory slice passes 103 tests and 1,273 assertions with one intentional platform skip. The authoritative Windows suite passes 1,142 tests and 8,662 assertions across 120 files with the same 19 intentional environment/integration skips and no failures. Compiled self-review remains 96 deterministic rows with neither basename specialization. All four Maven basename fixtures compile, all four JDK witnesses retain exact exploit/control behavior, and compiled review preserves one specialization per fixture with helper evidence at `DocumentNames.java:9` and caller-side parent rejection only in the two controls. Formatting, generated-model drift, TypeScript checking, clean production build, and the production audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; three isolated installations validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,520,449-byte archive had SHA-1 `898e7e2ba729ea1d51bb4a08483f7968f64dfa81` and SHA-256 `6e582e67a5eb717aa33e62c5b292da73d341278d39de5f4eee521224ec275b1d`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `5c8b9fb1f05d24fd385a058b3ccaf197783b5fde362623273b4516285ee6e7ac`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added direct conventional Gradle project-dependency resolution to the exact Java `File.getName()` and `Path.getFileName()` cross-file helper specializations. A caller may now consume one helper module when its own top-level `dependencies` block declares a literal `api`, `implementation`, `compileOnly`, or `compileOnlyApi` `project(":path")` edge; the nearest unique `settings.gradle(.kts)` includes that standard project path; and caller and target each have exactly one conventional build file. Kotlin and Groovy DSL forms, nested project paths, dependency direction, helper evidence, and same-package shadow/duplicate checks across the caller's visible roots are preserved.
- Kept dependency inference deliberately fail-closed: undeclared and reverse-direction siblings, `testImplementation`, `runtimeOnly`, dynamic project expressions, transitive reachability, nonstandard production source sets, custom `projectDir`/`buildFileName`, `includeBuild`, ambiguous settings/build ownership, Gradle-specific multiline string forms, nested dependency declarations, and absent or partially inventoried modules never create an edge. The paired deterministic regression retains all thirteen broad Spring path rows while admitting only five literal compile-classpath positives across all four accepted configurations and rejecting both an owner duplicated across two visible dependency modules and a declared helper parked outside `src/main/java`.
- The focused Java path lane passes 24 tests and 144 assertions; the six-file Java/framework/inventory slice passes 113 tests and 1,310 assertions with one intentional platform skip. The authoritative suite passes 1,140 tests and 8,652 assertions across 120 files with 19 intentional environment/integration skips and no failures. The production SDK remains 96 deterministic rows with no Java basename specialization. Formatting, generated-model drift, TypeScript checking, clean build, and the production audit pass with no known vulnerabilities. All four Maven basename fixtures compile, all four JDK witnesses retain their exploit/control outcomes, and compiled review preserves the four exact helper evidence paths and caller-only control lines. Strict package inspection validates 251 entries; three isolated installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,494,486-byte archive had SHA-1 `1c05d226554d797d048a0f2170d8b029db536eb8` and SHA-256 `523360b2bb0c10c16fb9e9d92ea8a50acfff379fbbab983cd2e5945fe7166e40`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `93e4063dd4dabace479c1ac2d668c68043758f378660b0fb26ccbbeb619c14c6`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added exact Gradle project/module boundaries to the Java basename-helper specializations. `build.gradle`, `build.gradle.kts`, `settings.gradle`, and `settings.gradle.kts` now participate alongside `pom.xml`, with the deepest ancestor defining the bounded helper and same-package type scope. This recovers a legitimate local helper when an unrelated Gradle sibling declares the same package/type and prevents an undeclared sibling helper from being credited to a caller that cannot see it.
- Added `.gradle` Groovy DSL files to the bounded source inventory; Kotlin DSL `.kts` files were already retained. The paired regression covers Groovy and Kotlin build scripts, root and nested settings files, sibling-module duplicate isolation, nested composite-build isolation, exact helper evidence, and the cross-module false-positive control. Custom Gradle project-directory/build-file mappings and nonliteral or ambiguous cross-module dependencies intentionally remain fail-closed.
- The focused Java path lane passes 23 tests and 138 assertions; the six-file Java/framework/inventory slice passes 100 tests and 1,257 assertions with one intentional platform skip. The authoritative suite passes 1,139 tests and 8,646 assertions across 120 files with 19 intentional environment/integration skips and no failures. The production SDK remains 96 deterministic rows with no Java basename specialization. Formatting, generated-model drift, TypeScript checking, clean build, and the production audit pass with no known vulnerabilities. All four Maven basename fixtures compile and all four JDK witnesses retain their exploit/control outcomes. Strict package inspection validates 251 entries; three isolated installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,506,189-byte archive had SHA-1 `edb525a102adb5fcf2c6260252472e6527ebc7af` and SHA-256 `8a19cf597e3137a09986ef5d3c5546554d8c8e9dd33996adbb9a5e4a6c899062`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `e93a5fcb2938400453ae882e8c23fb8abeb4d55f2abb6f131d61ea3d76505c4c`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added exact project-local cross-file helper summaries to the Java `File.getName()` and `Path.getFileName()` specializations. A call is eligible only within the nearest Maven project when exactly one top-level owner resolves through the same package, one exact single-type import, or its fully qualified name; the method is static and accessible; cross-package owner and method access are public; and the existing official-type, unique-symbol, straight-line-return, arity, argument-position, and value-identity proofs all hold. Wildcard custom imports, duplicate owners, nested projects, inaccessible or instance methods, overloads, transformed arguments, and ambiguous calls fail closed.
- Preserved cross-file evidence boundaries: `incomplete-java-io-file-getname-reduction` and `incomplete-java-nio-path-getfilename-reduction` now identify the helper source and exact return line, while `parent-path-component-rejection` remains at the caller guard and must dominate the returned value before the sink. The four real Spring exploit/control fixtures now place their basename helper in `DocumentNames.java`; the matched dependency-free witnesses preserve their prior runtime behavior.
- The focused Java path lane passes 22 tests and 131 assertions; the six-file Java/framework/inventory slice passes 99 tests and 1,250 assertions with one intentional platform skip. The authoritative suite passes 1,138 tests and 8,639 assertions across 120 files with 19 intentional environment/integration skips and no failures. All four Spring fixtures compile and all four JDK witnesses prove their expected exploit/control outcomes. Compiled review emits one exact cross-file specialization for each fixture at `DocumentStore.java` lines 18, 21, 24, and 21; all four reduction leads point to `DocumentNames.java:9`, only the two controls retain caller-side rejection at `DocumentStore.java:18`, and the production SDK's 96 deterministic rows contain no Java basename specialization. Formatting, generated-model drift, TypeScript checking, clean build, and the production audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; three isolated installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,505,467-byte archive had SHA-1 `bd9a65f0ed70c4c57ee330379279dc247d29911c` and SHA-256 `feadde7ac4b9d0bd1177a326909b685bb87d4e61c17bd4534e3d00f95e2981c3`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `678c95be27998c410defa21c29c1ac9e4a3cf1b4d36f1477c16f99baa5c6989e`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added exact same-file helper-return summaries for the Java `File.getName()` and `Path.getFileName()` basename specializations. The scanner now preserves a proven Spring path through private, package, protected, or public local helpers when official input/return types, a unique method symbol, a straight-line single return, exact call ownership, arity, argument position, and value identity all agree. Overloads, branches, transformations, reassignment, nested helpers, foreign receivers, lookalike types, and ambiguous calls fail closed.
- Hardened Java member discovery after the executable fixtures exposed duplicate lexical declarations from leading blank or annotation lines. Identical signature/end-boundary discoveries collapse to the actual declaration while distinct overloads remain distinct and therefore ineligible for heuristic dispatch. Twenty-three positive and negative helper fixtures now cover `String`, `File`, and `Path` inputs; direct and alias returns; unqualified, `this`, and owner-qualified calls; multiple parameters; package shadows; controls on helper results; overloads; branches; transformations; reassignment; nesting; and foreign receivers.
- Routed all four existing Java basename exploit/control fixtures and their dependency-free JDK witnesses through private same-file helpers. The strict six-case manifest therefore exercises helper-summary recall at the real Spring controller-to-service-to-repository boundary while retaining exact exploit, negative-control, evidence, validation, attack-path, severity, and zero-false-positive gates.
- The focused Java path lane passes 20 tests and 122 assertions; the six-file Java/framework/inventory slice passes 109 tests and 1,288 assertions with one intentional platform skip. The authoritative suite passes 1,136 tests and 8,630 assertions across 120 files with 19 intentional environment/integration skips and no failures. All four Spring basename fixtures compile and all four JDK witnesses prove their expected exploit/control outcomes. Compiled review emits one exact helper-aware specialization for each fixture at lines 23, 26, 28, and 25 respectively, attaches `parent-path-component-rejection` only to the two controls, and emits no Java basename specialization from the production SDK's 96 deterministic rows. Formatting, generated models, TypeScript checking, the clean build, and the production audit pass with no known vulnerabilities. Strict package inspection validates 251 entries; three isolated installs validate public import, CLI behavior, and all 79 bundled plugin files. The removed 1,497,109-byte archive had SHA-1 `f23a96d35e82e16ef46be1608d39cd736a2c5f4a` and SHA-256 `43349afbde1b50ad723c5607dc5130d85ac809da1c7fefa65863affd936b7edf`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a 346,796-byte executable with SHA-256 `e1f663725ca8cde64c5b702ff70fc49ae0ed29adab78176b80a65e4b44ceb391`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Made Java basename parent rejection branch-sensitive for both `java.io.File.getName()` and `java.nio.file.Path.getFileName()`. An exact equality now contributes `parent-path-component-rejection` only when the matching, non-negated, non-conjoined branch itself unconditionally returns or throws and the guard shares the filesystem sink's lexical block path. Optional nested checks, caught throws, logging-only branches, and unrelated nearby abrupt completion fail closed instead of being credited as controls.
- Strengthened the `Path.getFileName()` exploit fixture with an exact `..` check that only logs, followed by an unrelated null-state throw. Its JDK witness proves the parent read still succeeds; the matched control retains an exact dominating throw and rejects the same input. The compiled analyzer emits only `incomplete-java-nio-path-getfilename-reduction` for the exploit, emits that lead plus `parent-path-component-rejection` for the control, and emits no Java basename specialization from the production SDK's 96 deterministic rows. Six widened framework/inventory suites pass 105 tests and 1,272 assertions with one intentional platform skip; formatting, generated models, TypeScript checking, the production build, both Maven fixtures, and both Linux JDK witnesses are clean.
- The authoritative SDK suite passes 1,132 tests and 8,614 assertions across 120 files with 19 intentional environment/integration skips. The production audit reports no known vulnerabilities. Strict package inspection validates 251 entries; two isolated installations validate public import, CLI behavior, and all 79 bundled-plugin files. The removed 1,491,884-byte validation archive had SHA-256 `631674a674521d3e232baa67ed108e5b587612d485fb416e8bb3f766902834cf`. Windows builds without warnings/errors, passes seven core and three shared tests, and publishes a fresh 346,796-byte executable with SHA-256 `2c0ffc204424ee15b9a226790796edf7ad9a458bde5edb4e2725fe765131660b`. WSL Ubuntu performs locked restores, builds without warnings/errors, passes seven core, three shared, and two Linux interface tests, and passes non-graphical plus X11/Xvfb startup. Its 72,568-byte executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Resolved Java `Path.getFileName()` factory identity across compilation units and static imports. Exact `java.nio.file.Path`/`Paths` single-type imports remain authoritative over a top-level same-package lookalike, while `java.nio.file.*` fails closed when the same project and package declares `Path` or `Paths`. Peer lookup is limited to the nearest Maven project and excludes tests/examples; a nested type or a declaration in another package does not suppress the JDK binding, and fully qualified factories remain unshadowable. Exact and on-demand static imports of `Path.of` and `Paths.get` now feed the same reduction model only when no local method declaration, qualified lookalike call, or competing same-name static import can own the call. Focused positive and negative regressions pass 14 tests and 90 assertions.
- The widened Java/Spring/framework lane passes 124 tests and 1,344 assertions with one intentional platform skip; the authoritative suite passes 1,130 tests and 8,598 assertions across 120 files with 19 intentional skips and no failures. Compiled review preserves the one exact positive and one exact control specialization and emits none from the production SDK's 96 deterministic records. Formatting, generated models, types, clean build, and the production advisory audit are clean. Strict inspection validates 251 archive entries; two isolated installations validate public import, CLI behavior, and all 79 bundled-plugin files. The removed 1,488,545-byte archive had SHA-256 `685125d6820580614843fc2085ae86626eede0e0642a7d2bebf24b6e9d4e8ca3`. Windows GUI acceptance builds without warnings/errors, passes seven core plus three shared tests, and publishes a 346,796-byte executable with SHA-256 `31a2439db5e1994f5c1b006c6accc7048aeef3d3a06507cf5786683de282a296`. WSL Ubuntu builds without warnings/errors; passes seven core, three shared, and two headless tests under a Linux-only PATH; and passes non-graphical plus X11/Xvfb startup. The 72,568-byte Linux executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- An authenticated GitHub Copilot `gpt-5.6-terra` high-effort deep campaign completed the new `Path.getFileName()` exploit/control pair with one true positive, zero false positives, zero misses, and perfect completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, and negative-control gates. The safe control completed on its first attempt in 4m11s with zero findings and complete coverage. The positive's first runner attempt reached the 20-minute model-turn deadline, started an internal fresh session, then reached the 25-minute outer scanner deadline; the runner archived that partial attempt and launched a new fixture/session without collision. Attempt two completed in 17m18s with one high-severity CWE-22 finding, exact controller-to-service-to-store evidence, the retained `..` component, the filesystem sink, and complete coverage. The original lock owner continued after the host wait expired and released its lock after final evaluation. Stored GitHub authentication remained valid throughout; no invocation reported an allowance, credit, rate-limit, authentication, or safety-classifier failure. Campaign `0274e420f5f0008cd665d0469c5ea27d3b35e45322a61c672f17bacc832b1ee3` remains isolated under `C:\security-benchmarks`.
- Added exact `java.nio.file.Path.getFileName()` parent-component analysis on top of an existing `spring-http-path` proof. Exact imported or fully qualified `Path.of` and `Paths.get` factories, exact typed Spring-bound `Path` parameters, receiver aliases, direct reductions, result aliases, and direct sink reductions are preserved only when the same request-derived value reaches the existing typed filesystem argument. The derived `java-path-getfilename-path-boundary` row records `incomplete-java-nio-path-getfilename-reduction`; the original Spring path row remains available for broader containment, link, race, platform, and authorization review.
- Removed the weak Java `single-path-component-validation` candidate that treated any `getFileName()` or `getNameCount()` occurrence as possible counterevidence. `Path.of("..").getFileName()` remains exact `..`, and a one-element path may itself be the parent component. The scanner now records `parent-path-component-rejection` only for exact equality between the same reaching reduced `Path` lineage and `Path.of("..")` or `Paths.get("..")` before a fail-closed return or throw. Another parallel reduction, a fixed factory, another object's method, a local `Path`/`Paths` lookalike, reassignment, logging, substring matching, comments, strings, tests, a post-sink check, or the wrong cross-file parameter fails closed.
- Added the ninety-second effectiveness increment and seventy-ninth exploit/control pair to `java-multi-hop-path-manifest.json` under perfect completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, and negative-control gates. The positive crosses a Spring controller, service, and repository, reduces the request with exact `Path.getFileName`, and proves `..` reads a parent `content.txt`; the matched control preserves topology, sink, payload, and allowed-name behavior while rejecting exact and nested parent names before the sink. The documented corpus now contains 474 scans at three runs per case. Both real Spring fixtures compile with Java 17 release semantics, both pure-JDK witnesses execute on Java 21, and hosted Java fixture CI covers all additions.
- The focused Java path lane passes 12 tests and 83 assertions, the widened Java/Spring/framework lane passes 122 tests and 1,337 assertions with one intentional platform skip, and the authoritative suite passes 1,128 tests and 8,591 assertions across 120 files with 19 intentional skips and no failures. Compiled review emits exactly one six-propagator specialization for each new fixture, adds exact parent-rejection evidence only to the control, keeps the vulnerable record limited to the incomplete-reduction lead, and emits no specialization from the 96-row production SDK inventory. Formatting, generated models, types, clean build, and the production advisory audit are clean. Strict package inspection validates 251 entries; two isolated installations validate public import, CLI behavior, and all 79 bundled-plugin files. The removed 1,484,513-byte archive had SHA-256 `97226e8447e991f8ee00b5a1f958a7df16fcef66fd90d9624355ea414e3a6da0`. Windows GUI acceptance builds without warnings/errors, passes seven core plus three shared tests, and publishes a 346,796-byte executable with SHA-256 `0df0ed41e39780e6100a8657d4414ec2e6bcb4f0ef6fdfe2495030f5710b1f67`. WSL Ubuntu builds without warnings/errors; passes seven core, three shared, and two headless tests under a Linux-only PATH; and passes non-graphical plus X11/Xvfb startup. The 72,568-byte Linux executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- An authenticated GitHub Copilot `gpt-5.6-terra` high-effort deep campaign completed the new Java `File.getName()` exploit/control pair with one true positive, zero false positives, zero misses, and perfect completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, and negative-control gates. The positive produced one substantive medium-severity finding and the safe control produced none. Stored GitHub authentication remained valid; neither invocation reported an allowance, credit, rate-limit, authentication, or safety-classifier failure. Campaign `d44245ae29499c3874b2427d72eda02de31f637301c23a21d77ed23e65ea8bdd` remains isolated under `C:\security-benchmarks`.
- Corrected Java basename-reduction semantics in line with CodeQL CLI 2.26.2. A proven Spring request-to-filesystem path that passes through exact `java.io.File.getName()` now emits the derived `java-file-getname-path-boundary` hypothesis because `new File("..").getName()` preserves the exact parent component. The original `spring-http-path` record remains available for broader link, race, authorization, and platform analysis.
- Required exact official `java.io.File` identity, exact basename-result reachability to the existing typed sink, and a containing exported Java method. Imported and fully qualified construction plus exact receiver aliases are supported; a cross-file specialization seeds only the wrapper parameter already proven by the Spring graph, and a direct construction requires its own constructor argument to be tainted. A local `File` type, another object's `getName`, a fixed construction beside an unrelated remote subexpression, cleared values, comments, tests, examples, unrelated variables, logging-only checks, partial string folklore, and post-sink rejection fail closed. Exact pre-sink `"..".equals(value)` or `value.equals("..")` with a fail-closed return or throw is retained only as `parent-path-component-rejection` candidate evidence.
- Added the ninety-first effectiveness increment and seventy-eighth exploit/control pair to `java-multi-hop-path-manifest.json` under perfect completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, and negative-control gates. The positive crosses a Spring controller, service, and repository, reduces the request with `File.getName`, and proves `..` reads a parent `content.txt`; the matched control preserves topology, sink, payload, and allowed-basename behavior while rejecting exact and nested parent basenames before the sink. The documented corpus now contains 468 scans at three runs per case, and hosted Java fixture CI compiles and executes both additions.
- Expanded the Java path quality gate to state that `File.getName` and `Path.getFileName` are lexical basename operations rather than parent-component sanitizers, while separating exact parent rejection from link, junction, mount, writable-directory, race, decoding, platform, tenant, and object-authorization proof. Both new Maven fixtures pin the current stable compiler plugin so Java 17 release semantics remain portable across Maven 3.8.7 WSL and hosted runners.
- The focused Java path lane passes 9 tests and 54 assertions; the widened Java, Spring, shared-framework, multi-hop, and residual slice passes 137 tests and 1,399 assertions with one intentional platform skip. The authoritative Windows suite passes 1,119 tests with 19 intentional environment/integration skips, no failures, and 8,543 assertions across 120 files. Compiled deterministic review emits one exact six-propagator specialized row for the vulnerable fixture at `DocumentStore.java:19`, one structurally identical controlled row at line 22 with `parent-path-component-rejection`, and no specialization from the 96-record production SDK inventory.
- Formatting, generated-model drift, TypeScript checking, the clean production build, the production advisory query, and strict package inspection are clean. The package gate validates 251 entries, two isolated installations, public import, CLI behavior, and all 79 bundled-plugin files. The removed 1,461,543-byte archive had SHA-1 `a43874cad3c5bc01562b201810781cf3199613bc`, SHA-256 `a8b3beebf74c3254594a3ec43c13693aaaed0d18eff7faf092ca07a7358c50a0`, and integrity `sha512-fNfp4q8/cra0AzqxycCz8KGgfWgLUFjJTHXf3KXJWXK+XBBpYXMAO/3YCFnglt0OsTEGVuGAGh97mUdllE2xHg==`. Windows GUI acceptance builds without warnings/errors, passes seven core plus three shared tests, and publishes a 346,796-byte executable with SHA-256 `dcea4dfe42fcc714fe1717f4207c333e47b32090c3c10b8d7cde6ab0d441ce65`. WSL Ubuntu builds without warnings/errors; passes seven core, three shared, and two headless tests under a Linux-only PATH; and passes non-graphical plus X11/Xvfb startup. The 72,568-byte Linux executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Corrected Go filesystem-path control semantics for `filepath.Rel` in line with the CodeQL 2.26.2 path-injection model. `Rel` remains a `go-filesystem-path-construction` propagator and is no longer mislabeled as a containment check. The model records `relative-parent-boundary-rejection` only when the exact derived variable is compared with `..` and passed to `strings.HasPrefix` with `".." + string(os.PathSeparator)` before the sink. Either half, a different value, a post-sink check, comments, and string examples do not create the exact candidate; every candidate remains subject to dominance and fail-closed review.
- Tightened all Go filesystem-path candidate controls to the pre-sink boundary. A control lexically after the exact filesystem operation is no longer attached as counterevidence. Updated quality-gate guidance explicitly rejects treating lexical relativity as filesystem authorization in the presence of links, mounts, renames, or incomplete control flow.
- Added the ninetieth effectiveness increment and seventy-seventh exploit/control pair to `go-http-filesystem-path-manifest.json` under perfect completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, and negative-control gates. The positive passes an HTTP query through a unique same-package wrapper, computes and rejoins `filepath.Rel`, and proves a `..` payload reads a sibling signing key. The matched control preserves topology, bytes, and allowed-file behavior while rejecting both exact-parent and separator-delimited parent results. The documented corpus now contains 462 scans at three runs per case, and hosted Go fixture CI executes both additions.
- Restored executable compatibility between the current benchmark evaluator and committed specialized manifests. An exact legacy `title`/`path`/`line` expectation receives a stable per-case `legacy-expectation-N` identity and canonical location; arbitrary malformed expectations still fail closed. All eleven legacy perfect-gate names now map to the current `min*` thresholds, while defining both names is rejected instead of choosing silently. This closes the prior failure mode in which a costly scan could finish and then fail on the missing modern `id`, while legacy thresholds were ignored.
- An authenticated GitHub Copilot `gpt-5.6-terra` high-effort deep campaign completed all four Go filesystem cases with two true positives, zero false positives, zero misses, and perfect completion, precision, recall, F1, case, negative-control, stability, validation, attack-path, code-evidence, and severity gates. The first bounded runner invocation preserved three sealed receipts before its command ceiling; a resumed single-worker invocation preserved those receipts and completed the separator-aware control with zero findings and complete coverage. No allowance, authentication, or safety-classifier failure occurred. Campaign `b7f682152c8a8d74b64069c45467e64ae7d1300933092c12ce16120a7d1f6e08` remains isolated under `C:\security-benchmarks`.
- The focused Go filesystem lane passes 15 tests and 96 assertions; all eleven typed Go suites pass 299 tests and 1,773 assertions. The authoritative Windows suite passes 1,116 tests with 19 intentional environment/integration skips, no failures, and 8,515 assertions across 120 files. Both Go modules pass execution and vet. Compiled deterministic review emits one exact five-propagator cross-file path row for the vulnerable fixture at `document.go:14`, one controlled row at line 18 with `path-string-validation` and `relative-parent-boundary-rejection`, and no Go filesystem row from the 96-record production SDK inventory.
- Formatting, generated-model drift, TypeScript checking, the clean production build, the production advisory query, and strict package inspection are clean. The package gate validates 251 entries, an isolated installation, public import, CLI behavior, and all 79 bundled-plugin files. The removed 1,470,678-byte archive had SHA-1 `e8443862fe6cfc3eb8b50ac6f017e3ece14eb3c4`, SHA-256 `ee49c9d56df233883d5c4f2af363f199602dd7a4a505ba22405150a51564ce96`, and integrity `sha512-LHUfSV+9oRvaxTtKxOr3XVp3zqUIWI4TCTYJYdS4U5SijVCTSAkOY82w/mEebmbtiSJ6CvA0ddfmgbs6yi/O7Q==`. Windows GUI acceptance builds with no warnings/errors, passes seven core plus three shared tests, and freshly publishes a 346,796-byte executable with SHA-256 `9fa2ef0315b9197d98de3840e84ac186d606b07d53b272aa9a92c98c13ab8082`. WSL Ubuntu builds with no warnings/errors; passes seven core, three shared, and two headless tests under a Linux-only PATH; and passes non-graphical plus X11/Xvfb published-binary startup. The Linux executable is 72,568 bytes with SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added exact ASP.NET Core Razor Pages remote-source modeling across all six typed ASP.NET sink families. Public non-static `OnGet`/`OnPost`/HTTP-verb handler parameters on exact official `PageModel` subclasses now feed same-file, uniquely typed cross-file, and one-relay paths without requiring controller-style source attributes. The host follows at most eight unique local base-class edges and preserves `aspnet-razor-page-handler-parameter` as the source kind.
- Improved beyond the upstream handler-parameter addition with `aspnet-razor-page-bound-property`. Official `[BindProperty]` and `[BindProperties]` public writable properties flow through bounded local aliases; GET/HEAD properties require `SupportsGet = true`. Official `[NonHandler]`, `[BindNever]`, `[FromServices]`, `[FromKeyedServices]`, framework service types, protected/internal/static methods, fixed or reassigned values, local framework/attribute shadows, duplicate/unresolved/external bases, cycles, and a ninth inheritance edge fail closed. Same-file C# source selection now requires an exact parameter/property-to-sink relation for Razor sources while retaining the prior annotated top-level fallback.
- Corrected bounded C#/Java-style call extraction for compact one-line methods. When a public/protected/private/internal method declaration and its body share a line, the extractor now skips the signature parentheses and starts at the first body call. The rule is limited to a syntactic method declaration so later object-initializer braces cannot redirect multiline sink parsing or turn safe typed SQL parameters into query-text flow.
- Added the eighty-ninth model increment and seventy-sixth exploit/control pair under `aspnet-razor-page-sql-manifest.json` with perfect single-run completion, precision, recall, F1, validation, attack-path, code-evidence, severity, stability, and negative-control gates. The real Razor Pages positive carries unannotated `OnGetLookupAsync(string filter)` input through a constructor-injected service into concatenated `SqlCommand` text; the matched control preserves topology and bytes but uses a typed `SqlParameter`. Hermetic executable witnesses prove the exploit selects `Administrator`, while the control rejects the payload and still selects `Alice` exactly. The documented corpus now contains 456 scans at three runs per case, and hosted .NET fixture CI builds and executes both new halves.
- The focused Razor Pages lane passes 7 tests and 28 assertions; the adjacent ASP.NET/framework slice passes 50 tests and 237 assertions. The authoritative Windows suite passes 1,112 tests with 19 intentional environment/integration skips, no failures, and 8,486 assertions across 120 files. Compiled deterministic review emits exactly one `aspnet-http-sql` cross-file wrapper row for the vulnerable fixture at `Services/UserQueries.cs:19`, with source `Pages/Search.cshtml.cs:17` and three exact propagators; the parameterized control and production SDK emit none. The SDK inventory remains 96 deterministic rows.
- Formatting, generated-model drift, TypeScript checking, the clean production build, both .NET witnesses, and the production advisory query are clean. Strict package inspection validates 251 entries, an isolated installation, public import, CLI behavior, and all 79 bundled-plugin files. The removed validation archive was 1,467,879 bytes with SHA-1 `a00551cd60650b6591f3d3c1ae301cc0d63ed746`, SHA-256 `52f4471765d738b75ce77574570979f127e0352d9d55853c5feb91b88419a5aa`, and integrity `sha512-SQ9SWQGm8YtqEfQqj0QNIXH2HijJBxdlTepUklJJ7wgSkE7BrJEaKUao1qJEUhzEDxZ3x5sPDGl4Cduzj63YgQ==`. Windows GUI acceptance builds with no warnings/errors, passes seven core plus three shared tests, and publishes a 346,796-byte executable with SHA-256 `967f164f0e08949d078c1d55bccaead085dfc0c041d0dd57560ca9aa63e7ae00`. WSL Ubuntu builds with no warnings/errors; passes seven core, three shared, and two headless tests under a Linux-only PATH; and passes non-graphical plus X11/Xvfb published-binary startup. The Linux executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Added `node-ssrf-ipv6-transition-incomplete-guard` for CWE-918 with CWE-1389 context. The specialization starts from an existing typed Node request-to-outbound-URL path, requires a fail-closed IPv4-only private-address check on the same parsed host in the sink wrapper, and preserves the exact guard as broken-control evidence. A same-file or relative-wrapper alert therefore cannot arise from validator naming or package co-occurrence alone.
- Improved the upstream experimental-query boundary by treating IPv4-mapped IPv6, NAT64, and 6to4 as three independent validation families. Canonicalizing only `::ffff:` remains positive. Suppression requires a called canonicalizer whose exact returned value reaches the private-address guard and whose own bounded body handles all three families; an unused complete helper, unrelated host, log-only branch, comments, or non-dominating check cannot suppress the path. Conventional JavaScript test/spec, test-directory, and example-directory paths are excluded from this specialization. The quality gate requires deployed parser, resolver, proxy, client, operating-system, and network acceptance plus a concrete internal effect before reporting.
- Added the eighty-eighth exploit/control pair and `node-ipv6-transition-ssrf-manifest.json` under perfect single-run gates. The exploit crosses a relative import into `fetch` after dotted-quad-only filtering; the control retains the topology and canonicalizes all three transition families first. An executable Node witness validates every literal as IPv6, proves the IPv4-only guard accepts it, and proves complete canonicalization exposes `127.0.0.1`. The documented corpus now contains seventy-five exploit/control pairs and 450 scans at three runs per case.
- The focused IPv6-transition lane passes 9 tests and 24 assertions. The adjacent SSRF, Axios, framework, and residual suite passes 99 tests and 1,204 assertions with one intentional platform skip; TypeScript checking and both executable witness tests are clean. The authoritative Windows suite passes 1,105 tests with 19 intentional environment/integration skips, no failures, and 8,458 assertions across 119 files. Compiled deterministic review emits exactly one specialized whole-repository row—the intentional vulnerable benchmark—rejects the safe twin, and emits zero specialized rows from the SDK source tree.
- Windows GUI acceptance builds with zero warnings/errors, passes seven core plus three shared desktop checks, and publishes a fresh 346,796-byte executable with SHA-256 `F5037A6D8DAA4B14E32D45BCD07B47B57C3567B841323DDF5EB055613C322F85`. WSL Ubuntu builds with zero warnings/errors; passes seven core, three shared desktop, and two headless Avalonia checks; and passes both non-graphical and X11/Xvfb published-binary startup tests. Formatting, generated-model drift, types, the clean build, the production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The final 251-entry archive was 1,460,269 bytes, had SHA-1 `d927ef3b85add2ba8097e12cfdd86971634eb43e`, SHA-256 `4d3e9bc43550cba9b928445e8eb988c5774e380a779aa8f8655359a69ffd6584`, and integrity `sha512-WRE8d3RGLGyIzDo8XFuqo2qFWODpT3H97+6cOBdyk7DwzyaWFAsibAwbgG9bt8dA7bGG/rU309DI4A7EkSx6JQ==` before removal.
- Added exact GitHub Copilot SDK trusted-instruction injection discovery as `node-copilot-system-prompt-injection` with CWE-1427. The model requires a named `CopilotClient` binding from `@github/copilot-sdk`, a uniquely constructed non-reassigned client, and `createSession` or `resumeSession`; it then follows an HTTP request value only into `systemMessage.content`, consumed customize-section content or known-section transforms, inference-visible custom-agent prompts/descriptions, and tool descriptions. Content-bearing unknown customize sections are modeled according to the SDK's appended-instruction fallback. Ordinary `session.send` or `sendAndWait` prompt data remains a negative user-channel control.
- Preserved exact same-file and three-file evidence across up to two relative-module wrappers and eight local value aliases. ESM import aliases and CommonJS destructuring are supported. A ninth alias, wrong/lookalike packages, default or namespace guesses, duplicate or reassigned clients, unrelated same-named methods, fixed trusted fields, content ignored by `remove`/`preserve`, non-inferred agent descriptions, completion-UI-only command descriptions, attacker-controlled agent names without trusted text, comments, and string-only pseudo-flows fail closed. The quality gate now distinguishes append from replace semantics, rejects encoding and delimiter folklore as hierarchy controls, and requires concrete tool, command, MCP, filesystem, network, credential, tenant, disclosure, and unintended-operation impact analysis.
- Corrected the shared bounded JavaScript initializer slicer while adding named section-action and agent-inference controls. Structural string masking could previously let trailing masked whitespace move the slice past a quoted right-hand side. Resolution now anchors immediately after the actual assignment operator and skips whitespace in the original source, allowing exact quoted action constants and `infer` constants to suppress only the SDK content that those controls really make non-model-visible.
- Added the eighty-seventh exploit/control pair and `node-copilot-prompt-injection-manifest.json` under perfect single-run completion, precision, recall, validation, attack-path, evidence, severity, and negative-control gates. The exploit carries a request-selected persona through two wrappers into `systemMessage.content`; the control preserves the topology and fixed system message while sending the same request data only through the ordinary user-message channel. The documented corpus now contains seventy-four exploit/control pairs and 444 scans at three runs per case.
- The focused GitHub Copilot SDK prompt-injection lane passes 7 tests and 36 assertions; the adjacent Node/framework/residual gate passes 114 tests and 1,340 assertions with one intentional platform skip. The authoritative Windows suite passes 1,096 tests with 19 intentional skips, no failures, and 8,434 assertions across 118 files. Compiled-output review emits exactly one six-propagator CWE-1427 path from `src/server.js:4` to `src/session.js:9`, while the ordinary-user-message control emits none; deterministic production-SDK review emits 96 residual records and no prompt-injection hypothesis. Windows builds with zero warnings/errors, passes seven core plus three shared desktop checks, and publishes a 346,796-byte single-file executable with SHA-256 `96700B3A889143EA8B2B3B657D48C6A133CF863A287CAE01A0751A181E98476D`. WSL Ubuntu builds with zero warnings/errors, passes seven core, three shared desktop, and two headless Avalonia checks, and passes both non-graphical and X11 published-binary startup tests. Formatting, generated-model drift, TypeScript checking, the clean build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive was 1,437,137 bytes packed and 6,683,548 bytes unpacked, had SHA-1 `528fb8ada759b0e6c870490cd4ed828c642acce8`, integrity `sha512-lkH709OgXPOCEXm+STsNqx3r6bDbKt+TP/YEARSpcqygKFm0zWQeh6eebxqMIq2/38c6zDK02UUq3VKBVCVnng==`, and was removed after inspection.
- Resolved exact Go method promotion through local embedded concrete structs in the object-authorization graph. Struct discovery now recognizes direct and pointer embedded fields, derives their Go field names, and performs bounded breadth-first selector lookup. A direct field or method hides deeper names; more than one field or method at the shallowest depth is rejected as ambiguous. Interface satisfaction uses the exact method set of `T` versus `*T`, while an ordinary call on an addressable concrete binding may use the language's implicit address operation. Every promotion edge is recorded as `go-method-receiver-promoted-field` evidence.
- Kept promoted dispatch fail closed and state-aware. Resolution stops on cycles, a ninth edge, unresolved or external types, embedded interfaces, generic or unsupported fields, visibility violations, duplicate methods, pointer/value method-set mismatches, and same-depth collisions. Embedded pointer fields additionally require exact constructor materialization before a sink can be emitted. The new negative matrix exposed that final direct-summary matching enforced only callee requirements; it now combines call-site receiver requirements with correctly prefixed callee requirements, preventing an uninitialized promoted pointer from becoming a false executable path.
- Added the eighty-sixth exploit/control pair and expanded the strict Go authorization manifest from sixty-eight to seventy cases. Both executable Go 1.26 modules cross `Service.RepositoryLayer` and `RepositoryLayer.*Store` before invoking a promoted repository deletion. The exploit proves deletion of an attacker-selected victim through an ID-only predicate. The control preserves the complete constructor and promotion graph, binds the same predicate to the context-derived account, blocks the victim deletion, and permits an owned deletion. Hosted Go CI executes both modules. The documented corpus now contains seventy-three exploit/control pairs and 438 scans at three runs per case.
- The focused Go authorization lane passes 133 tests and 881 assertions; all eleven typed Go suites pass 296 tests and 1,749 assertions; and all seventy manifest-backed authorization modules compile and execute successfully. The authoritative Windows suite passes 1,089 tests with 19 intentional skips, no failures, and 8,398 assertions across 117 files. Built-output review emits exactly one 11-propagator positive at `internal/store/store.go:11`, with source `handler.go:11`, promoted fields at service lines 10 and 6, and no candidate control; the matched control preserves the receiver path and adds only `principal-bound-object-query`. Deterministic production-SDK review emits 96 records and no Go object-authorization hypothesis. Both new modules pass `go test ./...` and `go vet ./...`. Windows builds without warnings or errors and passes seven core plus three shared desktop checks; WSL Ubuntu builds without warnings or errors and passes both headless Linux GUI checks. Formatting, generated models, TypeScript checking, the clean build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive was 1,441,178 bytes packed and 6,618,908 bytes unpacked, had SHA-1 `c2415d88dcf5b79362ccc637b23eaff847f603c5`, integrity `sha512-oslHon27+yxlPX0rqTqbMa+6CaVwHEFhRvl47dOte7lNRE+VaIKYlPF6zmPtq/fJvxuOpnwbBdq/FFc6IlKWOg==`, and was removed after inspection.
- Resolved exact local Go type aliases across every interface proof path used by object-authorization analysis. Direct and grouped non-generic aliases can now name method-signature types, embedded interface elements, constructor parameters and fields, type-switch sources, and explicit conversion targets. One shared resolver follows same-package and qualified local-module aliases through at most eight declarations in each declaration's own file/import/package context. Alias identity is preserved rather than approximated as a new named type, including aliases of `any` and `interface{}`.
- Kept the new coverage fail closed: alias cycles, a ninth declaration, duplicate alias or alias/interface identities, generic aliases, pointers, unexported qualified aliases, incomplete or ambiguous imports, unresolved or external targets, and aliases of non-interface types do not create dispatch. Defined types remain distinct, so `type InvoiceID string` cannot satisfy a method requiring `string` while `type InvoiceID = string` can. Added focused composition, grouped-declaration, empty-interface, exact eight/nine boundary, cycle, generic, defined-type, concrete-target, duplicate, visibility, unresolved-target, and method-signature regressions.
- Added the eighty-fifth exploit/control pair and expanded the strict Go authorization manifest from sixty-six to sixty-eight cases. Both executable Go 1.26 modules cross exact aliases in method signatures, embedded source and target contracts, constructor parameters and fields, and the conversion target. The exploit proves attacker-selected victim deletion; the control preserves the entire alias topology and adds only the authenticated account predicate, proving victim survival and successful owned deletion. The focused lane passes 129 tests and 853 assertions, both witnesses execute, and the documented corpus now contains seventy-two exploit/control pairs and 432 scans at three runs per case.
- The expanded focused authorization lane passes 129 tests and 853 assertions; all eleven typed Go suites pass 292 tests and 1,723 assertions; and all sixty-eight manifest-backed authorization witnesses execute successfully. The authoritative Windows suite passes 1,085 tests with 19 intentional skips, no failures, and 8,370 assertions across 117 files. Compiled-output review emits one positive at `internal/primary/store.go:11` with 22 exact propagators, all three parent writes at lines 42, 44, and 46, and no candidate control; the control preserves that path and adds only `principal-bound-object-query`. Production-SDK review emits 96 deterministic records and no Go object-authorization hypothesis. Both new fixtures pass Go tests and vet. Windows and WSL builds have zero warnings or errors; Windows passes seven core plus three shared desktop checks, and WSL Ubuntu passes both headless Linux GUI checks. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,436,646 bytes packed and 6,601,857 bytes unpacked, has SHA-1 `df8f74cd93397a8bee43a563eb52377ee43c1f13`, integrity `sha512-zvssOKfu1vTqYOpYnOK7snH541auWnChWl70S18WVt8AfegPbyg95ymy5hPB+EtZJQ9W9K+RkJKvBUJTslioww==`, and was removed after inspection.
- Expanded Go named basic interfaces through exact, bounded embedding graphs before assignability, conversion, dispatch, and concrete-implementation checks. Same-package names and qualified local-module names must resolve to one interface declaration. The resolver admits at most eight embedding edges and 64 canonical methods, preserves each unexported method's declaring-package identity, and accepts repeated diamond methods only when their canonical signatures are identical. Cycles, a ninth edge, signature conflicts, ambiguous declarations, incomplete or external imports, non-interface terms, constraints, and oversized method sets fail closed. Empty interfaces remain distinguishable from incomplete descriptors.
- Added the eighty-fourth exploit/control pair and expanded the strict Go authorization manifest from sixty-four to sixty-six cases. Both Go 1.26 modules compose `parent.InvoiceRepository` from a same-package leaf and compose `contracts.SelectedRepository` through an explicitly aliased interface in a third local-module package before the existing all-path type-switch join. The exploit proves unscoped victim deletion; the control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Both modules pass execution and vet, hosted Go CI covers them, and the documented corpus now contains seventy-one exploit/control pairs and 426 scans at three runs per case.
- Added focused regressions for same-package source embedding, qualified imported target embedding, identical diamond merges, and exact eight-level nesting. Negative cases cover a ninth level, cycles, conflicting embedded signatures, ambiguous duplicate declarations, unresolved external embeddings, and same-spelling unexported methods from different packages. The existing canonical same-package and cross-package interface-conversion matrix remains green.
- Required each concrete Go implementation method to have the same canonical parameter and result identity as the interface method, in addition to the existing unique receiver, method-name, pointer-set, directory, package, and unexported-method visibility proofs. A same-named concrete method with an incompatible identifier type now fails closed.
- Removed four .NET compiler-version ambiguities from the shared desktop/core path by making every multi-separator `string.Split` argument an explicit `char[]`. Windows' toolchain and Ubuntu's older Roslyn selected different overload behavior for collection expressions. The explicit arrays compile on both platforms without changing path validation, diagnostic trimming, artifact containment, or GUI path-list semantics.
- The focused Go authorization lane passes 126 tests and 831 assertions; all eleven typed Go suites pass 289 tests and 1,701 assertions; and all sixty-six authorization witnesses execute successfully. The authoritative Windows suite passes 1,082 tests and 8,348 assertions across 117 files with 19 intentional environment-specific skips and no failures. Compiled-output review emits exactly one 22-propagator Go authorization model at `internal/primary/store.go:11` for each new fixture, preserving source `handler.go:11`, all three writes at parent lines 36, 38, and 40, and the complete service/layer/holder path; only the control contains `principal-bound-object-query`. Production-SDK review emits 96 deterministic records and no Go object-authorization hypothesis. The Windows GUI builds with no warnings or errors and passes all seven core plus three shared desktop checks; WSL Ubuntu passes both headless Linux GUI checks. Both fixtures pass Go tests and vet. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,421,683 bytes packed and 6,584,684 bytes unpacked, has SHA-1 `7fcb53569857a9d254bb477d0aea9bc7da73f85a`, integrity `sha512-7feAOQyNf3rNB2IDrvq8SkTHCJbhlfLezSmirRlm1aqeiPQesDID7wQueoD0SlU8/GEBO6tFyLuB1CnsRWeD5g==`, and was removed after inspection.
- Replaced textual Go interface-signature equality with bounded canonical type identities for exact named-interface conversions. Parameter and result names are removed, grouped declarations are expanded, predeclared `byte`/`rune` aliases are normalized, and pointers, slices, fixed numeric arrays, maps, directional channels, function types, empty interfaces, named types, and bounded named-type arguments receive structural identities. Each file's explicit import aliases resolve to import paths; unaliased local-module imports resolve through a precomputed index of imported package clauses, conservative standard-library imports use their package basename, local named types retain package identity, and unexported methods require the same declaring-package identity. Exact exported method-set subsets can now cross files and local-module packages without rescanning the Go inventory per import. Duplicate, dot, blank, ambiguous, unresolved, version-basename, malformed, unsupported, or differently bound type identities continue to fail closed.
- Added the eighty-third exploit/control pair and expanded the strict Go authorization manifest from sixty-two to sixty-four cases. The Go 1.26 modules place `InvoiceRepository` and `SelectedRepository` in different packages, deliberately use named parameters/results and explicit import aliases on the source versus unnamed parameters and natural package names on the target, then preserve the converted dynamic value through the existing bounded type-switch join. The exploit proves unscoped victim deletion; the control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Both modules pass execution and vet, hosted Go CI covers them, and the documented corpus now contains seventy exploit/control pairs and 420 scans at three runs per case.
- Added focused positive regressions for canonical cross-package and same-package cross-file identities, import-alias differences, named-versus-unnamed parameters/results, grouped names, and method-set subsets. Negative controls cover different import paths behind the same alias text, result mismatches, same-spelling unexported methods across packages, duplicate aliases, and unresolved qualified types. The original identical, empty, mismatch, broader-target, lexical-shadow, stale-alias, and depth controls remain intact.
- The focused Go authorization lane passes 124 tests and 813 assertions; all eleven typed Go suites pass 287 tests and 1,683 assertions; and all sixty-four authorization witnesses execute successfully. The authoritative Windows suite passes 1,080 tests and 8,330 assertions across 117 files with 19 intentional environment-specific skips and no failures. Compiled-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 22 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, service construction and receiver flow, parent holder creation, all three canonical cross-package-interface writes at parent lines 32, 34, and 36, the static service/layer/holder fields, and only the primary SQL mutation; no archive evidence is present. The control preserves that path and adds only `principal-bound-object-query`. Production-SDK review emits 96 deterministic records and no Go object-authorization hypothesis. Both new fixtures pass Go tests and vet. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,432,493 bytes packed and 6,567,505 bytes unpacked, has SHA-1 `2f4422139ba9686f2fac9673f48253545b5e2f2b`, integrity `sha512-1Aoi8CPgrsOz3B61C60A5Vzqeyk6nD19nsC23f6cFyHETfvrUAG6bopz/jyhAawvfN3jiZIAVg8nqweCCeydEQ==`, and was removed after inspection.
- Extended exact Go interface type-switch value flow through named basic-interface conversions. Inline and top-level assigned conversions may now target one uniquely resolved local-module interface after lexical shadow checks. Identical interfaces and named empty interfaces are accepted directly. A distinct nonempty target must be a basic interface in the same package as the source, and every target method must occur in the source method set with an exact canonical signature; cross-file signatures containing unresolved qualifiers remain fail closed. Each assignment still consumes the shared eight-edge alias budget, changes only the tracked static interface descriptor, and preserves the original parameter and dynamic value. Broader or signature-mismatched targets, embedded or constraint interfaces, ambiguous identities, unresolved cross-package nonempty method sets, nested inputs, selectors, composites, local type or value shadowing, and a ninth edge remain rejected.
- Strengthened interface identity and lexical-scope proof while adding that flow. Interface descriptors now retain their declaring file and exact method signatures when the bounded parser can prove them, and exact named empty interfaces participate without inventing callable methods. The prior `any` shadow checks now reuse a generic identifier-scope resolver covering named results, parameters, receivers, direct and grouped `const`/`type`/`var` declarations, short declarations, and prior assignments. Qualified named targets additionally require exact local-module import identity and an unshadowed qualifier.
- Added the eighty-second exploit/control pair and expanded the strict Go authorization manifest from sixty to sixty-two cases. Both Go 1.26 modules import a helper that creates a value layer with one pointer holder, makes three shallow copies, converts its injected repository to a distinct `SelectedRepository` basic interface with the same method signature, carries the converted value through one local alias, and writes the original primary repository under `nil`, named-interface, and final-default type-switch arms. The positive proves unscoped victim deletion. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules. The documented corpus now contains sixty-nine exploit/control pairs and 414 scans at three runs per case.
- The focused Go authorization lane passes 122 tests and 796 assertions; all eleven typed Go suites pass 285 tests and 1,666 assertions; and all sixty-two authorization witnesses execute successfully. The authoritative Windows suite passes 1,078 tests and 8,313 assertions across 117 files with 19 intentional environment-specific skips and no failures. Compiled-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture, each with 28 propagators, the imported helper call and return, writes at parent lines 35, 37, and 39, and no archive evidence; only the control contains `principal-bound-object-query`. Production-SDK review emits 96 deterministic records and no Go object-authorization hypothesis. Both fixtures pass Go tests and vet. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,426,590 bytes packed and 6,527,262 bytes unpacked, has SHA-1 `8b02b6ddce106da44cbeb7cbd53707c9d571d164`, integrity `sha512-noB5ia+EG8XaZdLmH2x0oPhWV9kKT4D03v/RPkgcOygH93T9HLuzARt6fhE7n9SumT2QNGHB/0kZxqjIO3etfg==`, and the generated archive was removed after inspection.
- Extended exact Go interface type-switch value flow through empty-interface conversions. Both inline `interface{}(repository).(type)` / `any(repository).(type)` sources and top-level conversion assignments from one bare live interface alias are admitted in ordinary constructors and imported constructor helpers. Each conversion assignment consumes one of the shared eight alias edges and retains kill-on-write semantics. Literal `interface{}` is unshadowable. Predeclared `any` additionally requires a compatible enclosing module language version when declared and proof that no same-package function, type, variable, constant, grouped declaration, current-file explicit or effective import name, parameter, receiver, named result, or preceding local declaration shadows it. Effective local import names use the imported package clause before the path-basename fallback. Results are cached per switch. Named-interface conversions, nested calls or conversions, selector or composite arguments, a shadowed `any`, pre-Go-1.18 module directives, nested assignments, and a ninth edge fail closed.
- Tightened constructor-helper call discovery while preserving complete attack paths. An unqualified call-shaped expression now enters a constructor-helper summary only when a real same-package function declaration with that name exists; qualified calls still require the existing exact local-module/import/callable resolution during materialization. Built-ins and type conversions can no longer poison an otherwise exact helper summary. The new empty-interface conversion witness therefore retains the helper call, allocation and shallow-copy aliases, all three branch write origins, and helper return rather than falling back to a thinner leaf path.
- Added the eighty-first exploit/control pair and expanded the strict Go authorization manifest from fifty-eight to sixty cases. Both Go 1.26 modules import a helper that creates a value layer with one pointer holder, makes three shallow copies, converts its exact repository parameter to predeclared `any`, carries the dynamic value through a local alias, and writes the selected primary repository under `nil`, interface, and final-default type-switch arms. The positive proves unscoped victim deletion. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules. The documented corpus now contains sixty-eight exploit/control pairs and 408 scans at three runs per case. The focused Go authorization lane passes 121 tests and 773 assertions; all eleven typed Go suites pass 284 tests and 1,643 assertions; and all sixty authorization witnesses execute successfully. The authoritative Windows suite passes 1,077 tests and 8,290 assertions across 117 files with 19 intentional environment-specific skips and no failures. Compiled-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture, each with 28 propagators, helper call and return boundaries, writes at parent lines 31, 33, and 35, and no archive evidence; only the control contains `principal-bound-object-query`. Production-SDK review emits 96 deterministic records and no Go object-authorization hypothesis. Go tests and vet, formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,423,856 bytes packed and 6,508,572 bytes unpacked, has SHA-1 `eb007e6cae282d44b2fed2a94fb37d91cc6d0fc4`, integrity `sha512-GFn1SU7Ztgd9avlbpmgbTlX6Sax08e5JTadPdgPpusIwb6xygnhM1Nnm9uMZHPU6tZlKtwcJFk39B6L5rCO0sA==`, and the generated archive was removed after inspection.
- Extended exact Go interface type-switch sources through bounded local value flow in ordinary constructors and constructor helpers. Starting from every uniquely resolved non-pointer interface parameter, the scanner follows as many as eight top-level, single-name assignments whose right side is one bare live alias. Each assignment kills its left-side names before an exact eligible rebind, so concrete replacement, conversion, selector extraction, tuple or multi-name assignment, nested/conditional binding, stale aliases, and a ninth hop fail closed. A source may rebind from another exact interface parameter without losing proof. The existing direct/unbound and fresh guard-bound type-switch grammars, compiler-valid leading blank guard use, mandatory final default, independent complete-world replay, bidirectional identity-topology convergence, equal nonzero writes, evidence union, and resource bounds remain unchanged.
- Added the eightieth exploit/control pair and expanded the perfect-gate Go authorization manifest from fifty-six to fifty-eight cases. Both Go 1.26 modules import a helper that creates a value layer with one pointer holder, makes three shallow copies, carries its exact interface parameter through two local aliases, and writes the selected primary repository through a different copy under `nil`, interface, and final-default type-switch arms. The positive proves unscoped victim deletion through the converged shared holder. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules. The documented corpus now contains sixty-seven exploit/control pairs and 402 scans at three runs per case.
- The focused Go authorization lane passes 120 tests and 749 assertions; all eleven typed Go model suites pass 283 tests and 1,619 assertions; and all fifty-eight authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,076 tests and 8,266 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 28 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, service aliases `internal/service/service.go:15,18`, imported helper call at line 16, helper allocation and value-copy aliases `internal/parent/layer.go:22-25`, shared holder creation at line 22, all three aliased-type-switch writes at lines 31, 33, and 35, helper return at line 37, service return at line 20, receiver and object flow at lines 23-25, the static service, layer, and holder fields, and only the primary SQL mutation. The switch source is separately proven through exact local assignments at parent lines 26-27 and intentionally creates no state/evidence edge. The control preserves that 28-step output path plus only `principal-bound-object-query` at `internal/primary/store.go:11`; neither path contains archive-store evidence. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Go tests and vet, formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,417,635 bytes packed and 6,474,535 bytes unpacked, has SHA-1 `e7c0281635cf35839fe35c8d70b26a6029eab189`, integrity `sha512-k+QhMyGX8nvANjBUL+Mxx2ZcZu311UYv6JsR091xnff7HXggNAaIZyLpR7gqDonZ68mAc4gt8zCvLRNoLTj3fw==`, and the generated archive was removed after inspection.
- Extended bounded all-path Go switch replay to exact interface type switches in ordinary constructors and constructor helpers. The source must be a bare function parameter whose non-pointer interface identity resolves uniquely in the local module, or an exact empty `interface{}` parameter. Both `switch repository.(type)` and `switch selected := repository.(type)` are admitted. A named guard must be fresh and can appear only in leading exact `_ = selected` blank assignments, which are removed as semantic no-ops before exact-write replay; every value-bearing or later guard use fails closed. The mandatory final default, two-through-four-arm cap, independent complete-world replay, bidirectional identity-topology join, equal nonzero writes, evidence union, and existing resource bounds remain unchanged. Scalars, parameter aliases, selectors, conversions, unconstrained `any`, pointer parameters, shadowed or ambiguous interfaces, malformed guards, divergent writes, and every other type-switch source remain rejected.
- Added the seventy-ninth exploit/control pair and expanded the perfect-gate Go authorization manifest from fifty-four to fifty-six cases. Both Go 1.26 modules import a helper that creates a value layer with one pointer holder, makes three shallow copies, and writes the selected primary repository through a different copy under `nil`, interface, and final-default type-switch arms. The named guard is consumed only by a leading blank assignment. The positive proves unscoped victim deletion through the converged shared holder. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules. The documented corpus now contains sixty-six exploit/control pairs and 396 scans at three runs per case.
- The focused Go authorization lane passes 119 tests and 732 assertions; all eleven typed Go model suites pass 282 tests and 1,602 assertions; and all fifty-six authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,075 tests and 8,249 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 28 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, service aliases `internal/service/service.go:15,18`, imported helper call at line 16, helper allocation and value-copy aliases `internal/parent/layer.go:22-25`, shared holder creation at line 22, all three type-switch writes at lines 29, 31, and 33, helper return at line 35, service return at line 20, receiver and object flow at lines 23-25, the static service, layer, and holder fields, and only the primary SQL mutation. The control preserves that 28-step path plus only `principal-bound-object-query` at `internal/primary/store.go:11`; neither path contains archive-store evidence. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Go tests and vet, formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,416,881 bytes packed and 6,469,992 bytes unpacked, has SHA-1 `283115baa5561ad6be26585cb6616d4b78a0d2ac`, integrity `sha512-GyGVjvmrlwOEKpzMEpT6//0PVBmK4lL86OEhIh/Vb9N8pACLsVs5mQQdVTIJ+981n23vBPxl4DQgwFLzhPAVAQ==`, and the generated archive was removed after inspection.
- Extended bounded all-path Go switch replay to one exact initializer-bound expression form in ordinary constructors and constructor helpers: `switch selected := label; selected`. The initializer must short-declare one fresh guard from one exact built-in scalar parameter, and that guard must be the switch expression without appearing in any arm body. The existing independent world replay, mandatory final default, bidirectional identity-topology join, equal nonzero writes, evidence union, and resource bounds remain unchanged. Call or composite expressions, non-scalar parameters, a mismatched guard, parameter or prior-local shadowing, guard use inside an arm, assignment rather than short declaration, type switches, and every other initializer form fail closed.
- Added the seventy-eighth exploit/control pair and expanded the perfect-gate Go authorization manifest from fifty-two to fifty-four cases. Both Go 1.26 modules import a helper that creates a value layer with one pointer holder, makes three shallow copies, binds a fresh switch guard directly from its string parameter, and writes the selected primary repository through a different copy in each arm. The positive proves unscoped victim deletion through the converged shared holder. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules. The documented corpus now contains sixty-five exploit/control pairs and 390 scans at three runs per case.
- The focused Go authorization lane passes 118 tests and 707 assertions; all eleven typed Go model suites pass 281 tests and 1,577 assertions; and all fifty-four authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,074 tests and 8,224 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 28 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, service aliases `internal/service/service.go:15,18`, imported helper call at line 16, helper allocation and value-copy aliases `internal/parent/layer.go:22-25`, shared holder creation at line 22, all three initialized-switch writes at lines 28, 30, and 32, helper return at line 34, service return at line 20, receiver and object flow at lines 23-25, the static service, layer, and holder fields, and only the primary SQL mutation. The control preserves that 28-step path plus only `principal-bound-object-query` at `internal/primary/store.go:11`; neither path contains archive-store evidence. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Go vet, formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,400,397 bytes packed and 6,463,691 bytes unpacked, has SHA-1 `93e6b056bb63a03c09a233c08e51d81916da4952`, integrity `sha512-c54teFtsxyYaaXD+1ok7+w6i6VmBLm4DHF9FgPMgiQfATe8ElKTaB4gJl2hZxOGZpcE2TeZ56FHZqSGWjdbT4A==`, and the generated archive was removed after inspection.
- Extended bounded all-path Go switch replay to exact expressionless `switch { ... }` forms in ordinary constructors and constructor helpers. Every condition arm and the mandatory final `default` still execute against independent identity-preserving clones of the complete tracked graph and must converge under the existing bidirectional topology join. An exact unlabelled `break`, with an optional semicolon, is ignored only when it is the final nonblank statement of an arm because it is semantically identical to Go's implicit case termination. Switch initializers, type switches, `fallthrough`, labelled or non-terminal breaks, missing or non-final defaults, empty or divergent arms, nested control, branch-local state, a fifth arm, unequal budgets, and unresolved identities continue to fail closed.
- Added the seventy-seventh exploit/control pair and expanded the perfect-gate Go authorization manifest from fifty to fifty-two cases. Both Go 1.26 modules import a helper that creates a value layer with one pointer holder, makes three shallow copies, and writes the selected primary repository through a different copy in each arm of an expressionless switch; every arm ends in an explicit redundant break. The positive proves unscoped victim deletion through the converged shared holder. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules. The documented corpus now contains sixty-four exploit/control pairs and 384 scans at three runs per case.
- The focused Go authorization lane passes 117 tests and 685 assertions; all eleven typed Go model suites pass 280 tests and 1,555 assertions; and all fifty-two authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,073 tests and 8,202 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 28 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, service aliases `internal/service/service.go:15,18`, imported helper call at line 16, helper allocation and value-copy aliases `internal/parent/layer.go:22-25`, shared holder creation at line 22, all three expressionless-switch writes at lines 28, 31, and 34, their terminal breaks at lines 29, 32, and 35 as syntax rather than evidence, helper return at line 37, service return at line 20, receiver and object flow at lines 23-25, the static service, layer, and holder fields, and only the primary SQL mutation. The control preserves that 28-step path plus only `principal-bound-object-query` at `internal/primary/store.go:11`; neither path contains archive-store evidence. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,399,617 bytes packed and 6,458,872 bytes unpacked, has SHA-1 `b4ac372918a9696d74ec9264e37a34039c89193b`, integrity `sha512-wQREmATZrjaGf5tCskj40TrquvTUDmsLBbngqcuVviGktYMhEk4IJ1F3zV1U8k68vTThOEkrAkCJ/Y3OvKz3YA==`, and the generated archive was removed after inspection.
- Added bounded all-path Go `switch` replay to ordinary constructors and constructor helpers. An exact expression switch may contain two through four arms, must end in one explicit `default`, and may contain only equal nonzero sets of exact field writes through aliases proven before the switch. Every case executes in an identity-preserving clone of the complete tracked graph and reuses the bidirectional topology join, per-path write budget, selector bound, statement bound, and arm-line bound. All convergent case origins remain evidence. Expressionless or initialized switches, missing or non-final `default`, `fallthrough`, `break`, empty or divergent arms, nested control, branch-local state, a fifth arm, unequal budgets, and unresolved identities fail closed.
- Added the seventy-sixth exploit/control pair and expanded the perfect-gate Go authorization manifest from forty-eight to fifty cases. Both Go 1.26 modules import a helper that creates a value layer with one pointer holder, makes three shallow copies, and writes the selected primary repository through a different copy in each arm of an exact `switch` with two named cases and a final `default`. The positive proves unscoped victim deletion through the converged shared holder; the control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules. The documented corpus now contains sixty-three exploit/control pairs and 378 scans at three runs per case.
- The focused Go authorization lane passes 116 tests and 667 assertions; all eleven typed Go model suites pass 279 tests and 1,537 assertions; and all fifty authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,072 tests and 8,184 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 28 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, service aliases `internal/service/service.go:15,18`, imported helper call at line 16, helper allocation and value-copy aliases `internal/parent/layer.go:22-25`, shared holder creation at line 22, all three switch-arm writes at lines 28, 30, and 32, helper return at line 34, service return at line 20, receiver and object flow at lines 23-25, the static service, layer, and holder fields, and only the primary SQL mutation. The control preserves that 28-step path plus only `principal-bound-object-query` at `internal/primary/store.go:11`; neither path contains archive-store evidence. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,399,311 bytes packed and 6,457,533 bytes unpacked, has SHA-1 `4b248b1116b030d9ae41eeb46874a87453867a8a`, integrity `sha512-e5Uoe7ipuwPMq8d+1YGoM4x9qWD5qvJyNsNcAIPZZGTtaFUmk0ygPdWjwPh0VwX7q4PstdM5R1lvbKwhnbNTXw==`, and the generated archive was removed after inspection.
- Generalized bounded Go constructor and constructor-helper branch replay from one two-arm `if`/`else` to exact two-through-four-arm `if / else if / ... / else` chains. Every arm executes in an identity-preserving clone of the complete tracked alias graph. Sequential joins require equal nonzero write counts, equal per-path budgets, structurally identical values, and one-to-one nested-node topology across every arm; distinct field-write origins from every convergent path remain evidence. A mandatory final `else`, four-arm cap, eight writes per path, eight selector fields, thirteen lines per statement, and sixteen lines per arm keep the proof finite. Missing final arms, fifth arms, divergent values, unequal writes, asymmetric topology, nested control, early returns, branch-local state, and unresolved identities fail closed.
- Added the seventy-fifth exploit/control pair and expanded the perfect-gate Go authorization manifest from forty-six to forty-eight cases. Both Go 1.26 modules import a helper that creates a value layer with one pointer holder, makes three shallow value copies, and writes the selected primary repository through a different copy on each arm of an `if / else if / else` chain. The positive proves unscoped victim deletion through the converged shared holder; the control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules. The documented corpus now contains sixty-two exploit/control pairs and 372 scans at three runs per case.
- The focused Go authorization lane passes 115 tests and 643 assertions; all eleven typed Go model suites pass 278 tests and 1,513 assertions; and all forty-eight authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,071 tests and 8,160 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 28 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, service aliases `internal/service/service.go:15,18`, imported helper call at line 16, helper allocation and value-copy aliases `internal/parent/layer.go:22-25`, shared holder creation at line 22, all three branch writes at lines 27, 29, and 31, helper return at line 33, service return at line 20, receiver and object flow at lines 23-25, the static service, layer, and holder fields, and only the primary SQL mutation. The control preserves that 28-step path plus only `principal-bound-object-query` at `internal/primary/store.go:11`; neither path contains archive-store evidence. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,398,538 bytes packed and 6,448,209 bytes unpacked, has SHA-1 `b74f1d3a271de89ae32109d6282292b97e541e9f`, integrity `sha512-tLZsGwTnYjoGKvFnTu5H3tKZDMCEArzrBpEDexFHtZUhuXX+7I6tzBGJCV238MvzyUXjP3y8aoeFCzpFVzb26w==`, and the generated archive was removed after inspection.
- Extended bounded Go constructor-helper replay through one explicit top-level `if`/`else`. Each arm executes exact field writes against a complete identity-preserving clone of every materialized alias and nested value node; the host continues only when all tracked aliases converge to structurally identical state under a bidirectional node mapping. Shared pointer nodes remain shared within each path and after the join, asymmetric sharing topologies are rejected, concrete value copies remain isolated, and exact evidence from both branch aliases and write origins is merged independently of semantic state. Each arm accepts only writes through aliases proven before the branch, with at most eight writes per executable path and sixteen structural lines. One-sided or divergent state, pointer-slot replacement on different copies, branch-local assignments, nested control flow, `else if`, early returns, unequal write counts, and over-budget paths fail closed.
- Added the seventy-fourth exploit/control pair and expanded the perfect-gate Go authorization manifest from forty-four to forty-six cases. Both Go 1.26 modules import a helper that creates a value layer with a pointer holder, copies the layer twice, writes the selected primary repository through a different copy on each explicit branch, and returns the original value while an archive implementation remains unused. The positive proves unscoped victim deletion through the all-path shared holder. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules, and the documented corpus now contains sixty-one exploit/control pairs.
- The expanded focused Go authorization lane passes 113 tests and 620 assertions; all eleven typed Go model suites pass 276 tests and 1,490 assertions; and all forty-six authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,069 tests and 8,137 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 26 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, service aliases `internal/service/service.go:15,18`, imported helper call at line 16, helper allocation and value-copy aliases `internal/parent/layer.go:22-24`, shared holder creation at line 22, both all-path repository writes at lines 26 and 28, helper return at line 30, service return at line 20, receiver and object flow at lines 23-25, the static service, layer, and holder fields, and only the primary SQL mutation. The control preserves that 26-step path plus only `principal-bound-object-query` at `internal/primary/store.go:11`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,411,812 bytes packed and 6,443,230 bytes unpacked, has SHA-1 `2c149db8951ea46637a8e89e16dfb8db5292abb3`, integrity `sha512-2xZzTFSUNovlrcB89B8MoY5IIs/sTr4SoYepE7axZyoiuNFWKtUXD+EOCZHr9jm9q1TyrZIRICeucsxn1FQPjQ==`, and the generated archive was removed after inspection.
- Replaced flat constructor-helper mutation plans with bounded call-site state replay. Helper allocation, exact helper calls, value or pointer alias assignments, field writes, and the selected return alias now execute against the fully materialized recursive state graph. Copying a value recursively copies concrete value fields while sharing pointer-field state at any materialized depth; overwriting a pointer field detaches only that value copy. Helper-boundary evidence propagates through shared nested nodes so the call, every relevant alias, write, and return remain visible at the final receiver. Missing parents, concrete-value isolation, wrong static identity, invalid overwrite state, and unresolved copies fail closed.
- Added the seventy-third exploit/control pair and expanded the perfect-gate Go authorization manifest from forty-two to forty-four cases. Both Go 1.26 modules import a factory that creates a value layer containing a pointer holder, copies the layer twice, injects the selected primary repository through the copied value's shared holder, and returns the original value while an archive implementation remains unused. The positive proves unscoped victim deletion through the shared pointer. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules, and the documented corpus now contains sixty exploit/control pairs.
- The expanded focused Go authorization lane passes 110 tests and 594 assertions; all eleven typed Go model suites pass 273 tests and 1,464 assertions; and all forty-four authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,066 tests and 8,111 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one Go authorization model at `internal/primary/store.go:11` for each new fixture. The positive has 25 propagators and no candidate control, preserving source `handler.go:11`, selected repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, service aliases `internal/service/service.go:15,18`, imported helper call at line 16, helper allocation and shallow-copy aliases `internal/parent/layer.go:22-24`, shared holder creation at line 22, repository write through the final copy at line 25, helper return at line 26, service return at line 20, receiver and object flow at lines 23-25, the static service, layer, and holder fields, and only the primary SQL mutation. The control preserves that 25-step path plus only `principal-bound-object-query` at `internal/primary/store.go:11`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,407,349 bytes packed and 6,419,469 bytes unpacked, has SHA-1 `b5b9fdeacbc084fc8d6e629a496ea156b740a085`, integrity `sha512-P/ojqB6bjxkrnXATYXwRQf2VYPpJeoQ7E0sMthJfhaFizMBYUn5yTxM1jtFYGA73DNR/Wu3WY8vNnN81PXnqxw==`, and the generated archive was removed after inspection.
- Extended exact Go constructor-parent helpers through bounded allocate-then-initialize bodies. A helper may write declared fields through a live result alias before returning it; pointer aliases share the mutation plan, direct fields on value aliases use independent plan snapshots, explicit dereference requires a pointer, and nested writes require every materialized parent and exact static field type. Helper writer aliases and field writes retain their own paths and lines. Imported and local helpers share the eight-write and eight-selector-field limits. Conditional or nested writes, missing fields or parents, transformed parameters, invalid dereferences, divergent concrete-value copies, a ninth receiver-bearing write, and unresolved identities fail closed.
- Added the seventy-second exploit/control pair and expanded the perfect-gate Go authorization manifest from forty to forty-two cases. Both Go 1.26 modules import a parent factory from a fourth local-module package; the factory allocates an empty layer, creates a pointer alias, injects the selected primary repository through a later exported interface field write, initializes scalar state, and returns the original pointer while an archive implementation remains unused. The positive proves unscoped victim deletion through only the selected primary repository. The control changes only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules, and the documented corpus now contains fifty-nine exploit/control pairs.
- The expanded focused Go authorization lane passes 108 tests and 576 assertions; all eleven typed Go model suites pass 271 tests and 1,446 assertions; and all forty-two authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,064 tests and 8,093 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly the selected primary mutation at `internal/primary/store.go:11` with 23 propagators, preserving source `handler.go:11`, repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, constructor aliases `internal/service/service.go:15,18`, qualified helper call and outer field at line 16, helper aliases `internal/parent/layer.go:18-19`, helper repository write at line 20, helper return at line 22, constructor return at service line 20, receiver at line 23, static service and parent fields at lines 10 and 13, and no archive-repository evidence; the control retains that path plus only `principal-bound-object-query` at `internal/primary/store.go:11`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,403,840 bytes packed and 6,404,028 bytes unpacked, has SHA-1 `8903f10ebc13d989a5a98899bf2975efd973abf2`, integrity `sha512-Jeh0niH7nj03ZmdcM5JZUR0eF4iYcF3PeOj4Ja7EX3Lqn8SXhNqDKwvXfP1ToCoivH4ZUElxYlQGpLgh+ZIXHw==`, and the generated archive was removed after inspection.
- Extended exact Go constructor-parent helper materialization across packages in the same authoritative local module. Qualified calls require the exact ordinary import alias, exported helper, unique local definition, and unshadowed package binding. Every materialized keyed composite is canonicalized to its defining directory, package, import path, type, and pointer mode before constructor substitution; nested constructor writes and receiver selectors additionally enforce exported-type and exported-field visibility across package boundaries. Imported and same-package calls share the eight-call depth limit. Multiline constructor composites preserve newlines so helper-call and field evidence use the expression's actual line. Wrong or external module paths, dot or unavailable imports, function values, shadowed aliases, unexported helpers, types, or fields, duplicate definitions, reassigned or transformed parameters, pointer/value mismatches, cycles, and ninth calls fail closed.
- Added the seventy-first exploit/control pair and expanded the perfect-gate Go authorization manifest from thirty-eight to forty cases. Both Go 1.26 modules import an exported parent allocator from a fourth local-module package, alias its result internally, inject the selected primary repository through the returned layer's exported interface field, retain an unused archive implementation, and preserve request, service, interface, SQL, response, and deterministic driver behavior. The positive proves unscoped victim deletion through only the selected primary repository. The control adds only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules, and the documented corpus now contains fifty-eight exploit/control pairs.
- The expanded focused Go authorization lane passes 106 tests and 554 assertions; all eleven typed Go model suites pass 269 tests and 1,424 assertions; and all forty authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,062 tests and 8,071 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly the selected primary mutation at `internal/primary/store.go:11`, preserving source `handler.go:11`, repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, constructor alias `internal/service/service.go:15`, qualified helper call and outer field at line 16, helper aliases `internal/parent/layer.go:18-19`, helper return at line 20, nested repository write `internal/service/service.go:19`, constructor return at line 21, receiver at line 24, static service and parent fields at lines 10 and 13, and no archive-repository evidence; the control retains that path plus only `principal-bound-object-query` at `internal/primary/store.go:11`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,402,192 bytes packed and 6,389,423 bytes unpacked, has SHA-1 `fd1414cea75e0400d9d2eab0e33385a804b666ba`, integrity `sha512-mJrfyDxH21TixzA4zGRcWoD6x/uzv+6iTfLLH87+4YTybCywIQc2zBKW0NsHJ5m2Jrple0XSaDr0P08HWr8cCQ==`, and the generated archive was removed after inspection.
- Added exact local helper materialization to Go constructor receiver state. A unique receiverless same-package helper may return the constructor parent as a matching keyed composite directly, through up to eight exact aliases, or through up to eight exact helper calls. Bare arguments retain their real constructor use line for reassignment validation, and call, helper alias, helper return, composite creation, constructor binding, nested write, and receiver evidence retain independent paths and lines. One-line returns are supported. Duplicate or shadowed helpers, recursive or ninth calls, pointer/value result mismatch, parameter reassignment, transformed parameters, positional composites, nested or multiple returns, wrong types, ambiguous definitions, and unresolved dynamic state fail closed.
- Added the seventieth exploit/control pair and expanded the perfect-gate Go authorization manifest from thirty-six to thirty-eight cases. Both Go 1.26 modules obtain a pointer repository layer from a helper in a separate service-package file, alias the helper result, inject the selected primary repository through a nested constructor write, retain an unused archive implementation, and preserve request, service, interface, SQL, response, and deterministic driver behavior. The positive proves unscoped victim deletion through only the selected primary repository. The control adds only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules, and the documented corpus now contains fifty-seven exploit/control pairs.
- The expanded focused Go authorization lane passes 102 tests and 528 assertions; all eleven typed Go model suites pass 265 tests and 1,398 assertions; and all thirty-eight authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,058 tests and 8,045 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly the selected primary mutation at `internal/primary/store.go:11`, preserving source `handler.go:11`, repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, constructor result alias and helper binding `internal/service/service.go:18`, helper creation and aliases `internal/service/layer.go:9-10`, helper return at line 11, nested repository write `internal/service/service.go:22`, constructor return at line 24, receiver at line 27, and no archive-repository evidence; the control retains that path plus only `principal-bound-object-query`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,401,026 bytes packed and 6,379,417 bytes unpacked, has SHA-1 `f09be04e8a19737b0af30c5120898dbb3a3dc0f4`, integrity `sha512-YngzH+uYPd/vg74PCVSWpltmr/HPtaVGFnbPIDxVRX3945q+5BmVkT5RMuu6N9xWjtsSs2kjS2i6GiPlgTbmvQ==`, and the generated archive was removed after inspection.
- Added exact all-path joins for Go constructor field state. One top-level `if`/`else` may now clone the complete pre-existing alias graph, apply bounded field writes independently to both arms, and continue only when every tracked post-branch object is structurally identical. Clone and join memoization preserves shared nested pointer identity across distinct value copies. The existing eight-write limit applies per executable path; each arm is capped at sixteen structural lines. Joined writes retain both source origins as `go-method-receiver-constructor-field-write` evidence. One-sided or divergent writes, separate object identities, branch-local assignments, nested control flow, `else if`, early returns, unequal write budgets, a seventeenth arm line, unresolved state, and ambiguity fail closed.
- Added the sixty-ninth exploit/control pair and expanded the perfect-gate Go authorization manifest from thirty-four to thirty-six cases. Both Go 1.26 modules construct a pointer layer, retain primary and archive implementations, create two aliases of the returned service pointer, inject the selected primary through the same nested field on both explicit constructor branches, initialize scalar state after the join, and preserve interface dispatch, SQL, request, response, and deterministic driver behavior. The positive proves unscoped victim deletion through only the selected primary repository. The control adds only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules, and the documented corpus now contains fifty-six exploit/control pairs.
- The expanded focused Go authorization lane passes 99 tests and 502 assertions; all eleven typed Go model suites pass 262 tests and 1,372 assertions; and all thirty-six authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,055 tests and 8,019 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly the selected primary mutation at `internal/primary/store.go:11`, preserving source `handler.go:11`, repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, parent allocation and outer-field proof `internal/service/service.go:23`, both joined repository writes at lines 29 and 31, constructor return at line 34, service receiver at line 37, static fields at lines 18 and 13, and no archive-repository evidence; the control retains that path plus only `principal-bound-object-query`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,382,924 bytes packed and 6,327,111 bytes unpacked, has SHA-1 `cb5ddb4930f3df36a701c820bea6ba13d3a37e06`, integrity `sha512-phRKJlP1P8lJHIwRfjtuTqM3lvsyd61Dh39mLXnMjKqgB/iO+HvPEr1mLVw4YuICH6LwyTHgmrwMGMpMiTVngg==`, and the generated archive was removed after inspection.
- Extended exact Go constructor state through nested field writes. Constructor composites now retain a recursive value tree with a separate creation or write origin per field. A write may traverse up to eight exact materialized keyed-composite parents and replaces only its leaf. Pointer fields share nested state across shallow value copies, while concrete value fields recursively copy their state. Leaf parameter reassignment is checked at the leaf's own write line. Missing or unresolved parents, wrong fields or types, conditional writes, invalid dereferences, a ninth selector field, ambiguity, and unsupported dynamic parent state fail closed. An exact overwrite now selects the replacement implementation rather than suppressing or retaining the stale target.
- Added the sixty-eighth exploit/control pair and expanded the perfect-gate Go authorization manifest from thirty-two to thirty-four cases. Both Go 1.26 modules construct a pointer layer before repository injection, retain primary and archive implementations, inject the selected primary through a later nested write on a pointer alias, initialize scalar state, and preserve interface dispatch, SQL, request, response, and deterministic driver behavior. The positive proves unscoped victim deletion through only the selected primary repository. The control adds only the context-derived account predicate and proves victim survival plus successful owned deletion. Hosted Go CI executes both modules.
- The expanded focused Go authorization lane passes 94 tests and 474 assertions; all eleven typed Go model suites pass 257 tests and 1,344 assertions; and all thirty-four authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,050 tests and 7,991 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly the selected primary mutation at `internal/primary/store.go:11`, preserving source `handler.go:11`, repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, parent allocation and outer-field proof `internal/service/service.go:23`, nested repository write at line 27, constructor return at line 29, service receiver at line 32, static fields at lines 18 and 13, and no archive-repository evidence; the control retains that path plus only `principal-bound-object-query`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,376,719 bytes packed and 6,295,811 bytes unpacked, has SHA-1 `66c6baaa1c858e0a2d1ab74203c5f3d6e3e7dfa3`, integrity `sha512-3dC1cEqRz0rrNqSxAAO7BsUqPQvI+lrYDlOPAwVjjSSxzJCy8Ev14/xGwVauv/II7zuN8tDlo4LjRZxnTrhC7Q==`, and the generated archive was removed after inspection.
- Extended exact Go constructor state through post-construction field writes. Direct top-level selectors and explicit pointer dereferences update only a proven result alias; pointer aliases share one state while value aliases receive a copy. The latest linear overwrite replaces prior provenance, every accepted receiver-bearing write emits `go-method-receiver-constructor-field-write`, and the returned instance is snapshotted. Eight writes and thirteen structural lines per statement are accepted. A ninth write, fourteenth line, conditional or nested-selector write, invalid value dereference, unresolved or wrong typed value, overwritten receiver, parameter reassignment, ambiguity, or missing receiver state fails closed.
- Added the sixty-seventh exploit/control pair and expanded the perfect-gate Go authorization manifest from thirty to thirty-two cases. Both Go 1.26 modules retain primary and archive implementations, constructor injection, a pointer alias, an initially empty service, multiline nested layer assignment, scalar field write, interface dispatch, SQL, request, response, and deterministic driver. The positive proves only the primary repository performs an unscoped deletion. The control adds only the context-derived account predicate and proves both victim survival and successful owned deletion. Hosted Go CI executes both modules.
- The expanded focused Go authorization lane passes 90 tests and 453 assertions; all eleven typed Go model suites pass 253 tests and 1,323 assertions; and all thirty-two authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,046 tests and 7,970 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly the selected primary mutation at `internal/primary/store.go:11`, preserving source `handler.go:11`, repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, allocation alias `internal/service/service.go:23`, exact outer field write and nested composite assignment at line 25, constructor return at line 30, service receiver at line 33, static fields at lines 18 and 13, and no archive-repository evidence; the control retains that dispatch plus only `principal-bound-object-query`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; it is 1,389,134 bytes packed and 6,281,731 bytes unpacked, has SHA-1 `917a4c1f56ebee8bc337f4008c7b3c6da412e5c7`, integrity `sha512-ZlSigokAeRcfaXv3RKfS0rE9B98q0kcmICXGCvIBt7m+uNQEXmf8k7qNlvTUHv2ZVHJD4fTDTyRfrjcxzNLFfw==`, and the generated archive was removed after inspection.
- Extended constructor-selected Go receiver provenance through nested keyed composites. The host now recursively materializes exact repository-local struct and basic-interface fields, preserves each nested assignment as `go-method-receiver-composite-field` evidence, and carries the resulting field map through the existing receiver requirements. Normal multiline composites with trailing commas are accepted through an explicit thirteen-structural-line bound; a fourteenth line fails closed. Unrelated scalar fields no longer invalidate an exact receiver path, while positional composites, missing receiver fields, wrong nested concrete or pointer identity, unsatisfied interface method sets, unbound nested parameters, parameter reassignment before construction, a ninth field, and unresolved ambiguity remain rejected.
- Added the sixty-sixth exploit/control pair and expanded the perfect-gate Go authorization manifest from twenty-eight to thirty cases. Both Go 1.26 modules include primary and archive implementations, inject the primary through an interface parameter, nest it beneath a constructor-created pointer layer, initialize unrelated labels, and dispatch the route-selected object through the nested interface. The positive witness proves only the primary repository deletes without principal scope. The control preserves both implementations, pointer layer, scalar fields, multiline composite, constructor, SQL, request, response, and deterministic driver while adding only the context-derived account predicate. Hosted Go CI executes both modules.
- The expanded focused Go authorization lane passes 85 tests and 428 assertions; all eleven typed Go model suites pass 248 tests and 1,298 assertions; and all thirty authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,041 tests and 7,945 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly the selected primary mutation at `internal/primary/store.go:11`, preserving source `handler.go:11`, concrete repository binding `handler.go:12`, constructor call and service binding `handler.go:13`, constructor alias, outer field, and nested composite field at `internal/service/service.go:23`, constructor return at line 27, service receiver at line 30, static fields at lines 18 and 13, and no archive-repository evidence; the control retains the exact nested dispatch plus only `principal-bound-object-query`. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; the npm publish preview is 1,371,475 bytes packed and 6,273,918 bytes unpacked, has SHA-1 `1db314a64788486132d32bd8a12de4e9d8a6b959`, integrity `sha512-ZEflMxIMrA/DWNBiBlkGqO5gAya6KXs+ATwpFhLzKSBrCFrtY+wUbCFo1RxElF3xbSM0mPwOnBsG59rVMunNxA==`, and the generated archive was removed after inspection.
- Extended the bounded Go object-authorization method graph through constructor-initialized pointer and interface receiver fields. Keyed constructor composites now map a field to an exact parameter or direct concrete expression, carry the selected instance through call-site aliases and assignments, and retain constructor-field provenance separately from the static field declaration. Interface summaries may enumerate multiple valid receiver implementations, but a finding survives only when the actual constructor argument selects one exact module/package/type identity and satisfies its Go pointer/value method set. Missing initialization, unbound interface values, constructor-parameter reassignment, wrong concrete field types, incompatible interface parameters, value instances lacking a required pointer method, and unresolved ambiguity fail closed.
- Added the sixty-fifth exploit/control pair and expanded the perfect-gate Go authorization manifest from twenty-six to twenty-eight cases. Both Go 1.26 modules include two repository implementations, inject the primary implementation through an exact imported constructor into an interface field, and dispatch the route-selected object ID through the selected method. The positive proves the primary repository deletes without principal scope and the unused archive repository is not selected. The control preserves both implementations, constructor, interface, aliases, SQL, request, response, and deterministic witness while adding only the context-derived account predicate. Hosted Go CI executes both modules.
- The expanded focused Go authorization lane passes 81 tests and 410 assertions; all eleven typed Go model suites pass 244 tests and 1,280 assertions; and all twenty-eight authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,037 tests and 7,927 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly the constructor-selected primary mutation at `internal/primary/store.go:11`, preserving source `handler.go:11`, concrete repository alias `handler.go:12`, constructor call and service binding `handler.go:13`, constructor alias and keyed-field assignment `internal/service/service.go:17`, constructor return at line 18, service receiver at line 21, static interface field at line 13, and no archive-repository evidence; the control retains that exact dispatch plus only `principal-bound-object-query` at its sink. Deterministic review of the production SDK emits 96 records and no Go object-authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; the npm publish preview is 1,368,806 bytes packed and 6,247,263 bytes unpacked, has SHA-1 `009dd249f00fea0f54f77f53ba50cd445372bf3e`, integrity `sha512-wzX7FdocZ9cAyT+R+87HE1pqBqxXjzhY80WMKJgkD8Toiq/YFo4bDGOIXJ+1ewc39JGMU2BaNtQjV0JJk99lXA==`, and the generated archive was removed after inspection.
- Extended the bounded Go object-authorization method graph through exact constructor-returned receivers and named concrete value fields. A constructor must be one unique same-package or authoritative local-module non-method function, declare one exact local struct result, receive a valid ordinary or variadic argument count, and return a matching composite directly or through at most eight top-level exact aliases. Method selectors may traverse at most eight named non-pointer concrete value fields; every field resolves in its declaring file's package/import context, while non-semantic struct tags are masked. Evidence distinguishes the constructor call, internal aliases, exact return, receiver binding, and each field declaration. Returned constructor parameters, nested or multiple returns, callable shadowing or function values, a ninth constructor alias, and pointer, interface, embedded, anonymous, generic, duplicate, missing, ambiguous, or ninth fields fail closed.
- Added the sixty-fourth exploit/control pair and expanded the perfect-gate Go authorization manifest from twenty-four to twenty-six cases. Both Go 1.26 modules obtain an imported service through an exact constructor, retain the constructor's local result alias, traverse an imported concrete repository value field, and call its method with the exact object ID. The positive proves the victim invoice is deleted without principal scope. The control preserves the route, constructor, receiver and field types, aliases, SQL, attack ID, response, and deterministic driver while adding only the context-derived account predicate; it proves the victim survives and an owned invoice still deletes. Focused regressions cover same-package and renamed imported constructors, typed constructor results, direct and aliased returns, exact eight-versus-nine constructor and field bounds, principal propagation, constructor name shadowing and ambiguity, returned parameters, branch/multiple returns, allocation returns, pointer and interface fields, embedded fields, and hosted Go execution.
- The expanded focused Go authorization lane passes 78 tests and 388 assertions; all eleven typed Go model suites pass 241 tests and 1,258 assertions. All twenty-six authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,034 tests and 7,905 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one mutation at `internal/invoicestore/store.go:11`, preserving source `handler.go:10`, constructor call `handler.go:11`, constructor alias and return `internal/invoicesvc/service.go:14-15`, receiver binding `handler.go:11`, service method call `handler.go:12`, service parameter `internal/invoicesvc/service.go:18`, concrete repository field `internal/invoicesvc/service.go:10`, object alias and repository call `internal/invoicesvc/service.go:19-20`, repository parameter `internal/invoicestore/store.go:10`, and exact predicate and execution at line 11; the matched control retains that path plus only `principal-bound-object-query` at the sink, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; the npm publish preview is 1,363,217 bytes packed and 6,202,661 bytes unpacked, has SHA-1 `e38c8760d1043c97a98b13cac29fe7a8a084e320`, integrity `sha512-r9z9X+tEp2HqQ3wDT236PZgbwl3HVlMt/3Om/riB7t+k1ZMVbk/XrT1fLeA1IDESrLXqCSXS6a+a5a4Zh22dEw==`, and the generated archive was removed after inspection.
- Extended the bounded Go object-authorization graph through exact concrete receiver methods and explicitly bound local interfaces. Method summaries retain unique receiver type and pointer identity, same-package or authoritative local-module identity, typed receiver parameters, zero-value concrete variables, direct composite and `new` construction, exact interface conversions, and up to eight receiver aliases. Interface calls require a local basic interface that directly declares the method and a live value resolved from one concrete implementation. Evidence distinguishes receiver parameters, concrete bindings, aliases, and interface-to-concrete dispatch. Unbound interface parameters, nil pointer variables, inexact constructor results, embedded promotion, method values, dynamic callbacks, nested or unknown reassignment, duplicate receiver methods, pointer methods on interface-held concrete values, and a ninth alias fail closed.
- Added the sixty-third exploit/control pair and expanded the perfect-gate Go authorization manifest from twenty-two to twenty-four cases. Both Go 1.26 modules call an imported concrete service method, bind an imported repository implementation to a local interface, and call its method with the exact object ID. The positive proves the victim invoice is deleted without principal scope. The control preserves the route, service and repository receiver types, interface, aliases, SQL, attack ID, response, and deterministic driver while adding only the context-derived account predicate; it proves the victim survives and an owned invoice still deletes. Focused regressions cover concrete parameters, value and pointer receivers, interface method membership and pointer method sets, local and imported construction, principal propagation, the exact eight-versus-nine receiver-alias bound, unbound interfaces, promotion, constructors, method values, nested reassignment, duplicate methods, exact fixture evidence, and hosted Go execution.
- The expanded focused Go authorization lane passes 72 tests and 355 assertions; all eleven typed Go model suites pass 235 tests and 1,225 assertions. All twenty-four authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,028 tests and 7,872 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one mutation at `internal/invoicestore/store.go:11`, preserving the source at `handler.go:10`, concrete service binding at line 11, service method call at line 12, service parameter and object alias at `internal/invoicesvc/service.go:15-16`, interface-to-store binding at line 17, repository method call at line 18, repository parameter at `internal/invoicestore/store.go:10`, and exact predicate and execution at line 11; the matched control retains that path plus only `principal-bound-object-query` at the sink, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; the npm publish preview is 1,356,016 bytes packed and 6,153,897 bytes unpacked, has SHA-1 `5da923173549720446af39daa3c9d02579e8f701`, integrity `sha512-Plw4wTqFbSTbdAoF6aT/NQueJRV25ARR8JW85c9uTPJrvARFI87F6XQO1kTucvQVPZ3/OTmVPbltacbj3tfHjw==`, and the generated archive was removed after inspection.
- Composed exact Go object-authorization wrapper summaries across up to 32 same-package or cross-package local-module boundaries. Each edge requires one unique non-method function, a top-level non-deferred and non-goroutine call, and exact string-parameter or live-alias flow; imported edges additionally require the deepest enclosing `go.mod`, exact module path and ordinary alias, exported target, and unshadowed binding. Evidence now retains every call, parameter, and object alias, while authenticated-principal positions are remapped through the full chain. Duplicate paths to one sink, duplicate module identities, ambiguous targets, cycles, package or function shadowing, nested calls, multi-name assignments, immutable-map selection, replacement with a fixed object, a thirty-third boundary, and more than 4,096 candidate paths fail closed. Final request-call resolution now also rejects duplicate local module identities, and outer-wrapper parameter evidence records the real declaration rather than the leaf parameter.
- Added the sixty-second exploit/control pair and expanded the perfect-gate Go authorization manifest from twenty to twenty-two cases. Both Go 1.26 modules carry a path-selected invoice through an exact handler-to-service-to-repository chain spanning two renamed local-package imports. The positive proves the victim invoice is deleted by an unscoped fixed query. The control preserves every source, wrapper, alias, repository, SQL, attack ID, response, and deterministic driver behavior while adding only the context-derived account predicate; it proves the victim survives and an owned invoice still deletes. Focused regressions cover same-package and cross-package chains, object and principal aliases, attacker-provided principals, missing and wrong modules or imports, package-alias shadowing, duplicate modules, the exact 32-versus-33 boundary, cycles, duplicate routes, nested calls, function-parameter shadowing, immutable maps, reassignment, exact fixture evidence, and hosted Go execution.
- The expanded focused Go authorization lane passes 66 tests and 321 assertions; all eleven typed Go model suites pass 229 tests and 1,191 assertions. All twenty-two authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,022 tests and 7,838 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one mutation at `internal/invoicestore/store.go:9`, preserving the source and object alias at `handler.go:10`, outer wrapper call at `handler.go:11`, service parameter and alias at `internal/invoicesvc/service.go:9-10`, repository call at line 11, repository parameter at `internal/invoicestore/store.go:8`, and exact predicate and execution at line 9; the matched control retains that path plus only `principal-bound-object-query` at the sink, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The 251-entry archive passed strict validation; the npm publish preview is 1,346,576 bytes packed and 6,102,641 bytes unpacked, has SHA-1 `2e2ab32390a3faccac213eebb710f146d39d6993`, integrity `sha512-b90pMoHsWh/56GSZz22NHHimO+swt3uWOyDuMfZUuiM+/jmBdgRpRBEVcVe37+l0O3QLbjDxjW8Cb6Q8q87HKA==`, and the generated archive was removed after inspection.
- Resolved exact Go transaction factory and finalizer calls through local function values. The model follows at most eight top-level single-name, single-assignment bindings to exact identifiers or qualified functions, validates imported targets at capture time, composes aliases inside factory and finalizer helper packages, and records every binding before the existing helper and leaf evidence. Parameters, receivers, local declarations without a proven binding, helper or package shadowing, reassignment, nested or multi-name assignment, unknown targets, cycles, and a ninth binding fail closed. Plain helper calls now also reject local ownership of the same name, removing a shadowing false positive.
- Added the sixty-first exploit/control pair and expanded the perfect-gate Go authorization manifest from eighteen to twenty cases. Both Go 1.26 modules capture imported application factory and finalizer functions and capture the leaf begin and commit functions inside their helper packages. The positive proves that a path-selected victim deletion becomes durable through all four function-value boundaries. The matched control preserves that complete path and adds only a context-principal account predicate, proving that the victim survives and an owned deletion still commits. Focused regressions cover factory and finalizer aliases, exact eight- versus nine-binding depth, internal-package composition, parameter and local shadowing, reassignment, and nested assignment; hosted Go CI executes both modules.
- The expanded focused Go authorization lane passes 60 tests and 293 assertions; all eleven typed Go model suites pass 223 tests and 1,163 assertions. All twenty authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,016 tests and 7,810 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one committed mutation at `store.go:22`, preserving source `handler.go:9`, application factory capture `store.go:11`, factory call `store.go:12`, internal leaf capture `internal/txfactory/coordinator.go:10`, actual `BeginTx` at `internal/txleaf/transaction.go:9`, application finalizer capture and call at `store.go:21-22`, internal commit capture `internal/txguard/coordinator.go:9`, and actual commit `internal/txleaf/transaction.go:13`; the control retains the identical path plus only `principal-bound-object-query` at `store.go:18`, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,337,439 bytes packed and 6,060,933 bytes unpacked, has SHA-1 `13f22422d9463044d8fda5a8b8606d7d1395dc2c`, integrity `sha512-baV/vj6kQVZsbT14WpZ3RlStT+oK1gjsdgLH29mM8f/JuVizaKuWxn03/3vJbbfTYcqO3KnTySK5dyVRKk4yLQ==`, and was removed after inspection.
- Resolved exact Go transaction creation through bounded same-package, cross-package, and nested-module factory-helper chains. A factory must accept an exact `*database/sql.DB` or `*database/sql.Conn`, return `*database/sql.Tx` first with only an optional `error`, and directly return or assign once and return the exact `Begin`/`BeginTx` result. `Begin` is now restricted to DB while `BeginTx` accepts DB or Conn, removing the prior typed-`Tx.Begin` lookalike false positive. Each unique edge preserves the exact receiver argument or alias, authoritative module/import/export identity, and real leaf begin path. Wrong return shapes, transformed or replaced results, methods, interfaces, function values, nested creation, package shadowing, ambiguity, cycles, and chains beyond 32 boundaries fail closed.
- Added the sixtieth exploit/control pair and expanded the perfect-gate Go authorization manifest from sixteen to eighteen cases. Both Go 1.26 modules obtain a transaction through aliased `internal/txfactory` and `internal/txleaf` packages before executing and committing an invoice deletion. The positive proves a path-selected victim deletion becomes durable. The control preserves the route, wrapper, transaction factory chain, leaf `BeginTx`, SQL, attack ID, commit, response, and driver while adding only a context-principal account predicate; it proves the victim survives and an owned deletion commits. Focused regressions cover direct and assigned returns, DB and Conn leaves, renamed cross-package chains, deepest nested modules, exact 32-bound behavior, cycles, over-depth graphs, missing and wrong modules/imports, dot imports, alias shadowing, duplicate module identities, wrong return types, reassignment, nesting, and direct typed-receiver lookalikes; hosted Go CI executes both new modules.
- The expanded focused Go authorization lane passes 55 tests and 275 assertions; all eleven typed Go model suites pass 218 tests and 1,145 assertions. All eighteen authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,011 tests and 7,792 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one committed mutation at `store.go:19`, preserving source `handler.go:9`, wrapper call and string parameter, factory boundary `store.go:10`, internal factory delegation `internal/txfactory/coordinator.go:11`, actual `BeginTx` at `internal/txleaf/transaction.go:9`, object predicate and provisional execution at `store.go:16`, and commit at `store.go:19`; the matched control retains the identical factory, mutation, and commit path plus only `principal-bound-object-query` at `store.go:16`, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,350,451 bytes packed and 6,051,103 bytes unpacked, has SHA-1 `5c0cd11c48eb64b5150c2c6a43883a788338981f`, integrity `sha512-RpWIOtKe50LHlAFJ11QKUC3hcsgmaRnTfm7yFSYYXNg3d9ZArEjeeJi2HLTKYJHePyMjucd/EFbhO9EO+rNG6Q==`, and was removed after inspection.
- Resolved exact Go transaction finalizer helpers and chains across local package and nested-module boundaries. The trusted residual-risk inventory now admits exact `go.mod` files; the model selects the deepest enclosing module, derives each local package import path, and crosses a qualified call only through one ordinary unique import or renamed alias to an exported unique function with an unshadowed package binding and the exact live transaction argument. Cross-package commit and rollback outcomes retain all internal paths. Missing modules, external or wrong imports, dot and blank imports, unexported targets, package alias shadowing, duplicate local module identities, ambiguous functions, wrong transactions, cycles, and the existing nesting, defer, reassignment, outcome, and 32-bound violations fail closed.
- Added the fifty-ninth exploit/control pair and expanded the perfect-gate Go authorization manifest from fourteen to sixteen cases. Both fixtures stage an invoice deletion in the application package, import a typed coordinator from `internal/txguard`, alias and forward the transaction into `internal/txleaf`, and make state durable only at the real commit. The positive proves victim deletion. The control preserves the route, wrapper, SQL, transaction, import paths, renamed aliases, both internal packages, attack ID, commit, and response while adding only a context-principal account predicate; it proves the victim survives and an owned deletion commits. Focused regressions additionally cover exact renamed imports, cross-package chains and rollback, deepest nested modules, missing and wrong modules/imports, unexported and dot-import targets, local package shadowing, and duplicate module identity; hosted Go CI executes both new modules.
- The expanded focused Go authorization lane passes 47 tests and 243 assertions; all eleven typed Go model suites pass 210 tests and 1,113 assertions. All sixteen authorization witnesses execute successfully. The complete authoritative Windows suite passes 1,003 tests and 7,760 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one committed mutation at `store.go:19`, preserving the path source at `handler.go:9`, wrapper call at `handler.go:10`, string parameter at `store.go:9`, object predicate and provisional execution at `store.go:16`, imported outer helper boundary at `store.go:19`, cross-package delegation at `internal/txguard/coordinator.go:11`, and actual commit at `internal/txleaf/transaction.go:6`; the matched control retains the identical path plus only `principal-bound-object-query` at `store.go:16`, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,332,133 bytes packed and 6,005,794 bytes unpacked, has SHA-1 `86447f2a9eceb4143aeeba83e1aa2b951a0b7dc0`, integrity `sha512-43HMHevWLkwBOqXavaIPu1qA9H2n5sAe8BgwoqsBcLIk69OrJBT496FpMU7XoTtYx3ePqaURHznuH/YToqP9Mg==`, and was removed after inspection.
- Composed exact Go transaction finalizer summaries across up to 32 uniquely resolved same-package helper boundaries. Each forwarding edge must pass the exact typed `database/sql` transaction parameter or a live local alias into the next summary, and the chain must reach one unambiguous top-level non-deferred `Commit` or `Rollback`. Evidence records the caller, every internal helper call, and the real leaf finalizer path. Cycles, multiple reachable outcomes, definition ambiguity, transaction reassignment, wrong parameter position, nested or deferred forwarding, and over-depth graphs fail closed. Direct leaf helpers now also preserve transaction aliases and reject parameters reassigned before finalization.
- Added the fifty-eighth exploit/control pair and expanded the perfect-gate Go authorization manifest from twelve to fourteen cases. Both fixtures stage a path-selected invoice deletion, call a typed coordinator with the transaction in parameter position one, alias it, forward it to a leaf commit helper in a fourth source file, and make state durable only at the real commit. The positive proves victim deletion. The control preserves the complete route, wrapper, transaction, helper chain, alias, attack ID, execution, commit, and response while adding only a context-principal account predicate; it proves the victim survives and an owned deletion still commits. Focused regressions cover ordered multi-file evidence, commit and rollback chains, aliases, parameter binding, cycles with and without a leaf, multiple outcomes, reassignment, nesting, defer, and the depth bound; hosted Go CI executes both new modules.
- The expanded focused Go authorization lane passes 42 tests and 224 assertions; all eleven typed Go model suites pass 205 tests and 1,094 assertions. All fourteen authorization witnesses execute successfully. The complete authoritative Windows suite passes 998 tests and 7,741 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one committed mutation at `store.go:18`, preserving the path source at `handler.go:9`, wrapper call at `handler.go:10`, string parameter at `store.go:8`, object predicate and provisional execution at `store.go:15`, outer helper boundary at `store.go:18`, internal delegation at `coordinator.go:8`, and actual commit at `transaction.go:6`; the matched control retains the identical path plus only `principal-bound-object-query` at `store.go:15`, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,329,106 bytes packed and 5,990,183 bytes unpacked, has SHA-1 `bff217d9e411b1491ea1894a625fbd32f3f0eaf6`, integrity `sha512-CHCdBz9XJj4qD9kUw3w6fMw5oKXVPfVWFUNbRdFygD/ozMwvgAkMyQpLRbOdFDSb3WCcvRUrhyYZuCU2l85e3Q==`, and was removed after inspection.
- Closed exact same-package Go transaction finalizer helpers in the object-authorization model. A pending mutation can now reach durable commit, or be discarded by rollback, through one uniquely resolved non-method function only when an exact typed `database/sql` transaction parameter reaches exactly one non-deferred function-level `Commit` or `Rollback`. Caller transaction aliases and arbitrary parameter positions retain identity; helper calls in standard `if err := ...` initializers close normally, while error-branch rollback helpers remain compatible with a later success commit. Evidence separates the caller helper boundary from the internal finalizer and preserves the helper's real file and line. Ambiguous definitions, untyped parameters, methods, wrong or reassigned transactions, nested or deferred caller/helper finalizers, mixed top-level finalizers, finalization before mutation, and nonempty finalizer calls fail closed.
- Added the fifty-seventh exploit/control pair and expanded the perfect-gate Go authorization manifest from ten to twelve cases. Both fixtures carry a path-selected invoice through a mutation wrapper and `Tx.ExecContext`, then call a typed commit helper in a third source file; their deterministic drivers stage deletion until that helper reaches the real commit. The positive proves durable victim deletion without principal scope. The control preserves route, wrapper, transaction, helper, attack ID, execution, commit, and response while adding only a context-derived account predicate, proving the victim survives and an owned deletion still commits. Focused regressions cover helper parameter position, transaction aliases, deferred rollback idioms, direct and `if`-initializer calls, helper evidence paths, rollback dominance, ambiguity, type identity, nesting, defer, mixed finalizers, ordering, and wrong transaction arguments; hosted Go CI executes both new modules.
- The expanded focused Go authorization lane passes 36 tests and 200 assertions; all eleven typed Go model suites pass 199 tests and 1,070 assertions. All twelve authorization witnesses execute successfully. The complete authoritative Windows suite passes 992 tests and 7,717 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits exactly one committed mutation at `store.go:18`, preserving the path source at `handler.go:9`, wrapper call at `handler.go:10`, string parameter at `store.go:8`, object predicate and provisional execution at `store.go:15`, caller helper boundary at `store.go:18`, and actual commit at `transaction.go:6`; the matched control retains only `principal-bound-object-query` at `store.go:15`, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,326,294 bytes packed and 5,975,154 bytes unpacked, has SHA-1 `2daa333cb120f67661d64e04a37a465d47d3082c`, integrity `sha512-7SM7kqMHQrUOw61t43HoA92C9PU6/Whp+19djUJDkLL34EaB5IPzqZZ2UNU/45E5MfVRUsrnVwGV63qla3wQig==`, and was removed after inspection.
- Closed a standard-library Go object-authorization false-negative through exact transaction statement transfer. A fixed mutation prepared on a proven DB can now flow through the exact source argument and assigned result of `Tx.Stmt` or `Tx.StmtContext`, or through an exact same-expression `tx.Stmt(...).Exec(...)` chain; the returned statement preserves the original predicate, records `go-sql-transaction-statement-transfer`, and queues its execution on the destination transaction until exact commit closure. The original DB statement remains independent. Ignored transfer results, unrelated same-line execution, context/source argument reversal, unknown, closed, or replaced sources, cross-transaction sources, closed or replaced results, rollback, missing commit, and operations after finalization fail closed; aliases share the appropriate statement or transaction state.
- Added the fifty-sixth exploit/control pair and expanded the perfect-gate Go authorization manifest from eight to ten cases. The positive prepares fixed DELETE SQL on a DB, transfers it with `Tx.StmtContext`, executes a path-selected victim invoice through the returned clone, and commits; its offline driver proves execution is staged until commit and then deletes the victim record. The control preserves route, wrapper, preparation, transfer, attack ID, execution, commit, and response while adding only a context-derived account predicate; its witness proves the victim survives and an owned invoice still commits deletion. Focused regressions cover `Stmt` and `StmtContext`, source/result identities, original/clone independence, aliases, context position, close and replacement, ignored results, transaction mismatch, rollback, missing commit, exact evidence, and principal controls; hosted Go CI executes both modules.
- The expanded focused Go authorization lane passes 31 tests and 173 assertions; all eleven typed Go model suites pass 194 tests and 1,043 assertions. All ten authorization witnesses execute successfully. The complete authoritative Windows suite passes 987 tests and 7,690 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits one committed mutation at `store.go:25`, preserving the path source at `handler.go:9`, wrapper call at `handler.go:10`, string parameter and preparation at `store.go:8-9`, exact transaction statement transfer at `store.go:20`, object predicate at `store.go:9`, statement execution at `store.go:22`, and commit at `store.go:25`; the matched control retains only `principal-bound-object-query` at `store.go:22`, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,324,131 bytes packed and 5,961,762 bytes unpacked, has SHA-1 `50261671b78d988819591218ba8c821244311bc1`, integrity `sha512-+67p89aDsZ+xRPUAzT2P9JwHPdDAhfMiIGKleL0QX3kAXJEWJFub0MMwkm4QFHggTAlUt0PjZjPDvGapfnrRxg==`, and was removed after inspection.
- Made Go object-mutation analysis transaction aware. Mutations on exact typed or `Begin`/`BeginTx`-derived `*sql.Tx` identities are now provisional until the same transaction reaches a non-deferred function-level `Commit`, where the distinct `go-database-object-committed-mutation` sink records durable-effect evidence. Missing finalization, unconditional function-level rollback, commit before execution, deferred commit, commit confined to a nested conditional, and operations after finalization are rejected. Transaction aliases share state; the conventional deferred rollback and error-branch rollback remain compatible with a later success-path commit; statements prepared on a transaction inherit its outcome boundary.
- Added the fifty-fifth exploit/control pair and expanded the perfect-gate Go authorization manifest from six to eight cases. The positive carries a path-selected victim invoice through one wrapper, `BeginTx`, `Tx.ExecContext`, and `Tx.Commit`; an offline transactional driver proves the deletion is staged and becomes durable only at commit. The matched control preserves the route, wrapper, transaction, attack ID, execution, commit, and response while adding a context-derived account predicate; its witness proves the committed attack does not delete the victim and a second transaction still commits deletion of the caller's invoice. Focused regressions cover direct and prepared Tx mutations, typed and derived identities, aliases, commit forms, rollback dominance, standard error branches, finalization order, conditional and deferred commit, principal controls, and exact evidence locations; hosted Go CI executes both modules.
- The expanded focused Go authorization lane passes 26 tests and 130 assertions; all eleven typed Go model suites pass 189 tests and 1,000 assertions. All eight authorization witnesses execute successfully. The complete authoritative Windows suite passes 982 tests and 7,647 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits one committed mutation at `store.go:22`, preserving the path source at `handler.go:9`, wrapper call at `handler.go:10`, string parameter at `store.go:8`, object predicate and provisional execution at `store.go:19`, and exact transaction commit at `store.go:22`; the matched control retains only `principal-bound-object-query` at execution, and production SDK source emits no committed Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,333,119 bytes packed and 5,952,556 bytes unpacked, has SHA-1 `c7d1faa7043207ddd9cece594a09f3bcef14425e`, integrity `sha512-uqRvdONMNrG3PZLXZLAlkD7nQGfGDcq/cxMINS15zeLIoc/Bm7+QFuV6scurXnwP1BUF3E1cWviWUBubZPRByQ==`, and was removed after inspection.
- Extended Go object-level authorization into the full standard-library prepared-mutation lifecycle. Fixed `UPDATE` and `DELETE` statements created through exact typed DB, Tx, or Conn `Prepare`/`PrepareContext` calls now retain their parsed object and security predicates until the exact returned `Stmt`, or a proven non-reassigned alias, reaches `Exec`/`ExecContext`. Preparation without execution, unrelated statements, replacements, non-mutations, action-prefix lookalikes, and statements explicitly closed before dispatch fail closed; deferred cleanup remains compatible with later execution. Direct mutation matching now requires an exact SQL action token and records explicit dispatch evidence.
- Added the fifty-fourth exploit/control pair and expanded the perfect-gate Go authorization manifest from four to six cases. The positive carries a path-selected invoice through one wrapper into a prepared DELETE and an offline driver proves the victim record is removed. The matched control preserves the route, wrapper, statement lifecycle, attack ID, and response while adding a context-derived account predicate; its witness proves the victim survives and the caller can still delete its own invoice. Focused regressions cover Prepare/PrepareContext and Exec/ExecContext roles, DB/Tx/Conn receivers, aliases, deferred and eager close, close-through-alias, replacement, unrelated execution, positional and named values, context-only controls, and exact evidence locations; hosted Go CI executes both modules.
- The expanded focused Go authorization lane passes 21 tests and 99 assertions; all eleven typed Go model suites pass 184 tests and 969 assertions. All six authorization witnesses execute successfully. The complete authoritative Windows suite passes 977 tests and 7,616 assertions across 117 files with 19 intentional environment-specific skips and no failures. Built-output review emits one vulnerable mutation at `store.go:19`, preserving the path source at `handler.go:9`, wrapper call at `handler.go:10`, string parameter at `store.go:8`, prepare and object predicate at `store.go:13`, and exact statement execution at `store.go:19`; the matched control retains only `principal-bound-object-query` at its execution line, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, production advisory audit, strict package inspection, isolated installation, public import, CLI, and all 79 bundled-plugin checks are clean. The validated 251-entry archive is 1,330,790 bytes packed and 5,941,585 bytes unpacked, has SHA-1 `ee8b2d70e688ec7ffb3c881171c4bd7fd78ce93c`, integrity `sha512-cIzecH5UPjCiHi7/7wCKRU++5JIbtnK0fO39dkq4OUNWaARjIMotbnKIItLeCmbbpXZagkJRjsBo/zG2mWcGMA==`, and was removed after inspection.
- Extended the typed Go CWE-639/CWE-862 object-authorization model from single-record `QueryRow` lookups into collection disclosure through exact `database/sql` `Query` and `QueryContext` operations. A collection hypothesis now requires the request-derived object predicate to execute on a proven DB, Tx, or Conn, the exact returned `Rows` cursor or a non-reassigned alias to advance through `Next` in an `if` or `for` condition, that same cursor to `Scan`, and scanned data to reach an HTTP writer. The distinct `go-database-object-collection-response` sink keeps list/export effects separate from single-object reads and mutations.
- Tightened lifecycle and identity precision while broadening recall. Bare chained `Scan` is accepted only on the same line as its `QueryRow`; receiver `Scan` must use the exact returned row or cursor; an unrelated same-named object cannot inherit a pending query; calling `Next` without consuming its boolean is not iteration; cursor reassignment clears identity; and multiple attacker-controlled wrapper parameters reaching one protected effect deduplicate to one hypothesis. Security-named columns such as `account_id` may now be attacker-selected object keys rather than being excluded by name, while a same-query security predicate remains control evidence only when its exact argument is context-principal derived.
- Added the fifty-third exploit/control pair and expanded the perfect-gate Go authorization manifest from two to four cases. The new positive carries a path-selected project through one wrapper into `QueryContext`, `Rows.Next`, `Rows.Scan`, and response disclosure; an offline driver proves both victim signing and recovery secrets are listed. The matched control adds a context-derived account predicate and proves the cross-account collection is empty while an owned project still lists normally. Two hosted Go CI steps, two executable cross-platform modules, bundled reviewer guidance, SDK/operator documentation, scanner-landscape comparison, and focused regressions cover Query/QueryContext positions, cursor aliases, exact lifecycle closure, unrelated cursor and ignored-Next rejection, security-named object keys, controls, and evidence locations.
- The expanded focused Go authorization lane passes 16 tests and 72 assertions; all eleven typed Go model suites pass 179 tests and 942 assertions. Both new collection witnesses execute successfully. The complete authoritative Windows suite passes 972 tests and 7,589 assertions across 117 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review preserves the original single-record pair and emits exactly one collection positive at `store.go:22`, with the path source at `handler.go:9`, wrapper call at `handler.go:10`, parameter and query at `store.go:10-11`, `Rows.Next` at `store.go:17`, `Rows.Scan` at `store.go:19`, and disclosure at `store.go:22`; the collection control retains only `principal-bound-object-query` at `store.go:11`, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, all four Go authorization fixtures, strict package inspection, isolated installation, public import, CLI, all 79 bundled-plugin checks, and the production advisory query are clean. The 251-entry, 1,317,171-byte archive has SHA-1 `e1e77e48d06826ab259a478a8427dae7d2047010`, integrity `sha512-3GEcmAFkifn4vdXzweDSUjmE+ev+w6uVOAUzFJIkG1B/xk+68NL9Vouekv9CZshOzWXUD4LENBSu+7rHLvw+3w==`, passed validation, and was removed after inspection.
- Added a standalone typed Go HTTP object-level authorization model for CWE-639 and CWE-862. The host requires exact `net/http` and `database/sql` identities, typed query/form/path/header input, a fixed SQL object-key equality predicate on a proven `*sql.DB`, `*sql.Tx`, or `*sql.Conn`, and a concrete protected effect. Reads close only when `QueryRow` reaches `Scan` and scanned data reaches an HTTP response; request-selected `UPDATE` and `DELETE` calls through `Exec` are immediate mutation effects. The model preserves positional, numbered, and `sql.Named` placeholder roles, inferred handles, fixed query constants, returned-data aliases, and one unique same-package wrapper.
- Kept authentication, object selection, principal provenance, authorization, and protected effects separate. A same-query account, customer, organization, owner, tenant, user, or workspace predicate is candidate control evidence only when its exact value derives from `Request.Context`; request headers and query values remain attacker controlled. A post-lookup ownership comparison is retained only when returned owner-like data is compared to a context principal and a fail-closed return dominates disclosure. Fixed or reassigned IDs, immutable server-owned object maps, dynamic SQL, package lookalikes, generic responses, ambiguous wrappers, comments, and strings are rejected. Shared Go argument parsing now preserves commas inside quoted and raw string literals, closing a model-wide false-negative edge without changing neighboring Go behavior.
- Added the fifty-second exploit/control pair to the versioned corpus, a perfect-gate Go object-authorization manifest, two executable cross-platform fixtures, two hosted Go CI steps, 14 focused regressions, bundled reviewer guidance, SDK/operator documentation, and a primary-source comparison with OWASP API1:2023, current CodeQL Go coverage, gosec's published rules, and the standard `database/sql` contract. The positive carries a path value through one wrapper into an ID-only invoice lookup and proves victim signing-key disclosure. The matched control preserves the path, wrapper, query mechanism, scan, response, and attack request but adds a context-derived account predicate, proving that the cross-account read is blocked while an owned invoice still succeeds.
- The focused Go authorization lane passes 14 tests and 54 assertions; all eleven typed Go model suites pass 177 tests and 924 assertions. Both offline `database/sql/driver` witnesses execute successfully. The complete authoritative Windows suite passes 970 tests and 7,571 assertions across 117 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one positive at `store.go:16`, preserving the path source at `handler.go:9`, wrapper call at `handler.go:10`, parameter at `store.go:9`, object predicate and `Scan` at `store.go:11`, and response at `store.go:16`; the matched control retains only `principal-bound-object-query` at `store.go:11`, and production SDK source emits no Go authorization record. Formatting, generated-model drift, TypeScript checking, the clean production build, both Go fixtures, strict package inspection, isolated installation, public import, CLI, all 79 bundled-plugin file checks, and the production advisory query are clean. The 251-entry, 1,316,085-byte archive has SHA-1 `00714970e66caf7b3667f3fa203120e065d68bf5`, integrity `sha512-ey20scMPGPuG21Q6MabWnupTRGMQrmWjP3hXR6Se3YAiovgdZzwGDM0t6HdcB8C6FJuPa6bu1CrSMYUpLkL5kQ==`, passed validation, and was removed after inspection.
- Added a standalone typed Go HTTP-to-`text/template` server-side template-injection model for CWE-1336. The host requires exact default or aliased standard-library identity, a typed query/form/path/header source, template-source argument zero to `Template.Parse`, the same non-reassigned parsed object, and a subsequent `Execute` or `ExecuteTemplate`. It follows direct expressions, string assignments, separate builders, direct chains, builder and parsed-object aliases, and one unique same-package string wrapper. `FuncMap` registration and non-nil execution data remain explicit capability evidence for concrete impact review.
- Tightened the boundary beyond the inspected gosec G708 configuration and the current CodeQL Go suite. Parsing without execution is inert; fixed server-owned source with request data only at execution is not SSTI; `html/template`, package lookalikes, dot or duplicate imports, local package shadows, immutable source maps, reassignment, ambiguous wrappers, comments, and strings are rejected. HTML, query, or path escaping does not silently clear template-source taint because brace-delimited Go directives can remain active. Reviewer guidance requires exact registered functions, exported data methods, output, secrets, side effects, recursion/resource behavior, and deployment authority instead of treating every template grammar as equivalent code execution.
- Added the fifty-first exploit/control pair to the versioned corpus, a perfect-gate Go template manifest, two cross-platform executable fixtures, two hosted Go CI steps, 13 focused regressions, bundled reviewer guidance, SDK/operator documentation, and a primary-source comparison. The positive carries a query value through one wrapper into `Parse`, registers `readSigningKey`, executes the parsed object, and proves `{{readSigningKey}}` discloses the fixture key. The matched control preserves the request, wrapper, payload, renderer, and response but parses a fixed `html/template`, proving the directive remains literal, script markup is escaped, and the key is not disclosed.
- The focused Go template lane passes 13 tests and 50 assertions; all ten typed Go model suites pass 163 tests and 870 assertions. Both new Go witnesses execute successfully. The complete authoritative Windows suite passes 956 tests and 7,517 assertions across 116 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one positive at `renderer.go:16`, preserving the query source at `handler.go:6`, wrapper call at `handler.go:7`, string parameter at `renderer.go:10`, exact `template.New` and `Funcs` construction plus `Parse` at `renderer.go:12`, and `Execute` closure at `renderer.go:16`; it emits nothing for the fixed-template control or production SDK source. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting and execution, and the production advisory query are clean. The 247-entry, 1,298,819-byte archive has SHA-1 `02bfc32487d3d839e654d118e40d603681f7ebd1`, integrity `sha512-o/tluC18OEGZuamVNXFfBmgfPHmTwyNdtnhaB2FdmLN+5Qa1khn70yKsQcoLxcg8AF8LlcjnZ1wCXL/dBySHPg==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a standalone typed Go HTTP-to-filesystem path model covering CWE-22, CWE-23, CWE-36, and CWE-73. The host requires exact default or aliased standard-library identity and preserves typed query, form, route, and header input through assignments, `filepath` construction, and one unique same-package string wrapper into exact `os`, legacy `io/ioutil`, `filepath.Walk*`, and `net/http.ServeFile*` arguments. Read, open, write, delete, metadata, link source/destination, move source/destination, filesystem-root selection, walk-root, and response-file effects remain distinct. A request-controlled `OpenRoot` or `OpenInRoot` root is reported while a request-derived name under a fixed root remains control evidence. Reassignment, direct or assigned fixed immutable file maps, lookalikes, duplicate imports, ambiguous wrappers, and comment/string examples are rejected.
- Kept path normalization, containment, authorization, and filesystem behavior separate. `filepath.Join`, `Clean`, `Abs`, `Rel`, `EvalSymlinks`, and related conversions preserve request taint and become candidate evidence rather than universal sanitizers. `filepath.IsLocal` remains lexical and does not prove link safety. Root-scoped `os.OpenInRoot`, `os.OpenRoot`, and `os.Root` operations are strong counterevidence only after reviewer proof of the exact root, platform, links/mounts/races, authorization, and a patched runtime. Guidance explicitly requires Go 1.25.12 or 1.26.5 or newer for affected Unix GO-2026-4970/CVE-2026-39822 deployments. This retains high-precision CodeQL boundaries while avoiding gosec G703's blanket sanitizer treatment of several path transformations.
- Added the fiftieth exploit/control pair to the versioned corpus, a perfect-gate Go filesystem-path manifest, two cross-platform executable fixtures, two hosted Go CI steps, 12 focused regressions, mandatory reviewer guidance, SDK/operator documentation, and a primary-source scanner comparison. The positive carries a query value through one wrapper and `filepath.Join` into `os.ReadFile`, proving sibling signing-key disclosure. The control preserves the request, wrapper, layout, payload, and allowed-file behavior but uses `os.OpenInRoot`, proving that the same traversal is rejected.
- The focused Go filesystem lane passes 12 tests and 74 assertions; all nine typed Go framework-model suites pass 150 tests and 820 assertions. Both new Go witnesses execute successfully. The complete authoritative Windows suite passes 943 tests and 7,467 assertions across 115 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one positive at `document.go:10`, preserving the query source at `handler.go:8`, wrapper call at `handler.go:9`, string parameter at `document.go:8`, `filepath.Join` construction at `document.go:9`, and exact `os.ReadFile` argument, and emits nothing for the rooted control or production SDK source. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting and execution, and the production advisory query are clean. The 243-entry, 1,299,384-byte archive has SHA-1 `7d3701d8d61f1ef9c9d8971c5a98e8f29c8505f0`, integrity `sha512-t2GxuRy4846SfLnjTuBCpTZgByEhP07l00WZefb6sDDk9ysvatjoecpyQNFjXIkm1qEvVY8tesVjcaJsts+yUQ==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Extended the typed Go CWE-78 lane through manually constructed `exec.Cmd` values and lower-level standard-library process dispatch. Exact default or aliased `os/exec`, `execabs`, `os`, and `syscall` imports are required. The model follows composite, zero-value, and `new(exec.Cmd)` construction; `Path`; complete `Args` replacement; exact `Args[index]` and local slice-element mutation; slice aliases; and pointer-versus-value `Cmd` aliases. A manual command remains inert until the same non-reassigned object reaches `Run`, `Start`, `Output`, or `CombinedOutput`, while `os.StartProcess` and `syscall.Exec`, `ForkExec`, and `StartProcess` are modeled as immediate dispatchers at their documented executable and argv positions.
- Preserved exact process semantics while broadening recall. `Cmd.Path` or low-level argument zero selects the executable; nonempty argv includes process-visible `Args[0]`, which is not promoted into executable selection. Fixed-program ordinary argv remains a negative control, but shell, interpreter, batch, SSH, Git, and rsync positions retain their existing grammar-sensitive behavior. Replacement clears state, pointer aliases share later field mutation, value aliases copy fields, immutable command-map selection remains a barrier, and package lookalikes plus ambiguous imports or wrappers remain rejected. This closes process surfaces covered broadly by gosec G204/G702 but absent from CodeQL's shipped `os/exec` sink model without adopting construction-time unresolved-argument false positives.
- Expanded the perfect-gate Go process manifest from two to four cases with a cross-platform manual-`Cmd` exploit/control pair and two hosted Go fixture steps. The positive carries an indexed request value through one wrapper into an assigned `Cmd.Args` shell command and proves that `CombinedOutput` exposes an internal signing-key witness. The matched control preserves the request, wrapper, manual fields, shell, flag, execution closure, and attack bytes but uses an immutable map of complete commands. Both tests execute a copied test binary through a temporary working directory rather than invoking the host shell. Reviewer guidance, operator/SDK documentation, and the primary-source scanner comparison now cover manual fields and immediate low-level dispatch.
- The expanded focused Go process lane passes 23 tests and 103 assertions; the eight-model Go SSRF/process/database adjacency gate passes 138 tests and 746 assertions. All four process fixture modules pass their executable witnesses. The complete authoritative Windows suite passes 931 tests and 7,393 assertions across 114 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits one constructor positive at `render.go:11` and one manual-field positive at `render.go:14`, preserves their exact indexed sources, wrapper calls, parameters, assignments, process state, and execution closure, and emits nothing for either immutable-command control or production SDK source. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting and execution, and the production advisory query are clean. The 239-entry, 1,274,811-byte archive has SHA-1 `8987902820a58a3ca3841256456a87078425c9bc`, integrity `sha512-wVvM7CU3DrDhEAoWt3o/ZbBzToGsJ6FT3akqkPD7I+VeR8T05Ck4WiNobaSXXVJ+5/6LM/i0fMJgjCfN81RITw==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a standalone exact Go CWE-78 model for typed HTTP input reaching `os/exec` or `golang.org/x/sys/execabs`. The model distinguishes request-controlled executable selection, explicit POSIX/Windows/PowerShell/interpreter command grammar, Windows batch-file arguments, interpreter script selection, fixed-host SSH remote commands, and option-sensitive Git/rsync arguments from ordinary fixed-executable argument vectors. Exact aliases, immutable local and package constants, command aliases, one unique same-package wrapper, and reassignment clearing are preserved while forks, lookalikes, dot or duplicate imports, ambiguous wrappers, and comments or string examples are rejected.
- Required actual process execution rather than reporting command construction. A risky `Command` or `CommandContext` is retained only until the same non-reassigned `Cmd` reaches `Run`, `Start`, `Output`, or `CombinedOutput`; construction, pipe setup, `LookPath`, and unrelated same-named methods remain inert. POSIX post-`-c` positional data remains an argument rather than command grammar, ordinary direct argument vectors remain controls, complete immutable command-map selection blocks shell injection, and an exact preceding `--` blocks the modeled Git/rsync option path. Regex/prefix checks, deadlines, and executable lookup remain reviewer evidence rather than universal sanitizers.
- Added a perfect-gate cross-platform exploit/control benchmark, two hosted Go fixture steps, 17 focused regressions, reviewer guidance, SDK/operator documentation, and a primary-source comparison with Go `os/exec`, CodeQL's high-precision command-injection query and process model, and gosec G204. Both fixture modules copy their running test executable into a temporary `sh` witness, so the positive proves request-derived `sh -c` grammar exposes an internal record and the matched immutable-command control proves the same attack bytes remain inert on Windows and Linux without invoking the host shell.
- The focused Go process lane passes 17 tests and 68 assertions; the eight-model Go SSRF/process/database adjacency gate passes 132 tests and 711 assertions. Both process fixture modules pass their executable witnesses. The complete authoritative Windows suite passes 925 tests and 7,358 assertions across 114 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one vulnerable record at `render.go:11`, with its indexed request source at `handler.go:6`, wrapper call at `handler.go:7`, string parameter at `render.go:9`, command assignment at `render.go:10`, and shell construction plus `CombinedOutput` closure at `render.go:11`; the immutable-command control and production SDK source emit none. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting and execution, and the production advisory query are clean. The 239-entry, 1,267,898-byte archive has SHA-1 `30727d8d99a7da1af5e980e584e1df38804b7597`, integrity `sha512-eFez/IbEj2/5df0kNYUqF5Xjxu7MHhoR9Vk2JLggUcQwI2IGJi6AFswmnF17guG6MHxffCWHOpbr0X4tdfDOSA==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Extended the exact `gorm.io/gorm` CWE-89 model through the generics API introduced in GORM v1.30. The scanner now proves `gorm.G[T](db)` only from a typed database handle; tracks exact generic `Interface`, `CreateInterface`, `ChainInterface`, `ExecInterface`, and set/update interfaces; preserves assigned aliases and clears replacements; and parses generic function calls without weakening import, type, or receiver identity for other Go models.
- Preserved the generic API's distinct grammar, value, and execution signatures. Context-first `Exec` treats argument one as SQL and later arguments as values; generic `Raw` remains deferred until an `ExecInterface` finisher; `Where`, `Not`, `Or`, `Select`, `Distinct`, `Group`, `Having`, `Order`, and `Table` retain grammar until execution; and `Count` treats its context-following column as grammar. Exact `JoinBuilder` and `PreloadBuilder` callbacks propagate their clause grammar, while typed join targets, preload association names, placeholders, maps, later arguments, traditional inline-condition pseudo-signatures, and inert `Build` remain negative controls. Constructor options and `Set` assignments can carry nested `gorm.Expr` grammar.
- Expanded the perfect-gate GORM benchmark from two to four cases with an executable generic exploit/control pair and two hosted Go fixture steps. The positive carries an indexed request value through one wrapper into `gorm.G[string](db).Where(predicate).Find(ctx)` and exposes an internal record through a deterministic offline driver; the matched control preserves the topology and attack bytes but supplies them only after a placeholder. Added exact reviewer guidance, SDK/operator documentation, scanner-landscape comparison, and regressions for every generic clause, finisher family, callback, expression path, identity proof, reassignment barrier, and false-positive control.
- The focused GORM lane passes 27 tests and 134 assertions; the seven-model Go SSRF/database adjacency gate passes 115 tests and 643 assertions. Both new generic fixture modules pass their executable witnesses. The complete authoritative Windows suite passes 908 tests and 7,290 assertions across 113 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one generic positive at `search.go:12`, with its indexed request source at `handler.go:10`, wrapper call at `handler.go:11`, string parameter at `search.go:10`, query assignment at `search.go:11`, and `Where` construction plus `Find` closure at `search.go:12`; the generic placeholder control and production SDK source emit none. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting and execution, and the production advisory query are clean. The 235-entry, 1,249,736-byte archive has SHA-1 `564eee270f2100b6cf69cad719a8f4f5f1eaff31`, integrity `sha512-2bYm66jdStZDfjgHWpm+NeKoQDFNXELaiVmHEWkiD0yLxaSd7oQMEHTWy5EhtcxfuqfWmnipmUD21GqhsnZgwA==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a standalone exact `github.com/Masterminds/squirrel` CWE-89 model for request-derived SQL grammar crossing typed immutable Select, Insert/Replace, Update, Delete, StatementBuilder, Case, and nested Sqlizer values. The model preserves exact Squirrel and `database/sql` runner identity, fluent and assigned builders, aliases, all variadic structural arguments, map and Eq-like value containers, cache and standard-SQL wrappers, and one unique same-package wrapper while rejecting legacy/fork/lookalike, dot, duplicate, untyped, runnerless, arbitrary-runner, fixed, ambiguous, and reassigned identities.
- Closed Squirrel findings through actual execution rather than construction alone. `RunWith` must lead to builder `Exec`/`Query`/`QueryRow`/`Scan` or a Context variant; exact package helpers require a proven runner; and `ToSql`/`MustSql` output requires typed direct or prepared-statement execution. `DebugSqlizer` output is retained only when executed. Placeholder values, `Values`, `Set` values, later expression arguments, and `Where`/`Having` map or Eq-like values remain data. A fixture-driven regression also prevents an unrelated later `database/sql.Rows.Scan` from inheriting the builder result identity.
- Added a perfect-gate Squirrel exploit/control benchmark, deterministic offline signature-compatible subsets and standard-library drivers, two hosted Go fixture steps, 19 focused regressions, reviewer guidance, operator and SDK documentation, and a primary-source comparison with upstream Squirrel, CodeQL, and gosec. The positive proves a request-derived predicate crossing one wrapper through `Where(...).RunWith(...).Query()` exposes an internal record; the matched control preserves the topology and bytes but keeps them in one placeholder value.
- The focused Squirrel lane passes 19 tests and 121 assertions; the seven-model Go SSRF/database adjacency gate passes 107 tests and 599 assertions. Both Squirrel modules pass their executable witnesses. The complete authoritative Windows suite passes 900 tests and 7,246 assertions across 113 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one vulnerable record at `search.go:12`, with the indexed request source at `handler.go:10`, wrapper call at `handler.go:11`, string parameter at `search.go:10`, query assignment at `search.go:11`, and `Where` construction plus runner/`Query` closure at `search.go:12`; the placeholder control and production SDK source emit none. Formatting, generated-model drift, TypeScript checking, the clean production build, both Go witnesses, and the production advisory query are clean. The 235-entry, 1,245,051-byte archive has SHA-1 `c3006f9bfeb47fc7d6434f38793994e8a3694d0b`, integrity `sha512-E52/LfhYQZgDC80fh2MuqbaccdOkejoag6/ez+Acy5cRcC3TOBHiRx7lpFWvL3uf6U9lccR4NQIPvUZfdI2g6w==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history remote self-scan is not claimed because repository and reachable-history export still requires separate explicit disclosure approval.
- Added a standalone exact `gorm.io/gorm` v2 CWE-89 model for request-derived SQL grammar reaching proven `*gorm.DB` receivers. The model covers typed parameters, package/current-function declarations, unique same-file receiver fields, explicit aliases, `gorm.Open`, sessions, transactions, direct and multiline fluent chains, assigned builders, one unique same-package wrapper, fixed fragment-map selection, and reassignment clearing while rejecting legacy, fork, suffix-lookalike, dot, duplicate, and untyped identities.
- Preserved GORM's query grammar and execution boundaries rather than matching method names alone. `Raw`, `Where`, `Not`, `Or`, `Select`, `Distinct`, `Table`, `Group`, `Having`, `Order`, `Joins`, and `InnerJoins` retain tainted fragments only until the same non-reassigned builder reaches a query or mutation finisher; `Exec`, inline finisher conditions, variadic structural `Select`/`Distinct` columns, `Pluck` identifiers, and `gorm.Expr` text used by raw or mutation finishers retain their distinct execution positions. Later placeholder and expression arguments plus map or struct condition fields remain values, and unexecuted builders are rejected. DryRun, prepared-statement mode, global-update guards, deadlines, manual escaping, regex fragment checks, and bound arguments remain candidate evidence for validation rather than universal sanitizers.
- Added a perfect-gate GORM exploit/control benchmark, deterministic offline signature-compatible subsets and standard-library drivers, hosted Go fixture coverage, focused regression tests, reviewer guidance, operator and SDK documentation, and primary-source scanner comparison. The positive proves a request-derived predicate crossing one wrapper through `Raw(...).Scan(...)` exposes an internal record; the matched control preserves the topology and attack bytes but keeps them in one placeholder value.
- The focused GORM lane passes 19 tests and 90 assertions; the six-model Go SSRF/database adjacency gate passes 88 tests and 478 assertions. Both GORM modules pass their executable witnesses. The complete authoritative Windows suite passes 881 tests and 7,125 assertions across 112 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one vulnerable record at `search.go:12`, with the indexed request source at `handler.go:10`, wrapper call at `handler.go:11`, string parameter at `search.go:9`, query assignment at `search.go:10`, and `Raw` construction closed by `Scan` at `search.go:12`; the placeholder control and production SDK source emit none. Formatting, generated-model drift, TypeScript checking, the clean production build, both Go witnesses, and the current production advisory query are clean. The 231-entry, 1,232,112-byte archive has SHA-1 `a95846538d5476e90dbb563475f29a86554e9d1a`, integrity `sha512-XiY4l11aC6GoDfY2j8WsLILeW0hraHvZerBaN7euJcQXs+QFNURjHUXayIkmKRlMJiNcvd3+HUA1gL5XG889Eg==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history remote self-scan is not claimed because repository and reachable-history export still requires separate explicit disclosure approval.
- Added a separate exact `github.com/jmoiron/sqlx` CWE-89 model for typed DB, Tx, and Conn receivers plus exact package helpers. The model preserves destination-before-query `Select`/`Get` signatures, context positions, embedded and extended query methods, named execution, exact constructors and derived handles, one unique same-package wrapper, and fixed query-map selection while rejecting forks, lookalikes, dot/duplicate imports, arbitrary Queryer/Execer implementations, untyped methods, and reassignment.
- Closed deferred sqlx query paths through actual execution. `Prepare`, `Preparex`, and `PrepareNamed`, including package and context variants, become reportable only when the resulting non-reassigned `Stmt` or `NamedStmt` reaches an execution method; exact `Tx.Stmtx`, `StmtxContext`, and `NamedStmt` transfers preserve identity. `Rebind`, `Named`, and `BindNamed` propagate tainted query grammar but never promote request data confined to positional or named value arguments. Manual escaping, allowlists, deadlines, read-only transactions, rebinding, and extra arguments remain candidate evidence rather than universal sanitizers.
- Added a strict offline sqlx exploit/control benchmark, 14 focused regressions, two hosted Go fixture steps, reviewer guidance, SDK and operator documentation, and scanner-landscape comparison. The positive proves a request-derived predicate crossing one wrapper into `DB.Select` exposes an internal record; the matched control preserves the topology but keeps identical attack bytes in one placeholder value. The multi-result `sqlx.Named` control also guards against incorrectly tainting fixed query text from its value map.
- The focused sqlx lane passes 14 tests and 98 assertions; the five-model Go SSRF/database adjacency gate passes 69 tests and 388 assertions. Both sqlx modules pass their executable witnesses. The complete authoritative Windows suite passes 862 tests and 7,035 assertions across 111 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one vulnerable record at `search.go:12`, with the request source at `handler.go:10`, wrapper call at `handler.go:11`, string parameter at `search.go:9`, and query construction at `search.go:10`; the placeholder control and production SDK source emit none. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting, and the current production advisory query are clean. The 227-entry, 1,205,187-byte archive has SHA-1 `a3caa55d8f361d68ef0cd9771010b3f072dd0cb0`, integrity `sha512-AW6LkrSD455Opi4iN58LSmeVnh77trfccagByjb3xAjvWCT16rN1yovQ8CNPWjQsGaC8N1NroVELMlMlgUfyZg==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history remote self-scan is not claimed because repository and reachable-history export still requires separate explicit disclosure approval.
- Added exact local custom pgx v5 `QueryRewriter` modeling to the typed Go CWE-89 lane. The scanner requires a unique same-directory/package struct and exact value or pointer `RewriteQuery(context.Context, *pgx.Conn, string, []any) (string, []any, error)` method, follows request-derived struct fields and preserved input SQL into only the first returned expression, and reports direct `Exec`/`Query`/`QueryRow` dispatch with explicit cross-file propagators.
- Extended rewriter closure through pgx's real leading-option and batch behavior. Exact pgx query options may precede the rewriter; an ordinary value stops option resolution. `Batch.Queue` rewrites become reportable only when the same non-reassigned typed batch reaches `SendBatch`. A fixed first return with request data confined to returned `[]any` is rejected, as are pointer/value method-set mismatches, inexact imports or signatures, duplicate types or methods, non-leading instances, and cleared fields or instances.
- Expanded the strict pgx benchmark from one exploit/control pair to two. The new offline exact-module witness proves a custom rewriter can expose an internal signing-key record by returning formatted SQL, while the matched control proves the same attack bytes remain one bound argument and the intended public value still works. Added hosted Go execution, focused regressions, reviewer guidance, SDK and operator documentation, and scanner-landscape comparison.
- The expanded pgx lane passes 19 focused tests and 98 assertions; the four-model Go parser and SQL/SSRF adjacency gate passes 55 tests and 288 assertions. All ten hosted Go fixture modules pass locally. The complete authoritative Windows suite passes 848 tests and 6,937 assertions across 110 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one custom-rewriter record at `handler.go:12`, with the form source and field construction at `handler.go:11`, receiver-field and SQL-assignment evidence at `query_rewriter.go:14-15`, and first returned SQL at `query_rewriter.go:16`; the returned-argument control and production source emit none. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting, and the production advisory query are clean. The 223-entry, 1,194,341-byte archive has SHA-1 `0404b346b1d8ed357a66309864d6bca892637a2f`, integrity `sha512-SPvPTpcSK1PONTD4YyH3gMGLjxDhOsyUE1Dl+vnui6Y1j4laWfswtSiF+JsWW0iIRAH7yBf1N/m2sy20gbIZDA==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history remote self-scan is not claimed because repository and reachable-history export still requires separate explicit disclosure approval.
- Added a separate exact Go `pgconn` CWE-89 model for request-derived SQL reaching a proven `*pgconn.PgConn`, including typed parameters and fields, package handles, `pgconn.Connect*`/`Construct`, and the exact `pgx.Conn.PgConn()` low-level escape hatch. Immediate sinks preserve `Exec` and `ExecParams` SQL at argument one plus `CopyFrom` and `CopyTo` commands at argument two, while later parameter bytes, OIDs, formats, COPY readers, and COPY writers remain data.
- Closed deferred low-level execution through concrete object identity. `Prepare` requires later `ExecPrepared` with a fixed name on the same non-reassigned connection or `ExecStatement` with the exact returned `StatementDescription`. `pgconn.Batch.ExecParams`, `ExecPrepared`, and `ExecStatement` require the exact non-reassigned batch at `PgConn.ExecBatch`. Pipeline sends require the same pipeline at `Flush` or `Sync`; pending work is consumed once, reassignment clears it, and `Pipeline.Close` plus later dead sends remain inert because upstream closes unsynchronized pipelines with an error instead of flushing them.
- Added explicit candidate evidence for manual escaping, fragment allowlists, deadlines, `PgConn.EscapeString`, and separate extended-protocol parameter bytes without promoting those leads into universal sanitizers. Reviewer guidance distinguishes simple-protocol multiple statements, extended-protocol single commands, raw COPY SQL, preparation and statement-description closure, pipeline ordering, role and transaction privileges, tenant predicates, returned or written data, and concrete impact. Primary-source comparison found gosec's current taint sink table limited to `database/sql`, the community Semgrep rule limited to legacy pgx construction patterns, and no explicit pgconn pipeline closure in the visible CodeQL SQL customization.
- Added paired offline Go modules with the exact pgx v5 module path, deterministic signature-compatible `pgconn` witnesses, a perfect-gate benchmark manifest, 11 focused regression tests, package coverage, documentation, and two hosted Go fixture steps. The positive proves simple-protocol predicate injection exposes an internal record; the matched control proves identical metacharacters remain one `ExecParams` value while an allowed value still returns its intended row.
- The focused pgconn lane passes 11 tests and 66 assertions; the nine-file adjacent Go and cross-language framework gate passes 63 tests and 380 assertions. Both pgconn modules pass their executable witnesses. The complete authoritative Windows suite passes 841 tests and 6,903 assertions across 110 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one vulnerable record at `search.go:12`, with the indexed request source at `handler.go:10`, wrapper call at `handler.go:11`, string parameter at `search.go:10`, query construction at `search.go:11`, and typed dispatch at `search.go:12`; the extended-protocol control and production source emit none. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting, and the pnpm production advisory query are clean. The 223-entry, 1,181,769-byte archive has SHA-1 `f21693e637b9c8fe0a6c80267e62ef8b505e0ccf`, integrity `sha512-6rHBqmPxn9GFdihos0ztdKcAtybkWVK0aMc6XBRDfGg0NkmpU9EytOdvoNwTEBBcmI9Z0qy91iddgkDDR72JiA==`, and passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history remote self-scan is not claimed because repository and reachable-history export still requires separate explicit disclosure approval.
- Added an exact Go `pgx/v5` and `pgxpool` CWE-89 model for request-derived values reaching the SQL-text argument of a proven `*pgx.Conn`, `pgx.Tx`, `*pgxpool.Pool`, `*pgxpool.Conn`, or `*pgxpool.Tx`. The model covers typed parameters and fields, package handles, `pgx.Connect*`, `pgxpool.New*`, acquired connections, derived transactions, aliases, and one unique same-package string wrapper while rejecting pgx v4, forks, import lookalikes, dot or duplicate imports, unrelated `Query`/`Exec` methods, and receiver types borrowed from another function.
- Preserved pgx argument and execution roles across `Exec`, `Query`, and `QueryRow`: context is argument zero, SQL or a prepared-statement name is argument one, and later values and execution options are not SQL grammar. Manual `Prepare` paths require a fixed statement name and later execution on the same non-reassigned receiver. `Batch.Queue` paths require the exact typed, non-reassigned `*pgx.Batch` to reach `SendBatch`; inert preparation, undispatched queues, fixed query text, and request data used only through `$1`, `NamedArgs`, `StrictNamedArgs`, `StructArgs`, or `StrictStructArgs` are rejected.
- Added candidate evidence for manual escaping, fragment regexes, deadlines, read-only pgx transactions, `Identifier.Sanitize`, simple-protocol review, separate arguments, and pgx parameter rewriters without treating those leads as universal sanitizers. Reviewer guidance distinguishes automatic statement caching, prepared-name resolution, batch dispatch, extended versus simple protocol, `QueryRewriter`, identifier quoting, statement stacking, database privileges, tenant predicates, returned columns, and concrete read/write impact.
- Added paired offline Go modules with an exact pgx v5 import-path replacement, deterministic API-compatible query witnesses, a perfect-gate benchmark manifest, 12 focused regressions, package coverage, documentation, and two hosted Go fixture steps. The positive proves an injected predicate changes query grammar and exposes an internal record; the control proves identical metacharacters remain one `$1` value while an allowed value still returns its intended row.
- The focused pgx lane passes 12 tests and 64 assertions; the eight-file adjacent Go and cross-language framework gate passes 55 tests and 297 assertions. Both pgx modules pass their executable witnesses. The complete authoritative Windows suite passes 830 tests and 6,837 assertions across 109 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one vulnerable record at `search.go:12`, with the indexed request source at `handler.go:11`, wrapper call at `handler.go:12`, string parameter at `search.go:10`, query construction at `search.go:11`, and typed dispatch at `search.go:12`; the `$1` control and production source emit none. Formatting, generated-model drift, TypeScript checking, the clean production build, Go formatting, and the production advisory query are clean. The 219-entry archive (`d85d2fa10e8ed802785a065848fcae411caf8c33`) passes strict inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history remote self-scan is not claimed because exporting the uncommitted repository and reachable history still requires separate explicit disclosure approval.
- Added a typed Go `database/sql` CWE-89 model for request-derived values reaching the exact query-text argument of a proven standard-library `*sql.DB`, `*sql.Tx`, or `*sql.Conn`. The model covers direct parameters, package-level typed handles, `sql.Open`/`OpenDB`, derived transactions and connections, and same-file typed receiver fields while rejecting package lookalikes, dot imports, unrelated `Query`/`Exec` methods, and receiver names borrowed from another function's scope.
- Preserved every query argument role across `Exec`, `Query`, `QueryRow`, and their context variants. Request data passed only in later placeholder arguments or `sql.Named` values is not query grammar. Tainted `Prepare`/`PrepareContext` text becomes reportable only when the exact resulting statement later reaches `Exec`, `Query`, or `QueryRow`; unused or replaced prepared statements are rejected.
- Added bounded local propagation and one unique same-package string wrapper, indexed and `Get` forms of standard `net/http` query/form sources, fixed server-owned query selection, multi-variable reassignment clearing, exact receiver and function ambiguity checks, and candidate evidence for manual escaping, regular-expression allowlists, deadlines, read-only transactions, and separate arguments attached to an already tainted query. Reviewer guidance keeps driver-specific placeholders, identifier selection, stacked statements, database roles, tenant predicates, returned columns, and concrete read/write impact separate.
- Added paired Go modules, a perfect-gate manifest, deterministic standard-library `database/sql/driver` witnesses, 12 focused regressions, documentation, and two hosted Go fixture steps. The exploit proves an injected predicate changes query grammar and exposes an otherwise internal record; the control proves the same bytes remain one bound value while an allowed value still returns its intended row.
- The focused Go SQL lane passes 12 tests and 60 assertions; the seven-file adjacent Go and cross-language SQL/framework gate passes 43 tests and 233 assertions. Both Go modules pass their executable database witnesses. The complete authoritative Windows suite passes 818 tests and 6,773 assertions across 108 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one vulnerable record at `search.go:11`, no parameterized-control record, and no production-source record. Formatting, generated-model drift, TypeScript checks, the clean production build, Go formatting, and the production advisory query are clean; the 215-entry archive passes strict inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history remote self-scan is not claimed because exporting the uncommitted repository and reachable history still requires separate explicit disclosure approval.
- Added a typed Go `net/http` CWE-918 model for request-derived complete URLs reaching an actual outbound dispatch. Sources require a typed `*http.Request` parameter and exact `URL.Query().Get`, `FormValue`, `PostFormValue`, `PathValue`, or `Header.Get` access. Sinks require the standard `net/http` import and an exact package function, `DefaultClient`, typed `http.Client`, or locally constructed client; `NewRequest` and `NewRequestWithContext` become relevant only when the resulting request later reaches a proven `Client.Do`.
- Added bounded same-package propagation across one uniquely resolved string wrapper, including cross-file calls, while preserving every source, call argument, wrapper parameter, request construction, and dispatch position. Fixed server-owned destination-map selection breaks URL taint only while the map remains unmodified. Request bodies, inert request construction, untyped receivers, import lookalikes, dot or blank imports, reassigned values, duplicate function identities, different packages or directories, and comment or string examples are rejected before review.
- Kept Go transport hardening separate from destination authorization. `CheckRedirect` fail-closed behavior, `http.ErrUseLastResponse`, exact-host checks, network-address validation, custom `DialContext`, and scheme checks remain candidate control leads; none silently sanitizes an attacker-controlled initial URL. Package-level convenience calls and body-only `Post`/`PostForm` values retain their distinct argument roles.
- Added paired Go modules, a perfect-gate manifest, real `httptest` loopback witnesses, 13 focused regressions, reviewer guidance, documentation, and a seventh hosted fixture workflow. The positive proves a query-controlled URL crosses a wrapper into `NewRequestWithContext` and `Client.Do` and reaches a mock metadata service. The control proves an arbitrary internal URL is rejected before transport and that a permitted destination cannot redirect into the mock metadata service.
- The focused Go lane passes 13 tests and 66 assertions; the 11-file adjacent framework and SSRF gate passes 61 tests and 326 assertions. Both Go modules pass their real loopback witnesses. The complete authoritative Windows suite passes 806 tests and 6,713 assertions across 107 files with 19 intentional environment-specific skips and no failures. Deterministic built-output review emits exactly one vulnerable record at `fetch.go:15`, no safe-fixture record, and no production-source record. Formatting, generated-model drift, TypeScript checks, the clean production build, Go formatting, and the production advisory query are clean; the 211-entry archive passes strict inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history remote self-scan is not claimed because exporting the uncommitted repository and reachable history still requires separate explicit disclosure approval.
- Added a strict same-file GitHub Actions CWE-284/CWE-829 model for pull-request-capable workflows that schedule attacker-controlled repository code on an explicit self-hosted label, a statically classified custom runner label, or a runner group. A report now requires the complete trigger, runner selection, official untrusted checkout, matching workspace path, and later command or local-action execution closure; a trigger or `runs-on` value alone is insufficient.
- Synchronized hosted-runner exclusions with the current CodeQL 2.26.0 label model, including GitHub-hosted Ubuntu, macOS, and Windows forms plus BuildJet and Warp labels. Fully dynamic runner expressions, trusted or fixed-repository checkouts, clean trusted replacement checkouts, unrelated execution paths, data-only jobs, malformed/duplicate/aliased YAML, and non-workflow files are rejected before review. Exact `pull_request` default, `github.sha`, `github.ref`, merge SHA, head SHA, `refs/pull`, and issue-number pull-ref forms are covered without inventing write-token or secret access for ordinary fork pull requests.
- Kept runner persistence separate from current-job authority. The record preserves event, runner kind and labels, checkout and sink lines, effective permissions, structural secret access, immutable selection, credential persistence, review/environment gates, and Checkout v7 evidence. Reviewer guidance requires proof of actual customer-controlled scheduling and examines persistent work directories, service identities, signing keys, cloud metadata, internal services, Docker sockets, tool caches, and later jobs; a proven freshly destroyed single-job JIT runner is strong persistence counterevidence.
- Added paired self-hosted/hosted pull-request fixtures, a perfect-gate manifest, a harmless executable persistence witness, 13 focused regressions, reviewer guidance, CI execution, and documentation. The witness proves an untrusted job can replace a user-writable helper observed by a later privileged job on a reused host, while a fresh hosted machine retains the trusted helper. The focused lane passes 13 tests and 72 assertions; all six GitHub Actions lanes pass 64 tests and 356 assertions, and all six witnesses pass. The complete authoritative scanner suite passes 793 tests and 6,647 assertions across 106 files with 19 intentional environment-specific skips and no failures. Deterministic review emits exactly one vulnerable fixture record at the execution step, no hosted-control record, and no production-repository record. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 207-entry archive passes strict inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin file checks. An authenticated full-history self-scan is not claimed because exporting the uncommitted tree and 128 reachable commits requires separate explicit disclosure approval.
- Added a strict same-file GitHub Actions CWE-094/CWE-095/CWE-116 model for attacker-controlled pull-request, issue, discussion, review, comment, branch, and triggering-workflow fields compiled into a workflow `run` script or an exact known action code-input. Trigger, event-field, environment-alias, interpreter-input, permission, secret, and control provenance remain explicit. The action boundary uses the current CodeQL/zizmor sink map across 18 exact action identities instead of treating arbitrary `with` values as executable code.
- Added bounded value-flow semantics for direct contexts, single-quoted property indexing, parentheses, `toJSON`, `fromJSON`, `format`, `join`, and reachable `&&`/`||` results. Comparisons, `contains`/prefix/suffix predicates, unknown functions, fixed or unreachable short-circuit results, trigger/field mismatches, dynamic or lookalike actions, unknown code inputs, malformed/duplicate/aliased YAML, and fixed environment overrides are rejected. Workflow, job, and step environment shadowing is explicit: `${{ env.NAME }}` re-expansion remains generated code, while native shell variables and `process.env` remain data-only counterevidence.
- Kept execution capability separate from privilege impact. Ordinary `pull_request` injection remains reportable code execution but does not inherit secret or write-token categories merely because the workflow text mentions them; default-branch-capable events require exact effective permission and structural secret/token evidence. Read-only permissions, review-label gates, and deployment environments remain candidate controls rather than silent sanitizers.
- Added paired `pull_request_target`/GitHub Script fixtures, a perfect-gate manifest, a harmless executable substitution witness, 11 focused regressions, reviewer guidance, CI execution, and documentation. The positive injects a second JavaScript statement and observes a mock release token; the control supplies the identical bytes through an intermediate environment value and logs one inert `process.env` string. The focused lane passes 11 tests and 95 assertions; all five GitHub Actions lanes pass 51 tests and 284 assertions, and all five executable witnesses pass. The complete authoritative scanner suite passes 780 tests and 6,575 assertions across 105 files with 19 intentional environment-specific skips and no failures. Deterministic fixture review emits exactly the vulnerable same-workflow expression-compilation path, no native-environment control hypothesis, and no production-source hypothesis. A fresh-key 128-commit self-scan examines 1,126 current plaintext files plus 2,440 reachable historical blobs totaling 56,269,962 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 207-entry archive passes strict inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin file checks.
- Added a strict cross-file GitHub Actions CWE-094/CWE-095/CWE-116 model for an externally influenced default-branch event field forwarded through an exact workflow step into a literal repository-local composite action and then interpolated into a runnable `run` script or official `actions/github-script` source. Trigger, caller field, action directory, descriptor identity, declared input, step-local environment alias, sink, permission, explicitly forwarded secret, and control provenance remain explicit.
- Added exact composite metadata and interpreter boundaries. The scanner requires one unambiguous strict-YAML `action.yml` or `action.yaml`, required action name and description, a declared input description, `runs.using: composite`, and a real steps sequence. Direct `${{ inputs.NAME }}` and same-step input-derived `${{ env.NAME }}` expansion remain code generation; native shell or `process.env` reads remain data-only. Remote, expression-built, backslash, absolute, and parent-traversing targets, both-descriptor ambiguity, mismatched inputs, non-composite runtimes, shell-less `run`, ordinary action arguments, script-action lookalikes, cross-step environment assumptions, raw-comment secret evidence, malformed/duplicate/aliased metadata, and missing descriptors are rejected.
- Added paired issue-comment/composite-action fixtures, a perfect-gate manifest, a harmless executable JavaScript substitution witness, ten focused regressions, reviewer guidance, CI execution, and documentation. The positive injects a second JavaScript statement and observes a mock explicitly forwarded release token; the control supplies the identical payload through the same step's environment and logs it as one inert `process.env` value.
- The composite-action lane passes 10 focused tests and 54 assertions; the four adjacent GitHub Actions lanes pass 40 tests and 189 assertions. All four executable witnesses pass. The complete authoritative scanner suite passes 769 tests and 6,480 assertions across 104 files with 19 intentional environment-specific skips and no failures. Deterministic fixture review emits exactly the vulnerable workflow-to-action expression-compilation path and no native-environment control hypothesis, while production source emits no composite-action injection hypothesis. A fresh-key 128-commit self-scan examines 1,121 current plaintext files plus 2,424 reachable historical blobs totaling 55,538,232 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 207-entry archive passes strict inspection, two isolated installations, public import, CLI, and all 79 bundled-plugin file checks.
- Added a strict cross-file GitHub Actions CWE-094/CWE-095/CWE-116 model for an externally influenced default-branch event field forwarded through an exact local reusable-workflow job into a matching declared `workflow_call` string input and then interpolated into a called `run` script or official `actions/github-script` source. Trigger, caller field, target path, forwarded name, declaration, environment alias, sink, permission, secret, OIDC, and control provenance remain explicit.
- Added exact expression-timing and privilege semantics. Direct `${{ inputs.NAME }}` compilation and input-derived `${{ env.NAME }}` re-expansion remain unsafe even when quoted inside the generated program; assigning the expression once to an environment entry and reading it only with native shell syntax or `process.env` remains data-only counterevidence. Caller and called read-only permissions intersect as a ceiling, and a secret category requires both actual forwarding/inheritance and called-workflow use. Fixed or boolean-transformed caller values, trigger/field mismatches, pull-request-only callers, remote or dynamic targets, undeclared or non-string inputs, ordinary action inputs, lookalike script actions, fixed environment overrides, malformed/duplicate/aliased YAML, missing targets, and non-workflow paths are rejected.
- Added paired issue-comment/reusable-workflow fixtures, a perfect-gate manifest, a harmless executable `actions/github-script` substitution witness, ten focused regressions, reviewer guidance, CI execution, and documentation. The positive injects a second JavaScript statement and observes a mock inherited release token; the control supplies the identical payload through `process.env` and logs it as one inert value.
- Rejected a proposed broad cache-poisoning rule after current GitHub documentation showed that `pull_request_target`, `issue_comment`, and `workflow_run` receive read-only cache access in the default-branch scope and `pull_request` writes remain merge-ref scoped. Future cache analysis must prove a currently writable scope, attacker-controlled cached bytes, matching key/version/path semantics, and later trusted execution rather than reviving platform-blocked findings.
- The reusable-workflow lane passes 10 focused tests and 48 assertions; the three adjacent GitHub Actions lanes pass 30 tests and 135 assertions. All three executable witnesses pass. The complete authoritative scanner suite passes 759 tests and 6,426 assertions across 103 files with 19 intentional environment-specific skips and no failures. Deterministic fixture review emits exactly the vulnerable cross-file expression-compilation path and no native-environment control hypothesis, while production source emits no reusable-workflow injection hypothesis. A fresh-key 128-commit self-scan examines 1,110 current plaintext files plus 2,416 reachable historical blobs totaling 55,358,226 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 207-entry archive passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a cross-workflow GitHub Actions CWE-829 artifact-poisoning model that requires an unprivileged `pull_request` producer, official untrusted checkout, exact official upload name/path, matching privileged `workflow_run` consumer, official download bound to `github.event.workflow_run.id`, overlapping extraction path, and later executable command or local action. Producer workflow identity, artifact identity, action pins, source/upload/download/sink lines, and effective privileges remain explicit.
- Added strict state and control semantics for named and all-artifact downloads, symbolic `runner.temp` paths, workflow/job/step working directories, clean trusted checkout replacement, read-only consumer permissions, explicit secrets/OIDC, and write tokens. Producer success and artifact transport integrity do not imply trust; `runner.temp` isolation plus fail-closed typed-data parsing is counterevidence only when the artifact is not executed, while direct execution from that temporary path remains detectable. Name/run/token mismatches, uploads outside the untrusted checkout, unrelated paths, lookalike actions, malformed/duplicate/aliased YAML, and non-workflow files are rejected.
- Added paired pull-request producer/privileged consumer fixtures, a perfect-gate benchmark manifest, a harmless executable artifact-replacement witness, ten focused regressions, reviewer guidance, CI execution, and documentation. The exploit overwrites a trusted workspace script and observes a mock release token; the control isolates the same attacker bytes and rejects them as non-integer data without execution.
- Corrected trusted-checkout state clearing in the existing pwn-request model: `actions/checkout` now removes taint only when its effective `clean` setting is not false, preventing a false negative when a trusted checkout deliberately preserves downloaded or previously checked-out files.
- The artifact-poisoning and adjacent pwn-request lanes pass 20 focused tests and 87 assertions. The complete authoritative scanner suite passes 749 tests and 6,378 assertions across 102 files with 19 intentional environment-specific skips and no failures. Both executable witnesses pass; deterministic fixture review emits exactly the vulnerable cross-workflow execution and no isolated typed-data hypothesis, while production source emits no artifact-poisoning hypothesis. A fresh-key 128-commit self-scan examines 1,101 current plaintext files plus 2,399 reachable historical blobs totaling 54,772,809 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 207-entry archive passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a strict typed GitHub Actions CWE-829 model for `pull_request_target` workflows that explicitly fetch a fork pull request and later execute a command or local action from the same tainted workspace path. Exact trigger, checkout, ref, repository, step order, workspace, working directory, execution sink, permissions, credentials, secrets/OIDC, and control provenance remain explicit; a privileged trigger, checkout, or execution step alone is insufficient.
- Added current Checkout v7 semantics and bounded controls: default fork-checkout refusal is strong counterevidence unless `allow-unsafe-pr-checkout: true`, a later trusted checkout clears the affected workspace, and immutable SHA selection, read-only effective permissions, disabled credential persistence, review labels, and deployment environments remain separate reviewer leads. Official semver and pinned-commit Checkout references, fork-repository default branches, and workflow/job default working directories are modeled. Malformed or duplicate-key YAML, aliases, wrong workflow paths, `pull_request`-only triggers, trusted/base refs, unrelated workspaces, inline interpreter/version commands, fixed non-loading commands, and package installation with scripts disabled are rejected.
- Added paired privileged-workflow fixtures, a perfect-gate benchmark manifest, a harmless executable pwn-request/Checkout-v7 witness, ten focused regressions, Copilot reviewer guidance, CI execution, and documentation. The positive explicitly opts Checkout v7 into unsafe fork checkout and proves attacker-controlled code can observe a mock secret; the matched control proves default v7 protection stops before execution.
- The GitHub Actions lane passes 10 focused tests and 45 assertions. The complete authoritative scanner suite passes 739 tests and 6,336 assertions across 101 files with 19 intentional environment-specific skips and no failures. The executable witness passes, deterministic review emits the exact positive and protected-control paths, and production source emits no GitHub Actions hypothesis. A fresh-key 128-commit self-scan examines 1,092 current plaintext files plus 2,383 reachable historical blobs totaling 54,065,061 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 207-entry archive passes strict inspection, isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a typed Spring MVC/JPA CWE-915 mass-assignment model for an official `@ModelAttribute` domain object on a state-changing controller reaching the exact `CrudRepository` or `JpaRepository` `save` argument through same-file, one-service, or two-service Java paths. The persisted domain must resolve uniquely to an official JPA entity, and every type binding, call argument, wrapper parameter, source, sink, and control remains explicit.
- Added strict binding-control semantics: an applicable official `@InitBinder` and `WebDataBinder.setAllowedFields` or `setDeclarativeBinding(true)` is retained, while denylists, `@Valid`, authentication, role checks, disabled binding, GET handlers, DTO projection, replaced values, local framework/repository/entity shadows, domain mismatches, and ambiguous service identities cannot silently close or create the hypothesis.
- Added paired Spring Boot 4.1 MVC/Spring Data JPA/Hibernate/H2 fixtures, a perfect-gate benchmark manifest, real MockMvc persistence witnesses, nine focused regressions, reviewer guidance, Linux CI execution, and documentation. The exploit proves a submitted `administrator=true` field persists; the matched allowlist control proves the intended display name persists while the administrative field remains false.
- The mass-assignment lane passes 9 focused tests and 39 assertions; the adjacent Java/framework gate passes 43 tests and 188 assertions across seven files. Both Maven fixtures pass their real MockMvc/Hibernate/H2 witnesses. The complete rebuilt scanner suite passes 729 tests and 6,291 assertions across 100 files with 19 intentional environment-specific skips and no failures. Deterministic review emits exactly the vulnerable typed save path and paired allowlist control while emitting no production-source mass-assignment hypothesis. A fresh-key 128-commit self-scan examines 1,084 current plaintext files plus 2,362 reachable historical blobs totaling 53,388,170 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 203-entry archive passes isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a typed Spring Data object-authorization model for annotated or servlet-derived identifiers reaching official `CrudRepository` or `JpaRepository` `findById` and declared owner-qualified derived queries through same-file, one-service, or two-service Java paths. Exact source, type binding, argument, parameter, sink, and CWE-639/CWE-862 provenance remains explicit.
- Added strict object-control leads for same-query owner, tenant, customer, account, user, organization, or workspace fields bound to a real typed Spring Security `Authentication`, Java `Principal`, or official `SecurityContextHolder` value. Active exact `@PostAuthorize` return-object ownership policy is retained only on an official Spring-managed read method with enabled pre/post interception; authentication, role-only policies, inactive or shadow annotations, attacker owner values, and post-write checks do not close the hypothesis.
- Added paired Spring Boot 4.1/Spring Data JPA/Spring Security/Hibernate/H2 exploit and control fixtures, a perfect-gate benchmark manifest, executable cross-customer witnesses, focused regressions, reviewer guidance, and Linux CI coverage. The exploit retrieves another customer's invoice through `findById`; the control rejects the same key by binding `Authentication.getName()` in the declared `findByIdAndCustomerId` query.
- The Spring lane passes 10 focused tests and 37 assertions; the adjacent Java/framework gate passes 119 tests and 1,288 assertions across eight files with one intentional platform skip. Both Maven fixtures compile and their H2-backed witnesses pass. The complete rebuilt scanner suite passes 720 tests and 6,252 assertions across 99 files with 19 intentional environment-specific skips and no failures. Deterministic review emits exactly the vulnerable Spring Data lookup and paired principal-bound control while emitting no production-source Spring object-authorization hypothesis. A fresh-key 128-commit self-scan examines 1,066 current plaintext files plus 2,350 reachable historical blobs totaling 53,295,906 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 203-entry archive passes isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a typed ASP.NET Core/EF Core object-authorization model for `[FromRoute]`, `[FromQuery]`, and request-derived identifiers reaching typed `DbSet` or `DbContext` single-record lookups through same-file or uniquely resolved C# service paths. Exact source, type binding, argument, parameter, sink, and CWE-639/CWE-862 provenance remain explicit.
- Added exact resource-control leads for principal-bound owner, tenant, customer, account, user, organization, or workspace predicates in the same EF query and for enforced `IAuthorizationService.AuthorizeAsync(User, exactReturnedEntity, policy)` results. `[Authorize]`, authentication, EF tracking, opaque keys, attacker owner fields, untyped or shadow APIs, wrong-resource checks, and ignored authorization results do not close the hypothesis.
- Added real EF Core 8.0.29 exploit/control fixtures, a strict selected-run manifest, executable InMemory witnesses, seven focused regressions with 28 assertions, CI build/witness/advisory coverage, and reviewer guidance. The exploit returns another customer's invoice by primary key under `[Authorize]`; the paired query rejects the same cross-customer selection.
- The new ASP.NET lane and adjacent framework/residual-risk gate passes 110 tests and 1,272 assertions across eight files with one intentional platform skip. The complete rebuilt scanner suite passes 710 tests and 6,215 assertions across 98 files with 19 intentional environment-specific skips and no failures. Deterministic review emits exactly the vulnerable EF lookup and paired principal-bound control while emitting no production-source object-authorization hypothesis. A fresh-key 128-commit self-scan examines 1,048 current plaintext files plus 2,323 reachable historical blobs totaling 52,677,933 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 203-entry archive passes isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added a typed Node/TypeScript object-level authorization model for request-controlled record identifiers reaching `findById`, `findByPk`, `findOne`, `findFirst`, `findUnique`, and repository-style ID lookups. It preserves exact same-file and relative-module source/argument/parameter/sink paths with CWE-639/CWE-862 provenance.
- Added exact counterevidence for owner, tenant, account, customer, user, organization, or workspace filters bound to an authenticated-principal value in the same lookup, plus dominating post-lookup ownership or policy checks. Fixed or unused IDs, reassignment, attacker-controlled owner filters, unrelated principal text, UUID opacity, authentication alone, and comment/string pseudo-code do not close object authorization.
- Extended JavaScript wrapper and call parsing across bounded multiline declarations and invocations, restoring deterministic cross-file summaries after normal formatter wrapping. Added paired same-file and cross-file IDOR/control cases, a strict object-authorization manifest, 36 focused assertions, and reviewer guidance grounded in OWASP API1 and CWE-639.
- The complete rebuilt scanner suite passes 703 tests and 6,187 assertions across 97 files, with 19 intentional environment-specific skips and no failures. A deterministic self-review emits the vulnerable cross-file object lookup, its principal-bound control, and one existing post-lookup-authorized benchmark path, with no uncontrolled production-code hypothesis. A fresh-key 128-commit self-scan examines 1,028 current plaintext files plus 2,317 reachable historical blobs totaling 52,549,127 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, the production build, and the production advisory query are clean; the 203-entry archive passes isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Added module-identity-aware Axios SSRF discovery for default, namespace, TypeScript import-equals, CommonJS, and `axios.create(...)` clients. The model follows only the destination-bearing URL argument or request-config `url` property across bounded relative-module wrappers, including multiline and generic calls; request bodies, local shadows, and reassigned instances do not become URL flow.
- Added Axios-specific control leads for disabling absolute-URL override, redirect rejection, fixed destination selection, and relative-path validation. Comment-only lookalikes are excluded, and scanner guidance now distinguishes a fixed `baseURL` from authority and path confinement.
- Added paired Axios instance SSRF and fixed-destination fixtures plus a strict CWE-918 benchmark manifest. The vulnerable case proves that Axios's default absolute-URL behavior can override a server-owned base; the control maps exact keys to server-owned paths, sets `allowAbsoluteUrls: false`, and disables redirects.
- Extended deterministic secret discovery to credentials removed from the working tree but retained in reachable Git history. The default 128-commit horizon is configurable from 0 through 2048 in the SDK, CLI, saved recipes/history, and Windows/Linux GUIs; repeated rule/path/value occurrences across blobs collapse into one keyed identity with bounded opaque object provenance.
- Added a real-Git fragment-materialized history benchmark with deleted GitHub, GitLab, and generic refresh credentials, placeholder/public-key controls, revision deduplication, perfect precision/recall gates, and proof that materialized values never enter inventory or report. Boundary regressions cover shallow horizons, immutable path scopes, disabled/non-Git/unavailable states, and numeric validation.
- Rejected multi-segment uppercase credential environment-variable references such as `SERVICE_ACCESS_TOKEN` from the generic entropy rule. This closes the three redacted false positives found in historical scanner tests without allow-listing test paths or weakening provider-specific credential detection.
- Added a deterministic pre-model secret-candidate engine for typed GitHub, GitLab, Slack, Stripe, npm, PyPI, SendGrid, Google, AWS, private-key, and high-entropy assigned credentials. Repository scans cover bounded plaintext; scoped and diff scans honor the immutable host path inventory.
- Added repository-scoped HMAC-SHA-256 candidate identity, structural redaction, private local JSONL reports, exact expiring justified baselines, strict link/path/size/key validation, CLI/SDK and Windows/Linux GUI baseline selection, and a fragment-materialized benchmark gated at perfect precision and recall. Candidate bytes are excluded from the detector's model inventory, report, baseline, diagnostics, and errors.
- Extended typed ASP.NET template-injection discovery to RazorLight runtime compilation. The model proves a real imported or fully qualified engine receiver, preserves `CompileRenderStringAsync`'s key/content/model argument roles including reordered named arguments, and follows the exact second `content` argument across controller/service boundaries.
- Added paired RazorLight exploit/control fixtures, executable .NET 8 witnesses, a strict CWE-1336 manifest, scanner guidance, and CI coverage. It rejects fixed content with attacker-controlled model data, key-only flow, `CompileRenderAsync` project-template resolution, reassignment, untyped receivers, local engine shadows, incomplete builders, and comment/string lookalikes. Explicit patched dependency floors keep RazorLight's legacy caching and JSON transitives outside two high-severity advisory ranges, and a machine-readable CI gate fails on any future direct or transitive NuGet vulnerability.
- Added a typed, execution-aware ASP.NET-to-Scriban server-side template-injection model. It preserves the exact controller source, unique C# service type, call argument, wrapper parameter, bounded local aliases, the first `Template.Parse` source argument, and subsequent `Render`/`RenderAsync` dispatch while rejecting inert parsing, render-only data, second-argument source metadata, reassignment, missing imports, local `Template` shadows, and comment/string lookalikes.
- Added paired ASP.NET Scriban exploit/control fixtures, a strict CWE-1336 benchmark manifest, executable .NET 8 witnesses pinned to Scriban 7.2.5, scanner guidance, and CI coverage. The vulnerable witness proves attacker template source can disclose a server-owned model secret; the matching fixed-template witness proves the same delimiter text remains non-recursive render data.
- Added execution-aware Java OkHttp SSRF modeling for imported and fully qualified clients, request-builder aliases, inline requests, directly constructed clients, and prepared `Call` values that are later executed or enqueued.
- Rejected inert request construction, unexecuted `newCall` values, unrelated execution statements, reassigned calls and inputs, unrelated builders, and local type shadows to keep OkHttp coverage precise.
- Added vulnerable and safe OkHttp benchmark fixtures, executable Maven witnesses using OkHttp 5.3.0, a strict benchmark manifest, regression tests, scanner guidance, and Java CI coverage.

### Resilience

- Added an exclusive, results-directory-scoped benchmark runner lock before campaign creation, resume, scan, finalization, or report mutation. A second live process now fails immediately with the owning PID and start time instead of launching duplicate scans or racing canonical output promotion. Normal and process-exit cleanup are token-bound so an old process cannot remove a replacement owner's lock.
- Added fail-closed stale-owner recovery. A well-formed lock whose PID is no longer alive is reread for stability, archived intact under `.benchmark-runner-locks/`, and replaced through exclusive creation; malformed, oversized, symlinked, permission-denied, PID-reused, or otherwise unverifiable state is never deleted automatically. Campaign bootstrap recognizes only these two operational entries, preserving the rule that unrelated unprovenanced results cannot enter a fresh campaign.
- The hardening follows a live timeout/resume failure in which the first host command reached its 20-minute ceiling but its runner process tree continued. A resumed runner completed a substantively perfect Java evaluation, while both surviving processes later attempted to promote the same canonical run directories and one invocation exited nonzero on collision. The new single-writer boundary prevents that class of orphan/resume race without overwriting either attempt. Focused campaign and runner recovery coverage passes 20 tests and 110 assertions, including active-owner refusal before mutation, dead-PID archival, malformed-state retention, archive-directory lookalike rejection, ownership-token changes, normal release, SARIF propagation, atomic finalization, and retry preservation. The authoritative Windows suite passes 1,125 tests with 19 intentional environment/integration skips, no failures, and 8,562 assertions across 120 files.
- Formatting, generated-model drift, TypeScript checking, the clean production build, and the production advisory query are clean. Strict package inspection validates 251 entries, two isolated installations, public import, CLI behavior, and all 79 bundled-plugin files. The removed 1,481,476-byte archive had SHA-1 `9a8457d2005435dec70d7a89c9f5ee899f00ced7`, SHA-256 `1e34e5d7bb79a75f31c9f3f4025e28e294cb5cc4b7a8def287151ad68efaf923`, and integrity `sha512-0Qbq4WNIEHb53J++8lMUv1RMxjf/sc4ur6jU8xBEHgaCbRPLv9jdaa8t7aPmOd1PzXh1ZA9NfeG/JVV3sMJsTw==`. Windows GUI acceptance builds without warnings/errors, passes seven core plus three shared tests, and publishes a fresh 346,796-byte executable with SHA-256 `c5ca5c6ed00b47d998df3d2a5313a7f6e562498f1aa34ca57e8d0de472006f2c`. WSL Ubuntu builds without warnings/errors; passes seven core, three shared, and two headless tests under a Linux-only PATH; and passes non-graphical plus X11/Xvfb startup. The 72,568-byte Linux executable has SHA-256 `53c4e49e6f0aecdafec913a4d5b2423d70503f35db12c5228c0e25768fc6421d`.
- Hardened history discovery around the trusted host Git boundary: repository-supplied executables and ambient Git controls are excluded, system/global configuration, replacement objects, lazy fetching, optional locks, pagers, and shells are disabled, while the one canonical target root is supplied as an exact command-line `safe.directory`. Blobs are type/size checked before bounded batch reads, and every missing-tool, dubious-ownership, malformed-object, timeout, path, byte, object, blob, occurrence, or provenance cutoff becomes explicit incomplete history rather than a clean result.
- Made the cross-platform state-link regression assert rejection at the first host safety gate instead of depending on a later canonical-containment diagnostic, and widened the PDF/DOCX extraction fixture's per-case ceiling for slow Windows CI cold starts without weakening its content checks.
- Upgraded the direct and AJV-resolved `fast-uri` dependency from 3.1.4 to 3.1.5 after the production audit identified high-severity host confusion through a backslash authority introducer (`GHSA-7p8r-x3mc-p8w7`). The patched lock graph now passes the high-severity production advisory gate with no known vulnerabilities.
- Replaced the single closure-repair turn with three bounded, host-re-audited repair attempts. Each attempt receives only the newest deterministic coverage and finding-quality gaps, exits immediately on verified closure, preserves transport failures as causal errors, and still fails closed after the finite budget.
- Added explicit coverage-serialization invariants to both correction and repair prompts: one parseable JSON object, no trailing bytes, exact immutable inventory paths, and only canonical scalar dispositions. Broad repairs must use a real JSON serializer, validate the exact path set and count, and atomically replace the document; regex, `perl`, `sed`, `awk`, textual comma insertion, and concatenation are forbidden for JSON repair.
- Added a host-owned direct-review proof gate. Only a successfully completed built-in `view` of an exact staged-repository file can close its immutable inventory path; failed views, shell commands, MCP lookalikes, out-of-root paths, coverage labels, receipts, summaries, and model-authored dispositions cannot manufacture review evidence. Review proof resets for every fresh Copilot session.
- Added review-aware gap metadata and a read-once inventory protocol. Correction turns distinguish already-proven file review from missing review, repair `label`-versus-`path` coverage shape without replaying code, preserve prior progress across compaction, and reopen only failed views or narrow candidate/proof ranges instead of the entire inventory after every artifact operation.
- Bound `coverage.mode` to a trusted host-selected runtime value for repository, deep-repository, scoped-path, branch-diff, and working-tree scans. The deterministic closure auditor now emits an exact expected/actual synthetic mode gap, so a structurally complete draft is corrected before final sealing instead of failing after its repair budget has already ended.
- Kept the OkHttp typed fallback bounded to a confirmed request-construction-to-network-dispatch path so incomplete or ambiguous code does not become a synthetic finding.
- Made Linux and Windows scan turns independent of shell environment expansion by attaching an allow-listed, JSON-escaped map of exact non-secret host paths to the initial, quality-correction, and closure-repair prompts. Built-in file tools now own repository reads and draft-artifact writes on every platform.
- Hardened runtime-value prompt framing against control characters, tag-like strings, unknown scanner-prefixed values, and unrelated secrets, and added regressions proving exact POSIX and Windows path delivery without path-driven prompt structure.
- Corrected finding-quality closure to recognize canonical short `codeEvidence` IDs in validation evidence, data-flow endpoints, and nested attack-path steps while recursively rejecting unknown `evidenceRefs`. This removes a false failure without relaxing repository grounding, CWE, reachability, counterevidence, or broken-control gates.
- Recovered an omitted coverage `disposition` from an exact canonical `outcome` or `status` alias without inventing review results. Ambiguous aliases still fail closed as `needs_follow_up` and force partial coverage; canonical `disposition` values retain precedence.
- Precreated the fixed, private scan-contract directory skeleton in the trusted host before model execution and assigned stable IDs to the required deep-discovery passes. This removes avoidable parent-directory tool failures without creating draft files, receipts, ledgers, reports, or evidence on the model's behalf.
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

- Final acceptance for Joblib report closure and benchmark build provenance is
  green at exact checkpoint
  `2c5f2ce1e5b18c47a0e0030196922742d2d856fb`. The production advisory audit
  reports no known vulnerabilities. A fresh 259-entry, 1,867,960-byte archive
  with SHA-256
  `ef34269e17817524d22ff1861bacfc65c050336144dd8efa38912d7d37149823`
  passed two isolated 67-package installs, public import, CLI, and all 79
  bundled-plugin file checks before its unique temporary directory was
  removed. Exact-source hosted runs pass for Node `32845476828`, Windows GUI
  `32845476873`, Linux GUI `32845476864`, Go fixtures `32845476802`, Java
  fixtures `32845476755`, and .NET fixtures `32845476877`. The Node matrix is
  green on Ubuntu Node 22, 24, 24.0.0, 26, and 26.0.0, Windows Node 22, and
  macOS Node 22.
- The Axios lane's six focused regressions pass 31 assertions; the broader SSRF and residual-model gate passes 82 tests and 1,156 assertions with one intentional skip. The complete rebuilt scanner suite passes 696 tests and 6,144 assertions across 96 files, with 19 environment-specific skips and no failures. A deterministic self-review emits exactly the vulnerable and controlled Axios benchmark paths and no production-code Axios hypothesis. A fresh-key self-scan examines 1,018 current plaintext files plus 2,302 reachable historical blobs totaling 52,004,864 bytes, reports zero candidates, and completes without truncation. Formatting, generated-model drift, TypeScript checks, and the production advisory query are clean; the 203-entry archive passes isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- The reachable-history corpus recovers all three deleted credentials with zero false positives or false negatives and deduplicates one credential across distinct blobs. A fresh-key 128-commit self-scan examines 1,008 current plaintext files plus 2,274 unique historical plaintext blobs totaling 51,094,954 bytes; it reports zero candidates, complete history, and no truncation after the environment-reference control. The complete scanner suite passes 690 tests and 6,113 assertions across 95 files, with 19 environment-specific skips and no failures. Formatting, generated-model drift, TypeScript checks, and the production advisory query are clean; the 203-entry archive passes isolated installation, public import, CLI, and all 79 bundled-plugin file checks. Windows and Linux GUI builds remain warning-free, with shared desktop, Windows core, and Linux headless tests passing 3/3, 7/7, and 2/2.
- The deterministic secret corpus reports 14/14 true positives, zero false positives, and zero false negatives; a no-baseline self-scan of 1,005 scanner plaintext files reports zero candidates and no truncation after semantic fixture/expression controls. The complete scanner suite passes 686 tests and 6,063 assertions across 93 files, with 19 environment-specific skips and no failures. Windows and Linux GUI builds are warning-free; shared desktop, Windows core, and Linux headless tests pass 3/3, 7/7, and 2/2. The production advisory query reports no known vulnerability, and the 203-entry archive passes isolated installation, public import, CLI, and all 79 bundled-plugin file checks.
- Built both RazorLight Web SDK fixtures without warnings on .NET 8, ran the exploit and fixed-source witnesses against the patched graph, and confirmed the official advisory query reports no vulnerable direct or transitive packages. The Linux CI JSON predicate returns false for the real clean graph and true for a synthetic vulnerable transitive. The complete scanner suite passes 678 tests and 5,997 assertions across 91 files, with 19 environment-specific skips and no failures; the 199-entry archive passes isolated installation, public-import, CLI, and all 79 bundled-plugin file checks.
- Built both new ASP.NET Scriban fixtures on .NET 8, executed the vulnerable secret-disclosure and fixed-template witnesses successfully, and verified against the official NuGet advisory feed that the direct and transitive Scriban 7.2.5 graph has no known vulnerable packages. The complete scanner suite now passes 674 tests and 5,969 assertions across 90 files, with 19 environment-specific skips and no failures; the final 199-entry archive also passes isolated installation, public-import, CLI, and all 79 bundled-plugin file checks.
- Investigated the only failing job from the post-change CI matrix: all platform, container, GUI, and other Node jobs passed, while the designated Node 22 dependency-audit job rejected `fast-uri` 3.1.4 under `GHSA-7p8r-x3mc-p8w7`. Resolving the graph to 3.1.5 updates both the direct dependency and AJV edge, and a fresh production audit reports no known vulnerabilities. The resulting 199-entry public archive also passes isolated installation, public-import, CLI, and all 79 bundled-plugin file checks.
- Self-scanned the packaged production TypeScript, bundled workbench, and Windows/Linux desktop source across an exact 88-file scope. Copilot directly opened all 88 inventory paths over 61 assistant turns and six stable discovery passes, completed 150 tools, had one correctly denied out-of-scope temporary-file read, resolved `auto` to `gpt-5-mini`, reported zero premium requests and no session/quota/credit-limit/refusal error, and recorded 27.110705 AIU-equivalent usage.
- The same self-scan correctly failed closed: its finding-quality inventory had zero gaps and it produced no findings, but a line-oriented final repair appended trailing data to `coverage.json`, misspelled paths, and emitted object-valued dispositions. The host rejected the unreadable coverage as 88 unresolved surfaces rather than treating file access or a model-written `complete` claim as proof of review. This evidence motivated the bounded serialization-safe closure loop above.
- A second packaged self-scan exposed the complementary false-completion case: it exited with 88 canonical `rejected` surfaces and zero deterministic gaps even though session telemetry proved that Copilot directly opened 0 of the 88 production files. The session completed 41 assistant turns and 42 successful tools, reported zero premium requests and no session error, and used 15.390385 AIU-equivalent. This result is retained as negative acceptance evidence and motivated the host-owned direct-review gate above.
- A third packaged self-scan with direct-review enforcement proved all 88 production paths were directly opened, but hit the explicit one-hour acceptance ceiling instead of falsely completing. Its 68 assistant turns performed 2,681 built-in views and 2,694 successful tools, repeatedly replaying almost the entire inventory before artifact writes; 13 failed built-in grep calls traced to Copilot CLI 1.0.78-3 retaining an unavailable 1.0.77 ripgrep path. The preserved draft also used `path` instead of required coverage `label`, leaving 88 exact-path gaps. The session reported zero premium requests, no session error, and 27.919905 AIU-equivalent. This bounded liveness evidence motivated the review-aware no-replay protocol above.
- A five-file packaged production scan demonstrated the no-replay improvement: all five exact paths were directly viewed, only 28 total views were attempted instead of the broad run's 30.5 views per path, and exact `label` coverage reconciled to zero gaps in 6m48s. It still failed closed because the model selected repository mode instead of host-required `scoped_path`, motivating deterministic mode binding.
- Repacked with mode binding and repeated the identical five-file deep scan. It completed successfully in 8m53s after repair 1/3, with 5/5 exact direct views, 19 total views, 35 assistant turns, 36 successful tools, one correctly denied out-of-scope read, no session error, zero premium requests, and 10.880370 AIU-equivalent. Coverage was complete `scoped_path` with zero gaps/deferred work and exact labels; all 10 sealed artifact hashes independently reproduced and the SARIF export was nonempty.
- Installed and verified native Linux Node.js 22.23.1, Copilot CLI 1.0.77, GitHub CLI authentication, and `bubblewrap` 0.9.0 in Ubuntu 24.04 WSL 2 without using Windows-mounted runtime shims.
- Verified that a native Copilot request succeeds with `auto`, while an unavailable explicit model fails as a catalog mismatch rather than an allowance error. A live deep scanner run resolved to `gpt-5-mini`, reported zero premium requests, completed 38 model turns and 48 successful sandboxed tool operations, and returned no session, authentication, quota, credit-limit, or rate-limit error.
- Demonstrated the Linux orchestration improvement on the intentionally vulnerable multi-hop OkHttp fixture: the pre-fix run could not create canonical drafts and retained four coverage gaps; the exact-path run created all drafts, closed coverage to zero gaps, and produced the expected high-confidence CWE-918 finding. Re-auditing that preserved finding with the corrected semantic evidence gate returns zero quality gaps.
- Reinstalled the exact inspected release tarball into an isolated WSL runtime and completed a native deep scan in 4m11s. It produced the expected high-confidence CWE-918 source-to-propagator-to-sink trace, sealed hashed findings/coverage/report/ledger artifacts, exported SARIF, and reported zero premium requests. The run also exposed one recoverable model-shape defect: `pom.xml` carried canonical `status: no_issue_found` without the required duplicate `disposition`, so the fail-closed finalizer correctly left coverage partial and motivated the exact-alias recovery above.
- Repacked and reinstalled the corrected archive, then repeated the native deep scan in a fresh WSL output directory. The scanner exited successfully with complete coverage, no deferred work, one high-confidence CWE-918 finding, zero finding-quality gaps, a nonempty SARIF export, and independently reproduced hashes for every sealed artifact. The 32-turn Copilot session resolved `auto` to `gpt-5-mini`, recorded zero premium requests, no session error, 38 successful sandboxed tool calls, and 11 recovered not-yet-created parent/file attempts for follow-up orchestration optimization.
- Revalidated the native WSL package with a non-graphical smoke test and a real WSLg window open/close test, plus 7/7 core tests, 3/3 shared-desktop tests, 2/2 headless Linux UI tests, and clean Windows and Linux GUI builds.
- Expanded the scanner regression suite to 670 passing tests with 5,949 assertions across 89 files; 19 environment-specific tests remain explicitly skipped and no test fails. Formatting, generated-model drift, and TypeScript checks are clean.
