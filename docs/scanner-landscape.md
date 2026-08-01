# Scanner landscape and improvement roadmap

This document records ideas worth adopting from mature security scanners and
the constraints for integrating them without turning Copilot Security into an
unverifiable alert aggregator. It is a living engineering backlog, not a claim
that dissimilar products can be reduced to one score.

## Design principles extracted from other scanners

| Scanner or ecosystem                                                                                                         | Useful design                                                                                                                                                      | Copilot Security application                                                                                                                                                          |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)                          | A result is stronger when it explains a source-to-sink path rather than naming only a suspicious line.                                                             | Preserve SARIF code-flow locations as source/evidence/sink hints, then independently validate the exact data flow and controls.                                                       |
| [CodeQL data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)                 | Local and global flow have different precision, performance, and completeness tradeoffs.                                                                           | Keep deterministic full-file inventory separate from expensive cross-file/deep passes; report deferred closure rather than silently narrowing scope.                                  |
| [CodeQL custom models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-cpp/)            | Framework-specific source, sink, summary, barrier, and threat models extend coverage beyond built-in libraries.                                                    | Add a future bounded, typed framework-model format that augments discovery without allowing repository prompt injection.                                                              |
| [Semgrep taint rules](https://semgrep.dev/docs/writing-rules/glossary)                                                       | Explicit sources, sinks, propagators, and sanitizers make taint assumptions reviewable; cross-file and per-file analysis have distinct guarantees.                 | Preserve model provenance and demand source/control/sink closure for imported candidates. Build regression fixtures for custom propagators and sanitizers.                            |
| [Sonar security rules](https://docs.sonarsource.com/sonarqube-server/user-guide/rules/security-related-rules)                | Taint vulnerabilities and review-required security hotspots are different evidence classes. Sonar also supports custom sources, sanitizers, validators, and sinks. | Treat all imported results as candidates, not findings. Validation decides reportable, rejected, or deferred; a hotspot cannot inherit vulnerability status merely from its producer. |
| [OSV-Scanner](https://google.github.io/osv-scanner/usage/) and [call analysis](https://google.github.io/osv-scanner/output/) | Extract dependencies deterministically, match authoritative advisories, and use call information to distinguish called from apparently unused vulnerable code.     | Add deterministic SBOM/lockfile inventory and advisory ingestion, then use Copilot for repository-specific reachability, compensating controls, and remediation boundary analysis.    |
| [Trivy repository scanning](https://www.trivy.dev/docs/latest/guide/target/repository/)                                      | One repository pass can cover vulnerable dependencies, misconfiguration, secrets, and licenses.                                                                    | Accept these result families through SARIF now; later add opt-in local adapters while keeping each family’s evidence and completion semantics distinct.                               |
| [Trivy SARIF reporting](https://trivy.dev/docs/latest/configuration/reporting/)                                              | SARIF 2.1.0 is a practical interchange format across vulnerability, misconfiguration, secret, and license scanners.                                                | Implement repeatable `--seed-sarif` intake rather than tool-specific parsers. Preserve normalized provenance and never copy a producer’s conclusion into canonical findings.          |
| [Trivy secret scanning](https://www.trivy.dev/docs/latest/guide/scanner/secret/)                                             | Built-in and custom rules, allow rules, path bounds, and explicit skip behavior reduce secret-scanning cost and noise.                                             | Future deterministic secret discovery must redact values before model access, preserve only local fingerprints, distinguish test fixtures, and make exclusions auditable.             |
| [Gitleaks](https://github.com/gitleaks/gitleaks)                                                                             | Full redaction, stable fingerprints, baselines, and scoped allowlists make high-volume secret findings manageable.                                                 | Extend false-positive feedback with expiring, justified fingerprint baselines; never persist or display raw secret material by default.                                               |
| [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)           | Stable rule IDs, relative paths, locations, severity/precision metadata, and partial fingerprints support interoperable alert tracking.                            | Normalize relative paths and rule metadata, but hash source documents locally and omit imported fingerprints because they may contain arbitrary or sensitive producer data.           |

## Implemented: hardened SARIF seed ingestion

The CLI and SDK accept repeatable `--seed-sarif` / `seedSarifPaths` inputs. The
Windows GUI exposes the same capability. An optional `--sarif-source-root`
maps absolute artifact paths produced from a separate checkout.

The host performs these steps before Copilot sees any imported candidate:

1. Require regular, non-symlink SARIF 2.1.0 files and bounded file, run,
   result, and location counts.
2. Parse strict UTF-8 JSON and reject malformed run or tool structures.
3. Ignore suppressed and baseline-absent results.
4. Map only primary and code-flow locations that resolve to regular files
   inside the current repository, with valid positive line ranges.
5. Extract bounded tool, rule, CWE, severity, and source-to-sink hints.
6. Deliberately omit result messages, source snippets, fixes, fingerprints,
   arbitrary properties, and embedded source. This prevents prompt injection
   and stops secret-scanner matches from becoming model input.
7. Store only normalized candidate JSONL plus source name, SHA-256 digest,
   counts, and tool provenance under the isolated scan artifact tree.
8. Merge every in-scope seed into the normal candidate ledger and require the
   same independent validation and attack-path closure as native discovery.

`benchmarks/sarif-seed-manifest.json` is the initial ensemble lane. Its
positive case should retain a seeded command injection; its negative case
feeds a high-severity false-positive process-execution seed that must be
rejected. Both source SARIF files contain hostile messages and fake credential
text, allowing artifact inspection to prove that the host removed those fields
before model execution.

The import does not execute another analyzer, trust imported severity, or
claim that a seeded tool completed its own coverage. Native inventory,
multi-pass discovery, residual-miss review, negative controls, deterministic
contract validation, and sealed outputs remain mandatory.

## Prioritized next improvements

1. **Typed framework security models.** Define a bounded provider-neutral
   schema for sources, sinks, sanitizers/barriers, propagators/summaries, and
   threat domains. Sign or hash external model packs, treat their strings as
   data, and benchmark each pack against paired positive and negative fixtures.
2. **Dependency and advisory reachability.** Build deterministic lockfile/SBOM
   extraction, accept OSV identifiers and fixed-version facts, and require a
   repository call/use path or explicit deployment exposure before escalating
   severity. Preserve uncalled/unknown rather than equating both with safe.
3. **Local secret candidate engine.** Run deterministic pattern and entropy
   checks without sending secret bytes to Copilot. Persist a keyed local
   fingerprint, rule, path, line, and redacted shape only. Support expiring
   justified baselines and negative-control fixtures.
4. **Configuration and IaC model packs.** Add deterministic parsers and typed
   checks for high-value Docker, Kubernetes, Terraform, CI, and cloud policy
   surfaces, then ask Copilot to evaluate deployment reachability and
   compensating controls.
5. **Seed-coverage receipts.** Make imported-candidate closure a workbench
   contract field, not only a ledger invariant, so a future host can prove the
   exact imported count that was reportable, rejected, deferred, or out of
   scope without relying on prose.
6. **Ensemble benchmark lanes.** Run native-only and native-plus-seed campaigns
   over the same selected manifest. Gate the integration on improved recall or
   completion without precision, evidence, validation, attack-path, stability,
   or negative-control regressions.
7. **Optional analyzer adapters.** Provide opt-in command adapters that invoke
   a locally installed analyzer with argument arrays, resource/time bounds,
   no shell, no network by default, and SARIF-only handoff. Keep analyzer
   installation and licensing outside the core scanner.

## Benchmark acceptance criteria

An integration is useful only when its comparative campaign demonstrates all
of the following:

- no decline in completion rate or negative-control pass rate;
- no precision or duplicate-rate regression outside configured tolerance;
- statistically useful recall or first-attempt recall improvement;
- every new true positive retains concrete code evidence, independent
  validation, and attack-path closure;
- imported false positives receive explicit rejected dispositions rather than
  disappearing during merge;
- repeated runs remain stable enough that improvement is not one lucky model
  sample; and
- source provenance, selection policy, model, scanner revision, and seed
  digests are recorded so the campaign can be reproduced.
