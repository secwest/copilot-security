# Copilot Security for Windows

This directory contains the native Windows desktop interface and the shared,
separately testable execution core. The application is a WPF `.NET 8` client for the
standalone scanner; it does not reimplement security analysis or make model
calls itself. It builds an exact argument list for the scanner CLI, supervises
that process, and validates the scanner's sealed artifacts before displaying
them.

## Capabilities

- standard and deep whole-repository scans;
- scoped path, committed-diff, and working-tree targets;
- selectable Copilot model, reasoning effort, and authentication mode;
- repeatable hardened SARIF 2.1.0 candidate imports with optional original
  checkout-root mapping;
- optional expiring, justified local secret-fingerprint baselines using the
  scanner's redacted pre-model candidate engine;
- bounded reachable-Git secret history from 0 through 2048 commits, defaulting
  to 128, with host-only object reads and no credential bytes in GUI state;
- optional cost and AI-credit ceilings, with no ceiling inferred by default;
- live progress, elapsed time, bounded output capture, cancellation, and
  process-tree termination;
- finding tables with severity, confidence, CWE, locations, validation,
  attack path, and remediation;
- full Markdown report display and native report opening;
- durable scan history under the scanner's private runtime home;
- corpus benchmark result evaluation and fail-closed status receipts;
- baseline/candidate benchmark comparison with metric and per-case regression
  gates; and
- runtime path and state-isolation diagnostics.

The comparison reader accepts version `1.0` benchmark reports whose document
type ends in `.benchmark`. This permits a compatible baseline scanner to be
measured on exactly the same manifest without coupling this application to its
brand, installation, credentials, or state tree. Case IDs, case counts, and run
counts must match before a comparison is accepted. New campaign-schema `1.1`
reports must both have identical `corpusId` and provider-neutral
`comparisonPolicyId` values. This binds fixture and manifest bytes, exact
case/run selection, mode, effort, and any explicit credit bound while allowing
provider model, scanner implementation, and authentication source to differ.
Those differing identities remain visible in the comparison and sealed by each
report's exact `scanPolicyId` and `campaignId`. Per-case expectation and run
counts must also match.

Two campaign-schema `1.0` reports remain comparable only under their legacy
model-bound `scanPolicyId`, and cannot be mixed with `1.1`. Two reports without
campaign provenance remain legacy-comparable, but a provenanced report cannot
be compared with an unprovenanced one.

## Architecture and trust boundaries

```text
WPF views
        |
        v
CopilotSecurity.Desktop
  - shared view model and durable settings
  - progress, history, findings, and benchmarks
        |
        v
CopilotSecurity.Core
  - path and state policy
  - argument-list construction
  - bounded process supervision
  - sealed artifact verification
  - history reader
  - benchmark comparison
        |
        v
Node.js -> copilot-security.mjs -> installed Copilot CLI
```

The GUI never invokes a command shell for a scan. `ProcessStartInfo.ArgumentList`
keeps every repository path, revision, and option a literal argument. The GUI
does not read, store, or copy Copilot tokens.

`StateRoot` defaults to `%USERPROFILE%\.copilot-security`. Scanner runtime
state is always below
`%COPILOT_SECURITY_HOME%\copilot-security-home`. GUI runs, benchmarks, and
scanner artifacts live in `gui-runs` and `gui-benchmarks` below that private
runtime directory. Executable and scanner-path preferences are stored instead
under `%LOCALAPPDATA%\Secwest\CopilotSecurity\gui`, outside the model-writable
scanner state tree. The command builder refuses a state or result tree that
overlaps the repository being scanned. It also refuses to execute a scanner
entry point from inside the target repository and rejects reparse-point
ancestors that could turn a lexically separate path into the same physical
tree.

Every GUI scan inherits the CLI's complete model boundary: an expendable
repository/plugin snapshot with links omitted into a manifest, a stripped
allowlisted environment, category-scoped permissions, disabled tool network
and credential forwarding, positive native-sandbox telemetry, and immutable
host-generated file/review/`SECURITY.md` inventories verified again before
sealing. The Windows native sandbox is treated as a public-preview layer; the
model uses built-in file tools for exact worklist reads and does not execute
Python, Git, ripgrep, or plugin helpers inside that sandbox.

The artifact reader bounds every input, rejects reparse-point artifacts,
requires completed scan status and the expected document types, and recomputes
the manifest SHA-256 values for every sealed artifact—including
`findings.json`, `coverage.json`, and `report.md`—using a fixed-time comparison.
A canceled, failed, malformed, incomplete, or tampered run is not presented as
a completed scan. Partial files remain available for diagnosis.

Preferences contain paths and ordinary scan defaults only. They never contain
credentials. Writes use a same-directory temporary file, write-through flush,
and atomic replacement.

## Prerequisites

- Windows 10 or later;
- .NET 8 Desktop Runtime (or the .NET 8 SDK for development);
- Node.js 22.13 or a supported newer release;
- GitHub Copilot CLI authenticated on the machine; and
- a built or installed `copilot-security.mjs` entry point.

The development checkout is auto-detected only by walking upward from the
application's installed base directory. The process working directory and the
repository selected for scanning are never searched for executable scanner
modules. Packaged installations can set the three runtime paths on the
**Diagnostics & settings** tab; the scanner entry point must remain outside the
target repository.

## Build and test

```powershell
dotnet build apps/windows/CopilotSecurity.Gui/CopilotSecurity.Gui.csproj `
  --configuration Release

dotnet run `
  --project apps/windows/CopilotSecurity.Core.Tests/CopilotSecurity.Core.Tests.csproj `
  --configuration Release
```

Publish a framework-dependent, single-file Windows executable:

```powershell
dotnet publish apps/windows/CopilotSecurity.Gui/CopilotSecurity.Gui.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained false `
  -p:PublishSingleFile=true `
  -p:DebugType=None `
  --output artifacts/windows-x64
```

Framework-dependent publication keeps the artifact small while allowing
Microsoft-serviced desktop runtime updates. A self-contained build can be
produced after selecting a runtime patch-management policy.

## Benchmark workflow

1. Run the complete manifest with three repetitions into an external results
   directory for the candidate measurement.
2. Run the same manifest, cases, and repetition count with the compatible
   baseline scanner and preserve its version `1.0` benchmark report.
3. In the GUI's **Benchmark** tab, select the baseline and candidate
   `benchmark-report.json` files and choose **Compare**.
4. Treat metric or per-case regressions as failures. Investigate changed
   TP/FP/FN rows before accepting an aggregate improvement.
5. Add every confirmed false negative and false positive to the corpus as a
   vulnerable/control pair, then rerun the pair before the full corpus.

The quality index is a transparent weighted summary for sorting experiments.
It cannot override the individual precision, recall, stability, evidence, or
per-case gates.

## Failure behavior and recovery

- Missing runtimes or invalid paths fail before process creation.
- Deep diff targets are rejected because deep analysis requires a repository
  or scoped-path target.
- Output beyond the bounded capture limit terminates the process tree and
  fails the run.
- User cancellation terminates the complete scanner process tree and retains
  partial output.
- Scanner nonzero exit status remains visible with the final bounded diagnostic
  lines.
- Invalid hashes, document types, JSON, completion state, or required files
  reject the result.
- Unexpected UI-thread errors produce a diagnostic and close safely rather
  than continuing in an unknown state.

For authentication and provider failures, use the full diagnostic in the
Progress tab. The scanner owns its native retry, refusal-reframing, deadline,
recovery, and fail-closed artifact logic; the GUI deliberately does not create
a second retry layer that could duplicate expensive scans.
