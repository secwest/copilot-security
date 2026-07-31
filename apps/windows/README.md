# Copilot Security for Windows

This directory contains the native Windows desktop interface and its separately
testable execution core. The application is a WPF `.NET 8` client for the
standalone scanner; it does not reimplement security analysis or make model
calls itself. It builds an exact argument list for the scanner CLI, supervises
that process, and validates the scanner's sealed artifacts before displaying
them.

## Capabilities

- standard and deep whole-repository scans;
- scoped path, committed-diff, and working-tree targets;
- selectable Copilot model, reasoning effort, and authentication mode;
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
counts must match before a comparison is accepted. Campaign-aware reports must
both include provenance and have identical `corpusId` and `scanPolicyId` values;
this binds fixture and manifest bytes, the exact case/run selection, and the
model/mode/effort policy while allowing the scanner implementation and
authentication source to differ. Per-case expectation and run counts must also
match. Two legacy reports without campaign provenance remain comparable, but a
provenanced report cannot be compared with an unprovenanced one.

## Architecture and trust boundaries

```text
WPF views / view model
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
preferences live in `gui-runs`, `gui-benchmarks`, and `gui` below that private
runtime directory. The command builder refuses a state or result tree that
overlaps the repository being scanned and rejects reparse-point ancestors that
could turn a lexically separate path into the same physical tree.

The artifact reader bounds every input, rejects reparse-point artifacts,
requires completed scan status and the expected document types, and recomputes
the manifest SHA-256 values for `findings.json` and `coverage.json` using a
fixed-time comparison. A canceled, failed, malformed, incomplete, or tampered
run is not presented as a completed scan. Partial files remain available for
diagnosis.

Preferences contain paths and ordinary scan defaults only. They never contain
credentials. Writes use a same-directory temporary file, write-through flush,
and atomic replacement.

## Prerequisites

- Windows 10 or later;
- .NET 8 Desktop Runtime (or the .NET 8 SDK for development);
- Node.js 22.13 or a supported newer release;
- GitHub Copilot CLI authenticated on the machine; and
- a built or installed `copilot-security.mjs` entry point.

The development checkout is auto-detected when the application is launched
from this repository. Packaged installations can set the three runtime paths
on the **Diagnostics & settings** tab.

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
