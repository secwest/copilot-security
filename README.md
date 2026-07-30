# Copilot Security

Copilot Security is a repository security scanner driven by the GitHub Copilot
CLI installed on the local machine. It combines deterministic inventory and
artifact validation with threat modeling, multi-pass discovery, exploit
validation, attack-path analysis, canonical JSON, SARIF/report generation,
scan history, diff scanning, bulk scanning, and finding management.

Production scans use GitHub's official `@github/copilot-sdk` to control the
system `copilot` executable.

## Status

This is an early standalone Secwest scanner. Standard repository, path,
committed-diff, and working-tree scans use a Copilot-native plugin and runtime.
Deep mode uses repeated independent Copilot subagents and adds explicit
systems, supply-chain/configuration, business-logic, control-differential, and
compositional/temporal attack-path, and residual-miss review lenses before
centralized validation.

Every scan also receives a mandatory independent correction turn. The host
builds a bounded, prioritized residual-risk inventory from exact source
locations across common application, systems, infrastructure, and CI
languages. Overlapping hits are coalesced into bounded evidence windows, and
category and file diversity are preserved before the remaining prompt budget
is filled by risk priority. Repository-controlled excerpt bytes are
base64-encoded before entering the correction prompt, path and line ranges
remain structured, and prompt metacharacters in all host inventories are
escaped. The correction turn reopens the source, traces each signal through
attacker control and nearby guards, adds missed exploitable defects, and
rejects safe or mitigated flows. This supplements model-led discovery without
treating lexical matches or repository-written scanner instructions as
findings or control flow.

The correction turn also receives a deterministic reconciliation of
`in_scope_files.txt` against the draft coverage document. This catches omitted
files even when they contain no known lexical risk signal. The host repeats the
same reconciliation while sealing: an unreviewed inventory path is added as
explicit deferred work and coverage is downgraded to `partial`, so a
model-written `complete` claim cannot conceal a coverage gap.

The host separately audits every draft finding before that correction turn.
It lists missing CWE assignments, absent or unanchored code evidence, weak
validation, weak attack paths, and validation or attack-path dispositions that
contradict reportability. Copilot must either repair each row from repository
evidence or remove it from `findings.json` and close coverage accurately. This
prevents a structurally valid but evidentially empty finding from silently
surviving the model-to-contract boundary.

After the correction turn, the host rebuilds both the coverage-gap and
finding-quality inventories from the files Copilot actually wrote. If any gap
remains, Copilot receives one bounded repair turn containing only the
outstanding host inventories. The host then audits the files again and fails
closed instead of reporting completion when a gap persists or the closure
state cannot be read. The first correction turn's existing artifact-recovery
path remains available for a transport failure after all drafts were written;
an unsuccessful deterministic closure audit does not use that escape hatch.

Recoverable Copilot model-call failures are retried by the CLI inside the
existing turn, with a fixed two-retry ceiling. The host does not resubmit the
scan or correction prompt, so a transient retry cannot duplicate completed
tool work. Tool, system, user-input, terminal, and transport failures remain
visible to the normal failure and artifact-recovery paths. Startup and session
creation are cancellation-aware, and a partially started CLI runtime is
gracefully stopped or force-stopped before the original error is returned.

## Requirements

- GitHub Copilot CLI, installed and signed in (`copilot login`)
- Node.js 22.13+, 24, or 26
- Python 3.10+ (`tomli` is also needed on Python 3.10)
- Git

The scanner uses the installed CLI found on `PATH`. Set `COPILOT_CLI_PATH` or
the SDK `copilotPath` option to select another executable.

## Scan history

`copilot-security scans compare BEFORE_SCAN_ID AFTER_SCAN_ID` automatically
matches findings by root cause, reuses saved matches, and identifies new,
persisting, reopened, resolved, or unknown findings. Missing findings remain
unknown when the later scan is incomplete or their original location was not
reviewed.

## Build and run

```powershell
cd sdk/typescript
npx --yes pnpm@11.9.0 install
npx --yes pnpm@11.9.0 run build
node ./bin/copilot-security.mjs scan C:\path\to\repository --auth github
```

Common scan forms:

```powershell
# Whole repository
node ./bin/copilot-security.mjs scan C:\code\project

# Selected paths
node ./bin/copilot-security.mjs scan C:\code\project --path src --path server

# Committed diff
node ./bin/copilot-security.mjs scan C:\code\project --diff origin/main

# Staged and unstaged changes
node ./bin/copilot-security.mjs scan C:\code\project --working-tree

# Repeated independent discovery with centralized validation
node ./bin/copilot-security.mjs scan C:\code\project --mode deep
```

Use `--model` and `--effort` to select a Copilot model and reasoning effort.
The default is `gpt-5.6-sol` with `xhigh` effort.
Use `--max-ai-credits N` to have Copilot enforce a native credit limit across
the root session and its subagents. Copilot CLI requires at least 30 credits.

### Isolated scanner state

Copilot Security keeps its state under `~/.copilot-security` by default. Set
`COPILOT_SECURITY_HOME` to choose a different absolute scanner-owned root. Its
private runtime subdirectory is named `copilot-security-home`.

Scanner artifacts, locks, configuration, temporary directories, and output
roots remain outside every other scanner's state tree. `COPILOT_HOME` is read
only to obtain the user's existing Copilot CLI authentication and is copied
into the isolated `copilot-security-home` runtime when needed. The deprecated
`COPILOT_SECURITY_STATE_DIR` alias selects this scanner's state root only. This
separation lets multiple scanners run concurrently without sharing mutable
state.

## Effectiveness benchmark

`benchmarks/manifest.json` defines paired vulnerable and fixed fixtures for
command injection, path traversal, object-level authorization, SQL injection,
server-side request forgery, unsafe deserialization, reflected XSS, XML
external entities, JWT signature-verification bypass, prototype pollution,
disabled TLS certificate verification, predictable security tokens,
server-side template injection, check/use state races, and adversarial
repository instructions. Each of the 30 cases is scanned three times, producing
90 scans that measure both accuracy and model variance. The evaluator uses
one-to-one CWE-plus-location matching, counts duplicate reports as false
positives, and records missing scan artifacts as completion failures.

```powershell
# Evaluate existing outputs
node ./bin/copilot-security.mjs benchmark `
  ../../benchmarks/manifest.json `
  --results-dir C:\security-benchmarks\copilot-security `
  --format json

# Build fresh isolated Git repositories and scan the complete corpus
node ../../benchmarks/run-benchmark.mjs `
  --results-dir C:\security-benchmarks\copilot-security `
  --auth github `
  --mode deep
```

Use repeatable `--case <id>` options, `--runs 1`, and `--selection-only` for a
quick paired vulnerable/control diagnostic with its own durable report. Omit
`--selection-only` when a partial run should intentionally exercise the
full-corpus completion gate.

The measured gates cover completion, precision, recall, F1, exact-case and
negative-control passes, repeated-run stability, validation, attack paths,
code evidence, severity accuracy, and false positives per run. Validation,
attack-path, and code-evidence rates reject nonempty placeholder objects and
require substantive source-to-impact proof. See
[`benchmarks/README.md`](benchmarks/README.md).

## Container

The customer container includes both `copilot-security` and the official
`@github/copilot` CLI. It keeps the inherited noninteractive CSV bulk-scan
contract. The Compose service runs as an unprivileged user with dropped Linux
capabilities, `no-new-privileges`, and the inherited seccomp profile.

```bash
docker build -t copilot-security:local .
docker run --rm copilot-security:local --version

mkdir -p results state
printf 'id,repository,revision\n' > repositories.csv
GH_TOKEN=... docker compose run --rm copilot-security
```

The Compose interface uses `COPILOT_SECURITY_IMAGE`,
`COPILOT_SECURITY_USER`, `COPILOT_SECURITY_CSV`,
`COPILOT_SECURITY_RESULTS`, `COPILOT_SECURITY_STATE`, and
`COPILOT_SECURITY_GIT_HOST`. `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, and
`GITHUB_TOKEN` are accepted for noninteractive Copilot and GitHub access.

## Authentication

`--auth github` uses the login stored by the Copilot CLI and ignores ambient
token variables. `--auth token` requires one of:

- `COPILOT_GITHUB_TOKEN`
- `GH_TOKEN`
- `GITHUB_TOKEN`

`--auth auto` uses a token when one is present and otherwise uses the stored
Copilot login. Token values are passed only to the child Copilot process and
are never printed or copied into scan artifacts.

## TypeScript

```ts
import { CopilotSecurity } from "@secwest/copilot-security";

const scanner = new CopilotSecurity({
  copilotPath: "C:\\path\\to\\copilot.exe", // optional
  copilotOverrides: {
    model: "gpt-5.6-sol",
    reasoning_effort: "xhigh",
  },
});

try {
  const result = await scanner.run("C:\\code\\project", {
    auth: "github",
    mode: "standard",
    outputDir: "C:\\security-results\\project",
  });
  console.log(result.reportPath);
} finally {
  await scanner.close();
}
```

`CopilotSecurity`, `CopilotSecurityConfig`, and `copilotOverrides` are the
canonical SDK names. Scanner-owned environment variables use the
`COPILOT_SECURITY_*` prefix.

## Safety

Scans are report-only. The scanning prompt forbids modifying the target
repository, publishing findings, opening issues, committing, pushing, or
contacting third parties. Scan output must be outside the target repository and
its enclosing Git worktree. The Copilot CLI still receives normal local tool
permissions so it can inspect files and run bounded repository-native
validation; run only against repositories you are authorized to assess.

## License

Copyright and license terms are in [LICENSE](LICENSE).
