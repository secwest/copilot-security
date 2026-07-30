# `@secwest/copilot-security`

TypeScript SDK and CLI for the Copilot CLI-backed security scanner. See the
[repository README](../../README.md) for setup, usage, authentication, safety,
and attribution.

The package is ESM-only and provides:

- `copilot-security` CLI
- `CopilotSecurity` SDK class
- repository, path, committed-diff, and working-tree targets
- standard and deep multi-pass modes
- deterministic scan artifacts, Markdown report, SARIF, exports, history,
  reruns, comparison, bulk scans, and finding feedback
- cancellation and streamed Copilot usage/subagent events

```ts
import { CopilotSecurity } from "@secwest/copilot-security";

await using scanner = new CopilotSecurity({
  copilotOverrides: {
    model: "gpt-5.6-sol",
    reasoning_effort: "xhigh",
  },
});

const result = await scanner.run("/path/to/repository", {
  auth: "github",
  outputDir: "/path/outside/repository/results",
});

console.log(result.reportPath);
```

Configuration:

| Option                              | Meaning                                                               |
| ----------------------------------- | --------------------------------------------------------------------- |
| `copilotPath`                       | System Copilot CLI executable; otherwise `COPILOT_CLI_PATH` or `PATH` |
| `copilotOverrides.model`            | Copilot model, default `gpt-5.6-sol`                                  |
| `copilotOverrides.reasoning_effort` | `low`, `medium`, `high`, or `xhigh`                                   |
| `pluginPath`                        | Alternate Copilot Security plugin directory or ZIP                    |
| `pythonPath`                        | Python interpreter used by deterministic helpers                      |

Scan authentication accepts `"auto"`, `"github"`, or `"token"`. Output
directories must be outside the scanned repository and any enclosing Git
worktree. `maxAiCredits` maps to Copilot's native per-session AI-credit limit
and includes subagent use; Copilot CLI requires a limit of at least `30`.
Scanner-owned state is isolated under `COPILOT_SECURITY_HOME` (default:
`~/.copilot-security`). `COPILOT_HOME` is read only as the source of existing
Copilot CLI authentication; a private copy is prepared under the scanner-owned
`copilot-security-home` runtime directory. The deprecated
`COPILOT_SECURITY_STATE_DIR` alias selects this scanner's state root only.

### Runtime environment

| Variable                            | Purpose                                                                                      |
| ----------------------------------- | -------------------------------------------------------------------------------------------- |
| `COPILOT_SECURITY_HOME`             | Scanner-owned state, locks, configuration, runtime copy, and default results root            |
| `COPILOT_CLI_PATH`                  | Absolute path to the installed GitHub Copilot CLI                                            |
| `COPILOT_HOME`                      | Source location for existing Copilot CLI authentication; never used as mutable scanner state |
| `COPILOT_GITHUB_TOKEN`              | Highest-precedence noninteractive GitHub token                                               |
| `GH_TOKEN`                          | GitHub CLI-compatible token fallback                                                         |
| `GITHUB_TOKEN`                      | Generic GitHub token fallback                                                                |
| `GH_HOST`                           | GitHub Enterprise host used for repository discovery                                         |
| `PYTHON`                            | Python interpreter for deterministic contract and workbench helpers                          |
| `COPILOT_SECURITY_NO_UPDATE_NOTICE` | Disable the interactive package update notice                                                |
| `NO_COLOR`                          | Disable terminal styling                                                                     |
| `CI`                                | Select noninteractive behavior                                                               |

The default native Copilot configuration is equivalent to:

```toml
model = "gpt-5.6-sol"
model_reasoning_effort = "xhigh"

[features]
plugins = true
goals = true

[features.multi_agent_v2]
enabled = true
max_concurrent_threads_per_session = 9
```

Deep discovery computes bounded parallelism from the machine and Copilot
capacity. With 12 available processors its deterministic defaults are
`workers = 6`, `subagents = 3`, `stop_after_no_new = 6`, and
`max_discovery_runs = 60`. These are execution bounds, not substitutes for the
per-file and per-candidate closure requirements.

## Benchmarking scanner effectiveness

Use the read-only `benchmark` command to compare completed scan directories
with versioned ground truth:

```bash
copilot-security benchmark ./benchmarks/manifest.json \
  --results-dir /absolute/path/to/benchmark-results \
  --format json
```

The command exits `1` when a case or configured threshold fails. It matches
findings one-to-one by CWE and code location, treats duplicates as false
positives, measures repeated-run stability and negative controls, and includes
completion, validation, attack-path, evidence, and severity metrics. Use
`--no-enforce` to produce a report without enforcing the gates.
