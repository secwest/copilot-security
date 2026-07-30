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
and includes subagent use.
