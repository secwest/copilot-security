# Copilot Security

Copilot Security is a repository security scanner driven by the GitHub Copilot
CLI installed on the local machine. It is derived from
[OpenAI Codex Security](https://github.com/openai/codex-security) and preserves
its deterministic inventory, threat modeling, candidate validation,
attack-path analysis, canonical JSON, SARIF/report generation, scan history,
diff scanning, bulk scanning, and finding-management workflows.

The model runtime is different: production scans use GitHub's official
`@github/copilot-sdk` to control the system `copilot` executable. They do not
invoke Codex or send model requests to OpenAI's Codex service.

## Status

This is an early Secwest port. Standard repository, path, committed-diff, and
working-tree scans use the inherited scanner harness. Deep mode uses repeated
independent native Copilot subagents and adds explicit systems,
supply-chain/configuration, and business-logic review lenses before one
centralized validation pass.

## Requirements

- GitHub Copilot CLI, installed and signed in (`copilot login`)
- Node.js 22.13+, 24, or 26
- Python 3.10+ (`tomli` is also needed on Python 3.10)
- Git

The scanner uses the installed CLI found on `PATH`. Set `COPILOT_CLI_PATH` or
the SDK `copilotPath` option to select another executable.

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
the root session and its subagents.

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

`CodexSecurity`, `codexOverrides`, and the original `CODEX_SECURITY_*`
environment names remain temporary compatibility aliases. New integrations
should use `CopilotSecurity`, `copilotOverrides`, and
`COPILOT_SECURITY_STATE_DIR`.

## Safety

Scans are report-only. The scanning prompt forbids modifying the target
repository, publishing findings, opening issues, committing, pushing, or
contacting third parties. Scan output must be outside the target repository and
its enclosing Git worktree. The Copilot CLI still receives normal local tool
permissions so it can inspect files and run bounded repository-native
validation; run only against repositories you are authorized to assess.

## Attribution

The inherited scanner harness, methodologies, schemas, and workbench are
derived from OpenAI's `codex-security` project under the Apache License 2.0.
Secwest's Copilot runtime adapter and porting changes are maintained in this
repository. See [LICENSE](LICENSE).
