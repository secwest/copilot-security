import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface InjectionRecord {
  path: string;
  line: number;
  categories: string[];
  frameworkModel?: {
    schemaVersion: string;
    id: string;
    language: string;
    scope: string;
    source: { kind: string; path: string; line: number; symbol: string };
    sink: {
      kind: string;
      path: string;
      line: number;
      symbol: string;
      cweIds: string[];
    };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    expected: Array<{
      cwe?: string[];
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "github-actions-workflow-script-injection",
  "github-actions-safe-workflow-script-input",
] as const;
const temporaryPaths: string[] = [];
const pullRequestTitle = "github.event.pull_request.title";
const issueTitle = "github.event.issue.title";
const titleExpression = `\${{ ${pullRequestTitle} }}`;
const issueExpression = `\${{ ${issueTitle} }}`;
const secretExpression = "${{ secrets.RELEASE_TOKEN }}";
const envTitleExpression = "${{ env.TITLE }}";

const knownCodeInputs = [
  ["8398a7/action-slack", "custom_payload"],
  ["actions/github-script", "script"],
  ["addnab/docker-run-action", "run"],
  ["amadevus/pwsh-script", "script"],
  ["appleboy/ssh-action", "script"],
  ["azure/cli", "inlineScript"],
  ["azure/powershell", "inlineScript"],
  ["cardinalby/js-eval-action", "expression"],
  ["devorbitus/yq-action-output", "cmd"],
  ["gautamkrishnar/blog-post-workflow", "item_exec"],
  ["imjohnbo/issue-bot", "body"],
  ["jannekem/run-python-script-action", "script"],
  ["lucasbento/auto-close-issues", "issue-close-message"],
  ["mikefarah/yq", "cmd"],
  ["roots/issue-closer-action", "issue-close-message"],
  ["sergeysova/jq-action", "cmd"],
  ["skitionek/notify-microsoft-teams", "overwrite"],
  ["tibdex/backport", "title_template"],
] as const;

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): InjectionRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as InjectionRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "github-actions-workflow-script-injection",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<InjectionRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-actions-workflow-injection-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function workflow(
  options: {
    path?: string;
    trigger?: string;
    permissions?: string;
    workflowEnvironment?: string;
    jobIf?: string;
    jobEnvironment?: string;
    step?: string;
  } = {},
): Record<string, string> {
  const step =
    options.step ??
    `- uses: actions/github-script@v8
        env:
          RELEASE_TOKEN: ${secretExpression}
        with:
          script: core.info("${titleExpression}")`;
  return {
    [options.path ?? ".github/workflows/check.yml"]: `
name: Check
on:
  ${options.trigger ?? "pull_request_target"}:
permissions: ${options.permissions ?? "write-all"}
${options.workflowEnvironment ?? ""}
jobs:
  check:
    ${options.jobIf ?? ""}
    runs-on: ubuntu-latest
    ${options.jobEnvironment ?? ""}
    steps:
      ${step}
`,
  };
}

function githubScript(expression: string, extra = ""): string {
  return `- uses: actions/github-script@v8
        ${extra}
        with:
          script: core.info("${expression}")`;
}

describe("GitHub Actions same-workflow injection model benchmark", () => {
  test("keeps generated source and the native-environment control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "github-actions-workflow-script-injection-manifest.json",
        ),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-094", "CWE-095", "CWE-116"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves trigger, event field, interpreter, secret, permission, and sink provenance", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: ".github/workflows/check-title.yml",
      line: 16,
      categories: [
        "github-actions-workflow-script-injection",
        "github-actions-explicit-secret-access",
        "github-actions-write-token-permission",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "github-actions-yaml",
        scope: "same-file",
        source: {
          kind: "attacker-controlled-event-script-expression",
          path: ".github/workflows/check-title.yml",
          line: 16,
          symbol: pullRequestTitle,
        },
        sink: {
          kind: "workflow-action-code-input-interpolation",
          path: ".github/workflows/check-title.yml",
          line: 16,
          symbol: "actions/github-script:script",
          cweIds: ["CWE-094", "CWE-095", "CWE-116"],
        },
        propagators: [
          {
            kind: "attacker-influenced-workflow-trigger",
            path: ".github/workflows/check-title.yml",
            line: 3,
            symbol: "event=pull_request_target",
          },
        ],
        candidateControls: [],
      },
    });
    expect(safe).toEqual([]);
  });

  test("couples direct event fields to pull request and default-branch triggers", async () => {
    const pullRequest = await repositoryInventory(
      workflow({ trigger: "pull_request" }),
    );
    expect(pullRequest).toHaveLength(1);
    expect(pullRequest[0]?.categories).toEqual([
      "github-actions-workflow-script-injection",
    ]);
    expect(
      await repositoryInventory(
        workflow({ trigger: "issues", step: githubScript(issueExpression) }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(
        workflow({ trigger: "issues", step: githubScript(titleExpression) }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({ trigger: "push", step: githubScript(titleExpression) }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          step: githubScript("${{ github.event.pull_request.base.sha }}"),
        }),
      ),
    ).toEqual([]);
  });

  test("follows bounded value-preserving functions and reachable short-circuit arms", async () => {
    for (const expression of [
      `\${{ toJSON(${pullRequestTitle}) }}`,
      `\${{ fromJSON(${pullRequestTitle}) }}`,
      `\${{ format('{0}', ${pullRequestTitle}) }}`,
      `\${{ join(${pullRequestTitle}, ',') }}`,
      `\${{ false || ${pullRequestTitle} }}`,
      `\${{ ${pullRequestTitle} || 'fixed' }}`,
      `\${{ 'fixed' && ${pullRequestTitle} }}`,
      `\${{ (false || (${pullRequestTitle})) }}`,
      "${{ github['event']['pull_request']['title'] }}",
    ]) {
      expect(
        await repositoryInventory(workflow({ step: githubScript(expression) })),
      ).toHaveLength(1);
    }
  });

  test("rejects boolean-only and unreachable expression results", async () => {
    for (const expression of [
      `\${{ contains(${pullRequestTitle}, 'release') }}`,
      `\${{ startsWith(${pullRequestTitle}, 'release') }}`,
      `\${{ ${pullRequestTitle} == 'release' }}`,
      `\${{ ${pullRequestTitle} && 'fixed' }}`,
      `\${{ true || ${pullRequestTitle} }}`,
      `\${{ format('{0}', contains(${pullRequestTitle}, 'x')) }}`,
    ]) {
      expect(
        await repositoryInventory(workflow({ step: githubScript(expression) })),
      ).toEqual([]);
    }
  });

  test("tracks workflow, job, and step env shadowing but not native data consumption", async () => {
    const indirect = await repositoryInventory(
      workflow({
        workflowEnvironment: `env:
  TITLE: ${titleExpression}`,
        step: githubScript(envTitleExpression),
      }),
    );
    expect(indirect).toHaveLength(1);
    expect(indirect[0]?.frameworkModel?.propagators.at(-1)).toMatchObject({
      kind: "workflow-expression-env-alias",
      symbol: `source=${pullRequestTitle};env=TITLE`,
    });
    expect(
      await repositoryInventory(
        workflow({
          workflowEnvironment: `env:
  TITLE: ${titleExpression}`,
          jobEnvironment: `env:
      TITLE: fixed`,
          step: githubScript(envTitleExpression),
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          step: `- env:
          TITLE: ${titleExpression}
        run: printf '%s\\n' "$TITLE"`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          step: `- uses: actions/github-script@v8
        env:
          TITLE: ${titleExpression}
        with:
          script: core.info(process.env.TITLE)`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          step: `- env:
          TITLE: ${titleExpression}
        run: echo fixed
      - run: echo "${envTitleExpression}"`,
        }),
      ),
    ).toEqual([]);
  });

  test("recognizes run plus the exact current CodeQL and zizmor action code-input map", async () => {
    const run = await repositoryInventory(
      workflow({ step: `- run: echo "${titleExpression}"` }),
    );
    expect(run).toHaveLength(1);
    expect(run[0]?.frameworkModel?.sink).toMatchObject({
      kind: "workflow-run-script-interpolation",
      symbol: "run",
    });
    for (const [identity, input] of knownCodeInputs) {
      const found = await repositoryInventory(
        workflow({
          step: `- uses: ${identity}@main
        with:
          ${input}: ${titleExpression}`,
        }),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel?.sink.symbol).toBe(
        `${identity}:${input}`,
      );
    }
  });

  test("rejects ordinary action data, unknown code inputs, and action lookalikes", async () => {
    expect(
      await repositoryInventory(
        workflow({
          step: `- uses: fakeaction/checktitle@v3
        with:
          title: ${titleExpression}`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          step: `- uses: actions/github-script@v8
        with:
          retries: ${titleExpression}
          script: core.info('fixed')`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          step: `- uses: attacker/github-script@v8
        with:
          script: ${titleExpression}`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          step: `- uses: actions/github-script@\${{ matrix.ref }}
        with:
          script: ${titleExpression}`,
        }),
      ),
    ).toEqual([]);
  });

  test("keeps exact secret, permission, review, and environment impact evidence", async () => {
    const readOnly = await repositoryInventory(
      workflow({ permissions: "read-all" }),
    );
    expect(readOnly).toHaveLength(1);
    expect(readOnly[0]?.categories).not.toContain(
      "github-actions-write-token-permission",
    );
    expect(
      readOnly[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("explicit-read-only-token");

    const inheritedSecret = await repositoryInventory(
      workflow({
        workflowEnvironment: `env:
  RELEASE_TOKEN: ${secretExpression}`,
        step: githubScript(titleExpression),
      }),
    );
    expect(inheritedSecret[0]?.categories).toContain(
      "github-actions-explicit-secret-access",
    );
    const overriddenSecret = await repositoryInventory(
      workflow({
        workflowEnvironment: `env:
  RELEASE_TOKEN: ${secretExpression}`,
        step: githubScript(
          titleExpression,
          `env:
          RELEASE_TOKEN: fixed`,
        ),
      }),
    );
    expect(overriddenSecret[0]?.categories).not.toContain(
      "github-actions-explicit-secret-access",
    );

    const gated = await repositoryInventory(
      workflow({
        jobIf:
          "if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')",
        jobEnvironment: "environment: production",
        step: githubScript(
          titleExpression,
          "if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')",
        ),
      }),
    );
    expect(gated).toHaveLength(1);
    expect(
      gated[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "mutable-review-label-gate",
      "deployment-environment-gate",
      "mutable-review-label-gate",
    ]);
  });

  test("rejects malformed, duplicate-key, aliased, and non-workflow YAML", async () => {
    expect(
      await repositoryInventory({
        ".github/workflows/check.yml": "on: [pull_request_target\njobs: {}",
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        ".github/workflows/check.yml": `
on: pull_request_target
on: pull_request_target
jobs: {}
`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        ".github/workflows/check.yml": `
on: pull_request_target
env: &shared
  TITLE: ${titleExpression}
copy: *shared
jobs: {}
`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory(workflow({ path: "config/check.yml" })),
    ).toEqual([]);
  });

  test("teaches the reviewer event capability, bounded dataflow, exact sinks, and pull-request impact", () => {
    const prompt = scanQualityGatePrompt("scan", "/repo", "inventory-row", "");
    expect(prompt).toContain("github-actions-workflow-script-injection");
    expect(prompt).toContain("same-workflow expression-compilation chain");
    expect(prompt).toContain("toJSON/fromJSON/format/join");
    expect(prompt).toContain("unreachable short-circuit arms");
    expect(prompt).toContain("ordinary action argument");
    expect(prompt).toContain("pull_request row remains code execution");
    expect(prompt).toContain("do not invent those impacts");
  });
});
