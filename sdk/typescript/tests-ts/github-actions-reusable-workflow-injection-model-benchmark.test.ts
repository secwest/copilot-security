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
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
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
  "github-actions-reusable-workflow-injection",
  "github-actions-safe-reusable-workflow-input",
] as const;
const temporaryPaths: string[] = [];
const commentBody = "${{ github.event.comment.body }}";
const pullRequestTitle = "${{ github.event.pull_request.title }}";
const workflowRunBranch = "${{ github.event.workflow_run.head_branch }}";
const inputExpression = "${{ inputs.release-name }}";
const envExpression = "${{ env.RELEASE_NAME }}";
const releaseSecret = "${{ secrets.RELEASE_TOKEN }}";
const commitPin = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

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
        "github-actions-reusable-workflow-script-injection",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function workflowInventory(
  files: Record<string, string>,
): Promise<InjectionRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-actions-reusable-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function workflowPair(
  options: {
    callerPath?: string;
    calledPath?: string;
    target?: string;
    trigger?: string;
    source?: string;
    inputName?: string;
    declaredName?: string;
    inputType?: string;
    callerPermissions?: string;
    callerIf?: string;
    secrets?: string;
    calledPermissions?: string;
    calledPrelude?: string;
    calledEnvironment?: string;
    step?: string;
  } = {},
): Record<string, string> {
  const callerPath = options.callerPath ?? ".github/workflows/caller.yml";
  const calledPath = options.calledPath ?? ".github/workflows/reusable.yml";
  const inputName = options.inputName ?? "release-name";
  const declaredName = options.declaredName ?? inputName;
  const step =
    options.step ??
    `- uses: actions/github-script@v8
        env:
          RELEASE_TOKEN: ${releaseSecret}
        with:
          script: |
            core.info("Publishing ${inputExpression}");`;
  return {
    [callerPath]: `
name: Caller
on:
  ${options.trigger ?? "issue_comment"}:
permissions: ${options.callerPermissions ?? "write-all"}
jobs:
  publish:
    ${options.callerIf ?? "if: github.event.issue.pull_request"}
    uses: ${options.target ?? "./.github/workflows/reusable.yml"}
    with:
      ${inputName}: ${options.source ?? commentBody}
    secrets: ${options.secrets ?? "inherit"}
`,
    [calledPath]: `
name: Reusable
on:
  workflow_call:
    inputs:
      ${declaredName}:
        required: true
        type: ${options.inputType ?? "string"}
permissions: ${options.calledPermissions ?? "write-all"}
${options.calledEnvironment ?? ""}
jobs:
  publish:
    runs-on: ubuntu-latest
    ${options.calledPrelude ?? ""}
    steps:
      ${step}
`,
  };
}

describe("GitHub Actions reusable-workflow injection model benchmark", () => {
  test("keeps expression compilation and native environment data use under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "github-actions-reusable-workflow-injection-manifest.json",
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

  test("preserves exact caller, input, declaration, sink, secret, and permission provenance", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: ".github/workflows/reusable-release.yml",
      line: 16,
      categories: [
        "github-actions-reusable-workflow-script-injection",
        "github-actions-explicit-secret-access",
        "github-actions-write-token-permission",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "github-actions-yaml",
        scope: "cross-file",
        source: {
          kind: "attacker-controlled-event-field-forwarding",
          path: ".github/workflows/comment-release.yml",
          line: 13,
        },
        sink: {
          kind: "reusable-workflow-script-interpolation",
          path: ".github/workflows/reusable-release.yml",
          line: 16,
          cweIds: ["CWE-094", "CWE-095", "CWE-116"],
        },
        propagators: [
          {
            kind: "attacker-influenced-workflow-trigger",
            path: ".github/workflows/comment-release.yml",
            line: 3,
            symbol: "event=issue_comment",
          },
          {
            kind: "local-reusable-workflow-call",
            path: ".github/workflows/comment-release.yml",
            line: 11,
            symbol: "workflow=.github/workflows/reusable-release.yml",
          },
          {
            kind: "workflow-call-string-input",
            path: ".github/workflows/reusable-release.yml",
            line: 5,
            symbol: "input=release-name",
          },
        ],
        candidateControls: [],
      },
    });
    expect(safe).toEqual([]);
  });

  test("requires an exact local target, forwarded name, and declared string input", async () => {
    expect(
      await workflowInventory(
        workflowPair({
          target: "secwest/example/.github/workflows/reusable.yml@main",
        }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({ target: ".github/workflows/reusable.yml" }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({ target: ".\\.github\\workflows\\reusable.yml" }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(workflowPair({ declaredName: "other-name" })),
    ).toEqual([]);
    expect(
      await workflowInventory(workflowPair({ inputType: "boolean" })),
    ).toEqual([]);
    expect(
      await workflowInventory(workflowPair({ source: "fixed release" })),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          source: "${{ contains(github.event.comment.body, 'ok') }}",
        }),
      ),
    ).toEqual([]);
  });

  test("couples each externally influenced trigger to its own attacker field", async () => {
    expect(
      await workflowInventory(
        workflowPair({
          trigger: "pull_request_target",
          source: pullRequestTitle,
        }),
      ),
    ).toHaveLength(1);
    expect(
      await workflowInventory(
        workflowPair({ trigger: "workflow_run", source: workflowRunBranch }),
      ),
    ).toHaveLength(1);
    expect(
      await workflowInventory(
        workflowPair({ trigger: "pull_request", source: pullRequestTitle }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({ trigger: "issues", source: commentBody }),
      ),
    ).toEqual([]);
  });

  test("recognizes direct run and official github-script sinks but rejects ordinary inputs and lookalikes", async () => {
    expect(
      await workflowInventory(
        workflowPair({ step: `- run: echo "${inputExpression}"` }),
      ),
    ).toHaveLength(1);
    expect(
      await workflowInventory(
        workflowPair({
          step: `- uses: actions/github-script@${commitPin}
        with:
          script: core.info("${inputExpression}")`,
        }),
      ),
    ).toHaveLength(1);
    expect(
      await workflowInventory(
        workflowPair({
          step: `- uses: attacker/github-script@v8
        with:
          script: core.info("${inputExpression}")`,
        }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          step: `- uses: actions/github-script@v8
        with:
          retries: ${inputExpression}
          script: core.info("fixed")`,
        }),
      ),
    ).toEqual([]);
  });

  test("distinguishes unsafe workflow env re-expansion from native environment data use", async () => {
    const indirect = await workflowInventory(
      workflowPair({
        calledPrelude: `env:
      RELEASE_NAME: ${inputExpression}`,
        step: `- run: echo "${envExpression}"`,
      }),
    );
    expect(indirect).toHaveLength(1);
    expect(indirect[0]?.frameworkModel?.propagators.at(-1)).toMatchObject({
      kind: "workflow-expression-env-alias",
      symbol: "input=release-name;env=RELEASE_NAME",
    });
    expect(
      await workflowInventory(
        workflowPair({
          calledPrelude: `env:
      RELEASE_NAME: ${inputExpression}`,
          step: `- env:
          RELEASE_NAME: fixed
        run: echo "${envExpression}"`,
        }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          calledPrelude: `env:
      RELEASE_NAME: ${inputExpression}`,
          step: "- run: printf '%s\\n' \"$RELEASE_NAME\"",
        }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          step: `- uses: actions/github-script@v8
        env:
          RELEASE_NAME: ${inputExpression}
        with:
          script: core.info(process.env.RELEASE_NAME)`,
        }),
      ),
    ).toEqual([]);
  });

  test("intersects caller and called permissions and requires actual secret forwarding", async () => {
    const callerReadOnly = await workflowInventory(
      workflowPair({ callerPermissions: "read-all" }),
    );
    expect(callerReadOnly).toHaveLength(1);
    expect(callerReadOnly[0]?.categories).not.toContain(
      "github-actions-write-token-permission",
    );
    expect(
      callerReadOnly[0]?.frameworkModel?.candidateControls.map(
        ({ kind }) => kind,
      ),
    ).toContain("explicit-read-only-token");

    const calledReadOnly = await workflowInventory(
      workflowPair({ calledPermissions: "read-all" }),
    );
    expect(calledReadOnly).toHaveLength(1);
    expect(calledReadOnly[0]?.categories).not.toContain(
      "github-actions-write-token-permission",
    );

    const mappedSecret = await workflowInventory(
      workflowPair({ secrets: `{ RELEASE_TOKEN: '${releaseSecret}' }` }),
    );
    expect(mappedSecret[0]?.categories).toContain(
      "github-actions-explicit-secret-access",
    );
    const noSecret = await workflowInventory(workflowPair({ secrets: "{}" }));
    expect(noSecret[0]?.categories).not.toContain(
      "github-actions-explicit-secret-access",
    );
  });

  test("retains mutable review and deployment environment controls without closing the flow", async () => {
    const found = await workflowInventory(
      workflowPair({
        callerIf:
          "if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')",
        calledPrelude: "environment: production",
      }),
    );
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual(["mutable-review-label-gate", "deployment-environment-gate"]);
  });

  test("rejects malformed, duplicate-key, aliased, missing, and non-workflow targets", async () => {
    const valid = workflowPair();
    expect(
      await workflowInventory({
        ...valid,
        ".github/workflows/reusable.yml": "on: [workflow_call\njobs: {}",
      }),
    ).toEqual([]);
    expect(
      await workflowInventory({
        ...valid,
        ".github/workflows/reusable.yml": `
on: workflow_call
on: workflow_call
jobs: {}
`,
      }),
    ).toEqual([]);
    expect(
      await workflowInventory({
        ...valid,
        ".github/workflows/reusable.yml": `
on:
  workflow_call:
    inputs: &inputs
      release-name:
        type: string
copied: *inputs
jobs: {}
`,
      }),
    ).toEqual([]);
    expect(
      await workflowInventory({
        ".github/workflows/caller.yml": valid[".github/workflows/caller.yml"]!,
      }),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          calledPath: "config/reusable.yml",
          target: "./config/reusable.yml",
        }),
      ),
    ).toEqual([]);
  });

  test("teaches the reviewer expression timing, privilege intersection, and native env control", () => {
    const prompt = scanQualityGatePrompt("scan", "/repo", "inventory-row", "");
    expect(prompt).toContain(
      "github-actions-reusable-workflow-script-injection",
    );
    expect(prompt).toContain(
      "complete cross-file expression-compilation chain",
    );
    expect(prompt).toContain("GitHub expression substitution happens before");
    expect(prompt).toContain("process.env");
    expect(prompt).toContain("intersecting privilege ceiling");
    expect(prompt).toContain("pull_request-only callers");
  });
});
