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
  "github-actions-composite-action-injection",
  "github-actions-safe-composite-action-input",
] as const;
const temporaryPaths: string[] = [];
const commentBody = "${{ github.event.comment.body }}";
const pullRequestTitle = "${{ github.event.pull_request.title }}";
const workflowRunBranch = "${{ github.event.workflow_run.head_branch }}";
const inputExpression = "${{ inputs.release-name }}";
const envExpression = "${{ env.RELEASE_NAME }}";
const releaseTokenInput = "${{ inputs.release-token }}";
const releaseSecret = "${{ secrets.RELEASE_TOKEN }}";
const githubTokenExpression = "${{ github.token }}";
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
        "github-actions-composite-action-script-injection",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<InjectionRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-actions-composite-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function actionPair(
  options: {
    callerPath?: string;
    actionPath?: string;
    target?: string;
    trigger?: string;
    source?: string;
    inputName?: string;
    declaredName?: string;
    using?: string;
    inputDescription?: string;
    actionName?: string;
    actionDescription?: string;
    callerPermissions?: string;
    callerIf?: string;
    jobEnvironment?: string;
    stepIf?: string;
    secretValue?: string;
    step?: string;
  } = {},
): Record<string, string> {
  const callerPath = options.callerPath ?? ".github/workflows/caller.yml";
  const actionPath = options.actionPath ?? ".github/actions/release/action.yml";
  const inputName = options.inputName ?? "release-name";
  const declaredName = options.declaredName ?? inputName;
  const step =
    options.step ??
    `- uses: actions/github-script@v8
      env:
        RELEASE_TOKEN: ${releaseTokenInput}
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
    runs-on: ubuntu-latest
    ${options.jobEnvironment ?? ""}
    steps:
      - ${options.stepIf ?? ""}
        uses: ${options.target ?? "./.github/actions/release"}
        with:
          ${inputName}: ${options.source ?? commentBody}
          release-token: ${options.secretValue ?? releaseSecret}
`,
    [actionPath]: `
name: ${options.actionName ?? "Release"}
description: ${options.actionDescription ?? "Publish a release"}
inputs:
  ${declaredName}:
    description: ${options.inputDescription ?? "Release name"}
    required: true
  release-token:
    description: Release token
    required: true
runs:
  using: ${options.using ?? "composite"}
  steps:
    ${step}
`,
  };
}

describe("GitHub Actions composite-action injection model benchmark", () => {
  test("keeps expression compilation and native environment data use under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "github-actions-composite-action-injection-manifest.json",
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

  test("preserves exact caller, action, input, sink, secret, and permission provenance", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: ".github/actions/publish-release/action.yml",
      line: 17,
      categories: [
        "github-actions-composite-action-script-injection",
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
          line: 15,
        },
        sink: {
          kind: "composite-action-script-interpolation",
          path: ".github/actions/publish-release/action.yml",
          line: 17,
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
            kind: "local-composite-action-call",
            path: ".github/workflows/comment-release.yml",
            line: 13,
            symbol: "action=.github/actions/publish-release",
          },
          {
            kind: "composite-action-input",
            path: ".github/actions/publish-release/action.yml",
            line: 4,
            symbol: "input=release-name",
          },
        ],
        candidateControls: [],
      },
    });
    expect(safe).toEqual([]);
  });

  test("requires an exact local directory and one valid composite metadata file", async () => {
    expect(
      await repositoryInventory(actionPair({ target: "secwest/example@main" })),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({ target: ".github/actions/release" }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({ target: ".\\.github\\actions\\release" }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(actionPair({ target: "./../outside" })),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({ target: "./${{ matrix.action }}" }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(actionPair({ declaredName: "other-name" })),
    ).toEqual([]);
    expect(await repositoryInventory(actionPair({ using: "node24" }))).toEqual(
      [],
    );
    expect(
      await repositoryInventory(actionPair({ inputDescription: "" })),
    ).toEqual([]);
    const ambiguous = actionPair();
    ambiguous[".github/actions/release/action.yaml"] =
      ambiguous[".github/actions/release/action.yml"]!;
    expect(await repositoryInventory(ambiguous)).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({ actionPath: ".github/actions/release/action.yaml" }),
      ),
    ).toHaveLength(1);
  });

  test("couples each externally influenced trigger to its own attacker field", async () => {
    expect(
      await repositoryInventory(
        actionPair({
          trigger: "pull_request_target",
          source: pullRequestTitle,
        }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(
        actionPair({ trigger: "workflow_run", source: workflowRunBranch }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(
        actionPair({ trigger: "pull_request", source: pullRequestTitle }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({ trigger: "issues", source: commentBody }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(actionPair({ source: "fixed release" })),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({
          source: "${{ contains(github.event.comment.body, 'ok') }}",
        }),
      ),
    ).toEqual([]);
  });

  test("recognizes runnable shell and official github-script sinks only", async () => {
    expect(
      await repositoryInventory(
        actionPair({
          step: `- run: echo "${inputExpression}"
      shell: bash`,
        }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(
        actionPair({ step: `- run: echo "${inputExpression}"` }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({
          step: `- uses: actions/github-script@${commitPin}
      with:
        script: core.info("${inputExpression}")`,
        }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(
        actionPair({
          step: `- uses: attacker/github-script@v8
      with:
        script: core.info("${inputExpression}")`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({
          step: `- uses: actions/github-script@v8
      with:
        retries: ${inputExpression}
        script: core.info("fixed")`,
        }),
      ),
    ).toEqual([]);
  });

  test("distinguishes same-step expression re-expansion from native environment data use", async () => {
    const indirect = await repositoryInventory(
      actionPair({
        step: `- env:
        RELEASE_NAME: ${inputExpression}
      run: echo "${envExpression}"
      shell: bash`,
      }),
    );
    expect(indirect).toHaveLength(1);
    expect(indirect[0]?.frameworkModel?.propagators.at(-1)).toMatchObject({
      kind: "workflow-expression-env-alias",
      symbol: "input=release-name;env=RELEASE_NAME",
    });
    expect(
      await repositoryInventory(
        actionPair({
          step: `- env:
        RELEASE_NAME: ${inputExpression}
      run: printf '%s\\n' "$RELEASE_NAME"
      shell: bash`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({
          step: `- env:
        RELEASE_NAME: ${inputExpression}
      run: echo fixed
      shell: bash
    - run: echo "${envExpression}"
      shell: bash`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({
          step: `- uses: actions/github-script@v8
      env:
        RELEASE_NAME: ${inputExpression}
      with:
        script: core.info(process.env.RELEASE_NAME)`,
        }),
      ),
    ).toEqual([]);
  });

  test("tracks effective permissions and only secrets explicitly forwarded into the sink step", async () => {
    const readOnly = await repositoryInventory(
      actionPair({ callerPermissions: "read-all" }),
    );
    expect(readOnly).toHaveLength(1);
    expect(readOnly[0]?.categories).not.toContain(
      "github-actions-write-token-permission",
    );
    expect(
      readOnly[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("explicit-read-only-token");

    const fixedSecret = await repositoryInventory(
      actionPair({ secretValue: "not-a-secret" }),
    );
    expect(fixedSecret[0]?.categories).not.toContain(
      "github-actions-explicit-secret-access",
    );
    const unusedSecret = await repositoryInventory(
      actionPair({
        step: `- run: echo "${inputExpression}"
      shell: bash`,
      }),
    );
    expect(unusedSecret[0]?.categories).not.toContain(
      "github-actions-explicit-secret-access",
    );
    const commentOnlySecret = await repositoryInventory(
      actionPair({
        step: `- run: echo "${inputExpression}"
      shell: bash
      # ${releaseTokenInput}`,
      }),
    );
    expect(commentOnlySecret[0]?.categories).not.toContain(
      "github-actions-explicit-secret-access",
    );
    const githubToken = await repositoryInventory(
      actionPair({
        step: `- uses: actions/github-script@v8
      env:
        TOKEN: ${githubTokenExpression}
      with:
        script: core.info("${inputExpression}")`,
      }),
    );
    expect(githubToken[0]?.categories).toContain(
      "github-actions-explicit-secret-access",
    );
  });

  test("retains review and deployment gates without treating them as sanitizers", async () => {
    const found = await repositoryInventory(
      actionPair({
        callerIf:
          "if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')",
        jobEnvironment: "environment: production",
        stepIf:
          "if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')",
      }),
    );
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "mutable-review-label-gate",
      "deployment-environment-gate",
      "mutable-review-label-gate",
    ]);
  });

  test("rejects malformed, duplicate-key, aliased, missing, and non-action metadata", async () => {
    const valid = actionPair();
    expect(
      await repositoryInventory({
        ...valid,
        ".github/actions/release/action.yml": "runs: [composite\n",
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        ...valid,
        ".github/actions/release/action.yml": `
name: Duplicate
description: invalid
runs: { using: composite, steps: [] }
runs: { using: composite, steps: [] }
`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        ...valid,
        ".github/actions/release/action.yml": `
name: Aliased
description: invalid
inputs: &inputs
  release-name: { description: Release name }
copied: *inputs
runs: { using: composite, steps: [] }
`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        ".github/workflows/caller.yml": valid[".github/workflows/caller.yml"]!,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        actionPair({
          actionPath: ".github/actions/release/workflow.yml",
        }),
      ),
    ).toEqual([]);
  });

  test("teaches the reviewer descriptor identity, expression timing, and native env control", () => {
    const prompt = scanQualityGatePrompt("scan", "/repo", "inventory-row", "");
    expect(prompt).toContain(
      "github-actions-composite-action-script-injection",
    );
    expect(prompt).toContain("workflow-to-action expression-compilation chain");
    expect(prompt).toContain("exactly one valid action.yml or action.yaml");
    expect(prompt).toContain("before the generated program reaches");
    expect(prompt).toContain("process.env");
    expect(prompt).toContain("parent traversal");
  });
});
