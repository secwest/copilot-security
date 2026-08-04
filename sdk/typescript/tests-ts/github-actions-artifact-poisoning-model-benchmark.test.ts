import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface ArtifactRecord {
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
  "github-actions-artifact-poisoning",
  "github-actions-safe-artifact-data",
] as const;
const temporaryPaths: string[] = [];
const triggeringRunId = "${{ github.event.workflow_run.id }}";
const githubToken = "${{ secrets.GITHUB_TOKEN }}";
const runnerTemp = "${{ runner.temp }}";
const commitPin = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): ArtifactRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as ArtifactRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "github-actions-artifact-poisoning-code-execution",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function workflowInventory(
  files: Record<string, string>,
): Promise<ArtifactRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-actions-artifact-"),
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
    producerName?: string;
    producerTrigger?: string;
    checkoutUses?: string;
    checkoutInputs?: string;
    beforeUpload?: string;
    uploadUses?: string;
    uploadName?: string;
    uploadPath?: string;
    consumerProducerName?: string;
    permissions?: string;
    jobPrelude?: string;
    beforeDownload?: string;
    downloadUses?: string;
    downloadName?: string | null;
    downloadPath?: string;
    runId?: string;
    token?: string;
    afterDownload?: string;
  } = {},
): Record<string, string> {
  const producerName = options.producerName ?? "PR Build";
  const uploadName = options.uploadName ?? "release-input";
  const downloadName =
    options.downloadName === null
      ? ""
      : `name: ${options.downloadName ?? uploadName}`;
  return {
    ".github/workflows/pr-build.yml": `
name: ${producerName}
on:
  ${options.producerTrigger ?? "pull_request"}:
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ${options.checkoutUses ?? "actions/checkout@v6"}
        with:
          ${options.checkoutInputs ?? "persist-credentials: false"}
      ${options.beforeUpload ?? ""}
      - uses: ${options.uploadUses ?? "actions/upload-artifact@v4"}
        with:
          name: ${uploadName}
          path: ${options.uploadPath ?? "release.mjs"}
`,
    ".github/workflows/publish.yml": `
name: Publish
on:
  workflow_run:
    workflows: [${options.consumerProducerName ?? producerName}]
    types: [completed]
permissions: ${options.permissions ?? "write-all"}
jobs:
  publish:
    runs-on: ubuntu-latest
    ${options.jobPrelude ?? ""}
    steps:
      ${options.beforeDownload ?? ""}
      - uses: ${options.downloadUses ?? "actions/download-artifact@v5"}
        with:
          ${downloadName}
          path: ${options.downloadPath ?? "."}
          run-id: ${options.runId ?? triggeringRunId}
          github-token: ${options.token ?? githubToken}
      ${options.afterDownload ?? "- run: node release.mjs"}
`,
  };
}

describe("GitHub Actions artifact-poisoning model benchmark", () => {
  test("keeps executable artifact poisoning and isolated typed data under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "github-actions-artifact-poisoning-manifest.json"),
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
      cwe: ["CWE-829"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves exact producer, upload, triggering-run download, execution, and privilege provenance", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: ".github/workflows/publish.yml",
      line: 29,
      categories: [
        "github-actions-artifact-poisoning-code-execution",
        "github-actions-explicit-secret-access",
        "github-actions-write-token-permission",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "github-actions-yaml",
        scope: "cross-file",
        source: {
          kind: "untrusted-pull-request-artifact-upload",
          path: ".github/workflows/pr-build.yml",
          line: 15,
        },
        sink: {
          kind: "privileged-artifact-code-execution",
          path: ".github/workflows/publish.yml",
          line: 29,
          cweIds: ["CWE-829"],
        },
        propagators: [
          {
            kind: "untrusted-pull-request-checkout",
            path: ".github/workflows/pr-build.yml",
            line: 12,
            symbol: "artifact=release-input;path=release.mjs",
          },
          {
            kind: "triggering-run-artifact-download",
            path: ".github/workflows/publish.yml",
            line: 23,
            symbol: "artifact=release-input;workspace=.",
          },
        ],
        candidateControls: [],
      },
    });
    expect(safe).toEqual([]);
  });

  test("requires exact workflow, artifact, triggering run, token, and later execution closure", async () => {
    expect(
      await workflowInventory(
        workflowPair({ consumerProducerName: "Other Build" }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(workflowPair({ downloadName: "other" })),
    ).toEqual([]);
    expect(await workflowInventory(workflowPair({ runId: "123" }))).toEqual([]);
    expect(await workflowInventory(workflowPair({ token: "missing" }))).toEqual(
      [],
    );
    expect(
      await workflowInventory(
        workflowPair({ afterDownload: "- run: echo inspected" }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(workflowPair({ producerTrigger: "push" })),
    ).toEqual([]);
  });

  test("binds uploads to an active untrusted pull-request checkout path", async () => {
    expect(
      await workflowInventory(
        workflowPair({
          checkoutInputs: `path: pr
          persist-credentials: false`,
          uploadPath: "pr/release.mjs",
        }),
      ),
    ).toHaveLength(1);
    expect(
      await workflowInventory(
        workflowPair({
          checkoutInputs: `path: pr
          persist-credentials: false`,
          uploadPath: "trusted/release.mjs",
        }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          beforeUpload: `- uses: actions/checkout@v6
        with:
          ref: main`,
        }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          beforeUpload: `- uses: actions/checkout@v6
        with:
          ref: main
          clean: false`,
        }),
      ),
    ).toHaveLength(1);
  });

  test("tracks named and all-artifact extraction paths through effective working directories", async () => {
    const allArtifacts = await workflowInventory(
      workflowPair({
        downloadName: null,
        downloadPath: "artifacts",
        jobPrelude: `defaults:
      run:
        working-directory: artifacts/release-input`,
        afterDownload: "- run: npm test",
      }),
    );
    expect(allArtifacts).toHaveLength(1);
    expect(allArtifacts[0]?.frameworkModel?.propagators[1]?.symbol).toBe(
      "artifact=release-input;workspace=artifacts/release-input",
    );
    expect(
      await workflowInventory(
        workflowPair({
          downloadPath: "artifacts",
          afterDownload: `- working-directory: trusted
        run: npm test`,
        }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          downloadPath: "artifacts",
          afterDownload: "- uses: ./artifacts/action",
        }),
      ),
    ).toHaveLength(1);

    const temporaryExecution = await workflowInventory(
      workflowPair({
        downloadPath: `${runnerTemp}/artifacts`,
        afterDownload: `- run: node ${runnerTemp}/artifacts/release.mjs`,
      }),
    );
    expect(temporaryExecution).toHaveLength(1);
    expect(temporaryExecution[0]?.frameworkModel?.propagators[1]?.symbol).toBe(
      "artifact=release-input;workspace=@runner-temp/artifacts",
    );
  });

  test("clears downloaded artifact taint only when a trusted checkout actually cleans it", async () => {
    expect(
      await workflowInventory(
        workflowPair({
          afterDownload: `- uses: actions/checkout@v6
      - run: node release.mjs`,
        }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({
          afterDownload: `- uses: actions/checkout@v6
        with:
          clean: false
      - run: node release.mjs`,
        }),
      ),
    ).toHaveLength(1);
  });

  test("accepts official commit pins but rejects lookalike artifact actions", async () => {
    expect(
      await workflowInventory(
        workflowPair({
          checkoutUses: `actions/checkout@${commitPin}`,
          uploadUses: `actions/upload-artifact@${commitPin}`,
          downloadUses: `actions/download-artifact@${commitPin}`,
        }),
      ),
    ).toHaveLength(1);
    expect(
      await workflowInventory(
        workflowPair({ uploadUses: "attacker/upload-artifact@v4" }),
      ),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflowPair({ downloadUses: "attacker/download-artifact@v5" }),
      ),
    ).toEqual([]);
  });

  test("retains read-only consumer permissions without treating producer success as trust", async () => {
    const found = await workflowInventory(
      workflowPair({
        permissions: "read-all",
        jobPrelude: "if: github.event.workflow_run.conclusion == 'success'",
      }),
    );
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual(["explicit-read-only-token"]);
  });

  test("rejects malformed, duplicate-key, aliased, and non-workflow cross-file YAML", async () => {
    const valid = workflowPair();
    expect(
      await workflowInventory({
        ...valid,
        ".github/workflows/pr-build.yml": "on: [pull_request\njobs: {}",
      }),
    ).toEqual([]);
    expect(
      await workflowInventory({
        ...valid,
        ".github/workflows/pr-build.yml": `
name: PR Build
on: pull_request
on: pull_request
jobs: {}
`,
      }),
    ).toEqual([]);
    expect(
      await workflowInventory({
        ...valid,
        ".github/workflows/pr-build.yml": `
name: PR Build
on: pull_request
producer_steps: &producer_steps
  - uses: actions/checkout@v6
  - uses: actions/upload-artifact@v4
    with:
      name: release-input
      path: release.mjs
jobs:
  build:
    runs-on: ubuntu-latest
    steps: *producer_steps
`,
      }),
    ).toEqual([]);
    expect(
      await workflowInventory({
        "config/pr-build.yml": valid[".github/workflows/pr-build.yml"]!,
        ".github/workflows/publish.yml":
          valid[".github/workflows/publish.yml"]!,
      }),
    ).toEqual([]);
  });

  test("teaches the reviewer producer-consumer identity, extraction, and typed-data controls", () => {
    const prompt = scanQualityGatePrompt("scan", "/repo", "inventory-row", "");
    expect(prompt).toContain(
      "github-actions-artifact-poisoning-code-execution",
    );
    expect(prompt).toContain("complete cross-workflow chain");
    expect(prompt).toContain("github.event.workflow_run.id");
    expect(prompt).toContain("beneath runner.temp");
    expect(prompt).toContain("parses a narrowly typed value as data");
    expect(prompt).toContain(
      "workflow_run conclusion == success check does not establish artifact trust",
    );
  });
});
