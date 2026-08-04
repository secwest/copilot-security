import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
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
      symbol?: string;
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
  "github-actions-pwn-request",
  "github-actions-safe-pr-checkout",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "github-actions-privileged-pr-code-execution",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function workflowInventory(
  workflow: string,
  path = ".github/workflows/ci.yml",
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-actions-risk-"),
  );
  temporaryPaths.push(repository);
  const absolute = join(repository, path);
  await mkdir(dirname(absolute), { recursive: true });
  await writeFile(absolute, workflow);
  return models(await buildResidualRiskInventory(repository));
}

const untrustedSha = "${{ github.event.pull_request.head.sha }}";
const untrustedRepository =
  "${{ github.event.pull_request.head.repo.full_name }}";

function workflow(
  options: {
    trigger?: string;
    checkoutVersion?: number;
    checkoutUses?: string;
    checkoutInputs?: string;
    jobPrelude?: string;
    stepsAfterCheckout?: string;
    permissions?: string;
  } = {},
): string {
  return `
name: Test
on:
  ${options.trigger ?? "pull_request_target"}:
permissions: ${options.permissions ?? "write-all"}
jobs:
  test:
    runs-on: ubuntu-latest
    ${options.jobPrelude ?? ""}
    steps:
      - uses: ${options.checkoutUses ?? `actions/checkout@v${options.checkoutVersion ?? 7}`}
        with:
          ref: ${untrustedSha}
          ${options.checkoutInputs ?? "allow-unsafe-pr-checkout: true"}
      ${options.stepsAfterCheckout ?? "- run: npm test"}
`;
}

describe("GitHub Actions privileged PR execution model benchmark", () => {
  test("keeps the real exploit and Checkout v7 control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "github-actions-pwn-request-manifest.json"),
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

  test("preserves exact trigger, checkout, execution, and current platform controls", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "github-actions-privileged-pr-code-execution",
      language: "github-actions-yaml",
      scope: "same-file",
      source: {
        kind: "privileged-pull-request-trigger",
        path: ".github/workflows/ci.yml",
        line: 4,
      },
      sink: {
        kind: "untrusted-workspace-code-execution",
        path: ".github/workflows/ci.yml",
        line: 22,
        cweIds: ["CWE-829"],
      },
      propagators: [
        {
          kind: "untrusted-checkout-request",
          path: ".github/workflows/ci.yml",
          line: 17,
          symbol: "workspace=.",
        },
      ],
      candidateControls: [
        {
          kind: "checkout-credentials-not-persisted",
          path: ".github/workflows/ci.yml",
          line: 21,
        },
        {
          kind: "immutable-pr-commit",
          path: ".github/workflows/ci.yml",
          line: 19,
        },
      ],
    });
    expect(safe).toHaveLength(1);
    expect(
      safe[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "explicit-read-only-token",
      "checkout-v7-fork-protection",
      "checkout-credentials-not-persisted",
      "immutable-pr-commit",
    ]);
  });

  test("requires a privileged trigger, untrusted fork contents, and later workspace execution", async () => {
    expect(
      await workflowInventory(workflow({ trigger: "pull_request" })),
    ).toEqual([]);
    expect(
      await workflowInventory(`
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - run: npm test
`),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflow({ stepsAfterCheckout: "- run: echo inspected" }),
      ),
    ).toEqual([]);
    for (const run of [
      "npm ci --ignore-scripts",
      "node --version",
      "node -e 'console.log(1)'",
      "python -c 'print(1)'",
      "bash -c 'echo inspected'",
      "bash /opt/trusted/check.sh",
    ]) {
      expect(
        await workflowInventory(
          workflow({ stepsAfterCheckout: `- run: ${run}` }),
        ),
      ).toEqual([]);
    }
    expect(
      await workflowInventory(`
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
      - uses: actions/checkout@v6
        with:
          ref: ${untrustedSha}
`),
    ).toEqual([]);
  });

  test("tracks checkout paths into matching working directories and local actions", async () => {
    const workingDirectory = await workflowInventory(
      workflow({
        checkoutInputs: `path: pr
          allow-unsafe-pr-checkout: true`,
        stepsAfterCheckout: `- working-directory: pr
        run: npm test`,
      }),
    );
    expect(workingDirectory).toHaveLength(1);
    expect(workingDirectory[0]?.frameworkModel?.propagators[0]?.symbol).toBe(
      "workspace=pr",
    );

    expect(
      await workflowInventory(
        workflow({
          checkoutInputs: `path: pr
          allow-unsafe-pr-checkout: true`,
          stepsAfterCheckout: `- working-directory: trusted
        run: npm test`,
        }),
      ),
    ).toEqual([]);

    const localAction = await workflowInventory(
      workflow({
        checkoutInputs: `path: pr
          allow-unsafe-pr-checkout: true`,
        stepsAfterCheckout: "- uses: ./pr/action",
      }),
    );
    expect(localAction).toHaveLength(1);

    const jobDefault = await workflowInventory(
      workflow({
        checkoutInputs: `path: pr
          allow-unsafe-pr-checkout: true`,
        jobPrelude: `defaults:
      run:
        working-directory: pr`,
      }),
    );
    expect(jobDefault).toHaveLength(1);
  });

  test("clears an untrusted workspace when a later trusted checkout replaces it", async () => {
    expect(
      await workflowInventory(`
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${untrustedSha}
      - uses: actions/checkout@v7
      - run: npm test
`),
    ).toEqual([]);
    expect(
      await workflowInventory(`
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${untrustedSha}
      - uses: actions/checkout@v7
        with:
          clean: false
      - run: npm test
`),
    ).toHaveLength(1);
    expect(
      await workflowInventory(`
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          repository: ${untrustedRepository}
          path: pr
      - uses: actions/checkout@v7
      - working-directory: pr
        run: npm test
`),
    ).toEqual([]);
  });

  test("distinguishes Checkout v6 exposure from v7 default fork protection", async () => {
    const versionSix = await workflowInventory(
      workflow({
        checkoutVersion: 6,
        checkoutInputs: "persist-credentials: false",
      }),
    );
    expect(versionSix).toHaveLength(1);
    expect(
      versionSix[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).not.toContain("checkout-v7-fork-protection");

    const versionSeven = await workflowInventory(
      workflow({ checkoutInputs: "persist-credentials: false" }),
    );
    expect(
      versionSeven[0]?.frameworkModel?.candidateControls.map(
        ({ kind }) => kind,
      ),
    ).toContain("checkout-v7-fork-protection");

    const pinned = await workflowInventory(
      workflow({
        checkoutUses:
          "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        checkoutInputs: "persist-credentials: false",
      }),
    );
    expect(pinned).toHaveLength(1);
    expect(
      pinned[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).not.toContain("checkout-v7-fork-protection");
  });

  test("retains immutable review, environment, permission, and credential leads", async () => {
    const found = await workflowInventory(
      workflow({
        permissions: "read-all",
        jobPrelude: `if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
    environment: reviewed-pr`,
        checkoutInputs: "persist-credentials: false",
      }),
    );
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "mutable-review-label-gate",
      "deployment-environment-gate",
      "explicit-read-only-token",
      "checkout-v7-fork-protection",
      "checkout-credentials-not-persisted",
      "immutable-pr-commit",
    ]);
  });

  test("accepts fork repository plus mutable head ref but does not call it immutable", async () => {
    const found = await workflowInventory(`
on: [push, pull_request_target]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          repository: ${untrustedRepository}
          ref: \${{ github.event.pull_request.head.ref }}
      - run: ./gradlew test
`);
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).not.toContain("immutable-pr-commit");

    const repositoryDefaultBranch = await workflowInventory(`
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          repository: ${untrustedRepository}
      - run: make
`);
    expect(repositoryDefaultBranch).toHaveLength(1);
  });

  test("rejects malformed, duplicate-key, aliased, and non-workflow YAML", async () => {
    expect(
      await workflowInventory("on: [pull_request_target\njobs: {}"),
    ).toEqual([]);
    expect(
      await workflowInventory(`
on: pull_request_target
on: pull_request_target
jobs: {}
`),
    ).toEqual([]);
    expect(
      await workflowInventory(
        workflow(),
        "config/examples/pretend-workflow.yml",
      ),
    ).toEqual([]);
  });

  test("teaches the reviewer the current trigger, path, v7, and privilege boundary", () => {
    const prompt = scanQualityGatePrompt("scan", "/repo", "inventory-row", "");
    expect(prompt).toContain("github-actions-privileged-pr-code-execution");
    expect(prompt).toContain("complete same-job chain");
    expect(prompt).toContain("Checkout v7 and later refuses");
    expect(prompt).toContain("allow-unsafe-pr-checkout is exactly true");
    expect(prompt).toContain(
      "later trusted checkout that replaces the same path",
    );
    expect(prompt).toContain("immutable reviewed commit SHA");
  });
});
