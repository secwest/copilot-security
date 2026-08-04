import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface SelfHostedRecord {
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
  "github-actions-self-hosted-pr-execution",
  "github-actions-safe-hosted-pr-execution",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): SelfHostedRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as SelfHostedRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "github-actions-self-hosted-pr-code-execution",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<SelfHostedRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-actions-self-hosted-pr-"),
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
    runsOn?: string;
    permissions?: string;
    jobPrefix?: string;
    steps?: string;
  } = {},
): Record<string, string> {
  return {
    [options.path ?? ".github/workflows/test.yml"]: `
name: Test
on:
  ${options.trigger ?? "pull_request"}:
permissions: ${options.permissions ?? "read-all"}
jobs:
  test:
    ${options.jobPrefix ?? ""}
    runs-on: ${options.runsOn ?? "[self-hosted, linux, x64]"}
    steps:
      ${
        options.steps ??
        `- uses: actions/checkout@v6
      - run: npm test`
      }
`,
  };
}

const titleCheckout = `- uses: actions/checkout@v6
        with:
          repository: \${{ github.event.pull_request.head.repo.full_name }}
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test`;

describe("GitHub Actions self-hosted pull-request model benchmark", () => {
  test("keeps runner persistence and the hosted-runner control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "github-actions-self-hosted-pr-manifest.json"),
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
      cwe: ["CWE-284", "CWE-829"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves trigger, runner, checkout, execution, permission, and control provenance", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: ".github/workflows/test.yml",
      line: 12,
      categories: ["github-actions-self-hosted-pr-code-execution"],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "github-actions-yaml",
        scope: "same-file",
        source: {
          kind: "pull-request-capable-workflow-trigger",
          path: ".github/workflows/test.yml",
          line: 3,
          symbol: "event=pull_request",
        },
        sink: {
          kind: "untrusted-workspace-code-execution-on-self-hosted-runner",
          path: ".github/workflows/test.yml",
          line: 12,
          symbol: "run",
          cweIds: ["CWE-284", "CWE-829"],
        },
        propagators: [
          {
            kind: "self-hosted-runner-selection",
            path: ".github/workflows/test.yml",
            line: 7,
            symbol:
              "kind=explicit-self-hosted-label;selection=self-hosted,linux,x64",
          },
          {
            kind: "untrusted-checkout-request",
            path: ".github/workflows/test.yml",
            line: 9,
            symbol: "workspace=.",
          },
        ],
        candidateControls: [
          {
            kind: "explicit-read-only-token",
            path: ".github/workflows/test.yml",
            line: 4,
          },
          {
            kind: "checkout-credentials-not-persisted",
            path: ".github/workflows/test.yml",
            line: 11,
          },
        ],
      },
    });
    expect(safe).toEqual([]);
  });

  test("matches the current explicit and custom self-hosted runner forms", async () => {
    for (const runsOn of [
      "self-hosted",
      "[self-hosted, linux, x64]",
      '[self-hosted, "${{ matrix.os }}"]',
      "secwest-linux-x64",
    ]) {
      expect(await repositoryInventory(workflow({ runsOn }))).toHaveLength(1);
    }
    const grouped = await repositoryInventory(
      workflow({
        runsOn: `
      group: release-runners
      labels: [linux, x64]`,
      }),
    );
    expect(grouped).toHaveLength(1);
    expect(grouped[0]?.frameworkModel?.propagators[0]?.symbol).toContain(
      "kind=runner-group",
    );
  });

  test("rejects current standard GitHub and recognized third-party hosted labels", async () => {
    for (const runsOn of [
      "ubuntu-latest",
      "ubuntu-24.04",
      "ubuntu-24.04-arm",
      "ubuntu-slim",
      "macos-latest",
      "macos-15",
      "macos-15-large",
      "macos-15-xlarge",
      "macos-15-intel",
      "windows-latest",
      "windows-2025",
      "windows-2025-vs2026",
      "windows-2025-arm",
      "buildjet-2vcpu-ubuntu-2204",
      "warp-ubuntu-latest-x64",
    ]) {
      expect(await repositoryInventory(workflow({ runsOn }))).toEqual([]);
    }
    expect(
      await repositoryInventory(workflow({ runsOn: "${{ matrix.runner }}" })),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({ runsOn: '[custom, "${{ matrix.runner }}"]' }),
      ),
    ).toEqual([]);
  });

  test("requires exact pull-request checkout and later workspace execution closure", async () => {
    expect(
      await repositoryInventory(workflow({ steps: "- run: npm test" })),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          steps: `- uses: actions/checkout@v6
      - run: echo fixed`,
        }),
      ),
    ).toEqual([]);
    const localAction = await repositoryInventory(
      workflow({
        steps: `- uses: actions/checkout@v6
      - uses: ./ci/test-action`,
      }),
    );
    expect(localAction).toHaveLength(1);
    expect(localAction[0]?.frameworkModel?.sink.symbol).toBe(
      "uses=./ci/test-action",
    );
  });

  test("tracks checkout paths, effective working directories, and trusted cleanup", async () => {
    expect(
      await repositoryInventory(
        workflow({
          jobPrefix: `defaults:
      run:
        working-directory: pr`,
          steps: `- uses: actions/checkout@v6
        with:
          path: pr
      - run: npm test`,
        }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(
        workflow({
          steps: `- uses: actions/checkout@v6
        with:
          path: pr
      - run: npm test`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          steps: `- uses: actions/checkout@v6
      - uses: actions/checkout@v6
        with:
          ref: \${{ github.event.pull_request.base.sha }}
      - run: npm test`,
        }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          steps: `- uses: actions/checkout@v6
      - uses: actions/checkout@v6
        with:
          ref: \${{ github.event.pull_request.base.sha }}
          clean: false
      - run: npm test`,
        }),
      ),
    ).toHaveLength(1);
  });

  test("couples default and explicit pull-request checkout semantics to their triggers", async () => {
    expect(await repositoryInventory(workflow())).toHaveLength(1);
    for (const reference of [
      "${{ github.sha }}",
      "${{ github.ref }}",
      "${{ github.event.pull_request.merge_commit_sha }}",
      "${{ github.event.pull_request.head.sha }}",
    ]) {
      expect(
        await repositoryInventory(
          workflow({
            steps: `- uses: actions/checkout@v6
        with:
          ref: ${reference}
      - run: npm test`,
          }),
        ),
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory(workflow({ trigger: "pull_request_target" })),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({ trigger: "pull_request_target", steps: titleCheckout }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(
        workflow({ trigger: "pull_request_review", steps: titleCheckout }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(
        workflow({ trigger: "push", steps: titleCheckout }),
      ),
    ).toEqual([]);
    expect(
      await repositoryInventory(
        workflow({
          steps: `- uses: actions/checkout@v6
        with:
          repository: trusted/tools
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test`,
        }),
      ),
    ).toEqual([]);
  });

  test("recognizes issue-comment pull refs without guessing ordinary issue jobs", async () => {
    const issueCheckout = `- uses: actions/checkout@v6
        with:
          ref: refs/pull/\${{ github.event.issue.number }}/head
      - run: npm test`;
    expect(
      await repositoryInventory(
        workflow({ trigger: "issue_comment", steps: issueCheckout }),
      ),
    ).toHaveLength(1);
    expect(
      await repositoryInventory(workflow({ trigger: "issue_comment" })),
    ).toEqual([]);
  });

  test("keeps Checkout v7 protection distinct from ordinary pull-request checkout", async () => {
    const protectedTarget = await repositoryInventory(
      workflow({
        trigger: "pull_request_target",
        steps: titleCheckout.replace("checkout@v6", "checkout@v7"),
      }),
    );
    expect(protectedTarget).toHaveLength(1);
    expect(
      protectedTarget[0]?.frameworkModel?.candidateControls.map(
        ({ kind }) => kind,
      ),
    ).toContain("checkout-v7-fork-protection");
    const ordinary = await repositoryInventory(
      workflow({
        steps: `- uses: actions/checkout@v7
      - run: npm test`,
      }),
    );
    expect(ordinary).toHaveLength(1);
    expect(
      ordinary[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).not.toContain("checkout-v7-fork-protection");
    const ordinaryHead = await repositoryInventory(
      workflow({
        steps: titleCheckout.replace("checkout@v6", "checkout@v7"),
      }),
    );
    expect(ordinaryHead).toHaveLength(1);
    expect(
      ordinaryHead[0]?.frameworkModel?.candidateControls.map(
        ({ kind }) => kind,
      ),
    ).not.toContain("checkout-v7-fork-protection");
  });

  test("does not invent fork token impact but retains exact privileged-event evidence", async () => {
    const pullRequest = await repositoryInventory(
      workflow({
        permissions: "write-all",
        jobPrefix: "env:\n      RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}",
      }),
    );
    expect(pullRequest[0]?.categories).toEqual([
      "github-actions-self-hosted-pr-code-execution",
    ]);
    const target = await repositoryInventory(
      workflow({
        trigger: "pull_request_target",
        permissions: "write-all",
        jobPrefix: "env:\n      RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}",
        steps: titleCheckout,
      }),
    );
    expect(target[0]?.categories).toEqual([
      "github-actions-self-hosted-pr-code-execution",
      "github-actions-explicit-secret-access",
      "github-actions-write-token-permission",
    ]);
  });

  test("retains review, environment, immutable-ref, and read-only evidence", async () => {
    const gated = await repositoryInventory(
      workflow({
        trigger: "pull_request_target",
        jobPrefix: `if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
    environment: production`,
        steps: titleCheckout,
      }),
    );
    expect(gated).toHaveLength(1);
    expect(
      gated[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "mutable-review-label-gate",
      "deployment-environment-gate",
      "explicit-read-only-token",
      "immutable-pr-commit",
    ]);
  });

  test("rejects malformed, duplicate-key, aliased, dynamic, and non-workflow YAML", async () => {
    expect(
      await repositoryInventory({
        ".github/workflows/test.yml": "on: [pull_request\njobs: {}",
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        ".github/workflows/test.yml": `
on: pull_request
on: pull_request
jobs: {}
`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        ".github/workflows/test.yml": `
on: pull_request
jobs: &jobs {}
copy: *jobs
`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory(workflow({ path: "config/test.yml" })),
    ).toEqual([]);
  });

  test("teaches the reviewer runner ownership, persistence, scheduling, and isolation boundaries", () => {
    const prompt = scanQualityGatePrompt("scan", "/repo", "inventory-row", "");
    expect(prompt).toContain("github-actions-self-hosted-pr-code-execution");
    expect(prompt).toContain("complete runner-compromise chain");
    expect(prompt).toContain("runs-on-only warning");
    expect(prompt).toContain("truly ephemeral and single-job");
    expect(prompt).toContain("Docker sockets");
    expect(prompt).toContain("read-only token and absent ordinary secrets");
    expect(prompt).toContain("do not invent direct token or secret impact");
  });
});
