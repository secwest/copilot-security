import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  frameworkModel?: {
    id: string;
    language: string;
    scope: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{ kind: string; path: string; line: number }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    findingsPaths: string[];
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
  "node-multi-hop-prototype-pollution",
  "node-multi-hop-safe-prototype-map",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function prototypeRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-http-prototype-pollution",
    );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-prototype-pollution-"),
  );
  temporaryPaths.push(repository);
  return repository;
}

async function writeRepositoryFile(
  repository: string,
  relativePath: string,
  contents: string,
): Promise<void> {
  const path = join(repository, relativePath);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, contents);
}

describe("Node prototype-pollution framework model", () => {
  test("keeps a strict exploit/control pair under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-prototype-pollution-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(
      manifest.cases.every(({ findingsPaths }) => findingsPaths.length === 1),
    ).toBeTrue();
  });

  test("preserves the exact three-boundary path to nested computed keys", async () => {
    const [unsafe, safe] = (await Promise.all(
      caseIds.map(async (caseId) =>
        prototypeRecords(
          await buildResidualRiskInventory(
            join(benchmarkRoot, "fixtures", caseId),
          ),
        ),
      ),
    )) as [FrameworkRecord[], FrameworkRecord[]];

    expect(unsafe).toHaveLength(1);
    expect(safe).toEqual([]);
    expect(unsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: {
        path: "src/server.js",
        line: 8,
        kind: "http-request-field",
      },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "nested-computed-property-write",
        cweIds: ["CWE-1321"],
      },
      candidateControls: [],
    });
    expect(
      unsafe[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
  });

  test("retains the exploit and excludes the Map control under the repository cap", async () => {
    const records = prototypeRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    );

    expect(records.map(({ path }) => path)).toEqual([
      ["benchmarks", "fixtures", caseIds[0], "src", "storage.js"].join("/"),
    ]);
  }, 60_000);

  test("requires remote flow into two dynamic key positions", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "accepted.mjs",
        "export function handler(request, target) { target[request.body.namespace][request.body.key] = request.body.value; }\n",
      ],
      [
        "prior-assignment.mjs",
        "export function handler(request, target) { const marker = true; target[request.body.namespace][request.body.key] = marker; }\n",
      ],
      [
        "value-only.mjs",
        "export function handler(request, target) { target.fixed.value = request.body.value; }\n",
      ],
      [
        "one-key.mjs",
        "export function handler(request, target) { target[request.body.key] = request.body.value; }\n",
      ],
      [
        "dynamic-local-keys-value-only.mjs",
        'export function handler(request, target) { const namespace = "preferences"; const key = "theme"; target[namespace][key] = request.body.value; }\n',
      ],
      [
        "fixed-first-key.mjs",
        'export function handler(request, target) { target["preferences"][request.body.key] = request.body.value; }\n',
      ],
      [
        "comparison.mjs",
        "export function handler(request, target) { return target[request.body.namespace][request.body.key] === request.body.value; }\n",
      ],
      [
        "compound-assignment.mjs",
        "export function handler(request, target) { target[request.body.namespace][request.body.key] += request.body.value; }\n",
      ],
      [
        "map.mjs",
        "export function handler(request, target) { const nested = target.get(request.body.namespace) ?? new Map(); nested.set(request.body.key, request.body.value); }\n",
      ],
      [
        "text.mjs",
        'export function handler(request) { return "target[request.body.namespace][request.body.key] = request.body.value"; }\n',
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = prototypeRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "accepted.mjs",
      "prior-assignment.mjs",
    ]);
  });

  test("teaches exact prototype reachability and resilient key storage", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("prototype pollution");
    expect(prompt).toContain("CWE-1321");
    expect(prompt).toContain("nested computed");
    expect(prompt).toContain("__proto__");
    expect(prompt).toContain("constructor");
    expect(prompt).toContain("prototype");
    expect(prompt).toContain("Map");
    expect(prompt).toContain("Object.create(null)");
  });
});
