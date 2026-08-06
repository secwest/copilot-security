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
  "node-multi-hop-object-assign-prototype-pollution",
  "node-multi-hop-null-prototype-assign",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function copyRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-http-prototype-copy",
    );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-object-assign-"),
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

describe("Node Object.assign prototype-copy framework model", () => {
  test("keeps a strict exploit/control pair under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-object-assign-prototype-manifest.json"),
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

  test("preserves source-argument flow and exact null-prototype counterevidence", async () => {
    const [unsafe, safe] = (await Promise.all(
      caseIds.map(async (caseId) =>
        copyRecords(
          await buildResidualRiskInventory(
            join(benchmarkRoot, "fixtures", caseId),
          ),
        ),
      ),
    )) as [FrameworkRecord[], FrameworkRecord[]];

    expect(unsafe).toHaveLength(1);
    expect(safe).toHaveLength(1);
    expect(unsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "object-assign-prototype-copy",
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
    expect(safe[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "null-prototype-assignment-target",
      path: "src/storage.js",
      line: 4,
    });
  });

  test("retains the exploit and exact control under the repository cap", async () => {
    const paths = copyRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);

    for (const caseId of caseIds) {
      expect(paths).toContain(
        ["benchmarks", "fixtures", caseId, "src", "storage.js"].join("/"),
      );
    }
  }, 60_000);

  test("requires the built-in receiver and remote data in a source argument", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "accepted.mjs",
        "export function handler(request) { return Object.assign({}, request.body); }\n",
      ],
      [
        "alias.mjs",
        "export function handler(request) {\n  const patch = request.body;\n  return Object.assign({}, patch);\n}\n",
      ],
      [
        "multiple-sources.mjs",
        "export function handler(request) { return Object.assign({}, { mode: 'strict' }, request.body); }\n",
      ],
      [
        "safe-null.mjs",
        "export function handler(request) { return Object.assign(Object.create(null), request.body); }\n",
      ],
      [
        "target-only.mjs",
        "export function handler(request) { return Object.assign(request.body, { mode: 'strict' }); }\n",
      ],
      [
        "shadow-parameter.mjs",
        "export function handler(request, Object) { return Object.assign({}, request.body); }\n",
      ],
      [
        "shadow-local.mjs",
        "const Object = { assign: (target, source) => target }; export function handler(request) { return Object.assign({}, request.body); }\n",
      ],
      [
        "reassigned-member.mjs",
        "Object.assign = helper; export function handler(request) { return Object.assign({}, request.body); }\n",
      ],
      [
        "lookalike.mjs",
        "export function handler(request, copier) { return copier.assign({}, request.body); }\n",
      ],
      [
        "spread.mjs",
        "export function handler(request) { return { ...request.body }; }\n",
      ],
      [
        "text.mjs",
        "export function handler(request) { return 'Object.assign({}, request.body)'; }\n",
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = copyRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "accepted.mjs",
      "alias.mjs",
      "multiple-sources.mjs",
      "safe-null.mjs",
    ]);
    expect(
      records.find(({ path }) => path === "safe-null.mjs")?.frameworkModel
        ?.candidateControls,
    ).toContainEqual({
      kind: "null-prototype-assignment-target",
      path: "safe-null.mjs",
      line: 1,
    });
  });

  test("teaches setter semantics and separates shallow copy from recursive merge", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("Object.assign");
    expect(prompt).toContain("source arguments");
    expect(prompt).toContain("CWE-1321");
    expect(prompt).toContain("__proto__");
    expect(prompt).toContain("null-prototype");
    expect(prompt).toContain("object spread");
    expect(prompt).toContain("recursive merge");
  });
});
