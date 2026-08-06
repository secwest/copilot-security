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
  "node-mongoose-multi-hop-aggregate-lookup-injection",
  "node-mongoose-multi-hop-safe-aggregate-match",
  "node-mongoose-multi-hop-aggregate-merge-injection",
  "node-mongoose-multi-hop-safe-aggregate-write-scope",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function aggregateRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-http-mongoose-aggregate",
    );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-mongoose-aggregate-"),
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

describe("Node Mongoose aggregate framework model", () => {
  test("keeps read/write exploit-control pairs under perfect benchmark gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-mongoose-aggregate-manifest.json"),
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
      cwe: ["CWE-943"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected[0]).toMatchObject({
      cwe: ["CWE-943", "CWE-915"],
      acceptableSeverities: ["high"],
    });
    expect(manifest.cases[3]?.expected).toEqual([]);
    expect(
      manifest.cases.every(({ findingsPaths }) => findingsPaths.length === 1),
    ).toBeTrue();
  });

  test("preserves three boundaries and exact match counterevidence", async () => {
    const inventories = await Promise.all(
      caseIds.map((caseId) =>
        buildResidualRiskInventory(join(benchmarkRoot, "fixtures", caseId)),
      ),
    );
    const [unsafeLookup, safeMatch, unsafeMerge, safeWrite] = inventories.map(
      aggregateRecords,
    ) as [
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
    ];

    for (const records of inventories.map(aggregateRecords)) {
      expect(records).toHaveLength(1);
      expect(
        records[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
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
    }
    expect(unsafeLookup[0]?.frameworkModel).toMatchObject({
      id: "node-http-mongoose-aggregate",
      language: "javascript-typescript",
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 12,
        kind: "mongoose-aggregate-pipeline",
        cweIds: ["CWE-943", "CWE-915"],
      },
      candidateControls: [],
    });
    expect(safeMatch[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-aggregate-match-value-boundary",
      path: "src/storage.js",
      line: 12,
    });
    expect(unsafeMerge[0]?.frameworkModel?.sink).toMatchObject({
      kind: "mongoose-aggregate-pipeline",
      cweIds: ["CWE-943", "CWE-915"],
    });
    expect(unsafeMerge[0]?.frameworkModel?.candidateControls).toEqual([]);
    expect(safeWrite[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-aggregate-match-value-boundary",
      path: "src/storage.js",
      line: 12,
    });
  });

  test("requires exact Model identity, pipeline position, and aggregate consumption", async () => {
    const repository = await temporaryRepository();
    const prefix =
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\n';
    const cases: Array<[string, string]> = [
      [
        "await.mjs",
        `${prefix}export async function handler(request) { return await User.aggregate(request.body.pipeline); }\n`,
      ],
      [
        "exec.mjs",
        `${prefix}export async function handler(request) { return User.aggregate(request.body.pipeline).exec(); }\n`,
      ],
      [
        "then.mjs",
        `${prefix}export function handler(request) { return User.aggregate(request.body.pipeline).then(Boolean); }\n`,
      ],
      [
        "cursor.mjs",
        `${prefix}export function handler(request) { return User.aggregate(request.body.pipeline).cursor(); }\n`,
      ],
      [
        "async-return.mjs",
        `${prefix}export async function handler(request) { return User.aggregate(request.body.pipeline); }\n`,
      ],
      [
        "catch.mjs",
        `${prefix}export function handler(request) { return User.aggregate(request.body.pipeline).catch(Boolean); }\n`,
      ],
      [
        "finally.mjs",
        `${prefix}export function handler(request) { return User.aggregate(request.body.pipeline).finally(Boolean); }\n`,
      ],
      [
        "multiline-exec.mjs",
        `${prefix}export async function handler(request) {\n  return User.aggregate([{ $match: request.body.filter }])\n    .exec();\n}\n`,
      ],
      [
        "assigned-await.mjs",
        `${prefix}export async function handler(request) {\n  const aggregate = User.aggregate(request.body.pipeline);\n  return await aggregate;\n}\n`,
      ],
      [
        "match-stage.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $match: request.body.filter }]).exec(); }\n`,
      ],
      [
        "lookup-stage.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $lookup: request.body.lookup }]).exec(); }\n`,
      ],
      [
        "merge-stage.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $merge: request.body.merge }]).exec(); }\n`,
      ],
      [
        "spread-stage.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ ...request.body.stage }]).exec(); }\n`,
      ],
      [
        "options-only.mjs",
        `${prefix}export async function handler(request) { console.log(request.body.note); return User.aggregate([{ $match: { active: true } }], { comment: request.body.note }).exec(); }\n`,
      ],
      [
        "inert.mjs",
        `${prefix}export function handler(request) { const aggregate = User.aggregate(request.body.pipeline); return aggregate.pipeline(); }\n`,
      ],
      [
        "lookalike.mjs",
        "const User = { aggregate(pipeline) { return pipeline; } };\nexport async function handler(request) { return await User.aggregate(request.body.pipeline); }\n",
      ],
      [
        "reassigned.mjs",
        `${prefix}User = { aggregate(pipeline) { return pipeline; } };\nexport async function handler(request) { return await User.aggregate(request.body.pipeline); }\n`,
      ],
      [
        "assigned-reassigned.mjs",
        `${prefix}export async function handler(request) {\n  let aggregate = User.aggregate(request.body.pipeline);\n  aggregate = { exec() { return []; } };\n  return aggregate.exec();\n}\n`,
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = aggregateRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(13);
    for (const accepted of [
      "await.mjs",
      "exec.mjs",
      "then.mjs",
      "cursor.mjs",
      "async-return.mjs",
      "catch.mjs",
      "finally.mjs",
      "multiline-exec.mjs",
      "assigned-await.mjs",
      "match-stage.mjs",
      "lookup-stage.mjs",
      "merge-stage.mjs",
      "spread-stage.mjs",
    ]) {
      expect(records.some(({ path }) => path === accepted)).toBeTrue();
    }
    for (const rejected of [
      "options-only.mjs",
      "inert.mjs",
      "lookalike.mjs",
      "reassigned.mjs",
      "assigned-reassigned.mjs",
    ]) {
      expect(records.some(({ path }) => path === rejected)).toBeFalse();
    }
  });

  test("credits only exact $eq match values", async () => {
    const repository = await temporaryRepository();
    const prefix =
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\n';
    const cases: Array<[string, string]> = [
      [
        "direct-equality.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $match: { name: request.body.name } }]).exec(); }\n`,
      ],
      [
        "eq-equality.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $match: { name: { $eq: request.body.name } } }]).exec(); }\n`,
      ],
      [
        "regex-value.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $match: { name: { $regex: request.body.pattern } } }]).exec(); }\n`,
      ],
      [
        "computed-field.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $match: { [request.body.field]: request.body.value } }]).exec(); }\n`,
      ],
      [
        "spread-filter.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $match: { active: true, ...request.body.filter } }]).exec(); }\n`,
      ],
      [
        "lookup-from.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $lookup: { from: request.body.collection, localField: "id", foreignField: "id", as: "joined" } }]).exec(); }\n`,
      ],
      [
        "merge-into.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $merge: { into: request.body.collection, whenMatched: "replace" } }]).exec(); }\n`,
      ],
      [
        "out-target.mjs",
        `${prefix}export async function handler(request) { return User.aggregate([{ $out: request.body.collection }]).exec(); }\n`,
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = aggregateRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(8);
    expect(
      records.find(({ path }) => path === "eq-equality.mjs")?.frameworkModel
        ?.candidateControls,
    ).toContainEqual({
      kind: "fixed-aggregate-match-value-boundary",
      path: "eq-equality.mjs",
      line: 3,
    });
    for (const unsafe of [
      "direct-equality.mjs",
      "regex-value.mjs",
      "computed-field.mjs",
      "spread-filter.mjs",
      "lookup-from.mjs",
      "merge-into.mjs",
      "out-target.mjs",
    ]) {
      expect(
        records.find(({ path }) => path === unsafe)?.frameworkModel
          ?.candidateControls,
      ).toEqual([]);
    }
  });

  test("teaches lazy execution, uncast stages, read/write impact, and exact controls", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({
        frameworkModel: { id: "node-http-mongoose-aggregate" },
      }),
    );
    expect(prompt).toContain("For node-http-mongoose-aggregate rows");
    expect(prompt).toContain("Mongoose does not cast aggregation stages");
    expect(prompt).toContain("$lookup");
    expect(prompt).toContain("$merge");
    expect(prompt).toContain("$out");
    expect(prompt).toContain("lazy Aggregate");
    expect(prompt).toContain("fixed $match");
    expect(prompt).toContain("CWE-943");
    expect(prompt).toContain("CWE-915");
  });
});
