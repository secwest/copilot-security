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
  "node-mongoose-multi-hop-bulk-update-operator-injection",
  "node-mongoose-multi-hop-safe-bulk-update-field",
  "node-mongoose-multi-hop-bulk-replacement-mass-assignment",
  "node-mongoose-multi-hop-safe-bulk-replacement-projection",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function bulkWriteRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-http-mongoose-bulk-write",
    );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-mongoose-bulk-write-"),
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

describe("Node Mongoose bulkWrite framework model", () => {
  test("keeps two exploit/control pairs under perfect benchmark gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-mongoose-bulk-write-manifest.json"),
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
      cwe: ["CWE-943", "CWE-915"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected[0]?.cwe).toEqual(["CWE-915"]);
    expect(manifest.cases[3]?.expected).toEqual([]);
    expect(
      manifest.cases.every(({ findingsPaths }) => findingsPaths.length === 1),
    ).toBeTrue();
  });

  test("preserves three boundaries and position-specific counterevidence", async () => {
    const inventories = await Promise.all(
      caseIds.map((caseId) =>
        buildResidualRiskInventory(join(benchmarkRoot, "fixtures", caseId)),
      ),
    );
    const [unsafeUpdate, safeUpdate, unsafeReplacement, safeReplacement] =
      inventories.map(bulkWriteRecords) as [
        FrameworkRecord[],
        FrameworkRecord[],
        FrameworkRecord[],
        FrameworkRecord[],
      ];

    for (const records of inventories.map(bulkWriteRecords)) {
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
    expect(unsafeUpdate[0]?.frameworkModel).toMatchObject({
      id: "node-http-mongoose-bulk-write",
      language: "javascript-typescript",
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 12,
        kind: "mongoose-bulk-update-document",
        cweIds: ["CWE-943", "CWE-915"],
      },
      candidateControls: [],
    });
    expect(safeUpdate[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-update-field-value-boundary",
      path: "src/storage.js",
      line: 12,
    });
    expect(unsafeReplacement[0]?.frameworkModel?.candidateControls).toEqual([]);
    expect(
      safeReplacement[0]?.frameworkModel?.candidateControls,
    ).toContainEqual({
      kind: "fixed-document-field-projection",
      path: "src/storage.js",
      line: 12,
    });
  });

  test("models every documented nested data position and rejects unrelated fields", async () => {
    const repository = await temporaryRepository();
    const prefix =
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\n';
    const cases: Array<[string, string]> = [
      [
        "update-filter.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateOne: { filter: request.body.filter, update: { $set: { active: true } } } }]); }\n`,
      ],
      [
        "update-document.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateMany: { filter: {}, update: request.body.patch } }]); }\n`,
      ],
      [
        "delete-filter.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ deleteMany: { filter: request.body.filter } }]); }\n`,
      ],
      [
        "replace-filter.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ replaceOne: { filter: request.body.filter, replacement: { name: "fixed" } } }]); }\n`,
      ],
      [
        "replacement.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ replaceOne: { filter: {}, replacement: request.body.document } }]); }\n`,
      ],
      [
        "insert-document.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ insertOne: { document: request.body.document } }]); }\n`,
      ],
      [
        "whole-array.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite(request.body.operations); }\n`,
      ],
      [
        "spread-operation.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ ...request.body.operation }]); }\n`,
      ],
      [
        "spread-spec.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateOne: { filter: {}, ...request.body.spec } }]); }\n`,
      ],
      [
        "options-only.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateOne: { filter: {}, update: { $set: { active: true } } } }], { comment: request.body.note }); }\n`,
      ],
      [
        "array-filters-only.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateOne: { filter: {}, update: { $set: { active: true } }, arrayFilters: request.body.filters } }]); }\n`,
      ],
      [
        "fixed-only.mjs",
        `${prefix}export async function handler(request) { console.log(request.body.note); return User.bulkWrite([{ insertOne: { document: { name: "fixed" } } }]); }\n`,
      ],
      [
        "lookalike.mjs",
        "const User = { bulkWrite(operations) { return operations; } };\nexport async function handler(request) { return User.bulkWrite(request.body.operations); }\n",
      ],
      [
        "reassigned.mjs",
        `${prefix}User = { bulkWrite(operations) { return operations; } };\nexport async function handler(request) { return User.bulkWrite(request.body.operations); }\n`,
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = bulkWriteRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(9);
    for (const rejected of [
      "options-only.mjs",
      "array-filters-only.mjs",
      "fixed-only.mjs",
      "lookalike.mjs",
      "reassigned.mjs",
    ]) {
      expect(records.some(({ path }) => path === rejected)).toBeFalse();
    }
  });

  test("credits only complete position-specific literal boundaries", async () => {
    const repository = await temporaryRepository();
    const prefix =
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\n';
    const cases: Array<[string, string]> = [
      [
        "eq-filter.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ deleteOne: { filter: { name: { $eq: request.body.name } } } }]); }\n`,
      ],
      [
        "fixed-update.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateOne: { filter: {}, update: { $set: { name: request.body.name } } } }]); }\n`,
      ],
      [
        "fixed-insert.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ insertOne: { document: { name: request.body.name, role: "user" } } }]); }\n`,
      ],
      [
        "whole-update.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateOne: { filter: {}, update: request.body.patch } }]); }\n`,
      ],
      [
        "computed-document.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ insertOne: { document: { [request.body.field]: request.body.value } } }]); }\n`,
      ],
      [
        "spread-document.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ replaceOne: { filter: {}, replacement: { name: "fixed", ...request.body.document } } }]); }\n`,
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = bulkWriteRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(6);
    expect(
      records.find(({ path }) => path === "eq-filter.mjs")?.frameworkModel
        ?.candidateControls,
    ).toContainEqual({
      kind: "literal-query-value-equality",
      path: "eq-filter.mjs",
      line: 3,
    });
    expect(
      records.find(({ path }) => path === "fixed-update.mjs")?.frameworkModel
        ?.candidateControls,
    ).toContainEqual({
      kind: "fixed-update-field-value-boundary",
      path: "fixed-update.mjs",
      line: 3,
    });
    expect(
      records.find(({ path }) => path === "fixed-insert.mjs")?.frameworkModel
        ?.candidateControls,
    ).toContainEqual({
      kind: "fixed-document-field-projection",
      path: "fixed-insert.mjs",
      line: 3,
    });
    for (const unsafe of [
      "whole-update.mjs",
      "computed-document.mjs",
      "spread-document.mjs",
    ]) {
      expect(
        records.find(({ path }) => path === unsafe)?.frameworkModel
          ?.candidateControls,
      ).toEqual([]);
    }
  });

  test("ranks both unmitigated operation kinds before controlled siblings", async () => {
    const repository = await temporaryRepository();
    const prefix =
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\n';
    const cases: Array<[string, string]> = [
      [
        "a-safe-update.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateOne: { filter: {}, update: { $set: { name: request.body.name } } } }]); }\n`,
      ],
      [
        "b-safe-replacement.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ replaceOne: { filter: {}, replacement: { name: request.body.name, role: "user" } } }]); }\n`,
      ],
      [
        "y-unsafe-replacement.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ replaceOne: { filter: {}, replacement: request.body.document } }]); }\n`,
      ],
      [
        "z-unsafe-update.mjs",
        `${prefix}export async function handler(request) { return User.bulkWrite([{ updateOne: { filter: {}, update: request.body.patch } }]); }\n`,
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = bulkWriteRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "y-unsafe-replacement.mjs",
      "z-unsafe-update.mjs",
      "a-safe-update.mjs",
      "b-safe-replacement.mjs",
    ]);
    expect(
      records.map(({ frameworkModel }) => frameworkModel?.sink.kind),
    ).toEqual([
      "mongoose-bulk-replacement-document",
      "mongoose-bulk-update-document",
      "mongoose-bulk-update-document",
      "mongoose-bulk-replacement-document",
    ]);
    expect(
      records.map(({ frameworkModel }) => frameworkModel?.sink.cweIds),
    ).toEqual([
      ["CWE-915"],
      ["CWE-943", "CWE-915"],
      ["CWE-943", "CWE-915"],
      ["CWE-915"],
    ]);
  });

  test("teaches the nested grammar, execution contract, and impact split", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({
        frameworkModel: { id: "node-http-mongoose-bulk-write" },
      }),
    );
    expect(prompt).toContain("For node-http-mongoose-bulk-write rows");
    expect(prompt).toContain("updateOne.update");
    expect(prompt).toContain("replaceOne.replacement");
    expect(prompt).toContain("insertOne.document");
    expect(prompt).toContain("bulkWrite starts execution when called");
    expect(prompt).toContain("CWE-943");
    expect(prompt).toContain("CWE-915");
  });
});
