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
  "node-mongoose-multi-hop-nosql-injection",
  "node-mongoose-multi-hop-safe-selector",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function nosqlRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-http-mongoose-nosql",
    );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-nosql-"));
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

describe("Node Mongoose NoSQL selector framework model", () => {
  test("keeps the exploit/control pair under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-mongoose-nosql-manifest.json"),
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
    expect(
      manifest.cases.every(({ findingsPaths }) => findingsPaths.length === 1),
    ).toBeTrue();
  });

  test("preserves three boundaries and the exact $eq counterevidence", async () => {
    const vulnerable = nosqlRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = nosqlRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-http-mongoose-nosql",
      language: "javascript-typescript",
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 10,
        kind: "mongoose-query-filter",
        cweIds: ["CWE-943"],
      },
      candidateControls: [],
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
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
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "literal-query-value-equality",
      path: "src/storage.js",
      line: 10,
    });
  });

  test("accepts exact Mongoose model bindings and only filter positions", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "default.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.findOne({ name: request.body.name }).exec(); }\n',
      ],
      [
        "namespace.mjs",
        'import * as mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.deleteOne({ name: request.body.name }).exec(); }\n',
      ],
      [
        "named.mjs",
        'import { model as makeModel, Schema } from "mongoose";\nconst User = makeModel("User", new Schema({name:String}));\nexport async function handler(request) { return User.updateOne({ name: request.body.name }, { $set: { active: false } }).exec(); }\n',
      ],
      [
        "commonjs.cjs",
        'const mongoose = require("mongoose");\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexports.handler = async function handler(request) { return User.findOneAndDelete({ name: request.body.name }).exec(); };\n',
      ],
      [
        "update-only.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({note:String}));\nexport async function handler(request) { return User.updateOne({ name: "fixed" }, { $set: { note: request.body.note } }).exec(); }\n',
      ],
      [
        "options-only.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.findOne({ name: "fixed" }, null, { comment: request.body.note }).exec(); }\n',
      ],
      [
        "lookalike.mjs",
        "const User = { findOne(filter) { return filter; } };\nexport async function handler(request) { return User.findOne({ name: request.body.name }); }\n",
      ],
      [
        "receiver-call.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose("User");\nexport async function handler(request) { return User.findOne({ name: request.body.name }).exec(); }\n',
      ],
      [
        "reassigned-factory.mjs",
        'import mongoose from "mongoose";\nmongoose = { model() { return { findOne(filter) { return filter; } }; } };\nconst User = mongoose.model("User");\nexport async function handler(request) { return User.findOne({ name: request.body.name }).exec(); }\n',
      ],
      [
        "inert-return.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport function handler(request) { return User.findOne({ name: request.body.name }); }\n',
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = nosqlRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(4);
    expect(records.some(({ path }) => path === "update-only.mjs")).toBeFalse();
    expect(records.some(({ path }) => path === "options-only.mjs")).toBeFalse();
    expect(records.some(({ path }) => path === "lookalike.mjs")).toBeFalse();
    expect(
      records.some(({ path }) => path === "receiver-call.mjs"),
    ).toBeFalse();
    expect(
      records.some(({ path }) => path === "reassigned-factory.mjs"),
    ).toBeFalse();
    expect(records.some(({ path }) => path === "inert-return.mjs")).toBeFalse();
  });

  test("retains exact literal-value controls without trusting lookalikes", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "eq.mjs",
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.findOne({ name: { $eq: request.body.name } }).exec(); }\n',
    );
    await writeRepositoryFile(
      repository,
      "sanitize.mjs",
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) {\n  const filter = mongoose.sanitizeFilter({ name: request.body.name });\n  return User.findOne(filter).exec();\n}\n',
    );
    await writeRepositoryFile(
      repository,
      "fake-sanitize.mjs",
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nfunction sanitizeFilter(value) { return value; }\nexport async function handler(request) {\n  const filter = sanitizeFilter({ name: request.body.name });\n  return User.findOne(filter).exec();\n}\n',
    );
    await writeRepositoryFile(
      repository,
      "unrelated-eq.mjs",
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.findOne({ tenant: { $eq: "public" }, name: request.body.name }).exec(); }\n',
    );
    await writeRepositoryFile(
      repository,
      "reassigned-sanitize.mjs",
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nmongoose = { sanitizeFilter(value) { return value; } };\nexport async function handler(request) {\n  const filter = mongoose.sanitizeFilter({ name: request.body.name });\n  return User.findOne(filter).exec();\n}\n',
    );
    await writeRepositoryFile(
      repository,
      "fake-store.mjs",
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nfunction sanitizeFilter(value) { return value; }\nexport async function fakeLoad(selector) {\n  const filter = sanitizeFilter({ name: selector });\n  return User.findOne(filter).exec();\n}\n',
    );
    await writeRepositoryFile(
      repository,
      "fake-server.mjs",
      'import { fakeLoad } from "./fake-store.mjs";\nexport async function handler(request) { return fakeLoad(request.body.name); }\n',
    );

    const records = nosqlRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(6);
    expect(
      records.find(({ path }) => path === "eq.mjs")?.frameworkModel
        ?.candidateControls,
    ).toContainEqual({
      kind: "literal-query-value-equality",
      path: "eq.mjs",
      line: 3,
    });
    expect(
      records.find(({ path }) => path === "sanitize.mjs")?.frameworkModel
        ?.candidateControls,
    ).toContainEqual({
      kind: "mongoose-filter-sanitization",
      path: "sanitize.mjs",
      line: 4,
    });
    expect(
      records.find(({ path }) => path === "fake-sanitize.mjs")?.frameworkModel
        ?.candidateControls,
    ).toEqual([]);
    expect(
      records.find(({ path }) => path === "unrelated-eq.mjs")?.frameworkModel
        ?.candidateControls,
    ).toEqual([]);
    expect(
      records.find(({ path }) => path === "reassigned-sanitize.mjs")
        ?.frameworkModel?.candidateControls,
    ).toEqual([]);
    expect(
      records.find(({ path }) => path === "fake-store.mjs")?.frameworkModel
        ?.candidateControls,
    ).toEqual([]);
  });

  test("teaches selector grammar, execution, and exact counterevidence", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "node-http-mongoose-nosql" } }),
    );
    expect(prompt).toContain("For node-http-mongoose-nosql rows");
    expect(prompt).toContain(
      "filter argument rather than update, projection, or options data",
    );
    expect(prompt).toContain("$eq literal-value boundary");
    expect(prompt).toContain("sanitizeFilter is opt-in");
    expect(prompt).toContain("CWE-943");
  });
});
