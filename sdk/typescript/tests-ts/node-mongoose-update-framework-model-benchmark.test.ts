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
  "node-mongoose-multi-hop-update-operator-injection",
  "node-mongoose-multi-hop-safe-update-field",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function updateRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-http-mongoose-update",
    );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-mongoose-update-"),
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

describe("Node Mongoose update-document framework model", () => {
  test("keeps the operator exploit and fixed-field control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-mongoose-update-manifest.json"),
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
    expect(
      manifest.cases.every(({ findingsPaths }) => findingsPaths.length === 1),
    ).toBeTrue();
  });

  test("preserves three boundaries and the fixed $set field counterevidence", async () => {
    const vulnerable = updateRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = updateRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-http-mongoose-update",
      language: "javascript-typescript",
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 12,
        kind: "mongoose-update-document",
        cweIds: ["CWE-943", "CWE-915"],
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
      kind: "fixed-update-field-value-boundary",
      path: "src/storage.js",
      line: 12,
    });
  });

  test("accepts exact Model update positions without tainting filters, options, or replacements", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "default.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.updateOne({ name: "fixed" }, request.body.patch).exec(); }\n',
      ],
      [
        "namespace.mjs",
        'import * as mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.updateMany({ active: true }, request.body.patch).exec(); }\n',
      ],
      [
        "named.mjs",
        'import { model as makeModel, Schema } from "mongoose";\nconst User = makeModel("User", new Schema({name:String}));\nexport async function handler(request) { return User.findOneAndUpdate({ name: "fixed" }, request.body.patch).exec(); }\n',
      ],
      [
        "commonjs.cjs",
        'const mongoose = require("mongoose");\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexports.handler = async function handler(request) { return User.findByIdAndUpdate("fixed", request.body.patch).exec(); };\n',
      ],
      [
        "filter-only.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.updateOne({ name: request.body.name }, { $set: { active: false } }).exec(); }\n',
      ],
      [
        "options-only.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.updateOne({ name: "fixed" }, { $set: { active: false } }, { comment: request.body.note }).exec(); }\n',
      ],
      [
        "replacement.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.replaceOne({ name: "fixed" }, request.body.document).exec(); }\n',
      ],
      [
        "one-argument.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport async function handler(request) { return User.findOneAndUpdate(request.body.patch).exec(); }\n',
      ],
      [
        "lookalike.mjs",
        "const User = { updateOne(filter, update) { return update; } };\nexport async function handler(request) { return User.updateOne({}, request.body.patch); }\n",
      ],
      [
        "inert.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({name:String}));\nexport function handler(request) { return User.updateOne({}, request.body.patch); }\n',
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = updateRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(4);
    for (const rejected of [
      "filter-only.mjs",
      "options-only.mjs",
      "replacement.mjs",
      "one-argument.mjs",
      "lookalike.mjs",
      "inert.mjs",
    ]) {
      expect(records.some(({ path }) => path === rejected)).toBeFalse();
    }
  });

  test("credits only a fixed operator and field around the tainted scalar", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "fixed-field.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({displayName:String}));\nexport async function handler(request) { return User.updateOne({}, { $set: { displayName: request.body.displayName } }).exec(); }\n',
      ],
      [
        "whole-set.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({displayName:String}));\nexport async function handler(request) { return User.updateOne({}, { $set: request.body.patch }).exec(); }\n',
      ],
      [
        "computed-field.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({displayName:String}));\nexport async function handler(request) { return User.updateOne({}, { $set: { [request.body.field]: request.body.value } }).exec(); }\n',
      ],
      [
        "spread-update.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({displayName:String}));\nexport async function handler(request) { return User.updateOne({}, { $set: { displayName: "fixed" }, ...request.body.patch }).exec(); }\n',
      ],
      [
        "validators.mjs",
        'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({displayName:String}));\nexport async function handler(request) { return User.updateOne({}, request.body.patch, { runValidators: true }).exec(); }\n',
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = updateRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(5);
    expect(
      records.find(({ path }) => path === "fixed-field.mjs")?.frameworkModel
        ?.candidateControls,
    ).toContainEqual({
      kind: "fixed-update-field-value-boundary",
      path: "fixed-field.mjs",
      line: 3,
    });
    for (const unsafe of [
      "whole-set.mjs",
      "computed-field.mjs",
      "spread-update.mjs",
      "validators.mjs",
    ]) {
      expect(
        records.find(({ path }) => path === unsafe)?.frameworkModel
          ?.candidateControls,
      ).toEqual([]);
    }
  });

  test("ranks the unmitigated update before its controlled sibling", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "a-controlled.mjs",
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({displayName:String}));\nexport async function handler(request) { return User.updateOne({}, { $set: { displayName: request.body.displayName } }).exec(); }\n',
    );
    await writeRepositoryFile(
      repository,
      "z-unmitigated.mjs",
      'import mongoose from "mongoose";\nconst User = mongoose.model("User", new mongoose.Schema({displayName:String}));\nexport async function handler(request) { return User.updateOne({}, request.body.patch).exec(); }\n',
    );

    const records = updateRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "z-unmitigated.mjs",
      "a-controlled.mjs",
    ]);
  });

  test("teaches update grammar, validator limits, and exact impact classification", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "node-http-mongoose-update" } }),
    );
    expect(prompt).toContain("For node-http-mongoose-update rows");
    expect(prompt).toContain(
      "update argument rather than filter or options data",
    );
    expect(prompt).toContain("fixed server-owned $set field");
    expect(prompt).toContain("update validators are off by default");
    expect(prompt).toContain("CWE-943");
    expect(prompt).toContain("CWE-915");
  });
});
