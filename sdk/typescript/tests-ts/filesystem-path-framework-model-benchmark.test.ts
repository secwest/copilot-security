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
  "javascript-multi-hop-path-traversal",
  "javascript-multi-hop-safe-path",
  "python-multi-hop-path-traversal",
  "python-multi-hop-safe-path",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function parseRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function pathRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter((record) =>
    ["node-http-path", "python-web-path"].includes(
      record.frameworkModel?.id ?? "",
    ),
  );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-node-python-path-"),
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

describe("Node and Python filesystem-path framework models", () => {
  test("keeps both exploit/control pairs under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "filesystem-path-framework-manifest.json"),
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
    expect(
      manifest.cases.filter(({ expected }) => expected.length > 0),
    ).toHaveLength(2);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(2);
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(1);
    }
    for (const benchmarkCase of manifest.cases.filter(
      ({ expected }) => expected.length > 0,
    )) {
      expect(benchmarkCase.expected[0]).toMatchObject({
        cwe: ["CWE-22"],
        acceptableSeverities: ["high", "medium"],
        requireValidation: true,
        requireAttackPath: true,
        requireCodeEvidence: true,
      });
    }
  });

  test("preserves three exact boundaries and fixed-map counterevidence", async () => {
    const inventories = new Map<string, FrameworkRecord[]>();
    for (const id of caseIds) {
      inventories.set(
        id,
        pathRecords(
          await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
        ),
      );
    }

    const nodeVulnerable = inventories.get(caseIds[0])!;
    const nodeSafe = inventories.get(caseIds[1])!;
    const pythonVulnerable = inventories.get(caseIds[2])!;
    const pythonSafe = inventories.get(caseIds[3])!;

    expect(nodeVulnerable).toHaveLength(1);
    expect(nodeVulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-http-path",
      language: "javascript-typescript",
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 7,
        kind: "filesystem-path",
        cweIds: ["CWE-22"],
      },
      candidateControls: [],
    });
    expect(
      nodeVulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
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
    expect(nodeSafe).toHaveLength(1);
    expect(nodeSafe[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-path-allowlist",
      path: "src/storage.js",
      line: 5,
    });

    expect(pythonVulnerable).toHaveLength(1);
    expect(pythonVulnerable[0]?.frameworkModel).toMatchObject({
      id: "python-web-path",
      language: "python",
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.py", kind: "framework-request-field" },
      sink: {
        path: "src/storage.py",
        line: 7,
        kind: "filesystem-path",
        cweIds: ["CWE-22"],
      },
      candidateControls: [],
    });
    expect(
      pythonVulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-python-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-python-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-python-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
    expect(pythonSafe).toHaveLength(1);
    expect(pythonSafe[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-path-allowlist",
      path: "src/storage.py",
      line: 4,
    });
  });

  test("accepts exact Node filesystem bindings and only path positions", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "named.mjs",
        'import { readFile as load } from "node:fs/promises";\nexport function handler(request) { return load(request.query.path, "utf8"); }\n',
      ],
      [
        "namespace.mjs",
        'import * as fs from "node:fs/promises";\nexport function handler(request) { return fs.readFile(request.query.path, "utf8"); }\n',
      ],
      [
        "default.mjs",
        'import fs from "node:fs";\nexport function handler(request) { return fs.readFileSync(request.query.path, "utf8"); }\n',
      ],
      [
        "commonjs.cjs",
        'const fs = require("node:fs");\nexports.handler = function handler(request) { return fs.readFileSync(request.query.path, "utf8"); };\n',
      ],
      [
        "destructured.cjs",
        'const { copyFileSync: copy } = require("node:fs");\nexports.handler = function handler(request) { return copy("fixed.txt", request.query.path); };\n',
      ],
      [
        "data-only.mjs",
        'import { writeFile } from "node:fs/promises";\nexport function handler(request) { return writeFile("fixed.txt", request.body); }\n',
      ],
      [
        "lookalike.mjs",
        "function readFile(path) { return path; }\nexport function handler(request) { return readFile(request.query.path); }\n",
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = pathRecords(await buildResidualRiskInventory(repository));
    expect(
      records.filter(
        (record) => record.frameworkModel?.id === "node-http-path",
      ),
    ).toHaveLength(5);
    expect(
      records.some((record) => record.path === "data-only.mjs"),
    ).toBeFalse();
    expect(
      records.some((record) => record.path === "lookalike.mjs"),
    ).toBeFalse();
  });

  test("accepts exact Python filesystem bindings and rejects shadows", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "builtin.py",
        'from flask import request\ndef handler():\n    return open(request.args.get("path"), encoding="utf-8").read()\n',
      ],
      [
        "module.py",
        'import builtins as trusted\nfrom flask import request\ndef handler():\n    return trusted.open(request.args.get("path"), encoding="utf-8").read()\n',
      ],
      [
        "named.py",
        'from builtins import open as load\nfrom flask import request\ndef handler():\n    return load(request.args.get("path"), encoding="utf-8").read()\n',
      ],
      [
        "os_alias.py",
        'import os as operating\nfrom flask import request\ndef handler():\n    return operating.remove(request.args.get("path"))\n',
      ],
      [
        "copy.py",
        'from shutil import copyfile as copy_path\nfrom flask import request\ndef handler():\n    return copy_path("fixed.txt", request.args.get("path"))\n',
      ],
      [
        "shadow.py",
        'from flask import request\ndef open(path, encoding=None):\n    return path\ndef handler():\n    return open(request.args.get("path"))\n',
      ],
      [
        "import_shadow.py",
        'from fake_files import open\nfrom flask import request\ndef handler():\n    return open(request.args.get("path"))\n',
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = pathRecords(await buildResidualRiskInventory(repository));
    expect(
      records.filter(
        (record) => record.frameworkModel?.id === "python-web-path",
      ),
    ).toHaveLength(5);
    expect(records.some((record) => record.path === "shadow.py")).toBeFalse();
    expect(
      records.some((record) => record.path === "import_shadow.py"),
    ).toBeFalse();
  });

  test("teaches exact path arguments and containment limits", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "node-http-path" } }),
    );
    expect(prompt).toContain("For node-http-path and python-web-path rows");
    expect(prompt).toContain("file contents or encoding arguments");
    expect(prompt).toContain("path.isAbsolute alone");
    expect(prompt).toContain("os.path.commonprefix is not component-aware");
  });
});
