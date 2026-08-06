import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
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
  "node-multi-hop-lodash-merge-prototype-pollution",
  "node-multi-hop-patched-lodash-merge",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function mergeRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-http-prototype-merge",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  dependencySection = "dependencies",
  version = "4.17.11",
): Promise<void> {
  const root = join(repository, id);
  await mkdir(root, { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [dependencySection]: { lodash: version },
      },
      null,
      2,
    ),
  );
  await writeFile(join(root, "handler.mjs"), source);
}

describe("Node version-aware Lodash prototype-merge framework model", () => {
  test("keeps a strict vulnerable-version/patched-version pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-lodash-prototype-merge-manifest.json"),
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

  test("preserves the three-boundary source flow only for the vulnerable pin", async () => {
    const [unsafe, safe] = (await Promise.all(
      caseIds.map(async (caseId) =>
        mergeRecords(
          await buildResidualRiskInventory(
            join(benchmarkRoot, "fixtures", caseId),
          ),
        ),
      ),
    )) as [FrameworkRecord[], FrameworkRecord[]];

    expect(unsafe).toHaveLength(1);
    expect(safe).toHaveLength(0);
    expect(unsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-lodash-recursive-merge",
        cweIds: ["CWE-1321"],
      },
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

  test("retains the vulnerable row under the repository cap", async () => {
    const paths = mergeRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);

    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-lodash-merge-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-lodash-merge/src/storage.js",
    );
  }, 60_000);

  test("requires an official binding, vulnerable exact runtime pin, and source operand", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-lodash-merge-"),
    );
    temporaryPaths.push(repository);
    const accepted = [
      [
        "default",
        'import lodash from "lodash";\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
      ],
      [
        "namespace",
        'import * as lodash from "lodash";\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
      ],
      [
        "commonjs",
        'const lodash = require("lodash");\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
      ],
      [
        "subpath",
        'import combine from "lodash/merge.js";\nexport function handler(request) { return combine({}, request.body); }\n',
      ],
      [
        "destructured",
        'const { merge: combine } = require("lodash");\nexport function handler(request) { return combine({}, request.body); }\n',
      ],
    ] as const;
    for (const [id, source] of accepted) {
      await writeCase(repository, id, source);
    }
    await writeCase(
      repository,
      "optional",
      'import lodash from "lodash";\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
      "optionalDependencies",
    );
    const rejected: Array<[string, string, string, string]> = [
      ["patched", accepted[0][1], "dependencies", "4.17.21"],
      ["range", accepted[0][1], "dependencies", "^4.17.11"],
      ["dev-only", accepted[0][1], "devDependencies", "4.17.11"],
      [
        "target-only",
        'import lodash from "lodash";\nexport function handler(request) { return lodash.merge(request.body, { mode: "strict" }); }\n',
        "dependencies",
        "4.17.11",
      ],
      [
        "lookalike",
        'import lodash from "lodash-lookalike";\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
        "dependencies",
        "4.17.11",
      ],
      [
        "reassigned",
        'import lodash from "lodash";\nlodash = helper;\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
        "dependencies",
        "4.17.11",
      ],
      [
        "member-reassigned",
        'import lodash from "lodash";\nlodash.merge = helper;\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
        "dependencies",
        "4.17.11",
      ],
      [
        "same-line-reassigned",
        'import lodash from "lodash";\nexport function handler(request) { lodash.merge = helper; return lodash.merge({}, request.body); }\n',
        "dependencies",
        "4.17.11",
      ],
      [
        "text",
        'import lodash from "lodash";\nexport function handler(request) { return "lodash.merge({}, request.body)"; }\n',
        "dependencies",
        "4.17.11",
      ],
    ];
    for (const [id, source, section, version] of rejected) {
      await writeCase(repository, id, source, section, version);
    }
    for (const id of ["missing", "malformed"] as const) {
      const root = join(repository, id);
      await mkdir(root, { recursive: true });
      await writeFile(
        join(root, "handler.mjs"),
        'import lodash from "lodash";\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
      );
      if (id === "malformed") {
        await writeFile(join(root, "package.json"), "{\n");
      }
    }

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "commonjs/handler.mjs",
      "default/handler.mjs",
      "destructured/handler.mjs",
      "namespace/handler.mjs",
      "optional/handler.mjs",
      "subpath/handler.mjs",
    ]);
  });

  test("teaches version, recursion, manifest, and constructor.prototype proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-prototype-merge");
    expect(prompt).toContain("lodash");
    expect(prompt).toContain("4.17.12");
    expect(prompt).toContain("nearest package.json");
    expect(prompt).toContain("source operands");
    expect(prompt).toContain("constructor.prototype");
    expect(prompt).toContain("CWE-1321");
  });
});
