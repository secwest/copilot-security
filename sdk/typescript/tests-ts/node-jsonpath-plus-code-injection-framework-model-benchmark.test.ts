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
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function jsonPathRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-jsonpath-plus-code-injection",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "10.3.0",
  dependencySection = "dependencies",
  dependencyName = "jsonpath-plus",
): Promise<void> {
  const root = join(repository, id);
  await mkdir(root, { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [dependencySection]: { [dependencyName]: version },
      },
      null,
      2,
    ),
  );
  await writeFile(join(root, "handler.mjs"), source);
}

async function writeNpmLock(
  repository: string,
  id: string,
  declaration: string,
  resolved: string,
): Promise<void> {
  await writeFile(
    join(repository, id, "package-lock.json"),
    JSON.stringify(
      {
        name: id,
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "jsonpath-plus": declaration } },
          "node_modules/jsonpath-plus": { version: resolved },
        },
      },
      null,
      2,
    ),
  );
}

describe("jsonpath-plus code-injection framework benchmark", () => {
  test("keeps a strict vulnerable and patched benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-jsonpath-plus-code-injection-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 1 || value === 0,
      ),
    ).toBe(true);
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-jsonpath-plus-rce",
      "node-multi-hop-patched-jsonpath-plus",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-94"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, sink, and wrapper chain", async () => {
    const vulnerable = jsonPathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-jsonpath-plus-rce"),
      ),
    );
    const patched = jsonPathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-patched-jsonpath-plus"),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(patched).toEqual([]);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-jsonpath-plus-safe-eval",
        cweIds: ["CWE-94"],
      },
      propagators: [
        { kind: "relative-module-import", path: "src/server.js", line: 2 },
        { kind: "wrapper-call-argument", path: "src/server.js", line: 8 },
        { kind: "wrapper-parameter", path: "src/gateway.js", line: 3 },
        { kind: "relative-module-import", path: "src/gateway.js", line: 1 },
        { kind: "wrapper-call-argument", path: "src/gateway.js", line: 4 },
        { kind: "wrapper-parameter", path: "src/service.js", line: 3 },
        { kind: "relative-module-import", path: "src/service.js", line: 1 },
        { kind: "wrapper-call-argument", path: "src/service.js", line: 4 },
        { kind: "wrapper-parameter", path: "src/storage.js", line: 3 },
      ],
    });
  });

  test("retains the vulnerable row under the repository candidate cap", async () => {
    const paths = jsonPathRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-jsonpath-plus-rce/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-jsonpath-plus/src/storage.js",
    );
  }, 60_000);

  test("accepts official API shapes, safe-eval versions, and explicit native evaluation", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-jsonpath-plus-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "named-object",
        'import { JSONPath } from "jsonpath-plus";\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [] }); }\n',
        "10.3.0",
      ],
      [
        "aliased",
        'import { JSONPath as select } from "jsonpath-plus";\nexport function handler(request) { return select(request.query.path, []); }\n',
        "9.0.0",
      ],
      [
        "destructured",
        'const { JSONPath: select } = require("jsonpath-plus");\nexport function handler(request) { return select({ path: request.query.path, json: [] }); }\n',
        "10.2.0",
      ],
      [
        "namespace",
        'import * as jp from "jsonpath-plus";\nexport function handler(request) { return jp.JSONPath(request.query.path, []); }\n',
        "10.3.0",
      ],
      [
        "commonjs",
        'const jp = require("jsonpath-plus");\nexport function handler(request) { return new jp.JSONPath({ path: request.query.path, json: [] }); }\n',
        "10.3.0",
      ],
      [
        "direct-member",
        'const select = require("jsonpath-plus").JSONPath;\nexport function handler(request) { return select({ path: request.query.path, json: [] }); }\n',
        "10.3.0",
      ],
      [
        "shorthand",
        'import { JSONPath } from "jsonpath-plus";\nexport function handler(request) {\n  const path = request.query.path;\n  const options = { path, json: [] };\n  return JSONPath(options);\n}\n',
        "10.3.0",
      ],
      [
        "positional-options",
        'import { JSONPath } from "jsonpath-plus";\nexport function handler(request) { return JSONPath({ eval: "safe" }, request.query.path, []); }\n',
        "10.3.0",
      ],
      [
        "native-patched",
        'import { JSONPath } from "jsonpath-plus";\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [], eval: "native" }); }\n',
        "10.4.0",
      ],
      [
        "late-call",
        `import { JSONPath } from "jsonpath-plus";\n${Array.from({ length: 40 }, (_, index) => `helper${index}();`).join("\n")}\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [] }); }\n`,
        "10.3.0",
      ],
    ] as const;
    for (const [id, source, version] of cases) {
      await writeCase(repository, id, source, version);
    }

    const records = jsonPathRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "aliased/handler.mjs",
      "commonjs/handler.mjs",
      "destructured/handler.mjs",
      "direct-member/handler.mjs",
      "late-call/handler.mjs",
      "named-object/handler.mjs",
      "namespace/handler.mjs",
      "native-patched/handler.mjs",
      "positional-options/handler.mjs",
      "shorthand/handler.mjs",
    ]);
    expect(
      records.find(({ path }) => path.startsWith("native-patched/"))
        ?.frameworkModel?.sink.kind,
    ).toBe("jsonpath-plus-native-eval");
  });

  test("rejects patched safe evaluation and structural false positives", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-jsonpath-plus-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["patched", "10.4.0", "{ path: request.query.path, json: [] }"],
      ["later", "11.0.0", "{ path: request.query.path, json: [] }"],
      [
        "disabled",
        "10.3.0",
        "{ path: request.query.path, json: [], eval: false }",
      ],
      [
        "custom",
        "10.3.0",
        "{ path: request.query.path, json: [], eval: evaluator }",
      ],
      ["wrong-argument", "10.3.0", '{ path: "$.fixed", json: request.body }'],
      ["no-source", "10.3.0", '{ path: "$.fixed", json: [] }'],
    ] as const;
    for (const [id, version, options] of cases) {
      await writeCase(
        repository,
        id,
        `import { JSONPath } from "jsonpath-plus";\nexport function handler(request) { request.body; return JSONPath(${options}); }\n`,
        version,
      );
    }
    await writeCase(
      repository,
      "default-guess",
      'import JSONPath from "jsonpath-plus";\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [] }); }\n',
    );
    await writeCase(
      repository,
      "wrong-member",
      'import * as jp from "jsonpath-plus";\nexport function handler(request) { return jp.toPathArray(request.query.path); }\n',
    );
    await writeCase(
      repository,
      "wrong-package",
      'import { JSONPath } from "jsonpath-plus";\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [] }); }\n',
      "10.3.0",
      "dependencies",
      "jsonpath",
    );
    await writeCase(
      repository,
      "receiver-reassigned",
      'import * as jp from "jsonpath-plus";\njp = helper;\nexport function handler(request) { return jp.JSONPath({ path: request.query.path, json: [] }); }\n',
    );
    await writeCase(
      repository,
      "member-reassigned",
      'import * as jp from "jsonpath-plus";\njp.JSONPath = helper;\nexport function handler(request) { return jp.JSONPath({ path: request.query.path, json: [] }); }\n',
    );
    await writeCase(
      repository,
      "binding-reassigned",
      'import { JSONPath } from "jsonpath-plus";\nJSONPath = helper;\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [] }); }\n',
    );
    await writeCase(
      repository,
      "shadowed",
      'import { JSONPath } from "jsonpath-plus";\nexport function handler(JSONPath, request) { return JSONPath({ path: request.query.path, json: [] }); }\n',
    );
    await writeCase(
      repository,
      "range-without-lock",
      'import { JSONPath } from "jsonpath-plus";\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [] }); }\n',
      "^10.0.0",
    );
    await writeCase(
      repository,
      "development-only",
      'import { JSONPath } from "jsonpath-plus";\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [] }); }\n',
      "10.3.0",
      "devDependencies",
    );

    expect(
      jsonPathRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("uses fresh npm lock proof without trusting patched or inconsistent resolutions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-jsonpath-plus-locks-"),
    );
    temporaryPaths.push(repository);
    const source =
      'import { JSONPath } from "jsonpath-plus";\nexport function handler(request) { return JSONPath({ path: request.query.path, json: [] }); }\n';
    for (const id of ["vulnerable", "patched", "mismatch", "v1"]) {
      await writeCase(repository, id, source, "^10.0.0");
    }
    await writeNpmLock(repository, "vulnerable", "^10.0.0", "10.3.0");
    await writeNpmLock(repository, "patched", "^10.0.0", "10.4.0");
    await writeNpmLock(repository, "mismatch", "~10.0.0", "10.3.0");
    await writeNpmLock(repository, "v1", "^10.0.0", "10.3.0");
    const v1 = JSON.parse(
      await readFile(join(repository, "v1", "package-lock.json"), "utf8"),
    ) as Record<string, unknown>;
    v1["lockfileVersion"] = 1;
    await writeFile(
      join(repository, "v1", "package-lock.json"),
      JSON.stringify(v1, null, 2),
    );

    const records = jsonPathRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual(["vulnerable/handler.mjs"]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-jsonpath-plus-safe-eval",
    );
  });

  test("teaches both safe-evaluator boundaries and concrete execution proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-jsonpath-plus-code-injection");
    expect(prompt).toContain("jsonpath-plus");
    expect(prompt).toContain("10.4.0 boundary");
    expect(prompt).toContain("__lookupGetter__");
    expect(prompt).toContain("Function");
    expect(prompt).toContain('eval: "native"');
    expect(prompt).toContain("eval: false");
  });
});
