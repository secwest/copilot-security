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

function dsetRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-dset-prototype-pollution",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "3.1.3",
  dependencySection = "dependencies",
  dependencyName = "dset",
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
          "": { dependencies: { dset: declaration } },
          "node_modules/dset": { version: resolved },
        },
      },
      null,
      2,
    ),
  );
}

describe("dset prototype-pollution framework benchmark", () => {
  test("keeps the vulnerable 3.1.3 and repaired 3.1.4 pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-dset-prototype-pollution-manifest.json"),
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
      "node-multi-hop-dset-prototype-pollution",
      "node-multi-hop-patched-dset",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, sink, and wrapper chain", async () => {
    const vulnerable = dsetRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-dset-prototype-pollution",
        ),
      ),
    );
    const patched = dsetRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-patched-dset"),
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
        kind: "vulnerable-dset-path",
        cweIds: ["CWE-1321"],
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
    const paths = dsetRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-dset-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-dset/src/storage.js",
    );
  }, 60_000);

  test("accepts official historical and current bindings", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-dset-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "legacy-default",
        'import dset from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "1.0.1",
      ],
      [
        "legacy-commonjs",
        'const dset = require("dset");\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "2.1.0",
      ],
      [
        "named",
        'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "3.0.0",
      ],
      [
        "aliased",
        'import { dset as write } from "dset";\nexport function handler(request) { return write({}, request.body.path, true); }\n',
        "3.1.3",
      ],
      [
        "destructured",
        'const { dset: write } = require("dset");\nexport function handler(request) { return write({}, request.body.path, true); }\n',
        "3.1.3",
      ],
      [
        "namespace",
        'import * as api from "dset";\nexport function handler(request) { return api.dset({}, request.body.path, true); }\n',
        "3.1.3",
      ],
      [
        "commonjs-receiver",
        'const api = require("dset");\nexport function handler(request) { return api.dset({}, request.body.path, true); }\n',
        "3.1.3",
      ],
      [
        "direct-member",
        'const write = require("dset").dset;\nexport function handler(request) { return write({}, request.body.path, true); }\n',
        "3.1.3",
      ],
      [
        "merge-named",
        'import { dset } from "dset/merge";\nexport function handler(request) { return dset({ profile: {} }, request.body.path, true); }\n',
        "3.1.3",
      ],
      [
        "late-call",
        `import { dset } from "dset";\n${Array.from({ length: 40 }, (_, index) => `helper${index}();`).join("\n")}\nexport function handler(request) { return dset({}, request.body.path, true); }\n`,
        "3.1.3",
      ],
    ] as const;
    for (const [id, source, version] of cases) {
      await writeCase(repository, id, source, version);
    }
    await writeCase(
      repository,
      "optional-runtime",
      'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
      "3.1.3",
      "optionalDependencies",
    );

    const records = dsetRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "aliased/handler.mjs",
      "commonjs-receiver/handler.mjs",
      "destructured/handler.mjs",
      "direct-member/handler.mjs",
      "late-call/handler.mjs",
      "legacy-commonjs/handler.mjs",
      "legacy-default/handler.mjs",
      "merge-named/handler.mjs",
      "named/handler.mjs",
      "namespace/handler.mjs",
      "optional-runtime/handler.mjs",
    ]);
  });

  test("preserves path and merge-value sink provenance", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-dset-positions-"),
    );
    temporaryPaths.push(repository);
    await writeCase(
      repository,
      "direct-path",
      'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
    );
    await writeCase(
      repository,
      "merge-path",
      'import { dset } from "dset/merge";\nexport function handler(request) { return dset({ profile: {} }, request.body.path, true); }\n',
    );
    await writeCase(
      repository,
      "merge-value",
      'import { dset } from "dset/merge";\nexport function handler(request) { return dset({ profile: {} }, "profile", request.body); }\n',
      "3.1.1",
    );
    await writeCase(
      repository,
      "repaired-merge-value",
      'import { dset } from "dset/merge";\nexport function handler(request) { return dset({ profile: {} }, "profile", request.body); }\n',
      "3.1.2",
    );

    const records = dsetRecords(await buildResidualRiskInventory(repository));
    expect(
      records.map((record) => [record.path, record.frameworkModel?.sink.kind]),
    ).toEqual([
      ["direct-path/handler.mjs", "vulnerable-dset-path"],
      ["merge-path/handler.mjs", "vulnerable-dset-merge-path"],
      ["merge-value/handler.mjs", "vulnerable-dset-merge-value"],
    ]);
  });

  test("rejects repaired versions, wrong export shapes, and false argument flow", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-dset-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "fixed-3-1-4",
        'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "3.1.4",
        "dset",
      ],
      [
        "fixed-4",
        'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "4.0.0",
        "dset",
      ],
      [
        "named-on-v2",
        'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "2.1.0",
        "dset",
      ],
      [
        "callable-on-v3",
        'import dset from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "3.1.3",
        "dset",
      ],
      [
        "merge-before-export",
        'import { dset } from "dset/merge";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "3.0.0",
        "dset",
      ],
      [
        "main-value-only",
        'import { dset } from "dset";\nexport function handler(request) { return dset({}, "fixed", request.body); }\n',
        "3.1.3",
        "dset",
      ],
      [
        "target-only",
        'import { dset } from "dset";\nexport function handler(request) { return dset(request.body, "fixed", true); }\n',
        "3.1.3",
        "dset",
      ],
      [
        "wrong-package",
        'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "3.1.3",
        "dlv",
      ],
      [
        "wrong-member",
        'import * as api from "dset";\nexport function handler(request) { return api.set({}, request.body.path, true); }\n',
        "3.1.3",
        "dset",
      ],
      [
        "binding-reassigned",
        'import { dset } from "dset";\ndset = helper;\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
        "3.1.3",
        "dset",
      ],
      [
        "member-reassigned",
        'import * as api from "dset";\napi.dset = helper;\nexport function handler(request) { return api.dset({}, request.body.path, true); }\n',
        "3.1.3",
        "dset",
      ],
      [
        "shadowed",
        'import { dset } from "dset";\nexport function handler(dset, request) { return dset({}, request.body.path, true); }\n',
        "3.1.3",
        "dset",
      ],
      [
        "no-source",
        'import { dset } from "dset";\nexport function handler(request) { request.body; return dset({}, "fixed", true); }\n',
        "3.1.3",
        "dset",
      ],
    ] as const;
    for (const [id, source, version, dependency] of cases) {
      await writeCase(
        repository,
        id,
        source,
        version,
        "dependencies",
        dependency,
      );
    }
    await writeCase(
      repository,
      "range-without-lock",
      'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
      "^3.1.0",
    );
    await writeCase(
      repository,
      "development-only",
      'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n',
      "3.1.3",
      "devDependencies",
    );

    expect(dsetRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("uses fresh npm lock proof without trusting repaired or inconsistent resolutions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-dset-locks-"),
    );
    temporaryPaths.push(repository);
    const source =
      'import { dset } from "dset";\nexport function handler(request) { return dset({}, request.body.path, true); }\n';
    for (const id of ["vulnerable", "patched", "mismatch", "v1"]) {
      await writeCase(repository, id, source, "^3.1.0");
    }
    await writeNpmLock(repository, "vulnerable", "^3.1.0", "3.1.3");
    await writeNpmLock(repository, "patched", "^3.1.0", "3.1.4");
    await writeNpmLock(repository, "mismatch", "~3.0.0", "3.1.3");
    await writeNpmLock(repository, "v1", "^3.1.0", "3.1.3");
    const v1 = JSON.parse(
      await readFile(join(repository, "v1", "package-lock.json"), "utf8"),
    ) as Record<string, unknown>;
    v1["lockfileVersion"] = 1;
    await writeFile(
      join(repository, "v1", "package-lock.json"),
      JSON.stringify(v1, null, 2),
    );

    const records = dsetRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual(["vulnerable/handler.mjs"]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-dset-path",
    );
  });

  test("teaches nested path coercion and merge-value impact proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-dset-prototype-pollution");
    expect(prompt).toContain("dset(target, path, value)");
    expect(prompt).toContain('[["__proto__"], "polluted"]');
    expect(prompt).toContain("3.1.3");
    expect(prompt).toContain("3.1.4");
    expect(prompt).toContain("dset/merge");
    expect(prompt).toContain("3.1.1");
    expect(prompt).toContain("3.1.2");
    expect(prompt).toContain("pre-existing destination");
    expect(prompt).toContain("Object.prototype");
  });
});
