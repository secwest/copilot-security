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

function objectPathRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-object-path-prototype-pollution",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "0.11.7",
  dependencySection = "dependencies",
  dependencyName = "object-path",
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
          "": { dependencies: { "object-path": declaration } },
          "node_modules/object-path": { version: resolved },
        },
      },
      null,
      2,
    ),
  );
}

describe("object-path prototype-pollution framework benchmark", () => {
  test("keeps the vulnerable 0.11.7 and repaired 0.11.8 pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-object-path-prototype-pollution-manifest.json",
        ),
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
      "node-multi-hop-object-path-prototype-pollution",
      "node-multi-hop-patched-object-path",
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
    const vulnerable = objectPathRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-object-path-prototype-pollution",
        ),
      ),
    );
    const patched = objectPathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-patched-object-path"),
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
        kind: "vulnerable-object-path-inherited-del",
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
    const paths = objectPathRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-object-path-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-object-path/src/storage.js",
    );
  }, 60_000);

  test("accepts official legacy, inherited, configured, direct, and bound APIs", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-object-path-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "legacy-commonjs-set",
        'const objectPath = require("object-path");\nexport function handler(request) { return objectPath.set({}, request.body.path, true); }\n',
        "0.9.3",
      ],
      [
        "legacy-default-bound",
        'import objectPath from "object-path";\nconst model = objectPath({});\nexport function handler(request) { return model.push(request.body.path, true); }\n',
        "0.10.0",
      ],
      [
        "legacy-destructured",
        'const { ensureExists: ensure } = require("object-path");\nexport function handler(request) { return ensure({}, request.body.path, true); }\n',
        "0.10.0",
      ],
      [
        "legacy-direct-member",
        'const insert = require("object-path").insert;\nexport function handler(request) { return insert({}, request.body.path, true, 0); }\n',
        "0.10.0",
      ],
      [
        "inherited-alias-set",
        'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.set({}, request.body.path, true); }\n',
        "0.11.5",
      ],
      [
        "inherited-configured-ensure",
        'const objectPath = require("object-path");\nconst inherited = objectPath.create({ includeInheritedProps: true });\nexport function handler(request) { return inherited.ensureExists({}, request.body.path, true); }\n',
        "0.11.5",
      ],
      [
        "inherited-inline-del",
        'import objectPath from "object-path";\nexport function handler(request) { return objectPath.withInheritedProps.del({}, request.body.path); }\n',
        "0.11.7",
      ],
      [
        "inherited-direct-require",
        'const inherited = require("object-path").withInheritedProps;\nexport function handler(request) { return inherited.empty({}, request.body.path); }\n',
        "0.11.7",
      ],
      [
        "inherited-bound",
        'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nconst model = inherited({});\nexport function handler(request) { return model.push(request.body.path, true); }\n',
        "0.11.7",
      ],
      [
        "inherited-member-binding",
        'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nconst remove = inherited.del;\nexport function handler(request) { return remove({}, request.body.path); }\n',
        "0.11.7",
      ],
      [
        "late-call",
        `const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\n${Array.from({ length: 40 }, (_, index) => `helper${index}();`).join("\n")}\nexport function handler(request) { return inherited.del({}, request.body.path); }\n`,
        "0.11.7",
      ],
    ] as const;
    for (const [id, source, version] of cases) {
      await writeCase(repository, id, source, version);
    }
    await writeCase(
      repository,
      "optional-runtime",
      'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.del({}, request.body.path); }\n',
      "0.11.7",
      "optionalDependencies",
    );

    const records = objectPathRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "inherited-alias-set/handler.mjs",
      "inherited-bound/handler.mjs",
      "inherited-configured-ensure/handler.mjs",
      "inherited-direct-require/handler.mjs",
      "inherited-inline-del/handler.mjs",
      "inherited-member-binding/handler.mjs",
      "late-call/handler.mjs",
      "legacy-commonjs-set/handler.mjs",
      "legacy-default-bound/handler.mjs",
      "legacy-destructured/handler.mjs",
      "legacy-direct-member/handler.mjs",
      "optional-runtime/handler.mjs",
    ]);
    expect(records.map((record) => record.frameworkModel?.sink.kind)).toEqual([
      "vulnerable-object-path-inherited-set",
      "vulnerable-object-path-inherited-push",
      "vulnerable-object-path-inherited-ensure-exists",
      "vulnerable-object-path-inherited-empty",
      "vulnerable-object-path-inherited-del",
      "vulnerable-object-path-inherited-del",
      "vulnerable-object-path-inherited-del",
      "vulnerable-object-path-legacy-set",
      "vulnerable-object-path-legacy-push",
      "vulnerable-object-path-legacy-ensure-exists",
      "vulnerable-object-path-legacy-insert",
      "vulnerable-object-path-inherited-del",
    ]);
  });

  test("keeps all three repair stages and method boundaries exact", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-object-path-boundaries-"),
    );
    temporaryPaths.push(repository);
    const inherited = (method: string): string =>
      `const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.${method}({}, request.body.path, true, 0); }\n`;
    for (const [id, method, version] of [
      ["set-array-bypass", "set", "0.11.5"],
      ["set-repaired", "set", "0.11.6"],
      ["ensure-array-bypass", "ensureExists", "0.11.5"],
      ["ensure-repaired", "ensureExists", "0.11.6"],
      ["del-late", "del", "0.11.7"],
      ["del-repaired", "del", "0.11.8"],
      ["empty-late", "empty", "0.11.7"],
      ["empty-repaired", "empty", "0.11.8"],
      ["push-late", "push", "0.11.7"],
      ["push-repaired", "push", "0.11.8"],
      ["insert-late", "insert", "0.11.7"],
      ["insert-repaired", "insert", "0.11.8"],
    ] as const) {
      await writeCase(repository, id, inherited(method), version);
    }

    expect(
      objectPathRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual([
      "del-late/handler.mjs",
      "empty-late/handler.mjs",
      "ensure-array-bypass/handler.mjs",
      "insert-late/handler.mjs",
      "push-late/handler.mjs",
      "set-array-bypass/handler.mjs",
    ]);
  });

  test("rejects safe modes, false argument flow, structural guesses, and unsafe metadata", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-object-path-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "default-after-0-11",
        'const objectPath = require("object-path");\nexport function handler(request) { return objectPath.set({}, request.body.path, true); }\n',
        "0.11.4",
        "object-path",
      ],
      [
        "legacy-del",
        'const objectPath = require("object-path");\nexport function handler(request) { return objectPath.del({}, request.body.path); }\n',
        "0.10.0",
        "object-path",
      ],
      [
        "legacy-empty",
        'const objectPath = require("object-path");\nexport function handler(request) { return objectPath.empty({}, request.body.path); }\n',
        "0.10.0",
        "object-path",
      ],
      [
        "configured-false",
        'const objectPath = require("object-path");\nconst safe = objectPath.create({ includeInheritedProps: false });\nexport function handler(request) { return safe.del({}, request.body.path); }\n',
        "0.11.7",
        "object-path",
      ],
      [
        "configured-dynamic",
        'const objectPath = require("object-path");\nconst maybe = objectPath.create({ includeInheritedProps: process.env.MODE });\nexport function handler(request) { return maybe.del({}, request.body.path); }\n',
        "0.11.7",
        "object-path",
      ],
      [
        "target-only",
        'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.del(request.body, "fixed"); }\n',
        "0.11.7",
        "object-path",
      ],
      [
        "value-only",
        'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.push({}, "fixed", request.body); }\n',
        "0.11.7",
        "object-path",
      ],
      [
        "read-only",
        'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.get({}, request.body.path); }\n',
        "0.11.7",
        "object-path",
      ],
      [
        "namespace-guess",
        'import * as objectPath from "object-path";\nexport function handler(request) { return objectPath.set({}, request.body.path, true); }\n',
        "0.10.0",
        "object-path",
      ],
      [
        "wrong-package",
        'const objectPath = require("object-path");\nexport function handler(request) { return objectPath.set({}, request.body.path, true); }\n',
        "0.10.0",
        "objectpath",
      ],
      [
        "binding-reassigned",
        'const objectPath = require("object-path");\nobjectPath = helper;\nexport function handler(request) { return objectPath.set({}, request.body.path, true); }\n',
        "0.10.0",
        "object-path",
      ],
      [
        "member-reassigned",
        'const objectPath = require("object-path");\nobjectPath.set = helper;\nexport function handler(request) { return objectPath.set({}, request.body.path, true); }\n',
        "0.10.0",
        "object-path",
      ],
      [
        "shadowed",
        'const objectPath = require("object-path");\nexport function handler(objectPath, request) { return objectPath.set({}, request.body.path, true); }\n',
        "0.10.0",
        "object-path",
      ],
      [
        "no-source",
        'const objectPath = require("object-path");\nexport function handler(request) { request.body; return objectPath.set({}, "fixed", true); }\n',
        "0.10.0",
        "object-path",
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
      'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.del({}, request.body.path); }\n',
      "^0.11.0",
    );
    await writeCase(
      repository,
      "development-only",
      'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.del({}, request.body.path); }\n',
      "0.11.7",
      "devDependencies",
    );

    expect(
      objectPathRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("uses fresh npm lock proof without trusting repaired or inconsistent resolutions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-object-path-locks-"),
    );
    temporaryPaths.push(repository);
    const source =
      'const objectPath = require("object-path");\nconst inherited = objectPath.withInheritedProps;\nexport function handler(request) { return inherited.del({}, request.body.path); }\n';
    for (const id of ["vulnerable", "patched", "mismatch", "v1"]) {
      await writeCase(repository, id, source, "^0.11.0");
    }
    await writeNpmLock(repository, "vulnerable", "^0.11.0", "0.11.7");
    await writeNpmLock(repository, "patched", "^0.11.0", "0.11.8");
    await writeNpmLock(repository, "mismatch", "~0.11.0", "0.11.7");
    await writeNpmLock(repository, "v1", "^0.11.0", "0.11.7");
    const v1 = JSON.parse(
      await readFile(join(repository, "v1", "package-lock.json"), "utf8"),
    ) as Record<string, unknown>;
    v1["lockfileVersion"] = 1;
    await writeFile(
      join(repository, "v1", "package-lock.json"),
      JSON.stringify(v1, null, 2),
    );

    const records = objectPathRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual(["vulnerable/handler.mjs"]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-object-path-inherited-del",
    );
  });

  test("teaches mode, callable argument shifts, all repairs, and impact proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-object-path-prototype-pollution");
    expect(prompt).toContain("withInheritedProps");
    expect(prompt).toContain("includeInheritedProps:true");
    expect(prompt).toContain("0.11.5");
    expect(prompt).toContain("0.11.6");
    expect(prompt).toContain("0.11.7");
    expect(prompt).toContain("0.11.8");
    expect(prompt).toContain('[["__proto__"], "polluted"]');
    expect(prompt).toContain("path argument one");
    expect(prompt).toContain("path is argument zero");
    expect(prompt).toContain("del, empty, push, and insert");
    expect(prompt).toContain("Object.prototype");
  });
});
