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
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
  };
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-http-nanoid-size-dos",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-nanoid-dos-"));
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
    packageName?: string;
    version?: string;
    declaration?: string;
    lockedVersion?: string;
    section?: "dependencies" | "devDependencies";
    lock?: boolean;
    lockfileVersion?: number;
    path?: string;
  } = {},
): Promise<void> {
  const directory = join(root, id);
  await mkdir(directory, { recursive: true });
  const packageName = options.packageName ?? "nanoid";
  const declaration = options.declaration ?? options.version ?? "5.1.15";
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({
      name: id,
      private: true,
      [options.section ?? "dependencies"]: { [packageName]: declaration },
    }),
  );
  if (options.lock === true) {
    await writeFile(
      join(directory, "package-lock.json"),
      JSON.stringify({
        name: id,
        lockfileVersion: options.lockfileVersion ?? 3,
        packages: {
          "": { dependencies: { [packageName]: declaration } },
          "node_modules/nanoid": {
            version: options.lockedVersion ?? options.version ?? "5.1.15",
          },
        },
      }),
    );
  }
  const sourcePath = join(directory, options.path ?? "server.mjs");
  await mkdir(resolve(sourcePath, ".."), { recursive: true });
  await writeFile(sourcePath, source);
}

describe("nanoid attacker-controlled size denial-of-service model", () => {
  test("supports official non-secure nanoid bindings and custom generators", async () => {
    const root = await repository();
    const cases = [
      [
        "legacy-default-v1",
        'import makeId from "nanoid/non-secure";\nmakeId(req.query.size);',
        "1.3.4",
      ],
      [
        "legacy-namespace-v2",
        'import * as unsafeId from "nanoid/non-secure";\nunsafeId.default(req.query.size);',
        "2.1.11",
      ],
      [
        "legacy-commonjs-v2",
        'const makeId = require("nanoid/non-secure");\nmakeId(req.query.size);',
        "2.1.11",
      ],
      [
        "legacy-inline-v2",
        'require("nanoid/non-secure")(req.query.size);',
        "2.1.11",
      ],
      [
        "named",
        'import { nanoid as makeId } from "nanoid/non-secure";\nmakeId(req.query.size);',
      ],
      [
        "namespace",
        'import * as unsafeId from "nanoid/non-secure";\nunsafeId.nanoid(req.query.size);',
      ],
      [
        "typescript",
        'import unsafeId = require("nanoid/non-secure");\nunsafeId.nanoid(req.query.size);',
      ],
      [
        "commonjs-member",
        'const makeId = require("nanoid/non-secure").nanoid;\nmakeId(req.query.size);',
      ],
      [
        "commonjs-destructure",
        'const { nanoid: makeId } = require("nanoid/non-secure");\nmakeId(req.query.size);',
      ],
      ["inline", 'require("nanoid/non-secure").nanoid(req.query.size);'],
      [
        "custom-call-size",
        'import { customAlphabet } from "nanoid/non-secure";\nconst makeId = customAlphabet("abc");\nmakeId(req.query.size);',
      ],
      [
        "custom-default-size",
        'import { customAlphabet } from "nanoid/non-secure";\nconst makeId = customAlphabet("abc", req.query.size);\nmakeId();',
      ],
      [
        "custom-default-explicit-undefined",
        'import { customAlphabet } from "nanoid/non-secure";\nconst makeId = customAlphabet("abc", req.query.size);\nmakeId(undefined);',
      ],
      [
        "inline-custom-call-size",
        'import { customAlphabet } from "nanoid/non-secure";\ncustomAlphabet("abc")(req.query.size);',
      ],
      [
        "inline-commonjs-custom-call-size",
        'require("nanoid/non-secure").customAlphabet("abc")(req.query.size);',
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, source, version]) =>
        writeCase(root, id, source, { version }),
      ),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path).sort()).toEqual(
      cases.map(([id]) => `${id}/server.mjs`).sort(),
    );
    for (const record of found) {
      expect(record.frameworkModel?.sink.kind).toBe(
        "vulnerable-nanoid-negative-non-secure-size-infinite-loop",
      );
      expect(record.frameworkModel?.sink.cweIds).toEqual([
        "CWE-835",
        "CWE-400",
      ]);
      expect(record.frameworkModel?.propagators[0]?.symbol).toBe(
        `nanoid@${record.path.startsWith("legacy-default-v1/") ? "1.3.4" : record.path.startsWith("legacy-") ? "2.1.11" : "5.1.15"}:manifest-exact:non-secure-negative-size-infinite-loop`,
      );
    }
  });

  test("requires a remote zero default at the main custom generator factory", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "alphabet",
        'import { customAlphabet } from "nanoid";\nconst makeId = customAlphabet("abc", req.query.size);\nmakeId();',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "random",
        'import { customRandom } from "nanoid";\nconst makeId = customRandom("abc", req.body.size, random);\nmakeId();',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "inline-alphabet",
        'import { customAlphabet } from "nanoid";\ncustomAlphabet("abc", req.query.size)();',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "commonjs-factory",
        'const makeId = require("nanoid").customAlphabet("abc", req.query.size);\nmakeId(undefined);',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "commonjs-inline",
        'require("nanoid").customAlphabet("abc", req.query.size)();',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "invocation-only-control",
        'import { customAlphabet } from "nanoid";\nconst makeId = customAlphabet("abc", 21);\nmakeId(req.query.size);',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "factory-not-invoked",
        'import { customAlphabet } from "nanoid";\nconst makeId = customAlphabet("abc", req.query.size);',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "factory-default-overridden",
        'import { customAlphabet } from "nanoid";\nconst makeId = customAlphabet("abc", req.query.size);\nmakeId(12);',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "inline-default-overridden",
        'import { customAlphabet } from "nanoid";\ncustomAlphabet("abc", req.query.size)(12);',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "unavailable-before-v3",
        'import { customAlphabet } from "nanoid";\ncustomAlphabet("abc", req.query.size)();',
        { version: "2.1.11" },
      ),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path).sort()).toEqual(
      [
        "alphabet/server.mjs",
        "commonjs-factory/server.mjs",
        "commonjs-inline/server.mjs",
        "inline-alphabet/server.mjs",
        "random/server.mjs",
      ].sort(),
    );
    for (const record of found) {
      expect(record.frameworkModel?.sink.kind).toBe(
        "vulnerable-nanoid-zero-custom-default-size-infinite-loop",
      );
    }
  });

  test("enforces the exact Node repair boundaries for both causes", async () => {
    const root = await repository();
    const negative =
      'import { nanoid } from "nanoid/non-secure";\nnanoid(req.query.size);';
    const zero =
      'import { customAlphabet } from "nanoid";\nconst makeId = customAlphabet("abc", req.query.size);\nmakeId();';
    await Promise.all([
      writeCase(root, "negative-3-affected", negative, { version: "3.3.15" }),
      writeCase(root, "negative-3-fixed", negative, { version: "3.3.16" }),
      writeCase(root, "negative-5-affected", negative, { version: "5.1.15" }),
      writeCase(root, "negative-5-fixed", negative, { version: "5.1.16" }),
      writeCase(root, "zero-3-affected", zero, { version: "3.3.16" }),
      writeCase(root, "zero-3-fixed", zero, { version: "3.3.17" }),
      writeCase(root, "zero-4-affected", zero, { version: "4.0.2" }),
      writeCase(root, "zero-5-affected", zero, { version: "5.1.5" }),
      writeCase(root, "zero-5-fixed", zero, { version: "5.1.6" }),
    ]);
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(
      [
        "negative-3-affected/server.mjs",
        "negative-5-affected/server.mjs",
        "zero-3-affected/server.mjs",
        "zero-4-affected/server.mjs",
        "zero-5-affected/server.mjs",
      ].sort(),
    );
  });

  test("requires production version proof and exact official APIs", async () => {
    const root = await repository();
    const source =
      'import { nanoid } from "nanoid/non-secure";\nnanoid(req.query.size);';
    await Promise.all([
      writeCase(root, "lock-resolved", source, {
        declaration: "^5.0.0",
        lockedVersion: "5.1.15",
        lock: true,
      }),
      writeCase(root, "range-without-lock", source, {
        declaration: "^5.0.0",
      }),
      writeCase(root, "development-only", source, {
        section: "devDependencies",
      }),
      writeCase(root, "wrong-package", source, { packageName: "nanoid-safe" }),
      writeCase(
        root,
        "wrong-main-api",
        'import { nanoid } from "nanoid";\nnanoid(req.query.size);',
      ),
      writeCase(
        root,
        "fixed-input",
        'import { nanoid } from "nanoid/non-secure";\nnanoid(21);',
      ),
      writeCase(root, "test-path", source, { path: "test/server.mjs" }),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("lock-resolved/server.mjs");
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-nanoid-negative-non-secure-size-infinite-loop",
    );
    expect(found[0]?.frameworkModel?.propagators[0]?.symbol).toBe(
      "nanoid@5.1.15:npm-lockfile:non-secure-negative-size-infinite-loop",
    );
  });

  test("accepts only fresh declaration-consistent npm v2/v3 lock proof", async () => {
    const root = await repository();
    const source =
      'import { nanoid } from "nanoid/non-secure";\nnanoid(req.query.size);';
    for (const [id, lockfileVersion] of [
      ["locked-v2", 2],
      ["locked-v3", 3],
    ] as const) {
      await writeCase(root, id, source, {
        declaration: "^5.0.0",
        lockedVersion: "5.1.15",
        lock: true,
        lockfileVersion,
      });
    }
    await writeCase(root, "stale", source, { declaration: "^5.0.0" });
    await writeFile(
      join(root, "stale", "package-lock.json"),
      JSON.stringify({
        name: "stale",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { nanoid: "^4.0.0" } },
          "node_modules/nanoid": { version: "5.1.15" },
        },
      }),
    );
    await writeCase(root, "legacy-v1", source, { declaration: "^5.0.0" });
    await writeFile(
      join(root, "legacy-v1", "package-lock.json"),
      JSON.stringify({
        name: "legacy-v1",
        lockfileVersion: 1,
        dependencies: { nanoid: { version: "5.1.15" } },
      }),
    );
    await writeCase(root, "fixed-lock", source, {
      declaration: "^5.0.0",
      lockedVersion: "5.1.16",
      lock: true,
    });
    await writeCase(root, "invalid-shrinkwrap-wins", source, {
      declaration: "^5.0.0",
      lockedVersion: "5.1.15",
      lock: true,
    });
    await writeFile(
      join(root, "invalid-shrinkwrap-wins", "npm-shrinkwrap.json"),
      "{\n",
    );
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(["locked-v2/server.mjs", "locked-v3/server.mjs"]);
  });

  test("rejects reassigned, replaced, shadowed, and uninvoked generators", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "reassigned-binding",
        'import { nanoid } from "nanoid/non-secure";\nnanoid = local;\nnanoid(req.query.size);',
      ),
      writeCase(
        root,
        "replaced-member",
        'import * as unsafeId from "nanoid/non-secure";\nunsafeId.nanoid = local;\nunsafeId.nanoid(req.query.size);',
      ),
      writeCase(
        root,
        "shadowed-binding",
        'import { nanoid } from "nanoid/non-secure";\nexport function run(nanoid, req) { return nanoid(req.query.size); }',
      ),
      writeCase(
        root,
        "reassigned-generator",
        'import { customAlphabet } from "nanoid/non-secure";\nlet makeId = customAlphabet("abc");\nmakeId = safe;\nmakeId(req.query.size);',
      ),
      writeCase(
        root,
        "generator-not-called",
        'import { customAlphabet } from "nanoid/non-secure";\nconst makeId = customAlphabet("abc", req.query.size);',
      ),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("credits only fail-closed guards that exclude the exact trigger", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "negative-guard",
        'import { nanoid } from "nanoid/non-secure";\nexport function handler(req) {\n  const size = Number(req.query.size);\n  if (size < 0) throw new RangeError("negative");\n  return nanoid(size);\n}',
      ),
      writeCase(
        root,
        "zero-guard",
        'import { customAlphabet } from "nanoid";\nexport function handler(req) {\n  const size = Number(req.query.size);\n  if (!Number.isInteger(size) || size <= 0) return "";\n  const makeId = customAlphabet("abc", size);\n  return makeId();\n}',
        { version: "5.1.5" },
      ),
      writeCase(
        root,
        "zero-bound-only",
        'import { customAlphabet } from "nanoid";\nexport function handler(req) {\n  const size = Number(req.query.size);\n  if (size <= 0) return "";\n  const makeId = customAlphabet("abc", size);\n  return makeId();\n}',
        { version: "5.1.5" },
      ),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("zero-bound-only/server.mjs");
  });

  test("preserves a typed cross-file wrapper path", async () => {
    const root = await repository();
    await writeCase(
      root,
      "cross-file",
      'import { issueId } from "./ids.mjs";\nexport function handler(req) { return issueId(req.query.size); }',
      { version: "5.1.5" },
    );
    await writeFile(
      join(root, "cross-file", "ids.mjs"),
      'import { customAlphabet } from "nanoid";\nconst makeId = customAlphabet("abc", 0);\nexport function issueId(size) {\n  const configured = customAlphabet("abc", size);\n  return configured();\n}',
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.source.path).toBe("cross-file/server.mjs");
    expect(found[0]?.frameworkModel?.sink.path).toBe("cross-file/ids.mjs");
    expect(
      found[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("nanoid-runtime-dependency");
  });

  test("keeps the benchmark pair source-identical and under perfect gates", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-nanoid-size-dos",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-nanoid-size",
    );
    const found = records(await buildResidualRiskInventory(vulnerable));
    expect(found).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(found[0]?.frameworkModel?.source.line).toBe(4);
    expect(found[0]?.frameworkModel?.sink.line).toBe(4);
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "vulnerable-nanoid-negative-non-secure-size-infinite-loop",
    );
    expect(found[0]?.frameworkModel?.sink.cweIds).toEqual([
      "CWE-835",
      "CWE-400",
    ]);
    expect(found[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "nanoid@5.1.15:manifest-exact:non-secure-negative-size-infinite-loop",
    );
    for (const path of [
      join("src", "server.mjs"),
      join("src", "gateway.mjs"),
      join("src", "service.mjs"),
      join("src", "storage.mjs"),
      "witness.mjs",
    ]) {
      expect(await readFile(join(vulnerable, path), "utf8")).toBe(
        await readFile(join(patched, path), "utf8"),
      );
    }
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-nanoid-size-dos-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        expected: unknown[];
        findingsPaths: string[];
      }>;
    };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-nanoid-size-dos",
      "node-multi-hop-patched-nanoid-size",
    ]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("teaches the exact runtime trigger and Node-specific repair boundary", () => {
    const prompt = scanQualityGatePrompt("C:/scan");
    expect(prompt).toContain("node-http-nanoid-size-dos");
    expect(prompt).toContain("nanoid/non-secure");
    expect(prompt).toContain("callable 1.x/2.x");
    expect(prompt).toContain("zero configures the factory default size");
    expect(prompt).toContain("Do not treat generator(0)");
    expect(prompt).toContain("React-Native-specific async file");
    expect(prompt).toContain("kill-bounded child process");
    expect(prompt).toContain("CWE-835");
  });
});
