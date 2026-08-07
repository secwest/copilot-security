import { afterEach, describe, expect, test } from "bun:test";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
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
  "node-multi-hop-locked-lodash-merge-prototype-pollution",
  "node-multi-hop-locked-patched-lodash-merge",
  "node-multi-hop-lodash-merge-package-prototype-pollution",
  "node-multi-hop-patched-lodash-merge-package",
  "node-multi-hop-merge-deep-prototype-pollution",
  "node-multi-hop-patched-merge-deep",
  "node-multi-hop-extend-deep-prototype-pollution",
  "node-multi-hop-patched-extend-deep",
  "node-multi-hop-deep-extend-prototype-pollution",
  "node-multi-hop-patched-deep-extend",
  "node-multi-hop-just-extend-prototype-pollution",
  "node-multi-hop-patched-just-extend",
  "node-multi-hop-merge-options-prototype-pollution",
  "node-multi-hop-patched-merge-options",
  "node-multi-hop-node-extend-prototype-pollution",
  "node-multi-hop-patched-node-extend",
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
  version = "4.17.10",
  dependencyName = "lodash",
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
  resolvedVersion: string,
  options: {
    name?: "package-lock.json" | "npm-shrinkwrap.json";
    lockfileVersion?: number;
    rootDeclaration?: string;
    includeInstalledPackage?: boolean;
    dependencyName?: string;
  } = {},
): Promise<void> {
  const dependencyName = options.dependencyName ?? "lodash";
  await writeFile(
    join(repository, id, options.name ?? "package-lock.json"),
    JSON.stringify(
      {
        name: id,
        lockfileVersion: options.lockfileVersion ?? 3,
        packages: {
          "": {
            dependencies: {
              [dependencyName]: options.rootDeclaration ?? declaration,
            },
          },
          ...(options.includeInstalledPackage === false
            ? {}
            : {
                [`node_modules/${dependencyName}`]: {
                  version: resolvedVersion,
                },
              }),
        },
      },
      null,
      2,
    ),
  );
}

describe("Node version-aware Lodash prototype-merge framework model", () => {
  test("keeps exact-pin and lock-resolved vulnerable/patched pairs", async () => {
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
    expect(manifest.cases[2]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[3]?.expected).toEqual([]);
    expect(manifest.cases[4]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[5]?.expected).toEqual([]);
    expect(manifest.cases[6]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[7]?.expected).toEqual([]);
    expect(manifest.cases[8]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[9]?.expected).toEqual([]);
    expect(manifest.cases[10]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[11]?.expected).toEqual([]);
    expect(manifest.cases[12]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[13]?.expected).toEqual([]);
    expect(manifest.cases[14]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[15]?.expected).toEqual([]);
    expect(manifest.cases[16]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[17]?.expected).toEqual([]);
    expect(
      manifest.cases.every(({ findingsPaths }) => findingsPaths.length === 1),
    ).toBeTrue();
  });

  test("preserves the three-boundary source flow only for vulnerable resolved versions", async () => {
    const [
      unsafe,
      safe,
      lockedUnsafe,
      lockedSafe,
      packageUnsafe,
      packageSafe,
      mergeDeepUnsafe,
      mergeDeepSafe,
      extendUnsafe,
      extendSafe,
      deepExtendUnsafe,
      deepExtendSafe,
      justExtendUnsafe,
      justExtendSafe,
      mergeOptionsUnsafe,
      mergeOptionsSafe,
      nodeExtendUnsafe,
      nodeExtendSafe,
    ] = (await Promise.all(
      caseIds.map(async (caseId) =>
        mergeRecords(
          await buildResidualRiskInventory(
            join(benchmarkRoot, "fixtures", caseId),
          ),
        ),
      ),
    )) as [
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
      FrameworkRecord[],
    ];

    expect(unsafe).toHaveLength(1);
    expect(safe).toHaveLength(0);
    expect(lockedUnsafe).toHaveLength(1);
    expect(lockedSafe).toHaveLength(0);
    expect(packageUnsafe).toHaveLength(1);
    expect(packageSafe).toHaveLength(0);
    expect(mergeDeepUnsafe).toHaveLength(1);
    expect(mergeDeepSafe).toHaveLength(0);
    expect(extendUnsafe).toHaveLength(1);
    expect(extendSafe).toHaveLength(0);
    expect(deepExtendUnsafe).toHaveLength(1);
    expect(deepExtendSafe).toHaveLength(0);
    expect(justExtendUnsafe).toHaveLength(1);
    expect(justExtendSafe).toHaveLength(0);
    expect(mergeOptionsUnsafe).toHaveLength(1);
    expect(mergeOptionsSafe).toHaveLength(0);
    expect(nodeExtendUnsafe).toHaveLength(1);
    expect(nodeExtendSafe).toHaveLength(0);
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
    expect(lockedUnsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "lock-resolved-vulnerable-lodash-recursive-merge",
        cweIds: ["CWE-1321"],
      },
    });
    expect(lockedUnsafe[0]?.frameworkModel?.propagators).toEqual(
      unsafe[0]?.frameworkModel?.propagators,
    );
    expect(packageUnsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-lodash-merge-package-recursive-merge",
        cweIds: ["CWE-1321"],
      },
    });
    expect(packageUnsafe[0]?.frameworkModel?.propagators).toEqual(
      unsafe[0]?.frameworkModel?.propagators,
    );
    expect(mergeDeepUnsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-merge-deep-recursive-merge",
        cweIds: ["CWE-1321"],
      },
    });
    expect(mergeDeepUnsafe[0]?.frameworkModel?.propagators).toEqual(
      unsafe[0]?.frameworkModel?.propagators,
    );
    expect(extendUnsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-extend-deep-merge",
        cweIds: ["CWE-1321"],
      },
    });
    expect(extendUnsafe[0]?.frameworkModel?.propagators).toEqual(
      unsafe[0]?.frameworkModel?.propagators,
    );
    expect(deepExtendUnsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-deep-extend-recursive-merge",
        cweIds: ["CWE-1321"],
      },
    });
    expect(deepExtendUnsafe[0]?.frameworkModel?.propagators).toEqual(
      unsafe[0]?.frameworkModel?.propagators,
    );
    expect(justExtendUnsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-just-extend-deep-merge",
        cweIds: ["CWE-1321"],
      },
    });
    expect(justExtendUnsafe[0]?.frameworkModel?.propagators).toEqual(
      unsafe[0]?.frameworkModel?.propagators,
    );
    expect(mergeOptionsUnsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-merge-options-recursive-merge",
        cweIds: ["CWE-1321"],
      },
    });
    expect(mergeOptionsUnsafe[0]?.frameworkModel?.propagators).toEqual(
      unsafe[0]?.frameworkModel?.propagators,
    );
    expect(nodeExtendUnsafe[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 8, kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-node-extend-deep-merge",
        cweIds: ["CWE-1321"],
      },
    });
    expect(nodeExtendUnsafe[0]?.frameworkModel?.propagators).toEqual(
      unsafe[0]?.frameworkModel?.propagators,
    );
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
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-locked-lodash-merge-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-locked-patched-lodash-merge/src/storage.js",
    );
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-lodash-merge-package-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-lodash-merge-package/src/storage.js",
    );
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-merge-deep-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-merge-deep/src/storage.js",
    );
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-extend-deep-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-extend-deep/src/storage.js",
    );
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-deep-extend-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-deep-extend/src/storage.js",
    );
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-just-extend-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-just-extend/src/storage.js",
    );
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-merge-options-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-merge-options/src/storage.js",
    );
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-node-extend-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-node-extend/src/storage.js",
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
      ["fixed-boundary", accepted[0][1], "dependencies", "4.17.11"],
      ["patched", accepted[0][1], "dependencies", "4.17.21"],
      ["range", accepted[0][1], "dependencies", "^4.17.10"],
      ["dev-only", accepted[0][1], "devDependencies", "4.17.10"],
      [
        "target-only",
        'import lodash from "lodash";\nexport function handler(request) { return lodash.merge(request.body, { mode: "strict" }); }\n',
        "dependencies",
        "4.17.10",
      ],
      [
        "lookalike",
        'import lodash from "lodash-lookalike";\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
        "dependencies",
        "4.17.10",
      ],
      [
        "reassigned",
        'import lodash from "lodash";\nlodash = helper;\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
        "dependencies",
        "4.17.10",
      ],
      [
        "member-reassigned",
        'import lodash from "lodash";\nlodash.merge = helper;\nexport function handler(request) { return lodash.merge({}, request.body); }\n',
        "dependencies",
        "4.17.10",
      ],
      [
        "same-line-reassigned",
        'import lodash from "lodash";\nexport function handler(request) { lodash.merge = helper; return lodash.merge({}, request.body); }\n',
        "dependencies",
        "4.17.10",
      ],
      [
        "text",
        'import lodash from "lodash";\nexport function handler(request) { return "lodash.merge({}, request.body)"; }\n',
        "dependencies",
        "4.17.10",
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

  test("accepts fresh npm v2/v3 resolution and rejects stale or unsupported lock evidence", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-lodash-lock-"),
    );
    temporaryPaths.push(repository);
    const source =
      'import lodash from "lodash";\nexport function handler(request) { return lodash.merge({}, request.body); }\n';

    for (const [id, declaration, lockfileVersion] of [
      ["caret-v3", "^4.17.0", 3],
      ["comparator-v2", ">=4.0.0 <4.17.11", 2],
      ["wildcard-v3", "4.x", 3],
    ] as const) {
      await writeCase(repository, id, source, "dependencies", declaration);
      await writeNpmLock(repository, id, declaration, "4.17.10", {
        lockfileVersion,
      });
    }

    await writeCase(
      repository,
      "shrinkwrap-wins",
      source,
      "dependencies",
      "^4.17.0",
    );
    await writeNpmLock(repository, "shrinkwrap-wins", "^4.17.0", "4.17.21");
    await writeNpmLock(repository, "shrinkwrap-wins", "^4.17.0", "4.17.10", {
      name: "npm-shrinkwrap.json",
    });

    await writeCase(
      repository,
      "invalid-shrinkwrap-wins",
      source,
      "dependencies",
      "^4.17.0",
    );
    await writeNpmLock(
      repository,
      "invalid-shrinkwrap-wins",
      "^4.17.0",
      "4.17.10",
    );
    await writeFile(
      join(repository, "invalid-shrinkwrap-wins", "npm-shrinkwrap.json"),
      "{\n",
    );

    for (const [id, declaration] of [
      ["patched", "^4.17.0"],
      ["fixed-boundary", "^4.17.0"],
      ["stale", "^4.17.0"],
      ["v1", "^4.17.0"],
      ["missing-installed", "^4.17.0"],
      ["alias", "npm:lodash@4.17.10"],
      ["workspace", "workspace:^4.17.0"],
      ["tag", "latest"],
    ] as const) {
      await writeCase(repository, id, source, "dependencies", declaration);
    }
    await writeNpmLock(repository, "patched", "^4.17.0", "4.17.21");
    await writeNpmLock(repository, "fixed-boundary", "^4.17.0", "4.17.11");
    await writeNpmLock(repository, "stale", "^4.17.0", "4.17.10", {
      rootDeclaration: "^4.16.0",
    });
    await writeNpmLock(repository, "v1", "^4.17.0", "4.17.10", {
      lockfileVersion: 1,
    });
    await writeNpmLock(repository, "missing-installed", "^4.17.0", "4.17.10", {
      includeInstalledPackage: false,
    });
    for (const id of ["alias", "workspace", "tag"] as const) {
      await writeNpmLock(
        repository,
        id,
        id === "alias"
          ? "npm:lodash@4.17.10"
          : id === "workspace"
            ? "workspace:^4.17.0"
            : "latest",
        "4.17.10",
      );
    }

    await writeCase(repository, "malformed", source, "dependencies", "^4.17.0");
    await writeFile(join(repository, "malformed", "package-lock.json"), "{\n");
    await writeCase(repository, "oversized", source, "dependencies", "^4.17.0");
    await writeFile(
      join(repository, "oversized", "package-lock.json"),
      " ".repeat(4 * 1024 * 1024 + 1),
    );
    const boundaryRoot = join(repository, "oversized-child-boundary");
    await mkdir(join(boundaryRoot, "child"), { recursive: true });
    await writeFile(
      join(boundaryRoot, "package.json"),
      JSON.stringify({ dependencies: { lodash: "4.17.10" } }),
    );
    await writeFile(
      join(boundaryRoot, "child", "package.json"),
      " ".repeat(256 * 1024 + 1),
    );
    await writeFile(join(boundaryRoot, "child", "handler.mjs"), source);

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "caret-v3/handler.mjs",
      "comparator-v2/handler.mjs",
      "shrinkwrap-wins/handler.mjs",
      "wildcard-v3/handler.mjs",
    ]);
  });

  test.skipIf(process.platform === "win32")(
    "rejects a symlinked npm lockfile instead of following version evidence",
    async () => {
      const repository = await mkdtemp(
        join(tmpdir(), "copilot-security-lodash-lock-link-"),
      );
      temporaryPaths.push(repository);
      const id = "linked-lock";
      const source =
        'import lodash from "lodash";\nexport function handler(request) { return lodash.merge({}, request.body); }\n';
      await writeCase(repository, id, source, "dependencies", "^4.17.0");
      await mkdir(join(repository, "evidence"));
      await writeNpmLock(repository, "evidence", "^4.17.0", "4.17.10");
      await symlink(
        join(repository, "evidence", "package-lock.json"),
        join(repository, id, "package-lock.json"),
        "file",
      );

      expect(
        mergeRecords(await buildResidualRiskInventory(repository)),
      ).toHaveLength(0);
    },
  );

  test("keeps the standalone lodash.merge package on its own 4.6.2 version line", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-lodash-merge-package-"),
    );
    temporaryPaths.push(repository);
    const importSource =
      'import merge from "lodash.merge";\nexport function handler(request) { return merge({}, request.body); }\n';
    const requireSource =
      'const merge = require("lodash.merge");\nexport function handler(request) { return merge({}, request.body); }\n';

    await writeCase(
      repository,
      "exact-import",
      importSource,
      "dependencies",
      "4.6.1",
      "lodash.merge",
    );
    await writeCase(
      repository,
      "exact-require",
      requireSource,
      "optionalDependencies",
      "4.6.1",
      "lodash.merge",
    );
    await writeCase(
      repository,
      "locked-range",
      importSource,
      "dependencies",
      "^4.6.0",
      "lodash.merge",
    );
    await writeNpmLock(repository, "locked-range", "^4.6.0", "4.6.1", {
      dependencyName: "lodash.merge",
    });

    for (const [id, source, version, dependencyName] of [
      ["fixed-boundary", importSource, "4.6.2", "lodash.merge"],
      ["wrong-manifest", importSource, "4.17.10", "lodash"],
      [
        "namespace",
        'import * as merge from "lodash.merge";\nexport function handler(request) { return merge({}, request.body); }\n',
        "4.6.1",
        "lodash.merge",
      ],
      [
        "named",
        'import { merge } from "lodash.merge";\nexport function handler(request) { return merge({}, request.body); }\n',
        "4.6.1",
        "lodash.merge",
      ],
      [
        "reassigned",
        'import merge from "lodash.merge";\nmerge = helper;\nexport function handler(request) { return merge({}, request.body); }\n',
        "4.6.1",
        "lodash.merge",
      ],
    ] as const) {
      await writeCase(
        repository,
        id,
        source,
        "dependencies",
        version,
        dependencyName,
      );
    }
    await writeCase(
      repository,
      "locked-fixed",
      importSource,
      "dependencies",
      "^4.6.0",
      "lodash.merge",
    );
    await writeNpmLock(repository, "locked-fixed", "^4.6.0", "4.6.2", {
      dependencyName: "lodash.merge",
    });

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(
      records.map((record) => ({
        path: record.path,
        kind: record.frameworkModel?.sink.kind,
      })),
    ).toEqual([
      {
        path: "exact-import/handler.mjs",
        kind: "vulnerable-lodash-merge-package-recursive-merge",
      },
      {
        path: "exact-require/handler.mjs",
        kind: "vulnerable-lodash-merge-package-recursive-merge",
      },
      {
        path: "locked-range/handler.mjs",
        kind: "lock-resolved-vulnerable-lodash-merge-package-recursive-merge",
      },
    ]);
  });

  test("keeps merge-deep on its own critical 3.0.3 boundary", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-merge-deep-package-"),
    );
    temporaryPaths.push(repository);
    const importSource =
      'import mergeDeep from "merge-deep";\nexport function handler(request) { return mergeDeep({}, request.body); }\n';
    const requireSource =
      'const mergeDeep = require("merge-deep");\nexport function handler(request) { return mergeDeep({}, request.body); }\n';

    await writeCase(
      repository,
      "exact-import",
      importSource,
      "dependencies",
      "3.0.2",
      "merge-deep",
    );
    await writeCase(
      repository,
      "exact-require",
      requireSource,
      "optionalDependencies",
      "3.0.2",
      "merge-deep",
    );
    await writeCase(
      repository,
      "locked-range",
      importSource,
      "dependencies",
      "^3.0.0",
      "merge-deep",
    );
    await writeNpmLock(repository, "locked-range", "^3.0.0", "3.0.2", {
      dependencyName: "merge-deep",
    });

    for (const [id, source, version, dependencyName] of [
      ["fixed-boundary", importSource, "3.0.3", "merge-deep"],
      ["wrong-manifest", importSource, "4.6.1", "lodash.merge"],
      [
        "namespace",
        'import * as mergeDeep from "merge-deep";\nexport function handler(request) { return mergeDeep({}, request.body); }\n',
        "3.0.2",
        "merge-deep",
      ],
      [
        "named",
        'import { mergeDeep } from "merge-deep";\nexport function handler(request) { return mergeDeep({}, request.body); }\n',
        "3.0.2",
        "merge-deep",
      ],
      [
        "reassigned",
        'import mergeDeep from "merge-deep";\nmergeDeep = helper;\nexport function handler(request) { return mergeDeep({}, request.body); }\n',
        "3.0.2",
        "merge-deep",
      ],
    ] as const) {
      await writeCase(
        repository,
        id,
        source,
        "dependencies",
        version,
        dependencyName,
      );
    }
    await writeCase(
      repository,
      "locked-fixed",
      importSource,
      "dependencies",
      "^3.0.0",
      "merge-deep",
    );
    await writeNpmLock(repository, "locked-fixed", "^3.0.0", "3.0.3", {
      dependencyName: "merge-deep",
    });

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(
      records.map((record) => ({
        path: record.path,
        kind: record.frameworkModel?.sink.kind,
      })),
    ).toEqual([
      {
        path: "exact-import/handler.mjs",
        kind: "vulnerable-merge-deep-recursive-merge",
      },
      {
        path: "exact-require/handler.mjs",
        kind: "vulnerable-merge-deep-recursive-merge",
      },
      {
        path: "locked-range/handler.mjs",
        kind: "lock-resolved-vulnerable-merge-deep-recursive-merge",
      },
    ]);
  });

  test("requires recursive extend mode across both vulnerable version lines", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-extend-package-"),
    );
    temporaryPaths.push(repository);
    const importSource =
      'import extend from "extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n';
    const requireSource =
      'const extend = require("extend");\nexport function handler(request) { return extend(true, {}, request.body); }\n';

    for (const [id, source, section, version] of [
      ["exact-three", importSource, "dependencies", "3.0.1"],
      ["exact-two", requireSource, "optionalDependencies", "2.0.1"],
      ["exact-one", importSource, "dependencies", "1.1.3"],
    ] as const) {
      await writeCase(repository, id, source, section, version, "extend");
    }
    await writeCase(
      repository,
      "locked-range",
      importSource,
      "dependencies",
      "^3.0.0",
      "extend",
    );
    await writeNpmLock(repository, "locked-range", "^3.0.0", "3.0.1", {
      dependencyName: "extend",
    });

    for (const [id, source, version, dependencyName] of [
      ["fixed-three", importSource, "3.0.2", "extend"],
      ["fixed-two", importSource, "2.0.2", "extend"],
      ["later-two", importSource, "2.1.0", "extend"],
      ["later-three", importSource, "3.1.0", "extend"],
      ["before-affected", importSource, "1.1.2", "extend"],
      ["wrong-manifest", importSource, "3.0.2", "merge-deep"],
      [
        "shallow-omitted",
        'import extend from "extend";\nexport function handler(request) { return extend({}, request.body); }\n',
        "3.0.1",
        "extend",
      ],
      [
        "shallow-false",
        'import extend from "extend";\nexport function handler(request) { return extend(false, {}, request.body); }\n',
        "3.0.1",
        "extend",
      ],
      [
        "dynamic-mode",
        'import extend from "extend";\nexport function handler(request) { return extend(request.query.deep, {}, request.body); }\n',
        "3.0.1",
        "extend",
      ],
      [
        "target-only",
        'import extend from "extend";\nexport function handler(request) { return extend(true, request.body, {}); }\n',
        "3.0.1",
        "extend",
      ],
      [
        "namespace",
        'import * as extend from "extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "3.0.1",
        "extend",
      ],
      [
        "named",
        'import { extend } from "extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "3.0.1",
        "extend",
      ],
      [
        "reassigned",
        'import extend from "extend";\nextend = helper;\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "3.0.1",
        "extend",
      ],
    ] as const) {
      await writeCase(
        repository,
        id,
        source,
        "dependencies",
        version,
        dependencyName,
      );
    }
    await writeCase(
      repository,
      "locked-fixed",
      importSource,
      "dependencies",
      "^3.0.0",
      "extend",
    );
    await writeNpmLock(repository, "locked-fixed", "^3.0.0", "3.0.2", {
      dependencyName: "extend",
    });

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(
      records.map((record) => ({
        path: record.path,
        kind: record.frameworkModel?.sink.kind,
      })),
    ).toEqual([
      {
        path: "exact-one/handler.mjs",
        kind: "vulnerable-extend-deep-merge",
      },
      {
        path: "exact-three/handler.mjs",
        kind: "vulnerable-extend-deep-merge",
      },
      {
        path: "exact-two/handler.mjs",
        kind: "vulnerable-extend-deep-merge",
      },
      {
        path: "locked-range/handler.mjs",
        kind: "lock-resolved-vulnerable-extend-deep-merge",
      },
    ]);
  });

  test("keeps deep-extend on its own critical 0.5.1 boundary", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-deep-extend-package-"),
    );
    temporaryPaths.push(repository);
    const importSource =
      'import deepExtend from "deep-extend";\nexport function handler(request) { return deepExtend({}, request.body); }\n';
    const requireSource =
      'const deepExtend = require("deep-extend");\nexport function handler(request) { return deepExtend({}, request.body); }\n';

    for (const [id, source, section, version] of [
      ["exact-import", importSource, "dependencies", "0.5.0"],
      ["exact-require", requireSource, "optionalDependencies", "0.4.2"],
    ] as const) {
      await writeCase(repository, id, source, section, version, "deep-extend");
    }
    await writeCase(
      repository,
      "locked-range",
      importSource,
      "dependencies",
      "^0.5.0",
      "deep-extend",
    );
    await writeNpmLock(repository, "locked-range", "^0.5.0", "0.5.0", {
      dependencyName: "deep-extend",
    });

    for (const [id, source, version, dependencyName] of [
      ["fixed-boundary", importSource, "0.5.1", "deep-extend"],
      ["later-minor", importSource, "0.6.0", "deep-extend"],
      ["later-major", importSource, "1.0.0", "deep-extend"],
      ["wrong-manifest", importSource, "0.5.0", "extend"],
      [
        "target-only",
        'import deepExtend from "deep-extend";\nexport function handler(request) { return deepExtend(request.body, {}); }\n',
        "0.5.0",
        "deep-extend",
      ],
      [
        "namespace",
        'import * as deepExtend from "deep-extend";\nexport function handler(request) { return deepExtend({}, request.body); }\n',
        "0.5.0",
        "deep-extend",
      ],
      [
        "named",
        'import { deepExtend } from "deep-extend";\nexport function handler(request) { return deepExtend({}, request.body); }\n',
        "0.5.0",
        "deep-extend",
      ],
      [
        "reassigned",
        'import deepExtend from "deep-extend";\ndeepExtend = helper;\nexport function handler(request) { return deepExtend({}, request.body); }\n',
        "0.5.0",
        "deep-extend",
      ],
    ] as const) {
      await writeCase(
        repository,
        id,
        source,
        "dependencies",
        version,
        dependencyName,
      );
    }
    await writeCase(
      repository,
      "locked-fixed",
      importSource,
      "dependencies",
      "^0.5.0",
      "deep-extend",
    );
    await writeNpmLock(repository, "locked-fixed", "^0.5.0", "0.5.1", {
      dependencyName: "deep-extend",
    });

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(
      records.map((record) => ({
        path: record.path,
        kind: record.frameworkModel?.sink.kind,
      })),
    ).toEqual([
      {
        path: "exact-import/handler.mjs",
        kind: "vulnerable-deep-extend-recursive-merge",
      },
      {
        path: "exact-require/handler.mjs",
        kind: "vulnerable-deep-extend-recursive-merge",
      },
      {
        path: "locked-range/handler.mjs",
        kind: "lock-resolved-vulnerable-deep-extend-recursive-merge",
      },
    ]);
  });

  test("keeps just-extend 4.0.0 vulnerable and requires literal deep mode", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-just-extend-package-"),
    );
    temporaryPaths.push(repository);
    const importSource =
      'import extend from "just-extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n';
    const requireSource =
      'const extend = require("just-extend");\nexport function handler(request) { return extend(true, {}, request.body); }\n';

    for (const [id, source, section, version] of [
      ["exact-reviewed-gap", importSource, "dependencies", "4.0.0"],
      ["exact-require", requireSource, "optionalDependencies", "3.1.0"],
    ] as const) {
      await writeCase(repository, id, source, section, version, "just-extend");
    }
    await writeCase(
      repository,
      "locked-range",
      importSource,
      "dependencies",
      "^4.0.0",
      "just-extend",
    );
    await writeNpmLock(repository, "locked-range", "^4.0.0", "4.0.0", {
      dependencyName: "just-extend",
    });

    for (const [id, source, version, dependencyName] of [
      ["fixed-boundary", importSource, "4.0.1", "just-extend"],
      ["later-minor", importSource, "4.1.0", "just-extend"],
      ["later-major", importSource, "5.0.0", "just-extend"],
      ["wrong-manifest", importSource, "4.0.0", "extend"],
      [
        "target-only",
        'import extend from "just-extend";\nexport function handler(request) { return extend(true, request.body, {}); }\n',
        "4.0.0",
        "just-extend",
      ],
      [
        "shallow-omitted",
        'import extend from "just-extend";\nexport function handler(request) { return extend({}, request.body); }\n',
        "4.0.0",
        "just-extend",
      ],
      [
        "shallow-false",
        'import extend from "just-extend";\nexport function handler(request) { return extend(false, {}, request.body); }\n',
        "4.0.0",
        "just-extend",
      ],
      [
        "dynamic-mode",
        'import extend from "just-extend";\nexport function handler(request) { return extend(request.query.deep, {}, request.body); }\n',
        "4.0.0",
        "just-extend",
      ],
      [
        "namespace",
        'import * as extend from "just-extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "4.0.0",
        "just-extend",
      ],
      [
        "named",
        'import { extend } from "just-extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "4.0.0",
        "just-extend",
      ],
      [
        "reassigned",
        'import extend from "just-extend";\nextend = helper;\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "4.0.0",
        "just-extend",
      ],
    ] as const) {
      await writeCase(
        repository,
        id,
        source,
        "dependencies",
        version,
        dependencyName,
      );
    }
    await writeCase(
      repository,
      "locked-fixed",
      importSource,
      "dependencies",
      "^4.0.0",
      "just-extend",
    );
    await writeNpmLock(repository, "locked-fixed", "^4.0.0", "4.0.1", {
      dependencyName: "just-extend",
    });

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(
      records.map((record) => ({
        path: record.path,
        kind: record.frameworkModel?.sink.kind,
      })),
    ).toEqual([
      {
        path: "exact-require/handler.mjs",
        kind: "vulnerable-just-extend-deep-merge",
      },
      {
        path: "exact-reviewed-gap/handler.mjs",
        kind: "vulnerable-just-extend-deep-merge",
      },
      {
        path: "locked-range/handler.mjs",
        kind: "lock-resolved-vulnerable-just-extend-deep-merge",
      },
    ]);
  });

  test("keeps every merge-options argument on its critical 1.0.1 boundary", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-merge-options-package-"),
    );
    temporaryPaths.push(repository);
    const firstArgumentSource =
      'import mergeOptions from "merge-options";\nexport function handler(request) { return mergeOptions(request.body); }\n';
    const laterArgumentSource =
      'const mergeOptions = require("merge-options");\nexport function handler(request) { return mergeOptions({ mode: "strict" }, request.body); }\n';

    for (const [id, source, section, version] of [
      ["exact-first", firstArgumentSource, "dependencies", "1.0.0"],
      ["exact-require", laterArgumentSource, "optionalDependencies", "0.9.1"],
    ] as const) {
      await writeCase(
        repository,
        id,
        source,
        section,
        version,
        "merge-options",
      );
    }
    await writeCase(
      repository,
      "locked-range",
      laterArgumentSource,
      "dependencies",
      "^1.0.0",
      "merge-options",
    );
    await writeNpmLock(repository, "locked-range", "^1.0.0", "1.0.0", {
      dependencyName: "merge-options",
    });

    for (const [id, source, version, dependencyName] of [
      ["fixed-boundary", firstArgumentSource, "1.0.1", "merge-options"],
      ["later-minor", firstArgumentSource, "1.1.0", "merge-options"],
      ["later-major", firstArgumentSource, "2.0.0", "merge-options"],
      ["wrong-manifest", firstArgumentSource, "1.0.0", "deep-extend"],
      [
        "zero-arguments",
        'import mergeOptions from "merge-options";\nexport function handler(request) { request.body; return mergeOptions(); }\n',
        "1.0.0",
        "merge-options",
      ],
      [
        "namespace",
        'import * as mergeOptions from "merge-options";\nexport function handler(request) { return mergeOptions(request.body); }\n',
        "1.0.0",
        "merge-options",
      ],
      [
        "named",
        'import { mergeOptions } from "merge-options";\nexport function handler(request) { return mergeOptions(request.body); }\n',
        "1.0.0",
        "merge-options",
      ],
      [
        "reassigned",
        'import mergeOptions from "merge-options";\nmergeOptions = helper;\nexport function handler(request) { return mergeOptions(request.body); }\n',
        "1.0.0",
        "merge-options",
      ],
    ] as const) {
      await writeCase(
        repository,
        id,
        source,
        "dependencies",
        version,
        dependencyName,
      );
    }
    await writeCase(
      repository,
      "locked-fixed",
      laterArgumentSource,
      "dependencies",
      "^1.0.0",
      "merge-options",
    );
    await writeNpmLock(repository, "locked-fixed", "^1.0.0", "1.0.1", {
      dependencyName: "merge-options",
    });

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(
      records.map((record) => ({
        path: record.path,
        kind: record.frameworkModel?.sink.kind,
      })),
    ).toEqual([
      {
        path: "exact-first/handler.mjs",
        kind: "vulnerable-merge-options-recursive-merge",
      },
      {
        path: "exact-require/handler.mjs",
        kind: "vulnerable-merge-options-recursive-merge",
      },
      {
        path: "locked-range/handler.mjs",
        kind: "lock-resolved-vulnerable-merge-options-recursive-merge",
      },
    ]);
  });

  test("keeps node.extend's disjoint vulnerable ranges and requires literal deep mode", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-node-extend-package-"),
    );
    temporaryPaths.push(repository);
    const importSource =
      'import extend from "node.extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n';
    const requireSource =
      'const extend = require("node.extend");\nexport function handler(request) { return extend(true, {}, request.body); }\n';

    for (const [id, source, section, version] of [
      ["exact-legacy", importSource, "dependencies", "1.1.6"],
      ["exact-disjoint", requireSource, "optionalDependencies", "2.0.0"],
      ["exact-zero", importSource, "dependencies", "0.0.2"],
    ] as const) {
      await writeCase(repository, id, source, section, version, "node.extend");
    }
    await writeCase(
      repository,
      "locked-range",
      importSource,
      "dependencies",
      "^2.0.0",
      "node.extend",
    );
    await writeNpmLock(repository, "locked-range", "^2.0.0", "2.0.0", {
      dependencyName: "node.extend",
    });

    for (const [id, source, version, dependencyName] of [
      ["fixed-legacy-boundary", importSource, "1.1.7", "node.extend"],
      ["later-legacy-patch", importSource, "1.1.8", "node.extend"],
      ["safe-gap", importSource, "1.2.0", "node.extend"],
      ["fixed-two-boundary", importSource, "2.0.1", "node.extend"],
      ["later-two-patch", importSource, "2.0.2", "node.extend"],
      ["later-major", importSource, "3.0.0", "node.extend"],
      ["wrong-manifest", importSource, "2.0.0", "extend"],
      [
        "target-only",
        'import extend from "node.extend";\nexport function handler(request) { return extend(true, request.body, {}); }\n',
        "2.0.0",
        "node.extend",
      ],
      [
        "shallow-omitted",
        'import extend from "node.extend";\nexport function handler(request) { return extend({}, request.body); }\n',
        "2.0.0",
        "node.extend",
      ],
      [
        "shallow-false",
        'import extend from "node.extend";\nexport function handler(request) { return extend(false, {}, request.body); }\n',
        "2.0.0",
        "node.extend",
      ],
      [
        "dynamic-mode",
        'import extend from "node.extend";\nexport function handler(request) { return extend(request.query.deep, {}, request.body); }\n',
        "2.0.0",
        "node.extend",
      ],
      [
        "namespace",
        'import * as extend from "node.extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "2.0.0",
        "node.extend",
      ],
      [
        "named",
        'import { extend } from "node.extend";\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "2.0.0",
        "node.extend",
      ],
      [
        "reassigned",
        'import extend from "node.extend";\nextend = helper;\nexport function handler(request) { return extend(true, {}, request.body); }\n',
        "2.0.0",
        "node.extend",
      ],
    ] as const) {
      await writeCase(
        repository,
        id,
        source,
        "dependencies",
        version,
        dependencyName,
      );
    }
    await writeCase(
      repository,
      "locked-fixed",
      importSource,
      "dependencies",
      "^2.0.0",
      "node.extend",
    );
    await writeNpmLock(repository, "locked-fixed", "^2.0.0", "2.0.1", {
      dependencyName: "node.extend",
    });

    const records = mergeRecords(await buildResidualRiskInventory(repository));
    expect(
      records.map((record) => ({
        path: record.path,
        kind: record.frameworkModel?.sink.kind,
      })),
    ).toEqual([
      {
        path: "exact-disjoint/handler.mjs",
        kind: "vulnerable-node-extend-deep-merge",
      },
      {
        path: "exact-legacy/handler.mjs",
        kind: "vulnerable-node-extend-deep-merge",
      },
      {
        path: "exact-zero/handler.mjs",
        kind: "vulnerable-node-extend-deep-merge",
      },
      {
        path: "locked-range/handler.mjs",
        kind: "lock-resolved-vulnerable-node-extend-deep-merge",
      },
    ]);
  });

  test("teaches version, recursion, manifest, and constructor.prototype proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-prototype-merge");
    expect(prompt).toContain("lodash");
    expect(prompt).toContain("4.17.11");
    expect(prompt).toContain("nearest package.json");
    expect(prompt).toContain("package-lock.json");
    expect(prompt).toContain("npm-shrinkwrap.json");
    expect(prompt).toContain("lodash.merge");
    expect(prompt).toContain("4.6.2");
    expect(prompt).toContain("merge-deep");
    expect(prompt).toContain("3.0.3");
    expect(prompt).toContain("extend(true, target, ...sources)");
    expect(prompt).toContain(">=1.1.3 <2.0.2");
    expect(prompt).toContain(">=3.0.0 <3.0.2");
    expect(prompt).toContain("deep-extend");
    expect(prompt).toContain("0.5.1");
    expect(prompt).toContain("just-extend");
    expect(prompt).toContain("4.0.0 remains vulnerable");
    expect(prompt).toContain("upstream-patched 4.0.1 boundary");
    expect(prompt).toContain("own destination property");
    expect(prompt).toContain("merge-options");
    expect(prompt).toContain("patched 1.0.1 boundary");
    expect(prompt).toContain("argument zero is not a destination");
    expect(prompt).toContain("defines own data properties");
    expect(prompt).toContain("node.extend");
    expect(prompt).toContain("below 1.1.7, or exactly 2.0.0");
    expect(prompt).toContain("1.1.7 through 1.x");
    expect(prompt).toContain("2.0.1 or later");
    expect(prompt).toContain("read __proto__ only when it is an own property");
    expect(prompt).toContain("source operands");
    expect(prompt).toContain("constructor.prototype");
    expect(prompt).toContain("CWE-1321");
  });
});
