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
  } = {},
): Promise<void> {
  await writeFile(
    join(repository, id, options.name ?? "package-lock.json"),
    JSON.stringify(
      {
        name: id,
        lockfileVersion: options.lockfileVersion ?? 3,
        packages: {
          "": {
            dependencies: {
              lodash: options.rootDeclaration ?? declaration,
            },
          },
          ...(options.includeInstalledPackage === false
            ? {}
            : {
                "node_modules/lodash": {
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
    expect(
      manifest.cases.every(({ findingsPaths }) => findingsPaths.length === 1),
    ).toBeTrue();
  });

  test("preserves the three-boundary source flow only for vulnerable resolved versions", async () => {
    const [unsafe, safe, lockedUnsafe, lockedSafe] = (await Promise.all(
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
    ];

    expect(unsafe).toHaveLength(1);
    expect(safe).toHaveLength(0);
    expect(lockedUnsafe).toHaveLength(1);
    expect(lockedSafe).toHaveLength(0);
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

  test("teaches version, recursion, manifest, and constructor.prototype proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-prototype-merge");
    expect(prompt).toContain("lodash");
    expect(prompt).toContain("4.17.11");
    expect(prompt).toContain("nearest package.json");
    expect(prompt).toContain("package-lock.json");
    expect(prompt).toContain("npm-shrinkwrap.json");
    expect(prompt).toContain("source operands");
    expect(prompt).toContain("constructor.prototype");
    expect(prompt).toContain("CWE-1321");
  });
});
