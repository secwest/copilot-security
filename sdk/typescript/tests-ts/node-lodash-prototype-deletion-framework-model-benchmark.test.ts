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

function lodashDeleteRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-lodash-prototype-deletion",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  dependencyName = "lodash",
  version = "4.17.23",
  dependencySection = "dependencies",
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
  dependencyName: string,
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
          "": { dependencies: { [dependencyName]: declaration } },
          [`node_modules/${dependencyName}`]: { version: resolved },
        },
      },
      null,
      2,
    ),
  );
}

describe("Lodash prototype-deletion framework benchmark", () => {
  test("keeps the 4.17.23 array bypass and current repaired pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-lodash-prototype-deletion-manifest.json"),
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
      "node-multi-hop-lodash-unset-prototype-deletion",
      "node-multi-hop-patched-lodash-unset",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, sink, and wrapper chain", async () => {
    const vulnerable = lodashDeleteRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-lodash-unset-prototype-deletion",
        ),
      ),
    );
    const patched = lodashDeleteRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-patched-lodash-unset"),
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
        kind: "vulnerable-lodash-unset-array-path-prototype-deletion",
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

  test("accepts official core, ES, AMD, subpath, and standalone bindings", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-lodash-delete-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "core-default-unset",
        'import _ from "lodash";\nexport function handler(request) { return _.unset({}, request.body.path); }\n',
        "lodash",
        "4.17.23",
        "vulnerable-lodash-unset-array-path-prototype-deletion",
      ],
      [
        "core-namespace-omit",
        'import * as _ from "lodash";\nexport function handler(request) { return _.omit({}, [request.body.paths]); }\n',
        "lodash",
        "4.17.23",
        "vulnerable-lodash-omit-array-path-prototype-deletion",
      ],
      [
        "core-named",
        'import { unset as remove } from "lodash";\nexport function handler(request) { return remove({}, request.body.path); }\n',
        "lodash",
        "4.17.21",
        "vulnerable-lodash-unset-prototype-deletion",
      ],
      [
        "core-destructured",
        'const { omit: remove } = require("lodash");\nexport function handler(request) { return remove({}, request.body.paths); }\n',
        "lodash",
        "4.17.21",
        "vulnerable-lodash-omit-prototype-deletion",
      ],
      [
        "core-subpath",
        'import unset from "lodash/unset.js";\nexport function handler(request) { return unset({}, request.body.path); }\n',
        "lodash",
        "4.17.23",
        "vulnerable-lodash-unset-array-path-prototype-deletion",
      ],
      [
        "core-require-subpath",
        'const omit = require("lodash/omit");\nexport function handler(request) { return omit({}, request.body.paths); }\n',
        "lodash",
        "4.17.21",
        "vulnerable-lodash-omit-prototype-deletion",
      ],
      [
        "es-named",
        'import { unset as remove } from "lodash-es";\nexport function handler(request) { return remove({}, request.body.path); }\n',
        "lodash-es",
        "4.17.23",
        "vulnerable-lodash-es-unset-array-path-prototype-deletion",
      ],
      [
        "es-subpath",
        'import omit from "lodash-es/omit.js";\nexport function handler(request) { return omit({}, [request.body.paths]); }\n',
        "lodash-es",
        "4.17.22",
        "vulnerable-lodash-es-omit-prototype-deletion",
      ],
      [
        "standalone-default",
        'import unset from "lodash.unset";\nexport function handler(request) { return unset({}, request.body.path); }\n',
        "lodash.unset",
        "4.5.2",
        "vulnerable-lodash-unset-package-prototype-deletion",
      ],
      [
        "standalone-require",
        'const unset = require("lodash.unset");\nexport function handler(request) { return unset({}, request.body.path); }\n',
        "lodash.unset",
        "4.5.2",
        "vulnerable-lodash-unset-package-prototype-deletion",
      ],
      [
        "amd-receiver",
        'define(["lodash"], function (_) {\n  return function handler(request) { return _.unset({}, request.body.path); };\n});\n',
        "lodash-amd",
        "4.17.23",
        "vulnerable-lodash-amd-unset-array-path-prototype-deletion",
      ],
    ] as const;
    for (const [id, source, dependencyName, version] of cases) {
      await writeCase(repository, id, source, dependencyName, version);
    }
    const records = lodashDeleteRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(cases.length);
    for (const [id, , , , kind] of cases) {
      expect(
        records.find(({ path }) => path === `${id}/handler.mjs`)?.frameworkModel
          ?.sink.kind,
      ).toBe(kind);
    }
  });

  test("keeps both repair stages, argument roles, and package identity exact", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-lodash-delete-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "patched-core",
        'import _ from "lodash";\nexport function handler(request) { return _.unset({}, request.body.path); }\n',
        "lodash",
        "4.18.0",
      ],
      [
        "pre-api-core",
        'import _ from "lodash";\nexport function handler(request) { return _.unset({}, request.body.path); }\n',
        "lodash",
        "3.10.1",
      ],
      [
        "patched-es",
        'import { omit } from "lodash-es";\nexport function handler(request) { return omit({}, request.body.paths); }\n',
        "lodash-es",
        "4.18.1",
      ],
      [
        "patched-standalone",
        'const unset = require("lodash.unset");\nexport function handler(request) { return unset({}, request.body.path); }\n',
        "lodash.unset",
        "4.18.0",
      ],
      [
        "safe-standalone-omit",
        'const omit = require("lodash.omit");\nexport function handler(request) { return omit({}, request.body.paths); }\n',
        "lodash.omit",
        "4.5.0",
      ],
      [
        "target-only",
        'import _ from "lodash";\nexport function handler(request) { return _.unset(request.body.target, "fixed.path"); }\n',
        "lodash",
        "4.17.21",
      ],
      [
        "read-only",
        'import _ from "lodash";\nexport function handler(request) { return _.get({}, request.body.path); }\n',
        "lodash",
        "4.17.21",
      ],
      [
        "wrong-package",
        'import { unset } from "underscore";\nexport function handler(request) { return unset({}, request.body.path); }\n',
        "lodash",
        "4.17.21",
      ],
      [
        "reassigned-root",
        'import _ from "lodash";\n_ = local;\nexport function handler(request) { return _.unset({}, request.body.path); }\n',
        "lodash",
        "4.17.21",
      ],
      [
        "reassigned-member",
        'const _ = require("lodash");\n_.unset = local;\nexport function handler(request) { return _.unset({}, request.body.path); }\n',
        "lodash",
        "4.17.21",
      ],
      [
        "no-source",
        'import _ from "lodash";\nexport function handler(path) { return _.unset({}, path); }\n',
        "lodash",
        "4.17.21",
      ],
      [
        "dev-only",
        'import _ from "lodash";\nexport function handler(request) { return _.unset({}, request.body.path); }\n',
        "lodash",
        "4.17.21",
        "devDependencies",
      ],
    ] as const;
    for (const candidate of cases) {
      await writeCase(
        repository,
        candidate[0],
        candidate[1],
        candidate[2],
        candidate[3],
        candidate[4] ?? "dependencies",
      );
    }
    expect(
      lodashDeleteRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("uses fresh lock proof and rejects absent or inconsistent resolutions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-lodash-delete-lock-"),
    );
    temporaryPaths.push(repository);
    const source =
      'import { unset } from "lodash-es";\nexport function handler(request) { return unset({}, request.body.path); }\n';
    await writeCase(repository, "locked", source, "lodash-es", "^4.17.0");
    await writeNpmLock(repository, "locked", "lodash-es", "^4.17.0", "4.17.23");
    await writeCase(repository, "patched", source, "lodash-es", "^4.17.0");
    await writeNpmLock(repository, "patched", "lodash-es", "^4.17.0", "4.18.1");
    await writeCase(repository, "missing-lock", source, "lodash-es", "^4.17.0");
    await writeCase(repository, "inconsistent", source, "lodash-es", "^4.17.0");
    await writeNpmLock(
      repository,
      "inconsistent",
      "lodash-es",
      "~4.17.0",
      "4.17.23",
    );
    const records = lodashDeleteRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.path).toBe("locked/handler.mjs");
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-lodash-es-unset-array-path-prototype-deletion",
    );
  });

  test("retains a late valid call under the package-local candidate cap", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-lodash-delete-cap-"),
    );
    temporaryPaths.push(repository);
    await writeCase(
      repository,
      "late-call",
      `import _ from "lodash";\n${Array.from({ length: 40 }, (_, index) => `helper${index}();`).join("\n")}\nexport function handler(request) { return _.unset({}, request.body.path); }\n`,
      "lodash",
      "4.17.23",
    );
    const records = lodashDeleteRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "vulnerable-lodash-unset-array-path-prototype-deletion",
    );
  });

  test("retains the canonical row and teaches deletion-specific validation", async () => {
    const paths = lodashDeleteRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-lodash-unset-prototype-deletion/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-lodash-unset/src/storage.js",
    );
    const prompt = scanQualityGatePrompt("draft");
    expect(prompt).toContain("node-http-lodash-prototype-deletion");
    expect(prompt).toContain("array-wrapped keys");
    expect(prompt).toContain("primitive-root");
    expect(prompt).toContain("lodash.omit package");
    expect(prompt).toContain("does not overwrite");
  }, 60_000);
});
