import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  line: number;
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

function immutableRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-immutable-prototype-replacement",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "5.1.4",
  dependencySection = "dependencies",
  dependencyName = "immutable",
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
          "": { dependencies: { immutable: declaration } },
          "node_modules/immutable": { version: resolved },
        },
      },
      null,
      2,
    ),
  );
}

describe("Immutable.js prototype-replacement framework benchmark", () => {
  test("keeps the returned-profile exploit and repaired pair under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-immutable-prototype-replacement-manifest.json",
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
      "node-multi-hop-immutable-prototype-replacement",
      "node-multi-hop-patched-immutable",
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
    const vulnerable = immutableRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-immutable-prototype-replacement",
        ),
      ),
    );
    const patched = immutableRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-patched-immutable"),
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
        kind: "vulnerable-immutable-merge-deep-prototype-replacement",
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

  test("accepts official functional and conversion binding shapes", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-immutable-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "named-merge-deep",
        'import { mergeDeep } from "immutable";\nexport function handler(request) { return mergeDeep({ role: "user" }, request.body.profile); }\n',
        "5.1.4",
        "vulnerable-immutable-merge-deep-prototype-replacement",
      ],
      [
        "namespace-merge",
        'import * as Immutable from "immutable";\nexport function handler(request) { return Immutable.merge(request.body.profile, { active: true }); }\n',
        "4.3.7",
        "vulnerable-immutable-merge-prototype-replacement",
      ],
      [
        "default-merge-with",
        'import Immutable from "immutable";\nexport function handler(request) { return Immutable.mergeWith((a, b) => b, {}, request.body.profile); }\n',
        "4.2.4",
        "vulnerable-immutable-merge-with-prototype-replacement",
      ],
      [
        "commonjs-set-path",
        'const Immutable = require("immutable");\nexport function handler(request) { return Immutable.set({}, request.body.key, false); }\n',
        "5.0.3",
        "vulnerable-immutable-set-prototype-replacement",
      ],
      [
        "destructured-update-in",
        'const { updateIn: revise } = require("immutable");\nexport function handler(request) { return revise({}, request.body.path, () => true); }\n',
        "4.3.7",
        "vulnerable-immutable-update-in-prototype-replacement",
      ],
      [
        "direct-member-deep-with",
        'const combine = require("immutable").mergeDeepWith;\nexport function handler(request) { return combine((a, b) => b, {}, request.body.profile); }\n',
        "5.1.4",
        "vulnerable-immutable-merge-deep-with-prototype-replacement",
      ],
      [
        "literal-magic-value",
        'import { set } from "immutable";\nexport function handler(request) { return set({}, "__proto__", request.body.value); }\n',
        "4.3.7",
        "vulnerable-immutable-set-prototype-replacement",
      ],
      [
        "map-chain",
        'import { Map } from "immutable";\nexport function handler(request) { return Map(request.body.profile).toObject(); }\n',
        "3.8.2",
        "vulnerable-immutable-map-to-object-prototype-replacement",
      ],
      [
        "fromjs-chain",
        'const fromJS = require("immutable").fromJS;\nexport function handler(request) { return fromJS(request.body.profile).toJS(); }\n',
        "3.8.2",
        "vulnerable-immutable-from-js-to-js-prototype-replacement",
      ],
      [
        "retained-map",
        'import { Map } from "immutable";\nexport function handler(request) {\n  const values = Map(request.body.profile);\n  return values.toJS();\n}\n',
        "3.8.2",
        "vulnerable-immutable-map-to-js-prototype-replacement",
      ],
    ] as const;
    for (const [id, source, version] of cases) {
      await writeCase(repository, id, source, version);
    }
    const records = immutableRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(cases.length);
    for (const [id, , , kind] of cases) {
      expect(
        records.find(({ path }) => path === `${id}/handler.mjs`)?.frameworkModel
          ?.sink.kind,
      ).toBe(kind);
    }
  });

  test("keeps release, API, operand, and package boundaries exact", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-immutable-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "patched-three",
        'import { Map } from "immutable";\nexport function handler(request) { return Map(request.body.profile).toObject(); }\n',
        "3.8.3",
      ],
      [
        "patched-four",
        'import { mergeDeep } from "immutable";\nexport function handler(request) { return mergeDeep({}, request.body.profile); }\n',
        "4.3.8",
      ],
      [
        "patched-five",
        'import { setIn } from "immutable";\nexport function handler(request) { return setIn({}, request.body.path, true); }\n',
        "5.1.5",
      ],
      [
        "unavailable-three-functional",
        'import { mergeDeep } from "immutable";\nexport function handler(request) { return mergeDeep({}, request.body.profile); }\n',
        "3.8.2",
      ],
      [
        "safe-key-value-only",
        'import { set } from "immutable";\nexport function handler(request) { return set({}, "name", request.body.name); }\n',
        "5.1.4",
      ],
      [
        "merger-only",
        'import { mergeDeepWith } from "immutable";\nexport function handler(request) { return mergeDeepWith(request.body.merger, {}, { fixed: true }); }\n',
        "5.1.4",
      ],
      [
        "unrelated-same-line",
        'import { mergeDeep } from "immutable";\nexport function handler(request) { const value = mergeDeep({}, { fixed: true }); console.log(request.body); return value; }\n',
        "5.1.4",
      ],
      [
        "unconnected-conversion-same-line",
        'import { Map } from "immutable";\nexport function handler(request) { Map(request.body.profile); return other.toJS(); }\n',
        "3.8.2",
      ],
      [
        "wrong-package",
        'import { mergeDeep } from "seamless-immutable";\nexport function handler(request) { return mergeDeep({}, request.body.profile); }\n',
        "5.1.4",
      ],
      [
        "read-only",
        'import { getIn } from "immutable";\nexport function handler(request) { return getIn({}, request.body.path); }\n',
        "5.1.4",
      ],
      [
        "no-source",
        'import { mergeDeep } from "immutable";\nexport function handler(profile) { return mergeDeep({}, profile); }\n',
        "5.1.4",
      ],
      [
        "reassigned-root",
        'import * as Immutable from "immutable";\nImmutable = local;\nexport function handler(request) { return Immutable.mergeDeep({}, request.body.profile); }\n',
        "5.1.4",
      ],
      [
        "reassigned-member",
        'const Immutable = require("immutable");\nImmutable.mergeDeep = local;\nexport function handler(request) { return Immutable.mergeDeep({}, request.body.profile); }\n',
        "5.1.4",
      ],
      [
        "dev-only",
        'import { mergeDeep } from "immutable";\nexport function handler(request) { return mergeDeep({}, request.body.profile); }\n',
        "5.1.4",
        "devDependencies",
      ],
    ] as const;
    for (const candidate of cases) {
      await writeCase(
        repository,
        candidate[0],
        candidate[1],
        candidate[2],
        candidate[3] ?? "dependencies",
        candidate[0] === "wrong-package" ? "immutable" : "immutable",
      );
    }
    expect(
      immutableRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("uses fresh lock proof and rejects absent or inconsistent resolutions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-immutable-lock-"),
    );
    temporaryPaths.push(repository);
    const source =
      'import { mergeDeep } from "immutable";\nexport function handler(request) { return mergeDeep({}, request.body.profile); }\n';
    await writeCase(repository, "locked", source, "^5.1.0");
    await writeNpmLock(repository, "locked", "^5.1.0", "5.1.4");
    await writeCase(repository, "patched", source, "^5.1.0");
    await writeNpmLock(repository, "patched", "^5.1.0", "5.1.5");
    await writeCase(repository, "missing-lock", source, "^5.1.0");
    await writeCase(repository, "inconsistent", source, "^5.1.0");
    await writeNpmLock(repository, "inconsistent", "~5.1.0", "5.1.4");
    const records = immutableRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.path).toBe("locked/handler.mjs");
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-immutable-merge-deep-prototype-replacement",
    );
  });

  test("retains a late valid call under the package-local candidate cap", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-immutable-cap-"),
    );
    temporaryPaths.push(repository);
    await writeCase(
      repository,
      "late-call",
      `import { mergeDeep } from "immutable";\n${Array.from({ length: 40 }, (_, index) => `helper${index}();`).join("\n")}\nexport function handler(request) { return mergeDeep({}, request.body.profile); }\n`,
    );
    const records = immutableRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "vulnerable-immutable-merge-deep-prototype-replacement",
    );
  });

  test("retains the canonical row and teaches object-local impact validation", async () => {
    const paths = immutableRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-immutable-prototype-replacement/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-immutable/src/storage.js",
    );
    const prompt = scanQualityGatePrompt("draft");
    expect(prompt).toContain("node-http-immutable-prototype-replacement");
    expect(prompt).toContain("below 3.8.3");
    expect(prompt).toContain("argument zero");
    expect(prompt).toContain("absence of an own security field");
    expect(prompt).toContain("Do not claim global pollution");
  }, 60_000);
});
