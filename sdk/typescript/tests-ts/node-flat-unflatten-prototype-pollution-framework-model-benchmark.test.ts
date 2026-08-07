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

function flatRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-flat-unflatten-prototype-pollution",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "4.1.0",
  dependencySection = "dependencies",
  dependencyName = "flat",
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
          "": { dependencies: { flat: declaration } },
          "node_modules/flat": { version: resolved },
        },
      },
      null,
      2,
    ),
  );
}

describe("flat.unflatten prototype-pollution framework benchmark", () => {
  test("keeps the omitted vulnerable 4.1.0 and repaired 4.1.1 pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-flat-unflatten-prototype-pollution-manifest.json",
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
      "node-multi-hop-flat-unflatten-prototype-pollution",
      "node-multi-hop-patched-flat-unflatten",
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
    const vulnerable = flatRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-flat-unflatten-prototype-pollution",
        ),
      ),
    );
    const patched = flatRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-patched-flat-unflatten",
        ),
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
        kind: "vulnerable-flat-unflatten",
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
    const paths = flatRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-flat-unflatten-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-flat-unflatten/src/storage.js",
    );
  }, 60_000);

  test("accepts official historical bindings and every published vulnerable line", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-flat-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "named",
        'import { unflatten } from "flat";\nexport function handler(request) { return unflatten(request.body); }\n',
        "0.2.0",
      ],
      [
        "aliased",
        'import { unflatten as expand } from "flat";\nexport function handler(request) { return expand(request.body); }\n',
        "1.6.1",
      ],
      [
        "destructured",
        'const { unflatten: expand } = require("flat");\nexport function handler(request) { return expand(request.body); }\n',
        "2.0.1",
      ],
      [
        "namespace",
        'import * as flat from "flat";\nexport function handler(request) { return flat.unflatten(request.body); }\n',
        "3.0.0",
      ],
      [
        "commonjs",
        'const flat = require("flat");\nexport function handler(request) { return flat.unflatten(request.body); }\n',
        "4.0.0",
      ],
      [
        "default-receiver",
        'import flat from "flat";\nexport function handler(request) { return flat.unflatten(request.body); }\n',
        "4.1.0",
      ],
      [
        "direct-member",
        'const expand = require("flat").unflatten;\nexport function handler(request) { return expand(request.body); }\n',
        "5.0.0",
      ],
      [
        "late-call",
        `import { unflatten } from "flat";\n${Array.from({ length: 40 }, (_, index) => `helper${index}();`).join("\n")}\nexport function handler(request) { return unflatten(request.body); }\n`,
        "4.1.0",
      ],
    ] as const;
    for (const [id, source, version] of cases) {
      await writeCase(repository, id, source, version);
    }
    await writeCase(
      repository,
      "optional-runtime",
      'import { unflatten } from "flat";\nexport function handler(request) { return unflatten(request.body); }\n',
      "4.1.0",
      "optionalDependencies",
    );

    const records = flatRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "aliased/handler.mjs",
      "commonjs/handler.mjs",
      "default-receiver/handler.mjs",
      "destructured/handler.mjs",
      "direct-member/handler.mjs",
      "late-call/handler.mjs",
      "named/handler.mjs",
      "namespace/handler.mjs",
      "optional-runtime/handler.mjs",
    ]);
    expect(
      records.every(
        (record) =>
          record.frameworkModel?.sink.kind === "vulnerable-flat-unflatten",
      ),
    ).toBe(true);
  });

  test("rejects every repaired branch and structural false positives", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-flat-negatives-"),
    );
    temporaryPaths.push(repository);
    const fixedVersions = [
      "1.6.2",
      "2.0.2",
      "3.0.1",
      "4.1.1",
      "5.0.1",
      "6.0.0",
    ];
    for (const version of fixedVersions) {
      await writeCase(
        repository,
        `fixed-${version.replaceAll(".", "-")}`,
        'import { unflatten } from "flat";\nexport function handler(request) { return unflatten(request.body); }\n',
        version,
      );
    }
    const cases = [
      [
        "wrong-member",
        'import * as flat from "flat";\nexport function handler(request) { return flat.flatten(request.body); }\n',
        "flat",
      ],
      [
        "wrong-package",
        'import { unflatten } from "flat";\nexport function handler(request) { return unflatten(request.body); }\n',
        "flatley",
      ],
      [
        "second-argument",
        'import { unflatten } from "flat";\nexport function handler(request) { return unflatten({ fixed: true }, request.body); }\n',
        "flat",
      ],
      [
        "no-source",
        'import { unflatten } from "flat";\nexport function handler(request) { request.body; return unflatten({ fixed: true }); }\n',
        "flat",
      ],
      [
        "receiver-reassigned",
        'import * as flat from "flat";\nflat = helper;\nexport function handler(request) { return flat.unflatten(request.body); }\n',
        "flat",
      ],
      [
        "member-reassigned",
        'import * as flat from "flat";\nflat.unflatten = helper;\nexport function handler(request) { return flat.unflatten(request.body); }\n',
        "flat",
      ],
      [
        "binding-reassigned",
        'import { unflatten } from "flat";\nunflatten = helper;\nexport function handler(request) { return unflatten(request.body); }\n',
        "flat",
      ],
      [
        "shadowed",
        'import { unflatten } from "flat";\nexport function handler(unflatten, request) { return unflatten(request.body); }\n',
        "flat",
      ],
    ] as const;
    for (const [id, source, dependency] of cases) {
      await writeCase(
        repository,
        id,
        source,
        "4.1.0",
        "dependencies",
        dependency,
      );
    }
    await writeCase(
      repository,
      "range-without-lock",
      'import { unflatten } from "flat";\nexport function handler(request) { return unflatten(request.body); }\n',
      "^4.0.0",
    );
    await writeCase(
      repository,
      "development-only",
      'import { unflatten } from "flat";\nexport function handler(request) { return unflatten(request.body); }\n',
      "4.1.0",
      "devDependencies",
    );

    expect(flatRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("uses fresh npm lock proof without trusting repaired or inconsistent resolutions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-flat-locks-"),
    );
    temporaryPaths.push(repository);
    const source =
      'import { unflatten } from "flat";\nexport function handler(request) { return unflatten(request.body); }\n';
    for (const id of ["vulnerable", "patched", "mismatch", "v1"]) {
      await writeCase(repository, id, source, "^4.0.0");
    }
    await writeNpmLock(repository, "vulnerable", "^4.0.0", "4.1.0");
    await writeNpmLock(repository, "patched", "^4.0.0", "4.1.1");
    await writeNpmLock(repository, "mismatch", "~4.0.0", "4.1.0");
    await writeNpmLock(repository, "v1", "^4.0.0", "4.1.0");
    const v1 = JSON.parse(
      await readFile(join(repository, "v1", "package-lock.json"), "utf8"),
    ) as Record<string, unknown>;
    v1["lockfileVersion"] = 1;
    await writeFile(
      join(repository, "v1", "package-lock.json"),
      JSON.stringify(v1, null, 2),
    );

    const records = flatRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual(["vulnerable/handler.mjs"]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-flat-unflatten",
    );
  });

  test("teaches the omitted branch, path semantics, and concrete impact proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-flat-unflatten-prototype-pollution");
    expect(prompt).toContain("unflatten(original, options)");
    expect(prompt).toContain("unpublished 4.0.2");
    expect(prompt).toContain("4.1.0 vulnerable");
    expect(prompt).toContain("4.1.1 repaired");
    expect(prompt).toContain("__proto__");
    expect(prompt).toContain("Object.prototype");
    expect(prompt).toContain("transformKey");
  });
});
