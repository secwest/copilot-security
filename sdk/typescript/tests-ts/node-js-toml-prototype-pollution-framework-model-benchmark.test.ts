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
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
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

function tomlRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-js-toml-prototype-pollution",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "1.0.1",
  dependencySection = "dependencies",
  dependencyName = "js-toml",
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
  name = "package-lock.json",
): Promise<void> {
  await writeFile(
    join(repository, id, name),
    JSON.stringify(
      {
        name: id,
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "js-toml": declaration } },
          "node_modules/js-toml": { version: resolved },
        },
      },
      null,
      2,
    ),
  );
}

describe("js-toml prototype-pollution framework benchmark", () => {
  test("keeps a strict vulnerable and patched benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-js-toml-prototype-pollution-manifest.json"),
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
      "node-multi-hop-js-toml-prototype-pollution",
      "node-multi-hop-patched-js-toml",
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
    const vulnerable = tomlRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-js-toml-prototype-pollution",
        ),
      ),
    );
    const patched = tomlRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-patched-js-toml"),
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
        kind: "vulnerable-js-toml-load",
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

  test("retains the vulnerable row under the repository cap", async () => {
    const paths = tomlRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-js-toml-prototype-pollution/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-js-toml/src/storage.js",
    );
  }, 60_000);

  test("accepts only official load bindings with vulnerable runtime proof and argument-zero flow", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-js-toml-bindings-"),
    );
    temporaryPaths.push(repository);
    const accepted = [
      [
        "named",
        'import { load } from "js-toml";\nexport function handler(request) { return load(request.body); }\n',
        "0.1.0",
      ],
      [
        "aliased",
        'import { load as parseToml } from "js-toml";\nexport function handler(request) { return parseToml(request.body); }\n',
        "1.0.0",
      ],
      [
        "destructured",
        'const { load: parseToml } = require("js-toml");\nexport function handler(request) { return parseToml(request.body); }\n',
        "1.0.1",
      ],
      [
        "namespace",
        'import * as TOML from "js-toml";\nexport function handler(request) { return TOML.load(request.body); }\n',
        "1.0.1",
      ],
      [
        "commonjs",
        'const TOML = require("js-toml");\nexport function handler(request) { return TOML.load(request.body); }\n',
        "1.0.1",
      ],
      [
        "direct-member",
        'const parseToml = require("js-toml").load;\nexport function handler(request) { return parseToml(request.body); }\n',
        "1.0.1",
      ],
    ] as const;
    for (const [id, source, version] of accepted) {
      await writeCase(repository, id, source, version);
    }
    await writeCase(
      repository,
      "optional-runtime",
      'import { load } from "js-toml";\nexport function handler(request) { return load(request.body); }\n',
      "1.0.1",
      "optionalDependencies",
    );
    await writeCase(
      repository,
      "late-load-call",
      `import { load } from "js-toml";\n${Array.from({ length: 40 }, (_, index) => `helper${index}();`).join("\n")}\nexport function handler(request) { return load(request.body); }\n`,
    );

    const rejected = [
      [
        "fixed",
        'import { load } from "js-toml";\nexport function handler(request) { return load(request.body); }\n',
        "1.0.2",
        "js-toml",
      ],
      [
        "later",
        'import { load } from "js-toml";\nexport function handler(request) { return load(request.body); }\n',
        "2.0.0",
        "js-toml",
      ],
      [
        "default-guess",
        'import TOML from "js-toml";\nexport function handler(request) { return TOML.load(request.body); }\n',
        "1.0.1",
        "js-toml",
      ],
      [
        "wrong-member",
        'import * as TOML from "js-toml";\nexport function handler(request) { return TOML.dump(request.body); }\n',
        "1.0.1",
        "js-toml",
      ],
      [
        "wrong-package",
        'import { load } from "js-toml";\nexport function handler(request) { return load(request.body); }\n',
        "1.0.1",
        "smol-toml",
      ],
      [
        "second-argument",
        'import { load } from "js-toml";\nexport function handler(request) { return load("fixed", request.body); }\n',
        "1.0.1",
        "js-toml",
      ],
      [
        "no-source",
        'import { load } from "js-toml";\nexport function handler(request) { request.body; return load("fixed"); }\n',
        "1.0.1",
        "js-toml",
      ],
      [
        "receiver-reassigned",
        'import * as TOML from "js-toml";\nTOML = helper;\nexport function handler(request) { return TOML.load(request.body); }\n',
        "1.0.1",
        "js-toml",
      ],
      [
        "member-reassigned",
        'import * as TOML from "js-toml";\nTOML.load = helper;\nexport function handler(request) { return TOML.load(request.body); }\n',
        "1.0.1",
        "js-toml",
      ],
      [
        "binding-reassigned",
        'import { load } from "js-toml";\nload = helper;\nexport function handler(request) { return load(request.body); }\n',
        "1.0.1",
        "js-toml",
      ],
      [
        "shadowed",
        'import { load } from "js-toml";\nexport function handler(load, request) { return load(request.body); }\n',
        "1.0.1",
        "js-toml",
      ],
      [
        "range-without-lock",
        'import { load } from "js-toml";\nexport function handler(request) { return load(request.body); }\n',
        "^1.0.0",
        "js-toml",
      ],
    ] as const;
    for (const [id, source, version, dependency] of rejected) {
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
      "development-only",
      'import { load } from "js-toml";\nexport function handler(request) { return load(request.body); }\n',
      "1.0.1",
      "devDependencies",
    );

    const records = tomlRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "aliased/handler.mjs",
      "commonjs/handler.mjs",
      "destructured/handler.mjs",
      "direct-member/handler.mjs",
      "late-load-call/handler.mjs",
      "named/handler.mjs",
      "namespace/handler.mjs",
      "optional-runtime/handler.mjs",
    ]);
    expect(
      records.every(
        (record) =>
          record.frameworkModel?.sink.kind === "vulnerable-js-toml-load",
      ),
    ).toBe(true);
  });

  test("uses fresh npm lock proof without trusting patched or inconsistent resolutions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-js-toml-locks-"),
    );
    temporaryPaths.push(repository);
    const source =
      'import { load } from "js-toml";\nexport function handler(request) { return load(request.body); }\n';
    for (const id of ["vulnerable", "patched", "mismatch", "v1"]) {
      await writeCase(repository, id, source, "^1.0.0");
    }
    await writeNpmLock(repository, "vulnerable", "^1.0.0", "1.0.1");
    await writeNpmLock(repository, "patched", "^1.0.0", "1.0.2");
    await writeNpmLock(repository, "mismatch", "~1.0.0", "1.0.1");
    await writeNpmLock(repository, "v1", "^1.0.0", "1.0.1");
    const v1 = JSON.parse(
      await readFile(join(repository, "v1", "package-lock.json"), "utf8"),
    ) as Record<string, unknown>;
    v1["lockfileVersion"] = 1;
    await writeFile(
      join(repository, "v1", "package-lock.json"),
      JSON.stringify(v1, null, 2),
    );

    const records = tomlRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual(["vulnerable/handler.mjs"]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-js-toml-load",
    );
  });

  test("teaches the parser boundary and concrete exploit proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-js-toml-prototype-pollution");
    expect(prompt).toContain("js-toml");
    expect(prompt).toContain("below 1.0.2");
    expect(prompt).toContain("load(text)");
    expect(prompt).toContain("[__proto__]");
    expect(prompt).toContain("null-prototype");
    expect(prompt).toContain("Object.prototype");
  });
});
