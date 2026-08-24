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

function jsonataRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-jsonata-expression-rce",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "2.2.0",
  dependencySection = "dependencies",
  dependencyName = "jsonata",
  filename = "handler.mjs",
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
  await writeFile(join(root, filename), source);
}

async function writeNpmLock(
  repository: string,
  id: string,
  declaration: string,
  resolved: string,
  lockfileVersion = 3,
  rootDeclaration = declaration,
): Promise<void> {
  await writeFile(
    join(repository, id, "package-lock.json"),
    JSON.stringify(
      lockfileVersion === 1
        ? {
            name: id,
            lockfileVersion,
            dependencies: { jsonata: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { jsonata: rootDeclaration } },
              "node_modules/jsonata": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const assigned = (binding: string, expression = "request.query.expression") =>
  `${binding}\nexport async function handler(request) {\n  const compiled = jsonata(${expression});\n  return compiled.evaluate({});\n}\n`;

describe("JSONata remote-expression RCE framework benchmark", () => {
  test("keeps a strict vulnerable and patched benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-jsonata-expression-rce-manifest.json"),
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
      "node-multi-hop-jsonata-expression-rce",
      "node-multi-hop-patched-jsonata-expression",
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

  test("preserves the exact multi-hop source, evaluate sink, and dependency proof", async () => {
    const vulnerable = jsonataRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-jsonata-expression-rce",
        ),
      ),
    );
    const patched = jsonataRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-patched-jsonata-expression",
        ),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(patched).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/storage.js",
      line: 6,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: {
          path: "src/server.js",
          line: 8,
          kind: "http-request-field",
        },
        sink: {
          path: "src/storage.js",
          line: 6,
          kind: "vulnerable-jsonata-expression-sandbox-escape",
          cweIds: ["CWE-94"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "jsonata-runtime-dependency",
          path: "package.json",
          symbol: "jsonata@2.2.0:manifest-exact:expression-sandbox-escape",
        }),
        expect.objectContaining({
          kind: "relative-module-import",
          path: "src/server.js",
          line: 2,
        }),
        expect.objectContaining({
          kind: "wrapper-parameter",
          path: "src/storage.js",
          line: 4,
        }),
      ]),
    );
    for (const relative of [
      "src/server.js",
      "src/gateway.js",
      "src/service.js",
      "src/storage.js",
      "witness.mjs",
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-jsonata-expression-rce",
            relative,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-patched-jsonata-expression",
            relative,
          ),
          "utf8",
        ),
      );
    }
  });

  test("accepts the official compiler forms and requires evaluate reachability", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-jsonata-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["default", assigned('import jsonata from "jsonata";')],
      ["default-alias", assigned('import jsonata as invalid from "jsonata";')],
      [
        "default-import-alias",
        'import compileExpression from "jsonata";\nexport async function handler(request) {\n  const compiled = compileExpression(request.query.expression);\n  return compiled.evaluate({});\n}\n',
      ],
      [
        "stable-compiler-alias",
        'import factory from "jsonata";\nconst jsonata = factory;\nexport async function handler(request) {\n  const compiled = jsonata(request.query.expression);\n  return compiled.evaluate({});\n}\n',
      ],
      [
        "namespace-default",
        'import * as module from "jsonata";\nexport async function handler(request) {\n  const compiled = module.default(request.query.expression);\n  return compiled.evaluate({});\n}\n',
      ],
      [
        "import-equals",
        'import jsonata = require("jsonata");\nexport async function handler(request) {\n  const compiled = jsonata(request.query.expression);\n  return compiled.evaluate({});\n}\n',
        "handler.ts",
      ],
      [
        "commonjs",
        'const jsonata = require("jsonata");\nexports.handler = async function handler(request) {\n  const compiled = jsonata(request.query.expression);\n  return compiled.evaluate({});\n};\n',
      ],
      [
        "direct-require",
        'export async function handler(request) {\n  return require("jsonata")(request.query.expression).evaluate({});\n}\n',
      ],
      [
        "immediate",
        'import jsonata from "jsonata";\nexport async function handler(request) {\n  return jsonata(request.query.expression).evaluate({});\n}\n',
      ],
      [
        "compact-assigned",
        'import jsonata from "jsonata";\nexport async function handler(request) { const compiled = jsonata(request.query.expression); return compiled.evaluate({}); }\n',
      ],
      [
        "await-evaluate",
        'import jsonata from "jsonata";\nexport async function handler(request) {\n  const compiled = jsonata(request.query.expression);\n  return await compiled.evaluate({});\n}\n',
      ],
      [
        "multiline",
        'import jsonata from "jsonata";\nexport async function handler(request) {\n  const compiled = jsonata(\n    request.query.expression,\n  );\n  return compiled\n    .evaluate({});\n}\n',
      ],
    ] as const;
    for (const [id, source, filename = "handler.mjs"] of cases) {
      await writeCase(
        repository,
        id,
        source,
        "2.2.0",
        "dependencies",
        "jsonata",
        filename,
      );
    }

    const paths = jsonataRecords(
      await buildResidualRiskInventory(repository),
    ).map(({ path }) => path);
    expect(paths).toEqual([
      "await-evaluate/handler.mjs",
      "commonjs/handler.mjs",
      "compact-assigned/handler.mjs",
      "default-import-alias/handler.mjs",
      "default/handler.mjs",
      "direct-require/handler.mjs",
      "immediate/handler.mjs",
      "import-equals/handler.ts",
      "multiline/handler.mjs",
      "namespace-default/handler.mjs",
      "stable-compiler-alias/handler.mjs",
    ]);
  });

  test("enforces both patched release lines and rejects non-stable versions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-jsonata-versions-"),
    );
    temporaryPaths.push(repository);
    const vulnerable = ["0.2.0", "1.0.0", "1.8.7", "2.0.0", "2.1.1", "2.2.0"];
    const safe = ["1.8.8", "1.8.9", "2.2.1", "2.2.2", "3.0.0", "2.2.0-beta.1"];
    for (const version of [...vulnerable, ...safe]) {
      await writeCase(
        repository,
        `v-${version.replaceAll(".", "-")}`,
        assigned('import jsonata from "jsonata";'),
        version,
      );
    }
    const paths = jsonataRecords(
      await buildResidualRiskInventory(repository),
    ).map(({ path }) => path.split("/")[0]);
    expect(paths).toEqual(
      vulnerable.map((version) => `v-${version.replaceAll(".", "-")}`).sort(),
    );
  });

  test("rejects package presence, trusted expressions, missing evaluation, and replaced capabilities", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-jsonata-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "compile-only",
        'import jsonata from "jsonata";\nexport function handler(request) { return jsonata(request.query.expression); }\n',
      ],
      [
        "remote-data-only",
        'import jsonata from "jsonata";\nexport function handler(request) { return jsonata("account.name").evaluate(request.query.expression); }\n',
      ],
      [
        "package-only",
        'import jsonata from "jsonata";\nexport function handler(request) { return request.query.expression; }\n',
      ],
      [
        "named-import-guess",
        'import { jsonata } from "jsonata";\nexport function handler(request) { return jsonata(request.query.expression).evaluate({}); }\n',
      ],
      [
        "commonjs-default-guess",
        'const jsonata = require("jsonata").default;\nexport function handler(request) { return jsonata(request.query.expression).evaluate({}); }\n',
      ],
      [
        "local-lookalike",
        'import jsonata from "./jsonata.js";\nexport function handler(request) { return jsonata(request.query.expression).evaluate({}); }\n',
      ],
      [
        "compiler-reassigned",
        'import jsonata from "jsonata";\nexport function handler(request) { jsonata = localCompiler; return jsonata(request.query.expression).evaluate({}); }\n',
      ],
      [
        "compiled-reassigned",
        'import jsonata from "jsonata";\nexport function handler(request) {\n let compiled = jsonata(request.query.expression);\n compiled = safeExpression;\n return compiled.evaluate({});\n}\n',
      ],
      [
        "evaluate-replaced",
        'import jsonata from "jsonata";\nexport function handler(request) {\n const compiled = jsonata(request.query.expression);\n compiled.evaluate = safeEvaluate;\n return compiled.evaluate({});\n}\n',
      ],
      [
        "evaluate-defined",
        'import jsonata from "jsonata";\nexport function handler(request) {\n const compiled = jsonata(request.query.expression);\n Object.defineProperty(compiled, "evaluate", { value: safeEvaluate });\n return compiled.evaluate({});\n}\n',
      ],
      [
        "binding-shadowed",
        'import jsonata from "jsonata";\nexport function handler(jsonata, request) { return jsonata(request.query.expression).evaluate({}); }\n',
      ],
      [
        "namespace-default-replaced",
        'import * as module from "jsonata";\nmodule.default = safeCompiler;\nexport function handler(request) { return module.default(request.query.expression).evaluate({}); }\n',
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    expect(
      jsonataRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exact production provenance or a declaration-consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-jsonata-dependencies-"),
    );
    temporaryPaths.push(repository);
    const source = assigned('import jsonata from "jsonata";');
    await writeCase(repository, "locked-range", source, "^2.0.0");
    await writeNpmLock(repository, "locked-range", "^2.0.0", "2.2.0");
    await writeCase(repository, "unlocked-range", source, "^2.0.0");
    await writeCase(repository, "v1-lock", source, "^2.0.0");
    await writeNpmLock(repository, "v1-lock", "^2.0.0", "2.2.0", 1);
    await writeCase(repository, "inconsistent-lock", source, "^2.2.1");
    await writeNpmLock(
      repository,
      "inconsistent-lock",
      "^2.2.1",
      "2.2.0",
      3,
      "^2.0.0",
    );
    await writeCase(repository, "dev-only", source, "2.2.0", "devDependencies");
    await writeCase(
      repository,
      "wrong-package",
      source,
      "2.2.0",
      "dependencies",
      "jsonata-clone",
    );

    const records = jsonataRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "locked-range/handler.mjs",
    ]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-jsonata-expression-sandbox-escape",
    );
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "jsonata-runtime-dependency",
          path: "locked-range/package.json",
          symbol: "jsonata@2.2.0:npm-lockfile:expression-sandbox-escape",
        }),
      ]),
    );
  });

  test("excludes test and example trees and retains the canonical row under the repository cap", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-jsonata-exclusions-"),
    );
    temporaryPaths.push(repository);
    const source = assigned('import jsonata from "jsonata";');
    for (const directory of [
      "test",
      "tests",
      "__tests__",
      "example",
      "examples",
    ] as const) {
      const root = join(repository, directory);
      await mkdir(root, { recursive: true });
      await writeFile(
        join(root, "package.json"),
        JSON.stringify({ dependencies: { jsonata: "2.2.0" } }),
      );
      await writeFile(join(root, "handler.mjs"), source);
    }
    expect(
      jsonataRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);

    const paths = jsonataRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-jsonata-expression-rce/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-patched-jsonata-expression/src/storage.js",
    );
  }, 60_000);

  test("requires exploit-specific validation before reporting host-process impact", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("JSONata");
    expect(prompt).toContain("GHSA-66mm-25pp-rfff");
    expect(prompt).toContain("GHSA-2943-5xfg-gq5f");
    expect(prompt).toContain("GHSA-8gq3-vp5j-2grp");
    expect(prompt).toContain("compiled expression actually reaches evaluate");
    expect(prompt).toContain("process/global/Function");
    expect(prompt).toContain("Do not report remote code execution");
  });
});
