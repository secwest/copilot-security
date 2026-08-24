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

function liquidJsRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-liquidjs-template-rce",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "10.25.7",
  dependencySection = "dependencies",
  dependencyName = "liquidjs",
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
            dependencies: { liquidjs: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { liquidjs: rootDeclaration } },
              "node_modules/liquidjs": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const direct = (
  binding: string,
  construction = "const engine = new Liquid();",
  expression = "request.query.template",
) =>
  `${binding}\n${construction}\nexport function handler(request) {\n  return engine.parseAndRender(${expression}, {});\n}\n`;

describe("LiquidJS remote-template RCE framework benchmark", () => {
  test("keeps a strict vulnerable and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-liquidjs-template-rce-manifest.json"),
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
      "node-multi-hop-liquidjs-template-rce",
      "node-multi-hop-repaired-liquidjs-template",
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

  test("preserves the exact multi-hop source, render sink, and dependency proof", async () => {
    const vulnerable = liquidJsRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-liquidjs-template-rce"),
      ),
    );
    const repaired = liquidJsRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-repaired-liquidjs-template",
        ),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/renderer.js",
      line: 6,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: {
          path: "src/server.js",
          line: 8,
          kind: "http-request-field",
        },
        sink: {
          path: "src/renderer.js",
          line: 6,
          kind: "vulnerable-liquidjs-inherited-filter-rce",
          cweIds: ["CWE-94"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "liquidjs-runtime-dependency",
          path: "package.json",
          symbol: "liquidjs@10.25.7:manifest-exact:inherited-filter-rce",
        }),
        expect.objectContaining({
          kind: "relative-module-import",
          path: "src/server.js",
          line: 2,
        }),
        expect.objectContaining({
          kind: "wrapper-parameter",
          path: "src/renderer.js",
          line: 5,
        }),
      ]),
    );
    for (const relative of [
      "src/server.js",
      "src/gateway.js",
      "src/service.js",
      "src/renderer.js",
      "witness.mjs",
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-liquidjs-template-rce",
            relative,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-repaired-liquidjs-template",
            relative,
          ),
          "utf8",
        ),
      );
    }
  });

  test("accepts official constructor bindings, stable aliases, and direct render methods", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-liquidjs-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", direct('import { Liquid } from "liquidjs";')],
      [
        "named-alias",
        direct(
          'import { Liquid as Engine } from "liquidjs";',
          "const engine = new Engine();",
        ),
      ],
      [
        "constructor-alias",
        'import { Liquid as OfficialLiquid } from "liquidjs";\nconst Engine = OfficialLiquid;\nconst engine = new Engine();\nexport function handler(request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "namespace",
        direct(
          'import * as liquidjs from "liquidjs";',
          "const engine = new liquidjs.Liquid();",
        ),
      ],
      [
        "default-receiver",
        direct(
          'import liquidjs from "liquidjs";',
          "const engine = new liquidjs.Liquid();",
        ),
      ],
      [
        "import-equals",
        direct(
          'import liquidjs = require("liquidjs");',
          "const engine = new liquidjs.Liquid();",
        ),
        "handler.ts",
      ],
      [
        "commonjs-receiver",
        'const liquidjs = require("liquidjs");\nconst engine = new liquidjs.Liquid();\nexports.handler = function handler(request) { return engine.parseAndRender(request.query.template, {}); };\n',
      ],
      [
        "commonjs-destructure",
        'const { Liquid: Engine } = require("liquidjs");\nconst engine = new Engine();\nexports.handler = function handler(request) { return engine.parseAndRender(request.query.template, {}); };\n',
      ],
      [
        "commonjs-member",
        'const Engine = require("liquidjs").Liquid;\nconst engine = new Engine();\nexports.handler = function handler(request) { return engine.parseAndRender(request.query.template, {}); };\n',
      ],
      [
        "instance-alias",
        'import { Liquid } from "liquidjs";\nconst official = new Liquid();\nconst engine = official;\nexport function handler(request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "sync",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(request) { return engine.parseAndRenderSync(request.query.template, {}); }\n',
      ],
      [
        "immediate",
        'import { Liquid } from "liquidjs";\nexport function handler(request) { return new Liquid().parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "multiline",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(request) {\n return engine.parseAndRender(\n   request.query.template,\n   {},\n );\n}\n',
      ],
    ] as const;
    for (const [id, source, filename = "handler.mjs"] of cases) {
      await writeCase(
        repository,
        id,
        source,
        "10.25.7",
        "dependencies",
        "liquidjs",
        filename,
      );
    }

    expect(
      liquidJsRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(
      cases
        .map(([id, , filename = "handler.mjs"]) => `${id}/${filename}`)
        .sort(),
    );
  });

  test("requires parsed templates to reach render on the same official instance", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-liquidjs-parse-render-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "retained",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(request) {\n const tokens = engine.parse(request.query.template);\n return engine.render(tokens, {});\n}\n',
      ],
      [
        "retained-sync",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(request) {\n const tokens = engine.parse(request.query.template);\n return engine.renderSync(tokens, {});\n}\n',
      ],
      [
        "nested",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(request) { return engine.render(engine.parse(request.query.template), {}); }\n',
      ],
      [
        "instance-alias",
        'const { Liquid } = require("liquidjs");\nconst official = new Liquid();\nconst engine = official;\nexports.handler = function handler(request) {\n const tokens = engine.parse(request.query.template);\n return engine.render(tokens, {});\n};\n',
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    const records = liquidJsRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual(
      cases.map(([id]) => `${id}/handler.mjs`).sort(),
    );
    expect(records.every(({ line }) => line >= 3)).toBe(true);
  });

  test("enforces the 10.26.0 repair boundary and rejects prereleases", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-liquidjs-versions-"),
    );
    temporaryPaths.push(repository);
    const vulnerable = ["1.0.0", "8.5.0", "9.3.1", "10.0.0", "10.25.7"];
    const safe = ["10.26.0", "10.27.2", "11.0.0", "10.25.7-beta.1"];
    for (const version of [...vulnerable, ...safe]) {
      await writeCase(
        repository,
        `v-${version.replaceAll(".", "-")}`,
        direct('import { Liquid } from "liquidjs";'),
        version,
      );
    }
    expect(
      liquidJsRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    ).toEqual(
      vulnerable.map((version) => `v-${version.replaceAll(".", "-")}`).sort(),
    );
  });

  test("rejects package-only, trusted-template, incomplete, lookalike, shadowed, and replaced capabilities", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-liquidjs-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "trusted-template",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(request) { return engine.parseAndRender("Hello {{ name }}", request.query); }\n',
      ],
      [
        "package-only",
        'import { Liquid } from "liquidjs";\nexport function handler(request) { return request.query.template; }\n',
      ],
      [
        "parse-only",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(request) { return engine.parse(request.query.template); }\n',
      ],
      [
        "different-instance-render",
        'import { Liquid } from "liquidjs";\nconst parser = new Liquid();\nconst renderer = new Liquid();\nexport function handler(request) { const tokens = parser.parse(request.query.template); return renderer.render(tokens, {}); }\n',
      ],
      [
        "local-lookalike",
        'import { Liquid } from "./liquidjs.js";\nconst engine = new Liquid();\nexport function handler(request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "constructor-reassigned",
        'import { Liquid } from "liquidjs";\nLiquid = SafeLiquid;\nconst engine = new Liquid();\nexport function handler(request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "receiver-member-replaced",
        'import * as liquidjs from "liquidjs";\nliquidjs.Liquid = SafeLiquid;\nconst engine = new liquidjs.Liquid();\nexport function handler(request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "receiver-member-defined",
        'import * as liquidjs from "liquidjs";\nObject.defineProperty(liquidjs, "Liquid", { value: SafeLiquid });\nconst engine = new liquidjs.Liquid();\nexport function handler(request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "instance-reassigned",
        'import { Liquid } from "liquidjs";\nlet engine = new Liquid();\nengine = safeEngine;\nexport function handler(request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "instance-shadowed",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(engine, request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "parse-and-render-replaced",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nengine.parseAndRender = safeRender;\nexport function handler(request) { return engine.parseAndRender(request.query.template, {}); }\n',
      ],
      [
        "parse-defined",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nObject.defineProperty(engine, "parse", { value: safeParse });\nexport function handler(request) { const tokens = engine.parse(request.query.template); return engine.render(tokens, {}); }\n',
      ],
      [
        "render-replaced",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nengine.render = safeRender;\nexport function handler(request) { const tokens = engine.parse(request.query.template); return engine.render(tokens, {}); }\n',
      ],
      [
        "tokens-reassigned",
        'import { Liquid } from "liquidjs";\nconst engine = new Liquid();\nexport function handler(request) {\n let tokens = engine.parse(request.query.template);\n tokens = trustedTokens;\n return engine.render(tokens, {});\n}\n',
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    expect(
      liquidJsRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exact production provenance or a declaration-consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-liquidjs-dependencies-"),
    );
    temporaryPaths.push(repository);
    const source = direct('import { Liquid } from "liquidjs";');
    await writeCase(repository, "locked-range", source, "^10.0.0");
    await writeNpmLock(repository, "locked-range", "^10.0.0", "10.25.7");
    await writeCase(repository, "unlocked-range", source, "^10.0.0");
    await writeCase(repository, "v1-lock", source, "^10.0.0");
    await writeNpmLock(repository, "v1-lock", "^10.0.0", "10.25.7", 1);
    await writeCase(repository, "inconsistent-lock", source, "^10.26.0");
    await writeNpmLock(
      repository,
      "inconsistent-lock",
      "^10.26.0",
      "10.25.7",
      3,
      "^10.0.0",
    );
    await writeCase(
      repository,
      "dev-only",
      source,
      "10.25.7",
      "devDependencies",
    );
    await writeCase(
      repository,
      "wrong-package",
      source,
      "10.25.7",
      "dependencies",
      "liquidjs-clone",
    );

    const records = liquidJsRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "locked-range/handler.mjs",
    ]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-liquidjs-inherited-filter-rce",
    );
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "liquidjs-runtime-dependency",
          path: "locked-range/package.json",
          symbol: "liquidjs@10.25.7:npm-lockfile:inherited-filter-rce",
        }),
      ]),
    );
  });

  test("excludes test/example trees and retains the canonical row under the repository cap", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-liquidjs-exclusions-"),
    );
    temporaryPaths.push(repository);
    const source = direct('import { Liquid } from "liquidjs";');
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
        JSON.stringify({ dependencies: { liquidjs: "10.25.7" } }),
      );
      await writeFile(join(root, "handler.mjs"), source);
    }
    expect(
      liquidJsRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);

    const repositoryInventory = await buildResidualRiskInventory(
      resolve(process.cwd(), "..", ".."),
    );
    const repositoryRecords = repositoryInventory
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as FrameworkRecord);
    expect(
      repositoryRecords.filter(({ frameworkModel }) => frameworkModel).length,
    ).toBeGreaterThanOrEqual(165);
    const paths = liquidJsRecords(repositoryInventory).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-liquidjs-template-rce/src/renderer.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-repaired-liquidjs-template/src/renderer.js",
    );
  }, 60_000);

  test("requires exploit-specific validation before reporting host-process impact", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-liquidjs-template-rce");
    expect(prompt).toContain("GHSA-gf2q-c269-pqgc");
    expect(prompt).toContain("CVE-2026-45618");
    expect(prompt).toContain("parse-and-render execution path");
    expect(prompt).toContain("valueOf");
    expect(prompt).toContain("Do not report remote code execution");
  });
});
