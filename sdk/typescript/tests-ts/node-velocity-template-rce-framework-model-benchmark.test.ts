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

function velocityRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-velocity-template-rce",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "2.1.6",
  dependencySection = "dependencies",
  dependencyName = "velocityjs",
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
            dependencies: { velocityjs: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { velocityjs: rootDeclaration } },
              "node_modules/velocityjs": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const direct = (binding: string, expression = "request.query.template") =>
  `${binding}\nexport function handler(request) {\n  return render(${expression}, { account: {} });\n}\n`;

describe("Velocity.js remote-template RCE framework benchmark", () => {
  test("keeps a strict vulnerable and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-velocity-template-rce-manifest.json"),
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
      "node-multi-hop-velocity-template-rce",
      "node-multi-hop-repaired-velocity-template",
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
    const vulnerable = velocityRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-velocity-template-rce"),
      ),
    );
    const repaired = velocityRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-repaired-velocity-template",
        ),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/renderer.js",
      line: 4,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: {
          path: "src/server.js",
          line: 8,
          kind: "http-request-field",
        },
        sink: {
          path: "src/renderer.js",
          line: 4,
          kind: "vulnerable-velocity-template-property-read-rce",
          cweIds: ["CWE-94"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "velocityjs-runtime-dependency",
          path: "package.json",
          symbol: "velocityjs@2.1.6:manifest-exact:prototype-property-read-rce",
        }),
        expect.objectContaining({
          kind: "relative-module-import",
          path: "src/server.js",
          line: 2,
        }),
        expect.objectContaining({
          kind: "wrapper-parameter",
          path: "src/renderer.js",
          line: 3,
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
            "node-multi-hop-velocity-template-rce",
            relative,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-repaired-velocity-template",
            relative,
          ),
          "utf8",
        ),
      );
    }
  });

  test("accepts official render bindings and stable aliases", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-velocity-render-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", direct('import { render } from "velocityjs";')],
      [
        "named-alias",
        'import { render as renderTemplate } from "velocityjs";\nexport function handler(request) { return renderTemplate(request.query.template, {}); }\n',
      ],
      [
        "stable-alias",
        'import { render as officialRender } from "velocityjs";\nconst renderTemplate = officialRender;\nexport function handler(request) { return renderTemplate(request.query.template, {}); }\n',
      ],
      [
        "namespace",
        'import * as velocity from "velocityjs";\nexport function handler(request) { return velocity.render(request.query.template, {}); }\n',
      ],
      [
        "default-receiver",
        'import velocity from "velocityjs";\nexport function handler(request) { return velocity.render(request.query.template, {}); }\n',
      ],
      [
        "import-equals",
        'import velocity = require("velocityjs");\nexport function handler(request) { return velocity.render(request.query.template, {}); }\n',
        "handler.ts",
      ],
      [
        "commonjs-receiver",
        'const velocity = require("velocityjs");\nexports.handler = function handler(request) { return velocity.render(request.query.template, {}); };\n',
      ],
      [
        "commonjs-destructure",
        'const { render: renderTemplate } = require("velocityjs");\nexports.handler = function handler(request) { return renderTemplate(request.query.template, {}); };\n',
      ],
      [
        "commonjs-member",
        'const renderTemplate = require("velocityjs").render;\nexports.handler = function handler(request) { return renderTemplate(request.query.template, {}); };\n',
      ],
      [
        "direct-require",
        'export function handler(request) { return require("velocityjs").render(request.query.template, {}); }\n',
      ],
      [
        "multiline",
        'import { render } from "velocityjs";\nexport function handler(request) {\n return render(\n   request.query.template,\n   {},\n );\n}\n',
      ],
    ] as const;
    for (const [id, source, filename = "handler.mjs"] of cases) {
      await writeCase(
        repository,
        id,
        source,
        "2.1.6",
        "dependencies",
        "velocityjs",
        filename,
      );
    }

    expect(
      velocityRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(
      cases
        .map(([id, , filename = "handler.mjs"]) => `${id}/${filename}`)
        .sort(),
    );
  });

  test("tracks the official parse to Compile to render execution path", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-velocity-compile-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "named-retained",
        'import { parse, Compile } from "velocityjs";\nexport function handler(request) {\n const ast = parse(request.query.template);\n const compiled = new Compile(ast);\n return compiled.render({});\n}\n',
      ],
      [
        "aliased-retained",
        'import { parse as parseTemplate, Compile as Template } from "velocityjs";\nexport function handler(request) {\n const ast = parseTemplate(request.query.template);\n const compiled = new Template(ast);\n return compiled.render({});\n}\n',
      ],
      [
        "namespace-retained",
        'import * as velocity from "velocityjs";\nexport function handler(request) {\n const ast = velocity.parse(request.query.template);\n const compiled = new velocity.Compile(ast);\n return compiled.render({});\n}\n',
      ],
      [
        "default-immediate",
        'import velocity from "velocityjs";\nexport function handler(request) {\n return new velocity.Compile(velocity.parse(request.query.template)).render({});\n}\n',
      ],
      [
        "commonjs-destructure",
        'const { parse, Compile } = require("velocityjs");\nexports.handler = function handler(request) {\n const ast = parse(request.query.template);\n const compiled = new Compile(ast);\n return compiled.render({});\n};\n',
      ],
      [
        "direct-require-parse",
        'const { Compile } = require("velocityjs");\nexports.handler = function handler(request) {\n const ast = require("velocityjs").parse(request.query.template);\n const compiled = new Compile(ast);\n return compiled.render({});\n};\n',
      ],
      [
        "stable-members",
        'const velocity = require("velocityjs");\nconst parseTemplate = velocity.parse;\nconst Template = velocity.Compile;\nexports.handler = function handler(request) {\n const ast = parseTemplate(request.query.template);\n const compiled = new Template(ast);\n return compiled.render({});\n};\n',
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    const records = velocityRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual(
      cases.map(([id]) => `${id}/handler.mjs`).sort(),
    );
    expect(records.every(({ line }) => line >= 3)).toBe(true);
  });

  test("enforces the 2.1.7 repair boundary and rejects prereleases", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-velocity-versions-"),
    );
    temporaryPaths.push(repository);
    const vulnerable = ["0.9.0", "1.7.0", "2.0.0", "2.1.0", "2.1.6"];
    const safe = ["2.1.7", "2.2.0", "3.0.0", "2.1.6-beta.1"];
    for (const version of [...vulnerable, ...safe]) {
      await writeCase(
        repository,
        `v-${version.replaceAll(".", "-")}`,
        direct('import { render } from "velocityjs";'),
        version,
      );
    }
    expect(
      velocityRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    ).toEqual(
      vulnerable.map((version) => `v-${version.replaceAll(".", "-")}`).sort(),
    );
  });

  test("rejects package-only, trusted-template, incomplete, lookalike, and replaced capabilities", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-velocity-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "trusted-template",
        'import { render } from "velocityjs";\nexport function handler(request) { return render("Hello $name", request.query); }\n',
      ],
      [
        "package-only",
        'import { render } from "velocityjs";\nexport function handler(request) { return request.query.template; }\n',
      ],
      [
        "parse-only",
        'import { parse } from "velocityjs";\nexport function handler(request) { return parse(request.query.template); }\n',
      ],
      [
        "compile-only",
        'import { parse, Compile } from "velocityjs";\nexport function handler(request) { const ast = parse(request.query.template); return new Compile(ast); }\n',
      ],
      [
        "default-call-guess",
        'import velocity from "velocityjs";\nexport function handler(request) { return velocity(request.query.template); }\n',
      ],
      [
        "local-lookalike",
        'import { render } from "./velocityjs.js";\nexport function handler(request) { return render(request.query.template, {}); }\n',
      ],
      [
        "render-reassigned",
        'import { render } from "velocityjs";\nexport function handler(request) { render = safeRender; return render(request.query.template, {}); }\n',
      ],
      [
        "receiver-member-replaced",
        'import velocity from "velocityjs";\nvelocity.render = safeRender;\nexport function handler(request) { return velocity.render(request.query.template, {}); }\n',
      ],
      [
        "receiver-member-defined",
        'import velocity from "velocityjs";\nObject.defineProperty(velocity, "render", { value: safeRender });\nexport function handler(request) { return velocity.render(request.query.template, {}); }\n',
      ],
      [
        "parse-member-replaced",
        'import velocity from "velocityjs";\nvelocity.parse = safeParse;\nexport function handler(request) { const ast = velocity.parse(request.query.template); return new velocity.Compile(ast).render({}); }\n',
      ],
      [
        "compile-member-replaced",
        'import velocity from "velocityjs";\nvelocity.Compile = SafeCompile;\nexport function handler(request) { const ast = velocity.parse(request.query.template); return new velocity.Compile(ast).render({}); }\n',
      ],
      [
        "binding-shadowed",
        'import { render } from "velocityjs";\nexport function handler(render, request) { return render(request.query.template, {}); }\n',
      ],
      [
        "parsed-reassigned",
        'import { parse, Compile } from "velocityjs";\nexport function handler(request) {\n let ast = parse(request.query.template);\n ast = trustedAst;\n return new Compile(ast).render({});\n}\n',
      ],
      [
        "compiled-reassigned",
        'import { parse, Compile } from "velocityjs";\nexport function handler(request) {\n const ast = parse(request.query.template);\n let compiled = new Compile(ast);\n compiled = safeTemplate;\n return compiled.render({});\n}\n',
      ],
      [
        "compiled-render-replaced",
        'import { parse, Compile } from "velocityjs";\nexport function handler(request) {\n const ast = parse(request.query.template);\n const compiled = new Compile(ast);\n compiled.render = safeRender;\n return compiled.render({});\n}\n',
      ],
      [
        "compiled-render-defined",
        'import { parse, Compile } from "velocityjs";\nexport function handler(request) {\n const ast = parse(request.query.template);\n const compiled = new Compile(ast);\n Object.defineProperty(compiled, "render", { value: safeRender });\n return compiled.render({});\n}\n',
      ],
      [
        "local-compile-lookalike",
        'import { parse } from "velocityjs";\nexport function handler(request) { const ast = parse(request.query.template); return new Compile(ast).render({}); }\n',
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    expect(
      velocityRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exact production provenance or a declaration-consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-velocity-dependencies-"),
    );
    temporaryPaths.push(repository);
    const source = direct('import { render } from "velocityjs";');
    await writeCase(repository, "locked-range", source, "^2.0.0");
    await writeNpmLock(repository, "locked-range", "^2.0.0", "2.1.6");
    await writeCase(repository, "unlocked-range", source, "^2.0.0");
    await writeCase(repository, "v1-lock", source, "^2.0.0");
    await writeNpmLock(repository, "v1-lock", "^2.0.0", "2.1.6", 1);
    await writeCase(repository, "inconsistent-lock", source, "^2.1.7");
    await writeNpmLock(
      repository,
      "inconsistent-lock",
      "^2.1.7",
      "2.1.6",
      3,
      "^2.0.0",
    );
    await writeCase(repository, "dev-only", source, "2.1.6", "devDependencies");
    await writeCase(
      repository,
      "wrong-package",
      source,
      "2.1.6",
      "dependencies",
      "velocityjs-clone",
    );

    const records = velocityRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "locked-range/handler.mjs",
    ]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-velocity-template-property-read-rce",
    );
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "velocityjs-runtime-dependency",
          path: "locked-range/package.json",
          symbol: "velocityjs@2.1.6:npm-lockfile:prototype-property-read-rce",
        }),
      ]),
    );
  });

  test("excludes test/example trees and retains the canonical row under the repository cap", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-velocity-exclusions-"),
    );
    temporaryPaths.push(repository);
    const source = direct('import { render } from "velocityjs";');
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
        JSON.stringify({ dependencies: { velocityjs: "2.1.6" } }),
      );
      await writeFile(join(root, "handler.mjs"), source);
    }
    expect(
      velocityRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);

    const paths = velocityRecords(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-velocity-template-rce/src/renderer.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-repaired-velocity-template/src/renderer.js",
    );
  }, 60_000);

  test("requires exploit-specific validation before reporting host-process impact", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("Velocity.js");
    expect(prompt).toContain("GHSA-7gfh-x38p-prh3");
    expect(prompt).toContain("CVE-2026-73649");
    expect(prompt).toContain("parse to Compile to render");
    expect(prompt).toContain("constructor.constructor");
    expect(prompt).toContain("Do not report remote code execution");
  });
});
