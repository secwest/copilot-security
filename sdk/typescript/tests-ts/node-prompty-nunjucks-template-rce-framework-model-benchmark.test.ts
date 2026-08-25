import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
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

function promptyRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-prompty-nunjucks-template-rce",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "2.0.0-beta.4",
  dependencySection = "dependencies",
  dependencyName = "@prompty/core",
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
  await mkdir(dirname(join(root, filename)), { recursive: true });
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
            dependencies: { "@prompty/core": { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { "@prompty/core": rootDeclaration } },
              "node_modules/@prompty/core": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const direct = (
  binding: string,
  construction = "const renderer = new NunjucksRenderer();",
  expression = "request.query.template",
) =>
  `${binding}\n${construction}\nconst agent = {};\nexport function handler(request) {\n  return renderer.render(agent, ${expression}, {});\n}\n`;

describe("Prompty Nunjucks remote-template RCE framework benchmark", () => {
  test("keeps a strict vulnerable and patched benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-prompty-nunjucks-template-rce-manifest.json"),
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
      "node-multi-hop-prompty-nunjucks-template-rce",
      "node-multi-hop-patched-prompty-nunjucks-template",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-94", "CWE-1336"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, renderer sink, and dependency proof", async () => {
    const vulnerable = promptyRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-prompty-nunjucks-template-rce",
        ),
      ),
    );
    const patched = promptyRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-patched-prompty-nunjucks-template",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(patched).toHaveLength(0);
    expect(vulnerable[0]).toMatchObject({
      path: "src/renderer.js",
      line: 6,
      frameworkModel: {
        id: "node-http-prompty-nunjucks-template-rce",
        scope: "cross-file-multi-hop-wrapper",
        source: { path: "src/server.js", kind: "http-request-field" },
        sink: {
          path: "src/renderer.js",
          kind: "vulnerable-prompty-nunjucks-template-rce",
          cweIds: ["CWE-94", "CWE-1336"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "prompty-core-runtime-dependency",
      path: "package.json",
      line: 10,
      symbol:
        "@prompty/core@2.0.0-beta.4:manifest-exact:explicit-nunjucks-renderer:nunjucks-member-traversal-rce",
    });
  });

  test("recognizes official ESM, namespace, import-equals, CommonJS, and stable aliases", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-prompty-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", direct('import { NunjucksRenderer } from "@prompty/core";')],
      [
        "named-alias",
        direct(
          'import { NunjucksRenderer as Renderer } from "@prompty/core";',
          "const renderer = new Renderer();",
        ),
      ],
      [
        "namespace",
        direct(
          'import * as core from "@prompty/core";',
          "const renderer = new core.NunjucksRenderer();",
        ),
      ],
      [
        "import-equals",
        direct(
          'import core = require("@prompty/core");',
          "const renderer = new core.NunjucksRenderer();",
        ),
      ],
      [
        "cjs-destructure",
        direct('const { NunjucksRenderer } = require("@prompty/core");'),
      ],
      [
        "cjs-receiver",
        direct(
          'const core = require("@prompty/core");',
          "const renderer = new core.NunjucksRenderer();",
        ),
      ],
      [
        "member-alias",
        direct(
          'const core = require("@prompty/core");\nconst Renderer = core.NunjucksRenderer;',
          "const renderer = new Renderer();",
        ),
      ],
      [
        "instance-alias",
        direct(
          'import { NunjucksRenderer } from "@prompty/core";',
          "const official = new NunjucksRenderer();\nconst renderer = official;",
        ),
      ],
    ] as const;
    for (const [id, source] of cases) await writeCase(repository, id, source);
    expect(
      promptyRecords(await buildResidualRiskInventory(repository))
        .map(({ path }) => path.split("/")[0])
        .sort(),
    ).toEqual(cases.map(([id]) => id).sort());
  });

  test("models render, prepare, and invoke only when untrusted instructions reach the pipeline", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-prompty-pipeline-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "render",
        'import { Prompty, render } from "@prompty/core";\nexport function handler(request) { const agent = new Prompty({ name: "x", model: "fixed", instructions: request.query.template }); return render(agent, {}); }\n',
      ],
      [
        "prepare-alias",
        'import { Prompty as Agent, prepare as compile } from "@prompty/core";\nexport function handler(request) { const agent = new Agent({ instructions: request.body.template }); return compile(agent, {}); }\n',
      ],
      [
        "invoke-load",
        'const { Prompty, invoke } = require("@prompty/core");\nexports.handler = function handler(request) { const agent = Prompty.load({ instructions: request.query.template }); return invoke(agent, {}); };\n',
      ],
      [
        "namespace-assignment",
        'import * as core from "@prompty/core";\nexport function handler(request) { const agent = new core.Prompty({ instructions: "fixed" }); agent.instructions = request.body.template; return core.prepare(agent, {}); }\n',
      ],
    ] as const;
    for (const [id, source] of cases) await writeCase(repository, id, source);
    expect(
      promptyRecords(await buildResidualRiskInventory(repository))
        .map(({ path }) => path.split("/")[0])
        .sort(),
    ).toEqual(cases.map(([id]) => id).sort());
  });

  test("enforces both published repair lines and rejects malformed previews", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-prompty-versions-"),
    );
    temporaryPaths.push(repository);
    const vulnerable = [
      "0.0.1",
      "0.1.0",
      "0.1.4",
      "2.0.0-alpha.3",
      "2.0.0-alpha.11",
      "2.0.0-beta.1",
      "2.0.0-beta.4",
    ];
    const safe = [
      "0.1.5",
      "0.2.0",
      "1.0.0",
      "2.0.0-beta.5",
      "2.0.0-beta.10",
      "2.0.0",
      "2.0.1",
      "2.0.0-beta.04",
      "v2.0.0-beta.4",
    ];
    for (const version of [...vulnerable, ...safe]) {
      await writeCase(
        repository,
        `v-${version.replaceAll(".", "-")}`,
        direct('import { NunjucksRenderer } from "@prompty/core";'),
        version,
      );
    }
    expect(
      promptyRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    ).toEqual(
      vulnerable.map((version) => `v-${version.replaceAll(".", "-")}`).sort(),
    );
  });

  test("uses declaration-consistent npm v2/v3 locks but rejects ambiguous provenance", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-prompty-locks-"),
    );
    temporaryPaths.push(repository);
    const source = direct('import { NunjucksRenderer } from "@prompty/core";');
    for (const [id, declaration, resolved] of [
      ["locked-vulnerable", "^2.0.0-beta.1", "2.0.0-beta.4"],
      ["locked-patched", "^2.0.0-beta.1", "2.0.0-beta.5"],
      ["tilde-legacy", "~0.1.0", "0.1.4"],
    ] as const) {
      await writeCase(repository, id, source, declaration);
      await writeNpmLock(repository, id, declaration, resolved);
    }
    await writeCase(repository, "range-no-lock", source, "<=2.0.0-beta.4");
    await writeCase(repository, "lock-v1", source, "^2.0.0-beta.1");
    await writeNpmLock(
      repository,
      "lock-v1",
      "^2.0.0-beta.1",
      "2.0.0-beta.4",
      1,
    );
    await writeCase(repository, "lock-mismatch", source, "^2.0.0-beta.1");
    await writeNpmLock(
      repository,
      "lock-mismatch",
      "^2.0.0-beta.1",
      "2.0.0-beta.4",
      3,
      "2.0.0-beta.4",
    );
    const records = promptyRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path.split("/")[0])).toEqual([
      "locked-vulnerable",
      "tilde-legacy",
    ]);
    expect(records[0]?.frameworkModel?.propagators[0]?.symbol).toContain(
      "npm-lockfile",
    );
  });

  test("rejects package-only, trusted-template, non-Nunjucks, lookalike, replaced, and data-only paths", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-prompty-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "trusted-template",
        'import { NunjucksRenderer } from "@prompty/core";\nconst renderer = new NunjucksRenderer();\nexport function handler(request) { return renderer.render({}, "Hello {{ name }}", request.body); }\n',
      ],
      [
        "mustache",
        'import { MustacheRenderer } from "@prompty/core";\nconst renderer = new MustacheRenderer();\nexport function handler(request) { return renderer.render({}, request.query.template, {}); }\n',
      ],
      [
        "package-only",
        'import { NunjucksRenderer } from "@prompty/core";\nexport function handler(request) { return request.query.template; }\n',
      ],
      [
        "local-lookalike",
        'import { NunjucksRenderer } from "./prompty.js";\nconst renderer = new NunjucksRenderer();\nexport function handler(request) { return renderer.render({}, request.query.template, {}); }\n',
      ],
      [
        "constructor-reassigned",
        'import { NunjucksRenderer } from "@prompty/core";\nNunjucksRenderer = SafeRenderer;\nconst renderer = new NunjucksRenderer();\nexport function handler(request) { return renderer.render({}, request.query.template, {}); }\n',
      ],
      [
        "instance-reassigned",
        'import { NunjucksRenderer } from "@prompty/core";\nlet renderer = new NunjucksRenderer();\nrenderer = safeRenderer;\nexport function handler(request) { return renderer.render({}, request.query.template, {}); }\n',
      ],
      [
        "render-replaced",
        'import { NunjucksRenderer } from "@prompty/core";\nconst renderer = new NunjucksRenderer();\nrenderer.render = safeRender;\nexport function handler(request) { return renderer.render({}, request.query.template, {}); }\n',
      ],
      [
        "pipeline-data-only",
        'import { Prompty, render } from "@prompty/core";\nconst agent = new Prompty({ instructions: "Hello {{ name }}" });\nexport function handler(request) { return render(agent, request.body); }\n',
      ],
      [
        "invoke-path-only",
        'import { invoke } from "@prompty/core";\nexport function handler(request) { return invoke(request.query.path, {}); }\n',
      ],
    ] as const;
    for (const [id, source] of cases) await writeCase(repository, id, source);
    expect(
      promptyRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("rejects development-only declarations, wrong packages, tests, and examples", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-prompty-boundaries-"),
    );
    temporaryPaths.push(repository);
    const source = direct('import { NunjucksRenderer } from "@prompty/core";');
    await writeCase(
      repository,
      "dev-only",
      source,
      "2.0.0-beta.4",
      "devDependencies",
    );
    await writeCase(
      repository,
      "wrong-package",
      source,
      "2.0.0-beta.4",
      "dependencies",
      "@prompty/openai",
    );
    await writeCase(
      repository,
      "test-file",
      source,
      "2.0.0-beta.4",
      "dependencies",
      "@prompty/core",
      "handler.test.mjs",
    );
    await writeCase(
      repository,
      "example-file",
      source,
      "2.0.0-beta.4",
      "dependencies",
      "@prompty/core",
      "examples/handler.mjs",
    );
    expect(
      promptyRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("teaches the validator the exact exploit and counterevidence boundary", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-http-prompty-nunjucks-template-rce");
    expect(prompt).toContain("GHSA-w28w-gp39-m4p6");
    expect(prompt).toContain("CVE-2026-73299");
    expect(prompt).toContain("2.0.0-beta.5");
    expect(prompt).toContain("range.constructor");
    expect(prompt).toContain("CWE-1336");
    expect(prompt).toContain("untrusted render inputs alone");
  });
});
