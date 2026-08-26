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

function swigRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-rhinostone-swig-template-path-traversal",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  template = "Selected: {% include partial %}",
  version = "2.7.0",
  packageName = "@rhinostone/swig",
  dependencySection = "dependencies",
  filename = "handler.mjs",
): Promise<void> {
  const root = join(repository, id);
  await mkdir(join(root, "views"), { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [dependencySection]: { [packageName]: version },
      },
      null,
      2,
    ),
  );
  await writeFile(join(root, filename), source);
  await writeFile(join(root, "views", "page.html"), template);
}

async function writeNpmLock(
  repository: string,
  id: string,
  packageName: string,
  declaration: string,
  resolvedVersion: string,
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
            dependencies: {
              [packageName]: { version: resolvedVersion },
            },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { [packageName]: rootDeclaration } },
              [`node_modules/${packageName}`]: { version: resolvedVersion },
            },
          },
      null,
      2,
    ),
  );
}

const rooted = (
  importLine = 'import swig from "@rhinostone/swig";',
  constructor = "swig.Swig",
  receiver = "swig",
  loaderArguments = '"views"',
) =>
  `${importLine}\nconst renderer = new ${constructor}({ loader: ${receiver}.loaders.fs(${loaderArguments}) });\nexport function handler(request) {\n  return renderer.renderFile("page.html", { partial: request.query.partial });\n}\n`;

describe("Rhinostone Swig template-path traversal framework benchmark", () => {
  test("keeps a strict vulnerable and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-rhinostone-swig-template-traversal-manifest.json",
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
      "node-multi-hop-rhinostone-swig-template-traversal",
      "node-multi-hop-repaired-rhinostone-swig-template-root",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-22"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact source, renderer sink, template tag, and dependency proof", async () => {
    const vulnerable = swigRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-rhinostone-swig-template-traversal",
        ),
      ),
    );
    const repaired = swigRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-repaired-rhinostone-swig-template-root",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/renderer.js",
      line: 9,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: {
          kind: "http-request-field",
          path: "src/server.js",
          line: 4,
        },
        sink: {
          kind: "vulnerable-rhinostone-swig-template-path-resolution",
          path: "src/renderer.js",
          line: 9,
          cweIds: ["CWE-22"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "rhinostone-swig-runtime-dependency",
      path: "package.json",
      line: 10,
      symbol: "@rhinostone/swig@2.7.0:manifest-exact:affected-rooted",
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "rhinostone-swig-dynamic-template-path",
      path: "src/views/page.html",
      line: 1,
      symbol: "include:partial",
    });
  });

  test("recognizes all four reviewed frontends and stable module forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-swig-forms-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "default",
        "@rhinostone/swig",
        "Swig",
        'import swig from "@rhinostone/swig";',
        "swig",
        "include",
      ],
      [
        "namespace",
        "@rhinostone/swig-twig",
        "Twig",
        'import * as swig from "@rhinostone/swig-twig";',
        "swig",
        "extends",
      ],
      [
        "import-equals",
        "@rhinostone/swig-jinja2",
        "Jinja2",
        'import swig = require("@rhinostone/swig-jinja2");',
        "swig",
        "import",
      ],
      [
        "commonjs",
        "@rhinostone/swig-django",
        "Django",
        'const swig = require("@rhinostone/swig-django");',
        "swig",
        "from",
      ],
    ] as const;
    for (const [
      id,
      packageName,
      constructor,
      importLine,
      receiver,
      tag,
    ] of cases) {
      await writeCase(
        repository,
        id,
        rooted(importLine, `${receiver}.${constructor}`, receiver),
        `Selected: {% ${tag} partial %}`,
        "2.7.0",
        packageName,
        "dependencies",
        id === "import-equals"
          ? "handler.ts"
          : id === "commonjs"
            ? "handler.cjs"
            : "handler.mjs",
      );
    }
    const records = swigRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path).sort()).toEqual(
      cases
        .map(
          ([id]) =>
            `${id}/handler.${id === "import-equals" ? "ts" : id === "commonjs" ? "cjs" : "mjs"}`,
        )
        .sort(),
    );
    expect(
      records.map(
        (record) =>
          record.frameworkModel?.propagators.find(
            ({ kind }) => kind === "rhinostone-swig-runtime-dependency",
          )?.symbol,
      ),
    ).toEqual(
      expect.arrayContaining(
        cases.map(
          ([, packageName]) =>
            `${packageName}@2.7.0:manifest-exact:affected-rooted`,
        ),
      ),
    );
  });

  test("distinguishes rooted repairs, unconfined loaders, and the documented opt-out", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-swig-routes-"),
    );
    temporaryPaths.push(repository);
    await writeCase(repository, "affected-rooted", rooted());
    await writeCase(
      repository,
      "repaired-rooted",
      rooted(),
      undefined,
      "2.7.2",
    );
    await writeCase(
      repository,
      "repaired-unconfined",
      rooted(undefined, undefined, undefined, "").replace(
        'renderFile("page.html"',
        'renderFile("views/page.html"',
      ),
      undefined,
      "2.7.2",
    );
    await writeCase(
      repository,
      "repaired-opt-out",
      rooted(undefined, undefined, undefined, '"views", "utf8", true'),
      undefined,
      "2.7.2",
    );
    const records = swigRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path).sort()).toEqual([
      "affected-rooted/handler.mjs",
      "repaired-opt-out/handler.mjs",
      "repaired-unconfined/handler.mjs",
    ]);
    const kinds = records.map(
      ({ frameworkModel }) => frameworkModel?.sink.kind,
    );
    expect(kinds).toEqual(
      expect.arrayContaining([
        "vulnerable-rhinostone-swig-template-path-resolution",
        "allow-outside-root-rhinostone-swig-template-path-resolution",
        "unconfined-rhinostone-swig-template-path-resolution",
      ]),
    );
  });

  test("supports the default instance and stable receiver and engine aliases", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-swig-aliases-"),
    );
    temporaryPaths.push(repository);
    await writeCase(
      repository,
      "set-defaults",
      'import swig from "@rhinostone/swig";\nswig.setDefaults({ loader: swig.loaders.fs("views") });\nexport function handler(request) {\n  return swig.renderFile("page.html", { partial: request.query.partial });\n}\n',
    );
    await writeCase(
      repository,
      "aliases",
      'import * as original from "@rhinostone/swig";\nconst swig = original;\nconst configured = new swig.Swig({ loader: swig.loaders.fs("views") });\nconst renderer = configured;\nexport function handler(request) {\n  return renderer.renderFile("page.html", { partial: request.query.partial });\n}\n',
    );
    await writeCase(
      repository,
      "direct-default-unconfined",
      'import swig from "@rhinostone/swig";\nexport function handler(request) {\n  return swig.renderFile("views/page.html", { partial: request.query.partial });\n}\n',
      undefined,
      "2.7.2",
    );
    await writeCase(
      repository,
      "static-path-root",
      'import path from "node:path";\nimport swig from "@rhinostone/swig";\nconst renderer = new swig.Swig({ loader: swig.loaders.fs(path.join(process.cwd(), "views")) });\nexport function handler(request) {\n  return renderer.renderFile("page.html", { partial: request.query.partial });\n}\n',
    );
    expect(
      swigRecords(await buildResidualRiskInventory(repository))
        .map(({ path }) => path)
        .sort(),
    ).toEqual([
      "aliases/handler.mjs",
      "direct-default-unconfined/handler.mjs",
      "set-defaults/handler.mjs",
      "static-path-root/handler.mjs",
    ]);
  });

  test("rejects non-reachable, unproven, mutated, and lookalike cases", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-swig-negatives-"),
    );
    temporaryPaths.push(repository);
    await writeCase(
      repository,
      "static-template-target",
      rooted(),
      'Selected: {% include "safe.html" %}',
    );
    await writeCase(
      repository,
      "different-local",
      rooted().replace(
        "partial: request.query.partial",
        "other: request.query.partial",
      ),
    );
    await writeCase(
      repository,
      "trusted-local",
      rooted().replace("request.query.partial", '"safe.html"'),
    );
    await writeCase(
      repository,
      "development-only",
      rooted(),
      undefined,
      "2.7.0",
      "@rhinostone/swig",
      "devDependencies",
    );
    await writeCase(
      repository,
      "unresolved-range",
      rooted(),
      undefined,
      "^2.7.0",
    );
    await writeCase(
      repository,
      "reassigned-engine",
      rooted().replace(
        "export function handler",
        "renderer = safeRenderer;\nexport function handler",
      ),
    );
    await writeCase(
      repository,
      "replaced-render-file",
      rooted().replace(
        "export function handler",
        "renderer.renderFile = safeRender;\nexport function handler",
      ),
    );
    await writeCase(
      repository,
      "replaced-loader-factory",
      rooted().replace(
        "const renderer",
        "swig.loaders = safeLoaders;\nconst renderer",
      ),
    );
    await writeCase(
      repository,
      "repaired-default-reconfigured-root",
      'import swig from "@rhinostone/swig";\nswig.setDefaults({ loader: swig.loaders.fs("views") });\nexport function handler(request) {\n  return swig.renderFile("page.html", { partial: request.query.partial });\n}\n',
      undefined,
      "2.7.2",
    );
    await writeCase(
      repository,
      "local-lookalike",
      rooted('import swig from "./swig.js";'),
      undefined,
      "2.7.0",
      "swig-clone",
    );
    expect(swigRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("requires exact production provenance or a declaration-consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-swig-locks-"),
    );
    temporaryPaths.push(repository);
    for (const id of ["fresh", "fixed", "stale", "legacy"] as const) {
      await writeCase(repository, id, rooted(), undefined, "^2.7.0");
    }
    await writeNpmLock(
      repository,
      "fresh",
      "@rhinostone/swig",
      "^2.7.0",
      "2.7.0",
    );
    await writeNpmLock(
      repository,
      "fixed",
      "@rhinostone/swig",
      "^2.7.0",
      "2.7.2",
    );
    await writeNpmLock(
      repository,
      "stale",
      "@rhinostone/swig",
      "^2.7.0",
      "2.7.0",
      3,
      "^2.6.0",
    );
    await writeNpmLock(
      repository,
      "legacy",
      "@rhinostone/swig",
      "^2.7.0",
      "2.7.0",
      1,
    );
    const records = swigRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      path: "fresh/handler.mjs",
      frameworkModel: {
        sink: {
          kind: "lock-resolved-vulnerable-rhinostone-swig-template-path-resolution",
        },
      },
    });
    expect(records[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "rhinostone-swig-runtime-dependency",
      path: "fresh/package.json",
      line: 5,
      symbol: "@rhinostone/swig@2.7.0:npm-lockfile:affected-rooted",
    });
  });

  test("adds focused review instructions without version-only overclaim", () => {
    const prompt = scanQualityGatePrompt("inventory", "coverage");
    expect(prompt).toContain(
      "node-http-rhinostone-swig-template-path-traversal",
    );
    expect(prompt).toContain("GHSA-2mf3-mr2r-r4vf");
    expect(prompt).toContain("allowOutsideRoot");
    expect(prompt).toContain("dynamic include");
  });
});
