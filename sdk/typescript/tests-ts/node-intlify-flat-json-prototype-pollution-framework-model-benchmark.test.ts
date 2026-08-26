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

function intlifyRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-intlify-flat-json-prototype-pollution",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  packageName = "vue-i18n",
  version = "9.14.2",
  dependencySection = "dependencies",
  relativePath = "handler.mjs",
): Promise<void> {
  const root = join(repository, id);
  await mkdir(dirname(join(root, relativePath)), { recursive: true });
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
  await writeFile(join(root, relativePath), source);
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
            dependencies: { "vue-i18n": { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { "vue-i18n": rootDeclaration } },
              "node_modules/vue-i18n": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const createRoute = (
  binding: string,
  callee = "createI18n",
  options = "{ legacy: false, flatJson: true, messages: { en: request.body.messages } }",
) =>
  `${binding}\nexport function handler(request) {\n  return ${callee}(${options});\n}\n`;

const setterRoute = (
  binding: string,
  construction = "const i18n = createI18n({ flatJson: true });",
  receiver = "i18n.global",
  operation = "setLocaleMessage",
) =>
  `${binding}\n${construction}\nexport function handler(request) {\n  return ${receiver}.${operation}("en", request.body.messages);\n}\n`;

describe("Intlify flat-JSON prototype-pollution framework benchmark", () => {
  test("keeps a strict affected and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-intlify-flat-json-prototype-pollution-manifest.json",
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
      "node-multi-hop-intlify-flat-json-prototype-pollution",
      "node-multi-hop-repaired-intlify-flat-json-prototype-guard",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-1321"],
      acceptableSeverities: ["medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, create route, configuration, and dependency proof", async () => {
    const vulnerable = intlifyRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-intlify-flat-json-prototype-pollution",
        ),
      ),
    );
    const repaired = intlifyRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-repaired-intlify-flat-json-prototype-guard",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(repaired).toHaveLength(0);
    expect(vulnerable[0]).toMatchObject({
      path: "src/i18n.js",
      line: 4,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: { path: "src/server.js", line: 4 },
        sink: {
          kind: "vulnerable-intlify-flat-json-prototype-write",
          cweIds: ["CWE-1321"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "intlify-runtime-dependency",
      path: "package.json",
      line: 10,
      symbol: "vue-i18n@9.14.2:manifest-exact:create-i18n-messages",
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "intlify-flat-json-configuration",
      path: "src/i18n.js",
      line: 6,
      symbol: "flatJson:true",
    });
  });

  test("recognizes official factory binding forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-intlify-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", createRoute('import { createI18n } from "vue-i18n";')],
      [
        "aliased",
        createRoute(
          'import { createI18n as configure } from "vue-i18n";',
          "configure",
        ),
      ],
      [
        "namespace",
        createRoute('import * as I18n from "vue-i18n";', "I18n.createI18n"),
      ],
      [
        "import-equals",
        createRoute('import I18n = require("vue-i18n");', "I18n.createI18n"),
      ],
      [
        "commonjs-receiver",
        createRoute('const I18n = require("vue-i18n");', "I18n.createI18n"),
      ],
      [
        "commonjs-destructure",
        createRoute('const { createI18n } = require("vue-i18n");'),
      ],
      [
        "stable-alias",
        createRoute(
          'import * as I18n from "vue-i18n";\nconst configure = I18n.createI18n;',
          "configure",
        ),
      ],
      ["direct-require", createRoute("", 'require("vue-i18n").createI18n')],
    ] as const;
    for (const [id, source] of cases) await writeCase(repository, id, source);
    expect(
      intlifyRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(cases.map(([id]) => `${id}/handler.mjs`).sort());
  });

  test("covers direct resolver and configured locale setter routes", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-intlify-routes-"),
    );
    temporaryPaths.push(repository);
    await writeCase(
      repository,
      "direct",
      'import { handleFlatJson as flatten } from "@intlify/message-resolver";\nexport function handler(request) {\n  return flatten(request.body.messages);\n}\n',
      "@intlify/message-resolver",
      "9.1.10",
    );
    await writeCase(
      repository,
      "core-browser-bundle",
      'import { handleFlatJson } from "@intlify/core-base/dist/core-base.esm-browser.js";\nexport function handler(request) {\n  return handleFlatJson(request.body.messages);\n}\n',
      "@intlify/core-base",
      "9.1.10",
    );
    await writeCase(
      repository,
      "set",
      setterRoute('import { createI18n } from "vue-i18n";'),
    );
    await writeCase(
      repository,
      "merge-alias",
      setterRoute(
        'import { createI18n } from "petite-vue-i18n";',
        "const i18n = createI18n({ flatJson: true, messageResolver: customResolver });\nconst composer = i18n.global;",
        "composer",
        "mergeLocaleMessage",
      ),
      "petite-vue-i18n",
      "10.0.5",
    );
    const records = intlifyRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(4);
    expect(
      records.flatMap(
        (record) =>
          record.frameworkModel?.propagators
            .filter(({ kind }) => kind === "intlify-runtime-dependency")
            .map(({ symbol }) => symbol) ?? [],
      ),
    ).toEqual([
      "@intlify/core-base@9.1.10:manifest-exact:direct-handle-flat-json",
      "@intlify/message-resolver@9.1.10:manifest-exact:direct-handle-flat-json",
      "petite-vue-i18n@10.0.5:manifest-exact:merge-locale-message",
      "vue-i18n@9.14.2:manifest-exact:set-locale-message",
    ]);
  });

  test("enforces every reviewed branch boundary", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-intlify-versions-"),
    );
    temporaryPaths.push(repository);
    const factory = createRoute('import { createI18n } from "vue-i18n";');
    const cases = [
      ["vue-9-min", "vue-i18n", "9.1.0", true],
      ["vue-9-last", "vue-i18n", "9.14.2", true],
      ["vue-9-fixed", "vue-i18n", "9.14.3", false],
      ["vue-10-alpha-min", "vue-i18n", "10.0.0-alpha.1", true],
      ["vue-10-alpha-before", "vue-i18n", "10.0.0-alpha.0", false],
      ["vue-10-last", "vue-i18n", "10.0.5", true],
      ["vue-10-fixed", "vue-i18n", "10.0.6", false],
      ["vue-11-beta-min", "vue-i18n", "11.0.0-beta.0", true],
      ["vue-11-alpha", "vue-i18n", "11.0.0-alpha.9", false],
      ["vue-11-last", "vue-i18n", "11.1.1", true],
      ["vue-11-fixed", "vue-i18n", "11.1.2", false],
      ["core-before", "@intlify/vue-i18n-core", "9.1.11", false],
      ["core-min", "@intlify/vue-i18n-core", "9.2.0", true],
      ["petite-alpha", "petite-vue-i18n", "10.0.0-alpha.9", false],
      ["petite-min", "petite-vue-i18n", "10.0.0", true],
    ] as const;
    for (const [id, packageName, version] of cases) {
      await writeCase(
        repository,
        id,
        factory.replaceAll("vue-i18n", packageName),
        packageName,
        version,
      );
    }
    const found = new Set(
      intlifyRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    );
    for (const [id, , , expected] of cases) {
      expect(found.has(id)).toBe(expected);
    }
  });

  test("accepts only declaration-consistent modern lock evidence", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-intlify-locks-"),
    );
    temporaryPaths.push(repository);
    const source = createRoute('import { createI18n } from "vue-i18n";');
    for (const id of ["affected", "fixed", "stale", "v1"]) {
      await writeCase(repository, id, source, "vue-i18n", "^9.0.0");
    }
    await writeNpmLock(repository, "affected", "^9.0.0", "9.14.2");
    await writeNpmLock(repository, "fixed", "^9.0.0", "9.14.3");
    await writeNpmLock(repository, "stale", "^9.0.0", "9.14.2", 3, "9.0.0");
    await writeNpmLock(repository, "v1", "^9.0.0", "9.14.2", 1);
    const records = intlifyRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.path).toBe("affected/handler.mjs");
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-intlify-flat-json-prototype-write",
    );
  });

  test("fails closed across configuration, provenance, identity, mutation, and test boundaries", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-intlify-negatives-"),
    );
    temporaryPaths.push(repository);
    const binding = 'import { createI18n } from "vue-i18n";';
    const cases = [
      [
        "flat-false",
        createRoute(
          binding,
          undefined,
          "{ flatJson: false, messages: { en: request.body.messages } }",
        ),
      ],
      [
        "flat-dynamic",
        createRoute(
          binding,
          undefined,
          "{ flatJson: enabled, messages: { en: request.body.messages } }",
        ),
      ],
      ["no-messages", createRoute(binding, undefined, "{ flatJson: true }")],
      [
        "custom-resolver",
        createRoute(
          binding,
          undefined,
          "{ flatJson: true, messageResolver: customResolver, messages: { en: request.body.messages } }",
        ),
      ],
      [
        "spread",
        createRoute(
          binding,
          undefined,
          "{ flatJson: true, messages: { en: request.body.messages }, ...overrides }",
        ),
      ],
      [
        "duplicate",
        createRoute(
          binding,
          undefined,
          "{ flatJson: true, flatJson: true, messages: { en: request.body.messages } }",
        ),
      ],
      [
        "fixed-input",
        createRoute(
          binding,
          undefined,
          "{ flatJson: true, messages: trustedMessages }",
        ),
      ],
      [
        "reassigned-factory",
        createRoute(`${binding}\ncreateI18n = replacement;`),
      ],
      [
        "replaced-member",
        createRoute(
          'import * as I18n from "vue-i18n";\nI18n.createI18n = replacement;',
          "I18n.createI18n",
        ),
      ],
      [
        "reassigned-instance",
        setterRoute(binding).replace(
          "export function",
          "i18n = replacement;\nexport function",
        ),
      ],
      [
        "replaced-setter",
        setterRoute(binding).replace(
          "export function",
          "i18n.global.setLocaleMessage = replacement;\nexport function",
        ),
      ],
      [
        "shadowed-require",
        createRoute("", 'require("vue-i18n").createI18n').replace(
          "handler(request)",
          "handler(request, require)",
        ),
      ],
    ] as const;
    for (const [id, source] of cases) await writeCase(repository, id, source);
    await writeCase(
      repository,
      "patched",
      createRoute(binding),
      "vue-i18n",
      "9.14.3",
    );
    await writeCase(
      repository,
      "dev-only",
      createRoute(binding),
      "vue-i18n",
      "9.14.2",
      "devDependencies",
    );
    await writeCase(
      repository,
      "test-path",
      createRoute(binding),
      "vue-i18n",
      "9.14.2",
      "dependencies",
      "tests/handler.test.mjs",
    );
    expect(
      intlifyRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("adds field-local validation guidance without overstating impact", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({
        frameworkModel: {
          id: "node-http-intlify-flat-json-prototype-pollution",
        },
      }),
    );
    expect(prompt).toContain("GHSA-p2ph-7g93-hw3m");
    expect(prompt).toContain("flatJson:true");
    expect(prompt).toContain("Object.prototype");
    expect(prompt).toContain("finally block");
    expect(prompt).toContain("Do not infer code execution");
  });
});
