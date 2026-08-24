import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
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
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function decompressRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-decompress-archive-escape",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "10.2.0",
  packageName = "@xhmikosr/decompress",
  dependencySection = "dependencies",
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
        [dependencySection]: { [packageName]: version },
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
  packageName: string,
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
            dependencies: { [packageName]: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { [packageName]: rootDeclaration } },
              [`node_modules/${packageName}`]: { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const direct = (
  importLine = 'import decompress from "@xhmikosr/decompress";',
  call = "decompress(request.body, extractionRoot)",
) => `${importLine}
const extractionRoot = "/srv/application/imports";
export async function handler(request) {
  return ${call};
}
`;

describe("decompress archive-escape framework benchmark", () => {
  test("keeps a strict multi-hop vulnerable and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-decompress-archive-escape-manifest.json"),
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
      "node-multi-hop-decompress-archive-escape",
      "node-multi-hop-repaired-decompress-archive",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-22", "CWE-59", "CWE-732"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const vulnerable = decompressRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-decompress-archive-escape",
        ),
      ),
    );
    const repaired = decompressRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-repaired-decompress-archive",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/storage.js",
      line: 6,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: {
          path: "src/server.js",
          line: 10,
          kind: "http-uploaded-archive-bytes",
        },
        sink: {
          path: "src/storage.js",
          line: 6,
          kind: "vulnerable-decompress-archive-escape",
          cweIds: ["CWE-22", "CWE-59", "CWE-732"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "decompress-runtime-dependency",
          path: "package.json",
          symbol:
            "@xhmikosr/decompress@10.2.0:manifest-exact:archive-path-link-mode-escape",
        }),
        expect.objectContaining({
          kind: "relative-module-import",
          path: "src/server.js",
          line: 2,
        }),
        expect.objectContaining({
          kind: "wrapper-parameter",
          path: "src/storage.js",
          line: 5,
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
            "node-multi-hop-decompress-archive-escape",
            relative,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-repaired-decompress-archive",
            relative,
          ),
          "utf8",
        ),
      );
    }
  });

  test("keeps both maintained affected branches and the unpatched upstream line", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-decompress-versions-"),
    );
    temporaryPaths.push(repository);
    const scopedVulnerable = [
      "5.0.0",
      "9.0.1",
      "10.0.1",
      "10.2.0",
      "11.0.2",
      "11.1.2",
    ];
    const scopedSafe = [
      "10.2.1",
      "10.2.2",
      "11.1.3",
      "11.1.4",
      "12.0.0",
      "10.2.0-beta.1",
    ];
    for (const version of [...scopedVulnerable, ...scopedSafe]) {
      await writeCase(
        repository,
        `scoped-${version.replaceAll(".", "-")}`,
        direct(),
        version,
      );
    }
    for (const version of ["3.0.0", "4.2.1", "4.2.2", "5.0.0"]) {
      await writeCase(
        repository,
        `upstream-${version.replaceAll(".", "-")}`,
        direct(
          'const decompress = require("decompress");',
          "decompress(request.body, extractionRoot)",
        ),
        version,
        "decompress",
        "dependencies",
        "handler.cjs",
      );
    }
    expect(
      decompressRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    ).toEqual(
      [
        ...scopedVulnerable.map(
          (version) => `scoped-${version.replaceAll(".", "-")}`,
        ),
        "upstream-3-0-0",
        "upstream-4-2-1",
      ].sort(),
    );
  });

  test("accepts official default, namespace, TypeScript, CommonJS, alias, and multiline forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-decompress-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["default", direct()],
      [
        "default-alias",
        direct(
          'import { default as unpack } from "@xhmikosr/decompress";',
          "unpack(request.body, extractionRoot)",
        ),
      ],
      [
        "namespace",
        direct(
          'import * as archive from "@xhmikosr/decompress";',
          "archive.default(request.body, extractionRoot)",
        ),
      ],
      [
        "typescript-import-equals",
        direct(
          'import unpack = require("@xhmikosr/decompress");',
          "unpack(request.body, extractionRoot)",
        ),
        "handler.ts",
      ],
      [
        "commonjs",
        direct(
          'const unpack = require("@xhmikosr/decompress");',
          "unpack(request.body, extractionRoot)",
        ),
        "handler.cjs",
      ],
      [
        "commonjs-default",
        direct(
          'const unpack = require("@xhmikosr/decompress").default;',
          "unpack(request.body, extractionRoot)",
        ),
        "handler.cjs",
      ],
      [
        "commonjs-destructure",
        direct(
          'const { default: unpack } = require("@xhmikosr/decompress");',
          "unpack(request.body, extractionRoot)",
        ),
        "handler.cjs",
      ],
      [
        "stable-alias",
        `${direct()
          .replace(
            "const extractionRoot",
            "const unpack = decompress;\nconst extractionRoot",
          )
          .replace("decompress(request.body", "unpack(request.body")}`,
      ],
      [
        "multiline",
        direct(
          undefined,
          `decompress(
    request.body,
    extractionRoot,
  )`,
        ),
      ],
      [
        "next-request-buffer",
        `import decompress from "@xhmikosr/decompress";
const extractionRoot = "/srv/application/imports";
export async function handler(request) {
  const archive = await request.arrayBuffer();
  return decompress(archive, extractionRoot);
}
`,
      ],
    ] as const;
    for (const [id, source, filename = "handler.mjs"] of cases) {
      await writeCase(
        repository,
        id,
        source,
        "10.2.0",
        "@xhmikosr/decompress",
        "dependencies",
        filename,
      );
    }
    expect(
      decompressRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(
      cases
        .map(([id, , filename = "handler.mjs"]) => `${id}/${filename}`)
        .sort(),
    );
  });

  test("rejects parse-only, fixed, patched, ambiguous, shadowed, and replaced flows", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-decompress-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["fixed-input", direct().replace("request.body", '"trusted.tar.gz"')],
      ["parse-only", direct(undefined, "decompress(request.body)")],
      [
        "options-only",
        direct(undefined, "decompress(request.body, { strip: 1 })"),
      ],
      ["null-output", direct(undefined, "decompress(request.body, null)")],
      [
        "local-lookalike",
        direct().replace(
          'from "@xhmikosr/decompress"',
          'from "./decompress.js"',
        ),
      ],
      [
        "binding-reassigned",
        direct().replace(
          "const extractionRoot",
          "decompress = safeDecompress;\nconst extractionRoot",
        ),
      ],
      [
        "namespace-default-replaced",
        direct(
          'import * as archive from "@xhmikosr/decompress";\narchive.default = safeDecompress;',
          "archive.default(request.body, extractionRoot)",
        ),
      ],
      [
        "parameter-shadow",
        direct().replace(
          "function handler(request)",
          "function handler(decompress, request)",
        ),
      ],
    ] as const;
    for (const [id, source] of cases) await writeCase(repository, id, source);
    await writeCase(repository, "patched", direct(), "10.2.1");
    await writeCase(
      repository,
      "dev-only",
      direct(),
      "10.2.0",
      "@xhmikosr/decompress",
      "devDependencies",
    );
    await writeCase(
      repository,
      "wrong-package",
      direct(),
      "10.2.0",
      "decompress-clone",
    );
    const ambiguous = join(repository, "ambiguous-packages");
    await mkdir(ambiguous);
    await writeFile(
      join(ambiguous, "package.json"),
      JSON.stringify({
        dependencies: {
          "@xhmikosr/decompress": "10.2.0",
          decompress: "4.2.1",
        },
      }),
    );
    await writeFile(join(ambiguous, "handler.mjs"), direct());
    expect(
      decompressRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exact production provenance or a declaration-consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-decompress-dependencies-"),
    );
    temporaryPaths.push(repository);
    const source = direct();
    await writeCase(repository, "locked-range", source, "^10.2.0");
    await writeNpmLock(
      repository,
      "locked-range",
      "@xhmikosr/decompress",
      "^10.2.0",
      "10.2.0",
    );
    await writeCase(repository, "unlocked-range", source, "^10.2.0");
    await writeCase(repository, "v1-lock", source, "^10.2.0");
    await writeNpmLock(
      repository,
      "v1-lock",
      "@xhmikosr/decompress",
      "^10.2.0",
      "10.2.0",
      1,
    );
    await writeCase(repository, "inconsistent-lock", source, "^10.2.1");
    await writeNpmLock(
      repository,
      "inconsistent-lock",
      "@xhmikosr/decompress",
      "^10.2.1",
      "10.2.0",
      3,
      "^10.2.0",
    );
    const records = decompressRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "locked-range/handler.mjs",
    ]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-decompress-archive-escape",
    );
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "decompress-runtime-dependency",
          path: "locked-range/package.json",
          symbol:
            "@xhmikosr/decompress@10.2.0:npm-lockfile:archive-path-link-mode-escape",
        }),
      ]),
    );
  });

  test("excludes test and example trees and retains the canonical row under the repository cap", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-decompress-exclusions-"),
    );
    temporaryPaths.push(repository);
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
        JSON.stringify({
          dependencies: { "@xhmikosr/decompress": "10.2.0" },
        }),
      );
      await writeFile(join(root, "handler.mjs"), direct());
    }
    expect(
      decompressRecords(await buildResidualRiskInventory(repository)),
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
    ).toBeGreaterThanOrEqual(169);
    const paths = decompressRecords(repositoryInventory).map(
      ({ path }) => path,
    );
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-decompress-archive-escape/src/storage.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-repaired-decompress-archive/src/storage.js",
    );
  }, 60_000);

  test("requires primitive-specific validation and impact discipline", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-decompress-archive-escape");
    expect(prompt).toContain("GHSA-mp2f-45pm-3cg9");
    expect(prompt).toContain("CVE-2026-53486");
    expect(prompt).toContain("10.2.1");
    expect(prompt).toContain("11.1.3");
    expect(prompt).toContain("unmaintained upstream decompress");
    expect(prompt).toContain("not arbitrary secret disclosure");
  });
});
