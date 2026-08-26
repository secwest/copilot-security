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

function contentfulRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-contentful-mcp-management-token-host-redirect",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "1.7.15",
  dependencySection = "dependencies",
  relativePath = "src/launcher.mjs",
  scripts?: Record<string, string>,
): Promise<void> {
  const root = join(repository, id);
  await mkdir(dirname(join(root, relativePath)), { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        type: "module",
        ...(scripts === undefined ? {} : { scripts }),
        [dependencySection]: { "@contentful/mcp-server": version },
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
            dependencies: {
              "@contentful/mcp-server": { version: resolved },
            },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": {
                dependencies: {
                  "@contentful/mcp-server": rootDeclaration,
                },
              },
              "node_modules/@contentful/mcp-server": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const staticLauncher = 'import "@contentful/mcp-server";\n';

describe("Contentful MCP management-token host redirect model", () => {
  test("keeps a strict affected and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-contentful-mcp-management-token-host-redirect-manifest.json",
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
      "node-contentful-mcp-management-token-host-redirect",
      "node-contentful-mcp-management-token-host-pinned",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-918", "CWE-441"],
      acceptableSeverities: ["high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    const affectedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-contentful-mcp-management-token-host-redirect",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-contentful-mcp-management-token-host-pinned",
    );
    for (const path of [
      "README.md",
      "src/launcher.mjs",
      "witness.mjs",
      "runtime-witness.mjs",
    ]) {
      expect(await readFile(join(affectedRoot, path), "utf8"), path).toBe(
        await readFile(join(repairedRoot, path), "utf8"),
      );
    }
    const affectedPackage = JSON.parse(
      await readFile(join(affectedRoot, "package.json"), "utf8"),
    ) as { dependencies: Record<string, string> };
    const repairedPackage = JSON.parse(
      await readFile(join(repairedRoot, "package.json"), "utf8"),
    ) as { dependencies: Record<string, string> };
    expect(affectedPackage.dependencies["@contentful/mcp-server"]).toBe(
      "1.7.15",
    );
    expect(repairedPackage.dependencies["@contentful/mcp-server"]).toBe(
      "1.7.19",
    );
  });

  test("emits exact operational launch and dependency evidence", async () => {
    const affected = contentfulRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-contentful-mcp-management-token-host-redirect",
        ),
      ),
    );
    const repaired = contentfulRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-contentful-mcp-management-token-host-pinned",
        ),
      ),
    );
    expect(affected).toHaveLength(1);
    expect(repaired).toHaveLength(0);
    expect(affected[0]).toMatchObject({
      path: "src/launcher.mjs",
      line: 1,
      frameworkModel: {
        source: {
          kind: "llm-controlled-contentful-migration-network-options",
          path: "src/launcher.mjs",
          line: 1,
        },
        sink: {
          kind: "vulnerable-contentful-mcp-management-token-authorized-request",
          path: "src/launcher.mjs",
          line: 1,
          cweIds: ["CWE-918", "CWE-441"],
        },
      },
    });
    expect(affected[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "contentful-mcp-operational-launch",
      path: "src/launcher.mjs",
      line: 1,
      symbol: "module-import",
    });
    expect(affected[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "contentful-mcp-runtime-dependency",
      path: "package.json",
      line: 12,
      symbol:
        "@contentful/mcp-server@1.7.15:manifest-exact:unpinned-migration-cma-host",
    });
  });

  test("enforces the reviewed server version boundary", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-contentful-mcp-versions-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["early", "0.9.0", true],
      ["one-six", "1.6.9", true],
      ["reported", "1.7.15", true],
      ["last", "1.7.18", true],
      ["prerelease", "1.7.18-beta.1", false],
      ["fixed", "1.7.19", false],
      ["later", "2.0.0", false],
    ] as const;
    for (const [id, version] of cases) {
      await writeCase(repository, id, staticLauncher, version);
    }
    const found = new Set(
      contentfulRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    );
    for (const [id, , expected] of cases) {
      expect(found.has(id)).toBe(expected);
    }
  });

  test("recognizes bounded module and operational script launch forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-contentful-mcp-launches-"),
    );
    temporaryPaths.push(repository);
    await writeCase(repository, "static", staticLauncher);
    await writeCase(
      repository,
      "dynamic",
      'await import("@contentful/mcp-server");\n',
    );
    const scripts = [
      ["binary", "contentful-mcp-server"],
      ["npx", "npx --yes @contentful/mcp-server"],
      ["npm-exec", "npm exec --yes -- @contentful/mcp-server"],
      ["cross-env", "cross-env NODE_ENV=production contentful-mcp-server"],
      ["windows", 'set "NODE_ENV=production"&& contentful-mcp-server'],
    ] as const;
    for (const [id, command] of scripts) {
      await writeCase(
        repository,
        id,
        'export const health = "ok";\n',
        "1.7.15",
        "dependencies",
        "src/health.mjs",
        { "start:mcp": command },
      );
    }
    const records = contentfulRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(7);
    expect(
      records.filter((record) => record.path.endsWith("package.json")),
    ).toHaveLength(5);
    expect(
      records.filter((record) =>
        record.frameworkModel?.propagators.some(
          ({ symbol }) => symbol === "module-import",
        ),
      ),
    ).toHaveLength(2);
  });

  test("accepts only declaration-consistent modern lock evidence", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-contentful-mcp-locks-"),
    );
    temporaryPaths.push(repository);
    for (const id of ["affected", "fixed", "stale", "v1"]) {
      await writeCase(repository, id, staticLauncher, "^1.7.0");
    }
    await writeNpmLock(repository, "affected", "^1.7.0", "1.7.15");
    await writeNpmLock(repository, "fixed", "^1.7.0", "1.7.19");
    await writeNpmLock(repository, "stale", "^1.7.0", "1.7.15", 3, "^1.6.0");
    await writeNpmLock(repository, "v1", "^1.7.0", "1.7.15", 1);
    const records = contentfulRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.path).toBe("affected/src/launcher.mjs");
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-contentful-mcp-management-token-authorized-request",
    );
  });

  test("fails closed on unlaunched, ambiguous, repaired, and nonproduction forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-contentful-mcp-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["package-only", 'export const health = "ok";\n'],
      [
        "nested",
        'export async function start() {\n  await import("@contentful/mcp-server");\n}\n',
      ],
      ["subpath", 'import "@contentful/mcp-server/package.json";\n'],
      ["lookalike", 'import "@example/contentful-mcp-server";\n'],
      [
        "bound-import",
        'import server from "@contentful/mcp-server";\nexport { server };\n',
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    await writeCase(
      repository,
      "dev-only",
      staticLauncher,
      "1.7.15",
      "devDependencies",
    );
    await writeCase(
      repository,
      "test-path",
      staticLauncher,
      "1.7.15",
      "dependencies",
      "tests/server.test.mjs",
    );
    await writeCase(
      repository,
      "arbitrary-script",
      'export const health = "ok";\n',
      "1.7.15",
      "dependencies",
      "src/health.mjs",
      { diagnostic: "contentful-mcp-server" },
    );
    await writeCase(
      repository,
      "echo",
      'export const health = "ok";\n',
      "1.7.15",
      "dependencies",
      "src/health.mjs",
      { start: "echo contentful-mcp-server" },
    );
    await writeCase(repository, "fixed", staticLauncher, "1.7.19");
    expect(
      contentfulRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires safe field-local validation and conservative impact", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({
        frameworkModel: {
          id: "node-contentful-mcp-management-token-host-redirect",
        },
      }),
    );
    expect(prompt).toContain("GHSA-2xhg-73j7-rrgx");
    expect(prompt).toContain("space_to_space_migration_handler");
    expect(prompt).toContain("CONTENTFUL_MANAGEMENT_TOKEN");
    expect(prompt).toContain("random loopback-only TLS capture endpoint");
    expect(prompt).toContain("Never use a real Contentful token");
    expect(prompt).toContain("CWE-918 and CWE-441");
  });
});
