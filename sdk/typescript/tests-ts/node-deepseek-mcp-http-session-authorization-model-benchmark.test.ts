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

function deepseekRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-deepseek-mcp-http-cross-session-authorization-bypass",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "1.6.0",
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
        [dependencySection]: {
          "@arikusi/deepseek-mcp-server": version,
        },
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
              "@arikusi/deepseek-mcp-server": { version: resolved },
            },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": {
                dependencies: {
                  "@arikusi/deepseek-mcp-server": rootDeclaration,
                },
              },
              "node_modules/@arikusi/deepseek-mcp-server": {
                version: resolved,
              },
            },
          },
      null,
      2,
    ),
  );
}

const dynamicLauncher =
  'process.env.TRANSPORT = "http";\nprocess.env.SKIP_CONNECTION_TEST = "true";\nawait import("@arikusi/deepseek-mcp-server");\n';

describe("DeepSeek MCP HTTP cross-session authorization model", () => {
  test("keeps a strict affected and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-deepseek-mcp-http-session-authorization-manifest.json",
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
      "node-deepseek-mcp-http-cross-session-bypass",
      "node-deepseek-mcp-http-session-isolated",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-639"],
      acceptableSeverities: ["high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves exact HTTP launch and production dependency evidence", async () => {
    const vulnerable = deepseekRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-deepseek-mcp-http-cross-session-bypass",
        ),
      ),
    );
    const repaired = deepseekRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-deepseek-mcp-http-session-isolated",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(repaired).toHaveLength(0);
    expect(vulnerable[0]).toMatchObject({
      path: "src/launcher.mjs",
      line: 3,
      frameworkModel: {
        scope: "same-file",
        source: {
          kind: "unauthenticated-multi-client-http-mcp-session",
          path: "src/launcher.mjs",
          line: 1,
        },
        sink: {
          kind: "vulnerable-deepseek-mcp-process-global-caller-keyed-session-store",
          path: "src/launcher.mjs",
          line: 3,
          cweIds: ["CWE-639"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "deepseek-mcp-http-launch-configuration",
      path: "src/launcher.mjs",
      line: 1,
      symbol: "module-dynamic-import:TRANSPORT=http",
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "deepseek-mcp-runtime-dependency",
      path: "package.json",
      line: 11,
      symbol:
        "@arikusi/deepseek-mcp-server@1.6.0:manifest-exact:process-global-session-store",
    });
  });

  test("enforces the reviewed version interval", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-deepseek-mcp-versions-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["before", "1.4.1", false],
      ["minimum", "1.4.2", true],
      ["middle", "1.5.7", true],
      ["reported", "1.6.0", true],
      ["last-branch", "1.6.99", true],
      ["prerelease", "1.6.1-beta.0", false],
      ["fixed", "1.7.0", false],
      ["later", "2.0.0", false],
    ] as const;
    for (const [id, version] of cases) {
      await writeCase(repository, id, dynamicLauncher, version);
    }
    const found = new Set(
      deepseekRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    );
    for (const [id, , expected] of cases) {
      expect(found.has(id)).toBe(expected);
    }
  });

  test("recognizes bounded operational npm launch forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-deepseek-mcp-scripts-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["posix", "TRANSPORT=http deepseek-mcp-server"],
      ["cross-env", "cross-env TRANSPORT=http deepseek-mcp-server"],
      ["env-npx", "env TRANSPORT=http npx --yes @arikusi/deepseek-mcp-server"],
      [
        "npm-exec",
        "TRANSPORT=http npm exec --yes -- @arikusi/deepseek-mcp-server",
      ],
      ["windows", 'set "TRANSPORT=http"&& deepseek-mcp-server'],
    ] as const;
    for (const [id, command] of cases) {
      await writeCase(
        repository,
        id,
        'export const health = "ok";\n',
        "1.6.0",
        "dependencies",
        "src/health.mjs",
        { "start:http": command },
      );
    }
    const records = deepseekRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(cases.length);
    expect(records.map(({ path }) => path)).toEqual(
      cases.map(([id]) => `${id}/package.json`).sort(),
    );
    expect(
      records.every((record) =>
        record.frameworkModel?.propagators.some(
          ({ symbol }) => symbol === "operational-npm-script:TRANSPORT=http",
        ),
      ),
    ).toBe(true);
  });

  test("accepts only declaration-consistent modern lock evidence", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-deepseek-mcp-locks-"),
    );
    temporaryPaths.push(repository);
    for (const id of ["affected", "fixed", "stale", "v1"]) {
      await writeCase(repository, id, dynamicLauncher, "^1.4.2");
    }
    await writeNpmLock(repository, "affected", "^1.4.2", "1.6.0");
    await writeNpmLock(repository, "fixed", "^1.4.2", "1.7.0");
    await writeNpmLock(repository, "stale", "^1.4.2", "1.6.0", 3, "1.5.0");
    await writeNpmLock(repository, "v1", "^1.4.2", "1.6.0", 1);
    const records = deepseekRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.path).toBe("affected/src/launcher.mjs");
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-deepseek-mcp-process-global-caller-keyed-session-store",
    );
  });

  test("fails closed across transport, launch, identity, provenance, and test boundaries", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-deepseek-mcp-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "stdio",
        'process.env.TRANSPORT = "stdio";\nawait import("@arikusi/deepseek-mcp-server");\n',
      ],
      [
        "overwritten",
        'process.env.TRANSPORT = "http";\nprocess.env.TRANSPORT = "stdio";\nawait import("@arikusi/deepseek-mcp-server");\n',
      ],
      [
        "deleted",
        'process.env.TRANSPORT = "http";\ndelete process.env.TRANSPORT;\nawait import("@arikusi/deepseek-mcp-server");\n',
      ],
      [
        "dynamic",
        'process.env.TRANSPORT = selectedTransport;\nawait import("@arikusi/deepseek-mcp-server");\n',
      ],
      [
        "nested",
        'export async function start() {\n  process.env.TRANSPORT = "http";\n  await import("@arikusi/deepseek-mcp-server");\n}\n',
      ],
      [
        "static-import",
        'process.env.TRANSPORT = "http";\nimport "@arikusi/deepseek-mcp-server";\n',
      ],
      [
        "subpath",
        'process.env.TRANSPORT = "http";\nawait import("@arikusi/deepseek-mcp-server/dist/session.js");\n',
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    await writeCase(
      repository,
      "dev-only",
      dynamicLauncher,
      "1.6.0",
      "devDependencies",
    );
    await writeCase(
      repository,
      "test-path",
      dynamicLauncher,
      "1.6.0",
      "dependencies",
      "tests/launcher.test.mjs",
    );
    await writeCase(
      repository,
      "arbitrary-script",
      'export const health = "ok";\n',
      "1.6.0",
      "dependencies",
      "src/health.mjs",
      { diagnostic: "TRANSPORT=http deepseek-mcp-server" },
    );
    await writeCase(
      repository,
      "echo-lookalike",
      'export const health = "ok";\n',
      "1.6.0",
      "dependencies",
      "src/health.mjs",
      { start: "TRANSPORT=http echo deepseek-mcp-server" },
    );
    await writeCase(
      repository,
      "script-stdio",
      'export const health = "ok";\n',
      "1.6.0",
      "dependencies",
      "src/health.mjs",
      { start: "TRANSPORT=stdio deepseek-mcp-server" },
    );
    expect(
      deepseekRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("adds field-local validation guidance without overstating impact", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({
        frameworkModel: {
          id: "node-deepseek-mcp-http-cross-session-authorization-bypass",
        },
      }),
    );
    expect(prompt).toContain("GHSA-fh3r-g96v-f578");
    expect(prompt).toContain("TRANSPORT=http");
    expect(prompt).toContain("process-global singleton");
    expect(prompt).toContain("STDIO");
    expect(prompt).toContain("without a listener");
    expect(prompt).toContain(
      "Do not claim unauthenticated Internet reachability",
    );
  });
});
