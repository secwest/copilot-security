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

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-opcua-server-nonce-cache-dos",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-node-opcua-nonce-cache-"),
  );
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
    declaration?: string;
    lockedVersion?: string;
    packageName?: string;
    path?: string;
    section?: "dependencies" | "devDependencies";
    lock?: boolean;
    lockfileVersion?: number;
  } = {},
): Promise<void> {
  const directory = join(root, id);
  await mkdir(directory, { recursive: true });
  const packageName = options.packageName ?? "node-opcua";
  const declaration = options.declaration ?? "2.165.0";
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({
      name: id,
      private: true,
      [options.section ?? "dependencies"]: { [packageName]: declaration },
    }),
  );
  if (options.lock === true) {
    await writeFile(
      join(directory, "package-lock.json"),
      JSON.stringify({
        name: id,
        lockfileVersion: options.lockfileVersion ?? 3,
        packages: {
          "": { dependencies: { [packageName]: declaration } },
          "node_modules/node-opcua": {
            version: options.lockedVersion ?? "2.165.0",
          },
        },
      }),
    );
  }
  const sourcePath = join(directory, options.path ?? "src/server.mjs");
  await mkdir(join(sourcePath, ".."), { recursive: true });
  await writeFile(sourcePath, source);
}

describe("node-opcua unbounded session nonce cache model", () => {
  test("resolves official server bindings that actually start listening", async () => {
    const root = await repository();
    const cases = [
      [
        "named",
        'import { OPCUAServer as UaServer } from "node-opcua";\nconst server = new UaServer({ port: 4840 });\nawait server.initialize();\nawait server.start();',
      ],
      [
        "namespace",
        'import * as opcua from "node-opcua";\nconst server = new opcua.OPCUAServer({ port: 4840 });\nserver.start();',
      ],
      [
        "typescript",
        'import opcua = require("node-opcua");\nconst server = new opcua.OPCUAServer({ port: 4840 });\nawait server.start();',
        "src/server.ts",
      ],
      [
        "commonjs-member",
        'const UaServer = require("node-opcua").OPCUAServer;\nconst server = new UaServer({ port: 4840 });\nserver.start();',
      ],
      [
        "commonjs-destructure",
        'const { OPCUAServer: UaServer } = require("node-opcua");\nconst server = new UaServer({ port: 4840 });\nserver.start();',
      ],
      [
        "commonjs-receiver",
        'const opcua = require("node-opcua");\nconst server = new opcua.OPCUAServer({ port: 4840 });\nserver.start();',
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, source, path]) => writeCase(root, id, source, { path })),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path).sort()).toEqual(
      cases.map(([id, , path]) => `${id}/${path ?? "src/server.mjs"}`).sort(),
    );
    for (const record of found) {
      expect(record.frameworkModel?.source.kind).toBe(
        "untrusted-opcua-session-nonce",
      );
      expect(record.frameworkModel?.sink.kind).toBe(
        "vulnerable-node-opcua-unbounded-nonce-cache-dos",
      );
      expect(record.frameworkModel?.sink.cweIds).toEqual([
        "CWE-770",
        "CWE-400",
      ]);
      expect(record.frameworkModel?.propagators).toHaveLength(1);
      expect(record.frameworkModel?.propagators[0]?.symbol).toBe(
        "node-opcua@2.165.0:manifest-exact:unbounded-session-nonce-cache",
      );
    }
  });

  test("uses the reviewed affected range and repaired release control", async () => {
    const root = await repository();
    const source =
      'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ port: 4840 });\nserver.start();';
    await Promise.all([
      writeCase(root, "affected-2-164", source, { declaration: "2.164.0" }),
      writeCase(root, "affected-2-165", source, { declaration: "2.165.0" }),
      writeCase(root, "outside-reviewed-range", source, {
        declaration: "2.165.1",
      }),
      writeCase(root, "repaired-release", source, { declaration: "2.168.0" }),
      writeCase(root, "new-major", source, { declaration: "3.0.0" }),
    ]);
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(
      ["affected-2-164/src/server.mjs", "affected-2-165/src/server.mjs"].sort(),
    );
  });

  test("preserves an exported server instance through a relative import", async () => {
    const root = await repository();
    await writeCase(
      root,
      "cross-file",
      'import { OPCUAServer as UaServer } from "node-opcua";\nexport const server = new UaServer({ port: 4840 });',
    );
    await writeFile(
      join(root, "cross-file", "src", "main.mjs"),
      'import { server as industrialServer } from "./server.mjs";\nawait industrialServer.initialize();\nawait industrialServer.start();',
    );
    await writeCase(
      root,
      "reassigned-cross-file",
      'import { OPCUAServer } from "node-opcua";\nexport const server = new OPCUAServer({ port: 4840 });',
    );
    await writeFile(
      join(root, "reassigned-cross-file", "src", "main.mjs"),
      'import { server } from "./server.mjs";\nserver = localServer;\nserver.start();',
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "untrusted-opcua-session-nonce",
      path: "cross-file/src/main.mjs",
      line: 3,
    });
    expect(found[0]?.frameworkModel?.sink).toEqual({
      kind: "vulnerable-node-opcua-unbounded-nonce-cache-dos",
      path: "cross-file/src/server.mjs",
      line: 2,
      cweIds: ["CWE-770", "CWE-400"],
    });
    expect(
      found[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(["relative-module-import", "node-opcua-runtime-dependency"]);
  });

  test("requires exact production or fresh npm v2/v3 dependency proof", async () => {
    const root = await repository();
    const source =
      'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ port: 4840 });\nserver.start();';
    await Promise.all([
      writeCase(root, "lock-v2", source, {
        declaration: "^2.160.0",
        lock: true,
        lockfileVersion: 2,
      }),
      writeCase(root, "lock-v3", source, {
        declaration: "^2.160.0",
        lock: true,
      }),
      writeCase(root, "range-without-lock", source, {
        declaration: "^2.160.0",
      }),
      writeCase(root, "development-only", source, {
        section: "devDependencies",
      }),
      writeCase(root, "wrong-package", source, {
        packageName: "node-opcua-client",
      }),
      writeCase(root, "legacy-lock", source, {
        declaration: "^2.160.0",
        lock: true,
        lockfileVersion: 1,
      }),
      writeCase(root, "fixed-lock", source, {
        declaration: "^2.160.0",
        lockedVersion: "2.168.0",
        lock: true,
      }),
    ]);
    await writeFile(
      join(root, "lock-v3", "npm-shrinkwrap.json"),
      await readFile(join(root, "lock-v3", "package-lock.json")),
    );
    await writeFile(join(root, "lock-v2", "npm-shrinkwrap.json"), "{\n");
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("lock-v3/src/server.mjs");
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-node-opcua-unbounded-nonce-cache-dos",
    );
    expect(found[0]?.frameworkModel?.propagators[0]?.symbol).toBe(
      "node-opcua@2.165.0:npm-lockfile:unbounded-session-nonce-cache",
    );
  });

  test("rejects client-only, unstarted, replaced, shadowed, and test code", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "unstarted",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ port: 4840 });',
      ),
      writeCase(
        root,
        "client-only",
        'import { OPCUAClient } from "node-opcua";\nconst client = OPCUAClient.create({});\nclient.connect("opc.tcp://example:4840");',
      ),
      writeCase(
        root,
        "reassigned-binding",
        'import { OPCUAServer } from "node-opcua";\nOPCUAServer = LocalServer;\nconst server = new OPCUAServer({});\nserver.start();',
      ),
      writeCase(
        root,
        "replaced-member",
        'import * as opcua from "node-opcua";\nopcua.OPCUAServer = LocalServer;\nconst server = new opcua.OPCUAServer({});\nserver.start();',
      ),
      writeCase(
        root,
        "reassigned-instance",
        'import { OPCUAServer } from "node-opcua";\nlet server = new OPCUAServer({});\nserver = localServer;\nserver.start();',
      ),
      writeCase(
        root,
        "replaced-start",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({});\nserver.start = localStart;\nserver.start();',
      ),
      writeCase(
        root,
        "shadowed-binding",
        'import { OPCUAServer } from "node-opcua";\nexport function launch(OPCUAServer) {\n const server = new OPCUAServer({});\n server.start();\n}',
      ),
      writeCase(
        root,
        "local-lookalike",
        'import "node-opcua";\nconst server = new OPCUAServer({});\nserver.start();',
      ),
      writeCase(
        root,
        "test-path",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({});\nserver.start();',
        { path: "test/server.mjs" },
      ),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("keeps the benchmark pair source-identical and under perfect gates", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-opcua-server-unbounded-nonce-cache",
    );
    const repaired = join(
      benchmarkRoot,
      "fixtures",
      "node-opcua-server-bounded-nonce-cache",
    );
    const found = records(await buildResidualRiskInventory(vulnerable));
    expect(found).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(repaired))).toEqual([]);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "untrusted-opcua-session-nonce",
      path: "src/server.mjs",
      line: 6,
    });
    expect(found[0]?.frameworkModel?.sink).toEqual({
      kind: "vulnerable-node-opcua-unbounded-nonce-cache-dos",
      path: "src/server.mjs",
      line: 3,
      cweIds: ["CWE-770", "CWE-400"],
    });
    expect(found[0]?.frameworkModel?.propagators[0]?.symbol).toBe(
      "node-opcua@2.165.0:manifest-exact:unbounded-session-nonce-cache",
    );
    for (const path of ["src/server.mjs", "witness.mjs"]) {
      expect(await readFile(join(vulnerable, path), "utf8")).toBe(
        await readFile(join(repaired, path), "utf8"),
      );
    }
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-opcua-nonce-cache-dos-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        expected: unknown[];
        findingsPaths: string[];
      }>;
    };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-opcua-server-unbounded-nonce-cache",
      "node-opcua-server-bounded-nonce-cache",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
  });

  test("teaches the exact exposure, proof, repair, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-opcua-server-nonce-cache-dos rows");
    expect(prompt).toContain("GHSA-6wvw-vrw4-363w");
    expect(prompt).toContain("50,000-entry ceiling");
    expect(prompt).toContain("OPCUAServer");
    expect(prompt).toContain("CWE-770");
  });
});
