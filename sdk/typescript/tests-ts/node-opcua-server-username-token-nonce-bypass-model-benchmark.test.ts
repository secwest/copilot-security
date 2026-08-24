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
        record.frameworkModel?.id ===
        "node-opcua-server-username-token-nonce-bypass",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-node-opcua-username-token-"),
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
  const declaration = options.declaration ?? "2.165.2";
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
            version: options.lockedVersion ?? "2.165.2",
          },
        },
      }),
    );
  }
  const sourcePath = join(directory, options.path ?? "src/server.mjs");
  await mkdir(join(sourcePath, ".."), { recursive: true });
  await writeFile(sourcePath, source);
}

const configuredServer =
  'import { OPCUAServer } from "node-opcua";\nconst userManager = { isValidUser(user, password) { return user === "operator" && password === "secret"; } };\nconst server = new OPCUAServer({ port: 4840, userManager });\nserver.start();';

describe("node-opcua UserNameIdentityToken nonce-binding model", () => {
  test("resolves official server bindings with configured username authentication", async () => {
    const root = await repository();
    const cases = [
      [
        "named",
        'import { OPCUAServer as UaServer } from "node-opcua";\nconst manager = { isValidUser: checkUser };\nconst server = new UaServer({ userManager: manager });\nawait server.start();',
      ],
      [
        "namespace",
        'import * as opcua from "node-opcua";\nconst server = new opcua.OPCUAServer({ userManager: security.userManager });\nserver.start();',
      ],
      [
        "typescript",
        'import opcua = require("node-opcua");\nconst server = new opcua.OPCUAServer({ userManager: makeUserManager() });\nawait server.start();',
        "src/server.ts",
      ],
      [
        "commonjs-member",
        'const UaServer = require("node-opcua").OPCUAServer;\nconst server = new UaServer({ userManager: { isValidUser: checkUser } });\nserver.start();',
      ],
      [
        "commonjs-destructure",
        'const { OPCUAServer: UaServer } = require("node-opcua");\nconst server = new UaServer({ userManager: { isValidUser() { return true; } } });\nserver.start();',
      ],
      [
        "commonjs-receiver",
        'const opcua = require("node-opcua");\nconst server = new opcua.OPCUAServer({ userManager: security.userManager });\nserver.start();',
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
        "untrusted-opcua-username-identity-token",
      );
      expect(record.frameworkModel?.sink.kind).toBe(
        "vulnerable-node-opcua-username-token-missing-nonce-binding",
      );
      expect(record.frameworkModel?.sink.cweIds).toEqual(["CWE-347"]);
      expect(record.frameworkModel?.propagators[0]?.symbol).toBe(
        "node-opcua@2.165.2:manifest-exact:username-token-missing-nonce-binding",
      );
    }
  });

  test("uses the published vulnerable artifacts and first repaired release", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(root, "affected-2-164", configuredServer, {
        declaration: "2.164.0",
      }),
      writeCase(root, "affected-2-165-0", configuredServer, {
        declaration: "2.165.0",
      }),
      writeCase(root, "affected-2-165-1", configuredServer, {
        declaration: "2.165.1",
      }),
      writeCase(root, "affected-2-165-2", configuredServer, {
        declaration: "2.165.2",
      }),
      writeCase(root, "repaired-2-166", configuredServer, {
        declaration: "2.166.0",
      }),
      writeCase(root, "later", configuredServer, { declaration: "2.168.0" }),
    ]);
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(
      [
        "affected-2-164/src/server.mjs",
        "affected-2-165-0/src/server.mjs",
        "affected-2-165-1/src/server.mjs",
        "affected-2-165-2/src/server.mjs",
      ].sort(),
    );
  });

  test("requires a usable user manager and an encrypted username-token policy", async () => {
    const root = await repository();
    const cases = [
      ["configured", configuredServer, true],
      [
        "explicit-encrypted-policy",
        'import { OPCUAServer, SecurityPolicy } from "node-opcua";\nconst server = new OPCUAServer({ userManager: security.userManager, securityPolicies: [SecurityPolicy.Basic256Sha256] });\nserver.start();',
        true,
      ],
      [
        "endpoint-default-policy",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ userManager: security.userManager, endpoints: [{ port: 4840 }] });\nserver.start();',
        true,
      ],
      [
        "no-manager",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ port: 4840 });\nserver.start();',
        false,
      ],
      [
        "null-manager",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ userManager: null });\nserver.start();',
        false,
      ],
      [
        "empty-manager",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ userManager: {} });\nserver.start();',
        false,
      ],
      [
        "certificate-only-manager",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ userManager: { isValidUserCertificate: checkCertificate } });\nserver.start();',
        false,
      ],
      [
        "none-only-policy",
        'import { OPCUAServer, SecurityPolicy } from "node-opcua";\nconst server = new OPCUAServer({ userManager: security.userManager, securityPolicies: [SecurityPolicy.None] });\nserver.start();',
        false,
      ],
      [
        "none-only-endpoint",
        'import { OPCUAServer, SecurityPolicy } from "node-opcua";\nconst server = new OPCUAServer({ userManager: security.userManager, endpoints: [{ securityPolicies: [SecurityPolicy.None] }] });\nserver.start();',
        false,
      ],
      [
        "dynamic-policy",
        'import { OPCUAServer } from "node-opcua";\nconst server = new OPCUAServer({ userManager: security.userManager, securityPolicies });\nserver.start();',
        false,
      ],
    ] as const;
    await Promise.all(cases.map(([id, source]) => writeCase(root, id, source)));
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(
      cases
        .filter(([, , expected]) => expected)
        .map(([id]) => `${id}/src/server.mjs`)
        .sort(),
    );
  });

  test("preserves a configured exported server through a relative import", async () => {
    const root = await repository();
    await writeCase(
      root,
      "cross-file",
      'import { OPCUAServer as UaServer } from "node-opcua";\nconst manager = { isValidUser: checkUser };\nexport const server = new UaServer({ userManager: manager });',
    );
    await writeFile(
      join(root, "cross-file", "src", "main.mjs"),
      'import { server as industrialServer } from "./server.mjs";\nawait industrialServer.initialize();\nawait industrialServer.start();',
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.scope).toBe("cross-file");
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "untrusted-opcua-username-identity-token",
      path: "cross-file/src/main.mjs",
      line: 3,
    });
    expect(found[0]?.frameworkModel?.sink).toEqual({
      kind: "vulnerable-node-opcua-username-token-missing-nonce-binding",
      path: "cross-file/src/server.mjs",
      line: 3,
      cweIds: ["CWE-347"],
    });
    expect(
      found[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(["relative-module-import", "node-opcua-runtime-dependency"]);
  });

  test("requires exact production or fresh npm v2/v3 dependency proof", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(root, "lock-v2", configuredServer, {
        declaration: "^2.160.0",
        lock: true,
        lockfileVersion: 2,
      }),
      writeCase(root, "lock-v3", configuredServer, {
        declaration: "^2.160.0",
        lock: true,
      }),
      writeCase(root, "range-without-lock", configuredServer, {
        declaration: "^2.160.0",
      }),
      writeCase(root, "development-only", configuredServer, {
        section: "devDependencies",
      }),
      writeCase(root, "wrong-package", configuredServer, {
        packageName: "node-opcua-client",
      }),
      writeCase(root, "legacy-lock", configuredServer, {
        declaration: "^2.160.0",
        lock: true,
        lockfileVersion: 1,
      }),
      writeCase(root, "fixed-lock", configuredServer, {
        declaration: "^2.160.0",
        lockedVersion: "2.166.0",
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
      "lock-resolved-vulnerable-node-opcua-username-token-missing-nonce-binding",
    );
  });

  test("rejects inert, replaced, shadowed, and test-only server shapes", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "unstarted",
        configuredServer.replace("server.start();", ""),
      ),
      writeCase(
        root,
        "client-only",
        'import { OPCUAClient } from "node-opcua";\nconst client = OPCUAClient.create({});\nclient.connect("opc.tcp://example:4840");',
      ),
      writeCase(
        root,
        "reassigned-binding",
        configuredServer.replace(
          "const userManager",
          "OPCUAServer = LocalServer;\nconst userManager",
        ),
      ),
      writeCase(
        root,
        "reassigned-instance",
        configuredServer
          .replace("const server", "let server")
          .replace("server.start();", "server = localServer;\nserver.start();"),
      ),
      writeCase(
        root,
        "replaced-start",
        configuredServer.replace(
          "server.start();",
          "server.start = localStart;\nserver.start();",
        ),
      ),
      writeCase(
        root,
        "shadowed-binding",
        'import { OPCUAServer } from "node-opcua";\nexport function launch(OPCUAServer) {\n const server = new OPCUAServer({ userManager: security.userManager });\n server.start();\n}',
      ),
      writeCase(root, "test-path", configuredServer, {
        path: "test/server.mjs",
      }),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("keeps the benchmark pair source-identical and under perfect gates", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-opcua-server-replayable-username-token",
    );
    const repaired = join(
      benchmarkRoot,
      "fixtures",
      "node-opcua-server-nonce-bound-username-token",
    );
    const found = records(await buildResidualRiskInventory(vulnerable));
    expect(found).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(repaired))).toEqual([]);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "untrusted-opcua-username-identity-token",
      path: "src/server.mjs",
      line: 11,
    });
    expect(found[0]?.frameworkModel?.sink).toEqual({
      kind: "vulnerable-node-opcua-username-token-missing-nonce-binding",
      path: "src/server.mjs",
      line: 8,
      cweIds: ["CWE-347"],
    });
    for (const path of ["src/server.mjs", "witness.mjs"]) {
      expect(await readFile(join(vulnerable, path), "utf8")).toBe(
        await readFile(join(repaired, path), "utf8"),
      );
    }
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-opcua-username-token-nonce-bypass-manifest.json",
        ),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{ id: string; expected: unknown[] }>;
    };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-opcua-server-replayable-username-token",
      "node-opcua-server-nonce-bound-username-token",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
  });

  test("teaches replay, forged-empty, version, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain(
      "node-opcua-server-username-token-nonce-bypass rows",
    );
    expect(prompt).toContain("GHSA-mq36-523m-x7vv");
    expect(prompt).toContain("2.165.2");
    expect(prompt).toContain("trailing session nonce");
    expect(prompt).toContain("CWE-347");
  });
});
