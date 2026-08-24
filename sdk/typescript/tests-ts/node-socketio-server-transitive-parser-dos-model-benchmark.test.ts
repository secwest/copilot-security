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
        record.frameworkModel?.id ===
        "node-socketio-server-transitive-parser-dos",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-socketio-server-dos-"),
  );
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
    childVersion?: string;
    childDeclaration?: string;
    parentVersion?: string;
    lockedParentVersion?: string;
    packageName?: string;
    section?: "dependencies" | "devDependencies";
    rootDeclaration?: string;
    lockfileVersion?: number;
    lock?: boolean;
    path?: string;
  } = {},
): Promise<void> {
  const directory = join(root, id);
  await mkdir(join(directory, "src"), { recursive: true });
  const packageName = options.packageName ?? "socket.io";
  const parentVersion = options.parentVersion ?? "4.8.3";
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({
      name: id,
      private: true,
      [options.section ?? "dependencies"]: { [packageName]: parentVersion },
    }),
  );
  if (options.lock !== false) {
    await writeFile(
      join(directory, "package-lock.json"),
      JSON.stringify({
        name: id,
        lockfileVersion: options.lockfileVersion ?? 3,
        packages: {
          "": {
            dependencies: {
              [packageName]: options.rootDeclaration ?? parentVersion,
            },
          },
          "node_modules/socket.io": {
            version: options.lockedParentVersion ?? parentVersion,
            dependencies: {
              "socket.io-parser": options.childDeclaration ?? "~4.2.4",
            },
          },
          "node_modules/socket.io-parser": {
            version: options.childVersion ?? "4.2.6",
          },
        },
      }),
    );
  }
  const sourcePath = join(directory, options.path ?? "src/server.mjs");
  await mkdir(join(sourcePath, ".."), { recursive: true });
  await writeFile(sourcePath, source);
}

describe("Socket.IO server transitive parser denial-of-service model", () => {
  test("resolves official Server bindings and real network exposure", async () => {
    const root = await repository();
    const cases = [
      [
        "named-http",
        'import { createServer } from "node:http";\nimport { Server as SocketServer } from "socket.io";\nconst httpServer = createServer();\nconst io = new SocketServer(httpServer, { transports: ["websocket"] });\nhttpServer.listen(3000);',
      ],
      [
        "namespace-port",
        'import * as socketIo from "socket.io";\nconst io = new socketIo.Server(3000);',
      ],
      [
        "typescript-attach",
        'import socketIo = require("socket.io");\nconst httpServer = makeServer();\nconst io = new socketIo.Server();\nio.attach(httpServer, { path: "/events" });\nhttpServer.listen(3000);',
      ],
      [
        "commonjs-member",
        'const SocketServer = require("socket.io").Server;\nconst io = new SocketServer({ transports: ["websocket"] });\nio.listen(3000);',
      ],
      [
        "commonjs-destructure",
        'const { Server: SocketServer } = require("socket.io");\nconst fastify = makeFastify();\nconst io = new SocketServer(fastify.server);\nfastify.listen({ port: 3000 });',
      ],
      [
        "commonjs-callable",
        'const socketIo = require("socket.io");\nconst httpServer = makeServer();\nconst io = socketIo(httpServer, { path: "/events" });\nhttpServer.listen(3000);',
      ],
      [
        "direct-commonjs-callable",
        'const io = require("socket.io")(3000, { transports: ["websocket"] });',
      ],
    ] as const;
    await Promise.all(cases.map(([id, source]) => writeCase(root, id, source)));
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path).sort()).toEqual(
      cases.map(([id]) => `${id}/src/server.mjs`).sort(),
    );
    for (const record of found) {
      expect(record.frameworkModel?.source.kind).toBe(
        "untrusted-socketio-network-packet",
      );
      expect(record.frameworkModel?.sink.kind).toBe(
        "lock-resolved-transitive-vulnerable-socketio-server-parser-dos",
      );
      expect(record.frameworkModel?.sink.cweIds).toEqual([
        "CWE-400",
        "CWE-20",
        "CWE-754",
      ]);
      expect(
        record.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toEqual([
        "socketio-server-runtime-dependency",
        "socketio-parser-transitive-runtime-dependency",
      ]);
      expect(record.frameworkModel?.propagators.at(-1)?.symbol).toBe(
        "socket.io-parser@4.2.6:npm-lockfile:~4.2.4:zero-attachment-buffer-retention",
      );
    }
  });

  test("uses the installed transitive child rather than guessing from the parent", async () => {
    const root = await repository();
    const source =
      'import { Server } from "socket.io";\nconst io = new Server(3000);';
    await Promise.all([
      writeCase(root, "vulnerable-child", source, { childVersion: "4.2.6" }),
      writeCase(root, "repaired-child", source, { childVersion: "4.2.7" }),
      writeCase(root, "v3-affected", source, {
        childDeclaration: "~3.4.0",
        childVersion: "3.4.4",
      }),
      writeCase(root, "v3-repaired", source, {
        childDeclaration: "~3.4.0",
        childVersion: "3.4.5",
      }),
      writeCase(
        root,
        "v2-callable-affected",
        'const socketIo = require("socket.io");\nconst io = socketIo(3000);',
        {
          parentVersion: "2.5.1",
          childDeclaration: "~3.4.0",
          childVersion: "3.4.4",
        },
      ),
      writeCase(
        root,
        "v2-callable-repaired",
        'const socketIo = require("socket.io");\nconst io = socketIo(3000);',
        {
          parentVersion: "2.5.1",
          childDeclaration: "~3.4.0",
          childVersion: "3.4.5",
        },
      ),
    ]);
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(
      [
        "v3-affected/src/server.mjs",
        "v2-callable-affected/src/server.mjs",
        "vulnerable-child/src/server.mjs",
      ].sort(),
    );
  });

  test("supports npm v2/v3, shrinkwrap precedence, and nested child installs", async () => {
    const root = await repository();
    const source =
      'import { Server } from "socket.io";\nconst io = new Server(3000);';
    await writeCase(root, "lock-v2", source, { lockfileVersion: 2 });
    await writeCase(root, "valid-shrinkwrap", source);
    await writeFile(
      join(root, "valid-shrinkwrap", "npm-shrinkwrap.json"),
      await readFile(join(root, "valid-shrinkwrap", "package-lock.json")),
    );
    await writeCase(root, "invalid-higher-precedence", source);
    await writeFile(
      join(root, "invalid-higher-precedence", "npm-shrinkwrap.json"),
      JSON.stringify({ lockfileVersion: 1, dependencies: {} }),
    );
    await writeCase(root, "nested-child", source);
    const nestedLockPath = join(root, "nested-child", "package-lock.json");
    const nestedLock = JSON.parse(await readFile(nestedLockPath, "utf8")) as {
      packages: Record<string, unknown>;
    };
    nestedLock.packages[
      "node_modules/socket.io/node_modules/socket.io-parser"
    ] = nestedLock.packages["node_modules/socket.io-parser"];
    delete nestedLock.packages["node_modules/socket.io-parser"];
    await writeFile(nestedLockPath, JSON.stringify(nestedLock));
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(
      [
        "lock-v2/src/server.mjs",
        "nested-child/src/server.mjs",
        "valid-shrinkwrap/src/server.mjs",
      ].sort(),
    );
  });

  test("rejects ambiguous parser selection and servers without a listener", async () => {
    const root = await repository();
    const cases = [
      [
        "custom-parser",
        'import { Server } from "socket.io";\nconst io = new Server(3000, { parser: safeParser });',
      ],
      [
        "dynamic-options",
        'import { Server } from "socket.io";\nconst io = new Server(3000, options);',
      ],
      [
        "spread-options",
        'import { Server } from "socket.io";\nconst io = new Server(3000, { ...options, path: "/events" });',
      ],
      [
        "unexposed",
        'import { Server } from "socket.io";\nconst io = new Server();',
      ],
      [
        "target-not-listening",
        'import { Server } from "socket.io";\nconst httpServer = makeServer();\nconst io = new Server(httpServer);',
      ],
      [
        "attach-not-listening",
        'import { Server } from "socket.io";\nconst httpServer = makeServer();\nconst io = new Server();\nio.attach(httpServer);',
      ],
      [
        "reassigned-listener-target",
        'import { Server } from "socket.io";\nlet httpServer = makeServer();\nconst io = new Server(httpServer);\nhttpServer = anotherServer;\nhttpServer.listen(3000);',
      ],
    ] as const;
    await Promise.all(cases.map(([id, source]) => writeCase(root, id, source)));
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("rejects inconsistent graphs, unsupported evidence, replacement, and tests", async () => {
    const root = await repository();
    const source =
      'import { Server } from "socket.io";\nconst io = new Server(3000);';
    await Promise.all([
      writeCase(root, "no-lock", source, { lock: false }),
      writeCase(root, "legacy-lock", source, { lockfileVersion: 1 }),
      writeCase(root, "stale-root", source, { rootDeclaration: "4.8.2" }),
      writeCase(root, "stale-parent", source, { lockedParentVersion: "4.8.2" }),
      writeCase(root, "child-outside-range", source, { childVersion: "4.3.0" }),
      writeCase(root, "wrong-package", source, {
        packageName: "socket.io-client",
      }),
      writeCase(root, "development-only", source, {
        section: "devDependencies",
      }),
      writeCase(
        root,
        "reassigned-binding",
        'import { Server } from "socket.io";\nServer = LocalServer;\nconst io = new Server(3000);',
      ),
      writeCase(
        root,
        "replaced-member",
        'import * as socketIo from "socket.io";\nsocketIo.Server = LocalServer;\nconst io = new socketIo.Server(3000);',
      ),
      writeCase(
        root,
        "reassigned-instance",
        'import { Server } from "socket.io";\nlet io = new Server();\nio = localServer;\nio.listen(3000);',
      ),
      writeCase(
        root,
        "replaced-parser",
        'import { Server } from "socket.io";\nconst io = new Server();\nio._parser = safeParser;\nio.listen(3000);',
      ),
      writeCase(root, "test-path", source, { path: "test/server.mjs" }),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("keeps the package-backed pair parent- and source-identical", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-socketio-server-transitive-parser-dos",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-socketio-server-transitive-patched-parser",
    );
    const found = records(await buildResidualRiskInventory(vulnerable));
    expect(found).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "untrusted-socketio-network-packet",
      path: "src/server.mjs",
      line: 6,
    });
    expect(found[0]?.frameworkModel?.sink).toEqual({
      kind: "lock-resolved-transitive-vulnerable-socketio-server-parser-dos",
      path: "src/server.mjs",
      line: 5,
      cweIds: ["CWE-400", "CWE-20", "CWE-754"],
    });
    expect(
      found[0]?.frameworkModel?.propagators.map(({ symbol }) => symbol),
    ).toEqual([
      "socket.io@4.8.3:manifest-exact:server-network-parser-exposure",
      "socket.io-parser@4.2.6:npm-lockfile:~4.2.4:zero-attachment-buffer-retention",
    ]);
    for (const path of ["package.json", "src/server.mjs"]) {
      expect(await readFile(join(vulnerable, path), "utf8")).toBe(
        await readFile(join(patched, path), "utf8"),
      );
    }
    const vulnerableLock = JSON.parse(
      await readFile(join(vulnerable, "package-lock.json"), "utf8"),
    ) as {
      packages: Record<string, { version?: string; dependencies?: object }>;
    };
    const patchedLock = JSON.parse(
      await readFile(join(patched, "package-lock.json"), "utf8"),
    ) as {
      packages: Record<string, { version?: string; dependencies?: object }>;
    };
    expect(vulnerableLock.packages["node_modules/socket.io"]?.version).toBe(
      "4.8.3",
    );
    expect(patchedLock.packages["node_modules/socket.io"]?.version).toBe(
      "4.8.3",
    );
    expect(
      vulnerableLock.packages["node_modules/socket.io"]?.dependencies,
    ).toEqual(patchedLock.packages["node_modules/socket.io"]?.dependencies);
    expect(
      vulnerableLock.packages["node_modules/socket.io-parser"]?.version,
    ).toBe("4.2.6");
    expect(patchedLock.packages["node_modules/socket.io-parser"]?.version).toBe(
      "4.2.7",
    );
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-socketio-server-transitive-parser-dos-manifest.json",
        ),
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
      "node-socketio-server-transitive-parser-dos",
      "node-socketio-server-transitive-patched-parser",
    ]);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(3);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.findingsPaths).toHaveLength(3);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
  });

  test("teaches transitive proof, wire protocol, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-socketio-server-transitive-parser-dos rows");
    expect(prompt).toContain("same socket.io 4.8.x declaration");
    expect(prompt).toContain('Socket.IO packet 50-["evt"]');
    expect(prompt).toContain("Engine.IO transport");
    expect(prompt).toContain("CWE-20/CWE-754 only");
  });
});
