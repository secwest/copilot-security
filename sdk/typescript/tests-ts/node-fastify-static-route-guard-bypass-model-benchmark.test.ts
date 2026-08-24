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
    candidateControls: Array<{ kind: string; path: string; line: number }>;
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
        "node-http-fastify-static-route-guard-bypass",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-fastify-static-"),
  );
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
    version?: string;
    section?: "dependencies" | "devDependencies";
  } = {},
): Promise<void> {
  const directory = join(root, id);
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({
      name: id,
      private: true,
      [options.section ?? "dependencies"]: {
        "@fastify/static": options.version ?? "10.1.0",
        fastify: "5.12.1",
      },
    }),
  );
  await writeFile(join(directory, "server.mjs"), source);
}

const guardedEsm = [
  'import Fastify from "fastify";',
  'import fastifyStatic from "@fastify/static";',
  "const app = Fastify();",
  'app.all("/deep/*", async (_request, reply) => reply.code(401).send("Unauthorized"));',
  'app.register(fastifyStatic, { root: "/srv/public" });',
  "",
].join("\n");

describe("Fastify Static route-guard bypass framework model", () => {
  test("supports official callable bindings through 10.1.0", async () => {
    const root = await repository();
    await writeCase(root, "default", guardedEsm);
    await writeCase(
      root,
      "import-equals",
      [
        'import Fastify = require("fastify");',
        'import fastifyStatic = require("@fastify/static");',
        "const app = Fastify();",
        'app.all("/deep/*", (_request, reply) => reply.code(403).send("Forbidden"));',
        'app.register(fastifyStatic, { root: "/srv/public" });',
        "",
      ].join("\n"),
      { version: "9.7.0" },
    );
    await writeCase(
      root,
      "commonjs",
      [
        'const app = require("fastify")();',
        'app.all("/deep/*", (_request, reply) => reply.code(401).send("Unauthorized"));',
        'app.register(require("@fastify/static"), { root: "/srv/public" });',
        "",
      ].join("\n"),
    );
    await writeCase(root, "patched", guardedEsm, { version: "10.1.1" });
    await writeCase(root, "development", guardedEsm, {
      section: "devDependencies",
    });

    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "commonjs/server.mjs",
      "default/server.mjs",
      "import-equals/server.mjs",
    ]);
    expect(
      found.every(
        (record) =>
          record.frameworkModel?.sink.kind ===
            "vulnerable-fastify-static-route-guard-bypass" &&
          record.frameworkModel.sink.cweIds[0] === "CWE-22",
      ),
    ).toBeTrue();
  });

  test("requires a protected wildcard route on the same exact Fastify instance", async () => {
    const root = await repository();
    await writeCase(
      root,
      "unguarded",
      [
        'import Fastify from "fastify";',
        'import fastifyStatic from "@fastify/static";',
        "const app = Fastify();",
        'app.get("/deep/*", (_request, reply) => reply.sendFile("index.html"));',
        'app.register(fastifyStatic, { root: "/srv/public" });',
        "",
      ].join("\n"),
    );
    await writeCase(
      root,
      "wrong-instance",
      [
        'import Fastify from "fastify";',
        'import fastifyStatic from "@fastify/static";',
        "const app = Fastify();",
        "const other = Fastify();",
        'other.all("/deep/*", (_request, reply) => reply.code(401).send("Unauthorized"));',
        'app.register(fastifyStatic, { root: "/srv/public" });',
        "",
      ].join("\n"),
    );
    await writeCase(
      root,
      "lookalike",
      [
        'import fastifyStatic from "@fastify/static";',
        "const app = makeApplication();",
        'app.all("/deep/*", (_request, reply) => reply.code(401).send("Unauthorized"));',
        'app.register(fastifyStatic, { root: "/srv/public" });',
        "",
      ].join("\n"),
    );
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("rejects disabled catch-all serving and retains allowedPath for review", async () => {
    const root = await repository();
    await writeCase(
      root,
      "serve-disabled",
      guardedEsm.replace(
        '{ root: "/srv/public" }',
        '{ root: "/srv/public", serve: false }',
      ),
    );
    await writeCase(
      root,
      "wildcard-disabled",
      guardedEsm.replace(
        '{ root: "/srv/public" }',
        '{ root: "/srv/public", wildcard: false }',
      ),
    );
    await writeCase(
      root,
      "filtered",
      guardedEsm.replace(
        '{ root: "/srv/public" }',
        '{ root: "/srv/public", allowedPath: (pathName) => !pathName.startsWith("deep/") }',
      ),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("filtered/server.mjs");
    expect(found[0]?.frameworkModel?.candidateControls).toEqual([
      {
        kind: "fastify-static-allowed-path-filter",
        path: "filtered/server.mjs",
        line: 5,
      },
    ]);
  });

  test("supports route options and rejects reassigned or shadowed bindings", async () => {
    const root = await repository();
    await writeCase(
      root,
      "route-options",
      [
        'import Fastify from "fastify";',
        'import fastifyStatic from "@fastify/static";',
        "const app = Fastify();",
        'app.route({ method: "GET", url: "/deep/*", onRequest: authenticate, handler });',
        'app.register(fastifyStatic, { root: "/srv/public" });',
        "",
      ].join("\n"),
    );
    await writeCase(
      root,
      "reassigned",
      guardedEsm.replace(
        'app.register(fastifyStatic, { root: "/srv/public" });',
        'fastifyStatic = replacement;\napp.register(fastifyStatic, { root: "/srv/public" });',
      ),
    );
    await writeCase(
      root,
      "shadowed",
      [
        'import Fastify from "fastify";',
        'import fastifyStatic from "@fastify/static";',
        "const app = Fastify();",
        'app.all("/deep/*", (_request, reply) => reply.code(401).send("Unauthorized"));',
        'export function install(fastifyStatic) { app.register(fastifyStatic, { root: "/srv/public" }); }',
        "",
      ].join("\n"),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("route-options/server.mjs");
  });

  test("requires fresh declaration-consistent lock proof and teaches exact impact", async () => {
    const root = await repository();
    const valid = join(root, "valid");
    await mkdir(valid);
    await writeFile(
      join(valid, "package.json"),
      JSON.stringify({
        name: "valid",
        dependencies: { "@fastify/static": "^10.0.0", fastify: "5.12.1" },
      }),
    );
    await writeFile(
      join(valid, "package-lock.json"),
      JSON.stringify({
        name: "valid",
        lockfileVersion: 3,
        packages: {
          "": {
            dependencies: {
              "@fastify/static": "^10.0.0",
              fastify: "5.12.1",
            },
          },
          "node_modules/@fastify/static": { version: "10.1.0" },
          "node_modules/fastify": { version: "5.12.1" },
        },
      }),
    );
    await writeFile(join(valid, "server.mjs"), guardedEsm);
    await writeCase(root, "unlocked", guardedEsm, { version: "^10.0.0" });

    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: {
        kind: "protected-static-route-guard",
        path: "valid/server.mjs",
        line: 4,
      },
      sink: {
        kind: "lock-resolved-vulnerable-fastify-static-route-guard-bypass",
        path: "valid/server.mjs",
        line: 5,
        cweIds: ["CWE-22"],
      },
    });

    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-fastify-static-route-guard-bypass");
    expect(prompt).toContain("10.1.1 rejects decoded parent segments");
    expect(prompt).toContain(
      "vulnerable package and public static registration alone",
    );
    expect(prompt).toContain(
      "do not generalize this path to arbitrary filesystem traversal",
    );
  });

  test("keeps the source-identical vulnerable and repaired benchmark pair strict", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-fastify-static-route-guard-manifest.json"),
        "utf8",
      ),
    ) as { cases: Array<{ id: string; expected: unknown[] }> };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-fastify-static-route-guard-bypass",
      "node-patched-fastify-static-route-guard",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);

    const vulnerableRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-fastify-static-route-guard-bypass",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-patched-fastify-static-route-guard",
    );
    const vulnerableSource = await readFile(
      join(vulnerableRoot, "src", "server.js"),
      "utf8",
    );
    const repairedSource = await readFile(
      join(repairedRoot, "src", "server.js"),
      "utf8",
    );
    expect(vulnerableSource).toBe(repairedSource);

    const vulnerable = records(
      await buildResidualRiskInventory(vulnerableRoot),
    );
    const repaired = records(await buildResidualRiskInventory(repairedRoot));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      source: {
        kind: "protected-static-route-guard",
        path: "src/server.js",
        line: 5,
      },
      sink: {
        kind: "vulnerable-fastify-static-route-guard-bypass",
        path: "src/server.js",
        line: 8,
        cweIds: ["CWE-22"],
      },
    });
    expect(repaired).toEqual([]);
  });
});
