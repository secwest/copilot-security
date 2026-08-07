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
    source: { path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{ kind: string; path: string; line: number }>;
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
      (record) => record.frameworkModel?.id === "node-http-tmp-path-traversal",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-tmp-model-"));
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
        tmp: options.version ?? "0.2.5",
      },
    }),
  );
  await writeFile(join(directory, "server.mjs"), source);
}

describe("tmp path-traversal framework model", () => {
  test("supports official receiver and direct creator bindings below 0.2.6", async () => {
    const root = await repository();
    await writeCase(
      root,
      "default",
      'import tmp from "tmp";\nexport function route(req) { return tmp.fileSync({ prefix: req.query.name }); }\n',
    );
    await writeCase(
      root,
      "namespace",
      'import * as temporary from "tmp";\nexport function route(req) { return temporary.dir({ dir: req.body.dir }, done); }\n',
    );
    await writeCase(
      root,
      "named",
      'import { fileSync as create } from "tmp";\nexport function route(req) { return create({ postfix: req.params.name }); }\n',
    );
    await writeCase(
      root,
      "member",
      'const create = require("tmp").dirSync;\nexports.route = function route(req) { return create({ template: req.query.template }); };\n',
    );
    await writeCase(
      root,
      "commonjs",
      'const temporary = require("tmp");\nexports.route = function route(req) { return temporary.fileSync({ prefix: req.query.name }); };\n',
    );
    await writeCase(
      root,
      "destructured-commonjs",
      'const { dir: createDirectory } = require("tmp");\nexports.route = function route(req) { return createDirectory({ dir: req.body.dir }, done); };\n',
    );
    await writeCase(
      root,
      "import-equals",
      'import temporary = require("tmp");\nexport function route(req) { return temporary.file({ prefix: req.query.name }, done); }\n',
    );
    await writeCase(
      root,
      "patched",
      'import tmp from "tmp";\nexport function route(req) { return tmp.fileSync({ prefix: req.query.name }); }\n',
      { version: "0.2.6" },
    );
    await writeCase(
      root,
      "development",
      'import tmp from "tmp";\nexport function route(req) { return tmp.fileSync({ prefix: req.query.name }); }\n',
      { section: "devDependencies" },
    );

    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "commonjs/server.mjs",
      "default/server.mjs",
      "destructured-commonjs/server.mjs",
      "import-equals/server.mjs",
      "member/server.mjs",
      "named/server.mjs",
      "namespace/server.mjs",
    ]);
    expect(
      found.map((record) => record.frameworkModel?.sink.kind).sort(),
    ).toEqual([
      "vulnerable-tmp-dir-path-traversal",
      "vulnerable-tmp-dir-path-traversal",
      "vulnerable-tmp-dir-sync-path-traversal",
      "vulnerable-tmp-file-path-traversal",
      "vulnerable-tmp-file-sync-path-traversal",
      "vulnerable-tmp-file-sync-path-traversal",
      "vulnerable-tmp-file-sync-path-traversal",
    ]);
  });

  test("retains only path-shaping options and unresolved option spreads", async () => {
    const root = await repository();
    await writeCase(
      root,
      "options",
      [
        'import tmp from "tmp";',
        "export function route(req) {",
        "  tmp.fileSync({ prefix: req.query.prefix });",
        "  tmp.fileSync({ postfix: req.query.postfix });",
        "  tmp.dirSync({ template: req.query.template });",
        "  tmp.dirSync({ dir: req.query.dir });",
        "  tmp.fileSync({ keep: req.query.keep, mode: req.query.mode });",
        "  tmp.fileSync({ ...req.body, keep: true });",
        '  tmp.fileSync({ ...req.body, prefix: "p", postfix: ".tmp", template: "x-XXXXXX", dir: "safe" });',
        "}",
        "",
      ].join("\n"),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ line }) => line)).toEqual([3, 4, 5, 6, 8]);
  });

  test("rejects wrong APIs, packages, fixed values, reassignment, and shadowing", async () => {
    const root = await repository();
    await writeCase(
      root,
      "negative",
      [
        'import tmp from "tmp";',
        'import local from "temporary";',
        "tmp.tmpNameSync({ prefix: request.query.name });",
        'tmp.fileSync({ prefix: "fixed" });',
        "local.fileSync({ prefix: request.query.name });",
        "tmp.fileSync = local.fileSync;",
        "tmp.fileSync({ prefix: request.query.name });",
        "export function shadow(tmp, request) { return tmp.dirSync({ dir: request.query.dir }); }",
        "",
      ].join("\n"),
    );
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("requires a fresh declaration-consistent npm lock resolution", async () => {
    const root = await repository();
    const valid = join(root, "valid");
    await mkdir(valid);
    await writeFile(
      join(valid, "package.json"),
      JSON.stringify({ name: "valid", dependencies: { tmp: "^0.2.4" } }),
    );
    await writeFile(
      join(valid, "package-lock.json"),
      JSON.stringify({
        name: "valid",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { tmp: "^0.2.4" } },
          "node_modules/tmp": { version: "0.2.5" },
        },
      }),
    );
    await writeFile(
      join(valid, "server.mjs"),
      'import tmp from "tmp";\nexport function route(req) { return tmp.fileSync({ prefix: req.query.name }); }\n',
    );
    await writeCase(
      root,
      "unlocked",
      'import tmp from "tmp";\nexport function route(req) { return tmp.fileSync({ prefix: req.query.name }); }\n',
      { version: "^0.2.4" },
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-tmp-file-sync-path-traversal",
    );
  });

  test("preserves a typed cross-file wrapper path", async () => {
    const root = await repository();
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ name: "wrapper", dependencies: { tmp: "0.2.5" } }),
    );
    await writeFile(
      join(root, "storage.mjs"),
      'import tmp from "tmp";\nexport function create(prefix) { return tmp.fileSync({ prefix }); }\n',
    );
    await writeFile(
      join(root, "server.mjs"),
      'import { create } from "./storage.mjs";\nexport function route(req) { return create(req.query.prefix); }\n',
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { path: "server.mjs", line: 2 },
      sink: {
        path: "storage.mjs",
        line: 2,
        kind: "vulnerable-tmp-file-sync-path-traversal",
        cweIds: ["CWE-22"],
      },
    });
    expect(found[0]?.frameworkModel?.propagators.length).toBeGreaterThan(0);
  });

  test("retains basename as a candidate control and teaches exact impact bounds", async () => {
    const root = await repository();
    await writeCase(
      root,
      "control",
      'import tmp from "tmp";\nimport path from "node:path";\nexport function route(req) { return tmp.fileSync({ prefix: path.basename(req.query.name) }); }\n',
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "temporary-name-component-basename",
      path: "control/server.mjs",
      line: 3,
    });
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-tmp-path-traversal");
    expect(prompt).toContain("below 0.2.6");
    expect(prompt).toContain("sibling-prefix containment bypass");
    expect(prompt).toContain("exclusive creation");
  });

  test("retains an exact creator after dense unrelated calls", async () => {
    const root = await repository();
    await writeCase(
      root,
      "dense",
      [
        'import tmp from "tmp";',
        "export function route(req) {",
        ...Array.from({ length: 40 }, (_, index) => `  helper${index}();`),
        "  return tmp.fileSync({ prefix: req.query.prefix });",
        "}",
        "",
      ].join("\n"),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.line).toBe(43);
  });

  test("keeps the executable benchmark pair strict and topology complete", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-tmp-path-traversal-manifest.json"),
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
      "node-multi-hop-tmp-path-traversal",
      "node-multi-hop-patched-tmp",
    ]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);

    const vulnerable = records(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-tmp-path-traversal"),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      source: { path: "src/server.js", line: 8 },
      sink: {
        path: "src/storage.js",
        line: 5,
        kind: "vulnerable-tmp-file-sync-path-traversal",
        cweIds: ["CWE-22"],
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toHaveLength(9);
    expect(
      records(
        await buildResidualRiskInventory(
          join(benchmarkRoot, "fixtures", "node-multi-hop-patched-tmp"),
        ),
      ),
    ).toHaveLength(0);
  });
});
