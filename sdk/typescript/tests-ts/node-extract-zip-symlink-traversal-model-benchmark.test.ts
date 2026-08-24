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
      (record) =>
        record.frameworkModel?.id === "node-http-extract-zip-symlink-traversal",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-extract-zip-"));
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
        "extract-zip": options.version ?? "2.0.1",
      },
    }),
  );
  await writeFile(join(directory, "server.mjs"), source);
}

describe("extract-zip symlink-target traversal framework model", () => {
  test("supports every official callable binding through 2.0.1", async () => {
    const root = await repository();
    await writeCase(
      root,
      "default",
      'import extract from "extract-zip";\nexport function route(req) { return extract(req.file.path, { dir: "/srv/plugins" }); }\n',
    );
    await writeCase(
      root,
      "import-equals",
      'import extract = require("extract-zip");\nexport function route(req) { return extract(req.body.archive, { dir: "/srv/plugins" }); }\n',
    );
    await writeCase(
      root,
      "commonjs",
      'const extract = require("extract-zip");\nexports.route = function route(req) { return extract(req.files.archive.path, { dir: "/srv/plugins" }); };\n',
      { version: "1.7.0" },
    );
    await writeCase(
      root,
      "direct-require",
      'exports.route = function route(req) { return require("extract-zip")(req.query.archive, { dir: "/srv/plugins" }); };\n',
    );
    await writeCase(
      root,
      "future-repair",
      'import extract from "extract-zip";\nexport function route(req) { return extract(req.file.path, { dir: "/srv/plugins" }); }\n',
      { version: "2.0.2" },
    );
    await writeCase(
      root,
      "development-only",
      'import extract from "extract-zip";\nexport function route(req) { return extract(req.file.path, { dir: "/srv/plugins" }); }\n',
      { section: "devDependencies" },
    );

    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "commonjs/server.mjs",
      "default/server.mjs",
      "direct-require/server.mjs",
      "import-equals/server.mjs",
    ]);
    expect(
      found.every(
        (record) =>
          record.frameworkModel?.sink.kind ===
            "vulnerable-extract-zip-symlink-traversal" &&
          record.frameworkModel.sink.cweIds[0] === "CWE-22",
      ),
    ).toBeTrue();
  });

  test("requires archive flow, destination options, and an unshadowed binding", async () => {
    const root = await repository();
    await writeCase(
      root,
      "negative",
      [
        'import extract from "extract-zip";',
        'import other from "other-extractor";',
        "export function route(request) {",
        '  extract("/srv/uploads/fixed.zip", { dir: request.body.dir });',
        "  extract(request.file.path);",
        '  other(request.file.path, { dir: "/srv/plugins" });',
        "  extract = other;",
        '  extract(request.file.path, { dir: "/srv/plugins" });',
        "}",
        'export function shadow(extract, request) { return extract(request.file.path, { dir: "/srv/plugins" }); }',
        "",
      ].join("\n"),
    );

    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("recognizes an exact pre-extraction symlink rejection callback", async () => {
    const root = await repository();
    await writeCase(
      root,
      "guarded",
      [
        'import extract from "extract-zip";',
        "export function route(request) {",
        "  return extract(request.file.path, {",
        '    dir: "/srv/plugins",',
        "    onEntry: (entry) => {",
        "      const mode = (entry.externalFileAttributes >>> 16) & 0o170000;",
        '      if (mode === 0o120000) throw new Error("links rejected");',
        "    },",
        "  });",
        "}",
        "",
      ].join("\n"),
    );
    await writeCase(
      root,
      "observe-only",
      [
        'import extract from "extract-zip";',
        "export function route(request) {",
        "  return extract(request.file.path, {",
        '    dir: "/srv/plugins",',
        "    onEntry: (entry) => {",
        "      const mode = (entry.externalFileAttributes >>> 16) & 0o170000;",
        "      if (mode === 0o120000) return entry.fileName;",
        "    },",
        "  });",
        "}",
        "",
      ].join("\n"),
    );

    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("observe-only/server.mjs");
  });

  test("requires a fresh declaration-consistent npm lock resolution", async () => {
    const root = await repository();
    const valid = join(root, "valid");
    await mkdir(valid);
    await writeFile(
      join(valid, "package.json"),
      JSON.stringify({
        name: "valid",
        dependencies: { "extract-zip": "^2.0.0" },
      }),
    );
    await writeFile(
      join(valid, "package-lock.json"),
      JSON.stringify({
        name: "valid",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "extract-zip": "^2.0.0" } },
          "node_modules/extract-zip": { version: "2.0.1" },
        },
      }),
    );
    await writeFile(
      join(valid, "server.mjs"),
      'import extract from "extract-zip";\nexport function route(req) { return extract(req.file.path, { dir: "/srv/plugins" }); }\n',
    );
    await writeCase(
      root,
      "unlocked",
      'import extract from "extract-zip";\nexport function route(req) { return extract(req.file.path, { dir: "/srv/plugins" }); }\n',
      { version: "^2.0.0" },
    );

    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-extract-zip-symlink-traversal",
    );
  });

  test("preserves a cross-file wrapper and gives exact impact guidance", async () => {
    const root = await repository();
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({
        name: "wrapper",
        dependencies: { "extract-zip": "2.0.1" },
      }),
    );
    await writeFile(
      join(root, "storage.mjs"),
      'import extract from "extract-zip";\nexport function install(path) { return extract(path, { dir: "/srv/plugins" }); }\n',
    );
    await writeFile(
      join(root, "server.mjs"),
      'import { install } from "./storage.mjs";\nexport function route(req) { return install(req.file.path); }\n',
    );

    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { path: "server.mjs", line: 2 },
      sink: {
        path: "storage.mjs",
        line: 2,
        kind: "vulnerable-extract-zip-symlink-traversal",
        cweIds: ["CWE-22"],
      },
    });
    expect(found[0]?.frameworkModel?.propagators).toHaveLength(3);

    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-extract-zip-symlink-traversal rows");
    expect(prompt).toContain("do not invent the audit service's unpublished");
    expect(prompt).toContain("Member-name containment");
    expect(prompt).toContain("concrete disclosure or integrity path");
  });

  test("keeps a strict topology-identical benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-extract-zip-symlink-traversal-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{ id: string; expected: unknown[] }>;
    };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-extract-zip-symlink-traversal",
      "node-multi-hop-safe-extract-zip",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 1 || value === 0,
      ),
    ).toBeTrue();

    const vulnerable = records(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-extract-zip-symlink-traversal",
        ),
      ),
    );
    const safe = records(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-safe-extract-zip"),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      source: { path: "src/server.js", line: 7 },
      sink: {
        path: "src/storage.js",
        line: 4,
        kind: "vulnerable-extract-zip-symlink-traversal",
        cweIds: ["CWE-22"],
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toHaveLength(9);
    expect(safe).toEqual([]);
  });
});
