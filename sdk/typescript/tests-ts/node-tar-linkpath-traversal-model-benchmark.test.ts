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
        record.frameworkModel?.id === "node-http-tar-linkpath-traversal",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-node-tar-"));
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
        tar: options.version ?? "7.5.10",
      },
    }),
  );
  await writeFile(join(directory, "server.mjs"), source);
}

describe("node-tar linkpath traversal framework model", () => {
  test("supports official extraction bindings through 7.5.10", async () => {
    const root = await repository();
    const variants: Array<[string, string]> = [
      [
        "namespace",
        'import * as tar from "tar";\nexport function route(req) { return tar.x({ file: req.file.path, cwd: "/srv/imports" }); }\n',
      ],
      [
        "default",
        'import tar from "tar";\nexport function route(req) { return tar.extract({ file: req.file.path, cwd: "/srv/imports" }); }\n',
      ],
      [
        "import-equals",
        'import tar = require("tar");\nexport function route(req) { return tar.x({ file: req.file.path }); }\n',
      ],
      [
        "named",
        'import { extract as unpack } from "tar";\nexport function route(req) { return unpack({ file: req.file.path, cwd: "/srv/imports" }); }\n',
      ],
      [
        "commonjs",
        'const tar = require("tar");\nexports.route = function route(req) { return tar.x({ file: req.file.path }); };\n',
      ],
      [
        "destructured",
        'const { x: unpack } = require("tar");\nexports.route = function route(req) { return unpack({ file: req.file.path }); };\n',
      ],
      [
        "direct",
        'exports.route = function route(req) { return require("tar").extract({ file: req.file.path }); };\n',
      ],
    ];
    for (const [id, source] of variants) await writeCase(root, id, source);
    await writeCase(root, "patched", variants[0]?.[1] ?? "", {
      version: "7.5.11",
    });
    await writeCase(root, "development", variants[0]?.[1] ?? "", {
      section: "devDependencies",
    });

    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "commonjs/server.mjs",
      "default/server.mjs",
      "destructured/server.mjs",
      "direct/server.mjs",
      "import-equals/server.mjs",
      "named/server.mjs",
      "namespace/server.mjs",
    ]);
    expect(
      found.every(
        (record) =>
          record.frameworkModel?.sink.kind ===
            "vulnerable-node-tar-linkpath-traversal" &&
          record.frameworkModel.sink.cweIds.join(",") === "CWE-22,CWE-59",
      ),
    ).toBeTrue();
  });

  test("requires attacker-controlled extraction rather than package presence", async () => {
    const root = await repository();
    await writeCase(
      root,
      "fixed",
      'import * as tar from "tar";\nexport function route() { return tar.x({ file: "/srv/releases/app.tar", cwd: "/srv/imports" }); }\n',
    );
    await writeCase(
      root,
      "create",
      'import * as tar from "tar";\nexport function route(req) { return tar.create({ file: req.file.path }, ["dist"]); }\n',
    );
    await writeCase(
      root,
      "wrong-package",
      'import * as tar from "other-tar";\nexport function route(req) { return tar.x({ file: req.file.path }); }\n',
    );
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("credits only an exact filter that rejects both link entry types", async () => {
    const root = await repository();
    const base =
      'import * as tar from "tar";\nexport function route(req) { return tar.x({ file: req.file.path, cwd: "/srv/imports", FILTER }); }\n';
    await writeCase(
      root,
      "inequality-safe",
      base.replace(
        "FILTER",
        'filter: (_path, entry) => entry.type !== "Link" && entry.type !== "SymbolicLink"',
      ),
    );
    await writeCase(
      root,
      "branch-safe",
      base.replace(
        "FILTER",
        'filter: (_path, entry) => { if (entry.type === "Link" || entry.type === "SymbolicLink") return false; return true; }',
      ),
    );
    await writeCase(
      root,
      "collection-safe",
      base.replace(
        "FILTER",
        'filter: (_path, entry) => !["Link", "SymbolicLink"].includes(entry.type)',
      ),
    );
    await writeCase(
      root,
      "hardlink-only",
      base.replace("FILTER", 'filter: (_path, entry) => entry.type !== "Link"'),
    );
    await writeCase(
      root,
      "misleading-branch",
      base.replace(
        "FILTER",
        'filter: (_path, entry) => { if (entry.type === "Link") return false; if (entry.type === "SymbolicLink") return true; return false; }',
      ),
    );
    await writeCase(
      root,
      "misleading-collection",
      base.replace(
        "FILTER",
        'filter: (_path, entry) => { if (["Link", "SymbolicLink"].includes(entry.type)) return true; return false; }',
      ),
    );
    await writeCase(
      root,
      "preserve-false",
      base.replace("FILTER", "preservePaths: false"),
    );

    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "hardlink-only/server.mjs",
      "misleading-branch/server.mjs",
      "misleading-collection/server.mjs",
      "preserve-false/server.mjs",
    ]);
    expect(found[0]?.frameworkModel?.candidateControls[0]?.kind).toBe(
      "node-tar-link-entry-filter",
    );
    expect(found[1]?.frameworkModel?.candidateControls[0]?.kind).toBe(
      "node-tar-link-entry-filter",
    );
    expect(found[2]?.frameworkModel?.candidateControls[0]?.kind).toBe(
      "node-tar-link-entry-filter",
    );
    expect(found[3]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("supports request streams and rejects reassigned or shadowed bindings", async () => {
    const root = await repository();
    await writeCase(
      root,
      "stream",
      'import * as tar from "tar";\nexport function route(request) { return request.pipe(tar.x({ cwd: "/srv/imports" })); }\n',
    );
    await writeCase(
      root,
      "reassigned",
      'import * as tar from "tar";\ntar = replacement;\nexport function route(req) { return tar.x({ file: req.file.path }); }\n',
    );
    await writeCase(
      root,
      "shadowed",
      'import * as tar from "tar";\nexport function route(tar, req) { return tar.x({ file: req.file.path }); }\n',
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("stream/server.mjs");
    expect(found[0]?.frameworkModel?.source.kind).toBe(
      "http-request-archive-stream",
    );
  });

  test("requires fresh declaration-consistent npm lock proof", async () => {
    const root = await repository();
    for (const [id, resolvedVersion] of [
      ["vulnerable", "7.5.10"],
      ["patched", "7.5.11"],
    ] as const) {
      const directory = join(root, id);
      await mkdir(directory);
      await writeFile(
        join(directory, "package.json"),
        JSON.stringify({ name: id, dependencies: { tar: "^7.5.0" } }),
      );
      await writeFile(
        join(directory, "package-lock.json"),
        JSON.stringify({
          name: id,
          lockfileVersion: 3,
          packages: {
            "": { name: id, dependencies: { tar: "^7.5.0" } },
            "node_modules/tar": { version: resolvedVersion },
          },
        }),
      );
      await writeFile(
        join(directory, "server.mjs"),
        'import * as tar from "tar";\nexport function route(req) { return tar.x({ file: req.file.path }); }\n',
      );
    }
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("vulnerable/server.mjs");
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-node-tar-linkpath-traversal",
    );
  });

  test("keeps the benchmark pair strict and teaches exact impact", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-tar-linkpath-traversal",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-tar-linkpath",
    );
    const vulnerableRecords = records(
      await buildResidualRiskInventory(vulnerable),
    );
    const patchedRecords = records(await buildResidualRiskInventory(patched));
    expect(vulnerableRecords).toHaveLength(1);
    expect(patchedRecords).toEqual([]);
    expect(vulnerableRecords[0]?.frameworkModel?.source.line).toBe(7);
    expect(vulnerableRecords[0]?.frameworkModel?.sink.line).toBe(4);
    expect(vulnerableRecords[0]?.frameworkModel?.propagators).toHaveLength(9);
    expect(await readFile(join(vulnerable, "src", "server.js"), "utf8")).toBe(
      await readFile(join(patched, "src", "server.js"), "utf8"),
    );
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-http-tar-linkpath-traversal rows");
    expect(prompt).toContain("rejects both Link and SymbolicLink entries");
    expect(prompt).toContain(
      "before escalating to code execution, persistence, or privilege escalation",
    );
  });
});
