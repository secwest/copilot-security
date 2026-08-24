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
        record.frameworkModel?.id === "node-http-tar-decompression-dos",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-node-tar-decompression-"),
  );
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
    packageName?: string;
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
        [options.packageName ?? "tar"]: options.version ?? "7.5.18",
      },
    }),
  );
  await writeFile(join(directory, "server.mjs"), source);
}

describe("node-tar decompression DoS framework model", () => {
  test("supports official list, extract, parser, and unpack bindings", async () => {
    const root = await repository();
    const cases = [
      'import * as tar from "tar";\ntar.t({ file: req.file.path });',
      'import tar from "tar";\ntar.list({ file: req.file.path });',
      'import tar = require("tar");\ntar.x({ file: req.file.path });',
      'import { extract as unpack } from "tar";\nunpack({ file: req.file.path });',
      'import { Parse as Parser } from "tar";\nrequest.pipe(new Parser());',
      'const tar = require("tar");\ntar.list({ file: req.file.path });',
      'const { Unpack: Receiver } = require("tar");\nrequest.pipe(new Receiver());',
      'require("tar").extract({ file: req.file.path });',
    ];
    await Promise.all(
      cases.map((source, index) => writeCase(root, `case-${index}`, source)),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(cases.length);
    expect(
      found.every(
        (record) =>
          record.frameworkModel?.sink.cweIds.join(",") === "CWE-770" &&
          record.frameworkModel.sink.kind.includes(
            "vulnerable-node-tar-unbounded-decompression-",
          ),
      ),
    ).toBeTrue();
    expect(
      found.filter((record) =>
        record.frameworkModel?.sink.kind.endsWith("-list"),
      ),
    ).toHaveLength(3);
    expect(
      found.filter((record) =>
        record.frameworkModel?.sink.kind.endsWith("-extract"),
      ),
    ).toHaveLength(4);
    expect(
      found.filter((record) =>
        record.frameworkModel?.sink.kind.endsWith("-parse"),
      ),
    ).toHaveLength(1);
  });

  test("requires remote compressed-archive reachability and a consuming API", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "fixed",
        'import * as tar from "tar";\ntar.t({ file: "local.tgz" });',
      ),
      writeCase(
        root,
        "package-only",
        'import * as tar from "tar";\nconsole.log(tar);',
      ),
      writeCase(
        root,
        "create",
        'import * as tar from "tar";\ntar.c({ file: req.file.path }, ["payload"]);',
      ),
      writeCase(
        root,
        "parser-without-new",
        'import { Parse } from "tar";\nrequest.pipe(Parse());',
      ),
      writeCase(
        root,
        "max-read-size",
        'import * as tar from "tar";\ntar.x({ file: req.file.path, maxReadSize: 1024 });',
      ),
      writeCase(
        root,
        "sync-list",
        'import * as tar from "tar";\ntar.t({ file: req.file.path, sync: true });',
      ),
      writeCase(
        root,
        "dynamic-options",
        'import * as tar from "tar";\ntar.list(req.body.tarOptions);',
      ),
      writeCase(
        root,
        "stream",
        'import * as tar from "tar";\nrequest.pipe(tar.extract({ cwd: uploadRoot }));',
      ),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "dynamic-options/server.mjs",
      "max-read-size/server.mjs",
      "stream/server.mjs",
      "sync-list/server.mjs",
    ]);
    expect(
      found.find(({ path }) => path === "stream/server.mjs")?.frameworkModel
        ?.source.kind,
    ).toBe("http-request-compressed-archive-stream");
  });

  test("rejects reassigned, replaced, and wrapper-shadowed official bindings", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "stable",
        'import * as tar from "tar";\ntar.list({ file: req.file.path });',
      ),
      writeCase(
        root,
        "reassigned",
        'import * as tar from "tar";\ntar = fake;\ntar.list({ file: req.file.path });',
      ),
      writeCase(
        root,
        "replaced-member",
        'import * as tar from "tar";\ntar.list = fake;\ntar.list({ file: req.file.path });',
      ),
      writeCase(
        root,
        "shadowed",
        'import * as tar from "tar";\nexport function inspect(tar, req) { return tar.list({ file: req.file.path }); }',
      ),
      writeCase(
        root,
        "local-lookalike",
        "function list(options) { return options; }\nlist({ file: req.file.path });",
      ),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("stable/server.mjs");
  });

  test("requires exact or fresh declaration-consistent affected runtime proof", async () => {
    const root = await repository();
    const source =
      'import * as tar from "tar";\ntar.list({ file: req.file.path });';
    await Promise.all([
      writeCase(root, "last-vulnerable", source),
      writeCase(root, "older-major", source, { version: "6.2.1" }),
      writeCase(root, "patched", source, { version: "7.5.19" }),
      writeCase(root, "prerelease", source, { version: "7.5.19-beta.0" }),
      writeCase(root, "range-no-lock", source, { version: "^7.5.0" }),
      writeCase(root, "dev-only", source, { section: "devDependencies" }),
      writeCase(root, "wrong-package", source, { packageName: "node-tar" }),
      writeCase(root, "locked", source, { version: "^7.5.0" }),
      writeCase(root, "inconsistent-lock", source, { version: "^7.5.19" }),
      writeCase(root, "v1-lock", source, { version: "^7.5.0" }),
    ]);
    await writeFile(
      join(root, "locked", "package-lock.json"),
      JSON.stringify({
        name: "locked",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { tar: "^7.5.0" } },
          "node_modules/tar": { version: "7.5.18" },
        },
      }),
    );
    await writeFile(
      join(root, "inconsistent-lock", "package-lock.json"),
      JSON.stringify({
        name: "inconsistent-lock",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { tar: "^7.5.19" } },
          "node_modules/tar": { version: "7.5.18" },
        },
      }),
    );
    await writeFile(
      join(root, "v1-lock", "package-lock.json"),
      JSON.stringify({
        name: "v1-lock",
        lockfileVersion: 1,
        dependencies: { tar: { version: "7.5.18" } },
      }),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "last-vulnerable/server.mjs",
      "locked/server.mjs",
      "older-major/server.mjs",
    ]);
    const locked = found.find(({ path }) => path === "locked/server.mjs");
    expect(locked?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-node-tar-unbounded-decompression-list",
    );
    expect(locked?.frameworkModel?.propagators[0]?.symbol).toBe(
      "tar@7.5.18:npm-lockfile:unbounded-decompression-list",
    );
  });

  test("retains ineffective chunk limits and records stronger budget leads", async () => {
    const root = await repository();
    await writeCase(
      root,
      "limits",
      'import * as tar from "tar";\ntar.extract({ file: req.file.path, maxReadSize: 1024, maxDepth: 2, maxDecompressionRatio: 50 });',
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("decompression-ratio-or-output-budget");
  });

  test("keeps the benchmark pair strict and teaches operation-specific impact", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-tar-decompression-dos",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-tar-decompression",
    );
    const linkpathControl = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-tar-linkpath",
    );
    const vulnerableRecords = records(
      await buildResidualRiskInventory(vulnerable),
    );
    expect(vulnerableRecords).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(records(await buildResidualRiskInventory(linkpathControl))).toEqual(
      [],
    );
    expect(vulnerableRecords[0]?.frameworkModel?.source.line).toBe(7);
    expect(vulnerableRecords[0]?.frameworkModel?.sink.line).toBe(4);
    expect(
      vulnerableRecords[0]?.frameworkModel?.propagators.some(
        ({ symbol }) =>
          symbol === "tar@7.5.18:manifest-exact:unbounded-decompression-list",
      ),
    ).toBeTrue();
    for (const relative of [
      join("src", "server.js"),
      join("src", "gateway.js"),
      join("src", "service.js"),
      join("src", "storage.js"),
      "witness.mjs",
    ]) {
      expect(await readFile(join(vulnerable, relative), "utf8")).toBe(
        await readFile(join(patched, relative), "utf8"),
      );
    }
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-http-tar-decompression-dos rows");
    expect(prompt).toContain("maxDecompressionRatio of 1000");
    expect(prompt).toContain("For t/list/Parse");
    expect(prompt).toContain("for x/extract/Unpack");
    expect(prompt).toContain("Report CWE-770 availability impact only");
  });
});
