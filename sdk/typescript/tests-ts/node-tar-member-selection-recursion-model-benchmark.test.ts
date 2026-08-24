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
        "node-http-tar-member-selection-recursion",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-node-tar-recursion-"),
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
        [options.packageName ?? "tar"]: options.version ?? "7.5.20",
      },
    }),
  );
  await writeFile(join(directory, "server.mjs"), source);
}

describe("node-tar member-selection recursion framework model", () => {
  test("supports official list and extract bindings through 7.5.20", async () => {
    const root = await repository();
    const cases = [
      'import * as tar from "tar";\ntar.t({ file: req.file.path }, ["manifest"]);',
      'import tar from "tar";\ntar.list({ file: req.file.path }, ["manifest"]);',
      'import tar = require("tar");\ntar.x({ file: req.file.path }, ["manifest"]);',
      'import { extract as unpack } from "tar";\nunpack({ file: req.file.path }, ["manifest"]);',
      'const tar = require("tar");\ntar.t({ file: req.file.path }, ["manifest"]);',
      'const { x: unpack } = require("tar");\nunpack({ file: req.file.path }, ["manifest"]);',
      'require("tar").list({ file: req.file.path }, ["manifest"]);',
    ];
    await Promise.all(
      cases.map((source, index) => writeCase(root, `case-${index}`, source)),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(cases.length);
    expect(
      found.every(
        (record) =>
          record.frameworkModel?.sink.kind ===
            "vulnerable-node-tar-member-selection-recursion" &&
          record.frameworkModel.sink.cweIds.join(",") === "CWE-674",
      ),
    ).toBeTrue();
  });

  test("requires remote archive flow and a non-empty member list", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "fixed",
        'import * as tar from "tar";\ntar.t({ file: "local.tar" }, ["manifest"]);',
      ),
      writeCase(
        root,
        "omitted",
        'import * as tar from "tar";\ntar.t({ file: req.file.path });',
      ),
      writeCase(
        root,
        "empty",
        'import * as tar from "tar";\ntar.t({ file: req.file.path }, []);',
      ),
      writeCase(
        root,
        "sync",
        'import * as tar from "tar";\ntar.t({ file: req.file.path, sync: true }, ["manifest"]);',
      ),
      writeCase(
        root,
        "create",
        'import * as tar from "tar";\ntar.c({ file: req.file.path }, ["manifest"]);',
      ),
      writeCase(
        root,
        "max-depth-is-not-a-control",
        'import * as tar from "tar";\ntar.x({ file: req.file.path, maxDepth: 1, maxReadSize: 1 }, ["manifest"]);',
      ),
      writeCase(
        root,
        "try-catch-is-not-a-control",
        'import * as tar from "tar";\ntry { await tar.t({ file: req.file.path }, ["manifest"]); } catch (error) { log(error); }',
      ),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "max-depth-is-not-a-control/server.mjs",
      "try-catch-is-not-a-control/server.mjs",
    ]);
  });

  test("supports streaming selection and rejects reassigned or shadowed bindings", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "stream",
        'import * as tar from "tar";\nrequest.pipe(tar.t(["manifest"]));',
      ),
      writeCase(
        root,
        "reassigned",
        'import * as tar from "tar";\ntar = fake;\ntar.t({ file: req.file.path }, ["manifest"]);',
      ),
      writeCase(
        root,
        "shadowed",
        'import * as tar from "tar";\nexport function inspect(tar, req) { return tar.t({ file: req.file.path }, ["manifest"]); }',
      ),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("stream/server.mjs");
    expect(found[0]?.frameworkModel?.source.kind).toBe(
      "http-request-archive-stream",
    );
  });

  test("requires exact or fresh declaration-consistent runtime proof", async () => {
    const root = await repository();
    const source =
      'import * as tar from "tar";\ntar.t({ file: req.file.path }, ["manifest"]);';
    await Promise.all([
      writeCase(root, "patched", source, { version: "7.5.21" }),
      writeCase(root, "range-no-lock", source, { version: "^7.5.0" }),
      writeCase(root, "dev-only", source, {
        section: "devDependencies",
      }),
      writeCase(root, "wrong-package", source, {
        packageName: "node-tar",
      }),
      writeCase(root, "locked", source, { version: "^7.5.0" }),
    ]);
    await writeFile(
      join(root, "locked", "package-lock.json"),
      JSON.stringify({
        name: "locked",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { tar: "^7.5.0" } },
          "node_modules/tar": { version: "7.5.20" },
        },
      }),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("locked/server.mjs");
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-node-tar-member-selection-recursion",
    );
  });

  test("keeps the benchmark pair strict and teaches exact availability impact", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-tar-member-selection-recursion",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-tar-member-selection",
    );
    const vulnerableRecords = records(
      await buildResidualRiskInventory(vulnerable),
    );
    expect(vulnerableRecords).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(vulnerableRecords[0]?.frameworkModel?.source.line).toBe(7);
    expect(vulnerableRecords[0]?.frameworkModel?.sink.line).toBe(4);
    expect(vulnerableRecords[0]?.frameworkModel?.propagators).toHaveLength(9);
    expect(await readFile(join(vulnerable, "src", "server.js"), "utf8")).toBe(
      await readFile(join(patched, "src", "server.js"), "utf8"),
    );
    expect(await readFile(join(vulnerable, "src", "storage.js"), "utf8")).toBe(
      await readFile(join(patched, "src", "storage.js"), "utf8"),
    );
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-http-tar-member-selection-recursion rows");
    expect(prompt).toContain("filesFilter/mapHas");
    expect(prompt).toContain("Report CWE-674 availability impact only");
  });
});
