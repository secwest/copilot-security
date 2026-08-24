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
      (record) => record.frameworkModel?.id === "node-http-brace-expansion-dos",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-brace-expansion-dos-"),
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
    path?: string;
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
        [options.packageName ?? "brace-expansion"]: options.version ?? "5.0.8",
      },
    }),
  );
  const sourcePath = join(directory, options.path ?? "server.mjs");
  await mkdir(resolve(sourcePath, ".."), { recursive: true });
  await writeFile(sourcePath, source);
}

describe("brace-expansion denial-of-service framework model", () => {
  test("supports each official major-line API and module binding", async () => {
    const root = await repository();
    const cases = [
      [
        "v1-default",
        "1.1.17",
        'import expand from "brace-expansion";\nexpand(req.query.pattern);',
      ],
      [
        "v1-commonjs",
        "1.1.17",
        'const expand = require("brace-expansion");\nexpand(req.query.pattern);',
      ],
      [
        "v2-typescript",
        "2.1.3",
        'import expand = require("brace-expansion");\nexpand(req.query.pattern);',
      ],
      [
        "v3-default",
        "3.0.5",
        'import expand from "brace-expansion";\nexpand(req.query.pattern);',
      ],
      [
        "v3-namespace",
        "3.0.5",
        'import * as braces from "brace-expansion";\nbraces.default(req.query.pattern);',
      ],
      [
        "v4-member",
        "4.0.1",
        'const expand = require("brace-expansion").default;\nexpand(req.query.pattern);',
      ],
      [
        "v4-destructured",
        "4.0.1",
        'const { default: expand } = require("brace-expansion");\nexpand(req.query.pattern);',
      ],
      [
        "v5-named",
        "5.0.8",
        'import { expand as expandPattern } from "brace-expansion";\nexpandPattern(req.query.pattern);',
      ],
      [
        "v5-namespace",
        "5.0.8",
        'import * as braces from "brace-expansion";\nbraces.expand(req.query.pattern);',
      ],
      [
        "v5-receiver",
        "5.0.8",
        'const braces = require("brace-expansion");\nbraces.expand(req.query.pattern);',
      ],
      [
        "v5-member",
        "5.0.8",
        'const expandPattern = require("brace-expansion").expand;\nexpandPattern(req.query.pattern);',
      ],
      [
        "v5-destructured",
        "5.0.8",
        'const { expand: expandPattern } = require("brace-expansion");\nexpandPattern(req.query.pattern);',
      ],
      [
        "v5-inline",
        "5.0.8",
        'require("brace-expansion").expand(req.query.pattern);',
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, version, source]) =>
        writeCase(root, id, source, { version }),
      ),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(cases.length);
    for (const [id, version] of cases) {
      const record = found.find(({ path }) => path === `${id}/server.mjs`);
      expect(record?.frameworkModel?.sink.kind).toBe(
        "vulnerable-brace-expansion-unbounded-intermediate-dos",
      );
      expect(record?.frameworkModel?.sink.cweIds).toEqual([
        "CWE-400",
        "CWE-407",
      ]);
      expect(record?.frameworkModel?.propagators[0]?.symbol).toBe(
        `brace-expansion@${version}:manifest-exact:unbounded-intermediate-dos`,
      );
    }
  });

  test("enforces every repaired boundary and exact API shape", async () => {
    const root = await repository();
    const v5 =
      'import { expand } from "brace-expansion";\nexpand(req.query.pattern);';
    await Promise.all([
      writeCase(root, "v1-fixed", v5, { version: "1.1.18" }),
      writeCase(root, "v2-fixed", v5, { version: "2.1.4" }),
      writeCase(root, "v3-fixed", v5, { version: "3.0.6" }),
      writeCase(root, "v5-fixed", v5, { version: "5.0.9" }),
      writeCase(root, "v1-later-line", v5, { version: "1.2.0" }),
      writeCase(root, "v2-named-unavailable", v5, { version: "2.1.3" }),
      writeCase(
        root,
        "v3-commonjs-not-callable",
        'const expand = require("brace-expansion");\nexpand(req.query.pattern);',
        { version: "3.0.5" },
      ),
      writeCase(
        root,
        "v5-default-unavailable",
        'import expand from "brace-expansion";\nexpand(req.query.pattern);',
      ),
      writeCase(root, "v4-named-unavailable", v5, { version: "4.0.1" }),
      writeCase(
        root,
        "fixed-input",
        'import { expand } from "brace-expansion";\nexpand("{a,b}");',
      ),
      writeCase(
        root,
        "wrong-package",
        'import { expand } from "braces";\nexpand(req.query.pattern);',
        { packageName: "braces" },
      ),
      writeCase(root, "development-only", v5, {
        section: "devDependencies",
      }),
      writeCase(root, "range-without-lock", v5, { version: "^5.0.0" }),
      writeCase(root, "test-path", v5, { path: "test/server.mjs" }),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("rejects reassigned, shadowed, and lookalike bindings", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "reassigned-binding",
        'import { expand } from "brace-expansion";\nexpand = local;\nexpand(req.query.pattern);',
      ),
      writeCase(
        root,
        "reassigned-receiver",
        'import * as braces from "brace-expansion";\nbraces = local;\nbraces.expand(req.query.pattern);',
      ),
      writeCase(
        root,
        "replaced-member",
        'import * as braces from "brace-expansion";\nbraces.expand = local;\nbraces.expand(req.query.pattern);',
      ),
      writeCase(
        root,
        "shadowed-binding",
        'import { expand } from "brace-expansion";\nexport function run(expand, req) { return expand(req.query.pattern); }',
      ),
      writeCase(
        root,
        "local-lookalike",
        'import { expand } from "./brace-expansion.js";\nexpand(req.query.pattern);',
      ),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("retains explicit work bounds as candidate evidence", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "bounded",
        'import { expand } from "brace-expansion";\nexpand(req.query.pattern, { max: 100, maxLength: 10000 });',
      ),
      writeCase(
        root,
        "max-only",
        'import { expand } from "brace-expansion";\nexpand(req.query.pattern, { max: 100 });',
      ),
      writeCase(
        root,
        "spread",
        'import { expand } from "brace-expansion";\nexpand(req.query.pattern, { max: 100, maxLength: 10000, ...limits });',
      ),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(3);
    expect(
      found.find(({ path }) => path === "bounded/server.mjs")?.frameworkModel
        ?.candidateControls,
    ).toEqual([
      {
        kind: "brace-expansion-explicit-work-bounds",
        path: "bounded/server.mjs",
        line: 2,
      },
    ]);
    for (const path of ["max-only/server.mjs", "spread/server.mjs"]) {
      expect(
        found.find((record) => record.path === path)?.frameworkModel
          ?.candidateControls,
      ).toEqual([]);
    }
  });

  test("requires fresh declaration-consistent npm lock proof", async () => {
    const root = await repository();
    const source =
      'import { expand } from "brace-expansion";\nexpand(req.query.pattern);';
    for (const [id, lockfileVersion] of [
      ["locked-v2", 2],
      ["locked-v3", 3],
    ] as const) {
      await writeCase(root, id, source, { version: "^5.0.0" });
      await writeFile(
        join(root, id, "package-lock.json"),
        JSON.stringify({
          name: id,
          lockfileVersion,
          packages: {
            "": { dependencies: { "brace-expansion": "^5.0.0" } },
            "node_modules/brace-expansion": { version: "5.0.8" },
          },
        }),
      );
    }
    await writeCase(root, "inconsistent", source, { version: "^5.0.0" });
    await writeFile(
      join(root, "inconsistent", "package-lock.json"),
      JSON.stringify({
        name: "inconsistent",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "brace-expansion": "^4.0.0" } },
          "node_modules/brace-expansion": { version: "5.0.8" },
        },
      }),
    );
    await writeCase(root, "legacy-lock", source, { version: "^5.0.0" });
    await writeFile(
      join(root, "legacy-lock", "package-lock.json"),
      JSON.stringify({
        name: "legacy-lock",
        lockfileVersion: 1,
        dependencies: { "brace-expansion": { version: "5.0.8" } },
      }),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "locked-v2/server.mjs",
      "locked-v3/server.mjs",
    ]);
    for (const record of found) {
      expect(record.frameworkModel?.sink.kind).toBe(
        "lock-resolved-vulnerable-brace-expansion-unbounded-intermediate-dos",
      );
      expect(record.frameworkModel?.propagators[0]?.symbol).toBe(
        "brace-expansion@5.0.8:npm-lockfile:unbounded-intermediate-dos",
      );
    }
  });

  test("keeps the benchmark pair source-identical and strict", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-brace-expansion-dos",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-brace-expansion",
    );
    const found = records(await buildResidualRiskInventory(vulnerable));
    expect(found).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(found[0]?.frameworkModel?.source.line).toBe(7);
    expect(found[0]?.frameworkModel?.sink.line).toBe(4);
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "vulnerable-brace-expansion-unbounded-intermediate-dos",
    );
    expect(found[0]?.frameworkModel?.sink.cweIds).toEqual([
      "CWE-400",
      "CWE-407",
    ]);
    expect(found[0]?.frameworkModel?.propagators).toHaveLength(10);
    expect(found[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "brace-expansion@5.0.8:manifest-exact:unbounded-intermediate-dos",
    );
    for (const path of [
      join("src", "server.js"),
      join("src", "gateway.js"),
      join("src", "service.js"),
      join("src", "storage.js"),
      "witness.mjs",
    ]) {
      expect(await readFile(join(vulnerable, path), "utf8")).toBe(
        await readFile(join(patched, path), "utf8"),
      );
    }
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-brace-expansion-dos-manifest.json"),
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
      "node-multi-hop-brace-expansion-dos",
      "node-multi-hop-patched-brace-expansion",
    ]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("teaches exact version, work, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-http-brace-expansion-dos rows");
    expect(prompt).toContain("1.1.18");
    expect(prompt).toContain("2.1.4");
    expect(prompt).toContain("3.0.6");
    expect(prompt).toContain("5.0.9");
    expect(prompt).toContain("padded-sequence");
    expect(prompt).toContain("comma-alternative");
    expect(prompt).toContain("CWE-400/CWE-407");
  });
});
