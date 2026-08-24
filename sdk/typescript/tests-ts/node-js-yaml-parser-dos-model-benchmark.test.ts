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
      (record) => record.frameworkModel?.id === "node-http-js-yaml-parser-dos",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-js-yaml-dos-"));
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
        [options.packageName ?? "js-yaml"]: options.version ?? "4.2.0",
      },
    }),
  );
  await writeFile(join(directory, "server.mjs"), source);
}

describe("js-yaml parser denial-of-service framework model", () => {
  test("supports official loader bindings and distinguishes both parser defects", async () => {
    const root = await repository();
    const cases = [
      [
        "namespace",
        "4.2.0",
        'import * as yaml from "js-yaml";\nyaml.load(req.body.yaml);',
        "vulnerable-js-yaml-load-quadratic-merge-dos",
      ],
      [
        "default",
        "4.2.0",
        'import yaml from "js-yaml";\nyaml.loadAll(req.body.yaml);',
        "vulnerable-js-yaml-loadAll-quadratic-merge-dos",
      ],
      [
        "typescript",
        "3.14.2",
        'import yaml = require("js-yaml");\nyaml.safeLoad(req.body.yaml);',
        "vulnerable-js-yaml-safeLoad-quadratic-merge-dos",
      ],
      [
        "named",
        "5.2.1",
        'import { load as parseYaml } from "js-yaml";\nparseYaml(req.body.yaml);',
        "vulnerable-js-yaml-load-exponential-flow-dos",
      ],
      [
        "destructured",
        "5.2.1",
        'const { loadAll: parseAll } = require("js-yaml");\nparseAll(req.body.yaml);',
        "vulnerable-js-yaml-loadAll-exponential-flow-dos",
      ],
      [
        "member",
        "5.2.1",
        'const parseYaml = require("js-yaml").load;\nparseYaml(req.body.yaml);',
        "vulnerable-js-yaml-load-exponential-flow-dos",
      ],
      [
        "direct",
        "5.2.1",
        'require("js-yaml").load(req.body.yaml);',
        "vulnerable-js-yaml-load-exponential-flow-dos",
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, version, source]) =>
        writeCase(root, id, source, { version }),
      ),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(cases.length);
    for (const [id, , , kind] of cases) {
      const record = found.find(({ path }) => path === `${id}/server.mjs`);
      expect(record?.frameworkModel?.sink.kind).toBe(kind);
      expect(record?.frameworkModel?.sink.cweIds).toEqual([
        "CWE-400",
        "CWE-407",
      ]);
    }
  });

  test("enforces every repaired and API boundary", async () => {
    const root = await repository();
    const source =
      'import * as yaml from "js-yaml";\nyaml.load(req.body.yaml);';
    await Promise.all([
      writeCase(root, "pre-v3", source, { version: "2.1.3" }),
      writeCase(root, "v3-fixed", source, { version: "3.15.0" }),
      writeCase(root, "v4-fixed", source, { version: "4.3.0" }),
      writeCase(root, "v5-fixed", source, { version: "5.2.2" }),
      writeCase(
        root,
        "v4-safe-load-unavailable",
        'import * as yaml from "js-yaml";\nyaml.safeLoad(req.body.yaml);',
        { version: "4.2.0" },
      ),
      writeCase(
        root,
        "v5-safe-load-unavailable",
        'import * as yaml from "js-yaml";\nyaml.safeLoad(req.body.yaml);',
        { version: "5.2.1" },
      ),
      writeCase(
        root,
        "fixed-input",
        'import * as yaml from "js-yaml";\nyaml.load("a: 1");',
      ),
      writeCase(
        root,
        "wrong-package",
        'import * as yaml from "yaml";\nyaml.load(req.body.yaml);',
        { packageName: "yaml" },
      ),
      writeCase(root, "dev-only", source, { section: "devDependencies" }),
      writeCase(root, "range-no-lock", source, { version: "^4.0.0" }),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("rejects reassigned and shadowed loaders", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "reassigned-root",
        'import * as yaml from "js-yaml";\nyaml = local;\nyaml.load(req.body.yaml);',
      ),
      writeCase(
        root,
        "reassigned-member",
        'import { load } from "js-yaml";\nload = local;\nload(req.body.yaml);',
      ),
      writeCase(
        root,
        "replaced-receiver-member",
        'import * as yaml from "js-yaml";\nyaml.load = local;\nyaml.load(req.body.yaml);',
      ),
      writeCase(
        root,
        "shadowed",
        'import * as yaml from "js-yaml";\nexport function parse(yaml, req) { return yaml.load(req.body.yaml); }',
      ),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("accepts a fresh declaration-consistent npm lock and preserves provenance", async () => {
    const root = await repository();
    const source =
      'import { load } from "js-yaml";\nload(req.body.yaml, { maxDepth: 1 });';
    await writeCase(root, "locked", source, { version: "^5.0.0" });
    await writeFile(
      join(root, "locked", "package-lock.json"),
      JSON.stringify({
        name: "locked",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "js-yaml": "^5.0.0" } },
          "node_modules/js-yaml": { version: "5.2.1" },
        },
      }),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-js-yaml-load-exponential-flow-dos",
    );
  });

  test("keeps the cross-file benchmark pair topology-identical", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-js-yaml-exponential-dos",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-js-yaml-flow-parser",
    );
    const vulnerableRecords = records(
      await buildResidualRiskInventory(vulnerable),
    );
    expect(vulnerableRecords).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(vulnerableRecords[0]?.frameworkModel?.source.line).toBe(7);
    expect(vulnerableRecords[0]?.frameworkModel?.sink.line).toBe(4);
    expect(vulnerableRecords[0]?.frameworkModel?.sink.kind).toBe(
      "vulnerable-js-yaml-load-exponential-flow-dos",
    );
    expect(vulnerableRecords[0]?.frameworkModel?.propagators).toHaveLength(9);
    for (const path of [
      join("src", "server.js"),
      join("src", "gateway.js"),
      join("src", "service.js"),
      join("src", "storage.js"),
    ]) {
      expect(await readFile(join(vulnerable, path), "utf8")).toBe(
        await readFile(join(patched, path), "utf8"),
      );
    }

    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-js-yaml-parser-dos-manifest.json"),
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
      "node-multi-hop-js-yaml-exponential-dos",
      "node-multi-hop-patched-js-yaml-flow-parser",
    ]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("teaches distinct grammar, mitigation, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-http-js-yaml-parser-dos rows");
    expect(prompt).toContain("quadratic merge-chain family");
    expect(prompt).toContain("exponential flow-pair family");
    expect(prompt).toContain("maxDepth:100 is not protection");
    expect(prompt).toContain("CWE-400/CWE-407 availability impact");
  });
});
