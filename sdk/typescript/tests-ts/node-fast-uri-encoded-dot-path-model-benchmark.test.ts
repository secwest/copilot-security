import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface RecordShape {
  path: string;
  categories: string[];
  frameworkModel?: {
    id: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path?: string;
      line?: number;
      symbol?: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(import.meta.dir, "..", "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string): RecordShape[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as RecordShape)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-path-fast-uri-encoded-dot-segment-policy-bypass",
    );
}

async function repository(
  files: Record<string, string>,
  declaration = "3.1.0",
  options: {
    dependencyName?: string;
    dependencySection?: "dependencies" | "devDependencies";
    lockfileVersion?: number;
    resolvedVersion?: string;
  } = {},
): Promise<RecordShape[]> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-fast-uri-path-"));
  temporaryPaths.push(root);
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      [options.dependencySection ?? "dependencies"]: {
        [options.dependencyName ?? "fast-uri"]: declaration,
      },
    }),
  );
  if (options.resolvedVersion !== undefined) {
    await writeFile(
      join(root, "package-lock.json"),
      JSON.stringify({
        name: "fast-uri-encoded-dot-path-test",
        lockfileVersion: options.lockfileVersion ?? 3,
        packages: {
          "": { dependencies: { "fast-uri": declaration } },
          "node_modules/fast-uri": { version: options.resolvedVersion },
        },
      }),
    );
  }
  for (const [path, source] of Object.entries(files)) {
    const destination = join(root, path);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, source);
  }
  return records(await buildResidualRiskInventory(root));
}

async function fixtureFiles(
  storageTransform: (source: string) => string = (source) => source,
): Promise<Record<string, string>> {
  const fixture = join(
    benchmarkRoot,
    "fixtures",
    "node-multi-hop-fast-uri-encoded-dot-path",
    "src",
  );
  const files: Record<string, string> = {};
  for (const name of ["server.js", "gateway.js", "service.js", "storage.js"]) {
    const source = await readFile(join(fixture, name), "utf8");
    files[`src/${name}`] =
      name === "storage.js" ? storageTransform(source) : source;
  }
  return files;
}

describe("fast-uri encoded dot-segment path-policy model", () => {
  test("recognizes exact receiver, named, CommonJS, and path receiver bindings", async () => {
    const receiver = await repository(await fixtureFiles());
    const named = await repository(
      await fixtureFiles((source) =>
        source
          .replace(
            'import fastUri from "fast-uri";',
            'import { normalize, parse } from "fast-uri";',
          )
          .replace(
            "fastUri.parse(fastUri.normalize(assetUrl))",
            "parse(normalize(assetUrl))",
          ),
      ),
    );
    const commonjs = await repository(
      await fixtureFiles((source) =>
        source
          .replace(
            'import fastUri from "fast-uri";',
            'const { normalize, parse } = require("fast-uri");',
          )
          .replace(
            "fastUri.parse(fastUri.normalize(assetUrl))",
            "parse(normalize(assetUrl))",
          ),
      ),
    );
    const pathReceiver = await repository(
      await fixtureFiles((source) =>
        source
          .replace(
            'import { join } from "node:path";',
            'import path from "node:path";',
          )
          .replace("    join(", "    path.join("),
      ),
    );
    for (const found of [receiver, named, commonjs, pathReceiver]) {
      expect(found).toHaveLength(1);
      expect(found[0]?.categories).toContain(
        "broken-control:fast-uri-encoded-dot-segment-normalization",
      );
    }
  });

  test("enforces every published v2 and v3 repair boundary", async () => {
    const files = await fixtureFiles();
    for (const vulnerable of [
      "0.9.0",
      "1.9.9",
      "2.3.9",
      "2.4.0",
      "3.0.0",
      "3.1.0",
    ]) {
      expect(await repository(files, vulnerable)).toHaveLength(1);
    }
    for (const repaired of ["2.4.1", "2.5.0", "3.1.1", "3.2.0", "4.0.0"]) {
      expect(await repository(files, repaired)).toEqual([]);
    }
  });

  test("requires the same fail-closed canonical public prefix", async () => {
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            'if (!assetUrl.startsWith(PUBLIC_URL)) throw new Error("private asset path");',
            'if (!assetUrl.startsWith(PUBLIC_URL)) console.warn("private asset path");',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            'if (!assetUrl.startsWith(PUBLIC_URL)) throw new Error("private asset path");',
            'if (!assetUrl.startsWith(PUBLIC_URL)) { console.warn("private asset path"); }',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            'if (!assetUrl.startsWith(PUBLIC_URL)) throw new Error("private asset path");',
            'if (!assetUrl.startsWith(PUBLIC_URL)) { auditRejection(); throw new Error("private asset path"); }',
          ),
        ),
      ),
    ).toHaveLength(1);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace("if (!assetUrl.startsWith", "if (assetUrl.startsWith"),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            '"https://assets.example/public/"',
            '"https://assets.example/"',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source
            .replace(
              "storeAsset(assetUrl, content)",
              "storeAsset(assetUrl, content, policyUrl)",
            )
            .replace(
              "assetUrl.startsWith(PUBLIC_URL)",
              "policyUrl.startsWith(PUBLIC_URL)",
            ),
        ),
      ),
    ).toEqual([]);
  });

  test("requires normalize then parse.path inside a fixed rooted Node path", async () => {
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "fastUri.parse(fastUri.normalize(assetUrl))",
            "fastUri.parse(assetUrl)",
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "fastUri.parse(fastUri.normalize(assetUrl)).path",
            "new URL(fastUri.normalize(assetUrl)).pathname",
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "    join(ASSET_ROOT, fastUri.parse(fastUri.normalize(assetUrl)).path.slice(1)),",
            "    fastUri.parse(fastUri.normalize(assetUrl)).path,",
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace('from "node:path"', 'from "local-path"'),
        ),
      ),
    ).toEqual([]);
  });

  test("requires exact production dependency and non-reassigned official bindings", async () => {
    const files = await fixtureFiles();
    expect(
      await repository(files, "3.1.0", { dependencyName: "fast-url" }),
    ).toEqual([]);
    expect(
      await repository(files, "3.1.0", {
        dependencySection: "devDependencies",
      }),
    ).toEqual([]);
    expect(await repository(files, "^3.0.0")).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace('from "fast-uri"', 'from "local-fast-uri"'),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "export async function storeAsset",
            "fastUri = localFastUri;\n\nexport async function storeAsset",
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "export async function storeAsset",
            "join = localJoin;\n\nexport async function storeAsset",
          ),
        ),
      ),
    ).toEqual([]);
  });

  test("accepts fresh vulnerable locks and rejects repaired or v1 lock evidence", async () => {
    const files = await fixtureFiles();
    const vulnerable = await repository(files, "^3.0.0", {
      resolvedVersion: "3.1.0",
    });
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "fast-uri-runtime-dependency",
      path: "package.json",
      line: 1,
      symbol: "fast-uri@3.1.0:npm-lockfile:encoded-dot-segment-normalization",
    });
    expect(
      await repository(files, "^3.0.0", { resolvedVersion: "3.1.1" }),
    ).toEqual([]);
    expect(
      await repository(files, "^3.0.0", {
        lockfileVersion: 1,
        resolvedVersion: "3.1.0",
      }),
    ).toEqual([]);
  });

  test("excludes tests and preserves exact exploit/control topology", async () => {
    const testPath = await fixtureFiles();
    testPath["test/storage.js"] = testPath["src/storage.js"]!;
    delete testPath["src/storage.js"];
    testPath["src/service.js"] = testPath["src/service.js"]!.replace(
      'from "./storage.js"',
      'from "../test/storage.js"',
    );
    expect(await repository(testPath)).toEqual([]);

    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-fast-uri-encoded-dot-path",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-fast-uri-encoded-dot-path",
    );
    const found = records(await buildResidualRiskInventory(vulnerable));
    expect(found).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "http-request-field",
      path: "src/server.js",
      line: 7,
    });
    expect(found[0]?.frameworkModel?.sink).toMatchObject({
      path: "src/storage.js",
      line: 10,
      cweIds: ["CWE-22"],
    });
    expect(found[0]?.frameworkModel?.propagators).toHaveLength(10);
    expect(found[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "vulnerable-fast-uri-encoded-dot-segment-path-policy",
      path: "src/storage.js",
      line: 9,
    });
    for (const path of [
      "server.js",
      "gateway.js",
      "service.js",
      "storage.js",
    ]) {
      expect(await readFile(join(vulnerable, "src", path), "utf8")).toBe(
        await readFile(join(patched, "src", path), "utf8"),
      );
    }
  });

  test("teaches exact path semantics and keeps the specialized gate perfect", async () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain(
      "node-path-fast-uri-encoded-dot-segment-policy-bypass rows",
    );
    expect(prompt).toContain("2.4.1 and 3.1.1");
    expect(prompt).toContain("WHATWG URL reparsing");
    expect(prompt).toContain("separate SSRF model");

    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-fast-uri-encoded-dot-path-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{ id: string; expected: unknown[] }>;
    };
    expect(manifest.thresholds).toMatchObject({
      minCompletionRate: 1,
      minPrecision: 1,
      minRecall: 1,
      minF1: 1,
      minNegativeCasePassRate: 1,
      maxFalsePositivesPerRun: 0,
    });
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-fast-uri-encoded-dot-path",
      "node-multi-hop-patched-fast-uri-encoded-dot-path",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });
});
