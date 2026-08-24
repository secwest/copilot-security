import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
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
        "node-ssrf-fast-uri-host-policy-confusion",
    );
}

async function repository(
  files: Record<string, string>,
  declaration = "4.1.1",
  options: {
    dependencyName?: string;
    dependencySection?: "dependencies" | "devDependencies";
    resolvedVersion?: string;
  } = {},
): Promise<RecordShape[]> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-fast-uri-ssrf-"));
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
        name: "fast-uri-host-policy-test",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "fast-uri": declaration } },
          "node_modules/fast-uri": { version: options.resolvedVersion },
        },
      }),
    );
  }
  for (const [path, source] of Object.entries(files)) {
    const destination = join(root, path);
    await mkdir(resolve(destination, ".."), { recursive: true });
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
    "node-multi-hop-fast-uri-authority-ssrf",
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

async function literalBackslashFiles(
  transform: (source: string) => string = (source) => source,
): Promise<Record<string, string>> {
  return fixtureFiles(() =>
    transform(`import { parse } from "fast-uri";

export async function fetchProfile(reference) {
  const policyHost = parse(reference).host;
  if (policyHost !== "allowed.example") throw new Error("untrusted host");
  return fetch(reference);
}
`),
  );
}

describe("fast-uri host-policy SSRF model", () => {
  test("recognizes named, CommonJS, and receiver authority guards", async () => {
    const receiver = await repository(await fixtureFiles());
    const named = await repository(
      await fixtureFiles((source) =>
        source
          .replace(
            'import fastUri from "fast-uri";',
            'import { parse, resolve } from "fast-uri";',
          )
          .replace(
            "fastUri.resolve(BASE_URL, reference)",
            "resolve(BASE_URL, reference)",
          )
          .replace("fastUri.parse(policyUrl)", "parse(policyUrl)"),
      ),
    );
    const commonjs = await repository(
      await fixtureFiles((source) =>
        source
          .replace(
            'import fastUri from "fast-uri";',
            'const { parse, resolve } = require("fast-uri");',
          )
          .replace(
            "fastUri.resolve(BASE_URL, reference)",
            "resolve(BASE_URL, reference)",
          )
          .replace("fastUri.parse(policyUrl)", "parse(policyUrl)"),
      ),
    );
    expect(named).toHaveLength(1);
    expect(commonjs).toHaveLength(1);
    expect(receiver).toHaveLength(1);
    expect(named[0]?.categories).toContain(
      "broken-control:fast-uri-authority-introducer-parser-disagreement",
    );
    expect(named[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "vulnerable-fast-uri-authority-introducer-host-guard",
      path: "src/storage.js",
      line: 8,
    });
  });

  test("enforces every authority-introducer repair boundary", async () => {
    const files = await fixtureFiles();
    for (const vulnerable of ["1.9.9", "2.4.3", "3.1.4", "4.1.1"]) {
      expect(await repository(files, vulnerable)).toHaveLength(1);
    }
    for (const repaired of ["2.4.4", "3.1.5", "4.1.2", "5.0.0"]) {
      expect(await repository(files, repaired)).toEqual([]);
    }
  });

  test("models the direct literal-backslash parse disagreement separately", async () => {
    const files = await literalBackslashFiles();
    for (const vulnerable of [
      "2.3.1",
      "2.4.2",
      "3.0.0",
      "3.1.3",
      "4.0.0",
      "4.1.0",
    ]) {
      const found = await repository(files, vulnerable);
      expect(found).toHaveLength(1);
      expect(found[0]?.categories).toContain(
        "broken-control:fast-uri-literal-backslash-parser-disagreement",
      );
    }
    for (const outside of ["2.3.0", "2.4.3", "3.1.4", "4.1.1"]) {
      expect(await repository(files, outside)).toEqual([]);
    }
  });

  test("requires exact same-value resolution, host policy, and network use", async () => {
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            'if (policyHost !== "allowed.example") throw new Error("untrusted host");',
            'if (policyHost !== "allowed.example") console.warn("untrusted host");',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "fastUri.resolve(BASE_URL, reference)",
            'fastUri.resolve(BASE_URL, "safe/profile")',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "new URL(reference, BASE_URL)",
            'new URL(reference, "https://other.example/")',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            'policyHost !== "allowed.example"',
            'policyHost !== "other.example"',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await literalBackslashFiles((source) =>
          source.replace(
            "parse(reference)",
            'parse("https://allowed.example/")',
          ),
        ),
        "4.1.0",
      ),
    ).toEqual([]);
  });

  test("requires exact production package evidence and official bindings", async () => {
    expect(
      await repository(await fixtureFiles(), "4.1.1", {
        dependencyName: "fast-url",
      }),
    ).toEqual([]);
    expect(
      await repository(await fixtureFiles(), "4.1.1", {
        dependencySection: "devDependencies",
      }),
    ).toEqual([]);
    expect(await repository(await fixtureFiles(), "^4.0.0")).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace('from "fast-uri"', 'from "other-uri"'),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "export async function fetchProfile(reference) {",
            "fastUri = localFastUri;\n\nexport async function fetchProfile(reference) {",
          ),
        ),
      ),
    ).toEqual([]);
  });

  test("accepts exact vulnerable lock evidence and rejects repaired resolution", async () => {
    const vulnerable = await repository(await fixtureFiles(), "^4.0.0", {
      resolvedVersion: "4.1.1",
    });
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "fast-uri-runtime-dependency",
      path: "package.json",
      line: 1,
      symbol: "fast-uri@4.1.1:npm-lockfile:authority-introducer",
    });
    expect(
      await repository(await fixtureFiles(), "^4.0.0", {
        resolvedVersion: "4.1.2",
      }),
    ).toEqual([]);
  });

  test("excludes test paths and preserves the exact exploit/control topology", async () => {
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
      "node-multi-hop-fast-uri-authority-ssrf",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-fast-uri-authority",
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
      line: 9,
      cweIds: ["CWE-918", "CWE-436"],
    });
    expect(found[0]?.frameworkModel?.propagators).toHaveLength(10);
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

  test("teaches all host-policy causes without confusing the path advisory", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    const normalizedPrompt = prompt.toLowerCase();
    expect(prompt).toContain("node-ssrf-fast-uri-host-policy-confusion rows");
    expect(normalizedPrompt).toContain("authority introducer");
    expect(normalizedPrompt).toContain("literal backslash");
    expect(normalizedPrompt).toContain("failed idn canonicalization");
    expect(normalizedPrompt).toContain("percent-encoded authority delimiter");
    expect(normalizedPrompt).toContain("path traversal");
  });

  test("keeps the specialized benchmark at perfect positive and negative gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-fast-uri-host-policy-ssrf-manifest.json"),
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
      "node-multi-hop-fast-uri-authority-ssrf",
      "node-multi-hop-patched-fast-uri-authority",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });
});
