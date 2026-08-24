import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface RecordShape {
  path: string;
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
        "node-ssrf-ip-address-leading-zero-guard-bypass",
    );
}

async function repository(
  files: Record<string, string>,
  declaration = "10.3.0",
  options: {
    dependencyName?: string;
    dependencySection?: "dependencies" | "devDependencies";
    resolvedVersion?: string;
  } = {},
): Promise<RecordShape[]> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-ip-address-ssrf-"),
  );
  temporaryPaths.push(root);
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      [options.dependencySection ?? "dependencies"]: {
        [options.dependencyName ?? "ip-address"]: declaration,
      },
    }),
  );
  if (options.resolvedVersion !== undefined) {
    await writeFile(
      join(root, "package-lock.json"),
      JSON.stringify({
        name: "ip-address-leading-zero-test",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "ip-address": declaration } },
          "node_modules/ip-address": { version: options.resolvedVersion },
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
    "node-multi-hop-ip-address-leading-zero-ssrf",
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

describe("ip-address leading-zero SSRF guard model", () => {
  test("recognizes modern, CommonJS, and legacy private-range guards", async () => {
    const modern = await repository(await fixtureFiles());
    const commonjs = await repository(
      await fixtureFiles((source) =>
        source
          .replace(
            'import { Address4 } from "ip-address";',
            'const { Address4 } = require("ip-address");',
          )
          .replace("address.isPrivate()", "address.isLinkLocal()"),
      ),
    );
    const legacy = await repository(
      await fixtureFiles((source) =>
        source
          .replace(
            'import { Address4 } from "ip-address";',
            'const ip = require("ip-address");',
          )
          .replace("new Address4(host)", "new ip.v4.Address(host)")
          .replace(
            "address.isPrivate()",
            'address.isInSubnet(new ip.v4.Address("10.0.0.0/8"))',
          ),
      ),
      "4.2.0",
    );
    expect(modern).toHaveLength(1);
    expect(commonjs).toHaveLength(1);
    expect(legacy).toHaveLength(1);
    expect(modern[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "vulnerable-ip-address-leading-zero-isPrivate-guard",
      path: "src/storage.js",
      line: 6,
    });
  });

  test("enforces the published package and modern-classifier boundaries", async () => {
    const legacyFiles = await fixtureFiles((source) =>
      source
        .replace(
          'import { Address4 } from "ip-address";',
          'const ip = require("ip-address");',
        )
        .replace("new Address4(host)", "new ip.v4.Address(host)")
        .replace(
          "address.isPrivate()",
          'address.isInSubnet(new ip.v4.Address("10.0.0.0/8"))',
        ),
    );
    expect(await repository(legacyFiles, "3.2.0")).toHaveLength(1);
    expect(await repository(legacyFiles, "3.1.0")).toEqual([]);
    expect(await repository(await fixtureFiles(), "10.1.1")).toEqual([]);
  });

  test("requires an exact production dependency and a dominating same-value guard", async () => {
    expect(await repository(await fixtureFiles(), "10.3.1")).toEqual([]);
    expect(
      await repository(await fixtureFiles(), "10.3.0", {
        dependencyName: "ip-addresses",
      }),
    ).toEqual([]);
    expect(
      await repository(await fixtureFiles(), "10.3.0", {
        dependencySection: "devDependencies",
      }),
    ).toEqual([]);
    expect(await repository(await fixtureFiles(), "^10.0.0")).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            'if (address.isPrivate()) throw new Error("private address");',
            'if (address.isPrivate()) console.warn("private address");',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace("new Address4(host)", 'new Address4("8.8.8.8")'),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "export async function fetchProfile(rawUrl) {",
            "Address4 = LocalAddress;\n\nexport async function fetchProfile(rawUrl) {",
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source
            .replace(
              'import { Address4 } from "ip-address";',
              'import ip from "ip-address";',
            )
            .replace("new Address4(host)", "new ip.Address4(host)"),
        ),
      ),
    ).toEqual([]);
    const testPath = await fixtureFiles();
    testPath["test/storage.js"] = testPath["src/storage.js"]!;
    delete testPath["src/storage.js"];
    testPath["src/service.js"] = testPath["src/service.js"]!.replace(
      'from "./storage.js"',
      'from "../test/storage.js"',
    );
    expect(await repository(testPath)).toEqual([]);
  });

  test("suppresses an exact leading-zero rejection but not unrelated checks", async () => {
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "  const address = new Address4(host);",
            '  if (host.split(".").some((octet) => /^0\\d/.test(octet))) throw new Error("ambiguous");\n  const address = new Address4(host);',
          ),
        ),
      ),
    ).toEqual([]);
    expect(
      await repository(
        await fixtureFiles((source) =>
          source.replace(
            "  const address = new Address4(host);",
            '  if (/^0\\d/.test(requestId)) throw new Error("ambiguous request id");\n  const address = new Address4(host);',
          ),
        ),
      ),
    ).toHaveLength(1);
  });

  test("accepts exact vulnerable lock evidence and rejects a repaired resolution", async () => {
    const vulnerable = await repository(await fixtureFiles(), "^10.0.0", {
      resolvedVersion: "10.3.0",
    });
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "ip-address-runtime-dependency",
      path: "package.json",
      line: 1,
      symbol: "ip-address@10.3.0:npm-lockfile",
    });
    expect(
      await repository(await fixtureFiles(), "^10.0.0", {
        resolvedVersion: "10.3.1",
      }),
    ).toEqual([]);
  });

  test("keeps the exact cross-file exploit/control topology", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-ip-address-leading-zero-ssrf",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-ip-address-leading-zero",
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
      line: 7,
      cweIds: ["CWE-918", "CWE-20"],
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

  test("teaches the exact parser and network-use disagreement", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain(
      "node-ssrf-ip-address-leading-zero-guard-bypass rows",
    );
    expect(prompt).toContain("012.0.0.1");
    expect(prompt).toContain("10.3.1");
  });

  test("keeps the specialized benchmark at perfect positive and negative gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-ip-address-leading-zero-ssrf-manifest.json"),
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
      "node-multi-hop-ip-address-leading-zero-ssrf",
      "node-multi-hop-patched-ip-address-leading-zero",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });
});
