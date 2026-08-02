import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface BenchmarkCase {
  id: string;
  fixture: string;
  findingsPaths: string[];
  expected: unknown[];
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: BenchmarkCase[];
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

describe("multi-hop framework-model effectiveness benchmark", () => {
  test("keeps three-file positives and negatives paired under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "multi-hop-framework-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "javascript-multi-hop-command-injection",
      "javascript-multi-hop-safe-command",
      "javascript-multi-hop-sql-injection",
      "javascript-multi-hop-safe-sql",
    ]);
    expect(
      manifest.cases.filter(({ expected }) => expected.length > 0),
    ).toHaveLength(2);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(2);
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(1);
    }
  });

  test("emits ordered multi-hop propagation and preserves negative controls", async () => {
    const inventories = new Map<string, string>();
    for (const id of [
      "javascript-multi-hop-command-injection",
      "javascript-multi-hop-safe-command",
      "javascript-multi-hop-sql-injection",
      "javascript-multi-hop-safe-sql",
    ]) {
      inventories.set(
        id,
        await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
      );
    }

    const command = inventories.get("javascript-multi-hop-command-injection");
    expect(command).toContain('"scope":"cross-file-multi-hop-wrapper"');
    expect(command?.match(/"kind":"relative-module-import"/gu)).toHaveLength(2);
    expect(command?.match(/"kind":"wrapper-call-argument"/gu)).toHaveLength(2);
    expect(command?.match(/"kind":"wrapper-parameter"/gu)).toHaveLength(2);
    expect(inventories.get("javascript-multi-hop-safe-command")).not.toContain(
      '"scope":"cross-file-multi-hop-wrapper"',
    );
    expect(inventories.get("javascript-multi-hop-sql-injection")).toContain(
      '"id":"node-http-sql"',
    );
    expect(inventories.get("javascript-multi-hop-safe-sql")).toContain(
      '"kind":"bound-query-parameters"',
    );
  });
});
