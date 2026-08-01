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

describe("cross-file framework-model effectiveness benchmark", () => {
  test("keeps wrapper positives and negatives paired under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "cross-file-framework-manifest.json"),
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
      "javascript-cross-file-command-injection",
      "javascript-cross-file-safe-command",
      "javascript-cross-file-sql-injection",
      "javascript-cross-file-safe-sql",
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

  test("emits exact cross-file propagation and preserves negative controls", async () => {
    const inventories = new Map<string, string>();
    for (const id of [
      "javascript-cross-file-command-injection",
      "javascript-cross-file-safe-command",
      "javascript-cross-file-sql-injection",
      "javascript-cross-file-safe-sql",
    ]) {
      inventories.set(
        id,
        await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
      );
    }

    expect(
      inventories.get("javascript-cross-file-command-injection"),
    ).toContain('"scope":"cross-file-wrapper"');
    expect(
      inventories.get("javascript-cross-file-command-injection"),
    ).toContain('"kind":"wrapper-call-argument"');
    expect(inventories.get("javascript-cross-file-safe-command")).not.toContain(
      '"scope":"cross-file-wrapper"',
    );
    expect(inventories.get("javascript-cross-file-sql-injection")).toContain(
      '"id":"node-http-sql"',
    );
    expect(inventories.get("javascript-cross-file-safe-sql")).toContain(
      '"kind":"bound-query-parameters"',
    );
  });
});
