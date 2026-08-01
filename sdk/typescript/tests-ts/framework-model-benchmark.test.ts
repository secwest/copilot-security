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

describe("framework-model effectiveness benchmark", () => {
  test("keeps command and SQL cases paired with one strict run each", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "framework-model-manifest.json"),
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
      "javascript-command-injection",
      "javascript-safe-command",
      "javascript-sql-injection",
      "javascript-safe-sql",
    ]);
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(1);
    }
    expect(
      manifest.cases.filter(({ expected }) => expected.length > 0),
    ).toHaveLength(2);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(2);
  });

  test("deterministically seeds vulnerable flows and preserves the SQL negative control", async () => {
    const commandVulnerable = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", "javascript-command-injection"),
    );
    const commandSafe = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", "javascript-safe-command"),
    );
    const sqlVulnerable = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", "javascript-sql-injection"),
    );
    const sqlSafe = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", "javascript-safe-sql"),
    );

    expect(commandVulnerable).toContain('"id":"node-http-command"');
    expect(commandSafe).not.toContain('"id":"node-http-command"');
    expect(sqlVulnerable).toContain('"id":"node-http-sql"');
    expect(sqlSafe).toContain('"id":"node-http-sql"');
    expect(sqlSafe).toContain('"kind":"bound-query-parameters"');
  });
});
