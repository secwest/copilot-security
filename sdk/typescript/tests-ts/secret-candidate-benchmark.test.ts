import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildSecretCandidateInventory,
  prepareSecretScanning,
  type SecretCandidateRecord,
} from "../src/secret-candidates.js";

interface SecretBenchmarkManifest {
  schemaVersion: "1.0";
  thresholds: {
    minimumRecall: number;
    minimumPrecision: number;
  };
  cases: Array<{
    id: string;
    lineTemplate: string;
    value: {
      prefix: string;
      body: string;
      repeat: number;
      suffix?: string;
    };
    expectedRuleId: string | null;
  }>;
}

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("secret candidate corpus benchmark", () => {
  test("meets perfect typed-pattern and negative-control thresholds without leaking values", async () => {
    const manifestPath = join(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "secret-candidate-manifest.json",
    );
    const manifest = JSON.parse(
      await readFile(manifestPath, "utf8"),
    ) as SecretBenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    const root = await mkdtemp(
      join(tmpdir(), "copilot-security-secret-benchmark-"),
    );
    temporaryPaths.push(root);
    const repository = join(root, "repository");
    const credentialHome = join(root, "copilot-security-home");
    await mkdir(repository, { recursive: true });
    await mkdir(credentialHome, { recursive: true });

    const materialized = new Map<string, string>();
    for (const benchmarkCase of manifest.cases) {
      const value = `${benchmarkCase.value.prefix}${benchmarkCase.value.body.repeat(
        benchmarkCase.value.repeat,
      )}${benchmarkCase.value.suffix ?? ""}`;
      materialized.set(benchmarkCase.id, value);
      await writeFile(
        join(repository, `${benchmarkCase.id}.env`),
        `${benchmarkCase.lineTemplate.replace("{value}", value)}\n`,
      );
    }
    const prepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
    });
    const result = await buildSecretCandidateInventory(
      repository,
      prepared,
      "corpus-benchmark",
    );
    const rows = result.inventory
      .split("\n")
      .slice(1)
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as SecretCandidateRecord);
    const observed = new Map(
      rows.map((row) => [row.path.replace(/\.env$/u, ""), row.ruleId]),
    );
    let truePositive = 0;
    let falsePositive = 0;
    let falseNegative = 0;
    for (const benchmarkCase of manifest.cases) {
      const actual = observed.get(benchmarkCase.id);
      if (benchmarkCase.expectedRuleId === null) {
        if (actual !== undefined) falsePositive += 1;
      } else if (actual === benchmarkCase.expectedRuleId) {
        truePositive += 1;
      } else {
        falseNegative += 1;
      }
    }
    const recall = truePositive / (truePositive + falseNegative);
    const precision = truePositive / (truePositive + falsePositive);

    expect(recall).toBeGreaterThanOrEqual(manifest.thresholds.minimumRecall);
    expect(precision).toBeGreaterThanOrEqual(
      manifest.thresholds.minimumPrecision,
    );
    expect({ truePositive, falsePositive, falseNegative }).toEqual({
      truePositive: 14,
      falsePositive: 0,
      falseNegative: 0,
    });
    for (const value of materialized.values()) {
      expect(result.inventory).not.toContain(value);
    }
  });
});
