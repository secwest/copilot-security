import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { runWithFreshCopilotSessions } from "../src/copilot-client.js";
import { ScanClosureIncompleteError } from "../src/index.js";

interface CoverageClosureScenario {
  id: string;
  maxSessionAttempts: number;
  coverageGapSequence: number[];
  expected: {
    completed: boolean;
    sessionsUsed: number;
    broadDiscoverySessions: number;
    closureSessions: number;
    finalCoverageGaps: number;
  };
}

interface CoverageClosureBenchmark {
  schemaVersion: string;
  benchmark: string;
  observedBaseline: {
    checkpoint: string;
    inventorySurfaces: number;
    reviewedSurfaces: number;
    coverageGaps: number;
    coverageCompleteness: string;
  };
  thresholds: {
    minimumFinalClosureRate: number;
    minimumClosureRateGain: number;
    maximumTotalSessions: number;
    maximumBroadDiscoveryReplays: number;
    requirePartialOnExhaustion: boolean;
  };
  scenarios: CoverageClosureScenario[];
}

const manifestPath = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "benchmarks",
  "coverage-closure-orchestration-benchmark.json",
);

async function readManifest(): Promise<CoverageClosureBenchmark> {
  return JSON.parse(
    await readFile(manifestPath, "utf8"),
  ) as CoverageClosureBenchmark;
}

describe("coverage-closure orchestration benchmark", () => {
  test("records the sealed self-scan baseline without treating partial as clearance", async () => {
    const manifest = await readManifest();
    const baseline = manifest.observedBaseline;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(manifest.benchmark).toBe("coverage-closure-orchestration");
    expect(baseline.inventorySurfaces).toBe(
      baseline.reviewedSurfaces + baseline.coverageGaps,
    );
    expect(baseline.coverageCompleteness).toBe("partial");
    expect(baseline.coverageGaps).toBeGreaterThan(0);
    expect(baseline.checkpoint).toMatch(/^[0-9a-f]{40}$/u);
  });

  test("closes an observed-scale gap without replaying broad discovery", async () => {
    const manifest = await readManifest();
    const scenario = manifest.scenarios.find(
      ({ expected }) => expected.completed,
    );
    if (scenario === undefined) throw new Error("missing completion scenario");
    const gapSequence = [...scenario.coverageGapSequence];
    let broadDiscoverySessions = 0;
    let closureSessions = 0;

    const finalGaps = await runWithFreshCopilotSessions({
      maxAttempts: scenario.maxSessionAttempts,
      prompt: "broad discovery",
      runAttempt: async (_attempt, prompt, context) => {
        if (context.phase === "scan") broadDiscoverySessions += 1;
        else closureSessions += 1;
        const gaps = gapSequence.shift();
        if (gaps === undefined) throw new Error("benchmark sequence exhausted");
        if (context.phase !== "scan") {
          expect(prompt).not.toContain("broad discovery");
        }
        if (gaps > 0) throw new ScanClosureIncompleteError(0, gaps);
        return gaps;
      },
    });

    const sessionsUsed = broadDiscoverySessions + closureSessions;
    const baselineClosureRate =
      manifest.observedBaseline.reviewedSurfaces /
      manifest.observedBaseline.inventorySurfaces;
    const finalClosureRate =
      (manifest.observedBaseline.inventorySurfaces - finalGaps) /
      manifest.observedBaseline.inventorySurfaces;
    expect(finalGaps).toBe(scenario.expected.finalCoverageGaps);
    expect(sessionsUsed).toBe(scenario.expected.sessionsUsed);
    expect(broadDiscoverySessions).toBe(
      scenario.expected.broadDiscoverySessions,
    );
    expect(closureSessions).toBe(scenario.expected.closureSessions);
    expect(finalClosureRate).toBeGreaterThanOrEqual(
      manifest.thresholds.minimumFinalClosureRate,
    );
    expect(finalClosureRate - baselineClosureRate).toBeGreaterThanOrEqual(
      manifest.thresholds.minimumClosureRateGain,
    );
    expect(sessionsUsed).toBeLessThanOrEqual(
      manifest.thresholds.maximumTotalSessions,
    );
    expect(broadDiscoverySessions - 1).toBeLessThanOrEqual(
      manifest.thresholds.maximumBroadDiscoveryReplays,
    );
    expect(gapSequence).toHaveLength(0);
  });

  test("preserves partial coverage when the bounded follow-up budget is exhausted", async () => {
    const manifest = await readManifest();
    const scenario = manifest.scenarios.find(
      ({ expected }) => !expected.completed,
    );
    if (scenario === undefined) throw new Error("missing exhaustion scenario");
    const gapSequence = [...scenario.coverageGapSequence];
    let broadDiscoverySessions = 0;
    let closureSessions = 0;
    let terminal: ScanClosureIncompleteError | null = null;

    try {
      await runWithFreshCopilotSessions({
        maxAttempts: scenario.maxSessionAttempts,
        prompt: "broad discovery",
        runAttempt: async (_attempt, _prompt, context) => {
          if (context.phase === "scan") broadDiscoverySessions += 1;
          else closureSessions += 1;
          const gaps = gapSequence.shift();
          if (gaps === undefined)
            throw new Error("benchmark sequence exhausted");
          throw new ScanClosureIncompleteError(0, gaps);
        },
      });
    } catch (error) {
      if (error instanceof ScanClosureIncompleteError) terminal = error;
      else throw error;
    }

    const sessionsUsed = broadDiscoverySessions + closureSessions;
    expect(manifest.thresholds.requirePartialOnExhaustion).toBe(true);
    expect(terminal).not.toBeNull();
    expect(terminal?.coverageGapCount).toBe(
      scenario.expected.finalCoverageGaps,
    );
    expect(sessionsUsed).toBe(scenario.expected.sessionsUsed);
    expect(broadDiscoverySessions).toBe(
      scenario.expected.broadDiscoverySessions,
    );
    expect(closureSessions).toBe(scenario.expected.closureSessions);
    expect(broadDiscoverySessions - 1).toBeLessThanOrEqual(
      manifest.thresholds.maximumBroadDiscoveryReplays,
    );
    expect(gapSequence).toHaveLength(0);
  });
});
