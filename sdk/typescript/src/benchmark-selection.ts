import { join } from "node:path";
import type { BenchmarkCase, BenchmarkManifest } from "./benchmark.js";

export function selectBenchmarkCases(
  cases: readonly BenchmarkCase[],
  requestedCaseIds: readonly string[],
): BenchmarkCase[] {
  const configuredCaseIds = new Set(
    cases
      .map((benchmarkCase) => benchmarkCase?.id)
      .filter((id): id is string => typeof id === "string"),
  );
  const unknownCases = requestedCaseIds.filter(
    (id) => !configuredCaseIds.has(id),
  );
  if (unknownCases.length > 0) {
    throw new Error(`Unknown benchmark case: ${unknownCases.join(", ")}`);
  }
  return cases.filter(
    (benchmarkCase) =>
      requestedCaseIds.length === 0 ||
      requestedCaseIds.includes(benchmarkCase?.id),
  );
}

export function benchmarkFindingsPaths(
  benchmarkCase: BenchmarkCase,
  runs?: number,
): string[] {
  const configuredFindingsPaths = Array.isArray(benchmarkCase.findingsPaths)
    ? benchmarkCase.findingsPaths
    : [
        typeof benchmarkCase.findingsPath === "string"
          ? benchmarkCase.findingsPath
          : join(benchmarkCase.id, "findings.json"),
      ];
  return runs === undefined
    ? [...configuredFindingsPaths]
    : configuredFindingsPaths.slice(0, runs);
}

export function buildBenchmarkSelection(
  manifest: BenchmarkManifest,
  selectedCases: readonly BenchmarkCase[],
  runs?: number,
): BenchmarkManifest {
  return {
    ...structuredClone(manifest),
    cases: selectedCases.map((benchmarkCase) => {
      const selected = structuredClone(benchmarkCase);
      delete selected.findingsPath;
      selected.findingsPaths = benchmarkFindingsPaths(benchmarkCase, runs);
      return selected;
    }),
  };
}
