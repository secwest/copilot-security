import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { CopilotSecurityError } from "./errors.js";
import type { SeverityLevel } from "./models.js";

const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_FINDINGS_BYTES = 64 * 1024 * 1024;
const MAX_STATUS_BYTES = 64 * 1024;
const MAX_CASES = 10_000;
const MAX_RUNS_PER_CASE = 100;
const MAX_EXPECTATIONS_PER_CASE = 10_000;
const DEFAULT_LINE_TOLERANCE = 3;

export interface BenchmarkThresholds {
  minCompletionRate?: number;
  minPrecision?: number;
  minRecall?: number;
  minF1?: number;
  minCasePassRate?: number;
  minNegativeCasePassRate?: number;
  minStableDetectionRate?: number;
  minValidationRate?: number;
  minAttackPathRate?: number;
  minCodeEvidenceRate?: number;
  minSeverityAccuracy?: number;
  maxFalsePositivesPerRun?: number;
}

export interface BenchmarkLocationExpectation {
  path: string;
  startLine: number;
  endLine?: number;
  lineTolerance?: number;
}

export interface BenchmarkFindingExpectation {
  id: string;
  cwe: string[];
  locations: BenchmarkLocationExpectation[];
  acceptableSeverities?: SeverityLevel[];
  requireValidation?: boolean;
  requireAttackPath?: boolean;
  requireCodeEvidence?: boolean;
}

export interface BenchmarkCase {
  id: string;
  description?: string;
  fixture?: string;
  findingsPath?: string;
  findingsPaths?: string[];
  expected: BenchmarkFindingExpectation[];
}

export interface BenchmarkManifest {
  schemaVersion: "1.0";
  thresholds?: BenchmarkThresholds;
  cases: BenchmarkCase[];
}

export interface BenchmarkMatch {
  expectationId: string;
  findingId: string;
  score: number;
  validationPresent: boolean;
  attackPathPresent: boolean;
  codeEvidencePresent: boolean;
  severityAccepted: boolean | null;
}

export interface BenchmarkRunResult {
  id: string;
  findingsPath: string;
  completed: boolean;
  error?: string;
  expectedCount: number;
  findingCount: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  passed: boolean;
  matches: BenchmarkMatch[];
  missedExpectations: string[];
  unexpectedFindings: string[];
}

export interface BenchmarkCaseResult {
  id: string;
  description?: string;
  expectedCount: number;
  runs: BenchmarkRunResult[];
  stableExpectations: string[];
  unstableExpectations: string[];
  passed: boolean;
}

export interface BenchmarkMetrics {
  caseCount: number;
  runCount: number;
  completedRuns: number;
  completionRate: number;
  expectedInstances: number;
  reportedFindings: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  casePassRate: number;
  negativeCasePassRate: number;
  stableDetectionRate: number;
  validationRate: number;
  attackPathRate: number;
  codeEvidenceRate: number;
  severityAccuracy: number;
  falsePositivesPerRun: number;
}

export interface BenchmarkThresholdResult {
  metric: keyof BenchmarkMetrics;
  comparator: ">=" | "<=";
  expected: number;
  actual: number;
  passed: boolean;
}

export interface BenchmarkReport {
  documentType: "copilot-security.benchmark";
  schemaVersion: "1.0";
  generatedAt: string;
  manifestPath: string;
  resultsDirectory: string;
  passed: boolean;
  metrics: BenchmarkMetrics;
  thresholds: BenchmarkThresholdResult[];
  cases: BenchmarkCaseResult[];
}

interface FindingLocation {
  path: string;
  startLine: number;
  endLine?: number;
}

interface BenchmarkFinding {
  id: string;
  cwe: string[];
  locations: FindingLocation[];
  severity: SeverityLevel | null;
  validationPresent: boolean;
  attackPathPresent: boolean;
  codeEvidencePresent: boolean;
}

interface CandidateMatch {
  expectedIndex: number;
  findingIndex: number;
  score: number;
}

export async function evaluateBenchmark(options: {
  manifestPath: string;
  resultsDirectory?: string;
  requireRunStatus?: boolean;
  now?: () => Date;
}): Promise<BenchmarkReport> {
  const manifestPath = resolve(options.manifestPath);
  const manifest = parseManifest(
    await readBoundedFile(
      manifestPath,
      MAX_MANIFEST_BYTES,
      "benchmark manifest",
    ),
    manifestPath,
  );
  const manifestDirectory = resolve(manifestPath, "..");
  const resultsDirectory = resolve(
    options.resultsDirectory ?? join(manifestDirectory, "results"),
  );
  const cases: BenchmarkCaseResult[] = [];

  for (const benchmarkCase of manifest.cases) {
    const paths = resultPaths(benchmarkCase, resultsDirectory);
    const runs: BenchmarkRunResult[] = [];
    for (let index = 0; index < paths.length; index += 1) {
      const findingsPath = isAbsolute(paths[index]!)
        ? resolve(paths[index]!)
        : resolve(resultsDirectory, paths[index]!);
      const runId = `${benchmarkCase.id}#${index + 1}`;
      try {
        await requireSuccessfulRunStatus(
          findingsPath,
          benchmarkCase.id,
          index + 1,
          options.requireRunStatus ?? false,
        );
        const findings = parseFindings(
          await readBoundedFile(
            findingsPath,
            MAX_FINDINGS_BYTES,
            `findings for benchmark case ${benchmarkCase.id}`,
          ),
          findingsPath,
        );
        runs.push(evaluateRun(benchmarkCase, runId, findingsPath, findings));
      } catch (error) {
        runs.push(failedRun(benchmarkCase, runId, findingsPath, error));
      }
    }
    const stableExpectations = benchmarkCase.expected
      .map((expectation) => expectation.id)
      .filter((id) =>
        runs.every((run) =>
          run.matches.some((match) => match.expectationId === id),
        ),
      );
    const unstableExpectations = benchmarkCase.expected
      .map((expectation) => expectation.id)
      .filter(
        (id) =>
          !stableExpectations.includes(id) &&
          runs.some((run) =>
            run.matches.some((match) => match.expectationId === id),
          ),
      );
    cases.push({
      id: benchmarkCase.id,
      ...(benchmarkCase.description === undefined
        ? {}
        : { description: benchmarkCase.description }),
      expectedCount: benchmarkCase.expected.length,
      runs,
      stableExpectations,
      unstableExpectations,
      passed: runs.every((run) => run.passed),
    });
  }

  const metrics = benchmarkMetrics(cases);
  const thresholds = evaluateThresholds(metrics, manifest.thresholds ?? {});
  return {
    documentType: "copilot-security.benchmark",
    schemaVersion: "1.0",
    generatedAt: (options.now ?? (() => new Date()))().toISOString(),
    manifestPath,
    resultsDirectory,
    passed:
      cases.every((benchmarkCase) => benchmarkCase.passed) &&
      thresholds.every((threshold) => threshold.passed),
    metrics,
    thresholds,
    cases,
  };
}

async function requireSuccessfulRunStatus(
  findingsPath: string,
  caseId: string,
  run: number,
  required: boolean,
): Promise<void> {
  const statusPath = `${dirname(findingsPath)}.status.json`;
  let contents: Buffer;
  try {
    contents = await readFile(statusPath);
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      if (!required) return;
      throw new CopilotSecurityError(
        `Missing run status for benchmark case ${caseId}: ${statusPath}.`,
        { cause: error },
      );
    }
    throw new CopilotSecurityError(
      `Could not read run status for benchmark case ${caseId}: ${statusPath}.`,
      { cause: error },
    );
  }
  if (contents.byteLength > MAX_STATUS_BYTES) {
    throw new CopilotSecurityError(
      `Run status for benchmark case ${caseId} exceeds the ${MAX_STATUS_BYTES}-byte limit: ${statusPath}.`,
    );
  }
  const status = parseJson(contents.toString("utf8"), statusPath);
  requireRecord(status, `Benchmark run status ${statusPath}`);
  if (status["caseId"] !== caseId || status["run"] !== run) {
    throw new CopilotSecurityError(
      `Benchmark run status does not match ${caseId} run ${run}: ${statusPath}.`,
    );
  }
  if (
    !Number.isSafeInteger(status["status"]) ||
    (status["status"] as number) !== 0
  ) {
    throw new CopilotSecurityError(
      `Benchmark scan process failed for ${caseId} run ${run}: ${statusPath}.`,
    );
  }
}

function evaluateRun(
  benchmarkCase: BenchmarkCase,
  id: string,
  findingsPath: string,
  findings: BenchmarkFinding[],
): BenchmarkRunResult {
  const candidates = benchmarkCase.expected.flatMap(
    (expectation, expectedIndex) =>
      findings.flatMap((finding, findingIndex) => {
        const score = matchScore(expectation, finding);
        return score === null
          ? []
          : [{ expectedIndex, findingIndex, score } satisfies CandidateMatch];
      }),
  );
  const matches = maximumCardinalityMatches(
    benchmarkCase.expected.length,
    findings.length,
    candidates,
  );
  const matchedExpected = new Set(matches.map((match) => match.expectedIndex));
  const matchedFindings = new Set(matches.map((match) => match.findingIndex));
  const renderedMatches = matches
    .map((match) => {
      const expectation = benchmarkCase.expected[match.expectedIndex]!;
      const finding = findings[match.findingIndex]!;
      return {
        expectationId: expectation.id,
        findingId: finding.id,
        score: match.score,
        validationPresent: finding.validationPresent,
        attackPathPresent: finding.attackPathPresent,
        codeEvidencePresent: finding.codeEvidencePresent,
        severityAccepted:
          expectation.acceptableSeverities === undefined
            ? null
            : finding.severity !== null &&
              expectation.acceptableSeverities.includes(finding.severity),
      };
    })
    .sort(
      (left, right) =>
        left.expectationId.localeCompare(right.expectationId) ||
        left.findingId.localeCompare(right.findingId),
    );
  const missedExpectations = benchmarkCase.expected
    .filter((_expectation, index) => !matchedExpected.has(index))
    .map((expectation) => expectation.id);
  const unexpectedFindings = findings
    .filter((_finding, index) => !matchedFindings.has(index))
    .map((finding) => finding.id);
  const qualityPassed = renderedMatches.every((match) => {
    const expectation = benchmarkCase.expected.find(
      (candidate) => candidate.id === match.expectationId,
    )!;
    return (
      (!expectation.requireValidation || match.validationPresent) &&
      (!expectation.requireAttackPath || match.attackPathPresent) &&
      (!expectation.requireCodeEvidence || match.codeEvidencePresent) &&
      match.severityAccepted !== false
    );
  });
  return {
    id,
    findingsPath,
    completed: true,
    expectedCount: benchmarkCase.expected.length,
    findingCount: findings.length,
    truePositives: renderedMatches.length,
    falsePositives: unexpectedFindings.length,
    falseNegatives: missedExpectations.length,
    passed:
      missedExpectations.length === 0 &&
      unexpectedFindings.length === 0 &&
      qualityPassed,
    matches: renderedMatches,
    missedExpectations,
    unexpectedFindings,
  };
}

function failedRun(
  benchmarkCase: BenchmarkCase,
  id: string,
  findingsPath: string,
  error: unknown,
): BenchmarkRunResult {
  return {
    id,
    findingsPath,
    completed: false,
    error: error instanceof Error ? error.message : String(error),
    expectedCount: benchmarkCase.expected.length,
    findingCount: 0,
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: benchmarkCase.expected.length,
    passed: false,
    matches: [],
    missedExpectations: benchmarkCase.expected.map(
      (expectation) => expectation.id,
    ),
    unexpectedFindings: [],
  };
}

function maximumCardinalityMatches(
  expectedCount: number,
  findingCount: number,
  candidates: CandidateMatch[],
): CandidateMatch[] {
  const byExpected = Array.from(
    { length: expectedCount },
    (): CandidateMatch[] => [],
  );
  for (const candidate of candidates) {
    byExpected[candidate.expectedIndex]!.push(candidate);
  }
  for (const options of byExpected) {
    options.sort(
      (left, right) =>
        right.score - left.score || left.findingIndex - right.findingIndex,
    );
  }
  const expectedOrder = Array.from(
    { length: expectedCount },
    (_unused, index) => index,
  ).sort(
    (left, right) =>
      byExpected[left]!.length - byExpected[right]!.length || left - right,
  );
  const findingAssignments = Array<number>(findingCount).fill(-1);

  const assign = (expectedIndex: number, visited: Set<number>): boolean => {
    for (const candidate of byExpected[expectedIndex]!) {
      if (visited.has(candidate.findingIndex)) continue;
      visited.add(candidate.findingIndex);
      const previous = findingAssignments[candidate.findingIndex]!;
      if (previous === -1 || assign(previous, visited)) {
        findingAssignments[candidate.findingIndex] = expectedIndex;
        return true;
      }
    }
    return false;
  };
  for (const expectedIndex of expectedOrder) assign(expectedIndex, new Set());

  return findingAssignments.flatMap((expectedIndex, findingIndex) => {
    if (expectedIndex === -1) return [];
    return [
      byExpected[expectedIndex]!.find(
        (candidate) => candidate.findingIndex === findingIndex,
      )!,
    ];
  });
}

function matchScore(
  expectation: BenchmarkFindingExpectation,
  finding: BenchmarkFinding,
): number | null {
  const sharedCwe = expectation.cwe.filter((cwe) =>
    finding.cwe.includes(normalizeCwe(cwe)),
  ).length;
  if (sharedCwe === 0) return null;
  let bestLocation = -1;
  for (const expected of expectation.locations) {
    for (const actual of finding.locations) {
      if (normalizePath(expected.path) !== normalizePath(actual.path)) continue;
      const expectedEnd = expected.endLine ?? expected.startLine;
      const actualEnd = actual.endLine ?? actual.startLine;
      const tolerance = expected.lineTolerance ?? DEFAULT_LINE_TOLERANCE;
      const distance =
        actual.startLine > expectedEnd
          ? actual.startLine - expectedEnd
          : expected.startLine > actualEnd
            ? expected.startLine - actualEnd
            : 0;
      if (distance > tolerance) continue;
      bestLocation = Math.max(bestLocation, 50 - distance);
    }
  }
  if (bestLocation < 0) return null;
  return 100 + sharedCwe * 10 + bestLocation;
}

function benchmarkMetrics(cases: BenchmarkCaseResult[]): BenchmarkMetrics {
  const runs = cases.flatMap((benchmarkCase) => benchmarkCase.runs);
  const truePositives = sum(runs.map((run) => run.truePositives));
  const falsePositives = sum(runs.map((run) => run.falsePositives));
  const falseNegatives = sum(runs.map((run) => run.falseNegatives));
  const expectedInstances = sum(runs.map((run) => run.expectedCount));
  const reportedFindings = sum(runs.map((run) => run.findingCount));
  const matches = runs.flatMap((run) => run.matches);
  const completedRuns = runs.filter((run) => run.completed).length;
  const severityMatches = matches.filter(
    (match) => match.severityAccepted !== null,
  );
  const negativeRuns = cases
    .filter((benchmarkCase) => benchmarkCase.expectedCount === 0)
    .flatMap((benchmarkCase) => benchmarkCase.runs);
  const positiveExpectations = sum(
    cases.map((benchmarkCase) => benchmarkCase.expectedCount),
  );
  const stableExpectations = sum(
    cases.map((benchmarkCase) => benchmarkCase.stableExpectations.length),
  );
  const precision = ratio(truePositives, truePositives + falsePositives, 1);
  const recall = ratio(truePositives, truePositives + falseNegatives, 1);
  return {
    caseCount: cases.length,
    runCount: runs.length,
    completedRuns,
    completionRate: ratio(completedRuns, runs.length, 1),
    expectedInstances,
    reportedFindings,
    truePositives,
    falsePositives,
    falseNegatives,
    precision,
    recall,
    f1:
      precision + recall === 0
        ? 0
        : (2 * precision * recall) / (precision + recall),
    casePassRate: ratio(
      cases.filter((benchmarkCase) => benchmarkCase.passed).length,
      cases.length,
      1,
    ),
    negativeCasePassRate: ratio(
      negativeRuns.filter((run) => run.completed && run.falsePositives === 0)
        .length,
      negativeRuns.length,
      1,
    ),
    stableDetectionRate: ratio(stableExpectations, positiveExpectations, 1),
    validationRate: ratio(
      matches.filter((match) => match.validationPresent).length,
      matches.length,
      1,
    ),
    attackPathRate: ratio(
      matches.filter((match) => match.attackPathPresent).length,
      matches.length,
      1,
    ),
    codeEvidenceRate: ratio(
      matches.filter((match) => match.codeEvidencePresent).length,
      matches.length,
      1,
    ),
    severityAccuracy: ratio(
      severityMatches.filter((match) => match.severityAccepted).length,
      severityMatches.length,
      1,
    ),
    falsePositivesPerRun: ratio(falsePositives, runs.length, 0),
  };
}

function evaluateThresholds(
  metrics: BenchmarkMetrics,
  configured: BenchmarkThresholds,
): BenchmarkThresholdResult[] {
  const minimums: Array<[keyof BenchmarkThresholds, keyof BenchmarkMetrics]> = [
    ["minCompletionRate", "completionRate"],
    ["minPrecision", "precision"],
    ["minRecall", "recall"],
    ["minF1", "f1"],
    ["minCasePassRate", "casePassRate"],
    ["minNegativeCasePassRate", "negativeCasePassRate"],
    ["minStableDetectionRate", "stableDetectionRate"],
    ["minValidationRate", "validationRate"],
    ["minAttackPathRate", "attackPathRate"],
    ["minCodeEvidenceRate", "codeEvidenceRate"],
    ["minSeverityAccuracy", "severityAccuracy"],
  ];
  const results: BenchmarkThresholdResult[] = minimums.flatMap(
    ([threshold, metric]) => {
      const expected = configured[threshold];
      if (expected === undefined) return [];
      return [
        {
          metric,
          comparator: ">=" as const,
          expected,
          actual: metrics[metric],
          passed: metrics[metric] >= expected,
        },
      ];
    },
  );
  if (configured.maxFalsePositivesPerRun !== undefined) {
    results.push({
      metric: "falsePositivesPerRun",
      comparator: "<=",
      expected: configured.maxFalsePositivesPerRun,
      actual: metrics.falsePositivesPerRun,
      passed:
        metrics.falsePositivesPerRun <= configured.maxFalsePositivesPerRun,
    });
  }
  return results;
}

function resultPaths(
  benchmarkCase: BenchmarkCase,
  _resultsDirectory: string,
): string[] {
  if (benchmarkCase.findingsPaths !== undefined)
    return [...benchmarkCase.findingsPaths];
  if (benchmarkCase.findingsPath !== undefined)
    return [benchmarkCase.findingsPath];
  return [join(benchmarkCase.id, "findings.json")];
}

function parseManifest(contents: string, path: string): BenchmarkManifest {
  const value = parseJson(contents, path);
  requireRecord(value, `Benchmark manifest ${path}`);
  if (value["schemaVersion"] !== "1.0") {
    throw new CopilotSecurityError(
      `Benchmark manifest ${path} must use schemaVersion 1.0.`,
    );
  }
  const rawCases = value["cases"];
  if (!Array.isArray(rawCases) || rawCases.length > MAX_CASES) {
    throw new CopilotSecurityError(
      `Benchmark manifest ${path} must contain at most ${MAX_CASES} cases.`,
    );
  }
  const ids = new Set<string>();
  const cases = rawCases.map((entry, index) => {
    requireRecord(entry, `Benchmark case ${index + 1}`);
    const id = requireIdentifier(entry["id"], `Benchmark case ${index + 1} id`);
    if (ids.has(id))
      throw new CopilotSecurityError(`Duplicate benchmark case id: ${id}.`);
    ids.add(id);
    const fixture = optionalString(entry["fixture"]);
    const findingsPath = optionalString(entry["findingsPath"]);
    const findingsPaths =
      entry["findingsPaths"] === undefined
        ? undefined
        : requireStringArray(
            entry["findingsPaths"],
            `Benchmark case ${id} findingsPaths`,
            MAX_RUNS_PER_CASE,
          );
    if (findingsPath !== undefined && findingsPaths !== undefined) {
      throw new CopilotSecurityError(
        `Benchmark case ${id} cannot set both findingsPath and findingsPaths.`,
      );
    }
    if (findingsPaths?.length === 0) {
      throw new CopilotSecurityError(
        `Benchmark case ${id} findingsPaths must not be empty.`,
      );
    }
    const rawExpected = entry["expected"];
    if (
      !Array.isArray(rawExpected) ||
      rawExpected.length > MAX_EXPECTATIONS_PER_CASE
    ) {
      throw new CopilotSecurityError(
        `Benchmark case ${id} must contain at most ${MAX_EXPECTATIONS_PER_CASE} expectations.`,
      );
    }
    const expectationIds = new Set<string>();
    const expected = rawExpected.map((candidate, expectedIndex) =>
      parseExpectation(candidate, id, expectedIndex, expectationIds),
    );
    return {
      id,
      ...(optionalString(entry["description"]) === undefined
        ? {}
        : { description: optionalString(entry["description"]) }),
      ...(fixture === undefined ? {} : { fixture }),
      ...(findingsPath === undefined ? {} : { findingsPath }),
      ...(findingsPaths === undefined ? {} : { findingsPaths }),
      expected,
    };
  });
  return {
    schemaVersion: "1.0",
    ...(value["thresholds"] === undefined
      ? {}
      : { thresholds: parseThresholds(value["thresholds"]) }),
    cases,
  };
}

function parseExpectation(
  value: unknown,
  caseId: string,
  index: number,
  ids: Set<string>,
): BenchmarkFindingExpectation {
  requireRecord(value, `Benchmark case ${caseId} expectation ${index + 1}`);
  const id = requireIdentifier(
    value["id"],
    `Benchmark case ${caseId} expectation ${index + 1} id`,
  );
  if (ids.has(id)) {
    throw new CopilotSecurityError(
      `Duplicate expectation id ${id} in benchmark case ${caseId}.`,
    );
  }
  ids.add(id);
  const cwe = requireStringArray(
    value["cwe"],
    `Benchmark expectation ${caseId}/${id} cwe`,
    100,
  ).map(normalizeCwe);
  if (cwe.length === 0 || cwe.some((entry) => !/^CWE-[1-9]\d*$/u.test(entry))) {
    throw new CopilotSecurityError(
      `Benchmark expectation ${caseId}/${id} must contain valid CWE identifiers.`,
    );
  }
  const locations = value["locations"];
  if (!Array.isArray(locations) || locations.length === 0) {
    throw new CopilotSecurityError(
      `Benchmark expectation ${caseId}/${id} must contain locations.`,
    );
  }
  const parsedLocations = locations.map((location, locationIndex) => {
    requireRecord(
      location,
      `Benchmark expectation ${caseId}/${id} location ${locationIndex + 1}`,
    );
    const path = optionalString(location["path"]);
    const startLine = positiveInteger(location["startLine"]);
    const endLine =
      location["endLine"] === undefined
        ? undefined
        : positiveInteger(location["endLine"]);
    const lineTolerance =
      location["lineTolerance"] === undefined
        ? undefined
        : nonnegativeInteger(location["lineTolerance"]);
    if (
      path === undefined ||
      startLine === null ||
      endLine === null ||
      lineTolerance === null ||
      (endLine !== undefined && endLine < startLine)
    ) {
      throw new CopilotSecurityError(
        `Benchmark expectation ${caseId}/${id} contains an invalid location.`,
      );
    }
    return {
      path,
      startLine,
      ...(endLine === undefined ? {} : { endLine }),
      ...(lineTolerance === undefined ? {} : { lineTolerance }),
    };
  });
  const acceptableSeverities =
    value["acceptableSeverities"] === undefined
      ? undefined
      : requireSeverityArray(
          value["acceptableSeverities"],
          `Benchmark expectation ${caseId}/${id} acceptableSeverities`,
        );
  return {
    id,
    cwe,
    locations: parsedLocations,
    ...(acceptableSeverities === undefined ? {} : { acceptableSeverities }),
    requireValidation: value["requireValidation"] === true,
    requireAttackPath: value["requireAttackPath"] === true,
    requireCodeEvidence: value["requireCodeEvidence"] === true,
  };
}

function parseThresholds(value: unknown): BenchmarkThresholds {
  requireRecord(value, "Benchmark thresholds");
  const thresholds: BenchmarkThresholds = {};
  for (const name of [
    "minCompletionRate",
    "minPrecision",
    "minRecall",
    "minF1",
    "minCasePassRate",
    "minNegativeCasePassRate",
    "minStableDetectionRate",
    "minValidationRate",
    "minAttackPathRate",
    "minCodeEvidenceRate",
    "minSeverityAccuracy",
  ] as const) {
    if (value[name] === undefined) continue;
    const threshold = unitInterval(value[name]);
    if (threshold === null)
      throw new CopilotSecurityError(`${name} must be between 0 and 1.`);
    thresholds[name] = threshold;
  }
  if (value["maxFalsePositivesPerRun"] !== undefined) {
    const threshold = nonnegativeNumber(value["maxFalsePositivesPerRun"]);
    if (threshold === null) {
      throw new CopilotSecurityError(
        "maxFalsePositivesPerRun must be a nonnegative number.",
      );
    }
    thresholds.maxFalsePositivesPerRun = threshold;
  }
  return thresholds;
}

function parseFindings(contents: string, path: string): BenchmarkFinding[] {
  const value = parseJson(contents, path);
  requireRecord(value, `Findings document ${path}`);
  const findings = value["findings"];
  if (!Array.isArray(findings)) {
    throw new CopilotSecurityError(
      `Findings document ${path} must contain a findings array.`,
    );
  }
  return findings.map((finding, index) => {
    requireRecord(finding, `Finding ${index + 1} in ${path}`);
    const taxonomy = finding["taxonomy"];
    const severity = finding["severity"];
    const locations = finding["locations"];
    requireRecord(taxonomy, `Finding ${index + 1} taxonomy in ${path}`);
    const cwe = Array.isArray(taxonomy["cwe"])
      ? taxonomy["cwe"]
          .filter((entry): entry is string => typeof entry === "string")
          .map(normalizeCwe)
      : [];
    const parsedLocations = Array.isArray(locations)
      ? locations.flatMap((location) => {
          if (!isRecord(location)) return [];
          const locationPath = optionalString(location["path"]);
          const startLine = positiveInteger(location["startLine"]);
          const endLine =
            location["endLine"] === undefined
              ? undefined
              : positiveInteger(location["endLine"]);
          if (
            locationPath === undefined ||
            startLine === null ||
            endLine === null
          ) {
            return [];
          }
          return [
            {
              path: locationPath,
              startLine,
              ...(endLine === undefined ? {} : { endLine }),
            },
          ];
        })
      : [];
    const findingId =
      optionalString(finding["occurrenceId"]) ??
      optionalString(finding["findingId"]) ??
      `finding-${index + 1}`;
    return {
      id: findingId,
      cwe,
      locations: parsedLocations,
      severity:
        isRecord(severity) && isSeverity(severity["level"])
          ? severity["level"]
          : null,
      validationPresent: isNonemptyRecord(finding["validation"]),
      attackPathPresent: isNonemptyRecord(finding["attackPath"]),
      codeEvidencePresent:
        Array.isArray(finding["codeEvidence"]) &&
        finding["codeEvidence"].some(
          (evidence) =>
            isRecord(evidence) &&
            optionalString(evidence["code"]) !== undefined &&
            optionalString(evidence["explanation"]) !== undefined,
        ),
    };
  });
}

async function readBoundedFile(
  path: string,
  maxBytes: number,
  label: string,
): Promise<string> {
  const contents = await readFile(path).catch((error: unknown) => {
    throw new CopilotSecurityError(`Could not read ${label}: ${path}.`, {
      cause: error,
    });
  });
  if (contents.byteLength > maxBytes) {
    throw new CopilotSecurityError(
      `${label} exceeds the ${maxBytes}-byte limit: ${path}.`,
    );
  }
  return contents.toString("utf8");
}

function parseJson(contents: string, path: string): unknown {
  try {
    return JSON.parse(contents);
  } catch (error) {
    throw new CopilotSecurityError(`Invalid JSON in ${path}.`, {
      cause: error,
    });
  }
}

function requireRecord(
  value: unknown,
  label: string,
): asserts value is Record<string, unknown> {
  if (!isRecord(value))
    throw new CopilotSecurityError(`${label} must be an object.`);
}

function requireIdentifier(value: unknown, label: string): string {
  const candidate = optionalString(value);
  if (
    candidate === undefined ||
    candidate.length > 128 ||
    !/^[a-z0-9][a-z0-9._-]*$/u.test(candidate)
  ) {
    throw new CopilotSecurityError(
      `${label} must be a lowercase identifier of at most 128 characters.`,
    );
  }
  return candidate;
}

function requireStringArray(
  value: unknown,
  label: string,
  maxLength: number,
): string[] {
  if (
    !Array.isArray(value) ||
    value.length > maxLength ||
    value.some((entry) => optionalString(entry) === undefined)
  ) {
    throw new CopilotSecurityError(
      `${label} must be an array of at most ${maxLength} nonempty strings.`,
    );
  }
  return value.map((entry) => (entry as string).trim());
}

function requireSeverityArray(value: unknown, label: string): SeverityLevel[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((entry) => !isSeverity(entry))
  ) {
    throw new CopilotSecurityError(`${label} must contain severity levels.`);
  }
  return value as SeverityLevel[];
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

function positiveInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) > 0
    ? Number(value)
    : null;
}

function nonnegativeInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 0
    ? Number(value)
    : null;
}

function nonnegativeNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : null;
}

function unitInterval(value: unknown): number | null {
  const candidate = nonnegativeNumber(value);
  return candidate !== null && candidate <= 1 ? candidate : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonemptyRecord(value: unknown): boolean {
  return isRecord(value) && Object.keys(value).length > 0;
}

function isSeverity(value: unknown): value is SeverityLevel {
  return ["critical", "high", "medium", "low", "informational"].includes(
    String(value),
  );
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\/+/u, "");
}

function normalizeCwe(value: string): string {
  return value.trim().toUpperCase();
}

function sum(values: number[]): number {
  return values.reduce((total, value) => total + value, 0);
}

function ratio(numerator: number, denominator: number, empty: number): number {
  return denominator === 0 ? empty : numerator / denominator;
}
