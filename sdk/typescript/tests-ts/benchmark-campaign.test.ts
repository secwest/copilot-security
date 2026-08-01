import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BENCHMARK_CAMPAIGN_FILENAME,
  createBenchmarkAttemptOutput,
  createBenchmarkCampaign,
  ensureBenchmarkCampaign,
  preserveBenchmarkAttempt,
  promoteBenchmarkAttemptOutput,
  readBenchmarkCampaign,
  readBenchmarkReceiptAttempt,
  readSuccessfulBenchmarkReceipt,
  sha256Directory,
  sha256ScannerPackage,
  writeBenchmarkReceipt,
  writeBenchmarkTextAtomic,
  type BenchmarkCampaignDocument,
  type BenchmarkRunReceipt,
} from "../src/benchmark-campaign.js";
import { evaluateBenchmark } from "../src/benchmark.js";

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("benchmark campaign integrity", () => {
  test("separates corpus, scan-policy, scanner, runner, and authentication identities", () => {
    const base = campaign();
    const recreated = campaign({ createdAt: "2030-01-02T00:00:00.000Z" });
    expect(recreated.campaignId).toBe(base.campaignId);
    expect(recreated.corpusId).toBe(base.corpusId);
    expect(recreated.scanPolicyId).toBe(base.scanPolicyId);
    expect(recreated.comparisonPolicyId).toBe(base.comparisonPolicyId);

    const changedFixture = campaign({ fixtureSha256: hex("9") });
    expect(changedFixture.corpusId).not.toBe(base.corpusId);
    expect(changedFixture.scanPolicyId).toBe(base.scanPolicyId);
    expect(changedFixture.comparisonPolicyId).toBe(base.comparisonPolicyId);
    expect(changedFixture.campaignId).not.toBe(base.campaignId);

    const changedModel = campaign({ model: "different-model" });
    expect(changedModel.corpusId).toBe(base.corpusId);
    expect(changedModel.scanPolicyId).not.toBe(base.scanPolicyId);
    expect(changedModel.comparisonPolicyId).toBe(base.comparisonPolicyId);
    expect(changedModel.campaignId).not.toBe(base.campaignId);

    const changedEffort = campaign({ effort: "xhigh" });
    expect(changedEffort.scanPolicyId).not.toBe(base.scanPolicyId);
    expect(changedEffort.comparisonPolicyId).not.toBe(base.comparisonPolicyId);
    expect(changedEffort.campaignId).not.toBe(base.campaignId);

    const changedScanner = campaign({ packageSha256: hex("8") });
    expect(changedScanner.corpusId).toBe(base.corpusId);
    expect(changedScanner.scanPolicyId).toBe(base.scanPolicyId);
    expect(changedScanner.comparisonPolicyId).toBe(base.comparisonPolicyId);
    expect(changedScanner.campaignId).not.toBe(base.campaignId);

    const changedRunner = campaign({ runnerSha256: hex("7") });
    expect(changedRunner.campaignId).not.toBe(base.campaignId);

    const changedAuthentication = campaign({ auth: "token" });
    expect(changedAuthentication.scanPolicyId).toBe(base.scanPolicyId);
    expect(changedAuthentication.comparisonPolicyId).toBe(
      base.comparisonPolicyId,
    );
    expect(changedAuthentication.campaignId).not.toBe(base.campaignId);
  });

  test("creates an immutable campaign lock and refuses unprovenanced or mixed results", async () => {
    const empty = await temporaryDirectory("campaign-empty-");
    const expected = campaign();
    expect(await ensureBenchmarkCampaign(empty, expected)).toEqual(expected);
    expect(await readBenchmarkCampaign(empty)).toEqual(expected);

    const sameIdentity = campaign({
      createdAt: "2035-01-01T00:00:00.000Z",
    });
    const resumed = await ensureBenchmarkCampaign(empty, sameIdentity);
    expect(resumed.createdAt).toBe(expected.createdAt);

    await expect(
      ensureBenchmarkCampaign(empty, campaign({ model: "other" })),
    ).rejects.toThrow("Benchmark campaign mismatch");

    const occupied = await temporaryDirectory("campaign-occupied-");
    await writeFile(join(occupied, "findings.json"), "{}\n");
    await expect(ensureBenchmarkCampaign(occupied, expected)).rejects.toThrow(
      `without ${BENCHMARK_CAMPAIGN_FILENAME}`,
    );
  });

  test("detects a campaign lock whose identity was edited", async () => {
    const root = await temporaryDirectory("campaign-tamper-");
    const expected = campaign();
    await ensureBenchmarkCampaign(root, expected);
    const path = join(root, BENCHMARK_CAMPAIGN_FILENAME);
    const document = JSON.parse(await readFile(path, "utf8"));
    document.scan.model = "tampered-model";
    await writeFile(path, `${JSON.stringify(document)}\n`);

    await expect(readBenchmarkCampaign(root)).rejects.toThrow(
      "identity does not match its contents",
    );
  });

  test("reads a legacy model-bound campaign without inventing cross-provider comparability", async () => {
    const root = await temporaryDirectory("campaign-legacy-");
    const path = join(root, BENCHMARK_CAMPAIGN_FILENAME);
    const legacy = legacyCampaign(campaign());
    await writeFile(path, `${JSON.stringify(legacy)}\n`);

    expect(await readBenchmarkCampaign(root)).toEqual(legacy);
    expect(legacy.schemaVersion).toBe("1.0");
    expect(legacy.comparisonPolicyId).toBeUndefined();
  });

  test("requires a successful campaign-bound sealed-artifact receipt", async () => {
    const root = await temporaryDirectory("campaign-receipt-");
    const path = join(root, "run.status.json");
    const expected = campaign();
    const receipt = runReceipt(expected);
    await writeBenchmarkReceipt(path, receipt);

    expect(await readBenchmarkReceiptAttempt(path)).toBe(3);
    expect(
      await readSuccessfulBenchmarkReceipt(path, {
        campaignId: expected.campaignId,
        caseId: "case-one",
        run: 1,
      }),
    ).toEqual(receipt);
    await expect(
      readSuccessfulBenchmarkReceipt(path, {
        campaignId: hex("f"),
        caseId: "case-one",
        run: 1,
      }),
    ).rejects.toThrow("does not match");

    await rm(path);
    await writeBenchmarkReceipt(path, {
      ...receipt,
      status: 1,
      artifacts: undefined,
      error: "scanner failed",
    });
    await expect(
      readSuccessfulBenchmarkReceipt(path, {
        campaignId: expected.campaignId,
        caseId: "case-one",
        run: 1,
      }),
    ).rejects.toThrow("not a completed sealed scan");
  });

  test("atomically replaces benchmark evaluation artifacts without staging debris", async () => {
    const root = await temporaryDirectory("campaign-atomic-report-");
    const path = join(root, "benchmark-report.json");
    await writeFile(path, "stale\n");

    await writeBenchmarkTextAtomic(path, '{"passed":false}\n');

    expect(await readFile(path, "utf8")).toBe('{"passed":false}\n');
    expect((await readdir(root)).sort()).toEqual(["benchmark-report.json"]);
  });

  test("preserves partial output and its receipt before a retry", async () => {
    const results = await temporaryDirectory("campaign-preserve-");
    const output = join(results, "case-one", "run-1");
    const status = `${output}.status.json`;
    await mkdir(output, { recursive: true });
    await writeFile(join(output, "partial.txt"), "diagnostic\n");
    await writeFile(status, '{"status":1}\n');

    const archived = await preserveBenchmarkAttempt({
      resultsDirectory: results,
      caseId: "case-one",
      run: 1,
      attempt: 2,
      outputDirectory: output,
      statusPath: status,
    });
    expect(archived).not.toBeNull();
    expect(
      await readFile(join(archived!, "output", "partial.txt"), "utf8"),
    ).toBe("diagnostic\n");
    expect(await readFile(join(archived!, "status.json"), "utf8")).toBe(
      '{"status":1}\n',
    );
    expect(
      await preserveBenchmarkAttempt({
        resultsDirectory: results,
        caseId: "case-one",
        run: 1,
        attempt: 3,
        outputDirectory: output,
        statusPath: status,
      }),
    ).toBeNull();
  });

  test("gives every scanner invocation a fresh path before canonical promotion", async () => {
    const results = await temporaryDirectory("campaign-staging-");
    const output = join(results, "case-one", "run-1");
    const first = await createBenchmarkAttemptOutput({
      resultsDirectory: results,
      outputDirectory: output,
      attempt: 1,
    });
    const second = await createBenchmarkAttemptOutput({
      resultsDirectory: results,
      outputDirectory: output,
      attempt: 2,
    });
    expect(first).not.toBe(second);
    expect(first).not.toBe(output);
    expect(second).not.toBe(output);
    await writeFile(join(first, "partial.txt"), "first\n");
    await writeFile(join(second, "findings.json"), "{}\n");
    await rm(first, { recursive: true });
    await promoteBenchmarkAttemptOutput({
      resultsDirectory: results,
      attemptOutputDirectory: second,
      outputDirectory: output,
    });
    expect(await readFile(join(output, "findings.json"), "utf8")).toBe("{}\n");
    await expect(
      createBenchmarkAttemptOutput({
        resultsDirectory: results,
        outputDirectory: join(results, "..", "escaped"),
        attempt: 3,
      }),
    ).rejects.toThrow("escapes its campaign directory");
  });

  test("hashes fixture contents and the effective scanner package deterministically", async () => {
    const first = await temporaryDirectory("campaign-digest-a-");
    const second = await temporaryDirectory("campaign-digest-b-");
    for (const root of [first, second]) {
      await mkdir(join(root, "nested"));
      await writeFile(join(root, "nested", "b.txt"), "bravo\n");
      await writeFile(join(root, "a.txt"), "alpha\n");
    }
    expect(await sha256Directory(first)).toBe(await sha256Directory(second));
    await writeFile(join(second, "nested", "b.txt"), "changed\n");
    expect(await sha256Directory(first)).not.toBe(
      await sha256Directory(second),
    );

    const scanner = await temporaryDirectory("campaign-scanner-");
    for (const directory of ["bin", "dist", "_bundled_plugin"]) {
      await mkdir(join(scanner, directory));
      await writeFile(join(scanner, directory, "entry.js"), `${directory}\n`);
    }
    await writeFile(join(scanner, "package.json"), '{"name":"scanner"}\n');
    await writeFile(join(scanner, "pnpm-lock.yaml"), "lockfileVersion: 1\n");
    const before = await sha256ScannerPackage(scanner);
    await writeFile(
      join(scanner, "_bundled_plugin", "entry.js"),
      "changed policy\n",
    );
    expect(await sha256ScannerPackage(scanner)).not.toBe(before);
  });

  test("binds benchmark evaluation to the campaign recorded in each run receipt", async () => {
    const root = await temporaryDirectory("campaign-evaluator-");
    const manifestPath = join(root, "manifest.json");
    const results = join(root, "results");
    const findingsPath = join(results, "case-one", "run-1", "findings.json");
    const statusPath = join(results, "case-one", "run-1.status.json");
    const expected = campaign();
    await ensureBenchmarkCampaign(results, expected);
    await mkdir(join(results, "case-one", "run-1"), { recursive: true });
    await writeFile(
      manifestPath,
      `${JSON.stringify({
        schemaVersion: "1.0",
        cases: [
          {
            id: "case-one",
            findingsPaths: ["case-one/run-1/findings.json"],
            expected: [],
          },
        ],
      })}\n`,
    );
    await writeFile(findingsPath, `${JSON.stringify({ findings: [] })}\n`);
    await writeBenchmarkReceipt(statusPath, {
      ...runReceipt(expected),
      campaignId: hex("f"),
    });

    const mismatched = await evaluateBenchmark({
      manifestPath,
      resultsDirectory: results,
      requireRunStatus: true,
    });
    expect(mismatched.metrics.completedRuns).toBe(0);
    expect(mismatched.cases[0]?.runs[0]?.error).toContain(
      "belongs to a different campaign",
    );

    await rm(statusPath);
    await writeBenchmarkReceipt(statusPath, runReceipt(expected));
    const matched = await evaluateBenchmark({
      manifestPath,
      resultsDirectory: results,
      requireRunStatus: true,
    });
    expect(matched.passed).toBe(true);
    expect(matched.metrics.completedRuns).toBe(1);
    expect(matched.campaign?.campaignId).toBe(expected.campaignId);
  });
});

function campaign(
  overrides: {
    auth?: BenchmarkCampaignDocument["scan"]["auth"];
    createdAt?: string;
    fixtureSha256?: string;
    effort?: BenchmarkCampaignDocument["scan"]["effort"];
    model?: string;
    packageSha256?: string;
    runnerSha256?: string;
  } = {},
): BenchmarkCampaignDocument {
  return createBenchmarkCampaign({
    createdAt: overrides.createdAt ?? "2030-01-01T00:00:00.000Z",
    manifestPath: join(tmpdir(), "manifest.json"),
    manifestSha256: hex("a"),
    repositoryRevision: "0123456789abcdef",
    runnerSha256: overrides.runnerSha256 ?? hex("b"),
    runtime: { node: "v24.0.0", platform: "win32", arch: "x64" },
    scanner: {
      cliPath: join(tmpdir(), "scanner.mjs"),
      cliSha256: hex("c"),
      packageSha256: overrides.packageSha256 ?? hex("d"),
      label: "candidate",
    },
    selection: {
      caseIds: ["case-one"],
      findingsPathsByCase: {
        "case-one": ["case-one/run-1/findings.json"],
      },
      fixtureSha256ByCase: {
        "case-one": overrides.fixtureSha256 ?? hex("e"),
      },
    },
    scan: {
      auth: overrides.auth ?? "github",
      mode: "deep",
      model: overrides.model ?? "gpt-test",
      effort: overrides.effort ?? "high",
    },
  });
}

function legacyCampaign(
  current: BenchmarkCampaignDocument,
): BenchmarkCampaignDocument {
  const legacy = structuredClone(current);
  legacy.schemaVersion = "1.0";
  delete legacy.comparisonPolicyId;
  legacy.campaignId = identityDigest({
    schemaVersion: "1.0",
    corpusId: legacy.corpusId,
    scanPolicyId: legacy.scanPolicyId,
    scanner: {
      cliSha256: legacy.scanner.cliSha256,
      packageSha256: legacy.scanner.packageSha256,
      label: legacy.scanner.label,
    },
    auth: legacy.scan.auth,
    repositoryRevision: legacy.source.repositoryRevision,
    runnerSha256: legacy.source.runnerSha256,
    runtime: legacy.source.runtime,
  });
  return legacy;
}

function identityDigest(value: unknown): string {
  return createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right, "en"))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function runReceipt(
  campaignDocument: BenchmarkCampaignDocument,
): BenchmarkRunReceipt {
  return {
    documentType: "copilot-security.benchmark-run",
    schemaVersion: "1.0",
    campaignId: campaignDocument.campaignId,
    caseId: "case-one",
    run: 1,
    attempt: 3,
    status: 0,
    signal: null,
    timedOut: false,
    startedAt: "2030-01-01T00:00:00.000Z",
    completedAt: "2030-01-01T00:01:00.000Z",
    durationMs: 60_000,
    scanner: campaignDocument.scanner,
    scan: campaignDocument.scan,
    fixture: {
      sha256: campaignDocument.selection.fixtureSha256ByCase["case-one"]!,
      repositoryRevision: "fedcba9876543210",
    },
    artifacts: {
      scanId: "scan-one",
      findingsSha256: hex("1"),
      coverageSha256: hex("2"),
      manifestSha256: hex("3"),
    },
  };
}

function hex(character: string): string {
  return character.repeat(64);
}

async function temporaryDirectory(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  temporaryPaths.push(path);
  return path;
}
