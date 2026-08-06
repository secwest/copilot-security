import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
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
  BENCHMARK_RUNNER_LOCK_ARCHIVE_DIRECTORY,
  BENCHMARK_RUNNER_LOCK_FILENAME,
  BENCHMARK_CAMPAIGN_FILENAME,
  acquireBenchmarkRunnerLock,
  createBenchmarkAttemptOutput,
  createBenchmarkCampaign,
  ensureBenchmarkCampaign,
  nextBenchmarkAttemptArchiveSlot,
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
      await nextBenchmarkAttemptArchiveSlot({
        resultsDirectory: results,
        caseId: "case-one",
        run: 1,
        startingAt: 2,
      }),
    ).toBe(3);
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
    const repositoryFixture = await temporaryDirectory("campaign-git-fixture-");
    await mkdir(join(repositoryFixture, ".GiT"));
    await writeFile(join(repositoryFixture, ".GiT", "config"), "[core]\n");
    await expect(sha256Directory(repositoryFixture)).rejects.toThrow(
      "must not contain Git repository metadata",
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
    const runDirectory = join(results, "case-one", "run-1");
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
    const findingsBytes = Buffer.from(
      `${JSON.stringify({ scanId: "scan-one", findings: [] })}\n`,
    );
    const coverageBytes = Buffer.from('{"scanId":"scan-one"}\n');
    const scanManifestBytes = Buffer.from('{"scan":{"id":"scan-one"}}\n');
    await writeFile(findingsPath, findingsBytes);
    await writeFile(join(runDirectory, "coverage.json"), coverageBytes);
    await writeFile(
      join(runDirectory, "scan-manifest.json"),
      scanManifestBytes,
    );
    const receipt = {
      ...runReceipt(expected),
      artifacts: {
        scanId: "scan-one",
        findingsSha256: createHash("sha256")
          .update(findingsBytes)
          .digest("hex"),
        coverageSha256: createHash("sha256")
          .update(coverageBytes)
          .digest("hex"),
        manifestSha256: createHash("sha256")
          .update(scanManifestBytes)
          .digest("hex"),
      },
    };
    await writeBenchmarkReceipt(statusPath, {
      ...receipt,
      campaignId: hex("f"),
    });

    const mismatched = await evaluateBenchmark({
      manifestPath,
      resultsDirectory: results,
      requireRunStatus: true,
    });
    expect(mismatched.metrics.completedRuns).toBe(0);
    expect(mismatched.cases[0]?.runs[0]?.error).toContain(
      "does not match case-one run 1",
    );

    await rm(statusPath);
    await writeBenchmarkReceipt(statusPath, receipt);
    const matched = await evaluateBenchmark({
      manifestPath,
      resultsDirectory: results,
      requireRunStatus: true,
    });
    expect(matched.passed).toBe(true);
    expect(matched.metrics.completedRuns).toBe(1);
    expect(matched.campaign?.campaignId).toBe(expected.campaignId);

    await writeBenchmarkReceipt(statusPath, {
      ...receipt,
      fixture: { ...receipt.fixture, sha256: hex("9") },
    });
    const wrongFixture = await evaluateBenchmark({
      manifestPath,
      resultsDirectory: results,
      requireRunStatus: true,
    });
    expect(wrongFixture.metrics.completedRuns).toBe(0);
    expect(wrongFixture.cases[0]?.runs[0]?.error).toContain(
      "policy or fixture does not match its campaign",
    );

    await writeBenchmarkReceipt(statusPath, receipt);
    await writeFile(
      findingsPath,
      Buffer.concat([findingsBytes, Buffer.from(" ")]),
    );
    const tampered = await evaluateBenchmark({
      manifestPath,
      resultsDirectory: results,
      requireRunStatus: true,
    });
    expect(tampered.metrics.completedRuns).toBe(0);
    expect(tampered.cases[0]?.runs[0]?.error).toContain(
      "receipt artifact findingsSha256 does not match",
    );
  });
});

describe("benchmark runner lock", () => {
  test("refuses a live owner and permits a new owner after release", async () => {
    const root = await temporaryDirectory("benchmark-runner-lock-live-");
    const first = await acquireBenchmarkRunnerLock(root);

    await expect(acquireBenchmarkRunnerLock(root)).rejects.toThrow(
      `Another benchmark runner is active for ${root}`,
    );
    const owner = JSON.parse(
      await readFile(join(root, BENCHMARK_RUNNER_LOCK_FILENAME), "utf8"),
    );
    expect(owner.pid).toBe(process.pid);
    expect(owner.token).toBe(first.token);

    await first.release();
    const second = await acquireBenchmarkRunnerLock(root);
    expect(second.token).not.toBe(first.token);
    await second.release();
  });

  test("archives a dead owner and permits campaign creation with operational lock entries", async () => {
    const root = await temporaryDirectory("benchmark-runner-lock-stale-");
    const completed = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
    expect(completed.status).toBe(0);
    expect(completed.pid).toBeGreaterThan(0);
    await writeFile(
      join(root, BENCHMARK_RUNNER_LOCK_FILENAME),
      `${JSON.stringify({
        documentType: "copilot-security.benchmark-runner-lock",
        schemaVersion: "1.0",
        pid: completed.pid,
        token: "a".repeat(32),
        startedAt: "2030-01-02T03:04:05.000Z",
      })}\n`,
    );

    const lock = await acquireBenchmarkRunnerLock(root);
    expect(
      await readdir(join(root, BENCHMARK_RUNNER_LOCK_ARCHIVE_DIRECTORY)),
    ).toEqual([
      `stale-2030-01-02T03-04-05-000Z-${completed.pid}-${"a".repeat(32)}.json`,
    ]);
    expect(await ensureBenchmarkCampaign(root, campaign())).toEqual(campaign());
    await lock.release();
  });

  test("fails closed on malformed ownership evidence", async () => {
    const root = await temporaryDirectory("benchmark-runner-lock-invalid-");
    const path = join(root, BENCHMARK_RUNNER_LOCK_FILENAME);
    await writeFile(path, "{}\n");

    await expect(acquireBenchmarkRunnerLock(root)).rejects.toThrow(
      "Invalid benchmark runner lock",
    );
    expect(await readFile(path, "utf8")).toBe("{}\n");
    await expect(ensureBenchmarkCampaign(root, campaign())).rejects.toThrow(
      `without ${BENCHMARK_CAMPAIGN_FILENAME}`,
    );
  });

  test("rejects an archive lookalike before recovering a dead owner", async () => {
    const root = await temporaryDirectory("benchmark-runner-lock-archive-");
    const completed = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
    expect(completed.status).toBe(0);
    await writeFile(
      join(root, BENCHMARK_RUNNER_LOCK_FILENAME),
      `${JSON.stringify({
        documentType: "copilot-security.benchmark-runner-lock",
        schemaVersion: "1.0",
        pid: completed.pid,
        token: "c".repeat(32),
        startedAt: "2030-02-03T04:05:06.000Z",
      })}\n`,
    );
    await writeFile(
      join(root, BENCHMARK_RUNNER_LOCK_ARCHIVE_DIRECTORY),
      "not a directory\n",
    );

    await expect(acquireBenchmarkRunnerLock(root)).rejects.toThrow(
      "Benchmark runner lock archive is not a regular directory",
    );
    await expect(ensureBenchmarkCampaign(root, campaign())).rejects.toThrow(
      `without ${BENCHMARK_CAMPAIGN_FILENAME}`,
    );
  });

  test("does not remove a lock whose ownership token changed", async () => {
    const root = await temporaryDirectory("benchmark-runner-lock-token-");
    const lock = await acquireBenchmarkRunnerLock(root);
    const path = join(root, BENCHMARK_RUNNER_LOCK_FILENAME);
    const replacement = `${JSON.stringify({
      documentType: "copilot-security.benchmark-runner-lock",
      schemaVersion: "1.0",
      pid: process.pid,
      token: "b".repeat(32),
      startedAt: new Date().toISOString(),
    })}\n`;
    await writeFile(path, replacement);

    await lock.release();
    expect(await readFile(path, "utf8")).toBe(replacement);
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
