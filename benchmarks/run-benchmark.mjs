#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, constants, writeFileSync } from "node:fs";
import { cp, lstat, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";
import {
  acquireBenchmarkRunnerLock,
  createBenchmarkAttemptOutput,
  createBenchmarkCampaign,
  ensureBenchmarkCampaign,
  nextBenchmarkAttemptArchiveSlot,
  preserveBenchmarkAttempt,
  promoteBenchmarkAttemptOutput,
  readBenchmarkReceiptAttempt,
  readSuccessfulBenchmarkReceipt,
  requireFreshTypeScriptBuild,
  sha256Directory,
  sha256File,
  sha256ScannerPackage,
  writeBenchmarkReceipt,
  writeBenchmarkTextAtomic,
} from "../sdk/typescript/dist/benchmark-campaign.js";
import { createBestEffortWriter } from "./best-effort-output.mjs";
import { rejectGitControlPath } from "./fixture-security.mjs";
import {
  benchmarkFindingsPaths,
  buildBenchmarkSelection,
  selectBenchmarkCases,
} from "../sdk/typescript/dist/benchmark-selection.js";
import { loadContract } from "../sdk/typescript/dist/contract.js";

const runnerPath = fileURLToPath(import.meta.url);
const benchmarkRoot = dirname(runnerPath);
const repositoryRoot = resolve(benchmarkRoot, "..");
const pluginRoot = join(repositoryRoot, "sdk", "typescript", "_bundled_plugin");
const defaultCli = join(
  repositoryRoot,
  "sdk",
  "typescript",
  "bin",
  "copilot-security.mjs",
);
const MAX_BENCHMARK_MANIFEST_BYTES = 4 * 1024 * 1024;
const writeStandardOutput = createBestEffortWriter(process.stdout);
const writeDiagnostic = createBestEffortWriter(process.stderr);

if (process.argv.slice(2).includes("--help")) {
  process.stdout
    .write(`Usage: node benchmarks/run-benchmark.mjs --results-dir DIR [options]

Options:
  --manifest PATH          Benchmark manifest (default: benchmarks/manifest.json)
  --case ID                Select a case; repeatable
  --runs N                 Limit repetitions per selected case
  --selection-only         Evaluate only the selected cases and runs
  --scanner-cli PATH       Compatible Node scanner entrypoint
  --scanner-label NAME     Provenance label for the scanner
  --auth SOURCE            auto, github, or token
  --model MODEL            Scanner model
  --effort LEVEL           low, medium, high, or xhigh
  --mode MODE              standard or deep (default: deep)
  --max-ai-credits N       Optional per-scan credit bound, minimum 30
  --workers N              Concurrent case/runs, 1-8 (default: 1)
  --max-attempts N         Fresh attempts per invocation, 1-10 (default: 2)
  --scan-timeout-ms N      Outer process-tree deadline, minimum 60000
  --finalize-only          Rebuild reports from existing receipts; never scan
  --force                  Preserve and rerun already completed selected runs
  --help                   Show this help
`);
  process.exit(0);
}

const options = parseArguments(process.argv.slice(2));
const manifestPath = resolve(
  options.manifest ?? join(benchmarkRoot, "manifest.json"),
);
const manifestDirectory = dirname(manifestPath);
const resultsDirectory = resolve(options.resultsDirectory);
const scannerCli = resolve(options.scannerCli ?? defaultCli);
const scannerPackageRoot = resolve(dirname(scannerCli), "..");
requireOutsideRepository(resultsDirectory);
await requireRegularFile(scannerCli, "Scanner CLI");
await requireFreshTypeScriptBuild(
  join(repositoryRoot, "sdk", "typescript", "src"),
  join(repositoryRoot, "sdk", "typescript", "dist"),
);
const benchmarkRunnerLock = await acquireBenchmarkRunnerLock(resultsDirectory);
process.once("exit", () => benchmarkRunnerLock.releaseSync());

const manifestBytes = await readBoundedRegularFile(
  manifestPath,
  "Benchmark manifest",
  MAX_BENCHMARK_MANIFEST_BYTES,
);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
if (manifest?.schemaVersion !== "1.0" || !Array.isArray(manifest.cases)) {
  throw new Error(`Invalid benchmark manifest: ${manifestPath}`);
}
const selectedCases = selectBenchmarkCases(manifest.cases, options.cases);
const fixtureByCase = new Map();
const findingsPathsByCase = {};
const fixtureSha256ByCase = {};
const seedSarifByCase = new Map();
const seenCaseIds = new Set();
const seenResultPaths = new Set();
for (const benchmarkCase of selectedCases) {
  if (
    !benchmarkCase ||
    typeof benchmarkCase.id !== "string" ||
    typeof benchmarkCase.fixture !== "string"
  ) {
    throw new Error("Every runnable benchmark case must have id and fixture.");
  }
  if (seenCaseIds.has(benchmarkCase.id)) {
    throw new Error(`Duplicate benchmark case id: ${benchmarkCase.id}`);
  }
  seenCaseIds.add(benchmarkCase.id);
  const fixture = resolve(manifestDirectory, benchmarkCase.fixture);
  requireContained(
    manifestDirectory,
    fixture,
    `Fixture for ${benchmarkCase.id}`,
  );
  const metadata = await lstat(fixture);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Benchmark fixture is not a directory: ${fixture}`);
  }
  const findingsPaths = benchmarkFindingsPaths(benchmarkCase, options.runs);
  validateFindingsPaths(benchmarkCase.id, findingsPaths);
  for (const findingsPath of findingsPaths) {
    const canonical = resolve(resultsDirectory, findingsPath);
    const identity =
      process.platform === "win32" ? canonical.toLowerCase() : canonical;
    if (seenResultPaths.has(identity)) {
      throw new Error(`Duplicate benchmark result path: ${findingsPath}`);
    }
    seenResultPaths.add(identity);
  }
  fixtureByCase.set(benchmarkCase.id, fixture);
  findingsPathsByCase[benchmarkCase.id] = findingsPaths;
  const seedSarif = benchmarkCase.seedSarif ?? [];
  if (
    !Array.isArray(seedSarif) ||
    !seedSarif.every((path) => typeof path === "string" && path.length > 0)
  ) {
    throw new Error(
      `Benchmark case ${benchmarkCase.id} seedSarif must be an array of paths.`,
    );
  }
  const seedPaths = [];
  const seedDigests = [];
  for (const requested of seedSarif) {
    const seedPath = resolve(manifestDirectory, requested);
    requireContained(
      manifestDirectory,
      seedPath,
      `SARIF seed for ${benchmarkCase.id}`,
    );
    await requireRegularFile(seedPath, `SARIF seed for ${benchmarkCase.id}`);
    seedPaths.push(seedPath);
    seedDigests.push(await sha256File(seedPath));
  }
  seedSarifByCase.set(benchmarkCase.id, seedPaths);
  const fixtureDigest = await sha256Directory(fixture);
  fixtureSha256ByCase[benchmarkCase.id] =
    seedDigests.length === 0
      ? fixtureDigest
      : createHash("sha256")
          .update(
            JSON.stringify({
              schemaVersion: "1.0",
              fixtureSha256: fixtureDigest,
              seedSarifSha256: seedDigests,
            }),
          )
          .digest("hex");
}

const campaign = createBenchmarkCampaign({
  manifestPath,
  manifestSha256: await sha256File(manifestPath),
  repositoryRevision: runCapture("git", ["rev-parse", "HEAD"]),
  runnerSha256: await sha256File(runnerPath),
  runtime: {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
  },
  scanner: {
    cliPath: scannerCli,
    cliSha256: await sha256File(scannerCli),
    packageSha256: await sha256ScannerPackage(scannerPackageRoot),
    label: options.scannerLabel ?? basename(scannerCli),
  },
  selection: {
    caseIds: selectedCases.map((benchmarkCase) => benchmarkCase.id),
    findingsPathsByCase,
    fixtureSha256ByCase,
  },
  scan: {
    auth: options.auth,
    mode: options.mode,
    ...(options.model === undefined ? {} : { model: options.model }),
    ...(options.effort === undefined ? {} : { effort: options.effort }),
    ...(options.maxAiCredits === undefined
      ? {}
      : { maxAiCredits: options.maxAiCredits }),
  },
});
const activeCampaign = await ensureBenchmarkCampaign(
  resultsDirectory,
  campaign,
);
writeDiagnostic(
  `[benchmark] campaign ${activeCampaign.campaignId}; corpus ${activeCampaign.corpusId}; comparison policy ${activeCampaign.comparisonPolicyId ?? activeCampaign.scanPolicyId}; scanner ${activeCampaign.scanner.label}@${activeCampaign.scanner.cliSha256.slice(0, 12)}\n`,
);

const tasks = [];
for (const benchmarkCase of selectedCases) {
  const findingsPaths = findingsPathsByCase[benchmarkCase.id];
  for (let index = 0; index < findingsPaths.length; index += 1) {
    tasks.push({
      benchmarkCase,
      fixture: fixtureByCase.get(benchmarkCase.id),
      fixtureSha256: fixtureSha256ByCase[benchmarkCase.id],
      findingsPath: findingsPaths[index],
      run: index + 1,
      seedSarif: seedSarifByCase.get(benchmarkCase.id) ?? [],
    });
  }
}

let nextTask = 0;
let scanFailures = 0;
if (options.finalizeOnly) {
  writeDiagnostic(
    "[benchmark] finalize-only: preserving all scan outputs and rebuilding evaluation artifacts from existing receipts\n",
  );
} else {
  await Promise.all(
    Array.from(
      { length: Math.min(options.workers, Math.max(tasks.length, 1)) },
      async (_, workerIndex) => {
        while (true) {
          const index = nextTask;
          nextTask += 1;
          const task = tasks[index];
          if (task === undefined) return;
          try {
            const succeeded = await runTask(task, workerIndex + 1);
            if (!succeeded) scanFailures += 1;
          } catch (error) {
            scanFailures += 1;
            writeDiagnostic(
              `[benchmark:w${workerIndex + 1}] campaign task failed for ${task.benchmarkCase.id} run ${task.run}: ${errorMessage(error)}\n`,
            );
          }
        }
      },
    ),
  );
}

let evaluationManifestPath = manifestPath;
if (options.selectionOnly) {
  evaluationManifestPath = join(
    resultsDirectory,
    "benchmark-selection-manifest.json",
  );
  const selectionManifest = buildBenchmarkSelection(
    manifest,
    selectedCases,
    options.runs,
  );
  await writeBenchmarkTextAtomic(
    evaluationManifestPath,
    `${JSON.stringify(selectionManifest, null, 2)}\n`,
  );
}

const reportPath = join(resultsDirectory, "benchmark-report.json");
const evaluation = spawnSync(
  process.execPath,
  [
    defaultCli,
    "benchmark",
    evaluationManifestPath,
    "--results-dir",
    resultsDirectory,
    "--require-status",
    "--format",
    "json",
  ],
  {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: process.env,
    maxBuffer: 32 * 1024 * 1024,
    stdio: ["inherit", "pipe", "inherit"],
    windowsHide: true,
  },
);
if (typeof evaluation.stdout === "string") {
  await writeBenchmarkTextAtomic(reportPath, evaluation.stdout);
  writeStandardOutput(evaluation.stdout);
}
process.exitCode =
  scanFailures > 0 ? 1 : evaluation.status === null ? 1 : evaluation.status;
await benchmarkRunnerLock.release();

async function runTask(task, worker) {
  const { benchmarkCase, fixture, fixtureSha256, findingsPath, run } = task;
  const canonicalFindings = resolve(resultsDirectory, findingsPath);
  requireContained(
    resultsDirectory,
    canonicalFindings,
    `Result for ${benchmarkCase.id}`,
  );
  const outputDirectory = dirname(canonicalFindings);
  const statusPath = `${outputDirectory}.status.json`;
  let lastAttempt = (await readBenchmarkReceiptAttempt(statusPath)) ?? 0;

  if (!options.force) {
    try {
      const receipt = await readSuccessfulBenchmarkReceipt(statusPath, {
        campaignId: activeCampaign.campaignId,
        caseId: benchmarkCase.id,
        run,
        scanner: activeCampaign.scanner,
        scan: activeCampaign.scan,
        fixtureSha256,
      });
      const contract = await loadContract(outputDirectory, {
        pluginRoot,
        allowCompatibleNamespace: true,
      });
      await requireReceiptArtifacts(receipt, contract, outputDirectory);
      writeDiagnostic(
        `[benchmark:w${worker}] skipping ${benchmarkCase.id} run ${run}; sealed result and campaign receipt verified\n`,
      );
      return true;
    } catch (error) {
      if (
        (await lstat(outputDirectory).catch(() => null)) === null &&
        (await lstat(statusPath).catch(() => null)) === null
      ) {
        // A new run has nothing to resume.
      } else {
        writeDiagnostic(
          `[benchmark:w${worker}] preserving incomplete ${benchmarkCase.id} run ${run}: ${errorMessage(error)}\n`,
        );
        lastAttempt = await preserveCurrentAttempt({
          benchmarkCase,
          run,
          lastAttempt,
          outputDirectory,
          statusPath,
        });
      }
    }
  } else if (
    (await lstat(outputDirectory).catch(() => null)) !== null ||
    (await lstat(statusPath).catch(() => null)) !== null
  ) {
    lastAttempt = await preserveCurrentAttempt({
      benchmarkCase,
      run,
      lastAttempt,
      outputDirectory,
      statusPath,
    });
  }

  for (
    let invocationAttempt = 1;
    invocationAttempt <= options.maxAttempts;
    invocationAttempt += 1
  ) {
    if (invocationAttempt > 1) {
      lastAttempt = await preserveCurrentAttempt({
        benchmarkCase,
        run,
        lastAttempt,
        outputDirectory,
        statusPath,
      });
    }
    const attempt = lastAttempt + 1;
    const started = Date.now();
    const startedAt = new Date(started).toISOString();
    let repositoryRevision = "unavailable";
    let scan = {
      status: 1,
      signal: null,
      timedOut: false,
      error: "Benchmark attempt did not start.",
    };
    let temporaryRoot;
    let attemptOutputDirectory;
    try {
      await mkdir(dirname(outputDirectory), { recursive: true });
      attemptOutputDirectory = await createBenchmarkAttemptOutput({
        resultsDirectory,
        outputDirectory,
        attempt,
      });
      temporaryRoot = await mkdtemp(
        join(tmpdir(), "copilot-security-benchmark-"),
      );
      const repository = join(temporaryRoot, "repository");
      const gitGuardDirectory = join(temporaryRoot, "git-guard");
      const hooksDirectory = join(gitGuardDirectory, "disabled-hooks");
      await mkdir(hooksDirectory, { recursive: true });
      await cp(fixture, repository, {
        recursive: true,
        errorOnExist: true,
        force: false,
      });
      await rejectGitControlPath(
        repository,
        `Benchmark fixture ${benchmarkCase.id}`,
      );
      initializeFixtureRepository(repository, {
        hooksDirectory,
        globalConfigPath: join(gitGuardDirectory, "empty-global-config"),
      });
      repositoryRevision = runCapture("git", [
        "-C",
        repository,
        "rev-parse",
        "HEAD",
      ]);
      writeDiagnostic(
        `[benchmark:w${worker}] scanning ${benchmarkCase.id} run ${run}/${findingsPathsByCase[benchmarkCase.id].length} attempt ${attempt}\n`,
      );
      scan = await runScanner(
        repository,
        attemptOutputDirectory,
        task.seedSarif,
      );
      if (scan.status === 0) {
        const contract = await loadContract(attemptOutputDirectory, {
          pluginRoot,
          allowCompatibleNamespace: true,
        });
        await promoteBenchmarkAttemptOutput({
          resultsDirectory,
          attemptOutputDirectory,
          outputDirectory,
        });
        attemptOutputDirectory = undefined;
        const receipt = buildReceipt({
          task,
          attempt,
          repositoryRevision,
          started,
          startedAt,
          scan,
          artifacts: {
            scanId: contract.manifest.scan.id,
            findingsSha256: await sha256File(
              join(outputDirectory, "findings.json"),
            ),
            coverageSha256: await sha256File(
              join(outputDirectory, "coverage.json"),
            ),
            manifestSha256: await sha256File(
              join(outputDirectory, "scan-manifest.json"),
            ),
          },
        });
        await writeBenchmarkReceipt(statusPath, receipt);
        writeDiagnostic(
          `[benchmark:w${worker}] completed ${benchmarkCase.id} run ${run} attempt ${attempt}\n`,
        );
        return true;
      }
    } catch (error) {
      scan = {
        ...scan,
        status: scan.status === 0 ? 1 : scan.status,
        error: errorMessage(error),
      };
    } finally {
      if (temporaryRoot !== undefined) {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }
    if (attemptOutputDirectory !== undefined) {
      try {
        await promoteBenchmarkAttemptOutput({
          resultsDirectory,
          attemptOutputDirectory,
          outputDirectory,
        });
        attemptOutputDirectory = undefined;
      } catch (error) {
        throw new Error(
          `Could not preserve benchmark attempt output ${attemptOutputDirectory}: ${errorMessage(error)}`,
          { cause: error },
        );
      }
    }
    await writeBenchmarkReceipt(
      statusPath,
      buildReceipt({
        task,
        attempt,
        repositoryRevision,
        started,
        startedAt,
        scan,
      }),
    );
    lastAttempt = attempt;
    writeDiagnostic(
      `[benchmark:w${worker}] failed ${benchmarkCase.id} run ${run} attempt ${attempt}: ${scan.error ?? `status ${scan.status}`}\n`,
    );
  }
  return false;
}

async function preserveCurrentAttempt({
  benchmarkCase,
  run,
  lastAttempt,
  outputDirectory,
  statusPath,
}) {
  const archiveAttempt = await nextBenchmarkAttemptArchiveSlot({
    resultsDirectory,
    caseId: benchmarkCase.id,
    run,
    startingAt: lastAttempt,
  });
  const archived = await preserveBenchmarkAttempt({
    resultsDirectory,
    caseId: benchmarkCase.id,
    run,
    attempt: archiveAttempt,
    outputDirectory,
    statusPath,
  });
  return archived === null
    ? lastAttempt
    : Math.max(lastAttempt, archiveAttempt);
}

function buildReceipt({
  task,
  attempt,
  repositoryRevision,
  started,
  startedAt,
  scan,
  artifacts,
}) {
  const completedAt = new Date().toISOString();
  return {
    documentType: "copilot-security.benchmark-run",
    schemaVersion: "1.0",
    campaignId: activeCampaign.campaignId,
    caseId: task.benchmarkCase.id,
    run: task.run,
    attempt,
    status: scan.status,
    signal: scan.signal,
    timedOut: scan.timedOut,
    startedAt,
    completedAt,
    durationMs: Math.max(0, Date.parse(completedAt) - started),
    scanner: activeCampaign.scanner,
    scan: activeCampaign.scan,
    fixture: {
      sha256: task.fixtureSha256,
      repositoryRevision,
    },
    ...(artifacts === undefined ? {} : { artifacts }),
    ...(scan.error === undefined ? {} : { error: scan.error }),
  };
}

async function requireReceiptArtifacts(receipt, contract, outputDirectory) {
  const actual = {
    scanId: contract.manifest.scan.id,
    findingsSha256: await sha256File(join(outputDirectory, "findings.json")),
    coverageSha256: await sha256File(join(outputDirectory, "coverage.json")),
    manifestSha256: await sha256File(
      join(outputDirectory, "scan-manifest.json"),
    ),
  };
  for (const key of Object.keys(actual)) {
    if (receipt.artifacts[key] !== actual[key]) {
      throw new Error(`Benchmark receipt artifact ${key} does not match.`);
    }
  }
}

function runScanner(repository, outputDirectory, seedSarif) {
  const args = [
    scannerCli,
    "scan",
    repository,
    "--output-dir",
    outputDirectory,
    "--mode",
    options.mode,
    "--auth",
    options.auth,
    ...(options.model === undefined ? [] : ["--model", options.model]),
    ...(options.effort === undefined ? [] : ["--effort", options.effort]),
    ...(options.maxAiCredits === undefined
      ? []
      : ["--max-ai-credits", String(options.maxAiCredits)]),
    ...seedSarif.flatMap((path) => ["--seed-sarif", path]),
  ];
  const stdoutPath = `${outputDirectory}.scanner.stdout.log`;
  const stderrPath = `${outputDirectory}.scanner.stderr.log`;
  const captureStdout = createScannerOutputCapture(
    stdoutPath,
    writeStandardOutput,
  );
  const captureStderr = createScannerOutputCapture(stderrPath, writeDiagnostic);
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, args, {
      cwd: repositoryRoot,
      detached: process.platform !== "win32",
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    child.stdout.on("data", captureStdout);
    child.stderr.on("data", captureStderr);
    let timedOut = false;
    let settled = false;
    let forceTimer;
    const timer = setTimeout(() => {
      timedOut = true;
      terminateProcessTree(child.pid);
      if (process.platform !== "win32") {
        forceTimer = setTimeout(() => forceProcessTree(child.pid), 5_000);
      }
    }, options.scanTimeoutMs);
    const settle = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (forceTimer !== undefined) clearTimeout(forceTimer);
      resolvePromise(value);
    };
    child.once("error", (error) => {
      settle({
        status: 1,
        signal: null,
        timedOut,
        error: errorMessage(error),
      });
    });
    child.once("exit", (code, signal) => {
      settle({
        status: code ?? 1,
        signal,
        timedOut,
        ...(timedOut
          ? { error: `Scanner exceeded ${options.scanTimeoutMs} ms.` }
          : code === 0
            ? {}
            : {
                error: `Scanner exited with ${code ?? signal ?? "unknown"}. Diagnostics: ${relative(resultsDirectory, stdoutPath)}, ${relative(resultsDirectory, stderrPath)}.`,
              }),
      });
    });
  });
}

function createScannerOutputCapture(path, relay) {
  let persistent = true;
  try {
    writeFileSync(path, "", { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch {
    persistent = false;
  }
  return (chunk) => {
    if (persistent) {
      try {
        appendFileSync(path, chunk);
      } catch {
        persistent = false;
      }
    }
    relay(chunk);
  };
}

function terminateProcessTree(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/pid", String(pid), "/t", "/f"], {
      stdio: "ignore",
      windowsHide: true,
    });
    return;
  }
  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // The process may have exited while the deadline fired.
    }
  }
}

function forceProcessTree(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return;
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // The process tree already exited.
    }
  }
}

function initializeFixtureRepository(
  repository,
  { hooksDirectory, globalConfigPath },
) {
  const environment = sanitizedGitEnvironment(globalConfigPath);
  runGit(["init", "--quiet", repository], environment);
  const command = (...args) =>
    runGit(
      [
        "-C",
        repository,
        "-c",
        `core.hooksPath=${hooksDirectory}`,
        "-c",
        "commit.gpgsign=false",
        ...args,
      ],
      environment,
    );
  command("config", "user.name", "Benchmark Fixture");
  command("config", "user.email", "benchmark@example.invalid");
  command("config", "core.hooksPath", hooksDirectory);
  command("config", "commit.gpgsign", "false");
  command("add", "-A");
  command("commit", "--quiet", "--no-verify", "-m", "Benchmark fixture");
}

/*
 * Benchmark fixtures are untrusted scanner inputs. Strip inherited Git
 * controls, disable system/global attributes and configuration, and use an
 * empty hooks directory so corpus preparation cannot execute host commands.
 */
function sanitizedGitEnvironment(globalConfigPath) {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => !name.toUpperCase().startsWith("GIT_"),
    ),
  );
  return {
    ...environment,
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: globalConfigPath,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
  };
}

function runGit(args, environment) {
  const result = spawnSync("git", args, {
    cwd: repositoryRoot,
    env: environment,
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(
      `git failed with status ${result.status ?? result.signal ?? "unknown"}.`,
    );
  }
}

function validateFindingsPaths(caseId, findingsPaths) {
  if (!Array.isArray(findingsPaths) || findingsPaths.length === 0) {
    throw new Error(`Benchmark case has no result paths: ${caseId}`);
  }
  for (let index = 0; index < findingsPaths.length; index += 1) {
    const findingsPath = findingsPaths[index];
    if (typeof findingsPath !== "string" || isAbsolute(findingsPath)) {
      throw new Error(
        `Benchmark result path must be relative: ${caseId} run ${index + 1}`,
      );
    }
    const canonicalFindings = resolve(resultsDirectory, findingsPath);
    requireContained(
      resultsDirectory,
      canonicalFindings,
      `Result for ${caseId}`,
    );
    if (
      !canonicalFindings.endsWith(`${sep}findings.json`) &&
      canonicalFindings !== join(resultsDirectory, "findings.json")
    ) {
      throw new Error(
        `Benchmark result must end in findings.json: ${findingsPath}`,
      );
    }
  }
}

function parseArguments(args) {
  const result = {
    auth: "auto",
    cases: [],
    effort: undefined,
    finalizeOnly: false,
    force: false,
    manifest: undefined,
    maxAiCredits: undefined,
    maxAttempts: 2,
    mode: "deep",
    model: undefined,
    resultsDirectory: undefined,
    runs: undefined,
    scannerCli: undefined,
    scannerLabel: undefined,
    scanTimeoutMs: 4 * 60 * 60 * 1_000,
    selectionOnly: false,
    workers: 1,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--force") {
      result.force = true;
      continue;
    }
    if (argument === "--finalize-only") {
      result.finalizeOnly = true;
      continue;
    }
    if (argument === "--selection-only") {
      result.selectionOnly = true;
      continue;
    }
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`${argument} requires a value.`);
    }
    index += 1;
    if (argument === "--results-dir") result.resultsDirectory = value;
    else if (argument === "--manifest") result.manifest = value;
    else if (argument === "--case") result.cases.push(value);
    else if (argument === "--auth") result.auth = value;
    else if (argument === "--mode") result.mode = value;
    else if (argument === "--scanner-cli") result.scannerCli = value;
    else if (argument === "--scanner-label") result.scannerLabel = value;
    else if (argument === "--runs") {
      result.runs = positiveInteger(value, "--runs", 100);
    } else if (argument === "--workers") {
      result.workers = positiveInteger(value, "--workers", 8);
    } else if (argument === "--max-attempts") {
      result.maxAttempts = positiveInteger(value, "--max-attempts", 10);
    } else if (argument === "--scan-timeout-ms") {
      const timeout = positiveInteger(value, "--scan-timeout-ms", 86_400_000);
      if (timeout < 60_000) {
        throw new Error("--scan-timeout-ms must be at least 60000.");
      }
      result.scanTimeoutMs = timeout;
    } else if (argument === "--model") result.model = value;
    else if (argument === "--effort") result.effort = value;
    else if (argument === "--max-ai-credits") {
      const credits = Number(value);
      if (!Number.isFinite(credits) || credits < 30) {
        throw new Error("--max-ai-credits must be at least 30.");
      }
      result.maxAiCredits = credits;
    } else {
      throw new Error(`Unknown option: ${argument}`);
    }
  }
  if (result.resultsDirectory === undefined) {
    throw new Error(
      "--results-dir is required and must be outside the repository.",
    );
  }
  if (result.finalizeOnly && result.force) {
    throw new Error("--finalize-only cannot be combined with --force.");
  }
  if (!["auto", "github", "token"].includes(result.auth)) {
    throw new Error("--auth must be auto, github, or token.");
  }
  if (!["standard", "deep"].includes(result.mode)) {
    throw new Error("--mode must be standard or deep.");
  }
  if (
    result.effort !== undefined &&
    !["low", "medium", "high", "xhigh"].includes(result.effort)
  ) {
    throw new Error("--effort must be low, medium, high, or xhigh.");
  }
  if (
    result.scannerLabel !== undefined &&
    (result.scannerLabel.trim().length === 0 ||
      result.scannerLabel.length > 120)
  ) {
    throw new Error("--scanner-label must contain 1 to 120 characters.");
  }
  return result;
}

function positiveInteger(value, option, maximum) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error(`${option} must be an integer from 1 to ${maximum}.`);
  }
  return parsed;
}

function runCapture(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: process.env,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  if (result.status !== 0 || typeof result.stdout !== "string") {
    throw new Error(
      `${command} failed with status ${result.status ?? result.signal ?? "unknown"}.`,
    );
  }
  return result.stdout.trim();
}

async function requireRegularFile(path, label) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file: ${path}`);
  }
}

async function readBoundedRegularFile(path, label, maximumBytes) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file: ${path}`);
  }
  if (metadata.size > maximumBytes) {
    throw new Error(`${label} exceeds the ${maximumBytes}-byte limit: ${path}`);
  }
  const bytes = await readFile(path, {
    flag: constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  });
  if (bytes.byteLength > maximumBytes) {
    throw new Error(`${label} exceeds the ${maximumBytes}-byte limit: ${path}`);
  }
  return bytes;
}

function requireOutsideRepository(path) {
  const child = relative(repositoryRoot, path);
  if (
    child === "" ||
    (!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child))
  ) {
    throw new Error(
      `Benchmark results must be outside the repository: ${path}`,
    );
  }
}

function requireContained(root, path, label) {
  const child = relative(root, path);
  if (child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) {
    throw new Error(`${label} escapes its allowed directory: ${path}`);
  }
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
