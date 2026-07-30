#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const benchmarkRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(benchmarkRoot, "..");
const cli = join(
  repositoryRoot,
  "sdk",
  "typescript",
  "bin",
  "copilot-security.mjs",
);

const options = parseArguments(process.argv.slice(2));
const manifestPath = resolve(
  options.manifest ?? join(benchmarkRoot, "manifest.json"),
);
const manifestDirectory = dirname(manifestPath);
const resultsDirectory = resolve(options.resultsDirectory);
requireOutsideRepository(resultsDirectory);
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (manifest?.schemaVersion !== "1.0" || !Array.isArray(manifest.cases)) {
  throw new Error(`Invalid benchmark manifest: ${manifestPath}`);
}

let scanFailures = 0;
for (const benchmarkCase of manifest.cases) {
  if (
    !benchmarkCase ||
    typeof benchmarkCase.id !== "string" ||
    typeof benchmarkCase.fixture !== "string"
  ) {
    throw new Error("Every runnable benchmark case must have id and fixture.");
  }
  if (options.cases.length > 0 && !options.cases.includes(benchmarkCase.id)) {
    continue;
  }
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
  const configuredFindingsPaths = Array.isArray(benchmarkCase.findingsPaths)
    ? benchmarkCase.findingsPaths
    : [
        typeof benchmarkCase.findingsPath === "string"
          ? benchmarkCase.findingsPath
          : join(benchmarkCase.id, "findings.json"),
      ];
  const findingsPaths =
    options.runs === undefined
      ? configuredFindingsPaths
      : configuredFindingsPaths.slice(0, options.runs);

  for (let index = 0; index < findingsPaths.length; index += 1) {
    const findingsPath = findingsPaths[index];
    if (typeof findingsPath !== "string" || isAbsolute(findingsPath)) {
      throw new Error(
        `Benchmark result path must be relative: ${benchmarkCase.id} run ${index + 1}`,
      );
    }
    const canonicalFindings = resolve(resultsDirectory, findingsPath);
    requireContained(
      resultsDirectory,
      canonicalFindings,
      `Result for ${benchmarkCase.id}`,
    );
    if (
      !canonicalFindings.endsWith(`${sep}findings.json`) &&
      canonicalFindings !== join(resultsDirectory, "findings.json")
    ) {
      throw new Error(
        `Benchmark result must end in findings.json: ${findingsPath}`,
      );
    }
    if (
      !options.force &&
      (await lstat(canonicalFindings).catch(() => null))?.isFile()
    ) {
      process.stderr.write(
        `[benchmark] skipping ${benchmarkCase.id} run ${index + 1}; findings already exist\n`,
      );
      continue;
    }

    const outputDirectory = dirname(canonicalFindings);
    if (options.force) {
      await rm(outputDirectory, { recursive: true, force: true });
    }
    await mkdir(dirname(outputDirectory), { recursive: true });
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), `copilot-security-${benchmarkCase.id}-`),
    );
    const repository = join(temporaryRoot, "repository");
    try {
      await cp(fixture, repository, {
        recursive: true,
        errorOnExist: true,
        force: false,
      });
      run("git", ["init", "--quiet", repository]);
      run("git", [
        "-C",
        repository,
        "config",
        "user.name",
        "Benchmark Fixture",
      ]);
      run("git", [
        "-C",
        repository,
        "config",
        "user.email",
        "benchmark@example.invalid",
      ]);
      run("git", ["-C", repository, "add", "-A"]);
      run("git", [
        "-C",
        repository,
        "commit",
        "--quiet",
        "-m",
        "Benchmark fixture",
      ]);

      process.stderr.write(
        `[benchmark] scanning ${benchmarkCase.id} run ${index + 1}/${configuredFindingsPaths.length}\n`,
      );
      const startedAt = new Date().toISOString();
      const scan = spawnSync(
        process.execPath,
        [
          cli,
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
        ],
        {
          cwd: repositoryRoot,
          env: process.env,
          stdio: "inherit",
          windowsHide: true,
        },
      );
      const status = scan.status ?? 1;
      await writeFile(
        `${outputDirectory}.status.json`,
        `${JSON.stringify({
          caseId: benchmarkCase.id,
          run: index + 1,
          status,
          startedAt,
          completedAt: new Date().toISOString(),
          signal: scan.signal,
        })}\n`,
        { mode: 0o600 },
      );
      if (status !== 0) scanFailures += 1;
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }
}

const evaluation = spawnSync(
  process.execPath,
  [
    cli,
    "benchmark",
    manifestPath,
    "--results-dir",
    resultsDirectory,
    "--format",
    "json",
  ],
  {
    cwd: repositoryRoot,
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  },
);
process.exitCode =
  scanFailures > 0 ? 1 : evaluation.status === null ? 1 : evaluation.status;

function parseArguments(args) {
  const result = {
    auth: "auto",
    cases: [],
    effort: undefined,
    force: false,
    manifest: undefined,
    maxAiCredits: undefined,
    mode: "deep",
    model: undefined,
    resultsDirectory: undefined,
    runs: undefined,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--force") {
      result.force = true;
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
    else if (argument === "--runs") {
      const runs = Number(value);
      if (!Number.isSafeInteger(runs) || runs <= 0) {
        throw new Error("--runs must be a positive integer.");
      }
      result.runs = runs;
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
  return result;
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} failed with status ${result.status ?? result.signal ?? "unknown"}.`,
    );
  }
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
