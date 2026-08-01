import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const temporaryPaths: string[] = [];
const repositoryRoot = join(import.meta.dir, "..", "..", "..");
const runner = join(repositoryRoot, "benchmarks", "run-benchmark.mjs");
const manifest = join(repositoryRoot, "benchmarks", "manifest.json");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("benchmark runner interruption recovery", () => {
  test("rejects an oversized benchmark manifest before parsing", async () => {
    const root = await temporaryDirectory("benchmark-oversized-manifest-");
    const oversized = join(root, "manifest.json");
    await writeFile(oversized, "{");
    await truncate(oversized, 4 * 1024 * 1024 + 1);

    const result = runNode([
      runner,
      "--results-dir",
      join(root, "results"),
      "--manifest",
      oversized,
    ]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("4194304-byte limit");
  });

  test("binds per-case SARIF seed bytes into the campaign and scanner invocation", async () => {
    const root = await temporaryDirectory("benchmark-sarif-seed-");
    const corpus = join(root, "corpus");
    const fixture = join(corpus, "fixture");
    const seed = join(corpus, "seed.sarif");
    const customManifest = join(corpus, "manifest.json");
    const results = join(root, "results");
    const scanner = join(root, "scanner");
    const invocation = join(root, "scanner-arguments.json");
    const inheritedHooks = join(root, "inherited-hooks");
    const scannerCli = join(scanner, "bin", "fixture-scanner.mjs");
    await mkdir(fixture, { recursive: true });
    await writeFile(join(fixture, "source.js"), "export const safe = true;\n");
    await writeFile(seed, '{"version":"2.1.0","runs":[]}\n');
    await writeFile(
      customManifest,
      `${JSON.stringify({
        schemaVersion: "1.0",
        thresholds: {},
        cases: [
          {
            id: "seed-case",
            description: "runner seed propagation",
            fixture: "fixture",
            seedSarif: ["seed.sarif"],
            findingsPaths: ["seed-case/run-1/findings.json"],
            expected: [],
          },
        ],
      })}\n`,
    );
    for (const directory of ["bin", "dist", "_bundled_plugin"]) {
      await mkdir(join(scanner, directory), { recursive: true });
    }
    await writeFile(
      join(scanner, "package.json"),
      '{"name":"benchmark-seed-fixture","type":"module"}\n',
    );
    await writeFile(
      scannerCli,
      [
        'import { writeFileSync } from "node:fs";',
        `writeFileSync(${JSON.stringify(invocation)}, JSON.stringify(process.argv.slice(2)));`,
        "process.exit(1);",
        "",
      ].join("\n"),
    );
    await mkdir(inheritedHooks);
    const inheritedHook = join(inheritedHooks, "pre-commit");
    await writeFile(inheritedHook, "#!/bin/sh\nexit 73\n");
    await chmod(inheritedHook, 0o755);

    const result = runNode(
      [
        runner,
        "--results-dir",
        results,
        "--manifest",
        customManifest,
        "--runs",
        "1",
        "--selection-only",
        "--scanner-cli",
        scannerCli,
        "--scanner-label",
        "seed-fixture",
        "--auth",
        "github",
        "--mode",
        "standard",
        "--max-attempts",
        "1",
        "--scan-timeout-ms",
        "60000",
      ],
      {
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.hooksPath",
        GIT_CONFIG_VALUE_0: inheritedHooks,
      },
    );
    expect(result.status).toBe(1);
    const scannerArguments = JSON.parse(await readFile(invocation, "utf8"));
    const optionIndex = scannerArguments.indexOf("--seed-sarif");
    expect(optionIndex).toBeGreaterThan(-1);
    expect(scannerArguments[optionIndex + 1]).toBe(seed);

    const campaign = JSON.parse(
      await readFile(join(results, "benchmark-campaign.json"), "utf8"),
    );
    expect(campaign.selection.fixtureSha256ByCase["seed-case"]).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  test("finalizes failed receipts without launching another scanner attempt", async () => {
    const root = await temporaryDirectory("benchmark-finalize-only-");
    const results = join(root, "results");
    const scanner = join(root, "scanner");
    const marker = join(root, "scanner-invocations.txt");
    const scannerCli = join(scanner, "bin", "fixture-scanner.mjs");
    for (const directory of ["bin", "dist", "_bundled_plugin"]) {
      await mkdir(join(scanner, directory), { recursive: true });
    }
    await writeFile(
      join(scanner, "package.json"),
      '{"name":"benchmark-finalize-fixture","type":"module"}\n',
    );
    await writeFile(
      scannerCli,
      [
        'import { appendFileSync } from "node:fs";',
        `appendFileSync(${JSON.stringify(marker)}, "scan\\n", "utf8");`,
        "process.exit(1);",
        "",
      ].join("\n"),
    );

    const baseArguments = [
      runner,
      "--results-dir",
      results,
      "--manifest",
      manifest,
      "--case",
      "c-safe-literal-format-audit",
      "--runs",
      "1",
      "--selection-only",
      "--scanner-cli",
      scannerCli,
      "--scanner-label",
      "finalize-fixture",
      "--auth",
      "github",
      "--model",
      "fixture-model",
      "--effort",
      "high",
      "--mode",
      "standard",
      "--max-attempts",
      "1",
      "--workers",
      "1",
      "--scan-timeout-ms",
      "60000",
    ];
    const first = runNode(baseArguments);
    expect(first.status).toBe(1);
    expect(await readFile(marker, "utf8")).toBe("scan\n");

    const selectionPath = join(results, "benchmark-selection-manifest.json");
    const reportPath = join(results, "benchmark-report.json");
    await writeFile(selectionPath, "");
    await writeFile(reportPath, "stale\n");

    const finalized = runNode([...baseArguments, "--finalize-only"]);
    expect(finalized.status).toBe(1);
    expect(finalized.stderr).toContain("finalize-only");
    expect(await readFile(marker, "utf8")).toBe("scan\n");

    const selection = JSON.parse(await readFile(selectionPath, "utf8"));
    const report = JSON.parse(await readFile(reportPath, "utf8"));
    expect(selection.cases.map((item: { id: string }) => item.id)).toEqual([
      "c-safe-literal-format-audit",
    ]);
    expect(report.passed).toBe(false);
    expect(report.metrics.completedRuns).toBe(0);
    expect(report.metrics.completionRate).toBe(0);
    expect(
      JSON.parse(
        await readFile(
          join(results, "c-safe-literal-format-audit", "run-1.status.json"),
          "utf8",
        ),
      ).attempt,
    ).toBe(1);
    expect((await readdir(results)).some((name) => name.endsWith(".tmp"))).toBe(
      false,
    );
  });
});

function runNode(
  arguments_: string[],
  environment: Record<string, string> = {},
) {
  return spawnSync("node", arguments_, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    timeout: 25_000,
    windowsHide: true,
  });
}

async function temporaryDirectory(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  temporaryPaths.push(path);
  return path;
}
