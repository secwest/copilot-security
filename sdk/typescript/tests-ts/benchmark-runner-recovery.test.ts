import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
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

function runNode(arguments_: string[]) {
  return spawnSync("node", arguments_, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: process.env,
    timeout: 25_000,
    windowsHide: true,
  });
}

async function temporaryDirectory(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  temporaryPaths.push(path);
  return path;
}
