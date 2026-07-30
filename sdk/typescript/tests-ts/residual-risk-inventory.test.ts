import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

const benchmarkFixtures = join(
  process.cwd(),
  "..",
  "..",
  "benchmarks",
  "fixtures",
);
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

describe("residual risk inventory", () => {
  test("puts exact archive path and filesystem-write evidence in the correction prompt", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkFixtures, "python-path-traversal"),
    );

    expect(inventory).toContain('"archive-or-attacker-path"');
    expect(inventory).toContain('"filesystem-write"');
    expect(inventory).toContain("entry.filename");
    expect(inventory).toContain("target.write_bytes");
  });

  test("retains nearby mitigating controls so the model can reject safe flows", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkFixtures, "python-safe-path"),
    );

    expect(inventory).toContain("entry.filename");
    expect(inventory).toContain("root not in target.parents");
    expect(inventory).toContain("raise ValueError");
  });

  test("surfaces object lookup and ownership boundaries together", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-safe-authorization"),
    );

    expect(inventory).toContain('"query-or-object-lookup"');
    expect(inventory).toContain('"authorization-boundary"');
    expect(inventory).toContain("customerId");
  });

  test("prioritizes critical sinks instead of letting noisy files exhaust the prompt", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-residual-risk-"),
    );
    temporaryPaths.push(repository);
    await writeFile(
      join(repository, "signals.py"),
      `${Array.from({ length: 120 }, (_, index) => `open("file-${index}")`).join("\n")}
subprocess.run(user_input, shell=True)
`,
    );

    const records = (await buildResidualRiskInventory(repository))
      .split("\n")
      .map((line) => JSON.parse(line) as { categories: string[] });

    expect(records).toHaveLength(96);
    expect(records[0]?.categories).toContain("process-or-shell");
  });
});
