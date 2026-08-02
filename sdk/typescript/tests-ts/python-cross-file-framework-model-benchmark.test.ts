import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface BenchmarkCase {
  id: string;
  fixture: string;
  findingsPaths: string[];
  expected: Array<{
    id?: string;
    acceptableSeverities?: string[];
  }>;
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: BenchmarkCase[];
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "python-cross-file-command-injection",
  "python-cross-file-safe-command",
  "python-cross-file-sql-injection",
  "python-cross-file-safe-sql",
] as const;

describe("Python cross-file framework-model effectiveness benchmark", () => {
  test("keeps wrapper positives and negatives paired under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-cross-file-framework-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(
      manifest.cases.filter(({ expected }) => expected.length > 0),
    ).toHaveLength(2);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(2);
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(1);
    }
    const sql = manifest.cases.find(
      ({ id }) => id === "python-cross-file-sql-injection",
    );
    expect(sql?.expected[0]?.acceptableSeverities).toContain("medium");
  });

  test("emits exact Python import propagation and preserves controls", async () => {
    const inventories = new Map<string, string>();
    for (const id of caseIds) {
      inventories.set(
        id,
        await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
      );
    }

    const command = inventories.get("python-cross-file-command-injection");
    expect(command).toContain('"scope":"cross-file-wrapper"');
    expect(command).toContain('"id":"python-web-command"');
    expect(command).toContain('"kind":"relative-python-import"');
    expect(command).toContain('"path":"src/server.py","line":3');
    expect(command).toContain('"path":"src/runner.py","line":4');
    expect(command).toContain('"path":"src/runner.py","line":5');

    expect(inventories.get("python-cross-file-safe-command")).not.toContain(
      '"scope":"cross-file-wrapper"',
    );
    const sql = inventories.get("python-cross-file-sql-injection");
    expect(sql).toContain('"id":"python-web-sql"');
    expect(sql).toContain('"kind":"wrapper-call-argument"');
    expect(sql).toContain('"path":"src/users.py","line":8');
    expect(inventories.get("python-cross-file-safe-sql")).toContain(
      '"kind":"bound-query-parameters"',
    );
  });

  test("rejects fixed, reassigned, non-relative, and text-only pseudo flows", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-framework-controls-"));
    const source = join(root, "src");
    try {
      await mkdir(source, { recursive: true });
      await writeFile(join(source, "__init__.py"), "", "utf8");
      await writeFile(
        join(source, "runner.py"),
        [
          "import os",
          "",
          "def run_report(report_name):",
          '    return os.system(f"/opt/reports/{report_name}")',
          "",
        ].join("\n"),
        "utf8",
      );

      for (const caller of [
        [
          "from flask import request",
          "from .runner import run_report",
          "def report():",
          '    unused = request.args.get("name", "")',
          '    return run_report("fixed")',
        ],
        [
          "from flask import request",
          "from .runner import run_report",
          "def report():",
          '    name = request.args.get("name", "")',
          '    name = "fixed"',
          "    return run_report(name)",
        ],
        [
          "from flask import request",
          "from runner import run_report",
          "def report():",
          '    name = request.args.get("name", "")',
          "    return run_report(name)",
        ],
        [
          "from flask import request",
          "# from .runner import run_report",
          "def report():",
          '    example = "run_report(request.args.get(\\"name\\"))"',
          '    return "fixed"',
        ],
        [
          '"""Executable-looking documentation must remain inert.',
          "from .runner import run_report",
          "def report():",
          '    name = request.args.get("name", "")',
          "    return run_report(name)",
          '"""',
          "def report():",
          '    return "fixed"',
        ],
      ]) {
        await writeFile(join(source, "server.py"), `${caller.join("\n")}\n`);
        expect(await buildResidualRiskInventory(root)).not.toContain(
          '"scope":"cross-file-wrapper"',
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
