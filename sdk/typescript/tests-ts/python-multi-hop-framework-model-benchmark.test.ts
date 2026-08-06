import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface BenchmarkCase {
  id: string;
  fixture: string;
  findingsPaths: string[];
  expected: unknown[];
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: BenchmarkCase[];
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "python-multi-hop-command-injection",
  "python-multi-hop-safe-command",
  "python-multi-hop-sql-injection",
  "python-multi-hop-safe-sql",
] as const;

describe("Python multi-hop framework-model effectiveness benchmark", () => {
  test("keeps four-file positives and negatives paired under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-multi-hop-framework-manifest.json"),
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
  });

  test("emits exact ordered Python relays and preserves safe controls", async () => {
    const inventories = new Map<string, string>();
    for (const id of caseIds) {
      inventories.set(
        id,
        await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
      );
    }

    const command = inventories.get("python-multi-hop-command-injection");
    expect(command).toContain('"scope":"cross-file-multi-hop-wrapper"');
    expect(command).toContain('"id":"python-web-command"');
    expect(command?.match(/"kind":"relative-python-import"/gu)).toHaveLength(3);
    expect(command?.match(/"kind":"wrapper-call-argument"/gu)).toHaveLength(3);
    expect(command?.match(/"kind":"wrapper-parameter"/gu)).toHaveLength(3);
    expect(command).toContain('"path":"src/server.py","line":3');
    expect(command).toContain('"path":"src/server.py","line":11');
    expect(command).toContain('"path":"src/gateway.py","line":4');
    expect(command).toContain('"path":"src/gateway.py","line":1');
    expect(command).toContain('"path":"src/gateway.py","line":5');
    expect(command).toContain('"path":"src/service.py","line":4');
    expect(command).toContain('"path":"src/service.py","line":1');
    expect(command).toContain('"path":"src/service.py","line":5');
    expect(command).toContain('"path":"src/runner.py","line":4');
    expect(command).toContain('"path":"src/runner.py","line":5');

    expect(inventories.get("python-multi-hop-safe-command")).not.toContain(
      '"scope":"cross-file-multi-hop-wrapper"',
    );
    expect(inventories.get("python-multi-hop-sql-injection")).toContain(
      '"id":"python-web-sql"',
    );
    const safeSql = inventories.get("python-multi-hop-safe-sql");
    expect(safeSql).toContain('"scope":"cross-file-multi-hop-wrapper"');
    expect(safeSql).toContain('"kind":"bound-query-parameters"');
  });

  test("rejects fixed, reassigned, external, private, and text-only relays", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-multi-hop-controls-"));
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
      await writeFile(
        join(source, "server.py"),
        [
          "from flask import request",
          "from .service import dispatch_report",
          "def report():",
          '    report_name = request.args.get("name", "")',
          "    return dispatch_report(report_name)",
          "",
        ].join("\n"),
        "utf8",
      );

      for (const service of [
        [
          "from .runner import run_report",
          "def dispatch_report(report_name):",
          '    return run_report("fixed")',
        ],
        [
          "from .runner import run_report",
          "def dispatch_report(report_name):",
          '    report_name = "fixed"',
          "    return run_report(report_name)",
        ],
        [
          "from .runner import run_report",
          "def dispatch_report(report_name):",
          "    return report_name",
          'run_report("outside")',
        ],
        [
          "from runner import run_report",
          "def dispatch_report(report_name):",
          "    return run_report(report_name)",
        ],
        [
          "from .runner import run_report",
          "def _dispatch_report(report_name):",
          "    return run_report(report_name)",
        ],
        [
          '"""Text-only relay example.',
          "from .runner import run_report",
          "def dispatch_report(report_name):",
          "    return run_report(report_name)",
          '"""',
          "def dispatch_report(report_name):",
          "    return report_name",
        ],
      ]) {
        await writeFile(join(source, "service.py"), `${service.join("\n")}\n`);
        expect(await buildResidualRiskInventory(root)).not.toContain(
          '"scope":"cross-file-multi-hop-wrapper"',
        );
      }

      await writeFile(
        join(source, "service.py"),
        [
          "from .runner import run_report",
          "def dispatch_report(report_name):",
          "    return run_report(report_name)",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "server.py"),
        [
          "from flask import request",
          "from .gateway import route_report",
          "def report():",
          '    report_name = request.args.get("name", "")',
          "    return route_report(report_name)",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "gateway.py"),
        [
          "from .service import dispatch_report",
          "def route_report(report_name):",
          '    report_name = "fixed"',
          "    return dispatch_report(report_name)",
          "",
        ].join("\n"),
      );
      expect(await buildResidualRiskInventory(root)).not.toContain(
        '"scope":"cross-file-multi-hop-wrapper"',
      );

      await writeFile(
        join(source, "gateway.py"),
        [
          "from .facade import forward_report",
          "def route_report(report_name):",
          "    return forward_report(report_name)",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "facade.py"),
        [
          "from .service import dispatch_report",
          "def forward_report(report_name):",
          "    return dispatch_report(report_name)",
          "",
        ].join("\n"),
      );
      expect(await buildResidualRiskInventory(root)).not.toContain(
        '"scope":"cross-file-multi-hop-wrapper"',
      );

      await writeFile(
        join(source, "runner.py"),
        [
          "import os",
          "from .service import dispatch_report",
          "def run_report(report_name):",
          '    return os.system(f"/opt/reports/{report_name}")',
          "def reenter_report(report_name):",
          "    return dispatch_report(report_name)",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "server.py"),
        [
          "from flask import request",
          "from .runner import reenter_report",
          "def report():",
          '    report_name = request.args.get("name", "")',
          "    return reenter_report(report_name)",
          "",
        ].join("\n"),
      );
      expect(await buildResidualRiskInventory(root)).not.toContain(
        '"scope":"cross-file-multi-hop-wrapper"',
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
