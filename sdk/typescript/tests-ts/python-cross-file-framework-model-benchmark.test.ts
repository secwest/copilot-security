import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

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
  "python-cross-file-list-iadd-command-injection",
  "python-cross-file-list-iadd-safe-command",
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
    ).toHaveLength(3);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(3);
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
    const listIadd = inventories.get(
      "python-cross-file-list-iadd-command-injection",
    );
    expect(listIadd).toContain('"scope":"cross-file-wrapper"');
    expect(listIadd).toContain('"id":"python-web-command"');
    expect(listIadd).toContain('"kind":"python-list-iadd-element"');
    expect(listIadd).toContain('"path":"src/server.py","line":3');
    expect(listIadd).toContain(
      '"path":"src/runner.py","line":6,"symbol":"commands[0]"',
    );
    expect(listIadd).toContain('"path":"src/runner.py","line":7');
    expect(
      inventories.get("python-cross-file-list-iadd-safe-command"),
    ).not.toContain('"scope":"cross-file-wrapper"');
    const sql = inventories.get("python-cross-file-sql-injection");
    expect(sql).toContain('"id":"python-web-sql"');
    expect(sql).toContain('"kind":"wrapper-call-argument"');
    expect(sql).toContain('"path":"src/users.py","line":8');
    expect(inventories.get("python-cross-file-safe-sql")).toContain(
      '"kind":"bound-query-parameters"',
    );
  });

  test("follows exact Python list element mutation into an indexed shell operand", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-list-flow-"));
    const source = join(root, "src");
    try {
      await mkdir(source, { recursive: true });
      await writeFile(join(source, "__init__.py"), "", "utf8");
      await writeFile(
        join(source, "server.py"),
        [
          "from flask import request",
          "from .runner import run_report",
          "def report():",
          '    report_name = request.args.get("name", "")',
          "    return run_report(report_name)",
          "",
        ].join("\n"),
        "utf8",
      );

      for (const [mutation, propagator] of [
        [
          'commands.append(f"/opt/reports/{report_name}")',
          "python-list-append-element",
        ],
        [
          'commands.extend([f"/opt/reports/{report_name}"])',
          "python-list-extend-element",
        ],
        [
          'commands.insert(7, f"/opt/reports/{report_name}")',
          "python-list-insert-element",
        ],
        [
          'commands += [f"/opt/reports/{report_name}"]',
          "python-list-iadd-element",
        ],
      ] as const) {
        await writeFile(
          join(source, "runner.py"),
          [
            "import subprocess",
            "def run_report(report_name):",
            "    commands = []",
            `    ${mutation}`,
            "    return subprocess.run(commands[0], shell=True, check=True, timeout=2)",
            "",
          ].join("\n"),
          "utf8",
        );
        const inventory = await buildResidualRiskInventory(root);
        expect(inventory, mutation).toContain('"scope":"cross-file-wrapper"');
        expect(inventory, mutation).toContain('"id":"python-web-command"');
        expect(inventory, mutation).toContain(`"kind":"${propagator}"`);
        expect(inventory, mutation).toContain(
          '"path":"src/runner.py","line":4,"symbol":"commands[0]"',
        );
        expect(inventory, mutation).toContain(
          '"path":"src/runner.py","line":5',
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects list element flows that do not reach the selected shell operand", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-list-controls-"));
    const source = join(root, "src");
    try {
      await mkdir(source, { recursive: true });
      await writeFile(join(source, "__init__.py"), "", "utf8");
      await writeFile(
        join(source, "server.py"),
        [
          "from flask import request",
          "from .runner import run_report",
          "def report():",
          '    report_name = request.args.get("name", "")',
          "    return run_report(report_name)",
          "",
        ].join("\n"),
        "utf8",
      );

      for (const body of [
        ["    commands = []", '    commands.extend(["/opt/reports/fixed"])'],
        [
          "    commands = []",
          '    commands.extend([report_name, "/opt/reports/fixed"])',
          '    commands[0] = "/opt/reports/fixed"',
        ],
        [
          '    commands = ["/opt/reports/fixed"]',
          "    commands.extend([report_name])",
        ],
        [
          '    report_name = "fixed"',
          "    commands = []",
          "    commands += [report_name]",
        ],
        ["    commands = []", '    example = "commands.extend([report_name])"'],
      ]) {
        await writeFile(
          join(source, "runner.py"),
          [
            "import subprocess",
            "def run_report(report_name):",
            ...body,
            "    return subprocess.run(commands[0], shell=True, check=True, timeout=2)",
            "",
          ].join("\n"),
          "utf8",
        );
        expect(await buildResidualRiskInventory(root)).not.toContain(
          '"scope":"cross-file-wrapper"',
        );
      }

      await writeFile(
        join(source, "runner.py"),
        [
          "import subprocess",
          "def run_report(report_name):",
          "    commands = []",
          '    commands.extend([report_name, "/opt/reports/fixed"])',
          "    return subprocess.run(commands[1], shell=True, check=True, timeout=2)",
          "",
        ].join("\n"),
        "utf8",
      );
      expect(await buildResidualRiskInventory(root)).not.toContain(
        '"scope":"cross-file-wrapper"',
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "proves shell expansion only in the list-flow exploit fixture",
    () => {
      for (const [id, expected] of [
        ["python-cross-file-list-iadd-command-injection", 1],
        ["python-cross-file-list-iadd-safe-command", 0],
      ] as const) {
        const witness = spawnSync(
          "python3",
          [join(benchmarkRoot, "fixtures", id, "examples", "witness.py")],
          { encoding: "utf8", timeout: 10_000 },
        );
        expect(witness.status, witness.stderr).toBe(0);
        expect(witness.stdout).toContain(
          `'shell_expanded_marker': ${expected}`,
        );
      }
    },
  );

  test("requires list mutation and selected-index proof in review fields", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "python-cross-file-list-iadd-command-injection",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "python-list-quality-"));
    const finding = {
      occurrenceId: "occ_python_list_quality",
      taxonomy: { cwe: ["CWE-78"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/runner.py", startLine: 7, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "request-source",
          path: "src/server.py",
          startLine: 3,
          code: "from .runner import run_report",
          explanation: "The relative import supplies the wrapper edge.",
          role: "source",
        },
        {
          id: "shell-sink",
          path: "src/runner.py",
          startLine: 7,
          code: "    completed = subprocess.run(commands[0], shell=True, check=True, timeout=2)",
          explanation: "The selected list element enters the shell.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A remote value reaches subprocess.",
        method: "bounded source review and witness comparison",
        exploitWitness: "The temporary marker is created only by the exploit.",
        negativeControl: "The matched argv fixture does not create the marker.",
        evidence: ["request-source", "shell-sink"],
        counterEvidence: "The control keeps the value in literal argv.",
        remainingUncertainty: "Deployment reachability remains unproved.",
      },
      attackPath: {
        summary: "A remote value reaches a command.",
        dataflow: {
          source: "request-source",
          sink: "shell-sink",
          outcome: "shell behavior",
        },
        reachability: {
          attacker: "remote caller",
          entrypoint: "Flask route",
          outcome: "command interpretation",
        },
        brokenControls: ["shell interpretation"],
        evidenceRefs: ["request-source", "shell-sink"],
      },
    };
    try {
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      expect(incomplete).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(incomplete).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const contract =
        "The Flask remote request crosses the relative wrapper into an initially empty list. The exact list += in-place add contributes the hostile value, commands[0] is the constant index and selected list element, and no intervening mutation or overwrite occurs. subprocess.run then consumes that command string with shell=True as shell grammar, establishing CWE-78 command injection.";
      finding.validation.summary = contract;
      finding.attackPath.summary = contract;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );
      const complete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      expect(complete).not.toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(complete).not.toContain(
        "missing_model_specific_attack_path_evidence",
      );
    } finally {
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("teaches reviewers the bounded Python list-flow boundary", () => {
    const prompt = scanQualityGatePrompt("python-list-iadd-element");
    expect(prompt).toContain("python-list-iadd-element");
    expect(prompt).toContain("exact initially empty list");
    expect(prompt).toContain("constant indexed element");
    expect(prompt).toContain("no parameter reassignment");
    expect(prompt).toContain("shell=False");
    expect(prompt).toContain("absence of an intervening overwrite");
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
