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
  "python-cross-file-dict-update-command-injection",
  "python-cross-file-dict-update-safe-command",
  "python-cross-file-object-field-command-injection",
  "python-cross-file-object-field-safe-command",
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
    ).toHaveLength(5);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(5);
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
    const dictionary = inventories.get(
      "python-cross-file-dict-update-command-injection",
    );
    expect(dictionary).toContain('"scope":"cross-file-wrapper"');
    expect(dictionary).toContain('"id":"python-web-command"');
    expect(dictionary).toContain('"kind":"python-dict-update-element"');
    expect(dictionary).toContain('"path":"src/server.py","line":3');
    expect(dictionary).toContain(
      '"path":"src/runner.py","line":6,"symbol":"commands[\\"preview\\"]"',
    );
    expect(dictionary).toContain('"path":"src/runner.py","line":8');
    expect(
      inventories.get("python-cross-file-dict-update-safe-command"),
    ).not.toContain('"scope":"cross-file-wrapper"');
    const objectField = inventories.get(
      "python-cross-file-object-field-command-injection",
    );
    expect(objectField).toContain('"scope":"cross-file-wrapper"');
    expect(objectField).toContain('"id":"python-web-command"');
    expect(objectField).toContain(
      '"kind":"python-object-attribute-assignment"',
    );
    expect(objectField).toContain('"path":"src/server.py","line":3');
    expect(objectField).toContain(
      '"path":"src/runner.py","line":7,"symbol":"command.value"',
    );
    expect(objectField).toContain('"path":"src/runner.py","line":9');
    expect(
      inventories.get("python-cross-file-object-field-safe-command"),
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

  test("follows exact Python dictionary values into constant-key shell operands", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-dict-flow-"));
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
      await writeFile(
        join(source, "runner.py"),
        [
          "import subprocess",
          "def run_report(report_name):",
          '    commands = {"preview": "/usr/bin/printf fixed"}',
          '    commands.update({"preview": f"/opt/reports/{report_name}"})',
          '    example = "commands.clear() is documentation, not execution"',
          '    selected = commands.get("preview")',
          "    return subprocess.run(selected, shell=True, check=True, timeout=2)",
          "",
        ].join("\n"),
        "utf8",
      );

      const inventory = await buildResidualRiskInventory(root);
      expect(inventory).toContain('"scope":"cross-file-wrapper"');
      expect(inventory).toContain('"id":"python-web-command"');
      expect(inventory).toContain('"kind":"python-dict-update-element"');
      expect(inventory).toContain(
        '"path":"src/runner.py","line":4,"symbol":"commands[\\"preview\\"]"',
      );
      expect(inventory).toContain('"path":"src/runner.py","line":7');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("models exact dictionary construction, writes, updates, unions, defaults, and reads", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-dict-operations-"));
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

      for (const [body, sink, propagator, mutationLine, sinkLine] of [
        [
          ['    commands = {"preview": f"/opt/reports/{report_name}"}'],
          'commands["preview"]',
          "python-dict-literal-element",
          3,
          4,
        ],
        [
          [
            "    commands = dict()",
            '    commands["preview"] = f"/opt/reports/{report_name}"',
          ],
          'commands.get("preview")',
          "python-dict-item-assignment-element",
          4,
          5,
        ],
        [
          [
            "    commands = {}",
            '    commands.update({"preview": f"/opt/reports/{report_name}"})',
          ],
          'commands["preview"]',
          "python-dict-update-element",
          4,
          5,
        ],
        [
          [
            "    commands = {}",
            '    commands |= {"preview": f"/opt/reports/{report_name}"}',
          ],
          'commands.pop("preview")',
          "python-dict-ior-element",
          4,
          5,
        ],
        [
          [
            "    commands = {}",
            '    commands.setdefault("preview", f"/opt/reports/{report_name}")',
          ],
          'commands.get("preview")',
          "python-dict-setdefault-element",
          4,
          5,
        ],
      ] as const) {
        await writeFile(
          join(source, "runner.py"),
          [
            "import subprocess",
            "def run_report(report_name):",
            ...body,
            `    return subprocess.run(${sink}, shell=True, check=True, timeout=2)`,
            "",
          ].join("\n"),
          "utf8",
        );
        const inventory = await buildResidualRiskInventory(root);
        expect(inventory, propagator).toContain('"scope":"cross-file-wrapper"');
        expect(inventory, propagator).toContain(`"kind":"${propagator}"`);
        expect(inventory, propagator).toContain(
          `"path":"src/runner.py","line":${mutationLine},"symbol":"commands[\\"preview\\"]"`,
        );
        expect(inventory, propagator).toContain(
          `"path":"src/runner.py","line":${sinkLine}`,
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects ambiguous, overwritten, or unselected dictionary values", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-dict-controls-"));
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
        [
          '    commands = {"preview": "/usr/bin/printf fixed", "audit": report_name}',
        ],
        [
          '    commands = {"preview": report_name}',
          '    commands["preview"] = "/usr/bin/printf fixed"',
        ],
        [
          "    commands = {}",
          '    commands.update({"preview": report_name})',
          '    commands |= {"preview": "/usr/bin/printf fixed"}',
        ],
        [
          '    commands = {"preview": "/usr/bin/printf fixed"}',
          '    commands.setdefault("preview", report_name)',
        ],
        [
          "    commands = {}",
          '    key = "preview"',
          "    commands[key] = report_name",
        ],
        [
          "    commands = {}",
          '    payload = {"preview": report_name}',
          "    commands.update(payload)",
        ],
        [
          '    commands = {"preview": "/usr/bin/printf fixed"}',
          "    alias = commands",
          '    alias["preview"] = report_name',
        ],
        [
          '    commands = {"preview": report_name}',
          "    inspect_state(commands)",
        ],
        [
          '    commands = {"preview": "/usr/bin/printf fixed"}',
          '    example = "commands.update({\\"preview\\": report_name})"',
        ],
        [
          '    report_name = "/usr/bin/printf fixed"',
          '    commands = {"preview": report_name}',
        ],
      ]) {
        await writeFile(
          join(source, "runner.py"),
          [
            "import subprocess",
            "def run_report(report_name):",
            ...body,
            '    return subprocess.run(commands["preview"], shell=True, check=True, timeout=2)',
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
          '    selected_key = "preview"',
          '    commands = {"preview": report_name}',
          "    return subprocess.run(commands[selected_key], shell=True, check=True, timeout=2)",
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

  test("follows exact fresh-object fields into selected shell operands", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-object-field-flow-"));
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

      for (const [
        importLine,
        body,
        sink,
        propagator,
        mutationLine,
        sinkLine,
      ] of [
        [
          "from types import SimpleNamespace",
          [
            '    command = SimpleNamespace(value=f"/opt/reports/{report_name}")',
          ],
          "command.value",
          "python-object-constructor-field",
          4,
          5,
        ],
        [
          "from types import SimpleNamespace as Namespace",
          [
            '    command = Namespace(value="/usr/bin/printf fixed")',
            '    command.value = f"/opt/reports/{report_name}"',
          ],
          "command.value",
          "python-object-attribute-assignment",
          5,
          6,
        ],
        [
          "import types as namespace_types",
          [
            "    command = namespace_types.SimpleNamespace()",
            '    setattr(command, "value", f"/opt/reports/{report_name}")',
          ],
          'getattr(command, "value")',
          "python-object-setattr-assignment",
          5,
          6,
        ],
      ] as const) {
        await writeFile(
          join(source, "runner.py"),
          [
            "import subprocess",
            importLine,
            "def run_report(report_name):",
            ...body,
            `    return subprocess.run(${sink}, shell=True, check=True, timeout=2)`,
            "",
          ].join("\n"),
          "utf8",
        );
        const inventory = await buildResidualRiskInventory(root);
        expect(inventory, propagator).toContain('"scope":"cross-file-wrapper"');
        expect(inventory, propagator).toContain('"id":"python-web-command"');
        expect(inventory, propagator).toContain(`"kind":"${propagator}"`);
        expect(inventory, propagator).toContain(
          `"path":"src/runner.py","line":${mutationLine},"symbol":"command.value"`,
        );
        expect(inventory, propagator).toContain(
          `"path":"src/runner.py","line":${sinkLine}`,
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects ambiguous, overwritten, cross-object, or unselected fields", async () => {
    const root = await mkdtemp(join(tmpdir(), "python-object-field-controls-"));
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

      for (const [imports, body, sink] of [
        [
          ["from types import SimpleNamespace"],
          [
            '    command = SimpleNamespace(value="/usr/bin/printf fixed")',
            "    command.audit = report_name",
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace(value=report_name)",
            '    command.value = "/usr/bin/printf fixed"',
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace()",
            '    field = "value"',
            "    setattr(command, field, report_name)",
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace(value=report_name)",
            '    field = "value"',
          ],
          "getattr(command, field)",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            '    command = SimpleNamespace(value="/usr/bin/printf fixed")',
            "    alias = command",
            "    alias.value = report_name",
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace(value=report_name)",
            "    inspect_state(command)",
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace(value=report_name)",
            '    command = SimpleNamespace(value="/usr/bin/printf fixed")',
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    primary = SimpleNamespace(value=report_name)",
            '    command = SimpleNamespace(value="/usr/bin/printf fixed")',
          ],
          "command.value",
        ],
        [
          [],
          ["    command = SimpleNamespace(value=report_name)"],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    SimpleNamespace = namespace_factory",
            "    command = SimpleNamespace(value=report_name)",
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            '    command = SimpleNamespace(value="/usr/bin/printf fixed")',
            '    command.__dict__["value"] = report_name',
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            '    command = SimpleNamespace(value="/usr/bin/printf fixed")',
            '    example = "command.value = report_name"',
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            '    report_name = "/usr/bin/printf fixed"',
            "    command = SimpleNamespace(value=report_name)",
          ],
          "command.value",
        ],
        [
          [
            "from types import SimpleNamespace",
            "from other_types import SimpleNamespace",
          ],
          ["    command = SimpleNamespace(value=report_name)"],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    class SimpleNamespace:",
            "        pass",
            "    command = SimpleNamespace(value=report_name)",
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace(value=report_name)",
            '    (command.value, other) = ("/usr/bin/printf fixed", "fixed")',
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace(value=report_name)",
            '    command.__dict__["value"] = "/usr/bin/printf fixed"',
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace(value=report_name)",
            "    command.clear()",
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            "    command = SimpleNamespace(value=report_name)",
            "    del command.value",
          ],
          "command.value",
        ],
        [
          ["from types import SimpleNamespace"],
          [
            '    command = SimpleNamespace(value="/usr/bin/printf fixed")',
            "    command.value += report_name",
          ],
          "command.value",
        ],
      ] as const) {
        await writeFile(
          join(source, "runner.py"),
          [
            "import subprocess",
            ...imports,
            "def run_report(report_name):",
            ...body,
            `    return subprocess.run(${sink}, shell=True, check=True, timeout=2)`,
            "",
          ].join("\n"),
          "utf8",
        );
        expect(await buildResidualRiskInventory(root)).not.toContain(
          '"scope":"cross-file-wrapper"',
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "proves shell expansion only in the indirect-flow exploit fixtures",
    () => {
      for (const [id, expected] of [
        ["python-cross-file-list-iadd-command-injection", 1],
        ["python-cross-file-list-iadd-safe-command", 0],
        ["python-cross-file-dict-update-command-injection", 1],
        ["python-cross-file-dict-update-safe-command", 0],
        ["python-cross-file-object-field-command-injection", 1],
        ["python-cross-file-object-field-safe-command", 0],
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

  test("requires exact dictionary state and selected-key proof in review fields", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "python-cross-file-dict-update-command-injection",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "python-dict-quality-"));
    const finding = {
      occurrenceId: "occ_python_dict_quality",
      taxonomy: { cwe: ["CWE-78"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/runner.py", startLine: 8, role: "sink" },
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
          startLine: 8,
          code: "    completed = subprocess.run(selected, shell=True, check=True, timeout=2)",
          explanation: "The selected dictionary value enters the shell.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A remote value reaches subprocess.",
        method: "bounded source review and witness comparison",
        exploitWitness: "The temporary marker is created only by the exploit.",
        negativeControl: "The matched key-isolation fixture creates no marker.",
        evidence: ["request-source", "shell-sink"],
        counterEvidence: "The control stores the value under another key.",
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
        'The Flask request crosses the relative run_report wrapper. Exact dict.update overwrites the constant key preview; commands["preview"] is the selected dictionary value reached through commands.get. The deterministic last-write-wins dictionary state has no ambiguous mutation or intervening overwrite before subprocess.run consumes it with shell=True as shell grammar, establishing CWE-78.';
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

  test("requires exact receiver, field, and last-write proof in review fields", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "python-cross-file-object-field-command-injection",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "python-object-field-quality-"),
    );
    const finding = {
      occurrenceId: "occ_python_object_field_quality",
      taxonomy: { cwe: ["CWE-78"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/runner.py", startLine: 9, role: "sink" },
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
          startLine: 9,
          code: "    completed = subprocess.run(selected, shell=True, check=True, timeout=2)",
          explanation: "The selected object field enters the shell.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A remote value reaches subprocess through an object.",
        method: "bounded source review and witness comparison",
        exploitWitness: "The temporary marker is created only by the exploit.",
        negativeControl:
          "The matched field-isolation fixture creates no marker.",
        evidence: ["request-source", "shell-sink"],
        counterEvidence: "The control stores the value in another field.",
        remainingUncertainty: "Deployment reachability remains unproved.",
      },
      attackPath: {
        summary: "A remote value reaches a command through an object.",
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
        "The Flask request crosses the relative run_report wrapper into a fresh standard-library SimpleNamespace receiver. Exact attribute assignment writes report_name to command.value; that constant selected object field is read from the same receiver. Receiver-sensitive last-write-wins field state proves no receiver alias escape, ambiguous attribute mutation, or intervening overwrite before subprocess.run consumes it with shell=True as shell grammar, establishing CWE-78.";
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

  test("teaches reviewers the bounded Python collection and field-flow boundaries", () => {
    const prompt = scanQualityGatePrompt("python-list-iadd-element");
    expect(prompt).toContain("python-list-iadd-element");
    expect(prompt).toContain("exact initially empty list");
    expect(prompt).toContain("constant indexed element");
    expect(prompt).toContain("no parameter reassignment");
    expect(prompt).toContain("shell=False");
    expect(prompt).toContain("absence of an intervening overwrite");
    expect(prompt).toContain("python-dict-update-element");
    expect(prompt).toContain("deterministic last-write-wins dictionary state");
    expect(prompt).toContain("bracket/get/pop selection");
    expect(prompt).toContain(
      "taint confined to an unselected or overwritten value",
    );
    expect(prompt).toContain("python-object-attribute-assignment");
    expect(prompt).toContain("fresh standard-library types.SimpleNamespace");
    expect(prompt).toContain("receiver-sensitive last-write-wins field state");
    expect(prompt).toContain("object escape through an alias or helper");
    expect(prompt).toContain("taint confined to another receiver or field");
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
