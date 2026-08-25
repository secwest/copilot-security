import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  line: number;
  frameworkModel?: {
    id: string;
    scope: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    fixture: string;
    findingsPaths: string[];
    expected: Array<{
      cwe?: string[];
      requiredValidationTextAnyOf?: string[][];
      requiredAttackPathTextAnyOf?: string[][];
      forbiddenText?: string[];
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) =>
      rm(path, {
        recursive: true,
        force: true,
      }),
    ),
  );
});

function parseRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function pyyamlRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "python-web-pyyaml-unsafe-load",
  );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-pyyaml-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

describe("Python PyYAML unsafe deserialization model", () => {
  test("keeps a strict exploit/control benchmark and semantic gate", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-pyyaml-unsafe-load-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "python-pyyaml-unsafe-load",
      "python-pyyaml-safe-load",
    ]);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-502"]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(3);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(3);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf?.[2],
    ).toEqual([
      "request body",
      "POST body",
      "attacker-controlled YAML",
      "request-controlled document",
    ]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf?.[2],
    ).toEqual([
      "object construction",
      "Python object",
      "Python-specific constructor",
      "Python-specific YAML construction",
    ]);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(2);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-pyyaml-unsafe-load",
          "examples",
          "witness.py",
        ),
        "utf8",
      ),
    ).toBe(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-pyyaml-safe-load",
          "examples",
          "witness.py",
        ),
        "utf8",
      ),
    );
  });

  test("emits the exact relative-wrapper UnsafeLoader path and rejects safe_load", async () => {
    const vulnerable = pyyamlRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-pyyaml-unsafe-load"),
      ),
    );
    const control = pyyamlRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-pyyaml-safe-load"),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-wrapper",
      source: {
        kind: "framework-request-body",
        path: "src/server.py",
        line: 10,
      },
      sink: {
        kind: "pyyaml-load-with-unsafeloader",
        path: "src/parser.py",
        line: 5,
        cweIds: ["CWE-502"],
      },
      candidateControls: [],
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual([
      {
        kind: "relative-python-import",
        path: "src/server.py",
        line: 3,
        symbol: "parse_profile as parse_profile",
      },
      {
        kind: "wrapper-call-argument",
        path: "src/server.py",
        line: 11,
        symbol: "parse_profile[0]",
      },
      {
        kind: "wrapper-parameter",
        path: "src/parser.py",
        line: 4,
        symbol: "document",
      },
      {
        kind: "pyyaml-module-binding",
        path: "src/parser.py",
        line: 1,
        symbol: "yaml as yaml",
      },
      {
        kind: "explicit-unsafe-pyyaml-loader",
        path: "src/parser.py",
        line: 1,
        symbol: "UnsafeLoader",
      },
    ]);
    expect(control).toEqual([]);
  });

  test("supports receiver and imported aliases with exact stream roles", async () => {
    const cases = [
      {
        expectedKind: "pyyaml-explicit-unsafe-load",
        source: [
          "import yaml as parser",
          "from flask import request",
          "payload = request.get_data(as_text=True)",
          "result = parser.unsafe_load(stream=payload)",
        ].join("\n"),
      },
      {
        expectedKind: "pyyaml-load-with-loader",
        source: [
          "from yaml import Loader as ObjectLoader, load as parse_yaml",
          "from flask import request",
          "payload = request.data",
          "result = parse_yaml(payload, Loader=ObjectLoader)",
        ].join("\n"),
      },
      {
        expectedKind: "pyyaml-load-with-cunsafeloader",
        source: [
          "from yaml import CUnsafeLoader as ObjectLoader, load",
          "from flask import request",
          "payload = request.data",
          "result = load(stream=payload, Loader=ObjectLoader)",
        ].join("\n"),
      },
      {
        expectedKind: "pyyaml-load-with-unsafeloader",
        source: [
          "from yaml import (",
          "    load as parse_yaml,",
          "    UnsafeLoader as ObjectLoader,",
          ")",
          "from flask import request",
          "payload = request.data",
          "result = parse_yaml(payload, ObjectLoader)",
        ].join("\n"),
      },
    ] as const;

    for (const candidate of cases) {
      const repository = await writeRepository({ "app.py": candidate.source });
      const records = pyyamlRecords(
        await buildResidualRiskInventory(repository),
      );
      expect(records).toHaveLength(1);
      expect(records[0]?.frameworkModel?.sink.kind).toBe(
        candidate.expectedKind,
      );
      expect(records[0]?.frameworkModel?.source.kind).toBe(
        "framework-request-body",
      );
    }
  });

  test("preserves a two-relay Python path and the terminal PyYAML binding", async () => {
    const shared = {
      "src/__init__.py": "",
      "src/server.py": [
        "from flask import request",
        "from .service import import_profile",
        "",
        "def route():",
        "    document = request.get_data(as_text=True)",
        "    return import_profile(document)",
      ].join("\n"),
      "src/service.py": [
        "from .parser import parse_profile",
        "",
        "def import_profile(document):",
        "    return parse_profile(document)",
      ].join("\n"),
    };
    const vulnerable = await writeRepository({
      ...shared,
      "src/parser.py": [
        "import yaml",
        "",
        "def parse_profile(document):",
        "    return yaml.unsafe_load(document)",
      ].join("\n"),
    });
    const safe = await writeRepository({
      ...shared,
      "src/parser.py": [
        "import yaml",
        "",
        "def parse_profile(document):",
        "    return yaml.safe_load(document)",
      ].join("\n"),
    });

    const records = pyyamlRecords(await buildResidualRiskInventory(vulnerable));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source).toMatchObject({
      path: "src/server.py",
      line: 5,
    });
    expect(records[0]?.frameworkModel?.sink).toMatchObject({
      path: "src/parser.py",
      line: 4,
      kind: "pyyaml-explicit-unsafe-load",
      cweIds: ["CWE-502"],
    });
    expect(records[0]?.frameworkModel?.propagators.at(-1)).toEqual({
      kind: "pyyaml-module-binding",
      path: "src/parser.py",
      line: 1,
      symbol: "yaml as yaml",
    });
    expect(pyyamlRecords(await buildResidualRiskInventory(safe))).toEqual([]);
  });

  test("rejects safe or unproved loaders, fixed streams, and unrelated request arguments", async () => {
    const cases = [
      "yaml.safe_load(payload)",
      "yaml.full_load(payload)",
      "yaml.load(payload)",
      "yaml.load(payload, Loader=yaml.SafeLoader)",
      "yaml.load(payload, Loader=yaml.CSafeLoader)",
      "yaml.load(payload, Loader=yaml.FullLoader)",
      "yaml.load(payload, Loader=ConfiguredLoader)",
      'yaml.load("fixed: true", Loader=yaml.UnsafeLoader)',
      'yaml.load("fixed: true", Loader=yaml.UnsafeLoader, metadata=payload)',
    ];
    for (const call of cases) {
      const repository = await writeRepository({
        "app.py": [
          "import yaml",
          "from flask import request",
          "payload = request.get_data(as_text=True)",
          `result = ${call}`,
        ].join("\n"),
      });
      expect(
        pyyamlRecords(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    }
  });

  test("rejects local module shadows, reassignment, member replacement, comments, and strings", async () => {
    const base = [
      "import yaml",
      "from flask import request",
      "payload = request.data",
    ];
    const cases: Array<Record<string, string>> = [
      {
        "app.py": [
          ...base,
          "yaml = object()",
          "yaml.unsafe_load(payload)",
        ].join("\n"),
      },
      {
        "app.py": [
          ...base,
          "yaml.unsafe_load = yaml.safe_load",
          "yaml.unsafe_load(payload)",
        ].join("\n"),
      },
      {
        "app.py": [
          ...base,
          "# yaml.unsafe_load(payload)",
          'example = "yaml.unsafe_load(payload)"',
        ].join("\n"),
      },
      {
        "app.py": [...base, "yaml.unsafe_load(payload)"].join("\n"),
        "yaml.py": "def unsafe_load(value):\n    return value\n",
      },
      {
        "src/app.py": [...base, "yaml.unsafe_load(payload)"].join("\n"),
        "src/yaml/__init__.py": "def unsafe_load(value):\n    return value\n",
      },
    ];
    for (const files of cases) {
      const repository = await writeRepository(files);
      expect(
        pyyamlRecords(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    }
  });

  test("does not let an unrelated nested yaml module suppress a proven binding", async () => {
    const repository = await writeRepository({
      "app.py": [
        "import yaml",
        "from flask import request",
        "payload = request.data",
        "yaml.unsafe_load(payload)",
      ].join("\n"),
      "plugins/yaml.py": "def unsafe_load(value):\n    return value\n",
    });

    expect(
      pyyamlRecords(await buildResidualRiskInventory(repository)),
    ).toHaveLength(1);
  });

  test("reports source-backed object construction while bounding stronger impact", () => {
    const prompt = scanQualityGatePrompt("inventory-row");

    expect(prompt).toContain("For python-web-pyyaml-unsafe-load rows");
    expect(prompt).toContain("is sufficient to report CWE-502");
    expect(prompt).toContain("do not reject that finding merely because");
    expect(prompt).toContain("deployed-module observation");
    expect(prompt).toContain("In the validation section explicitly state");
    expect(prompt).toContain("in the attack path explicitly name");
    expect(prompt).toContain("discarding the returned value does not undo");
    expect(prompt).toContain("bounded non-destructive payload");
    expect(prompt).toContain("Before escalating beyond object/state integrity");
    expect(prompt).toContain("Report only the demonstrated impact");
    expect(prompt).not.toContain(
      "python-web-pyyaml-unsafe-load rows are always remote code execution",
    );
  });
});
