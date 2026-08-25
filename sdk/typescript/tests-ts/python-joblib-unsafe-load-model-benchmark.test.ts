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
    propagators: Array<{ kind: string; path: string; line: number }>;
  };
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function joblibRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "python-web-joblib-unsafe-load",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-joblib-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

describe("Python Joblib unsafe deserialization model", () => {
  test("keeps a strict Joblib benchmark and topology-matched JSON control", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-joblib-unsafe-load-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        expected: Array<{
          cwe?: string[];
          acceptableSeverities?: string[];
          requiredValidationTextAnyOf?: string[][];
          requiredAttackPathTextAnyOf?: string[][];
          forbiddenText?: string[];
        }>;
      }>;
    };

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "python-joblib-unsafe-load",
      "python-joblib-json-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-502"]);
    expect(manifest.cases[0]?.expected[0]?.acceptableSeverities).toEqual([
      "critical",
      "high",
    ]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(10);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(10);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(manifest.cases[1]?.expected).toEqual([]);

    for (const relativePath of [
      join("examples", "witness.py"),
      join("src", "effects.py"),
      join("src", "server.py"),
      "RUNTIME.md",
      "requirements.txt",
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-joblib-unsafe-load",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-joblib-json-control",
            relativePath,
          ),
          "utf8",
        ),
      );
    }
    const unsafeParser = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        "python-joblib-unsafe-load",
        "src",
        "parser.py",
      ),
      "utf8",
    );
    const controlParser = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        "python-joblib-json-control",
        "src",
        "parser.py",
      ),
      "utf8",
    );
    expect(unsafeParser).toContain("return joblib.load(document)");
    expect(controlParser).toContain("return json.load(document)");
    expect(unsafeParser).toContain("MAX_MODEL_BYTES");
  });

  test("emits the exact cross-file upload-to-Joblib path", async () => {
    const repository = await writeRepository({
      "src/server.py": [
        "from .parser import parse_model",
        "def route(request):",
        "    return parse_model(request.files['model'].stream)",
      ].join("\n"),
      "src/parser.py": [
        "import joblib",
        "def parse_model(document):",
        "    return joblib.load(document)",
      ].join("\n"),
    });

    const records = joblibRecords(await buildResidualRiskInventory(repository));

    expect(records).toHaveLength(1);
    expect(records[0]?.path.replaceAll("\\", "/")).toBe("src/parser.py");
    expect(records[0]?.line).toBe(3);
    expect(records[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(records[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-body",
      path: "src/server.py",
      line: 3,
    });
    expect(records[0]?.frameworkModel?.sink).toMatchObject({
      kind: "joblib-load-untrusted-file",
      path: "src/parser.py",
      line: 3,
      cweIds: ["CWE-502"],
    });
    expect(
      records[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "joblib-load-binding",
        "intrinsic-joblib-pickle-reduce-execution",
      ]),
    );
  });

  test("emits the benchmark upload path and suppresses its JSON control", async () => {
    const unsafe = joblibRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-joblib-unsafe-load"),
      ),
    );
    const control = joblibRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-joblib-json-control"),
      ),
    );

    expect(control).toEqual([]);
    expect(unsafe).toHaveLength(1);
    expect(unsafe[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-body",
      path: "src/server.py",
      line: 11,
    });
    expect(unsafe[0]?.frameworkModel?.sink).toMatchObject({
      kind: "joblib-load-untrusted-file",
      path: "src/parser.py",
      line: 13,
      cweIds: ["CWE-502"],
    });
  });

  test("supports receiver and named aliases plus filename keyword", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          "import joblib as persistence",
          "def route(request):",
          "    return persistence.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from joblib import load as load_model",
          "def route(request):",
          "    return load_model(filename=request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from joblib import (",
          "    load as load_model,",
          ")",
          "def route(request):",
          "    return load_model(request.stream)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        joblibRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1]);
  });

  test("rejects fixed and wrong-role values, dumps, and star expansion", async () => {
    const repository = await writeRepository({
      "app.py": [
        "import joblib",
        "def route(request):",
        "    joblib.load('models/reviewed.joblib')",
        "    joblib.load('models/reviewed.joblib', mmap_mode=request.args['mode'])",
        "    joblib.load(filename='models/reviewed.joblib', ensure_native_byte_order=request.data)",
        "    joblib.load(*request.stream)",
        "    joblib.load(request.stream, *request.options)",
        "    joblib.dump(request.data, 'models/output.joblib')",
      ].join("\n"),
    });

    expect(joblibRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("rejects local shadows, reassignment, member replacement, and text", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "joblib.py": "def load(value):\n    return value\n",
        "app.py": [
          "import joblib",
          "def route(request):",
          "    return joblib.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import joblib",
          "def route(request):",
          "    joblib = request.parser",
          "    return joblib.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import joblib",
          "def safe(value): return value",
          "def route(request):",
          "    joblib.load = safe",
          "    return joblib.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "text = 'import joblib; joblib.load(request.stream)'",
          "# import joblib; joblib.load(request.stream)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        joblibRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0]);
  });

  test("preserves a two-relay path to the terminal Joblib binding", async () => {
    const repository = await writeRepository({
      "server.py": [
        "from .relay import decode",
        "def route(request):",
        "    return decode(request.stream)",
      ].join("\n"),
      "relay.py": [
        "from .service import apply_model",
        "def decode(value):",
        "    return apply_model(value)",
      ].join("\n"),
      "service.py": [
        "from .parser import parse_model",
        "def apply_model(value):",
        "    return parse_model(value)",
      ].join("\n"),
      "parser.py": [
        "from joblib import load as load_model",
        "def parse_model(document):",
        "    return load_model(document)",
      ].join("\n"),
    });

    const records = joblibRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("parser.py");
  });

  test("requires versioned callable validation and false-positive controls", () => {
    const prompt = scanQualityGatePrompt("inventory-row");

    expect(prompt).toContain("For python-web-joblib-unsafe-load rows");
    expect(prompt).toContain("argument zero or the filename keyword");
    expect(prompt).toContain(
      "Joblib documents that load relies on Python pickle",
    );
    expect(prompt).toContain("Python 3.12.3 and 3.14.5 with joblib 1.5.3");
    expect(prompt).toContain("parse_model wrapper");
    expect(prompt).toContain("fixture-local effects.mark state change");
    expect(prompt).toContain("mmap_mode and ensure_native_byte_order");
    expect(prompt).toContain("Report CWE-502");
  });
});
