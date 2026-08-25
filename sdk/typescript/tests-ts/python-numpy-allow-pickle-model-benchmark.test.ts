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

function numpyRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "python-web-numpy-allow-pickle-load",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-numpy-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

describe("Python NumPy allow_pickle unsafe deserialization model", () => {
  test("keeps a strict object-array benchmark and identical fail-closed control", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-numpy-allow-pickle-manifest.json"),
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
      "python-numpy-allow-pickle",
      "python-numpy-no-pickle-control",
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
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(3);
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
            "python-numpy-allow-pickle",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-numpy-no-pickle-control",
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
        "python-numpy-allow-pickle",
        "src",
        "parser.py",
      ),
      "utf8",
    );
    const controlParser = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        "python-numpy-no-pickle-control",
        "src",
        "parser.py",
      ),
      "utf8",
    );
    expect(
      unsafeParser.replace("allow_pickle=True", "allow_pickle=False"),
    ).toBe(controlParser);
    expect(unsafeParser).toContain("MAX_ARRAY_BYTES");
    expect(unsafeParser).toContain("MAX_ARRAY_ELEMENTS");
    expect(unsafeParser).toContain("max_header_size=1024");
    const runtimeContract = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        "python-numpy-allow-pickle",
        "RUNTIME.md",
      ),
      "utf8",
    );
    expect(runtimeContract).toContain("Python 3.12.3");
    expect(runtimeContract).toContain("Python 3.14.5");
    expect(runtimeContract).toContain("NumPy 2.5.2");
  });

  test("emits the exact cross-file stream-to-object-array unpickling path", async () => {
    const repository = await writeRepository({
      "src/server.py": [
        "from .parser import parse_array",
        "def route(request):",
        "    return parse_array(request.stream)",
      ].join("\n"),
      "src/parser.py": [
        "import numpy as np",
        "def parse_array(document):",
        "    return np.load(document, allow_pickle=True)",
      ].join("\n"),
    });

    const records = numpyRecords(await buildResidualRiskInventory(repository));

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
      kind: "numpy-load-allow-pickle-untrusted-file",
      path: "src/parser.py",
      line: 3,
      cweIds: ["CWE-502"],
    });
    expect(
      records[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "numpy-load-binding",
        "explicit-numpy-allow-pickle",
        "intrinsic-numpy-object-array-unpickling",
      ]),
    );
  });

  test("emits the benchmark upload path and suppresses its false control", async () => {
    const unsafe = numpyRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-numpy-allow-pickle"),
      ),
    );
    const control = numpyRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-numpy-no-pickle-control"),
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
      kind: "numpy-load-allow-pickle-untrusted-file",
      path: "src/parser.py",
      line: 31,
      cweIds: ["CWE-502"],
    });
  });

  test("supports receiver and named aliases plus keyword file", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          "import numpy as arrays",
          "def route(request):",
          "    return arrays.load(request.stream, None, True)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from numpy import load as load_array",
          "def route(request):",
          "    return load_array(file=request.stream, allow_pickle=True)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from numpy import (",
          "    load as load_array,",
          ")",
          "def route(request):",
          "    return load_array(request.stream, allow_pickle=True)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        numpyRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1]);
  });

  test("rejects defaults, false or dynamic flags, wrong roles, and star expansion", async () => {
    const repository = await writeRepository({
      "app.py": [
        "import numpy as np",
        "def route(request):",
        "    np.load(request.stream)",
        "    np.load(request.stream, allow_pickle=False)",
        "    np.load(request.stream, allow_pickle=request.allow_pickle)",
        "    np.load(b'fixed.npy', mmap_mode=request.stream, allow_pickle=True)",
        "    np.load(file=b'fixed.npy', allow_pickle=True, encoding=request.data)",
        "    np.load(*request.stream, allow_pickle=True)",
        "    np.load(request.stream, *request.options, allow_pickle=True)",
      ].join("\n"),
    });

    expect(numpyRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("rejects local shadows, reassignment, member replacement, and text", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "numpy.py": "def load(value, **kwargs):\n    return value\n",
        "app.py": [
          "import numpy",
          "def route(request):",
          "    return numpy.load(request.stream, allow_pickle=True)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import numpy as np",
          "def route(request):",
          "    np = request.parser",
          "    return np.load(request.stream, allow_pickle=True)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import numpy as np",
          "def safe(value, **kwargs): return value",
          "def route(request):",
          "    np.load = safe",
          "    return np.load(request.stream, allow_pickle=True)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "text = 'import numpy as np; np.load(request.stream, allow_pickle=True)'",
          "# import numpy as np; np.load(request.stream, allow_pickle=True)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        numpyRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0]);
  });

  test("preserves a two-relay path to the terminal NumPy binding", async () => {
    const repository = await writeRepository({
      "server.py": [
        "from .relay import decode",
        "def route(request):",
        "    return decode(request.stream)",
      ].join("\n"),
      "relay.py": [
        "from .service import apply_array",
        "def decode(value):",
        "    return apply_array(value)",
      ].join("\n"),
      "service.py": [
        "from .parser import parse_array",
        "def apply_array(value):",
        "    return parse_array(value)",
      ].join("\n"),
      "parser.py": [
        "from numpy import load as load_array",
        "def parse_array(document):",
        "    return load_array(document, allow_pickle=True)",
      ].join("\n"),
    });

    const records = numpyRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("parser.py");
  });

  test("requires versioned object-array validation and the false-positive control", () => {
    const prompt = scanQualityGatePrompt("inventory-row");

    expect(prompt).toContain("For python-web-numpy-allow-pickle-load rows");
    expect(prompt).toContain("allow_pickle=False as the default");
    expect(prompt).toContain("object-dtype .npy witness");
    expect(prompt).toContain("exact tested Python and NumPy versions");
    expect(prompt).toContain("Validation and attack path must each separately");
    expect(prompt).toContain("parse_array wrapper");
    expect(prompt).toContain("Python 3.12.3 and 3.14.5 with NumPy 2.5.2");
    expect(prompt).toContain("__reduce__ callable");
    expect(prompt).toContain("inert .npz archive that is never indexed");
    expect(prompt).toContain("Report CWE-502");
  });
});
