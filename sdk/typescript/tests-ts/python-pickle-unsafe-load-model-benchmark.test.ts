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
      acceptableSeverities?: string[];
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

function pickleRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "python-web-pickle-unsafe-load",
  );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-pickle-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

describe("Python pickle unsafe deserialization model", () => {
  test("keeps a strict callable-execution benchmark and JSON control", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-pickle-unsafe-load-manifest.json"),
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
      "python-pickle-unsafe-load",
      "python-pickle-json-control",
    ]);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-502"]);
    expect(manifest.cases[0]?.expected[0]?.acceptableSeverities).toEqual([
      "critical",
      "high",
    ]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(3);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(4);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(3);
    expect(manifest.cases[1]?.expected).toEqual([]);
    for (const relativePath of [
      join("examples", "witness.py"),
      join("src", "effects.py"),
      join("src", "server.py"),
      "requirements.txt",
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-pickle-unsafe-load",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-pickle-json-control",
            relativePath,
          ),
          "utf8",
        ),
      );
    }
  });

  test("emits the exact request-to-pickle.loads wrapper path", async () => {
    const unsafeRoot = join(
      benchmarkRoot,
      "fixtures",
      "python-pickle-unsafe-load",
    );
    const safeRoot = join(
      benchmarkRoot,
      "fixtures",
      "python-pickle-json-control",
    );
    const unsafe = pickleRecords(await buildResidualRiskInventory(unsafeRoot));
    const safe = pickleRecords(await buildResidualRiskInventory(safeRoot));

    expect(safe).toEqual([]);
    expect(unsafe).toHaveLength(1);
    expect(unsafe[0]?.path.replaceAll("\\", "/")).toBe("src/parser.py");
    expect(unsafe[0]?.line).toBe(5);
    expect(unsafe[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(unsafe[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-body",
      path: "src/server.py",
      line: 10,
    });
    expect(unsafe[0]?.frameworkModel?.sink).toMatchObject({
      kind: "pickle-loads-untrusted-bytes",
      path: "src/parser.py",
      line: 5,
      cweIds: ["CWE-502"],
    });
    expect(
      unsafe[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("python-stdlib-pickle-binding");
    expect(
      unsafe[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("intrinsic-pickle-reduce-execution");
  });

  test("supports receiver, named, and parenthesized aliases with exact argument zero", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          "import pickle as serializer",
          "def route(request):",
          "    return serializer.loads(request.data)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from pickle import loads as decode",
          "def route(request):",
          "    return decode(request.body, fix_imports=False)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from pickle import (",
          "    load as decode,",
          ")",
          "def route(request):",
          "    return decode(request.stream)",
        ].join("\n"),
      }),
    ]);
    const records = await Promise.all(
      repositories.map(async (repository) =>
        pickleRecords(await buildResidualRiskInventory(repository)),
      ),
    );

    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1]);
    expect(records[0]?.[0]?.frameworkModel?.sink.kind).toBe(
      "pickle-loads-untrusted-bytes",
    );
    expect(records[1]?.[0]?.frameworkModel?.sink.kind).toBe(
      "pickle-loads-untrusted-bytes",
    );
    expect(records[2]?.[0]?.frameworkModel?.sink.kind).toBe(
      "pickle-load-untrusted-file",
    );
  });

  test("preserves a two-relay path and terminal pickle binding", async () => {
    const repository = await writeRepository({
      "server.py": [
        "from .relay import decode",
        "def route(request):",
        "    payload = request.get_data()",
        "    return decode(payload)",
      ].join("\n"),
      "relay.py": [
        "from .service import apply_profile",
        "def decode(value):",
        "    return apply_profile(value)",
      ].join("\n"),
      "service.py": [
        "from .parser import parse_profile",
        "def apply_profile(blob):",
        "    return parse_profile(blob)",
      ].join("\n"),
      "parser.py": [
        "import pickle",
        "def parse_profile(document):",
        "    return pickle.loads(document)",
      ].join("\n"),
    });
    const records = pickleRecords(await buildResidualRiskInventory(repository));

    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("parser.py");
    expect(
      records[0]?.frameworkModel?.propagators.map(({ path }) => path),
    ).toEqual(expect.arrayContaining(["relay.py", "service.py", "parser.py"]));
  });

  test("rejects safe APIs, fixed data, wrong argument roles, and star expansion", async () => {
    const repository = await writeRepository({
      "app.py": [
        "import json",
        "import pickle",
        "def route(request):",
        "    json.loads(request.data)",
        "    pickle.dumps(request.data)",
        "    pickle.loads(b'fixed')",
        "    pickle.loads(b'fixed', request.data)",
        "    pickle.loads(data=request.data)",
        "    pickle.loads(*request.data)",
      ].join("\n"),
    });

    expect(pickleRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("rejects local shadows, reassignment, member replacement, and text", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "pickle.py": "def loads(value):\n    return value\n",
        "app.py":
          "import pickle\ndef route(request):\n    return pickle.loads(request.data)\n",
      }),
      writeRepository({
        "app.py": [
          "import pickle",
          "def route(request):",
          "    pickle = request.parser",
          "    return pickle.loads(request.data)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import pickle",
          "def safe(value): return value",
          "def route(request):",
          "    pickle.loads = safe",
          "    return pickle.loads(request.data)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          'text = "import pickle; pickle.loads(request.data)"',
          "# import pickle; pickle.loads(request.data)",
        ].join("\n"),
      }),
    ]);
    const records = await Promise.all(
      repositories.map(async (repository) =>
        pickleRecords(await buildResidualRiskInventory(repository)),
      ),
    );

    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0]);
  });

  test("does not let an unrelated nested pickle module suppress a proven binding", async () => {
    const repository = await writeRepository({
      "app.py": [
        "import pickle",
        "def route(request):",
        "    return pickle.loads(request.data)",
      ].join("\n"),
      "plugins/pickle.py": "def loads(value):\n    return value\n",
    });

    expect(
      pickleRecords(await buildResidualRiskInventory(repository)),
    ).toHaveLength(1);
  });

  test("requires intrinsic execution validation and pre-load integrity controls", () => {
    const prompt = scanQualityGatePrompt("inventory-row");

    expect(prompt).toContain("For python-web-pickle-unsafe-load rows");
    expect(prompt).toContain("GLOBAL/STACK_GLOBAL and REDUCE machinery");
    expect(prompt).toContain("separately installed gadget is not required");
    expect(prompt).toContain("bounded non-destructive callable witness");
    expect(prompt).toContain("fails closed before unpickling");
    expect(prompt).toContain("Report CWE-502");
    expect(prompt).not.toContain(
      "python-web-pickle-unsafe-load rows are safe after authentication",
    );
  });
});
