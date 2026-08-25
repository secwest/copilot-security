import { afterEach, describe, expect, test } from "bun:test";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

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

function torchRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "python-web-torch-unsafe-load",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-torch-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

describe("Python PyTorch unsafe checkpoint model", () => {
  test("keeps a strict full-unpickler benchmark and patched weights-only control", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-torch-unsafe-load-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        findingsPaths: string[];
        expected: Array<{
          cwe?: string[];
          acceptableSeverities?: string[];
          requiredValidationTextAnyOf?: string[][];
          requiredAttackPathTextAnyOf?: string[][];
          forbiddenText?: string[];
        }>;
      }>;
    };
    const canonicalManifest = JSON.parse(
      await readFile(join(benchmarkRoot, "manifest.json"), "utf8"),
    ) as typeof manifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "python-torch-unsafe-load",
      "python-torch-weights-only-control",
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
    const canonicalCases = canonicalManifest.cases.filter(({ id }) =>
      id.startsWith("python-torch-"),
    );
    expect(canonicalCases.map(({ id }) => id)).toEqual(
      manifest.cases.map(({ id }) => id),
    );
    expect(
      canonicalCases.map(({ findingsPaths }) => findingsPaths.length),
    ).toEqual([3, 3]);
    expect(canonicalCases.map(({ expected }) => expected)).toEqual(
      manifest.cases.map(({ expected }) => expected),
    );

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
            "python-torch-unsafe-load",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-torch-weights-only-control",
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
        "python-torch-unsafe-load",
        "src",
        "parser.py",
      ),
      "utf8",
    );
    const controlParser = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        "python-torch-weights-only-control",
        "src",
        "parser.py",
      ),
      "utf8",
    );
    expect(unsafeParser).toContain("weights_only=False");
    expect(controlParser).toContain("weights_only=True");
    expect(unsafeParser.replace("False", "True")).toBe(controlParser);
  });

  test("emits the exact cross-file upload-to-Torch path and suppresses the control", async () => {
    const unsafe = torchRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-torch-unsafe-load"),
      ),
    );
    const control = torchRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-torch-weights-only-control"),
      ),
    );

    expect(control).toEqual([]);
    expect(unsafe).toHaveLength(1);
    expect(unsafe[0]?.path.replaceAll("\\", "/")).toBe("src/parser.py");
    expect(unsafe[0]?.line).toBe(13);
    expect(unsafe[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(unsafe[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-body",
      path: "src/server.py",
      line: 11,
    });
    expect(unsafe[0]?.frameworkModel?.sink).toMatchObject({
      kind: "torch-load-untrusted-checkpoint",
      path: "src/parser.py",
      line: 13,
      cweIds: ["CWE-502"],
    });
    expect(
      unsafe[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "torch-load-binding",
        "explicit-torch-full-unpickler",
        "intrinsic-torch-checkpoint-unpickling",
      ]),
    );
  });

  test("supports receiver and named aliases plus the f keyword", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          "import torch as framework",
          "def route(request):",
          "    return framework.load(request.stream, weights_only=False)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from torch import load as load_model",
          "def route(request):",
          "    return load_model(f=request.stream, weights_only=False)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from torch import (",
          "    load as load_model,",
          ")",
          "def route(request):",
          "    return load_model(request.stream, weights_only=False)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        torchRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1]);
  });

  test("models custom-pickle, legacy-default, and affected weights-only modes", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          "import pickle",
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, pickle_module=pickle)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==2.5.1\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==2.9.1+cpu\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, weights_only=True)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        torchRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1]);
    expect(
      records.map((rows) => rows[0]?.frameworkModel?.propagators[1]?.kind),
    ).toEqual([
      "custom-torch-pickle-module",
      "legacy-torch-full-unpickler-default",
      "affected-torch-weights-only-version",
    ]);
    expect(records[2]?.[0]?.frameworkModel?.propagators[1]?.symbol).toContain(
      "GHSA-63cw-57p8-fm3p",
    );
  });

  test("does not invent unsupported keywords, unsafe defaults, or affected versions", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "requirements.txt": "torch==1.12.1\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, weights_only=False)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==1.12.1\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, weights_only=True)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch>=2.0\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==2.10.0+cpu\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, weights_only=True)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==2.6.0+cpu\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==2.13.0+cpu\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==2.9.1\ntorch==2.13.0\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, weights_only=True)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==2.5.1\n",
        "src/requirements.txt": "Flask==3.1.2\n",
        "src/app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        torchRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([
      0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
  });

  test("accepts the first supported weights-only version boundary", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "requirements.txt": "torch==1.13.0\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, weights_only=False)",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "torch==1.13.0\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, weights_only=True)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        torchRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 1]);
    expect(
      records.map((rows) => rows[0]?.frameworkModel?.propagators[1]?.kind),
    ).toEqual([
      "explicit-torch-full-unpickler",
      "affected-torch-weights-only-version",
    ]);
  });

  test.skipIf(process.platform === "win32")(
    "does not follow a symlinked requirements file for version evidence",
    async () => {
      const repository = await writeRepository({
        "real-requirements.txt": "torch==2.5.1\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream)",
        ].join("\n"),
      });
      await symlink(
        "real-requirements.txt",
        join(repository, "requirements.txt"),
      );

      expect(
        torchRecords(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    },
  );

  test("rejects fixed and wrong-role values, dynamic modes, save, and star expansion", async () => {
    const repository = await writeRepository({
      "app.py": [
        "import torch",
        "def route(request):",
        "    torch.load('models/reviewed.pt', weights_only=False)",
        "    torch.load('models/reviewed.pt', map_location=request.args['device'], weights_only=False)",
        "    torch.load(f='models/reviewed.pt', weights_only=request.json['mode'])",
        "    torch.load(*request.stream, weights_only=False)",
        "    torch.load(request.stream, *request.options, weights_only=False)",
        "    torch.save(request.data, 'models/output.pt')",
      ].join("\n"),
    });

    expect(torchRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("rejects local shadows, reassignment, member replacement, and text", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "torch.py": "def load(value, **options):\n    return value\n",
        "app.py": [
          "import torch",
          "def route(request):",
          "    return torch.load(request.stream, weights_only=False)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import torch",
          "def route(request):",
          "    torch = request.parser",
          "    return torch.load(request.stream, weights_only=False)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import torch",
          "def safe(value, **options): return value",
          "def route(request):",
          "    torch.load = safe",
          "    return torch.load(request.stream, weights_only=False)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "text = 'import torch; torch.load(request.stream, weights_only=False)'",
          "# import torch; torch.load(request.stream, weights_only=False)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        torchRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0]);
  });

  test("preserves a two-relay path to the terminal Torch binding", async () => {
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
        "from torch import load as load_model",
        "def parse_model(document):",
        "    return load_model(document, weights_only=False)",
      ].join("\n"),
    });

    const records = torchRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("parser.py");
  });

  test("host re-audit requires Torch evidence in both report fields", async () => {
    const repository = await writeRepository({
      "src/server.py": [
        "from .parser import parse_model",
        "def route(request):",
        "    return parse_model(request.stream)",
      ].join("\n"),
      "src/parser.py": [
        "import torch",
        "def parse_model(document):",
        "    return torch.load(document, weights_only=False)",
      ].join("\n"),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-torch-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_torch_quality",
      taxonomy: { cwe: ["CWE-502"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/parser.py", startLine: 3, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "upload-source",
          path: "src/server.py",
          startLine: 3,
          code: "    return parse_model(request.stream)",
          explanation: "The request stream enters the parser wrapper.",
          role: "source",
        },
        {
          id: "torch-sink",
          path: "src/parser.py",
          startLine: 3,
          code: "    return torch.load(document, weights_only=False)",
          explanation: "The same stream reaches full checkpoint loading.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms a reachable unsafe deserializer.",
        method: "static source trace",
        exploitWitness: "A compact checkpoint reaches callable reconstruction.",
        negativeControl:
          "Patched weights-only loading rejects the fixture callable.",
        evidence: ["upload-source", "torch-sink"],
        counterEvidence: "A byte limit does not constrain reconstruction.",
        remainingUncertainty:
          "Deployment versions and privileges determine final impact.",
      },
      attackPath: {
        summary: "A remote caller reaches unsafe checkpoint reconstruction.",
        dataflow: {
          source: "upload-source",
          sink: "torch-sink",
          outcome: "attacker-selected callable reconstruction",
        },
        reachability: {
          attacker: "Unauthenticated remote caller",
          entrypoint: "Model import HTTP endpoint",
          outcome: "Service-process integrity is compromised",
        },
        brokenControls: ["Full unpickler explicitly enabled"],
        evidenceRefs: ["upload-source", "torch-sink"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const residualRiskInventory = await buildResidualRiskInventory(repository);

    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      residualRiskInventory,
    );
    const rows = incomplete.split("\n").map((line) => JSON.parse(line));
    expect(rows[1]).toMatchObject({
      findingId: "occ_torch_quality",
      frameworkModelId: "python-web-torch-unsafe-load",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "parse_model",
      "wrapper",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "Python 3.12.3",
    ]);

    const semanticContract = [
      "A model upload from request.files reaches the uploaded stream.",
      "The parse_model wrapper passes its file object as argument zero to torch.load.",
      "The explicit weights_only=False full unpickler uses the Python pickle protocol.",
      "The fixture __reduce__ callable invokes effects.mark.",
      "That in-process effect proves process integrity impact.",
      "The fixture was tested on Python 3.12.3 with torch 2.13.0+cpu;",
      "this does not prove deployment versions.",
    ].join(" ");
    finding.validation.summary = semanticContract;
    finding.attackPath.summary = semanticContract;
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );

    expect(
      await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        residualRiskInventory,
      ),
    ).toBe("");
  });

  test("requires versioned callable validation and precise false-positive controls", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain("For python-web-torch-unsafe-load rows");
    expect(prompt).toContain("artifact argument zero or f keyword");
    expect(prompt).toContain("explicit weights_only=False");
    expect(prompt).toContain("pre-2.6 default");
    expect(prompt).toContain(
      "PyTorch 1.13.0 introduced the weights_only keyword",
    );
    expect(prompt).toContain("known pre-1.13 keyword call");
    expect(prompt).toContain("GHSA-63cw-57p8-fm3p");
    expect(prompt).toContain("Python 3.12.3 and torch 2.13.0+cpu");
    expect(prompt).toContain("fixture-local effects.mark");
    expect(prompt).toContain("modern omitted default");
    expect(prompt).toContain("Report CWE-502");
  });
});
