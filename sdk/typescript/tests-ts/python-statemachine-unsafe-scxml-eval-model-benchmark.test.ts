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

function statemachineRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "python-web-statemachine-unsafe-scxml-eval",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
  requirements: string | null = "python-statemachine==3.1.2\n",
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-statemachine-"),
  );
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  if (requirements !== null) {
    await writeFile(join(repository, "requirements.txt"), requirements, "utf8");
  }
  return repository;
}

function directLifecycle(
  binding: string,
  constructor: string,
  parse = 'processor.parse_scxml("uploaded", document)',
  start = "return processor.start()",
): string {
  return [
    binding,
    "def route(request):",
    "    document = request.get_data(as_text=True)",
    `    processor = ${constructor}`,
    `    ${parse}`,
    `    ${start}`,
  ].join("\n");
}

describe("Python python-statemachine unsafe SCXML evaluation model", () => {
  test("keeps a strict affected and restricted-evaluator benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "python-statemachine-unsafe-scxml-eval-manifest.json",
        ),
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
      "python-statemachine-unsafe-scxml-eval",
      "python-statemachine-restricted-evaluator-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-95"]);
    expect(manifest.cases[0]?.expected[0]?.acceptableSeverities).toEqual([
      "critical",
      "high",
    ]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(11);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(11);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(manifest.cases[1]?.expected).toEqual([]);

    for (const relativePath of [
      ".python-version",
      join("examples", "witness.py"),
      join("src", "loader.py"),
      join("src", "server.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-statemachine-unsafe-scxml-eval",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-statemachine-restricted-evaluator-control",
            relativePath,
          ),
          "utf8",
        ),
      );
    }
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-statemachine-unsafe-scxml-eval",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toContain("python-statemachine==3.1.2");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-statemachine-restricted-evaluator-control",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toContain("python-statemachine==3.2.0");
  });

  test("emits the exact cross-file request-document-to-start path", async () => {
    const affected = statemachineRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-statemachine-unsafe-scxml-eval",
        ),
      ),
    );
    const control = statemachineRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-statemachine-restricted-evaluator-control",
        ),
      ),
    );

    expect(control).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/loader.py");
    expect(affected[0]?.line).toBe(9);
    expect(affected[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(affected[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-document",
      path: "src/server.py",
      line: 14,
    });
    expect(affected[0]?.frameworkModel?.sink).toMatchObject({
      kind: "statemachine-affected-default-untrusted-scxml-evaluation",
      path: "src/loader.py",
      line: 9,
      cweIds: ["CWE-95"],
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "statemachine-scxml-processor-binding",
        "python-statemachine-runtime-dependency",
        "statemachine-scxml-processor-construction",
        "statemachine-untrusted-scxml-edge",
        "statemachine-start-execution",
        "intrinsic-statemachine-datamodel-eval",
      ]),
    );
    expect(
      affected[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "python-statemachine-runtime-dependency",
      )?.symbol,
    ).toBe("python-statemachine@3.1.2:requirements-exact");
  });

  test("supports exact module, processor-module, direct, aliased, parenthesized, class alias, keyword document, and repaired trusted opt-in forms", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": directLifecycle(
          "import statemachine.io.scxml.processor",
          "statemachine.io.scxml.processor.SCXMLProcessor()",
        ),
      }),
      writeRepository({
        "app.py": directLifecycle(
          "import statemachine.io.scxml.processor as scxml_processor",
          "scxml_processor.SCXMLProcessor()",
        ),
      }),
      writeRepository({
        "app.py": directLifecycle(
          "from statemachine.io.scxml import processor as scxml_processor",
          "scxml_processor.SCXMLProcessor()",
        ),
      }),
      writeRepository({
        "app.py": directLifecycle(
          "from statemachine.io.scxml.processor import SCXMLProcessor as Processor",
          "Processor()",
        ),
      }),
      writeRepository({
        "app.py": directLifecycle(
          [
            "from statemachine.io.scxml.processor import (",
            "    SCXMLProcessor as Processor,",
            ")",
          ].join("\n"),
          "Processor()",
        ),
      }),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "Processor = SCXMLProcessor",
          "def route(request):",
          "    document = request.get_data(as_text=True)",
          "    processor = Processor()",
          '    processor.parse_scxml("uploaded", document)',
          "    return processor.start()",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": directLifecycle(
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "SCXMLProcessor()",
          'processor.parse_scxml(sm_name="uploaded", scxml_content=document)',
        ),
      }),
      writeRepository(
        {
          "app.py": directLifecycle(
            "from statemachine.io.scxml.processor import SCXMLProcessor",
            "SCXMLProcessor(trusted=True)",
          ),
        },
        "python-statemachine==3.2.0\n",
      ),
      writeRepository(
        {
          "app.py": directLifecycle(
            "from statemachine.io.scxml.processor import SCXMLProcessor",
            "SCXMLProcessor(True)",
          ),
        },
        "python-statemachine==4.0.0\n",
      ),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        statemachineRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([
      1, 1, 1, 1, 1, 1, 1, 1, 1,
    ]);
    expect(
      records[5]?.[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("statemachine-scxml-processor-alias");
    expect(records[7]?.[0]?.frameworkModel?.sink.kind).toBe(
      "statemachine-explicit-trusted-untrusted-scxml-evaluation",
    );
  });

  test("rejects repaired defaults, unsupported metadata, broken lifecycles, shadows, replacements, star expansion, fixed input, and lookalikes", async () => {
    const exact = directLifecycle(
      "from statemachine.io.scxml.processor import SCXMLProcessor",
      "SCXMLProcessor()",
    );
    const repositories = await Promise.all([
      writeRepository({ "app.py": exact }, "python-statemachine==3.2.0\n"),
      writeRepository({ "app.py": exact }, "python-statemachine==2.5.0\n"),
      writeRepository({ "app.py": exact }, "python-statemachine>=3.0.0\n"),
      writeRepository({ "app.py": exact }, null),
      writeRepository(
        { "app.py": exact },
        "python-statemachine==3.1.2\npython-statemachine==3.1.1\n",
      ),
      writeRepository({ "app.py": exact }, "python-statemachine==3.1.2rc1\n"),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "def route(request):",
          "    document = request.get_data(as_text=True)",
          "    processor = SCXMLProcessor()",
          '    processor.parse_scxml("uploaded", document)',
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "def route(request):",
          "    document = request.get_data(as_text=True)",
          "    first = SCXMLProcessor()",
          "    second = SCXMLProcessor()",
          '    first.parse_scxml("uploaded", document)',
          "    return second.start()",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "def route(request):",
          "    document = request.get_data(as_text=True)",
          "    processor = SCXMLProcessor()",
          '    processor.parse_scxml("uploaded", document)',
          "    processor = request.processor",
          "    return processor.start()",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "def safe(*args): return None",
          "def route(request):",
          "    document = request.get_data(as_text=True)",
          "    processor = SCXMLProcessor()",
          "    processor.parse_scxml = safe",
          '    processor.parse_scxml("uploaded", document)',
          "    return processor.start()",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "def identity(value): return value",
          "def route(request):",
          "    document = request.get_data(as_text=True)",
          "    processor = identity(SCXMLProcessor())",
          '    processor.parse_scxml("uploaded", document)',
          "    return processor.start()",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "def route(request, SCXMLProcessor):",
          "    document = request.get_data(as_text=True)",
          "    processor = SCXMLProcessor()",
          '    processor.parse_scxml("uploaded", document)',
          "    return processor.start()",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "def safe(*args): return None",
          "def route(request):",
          "    document = request.get_data(as_text=True)",
          "    processor = SCXMLProcessor()",
          '    processor.parse_scxml("uploaded", document)',
          "    processor.start = safe",
          "    return processor.start()",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": directLifecycle(
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "SCXMLProcessor(*request.args)",
        ),
      }),
      writeRepository({
        "statemachine.py": "class io: pass\n",
        "app.py": exact,
      }),
      writeRepository({
        "statemachine/__init__.py": "class io: pass\n",
        "app.py": exact,
      }),
      writeRepository({
        "app.py": directLifecycle(
          "from statemachine.io.scxml import SCXMLProcessor",
          "SCXMLProcessor()",
        ),
      }),
      writeRepository({
        "app.py": directLifecycle(
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "SCXMLProcessor()",
          'processor.parse_scxml("uploaded", *request.json)',
        ),
      }),
      writeRepository({
        "app.py": [
          "from statemachine.io.scxml.processor import SCXMLProcessor",
          "def route(request):",
          "    request.get_data(as_text=True)",
          "    processor = SCXMLProcessor()",
          '    processor.parse_scxml("uploaded", "<scxml><state id=\'safe\'/></scxml>")',
          "    return processor.start()",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "text = 'from statemachine.io.scxml.processor import SCXMLProcessor'",
          "# processor.parse_scxml('uploaded', request.get_data())",
          "# processor.start()",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        statemachineRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual(
      Array.from({ length: repositories.length }, () => 0),
    );
  });

  test.skipIf(process.platform === "win32")(
    "does not follow a symlinked requirements file for version evidence",
    async () => {
      const repository = await writeRepository(
        {
          "app.py": directLifecycle(
            "from statemachine.io.scxml.processor import SCXMLProcessor",
            "SCXMLProcessor()",
          ),
          "actual-requirements.txt": "python-statemachine==3.1.2\n",
        },
        null,
      );
      await symlink(
        "actual-requirements.txt",
        join(repository, "requirements.txt"),
      );

      expect(
        statemachineRecords(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    },
  );

  test("preserves a two-relay path to the terminal start execution", async () => {
    const repository = await writeRepository({
      "server.py": [
        "from .relay import decode",
        "def route(request):",
        "    return decode(request.get_data(as_text=True))",
      ].join("\n"),
      "relay.py": [
        "from .service import execute",
        "def decode(document):",
        "    return execute(document)",
      ].join("\n"),
      "service.py": [
        "from .loader import run_statechart",
        "def execute(document):",
        "    return run_statechart(document)",
      ].join("\n"),
      "loader.py": [
        "from statemachine.io.scxml.processor import SCXMLProcessor",
        "def run_statechart(document):",
        "    processor = SCXMLProcessor()",
        '    processor.parse_scxml("uploaded", document)',
        "    return processor.start()",
      ].join("\n"),
    });

    const records = statemachineRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("loader.py");
  });

  test("binding-derived candidates survive dense unrelated start calls", async () => {
    const decoys = Array.from(
      { length: 80 },
      (_, index) => `    worker${index}.start()`,
    );
    const repository = await writeRepository({
      "app.py": [
        "from statemachine.io.scxml.processor import SCXMLProcessor",
        "def route(request):",
        ...decoys,
        "    document = request.get_data(as_text=True)",
        "    processor = SCXMLProcessor()",
        '    processor.parse_scxml("uploaded", document)',
        "    return processor.start()",
      ].join("\n"),
    });

    const records = statemachineRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(86);
  });

  test("host re-audit requires the complete SCXML evaluator boundary in both report fields", async () => {
    const repository = await writeRepository({
      "src/server.py": [
        "from .loader import run_statechart",
        "def route(request):",
        "    return run_statechart(request.get_data(as_text=True))",
      ].join("\n"),
      "src/loader.py": [
        "from statemachine.io.scxml.processor import SCXMLProcessor",
        "def run_statechart(document):",
        "    processor = SCXMLProcessor()",
        '    processor.parse_scxml("uploaded", document)',
        "    return processor.start()",
      ].join("\n"),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-statemachine-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_statemachine_quality",
      taxonomy: { cwe: ["CWE-95"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/loader.py", startLine: 5, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "document-source",
          path: "src/server.py",
          startLine: 3,
          code: "    return run_statechart(request.get_data(as_text=True))",
          explanation: "The request body enters the statechart wrapper.",
          role: "source",
        },
        {
          id: "start-sink",
          path: "src/loader.py",
          startLine: 5,
          code: "    return processor.start()",
          explanation: "The parsed document is executed by the processor.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms remote data reaches a statechart.",
        method: "static source trace and bounded arithmetic capability witness",
        exploitWitness: "The fixed arithmetic sentinel returns 42.",
        negativeControl: "A repaired evaluator rejects the capability probe.",
        evidence: ["document-source", "start-sink"],
        counterEvidence: "A byte limit does not restrict expression grammar.",
        remainingUncertainty: "Deployment privileges determine final impact.",
      },
      attackPath: {
        summary: "A remote document reaches server-side statechart execution.",
        dataflow: {
          source: "document-source",
          sink: "start-sink",
          outcome: "SCXML expression evaluation",
        },
        reachability: {
          attacker: "Remote statechart API caller",
          entrypoint: "SCXML upload endpoint",
          outcome: "Service-process integrity can be affected",
        },
        brokenControls: ["Affected evaluator default"],
        evidenceRefs: ["document-source", "start-sink"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const inventory = await buildResidualRiskInventory(repository);
    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    const rows = incomplete.split("\n").map((line) => JSON.parse(line));
    expect(rows[1]).toMatchObject({
      findingId: "occ_statemachine_quality",
      frameworkModelId: "python-web-statemachine-unsafe-scxml-eval",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "_create_dataitem_callable",
      "_eval",
      "Python eval",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "python-statemachine 3.2.0",
      "restricted evaluator",
      "InvalidDefinition",
    ]);

    const semanticContract = [
      "An SCXML upload from request.get_data supplies the request body.",
      "The run_statechart wrapper constructs the official python-statemachine SCXMLProcessor binding.",
      "parse_scxml receives the document argument through scxml_content.",
      "The exact python-statemachine==3.1.2 pin runs a <data expr> SCXML datamodel expression.",
      "processor.start() provides start execution and reaches _create_dataitem_callable then _eval and Python eval.",
      "On Python 3.12.3 the __import__ arithmetic sentinel evaluates 6 * 7 to 42.",
      "The python-statemachine 3.2.0 restricted evaluator control raises InvalidDefinition.",
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
        inventory,
      ),
    ).toBe("");
  });

  test("requires exact lifecycle, repaired-mode, and bounded capability evidence in the quality prompt", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain(
      "For python-web-statemachine-unsafe-scxml-eval rows",
    );
    expect(prompt).toContain("GHSA-v4jc-pm6r-3vj8 / CVE-2026-47103");
    expect(prompt).toContain(
      "create_datamodel_action_callable -> _create_dataitem_callable -> _eval -> Python eval",
    );
    expect(prompt).toContain("SCXMLProcessor(trusted=True)");
    expect(prompt).toContain("fixed arithmetic expression 6 * 7");
    expect(prompt).toContain("Report CWE-95");
  });
});
