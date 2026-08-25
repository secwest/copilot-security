import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

function datamodelCodegenRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "python-web-datamodel-codegen-import-injection",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
  requirements: string | null = "datamodel-code-generator==0.63.0\n",
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-datamodel-codegen-"),
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

function fileLifecycle(
  generatorBinding = "from datamodel_code_generator import generate",
  generateCall = "generate(schema, output=output_path)",
  executionBinding = "import runpy",
  executionCall = "runpy.run_path(output_path)",
): string {
  return [
    generatorBinding,
    executionBinding,
    "def route(request):",
    "    schema = request.get_json()",
    '    output_path = "/tmp/generated_model.py"',
    `    ${generateCall}`,
    `    return ${executionCall}`,
  ].join("\n");
}

describe("Python datamodel-code-generator import injection model", () => {
  test("keeps a strict affected and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "python-datamodel-codegen-import-injection-manifest.json",
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
      "python-datamodel-codegen-import-injection",
      "python-datamodel-codegen-validated-import-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-94", "CWE-95"]);
    expect(manifest.cases[0]?.expected[0]?.acceptableSeverities).toEqual([
      "critical",
      "high",
    ]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(12);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(12);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(manifest.cases[1]?.expected).toEqual([]);

    for (const relativePath of [
      ".python-version",
      join("examples", "witness.py"),
      join("src", "__init__.py"),
      join("src", "loader.py"),
      join("src", "server.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-datamodel-codegen-import-injection",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-datamodel-codegen-validated-import-control",
            relativePath,
          ),
          "utf8",
        ),
      );
    }
  });

  test("detects only the affected topology-identical benchmark fixture", async () => {
    const affected = datamodelCodegenRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-datamodel-codegen-import-injection",
        ),
      ),
    );
    const control = datamodelCodegenRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-datamodel-codegen-validated-import-control",
        ),
      ),
    );

    expect(control).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/loader.py");
    expect(affected[0]?.line).toBe(12);
    expect(affected[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(affected[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-schema",
      path: "src/server.py",
      line: 12,
    });
    expect(affected[0]?.frameworkModel?.sink).toMatchObject({
      kind: "datamodel-codegen-affected-generated-module-execution",
      path: "src/loader.py",
      line: 12,
      cweIds: ["CWE-94", "CWE-95"],
    });
  });

  test("emits the exact request-schema-to-generated-module execution path", async () => {
    const repository = await writeRepository({ "app.py": fileLifecycle() });
    const records = datamodelCodegenRecords(
      await buildResidualRiskInventory(repository),
    );

    expect(records).toHaveLength(1);
    expect(records[0]?.path.replaceAll("\\", "/")).toBe("app.py");
    expect(records[0]?.line).toBe(7);
    expect(records[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-schema",
      path: "app.py",
      line: 7,
    });
    expect(records[0]?.frameworkModel?.sink).toMatchObject({
      kind: "datamodel-codegen-affected-generated-module-execution",
      path: "app.py",
      line: 7,
      cweIds: ["CWE-94", "CWE-95"],
    });
    expect(
      records[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "datamodel-codegen-generate-binding",
        "datamodel-codegen-runtime-dependency",
        "datamodel-codegen-untrusted-schema-edge",
        "datamodel-codegen-generated-source-edge",
        "datamodel-codegen-generated-module-execution",
        "intrinsic-datamodel-codegen-import-rendering",
      ]),
    );
  });

  test("supports module, import, parenthesized, direct alias, run_path alias, keyword, returned-source, compile, and builtins execution forms", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": fileLifecycle(
          "import datamodel_code_generator",
          "datamodel_code_generator.generate(schema, output=output_path)",
        ),
      }),
      writeRepository({
        "app.py": fileLifecycle(
          "import datamodel_code_generator as dcg",
          "dcg.generate(input_=schema, output=output_path)",
        ),
      }),
      writeRepository({
        "app.py": fileLifecycle(
          [
            "from datamodel_code_generator import (",
            "    generate as compile_schema,",
            ")",
          ].join("\n"),
          "compile_schema(schema, output=output_path)",
        ),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "compile_schema = generate",
          "import runpy",
          "def route(request):",
          "    schema = request.get_json()",
          '    output_path = "/tmp/generated_model.py"',
          "    compile_schema(schema, output=output_path)",
          "    return runpy.run_path(output_path)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": fileLifecycle(
          undefined,
          undefined,
          "from runpy import run_path as execute_model",
          "execute_model(path_name=output_path)",
        ),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "def route(request):",
          "    schema = request.get_json()",
          "    generated = generate(schema)",
          "    exec(generated)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "def route(request):",
          "    schema = request.get_json()",
          '    generated = generate(input_=schema, input_file_type="jsonschema")',
          '    exec(compile(generated, "<generated>", "exec"))',
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "import builtins as py_builtins",
          "def route(request):",
          "    schema = request.get_json()",
          "    generated = generate(schema)",
          "    py_builtins.exec(generated)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "from builtins import exec as execute_source",
          "def route(request):",
          "    schema = request.get_json()",
          "    execute_source(generate(schema))",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        datamodelCodegenRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([
      1, 1, 1, 1, 1, 1, 1, 1, 1,
    ]);
    expect(
      records[3]?.[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("datamodel-codegen-generate-alias");
  });

  test("rejects repaired or ambiguous metadata, broken lifecycles, shadows, replacements, star expansion, fixed input, and lookalikes", async () => {
    const exact = fileLifecycle();
    const repositories = await Promise.all([
      writeRepository(
        { "app.py": exact },
        "datamodel-code-generator==0.64.0\n",
      ),
      writeRepository(
        { "app.py": exact },
        "datamodel-code-generator==0.11.5\n",
      ),
      writeRepository(
        { "app.py": exact },
        "datamodel-code-generator>=0.11.6\n",
      ),
      writeRepository({ "app.py": exact }, null),
      writeRepository(
        { "app.py": exact },
        "datamodel-code-generator==0.63.0\ndatamodel-code-generator==0.62.0\n",
      ),
      writeRepository(
        { "app.py": exact },
        "datamodel-code-generator==0.63.0rc1\n",
      ),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "def route(request):",
          "    generate(request.get_json(), output='/tmp/model.py')",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "def route(request):",
          "    request.get_json()",
          "    exec('answer = 6 * 7')",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": fileLifecycle(
          undefined,
          "generate(schema, output=output_path)",
          undefined,
          "runpy.run_path(other_path)",
        ),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "import runpy",
          "def route(request):",
          "    schema = request.get_json()",
          '    output_path = "/tmp/first.py"',
          "    generate(schema, output=output_path)",
          '    output_path = "/tmp/second.py"',
          "    return runpy.run_path(output_path)",
        ].join("\n"),
      }),
      writeRepository({
        "datamodel_code_generator.py":
          "def generate(*args, **kwargs): return None\n",
        "app.py": exact,
      }),
      writeRepository({
        "datamodel_code_generator/__init__.py":
          "def generate(*args, **kwargs): return None\n",
        "app.py": exact,
      }),
      writeRepository({
        "runpy.py": "def run_path(path): return {}\n",
        "app.py": exact,
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "import runpy",
          "def safe(*args, **kwargs): return None",
          "def route(request):",
          "    schema = request.get_json()",
          '    output_path = "/tmp/model.py"',
          "    generate = safe",
          "    generate(schema, output=output_path)",
          "    return runpy.run_path(output_path)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "import runpy",
          "def safe(path): return {}",
          "def route(request):",
          "    schema = request.get_json()",
          '    output_path = "/tmp/model.py"',
          "    generate(schema, output=output_path)",
          "    runpy.run_path = safe",
          "    return runpy.run_path(output_path)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": fileLifecycle(
          undefined,
          "generate(*request.get_json(), output=output_path)",
        ),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "import runpy",
          "def route(request):",
          "    request.get_json()",
          '    output_path = "/tmp/model.py"',
          '    generate({"type": "object"}, output=output_path)',
          "    return runpy.run_path(output_path)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": fileLifecycle(
          undefined,
          'generate(schema, input_file_type="csv", output=output_path)',
        ),
      }),
      writeRepository({
        "app.py": [
          "from datamodel_code_generator import generate",
          "def route(request):",
          "    generated = generate(request.get_json(), output='/tmp/model.py')",
          "    exec(generated)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "text = 'from datamodel_code_generator import generate'",
          "# generate(request.get_json(), output='/tmp/model.py')",
          "# runpy.run_path('/tmp/model.py')",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        datamodelCodegenRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual(
      Array.from({ length: repositories.length }, () => 0),
    );
  });

  test("preserves a two-relay cross-file path to generated-module execution", async () => {
    const repository = await writeRepository({
      "server.py": [
        "from .relay import decode",
        "def route(request):",
        "    return decode(request.get_json())",
      ].join("\n"),
      "relay.py": [
        "from .service import compile_schema",
        "def decode(schema):",
        "    return compile_schema(schema)",
      ].join("\n"),
      "service.py": [
        "from .loader import compile_and_load",
        "def compile_schema(schema):",
        "    return compile_and_load(schema)",
      ].join("\n"),
      "loader.py": [
        "from datamodel_code_generator import generate",
        "import runpy",
        "def compile_and_load(schema):",
        '    output_path = "/tmp/generated_model.py"',
        "    generate(schema, output=output_path)",
        "    return runpy.run_path(output_path)",
      ].join("\n"),
    });

    const records = datamodelCodegenRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("loader.py");
  });

  test("binding-derived candidates survive dense unrelated exec calls", async () => {
    const decoys = Array.from(
      { length: 80 },
      (_, index) => `    exec("value_${index} = ${index}")`,
    );
    const repository = await writeRepository({
      "app.py": [
        "from datamodel_code_generator import generate",
        "import runpy",
        "def route(request):",
        ...decoys,
        "    schema = request.get_json()",
        '    output_path = "/tmp/generated_model.py"',
        "    generate(schema, output=output_path)",
        "    return runpy.run_path(output_path)",
      ].join("\n"),
    });

    const records = datamodelCodegenRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(87);
  });

  test("host re-audit requires the complete generation-to-execution boundary in both report fields", async () => {
    const repository = await writeRepository({
      "src/server.py": [
        "from .loader import compile_and_load",
        "def route(request):",
        "    return compile_and_load(request.get_json())",
      ].join("\n"),
      "src/loader.py": [
        "from datamodel_code_generator import generate",
        "import runpy",
        "def compile_and_load(schema):",
        '    output_path = "/tmp/generated.py"',
        "    generate(schema, output=output_path)",
        "    return runpy.run_path(output_path)",
      ].join("\n"),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-datamodel-codegen-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_datamodel_codegen_quality",
      taxonomy: { cwe: ["CWE-94", "CWE-95"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/loader.py", startLine: 6, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "schema-source",
          path: "src/server.py",
          startLine: 3,
          code: "    return compile_and_load(request.get_json())",
          explanation: "The request JSON enters the generator wrapper.",
          role: "source",
        },
        {
          id: "execution-sink",
          path: "src/loader.py",
          startLine: 6,
          code: "    return runpy.run_path(output_path)",
          explanation: "The application executes the generated source path.",
          role: "sink",
        },
      ],
      validation: {
        summary:
          "Static review confirms a remote schema reaches generation and execution.",
        method: "static source trace and bounded arithmetic capability witness",
        exploitWitness: "The fixed arithmetic sentinel returns 42.",
        negativeControl: "A repaired generator rejects the import path.",
        evidence: ["schema-source", "execution-sink"],
        counterEvidence: "A content size limit does not validate import paths.",
        remainingUncertainty: "Deployment privileges determine final impact.",
      },
      attackPath: {
        summary: "A remote schema reaches execution of generated Python.",
        dataflow: {
          source: "schema-source",
          sink: "execution-sink",
          outcome: "Generated module execution",
        },
        reachability: {
          attacker: "Remote schema API caller",
          entrypoint: "JSON Schema upload endpoint",
          outcome: "Service-process integrity can be affected",
        },
        brokenControls: ["Affected import-path validation"],
        evidenceRefs: ["schema-source", "execution-sink"],
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
      findingId: "occ_datamodel_codegen_quality",
      frameworkModelId: "python-web-datamodel-codegen-import-injection",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "Import.from_full_path",
      "Imports.create_line",
      "unvalidated import path",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "datamodel-code-generator 0.64.0",
      "validation Error",
      "repaired release",
    ]);

    const semanticContract = [
      "A schema upload from request.get_json supplies the request JSON Schema.",
      "The compile_and_load wrapper invokes the official datamodel_code_generator.generate binding with the input_ schema argument at argument zero.",
      "The exact datamodel-code-generator==0.63.0 pin accepts an x-python-import schema extension.",
      "Import.from_full_path reaches Imports.create_line with an unvalidated import path and writes generated model source to the generated output path.",
      "runpy.run_path provides module-scope execution of the generated source.",
      "On Python 3.12.3 the fixed 6 * 7 arithmetic sentinel produces 42.",
      "The datamodel-code-generator 0.64.0 repaired release raises validation Error.",
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

  test("requires exact package, extension, generated-source execution, and bounded witness evidence in the quality prompt", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain(
      "For python-web-datamodel-codegen-import-injection rows",
    );
    expect(prompt).toContain("GHSA-5578-w22f-pfx9 / CVE-2026-55415");
    expect(prompt).toContain(
      "x-python-import/customTypePath -> Import.from_full_path -> Imports.create_line",
    );
    expect(prompt).toContain("runpy.run_path or built-in exec");
    expect(prompt).toContain("fixed arithmetic statement print(6 * 7)");
    expect(prompt).toContain("Report CWE-94 and CWE-95");
  });
});
