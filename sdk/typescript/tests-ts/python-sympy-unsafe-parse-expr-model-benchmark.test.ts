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

function sympyRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "python-web-sympy-unsafe-parse-expr",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-sympy-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

const directRoute = (binding: string, call: string) =>
  [binding, "def route(request):", `    return ${call}`].join("\n");

describe("Python SymPy unsafe parse_expr model", () => {
  test("keeps a strict unsafe and restricted-namespace benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-sympy-unsafe-parse-expr-manifest.json"),
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
      "python-sympy-unsafe-parse-expr",
      "python-sympy-restricted-namespace-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-94", "CWE-95"]);
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
      ".python-version",
      "requirements.txt",
      join("examples", "witness.py"),
      join("src", "server.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-sympy-unsafe-parse-expr",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-sympy-restricted-namespace-control",
            relativePath,
          ),
          "utf8",
        ),
      );
    }
  });

  test("emits the exact cross-file request-expression-to-eval path", async () => {
    const affected = sympyRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-sympy-unsafe-parse-expr"),
      ),
    );
    const control = sympyRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-sympy-restricted-namespace-control",
        ),
      ),
    );

    expect(control).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/parser.py");
    expect(affected[0]?.line).toBe(7);
    expect(affected[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(affected[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-expression",
      path: "src/server.py",
      line: 14,
    });
    expect(affected[0]?.frameworkModel?.sink).toMatchObject({
      kind: "sympy-untrusted-parse-expr-evaluation",
      path: "src/parser.py",
      line: 7,
      cweIds: ["CWE-94", "CWE-95"],
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "sympy-parse-expr-binding",
        "sympy-untrusted-expression-edge",
        "sympy-evaluation-namespace",
        "intrinsic-sympy-eval-execution",
      ]),
    );
  });

  test("supports exact module, parser-module, direct, aliased, parenthesized, and callable aliases", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": directRoute(
          "import sympy",
          "sympy.parsing.sympy_parser.parse_expr(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "import sympy.parsing as parsing",
          "parsing.sympy_parser.parse_expr(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "import sympy.parsing.sympy_parser as parser",
          "parser.parse_expr(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "from sympy import parsing as parser_api",
          "parser_api.sympy_parser.parse_expr(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "from sympy.parsing import sympy_parser as parser",
          "parser.parse_expr(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "from sympy.parsing.sympy_parser import parse_expr as parse_math",
          "parse_math(s=request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": [
          "from sympy.parsing.sympy_parser import (",
          "    parse_expr as parse_math,",
          ")",
          "def route(request):",
          "    return parse_math(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from sympy.parsing.sympy_parser import parse_expr",
          "parse_math = parse_expr",
          "def route(request):",
          "    return parse_math(request.get_json())",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        sympyRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([
      1, 1, 1, 1, 1, 1, 1, 1,
    ]);
    expect(
      records[7]?.[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("sympy-parse-expr-callable-alias");
  });

  test("supports Qwed-style function-local imports and mapping request access", async () => {
    const repository = await writeRepository({
      "app.py": [
        '@app.post("/verify/math")',
        "async def verify_math(request: dict):",
        "    from sympy.parsing.sympy_parser import parse_expr",
        '    expression = request.get("expression")',
        '    expression_normalized = expression.replace(" ", "")',
        "    return parse_expr(expression_normalized)",
      ].join("\n"),
    });

    const records = sympyRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.source.line).toBe(4);
    expect(records[0]?.frameworkModel?.sink.line).toBe(6);
  });

  test("supports Qwed's multiline FastAPI signature and normalization flow", async () => {
    const repository = await writeRepository({
      "app.py": [
        '@app.post("/verify/math")',
        "async def verify_math(",
        "    request: dict,",
        "    tenant = Depends(get_current_tenant),",
        "):",
        "    try:",
        "        import sympy",
        "        from sympy.parsing.sympy_parser import parse_expr",
        '        expression = request.get("expression")',
        '        if "=" in expression:',
        '            left_str, right_str = expression.split("=", 1)',
        "            left = parse_expr(left_str)",
        "            right = parse_expr(right_str)",
        "            return left == right",
        "        else:",
        "            import re",
        "            expression_normalized = re.sub(r'(\\d)(\\()', r'\\1*\\2', expression)",
        ...Array.from(
          { length: 20 },
          (_, index) =>
            `            review_marker_${index} = expression is not None`,
        ),
        "            return parse_expr(expression_normalized)",
        "    except Exception:",
        "        return None",
      ].join("\n"),
    });

    const records = sympyRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.source.line).toBe(9);
    expect(records[0]?.frameworkModel?.sink.line).toBe(38);
  });

  test("credits only a stripped builtin namespace plus a literal mathematical local allowlist", async () => {
    const safePreamble = [
      "from sympy import Float, Integer, Rational, Symbol",
      "from sympy.parsing.sympy_parser import parse_expr",
      'SAFE_GLOBALS = {"__builtins__": {}}',
      'SAFE_LOCALS = {"Float": Float, "Integer": Integer, "Rational": Rational, "Symbol": Symbol}',
    ];
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          ...safePreamble,
          "def route(request):",
          "    return parse_expr(request.get_json(), local_dict=SAFE_LOCALS, global_dict=SAFE_GLOBALS)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          ...safePreamble,
          "def route(request):",
          "    return parse_expr(request.get_json(), SAFE_LOCALS, (), SAFE_GLOBALS)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          ...safePreamble,
          "SAFE_GLOBALS_COPY = dict(SAFE_GLOBALS)",
          "def route(request):",
          "    return parse_expr(request.get_json(), local_dict=SAFE_LOCALS, global_dict=SAFE_GLOBALS_COPY)",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          ...safePreamble,
          "SAFE_GLOBALS_COPY = SAFE_GLOBALS.copy()",
          "def route(request):",
          "    return parse_expr(request.get_json(), local_dict=SAFE_LOCALS, global_dict=SAFE_GLOBALS_COPY)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        sympyRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0]);
  });

  test("retains default, empty, None, dynamic, evaluate-false, and dangerous-local namespaces", async () => {
    const calls = [
      "parse_expr(request.get_json())",
      "parse_expr(request.get_json(), global_dict={})",
      "parse_expr(request.get_json(), global_dict=None)",
      "parse_expr(request.get_json(), global_dict=request.json['globals'])",
      "parse_expr(request.get_json(), evaluate=False)",
      'parse_expr(request.get_json(), local_dict={"runner": eval}, global_dict={"__builtins__": {}})',
    ];
    const repositories = await Promise.all(
      calls.map((call) =>
        writeRepository({
          "app.py": directRoute(
            "from sympy.parsing.sympy_parser import parse_expr",
            call,
          ),
        }),
      ),
    );
    const records = await Promise.all(
      repositories.map(async (repository) =>
        sympyRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1, 1, 1, 1]);
  });

  test("rejects fixed input, local shadows, binding replacements, parameter shadows, star expansion, and text", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          "from sympy.parsing.sympy_parser import parse_expr",
          "def route(request):",
          "    request.get_json()",
          '    return parse_expr("2 + 2")',
        ].join("\n"),
      }),
      writeRepository({
        "sympy.py": "class parsing: pass\n",
        "app.py": directRoute(
          "from sympy.parsing.sympy_parser import parse_expr",
          "parse_expr(request.get_json())",
        ),
      }),
      writeRepository({
        "sympy/__init__.py": "class parsing: pass\n",
        "app.py": directRoute(
          "import sympy",
          "sympy.parsing.sympy_parser.parse_expr(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": [
          "from sympy.parsing.sympy_parser import parse_expr",
          "def route(request):",
          "    parse_expr = request.parser",
          "    return parse_expr(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import sympy",
          "def safe(value): return value",
          "def route(request):",
          "    sympy.parsing.sympy_parser.parse_expr = safe",
          "    return sympy.parsing.sympy_parser.parse_expr(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from sympy.parsing.sympy_parser import parse_expr",
          "def route(request, parse_expr):",
          "    return parse_expr(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": directRoute(
          "from sympy.parsing.sympy_parser import parse_expr",
          "parse_expr(*request.json)",
        ),
      }),
      writeRepository({
        "app.py": [
          "text = 'from sympy.parsing.sympy_parser import parse_expr; parse_expr(request.get_json())'",
          "# from sympy.parsing.sympy_parser import parse_expr",
          "# parse_expr(request.get_json())",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        sympyRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([
      0, 0, 0, 0, 0, 0, 0, 0,
    ]);
  });

  test("preserves a two-relay path to the terminal SymPy binding", async () => {
    const repository = await writeRepository({
      "server.py": [
        "from .relay import decode",
        "def route(request):",
        "    return decode(request.get_json())",
      ].join("\n"),
      "relay.py": [
        "from .service import verify",
        "def decode(expression):",
        "    return verify(expression)",
      ].join("\n"),
      "service.py": [
        "from .parser import parse_expression",
        "def verify(expression):",
        "    return parse_expression(expression)",
      ].join("\n"),
      "parser.py": [
        "from sympy.parsing.sympy_parser import parse_expr",
        "def parse_expression(expression):",
        "    return parse_expr(expression)",
      ].join("\n"),
    });

    const records = sympyRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("parser.py");
  });

  test("binding-derived candidates survive dense unrelated parser calls", async () => {
    const decoys = Array.from(
      { length: 40 },
      (_, index) => `    parser${index}.parse_expr(value${index})`,
    );
    const repository = await writeRepository({
      "app.py": [
        "from sympy.parsing.sympy_parser import parse_expr",
        "def route(request):",
        ...decoys,
        "    return parse_expr(request.get_json())",
      ].join("\n"),
    });

    const records = sympyRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(43);
  });

  test("host re-audit requires the complete SymPy capability boundary in both report fields", async () => {
    const repository = await writeRepository({
      "src/server.py": [
        "from .parser import parse_expression",
        "def route(request):",
        "    return parse_expression(request.get_json())",
      ].join("\n"),
      "src/parser.py": [
        "from sympy.parsing.sympy_parser import parse_expr",
        "def parse_expression(expression):",
        "    return parse_expr(expression)",
      ].join("\n"),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-sympy-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_sympy_quality",
      taxonomy: { cwe: ["CWE-94", "CWE-95"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/parser.py", startLine: 3, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "expression-source",
          path: "src/server.py",
          startLine: 3,
          code: "    return parse_expression(request.get_json())",
          explanation: "Request JSON enters the parsing wrapper.",
          role: "source",
        },
        {
          id: "sympy-sink",
          path: "src/parser.py",
          startLine: 3,
          code: "    return parse_expr(expression)",
          explanation: "The expression reaches the official SymPy binding.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms request data reaches an evaluator.",
        method: "static source trace and bounded arithmetic capability witness",
        exploitWitness: "The fixed arithmetic sentinel returns 42.",
        negativeControl: "A restricted namespace rejects the capability probe.",
        evidence: ["expression-source", "sympy-sink"],
        counterEvidence: "A string type check does not restrict Python names.",
        remainingUncertainty: "Deployment privileges determine final impact.",
      },
      attackPath: {
        summary: "A remote expression reaches server-side evaluation.",
        dataflow: {
          source: "expression-source",
          sink: "sympy-sink",
          outcome: "Python expression evaluation",
        },
        reachability: {
          attacker: "Remote math API caller",
          entrypoint: "JSON verification endpoint",
          outcome: "Service-process integrity can be affected",
        },
        brokenControls: ["No restricted evaluation namespace"],
        evidenceRefs: ["expression-source", "sympy-sink"],
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
      findingId: "occ_sympy_quality",
      frameworkModelId: "python-web-sympy-unsafe-parse-expr",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "stringify_expr",
      "eval_expr",
      "Python eval",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "restricted namespace",
      "empty __builtins__",
      "SAFE_GLOBALS",
    ]);

    const semanticContract = [
      "An expression upload from request.get_json supplies request JSON.",
      "The parse_expression wrapper calls the official sympy.parsing.sympy_parser.parse_expr SymPy binding.",
      "The expression argument is argument zero under the default global_dict builtin namespace.",
      "The stringify_expr and eval_expr chain reaches Python eval with __import__ builtin capability.",
      "On Python 3.12.3 the arithmetic sentinel evaluates 6 * 7 to 42.",
      "The restricted namespace negative control uses empty __builtins__ in SAFE_GLOBALS.",
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

  test("requires exact namespace and bounded capability evidence in the quality prompt", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain("For python-web-sympy-unsafe-parse-expr rows");
    expect(prompt).toContain("GHSA-q27q-98j4-9pfv / CVE-2026-55585");
    expect(prompt).toContain("stringify_expr -> compile -> eval_expr -> eval");
    expect(prompt).toContain("evaluate=False");
    expect(prompt).toContain("fixed arithmetic expression 6 * 7");
    expect(prompt).toContain("Report CWE-94 and CWE-95");
  });
});
