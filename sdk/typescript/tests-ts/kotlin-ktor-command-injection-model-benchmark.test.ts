import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";
import {
  kotlinKtorCommandInjectionRecords,
  type KotlinKtorCommandInjectionRecord,
} from "../src/kotlin-ktor-command-risk.js";

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    expected: Array<{
      cwe?: string[];
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
      requiredValidationTextAnyOf?: string[][];
      requiredAttackPathTextAnyOf?: string[][];
      forbiddenText?: string[];
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "kotlin-ktor-shell-command-injection",
  "kotlin-ktor-argv-command",
] as const;
const handlerPath = "src/main/kotlin/example/Diagnostics.kt";

function records(
  source: string,
  path = handlerPath,
): KotlinKtorCommandInjectionRecord[] {
  return kotlinKtorCommandInjectionRecords(
    path,
    source.split(/\r?\n/u),
    source,
  );
}

function ktor(
  body: string,
  processImport = "import java.lang.ProcessBuilder",
): string {
  return `package example
import io.ktor.server.routing.*
${processImport}

fun routes() = routing {
    get("/diagnostics") {
${body}
    }
}
`;
}

async function fixtureRecords(
  id: (typeof caseIds)[number],
): Promise<KotlinKtorCommandInjectionRecord[]> {
  const inventory = await buildResidualRiskInventory(
    join(benchmarkRoot, "fixtures", id),
  );
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as KotlinKtorCommandInjectionRecord)
    .filter(
      (record) => record.frameworkModel?.id === "kotlin-ktor-command-injection",
    );
}

describe("Kotlin Ktor command-injection model benchmark", () => {
  test("keeps shell grammar and literal argv under perfect gates", async () => {
    const benchmark = JSON.parse(
      await readFile(
        join(benchmarkRoot, "kotlin-ktor-command-injection-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(benchmark.schemaVersion).toBe("1.0");
    expect(
      Object.values(benchmark.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(benchmark.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(benchmark.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(4);
    expect(
      benchmark.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(4);
    expect(benchmark.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(benchmark.cases[1]?.expected).toEqual([]);
  });

  test("preserves exact Ktor source, interpolation, ProcessBuilder, and start", async () => {
    const vulnerable = await fixtureRecords(caseIds[0]);
    const safe = await fixtureRecords(caseIds[1]);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: handlerPath,
      line: 14,
      categories: ["kotlin-ktor-command-injection"],
      frameworkModel: {
        schemaVersion: "1.2",
        id: "kotlin-ktor-command-injection",
        language: "kotlin",
        scope: "same-file",
        source: {
          kind: "ktor-query-parameter",
          path: handlerPath,
          line: 12,
          symbol: "call.request.queryParameters[target]",
        },
        sink: {
          kind: "kotlin-process-shell-command",
          path: handlerPath,
          line: 14,
          symbol: "java.lang.ProcessBuilder;method=start;argument=3",
          cweIds: ["CWE-78", "CWE-88"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual([
      "kotlin-local-assignment",
      "kotlin-string-interpolation",
      "kotlin-local-assignment",
    ]);
    expect(safe).toEqual([]);
  });

  test("keeps paired source and process topology aligned", async () => {
    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[0],
        "src",
        "main",
        "kotlin",
        "example",
        "Diagnostics.kt",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[1],
        "src",
        "main",
        "kotlin",
        "example",
        "Diagnostics.kt",
      ),
      "utf8",
    );
    for (const source of [vulnerable, safe]) {
      expect(source).toContain('call.request.queryParameters["target"]');
      expect(source).toContain("import java.lang.ProcessBuilder");
      expect(source).toContain(".start()");
      expect(source).toContain("process.inputStream");
      expect(source).toContain("call.respondText(stdout)");
    }
    expect(vulnerable).toContain('ProcessBuilder("sh", "-c", commandLine)');
    expect(safe).toContain('ProcessBuilder("printf", "%s", argument)');
  });

  test("keeps harmless native Kotlin witnesses and a dedicated hosted gate", async () => {
    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[0],
        "src",
        "test",
        "kotlin",
        "example",
        "ShellCommandWitnessTest.kt",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[1],
        "src",
        "test",
        "kotlin",
        "example",
        "ArgvCommandWitnessTest.kt",
      ),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain("KOTLIN_COMMAND_MARKER");
      expect(witness).toContain("ProcessBuilder");
      expect(witness).not.toContain("java.io.File");
      expect(witness).not.toContain("java.net");
    }
    expect(vulnerable).toContain('ProcessBuilder("sh", "-c", payload)');
    expect(safe).toContain('ProcessBuilder("printf", "%s", payload)');

    const workflow = await readFile(
      resolve(
        benchmarkRoot,
        "..",
        ".github",
        "workflows",
        "kotlin-fixture-ci.yml",
      ),
      "utf8",
    );
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(workflow).toContain(
      "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    );
    expect(workflow).toContain(
      "actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95",
    );
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain(
      "kotlin-ktor-shell-command-injection/pom.xml verify",
    );
    expect(workflow).toContain("kotlin-ktor-argv-command/pom.xml verify");
  });

  test("recognizes exact Ktor query, path, header, query-string, and body sources", () => {
    const sourceExpressions = [
      ['call.request.queryParameters["value"]!!', "ktor-query-parameter"],
      ['call.parameters["value"]!!', "ktor-path-parameter"],
      ['call.request.headers["X-Value"]!!', "ktor-header"],
      ["call.request.queryString()", "ktor-query-string"],
      ["call.receiveText()", "ktor-request-body"],
      ["call.receive<Payload>()", "ktor-request-body"],
    ] as const;
    for (const [expression, kind] of sourceExpressions) {
      const found = records(
        ktor(`        val value = ${expression}
        ProcessBuilder("sh", "-c", value).start()`),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.source.kind).toBe(kind);
    }
  });

  test("recognizes aliases, fully qualified identity, list construction, and retained builders", () => {
    const aliased = records(
      ktor(
        `        val value = call.request.queryParameters["value"]!!
        ProcessApi("bash", "-c", value).start()`,
        "import java.lang.ProcessBuilder as ProcessApi",
      ),
    );
    expect(aliased).toHaveLength(1);

    const qualified = records(
      ktor(
        `        val value = call.parameters["value"]!!
        java.lang.ProcessBuilder("cmd.exe", "/C", value).start()`,
        "",
      ),
    );
    expect(qualified).toHaveLength(1);

    const listed = records(
      ktor(`        val value = call.receiveText()
        ProcessBuilder(listOf("pwsh", "-Command", value)).start()`),
    );
    expect(listed).toHaveLength(1);

    const retained = records(
      ktor(`        val value = call.receiveText()
        val process = ProcessBuilder("python3", "-c", value)
        process.start()`),
    );
    expect(retained).toHaveLength(1);
    expect(retained[0]?.frameworkModel.sink.kind).toBe(
      "kotlin-process-interpreter-command",
    );

    const chained = records(
      ktor(`        val value = call.receiveText()
        val process = ProcessBuilder("sh", "-c", value)
            .start()`),
    );
    expect(chained).toHaveLength(1);
  });

  test("recognizes shell, interpreter, batch, and executable-selection boundaries", () => {
    const commands = [
      ['"/bin/sh"', '"-c"', "kotlin-process-shell-command"],
      ['"bash"', '"-c"', "kotlin-process-shell-command"],
      ['"cmd.exe"', '"/K"', "kotlin-process-shell-command"],
      ['"powershell.exe"', '"-Command"', "kotlin-process-shell-command"],
      ['"node"', '"--eval"', "kotlin-process-interpreter-command"],
      ['"ruby"', '"-e"', "kotlin-process-interpreter-command"],
      ['"trusted.cmd"', '"fixed"', "kotlin-process-shell-command"],
    ] as const;
    for (const [program, flag, kind] of commands) {
      const found = records(
        ktor(`        val value = call.receiveText()
        ProcessBuilder(${program}, ${flag}, value).start()`),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.kind).toBe(kind);
    }
    const selected = records(
      ktor(`        val program = call.parameters["program"]!!
        ProcessBuilder(program).start()`),
    );
    expect(selected[0]?.frameworkModel.sink.kind).toBe(
      "kotlin-process-executable-selection",
    );
  });

  test("rejects literal argv, inert or reassigned builders, numeric normalization, and lookalikes", () => {
    const safeBodies = [
      `        val value = call.receiveText()
        ProcessBuilder("printf", "%s", value).start()`,
      `        val value = call.receiveText()
        val process = ProcessBuilder("sh", "-c", value)`,
      `        val value = call.receiveText().toInt()
        ProcessBuilder("sh", "-c", value.toString()).start()`,
      `        val value = call.receiveText()
        var process = ProcessBuilder("sh", "-c", value)
        process = ProcessBuilder("printf", "%s", value)
        process.start()`,
    ];
    for (const body of safeBodies) expect(records(ktor(body))).toEqual([]);
    expect(
      records(
        ktor(
          `        val value = call.receiveText()
        ProcessBuilder("sh", "-c", value).start()`,
          "class ProcessBuilder(vararg values: String) { fun start() = Unit }",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        ktor(`        val value = call.receiveText()
        ProcessBuilder("sh", "-c", value).start()`).replace(
          "io.ktor.server.routing.*",
          "local.routing.*",
        ),
      ),
    ).toEqual([]);
  });

  test("tracks interpolation and concatenation while retaining validation candidates", () => {
    const interpolated = records(
      ktor(`        val value = call.request.queryParameters["value"]!!
        val commandLine = "printf fixed; $value"
        ProcessBuilder("sh", "-c", commandLine).start()`),
    );
    expect(interpolated).toHaveLength(1);
    expect(
      interpolated[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("kotlin-string-interpolation");

    const concatenated = records(
      ktor(`        val value = call.receiveText()
        val commandLine = "printf fixed; " + value
        ProcessBuilder("sh", "-c", commandLine).start()`),
    );
    expect(
      concatenated[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("kotlin-string-concatenation");

    const validated = records(
      ktor(`        val value = call.receiveText().takeIf { it.matches(Regex("[a-z]+")) }!!
        ProcessBuilder("sh", "-c", value).start()`),
    );
    expect(validated[0]?.frameworkModel.candidateControls).toContainEqual(
      expect.objectContaining({ kind: "process-input-validation-candidate" }),
    );
  });

  test("is CRLF-stable, bounded, and rejects malformed or non-production input", () => {
    const source = ktor(`        val value = call.receiveText()
        ProcessBuilder("sh", "-c", value).start()`);
    expect(records(source.replace(/\n/gu, "\r\n"))).toHaveLength(1);
    expect(records(source, "src/test/kotlin/example/Diagnostics.kt")).toEqual(
      [],
    );
    expect(records(source, "examples/Diagnostics.kt")).toEqual([]);
    expect(records(source.replace(/\}\s*$/u, ""))).toEqual([]);
    expect(records(`${source}\n/* unterminated`)).toEqual([]);
    expect(
      records(`${source}\n${"val bounded = 1\n".repeat(140_000)}`),
    ).toEqual([]);
  });

  test("feeds residual correction with Kotlin-specific proof obligations", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", caseIds[0]),
    );
    expect(inventory).toContain('"id":"kotlin-ktor-command-injection"');
    expect(inventory).toContain('"kind":"ktor-query-parameter"');
    expect(inventory).toContain('"kind":"kotlin-process-shell-command"');
    const prompt = scanQualityGatePrompt(inventory);
    expect(prompt).toContain("For kotlin-ktor-command-injection rows");
    expect(prompt).toContain("Ordinary later elements are distinct");
    expect(prompt).toContain("same route lambda");
    expect(prompt).toContain("bounded harmless environment-marker witness");
  });

  test("forces incomplete Kotlin evidence through host-audited correction", async () => {
    const repository = join(benchmarkRoot, "fixtures", caseIds[0]);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-kotlin-quality-"),
    );
    try {
      const finding = {
        findingId: "occ_kotlin_quality",
        taxonomy: { cwe: ["CWE-78", "CWE-88"] },
        locations: [
          { path: handlerPath, startLine: 12, endLine: 12, role: "source" },
          { path: handlerPath, startLine: 13, endLine: 14, role: "sink" },
        ],
        codeEvidence: [
          {
            id: "kotlin-source",
            path: handlerPath,
            startLine: 12,
            endLine: 12,
            role: "source",
            code: 'val target = call.request.queryParameters["target"]',
            explanation: "The route reads a request value.",
          },
          {
            id: "kotlin-sink",
            path: handlerPath,
            startLine: 13,
            endLine: 14,
            role: "sink",
            code: 'ProcessBuilder("sh", "-c", commandLine).start()',
            explanation: "The route launches a process.",
          },
        ],
        validation: {
          method: "static_source_trace",
          summary: "A request value reaches a process launch.",
          exploitWitness: "A bounded inert marker checks interpretation.",
          negativeControl: "A literal argv control does not interpret it.",
          evidence: ["kotlin-source", "kotlin-sink"],
          counterEvidence: "No source-backed repair was established.",
          remainingUncertainty: "Deployment remains unknown.",
        },
        attackPath: {
          summary: "A caller influences a launched process.",
          dataflow: {
            source: "An HTTP value.",
            sink: "A process boundary.",
            outcome: "Service-process integrity may be affected.",
          },
          reachability: {
            attacker: "A remote caller.",
            entrypoint: "The diagnostics handler.",
            outcome: "A child process starts.",
          },
          brokenControls: ["No exact command/data separation"],
          evidenceRefs: ["kotlin-source", "kotlin-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );
      const residualRiskInventory =
        await buildResidualRiskInventory(repository);
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        residualRiskInventory,
      );
      const rows = incomplete.split("\n").map((line) => JSON.parse(line));
      expect(rows[1]).toMatchObject({
        findingId: "occ_kotlin_quality",
        frameworkModelId: "kotlin-ktor-command-injection",
        reasons: [
          "missing_model_specific_validation_evidence",
          "missing_model_specific_attack_path_evidence",
        ],
      });

      finding.validation.summary = [
        "The Ktor query source is call.request.queryParameters for target.",
        "Kotlin interpolation assigns the formatted value to commandLine.",
        "java.lang.ProcessBuilder starts sh -c shell grammar.",
      ].join(" ");
      finding.attackPath.summary = [
        "The target request value is the query value.",
        "commandLine places it in a command string with shell grammar.",
        "ProcessBuilder starts the sh process.",
        "stdout is sent through respondText in the response.",
      ].join(" ");
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
    } finally {
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });
});
