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
  "kotlin-ktor-resource-shell-command-injection",
  "kotlin-ktor-resource-argv-command",
  "kotlin-ktor-resource-live-command-list-injection",
  "kotlin-ktor-resource-live-command-list-argv",
  "kotlin-ktor-resource-inline-pipeline-injection",
  "kotlin-ktor-resource-inline-pipeline-argv",
  "kotlin-ktor-resource-builder-factory-injection",
  "kotlin-ktor-resource-builder-factory-argv",
  "kotlin-ktor-resource-command-helper-injection",
  "kotlin-ktor-resource-command-helper-argv",
  "kotlin-ktor-resource-env-executable-injection",
  "kotlin-ktor-resource-env-argv",
  "kotlin-ktor-resource-runtime-env-executable-injection",
  "kotlin-ktor-resource-runtime-env-argv",
  "kotlin-ktor-resource-runtime-list-env-executable-injection",
  "kotlin-ktor-resource-runtime-list-env-argv",
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
    expect(benchmark.cases[2]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(benchmark.cases[3]?.expected).toEqual([]);
    expect(benchmark.cases[4]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(benchmark.cases[5]?.expected).toEqual([]);
    expect(benchmark.cases[6]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[6]?.expected[0]?.requiredValidationTextAnyOf?.[2],
    ).toContain("inline pipeline");
    expect(benchmark.cases[7]?.expected).toEqual([]);
    expect(benchmark.cases[8]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[8]?.expected[0]?.requiredAttackPathTextAnyOf?.[2],
    ).toContain("child shell");
    expect(benchmark.cases[9]?.expected).toEqual([]);
    expect(benchmark.cases[10]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(benchmark.cases[11]?.expected).toEqual([]);
    expect(benchmark.cases[12]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[12]?.expected[0]?.requiredValidationTextAnyOf?.[1],
    ).toContain("delegating launcher");
    expect(
      benchmark.cases[12]?.expected[0]?.requiredAttackPathTextAnyOf?.[2],
    ).toContain("executable selection");
    expect(benchmark.cases[13]?.expected).toEqual([]);
    expect(benchmark.cases[14]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[14]?.expected[0]?.requiredValidationTextAnyOf?.[3],
    ).toContain("Runtime.exec");
    expect(benchmark.cases[15]?.expected).toEqual([]);
    expect(benchmark.cases[16]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[16]?.expected[0]?.requiredValidationTextAnyOf?.[3],
    ).toContain("toTypedArray");
    expect(benchmark.cases[17]?.expected).toEqual([]);
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
    expect(workflow).toContain(
      "kotlin-ktor-resource-shell-command-injection/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-argv-command/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-live-command-list-injection/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-live-command-list-argv/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-inline-pipeline-injection/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-inline-pipeline-argv/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-builder-factory-injection/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-builder-factory-argv/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-command-helper-injection/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-command-helper-argv/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-env-executable-injection/pom.xml verify",
    );
    expect(workflow).toContain("kotlin-ktor-resource-env-argv/pom.xml verify");
    expect(workflow).toContain(
      "kotlin-ktor-resource-runtime-env-executable-injection/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-runtime-env-argv/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-runtime-list-env-executable-injection/pom.xml verify",
    );
    expect(workflow).toContain(
      "kotlin-ktor-resource-runtime-list-env-argv/pom.xml verify",
    );
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

  test("recognizes typed Resources handlers and effective command replacement", async () => {
    const vulnerable = await fixtureRecords(caseIds[2]);
    const safe = await fixtureRecords(caseIds[3]);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: handlerPath,
      line: 21,
      frameworkModel: {
        source: {
          kind: "ktor-typed-resource",
          line: 16,
          symbol: "input:DiagnosticResource",
        },
        sink: {
          kind: "kotlin-process-shell-command",
          symbol: "java.lang.ProcessBuilder;method=start;argument=3",
        },
      },
    });
    expect(
      vulnerable[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual([
      "kotlin-local-assignment",
      "kotlin-string-interpolation",
      "kotlin-local-assignment",
      "kotlin-process-command-replacement",
    ]);
    expect(safe).toEqual([]);

    const vulnerableSource = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[2], handlerPath),
      "utf8",
    );
    const safeSource = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[3], handlerPath),
      "utf8",
    );
    for (const source of [vulnerableSource, safeSource]) {
      expect(source).toContain("@Resource");
      expect(source).toContain("get<DiagnosticResource> { input ->");
      expect(source).toContain('ProcessBuilder("printf", "%s", "fixed")');
      expect(source).toContain("builder.command");
      expect(source).toContain("builder.start()");
      expect(source).toContain("call.respondText(stdout)");
    }
  });

  test("tracks vararg and list command replacement through start and startPipeline", () => {
    const resource = (body: string, annotation = "Resource"): string =>
      `package example
import io.ktor.resources.Resource
import io.ktor.server.resources.get
import io.ktor.server.routing.routing
import java.lang.ProcessBuilder

@${annotation}("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

fun routes() = routing {
    get<DiagnosticResource> { input ->
${body}
    }
}
`;
    const replaced = records(
      resource(`        val value = input.target
        val builder = ProcessBuilder("printf", "%s", "fixed")
        builder.command("sh", "-c", value)
        builder.start()`),
    );
    expect(replaced).toHaveLength(1);
    expect(replaced[0]?.frameworkModel.source.kind).toBe("ktor-typed-resource");

    const listed = records(
      resource(`        val value = input.target
        ProcessBuilder("printf", "%s", "fixed")
            .command(listOf("pwsh", "-Command", value))
            .start()`),
    );
    expect(listed).toHaveLength(1);

    const pipeline = records(
      resource(`        val value = input.target
        val builder = ProcessBuilder("fixed")
        builder.command(listOf("sh", "-c", value))
        ProcessBuilder.startPipeline(listOf(builder))`),
    );
    expect(pipeline).toHaveLength(1);
    expect(pipeline[0]?.frameworkModel.sink.symbol).toBe(
      "java.lang.ProcessBuilder;method=startPipeline;argument=3",
    );

    const safe = records(
      resource(`        val value = input.target
        val builder = ProcessBuilder("sh", "-c", value)
        builder.command("printf", "%s", value)
        builder.start()`),
    );
    expect(safe).toEqual([]);
  });

  test("tracks exact inline and retained ProcessBuilder pipeline lists", () => {
    const resource = (body: string): string =>
      `package example
import io.ktor.resources.Resource
import io.ktor.server.resources.get
import io.ktor.server.routing.routing
import java.lang.ProcessBuilder

@Resource("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

fun routes() = routing {
    get<DiagnosticResource> { input ->
${body}
    }
}
`;

    const inline = records(
      resource(`        val value = input.target
        ProcessBuilder.startPipeline(
            listOf(
                ProcessBuilder("printf", "%s", "fixed"),
                ProcessBuilder("sh", "-c", value),
            ),
        )`),
    );
    expect(inline).toHaveLength(1);
    expect(inline[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-shell-command",
      symbol: "java.lang.ProcessBuilder;method=startPipeline;argument=3",
    });
    expect(
      inline[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("kotlin-process-pipeline-assembly");

    const retained = records(
      resource(`        val value = input.target
        val builder = ProcessBuilder("sh", "-c", value)
        val pipeline = mutableListOf(builder)
        ProcessBuilder.startPipeline(pipeline)`),
    );
    expect(retained).toHaveLength(1);

    const chained = records(
      resource(`        val value = input.target
        val pipeline = arrayListOf(
            ProcessBuilder("printf", "%s", "fixed"),
            ProcessBuilder("printf", "%s", "fixed")
                .command("sh", "-c", value),
        )
        java.lang.ProcessBuilder.startPipeline(pipeline)`),
    );
    expect(chained).toHaveLength(1);

    const appended = records(
      resource(`        val value = input.target
        val pipeline = mutableListOf(
            ProcessBuilder("printf", "%s", "fixed"),
        )
        pipeline.add(ProcessBuilder("sh", "-c", value))
        ProcessBuilder.startPipeline(pipeline)`),
    );
    expect(appended).toHaveLength(1);
    expect(
      appended[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-process-pipeline-list-mutation",
        "kotlin-process-pipeline-assembly",
      ]),
    );

    const controls = [
      `        val value = input.target
        ProcessBuilder.startPipeline(
            listOf(ProcessBuilder("printf", "%s", value)),
        )`,
      `        val value = input.target
        val builder = ProcessBuilder("sh", "-c", value)
        val pipeline = listOf(builder)
        builder.command("printf", "%s", value)
        ProcessBuilder.startPipeline(pipeline)`,
      `        val value = input.target
        val builder = ProcessBuilder("sh", "-c", value)
        ProcessBuilder.startPipeline(notAList(builder))`,
      `        val value = input.target
        val dangerous = ProcessBuilder("sh", "-c", value)
        val pipeline = mutableListOf(dangerous)
        val retained = pipeline
        retained.clear()
        retained.add(ProcessBuilder("printf", "%s", value))
        ProcessBuilder.startPipeline(pipeline)`,
      `        val value = input.target
        val dangerous = ProcessBuilder("sh", "-c", value)
        val pipeline = arrayListOf(dangerous)
        pipeline[0] = ProcessBuilder("printf", "%s", value)
        ProcessBuilder.startPipeline(pipeline)`,
      `        val value = input.target
        val dangerous = ProcessBuilder("sh", "-c", value)
        val pipeline = mutableListOf(dangerous)
        pipeline.removeAt(0)
        ProcessBuilder.startPipeline(pipeline)`,
      `        val value = input.target
        val dangerous = ProcessBuilder("sh", "-c", value)
        val pipeline = mutableListOf(dangerous)
        pipeline.set(4, ProcessBuilder("printf", "%s", value))
        ProcessBuilder.startPipeline(pipeline)`,
    ];
    for (const control of controls)
      expect(records(resource(control))).toEqual([]);
  });

  test("summarizes exact same-file ProcessBuilder factories and command helpers", () => {
    const resource = (helpers: string, body: string): string =>
      `package example
import io.ktor.resources.Resource
import io.ktor.server.resources.get
import io.ktor.server.routing.routing
import java.lang.ProcessBuilder

@Resource("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

${helpers}

fun routes() = routing {
    get<DiagnosticResource> { input ->
${body}
    }
}
`;

    const expressionFactory = records(
      resource(
        `private fun shell(command: String): ProcessBuilder =
    ProcessBuilder("sh", "-c", command)`,
        `        val builder = shell(input.target)
        builder.start()`,
      ),
    );
    expect(expressionFactory).toHaveLength(1);
    expect(
      expressionFactory[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-process-builder-factory",
        "kotlin-process-helper-call",
      ]),
    );

    const blockFactory = records(
      resource(
        `private fun shell(command: String): java.lang.ProcessBuilder {
    return java.lang.ProcessBuilder("sh", "-c", "printf fixed; $command")
}`,
        `        shell(input.target).start()`,
      ),
    );
    expect(blockFactory).toHaveLength(1);

    const commandHelper = records(
      resource(
        `private fun configure(builder: ProcessBuilder, command: String) {
    builder.command("sh", "-c", command)
}`,
        `        val builder = ProcessBuilder("printf", "%s", "fixed")
        configure(builder, input.target)
        builder.start()`,
      ),
    );
    expect(commandHelper).toHaveLength(1);
    expect(
      commandHelper[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-process-command-helper",
        "kotlin-process-helper-call",
        "kotlin-process-command-replacement",
      ]),
    );

    const safeFactory = records(
      resource(
        `private fun output(value: String): ProcessBuilder =
    ProcessBuilder("printf", "%s", value)`,
        `        val builder = output(input.target)
        builder.start()`,
      ),
    );
    expect(safeFactory).toEqual([]);

    const safeReplacementAfterFactory = records(
      resource(
        `private fun shell(command: String): ProcessBuilder =
    ProcessBuilder("sh", "-c", command)`,
        `        val builder = shell(input.target)
        builder.command("printf", "%s", input.target)
        builder.start()`,
      ),
    );
    expect(safeReplacementAfterFactory).toEqual([]);

    const safeCommandHelper = records(
      resource(
        `private fun configure(builder: ProcessBuilder, value: String) {
    builder.command("printf", "%s", value)
}`,
        `        val builder = ProcessBuilder("sh", "-c", input.target)
        configure(builder, input.target)
        builder.start()`,
      ),
    );
    expect(safeCommandHelper).toEqual([]);

    const ambiguousOverload = records(
      resource(
        `private fun shell(command: String): ProcessBuilder =
    ProcessBuilder("sh", "-c", command)

private fun shell(command: CharSequence): ProcessBuilder =
    ProcessBuilder("sh", "-c", command.toString())`,
        `        val builder = shell(input.target)
        builder.start()`,
      ),
    );
    expect(ambiguousOverload).toEqual([]);

    const nontrivialMutator = records(
      resource(
        `private fun configure(builder: ProcessBuilder, command: String) {
    val selected = command
    builder.command("sh", "-c", selected)
}`,
        `        val builder = ProcessBuilder("printf", "%s", "fixed")
        configure(builder, input.target)
        builder.start()`,
      ),
    );
    expect(nontrivialMutator).toEqual([]);
  });

  test("tracks live command-list mutation, retained views, and builder aliases", () => {
    const resource = (body: string): string =>
      `package example
import io.ktor.resources.Resource
import io.ktor.server.resources.get
import io.ktor.server.routing.routing
import java.lang.ProcessBuilder

@Resource("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

fun routes() = routing {
    get<DiagnosticResource> { input ->
${body}
    }
}
`;

    const directIndex = records(
      resource(`        val value = input.target
        val builder = ProcessBuilder("sh", "-c", "fixed")
        builder.command()[2] = value
        builder.start()`),
    );
    expect(directIndex).toHaveLength(1);
    expect(
      directIndex[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("kotlin-command-list-mutation");

    const retainedView = records(
      resource(`        val value = input.target
        val builder = ProcessBuilder("sh", "-c", "fixed")
        val command = builder.command()
        command.set(2, value)
        builder.start()`),
    );
    expect(retainedView).toHaveLength(1);

    const constructorAlias = records(
      resource(`        val value = input.target
        val command = mutableListOf("sh", "-c", "fixed")
        val builder = ProcessBuilder(command)
        command[2] = value
        builder.start()`),
    );
    expect(constructorAlias).toHaveLength(1);

    const setterAndBuilderAliases = records(
      resource(`        val value = input.target
        val command = arrayListOf("sh", "-c", "fixed")
        val builder = ProcessBuilder("printf", "%s", "fixed")
        builder.command(command)
        val process = builder
        command.set(2, value)
        process.start()`),
    );
    expect(setterAndBuilderAliases).toHaveLength(1);
    expect(
      setterAndBuilderAliases[0]?.frameworkModel.propagators.map(
        ({ kind }) => kind,
      ),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-process-command-replacement",
        "kotlin-command-list-mutation",
      ]),
    );

    const rebuilt = records(
      resource(`        val value = input.target
        val builder = ProcessBuilder("printf", "%s", "fixed")
        val command = builder.command()
        command.clear()
        command.add("sh")
        command.add("-c")
        command.add(value)
        ProcessBuilder.startPipeline(listOf(builder))`),
    );
    expect(rebuilt).toHaveLength(1);
    expect(rebuilt[0]?.frameworkModel.sink.symbol).toBe(
      "java.lang.ProcessBuilder;method=startPipeline;argument=3",
    );

    const inserted = records(
      resource(`        val value = input.target
        val command = arrayListOf("sh", "fixed")
        val builder = ProcessBuilder(command)
        command.add(1, "-c")
        command.add(2, value)
        builder.start()`),
    );
    expect(inserted).toHaveLength(1);

    const shifted = records(
      resource(`        val value = input.target
        val command = arrayListOf("printf", "sh", "-c", value)
        val builder = ProcessBuilder(command)
        command.removeAt(0)
        builder.start()`),
    );
    expect(shifted).toHaveLength(1);
    expect(
      shifted[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("kotlin-command-list-mutation");

    const executable = records(
      resource(`        val value = input.target
        val builder = ProcessBuilder("printf", "%s", "fixed")
        builder.command()[0] = value
        builder.start()`),
    );
    expect(executable).toHaveLength(1);
    expect(executable[0]?.frameworkModel.sink.kind).toBe(
      "kotlin-process-executable-selection",
    );
  });

  test("models command-list detachment, overwrites, bounds, and argv controls", () => {
    const bodies = [
      `        val value = input.target
        val builder = ProcessBuilder("printf", "%s", "fixed")
        builder.command()[2] = value
        builder.start()`,
      `        val value = input.target
        val builder = ProcessBuilder("sh", "-c", "fixed")
        builder.command()[2] = value
        builder.command()[2] = "fixed"
        builder.start()`,
      `        val value = input.target
        val builder = ProcessBuilder("sh", "-c", "fixed")
        val detached = builder.command()
        builder.command("printf", "%s", "fixed")
        detached[0] = value
        builder.start()`,
      `        val value = input.target
        val builder = ProcessBuilder("sh", "-c", "fixed")
        builder.command()[20] = value
        builder.start()`,
      `        val value = input.target
        val builder = ProcessBuilder("sh", "-c", value)
        builder.command()[20] = "fixed"
        builder.start()`,
      `        val value = input.target
        val builder = ProcessBuilder("sh", "-c", value)
        val command = builder.command()
        command.clear()
        command.add("printf")
        command.add("%s")
        command.add(value)
        builder.start()`,
    ];
    for (const body of bodies) {
      const source = `package example
import io.ktor.resources.Resource
import io.ktor.server.resources.get
import io.ktor.server.routing.routing
import java.lang.ProcessBuilder

@Resource("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

fun routes() = routing {
    get<DiagnosticResource> { input ->
${body}
    }
}
`;
      expect(records(source)).toEqual([]);
    }
  });

  test("requires exact Resources identities and an annotated handler type", () => {
    const source = `package example
import io.ktor.resources.Resource as HttpResource
import io.ktor.server.resources.get
import io.ktor.server.routing.routing
import java.lang.ProcessBuilder

@HttpResource("/diagnostics/{target}")
data class DiagnosticResource(val target: String)

fun routes() = routing {
    get<DiagnosticResource> { input ->
        ProcessBuilder("sh", "-c", input.target).start()
    }
}
`;
    expect(records(source)).toHaveLength(1);
    expect(
      records(source.replace("{ input ->", "{\n        input ->")),
    ).toHaveLength(1);
    expect(records(source.replace("@HttpResource", "@LocalResource"))).toEqual(
      [],
    );
    expect(
      records(
        source.replace(
          "io.ktor.server.resources.get",
          "local.server.resources.get",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        ktor(
          `        val value = call.receiveText()
        Runtime.getRuntime().exec(arrayOf("sh", "-c", value))`,
          "import example.ProcessApi as Runtime",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        `${ktor(`        val value = call.receiveText()
        Runtime.getRuntime().exec(arrayOf("sh", "-c", value))`)}
fun arrayOf(vararg values: String): Array<String> = values as Array<String>`,
      ),
    ).toEqual([]);
  });

  test("keeps mutable-command witnesses harmless and paired", async () => {
    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[2],
        "src/test/kotlin/example/ResourceShellCommandWitnessTest.kt",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[3],
        "src/test/kotlin/example/ResourceArgvCommandWitnessTest.kt",
      ),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain("KOTLIN_RESOURCE_COMMAND_MARKER");
      expect(witness).toContain("builder.command");
      expect(witness).toContain("builder.start()");
      expect(witness).not.toContain("java.io.File");
      expect(witness).not.toContain("java.net");
    }
    expect(vulnerable).toContain('builder.command("sh", "-c", payload)');
    expect(safe).toContain('builder.command("printf", "%s", payload)');
  });

  test("keeps live-list fixtures executable, paired, and precisely modeled", async () => {
    const vulnerableRecords = await fixtureRecords(caseIds[4]);
    const safeRecords = await fixtureRecords(caseIds[5]);
    expect(vulnerableRecords).toHaveLength(1);
    expect(vulnerableRecords[0]).toMatchObject({
      line: 23,
      frameworkModel: {
        source: { kind: "ktor-typed-resource" },
        sink: {
          kind: "kotlin-process-shell-command",
          symbol: "java.lang.ProcessBuilder;method=start;argument=3",
        },
      },
    });
    expect(
      vulnerableRecords[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-string-interpolation",
        "kotlin-local-assignment",
        "kotlin-command-list-mutation",
      ]),
    );
    expect(safeRecords).toEqual([]);

    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[4],
        "src/test/kotlin/example/LiveCommandListInjectionWitnessTest.kt",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[5],
        "src/test/kotlin/example/LiveCommandListArgvWitnessTest.kt",
      ),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain("KOTLIN_LIVE_COMMAND_MARKER");
      expect(witness).toContain("builder.command()");
      expect(witness).toContain("val processBuilder = builder");
      expect(witness).not.toContain("java.io.File");
      expect(witness).not.toContain("java.net");
    }
    expect(vulnerable).toContain("liveCommand.set(2, payload)");
    expect(safe).toContain("liveCommand.clear()");
    expect(safe).toContain('liveCommand.add("printf")');
  });

  test("keeps inline-pipeline fixtures executable, paired, and precisely modeled", async () => {
    const vulnerableRecords = await fixtureRecords(caseIds[6]);
    const safeRecords = await fixtureRecords(caseIds[7]);
    expect(vulnerableRecords).toHaveLength(1);
    expect(vulnerableRecords[0]).toMatchObject({
      line: 18,
      frameworkModel: {
        source: { kind: "ktor-typed-resource" },
        sink: {
          kind: "kotlin-process-shell-command",
          symbol: "java.lang.ProcessBuilder;method=startPipeline;argument=3",
        },
      },
    });
    expect(
      vulnerableRecords[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("kotlin-process-pipeline-assembly");
    expect(safeRecords).toEqual([]);

    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[6],
        "src/test/kotlin/example/InlinePipelineInjectionWitnessTest.kt",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[7],
        "src/test/kotlin/example/InlinePipelineArgvWitnessTest.kt",
      ),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain("ProcessBuilder.startPipeline");
      expect(witness).toContain("listOf(");
      expect(witness).toContain("pipeline-expanded");
      expect(witness).not.toContain("java.io.File");
      expect(witness).not.toContain("java.net");
    }
    expect(vulnerable).toContain('ProcessBuilder("sh", "-c", commandLine)');
    expect(safe).toContain('ProcessBuilder("printf", "%s", argument)');
  });

  test("keeps helper fixtures executable, paired, and precisely modeled", async () => {
    const factoryRecords = await fixtureRecords(caseIds[8]);
    const factoryControl = await fixtureRecords(caseIds[9]);
    expect(factoryRecords).toHaveLength(1);
    expect(factoryRecords[0]).toMatchObject({
      line: 21,
      frameworkModel: {
        source: { kind: "ktor-typed-resource" },
        sink: {
          kind: "kotlin-process-shell-command",
          symbol: "java.lang.ProcessBuilder;method=start;argument=3",
        },
      },
    });
    expect(
      factoryRecords[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-process-builder-factory",
        "kotlin-process-helper-call",
      ]),
    );
    expect(factoryControl).toEqual([]);

    const helperRecords = await fixtureRecords(caseIds[10]);
    const helperControl = await fixtureRecords(caseIds[11]);
    expect(helperRecords).toHaveLength(1);
    expect(helperRecords[0]).toMatchObject({
      line: 24,
      frameworkModel: {
        source: { kind: "ktor-typed-resource" },
        sink: {
          kind: "kotlin-process-shell-command",
          symbol: "java.lang.ProcessBuilder;method=start;argument=3",
        },
      },
    });
    expect(
      helperRecords[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-process-command-helper",
        "kotlin-process-helper-call",
      ]),
    );
    expect(helperControl).toEqual([]);

    const witnesses = [
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[8],
          "src/test/kotlin/example/BuilderFactoryInjectionWitnessTest.kt",
        ),
        "utf8",
      ),
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[9],
          "src/test/kotlin/example/BuilderFactoryArgvWitnessTest.kt",
        ),
        "utf8",
      ),
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[10],
          "src/test/kotlin/example/CommandHelperInjectionWitnessTest.kt",
        ),
        "utf8",
      ),
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[11],
          "src/test/kotlin/example/CommandHelperArgvWitnessTest.kt",
        ),
        "utf8",
      ),
    ];
    for (const witness of witnesses) {
      expect(witness).toContain("ProcessBuilder");
      expect(witness).toContain("process.waitFor()");
      expect(witness).not.toContain("java.io.File");
      expect(witness).not.toContain("java.net");
    }
  });

  test("keeps env delegation fixtures executable, paired, and precisely modeled", async () => {
    const vulnerableRecords = await fixtureRecords(caseIds[12]);
    const safeRecords = await fixtureRecords(caseIds[13]);
    expect(vulnerableRecords).toHaveLength(1);
    expect(vulnerableRecords[0]).toMatchObject({
      line: 17,
      frameworkModel: {
        source: { kind: "ktor-typed-resource" },
        sink: {
          kind: "kotlin-process-executable-selection",
          symbol: "java.lang.ProcessBuilder;method=start;argument=3",
        },
      },
    });
    expect(vulnerableRecords[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({
        kind: "kotlin-process-delegated-launcher",
        symbol: "env",
      }),
    );
    expect(safeRecords).toEqual([]);

    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[12],
        "src/test/kotlin/example/EnvExecutableInjectionWitnessTest.kt",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[13],
        "src/test/kotlin/example/EnvArgvWitnessTest.kt",
      ),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain('ProcessBuilder("env", "--"');
      expect(witness).toContain("process.waitFor()");
      expect(witness).toContain("delegated-marker");
      expect(witness).not.toContain("java.io.File");
      expect(witness).not.toContain("java.net");
    }
    expect(vulnerable).toContain("requestProgram");
    expect(safe).toContain('"printf", "%s", requestValue');
  });

  test("keeps Runtime env fixtures executable, paired, and precisely modeled", async () => {
    const vulnerableRecords = await fixtureRecords(caseIds[14]);
    const safeRecords = await fixtureRecords(caseIds[15]);
    expect(vulnerableRecords).toHaveLength(1);
    expect(vulnerableRecords[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-executable-selection",
      symbol: "java.lang.Runtime;method=exec;argument=3",
    });
    expect(
      vulnerableRecords[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-runtime-exec",
        "kotlin-process-delegated-launcher",
      ]),
    );
    expect(safeRecords).toEqual([]);

    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[14],
        "src/test/kotlin/example/RuntimeEnvExecutableInjectionWitnessTest.kt",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[15],
        "src/test/kotlin/example/RuntimeEnvArgvWitnessTest.kt",
      ),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain("Runtime.getRuntime().exec(arrayOf(");
      expect(witness).toContain("process.waitFor()");
      expect(witness).toContain("delegated-marker");
      expect(witness).not.toContain("java.io.File");
      expect(witness).not.toContain("java.net");
    }
    expect(vulnerable).toContain("requestProgram");
    expect(safe).toContain('"printf", "%s", requestValue');
  });

  test("keeps converted-list Runtime fixtures executable, paired, and precisely modeled", async () => {
    const vulnerableRecords = await fixtureRecords(caseIds[16]);
    const safeRecords = await fixtureRecords(caseIds[17]);
    expect(vulnerableRecords).toHaveLength(1);
    expect(vulnerableRecords[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-executable-selection",
      symbol: "java.lang.Runtime;method=exec;argument=3",
    });
    expect(
      vulnerableRecords[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-runtime-array-conversion",
        "kotlin-runtime-exec",
        "kotlin-process-delegated-launcher",
      ]),
    );
    expect(safeRecords).toEqual([]);

    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[16],
        "src/test/kotlin/example/RuntimeListEnvExecutableInjectionWitnessTest.kt",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[17],
        "src/test/kotlin/example/RuntimeListEnvArgvWitnessTest.kt",
      ),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain(".toTypedArray()");
      expect(witness).toContain("Runtime.getRuntime().exec(command)");
      expect(witness).toContain("process.waitFor()");
      expect(witness).toContain("delegated-marker");
      expect(witness).not.toContain("java.io.File");
      expect(witness).not.toContain("java.net");
    }
    expect(vulnerable).toContain("requestProgram");
    expect(safe).toContain('"printf", "%s", requestValue');
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

  test("models env delegated commands, option operands, and split command strings", () => {
    const direct = records(
      ktor(`        val program = call.parameters["program"]!!
        ProcessBuilder("env", program).start()`),
    );
    expect(direct).toHaveLength(1);
    expect(direct[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-executable-selection",
      symbol: "java.lang.ProcessBuilder;method=start;argument=2",
    });
    expect(direct[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({
        kind: "kotlin-process-delegated-launcher",
        symbol: "env",
      }),
    );

    const afterAssignmentsAndDelimiter = records(
      ktor(`        val program = call.parameters["program"]!!
        ProcessBuilder("/usr/bin/env", "--", "MODE=fixed", program).start()`),
    );
    expect(afterAssignmentsAndDelimiter).toHaveLength(1);
    expect(afterAssignmentsAndDelimiter[0]?.frameworkModel.sink.symbol).toBe(
      "java.lang.ProcessBuilder;method=start;argument=4",
    );

    const delegatedShell = records(
      ktor(`        val commandLine = call.receiveText()
        ProcessBuilder("env", "-i", "--unset", "PATH", "sh", "-c", commandLine).start()`),
    );
    expect(delegatedShell).toHaveLength(1);
    expect(delegatedShell[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-shell-command",
      symbol: "java.lang.ProcessBuilder;method=start;argument=7",
    });

    const splitString = records(
      ktor(`        val commandLine = call.receiveText()
        ProcessBuilder("env", "--split-string=$commandLine").start()`),
    );
    expect(splitString).toHaveLength(1);
    expect(splitString[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-split-command",
      symbol: "java.lang.ProcessBuilder;method=start;argument=2",
    });

    const aliasedSplitString = records(
      ktor(`        val commandLine = call.receiveText()
        val splitOption = "--split-string=$commandLine"
        val optionAlias = splitOption
        ProcessBuilder("env", optionAlias).start()`),
    );
    expect(aliasedSplitString).toHaveLength(1);
    expect(aliasedSplitString[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-split-command",
      symbol: "java.lang.ProcessBuilder;method=start;argument=2",
    });

    const afterAliasedAssignment = records(
      ktor(`        val value = call.receiveText()
        val program = call.parameters["program"]!!
        val assignment = "MODE=$value"
        val assignmentAlias = assignment
        ProcessBuilder("env", "--", assignmentAlias, program).start()`),
    );
    expect(afterAliasedAssignment).toHaveLength(1);
    expect(afterAliasedAssignment[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-executable-selection",
      symbol: "java.lang.ProcessBuilder;method=start;argument=4",
    });

    const safeBodies = [
      `        val value = call.receiveText()
        ProcessBuilder("env", "printf", "%s", value).start()`,
      `        val value = call.receiveText()
        ProcessBuilder("env", "-u", value, "printf", "%s", "fixed").start()`,
      `        val value = call.receiveText()
        ProcessBuilder("env", "--unset=$value", "printf", "%s", "fixed").start()`,
      `        val value = call.receiveText()
        ProcessBuilder("env", "MODE=$value").start()`,
      `        val value = call.receiveText()
        val assignment = "MODE=$value"
        val assignmentAlias = assignment
        ProcessBuilder("env", "--", assignmentAlias).start()`,
      `        val value = call.receiveText()
        val unsetOption = "--unset=$value"
        ProcessBuilder("env", unsetOption, "printf", "%s", "fixed").start()`,
      `        val value = call.receiveText()
        ProcessBuilder("env", "--not-an-env-option", value).start()`,
      `        val value = call.receiveText()
        ProcessBuilder("env", "-S", "printf %s", value).start()`,
    ];
    for (const body of safeBodies) expect(records(ktor(body))).toEqual([]);

    const reassignedShape = records(
      ktor(`        val value = call.receiveText()
        var operand = "MODE=fixed"
        operand = value
        ProcessBuilder("env", operand).start()`),
    );
    expect(reassignedShape).toHaveLength(1);
    expect(reassignedShape[0]?.frameworkModel.sink.kind).toBe(
      "kotlin-process-executable-selection",
    );

    const attackerPrefixedShape = records(
      ktor(`        val value = call.receiveText()
        val operand = "$value=fixed"
        ProcessBuilder("env", operand).start()`),
    );
    expect(attackerPrefixedShape).toHaveLength(1);
  });

  test("models Runtime.exec command strings and exact command arrays", () => {
    const stringCommand = records(
      ktor(`        val value = call.receiveText()
        Runtime.getRuntime().exec("printf fixed; $value")`),
    );
    expect(stringCommand).toHaveLength(1);
    expect(stringCommand[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-split-command",
      symbol: "java.lang.Runtime;method=exec;argument=1",
    });
    expect(stringCommand[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({
        kind: "kotlin-runtime-exec",
        symbol: "java.lang.Runtime.exec",
      }),
    );

    const delegated = records(
      ktor(`        val program = call.parameters["program"]!!
        Runtime.getRuntime().exec(arrayOf("env", "--", program))`),
    );
    expect(delegated).toHaveLength(1);
    expect(delegated[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-executable-selection",
      symbol: "java.lang.Runtime;method=exec;argument=3",
    });
    expect(
      delegated[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-runtime-exec",
        "kotlin-process-delegated-launcher",
      ]),
    );

    const retained = records(
      ktor(`        val runtime = Runtime.getRuntime()
        val program = call.parameters["program"]!!
        val command = arrayOf("env", "--", "printf")
        command[2] = program
        runtime.exec(command)`),
    );
    expect(retained).toHaveLength(1);
    expect(retained[0]?.frameworkModel.sink.symbol).toBe(
      "java.lang.Runtime;method=exec;argument=3",
    );
    expect(retained[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({ kind: "kotlin-command-list-mutation" }),
    );

    const aliased = records(
      ktor(
        `        val commandLine = call.receiveText()
        RuntimeApi.getRuntime().exec(kotlin.arrayOf("sh", "-c", commandLine))`,
        "import java.lang.Runtime as RuntimeApi",
      ),
    );
    expect(aliased).toHaveLength(1);
    expect(aliased[0]?.frameworkModel.sink.kind).toBe(
      "kotlin-process-shell-command",
    );

    const qualified = records(
      ktor(`        val program = call.parameters["program"]!!
        java.lang.Runtime.getRuntime().exec(arrayOf(program))`),
    );
    expect(qualified).toHaveLength(1);
    expect(qualified[0]?.frameworkModel.sink.kind).toBe(
      "kotlin-process-executable-selection",
    );

    const converted = records(
      ktor(`        val program = call.parameters["program"]!!
        Runtime.getRuntime().exec(listOf("env", "--", program).toTypedArray())`),
    );
    expect(converted).toHaveLength(1);
    expect(converted[0]?.frameworkModel.sink).toMatchObject({
      kind: "kotlin-process-executable-selection",
      symbol: "java.lang.Runtime;method=exec;argument=3",
    });
    expect(
      converted[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "kotlin-runtime-array-conversion",
        "kotlin-runtime-exec",
        "kotlin-process-delegated-launcher",
      ]),
    );

    const qualifiedConversion = records(
      ktor(`        val commandLine = call.receiveText()
        Runtime.getRuntime().exec(kotlin.collections.listOf("sh", "-c", commandLine).toTypedArray())`),
    );
    expect(qualifiedConversion).toHaveLength(1);
    expect(qualifiedConversion[0]?.frameworkModel.sink.kind).toBe(
      "kotlin-process-shell-command",
    );

    const snapshot = records(
      ktor(`        val program = call.parameters["program"]!!
        val parts = mutableListOf("env", "--", "printf")
        parts[2] = program
        val command = parts.toTypedArray()
        parts[2] = "printf"
        Runtime.getRuntime().exec(command)`),
    );
    expect(snapshot).toHaveLength(1);
    expect(snapshot[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({ kind: "kotlin-runtime-array-conversion" }),
    );

    const repairedArray = records(
      ktor(`        val program = call.parameters["program"]!!
        val command = mutableListOf("env", "--", program).toTypedArray()
        command[2] = "printf"
        Runtime.getRuntime().exec(command)`),
    );
    expect(repairedArray).toEqual([]);

    const safeBodies = [
      `        val value = call.receiveText()
        Runtime.getRuntime().exec(arrayOf("printf", "%s", value))`,
      `        val value = call.receiveText()
        Runtime.getRuntime().exec(listOf("sh", "-c", value))`,
      `        val value = call.receiveText()
        Runtime.getRuntime().exec(arrayOf("env", "printf", "%s", value))`,
      `        val value = call.receiveText()
        Runtime.getRuntime().exec(listOf("env", "--", "printf", "%s", value).toTypedArray())`,
      `        val value = call.receiveText()
        Runtime.getRuntime().exec(listOf("sh", "-c", value))`,
    ];
    for (const body of safeBodies) expect(records(ktor(body))).toEqual([]);

    expect(
      records(
        ktor(
          `        val value = call.receiveText()
        Runtime.getRuntime().exec(arrayOf("sh", "-c", value))`,
          "class Runtime { fun exec(command: Array<String>) = Unit; companion object { fun getRuntime() = Runtime() } }",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        ktor(
          `        val value = call.receiveText()
        val command = listOf("sh", "-c", value)
        Runtime.getRuntime().exec(command.toTypedArray())`,
          "fun listOf(vararg values: String): List<String> = values.asList()",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        ktor(
          `        val value = call.receiveText()
        Runtime.getRuntime().exec(listOf("sh", "-c", value).toTypedArray())`,
          "fun <T> List<T>.toTypedArray(): Array<T> = arrayOf()",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        ktor(
          `        val value = call.receiveText()
        Runtime.getRuntime().exec(listOf("sh", "-c", value).toTypedArray())`,
          "fun listOf(vararg values: String): List<String> = values.asList()",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        ktor(
          `        val value = call.receiveText()
        Runtime.getRuntime().exec(arrayOf("sh", "-c", value))`,
          "import example.Runtime",
        ),
      ),
    ).toEqual([]);
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
    expect(prompt).toContain("live list returned by command()");
    expect(prompt).toContain("clear/rebuild order");
    expect(prompt).toContain("proven builder alias");
    expect(prompt).toContain("same route lambda");
    expect(prompt).toContain("bounded harmless environment-marker witness");
    expect(prompt).toContain("POSIX env is a delegating launcher");
    expect(prompt).toContain(
      "--split-string value as env-parsed command grammar",
    );
    expect(prompt).toContain("Runtime.getRuntime().exec overload");
    expect(prompt).toContain("Collection.toTypedArray");
    expect(prompt).toContain("snapshot command array");
    expect(prompt).toContain("unsupported List call shapes");
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

  test("requires helper-specific validation and attack-path closure", async () => {
    const helpers = [
      {
        caseId: caseIds[8],
        commandLine: 20,
        helperStart: 13,
        helperEnd: 14,
        helperCode:
          'private fun diagnosticProcess(commandLine: String): ProcessBuilder =\n    ProcessBuilder("sh", "-c", commandLine)',
        helperSymbol: "diagnosticProcess",
        validationAlternatives: [
          "diagnosticProcess",
          "builder factory",
          "factory helper",
        ],
        attackPathAlternatives: [
          "diagnosticProcess",
          "builder factory",
          "factory helper",
          "helper call",
        ],
        sinkLine: 21,
        sinkCode: "val process = diagnosticProcess(commandLine).start()",
      },
      {
        caseId: caseIds[10],
        commandLine: 21,
        helperStart: 13,
        helperEnd: 14,
        helperCode:
          'private fun configureProcess(builder: ProcessBuilder, commandLine: String) {\n    builder.command("sh", "-c", commandLine)\n}',
        helperSymbol: "configureProcess",
        validationAlternatives: [
          "configureProcess",
          "command helper",
          "mutator helper",
        ],
        attackPathAlternatives: [
          "configureProcess",
          "command helper",
          "mutator helper",
          "helper call",
        ],
        sinkLine: 24,
        sinkCode: "val process = builder.start()",
      },
    ] as const;

    for (const helper of helpers) {
      const repository = join(benchmarkRoot, "fixtures", helper.caseId);
      const scanDirectory = await mkdtemp(
        join(tmpdir(), "copilot-security-kotlin-helper-quality-"),
      );
      try {
        const finding = {
          findingId: `occ_${helper.helperSymbol}_quality`,
          taxonomy: { cwe: ["CWE-78", "CWE-88"] },
          locations: [
            {
              path: handlerPath,
              startLine: 10,
              endLine: 11,
              role: "source",
            },
            {
              path: handlerPath,
              startLine: helper.sinkLine,
              endLine: helper.sinkLine,
              role: "sink",
            },
          ],
          codeEvidence: [
            {
              id: "typed-resource-source",
              path: handlerPath,
              startLine: 10,
              endLine: 11,
              role: "source",
              code: '@Resource("/diagnostics/{target}")\ndata class DiagnosticResource(val target: String)',
              explanation: "The typed route value contains remote input.",
            },
            {
              id: "command-line",
              path: handlerPath,
              startLine: helper.commandLine,
              endLine: helper.commandLine,
              role: "propagator",
              code: 'val commandLine = "printf diagnostic; ${input.target}"',
              explanation: "The request value enters shell program text.",
            },
            {
              id: "helper-definition",
              path: handlerPath,
              startLine: helper.helperStart,
              endLine: helper.helperEnd,
              role: "propagator",
              code: helper.helperCode,
              explanation: "A same-file helper configures the process.",
            },
            {
              id: "process-start",
              path: handlerPath,
              startLine: helper.sinkLine,
              endLine: helper.sinkLine,
              role: "sink",
              code: helper.sinkCode,
              explanation: "The configured process starts.",
            },
          ],
          validation: {
            method: "static_source_trace",
            summary:
              "Ktor resource binding places input.target in commandLine, and ProcessBuilder executes the shell program through sh -c.",
            exploitWitness:
              "A bounded inert marker checks shell interpretation.",
            negativeControl:
              "A fixed executable with the same value in ordinary argv does not interpret it.",
            evidence: [
              "typed-resource-source",
              "command-line",
              "helper-definition",
              "process-start",
            ],
            counterEvidence:
              "An argument array is not a barrier when sh receives -c.",
            remainingUncertainty: "Deployment reachability remains unknown.",
          },
          attackPath: {
            summary:
              "The target resource value enters commandLine as a command string; ProcessBuilder start executes the shell program and stdout reaches respondText in the response.",
            dataflow: {
              source: "The target resource value.",
              sink: "ProcessBuilder start with commandLine.",
              outcome: "The shell program executes.",
            },
            reachability: {
              attacker: "A remote HTTP caller.",
              entrypoint: "The typed diagnostics route.",
              outcome: "A child process starts and its stdout is returned.",
            },
            brokenControls: ["No command/data separation"],
            evidenceRefs: [
              "typed-resource-source",
              "command-line",
              "helper-definition",
              "process-start",
            ],
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
        const gap = incomplete
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line))[1];
        expect(gap).toMatchObject({
          findingId: `occ_${helper.helperSymbol}_quality`,
          frameworkModelId: "kotlin-ktor-command-injection",
          reasons: [
            "missing_model_specific_validation_evidence",
            "missing_model_specific_attack_path_evidence",
          ],
          missingValidationTextAnyOf: [helper.validationAlternatives],
          missingAttackPathTextAnyOf: [helper.attackPathAlternatives],
        });

        finding.validation.summary += ` The ${helper.helperSymbol} helper preserves the exact interprocedural boundary.`;
        finding.attackPath.summary += ` The helper call to ${helper.helperSymbol} precedes the recorded process start.`;
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
    }
  });

  test("requires env delegation and executable-selection closure", async () => {
    const repository = join(benchmarkRoot, "fixtures", caseIds[12]);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-kotlin-env-quality-"),
    );
    try {
      const finding = {
        findingId: "occ_kotlin_env_quality",
        taxonomy: { cwe: ["CWE-78", "CWE-88"] },
        locations: [
          { path: handlerPath, startLine: 10, endLine: 11, role: "source" },
          { path: handlerPath, startLine: 17, endLine: 17, role: "sink" },
        ],
        codeEvidence: [
          {
            id: "env-resource-source",
            path: handlerPath,
            startLine: 10,
            endLine: 11,
            role: "source",
            code: '@Resource("/diagnostics/{target}")\ndata class DiagnosticResource(val target: String)',
            explanation: "The typed route value contains remote input.",
          },
          {
            id: "env-process-start",
            path: handlerPath,
            startLine: 17,
            endLine: 17,
            role: "sink",
            code: 'ProcessBuilder("env", "--", input.target).start()',
            explanation: "The process launcher starts.",
          },
        ],
        validation: {
          method: "static_source_trace",
          summary:
            "The typed Ktor resource input.target reaches java.lang.ProcessBuilder start.",
          exploitWitness:
            "A fixed harmless printf witness occupies the request-controlled position.",
          negativeControl:
            "The paired control fixes printf before the same value in ordinary argv.",
          evidence: ["env-resource-source", "env-process-start"],
          counterEvidence:
            "No shell is needed for this command-selection boundary.",
          remainingUncertainty: "Deployment reachability remains unknown.",
        },
        attackPath: {
          summary:
            "The target resource value reaches ProcessBuilder start and stdout reaches respondText in the response.",
          dataflow: {
            source: "The target resource value.",
            sink: "A ProcessBuilder start.",
            outcome: "A child process may start.",
          },
          reachability: {
            attacker: "A remote HTTP caller.",
            entrypoint: "The typed diagnostics route.",
            outcome: "Process output is returned.",
          },
          brokenControls: ["No fixed executable at the delegated boundary"],
          evidenceRefs: ["env-resource-source", "env-process-start"],
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
      const gap = incomplete
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))[1];
      expect(gap).toMatchObject({
        findingId: "occ_kotlin_env_quality",
        frameworkModelId: "kotlin-ktor-command-injection",
        reasons: [
          "missing_model_specific_validation_evidence",
          "missing_model_specific_attack_path_evidence",
        ],
        missingValidationTextAnyOf: [
          expect.arrayContaining(["executable selection"]),
          expect.arrayContaining(["delegating launcher"]),
        ],
        missingAttackPathTextAnyOf: [
          expect.arrayContaining(["executable selection"]),
          expect.arrayContaining(["delegated executable"]),
        ],
      });

      finding.validation.summary +=
        " The env delegating launcher uses input.target for executable selection.";
      finding.attackPath.summary +=
        " The env delegated executable is selected by the target value, creating executable selection.";
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

  test("requires Runtime exec evidence at the recorded launch boundary", async () => {
    const repository = join(benchmarkRoot, "fixtures", caseIds[14]);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-kotlin-runtime-quality-"),
    );
    try {
      const finding = {
        findingId: "occ_kotlin_runtime_quality",
        taxonomy: { cwe: ["CWE-78", "CWE-88"] },
        locations: [
          { path: handlerPath, startLine: 9, endLine: 10, role: "source" },
          { path: handlerPath, startLine: 16, endLine: 16, role: "sink" },
        ],
        codeEvidence: [
          {
            id: "runtime-resource-source",
            path: handlerPath,
            startLine: 9,
            endLine: 10,
            role: "source",
            code: '@Resource("/diagnostics/{target}")\ndata class DiagnosticResource(val target: String)',
            explanation: "The typed route value contains remote input.",
          },
          {
            id: "runtime-process-start",
            path: handlerPath,
            startLine: 16,
            endLine: 16,
            role: "sink",
            code: 'val process = Runtime.getRuntime().exec(arrayOf("env", "--", input.target))',
            explanation: "The runtime process launcher executes the array.",
          },
        ],
        validation: {
          method: "static_source_trace",
          summary:
            "The typed Ktor resource input.target reaches env as a delegating launcher and controls executable selection.",
          exploitWitness:
            "A fixed harmless printf witness occupies the selected program position.",
          negativeControl:
            "The paired control fixes printf before the same value in ordinary argv.",
          evidence: ["runtime-resource-source", "runtime-process-start"],
          counterEvidence: "No shell is needed for executable selection.",
          remainingUncertainty: "Deployment reachability remains unknown.",
        },
        attackPath: {
          summary:
            "The target resource value reaches the env delegated executable-selection position and stdout reaches respondText in the response.",
          dataflow: {
            source: "The target resource value.",
            sink: "The delegated program-selection boundary.",
            outcome: "A child process may start.",
          },
          reachability: {
            attacker: "A remote HTTP caller.",
            entrypoint: "The typed diagnostics route.",
            outcome: "Process output is returned.",
          },
          brokenControls: ["No fixed executable at the delegated boundary"],
          evidenceRefs: ["runtime-resource-source", "runtime-process-start"],
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
      const gap = incomplete
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))[1];
      expect(gap).toMatchObject({
        findingId: "occ_kotlin_runtime_quality",
        frameworkModelId: "kotlin-ktor-command-injection",
        reasons: [
          "missing_model_specific_validation_evidence",
          "missing_model_specific_attack_path_evidence",
        ],
      });
      expect(gap.missingValidationTextAnyOf.flat()).toContain("Runtime.exec");
      expect(gap.missingAttackPathTextAnyOf.flat()).toContain("Runtime.exec");

      finding.validation.summary +=
        " java.lang.Runtime.exec executes the exact command array.";
      finding.attackPath.summary +=
        " Runtime.exec carries that array into the executable selection and child-process boundary.";
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

  test("requires converted Runtime command arrays in validation and attack paths", async () => {
    const repository = join(benchmarkRoot, "fixtures", caseIds[16]);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-kotlin-runtime-conversion-quality-"),
    );
    try {
      const finding = {
        findingId: "occ_kotlin_runtime_conversion_quality",
        taxonomy: { cwe: ["CWE-78", "CWE-88"] },
        locations: [
          { path: handlerPath, startLine: 9, endLine: 10, role: "source" },
          { path: handlerPath, startLine: 16, endLine: 17, role: "sink" },
        ],
        codeEvidence: [
          {
            id: "converted-resource-source",
            path: handlerPath,
            startLine: 9,
            endLine: 10,
            role: "source",
            code: '@Resource("/diagnostics/{target}")\ndata class DiagnosticResource(val target: String)',
            explanation: "The typed route value contains remote input.",
          },
          {
            id: "converted-runtime-start",
            path: handlerPath,
            startLine: 16,
            endLine: 17,
            role: "sink",
            code: 'val command = listOf("env", "--", input.target).toTypedArray()\nval process = Runtime.getRuntime().exec(command)',
            explanation: "The runtime process launcher executes the array.",
          },
        ],
        validation: {
          method: "static_source_trace",
          summary:
            "The typed Ktor resource input.target reaches java.lang.Runtime.exec through env and controls delegated executable selection.",
          exploitWitness:
            "A fixed harmless printf witness occupies the selected program position.",
          negativeControl:
            "The paired control fixes printf before the same value in ordinary argv.",
          evidence: ["converted-resource-source", "converted-runtime-start"],
          counterEvidence: "No shell is needed for executable selection.",
          remainingUncertainty: "Deployment reachability remains unknown.",
        },
        attackPath: {
          summary:
            "The target resource value reaches Runtime.exec through env at the delegated executable-selection position and stdout reaches respondText in the response.",
          dataflow: {
            source: "The target resource value.",
            sink: "The delegated program-selection boundary.",
            outcome: "A child process may start.",
          },
          reachability: {
            attacker: "A remote HTTP caller.",
            entrypoint: "The typed diagnostics route.",
            outcome: "Process output is returned.",
          },
          brokenControls: ["No fixed executable at the delegated boundary"],
          evidenceRefs: [
            "converted-resource-source",
            "converted-runtime-start",
          ],
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
      const gap = incomplete
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))[1];
      expect(gap).toMatchObject({
        findingId: "occ_kotlin_runtime_conversion_quality",
        frameworkModelId: "kotlin-ktor-command-injection",
        reasons: [
          "missing_model_specific_validation_evidence",
          "missing_model_specific_attack_path_evidence",
        ],
      });
      expect(gap.missingValidationTextAnyOf).toContainEqual(
        expect.arrayContaining(["toTypedArray"]),
      );
      expect(gap.missingAttackPathTextAnyOf).toContainEqual(
        expect.arrayContaining(["toTypedArray"]),
      );

      finding.validation.summary +=
        " Collection.toTypedArray snapshots the list into the exact command array. env is the delegating launcher.";
      finding.attackPath.summary +=
        " The toTypedArray conversion carries the selected element into that array for executable selection.";
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
