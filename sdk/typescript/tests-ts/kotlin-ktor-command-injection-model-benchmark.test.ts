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
    expect(prompt).toContain("live list returned by command()");
    expect(prompt).toContain("clear/rebuild order");
    expect(prompt).toContain("proven builder alias");
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
