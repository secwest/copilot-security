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
  javaSpringCommandInjectionRecords,
  type JavaSpringCommandInjectionRecord,
} from "../src/java-spring-command-risk.js";

const handlerPath = "src/main/java/example/DiagnosticsController.java";
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

function spring(
  body: string,
  parameter = '@RequestParam("target") String target',
): string {
  return `package example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class DiagnosticsController {
    @GetMapping("/diagnostics")
    public String diagnostics(${parameter}) throws Exception {
${body}
        return "ok";
    }
}
`;
}

function records(
  source: string,
  path = handlerPath,
): JavaSpringCommandInjectionRecord[] {
  return javaSpringCommandInjectionRecords(
    path,
    source.split(/\r?\n/u),
    source,
  );
}

describe("Spring Java command-injection model", () => {
  test("keeps the executable benchmark pair under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "spring-java-command-injection-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{ id: string; expected: unknown[] }>;
    };
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "spring-java-fluent-process-builder-injection",
      "spring-java-fluent-process-builder-argv",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toHaveLength(0);

    const vulnerable = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", manifest.cases[0]!.id),
    );
    const safe = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", manifest.cases[1]!.id),
    );
    const modelRows = vulnerable
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as JavaSpringCommandInjectionRecord)
      .filter(
        (record) =>
          record.frameworkModel?.id === "spring-java-command-injection",
      );
    expect(modelRows).toHaveLength(1);
    expect(modelRows[0]?.frameworkModel.sink.kind).toBe(
      "java-process-shell-command",
    );
    expect(safe).not.toContain("spring-java-command-injection");
  });

  test("detects a fluent ProcessBuilder shell command including login flags", () => {
    const found = records(
      spring(`        new ProcessBuilder()
            .redirectErrorStream(true)
            .command("/bin/bash", "-l", "-c", target)
            .start();`),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      id: "spring-java-command-injection",
      source: { kind: "spring-bound-parameter", symbol: "RequestParam:target" },
      sink: {
        kind: "java-process-shell-command",
        symbol: "java.lang.ProcessBuilder;method=start;argument=4",
        cweIds: ["CWE-78", "CWE-88"],
      },
    });
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("java-process-command-replacement");
  });

  test("tracks assignments into a separately started builder", () => {
    const found = records(
      spring(`        String commandLine = "printf fixed; " + target;
        ProcessBuilder builder = new ProcessBuilder("printf", "%s", "fixed");
        builder.command("sh", "-c", commandLine);
        builder.start();`),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.sink.kind).toBe(
      "java-process-shell-command",
    );
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "java-string-concatenation",
        "java-local-assignment",
        "java-process-command-replacement",
        "java-process-execution",
      ]),
    );
  });

  test("detects executable selection and interpreter code positions", () => {
    const executable = records(
      spring(`        new ProcessBuilder(target).start();`),
    );
    const interpreter = records(
      spring(`        new ProcessBuilder("python3", "-c", target).start();`),
    );
    expect(executable[0]?.frameworkModel.sink).toMatchObject({
      kind: "java-process-executable-selection",
      symbol: "java.lang.ProcessBuilder;method=start;argument=1",
    });
    expect(interpreter[0]?.frameworkModel.sink).toMatchObject({
      kind: "java-process-interpreter-command",
      symbol: "java.lang.ProcessBuilder;method=start;argument=3",
    });
  });

  test("classifies CMD, PowerShell, batch, and exact list factory commands", () => {
    const sources = [
      `        new ProcessBuilder("cmd.exe", "/c", target).start();`,
      `        new ProcessBuilder("pwsh", "-Command", target).start();`,
      `        new ProcessBuilder("diagnostic.cmd", target).start();`,
      `        new ProcessBuilder(java.util.List.of("sh", "-c", target)).start();`,
      `        new ProcessBuilder().command(java.util.Arrays.asList("sh", "-c", target)).start();`,
    ];
    for (const source of sources) {
      const found = records(spring(source));
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.kind).toBe(
        "java-process-shell-command",
      );
    }
  });

  test("requires exact java.util ownership for unqualified list factories", () => {
    const imported = spring(
      `        new ProcessBuilder(List.of("sh", "-c", target)).start();
        new ProcessBuilder(Arrays.asList("sh", "-c", target)).start();`,
    ).replace(
      "import org.springframework.web.bind.annotation.RequestParam;",
      "import org.springframework.web.bind.annotation.RequestParam;\nimport java.util.Arrays;\nimport java.util.List;",
    );
    expect(records(imported)).toHaveLength(2);

    const lookalike = spring(
      `        new ProcessBuilder(List.of("sh", "-c", target)).start();`,
    ).concat(
      "\nclass List { static Object of(Object... values) { return values; } }\n",
    );
    expect(records(lookalike)).toEqual([]);
  });

  test("models Runtime command strings and inline String arrays", () => {
    const commandString = records(
      spring(`        Runtime.getRuntime().exec("printf " + target);`),
    );
    const array = records(
      spring(
        `        Runtime.getRuntime().exec(new String[] { "sh", "-c", target });`,
      ),
    );
    expect(commandString[0]?.frameworkModel.sink).toMatchObject({
      kind: "java-process-split-command",
      symbol: "java.lang.Runtime;method=exec;argument=1",
    });
    expect(array[0]?.frameworkModel.sink).toMatchObject({
      kind: "java-process-shell-command",
      symbol: "java.lang.Runtime;method=exec;argument=3",
    });
  });

  test("models POSIX env executable selection and nested shell grammar", () => {
    const selection = records(
      spring(
        `        new ProcessBuilder("env", "--", "MODE=fixed", target).start();`,
      ),
    );
    const nested = records(
      spring(
        `        Runtime.getRuntime().exec(new String[] { "env", "-i", "sh", "-c", target });`,
      ),
    );
    expect(selection[0]?.frameworkModel.sink).toMatchObject({
      kind: "java-process-executable-selection",
      symbol: "java.lang.ProcessBuilder;method=start;argument=4",
    });
    expect(nested[0]?.frameworkModel.sink).toMatchObject({
      kind: "java-process-shell-command",
      symbol: "java.lang.Runtime;method=exec;argument=5",
    });
    expect(
      nested[0]?.frameworkModel.propagators.some(
        ({ kind, symbol }) =>
          kind === "java-process-delegated-launcher" &&
          symbol === "env nested command",
      ),
    ).toBeTrue();
  });

  test("rejects ordinary argv, inert builders, and overwritten dangerous state", () => {
    expect(
      records(
        spring(`        new ProcessBuilder("printf", "%s", target).start();`),
      ),
    ).toEqual([]);
    expect(
      records(spring(`        new ProcessBuilder("sh", "-c", target);`)),
    ).toEqual([]);
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder("sh", "-c", target);
        builder.command("printf", "%s", target);
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(
          `        new ProcessBuilder(java.util.List.of("printf", "%s", target)).start();`,
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(
          `        new ProcessBuilder(new String[] { "printf", "%s", target }).start();`,
        ),
      ),
    ).toEqual([]);
  });

  test("accepts exact Spring wildcard imports and all supported bound sources", () => {
    for (const annotation of [
      "CookieValue",
      "MatrixVariable",
      "PathVariable",
      "RequestBody",
      "RequestHeader",
      "RequestParam",
    ]) {
      const source = spring(
        `        new ProcessBuilder(target).start();`,
        `@${annotation}("target") String target`,
      ).replace(
        "import org.springframework.web.bind.annotation.GetMapping;\nimport org.springframework.web.bind.annotation.RequestParam;",
        "import org.springframework.web.bind.annotation.*;",
      );
      expect(records(source)[0]?.frameworkModel.source.symbol).toBe(
        `${annotation}:target`,
      );
    }
  });

  test("clears reassigned request values and preserves proven builder aliases", () => {
    expect(
      records(
        spring(`        target = "fixed";
        new ProcessBuilder(target).start();`),
      ),
    ).toEqual([]);
    const aliased = records(
      spring(`        ProcessBuilder builder = new ProcessBuilder("sh", "-c", target);
        ProcessBuilder alias = builder;
        alias.start();`),
    );
    expect(aliased).toHaveLength(1);
    expect(aliased[0]?.frameworkModel.sink.kind).toBe(
      "java-process-shell-command",
    );
  });

  test("ignores command text inside comments and strings", () => {
    const source =
      spring(`        String note = "new ProcessBuilder(target).start()";
        // new ProcessBuilder("sh", "-c", target).start();`);
    expect(records(source)).toEqual([]);
  });

  test("rejects lookalike platform types and non-routes", () => {
    const shadowed = `${spring(`        new ProcessBuilder("sh", "-c", target).start();`)}
class ProcessBuilder {
    ProcessBuilder(String... values) {}
    ProcessBuilder start() { return this; }
}`;
    expect(records(shadowed)).toEqual([]);
    expect(
      records(
        spring(`        Runtime.getRuntime().exec(target);`).replace(
          "public class DiagnosticsController {",
          "public class DiagnosticsController {\n    static class Runtime { static Runtime getRuntime() { return new Runtime(); } void exec(String value) {} }",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(`        new ProcessBuilder(target).start();`).replace(
          '@GetMapping("/diagnostics")',
          "",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(`        new ProcessBuilder(target).start();`)
          .replace(
            "import org.springframework.web.bind.annotation.RequestParam;",
            "",
          )
          .concat("\n@interface RequestParam { String value(); }\n"),
      ),
    ).toEqual([]);
  });

  test("rejects tests and generated fixture paths", () => {
    const source = spring(`        new ProcessBuilder(target).start();`);
    expect(
      records(source, "src/test/java/example/DiagnosticsController.java"),
    ).toEqual([]);
    expect(
      records(source, "build/generated/example/DiagnosticsController.java"),
    ).toEqual([]);
  });

  test("gives validation the exact Java command boundary", () => {
    const prompt = scanQualityGatePrompt(
      "{}",
      JSON.stringify({
        frameworkModel: {
          id: "spring-java-command-injection",
          source: { kind: "spring-bound-parameter" },
          sink: { kind: "java-process-shell-command" },
        },
      }),
      "[]",
    );
    expect(prompt).toContain("For spring-java-command-injection rows");
    expect(prompt).toContain("intervening login flags");
    expect(prompt).toContain("strong counterevidence");
  });

  test("requires Java process semantics in finding-quality closure", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "spring-java-fluent-process-builder-injection",
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-spring-java-quality-"),
    );
    try {
      const finding = {
        findingId: "occ_spring_java_command",
        taxonomy: { cwe: ["CWE-78", "CWE-88"] },
        locations: [
          { path: handlerPath, startLine: 10, role: "source" },
          { path: handlerPath, startLine: 15, role: "sink" },
        ],
        codeEvidence: [
          {
            id: "java-source",
            path: handlerPath,
            startLine: 10,
            endLine: 10,
            role: "source",
            code: '@RequestParam("target") String target',
            explanation: "The handler binds target from the HTTP request.",
          },
          {
            id: "java-sink",
            path: handlerPath,
            startLine: 12,
            endLine: 15,
            role: "sink",
            code: 'new ProcessBuilder().command("/bin/bash", "-l", "-c", target).start()',
            explanation: "The fluent builder starts the configured process.",
          },
        ],
        validation: {
          method: "static_source_trace",
          summary: "A request value reaches a process.",
          exploitWitness: "A bounded fixed string checks the process boundary.",
          negativeControl: "A fixed executable receives one ordinary argument.",
          evidence: ["java-source", "java-sink"],
          counterEvidence: "No dominating exact repair is present.",
          remainingUncertainty: "Deployment remains unknown.",
        },
        attackPath: {
          summary: "An HTTP caller can influence a process operation.",
          dataflow: {
            source: "A bound HTTP value.",
            sink: "A process operation.",
            outcome: "Process integrity may be affected.",
          },
          reachability: {
            attacker: "A remote caller.",
            entrypoint: "The diagnostics handler.",
            outcome: "A child process may run.",
          },
          brokenControls: ["No exact command/data boundary"],
          evidenceRefs: ["java-source", "java-sink"],
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
      const gap = incomplete
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))[1];
      expect(gap).toMatchObject({
        findingId: "occ_spring_java_command",
        frameworkModelId: "spring-java-command-injection",
        reasons: [
          "missing_model_specific_validation_evidence",
          "missing_model_specific_attack_path_evidence",
        ],
      });

      finding.validation.summary =
        "Spring RequestParam target reaches java.lang.ProcessBuilder after the fluent command replacement; /bin/bash -l -c places it in shell command grammar before start.";
      finding.attackPath.summary =
        "The request parameter target enters a shell command string and ProcessBuilder start performs process execution before stdout is returned in the response.";
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
    } finally {
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });
});
