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
      "spring-java-live-command-list-injection",
      "spring-java-live-command-list-argv",
      "spring-java-caller-command-list-injection",
      "spring-java-caller-command-list-argv",
      "spring-java-collections-addall-injection",
      "spring-java-collections-addall-argv",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toHaveLength(0);
    expect(manifest.cases[2]?.expected).toHaveLength(1);
    expect(manifest.cases[3]?.expected).toHaveLength(0);
    expect(manifest.cases[4]?.expected).toHaveLength(1);
    expect(manifest.cases[5]?.expected).toHaveLength(0);
    expect(manifest.cases[6]?.expected).toHaveLength(1);
    expect(manifest.cases[7]?.expected).toHaveLength(0);

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

    const liveListVulnerable = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", manifest.cases[2]!.id),
    );
    const liveListSafe = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", manifest.cases[3]!.id),
    );
    expect(liveListVulnerable).toContain("java-command-list-mutation");
    expect(liveListSafe).not.toContain("spring-java-command-injection");

    const callerListVulnerable = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", manifest.cases[4]!.id),
    );
    const callerListSafe = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", manifest.cases[5]!.id),
    );
    expect(callerListVulnerable).toContain("java-caller-command-list-binding");
    expect(callerListVulnerable).toContain("caller-owned command list");
    expect(callerListSafe).not.toContain("spring-java-command-injection");

    const collectionsVulnerable = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", manifest.cases[6]!.id),
    );
    const collectionsSafe = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", manifest.cases[7]!.id),
    );
    expect(collectionsVulnerable).toContain("java-caller-command-list-binding");
    expect(collectionsVulnerable).toContain("java-command-list-mutation");
    expect(collectionsSafe).not.toContain("spring-java-command-injection");
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

  test("tracks live command-list aliases through clear and append", () => {
    const found = records(
      spring(`        ProcessBuilder builder = new ProcessBuilder("printf", "%s", "fixed");
        java.util.List<String> command = builder.command();
        java.util.List<String> alias = command;
        alias.clear();
        alias.add("sh");
        alias.add("-c");
        alias.add(target);
        builder.start();`),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.sink).toMatchObject({
      kind: "java-process-shell-command",
      symbol: "java.lang.ProcessBuilder;method=start;argument=3",
    });
    expect(found[0]?.frameworkModel.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "java-command-list-mutation",
          symbol: "ProcessBuilder.command live list",
        }),
        expect.objectContaining({ kind: "java-process-execution" }),
      ]),
    );
  });

  test("preserves caller-owned ArrayList identity through construction", () => {
    const source =
      spring(`        List<String> command = new ArrayList<>(List.of("printf", "%s", "fixed"));
        ProcessBuilder builder = new ProcessBuilder(command);
        List<String> alias = command;
        alias.clear();
        alias.add("sh");
        alias.add("-c");
        alias.add(target);
        builder.start();`).replace(
        "import org.springframework.web.bind.annotation.RequestParam;",
        "import org.springframework.web.bind.annotation.RequestParam;\nimport java.util.ArrayList;\nimport java.util.List;",
      );
    const found = records(source);
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.sink).toMatchObject({
      kind: "java-process-shell-command",
      symbol: "java.lang.ProcessBuilder;method=start;argument=3",
    });
    expect(found[0]?.frameworkModel.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "java-caller-command-list-binding",
          symbol: "ProcessBuilder(List) shared command list",
        }),
        expect.objectContaining({
          kind: "java-command-list-mutation",
          symbol: "caller-owned command list",
        }),
      ]),
    );
  });

  test("preserves caller-owned list identity through command(List)", () => {
    const source =
      spring(`        java.util.ArrayList<String> command = new java.util.ArrayList<>(java.util.List.of("printf", "%s", "fixed"));
        ProcessBuilder builder = new ProcessBuilder();
        builder.command(command);
        command.set(0, "sh");
        command.set(1, "-c");
        command.set(2, target);
        builder.start();`);
    const found = records(source);
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "java-caller-command-list-binding",
          symbol: "ProcessBuilder.command(List) shared command list",
        }),
        expect.objectContaining({ kind: "java-process-command-replacement" }),
      ]),
    );
  });

  test("models resizable, fixed-size, and unmodifiable list capabilities", () => {
    const imported = (body: string): string =>
      spring(body).replace(
        "import org.springframework.web.bind.annotation.RequestParam;",
        "import org.springframework.web.bind.annotation.RequestParam;\nimport java.util.ArrayList;\nimport java.util.Arrays;\nimport java.util.List;",
      );
    expect(
      records(
        imported(`        List<String> command = Arrays.asList("printf", "%s", target);
        ProcessBuilder builder = new ProcessBuilder(command);
        command.set(0, "sh");
        command.set(1, "-c");
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        imported(`        List<String> command = Arrays.asList("sh", "-c", target);
        ProcessBuilder builder = new ProcessBuilder(command);
        command.add("fixed");
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        imported(`        List<String> command = List.of("sh", "-c", target);
        ProcessBuilder builder = new ProcessBuilder(command);
        command.set(0, "printf");
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        imported(`        List<String> command = new ArrayList<>(List.of("sh", "-c", target));
        ProcessBuilder builder = new ProcessBuilder(command);
        command.set(0, "printf");
        command.set(1, "%s");
        builder.start();`),
      ),
    ).toEqual([]);
  });

  test("models exact bulk additions without flattening collection identity", () => {
    const imported = (body: string): string =>
      spring(body).replace(
        "import org.springframework.web.bind.annotation.RequestParam;",
        "import org.springframework.web.bind.annotation.RequestParam;\nimport java.util.ArrayList;\nimport java.util.Arrays;\nimport java.util.List;",
      );
    expect(
      records(
        imported(`        List<String> command = new ArrayList<>();
        ProcessBuilder builder = new ProcessBuilder(command);
        command.addAll(List.of("sh", "-c", target));
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        imported(`        List<String> suffix = List.of("-c", target);
        List<String> command = new ArrayList<>(List.of("sh"));
        ProcessBuilder builder = new ProcessBuilder(command);
        command.addAll(1, suffix);
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        imported(`        List<String> command = Arrays.asList("sh", "-c", target);
        ProcessBuilder builder = new ProcessBuilder(command);
        command.addAll(List.of("fixed"));
        builder.start();`),
      ),
    ).toEqual([]);
  });

  test("models exact Collections.addAll mutations and exception boundaries", () => {
    const imported = (body: string): string =>
      spring(body).replace(
        "import org.springframework.web.bind.annotation.RequestParam;",
        "import org.springframework.web.bind.annotation.RequestParam;\nimport java.util.ArrayList;\nimport java.util.Arrays;\nimport java.util.Collections;\nimport java.util.List;",
      );
    expect(
      records(
        imported(`        List<String> command = new ArrayList<>();
        ProcessBuilder builder = new ProcessBuilder(command);
        Collections.addAll(command, "sh", "-c", target);
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        spring(`        java.util.List<String> command = new java.util.ArrayList<>();
        ProcessBuilder builder = new ProcessBuilder(command);
        java.util.Collections.addAll(command, "printf", "%s", target);
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder();
        java.util.Collections.addAll(builder.command(), "sh", "-c", target);
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        imported(`        List<String> command = Arrays.asList("sh", "-c", target);
        ProcessBuilder builder = new ProcessBuilder(command);
        Collections.addAll(command, "fixed");
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        imported(`        List<String> command = List.of("sh", "-c", target);
        ProcessBuilder builder = new ProcessBuilder(command);
        Collections.addAll(command);
        builder.start();`),
      ),
    ).toHaveLength(1);

    const lookalike =
      imported(`        List<String> command = new ArrayList<>();
        ProcessBuilder builder = new ProcessBuilder(command);
        Collections.addAll(command, "sh", "-c", target);
        builder.start();`).replace(
        "import java.util.Collections;",
        "import example.Collections;",
      );
    expect(records(lookalike)).toEqual([]);
  });

  test("preserves exact LinkedList construction, copies, and ownership", () => {
    const imported = (body: string): string =>
      spring(body).replace(
        "import org.springframework.web.bind.annotation.RequestParam;",
        "import org.springframework.web.bind.annotation.RequestParam;\nimport java.util.LinkedList;\nimport java.util.List;",
      );
    expect(
      records(
        imported(`        List<String> command = new LinkedList<>(List.of("printf", "%s", "fixed"));
        ProcessBuilder builder = new ProcessBuilder(command);
        command.clear();
        command.add("sh");
        command.add("-c");
        command.add(target);
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        spring(`        java.util.List<String> original = java.util.List.of("sh", "-c", target);
        java.util.LinkedList<String> command = new java.util.LinkedList<>(original);
        ProcessBuilder builder = new ProcessBuilder(command);
        command.set(0, "printf");
        command.set(1, "%s");
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        imported(`        List<String> command = new LinkedList<>(8);
        ProcessBuilder builder = new ProcessBuilder(command);
        command.add("sh");
        command.add("-c");
        command.add(target);
        builder.start();`),
      ),
    ).toEqual([]);

    const lookalike =
      imported(`        List<String> command = new LinkedList<>();
        ProcessBuilder builder = new ProcessBuilder(command);
        command.add("sh");
        command.add("-c");
        command.add(target);
        builder.start();`).replace(
        "import java.util.LinkedList;",
        "import example.LinkedList;",
      );
    expect(records(lookalike)).toEqual([]);
  });

  test("models sequenced-list mutations for mutable list implementations", () => {
    expect(
      records(
        spring(`        java.util.List<String> command = new java.util.ArrayList<>(java.util.List.of("-c", target));
        ProcessBuilder builder = new ProcessBuilder(command);
        command.addFirst("sh");
        command.getFirst();
        command.getLast();
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        spring(`        java.util.LinkedList<String> command = new java.util.LinkedList<>();
        ProcessBuilder builder = new ProcessBuilder(command);
        command.addLast("sh");
        command.addLast("-c");
        command.addLast(target);
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        spring(`        java.util.LinkedList<String> command = new java.util.LinkedList<>(java.util.List.of("printf", "sh", "-c", target));
        ProcessBuilder builder = new ProcessBuilder(command);
        command.removeFirst();
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        spring(`        java.util.LinkedList<String> command = new java.util.LinkedList<>(java.util.List.of("sh", "-c", target));
        ProcessBuilder builder = new ProcessBuilder(command);
        command.removeLast();
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(`        java.util.List<String> command = new java.util.LinkedList<>(java.util.List.of("-c", target));
        ProcessBuilder builder = new ProcessBuilder(command);
        command.push("sh");
        builder.start();`),
      ),
    ).toEqual([]);
  });

  test("models empty capacity lists and copied command vectors", () => {
    const source =
      spring(`        java.util.ArrayList<String> command = new java.util.ArrayList<>(8);
        command.add("sh");
        command.add("-c");
        command.add(target);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.start();`);
    expect(records(source)).toHaveLength(1);

    const copied =
      spring(`        java.util.List<String> original = java.util.List.of("printf", "%s", "fixed");
        java.util.ArrayList<String> command = new java.util.ArrayList<>(original);
        ProcessBuilder builder = new ProcessBuilder(command);
        command.set(0, "sh");
        command.set(1, "-c");
        command.set(2, target);
        builder.start();`);
    expect(records(copied)).toHaveLength(1);

    const detachedEvidence =
      spring(`        java.util.List<String> original = java.util.List.of("sh", "-c", target);
        java.util.ArrayList<String> copy = new java.util.ArrayList<>(original);
        copy.set(0, "printf");
        copy.set(1, "%s");
        new ProcessBuilder(original).start();`);
    const originalRisk = records(detachedEvidence);
    expect(originalRisk).toHaveLength(1);
    expect(
      originalRisk[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).not.toContain("java-command-list-mutation");
  });

  test("detaches a caller list when command state is replaced", () => {
    const source =
      spring(`        java.util.ArrayList<String> command = new java.util.ArrayList<>(java.util.List.of("printf", "%s", "fixed"));
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.command("printf", "%s", target);
        command.set(0, "sh");
        command.set(1, "-c");
        command.set(2, target);
        builder.start();`);
    expect(records(source)).toEqual([]);
  });

  test("tracks direct command getter mutation and shared builder aliases", () => {
    const direct = records(
      spring(`        ProcessBuilder builder = new ProcessBuilder("printf", "%s", target);
        builder.command().set(0, "sh");
        builder.command().set(1, "-c");
        builder.start();`),
    );
    expect(direct).toHaveLength(1);
    expect(
      direct[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("java-command-list-mutation");

    const builderAlias = records(
      spring(`        ProcessBuilder builder = new ProcessBuilder("printf", "%s", "fixed");
        ProcessBuilder alias = builder;
        alias.command("sh", "-c", target);
        builder.start();`),
    );
    expect(builderAlias).toHaveLength(1);
    expect(
      builderAlias[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("java-process-command-replacement");
  });

  test("models list insertion, removal, repair, and detached old views", () => {
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder("sh", target);
        java.util.List<String> command = builder.command();
        command.add(1, "-c");
        builder.start();`),
      ),
    ).toHaveLength(1);
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder("sh", "-c", target);
        java.util.List<String> command = builder.command();
        command.remove(1);
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder("sh", "-c", target);
        java.util.List<String> command = builder.command();
        command.set(0, "printf");
        command.set(1, "%s");
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder("sh", "-c", target);
        java.util.List<String> oldCommand = builder.command();
        builder.command("printf", "%s", target);
        oldCommand.set(0, "sh");
        builder.start();`),
      ),
    ).toEqual([]);
  });

  test("fails closed on impossible or unresolved live-list mutation", () => {
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder("sh", "-c", target);
        java.util.List<String> command = builder.command();
        command.set(99, "fixed");
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder("sh", "-c", target);
        java.util.List<String> command = builder.command();
        command.replaceAll(String::trim);
        builder.start();`),
      ),
    ).toEqual([]);
    expect(
      records(
        spring(`        ProcessBuilder builder = new ProcessBuilder("sh", "-c", target);
        java.util.List<String> command = builder.command();
        command.size();
        builder.start();`),
      ),
    ).toHaveLength(1);
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
    expect(prompt).toContain("ProcessBuilder(List)");
    expect(prompt).toContain(
      "Arrays.asList permits set but rejects size changes",
    );
    expect(prompt).toContain("List.of rejects every mutation");
    expect(prompt).toContain("ArrayList and LinkedList are resizable");
    expect(prompt).toContain("Collections.addAll calls add");
    expect(prompt).toContain("addFirst/addLast/removeFirst/removeLast");
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

  test("requires live-list mutation evidence when the host row records it", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "spring-java-live-command-list-injection",
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-spring-java-live-quality-"),
    );
    try {
      const finding = {
        findingId: "occ_spring_java_live_command",
        taxonomy: { cwe: ["CWE-78", "CWE-88"] },
        locations: [
          { path: handlerPath, startLine: 12, role: "source" },
          { path: handlerPath, startLine: 21, role: "sink" },
        ],
        codeEvidence: [
          {
            id: "java-live-source",
            path: handlerPath,
            startLine: 12,
            endLine: 12,
            role: "source",
            code: '@RequestParam("target") String target',
            explanation: "The handler binds target from the HTTP request.",
          },
          {
            id: "java-live-sink",
            path: handlerPath,
            startLine: 15,
            endLine: 21,
            role: "sink",
            code: "List<String> command = builder.command(); ... builder.start();",
            explanation: "The configured process is started.",
          },
        ],
        validation: {
          method: "static_source_trace",
          summary:
            "Spring RequestParam target reaches java.lang.ProcessBuilder as a command string in sh -c shell grammar before start.",
          exploitWitness: "A bounded fixed string checks the process boundary.",
          negativeControl: "Fixed printf receives one ordinary argument.",
          evidence: ["java-live-source", "java-live-sink"],
          counterEvidence: "No dominating exact repair is present.",
          remainingUncertainty: "Deployment remains unknown.",
        },
        attackPath: {
          summary:
            "The Spring request parameter target enters a shell command string for sh -c and ProcessBuilder start performs process execution.",
          dataflow: {
            source: "The Spring request parameter target.",
            sink: "A sh -c command string executed by ProcessBuilder start.",
            outcome: "Process integrity may be affected.",
          },
          reachability: {
            attacker: "A remote caller.",
            entrypoint: "The diagnostics handler.",
            outcome: "A child process may run.",
          },
          brokenControls: ["No exact command/data boundary"],
          evidenceRefs: ["java-live-source", "java-live-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );
      const inventory = await buildResidualRiskInventory(repository);
      const gap = (
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        )
      )
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))[1];
      expect(gap).toMatchObject({
        findingId: "occ_spring_java_live_command",
        frameworkModelId: "spring-java-command-injection",
        reasons: [
          "missing_model_specific_validation_evidence",
          "missing_model_specific_attack_path_evidence",
        ],
        missingValidationTextAnyOf: [
          [
            "ProcessBuilder.command()",
            "live command list",
            "command list mutation",
            "List.set",
            "List.add",
            "List.addAll",
            "Collections.addAll",
            "LinkedList",
            "addFirst",
          ],
        ],
        missingAttackPathTextAnyOf: [
          [
            "ProcessBuilder.command()",
            "live command list",
            "command list mutation",
            "List.set",
            "List.add",
            "List.addAll",
            "Collections.addAll",
            "LinkedList",
            "addFirst",
          ],
        ],
      });

      finding.validation.summary +=
        " ProcessBuilder.command() returns the live command list, and List.add mutations install the tainted shell operand.";
      finding.attackPath.summary +=
        " The aliased live command list from ProcessBuilder.command() is rebuilt by List.add before dispatch.";
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

  test("requires caller-list binding evidence when the host row records it", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "spring-java-caller-command-list-injection",
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-spring-java-caller-quality-"),
    );
    try {
      const finding = {
        findingId: "occ_spring_java_caller_command",
        taxonomy: { cwe: ["CWE-78", "CWE-88"] },
        locations: [
          { path: handlerPath, startLine: 13, role: "source" },
          { path: handlerPath, startLine: 22, role: "sink" },
        ],
        codeEvidence: [
          {
            id: "java-caller-source",
            path: handlerPath,
            startLine: 13,
            endLine: 13,
            role: "source",
            code: '@RequestParam("target") String target',
            explanation: "The handler binds target from the HTTP request.",
          },
          {
            id: "java-caller-sink",
            path: handlerPath,
            startLine: 15,
            endLine: 22,
            role: "sink",
            code: "List<String> command = new ArrayList<>(...); ... builder.start();",
            explanation: "The configured process is started.",
          },
        ],
        validation: {
          method: "static_source_trace",
          summary:
            "Spring RequestParam target reaches sh -c shell grammar after an ArrayList command list mutation, before ProcessBuilder.start.",
          exploitWitness: "A bounded fixed string checks the process boundary.",
          negativeControl: "Fixed printf receives one ordinary argument.",
          evidence: ["java-caller-source", "java-caller-sink"],
          counterEvidence: "No dominating exact repair is present.",
          remainingUncertainty: "Deployment remains unknown.",
        },
        attackPath: {
          summary:
            "The request parameter enters sh -c through an ArrayList command list mutation and ProcessBuilder start executes the child process.",
          dataflow: {
            source: "The Spring request parameter target.",
            sink: "A sh -c command string executed by ProcessBuilder start.",
            outcome: "Process integrity may be affected.",
          },
          reachability: {
            attacker: "A remote caller.",
            entrypoint: "The diagnostics handler.",
            outcome: "A child process may run.",
          },
          brokenControls: ["No exact command/data boundary"],
          evidenceRefs: ["java-caller-source", "java-caller-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );
      const inventory = await buildResidualRiskInventory(repository);
      const gap = (
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        )
      )
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))[1];
      expect(gap).toMatchObject({
        findingId: "occ_spring_java_caller_command",
        frameworkModelId: "spring-java-command-injection",
        reasons: [
          "missing_model_specific_validation_evidence",
          "missing_model_specific_attack_path_evidence",
        ],
        missingValidationTextAnyOf: [
          [
            "caller-owned command list",
            "ProcessBuilder(List)",
            "ProcessBuilder.command(List)",
            "shared command list",
            "no-copy command list",
          ],
        ],
        missingAttackPathTextAnyOf: [
          [
            "caller-owned command list",
            "ProcessBuilder(List)",
            "ProcessBuilder.command(List)",
            "shared command list",
            "no-copy command list",
          ],
        ],
      });

      finding.validation.summary +=
        " ProcessBuilder(List) retains the caller-owned command list without a copy.";
      finding.attackPath.summary +=
        " The shared command list remains effective through ProcessBuilder(List).";
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
