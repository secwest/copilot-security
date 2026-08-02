import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  frameworkModel?: {
    schemaVersion: string;
    id: string;
    language: string;
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
    findingsPaths: string[];
    expected: Array<{
      cwe?: string[];
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "java-cross-file-template-injection",
  "java-cross-file-safe-template",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function parseRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function crossFileModels(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.scope === "cross-file-wrapper",
  );
}

async function writeRepositoryFile(
  repository: string,
  relativePath: string,
  contents: string,
): Promise<void> {
  const path = join(repository, relativePath);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, contents);
}

describe("Java cross-file framework-model effectiveness benchmark", () => {
  test("keeps the Velocity positive and encoded fixed-template control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "java-cross-file-template-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-1336"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[1],
          "src",
          "main",
          "java",
          "example",
          "TemplateRenderer.java",
        ),
        "utf8",
      ),
    ).toContain('context.put("name", HtmlUtils.htmlEscape(name));');
  });

  test("preserves the exact constructor-injected Spring-to-Velocity path", async () => {
    const vulnerable = crossFileModels(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = crossFileModels(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toEqual({
      id: "spring-http-template-injection",
      language: "java-kotlin",
      schemaVersion: "1.2",
      scope: "cross-file-wrapper",
      source: {
        kind: "spring-bound-parameter",
        path: "src/main/java/example/PreviewController.java",
        line: 16,
      },
      sink: {
        kind: "dynamic-template-source",
        path: "src/main/java/example/TemplateRenderer.java",
        line: 12,
        cweIds: ["CWE-1336"],
      },
      propagators: [
        {
          kind: "java-type-binding",
          path: "src/main/java/example/PreviewController.java",
          line: 9,
          symbol: "renderer:TemplateRenderer",
        },
        {
          kind: "wrapper-call-argument",
          path: "src/main/java/example/PreviewController.java",
          line: 17,
          symbol: "renderer.render[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "src/main/java/example/TemplateRenderer.java",
          line: 10,
          symbol: "template",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toEqual([]);

    const prompt = scanQualityGatePrompt(JSON.stringify(vulnerable[0]));
    expect(prompt).toContain(
      "Apache Velocity.evaluate receives template source in its fourth argument",
    );
    expect(prompt).toContain(
      "request data used only as a VelocityContext value is strong SSTI counterevidence",
    );
    expect(prompt).toContain(
      "It is not XSS counterevidence unless the rendered output context has proven encoding",
    );
    expect(prompt).toContain(
      "The same high-severity baseline applies to a directly reachable Spring or servlet source",
    );
  });

  test("reuses the Java method-flow layer for command and raw-SQL models", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-java-framework-families-"),
    );
    temporaryPaths.push(repository);
    await writeRepositoryFile(
      repository,
      "src/ReportController.java",
      `
import org.springframework.web.bind.annotation.RequestParam;
public final class ReportController {
  private final CommandRunner runner;
  private final UserQueries queries;
  public String run(@RequestParam String command, @RequestParam String sql) {
    runner.execute(command);
    return queries.lookup(sql);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/CommandRunner.java",
      `
public final class CommandRunner {
  public void execute(String command) throws Exception {
    new ProcessBuilder("sh", "-c", command).start();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/UserQueries.java",
      `
import org.springframework.jdbc.core.JdbcTemplate;
public final class UserQueries {
  private final JdbcTemplate jdbcTemplate = null;
  public String lookup(String sql) {
    return jdbcTemplate.queryForObject(sql, String.class);
  }
}
`,
    );

    const models = crossFileModels(
      await buildResidualRiskInventory(repository),
    );
    expect(models.map((record) => record.frameworkModel?.id).sort()).toEqual([
      "spring-http-command",
      "spring-http-sql",
    ]);
    expect(
      models.every(
        (record) =>
          record.frameworkModel?.source.kind === "spring-bound-parameter",
      ),
    ).toBeTrue();
  });

  test("supports servlet assignments and multiline Velocity calls", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-java-servlet-flow-"),
    );
    temporaryPaths.push(repository);
    await writeRepositoryFile(
      repository,
      "src/PreviewController.java",
      `
import jakarta.servlet.http.HttpServletRequest;
public final class PreviewController {
  private final TemplateRenderer renderer;
  public String preview(HttpServletRequest request) {
    String source = request.getParameter("template");
    return this.renderer.render(source);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/TemplateRenderer.java",
      `
import org.apache.velocity.app.Velocity;
public final class TemplateRenderer {
  public String render(
    String source
  ) {
    Velocity.evaluate(
      context,
      output,
      "preview",
      source
    );
    return output.toString();
  }
}
`,
    );

    const models = crossFileModels(
      await buildResidualRiskInventory(repository),
    );
    expect(models).toHaveLength(1);
    expect(models[0]?.frameworkModel).toMatchObject({
      id: "spring-http-template-injection",
      source: { kind: "servlet-request-parameter", line: 6 },
      sink: { kind: "dynamic-template-source", line: 7 },
    });
  });

  test("supports same-line Spring annotations and static service methods", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-java-static-flow-"),
    );
    temporaryPaths.push(repository);
    await writeRepositoryFile(
      repository,
      "src/PreviewController.java",
      `
public final class PreviewController {
  @PostMapping("/preview") public String preview(@RequestParam(name = "template", required = true) String source) {
    return TemplateRenderer.render(source);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/TemplateRenderer.java",
      `
import org.apache.velocity.app.Velocity;
public final class TemplateRenderer {
  public static String render(String source) {
    Velocity.evaluate(context, output, "preview", source);
    return output.toString();
  }
}
`,
    );

    const models = crossFileModels(
      await buildResidualRiskInventory(repository),
    );
    expect(models).toHaveLength(1);
    expect(models[0]?.frameworkModel).toMatchObject({
      source: { kind: "spring-bound-parameter", line: 3 },
      propagators: [
        {
          kind: "java-type-binding",
          line: 4,
          symbol: "TemplateRenderer:TemplateRenderer",
        },
        {
          kind: "wrapper-call-argument",
          line: 4,
          symbol: "TemplateRenderer.render[0]",
        },
        { kind: "wrapper-parameter", line: 4, symbol: "source" },
      ],
    });
  });

  test("rejects fixed, reassigned, text-only, and ambiguous Java pseudo-flows", async () => {
    const callers = [
      `return renderer.render("fixed template");`,
      `source = "fixed template"; return renderer.render(source);`,
      `String example = "renderer.render(source)"; return example;`,
    ];
    for (const body of callers) {
      const repository = await mkdtemp(
        join(tmpdir(), "copilot-security-java-negative-flow-"),
      );
      temporaryPaths.push(repository);
      await writeRepositoryFile(
        repository,
        "src/PreviewController.java",
        `
import org.springframework.web.bind.annotation.RequestParam;
public final class PreviewController {
  private final TemplateRenderer renderer;
  public String preview(@RequestParam String source) {
    ${body}
  }
}
`,
      );
      await writeRepositoryFile(
        repository,
        "src/TemplateRenderer.java",
        `
import org.apache.velocity.app.Velocity;
public final class TemplateRenderer {
  public String render(String source) {
    // Velocity.evaluate(context, output, "preview", source);
    /* Velocity.evaluate(context, output, "preview", source); */
    String inert = "Velocity.evaluate(" + source;
    return inert;
  }
}
`,
      );
      expect(
        crossFileModels(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    }

    const ambiguous = await mkdtemp(
      join(tmpdir(), "copilot-security-java-ambiguous-type-"),
    );
    temporaryPaths.push(ambiguous);
    await writeRepositoryFile(
      ambiguous,
      "src/PreviewController.java",
      `
public final class PreviewController {
  private final TemplateRenderer renderer;
  public String preview(@RequestParam String source) {
    return renderer.render(source);
  }
}
`,
    );
    for (const directory of ["one", "two"]) {
      await writeRepositoryFile(
        ambiguous,
        `src/${directory}/TemplateRenderer.java`,
        `
import org.apache.velocity.app.Velocity;
public final class TemplateRenderer {
  public String render(String source) {
    return Velocity.evaluate(context, output, "preview", source);
  }
}
`,
      );
    }
    expect(
      crossFileModels(await buildResidualRiskInventory(ambiguous)),
    ).toEqual([]);
  });
});
