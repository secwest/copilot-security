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
  "aspnet-cross-file-template-injection",
  "aspnet-cross-file-safe-template",
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

function templateModels(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "aspnet-http-template-injection",
  );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-aspnet-template-"),
  );
  temporaryPaths.push(repository);
  return repository;
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

describe("ASP.NET template framework-model effectiveness benchmark", () => {
  test("keeps the Scriban exploit and fixed-template control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "aspnet-template-framework-manifest.json"),
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
          caseIds[0],
          "Services",
          "TemplateRenderer.cs",
        ),
        "utf8",
      ),
    ).toContain("Template.Parse(templateSource)");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[1],
          "Services",
          "TemplateRenderer.cs",
        ),
        "utf8",
      ),
    ).toContain("Template.Parse(PreviewTemplate)");
  });

  test("preserves the exact typed controller-to-Scriban template-source path", async () => {
    const vulnerable = templateModels(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = templateModels(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "aspnet-http-template-injection",
      language: "dotnet",
      scope: "cross-file-wrapper",
      source: {
        kind: "aspnet-bound-parameter",
        path: "Controllers/PreviewController.cs",
        line: 18,
      },
      sink: {
        kind: "dynamic-template-source",
        path: "Services/TemplateRenderer.cs",
        line: 11,
        cweIds: ["CWE-1336"],
      },
      propagators: [
        {
          kind: "dotnet-type-binding",
          path: "Controllers/PreviewController.cs",
          line: 10,
          symbol: "_renderer:TemplateRenderer",
        },
        {
          kind: "wrapper-call-argument",
          path: "Controllers/PreviewController.cs",
          line: 20,
          symbol: "_renderer.Render[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "Services/TemplateRenderer.cs",
          line: 9,
          symbol: "templateSource",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toEqual([]);

    const prompt = scanQualityGatePrompt(JSON.stringify(vulnerable));
    expect(prompt).toContain("aspnet-http-template-injection");
    expect(prompt).toContain("Scriban Template.Parse");
    expect(prompt).toContain("first template-source argument");
    expect(prompt).toContain("fixed server-owned template");
    expect(prompt).toContain("CWE-1336");
  });

  test("accepts imported and fully qualified template parsing plus one bounded alias", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Imported.cs",
      `
using Scriban;
public sealed class ImportedController : ControllerBase
{
    public object Render([FromBody] string source)
    {
        var templateSource = source;
        return Template.Parse(templateSource).Render();
    }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "Qualified.cs",
      `
public sealed class QualifiedController : ControllerBase
{
    public object Render([FromQuery] string source)
    {
        return global::Scriban.Template.Parse(source).Render();
    }
}
`,
    );

    const models = templateModels(
      await buildResidualRiskInventory(repository),
    ).filter((record) => record.frameworkModel?.scope === "same-file");
    expect(models).toHaveLength(2);
    expect(models.map(({ path }) => path).sort()).toEqual([
      "Imported.cs",
      "Qualified.cs",
    ]);
    expect(
      models.every(
        (record) => record.frameworkModel?.sink.cweIds[0] === "CWE-1336",
      ),
    ).toBeTrue();
  });

  test("rejects render data, non-source arguments, reassignment, shadows, and text-only lookalikes", async () => {
    const cases = new Map<string, string>([
      [
        "render-data.cs",
        `
using Scriban;
public sealed class PreviewController : ControllerBase
{
    public object Render([FromBody] string name)
    {
        var template = Template.Parse("Hello {{ name }}");
        return template.Render(new { Name = name });
    }
}
`,
      ],
      [
        "source-name.cs",
        `
using Scriban;
public sealed class PreviewController : ControllerBase
{
    public object Render([FromQuery] string sourceFileName)
    {
        return Template.Parse("Hello", sourceFileName).Render();
    }
}
`,
      ],
      [
        "reassigned.cs",
        `
using Scriban;
public sealed class PreviewController : ControllerBase
{
    public object Render([FromBody] string source)
    {
        source = "Hello";
        return Template.Parse(source).Render();
    }
}
`,
      ],
      [
        "shadow.cs",
        `
using Scriban;
public sealed class PreviewController : ControllerBase
{
    public object Render([FromBody] string source)
    {
        return Template.Parse(source);
    }
}
public static class Template
{
    public static object Parse(string value) => value;
}
`,
      ],
      [
        "text-only.cs",
        `
using Scriban;
public sealed class PreviewController : ControllerBase
{
    public object Render([FromBody] string source)
    {
        // Template.Parse(source);
        var example = "Template.Parse(source)";
        return example;
    }
}
`,
      ],
      [
        "untyped.cs",
        `
public sealed class PreviewController : ControllerBase
{
    public object Render([FromBody] string source)
    {
        return Template.Parse(source);
    }
}
`,
      ],
      [
        "inert-parse.cs",
        `
using Scriban;
public sealed class PreviewController : ControllerBase
{
    public object Validate([FromBody] string source)
    {
        var parsed = Template.Parse(source);
        return parsed.HasErrors;
    }
}
`,
      ],
      [
        "reassigned-template.cs",
        `
using Scriban;
public sealed class PreviewController : ControllerBase
{
    public object Render([FromBody] string source)
    {
        var parsed = Template.Parse(source);
        parsed = Template.Parse("fixed");
        return parsed.Render();
    }
}
`,
      ],
    ]);

    const repository = await temporaryRepository();
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }
    expect(
      templateModels(await buildResidualRiskInventory(repository)),
    ).toEqual([]);

    const crossFileInert = await temporaryRepository();
    await writeRepositoryFile(
      crossFileInert,
      "Controllers/PreviewController.cs",
      `
public sealed class PreviewController : ControllerBase
{
    private readonly TemplateValidator _validator;
    public object Validate([FromBody] string source)
    {
        return _validator.Validate(source);
    }
}
`,
    );
    await writeRepositoryFile(
      crossFileInert,
      "Services/TemplateValidator.cs",
      `
using Scriban;
public sealed class TemplateValidator
{
    public bool Validate(string source)
    {
        return Template.Parse(source).HasErrors;
    }
}
`,
    );
    expect(
      templateModels(await buildResidualRiskInventory(crossFileInert)),
    ).toEqual([]);
  });
});
