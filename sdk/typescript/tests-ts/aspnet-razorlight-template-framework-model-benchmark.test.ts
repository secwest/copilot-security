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
  "aspnet-cross-file-razorlight-template-injection",
  "aspnet-cross-file-safe-razorlight-template",
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
    join(tmpdir(), "copilot-security-aspnet-razorlight-"),
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

describe("ASP.NET RazorLight template framework-model effectiveness benchmark", () => {
  test("keeps the RazorLight exploit and fixed-template control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "aspnet-razorlight-template-framework-manifest.json",
        ),
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
          "RazorTemplateRenderer.cs",
        ),
        "utf8",
      ),
    ).toContain("templateSource,");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[1],
          "Services",
          "RazorTemplateRenderer.cs",
        ),
        "utf8",
      ),
    ).toContain("PreviewTemplate,");

    for (const [caseId, projectName] of [
      [caseIds[0], "AspnetCrossFileRazorLightTemplateInjection.csproj"],
      [caseIds[1], "AspnetCrossFileSafeRazorLightTemplate.csproj"],
    ] as const) {
      const project = await readFile(
        join(benchmarkRoot, "fixtures", caseId, projectName),
        "utf8",
      );
      expect(project).toContain(
        '<PackageReference Include="RazorLight" Version="2.3.1" />',
      );
      expect(project).toContain(
        '<PackageReference Include="Microsoft.Extensions.Caching.Memory" Version="8.0.1" />',
      );
      expect(project).toContain(
        '<PackageReference Include="System.Text.Json" Version="8.0.5" />',
      );
    }

    const workflow = await readFile(
      resolve(
        benchmarkRoot,
        "..",
        ".github",
        "workflows",
        "dotnet-fixture-ci.yml",
      ),
      "utf8",
    );
    expect(workflow).toContain("Audit RazorLight fixture dependencies");
    expect(workflow).toContain(
      "--vulnerable --include-transitive --format json",
    );
    expect(workflow).toContain(".vulnerabilities // []");
  });

  test("preserves the exact typed controller-to-RazorLight content path", async () => {
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
        kind: "dynamic-razor-template-source",
        path: "Services/RazorTemplateRenderer.cs",
        line: 17,
        cweIds: ["CWE-1336"],
      },
      propagators: [
        {
          kind: "dotnet-type-binding",
          path: "Controllers/PreviewController.cs",
          line: 10,
          symbol: "_renderer:RazorTemplateRenderer",
        },
        {
          kind: "wrapper-call-argument",
          path: "Controllers/PreviewController.cs",
          line: 20,
          symbol: "_renderer.RenderAsync[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "Services/RazorTemplateRenderer.cs",
          line: 15,
          symbol: "templateSource",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toEqual([]);

    const prompt = scanQualityGatePrompt(JSON.stringify(vulnerable));
    expect(prompt).toContain("RazorLight CompileRenderStringAsync");
    expect(prompt).toContain("template content is the second argument");
    expect(prompt).toContain("CompileRenderAsync");
    expect(prompt).toContain("fixed server-owned template");
    expect(prompt).toContain("CWE-1336");
  });

  test("accepts typed imported, fully qualified, builder, generic, and named-content calls", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Imported.cs",
      `
using RazorLight;
public sealed class ImportedController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public ImportedController(IRazorLightEngine engine) => _engine = engine;
    public Task<string> Render([FromBody] string source)
    {
        var templateSource = source;
        return _engine.CompileRenderStringAsync("key", templateSource, new { });
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
    private readonly global::RazorLight.IRazorLightEngine _engine;
    public QualifiedController(global::RazorLight.IRazorLightEngine engine) => _engine = engine;
    public Task<string> Render([FromQuery] string source)
    {
        return _engine.CompileRenderStringAsync<object>("key", source, new { });
    }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "Named.cs",
      `
using RazorLight;
public sealed class NamedController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public NamedController(IRazorLightEngine engine) => _engine = engine;
    public Task<string> Render([FromForm] string source)
    {
        return _engine.CompileRenderStringAsync(
            model: new { },
            content: source,
            key: "key");
    }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "Builder.cs",
      `
using RazorLight;
public sealed class BuilderController : ControllerBase
{
    public Task<string> Render([FromHeader] string source)
    {
        var engine = new RazorLightEngineBuilder()
            .UseEmbeddedResourcesProject(typeof(BuilderController))
            .UseMemoryCachingProvider()
            .Build();
        return engine.CompileRenderStringAsync("key", source, new { });
    }
}
`,
    );

    const models = templateModels(
      await buildResidualRiskInventory(repository),
    ).filter((record) => record.frameworkModel?.scope === "same-file");
    expect(models).toHaveLength(4);
    expect(models.map(({ path }) => path).sort()).toEqual([
      "Builder.cs",
      "Imported.cs",
      "Named.cs",
      "Qualified.cs",
    ]);
    expect(
      models.every(
        (record) =>
          record.frameworkModel?.sink.kind ===
            "dynamic-razor-template-source" &&
          record.frameworkModel.sink.cweIds[0] === "CWE-1336",
      ),
    ).toBeTrue();
  });

  test("rejects keys, models, fixed content, reassignment, untyped receivers, shadows, incomplete builders, and text lookalikes", async () => {
    const cases = new Map<string, string>([
      [
        "model-data.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public Task<string> Render([FromBody] string name)
    {
        return _engine.CompileRenderStringAsync("key", "Hello @Model.Name", new { Name = name });
    }
}
`,
      ],
      [
        "key-only.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public Task<string> Render([FromQuery] string key)
    {
        return _engine.CompileRenderStringAsync(key, "fixed", new { });
    }
}
`,
      ],
      [
        "resolved-template.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public Task<string> Render([FromRoute] string key)
    {
        return _engine.CompileRenderAsync(key, new { });
    }
}
`,
      ],
      [
        "named-model.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public Task<string> Render([FromBody] string source)
    {
        return _engine.CompileRenderStringAsync(key: "key", model: source, content: "fixed");
    }
}
`,
      ],
      [
        "reassigned.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public Task<string> Render([FromBody] string source)
    {
        source = "fixed";
        return _engine.CompileRenderStringAsync("key", source, new { });
    }
}
`,
      ],
      [
        "untyped.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    private readonly object _engine;
    public object Render([FromBody] string source)
    {
        return _engine.CompileRenderStringAsync("key", source, new { });
    }
}
`,
      ],
      [
        "shadow.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public object Render([FromBody] string source)
    {
        return _engine.CompileRenderStringAsync("key", source, new { });
    }
}
public interface IRazorLightEngine { }
`,
      ],
      [
        "qualified-shadow.cs",
        `
public sealed class PreviewController : ControllerBase
{
    private readonly global::RazorLight.IRazorLightEngine _engine;
    public object Render([FromBody] string source)
    {
        return _engine.CompileRenderStringAsync("key", source, new { });
    }
}
namespace RazorLight { public interface IRazorLightEngine { } }
`,
      ],
      [
        "incomplete-builder.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    public object Render([FromBody] string source)
    {
        var engine = new RazorLightEngineBuilder();
        return engine.CompileRenderStringAsync("key", source, new { });
    }
}
`,
      ],
      [
        "text-only.cs",
        `
using RazorLight;
public sealed class PreviewController : ControllerBase
{
    private readonly IRazorLightEngine _engine;
    public string Render([FromBody] string source)
    {
        // _engine.CompileRenderStringAsync("key", source, new { });
        return "_engine.CompileRenderStringAsync(key, source, model)";
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
  });
});
