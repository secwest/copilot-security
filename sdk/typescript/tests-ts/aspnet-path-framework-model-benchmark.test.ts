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
  "aspnet-multi-hop-path-traversal",
  "aspnet-multi-hop-safe-path",
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

function aspnetPathRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "aspnet-http-path",
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

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-aspnet-path-"),
  );
  temporaryPaths.push(repository);
  return repository;
}

describe("ASP.NET path framework-model effectiveness benchmark", () => {
  test("keeps the exploit and canonical-containment control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "aspnet-multi-hop-path-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-22"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(1);
    }

    const vulnerableWitness = await readFile(
      join(benchmarkRoot, "witnesses", caseIds[0], "Program.cs"),
      "utf8",
    );
    expect(vulnerableWitness).toContain(
      'Path.Combine("..", "private", "deployment-secret.txt")',
    );
    expect(vulnerableWitness).toContain('absoluteReset != "deployment-secret"');
    const safeWitness = await readFile(
      join(benchmarkRoot, "witnesses", caseIds[1], "Program.cs"),
      "utf8",
    );
    expect(safeWitness).toContain(
      "await ExpectRejectedAsync(store, secretPath)",
    );
    expect(safeWitness).toContain('Path.Combine("..", "public-backup"');
    expect(safeWitness).toContain('ReadAsync("guide.txt"');
  });

  test("preserves both typed service boundaries into the System.IO sink", async () => {
    const vulnerable = aspnetPathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = aspnetPathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.path).toBe("Services/DocumentStore.cs");
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "aspnet-http-path",
      language: "dotnet",
      scope: "cross-file-multi-hop-wrapper",
      source: {
        kind: "aspnet-bound-parameter",
        path: "Controllers/DocumentController.cs",
        line: 18,
      },
      sink: {
        kind: "filesystem-path",
        path: "Services/DocumentStore.cs",
        line: 16,
        cweIds: ["CWE-22"],
      },
      propagators: [
        {
          kind: "dotnet-type-binding",
          path: "Controllers/DocumentController.cs",
          line: 10,
          symbol: "_documents:DocumentService",
        },
        {
          kind: "wrapper-call-argument",
          path: "Controllers/DocumentController.cs",
          line: 23,
          symbol: "_documents.ReadAsync[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "Services/DocumentService.cs",
          line: 12,
          symbol: "path",
        },
        {
          kind: "dotnet-type-binding",
          path: "Services/DocumentService.cs",
          line: 5,
          symbol: "_store:DocumentStore",
        },
        {
          kind: "wrapper-call-argument",
          path: "Services/DocumentService.cs",
          line: 14,
          symbol: "_store.ReadAsync[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "Services/DocumentStore.cs",
          line: 14,
          symbol: "path",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toEqual([]);
  });

  test("recognizes typed same-file and fully qualified sinks with containment leads", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Controllers/DocumentController.cs",
      [
        "using System.IO;",
        "using Microsoft.AspNetCore.Mvc;",
        "public sealed class DocumentController : ControllerBase {",
        "  public string Get([FromQuery] string path) {",
        "    if (Path.IsPathRooted(path)) throw new Exception();",
        '    var root = Path.GetFullPath("documents");',
        "    var candidate = Path.GetFullPath(Path.Combine(root, path));",
        "    var relative = Path.GetRelativePath(root, candidate);",
        '    if (relative.StartsWith($"..{Path.DirectorySeparatorChar}")) throw new Exception();',
        "    return File.ReadAllText(Path.Combine(root, path));",
        "  }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Controllers/FullyQualifiedController.cs",
      [
        "using Microsoft.AspNetCore.Mvc;",
        "public sealed class FullyQualifiedController : ControllerBase {",
        "  public string Get([FromRoute] string path) {",
        "    return System.IO.File.ReadAllText(path);",
        "  }",
        "}",
        "",
      ].join("\n"),
    );

    const records = aspnetPathRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(2);
    const modeled = records.find(
      (record) => record.path === "Controllers/DocumentController.cs",
    );
    expect(modeled?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "rooted-path-rejection",
          path: "Controllers/DocumentController.cs",
          line: 5,
        },
        {
          kind: "canonical-full-path",
          path: "Controllers/DocumentController.cs",
          line: 6,
        },
        {
          kind: "canonical-relative-containment",
          path: "Controllers/DocumentController.cs",
          line: 8,
        },
        {
          kind: "relative-parent-boundary-rejection",
          path: "Controllers/DocumentController.cs",
          line: 9,
        },
      ]),
    );
    expect(
      records.find(
        (record) => record.path === "Controllers/FullyQualifiedController.cs",
      )?.frameworkModel?.sink,
    ).toMatchObject({ kind: "filesystem-path", cweIds: ["CWE-22"] });
  });

  test("rejects shadow types, comments, strings, fixed values, and reassigned relays", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Services/DocumentStore.cs",
      [
        "using System.IO;",
        "public sealed class DocumentStore {",
        "  public Task<string> ReadAsync(string path, CancellationToken token) {",
        "    return File.ReadAllTextAsync(path, token);",
        "  }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Services/DocumentService.cs",
      [
        "public sealed class DocumentService {",
        "  private readonly DocumentStore _store;",
        "  public DocumentService(DocumentStore store) { _store = store; }",
        "  public Task<string> ReadAsync(string path, CancellationToken token) {",
        '    path = "fixed.txt";',
        "    return _store.ReadAsync(path, token);",
        "  }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Controllers/DocumentController.cs",
      [
        "using Microsoft.AspNetCore.Mvc;",
        "public sealed class DocumentController : ControllerBase {",
        "  private readonly DocumentService _documents;",
        "  public DocumentController(DocumentService documents) { _documents = documents; }",
        "  public Task<string> Get([FromQuery] string path, CancellationToken token) {",
        "    // _documents.ReadAsync(path, token);",
        '    var example = "_documents.ReadAsync(path, token)";',
        "    return _documents.ReadAsync(path, token);",
        "  }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Controllers/ShadowController.cs",
      [
        "using Microsoft.AspNetCore.Mvc;",
        "public sealed class File { public static string ReadAllText(string value) => value; }",
        "public sealed class ShadowController : ControllerBase {",
        "  public string Get([FromQuery] string path) => File.ReadAllText(path);",
        "}",
        "",
      ].join("\n"),
    );

    expect(
      aspnetPathRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("rejects duplicate service types instead of guessing a multi-hop receiver", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Storage/DocumentStore.cs",
      [
        "using System.IO;",
        "public sealed class DocumentStore {",
        "  public string Read(string path) { return File.ReadAllText(path); }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Other/DocumentStore.cs",
      [
        "public sealed class DocumentStore {",
        "  public string Read(string path) { return path; }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Services/DocumentService.cs",
      [
        "public sealed class DocumentService {",
        "  private readonly DocumentStore _store;",
        "  public string Read(string path) { return _store.Read(path); }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Controllers/DocumentController.cs",
      [
        "using Microsoft.AspNetCore.Mvc;",
        "public sealed class DocumentController : ControllerBase {",
        "  private readonly DocumentService _documents;",
        "  public string Get([FromQuery] string path) { return _documents.Read(path); }",
        "}",
        "",
      ].join("\n"),
    );

    expect(
      aspnetPathRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("teaches the reviewer the exact .NET path boundary and two-hop contract", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "aspnet-http-path" } }),
    );
    expect(prompt).toContain(
      "Path.Combine is not containment: a rooted later argument can discard the trusted prefix",
    );
    expect(prompt).toContain(
      "C# uses uniquely resolved receiver types at both service boundaries",
    );
    expect(prompt).toContain(
      "a root string-prefix check without an exact directory boundary can accept sibling paths",
    );
    expect(prompt).toContain(
      "symlinks, junctions, reparse points, rename races",
    );
    expect(prompt).toContain("values reassigned before either service call");
  });
});
