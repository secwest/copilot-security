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
  "aspnet-cross-file-ssrf",
  "aspnet-cross-file-safe-fetch",
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

function aspnetSsrfRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "aspnet-http-ssrf",
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
    join(tmpdir(), "copilot-security-aspnet-ssrf-"),
  );
  temporaryPaths.push(repository);
  return repository;
}

describe("ASP.NET SSRF framework-model effectiveness benchmark", () => {
  test("keeps the exploit and fixed-destination control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "aspnet-cross-file-ssrf-manifest.json"),
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
      cwe: ["CWE-918"],
      acceptableSeverities: ["critical", "high", "medium"],
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
    expect(vulnerableWitness).toContain("169.254.169.254");
    expect(vulnerableWitness).toContain(
      "handler.RequestedUri != attackerTarget",
    );
    const safeWitness = await readFile(
      join(benchmarkRoot, "witnesses", caseIds[1], "Program.cs"),
      "utf8",
    );
    expect(safeWitness).toContain("handler.RequestedUris.Count != 0");
    expect(safeWitness).toContain(
      "https://cdn.example.invalid/assets/logo.svg",
    );
  });

  test("preserves the exact controller, receiver, argument, wrapper, and HttpClient sink", async () => {
    const vulnerable = aspnetSsrfRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = aspnetSsrfRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.path).toBe("Services/PreviewClient.cs");
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "aspnet-http-ssrf",
      language: "dotnet",
      scope: "cross-file-wrapper",
      source: {
        kind: "aspnet-bound-parameter",
        path: "Controllers/PreviewController.cs",
        line: 18,
      },
      sink: {
        kind: "outbound-http-url",
        path: "Services/PreviewClient.cs",
        line: 17,
        cweIds: ["CWE-918"],
      },
      propagators: [
        {
          kind: "dotnet-type-binding",
          path: "Controllers/PreviewController.cs",
          line: 10,
          symbol: "_preview:PreviewClient",
        },
        {
          kind: "wrapper-call-argument",
          path: "Controllers/PreviewController.cs",
          line: 23,
          symbol: "_preview.FetchAsync[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "Services/PreviewClient.cs",
          line: 15,
          symbol: "target",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toEqual([]);
  });

  test("retains useful same-file controls without treating substring checks as host authorization", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Controllers/PreviewController.cs",
      [
        "using Microsoft.AspNetCore.Mvc;",
        "using System.Net.Http;",
        "public sealed class PreviewController : ControllerBase {",
        "  public async Task<string> Get([FromQuery] string target) {",
        '    if (!target.Contains("cdn.example.invalid")) throw new Exception();',
        "    using var handler = new HttpClientHandler { AllowAutoRedirect = false };",
        "    using var client = new HttpClient(handler);",
        "    return await client.GetStringAsync(target);",
        "  }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Controllers/NoiseController.cs",
      [
        "using Microsoft.AspNetCore.Mvc;",
        "using System.Net.Http;",
        "public sealed class QueueClient {",
        "  public Task<string> GetStringAsync(string key) => Task.FromResult(key);",
        "}",
        "public sealed class NoiseController : ControllerBase {",
        "  private readonly HttpClient _unusedHttpClient = new();",
        "  private readonly QueueClient _queue = new();",
        "  public Task<string> Get([FromQuery] string target) {",
        "    return _queue.GetStringAsync(target);",
        "  }",
        "}",
        "",
      ].join("\n"),
    );

    const records = aspnetSsrfRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel).toMatchObject({
      scope: "same-file",
      sink: { kind: "outbound-http-url", cweIds: ["CWE-918"] },
    });
    expect(records[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "redirects-disabled",
      path: "Controllers/PreviewController.cs",
      line: 6,
    });
    expect(records[0]?.frameworkModel?.candidateControls).not.toContainEqual(
      expect.objectContaining({ kind: "parsed-host-exact-allowlist" }),
    );

    const prompt = scanQualityGatePrompt(JSON.stringify(records[0]));
    expect(prompt).toContain(
      "HttpClient BaseAddress does not make an attacker-controlled absolute request URI safe",
    );
    expect(prompt).toContain(
      "AllowAutoRedirect=false does not constrain the initial destination",
    );
    expect(prompt).toContain(
      "request timeouts and response-size bounds limit resource use but do not constrain the destination",
    );
  });

  test("rejects fixed, reassigned, ambiguous, and text-only pseudo-flows", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Services/PreviewClient.cs",
      [
        "using System.Net.Http;",
        "public sealed class PreviewClient {",
        "  private readonly HttpClient _client = new();",
        "  public Task<HttpResponseMessage> FetchAsync(string target) {",
        "    return _client.GetAsync(target);",
        "  }",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Other/PreviewClient.cs",
      [
        "public sealed class PreviewClient {",
        "  public object FetchAsync(string target) => new object();",
        "}",
        "",
      ].join("\n"),
    );
    await writeRepositoryFile(
      repository,
      "Controllers/PreviewController.cs",
      [
        "using Microsoft.AspNetCore.Mvc;",
        "public sealed class PreviewController : ControllerBase {",
        "  private readonly PreviewClient _preview;",
        "  public PreviewController(PreviewClient preview) { _preview = preview; }",
        "  public object Get([FromQuery] string target) {",
        '    target = "https://cdn.example.invalid/fixed";',
        "    // _preview.FetchAsync(target);",
        '    var example = "_preview.FetchAsync(target)";',
        "    return _preview.FetchAsync(target);",
        "  }",
        "}",
        "",
      ].join("\n"),
    );

    expect(
      aspnetSsrfRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });
});
