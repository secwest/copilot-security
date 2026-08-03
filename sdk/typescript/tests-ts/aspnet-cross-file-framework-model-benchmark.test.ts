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
  "aspnet-cross-file-command-injection",
  "aspnet-cross-file-safe-command",
  "aspnet-cross-file-sql-injection",
  "aspnet-cross-file-safe-sql",
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

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-aspnet-flow-"),
  );
  temporaryPaths.push(repository);
  return repository;
}

describe("ASP.NET cross-file framework-model effectiveness benchmark", () => {
  test("keeps command and SQL pairs under strict exploit-and-control gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "aspnet-cross-file-framework-manifest.json"),
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
      cwe: ["CWE-78"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected[0]).toMatchObject({
      cwe: ["CWE-89"],
      acceptableSeverities: ["critical", "high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[3]?.expected).toEqual([]);
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[1],
          "Services",
          "CommandRunner.cs",
        ),
        "utf8",
      ),
    ).toContain("start.ArgumentList.Add(host);");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[3],
          "Services",
          "UserQueries.cs",
        ),
        "utf8",
      ),
    ).toContain('new SqlParameter("@name", SqlDbType.NVarChar, 128)');
    const vulnerableSqlClient = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[2],
        "Compatibility",
        "SqlClient.cs",
      ),
      "utf8",
    );
    expect(vulnerableSqlClient).toContain("users.Select(predicate)");
    expect(vulnerableSqlClient).toContain(
      "Connection.ExecuteScalar(CommandText)",
    );
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          caseIds[3],
          "Compatibility",
          "SqlClient.cs",
        ),
        "utf8",
      ),
    ).toContain('Connection.LookupExact(Parameters.Value("@name"))');
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "witnesses",
          "aspnet-cross-file-sql-injection",
          "Program.cs",
        ),
        "utf8",
      ),
    ).toContain("const string attackerName = \"' OR '1'='1\";");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "witnesses",
          "aspnet-cross-file-safe-sql",
          "Program.cs",
        ),
        "utf8",
      ),
    ).toContain("if (injectedResult is not null)");
  });

  test("preserves exact constructor-injected ASP.NET command and SQL paths", async () => {
    const command = crossFileModels(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const sql = crossFileModels(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[2]),
      ),
    );
    const safeCommand = crossFileModels(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );
    const safeSql = crossFileModels(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[3]),
      ),
    );

    expect(command).toHaveLength(1);
    expect(command[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "aspnet-http-command",
      language: "dotnet",
      scope: "cross-file-wrapper",
      source: {
        kind: "aspnet-bound-parameter",
        path: "Controllers/DiagnosticsController.cs",
        line: 18,
      },
      sink: {
        kind: "process-start",
        path: "Services/CommandRunner.cs",
        line: 9,
        cweIds: ["CWE-78"],
      },
      propagators: [
        {
          kind: "dotnet-type-binding",
          path: "Controllers/DiagnosticsController.cs",
          line: 10,
          symbol: "_runner:CommandRunner",
        },
        {
          kind: "wrapper-call-argument",
          path: "Controllers/DiagnosticsController.cs",
          line: 20,
          symbol: "_runner.Run[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "Services/CommandRunner.cs",
          line: 7,
          symbol: "command",
        },
      ],
      candidateControls: [],
    });
    expect(sql).toHaveLength(1);
    expect(sql[0]?.frameworkModel).toMatchObject({
      id: "aspnet-http-sql",
      language: "dotnet",
      source: {
        kind: "aspnet-bound-parameter",
        path: "Controllers/UsersController.cs",
        line: 18,
      },
      sink: {
        kind: "raw-sql-execution",
        path: "Services/UserQueries.cs",
        line: 19,
        cweIds: ["CWE-89"],
      },
      propagators: [
        {
          kind: "dotnet-type-binding",
          line: 10,
          symbol: "_queries:UserQueries",
        },
        {
          kind: "wrapper-call-argument",
          line: 20,
          symbol: "_queries.LookupAsync[0]",
        },
        { kind: "wrapper-parameter", line: 15, symbol: "name" },
      ],
      candidateControls: [],
    });
    expect(safeCommand).toEqual([]);
    expect(safeSql).toEqual([]);

    const prompt = scanQualityGatePrompt(JSON.stringify([...command, ...sql]));
    expect(prompt).toContain(
      "preserve the exact C# receiver type, controller method",
    );
    expect(prompt).toContain(
      "fixed executable started with UseShellExecute=false and one ArgumentList entry",
    );
    expect(prompt).toContain(
      "fixed query plus a typed DbParameter or SqlParameter",
    );
  });

  test("supports an assigned HttpRequest field and a multiline service call", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Controllers/DiagnosticsController.cs",
      `
public sealed class DiagnosticsController : ControllerBase
{
    private readonly CommandRunner _runner;
    public object Run()
    {
        string command = Request.Query["command"];
        return _runner.Run(
            command
        );
    }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "Services/CommandRunner.cs",
      `
using System.Diagnostics;
public sealed class CommandRunner
{
    public Process? Run(string command)
    {
        return Process.Start("cmd.exe", "/c " + command);
    }
}
`,
    );

    const models = crossFileModels(
      await buildResidualRiskInventory(repository),
    );
    expect(models).toHaveLength(1);
    expect(models[0]?.frameworkModel).toMatchObject({
      id: "aspnet-http-command",
      source: { kind: "aspnet-request-field", line: 7 },
      sink: { kind: "process-start", line: 7 },
      propagators: [
        { kind: "dotnet-type-binding", symbol: "_runner:CommandRunner" },
        { kind: "wrapper-call-argument", line: 8, symbol: "_runner.Run[0]" },
        { kind: "wrapper-parameter", symbol: "command" },
      ],
    });
  });

  test("rejects fixed, reassigned, text-only, and ambiguous C# pseudo-flows", async () => {
    for (const body of [
      `return Ok(_runner.Run("fixed"));`,
      `command = "fixed"; return Ok(_runner.Run(command));`,
      `var example = "_runner.Run(command)"; return Ok(example);`,
    ]) {
      const repository = await temporaryRepository();
      await writeRepositoryFile(
        repository,
        "Controllers/DiagnosticsController.cs",
        `
public sealed class DiagnosticsController : ControllerBase
{
    private readonly CommandRunner _runner;
    public IActionResult Run([FromQuery] string command)
    {
        ${body}
    }
}
`,
      );
      await writeRepositoryFile(
        repository,
        "Services/CommandRunner.cs",
        `
using System.Diagnostics;
public sealed class CommandRunner
{
    public Process? Run(string command)
    {
        // Process.Start("cmd.exe", "/c " + command);
        var example = "new ProcessStartInfo(" + command;
        return null;
    }
}
`,
      );
      expect(
        crossFileModels(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    }

    const ambiguous = await temporaryRepository();
    await writeRepositoryFile(
      ambiguous,
      "Controllers/DiagnosticsController.cs",
      `
public sealed class DiagnosticsController : ControllerBase
{
    private readonly CommandRunner _runner;
    public IActionResult Run([FromQuery] string command)
    {
        return Ok(_runner.Run(command));
    }
}
`,
    );
    for (const directory of ["One", "Two"]) {
      await writeRepositoryFile(
        ambiguous,
        `${directory}/CommandRunner.cs`,
        `
using System.Diagnostics;
public sealed class CommandRunner
{
    public Process? Run(string command)
    {
        return Process.Start("cmd.exe", "/c " + command);
    }
}
`,
      );
    }
    expect(
      crossFileModels(await buildResidualRiskInventory(ambiguous)),
    ).toEqual([]);
  });

  test("does not activate C# framework models from comments or string examples", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "Examples.cs",
      `
public sealed class Examples
{
    public string Show([FromQuery] string name)
    {
        // Process.Start("cmd.exe", name);
        var command = "Process.Start(" + name;
        var query = "new SqlCommand(" + name;
        return command + query;
    }
}
`,
    );

    expect(
      parseRecords(await buildResidualRiskInventory(repository)).some(
        (record) => record.frameworkModel !== undefined,
      ),
    ).toBeFalse();
  });
});
