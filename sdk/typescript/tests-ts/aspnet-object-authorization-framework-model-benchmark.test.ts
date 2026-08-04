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
  "aspnet-cross-file-idor",
  "aspnet-cross-file-safe-authorization",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function authorizationRecords(inventory: string): FrameworkRecord[] {
  return records(inventory).filter(
    (record) =>
      record.frameworkModel?.id === "aspnet-http-object-authorization",
  );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function temporaryRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-aspnet-authorization-"),
  );
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents);
  }
  return repository;
}

describe("ASP.NET object-authorization framework-model effectiveness benchmark", () => {
  test("keeps the EF Core exploit and principal-bound control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "aspnet-object-authorization-manifest.json"),
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
      cwe: ["CWE-639", "CWE-862"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    for (const id of caseIds) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            id,
            `${id === caseIds[0] ? "AspnetCrossFileIdor" : "AspnetCrossFileSafeAuthorization"}.csproj`,
          ),
          "utf8",
        ),
      ).toContain(
        '<PackageReference Include="Microsoft.EntityFrameworkCore.InMemory" Version="8.0.29" />',
      );
    }
  });

  test("preserves the exact typed controller-to-repository lookup and control", async () => {
    const vulnerable = authorizationRecords(await fixtureInventory(caseIds[0]));
    const safe = authorizationRecords(await fixtureInventory(caseIds[1]));

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "aspnet-http-object-authorization",
      language: "dotnet",
      scope: "cross-file-wrapper",
      source: {
        kind: "aspnet-object-reference",
        path: "Controllers/InvoicesController.cs",
        line: 21,
      },
      sink: {
        kind: "ef-core-object-record-lookup",
        path: "Repositories/InvoiceRepository.cs",
        line: 18,
        cweIds: ["CWE-639", "CWE-862"],
      },
      propagators: [
        {
          kind: "dotnet-type-binding",
          path: "Controllers/InvoicesController.cs",
          line: 13,
          symbol: "_invoices:InvoiceRepository",
        },
        {
          kind: "wrapper-call-argument",
          path: "Controllers/InvoicesController.cs",
          line: 23,
          symbol: "_invoices.LoadInvoiceAsync[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "Repositories/InvoiceRepository.cs",
          line: 16,
          symbol: "invoiceId",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.source).toEqual({
      kind: "aspnet-object-reference",
      path: "Controllers/InvoicesController.cs",
      line: 22,
    });
    expect(safe[0]?.frameworkModel?.sink).toEqual({
      kind: "ef-core-object-record-lookup",
      path: "Repositories/InvoiceRepository.cs",
      line: 20,
      cweIds: ["CWE-639", "CWE-862"],
    });
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      {
        kind: "principal-bound-object-filter",
        path: "Repositories/InvoiceRepository.cs",
        line: 22,
      },
    ]);
  });

  test("retains only enforced resource authorization of the exact returned entity", async () => {
    const safeRepository = await temporaryRepository({
      "InvoiceController.cs": `
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
public sealed class InvoiceController : ControllerBase {
  private readonly DbSet<Invoice> _invoices;
  private readonly IAuthorizationService _authorization;
  public async Task<IActionResult> Get([FromRoute] int invoiceId) {
    var invoice = await _invoices.FindAsync(invoiceId);
    if (invoice is null) return NotFound();
    var decision = await _authorization.AuthorizeAsync(User, invoice, "ReadInvoice");
    if (!decision.Succeeded) return Forbid();
    return Ok(invoice);
  }
}
public sealed class Invoice { public int Id { get; set; } }
`,
    });
    const ignoredRepository = await temporaryRepository({
      "InvoiceController.cs": `
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
public sealed class InvoiceController : ControllerBase {
  private readonly DbSet<Invoice> _invoices;
  private readonly IAuthorizationService _authorization;
  public async Task<IActionResult> Get([FromRoute] int invoiceId) {
    var invoice = await _invoices.FindAsync(invoiceId);
    var otherInvoice = await _invoices.FindAsync(7);
    await _authorization.AuthorizeAsync(User, otherInvoice, "ReadInvoice");
    await _authorization.AuthorizeAsync(User, invoice, "ReadInvoice");
    return Ok(invoice);
  }
}
public sealed class Invoice { public int Id { get; set; } }
`,
    });

    const safe = authorizationRecords(
      await buildResidualRiskInventory(safeRepository),
    );
    const ignored = authorizationRecords(
      await buildResidualRiskInventory(ignoredRepository),
    );
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      {
        kind: "resource-based-object-authorization",
        path: "InvoiceController.cs",
        line: 10,
      },
    ]);
    expect(ignored).toHaveLength(1);
    expect(ignored[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("supports typed EF query variants while rejecting fixed, reassigned, and untyped lookups", async () => {
    const repository = await temporaryRepository({
      "InvoiceController.cs": `
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
public sealed class InvoiceController : ControllerBase {
  private readonly DbSet<Invoice> _invoices;
  private readonly InvoiceStore _store;
  public async Task<IActionResult> First([FromQuery] int invoiceId) {
    var invoice = await _invoices.FirstOrDefaultAsync(row => row.Id == invoiceId);
    return Ok(invoice);
  }
  public async Task<IActionResult> Fixed([FromRoute] int invoiceId) {
    var invoice = await _invoices.FindAsync(42);
    return Ok(invoice);
  }
  public async Task<IActionResult> Reassigned([FromRoute] int invoiceId) {
    invoiceId = 42;
    var invoice = await _invoices.FindAsync(invoiceId);
    return Ok(invoice);
  }
  public async Task<IActionResult> Untyped([FromRoute] int invoiceId) {
    var invoice = await _store.FindAsync(invoiceId);
    return Ok(invoice);
  }
}
public sealed class Invoice { public int Id { get; set; } }
public sealed class InvoiceStore { public Task<Invoice?> FindAsync(int id) => Task.FromResult<Invoice?>(null); }
`,
    });
    const found = authorizationRecords(
      await buildResidualRiskInventory(repository),
    );

    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.source.line).toBe(7);
    expect(found[0]?.frameworkModel?.sink.line).toBe(8);
    expect(found[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("does not treat endpoint authorization or attacker owner predicates as object controls", async () => {
    const repository = await temporaryRepository({
      "InvoiceController.cs": `
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
[Authorize]
public sealed class InvoiceController : ControllerBase {
  private readonly DbSet<Invoice> _invoices;
  public async Task<IActionResult> Get([FromRoute] int invoiceId, [FromQuery] int customerId) {
    var invoice = await _invoices.SingleOrDefaultAsync(row =>
      row.Id == invoiceId && row.CustomerId == customerId);
    return Ok(invoice);
  }
}
public sealed class Invoice { public int Id { get; set; } public int CustomerId { get; set; } }
`,
    });
    const found = authorizationRecords(
      await buildResidualRiskInventory(repository),
    );

    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("rejects EF shadows plus comment and string pseudo-flows", async () => {
    const repository = await temporaryRepository({
      "InvoiceController.cs": `
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace Microsoft.EntityFrameworkCore { public sealed class DbSet<T> { public Task<T?> FindAsync(int id) => Task.FromResult<T?>(default); } }
public sealed class InvoiceController : ControllerBase {
  private readonly DbSet<Invoice> _invoices;
  public async Task<IActionResult> Get([FromRoute] int invoiceId) {
    // var fake = await _invoices.FindAsync(invoiceId);
    var example = "_invoices.FindAsync(invoiceId)";
    var invoice = await _invoices.FindAsync(invoiceId);
    return Ok(invoice);
  }
}
public sealed class Invoice { public int Id { get; set; } }
`,
    });
    expect(
      authorizationRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("teaches resource authorization rather than attribute or GUID folklore", () => {
    const prompt = scanQualityGatePrompt("{}");
    expect(prompt).toContain("aspnet-http-object-authorization");
    expect(prompt).toContain("[Authorize]");
    expect(prompt).toContain("IAuthorizationService.AuthorizeAsync");
    expect(prompt).toContain("ignored authorization results");
  });
});
