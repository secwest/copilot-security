import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  frameworkModel?: {
    id: string;
    scope: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
  };
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-razor-pages-"),
  );
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents);
  }
  return repository;
}

function frameworkRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter((record) => record.frameworkModel?.id.startsWith("aspnet-http-"));
}

describe("ASP.NET Razor Pages remote-source model", () => {
  test("keeps the executable exploit and parameterized control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "aspnet-razor-page-sql-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        findingsPaths: string[];
        expected: Array<{
          cwe?: string[];
          requireValidation?: boolean;
          requireAttackPath?: boolean;
          requireCodeEvidence?: boolean;
        }>;
      }>;
    };
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "aspnet-razor-page-sql-injection",
      "aspnet-razor-page-safe-sql",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-89"],
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
          "aspnet-razor-page-sql-injection",
          "Pages",
          "Search.cshtml.cs",
        ),
        "utf8",
      ),
    ).toContain("OnGetLookupAsync(string filter)");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "aspnet-razor-page-safe-sql",
          "Services",
          "UserQueries.cs",
        ),
        "utf8",
      ),
    ).toContain('new SqlParameter("@filter", SqlDbType.NVarChar, 128)');
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "witnesses",
          "aspnet-razor-page-sql-injection",
          "Program.cs",
        ),
        "utf8",
      ),
    ).toContain("await page.OnGetLookupAsync(attackerFilter);");
  });

  test("models an unannotated named handler parameter through a typed cross-file SQL wrapper", async () => {
    const repository = await temporaryRepository({
      "Pages/Search.cshtml.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
public sealed class SearchModel : PageModel
{
    private readonly UserQueries _queries;
    public SearchModel(UserQueries queries) { _queries = queries; }
    public Task<string?> OnGetLookupAsync(string filter)
    {
        return _queries.LookupAsync(filter);
    }
}
`,
      "Services/UserQueries.cs": `
using Microsoft.Data.SqlClient;
public sealed class UserQueries
{
    public Task<string?> LookupAsync(string filter)
    {
        var command = new SqlCommand("SELECT Name FROM Users WHERE Name = '" + filter + "'");
        return Task.FromResult<string?>(command.CommandText);
    }
}
`,
    });

    const records = frameworkRecords(
      await buildResidualRiskInventory(repository),
    ).filter((record) => record.frameworkModel?.id === "aspnet-http-sql");
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel).toMatchObject({
      id: "aspnet-http-sql",
      scope: "cross-file-wrapper",
      source: {
        kind: "aspnet-razor-page-handler-parameter",
        path: "Pages/Search.cshtml.cs",
        line: 7,
      },
      sink: {
        kind: "raw-sql-execution",
        path: "Services/UserQueries.cs",
        cweIds: ["CWE-89"],
      },
      propagators: [
        { kind: "dotnet-type-binding", symbol: "_queries:UserQueries" },
        { kind: "wrapper-call-argument", symbol: "_queries.LookupAsync[0]" },
        { kind: "wrapper-parameter", symbol: "filter" },
      ],
    });
  });

  test("preserves the exact executable fixture path and rejects its parameterized twin", async () => {
    const vulnerable = frameworkRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "aspnet-razor-page-sql-injection"),
      ),
    ).filter((record) => record.frameworkModel?.id === "aspnet-http-sql");
    const safe = frameworkRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "aspnet-razor-page-safe-sql"),
      ),
    ).filter((record) => record.frameworkModel?.id === "aspnet-http-sql");

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-wrapper",
      source: {
        kind: "aspnet-razor-page-handler-parameter",
        path: "Pages/Search.cshtml.cs",
        line: 17,
      },
      sink: {
        kind: "raw-sql-execution",
        path: "Services/UserQueries.cs",
        line: 19,
        cweIds: ["CWE-89"],
      },
      propagators: [
        { kind: "dotnet-type-binding", symbol: "_queries:UserQueries" },
        {
          kind: "wrapper-call-argument",
          symbol: "_queries.LookupAsync[0]",
        },
        { kind: "wrapper-parameter", symbol: "filter" },
      ],
    });
    expect(safe).toEqual([]);
  });

  test("feeds all six typed ASP.NET sink families from exact PageModel handlers", async () => {
    const repository = await temporaryRepository({
      "Pages/Command.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;
public sealed class CommandModel : PageModel {
  public object? OnPost(string command) { return Process.Start("cmd.exe", "/c " + command); }
}
`,
      "Pages/Sql.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class SqlModel : PageModel {
  public object OnPost(string filter) { return new SqlCommand("SELECT * FROM T WHERE N='" + filter + "'"); }
}
`,
      "Pages/Object.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
public sealed class ObjectModel : PageModel {
  private readonly DbSet<Invoice> _invoices;
  public object OnGet(int invoiceId) { return _invoices.Find(invoiceId); }
}
`,
      "Pages/Template.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using Scriban;
public sealed class TemplateModel : PageModel {
  public object OnPost(string source) { return Template.Parse(source).Render(); }
}
`,
      "Pages/Fetch.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http;
public sealed class FetchModel : PageModel {
  private readonly HttpClient _client;
  public Task<string> OnGetAsync(string target) { return _client.GetStringAsync(target); }
}
`,
      "Pages/File.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.IO;
public sealed class FileModel : PageModel {
  public string OnGet(string path) { return File.ReadAllText(path); }
}
`,
    });

    const records = frameworkRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(
      records
        .filter((record) => record.frameworkModel?.scope === "same-file")
        .map((record) => record.frameworkModel?.id)
        .sort(),
    ).toEqual([
      "aspnet-http-command",
      "aspnet-http-object-authorization",
      "aspnet-http-path",
      "aspnet-http-sql",
      "aspnet-http-ssrf",
      "aspnet-http-template-injection",
    ]);
    expect(
      records.every(
        (record) =>
          record.frameworkModel?.source.kind ===
          "aspnet-razor-page-handler-parameter",
      ),
    ).toBeTrue();
  });

  test("supports bounded local PageModel inheritance and one relay before the filesystem sink", async () => {
    const repository = await temporaryRepository({
      "Pages/SecwestPage.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
public abstract class SecwestPage : PageModel { }
`,
      "Pages/Documents.cs": `
public sealed class DocumentsModel : SecwestPage {
  private readonly DocumentService _documents;
  public DocumentsModel(DocumentService documents) { _documents = documents; }
  public Task<string> OnPostDownloadAsync(string path) { return _documents.ReadAsync(path); }
}
`,
      "Services/DocumentService.cs": `
public sealed class DocumentService {
  private readonly DocumentStore _store;
  public DocumentService(DocumentStore store) { _store = store; }
  public Task<string> ReadAsync(string path) { return _store.ReadAsync(path); }
}
`,
      "Services/DocumentStore.cs": `
using System.IO;
public sealed class DocumentStore {
  public Task<string> ReadAsync(string path) { return File.ReadAllTextAsync(path); }
}
`,
    });

    const records = frameworkRecords(
      await buildResidualRiskInventory(repository),
    ).filter((record) => record.frameworkModel?.id === "aspnet-http-path");
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: {
        kind: "aspnet-razor-page-handler-parameter",
        path: "Pages/Documents.cs",
      },
      sink: { path: "Services/DocumentStore.cs", cweIds: ["CWE-22"] },
    });
    expect(records[0]?.frameworkModel?.propagators).toHaveLength(6);
  });

  test("models POST and SupportsGet bound properties, including a bounded local alias", async () => {
    const repository = await temporaryRepository({
      "Pages/PostSearch.cs": `
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class PostSearchModel : PageModel {
  [BindProperty]
  public string Filter { get; set; } = "";
  public object OnPost() {
    var queryFilter = Filter;
    return new SqlCommand("SELECT * FROM T WHERE N='" + queryFilter + "'");
  }
}
`,
      "Pages/GetSearch.cs": `
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class GetSearchModel : PageModel {
  [BindProperty(SupportsGet = true)]
  public string Filter { get; set; } = "";
  public object OnGet() {
    return new SqlCommand("SELECT * FROM T WHERE N='" + Filter + "'");
  }
}
`,
      "Pages/BoundClass.cs": `
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
[BindProperties]
public sealed class BoundClassModel : global::Microsoft.AspNetCore.Mvc.RazorPages.PageModel {
  public string Filter { get; set; } = "";
  public object OnPostSave() {
    return new SqlCommand("SELECT * FROM T WHERE N='" + Filter + "'");
  }
}
`,
    });

    const records = frameworkRecords(
      await buildResidualRiskInventory(repository),
    ).filter((record) => record.frameworkModel?.id === "aspnet-http-sql");
    expect(records).toHaveLength(3);
    expect(records.map((record) => record.frameworkModel?.source.kind)).toEqual(
      [
        "aspnet-razor-page-bound-property",
        "aspnet-razor-page-bound-property",
        "aspnet-razor-page-bound-property",
      ],
    );
  });

  test("fails closed for non-pages, non-handlers, service inputs, opt-outs, GET-only property rules, reassignment, and shadows", async () => {
    const cases: Readonly<Record<string, string>> = {
      "Controller.cs": `
using Microsoft.Data.SqlClient;
public sealed class Controller {
  public object OnGet(string filter) { return new SqlCommand(filter); }
}
`,
      "Protected.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class ProtectedModel : PageModel {
  protected object OnGet(string filter) { return new SqlCommand(filter); }
}
`,
      "NonHandler.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class NonHandlerModel : PageModel {
  [NonHandler]
  public object OnGet(string filter) { return new SqlCommand(filter); }
}
`,
      "Service.cs": `
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class ServiceModel : PageModel {
  public object OnGet([FromServices] string filter) { return new SqlCommand(filter); }
}
`,
      "GetProperty.cs": `
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class GetPropertyModel : PageModel {
  [BindProperty]
  public string Filter { get; set; } = "";
  public object OnGet() { return new SqlCommand(Filter); }
}
`,
      "Reassigned.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class ReassignedModel : PageModel {
  public object OnGet(string filter) { filter = "fixed"; return new SqlCommand(filter); }
}
`,
    };
    for (const [name, source] of Object.entries(cases)) {
      const repository = await temporaryRepository({ [name]: source });
      expect(
        frameworkRecords(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    }

    const pageShadow = await temporaryRepository({
      "PageModel.cs": `public class PageModel { }`,
      "Shadow.cs": `
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class ShadowModel : PageModel {
  public object OnGet(string filter) { return new SqlCommand(filter); }
}
`,
    });
    expect(
      frameworkRecords(await buildResidualRiskInventory(pageShadow)),
    ).toEqual([]);

    const attributeShadow = await temporaryRepository({
      "BindPropertyAttribute.cs": `public sealed class BindPropertyAttribute : System.Attribute { }`,
      "Shadow.cs": `
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.SqlClient;
public sealed class ShadowModel : PageModel {
  [BindProperty]
  public string Filter { get; set; } = "";
  public object OnPost() { return new SqlCommand(Filter); }
}
`,
    });
    expect(
      frameworkRecords(await buildResidualRiskInventory(attributeShadow)),
    ).toEqual([]);
  });
});
