import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoGormRecord {
  path: string;
  line: number;
  categories: string[];
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
const caseIds = ["go-cross-file-gorm-sqli", "go-cross-file-safe-gorm"] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoGormRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoGormRecord)
    .filter((record) => record.frameworkModel?.id === "go-gorm-sql-injection");
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoGormRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-go-gorm-"));
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

function handler(
  body: string,
  options: { gormAlias?: string; gormImport?: string; httpAlias?: string } = {},
): string {
  const gormAlias = options.gormAlias ?? "gorm";
  const gormImport = options.gormImport ?? "gorm.io/gorm";
  const httpAlias = options.httpAlias ?? "http";
  const gormDeclaration =
    gormAlias === "gorm" ? `"${gormImport}"` : `${gormAlias} "${gormImport}"`;
  const httpDeclaration =
    httpAlias === "http" ? '"net/http"' : `${httpAlias} "net/http"`;
  return `package search

import (
	${gormDeclaration}
	${httpDeclaration}
)

func Search(db *${gormAlias}.DB, w ${httpAlias}.ResponseWriter, r *${httpAlias}.Request) {
${body}
}
`;
}

describe("Go GORM injection framework-model benchmark", () => {
  test("keeps the exploit and parameterized control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-gorm-sql-injection-manifest.json"),
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
      cwe: ["CWE-89"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact handler-to-Raw-and-Scan path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "search.go",
      categories: [
        "framework-dataflow:go-gorm-sql-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-gorm-raw-sql-execution",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: { kind: "go-http-query-parameter", path: "handler.go" },
        sink: {
          kind: "go-gorm-raw-sql-execution",
          path: "search.go",
          cweIds: ["CWE-89"],
        },
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-function-argument",
      "go-string-parameter",
      "go-string-assignment",
      "go-gorm-query-construction",
    ]);
    expect(safe).toEqual([]);
  });

  test("requires execution closure for deferred Raw and query clauses", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Raw(query)`),
      }),
    ).toEqual([]);
    for (const finisher of ["Scan(&[]string{})", "Find(&[]string{})", "Rows()"])
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Raw(query).${finisher}`),
        }),
      ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Where(query)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Where(query).Find(&[]string{})`),
      }),
    ).toHaveLength(1);
  });

  test("models immediate Exec query text but excludes bound values", async () => {
    const rows = await repositoryInventory({
      "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Exec(query)`),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      categories: [
        "framework-dataflow:go-gorm-sql-injection",
        "modeled-source:go-http-form-value",
        "modeled-sink:go-gorm-raw-sql-execution",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "same-file",
        sink: { cweIds: ["CWE-89"] },
      },
    });
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tdb.Exec("UPDATE records SET status = ?", value)`),
      }),
    ).toEqual([]);
  });

  test("follows direct same-line and multiline fluent chains", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Model(&struct{}{}).Where(query).Order("id").Find(&[]string{})`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Model(&struct{}{}).
\t\tWhere("active = true").
\t\tOrder(query).
\t\tFind(&[]string{})`),
      }),
    ).toHaveLength(1);
  });

  test("tracks assigned builders and clears them on reassignment", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tbuilder := db.Where(query)
\tbuilder = builder.Session(&gorm.Session{})
\tbuilder.Find(&[]string{})`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tbuilder := db.Where(query)
\tbuilder = db.Session(&gorm.Session{})
\tbuilder.Find(&[]string{})`),
      }),
    ).toEqual([]);
  });

  test("models every documented query-grammar chain position", async () => {
    for (const method of [
      "Distinct",
      "Group",
      "Having",
      "InnerJoins",
      "Joins",
      "Not",
      "Or",
      "Order",
      "Raw",
      "Select",
      "Table",
      "Where",
    ]) {
      const rows = await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tdb.${method}(query).Find(&[]string{})`),
      });
      expect(rows, method).toHaveLength(1);
    }
  });

  test("distinguishes variadic Select columns from expression values", async () => {
    for (const method of ["Distinct", "Select"]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tcolumn := r.FormValue("column")
\tdb.${method}("name", column).Find(&[]string{})`),
        }),
        `${method} structural column`,
      ).toHaveLength(1);
      expect(
        await repositoryInventory({
          "search.go": handler(`\tvalue := r.FormValue("value")
\tdb.${method}("COALESCE(name, ?)", value).Find(&[]string{})`),
        }),
        `${method} expression value`,
      ).toEqual([]);
    }
  });

  test("models inline conditions and excludes later bound arguments", async () => {
    for (const method of [
      "Delete",
      "Find",
      "First",
      "FirstOrCreate",
      "FirstOrInit",
      "Last",
      "Take",
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tcondition := r.FormValue("condition")
\tdb.${method}(&struct{}{}, condition)`),
        }),
        method,
      ).toHaveLength(1);
      expect(
        await repositoryInventory({
          "search.go": handler(`\tvalue := r.FormValue("value")
\tdb.${method}(&struct{}{}, "status = ?", value)`),
        }),
        `${method} bound value`,
      ).toEqual([]);
    }
  });

  test("keeps request data in map and struct conditions out of SQL grammar", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tdb.Where(map[string]any{"status": value}).Find(&[]string{})
\tdb.Not(Filter{Status: value}).Find(&[]string{})
\tdb.Find(&[]string{}, map[string]any{"status": value})`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tfilters := map[string]any{"status": value}
\talias := filters
\tdb.Or(alias).Find(&[]string{})
\tdb.Delete(&struct{}{}, filters)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tfilters := map[string]any{"status": value}
\tfilters = value
\tdb.Where(filters).Find(&[]string{})`),
      }),
    ).toHaveLength(1);
  });

  test("models Pluck grammar at execution", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tcolumn := r.FormValue("column")
\tdb.Pluck(column, &[]string{})`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tdb.Where("status = ?", value).Pluck("secret", &[]string{})`),
      }),
    ).toEqual([]);
  });

  test("models assigned and nested gorm.Expr grammar only", async () => {
    const assigned = await repositoryInventory({
      "search.go": handler(`\tquery := r.FormValue("query")
\texpression := gorm.Expr(query)
\tdb.Exec("UPDATE records SET score = ?", expression)`),
    });
    expect(assigned).toHaveLength(1);
    expect(assigned[0]?.frameworkModel?.sink.kind).toBe(
      "go-gorm-expression-sql-execution",
    );
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Exec("UPDATE records SET score = ?", gorm.Expr(query))`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\texpression := gorm.Expr("score + ?", value)
\tdb.Exec("UPDATE records SET score = ?", expression)`),
      }),
    ).toEqual([]);
    for (const mutation of [
      'Update("score", expression)',
      'UpdateColumn("score", expression)',
      'Updates(map[string]any{"score": expression})',
      'UpdateColumns(map[string]any{"score": expression})',
      "Create(expression)",
      "CreateInBatches(expression, 10)",
      "Save(expression)",
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\texpression := gorm.Expr(query)
\tdb.${mutation}`),
        }),
        mutation,
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tdb.Updates(map[string]any{"score": gorm.Expr(query)})`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tdb.Update("score", value)`),
      }),
    ).toEqual([]);
  });

  test("infers Open, Begin, Session, alias, globals, and fields", async () => {
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  orm "gorm.io/gorm"
  "net/http"
)
var global *orm.DB
type store struct { database *orm.DB }
func Search(w http.ResponseWriter, r *http.Request) {
  query := r.FormValue("query")
  opened, _ := orm.Open(nil)
  opened.Begin().Exec(query)
  global.Session(&orm.Session{}).Where(query).Find(&[]string{})
}
func (local *store) Search(w http.ResponseWriter, r *http.Request) {
  query := r.FormValue("query")
  local.database.Raw(query).Scan(&[]string{})
}`,
      }),
    ).toHaveLength(3);
  });

  test("clears taint and accepts fixed server-owned fragment maps", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tquery = "id ASC"
\tdb.Order(query).Find(&[]string{})`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  "gorm.io/gorm"
  "net/http"
)
var orders = map[string]string{"recent": "created_at DESC", "name": "name ASC"}
func Search(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
  key := r.FormValue("order")
  order, ok := orders[key]
  if !ok { return }
  db.Order(order).Find(&[]string{})
}`,
      }),
    ).toEqual([]);
  });

  test("follows one unique same-package wrapper", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`\tquery := r.FormValue("query")
\tRunQuery(db, query)`),
      "query.go": `package search
import "gorm.io/gorm"
func RunQuery(db *gorm.DB, query string) {
  db.Raw(query).Scan(&[]string{})
}`,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(
      rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-function-argument",
      "go-string-parameter",
      "go-gorm-query-construction",
    ]);
  });

  test("rejects ambiguity, package boundaries, lookalikes, and untyped methods", async () => {
    const wrapper = `package search
import "gorm.io/gorm"
func RunQuery(db *gorm.DB, query string) { db.Exec(query) }`;
    expect(
      await repositoryInventory({
        "handler.go": handler(`\tquery := r.FormValue("query")
\tRunQuery(db, query)`),
        "query.go": wrapper,
        "duplicate.go": wrapper,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  first "gorm.io/gorm"
  second "gorm.io/gorm"
  "net/http"
)
func Search(db *first.DB, w http.ResponseWriter, r *http.Request) {
  db.Exec(r.FormValue("query"))
  _ = second.ErrInvalidDB
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tdb.Exec(r.FormValue("query"))`, {
          gormImport: "example.com/gorm.io/gorm",
        }),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  . "gorm.io/gorm"
  "net/http"
)
func Search(db *DB, w http.ResponseWriter, r *http.Request) { db.Exec(r.FormValue("query")) }`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  "gorm.io/gorm"
  "net/http"
)
type localDB struct{}
func (localDB) Exec(string) {}
func Search(db localDB, w http.ResponseWriter, r *http.Request) {
  db.Exec(r.FormValue("query"))
  _ = gorm.ErrInvalidDB
}`,
      }),
    ).toEqual([]);
  });

  test("rejects comments and strings", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\t// db.Exec(r.FormValue("query"))
\texample := "db.Exec(r.FormValue(\\\"query\\\"))"
\t_ = example`),
      }),
    ).toEqual([]);
  });

  test("retains candidate controls without treating them as sanitizers", async () => {
    const rows = await repositoryInventory({
      "search.go": `package search
import (
  "context"
  "gorm.io/gorm"
  "net/http"
  "regexp"
  "strings"
)
func Search(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
  query := r.FormValue("query")
  query = strings.ReplaceAll(query, "'", "''")
  if !regexp.MustCompile("^[A-Za-z ]+$").MatchString(query) { return }
  ctx, cancel := context.WithTimeout(r.Context(), 1)
  defer cancel()
  session := db.Session(&gorm.Session{DryRun: true, PrepareStmt: true, AllowGlobalUpdate: false})
  session.WithContext(ctx).Where(query, "bound").Find(&[]string{})
}`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "manual-sql-escaping",
      "query-fragment-allowlist",
      "query-deadline",
      "gorm-dry-run-session",
      "gorm-prepared-statement-mode",
      "gorm-global-update-guard",
      "gorm-bound-arguments-present",
    ]);
  });

  test("teaches query grammar, execution closure, expressions, and impact", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "", "");
    expect(prompt).toContain("For go-gorm-sql-injection rows");
    expect(prompt).toContain("gorm.io/gorm");
    expect(prompt).toContain("Separate query construction from execution");
    expect(prompt).toContain("A gorm.Expr first argument");
    expect(prompt).toContain("DryRun is strong counterevidence only when");
    expect(prompt).toContain("identifier or table fragment allowlisting");
  });
});
