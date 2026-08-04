import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoSqlxRecord {
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
const caseIds = ["go-cross-file-sqlx-sqli", "go-cross-file-safe-sqlx"] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoSqlxRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoSqlxRecord)
    .filter((record) => record.frameworkModel?.id === "go-sqlx-sql-injection");
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoSqlxRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-go-sqlx-"));
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function handler(
  body: string,
  options: { sqlxAlias?: string; sqlxImport?: string; httpAlias?: string } = {},
): string {
  const sqlxAlias = options.sqlxAlias ?? "sqlx";
  const sqlxImport = options.sqlxImport ?? "github.com/jmoiron/sqlx";
  const httpAlias = options.httpAlias ?? "http";
  const sqlxDeclaration =
    sqlxAlias === "sqlx" ? `"${sqlxImport}"` : `${sqlxAlias} "${sqlxImport}"`;
  const httpDeclaration =
    httpAlias === "http" ? '"net/http"' : `${httpAlias} "net/http"`;
  return `package search

import (
	${sqlxDeclaration}
	${httpDeclaration}
)

func Search(db *${sqlxAlias}.DB, w ${httpAlias}.ResponseWriter, r *${httpAlias}.Request) {
${body}
}
`;
}

describe("Go sqlx injection framework-model benchmark", () => {
  test("keeps the exploit and parameterized control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-sqlx-sql-injection-manifest.json"),
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

  test("preserves the exact handler-to-Select query-text path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "search.go",
      categories: [
        "framework-dataflow:go-sqlx-sql-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-sqlx-query-text",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: {
          kind: "go-http-query-parameter",
          path: "handler.go",
        },
        sink: {
          kind: "go-sqlx-query-text",
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
    ]);
    expect(safe).toEqual([]);
  });

  test("models receiver query positions and excludes bound values", async () => {
    for (const method of [
      "Exec",
      "Query",
      "QueryRow",
      "Queryx",
      "QueryRowx",
      "MustExec",
      "NamedExec",
      "NamedQuery",
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\t_, _ = db.${method}(query)`),
        }),
      ).toHaveLength(1);
    }
    for (const method of [
      "ExecContext",
      "QueryContext",
      "QueryRowContext",
      "QueryxContext",
      "QueryRowxContext",
      "MustExecContext",
      "NamedExecContext",
      "NamedQueryContext",
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\t_, _ = db.${method}(r.Context(), query)`),
        }),
      ).toHaveLength(1);
    }
    for (const method of ["Select", "Get"]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\tvar destination []string
\t_ = db.${method}(&destination, query)`),
        }),
      ).toHaveLength(1);
    }
    for (const method of ["SelectContext", "GetContext"]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\tvar destination []string
\t_ = db.${method}(r.Context(), &destination, query)`),
        }),
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tvar destination []string
\t_ = db.Select(&destination, "SELECT secret FROM records WHERE status = :status", value)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\t_, _ = db.NamedExec("UPDATE records SET status=:status", map[string]any{"status": value})`),
      }),
    ).toEqual([]);
  });

  test("models exact package helpers only with proven sqlx executors", async () => {
    const cases = [
      ["Select", "sqlx.Select(db, &destination, query)"],
      ["Get", "sqlx.Get(db, &destination, query)"],
      ["MustExec", "sqlx.MustExec(db, query)"],
      ["NamedExec", "sqlx.NamedExec(db, query, destination)"],
      ["NamedQuery", "sqlx.NamedQuery(db, query, destination)"],
      [
        "SelectContext",
        "sqlx.SelectContext(r.Context(), db, &destination, query)",
      ],
      ["GetContext", "sqlx.GetContext(r.Context(), db, &destination, query)"],
      ["MustExecContext", "sqlx.MustExecContext(r.Context(), db, query)"],
      [
        "NamedExecContext",
        "sqlx.NamedExecContext(r.Context(), db, query, destination)",
      ],
      [
        "NamedQueryContext",
        "sqlx.NamedQueryContext(r.Context(), db, query, destination)",
      ],
    ];
    for (const [, call] of cases) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\tvar destination []string
\t_, _ = ${call}`),
        }),
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tvar unknown interface{}
\tvar destination []string
\t_ = sqlx.Select(unknown, &destination, query)`),
      }),
    ).toEqual([]);
  });

  test("recognizes exact DB, Tx, Conn, constructors, derivatives, fields, and aliases", async () => {
    for (const type of ["DB", "Tx", "Conn"]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\t_, _ = db.Queryx(query)`).replace("db *sqlx.DB", `db *sqlx.${type}`),
        }),
      ).toHaveLength(1);
    }
    for (const constructor of [
      'sqlx.Open("driver", "dsn")',
      'sqlx.MustOpen("driver", "dsn")',
      'sqlx.Connect("driver", "dsn")',
      'sqlx.ConnectContext(r.Context(), "driver", "dsn")',
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\topened, _ := ${constructor}
\t_, _ = opened.Queryx(query)`),
        }),
      ).toHaveLength(1);
    }
    for (const derivative of [
      "db.Beginx()",
      "db.BeginTxx(r.Context(), nil)",
      "db.Connx(r.Context())",
      "db.Unsafe()",
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\thandle, _ := ${derivative}
\t_, _ = handle.Queryx(query)`),
        }),
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": handler(
          `\tquery := r.FormValue("query")
\t_, _ = db.Queryx(query)`,
          { sqlxAlias: "dbx" },
        ),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  "github.com/jmoiron/sqlx"
  "net/http"
)
type Store struct { db *sqlx.DB }
func (store *Store) Search(w http.ResponseWriter, r *http.Request) {
  _, _ = store.db.Queryx(r.FormValue("query"))
}`,
      }),
    ).toHaveLength(1);
  });

  test("requires tainted sqlx prepared statements to execute", async () => {
    for (const prepare of ["Prepare", "Preparex", "PrepareNamed"]) {
      const rows = await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := db.${prepare}(query)
\t_, _ = statement.Queryx()`),
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-sqlx-prepared-query-execution",
      );
      expect(
        rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toContain("go-sqlx-statement-preparation");
    }
    for (const prepare of [
      "PrepareContext",
      "PreparexContext",
      "PrepareNamedContext",
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := db.${prepare}(r.Context(), query)
\t_, _ = statement.ExecContext(r.Context())`),
        }),
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := db.Preparex(query)
\t_ = statement`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := db.Preparex(query)
\tstatement, _ = db.Preparex("SELECT 1")
\t_, _ = statement.Queryx()`),
      }),
    ).toEqual([]);
  });

  test("tracks package preparation and typed transaction statement transfer", async () => {
    const rows = await repositoryInventory({
      "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := sqlx.PrepareNamed(db, query)
\ttx, _ := db.Beginx()
\ttransferred := tx.NamedStmt(statement)
\t_, _ = transferred.Exec(map[string]any{})`),
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-sqlx-statement-transfer");
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := sqlx.PreparexContext(r.Context(), db, query)
\t_, _ = statement.SelectContext(r.Context(), &[]string{})`),
      }),
    ).toHaveLength(1);
  });

  test("preserves taint through Rebind and Named without treating values as grammar", async () => {
    const rebound = await repositoryInventory({
      "search.go": handler(`\tquery := r.FormValue("query")
\trebound := sqlx.Rebind(sqlx.DOLLAR, query)
\t_, _ = db.Queryx(rebound)`),
    });
    expect(rebound).toHaveLength(1);
    expect(
      rebound[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("sqlx-placeholder-rebinding");
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tquery, arguments, _ := sqlx.Named("SELECT secret FROM records WHERE status=:status", map[string]any{"status": value})
\t_, _ = db.Queryx(query, arguments...)`),
      }),
    ).toEqual([]);
    for (const transform of [
      "sqlx.BindNamed(sqlx.DOLLAR, query, map[string]any{})",
      "db.BindNamed(query, map[string]any{})",
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tquery := r.FormValue("query")
\tboundQuery, arguments, _ := ${transform}
\t_, _ = db.Queryx(boundQuery, arguments...)`),
        }),
      ).toHaveLength(1);
    }
    for (const transform of [
      'sqlx.BindNamed(sqlx.DOLLAR, "SELECT secret FROM records WHERE status=:status", map[string]any{"status": value})',
      'db.BindNamed("SELECT secret FROM records WHERE status=:status", map[string]any{"status": value})',
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tvalue := r.FormValue("value")
\tquery, arguments, _ := ${transform}
\t_, _ = db.Queryx(query, arguments...)`),
        }),
      ).toEqual([]);
    }
  });

  test("clears reassignment and fixed server-owned query selection", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tquery = "SELECT 1"
\t_, _ = db.Queryx(query)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  "github.com/jmoiron/sqlx"
  "net/http"
)
var queries = map[string]string{"active": "SELECT secret FROM records WHERE active=true"}
func Search(db *sqlx.DB, w http.ResponseWriter, r *http.Request) {
  key := r.FormValue("query")
  query, ok := queries[key]
  if !ok { return }
  _, _ = db.Queryx(query)
}`,
      }),
    ).toEqual([]);
  });

  test("follows one unique same-package function boundary", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`\tquery := r.FormValue("query")
\t_ = RunQuery(db, query)`),
      "query.go": `package search
import "github.com/jmoiron/sqlx"
func RunQuery(db *sqlx.DB, query string) error {
  var rows []string
  return db.Select(&rows, query)
}`,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(
      rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(["go-function-argument", "go-string-parameter"]);
  });

  test("rejects ambiguity, package boundaries, lookalikes, and untyped methods", async () => {
    const wrapper = `package search
import "github.com/jmoiron/sqlx"
func RunQuery(db *sqlx.DB, query string) error { var rows []string; return db.Select(&rows, query) }`;
    expect(
      await repositoryInventory({
        "handler.go": handler(`\tquery := r.FormValue("query")
\t_ = RunQuery(db, query)`),
        "query.go": wrapper,
        "duplicate.go": wrapper,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\t_, _ = db.Queryx(r.FormValue("query"))`, {
          sqlxImport: "example.com/jmoiron/sqlx",
        }),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  . "github.com/jmoiron/sqlx"
  "net/http"
)
func Search(db *DB, w http.ResponseWriter, r *http.Request) { _, _ = db.Queryx(r.FormValue("query")) }`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  "github.com/jmoiron/sqlx"
  "net/http"
)
type localDB struct{}
func (localDB) Queryx(string) (any, error) { return nil, nil }
func Search(db localDB, w http.ResponseWriter, r *http.Request) {
  _, _ = db.Queryx(r.FormValue("query"))
  _ = sqlx.NameMapper
}`,
      }),
    ).toEqual([]);
  });

  test("rejects comments, strings, and statement value arguments", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\t// _, _ = db.Queryx(r.FormValue("query"))
\texample := "db.Queryx(r.FormValue(\\\"query\\\"))"
\t_ = example`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  "github.com/jmoiron/sqlx"
  "net/http"
)
func Search(statement *sqlx.Stmt, w http.ResponseWriter, r *http.Request) {
  _, _ = statement.Queryx(r.FormValue("value"))
}`,
      }),
    ).toEqual([]);
  });

  test("retains escaping, allowlist, deadline, transaction, rebinding, and argument leads", async () => {
    const rows = await repositoryInventory({
      "search.go": `package search
import (
  "context"
  "github.com/jmoiron/sqlx"
  "net/http"
  "regexp"
  "strings"
)
func Search(db *sqlx.DB, w http.ResponseWriter, r *http.Request) {
  query := r.FormValue("query")
  query = strings.ReplaceAll(query, "'", "''")
  if !regexp.MustCompile("^[A-Za-z ]+$").MatchString(query) { return }
  ctx, cancel := context.WithTimeout(r.Context(), 1)
  defer cancel()
  _, _ = db.BeginTxx(ctx, nil)
  query = db.Rebind(query)
  _, _ = db.QueryxContext(ctx, query, "bound")
}`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "manual-sql-escaping",
      "query-fragment-allowlist",
      "query-deadline",
      "sqlx-placeholder-rebinding",
      "separate-query-arguments-present",
    ]);
  });

  test("teaches sqlx query, named-value, preparation, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "", "");
    expect(prompt).toContain("For go-sqlx-sql-injection rows");
    expect(prompt).toContain("github.com/jmoiron/sqlx");
    expect(prompt).toContain("Select/Get place destination before query text");
    expect(prompt).toContain("NamedExec and NamedQuery bind values");
    expect(prompt).toContain("Rebind does not sanitize");
    expect(prompt).toContain("prepared-but-unexecuted");
  });
});
