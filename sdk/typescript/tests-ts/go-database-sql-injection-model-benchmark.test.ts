import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoSqlRecord {
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
const caseIds = [
  "go-cross-file-sql-injection",
  "go-cross-file-safe-sql",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoSqlRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoSqlRecord)
    .filter(
      (record) => record.frameworkModel?.id === "go-database-sql-injection",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoSqlRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-go-database-sql-"),
  );
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
  options: { sqlAlias?: string; sqlImport?: string; httpAlias?: string } = {},
): string {
  const sqlAlias = options.sqlAlias ?? "sql";
  const sqlImport = options.sqlImport ?? "database/sql";
  const httpAlias = options.httpAlias ?? "http";
  const sqlDeclaration =
    sqlAlias === "sql" ? `"${sqlImport}"` : `${sqlAlias} "${sqlImport}"`;
  const httpDeclaration =
    httpAlias === "http" ? '"net/http"' : `${httpAlias} "net/http"`;
  return `package search

import (
	${sqlDeclaration}
	${httpDeclaration}
)

func Search(db *${sqlAlias}.DB, w ${httpAlias}.ResponseWriter, r *${httpAlias}.Request) {
${body}
}
`;
}

describe("Go database/sql injection framework-model benchmark", () => {
  test("keeps the exploit and parameterized control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-database-sql-injection-manifest.json"),
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

  test("preserves the exact handler-to-query-text path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "search.go",
      line: 11,
      categories: [
        "framework-dataflow:go-database-sql-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-database-sql-query-text",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: {
          kind: "go-http-query-parameter",
          path: "handler.go",
          line: 10,
        },
        sink: {
          kind: "go-database-sql-query-text",
          path: "search.go",
          line: 11,
          cweIds: ["CWE-89"],
        },
        propagators: [
          {
            kind: "go-function-argument",
            path: "handler.go",
            line: 11,
            symbol: "Search[2]",
          },
          {
            kind: "go-string-parameter",
            path: "search.go",
            line: 9,
            symbol: "status",
          },
          {
            kind: "go-string-assignment",
            path: "search.go",
            line: 10,
            symbol: "query",
          },
        ],
      },
    });
    expect(safe).toEqual([]);
  });

  test("models exact DB query-text positions and excludes bound values", async () => {
    for (const method of ["Exec", "Query", "QueryRow"]) {
      expect(
        await repositoryInventory({
          "search.go": handler(
            `\tquery := r.FormValue("query")
\t_, _ = db.${method}(query)`,
          ),
        }),
      ).toHaveLength(1);
    }
    for (const method of ["ExecContext", "QueryContext", "QueryRowContext"]) {
      expect(
        await repositoryInventory({
          "search.go": handler(
            `\tquery := r.FormValue("query")
\t_, _ = db.${method}(r.Context(), query)`,
          ),
        }),
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\t_, _ = db.Query("SELECT secret FROM records WHERE status = ?", value)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\t_, _ = db.Query("SELECT secret FROM records WHERE status = :status", sql.Named("status", value))`),
      }),
    ).toEqual([]);
  });

  test("recognizes typed DB, Tx, Conn, inferred, and struct-field receivers", async () => {
    for (const type of ["DB", "Tx", "Conn"]) {
      const source = handler(`\tquery := r.FormValue("query")
\t_, _ = db.QueryContext(r.Context(), query)`).replace(
        "db *sql.DB",
        `db *sql.${type}`,
      );
      expect(await repositoryInventory({ "search.go": source })).toHaveLength(
        1,
      );
    }
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\topened, _ := sql.Open("driver", "dsn")
\ttx, _ := opened.Begin()
\t_, _ = tx.Query(query)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(
          `\tquery := r.FormValue("query")
\t_, _ = db.Query(query)`,
          { sqlAlias: "dbsql" },
        ),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"database/sql"
	"net/http"
)
var pool *sql.DB
func Search(w http.ResponseWriter, r *http.Request) {
	_, _ = pool.Query(r.FormValue("query"))
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"database/sql"
	"net/http"
)
type Store struct { db *sql.DB }
func (store *Store) Search(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	_, _ = store.db.Query(query)
}`,
      }),
    ).toHaveLength(1);
  });

  test("requires tainted prepared statements to execute", async () => {
    const executed = await repositoryInventory({
      "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := db.PrepareContext(r.Context(), query)
\t_, _ = statement.QueryContext(r.Context())`),
    });
    expect(executed).toHaveLength(1);
    expect(executed[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-sql-prepared-execution",
    );
    expect(
      executed[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-sql-statement-preparation");
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := db.Prepare(query)
\t_ = statement`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"database/sql"
	"net/http"
)
type localDB struct{}
func (localDB) Query(string) (any, error) { return nil, nil }
func TypedElsewhere() { var db *sql.DB; _ = db }
func Search(db localDB, w http.ResponseWriter, r *http.Request) {
	_, _ = db.Query(r.FormValue("query"))
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tstatement, _ := db.Prepare(query)
\tstatement, _ = db.Prepare("SELECT 1")
\t_, _ = statement.Query()`),
      }),
    ).toEqual([]);
  });

  test("recognizes exact indexed and Get request sources", async () => {
    for (const expression of [
      'r.URL.Query().Get("query")',
      'r.URL.Query()["query"][0]',
      'r.FormValue("query")',
      'r.PostFormValue("query")',
      'r.Form.Get("query")',
      'r.PostForm["query"][0]',
      'r.PathValue("query")',
      'r.Header.Get("X-Query")',
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\t_, _ = db.Query(${expression})`),
        }),
      ).toHaveLength(1);
    }
  });

  test("clears reassignment and fixed server-owned query selection", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tquery = "SELECT 1"
\t_, _ = db.Query(query)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"database/sql"
	"net/http"
)
var queries = map[string]string{"active": "SELECT secret FROM records WHERE active = true"}
func Search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	key := r.FormValue("query")
	query, ok := queries[key]
	if !ok { return }
	_, _ = db.Query(query)
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tquery := r.FormValue("query")
\tother := ""
\tother, query = query, "SELECT 1"
\t_, _ = db.Query(query)`),
      }),
    ).toEqual([]);
  });

  test("follows one exact same-package function boundary", async () => {
    const caller = handler(`\tquery := r.FormValue("query")
\t_, _ = RunQuery(db, query)`);
    const wrapper = `package search
import "database/sql"
func RunQuery(db *sql.DB, query string) (*sql.Rows, error) {
	return db.Query(query)
}`;
    const rows = await repositoryInventory({
      "handler.go": caller,
      "query.go": wrapper,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(
      rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(["go-function-argument", "go-string-parameter"]);
  });

  test("rejects ambiguity, package boundaries, lookalikes, and untyped methods", async () => {
    const caller = handler(`\tquery := r.FormValue("query")
\t_, _ = RunQuery(db, query)`);
    const wrapper = `package search
import "database/sql"
func RunQuery(db *sql.DB, query string) (*sql.Rows, error) { return db.Query(query) }`;
    expect(
      await repositoryInventory({
        "handler.go": caller,
        "query.go": wrapper,
        "duplicate.go": wrapper,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "api/handler.go": caller,
        "store/query.go": wrapper,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": caller,
        "query.go": wrapper.replace("package search", "package store"),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(
          `\tquery := r.FormValue("query")
\t_, _ = db.Query(query)`,
          { sqlImport: "example.com/database/sql" },
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	. "database/sql"
	"net/http"
)
func Search(db *DB, w http.ResponseWriter, r *http.Request) { _, _ = db.Query(r.FormValue("query")) }`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"database/sql"
	db "database/sql"
	"net/http"
)
func Search(handle *sql.DB, w http.ResponseWriter, r *http.Request) {
	_, _ = handle.Query(r.FormValue("query"))
	_ = db.ErrNoRows
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"database/sql"
	"net/http"
)
func Search(db interface{ Query(string) (any, error) }, w http.ResponseWriter, r *http.Request) {
	_, _ = db.Query(r.FormValue("query"))
	_ = sql.ErrNoRows
}`,
      }),
    ).toEqual([]);
  });

  test("rejects comments, strings, and statement value arguments", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\t// _, _ = db.Query(r.FormValue("query"))
\texample := "db.Query(r.FormValue(\\\"query\\\"))"
\t_ = example`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"database/sql"
	"net/http"
)
func Search(statement *sql.Stmt, w http.ResponseWriter, r *http.Request) {
	_, _ = statement.Query(r.FormValue("value"))
}`,
      }),
    ).toEqual([]);
  });

  test("retains escaping, allowlist, deadline, transaction, and argument leads", async () => {
    const rows = await repositoryInventory({
      "search.go": `package search
import (
	"context"
	"database/sql"
	"net/http"
	"regexp"
	"strings"
)
func Search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	query = strings.ReplaceAll(query, "'", "''")
	if !regexp.MustCompile("^[A-Za-z ]+$").MatchString(query) { return }
	ctx, cancel := context.WithTimeout(r.Context(), 1)
	defer cancel()
	_, _ = db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	_, _ = db.QueryContext(ctx, query, "bound")
}`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "manual-sql-escaping",
      "query-fragment-allowlist",
      "query-deadline",
      "read-only-transaction",
      "separate-query-arguments-present",
    ]);
  });

  test("teaches query-text, placeholder, preparation, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "", "");
    expect(prompt).toContain("For go-database-sql-injection rows");
    expect(prompt).toContain("typed *sql.DB/*sql.Tx/*sql.Conn receiver");
    expect(prompt).toContain("Later variadic arguments are placeholder values");
    expect(prompt).toContain("require the resulting statement to reach Exec");
    expect(prompt).toContain("Placeholder syntax is driver-specific");
    expect(prompt).toContain("stacked-statement support");
  });
});
