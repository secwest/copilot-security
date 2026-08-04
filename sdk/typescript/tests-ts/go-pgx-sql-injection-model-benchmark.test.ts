import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoPgxRecord {
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
const caseIds = ["go-cross-file-pgx-sqli", "go-cross-file-safe-pgx"] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoPgxRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoPgxRecord)
    .filter((record) => record.frameworkModel?.id === "go-pgx-sql-injection");
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoPgxRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-go-pgx-"));
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function poolHandler(
  body: string,
  options: { poolAlias?: string; poolImport?: string; httpAlias?: string } = {},
): string {
  const poolAlias = options.poolAlias ?? "pgxpool";
  const poolImport = options.poolImport ?? "github.com/jackc/pgx/v5/pgxpool";
  const httpAlias = options.httpAlias ?? "http";
  const poolDeclaration =
    poolAlias === "pgxpool"
      ? `"${poolImport}"`
      : `${poolAlias} "${poolImport}"`;
  const httpDeclaration =
    httpAlias === "http" ? '"net/http"' : `${httpAlias} "net/http"`;
  return `package search

import (
	${poolDeclaration}
	${httpDeclaration}
)

func Search(pool *${poolAlias}.Pool, w ${httpAlias}.ResponseWriter, r *${httpAlias}.Request) {
${body}
}
`;
}

function connHandler(
  body: string,
  pgxImport = "github.com/jackc/pgx/v5",
): string {
  return `package search

import (
	"${pgxImport}"
	"net/http"
)

func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
${body}
}
`;
}

describe("Go pgx/v5 SQL-injection framework-model benchmark", () => {
  test("keeps the exploit and bound-value control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-pgx-sql-injection-manifest.json"),
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

  test("preserves the exact request-to-pgxpool query path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "search.go",
      categories: [
        "framework-dataflow:go-pgx-sql-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-pgx-query-text",
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
          kind: "go-pgx-query-text",
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

  test("models exact pgx query positions and excludes bound values", async () => {
    for (const method of ["Exec", "Query", "QueryRow"]) {
      expect(
        await repositoryInventory({
          "search.go": poolHandler(
            `\tquery := r.FormValue("query")
\t_, _ = pool.${method}(r.Context(), query)`,
          ),
        }),
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": poolHandler(`\tvalue := r.FormValue("value")
\t_, _ = pool.Query(r.Context(), "SELECT secret FROM records WHERE status = $1", value)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
func Search(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
	value := r.FormValue("value")
	_, _ = pool.Query(r.Context(), "SELECT secret FROM records WHERE status = @status", pgx.NamedArgs{"status": value})
}`,
      }),
    ).toEqual([]);
  });

  test("recognizes connection, transaction, pool, aliases, and inferred handles", async () => {
    expect(
      await repositoryInventory({
        "search.go": connHandler(`\tquery := r.FormValue("query")
\t_, _ = conn.Query(r.Context(), query)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	driver "github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *driver.Conn, w http.ResponseWriter, r *http.Request) {
	_, _ = conn.Query(r.Context(), r.FormValue("query"))
}`,
      }),
    ).toHaveLength(1);
    for (const type of ["Conn", "Tx"]) {
      expect(
        await repositoryInventory({
          "search.go": `package search
import (
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
func Search(handle *pgxpool.${type}, w http.ResponseWriter, r *http.Request) {
	_, _ = handle.Query(r.Context(), r.FormValue("query"))
}`,
        }),
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(tx pgx.Tx, w http.ResponseWriter, r *http.Request) {
	_, _ = tx.Exec(r.Context(), r.FormValue("query"))
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": poolHandler(
          `\tquery := r.FormValue("query")
\ttx, _ := pool.Begin(r.Context())
\t_, _ = tx.Query(r.Context(), query)`,
          { poolAlias: "dbpool" },
        ),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
func Search(w http.ResponseWriter, r *http.Request) {
	pool, _ := pgxpool.New(r.Context(), "postgres://local")
	_, _ = pool.Query(r.Context(), r.FormValue("query"))
}`,
      }),
    ).toHaveLength(1);
  });

  test("requires manual prepared statements to execute by fixed name", async () => {
    const literal = await repositoryInventory({
      "search.go": connHandler(`\tquery := r.FormValue("query")
\t_, _ = conn.Prepare(r.Context(), "lookup", query)
\t_, _ = conn.Query(r.Context(), "lookup")`),
    });
    expect(literal).toHaveLength(1);
    expect(literal[0]?.frameworkModel?.sink.kind).toBe(
      "go-pgx-prepared-query-execution",
    );
    expect(
      literal[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-pgx-statement-preparation");
    expect(
      await repositoryInventory({
        "search.go": connHandler(`\tconst name = "lookup"
\tquery := r.FormValue("query")
\t_, _ = conn.Prepare(r.Context(), name, query)
\t_, _ = conn.Exec(r.Context(), name)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": connHandler(`\tquery := r.FormValue("query")
\t_, _ = conn.Prepare(r.Context(), "lookup", query)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": connHandler(`\tname := "lookup"
\tquery := r.FormValue("query")
\t_, _ = conn.Prepare(r.Context(), name, query)
\tname = "other"
\t_, _ = conn.Query(r.Context(), name)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(first *pgx.Conn, second *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	_, _ = first.Prepare(r.Context(), "lookup", query)
	_, _ = second.Query(r.Context(), "lookup")
}`,
      }),
    ).toEqual([]);
  });

  test("requires a typed batch to reach SendBatch", async () => {
    const dispatched = await repositoryInventory({
      "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	batch := &pgx.Batch{}
	batch.Queue(query)
	_ = conn.SendBatch(r.Context(), batch)
}`,
    });
    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]?.frameworkModel?.sink.kind).toBe(
      "go-pgx-batch-query-dispatch",
    );
    expect(
      dispatched[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-pgx-batch-queue");
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	batch := &pgx.Batch{}
	batch.Queue("SELECT secret FROM records WHERE status = $1", r.FormValue("value"))
	_ = conn.SendBatch(r.Context(), batch)
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	batch := &pgx.Batch{}
	batch.Queue(r.FormValue("query"))
	_ = batch
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	var batch pgx.Batch
	batch.Queue(r.FormValue("query"))
	_ = conn.SendBatch(r.Context(), &batch)
}`,
      }),
    ).toHaveLength(1);
    const multiple = await repositoryInventory({
      "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	first := r.FormValue("first")
	second := r.FormValue("second")
	batch := &pgx.Batch{}
	batch.Queue(first)
	batch.Queue(second)
	_ = conn.SendBatch(r.Context(), batch)
}`,
    });
    expect(multiple).toHaveLength(2);
    expect(
      multiple.map(
        (row) =>
          row.frameworkModel?.propagators.find(
            ({ kind }) => kind === "go-pgx-batch-queue",
          )?.line,
      ),
    ).toEqual([10, 11]);
    const preparedBatch = await repositoryInventory({
      "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	_, _ = conn.Prepare(r.Context(), "lookup", query)
	batch := &pgx.Batch{}
	batch.Queue("lookup")
	_ = conn.SendBatch(r.Context(), batch)
}`,
    });
    expect(preparedBatch).toHaveLength(1);
    expect(preparedBatch[0]?.frameworkModel?.sink.kind).toBe(
      "go-pgx-batch-query-dispatch",
    );
    expect(
      preparedBatch[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(["go-pgx-statement-preparation", "go-pgx-batch-queue"]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	batch := &pgx.Batch{}
	batch.Queue(r.FormValue("query"))
	batch = &pgx.Batch{}
	_ = conn.SendBatch(r.Context(), batch)
}`,
      }),
    ).toEqual([]);
  });

  test("recognizes package handles and same-file receiver fields", async () => {
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
var pool *pgxpool.Pool
func Search(w http.ResponseWriter, r *http.Request) {
	_, _ = pool.Query(r.Context(), r.FormValue("query"))
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
type Store struct { pool *pgxpool.Pool }
func (store *Store) Search(w http.ResponseWriter, r *http.Request) {
	_, _ = store.pool.Query(r.Context(), r.FormValue("query"))
}`,
      }),
    ).toHaveLength(1);
  });

  test("follows one unique same-package string wrapper", async () => {
    const caller = poolHandler(`\tquery := r.FormValue("query")
\t_, _ = RunQuery(r.Context(), pool, query)`);
    const wrapper = `package search
import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)
func RunQuery(ctx context.Context, pool *pgxpool.Pool, query string) (any, error) {
	return pool.Query(ctx, query)
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

  test("rejects ambiguity, boundaries, import lookalikes, and untyped methods", async () => {
    const caller = poolHandler(`\tquery := r.FormValue("query")
\t_, _ = RunQuery(r.Context(), pool, query)`);
    const wrapper = `package search
import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)
func RunQuery(ctx context.Context, pool *pgxpool.Pool, query string) (any, error) { return pool.Query(ctx, query) }`;
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
        "search.go": poolHandler(
          `\t_, _ = pool.Query(r.Context(), r.FormValue("query"))`,
          { poolImport: "github.com/jackc/pgx/v4/pgxpool" },
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": poolHandler(
          `\t_, _ = pool.Query(r.Context(), r.FormValue("query"))`,
          { poolImport: "example.com/jackc/pgx/v5/pgxpool" },
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	. "github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
func Search(pool *Pool, w http.ResponseWriter, r *http.Request) {
	_, _ = pool.Query(r.Context(), r.FormValue("query"))
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5/pgxpool"
	pool2 "github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
func Search(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
	_, _ = pool.Query(r.Context(), r.FormValue("query"))
	_ = pool2.Config{}
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
type localPool struct{}
func (localPool) Query(any, string, ...any) (any, error) { return nil, nil }
func TypedElsewhere() { var pool *pgxpool.Pool; _ = pool }
func Search(pool localPool, w http.ResponseWriter, r *http.Request) {
	_, _ = pool.Query(r.Context(), r.FormValue("query"))
}`,
      }),
    ).toEqual([]);
  });

  test("clears reassignment and fixed server-owned query selection", async () => {
    expect(
      await repositoryInventory({
        "search.go": poolHandler(`\tquery := r.FormValue("query")
\tquery = "SELECT 1"
\t_, _ = pool.Query(r.Context(), query)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
)
var queries = map[string]string{"active": "SELECT secret FROM records WHERE active = true"}
func Search(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
	key := r.FormValue("query")
	query, ok := queries[key]
	if !ok { return }
	_, _ = pool.Query(r.Context(), query)
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go":
          poolHandler(`\t// _, _ = pool.Query(r.Context(), r.FormValue("query"))
\texample := "pool.Query(r.Context(), r.FormValue(\\\"query\\\"))"
\t_ = example`),
      }),
    ).toEqual([]);
  });

  test("retains pgx-specific control and protocol review leads", async () => {
    const rows = await repositoryInventory({
      "search.go": `package search
import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"regexp"
	"strings"
)
func Search(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	query = strings.ReplaceAll(query, "'", "''")
	if !regexp.MustCompile("^[A-Za-z ]+$").MatchString(query) { return }
	ctx, cancel := context.WithTimeout(r.Context(), 1)
	defer cancel()
	_ = pgx.TxOptions{AccessMode: pgx.ReadOnly}
	_ = pgx.Identifier{query}.Sanitize()
	_, _ = pool.Query(ctx, query, pgx.QueryExecModeSimpleProtocol, pgx.NamedArgs{"value": "fixed"})
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
      "pgx-identifier-sanitization",
      "pgx-simple-protocol-review",
      "separate-query-arguments-present",
      "pgx-parameter-rewriter-present",
    ]);
  });

  test("teaches pgx argument, preparation, batch, protocol, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "", "");
    expect(prompt).toContain("For go-pgx-sql-injection rows");
    expect(prompt).toContain("proven *pgx.Conn/pgx.Tx");
    expect(prompt).toContain("later arguments are values or execution options");
    expect(prompt).toContain("QueryExecModeSimpleProtocol");
    expect(prompt).toContain("require a fixed statement name");
    expect(prompt).toContain("require the exact non-reassigned *pgx.Batch");
    expect(prompt).toContain("extended versus simple protocol");
  });
});
