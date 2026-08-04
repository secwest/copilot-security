import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoPgconnRecord {
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
  "go-cross-file-pgconn-sqli",
  "go-cross-file-safe-pgconn",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoPgconnRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoPgconnRecord)
    .filter(
      (record) => record.frameworkModel?.id === "go-pgconn-sql-injection",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoPgconnRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-go-pgconn-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function pgconnHandler(
  body: string,
  options: { alias?: string; importPath?: string; extraImports?: string } = {},
): string {
  const alias = options.alias ?? "pgconn";
  const importPath = options.importPath ?? "github.com/jackc/pgx/v5/pgconn";
  const declaration =
    alias === "pgconn" ? `"${importPath}"` : `${alias} "${importPath}"`;
  return `package search

import (
	${declaration}
	"net/http"
	${options.extraImports ?? ""}
)

func Search(conn *${alias}.PgConn, w http.ResponseWriter, r *http.Request) {
${body}
}
`;
}

describe("Go pgconn SQL-injection framework-model benchmark", () => {
  test("keeps the simple-protocol exploit and extended-protocol control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-pgconn-sql-injection-manifest.json"),
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

  test("preserves the exact cross-file request-to-PgConn path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "search.go",
      categories: [
        "framework-dataflow:go-pgconn-sql-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-pgconn-query-text",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: { kind: "go-http-query-parameter", path: "handler.go" },
        sink: {
          kind: "go-pgconn-query-text",
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

  test("models exact immediate SQL and COPY positions while excluding data arguments", async () => {
    const direct = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	_ = conn.Exec(r.Context(), query)
	_ = conn.ExecParams(r.Context(), query, nil, nil, nil, nil)
	_, _ = conn.CopyFrom(r.Context(), nil, query)
	_, _ = conn.CopyTo(r.Context(), nil, query)
`),
    });
    expect(direct).toHaveLength(4);
    expect(direct.map((record) => record.frameworkModel?.sink.kind)).toEqual([
      "go-pgconn-query-text",
      "go-pgconn-query-text",
      "go-pgconn-copy-command",
      "go-pgconn-copy-command",
    ]);
    expect(direct[1]?.categories).toContain(
      "candidate-control:separate-pgconn-parameter-bytes",
    );

    const dataOnly = await repositoryInventory({
      "search.go": pgconnHandler(
        `
	value := r.FormValue("value")
	_ = conn.ExecParams(r.Context(), "SELECT name FROM records WHERE status = $1", [][]byte{[]byte(value)}, nil, nil, nil)
	_, _ = conn.CopyFrom(r.Context(), strings.NewReader(value), "COPY records FROM STDIN")
	_, _ = conn.CopyTo(r.Context(), io.Discard, "COPY records TO STDOUT")
`,
        { extraImports: '"io"\n\t"strings"' },
      ),
    });
    expect(dataOnly).toEqual([]);
  });

  test("requires prepared SQL to execute by fixed name or exact statement description", async () => {
    const byName = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	_, _ = conn.Prepare(r.Context(), "find", query, nil)
	_ = conn.ExecPrepared(r.Context(), "find", nil, nil, nil)
`),
    });
    expect(byName).toHaveLength(1);
    expect(byName[0]?.frameworkModel?.sink.kind).toBe(
      "go-pgconn-prepared-query-execution",
    );
    expect(
      byName[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-pgconn-statement-preparation");

    const byDescription = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	statement, _ := conn.Prepare(r.Context(), "find", query, nil)
	_ = conn.ExecStatement(r.Context(), statement, nil, nil, nil)
`),
    });
    expect(byDescription).toHaveLength(1);

    for (const body of [
      `	query := r.FormValue("query")\n\t_, _ = conn.Prepare(r.Context(), "find", query, nil)`,
      `	query := r.FormValue("query")\n\tname := r.FormValue("name")\n\t_, _ = conn.Prepare(r.Context(), name, query, nil)\n\t_ = conn.ExecPrepared(r.Context(), name, nil, nil, nil)`,
      `	query := r.FormValue("query")\n\tstatement, _ := conn.Prepare(r.Context(), "find", query, nil)\n\tstatement = &pgconn.StatementDescription{}\n\t_ = conn.ExecStatement(r.Context(), statement, nil, nil, nil)`,
    ]) {
      expect(
        await repositoryInventory({ "search.go": pgconnHandler(body) }),
      ).toEqual([]);
    }
  });

  test("closes pgconn Batch only through the same PgConn ExecBatch", async () => {
    const direct = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	var batch pgconn.Batch
	batch.ExecParams(query, nil, nil, nil, nil)
	_ = conn.ExecBatch(r.Context(), &batch)
`),
    });
    expect(direct).toHaveLength(1);
    expect(direct[0]?.frameworkModel?.sink.kind).toBe(
      "go-pgconn-batch-query-dispatch",
    );
    expect(
      direct[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-pgconn-batch-query-queue");

    const prepared = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	_, _ = conn.Prepare(r.Context(), "find", query, nil)
	batch := &pgconn.Batch{}
	batch.ExecPrepared("find", nil, nil, nil)
	_ = conn.ExecBatch(r.Context(), batch)
`),
    });
    expect(prepared).toHaveLength(1);

    for (const body of [
      `	query := r.FormValue("query")\n\tvar batch pgconn.Batch\n\tbatch.ExecParams(query, nil, nil, nil, nil)`,
      `	value := r.FormValue("value")\n\tvar batch pgconn.Batch\n\tbatch.ExecParams("SELECT name FROM records WHERE status = $1", [][]byte{[]byte(value)}, nil, nil, nil)\n\t_ = conn.ExecBatch(r.Context(), &batch)`,
      `	query := r.FormValue("query")\n\tbatch := &pgconn.Batch{}\n\tbatch.ExecParams(query, nil, nil, nil, nil)\n\tbatch = &pgconn.Batch{}\n\t_ = conn.ExecBatch(r.Context(), batch)`,
    ]) {
      expect(
        await repositoryInventory({ "search.go": pgconnHandler(body) }),
      ).toEqual([]);
    }
  });

  test("requires pipeline query queues to reach Flush or Sync and keeps Close inert", async () => {
    for (const dispatch of ["Flush", "Sync"]) {
      const records = await repositoryInventory({
        "search.go": pgconnHandler(`
	query := r.FormValue("query")
	pipeline := conn.StartPipeline(r.Context())
	pipeline.SendQueryParams(query, nil, nil, nil, nil)
	_ = pipeline.${dispatch}()
`),
      });
      expect(records).toHaveLength(1);
      expect(records[0]?.frameworkModel?.sink.kind).toBe(
        "go-pgconn-pipeline-query-dispatch",
      );
      expect(
        records[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toContain("go-pgconn-pipeline-query-queue");
    }

    const multiple = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	pipeline := conn.StartPipeline(r.Context())
	pipeline.SendQueryParams(query, nil, nil, nil, nil)
	pipeline.SendQueryParams(query + " ORDER BY name", nil, nil, nil, nil)
	_ = pipeline.Sync()
`),
    });
    expect(multiple).toHaveLength(2);

    const flushedOnce = await repositoryInventory({
      "search.go": pgconnHandler(`
\tquery := r.FormValue("query")
\tpipeline := conn.StartPipeline(r.Context())
\tpipeline.SendQueryParams(query, nil, nil, nil, nil)
\t_ = pipeline.Flush()
\t_ = pipeline.Sync()
`),
    });
    expect(flushedOnce).toHaveLength(1);

    for (const ending of ["", "\n\t_ = pipeline.Close()"]) {
      expect(
        await repositoryInventory({
          "search.go": pgconnHandler(`
	query := r.FormValue("query")
	pipeline := conn.StartPipeline(r.Context())
	pipeline.SendQueryParams(query, nil, nil, nil, nil)${ending}
`),
        }),
      ).toEqual([]);
    }

    expect(
      await repositoryInventory({
        "search.go": pgconnHandler(`
\tquery := r.FormValue("query")
\tpipeline := conn.StartPipeline(r.Context())
\tpipeline.SendQueryParams(query, nil, nil, nil, nil)
\t_ = pipeline.Close()
\t_ = pipeline.Sync()
`),
      }),
    ).toEqual([]);
  });

  test("tracks prepared names and statement descriptions through pipeline dispatch", async () => {
    const inPipeline = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	pipeline := conn.StartPipeline(r.Context())
	pipeline.SendPrepare("find", query, nil)
	pipeline.SendQueryPrepared("find", nil, nil, nil)
	_ = pipeline.Sync()
`),
    });
    expect(inPipeline).toHaveLength(1);
    expect(
      inPipeline[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-pgconn-pipeline-statement-preparation");

    const fromConnection = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	statement, _ := conn.Prepare(r.Context(), "find", query, nil)
	pipeline := conn.StartPipeline(r.Context())
	pipeline.SendQueryPrepared("find", nil, nil, nil)
	pipeline.SendQueryStatement(statement, nil, nil, nil)
	_ = pipeline.Flush()
`),
    });
    expect(fromConnection).toHaveLength(2);

    const undispatched = await repositoryInventory({
      "search.go": pgconnHandler(`
	query := r.FormValue("query")
	pipeline := conn.StartPipeline(r.Context())
	pipeline.SendPrepare("find", query, nil)
	pipeline.SendQueryPrepared("find", nil, nil, nil)
`),
    });
    expect(undispatched).toEqual([]);
  });

  test("recognizes constructors, aliases, package handles, receiver fields, and pgx PgConn escape", async () => {
    const constructor = await repositoryInventory({
      "search.go": `package search
import (
	"github.com/jackc/pgx/v5/pgconn"
	"net/http"
)
func Search(w http.ResponseWriter, r *http.Request) {
	conn, _ := pgconn.Connect(r.Context(), "postgres://database")
	query := r.FormValue("query")
	_ = conn.Exec(r.Context(), query)
}`,
    });
    expect(constructor).toHaveLength(1);

    const escape = await repositoryInventory({
      "search.go": `package search
import (
	"github.com/jackc/pgx/v5"
	"net/http"
)
func Search(conn *pgx.Conn, w http.ResponseWriter, r *http.Request) {
	low := conn.PgConn()
	query := r.FormValue("query")
	_ = low.Exec(r.Context(), query)
}`,
    });
    expect(escape).toHaveLength(1);

    const poolEscape = await repositoryInventory({
      "search.go": `package search
import (
\t"github.com/jackc/pgx/v5/pgxpool"
\t"net/http"
)
func Search(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
\tpooled, _ := pool.Acquire(r.Context())
\thigh := pooled.Conn()
\tlow := high.PgConn()
\tquery := r.FormValue("query")
\t_ = low.Exec(r.Context(), query)
}`,
    });
    expect(poolEscape).toHaveLength(1);

    const invalidDirectPoolEscape = await repositoryInventory({
      "search.go": `package search
import (
\t"github.com/jackc/pgx/v5/pgxpool"
\t"net/http"
)
func Search(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
\tlow := pool.PgConn()
\tquery := r.FormValue("query")
\t_ = low.Exec(r.Context(), query)
}`,
    });
    expect(invalidDirectPoolEscape).toEqual([]);

    const typed = await repositoryInventory({
      "search.go": `package search
import (
	pgc "github.com/jackc/pgx/v5/pgconn"
	"net/http"
)
var shared *pgc.PgConn
type Store struct { connection *pgc.PgConn }
func (store *Store) Search(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	_ = shared.Exec(r.Context(), query)
	_ = store.connection.Exec(r.Context(), query)
}`,
    });
    expect(typed).toHaveLength(2);
  });

  test("follows one unique package wrapper and rejects ambiguous or lookalike boundaries", async () => {
    const wrapped = await repositoryInventory({
      "handler.go": `package search
import (
	"github.com/jackc/pgx/v5/pgconn"
	"net/http"
)
func Handler(conn *pgconn.PgConn, w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	Run(r.Context(), conn, query)
}`,
      "run.go": `package search
import (
	"context"
	"github.com/jackc/pgx/v5/pgconn"
)
func Run(ctx context.Context, conn *pgconn.PgConn, query string) {
	_ = conn.Exec(ctx, query)
}`,
    });
    expect(wrapped).toHaveLength(1);
    expect(wrapped[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");

    for (const source of [
      pgconnHandler(
        `\tquery := r.FormValue("query")\n\t_ = conn.Exec(r.Context(), query)`,
        { importPath: "example.com/pgconn" },
      ),
      pgconnHandler(
        `\tquery := r.FormValue("query")\n\t_ = conn.Exec(r.Context(), query)`,
        { importPath: "github.com/jackc/pgx/v4/pgconn" },
      ),
      `package search\nimport ( . "github.com/jackc/pgx/v5/pgconn"; "net/http" )\nfunc Search(conn *PgConn, w http.ResponseWriter, r *http.Request) { query := r.FormValue("query"); _ = conn.Exec(r.Context(), query) }`,
      `package search\nimport "net/http"\ntype PgConn struct{}\nfunc (p *PgConn) Exec(...any) any { return nil }\nfunc Search(conn *PgConn, w http.ResponseWriter, r *http.Request) { query := r.FormValue("query"); _ = conn.Exec(r.Context(), query) }`,
    ]) {
      expect(await repositoryInventory({ "search.go": source })).toEqual([]);
    }
  });

  test("clears fixed selections, query reassignment, and deferred-object replacement", async () => {
    const fixedMap = await repositoryInventory({
      "search.go": pgconnHandler(`
\tqueries := map[string]string{"public": "SELECT name FROM records WHERE visibility = 'public'"}
\tkey := r.FormValue("key")
\tquery := queries[key]
\t_ = conn.Exec(r.Context(), query)
`),
    });
    expect(fixedMap).toEqual([]);

    const reassigned = await repositoryInventory({
      "search.go": pgconnHandler(`
\tquery := r.FormValue("query")
\tquery = "SELECT name FROM records WHERE visibility = 'public'"
\t_ = conn.Exec(r.Context(), query)
`),
    });
    expect(reassigned).toEqual([]);

    const replacedPipeline = await repositoryInventory({
      "search.go": pgconnHandler(`
\tquery := r.FormValue("query")
\tpipeline := conn.StartPipeline(r.Context())
\tpipeline.SendQueryParams(query, nil, nil, nil, nil)
\tpipeline = conn.StartPipeline(r.Context())
\t_ = pipeline.Sync()
`),
    });
    expect(replacedPipeline).toEqual([]);

    const differentPreparedReceiver = await repositoryInventory({
      "search.go": `package search
import (
\t"github.com/jackc/pgx/v5/pgconn"
\t"net/http"
)
func Search(conn *pgconn.PgConn, other *pgconn.PgConn, w http.ResponseWriter, r *http.Request) {
\tquery := r.FormValue("query")
\t_, _ = conn.Prepare(r.Context(), "find", query, nil)
\tvar batch pgconn.Batch
\tbatch.ExecPrepared("find", nil, nil, nil)
\t_ = other.ExecBatch(r.Context(), &batch)
}`,
    });
    expect(differentPreparedReceiver).toEqual([]);
  });

  test("retains pgconn controls and teaches protocol, dispatch, and impact boundaries", async () => {
    const records = await repositoryInventory({
      "search.go": pgconnHandler(
        `
	query := r.FormValue("query")
	query = strings.ReplaceAll(query, "'", "''")
	_, _ = conn.EscapeString(query)
	_ = conn.ExecParams(r.Context(), query, nil, nil, nil, nil)
`,
        { extraImports: '"strings"' },
      ),
    });
    expect(records).toHaveLength(1);
    expect(records[0]?.categories).toContain(
      "candidate-control:manual-sql-escaping",
    );
    expect(records[0]?.categories).toContain(
      "candidate-control:pgconn-escape-string",
    );
    expect(records[0]?.categories).toContain(
      "candidate-control:separate-pgconn-parameter-bytes",
    );

    const prompt = scanQualityGatePrompt("deep");
    expect(prompt).toContain("For go-pgconn-sql-injection rows");
    expect(prompt).toContain(
      "simple query protocol and permits multiple statements",
    );
    expect(prompt).toContain(
      "Pipeline.Close does not flush unsynchronized requests",
    );
    expect(prompt).toContain("CopyFrom and CopyTo execute their SQL command");
    expect(prompt).toContain("concrete unauthorized impact");
  });
});
