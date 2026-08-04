import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoSquirrelRecord {
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
  "go-cross-file-squirrel-sqli",
  "go-cross-file-safe-squirrel",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoSquirrelRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoSquirrelRecord)
    .filter(
      (record) => record.frameworkModel?.id === "go-squirrel-sql-injection",
    );
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoSquirrelRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-go-squirrel-"),
  );
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
  options: {
    squirrelAlias?: string;
    squirrelImport?: string;
    sqlAlias?: string;
    httpAlias?: string;
  } = {},
): string {
  const squirrelAlias = options.squirrelAlias ?? "sq";
  const squirrelImport =
    options.squirrelImport ?? "github.com/Masterminds/squirrel";
  const sqlAlias = options.sqlAlias ?? "sql";
  const httpAlias = options.httpAlias ?? "http";
  const squirrelDeclaration = `${squirrelAlias} "${squirrelImport}"`;
  const sqlDeclaration =
    sqlAlias === "sql" ? '"database/sql"' : `${sqlAlias} "database/sql"`;
  const httpDeclaration =
    httpAlias === "http" ? '"net/http"' : `${httpAlias} "net/http"`;
  return `package search

import (
	${squirrelDeclaration}
	${sqlDeclaration}
	${httpDeclaration}
)

func Search(db *${sqlAlias}.DB, w ${httpAlias}.ResponseWriter, r *${httpAlias}.Request) {
${body}
}
`;
}

describe("Go Squirrel SQL-injection framework model", () => {
  test("keeps the exploit and parameterized control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-squirrel-sql-injection-manifest.json"),
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

  test("preserves the exact handler-to-Where-and-Query path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "search.go",
      line: 12,
      categories: [
        "framework-dataflow:go-squirrel-sql-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-squirrel-builder-execution",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: { kind: "go-http-query-parameter", path: "handler.go" },
        sink: {
          kind: "go-squirrel-builder-execution",
          path: "search.go",
          line: 12,
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
      "go-squirrel-query-construction",
    ]);
    expect(safe).toEqual([]);
  });

  test("requires a proven runner and execution closure", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tsq.Select("secret").From("records").Where(fragment)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tsq.Select("secret").From("records").Where(fragment).Query()`),
      }),
    ).toEqual([]);
    const rows = await repositoryInventory({
      "search.go": handler(`\tfragment := r.FormValue("fragment")
\tsq.Select("secret").From("records").Where(fragment).RunWith(db).Query()`),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      categories: [
        "framework-dataflow:go-squirrel-sql-injection",
        "modeled-source:go-http-form-value",
        "modeled-sink:go-squirrel-builder-execution",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "same-file",
        sink: { cweIds: ["CWE-89"] },
      },
    });
  });

  test("covers every builder family and execution variant", async () => {
    const cases = [
      'sq.Select(fragment).From("records")',
      'sq.Insert(fragment).Columns("secret").Values("x")',
      'sq.Replace(fragment).Columns("secret").Values("x")',
      'sq.Update(fragment).Set("secret", "x")',
      "sq.Delete(fragment)",
    ];
    for (const builder of cases) {
      for (const execution of [
        "Exec()",
        "ExecContext(r.Context())",
        "Query()",
        "QueryContext(r.Context())",
        "QueryRow()",
        "QueryRowContext(r.Context())",
        "Scan(&[]string{})",
        "ScanContext(r.Context(), &[]string{})",
      ]) {
        expect(
          await repositoryInventory({
            "search.go": handler(`\tfragment := r.FormValue("fragment")
\t${builder}.RunWith(db).${execution}`),
          }),
          `${builder}.${execution}`,
        ).toHaveLength(1);
      }
    }
  });

  test("models structural methods and every variadic grammar argument", async () => {
    const cases = [
      'sq.Select("id").Columns("name", fragment).From("records")',
      'sq.Select("id").Options("SQL_CALC_FOUND_ROWS", fragment).From("records")',
      'sq.Select("id").From("records").GroupBy("owner", fragment)',
      'sq.Select("id").From("records").OrderBy("owner", fragment)',
      'sq.Select("id").From(fragment)',
      'sq.Select("id").From("records").Join(fragment)',
      'sq.Select("id").From("records").LeftJoin(fragment)',
      'sq.Select("id").From("records").RightJoin(fragment)',
      'sq.Select("id").From("records").InnerJoin(fragment)',
      'sq.Select("id").From("records").CrossJoin(fragment)',
      'sq.Select("id").From("records").OrderByClause(fragment)',
      'sq.Select("id").From("records").Prefix(fragment)',
      'sq.Select("id").From("records").Suffix(fragment)',
      'sq.Insert("records").Columns("id", fragment).Values(1, 2)',
      'sq.Insert("records").Options("LOW_PRIORITY", fragment).Columns("id").Values(1)',
      'sq.Update("records").Set(fragment, "x")',
      'sq.Update("records").Set("x", 1).OrderBy("id", fragment)',
      'sq.Delete("records").OrderBy("id", fragment)',
    ];
    for (const builder of cases) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tfragment := r.FormValue("fragment")
\t${builder}.RunWith(db).Exec()`),
        }),
        builder,
      ).toHaveLength(1);
    }
  });

  test("keeps placeholder, map, and Eq values out of grammar", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tsq.Select("secret").From("records").Where("status = ?", value).RunWith(db).Query()
\tsq.Select("secret").From("records").Where(map[string]any{"status": value}).RunWith(db).Query()
\tsq.Select("secret").From("records").Where(sq.Eq{"status": value}).RunWith(db).Query()
\tsq.Update("records").Set("status", value).Where(sq.Eq{"id": 1}).RunWith(db).Exec()
\tsq.Insert("records").Columns("status").Values(value).RunWith(db).Exec()`),
      }),
    ).toEqual([]);
  });

  test("tracks assigned builders, StatementBuilder runners, and reassignment", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.StatementBuilder.RunWith(db).Select("secret").From("records").Where(fragment)
\tbuilder = builder.PlaceholderFormat(sq.Dollar)
\tbuilder.Query()`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.Select("secret").From("records").Where(fragment).RunWith(db)
\tbuilder = sq.Select("secret").From("records").RunWith(db)
\tbuilder.Query()`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.Select("secret").From("records").Where(fragment).RunWith(db)
\talias := builder
\talias.Query()`),
      }),
    ).toHaveLength(1);
  });

  test("closes package helpers only with proven runners", async () => {
    for (const call of [
      "sq.ExecWith(db, builder)",
      "sq.QueryWith(db, builder)",
      "sq.QueryRowWith(db, builder)",
      "sq.ExecContextWith(r.Context(), db, builder)",
      "sq.QueryContextWith(r.Context(), db, builder)",
      "sq.QueryRowContextWith(r.Context(), db, builder)",
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.Select("secret").From("records").Where(fragment)
\t${call}`),
        }),
        call,
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tsq.QueryWith(db, sq.Select("secret").From("records").Where(fragment))`),
      }),
    ).toHaveLength(1);
  });

  test("requires materialized SQL to reach typed database execution", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.Select("secret").From("records").Where(fragment)
\tquery, arguments, _ := builder.ToSql()
\t_ = query
\t_ = arguments`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.Select("secret").From("records").Where(fragment)
\tquery, arguments, _ := builder.ToSql()
\tdb.Query(query, arguments...)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.Select("secret").From("records").Where(fragment)
\tquery, arguments := builder.MustSql()
\tdb.QueryContext(r.Context(), query, arguments...)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.Select("secret").From("records").Where(fragment)
\tquery, arguments, _ := builder.ToSql()
\tstatement, _ := db.Prepare(query)
\tstatement.Query(arguments...)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tbuilder := sq.Select("secret").From("records").Where(fragment)
\tquery, _, _ := builder.ToSql()
\tdb.Prepare(query)`),
      }),
    ).toEqual([]);
  });

  test("treats executing DebugSqlizer output as unsafe interpolation", async () => {
    const rows = await repositoryInventory({
      "search.go": handler(`\tvalue := r.FormValue("value")
\tbuilder := sq.Select("secret").From("records").Where("status = ?", value)
\tquery := sq.DebugSqlizer(builder)
\tdb.Query(query)`),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.kind).toBe(
      "go-squirrel-debug-query-execution",
    );
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tbuilder := sq.Select("secret").From("records").Where("status = ?", value)
\tdb.Query(sq.DebugSqlizer(builder))`),
      }),
    ).toHaveLength(1);
  });

  test("tracks Expr, ConcatExpr, Alias, and Case only after embedding and execution", async () => {
    const cases = [
      `expression := sq.Expr(fragment)
\tbuilder := sq.Select("secret").From("records").Where(expression)`,
      `expression := sq.ConcatExpr("status = ", fragment)
\tbuilder := sq.Select("secret").From("records").Where(expression)`,
      `expression := sq.Expr(fragment)
\taliased := sq.Alias(expression, "computed")
\tbuilder := sq.Select("secret").Column(aliased).From("records")`,
      `expression := sq.Case().When(fragment, "1").Else("0")
\tbuilder := sq.Select("secret").Column(expression).From("records")`,
    ];
    for (const setup of cases) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tfragment := r.FormValue("fragment")
\t${setup}
\tbuilder.RunWith(db).Query()`),
        }),
        setup,
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\texpression := sq.Expr("score + ?", value)
\tbuilder := sq.Update("records").Set("score", expression)
\tbuilder.RunWith(db).Exec()`),
      }),
    ).toEqual([]);
    for (const builder of [
      'sq.Insert("records").Columns("score").Values(sq.Expr(fragment))',
      'sq.Update("records").Set("score", sq.Expr(fragment))',
      'sq.Select("secret").From("records").PrefixExpr(sq.Expr(fragment))',
      'sq.Select("secret").From("records").SuffixExpr(sq.ConcatExpr(fragment))',
    ]) {
      expect(
        await repositoryInventory({
          "search.go": handler(`\tfragment := r.FormValue("fragment")
\t${builder}.RunWith(db).Exec()`),
        }),
        builder,
      ).toHaveLength(1);
    }
  });

  test("recognizes typed builder and runner parameters, fields, and caches", async () => {
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  sq "github.com/Masterminds/squirrel"
  "net/http"
)
func Search(builder sq.SelectBuilder, runner sq.BaseRunner, w http.ResponseWriter, r *http.Request) {
  builder.Where(r.FormValue("fragment")).RunWith(runner).Query()
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  sq "github.com/Masterminds/squirrel"
  "net/http"
)
type service struct {
  builder sq.SelectBuilder
  runner sq.BaseRunner
}
func (s *service) Search(w http.ResponseWriter, r *http.Request) {
  s.builder.Where(r.FormValue("fragment")).RunWith(s.runner).Query()
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tcache := sq.NewStmtCache(db)
\tsq.Select("secret").From("records").Where(fragment).RunWith(cache).Query()`),
      }),
    ).toHaveLength(1);
  });

  test("rejects unproven custom runners", async () => {
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  sq "github.com/Masterminds/squirrel"
  "net/http"
)
type localRunner struct{}
func Search(runner localRunner, w http.ResponseWriter, r *http.Request) {
  sq.Select("secret").From("records").Where(r.FormValue("fragment")).RunWith(runner).Query()
}`,
      }),
    ).toEqual([]);
  });

  test("distinguishes SetMap values from dynamic structural keys", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(`\tvalue := r.FormValue("value")
\tsq.Update("records").SetMap(map[string]any{"status": value}).RunWith(db).Exec()
\tsq.Insert("records").SetMap(map[string]any{"status": value}).RunWith(db).Exec()`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tcolumn := r.FormValue("column")
\tsq.Update("records").SetMap(map[string]any{column: "x"}).RunWith(db).Exec()`),
      }),
    ).toHaveLength(1);
  });

  test("follows one unique same-package wrapper", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`\tfragment := r.FormValue("fragment")
\tRunQuery(db, fragment)`),
      "query.go": `package search
import (
  sq "github.com/Masterminds/squirrel"
  "database/sql"
)
func RunQuery(db *sql.DB, fragment string) {
  sq.Select("secret").From("records").Where(fragment).RunWith(db).Query()
}`,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
  });

  test("rejects lookalikes, dot imports, duplicate imports, and untyped builders", async () => {
    expect(
      await repositoryInventory({
        "search.go": handler(
          `\tsq.Select(r.FormValue("fragment")).RunWith(db).Query()`,
          {
            squirrelImport: "example.com/Masterminds/squirrel",
          },
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  . "github.com/Masterminds/squirrel"
  "database/sql"
  "net/http"
)
func Search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  Select(r.FormValue("fragment")).RunWith(db).Query()
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  first "github.com/Masterminds/squirrel"
  second "github.com/Masterminds/squirrel"
  "database/sql"
  "net/http"
)
func Search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  first.Select(r.FormValue("fragment")).RunWith(db).Query()
  _ = second.StatementBuilder
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": `package search
import (
  sq "github.com/Masterminds/squirrel"
  "database/sql"
  "net/http"
)
type localBuilder struct{}
func (localBuilder) Where(any) localBuilder { return localBuilder{} }
func (localBuilder) RunWith(any) localBuilder { return localBuilder{} }
func (localBuilder) Query() {}
func Search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  localBuilder{}.Where(r.FormValue("fragment")).RunWith(db).Query()
  _ = sq.StatementBuilder
}`,
      }),
    ).toEqual([]);
  });

  test("rejects comments, strings, fixed selections, and cleared fragments", async () => {
    expect(
      await repositoryInventory({
        "search.go":
          handler(`\t// sq.Select(r.FormValue("fragment")).RunWith(db).Query()
\texample := "sq.Select(r.FormValue(\\\"fragment\\\")).RunWith(db).Query()"
\t_ = example`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "search.go": handler(`\tfragment := r.FormValue("fragment")
\tfragment = "status = 'public'"
\tsq.Select("secret").From("records").Where(fragment).RunWith(db).Query()`),
      }),
    ).toEqual([]);
  });

  test("retains controls as evidence instead of universal sanitizers", async () => {
    const rows = await repositoryInventory({
      "search.go": `package search
import (
  "context"
  "database/sql"
  "net/http"
  "regexp"
  "strings"
  "time"
  sq "github.com/Masterminds/squirrel"
)
func Search(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  fragment := strings.ReplaceAll(r.FormValue("fragment"), "'", "''")
  if !regexp.MustCompile("^[A-Za-z ]+$").MatchString(fragment) { return }
  ctx, cancel := context.WithTimeout(r.Context(), time.Second)
  defer cancel()
  tx, _ := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
  sq.StatementBuilder.PlaceholderFormat(sq.Dollar).RunWith(tx).Select("secret").From("records").Where(fragment).QueryContext(ctx)
}`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "manual-sql-escaping",
      "query-fragment-allowlist",
      "query-deadline",
      "database-transaction",
      "squirrel-placeholder-format",
    ]);
  });

  test("teaches structural grammar, execution closure, DebugSqlizer, and impact", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "", "");
    expect(prompt).toContain("For go-squirrel-sql-injection rows");
    expect(prompt).toContain("github.com/Masterminds/squirrel");
    expect(prompt).toContain("RunWith");
    expect(prompt).toContain("Where and Having map or Eq-like values");
    expect(prompt).toContain("DebugSqlizer");
    expect(prompt).toContain("concrete unauthorized data or state effect");
  });
});
