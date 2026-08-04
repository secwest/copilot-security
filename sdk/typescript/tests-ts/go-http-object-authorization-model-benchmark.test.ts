import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface ModelRecord {
  path: string;
  line: number;
  categories: string[];
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
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): ModelRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as ModelRecord)
    .filter(
      (record) => record.frameworkModel?.id === "go-http-object-authorization",
    );
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<ModelRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-go-bola-"));
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

async function fixtureInventory(id: string): Promise<ModelRecord[]> {
  return models(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
  );
}

function handler(body: string, sqlImport = '"database/sql"'): string {
  return `package invoices
import (
  ${sqlImport}
  "fmt"
  "net/http"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
${body}
}
`;
}

describe("Go HTTP object-authorization framework model", () => {
  test("keeps the exploit and authorization control under perfect benchmark gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-http-object-authorization-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{ id: string; expected: unknown[] }>;
    };
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "go-cross-file-idor",
      "go-cross-file-safe-authorization",
      "go-cross-file-list-idor",
      "go-cross-file-safe-list-authorization",
      "go-cross-file-prepared-delete-idor",
      "go-cross-file-safe-prepared-delete-authorization",
      "go-cross-file-transaction-delete-idor",
      "go-cross-file-safe-transaction-delete-authorization",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected).toHaveLength(1);
    expect(manifest.cases[3]?.expected).toEqual([]);
    expect(manifest.cases[4]?.expected).toHaveLength(1);
    expect(manifest.cases[5]?.expected).toEqual([]);
    expect(manifest.cases[6]?.expected).toHaveLength(1);
    expect(manifest.cases[7]?.expected).toEqual([]);
  });

  test("models typed query, form, path, and header object identifiers", async () => {
    const sources = [
      ['r.URL.Query().Get("id")', "go-http-query-parameter"],
      ['r.FormValue("id")', "go-http-form-value"],
      ['r.PathValue("id")', "go-http-path-value"],
      ['r.Header.Get("X-Invoice-ID")', "go-http-header"],
    ] as const;
    for (const [expression, kind] of sources) {
      const rows = await repositoryInventory({
        "handler.go": handler(`  id := ${expression}
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
  fmt.Fprint(w, secret)`),
      });
      expect(rows, expression).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.source.kind).toBe(kind);
      expect(rows[0]?.frameworkModel?.sink).toMatchObject({
        kind: "go-database-object-read-response",
        cweIds: ["CWE-639", "CWE-862"],
      });
    }
  });

  test("preserves the exact cross-file exploit and authenticated control", async () => {
    const vulnerable = await fixtureInventory("go-cross-file-idor");
    const safe = await fixtureInventory("go-cross-file-safe-authorization");
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      line: 16,
      categories: [
        "framework-dataflow:go-http-object-authorization",
        "modeled-source:go-http-path-value",
        "modeled-sink:go-database-object-read-response",
      ],
      frameworkModel: {
        scope: "cross-file-wrapper",
        source: { kind: "go-http-path-value", path: "handler.go", line: 9 },
        sink: {
          kind: "go-database-object-read-response",
          path: "store.go",
          line: 16,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators.slice(0, 3)).toEqual([
      {
        kind: "go-object-identifier-assignment",
        path: "handler.go",
        line: 9,
        symbol: "invoiceID",
      },
      {
        kind: "go-function-argument",
        path: "handler.go",
        line: 10,
        symbol: "WriteInvoice[2]",
      },
      {
        kind: "go-string-parameter",
        path: "store.go",
        line: 9,
        symbol: "invoiceID",
      },
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 11 },
    ]);
  });

  test("requires Scan and disclosure of the selected data", async () => {
    for (const body of [
      `  id := r.PathValue("id")
  row := db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id)
  _ = row`,
      `  id := r.PathValue("id")
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
  fmt.Fprint(w, "done")`,
    ]) {
      expect(
        await repositoryInventory({ "handler.go": handler(body) }),
        body,
      ).toEqual([]);
    }
  });

  test("preserves the exact cross-file collection exploit and scoped control", async () => {
    const vulnerable = await fixtureInventory("go-cross-file-list-idor");
    const safe = await fixtureInventory(
      "go-cross-file-safe-list-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      line: 22,
      categories: [
        "framework-dataflow:go-http-object-authorization",
        "modeled-source:go-http-path-value",
        "modeled-sink:go-database-object-collection-response",
      ],
      frameworkModel: {
        scope: "cross-file-wrapper",
        source: { kind: "go-http-path-value", path: "handler.go", line: 9 },
        sink: {
          kind: "go-database-object-collection-response",
          path: "store.go",
          line: 22,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-object-identifier-assignment",
      "go-function-argument",
      "go-string-parameter",
      "go-sql-object-predicate",
      "go-sql-rows-iteration",
      "go-sql-rows-scan",
      "go-http-protected-response",
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 11 },
    ]);
  });

  test("requires Query rows to reach Next, Scan, and selected-data disclosure", async () => {
    const vulnerableBodies = [
      `  id := r.PathValue("projectID")
  rows, _ := db.Query("SELECT secret FROM invoices WHERE project_id = ?", id)
  for rows.Next() {
    var secret string
    rows.Scan(&secret)
    fmt.Fprint(w, secret)
  }`,
      `  id := r.PathValue("projectID")
  rows, _ := db.QueryContext(r.Context(), "SELECT secret FROM invoices WHERE project_id = ?", id)
  alias := rows
  for alias.Next() {
    var secret string
    alias.Scan(&secret)
    fmt.Fprint(w, secret)
  }`,
    ];
    for (const body of vulnerableBodies) {
      const rows = await repositoryInventory({
        "handler.go": handler(body),
      });
      expect(rows, body).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-database-object-collection-response",
      );
    }

    for (const body of [
      `  id := r.PathValue("projectID")
  rows, _ := db.Query("SELECT secret FROM invoices WHERE project_id = ?", id)
  var secret string
  rows.Scan(&secret)
  fmt.Fprint(w, secret)`,
      `  id := r.PathValue("projectID")
  rows, _ := db.Query("SELECT secret FROM invoices WHERE project_id = ?", id)
  rows.Next()
  var secret string
  rows.Scan(&secret)
  fmt.Fprint(w, secret)`,
      `  id := r.PathValue("projectID")
  rows, _ := db.Query("SELECT secret FROM invoices WHERE project_id = ?", id)
  for rows.Next() {
    fmt.Fprint(w, "done")
  }`,
      `  id := r.PathValue("projectID")
  rows, _ := db.Query("SELECT secret FROM invoices WHERE project_id = ?", id)
  for rows.Next() {
    var secret string
    rows.Scan(&secret)
    fmt.Fprint(w, "done")
  }`,
      `  id := r.PathValue("invoiceID")
  db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id)
  var secret string
  other.Scan(&secret)
  fmt.Fprint(w, secret)`,
    ]) {
      expect(
        await repositoryInventory({ "handler.go": handler(body) }),
        body,
      ).toEqual([]);
    }
  });

  test("models UPDATE and DELETE as immediate protected effects", async () => {
    for (const query of [
      "UPDATE invoices SET status = 'paid' WHERE id = ?",
      "DELETE FROM invoices WHERE invoice_id = $1",
    ]) {
      const rows = await repositoryInventory({
        "handler.go": handler(`  id := r.PathValue("id")
  db.Exec(${JSON.stringify(query)}, id)`),
      });
      expect(rows, query).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-database-object-mutation",
      );
    }
  });

  test("preserves the exact prepared mutation exploit and scoped control", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-file-prepared-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-file-safe-prepared-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      categories: [
        "framework-dataflow:go-http-object-authorization",
        "modeled-source:go-http-path-value",
        "modeled-sink:go-database-object-mutation",
      ],
      frameworkModel: {
        scope: "cross-file-wrapper",
        source: { kind: "go-http-path-value", path: "handler.go", line: 9 },
        sink: {
          kind: "go-database-object-mutation",
          path: "store.go",
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-object-identifier-assignment",
      "go-function-argument",
      "go-string-parameter",
      "go-sql-statement-prepare",
      "go-sql-object-predicate",
      "go-sql-statement-execution",
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 19 },
    ]);
  });

  test("preserves the exact committed transaction exploit and scoped control", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-file-transaction-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-file-safe-transaction-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      line: 22,
      categories: [
        "framework-dataflow:go-http-object-authorization",
        "modeled-source:go-http-path-value",
        "modeled-sink:go-database-object-committed-mutation",
      ],
      frameworkModel: {
        scope: "cross-file-wrapper",
        source: { kind: "go-http-path-value", path: "handler.go", line: 9 },
        sink: {
          kind: "go-database-object-committed-mutation",
          path: "store.go",
          line: 22,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-object-identifier-assignment",
      "go-function-argument",
      "go-string-parameter",
      "go-sql-object-predicate",
      "go-sql-mutation-execution",
      "go-sql-transaction-commit",
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 19 },
    ]);
  });

  test("closes Prepare and PrepareContext through the exact Stmt execution", async () => {
    const bodies = [
      `  id := r.PathValue("invoiceID")
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  defer stmt.Close()
  stmt.Exec(id)`,
      `  id := r.PathValue("invoiceID")
  stmt, _ := db.PrepareContext(r.Context(), "UPDATE invoices SET status = 'void' WHERE id = $1")
  alias := stmt
  defer alias.Close()
  alias.ExecContext(r.Context(), id)`,
    ];
    for (const body of bodies) {
      const rows = await repositoryInventory({ "handler.go": handler(body) });
      expect(rows, body).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-database-object-mutation",
      );
      expect(
        rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toContain("go-sql-statement-execution");
    }
  });

  test("rejects unexecuted, closed, replaced, unrelated, and non-mutation statements", async () => {
    for (const body of [
      `  id := r.PathValue("invoiceID")
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  _ = stmt
  _ = id`,
      `  id := r.PathValue("invoiceID")
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  stmt.Close()
  stmt.Exec(id)`,
      `  id := r.PathValue("invoiceID")
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  alias := stmt
  alias.Close()
  stmt.Exec(id)`,
      `  id := r.PathValue("invoiceID")
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  stmt, _ = db.Prepare("INSERT INTO invoices(id) VALUES (?)")
  stmt.Exec(id)`,
      `  id := r.PathValue("invoiceID")
  stmt, _ := db.Prepare("SELECT secret FROM invoices WHERE id = ?")
  stmt.Exec(id)`,
      `  id := r.PathValue("invoiceID")
  db.Exec("UPDATELOG records SET value = 1 WHERE id = ?", id)`,
      `  id := r.PathValue("invoiceID")
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  other.Exec(id)
  _ = stmt`,
    ]) {
      expect(
        await repositoryInventory({ "handler.go": handler(body) }),
        body,
      ).toEqual([]);
    }
  });

  test("supports prepared mutations on exact DB, Tx, and Conn receivers", async () => {
    for (const receiverType of ["DB", "Tx", "Conn"]) {
      const source = `package invoices
import (
  "database/sql"
  "net/http"
)
func Handler(db *sql.${receiverType}, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  defer stmt.Close()
  stmt.Exec(id)
${receiverType === "Tx" ? "  db.Commit()" : ""}
}`;
      const rows = await repositoryInventory({ "handler.go": source });
      expect(rows, receiverType).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        receiverType === "Tx"
          ? "go-database-object-committed-mutation"
          : "go-database-object-mutation",
      );
    }
  });

  test("requires transaction mutations to reach an exact top-level Commit", async () => {
    const bodies = [
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  defer tx.Rollback()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`,
      `  id := r.PathValue("invoiceID")
  tx, _ := db.BeginTx(r.Context(), nil)
  alias := tx
  alias.ExecContext(r.Context(), "DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`,
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  _, err := tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  if err != nil {
    tx.Rollback()
    return
  }
  if err := tx.Commit(); err != nil {
    return
  }`,
    ];
    for (const body of bodies) {
      const rows = await repositoryInventory({ "handler.go": handler(body) });
      expect(rows, body).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-database-object-committed-mutation",
      );
      expect(
        rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toContain("go-sql-transaction-commit");
    }
  });

  test("rejects transaction mutations without durable commit closure", async () => {
    for (const body of [
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)`,
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Rollback()`,
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Commit()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)`,
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  if id != "" {
    tx.Commit()
  }`,
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  defer tx.Commit()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)`,
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  alias := tx
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  alias.Rollback()
  tx.Commit()`,
    ]) {
      expect(
        await repositoryInventory({ "handler.go": handler(body) }),
        body,
      ).toEqual([]);
    }
  });

  test("closes transaction-prepared mutations only through transaction commit", async () => {
    const committed = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  stmt, _ := tx.Prepare("DELETE FROM invoices WHERE id = ?")
  defer stmt.Close()
  stmt.Exec(id)
  tx.Commit()`),
    });
    expect(committed).toHaveLength(1);
    expect(committed[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-object-committed-mutation",
    );
    expect(
      committed[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-object-identifier-assignment",
      "go-sql-statement-prepare",
      "go-sql-object-predicate",
      "go-sql-statement-execution",
      "go-sql-transaction-commit",
    ]);

    const rolledBack = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  stmt, _ := tx.Prepare("DELETE FROM invoices WHERE id = ?")
  stmt.Exec(id)
  tx.Rollback()`),
    });
    expect(rolledBack).toEqual([]);
  });

  test("tracks typed transaction parameters through commit", async () => {
    const source = `package invoices
import (
  "database/sql"
  "net/http"
)
func Handler(tx *sql.Tx, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()
}`;
    const rows = await repositoryInventory({ "handler.go": source });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-object-committed-mutation",
    );
  });

  test("maps prepared positional and named arguments and trusts only context principals", async () => {
    const safe = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  accountID := r.Context().Value(authenticatedAccountIDKey).(string)
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = :invoice AND account_id = :account")
  defer stmt.Close()
  stmt.Exec(sql.Named("invoice", id), sql.Named("account", accountID))`),
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toHaveLength(1);

    const attackerControlled = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  accountID := r.Header.Get("X-Account-ID")
  stmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ? AND account_id = ?")
  defer stmt.Close()
  stmt.Exec(id, accountID)`),
    });
    expect(attackerControlled).toHaveLength(1);
    expect(attackerControlled[0]?.frameworkModel?.candidateControls).toEqual(
      [],
    );
  });

  test("records only context-derived principal query controls", async () => {
    const safe = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("id")
  accountID := r.Context().Value(authenticatedAccountIDKey).(string)
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ? AND account_id = ?", id, accountID).Scan(&secret)
  fmt.Fprint(w, secret)`),
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "principal-bound-object-query",
      path: "handler.go",
      line: 11,
    });

    const attackerControlled = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("id")
  accountID := r.Header.Get("X-Account-ID")
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ? AND account_id = ?", id, accountID).Scan(&secret)
  fmt.Fprint(w, secret)`),
    });
    expect(attackerControlled).toHaveLength(1);
    expect(attackerControlled[0]?.frameworkModel?.candidateControls).toEqual(
      [],
    );

    const securityNamedObject = await repositoryInventory({
      "handler.go": handler(`  accountID := r.PathValue("accountID")
  var secret string
  db.QueryRow("SELECT secret FROM accounts WHERE account_id = ?", accountID).Scan(&secret)
  fmt.Fprint(w, secret)`),
    });
    expect(securityNamedObject).toHaveLength(1);
    expect(securityNamedObject[0]?.frameworkModel?.candidateControls).toEqual(
      [],
    );
  });

  test("supports positional, numbered, and sql.Named predicates", async () => {
    const cases = [
      [`"SELECT secret FROM invoices WHERE id = ?"`, "id"],
      [`"SELECT secret FROM invoices WHERE id = $1"`, "id"],
      [
        `"SELECT secret FROM invoices WHERE id = :invoice"`,
        `sql.Named("invoice", id)`,
      ],
    ];
    for (const [query, argument] of cases) {
      expect(
        await repositoryInventory({
          "handler.go": handler(`  id := r.PathValue("id")
  var secret string
  db.QueryRow(${query}, ${argument}).Scan(&secret)
  fmt.Fprint(w, secret)`),
        }),
        query,
      ).toHaveLength(1);
    }
  });

  test("requires exact database/sql receivers and fixed SQL", async () => {
    expect(
      await repositoryInventory({
        "handler.go": handler(`  id := r.PathValue("id")
  query := "SELECT secret FROM invoices WHERE id = " + id
  var secret string
  db.QueryRow(query).Scan(&secret)
  fmt.Fprint(w, secret)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  id := r.PathValue("id")
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
  fmt.Fprint(w, secret)`,
          '"example.com/database/sql"',
        ),
      }),
    ).toEqual([]);
  });

  test("supports DB, Tx, Conn, inferred handles, and fixed query constants", async () => {
    for (const [receiverType, receiver] of [
      ["DB", "db"],
      ["Tx", "db"],
      ["Conn", "db"],
    ]) {
      const source = `package invoices
import (
  "database/sql"
  "fmt"
  "net/http"
)
func Handler(db *sql.${receiverType}, w http.ResponseWriter, r *http.Request) {
  const query = "SELECT secret FROM invoices WHERE invoice_id = ?"
  id := r.PathValue("id")
  var secret string
  ${receiver}.QueryRow(query, id).Scan(&secret)
  fmt.Fprint(w, secret)
}`;
      expect(
        await repositoryInventory({ "handler.go": source }),
        receiverType,
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "handler.go": `package invoices
import (
  "database/sql"
  "fmt"
  "net/http"
)
func Handler(w http.ResponseWriter, r *http.Request) {
  db, _ := sql.Open("driver", "")
  tx, _ := db.Begin()
  id := r.PathValue("id")
  var secret string
  tx.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
  fmt.Fprint(w, secret)
}`,
      }),
    ).toHaveLength(1);
  });

  test("retains a fail-closed post-lookup ownership check as control evidence", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("id")
  accountID := r.Context().Value(authenticatedAccountIDKey).(string)
  var ownerID, secret string
  db.QueryRow("SELECT owner_id, secret FROM invoices WHERE id = ?", id).Scan(&ownerID, &secret)
  if ownerID != accountID {
    return
  }
  fmt.Fprint(w, secret)`),
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual(["post-lookup-principal-check"]);
  });

  test("treats immutable object maps as fixed selection and rejects ambiguous wrappers", async () => {
    expect(
      await repositoryInventory({
        "handler.go":
          handler(`  allowed := map[string]string{"mine": "attacker-invoice"}
  id := allowed[r.PathValue("name")]
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
  fmt.Fprint(w, secret)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": `package invoices
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { WriteInvoice(w, r.PathValue("id")) }`,
        "first.go": `package invoices
import ("database/sql"; "fmt"; "net/http")
func WriteInvoice(db *sql.DB, w http.ResponseWriter, id string) {
 var secret string
 db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
 fmt.Fprint(w, secret)
}`,
        "second.go": `package invoices
import ("database/sql"; "fmt"; "net/http")
func WriteInvoice(db *sql.DB, w http.ResponseWriter, id string) {
 var secret string
 db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
 fmt.Fprint(w, secret)
}`,
      }),
    ).toEqual([]);
  });

  test("follows one unique same-package wrapper and validates principal provenance", async () => {
    const handlerSource = (principal: string) => `package invoices
import (
  "database/sql"
  "net/http"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("id")
  accountID := ${principal}
  WriteInvoice(db, w, id, accountID)
}`;
    const wrapper = `package invoices
import (
  "database/sql"
  "fmt"
  "net/http"
)
func WriteInvoice(db *sql.DB, w http.ResponseWriter, id, accountID string) {
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ? AND account_id = ?", id, accountID).Scan(&secret)
  fmt.Fprint(w, secret)
}`;
    const safe = await repositoryInventory({
      "handler.go": handlerSource(
        "r.Context().Value(authenticatedAccountIDKey).(string)",
      ),
      "store.go": wrapper,
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(
      safe[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual(["principal-bound-object-query"]);
    const unsafe = await repositoryInventory({
      "handler.go": handlerSource('r.Header.Get("X-Account-ID")'),
      "store.go": wrapper,
    });
    expect(unsafe).toHaveLength(1);
    expect(unsafe[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("rejects fixed and reassigned identifiers, comments, and strings", async () => {
    for (const body of [
      `  id := "fixed"
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
  fmt.Fprint(w, secret)`,
      `  id := r.PathValue("id")
  id = "fixed"
  var secret string
  db.QueryRow("SELECT secret FROM invoices WHERE id = ?", id).Scan(&secret)
  fmt.Fprint(w, secret)`,
      `  // db.QueryRow("SELECT secret FROM invoices WHERE id = ?", r.PathValue("id")).Scan(&secret)
  example := "db.QueryRow SELECT secret FROM invoices WHERE id = ?"
  fmt.Fprint(w, example)`,
    ]) {
      expect(
        await repositoryInventory({ "handler.go": handler(body) }),
        body,
      ).toEqual([]);
    }
  });

  test("adds dedicated quality-gate guidance", () => {
    const prompt = scanQualityGatePrompt(
      "inventory.jsonl",
      "coverage.json",
      "findings.json",
    );
    expect(prompt).toContain("go-http-object-authorization");
    expect(prompt).toContain("context-derived");
  });
});
