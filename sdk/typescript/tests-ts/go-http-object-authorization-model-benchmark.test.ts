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

async function scopedRepositoryInventory(
  files: Record<string, string>,
): Promise<ModelRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-go-bola-"));
  const scanDirectory = await mkdtemp(
    join(tmpdir(), "copilot-security-go-bola-scan-"),
  );
  temporaryPaths.push(repository, scanDirectory);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  const inventory = join(
    scanDirectory,
    "artifacts",
    "02_discovery",
    "in_scope_files.txt",
  );
  await mkdir(dirname(inventory), { recursive: true });
  await writeFile(inventory, `${Object.keys(files).sort().join("\n")}\n`);
  return models(await buildResidualRiskInventory(repository, scanDirectory));
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
      "go-cross-file-transaction-stmt-delete-idor",
      "go-cross-file-safe-transaction-stmt-delete-authorization",
      "go-cross-file-helper-transaction-delete-idor",
      "go-cross-file-safe-helper-transaction-delete-authorization",
      "go-cross-file-helper-chain-transaction-delete-idor",
      "go-cross-file-safe-helper-chain-transaction-delete-authorization",
      "go-cross-package-helper-transaction-delete-idor",
      "go-cross-package-safe-helper-transaction-delete-authorization",
      "go-cross-package-transaction-factory-delete-idor",
      "go-cross-package-safe-transaction-factory-delete-authorization",
      "go-cross-package-transaction-function-value-delete-idor",
      "go-cross-package-safe-transaction-function-value-delete-authorization",
      "go-cross-package-wrapper-chain-delete-idor",
      "go-cross-package-safe-wrapper-chain-delete-authorization",
      "go-cross-package-method-interface-delete-idor",
      "go-cross-package-safe-method-interface-delete-authorization",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected).toHaveLength(1);
    expect(manifest.cases[3]?.expected).toEqual([]);
    expect(manifest.cases[4]?.expected).toHaveLength(1);
    expect(manifest.cases[5]?.expected).toEqual([]);
    expect(manifest.cases[6]?.expected).toHaveLength(1);
    expect(manifest.cases[7]?.expected).toEqual([]);
    expect(manifest.cases[8]?.expected).toHaveLength(1);
    expect(manifest.cases[9]?.expected).toEqual([]);
    expect(manifest.cases[10]?.expected).toHaveLength(1);
    expect(manifest.cases[11]?.expected).toEqual([]);
    expect(manifest.cases[12]?.expected).toHaveLength(1);
    expect(manifest.cases[13]?.expected).toEqual([]);
    expect(manifest.cases[14]?.expected).toHaveLength(1);
    expect(manifest.cases[15]?.expected).toEqual([]);
    expect(manifest.cases[16]?.expected).toHaveLength(1);
    expect(manifest.cases[17]?.expected).toEqual([]);
    expect(manifest.cases[18]?.expected).toHaveLength(1);
    expect(manifest.cases[19]?.expected).toEqual([]);
    expect(manifest.cases[20]?.expected).toHaveLength(1);
    expect(manifest.cases[21]?.expected).toEqual([]);
    expect(manifest.cases[22]?.expected).toHaveLength(1);
    expect(manifest.cases[23]?.expected).toEqual([]);
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

  test("preserves the exact transferred-statement exploit and scoped control", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-file-transaction-stmt-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-file-safe-transaction-stmt-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      line: 25,
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
          line: 25,
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
      "go-sql-transaction-statement-transfer",
      "go-sql-object-predicate",
      "go-sql-statement-execution",
      "go-sql-transaction-commit",
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 22 },
    ]);
  });

  test("preserves the helper-committed exploit, control, and commit evidence path", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-file-helper-transaction-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-file-safe-helper-transaction-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      line: 18,
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
          line: 18,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual([
      {
        kind: "go-object-identifier-assignment",
        line: 9,
        symbol: "invoiceID",
        path: "handler.go",
      },
      {
        kind: "go-function-argument",
        line: 10,
        symbol: "DeleteInvoice[2]",
        path: "handler.go",
      },
      {
        kind: "go-string-parameter",
        line: 8,
        symbol: "invoiceID",
        path: "store.go",
      },
      {
        kind: "go-sql-object-predicate",
        line: 15,
        symbol: "id",
        path: "store.go",
      },
      {
        kind: "go-sql-mutation-execution",
        line: 15,
        symbol: "tx",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-finalizer-helper",
        line: 18,
        symbol: "CommitTransaction",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-commit",
        line: 6,
        symbol: "tx",
        path: "transaction.go",
      },
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 15 },
    ]);
  });

  test("preserves the helper-chain exploit, control, and every finalizer boundary", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-file-helper-chain-transaction-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-file-safe-helper-chain-transaction-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      line: 18,
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
          line: 18,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          kind === "go-sql-transaction-finalizer-helper" ||
          kind === "go-sql-transaction-commit",
      ),
    ).toEqual([
      {
        kind: "go-sql-transaction-finalizer-helper",
        line: 18,
        symbol: "FinalizeTransaction",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-finalizer-helper",
        line: 8,
        symbol: "CommitTransaction",
        path: "coordinator.go",
      },
      {
        kind: "go-sql-transaction-commit",
        line: 6,
        symbol: "tx",
        path: "transaction.go",
      },
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 15 },
    ]);
  });

  test("preserves the cross-package helper-chain exploit and control", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-package-helper-transaction-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-package-safe-helper-transaction-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      line: 19,
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
          line: 19,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          kind === "go-sql-transaction-finalizer-helper" ||
          kind === "go-sql-transaction-commit",
      ),
    ).toEqual([
      {
        kind: "go-sql-transaction-finalizer-helper",
        line: 19,
        symbol: "FinalizeTransaction",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-finalizer-helper",
        line: 11,
        symbol: "CommitTransaction",
        path: "internal/txguard/coordinator.go",
      },
      {
        kind: "go-sql-transaction-commit",
        line: 6,
        symbol: "tx",
        path: "internal/txleaf/transaction.go",
      },
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 16 },
    ]);
  });

  test("preserves the cross-package transaction-factory exploit and control", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-package-transaction-factory-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-package-safe-transaction-factory-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "store.go",
      line: 19,
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
          line: 19,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          /^go-sql-transaction-begin/u.test(kind) ||
          kind === "go-sql-transaction-commit",
      ),
    ).toEqual([
      {
        kind: "go-sql-transaction-begin-helper",
        line: 10,
        symbol: "StartTransaction",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-begin-helper",
        line: 11,
        symbol: "OpenTransaction",
        path: "internal/txfactory/coordinator.go",
      },
      {
        kind: "go-sql-transaction-begin",
        line: 9,
        symbol: "db",
        path: "internal/txleaf/transaction.go",
      },
      {
        kind: "go-sql-transaction-commit",
        line: 19,
        symbol: "tx",
        path: "store.go",
      },
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 16 },
    ]);
  });

  test("preserves the transaction-function-value exploit and control", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-package-transaction-function-value-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-package-safe-transaction-function-value-delete-authorization",
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
      vulnerable[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          kind === "go-sql-transaction-helper-function-value" ||
          /^go-sql-transaction-begin/u.test(kind) ||
          /^go-sql-transaction-finalizer/u.test(kind) ||
          kind === "go-sql-transaction-commit",
      ),
    ).toEqual([
      {
        kind: "go-sql-transaction-helper-function-value",
        line: 11,
        symbol: "factory.StartTransaction",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-begin-helper",
        line: 12,
        symbol: "StartTransaction",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-helper-function-value",
        line: 10,
        symbol: "leaf.OpenTransaction",
        path: "internal/txfactory/coordinator.go",
      },
      {
        kind: "go-sql-transaction-begin-helper",
        line: 11,
        symbol: "OpenTransaction",
        path: "internal/txfactory/coordinator.go",
      },
      {
        kind: "go-sql-transaction-begin",
        line: 9,
        symbol: "db",
        path: "internal/txleaf/transaction.go",
      },
      {
        kind: "go-sql-transaction-helper-function-value",
        line: 21,
        symbol: "guard.FinalizeTransaction",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-finalizer-helper",
        line: 22,
        symbol: "FinalizeTransaction",
        path: "store.go",
      },
      {
        kind: "go-sql-transaction-helper-function-value",
        line: 9,
        symbol: "leaf.CommitTransaction",
        path: "internal/txguard/coordinator.go",
      },
      {
        kind: "go-sql-transaction-finalizer-helper",
        line: 10,
        symbol: "CommitTransaction",
        path: "internal/txguard/coordinator.go",
      },
      {
        kind: "go-sql-transaction-commit",
        line: 13,
        symbol: "tx",
        path: "internal/txleaf/transaction.go",
      },
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      { kind: "principal-bound-object-query", path: "store.go", line: 18 },
    ]);
  });

  test("preserves the cross-package object-wrapper exploit and control", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-package-wrapper-chain-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-package-safe-wrapper-chain-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "internal/invoicestore/store.go",
      line: 9,
      categories: [
        "framework-dataflow:go-http-object-authorization",
        "modeled-source:go-http-path-value",
        "modeled-sink:go-database-object-mutation",
      ],
      frameworkModel: {
        scope: "cross-file-wrapper",
        source: { kind: "go-http-path-value", path: "handler.go", line: 10 },
        sink: {
          kind: "go-database-object-mutation",
          path: "internal/invoicestore/store.go",
          line: 9,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          kind === "go-object-identifier-assignment" ||
          kind === "go-function-argument" ||
          kind === "go-string-parameter",
      ),
    ).toEqual([
      {
        kind: "go-object-identifier-assignment",
        line: 10,
        symbol: "invoiceID",
        path: "handler.go",
      },
      {
        kind: "go-function-argument",
        line: 11,
        symbol: "DeleteInvoice[2]",
        path: "handler.go",
      },
      {
        kind: "go-string-parameter",
        line: 9,
        symbol: "invoiceID",
        path: "internal/invoicesvc/service.go",
      },
      {
        kind: "go-object-identifier-assignment",
        line: 10,
        symbol: "selected",
        path: "internal/invoicesvc/service.go",
      },
      {
        kind: "go-function-argument",
        line: 11,
        symbol: "DeleteInvoice[2]",
        path: "internal/invoicesvc/service.go",
      },
      {
        kind: "go-string-parameter",
        line: 8,
        symbol: "invoiceID",
        path: "internal/invoicestore/store.go",
      },
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]).toMatchObject({
      path: "internal/invoicestore/store.go",
      line: 9,
      frameworkModel: {
        source: { kind: "go-http-path-value", path: "handler.go", line: 14 },
        candidateControls: [
          {
            kind: "principal-bound-object-query",
            path: "internal/invoicestore/store.go",
            line: 9,
          },
        ],
      },
    });
  });

  test("preserves the concrete-method and interface-bound exploit and control", async () => {
    const vulnerable = await fixtureInventory(
      "go-cross-package-method-interface-delete-idor",
    );
    const safe = await fixtureInventory(
      "go-cross-package-safe-method-interface-delete-authorization",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "internal/invoicestore/store.go",
      line: 11,
      frameworkModel: {
        scope: "cross-file-wrapper",
        source: { kind: "go-http-path-value", path: "handler.go", line: 10 },
        sink: {
          kind: "go-database-object-mutation",
          path: "internal/invoicestore/store.go",
          line: 11,
          cweIds: ["CWE-639", "CWE-862"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.filter(({ kind }) =>
        [
          "go-method-receiver-binding",
          "go-interface-receiver-binding",
          "go-object-identifier-assignment",
          "go-function-argument",
          "go-string-parameter",
        ].includes(kind),
      ),
    ).toEqual([
      {
        kind: "go-object-identifier-assignment",
        line: 10,
        symbol: "invoiceID",
        path: "handler.go",
      },
      {
        kind: "go-method-receiver-binding",
        line: 11,
        symbol: "invoices:service.Service",
        path: "handler.go",
      },
      {
        kind: "go-function-argument",
        line: 12,
        symbol: "DeleteInvoice[2]",
        path: "handler.go",
      },
      {
        kind: "go-string-parameter",
        line: 15,
        symbol: "invoiceID",
        path: "internal/invoicesvc/service.go",
      },
      {
        kind: "go-interface-receiver-binding",
        line: 17,
        symbol: "invoices:repository.Store",
        path: "internal/invoicesvc/service.go",
      },
      {
        kind: "go-object-identifier-assignment",
        line: 16,
        symbol: "selected",
        path: "internal/invoicesvc/service.go",
      },
      {
        kind: "go-function-argument",
        line: 18,
        symbol: "DeleteInvoice[2]",
        path: "internal/invoicesvc/service.go",
      },
      {
        kind: "go-string-parameter",
        line: 10,
        symbol: "invoiceID",
        path: "internal/invoicestore/store.go",
      },
    ]);
    expect(safe).toHaveLength(1);
    expect(safe[0]).toMatchObject({
      path: "internal/invoicestore/store.go",
      line: 11,
      frameworkModel: {
        source: { kind: "go-http-path-value", path: "handler.go", line: 14 },
        candidateControls: [
          {
            kind: "principal-bound-object-query",
            path: "internal/invoicestore/store.go",
            line: 11,
          },
        ],
      },
    });
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

  test("creates transactions through exact typed constructor helpers", async () => {
    const helpers = [
      `package invoices
import "database/sql"
func start(db *sql.DB) (*sql.Tx, error) {
  selected := db
  return selected.Begin()
}`,
      `package invoices
import "database/sql"
func start(db *sql.DB) (*sql.Tx, error) {
  tx, err := db.Begin()
  return tx, err
}`,
    ];
    for (const [index, helper] of helpers.entries()) {
      const invocation =
        index === 0
          ? "tx, _ := start(db)"
          : "selected := db\n  tx, _ := start(selected)";
      const rows = await repositoryInventory({
        "handler.go": handler(`  id := r.PathValue("invoiceID")
  ${invocation}
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`),
        "transaction.go": helper,
      });
      expect(rows, helper).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-database-object-committed-mutation",
      );
      expect(
        rows[0]?.frameworkModel?.propagators.filter(({ kind }) =>
          /^go-sql-transaction-begin/u.test(kind),
        ),
      ).toEqual([
        {
          kind: "go-sql-transaction-begin-helper",
          path: "handler.go",
          line: index === 0 ? 9 : 10,
          symbol: "start",
        },
        {
          kind: "go-sql-transaction-begin",
          path: "transaction.go",
          line: helper.includes("selected.Begin") ? 5 : 4,
          symbol: helper.includes("selected.Begin") ? "selected" : "db",
        },
      ]);
    }
  });

  test("creates a transaction through an exact sql Conn helper", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  conn, _ := db.Conn(r.Context())
  tx, _ := start(r.Context(), conn)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`),
      "transaction.go": `package invoices
import (
  "context"
  "database/sql"
)
func start(ctx context.Context, conn *sql.Conn) (*sql.Tx, error) {
  return conn.BeginTx(ctx, nil)
}`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "go-sql-transaction-begin",
      ),
    ).toEqual({
      kind: "go-sql-transaction-begin",
      path: "transaction.go",
      line: 7,
      symbol: "conn",
    });
  });

  test("composes exact cross-package transaction constructor chains", async () => {
    const rows = await scopedRepositoryInventory({
      "go.mod": `module example.com/billing
go 1.26`,
      "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
  factory "example.com/billing/internal/txfactory"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := factory.Start(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()
}`,
      "internal/txfactory/coordinator.go": `package txfactory
import (
  "database/sql"
  leaf "example.com/billing/internal/txleaf"
)
func Start(db *sql.DB) (*sql.Tx, error) {
  selected := db
  return leaf.Open(selected)
}`,
      "internal/txleaf/transaction.go": `package txleaf
import "database/sql"
func Open(db *sql.DB) (*sql.Tx, error) { return db.Begin() }`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.filter(({ kind }) =>
        /^go-sql-transaction-begin/u.test(kind),
      ),
    ).toEqual([
      {
        kind: "go-sql-transaction-begin-helper",
        path: "handler.go",
        line: 9,
        symbol: "Start",
      },
      {
        kind: "go-sql-transaction-begin-helper",
        path: "internal/txfactory/coordinator.go",
        line: 8,
        symbol: "Open",
      },
      {
        kind: "go-sql-transaction-begin",
        path: "internal/txleaf/transaction.go",
        line: 3,
        symbol: "db",
      },
    ]);
  });

  test("creates transactions through exact local function values", async () => {
    const rows = await scopedRepositoryInventory({
      "go.mod": `module example.com/billing
go 1.26`,
      "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
  factory "example.com/billing/internal/txfactory"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  begin := factory.Start
  selected := begin
  tx, _ := selected(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()
}`,
      "internal/txfactory/transaction.go": `package txfactory
import "database/sql"
func Start(db *sql.DB) (*sql.Tx, error) { return db.Begin() }`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          kind === "go-sql-transaction-helper-function-value" ||
          kind === "go-sql-transaction-begin-helper",
      ),
    ).toEqual([
      {
        kind: "go-sql-transaction-helper-function-value",
        path: "handler.go",
        line: 9,
        symbol: "factory.Start",
      },
      {
        kind: "go-sql-transaction-helper-function-value",
        path: "handler.go",
        line: 10,
        symbol: "begin",
      },
      {
        kind: "go-sql-transaction-begin-helper",
        path: "handler.go",
        line: 11,
        symbol: "Start",
      },
    ]);
  });

  test("accepts eight transaction function-value aliases and rejects nine", async () => {
    const files = {
      "transaction.go": `package invoices
import "database/sql"
func start(db *sql.DB) (*sql.Tx, error) { return db.Begin() }`,
    };
    const body = (count: number) => {
      const assignments = Array.from({ length: count }, (_, index) =>
        index === 0 ? "begin0 := start" : `begin${index} := begin${index - 1}`,
      ).join("\n  ");
      return `  id := r.PathValue("invoiceID")
  ${assignments}
  tx, _ := begin${count - 1}(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`;
    };
    const accepted = await repositoryInventory({
      "handler.go": handler(body(8)),
      ...files,
    });
    expect(accepted).toHaveLength(1);
    expect(
      accepted[0]?.frameworkModel?.propagators.filter(
        ({ kind }) => kind === "go-sql-transaction-helper-function-value",
      ),
    ).toHaveLength(8);
    expect(
      await repositoryInventory({
        "handler.go": handler(body(9)),
        ...files,
      }),
    ).toEqual([]);
  });

  test("resolves the deepest exact local Go module for transaction creation", async () => {
    const rows = await repositoryInventory({
      "go.mod": `module example.com/application
go 1.26`,
      "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
  factory "corp.example/transactions/factory"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := factory.Start(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()
}`,
      "components/transactions/go.mod": `module corp.example/transactions
go 1.26`,
      "components/transactions/factory/transaction.go": `package factory
import "database/sql"
func Start(db *sql.DB) (*sql.Tx, error) { return db.Begin() }`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "go-sql-transaction-begin",
      )?.path,
    ).toBe("components/transactions/factory/transaction.go");
  });

  test("accepts exactly the 32-constructor-helper resilience boundary", async () => {
    const files: Record<string, string> = {};
    for (let index = 0; index < 31; index += 1) {
      const name = index === 0 ? "start" : `start${index}`;
      const next = `start${index + 1}`;
      files[`factory_${index}.go`] = `package invoices
import "database/sql"
func ${name}(db *sql.DB) (*sql.Tx, error) { return ${next}(db) }`;
    }
    files["factory_31.go"] = `package invoices
import "database/sql"
func start31(db *sql.DB) (*sql.Tx, error) { return db.Begin() }`;
    const rows = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := start(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`),
      ...files,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.filter(
        ({ kind }) => kind === "go-sql-transaction-begin-helper",
      ),
    ).toHaveLength(32);
  });

  test("rejects cyclic and over-depth transaction constructor chains", async () => {
    const overDepth: Record<string, string> = {};
    for (let index = 0; index < 32; index += 1) {
      const name = index === 0 ? "start" : `start${index}`;
      const next = `start${index + 1}`;
      overDepth[`factory_${index}.go`] = `package invoices
import "database/sql"
func ${name}(db *sql.DB) (*sql.Tx, error) { return ${next}(db) }`;
    }
    overDepth["factory_32.go"] = `package invoices
import "database/sql"
func start32(db *sql.DB) (*sql.Tx, error) { return db.Begin() }`;
    const handlerFile = handler(`  id := r.PathValue("invoiceID")
  tx, _ := start(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`);
    expect(
      await repositoryInventory({ "handler.go": handlerFile, ...overDepth }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": handlerFile,
        "factory.go": `package invoices
import "database/sql"
func start(db *sql.DB) (*sql.Tx, error) { return again(db) }
func again(db *sql.DB) (*sql.Tx, error) { return start(db) }`,
      }),
    ).toEqual([]);
  });

  test("rejects inexact transaction constructor helpers", async () => {
    const handlerSource = (
      importDeclaration: string,
      call = "factory.Start(db)",
    ) => `package invoices
import (
  "database/sql"
  "net/http"
  ${importDeclaration}
)
type localFactory struct{}
func (localFactory) Start(*sql.DB) (*sql.Tx, error) { return nil, nil }
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := ${call}
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()
}`;
    const exactTarget = `package txfactory
import "database/sql"
func Start(db *sql.DB) (*sql.Tx, error) { return db.Begin() }`;
    const cases: Array<Record<string, string>> = [
      {
        "handler.go": handlerSource(
          'factory "example.com/billing/internal/txfactory"',
        ),
        "internal/txfactory/transaction.go": exactTarget,
      },
      {
        "go.mod": "module example.com/billing",
        "handler.go": handlerSource('factory "example.com/other/txfactory"'),
        "internal/txfactory/transaction.go": exactTarget,
      },
      {
        "go.mod": "module example.com/billing",
        "handler.go": handlerSource(
          '. "example.com/billing/internal/txfactory"',
          "Start(db)",
        ),
        "internal/txfactory/transaction.go": exactTarget,
      },
      {
        "go.mod": "module example.com/billing",
        "handler.go": handlerSource(
          'factory "example.com/billing/internal/txfactory"',
          "factory := localFactory{}\n  factory.Start(db)",
        ),
        "internal/txfactory/transaction.go": exactTarget,
      },
      {
        "go.mod": "module example.com/application",
        "handler.go": handlerSource('factory "corp.example/txfactory"'),
        "one/go.mod": "module corp.example/txfactory",
        "one/transaction.go": exactTarget,
        "two/go.mod": "module corp.example/txfactory",
        "two/transaction.go": exactTarget,
      },
      {
        "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := start(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`),
        "transaction.go": `package invoices
import "database/sql"
func start(db *sql.DB) (any, error) { return db.Begin() }`,
      },
      {
        "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := start(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`),
        "transaction.go": `package invoices
import "database/sql"
func start(db *sql.DB) (*sql.Tx, error) {
  tx, err := db.Begin()
  tx, err = nil, err
  return tx, err
}`,
      },
      {
        "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := start(db)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()`),
        "transaction.go": `package invoices
import "database/sql"
func start(db *sql.DB) (*sql.Tx, error) {
  if db != nil {
    return db.Begin()
  }
  return nil, nil
}`,
      },
      {
        "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
)
func Handler(db *sql.Tx, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  tx.Commit()
}`,
      },
    ];
    for (const files of cases) {
      expect(
        await repositoryInventory(files),
        Object.entries(files)
          .map(([path, source]) => `${path}\n${source}`)
          .join("\n"),
      ).toEqual([]);
    }
  });

  test("closes transactions through one exact typed finalizer helper", async () => {
    const helpers = [
      `package invoices
import "database/sql"
func finish(tx *sql.Tx) error {
  return tx.Commit()
}`,
      `package invoices
import "database/sql"
func finish(label string, tx *sql.Tx) error {
  _ = label
  defer tx.Rollback()
  return tx.Commit()
}`,
    ];
    for (const [index, helper] of helpers.entries()) {
      const invocation =
        index === 0
          ? "alias := tx\n  finish(alias)"
          : 'if err := finish("invoice-delete", tx); err != nil {\n    return\n  }';
      const rows = await repositoryInventory({
        "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  ${invocation}`),
        "transaction.go": helper,
      });
      expect(rows, helper).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-database-object-committed-mutation",
      );
      expect(
        rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toContain("go-sql-transaction-finalizer-helper");
      expect(
        rows[0]?.frameworkModel?.propagators.find(
          ({ kind }) => kind === "go-sql-transaction-commit",
        )?.path,
      ).toBe("transaction.go");
    }
  });

  test("closes exact typed transaction finalizer helper chains", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  selected := tx
  finish("invoice-delete", selected)`),
      "coordinator.go": `package invoices
import "database/sql"
func finish(label string, tx *sql.Tx) error {
  _ = label
  alias := tx
  return commit(alias)
}`,
      "transaction.go": `package invoices
import "database/sql"
func commit(tx *sql.Tx) error {
  final := tx
  return final.Commit()
}`,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-object-committed-mutation",
    );
    const finalizers = rows[0]?.frameworkModel?.propagators.filter(
      ({ kind }) =>
        kind === "go-sql-transaction-finalizer-helper" ||
        kind === "go-sql-transaction-commit",
    );
    expect(finalizers).toEqual([
      {
        kind: "go-sql-transaction-finalizer-helper",
        path: "handler.go",
        line: 12,
        symbol: "finish",
      },
      {
        kind: "go-sql-transaction-finalizer-helper",
        path: "coordinator.go",
        line: 6,
        symbol: "commit",
      },
      {
        kind: "go-sql-transaction-commit",
        path: "transaction.go",
        line: 5,
        symbol: "final",
      },
    ]);
  });

  test("closes exact cross-package transaction finalizer helper chains", async () => {
    const rows = await scopedRepositoryInventory({
      "go.mod": `module example.com/billing
go 1.26`,
      "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
  guard "example.com/billing/internal/dbtx"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  guard.Finalize(tx)
}`,
      "internal/dbtx/coordinator.go": `package dbtx
import (
  "database/sql"
  outcome "example.com/billing/internal/txleaf"
)
func Finalize(tx *sql.Tx) error {
  selected := tx
  return outcome.Commit(selected)
}`,
      "internal/txleaf/transaction.go": `package txleaf
import "database/sql"
func Commit(tx *sql.Tx) error { return tx.Commit() }`,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-object-committed-mutation",
    );
    expect(
      rows[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          kind === "go-sql-transaction-finalizer-helper" ||
          kind === "go-sql-transaction-commit",
      ),
    ).toEqual([
      {
        kind: "go-sql-transaction-finalizer-helper",
        path: "handler.go",
        line: 11,
        symbol: "Finalize",
      },
      {
        kind: "go-sql-transaction-finalizer-helper",
        path: "internal/dbtx/coordinator.go",
        line: 8,
        symbol: "Commit",
      },
      {
        kind: "go-sql-transaction-commit",
        path: "internal/txleaf/transaction.go",
        line: 3,
        symbol: "tx",
      },
    ]);
  });

  test("finalizes transactions through exact local function values", async () => {
    const rows = await scopedRepositoryInventory({
      "go.mod": `module example.com/billing
go 1.26`,
      "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
  guard "example.com/billing/internal/dbtx"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish := guard.Finalize
  selected := finish
  selected(tx)
}`,
      "internal/dbtx/transaction.go": `package dbtx
import "database/sql"
func Finalize(tx *sql.Tx) error { return tx.Commit() }`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          kind === "go-sql-transaction-helper-function-value" ||
          kind === "go-sql-transaction-finalizer-helper",
      ),
    ).toEqual([
      {
        kind: "go-sql-transaction-helper-function-value",
        path: "handler.go",
        line: 11,
        symbol: "guard.Finalize",
      },
      {
        kind: "go-sql-transaction-helper-function-value",
        path: "handler.go",
        line: 12,
        symbol: "finish",
      },
      {
        kind: "go-sql-transaction-finalizer-helper",
        path: "handler.go",
        line: 13,
        symbol: "Finalize",
      },
    ]);
  });

  test("rejects shadowed and reassigned transaction helper calls", async () => {
    const parameterShadow = `package invoices
import (
  "database/sql"
  "net/http"
)
func finish(tx *sql.Tx) error { return tx.Commit() }
func Handler(db *sql.DB, finish func(*sql.Tx) error, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)
}`;
    const localShadow = `package invoices
import (
  "database/sql"
  "net/http"
)
func finish(tx *sql.Tx) error { return tx.Commit() }
func noop(*sql.Tx) error { return nil }
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish := noop
  finish(tx)
}`;
    const nestedBinding = `package invoices
import (
  "database/sql"
  "net/http"
)
func finish(tx *sql.Tx) error { return tx.Commit() }
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  var selected func(*sql.Tx) error
  if id != "" {
    selected = finish
  }
  selected(tx)
}`;
    const reassignedBinding = `package invoices
import (
  "database/sql"
  "net/http"
)
func finish(tx *sql.Tx) error { return tx.Commit() }
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  selected := finish
  selected = finish
  selected(tx)
}`;
    for (const source of [
      parameterShadow,
      localShadow,
      nestedBinding,
      reassignedBinding,
    ]) {
      expect(
        await repositoryInventory({ "handler.go": source }),
        source,
      ).toEqual([]);
    }
  });

  test("resolves the deepest exact local Go module for finalization", async () => {
    const rows = await repositoryInventory({
      "go.mod": `module example.com/application
go 1.26`,
      "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
  txguard "corp.example/transaction/finalizer"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  txguard.Finalize(tx)
}`,
      "components/transaction/go.mod": `module corp.example/transaction
go 1.26`,
      "components/transaction/finalizer/transaction.go": `package finalizer
import "database/sql"
func Finalize(tx *sql.Tx) error { return tx.Commit() }`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "go-sql-transaction-commit",
      )?.path,
    ).toBe("components/transaction/finalizer/transaction.go");
  });

  test("propagates an exact cross-package rollback helper", async () => {
    const rows = await repositoryInventory({
      "go.mod": `module example.com/billing
go 1.26`,
      "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
  "example.com/billing/internal/dbtx"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  dbtx.Cancel(tx)
  tx.Commit()
}`,
      "internal/dbtx/transaction.go": `package dbtx
import "database/sql"
func Cancel(tx *sql.Tx) error { return tx.Rollback() }`,
    });
    expect(rows).toEqual([]);
  });

  test("rejects inexact cross-package finalizer resolution", async () => {
    const handlerSource = (
      importDeclaration: string,
      call = "dbtx.Finalize(tx)",
    ) =>
      `package invoices
import (
  "database/sql"
  "net/http"
  ${importDeclaration}
)
type localFinalizer struct{}
func (localFinalizer) Finalize(*sql.Tx) error { return nil }
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  ${call}
}`;
    const exactTarget = `package dbtx
import "database/sql"
func Finalize(tx *sql.Tx) error { return tx.Commit() }`;
    const cases: Array<Record<string, string>> = [
      {
        "handler.go": handlerSource('"example.com/billing/internal/dbtx"'),
        "internal/dbtx/transaction.go": exactTarget,
      },
      {
        "go.mod": "module example.com/billing",
        "handler.go": handlerSource('dbtx "example.com/other/dbtx"'),
        "internal/dbtx/transaction.go": exactTarget,
      },
      {
        "go.mod": "module example.com/billing",
        "handler.go": handlerSource(
          'dbtx "example.com/billing/internal/dbtx"',
          "dbtx.finalize(tx)",
        ),
        "internal/dbtx/transaction.go": `package dbtx
import "database/sql"
func finalize(tx *sql.Tx) error { return tx.Commit() }`,
      },
      {
        "go.mod": "module example.com/billing",
        "handler.go": handlerSource(
          '. "example.com/billing/internal/dbtx"',
          "Finalize(tx)",
        ),
        "internal/dbtx/transaction.go": exactTarget,
      },
      {
        "go.mod": "module example.com/billing",
        "handler.go": handlerSource(
          '"example.com/billing/internal/dbtx"',
          "_ = dbtx.Marker\n  dbtx := localFinalizer{}\n  dbtx.Finalize(tx)",
        ),
        "internal/dbtx/transaction.go": `package dbtx
import "database/sql"
var Marker = true
func Finalize(tx *sql.Tx) error { return tx.Commit() }`,
      },
      {
        "go.mod": "module example.com/application",
        "handler.go": handlerSource('dbtx "corp.example/dbtx"'),
        "one/go.mod": "module corp.example/dbtx",
        "one/transaction.go": exactTarget,
        "two/go.mod": "module corp.example/dbtx",
        "two/transaction.go": exactTarget,
      },
    ];
    for (const files of cases) {
      expect(
        await repositoryInventory(files),
        Object.entries(files)
          .map(([path, source]) => `${path}\n${source}`)
          .join("\n"),
      ).toEqual([]);
    }
  });

  test("propagates exact rollback helper chains and ignores non-dominating branches", async () => {
    const helperFiles = {
      "coordinator.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return rollback(tx) }`,
      "transaction.go": `package invoices
import "database/sql"
func rollback(tx *sql.Tx) error { return tx.Rollback() }`,
    };
    const dominated = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)
  tx.Commit()`),
      ...helperFiles,
    });
    expect(dominated).toEqual([]);

    const branchOnly = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  if id == "" {
    finish(tx)
    return
  }
  tx.Commit()`),
      ...helperFiles,
    });
    expect(branchOnly).toHaveLength(1);
    expect(branchOnly[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-object-committed-mutation",
    );
  });

  test("accepts exactly the 32-helper resilience boundary", async () => {
    const files: Record<string, string> = {};
    for (let index = 0; index < 31; index += 1) {
      const name = index === 0 ? "finish" : `finish${index}`;
      const next = `finish${index + 1}`;
      files[`transaction_${index}.go`] = `package invoices
import "database/sql"
func ${name}(tx *sql.Tx) error { return ${next}(tx) }`;
    }
    files["transaction_31.go"] = `package invoices
import "database/sql"
func finish31(tx *sql.Tx) error { return tx.Commit() }`;
    const rows = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)`),
      ...files,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.filter(
        ({ kind }) => kind === "go-sql-transaction-finalizer-helper",
      ),
    ).toHaveLength(32);
  });

  test("rejects ambiguous, cyclic, reassigned, nested, deferred, and over-depth helper chains", async () => {
    const baseBody = `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)`;
    const cases: Array<Record<string, string>> = [
      {
        "coordinator.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error {
  commit(tx)
  return rollback(tx)
}`,
        "transaction.go": `package invoices
import "database/sql"
func commit(tx *sql.Tx) error { return tx.Commit() }
func rollback(tx *sql.Tx) error { return tx.Rollback() }`,
      },
      {
        "coordinator.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return forward(tx) }
func forward(tx *sql.Tx) error { return finish(tx) }`,
      },
      {
        "coordinator.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error {
  forward(tx)
  return tx.Commit()
}
func forward(tx *sql.Tx) error { return finish(tx) }`,
      },
      {
        "coordinator.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error {
  tx = nil
  return commit(tx)
}`,
        "transaction.go": `package invoices
import "database/sql"
func commit(tx *sql.Tx) error { return tx.Commit() }`,
      },
      {
        "coordinator.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return commit(tx) }`,
        "transaction.go": `package invoices
import "database/sql"
func commit(tx *sql.Tx) error {
  tx = nil
  return tx.Commit()
}`,
      },
      {
        "coordinator.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error {
  if tx != nil {
    return commit(tx)
  }
  return nil
}`,
        "transaction.go": `package invoices
import "database/sql"
func commit(tx *sql.Tx) error { return tx.Commit() }`,
      },
      {
        "coordinator.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) { defer commit(tx) }`,
        "transaction.go": `package invoices
import "database/sql"
func commit(tx *sql.Tx) error { return tx.Commit() }`,
      },
    ];
    const depthFiles: Record<string, string> = {};
    for (let index = 0; index < 32; index += 1) {
      const name = index === 0 ? "finish" : `finish${index}`;
      const next = `finish${index + 1}`;
      depthFiles[`transaction_${index}.go`] = `package invoices
import "database/sql"
func ${name}(tx *sql.Tx) error { return ${next}(tx) }`;
    }
    depthFiles["transaction_32.go"] = `package invoices
import "database/sql"
func finish32(tx *sql.Tx) error { return tx.Commit() }`;
    cases.push(depthFiles);
    for (const files of cases) {
      expect(
        await repositoryInventory({
          "handler.go": handler(baseBody),
          ...files,
        }),
        Object.values(files).join("\n"),
      ).toEqual([]);
    }
  });

  test("binds a helper chain to the exact forwarded transaction parameter", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  other, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx, other)`),
      "coordinator.go": `package invoices
import "database/sql"
func finish(selected *sql.Tx, finalized *sql.Tx) error {
  _ = selected
  return commit(finalized)
}`,
      "transaction.go": `package invoices
import "database/sql"
func commit(tx *sql.Tx) error { return tx.Commit() }`,
    });
    expect(rows).toEqual([]);
  });

  test("keeps error-branch helper rollback compatible with later commit", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  if id == "" {
    rollback(tx)
    return
  }
  tx.Commit()`),
      "transaction.go": `package invoices
import "database/sql"
func rollback(tx *sql.Tx) error {
  return tx.Rollback()
}`,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-object-committed-mutation",
    );
  });

  test("rejects ambiguous, nested, deferred, mistyped, and misordered finalizer helpers", async () => {
    const cases: Array<{ body: string; files: Record<string, string> }> = [
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)`,
        files: {
          "transaction.go": `package invoices
import "database/sql"
func finish(tx any) error {
  _ = tx
  return nil
}`,
        },
      },
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)`,
        files: {
          "transaction_a.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return tx.Commit() }`,
          "transaction_b.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return tx.Commit() }`,
        },
      },
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)`,
        files: {
          "transaction.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error {
  if tx != nil {
    return tx.Commit()
  }
  return nil
}`,
        },
      },
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)`,
        files: {
          "transaction.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) {
  defer tx.Commit()
}`,
        },
      },
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(tx)`,
        files: {
          "transaction.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) {
  tx.Rollback()
  tx.Commit()
}`,
        },
      },
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  if id != "" {
    finish(tx)
  }`,
        files: {
          "transaction.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return tx.Commit() }`,
        },
      },
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  defer finish(tx)`,
        files: {
          "transaction.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return tx.Commit() }`,
        },
      },
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  finish(tx)
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)`,
        files: {
          "transaction.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return tx.Commit() }`,
        },
      },
      {
        body: `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  other, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  finish(other)`,
        files: {
          "transaction.go": `package invoices
import "database/sql"
func finish(tx *sql.Tx) error { return tx.Commit() }`,
        },
      },
    ];
    for (const { body, files } of cases) {
      expect(
        await repositoryInventory({ "handler.go": handler(body), ...files }),
        `${body}\n${Object.values(files).join("\n")}`,
      ).toEqual([]);
    }
  });

  test("lets an exact top-level rollback helper dominate later commit", async () => {
    const rows = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  tx.Exec("DELETE FROM invoices WHERE id = ?", id)
  rollback(tx)
  tx.Commit()`),
      "transaction.go": `package invoices
import "database/sql"
func rollback(tx *sql.Tx) error { return tx.Rollback() }`,
    });
    expect(rows).toEqual([]);
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

  test("binds exact DB statements to transactions through Stmt and StmtContext", async () => {
    for (const transfer of [
      "txStmt := tx.Stmt(baseStmt)",
      "txStmt := tx.StmtContext(r.Context(), baseStmt)",
      "txAlias := tx\n  txStmt := txAlias.Stmt(baseStmt)",
      "stmtAlias := baseStmt\n  txStmt := tx.Stmt(stmtAlias)",
    ]) {
      const rows = await repositoryInventory({
        "handler.go": handler(`  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  ${transfer}
  txStmt.ExecContext(r.Context(), id)
  tx.Commit()`),
      });
      expect(rows, transfer).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-database-object-committed-mutation",
      );
      expect(
        rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toEqual([
        "go-object-identifier-assignment",
        "go-sql-statement-prepare",
        "go-sql-transaction-statement-transfer",
        "go-sql-object-predicate",
        "go-sql-statement-execution",
        "go-sql-transaction-commit",
      ]);
    }
  });

  test("closes direct chained transaction statement execution", async () => {
    for (const execution of [
      "tx.Stmt(baseStmt).Exec(id)",
      "tx.StmtContext(r.Context(), baseStmt).ExecContext(r.Context(), id)",
      "_, err := tx.Stmt(baseStmt).Exec(id); _ = err",
    ]) {
      const rows = await repositoryInventory({
        "handler.go": handler(`  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  ${execution}
  tx.Commit()`),
      });
      expect(rows, execution).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-database-object-committed-mutation",
      );
      expect(
        rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toContain("go-sql-transaction-statement-transfer");
    }

    const unrelatedSameLine = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  tx.Stmt(baseStmt); other.Exec(id)
  tx.Commit()`),
    });
    expect(unrelatedSameLine).toEqual([]);
  });

  test("keeps transferred and original statement identities independent", async () => {
    const transferred = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  txStmt := tx.Stmt(baseStmt)
  baseStmt.Close()
  txStmt.Exec(id)
  tx.Commit()`),
    });
    expect(transferred).toHaveLength(1);
    expect(transferred[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-object-committed-mutation",
    );

    const original = await repositoryInventory({
      "handler.go": handler(`  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  txStmt := tx.Stmt(baseStmt)
  baseStmt.Exec(id)
  txStmt.Close()
  tx.Rollback()`),
    });
    expect(original).toHaveLength(1);
    expect(original[0]?.frameworkModel?.sink.kind).toBe(
      "go-database-object-mutation",
    );
    expect(
      original[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).not.toContain("go-sql-transaction-statement-transfer");
  });

  test("rejects inexact or non-durable transaction statement transfers", async () => {
    for (const body of [
      `  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  tx.Stmt(baseStmt)
  tx.Commit()
  _ = id`,
      `  id := r.PathValue("invoiceID")
  tx, _ := db.Begin()
  txStmt := tx.Stmt(otherStmt)
  txStmt.Exec(id)
  tx.Commit()`,
      `  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  baseStmt.Close()
  tx, _ := db.Begin()
  txStmt := tx.Stmt(baseStmt)
  txStmt.Exec(id)
  tx.Commit()`,
      `  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  txStmt := tx.Stmt(baseStmt)
  txStmt.Exec(id)`,
      `  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  txStmt := tx.Stmt(baseStmt)
  txStmt.Exec(id)
  tx.Rollback()`,
      `  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  txStmt := tx.Stmt(baseStmt)
  txStmt.Close()
  txStmt.Exec(id)
  tx.Commit()`,
      `  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  txStmt := tx.Stmt(baseStmt)
  txStmt, _ = db.Prepare("INSERT INTO invoices(id) VALUES (?)")
  txStmt.Exec(id)
  tx.Commit()`,
      `  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  first, _ := db.Begin()
  firstStmt, _ := first.Prepare("DELETE FROM invoices WHERE id = ?")
  second, _ := db.Begin()
  txStmt := second.Stmt(firstStmt)
  txStmt.Exec(id)
  second.Commit()
  first.Rollback()`,
      `  id := r.PathValue("invoiceID")
  baseStmt, _ := db.Prepare("DELETE FROM invoices WHERE id = ?")
  tx, _ := db.Begin()
  txStmt := tx.StmtContext(baseStmt, r.Context())
  txStmt.Exec(id)
  tx.Commit()`,
    ]) {
      expect(
        await repositoryInventory({ "handler.go": handler(body) }),
        body,
      ).toEqual([]);
    }
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

  test("follows exact concrete receiver methods and records receiver identity", async () => {
    const rows = await repositoryInventory({
      "invoices.go": `package invoices
import (
  "context"
  "database/sql"
  "net/http"
)
type Store struct{}
func (*Store) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
  _, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ?", invoiceID)
  return err
}
type Service struct{}
func (Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
  repository := Store{}
  return repository.DeleteInvoice(ctx, db, invoiceID)
}
func Handler(service *Service, db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
  service.DeleteInvoice(r.Context(), db, invoiceID)
  w.WriteHeader(http.StatusNoContent)
}`,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.line).toBe(9);
    expect(rows[0]?.frameworkModel?.source.line).toBe(18);
    expect(
      rows[0]?.frameworkModel?.propagators.filter(({ kind }) =>
        kind.startsWith("go-method-receiver"),
      ),
    ).toEqual([
      expect.objectContaining({
        kind: "go-method-receiver-parameter",
        line: 17,
        symbol: "service:Service",
      }),
      expect.objectContaining({
        kind: "go-method-receiver-binding",
        line: 14,
        symbol: "repository:Store",
      }),
    ]);
    expect(
      rows[0]?.frameworkModel?.propagators.filter(
        ({ kind }) => kind === "go-function-argument",
      ),
    ).toEqual([
      expect.objectContaining({ line: 19, symbol: "DeleteInvoice[2]" }),
      expect.objectContaining({ line: 15, symbol: "DeleteInvoice[2]" }),
    ]);
  });

  test("follows an exact local interface binding into a cross-package method", async () => {
    const handlerSource = (principal: string) => `package invoices
import (
  "database/sql"
  service "example.com/method-authorization/internal/invoicesvc"
  "net/http"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
  accountID := ${principal}
  invoices := &service.Service{}
  if err := invoices.DeleteInvoice(r.Context(), db, invoiceID, accountID); err != nil {
    http.Error(w, "delete failed", http.StatusInternalServerError)
    return
  }
  w.WriteHeader(http.StatusNoContent)
}`;
    const shared = {
      "go.mod": `module example.com/method-authorization

go 1.26
`,
      "internal/invoicesvc/service.go": `package invoicesvc
import (
  "context"
  "database/sql"
  repository "example.com/method-authorization/internal/invoicestore"
)
type InvoiceRepository interface {
  DeleteInvoice(context.Context, *sql.DB, string, string) error
}
type Service struct{}
func (*Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
  selected := invoiceID
  owner := accountID
  var invoices InvoiceRepository = &repository.Store{}
  return invoices.DeleteInvoice(ctx, db, selected, owner)
}`,
      "internal/invoicestore/store.go": `package invoicestore
import (
  "context"
  "database/sql"
)
type Store struct{}
func (*Store) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
  _, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?", invoiceID, accountID)
  return err
}`,
    };
    const safe = await repositoryInventory({
      ...shared,
      "handler.go": handlerSource(
        "r.Context().Value(authenticatedAccountIDKey).(string)",
      ),
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]?.path).toBe("internal/invoicestore/store.go");
    expect(
      safe[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual(["principal-bound-object-query"]);
    expect(
      safe[0]?.frameworkModel?.propagators.filter(({ kind }) =>
        /receiver-(?:binding|parameter)$/u.test(kind),
      ),
    ).toEqual([
      expect.objectContaining({
        kind: "go-method-receiver-binding",
        path: "handler.go",
        symbol: "invoices:service.Service",
      }),
      expect.objectContaining({
        kind: "go-interface-receiver-binding",
        path: "internal/invoicesvc/service.go",
        symbol: "invoices:repository.Store",
      }),
    ]);

    const attackerPrincipal = await repositoryInventory({
      ...shared,
      "handler.go": handlerSource('r.Header.Get("X-Account-ID")'),
    });
    expect(attackerPrincipal).toHaveLength(1);
    expect(attackerPrincipal[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("resolves exact later assignments and explicit interface conversions", async () => {
    for (const setup of [
      `  var repository InvoiceRepository
  repository = &Store{}`,
      `  repository := InvoiceRepository(&Store{})`,
    ]) {
      const rows = await repositoryInventory({
        "invoices.go": `package invoices
import (
  "context"
  "database/sql"
  "net/http"
)
type InvoiceRepository interface {
  DeleteInvoice(context.Context, *sql.DB, string) error
}
type Store struct{}
func (*Store) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
  _, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ?", invoiceID)
  return err
}
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
${setup}
  repository.DeleteInvoice(r.Context(), db, invoiceID)
}`,
      });
      expect(rows, setup).toHaveLength(1);
      expect(
        rows[0]?.frameworkModel?.propagators.some(
          ({ kind }) => kind === "go-interface-receiver-binding",
        ),
        setup,
      ).toBeTrue();
    }
  });

  test("accepts eight concrete receiver aliases and rejects nine", async () => {
    const repository = async (aliases: number): Promise<ModelRecord[]> => {
      const bindings = Array.from(
        { length: aliases },
        (_, index) => `  service${index + 1} := service${index}`,
      ).join("\n");
      return repositoryInventory({
        "invoices.go": `package invoices
import (
  "context"
  "database/sql"
  "net/http"
)
type Service struct{}
func (*Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
  _, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ?", invoiceID)
  return err
}
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
  service0 := &Service{}
${bindings}
  service${aliases}.DeleteInvoice(r.Context(), db, invoiceID)
  w.WriteHeader(http.StatusNoContent)
}`,
      });
    };
    const accepted = await repository(8);
    expect(accepted).toHaveLength(1);
    expect(
      accepted[0]?.frameworkModel?.propagators.filter(
        ({ kind }) => kind === "go-method-receiver-alias",
      ),
    ).toHaveLength(8);
    expect(await repository(9)).toEqual([]);
  });

  test("rejects unbound, promoted, dynamic, and ambiguous method dispatch", async () => {
    const sink = `package invoices
import ("context"; "database/sql")
type Store struct{}
func (*Store) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
  _, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ?", invoiceID)
  return err
}`;
    const handler = (setup: string, call: string, declarations = "") =>
      `package invoices
import ("context"; "database/sql"; "net/http")
${declarations}
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
${setup}
  ${call}
}`;
    expect(
      await repositoryInventory({
        "sink.go": sink,
        "handler.go": `package invoices
import ("context"; "database/sql"; "net/http")
type InvoiceRepository interface { DeleteInvoice(context.Context, *sql.DB, string) error }
func Handler(repository InvoiceRepository, db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
  repository.DeleteInvoice(r.Context(), db, invoiceID)
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "sink.go": sink,
        "handler.go": handler(
          "  var service *Store",
          "service.DeleteInvoice(r.Context(), db, invoiceID)",
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "sink.go": sink,
        "handler.go": handler(
          "  var repository InvoiceRepository = Store{}",
          "repository.DeleteInvoice(r.Context(), db, invoiceID)",
          "type InvoiceRepository interface { DeleteInvoice(context.Context, *sql.DB, string) error }",
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "sink.go": sink,
        "handler.go": handler(
          "  var repository InvoiceRepository = &Store{}",
          "repository.DeleteInvoice(r.Context(), db, invoiceID)",
          "type InvoiceRepository interface { Other(context.Context) error }",
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "sink.go": sink,
        "handler.go": handler(
          "  var repository InvoiceRepository = &Store{}",
          "repository.DeleteInvoice(r.Context(), db, invoiceID)",
          "type InvoiceRepository interface { ~int; DeleteInvoice(context.Context, *sql.DB, string) error }",
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "sink.go": sink,
        "handler.go": handler(
          "  service := &Service{}",
          "remove := service.DeleteInvoice; remove(r.Context(), db, invoiceID)",
          "type Service struct{ Store }",
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "sink.go": sink,
        "handler.go": handler(
          "  service := NewService()",
          "service.DeleteInvoice(r.Context(), db, invoiceID)",
          "func NewService() *Store { return &Store{} }",
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "sink.go": sink,
        "handler.go": handler(
          "  var repository InvoiceRepository = &Store{}\n  if true { repository = &Store{} }",
          "repository.DeleteInvoice(r.Context(), db, invoiceID)",
          "type InvoiceRepository interface { DeleteInvoice(context.Context, *sql.DB, string) error }",
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "sink-a.go": sink,
        "sink-b.go": sink,
        "handler.go": handler(
          "  service := &Store{}",
          "service.DeleteInvoice(r.Context(), db, invoiceID)",
        ),
      }),
    ).toEqual([]);
  });

  test("follows exact multi-hop wrappers and preserves principal provenance", async () => {
    const handlerSource = (principal: string) => `package invoices
import (
  "database/sql"
  "net/http"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
  accountID := ${principal}
  DeleteInvoiceService(r.Context(), db, invoiceID, accountID)
}`;
    const files = {
      "service.go": `package invoices
import (
  "context"
  "database/sql"
)
func DeleteInvoiceService(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
  selected := invoiceID
  owner := accountID
  return DeleteInvoiceRepository(ctx, db, selected, owner)
}`,
      "store.go": `package invoices
import (
  "context"
  "database/sql"
)
func DeleteInvoiceRepository(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
  _, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?", invoiceID, accountID)
  return err
}`,
    };
    const safe = await repositoryInventory({
      "handler.go": handlerSource(
        "r.Context().Value(authenticatedAccountIDKey).(string)",
      ),
      ...files,
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]).toMatchObject({
      path: "store.go",
      frameworkModel: {
        scope: "cross-file-wrapper",
        candidateControls: [
          {
            kind: "principal-bound-object-query",
            path: "store.go",
            line: 7,
          },
        ],
      },
    });
    expect(
      safe[0]?.frameworkModel?.propagators.filter(
        ({ kind }) =>
          kind === "go-function-argument" || kind === "go-string-parameter",
      ),
    ).toEqual([
      {
        kind: "go-function-argument",
        line: 9,
        symbol: "DeleteInvoiceService[2]",
        path: "handler.go",
      },
      {
        kind: "go-string-parameter",
        line: 6,
        symbol: "invoiceID",
        path: "service.go",
      },
      {
        kind: "go-function-argument",
        line: 9,
        symbol: "DeleteInvoiceRepository[2]",
        path: "service.go",
      },
      {
        kind: "go-string-parameter",
        line: 6,
        symbol: "invoiceID",
        path: "store.go",
      },
    ]);
    const unsafe = await repositoryInventory({
      "handler.go": handlerSource('r.Header.Get("X-Account-ID")'),
      ...files,
    });
    expect(unsafe).toHaveLength(1);
    expect(unsafe[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("follows exact cross-package object-wrapper chains", async () => {
    const rows = await scopedRepositoryInventory({
      "go.mod": `module example.com/billing
go 1.26`,
      "handler.go": `package invoices
import (
  "database/sql"
  "net/http"
  service "example.com/billing/internal/invoicesvc"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
  accountID := r.Context().Value(authenticatedAccountIDKey).(string)
  service.DeleteInvoice(r.Context(), db, invoiceID, accountID)
}`,
      "internal/invoicesvc/service.go": `package invoicesvc
import (
  "context"
  "database/sql"
  repository "example.com/billing/internal/invoicestore"
)
func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
  selected := invoiceID
  owner := accountID
  return repository.DeleteInvoice(ctx, db, selected, owner)
}`,
      "internal/invoicestore/store.go": `package invoicestore
import (
  "context"
  "database/sql"
)
func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
  _, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?", invoiceID, accountID)
  return err
}`,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      path: "internal/invoicestore/store.go",
      frameworkModel: {
        source: { path: "handler.go", line: 8 },
        sink: { path: "internal/invoicestore/store.go", line: 7 },
        candidateControls: [
          {
            kind: "principal-bound-object-query",
            path: "internal/invoicestore/store.go",
            line: 7,
          },
        ],
      },
    });
    expect(
      rows[0]?.frameworkModel?.propagators.filter(
        ({ kind }) => kind === "go-function-argument",
      ),
    ).toEqual([
      {
        kind: "go-function-argument",
        path: "handler.go",
        line: 10,
        symbol: "DeleteInvoice[2]",
      },
      {
        kind: "go-function-argument",
        path: "internal/invoicesvc/service.go",
        line: 10,
        symbol: "DeleteInvoice[2]",
      },
    ]);
  });

  test("rejects inexact cross-package object-wrapper resolution", async () => {
    const handlerSource = (importPath: string, shadow = "") => `package invoices
import (
  "database/sql"
  "net/http"
  service "${importPath}"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  invoiceID := r.PathValue("invoiceID")
  ${shadow}
  service.DeleteInvoice(db, invoiceID)
}`;
    const service = `package service
import (
  "database/sql"
  repository "example.com/billing/internal/repository"
)
func DeleteInvoice(db *sql.DB, invoiceID string) { repository.DeleteInvoice(db, invoiceID) }`;
    const repository = `package repository
import "database/sql"
func DeleteInvoice(db *sql.DB, invoiceID string) { db.Exec("DELETE FROM invoices WHERE id = ?", invoiceID) }`;
    const base = {
      "handler.go": handlerSource("example.com/billing/internal/service"),
      "internal/service/service.go": service,
      "internal/repository/store.go": repository,
    };
    expect(await repositoryInventory(base)).toEqual([]);
    expect(
      await repositoryInventory({
        "go.mod": `module example.com/billing
go 1.26`,
        ...base,
        "handler.go": handlerSource("example.com/lookalike/internal/service"),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "go.mod": `module example.com/billing
go 1.26`,
        ...base,
        "handler.go": handlerSource(
          "example.com/billing/internal/service",
          "service := localService{}",
        ),
        "lookalike.go": `package invoices
import "database/sql"
type localService struct{}
func (localService) DeleteInvoice(*sql.DB, string) {}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "go.mod": `module example.com/billing
go 1.26`,
        ...base,
        "nested/go.mod": `module example.com/billing/internal/service
go 1.26`,
        "nested/service.go": service.replace(
          "package service",
          "package duplicate",
        ),
      }),
    ).toEqual([]);
  });

  test("accepts exactly 32 object-wrapper boundaries and rejects 33", async () => {
    const source = (count: number) => {
      const wrappers = Array.from({ length: count }, (_, index) => {
        const next =
          index === count - 1 ? "DeleteInvoiceStore" : `Layer${index + 1}`;
        return `func Layer${index}(db *sql.DB, invoiceID string) { ${next}(db, invoiceID) }`;
      }).join("\n");
      return `package invoices
import (
  "database/sql"
  "net/http"
)
func DeleteInvoiceStore(db *sql.DB, invoiceID string) { db.Exec("DELETE FROM invoices WHERE id = ?", invoiceID) }
${wrappers}
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) { Layer0(db, r.PathValue("invoiceID")) }`;
    };
    const accepted = await repositoryInventory({ "handler.go": source(32) });
    expect(accepted).toHaveLength(1);
    expect(
      accepted[0]?.frameworkModel?.propagators.filter(
        ({ kind }) => kind === "go-function-argument",
      ),
    ).toHaveLength(33);
    expect(await repositoryInventory({ "handler.go": source(33) })).toEqual([]);
  });

  test("rejects ambiguous, cyclic, nested, shadowed, and fixed wrapper paths", async () => {
    const handlerSource = `package invoices
import (
  "database/sql"
  "net/http"
)
func Handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
  Service(db, r.PathValue("invoiceID"))
}`;
    const leaf = `package invoices
import "database/sql"
func Store(db *sql.DB, invoiceID string) { db.Exec("DELETE FROM invoices WHERE id = ?", invoiceID) }`;
    const candidates = [
      `package invoices
import "database/sql"
func Service(db *sql.DB, invoiceID string) {
  Store(db, invoiceID)
  Store(db, invoiceID)
}`,
      `package invoices
import "database/sql"
func Service(db *sql.DB, invoiceID string) { Cycle(db, invoiceID) }
func Cycle(db *sql.DB, invoiceID string) { Service(db, invoiceID) }`,
      `package invoices
import "database/sql"
func Service(db *sql.DB, invoiceID string) {
  if invoiceID != "" { Store(db, invoiceID) }
}`,
      `package invoices
import "database/sql"
func Service(db *sql.DB, invoiceID string, Store func(*sql.DB, string)) {
  Store(db, invoiceID)
}`,
      `package invoices
import "database/sql"
func Service(db *sql.DB, invoiceID string) {
  allowed := map[string]string{"mine": "owned-invoice"}
  Store(db, allowed[invoiceID])
}`,
      `package invoices
import "database/sql"
func Service(db *sql.DB, invoiceID string) {
  invoiceID = "owned-invoice"
  Store(db, invoiceID)
}`,
    ];
    for (const service of candidates) {
      expect(
        await repositoryInventory({
          "handler.go": handlerSource,
          "service.go": service,
          "store.go": leaf,
        }),
        service,
      ).toEqual([]);
    }
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
