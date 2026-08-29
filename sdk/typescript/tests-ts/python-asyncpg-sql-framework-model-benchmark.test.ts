import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  line: number;
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
const benchmarkRoot = resolve(import.meta.dir, "../../../benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function asyncpgRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter((record) => record.frameworkModel?.id === "python-asyncpg-sql");
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-asyncpg-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

const typedRoute = (body: string, imports = "import asyncpg") =>
  [
    imports,
    "async def route(request, connection: asyncpg.Connection):",
    "    query = request.get_json()",
    `    ${body}`,
  ].join("\n");

describe("Python asyncpg SQL-injection framework model", () => {
  test("covers every official query-bearing Connection and Pool method", async () => {
    const methods = new Map<string, string>([
      [
        "copy_from_query",
        "await connection.copy_from_query(query, output='out.csv')",
      ],
      ["cursor", "async for row in connection.cursor(query): pass"],
      ["execute", "await connection.execute(query)"],
      ["executemany", "await connection.executemany(query, [('x',)])"],
      ["fetch", "await connection.fetch(query)"],
      ["fetchmany", "await connection.fetchmany(query, [('x',)])"],
      ["fetchrow", "await connection.fetchrow(query)"],
      ["fetchval", "await connection.fetchval(query)"],
      ["prepare", "await connection.prepare(query)"],
    ]);
    const repository = await writeRepository(
      Object.fromEntries(
        [...methods].map(([method, call]) => [
          `${method}.py`,
          typedRoute(call),
        ]),
      ),
    );

    const records = asyncpgRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(methods.size);
    expect(records.map(({ path }) => path).sort()).toEqual(
      [...methods.keys()].map((method) => `${method}.py`).sort(),
    );
    expect(
      new Set(records.map((record) => record.frameworkModel?.sink.kind)),
    ).toEqual(
      new Set(
        [...methods.keys()].map((method) => `asyncpg-${method}-sql-grammar`),
      ),
    );
    expect(
      records.every(
        (record) =>
          record.frameworkModel?.sink.cweIds.join() === "CWE-89" &&
          record.frameworkModel.propagators.some(({ kind }) =>
            kind.startsWith("asyncpg-annotated-receiver"),
          ) &&
          record.frameworkModel.propagators.some(({ kind }) =>
            kind.includes("query-grammar-argument"),
          ) &&
          record.frameworkModel.propagators.some(
            ({ kind }) =>
              kind.includes("awaited-query-execution") ||
              kind.includes("consumed-cursor"),
          ),
      ),
    ).toBeTrue();
  });

  test("accepts live aliased factories, pools, and acquired connections", async () => {
    const repository = await writeRepository({
      "module-connection.py": [
        "import asyncpg as ap",
        "async def route(request):",
        "    connection = await ap.connect('postgres:///app')",
        "    query = request.get_json()",
        "    return await connection.fetch(query)",
      ].join("\n"),
      "direct-pool.py": [
        "from asyncpg import create_pool as open_pool",
        "async def route(request):",
        "    pool = await open_pool('postgres:///app')",
        "    query = request.get_json()",
        "    return await pool.fetchrow(query)",
      ].join("\n"),
      "pool-context.py": [
        "import asyncpg",
        "async def route(request):",
        "    async with asyncpg.create_pool('postgres:///app') as pool:",
        "        query = request.get_json()",
        "        return await pool.fetchval(query)",
      ].join("\n"),
      "acquire-context.py": [
        "import asyncpg",
        "async def route(request):",
        "    pool = await asyncpg.create_pool('postgres:///app')",
        "    async with pool.acquire() as connection:",
        "        query = request.get_json()",
        "        return await connection.execute(query)",
      ].join("\n"),
      "acquire-await.py": [
        "import asyncpg",
        "async def route(request):",
        "    pool = await asyncpg.create_pool('postgres:///app')",
        "    connection = await pool.acquire()",
        "    query = request.get_json()",
        "    return await connection.prepare(query)",
      ].join("\n"),
    });

    const records = asyncpgRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path).sort()).toEqual([
      "acquire-await.py",
      "acquire-context.py",
      "direct-pool.py",
      "module-connection.py",
      "pool-context.py",
    ]);
    expect(
      records.flatMap(
        (record) =>
          record.frameworkModel?.propagators.map(({ kind }) => kind) ?? [],
      ),
    ).toEqual(
      expect.arrayContaining([
        "asyncpg-connection-factory",
        "asyncpg-pool-factory",
        "asyncpg-pool-context-manager",
        "asyncpg-pool-acquired-connection",
        "asyncpg-pool-acquired-connection-context-manager",
      ]),
    );
  });

  test("follows a copied query and a FastAPI Annotated request parameter", async () => {
    const repository = await writeRepository({
      "alias.py": [
        "import asyncpg",
        "async def route(request, connection: asyncpg.Connection):",
        "    query = 'SELECT * FROM accounts WHERE name = ' + request.args['name']",
        "    query_copy = query",
        "    return await connection.fetch(query_copy)",
      ].join("\n"),
      "fastapi.py": [
        "from typing import Annotated",
        "from fastapi import Query",
        "from asyncpg import Connection",
        "async def route(name: Annotated[str, Query()], connection: Connection):",
        "    sql = f\"SELECT * FROM accounts WHERE name = '{name}'\"",
        "    return await connection.fetch(sql)",
      ].join("\n"),
    });

    const records = asyncpgRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path).sort()).toEqual([
      "alias.py",
      "fastapi.py",
    ]);
    expect(
      records.find(({ path }) => path === "fastapi.py")?.frameworkModel?.source
        .kind,
    ).toBe("fastapi-bound-parameter");
  });

  test("rejects bound-value-only, inert, lookalike, shadowed, reassigned, and invalid calls", async () => {
    const repository = await writeRepository({
      "bound-value.py": [
        "import asyncpg",
        "async def route(request, connection: asyncpg.Connection):",
        "    value = request.get_json()",
        "    return await connection.fetch('SELECT * FROM accounts WHERE name = $1', value)",
      ].join("\n"),
      "not-awaited.py": typedRoute("return connection.fetch(query)"),
      "lookalike.py": [
        "class Connection: pass",
        "async def route(request, connection: Connection):",
        "    return await connection.fetch(request.get_json())",
      ].join("\n"),
      "shadowed/asyncpg.py": "class Connection: pass\n",
      "shadowed/app.py": typedRoute("return await connection.fetch(query)"),
      "module-reassigned.py": [
        "import asyncpg",
        "async def route(request):",
        "    asyncpg = request.driver",
        "    connection = await asyncpg.connect('postgres:///app')",
        "    return await connection.fetch(request.get_json())",
      ].join("\n"),
      "member-reassigned.py": [
        "import asyncpg",
        "async def route(request):",
        "    asyncpg.connect = request.factory",
        "    connection = await asyncpg.connect('postgres:///app')",
        "    return await connection.fetch(request.get_json())",
      ].join("\n"),
      "receiver-reassigned.py": [
        "import asyncpg",
        "async def route(request, connection: asyncpg.Connection):",
        "    connection = request.connection",
        "    return await connection.fetch(request.get_json())",
      ].join("\n"),
      "method-reassigned.py": [
        "import asyncpg",
        "async def route(request, connection: asyncpg.Connection):",
        "    connection.fetch = request.callback",
        "    return await connection.fetch(request.get_json())",
      ].join("\n"),
      "pool-cursor.py": [
        "import asyncpg",
        "async def route(request, pool: asyncpg.Pool):",
        "    async for row in pool.cursor(request.get_json()): pass",
      ].join("\n"),
      "pool-prepare.py": [
        "import asyncpg",
        "async def route(request, pool: asyncpg.Pool):",
        "    return await pool.prepare(request.get_json())",
      ].join("\n"),
      "wrong-keyword.py": typedRoute(
        "return await connection.executemany(query=query, args=[('x',)])",
      ),
      "missing-rows.py": typedRoute("return await connection.fetchmany(query)"),
      "missing-output.py": typedRoute(
        "return await connection.copy_from_query(query)",
      ),
      "starred.py": typedRoute(
        "return await connection.fetch(*request.get_json())",
      ),
    });

    expect(
      asyncpgRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("preserves a two-relay path to an awaited asyncpg sink", async () => {
    const repository = await writeRepository({
      "server.py": [
        "from .relay import lookup",
        "async def route(request, connection):",
        "    return await lookup(connection, request.get_json())",
      ].join("\n"),
      "relay.py": [
        "from .queries import execute",
        "async def lookup(connection, query):",
        "    return await execute(connection, query)",
      ].join("\n"),
      "queries.py": [
        "import asyncpg",
        "async def execute(connection: asyncpg.Connection, query):",
        "    return await connection.fetch(query)",
      ].join("\n"),
    });

    const records = asyncpgRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("queries.py");
  });

  test("keeps a perfect strict pair and canonical registration", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-asyncpg-sql-injection-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        expected: Array<{
          cwe?: string[];
          requiredValidationTextAnyOf?: string[][];
          requiredAttackPathTextAnyOf?: string[][];
          forbiddenText?: string[];
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
      "python-asyncpg-sql-injection",
      "python-asyncpg-bound-parameter",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-89"]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(9);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(8);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(6);
    expect(manifest.cases[1]?.expected).toEqual([]);

    const canonical = JSON.parse(
      await readFile(join(benchmarkRoot, "manifest.json"), "utf8"),
    ) as { cases: Array<{ id: string }> };
    const canonicalIndex = canonical.cases.findIndex(
      ({ id }) => id === manifest.cases[0]?.id,
    );
    expect(canonicalIndex).toBeGreaterThanOrEqual(0);
    expect(canonical.cases.slice(canonicalIndex, canonicalIndex + 2)).toEqual(
      manifest.cases,
    );
    for (const relativePath of [
      ".python-version",
      "requirements.txt",
      join("examples", "witness.py"),
      join("src", "server.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-asyncpg-sql-injection",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-asyncpg-bound-parameter",
            relativePath,
          ),
          "utf8",
        ),
      );
    }
  });

  test("emits only the vulnerable fixture's exact SQL grammar edge", async () => {
    const affected = asyncpgRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-asyncpg-sql-injection"),
      ),
    );
    const control = asyncpgRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-asyncpg-bound-parameter"),
      ),
    );
    expect(control).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]).toMatchObject({
      path: "src/accounts.py",
      line: 11,
      frameworkModel: {
        id: "python-asyncpg-sql",
        scope: "cross-file-wrapper",
        source: { kind: "fastapi-bound-parameter", path: "src/server.py" },
        sink: {
          kind: "asyncpg-fetch-sql-grammar",
          path: "src/accounts.py",
          line: 11,
          cweIds: ["CWE-89"],
        },
      },
    });
  });

  test("quality guidance preserves the asyncpg proof boundary", () => {
    const prompt = scanQualityGatePrompt("python-asyncpg-sql");
    expect(prompt).toContain("asyncpg");
    expect(prompt).toContain("copy_from_query");
    expect(prompt).toContain("fetchmany");
    expect(prompt).toContain("await");
    expect(prompt).toContain("bound");
    expect(prompt).toContain("PostgreSQL");
  });

  test("host re-audit enforces asyncpg validation and attack-path semantics", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "python-asyncpg-sql-injection",
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-asyncpg-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_asyncpg_quality",
      taxonomy: { cwe: ["CWE-89"] },
      locations: [
        { path: "src/server.py", startLine: 12, role: "source" },
        { path: "src/accounts.py", startLine: 11, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "request-source",
          path: "src/server.py",
          startLine: 12,
          code: "    username: Annotated[str, Query()], connection: asyncpg.Connection",
          explanation: "FastAPI binds the remote username.",
          role: "source",
        },
        {
          id: "asyncpg-sink",
          path: "src/accounts.py",
          startLine: 11,
          code: "    return await connection.fetch(query_copy)",
          explanation: "The copied query reaches awaited asyncpg fetch.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A remote string reaches a database call.",
        method: "static source trace and bounded argument recording",
        exploitWitness: "The recording connection observes changed query text.",
        negativeControl: "The matched control observes separate arguments.",
        evidence: ["request-source", "asyncpg-sink"],
        counterEvidence: "The control uses fixed SQL.",
        remainingUncertainty: "Deployment behavior remains unproved.",
      },
      attackPath: {
        summary: "A request reaches a query.",
        dataflow: {
          source: "request-source",
          sink: "asyncpg-sink",
          outcome: "database query",
        },
        reachability: {
          attacker: "remote caller",
          entrypoint: "FastAPI endpoint",
          outcome: "database behavior may change",
        },
        brokenControls: ["query text is constructed"],
        evidenceRefs: ["request-source", "asyncpg-sink"],
      },
    };
    const inventory = await buildResidualRiskInventory(repository);
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const incomplete = (
      await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      )
    )
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    expect(incomplete[1]).toMatchObject({
      findingId: "occ_asyncpg_quality",
      frameworkModelId: "python-asyncpg-sql",
      reasons: expect.arrayContaining([
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ]),
    });

    const semanticContract =
      "FastAPI remote request Query parameter username reaches the official asyncpg Connection query argument zero as SQL grammar, then await performs query execution through the PostgreSQL protocol and known server version. The fixed $1 bound parameter keeps the same protocol value outside grammar. Confirm database role authorization and a concrete unauthorized read before retaining CWE-89 SQL injection.";
    finding.validation.summary = semanticContract;
    finding.attackPath.summary = semanticContract;
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const complete = (
      await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      )
    )
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    expect(complete[1]?.reasons ?? []).not.toEqual(
      expect.arrayContaining([
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ]),
    );
  });
});
