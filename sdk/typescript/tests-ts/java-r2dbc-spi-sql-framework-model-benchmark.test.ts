import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  frameworkModel?: {
    id: string;
    scope: string;
    sink: { kind: string };
    propagators: Array<{ kind: string; symbol?: string }>;
  };
}

interface BenchmarkManifest {
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    fixture: string;
    findingsPaths: string[];
    expected: Array<{
      cwe: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
      requiredValidationTextAnyOf?: string[][];
      requiredAttackPathTextAnyOf?: string[][];
    }>;
  }>;
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

function spiRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter((record) => record.frameworkModel?.id === "java-r2dbc-spi-sql");
}

async function writeRepositoryFile(
  repository: string,
  relativePath: string,
  contents: string,
): Promise<void> {
  const path = join(repository, relativePath);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, contents);
}

async function writeDirectCase(
  repository: string,
  id: string,
  imports: string,
  fields: string,
  body: string,
): Promise<void> {
  await writeRepositoryFile(
    repository,
    `${id}/QueryController.java`,
    `${imports}
import org.springframework.web.bind.annotation.RequestParam;
public final class QueryController {
  ${fields}
  public Object lookup(@RequestParam String value) {
    ${body}
  }
}
`,
  );
}

describe("R2DBC SPI SQL-injection framework model", () => {
  test("covers all six official SPI grammar boundaries with execution closure", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-spi-positive-"),
    );
    temporaryPaths.push(repository);
    const connectionImport = "import io.r2dbc.spi.Connection;";
    await writeDirectCase(
      repository,
      "statement",
      connectionImport,
      "private final Connection connection = null;",
      "return connection.createStatement(value).execute();",
    );
    await writeDirectCase(
      repository,
      "batch",
      "import io.r2dbc.spi.Batch;",
      "private final Batch batch = null;",
      "return batch.add(value).execute();",
    );
    await writeDirectCase(
      repository,
      "create-savepoint",
      connectionImport,
      "private final Connection connection = null;",
      "return connection.createSavepoint(value);",
    );
    await writeDirectCase(
      repository,
      "release-savepoint",
      connectionImport,
      "private final Connection connection = null;",
      "return connection.releaseSavepoint(value);",
    );
    await writeDirectCase(
      repository,
      "rollback-savepoint",
      connectionImport,
      "private final Connection connection = null;",
      "return connection.rollbackTransactionToSavepoint(value);",
    );
    await writeDirectCase(
      repository,
      "generated-column",
      "import io.r2dbc.spi.Statement;",
      "private final Statement statement = null;",
      "return statement.returnGeneratedValues(value).execute();",
    );

    const records = spiRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path).sort()).toEqual([
      "batch/QueryController.java",
      "create-savepoint/QueryController.java",
      "generated-column/QueryController.java",
      "release-savepoint/QueryController.java",
      "rollback-savepoint/QueryController.java",
      "statement/QueryController.java",
    ]);
    expect(
      new Set(records.map((record) => record.frameworkModel?.sink.kind)),
    ).toEqual(
      new Set([
        "r2dbc-connection-statement-sql-grammar",
        "r2dbc-batch-sql-grammar",
        "r2dbc-connection-create-savepoint-identifier",
        "r2dbc-connection-release-savepoint-identifier",
        "r2dbc-connection-rollback-savepoint-identifier",
        "r2dbc-statement-generated-column-identifier",
      ]),
    );
    expect(
      records.every((record) =>
        record.frameworkModel?.propagators.some(
          ({ kind }) =>
            kind.includes("execution-stage") ||
            kind.includes("publisher-stage"),
        ),
      ),
    ).toBeTrue();
  });

  test("follows assigned Statement and Batch values into execute", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-spi-assigned-"),
    );
    temporaryPaths.push(repository);
    await writeDirectCase(
      repository,
      "statement",
      "import io.r2dbc.spi.Connection;\nimport io.r2dbc.spi.Statement;",
      "private final Connection connection = null;",
      "Statement statement = connection.createStatement(value); return statement.execute();",
    );
    await writeDirectCase(
      repository,
      "batch",
      "import io.r2dbc.spi.Batch;",
      "private final Batch batch = null;",
      "batch.add(value); return batch.execute();",
    );

    const records = spiRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(2);
    expect(
      records.map(
        (record) => record.frameworkModel?.propagators.at(-1)?.symbol,
      ),
    ).toEqual(["Batch.execute", "Statement.execute"]);
  });

  test("covers fluent Connection-created Batch and generated-value grammar", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-spi-fluent-"),
    );
    temporaryPaths.push(repository);
    await writeDirectCase(
      repository,
      "batch",
      "import io.r2dbc.spi.Connection;",
      "private final Connection connection = null;",
      "return connection.createBatch().add(value).execute();",
    );
    await writeDirectCase(
      repository,
      "generated-column",
      "import io.r2dbc.spi.Connection;",
      "private final Connection connection = null;",
      'return connection.createStatement("INSERT INTO audit(message) VALUES ($1)").returnGeneratedValues(value, "fixed_id").execute();',
    );

    const records = spiRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(2);
    expect(
      records.map((record) => record.frameworkModel?.sink.kind).sort(),
    ).toEqual([
      "r2dbc-batch-sql-grammar",
      "r2dbc-statement-generated-column-identifier",
    ]);
    expect(
      records.every((record) =>
        record.frameworkModel?.propagators.some(
          ({ symbol }) => symbol === "Connection connection",
        ),
      ),
    ).toBeTrue();
  });

  test("accepts qualified, wildcard, and live method-parameter SPI receivers", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-spi-type-forms-"),
    );
    temporaryPaths.push(repository);
    await writeDirectCase(
      repository,
      "qualified",
      "",
      "private final io.r2dbc.spi.Connection connection = null;",
      "return connection.createStatement(value).execute();",
    );
    await writeDirectCase(
      repository,
      "wildcard",
      "import io.r2dbc.spi.*;",
      "private final Connection connection = null; private final org.reactivestreams.Subscriber<Void> subscriber = null;",
      "connection.createSavepoint(value).subscribe(subscriber); return null;",
    );
    await writeRepositoryFile(
      repository,
      "parameter/QueryController.java",
      `import io.r2dbc.spi.Connection;
import org.springframework.web.bind.annotation.RequestParam;
public final class QueryController {
  public Object lookup(@RequestParam String value, Connection connection) {
    return connection.createStatement(value).execute();
  }
}`,
    );

    const records = spiRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path).sort()).toEqual([
      "parameter/QueryController.java",
      "qualified/QueryController.java",
      "wildcard/QueryController.java",
    ]);
    expect(
      records
        .find(({ path }) => path.startsWith("wildcard/"))
        ?.frameworkModel?.propagators.at(-1)?.symbol,
    ).toBe("Connection.createSavepoint:subscribe");
  });

  test("rejects bound data, inert calls, lookalikes, wrong arity, and reassignment", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-spi-negative-"),
    );
    temporaryPaths.push(repository);
    await writeDirectCase(
      repository,
      "bound",
      "import io.r2dbc.spi.Connection;\nimport io.r2dbc.spi.Statement;",
      "private final Connection connection = null;",
      'Statement statement = connection.createStatement("SELECT * FROM accounts WHERE username = $1"); statement.bind(0, value); return statement.execute();',
    );
    await writeDirectCase(
      repository,
      "inert",
      "import io.r2dbc.spi.Connection;",
      "private final Connection connection = null;",
      "return connection.createStatement(value);",
    );
    await writeDirectCase(
      repository,
      "statement-add",
      "import io.r2dbc.spi.Statement;",
      "private final Statement statement = null;",
      "return statement.add(value).execute();",
    );
    await writeDirectCase(
      repository,
      "wrong-arity",
      "import io.r2dbc.spi.Connection;",
      "private final Connection connection = null;",
      "return connection.createStatement(value, value).execute();",
    );
    await writeDirectCase(
      repository,
      "reassigned",
      "import io.r2dbc.spi.Batch;",
      "private Batch batch; private final Batch replacement = null;",
      "batch = replacement; return batch.add(value).execute();",
    );
    await writeDirectCase(
      repository,
      "reassigned-after-add",
      "import io.r2dbc.spi.Batch;",
      "private Batch batch; private final Batch replacement = null;",
      "batch.add(value); batch = replacement; return batch.execute();",
    );
    await writeDirectCase(
      repository,
      "statement-reassigned-before-execute",
      "import io.r2dbc.spi.Connection;\nimport io.r2dbc.spi.Statement;",
      "private final Connection connection = null; private final Statement replacement = null;",
      "Statement statement = connection.createStatement(value); statement = replacement; return statement.execute();",
    );
    await writeDirectCase(
      repository,
      "local-lookalike",
      "final class Connection { Connection createStatement(String sql) { return this; } Connection execute() { return this; } }",
      "private final Connection connection = new Connection();",
      "return connection.createStatement(value).execute();",
    );
    await writeDirectCase(
      repository,
      "java-sql-lookalike",
      "import java.sql.Statement;",
      "private final Statement statement = null;",
      "return statement.returnGeneratedValues(value).execute();",
    );
    await writeDirectCase(
      repository,
      "unconsumed-savepoint",
      "import io.r2dbc.spi.Connection;",
      "private final Connection connection = null;",
      "connection.createSavepoint(value); return null;",
    );

    expect(spiRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("preserves a typed controller-to-service-to-Statement path", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-spi-relay-"),
    );
    temporaryPaths.push(repository);
    await writeRepositoryFile(
      repository,
      "pom.xml",
      `<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>spi-test</artifactId><version>1</version></project>`,
    );
    await writeRepositoryFile(
      repository,
      "src/QueryController.java",
      `import org.springframework.web.bind.annotation.RequestParam;
public final class QueryController {
  private final QueryService service;
  public Object lookup(@RequestParam String sql) { return service.lookup(sql); }
}`,
    );
    await writeRepositoryFile(
      repository,
      "src/QueryService.java",
      `public final class QueryService {
  private final QueryStore store;
  public Object lookup(String sql) { return store.lookup(sql); }
}`,
    );
    await writeRepositoryFile(
      repository,
      "src/QueryStore.java",
      `import io.r2dbc.spi.Connection;
public final class QueryStore {
  private final Connection connection;
  public Object lookup(String sql) { return connection.createStatement(sql).execute(); }
}`,
    );

    const records = spiRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "Statement.execute",
    );
  });

  test("follows a local SQL variable through a constructor-initialized final Connection", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-spi-constructor-"),
    );
    temporaryPaths.push(repository);
    await writeRepositoryFile(
      repository,
      "QueryController.java",
      `import io.r2dbc.spi.Connection;
import org.springframework.web.bind.annotation.RequestParam;
public final class QueryController {
  private final Connection connection;
  public QueryController(Connection connection) { this.connection = connection; }
  public Object lookup(@RequestParam String value) {
    String sql =
        "SELECT * FROM accounts WHERE username = '" + value + "'";
    return connection.createStatement(sql).execute();
  }
}`,
    );

    const records = spiRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "r2dbc-connection-statement-sql-grammar",
    );
  });

  test("resolves a same-package controller wrapper into the typed store", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-spi-package-"),
    );
    temporaryPaths.push(repository);
    await writeRepositoryFile(
      repository,
      "pom.xml",
      `<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>spi-test</artifactId><version>1</version></project>`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/example/QueryController.java",
      `package example;
import io.r2dbc.spi.Result;
import org.reactivestreams.Publisher;
import org.springframework.web.bind.annotation.RequestParam;
public final class QueryController {
  private final QueryStore store;
  public QueryController(QueryStore store) { this.store = store; }
  public Publisher<? extends Result> lookup(@RequestParam String value) { return store.lookup(value); }
}`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/example/QueryStore.java",
      `package example;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.Result;
import org.reactivestreams.Publisher;
public final class QueryStore {
  private final Connection connection;
  public QueryStore(Connection connection) { this.connection = connection; }
  public Publisher<? extends Result> lookup(String value) {
    String sql = "SELECT * FROM accounts WHERE username = '" + value + "'";
    return connection.createStatement(sql).execute();
  }
}`,
    );

    const records = spiRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
  });

  test("detects the executable fixture and suppresses its bound control", async () => {
    const positive = resolve(
      benchmarkRoot,
      "fixtures/java-r2dbc-spi-statement-sql-injection",
    );
    const control = resolve(
      benchmarkRoot,
      "fixtures/java-r2dbc-spi-statement-bound-parameter",
    );
    const positiveRecords = spiRecords(
      await buildResidualRiskInventory(positive),
    );
    const controlRecords = spiRecords(
      await buildResidualRiskInventory(control),
    );

    expect(positiveRecords).toHaveLength(1);
    expect(positiveRecords[0]?.path).toBe(
      "src/main/java/example/AccountQueries.java",
    );
    expect(controlRecords).toEqual([]);
  });

  test("registers a strict repeated-run exploit/control benchmark", async () => {
    const manifest = JSON.parse(
      await readFile(
        resolve(benchmarkRoot, "java-r2dbc-spi-sql-injection-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "java-r2dbc-spi-statement-sql-injection",
      "java-r2dbc-spi-statement-bound-parameter",
    ]);
    expect(
      manifest.cases.every(({ findingsPaths }) => findingsPaths.length === 3),
    ).toBeTrue();
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-89"]);
    expect(manifest.cases[0]?.expected[0]?.requireValidation).toBeTrue();
    expect(manifest.cases[0]?.expected[0]?.requireAttackPath).toBeTrue();
    expect(manifest.cases[0]?.expected[0]?.requireCodeEvidence).toBeTrue();
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf?.length,
    ).toBeGreaterThanOrEqual(8);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf?.length,
    ).toBeGreaterThanOrEqual(8);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 1 || value === 0,
      ),
    ).toBeTrue();
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
  });

  test("requires grammar, execution, result consumption, and identifier validation", () => {
    const prompt = scanQualityGatePrompt("java-r2dbc-spi-sql");
    expect(prompt).toContain("io.r2dbc.spi");
    expect(prompt).toContain("createStatement");
    expect(prompt).toContain("Batch.add");
    expect(prompt).toContain("savepoint");
    expect(prompt).toContain("returnGeneratedValues");
    expect(prompt).toContain("fully consumed");
    expect(prompt).toContain("bind or bindNull");
  });
});
