import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

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

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    findingsPaths: string[];
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
  "java-r2dbc-databaseclient-sql-injection",
  "java-r2dbc-databaseclient-bound-parameter",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function r2dbcRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter((record) => record.frameworkModel?.id === "spring-r2dbc-sql");
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
  body: string,
  prelude = "private final DatabaseClient client = DatabaseClient.create(null);",
  imports = "import org.springframework.r2dbc.core.DatabaseClient;",
): Promise<void> {
  await writeRepositoryFile(
    repository,
    `${id}/QueryController.java`,
    `${imports}
import org.springframework.web.bind.annotation.RequestParam;
public final class QueryController {
  ${prelude}
  public Object lookup(@RequestParam String username) {
    ${body}
  }
}
`,
  );
}

describe("Spring R2DBC DatabaseClient SQL-injection benchmark", () => {
  test("keeps a strict executable interpolation and bound-value pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "java-r2dbc-sql-injection-manifest.json"),
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
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(3);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-89"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the controller, wrapper, SQL grammar, and execution stage", async () => {
    const vulnerable = r2dbcRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const control = r2dbcRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(control).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/main/java/example/AccountQueries.java",
      line: 17,
      frameworkModel: {
        scope: "cross-file-wrapper",
        source: {
          kind: "spring-bound-parameter",
          path: "src/main/java/example/AccountController.java",
          line: 16,
        },
        sink: {
          kind: "r2dbc-databaseclient-sql-grammar",
          path: "src/main/java/example/AccountQueries.java",
          line: 17,
          cweIds: ["CWE-89"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "r2dbc-databaseclient-execution-stage",
      path: "src/main/java/example/AccountQueries.java",
      line: 17,
      symbol: "fetch",
    });
  });

  test("accepts direct and Supplier SQL across documented execution stages", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-positive-"),
    );
    temporaryPaths.push(repository);
    await writeDirectCase(
      repository,
      "direct",
      "return client.sql(username).then();",
    );
    await writeDirectCase(
      repository,
      "supplier",
      "return client.sql(() -> username).mapValue(row -> row);",
    );
    await writeDirectCase(
      repository,
      "multiline",
      "return client\n        .sql(username)\n        .fetch()\n        .one();",
    );
    await writeDirectCase(
      repository,
      "qualified",
      "return client.sql(username).flatMap(result -> null);",
      "private final org.springframework.r2dbc.core.DatabaseClient client = null;",
      "",
    );

    const records = r2dbcRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path).sort()).toEqual([
      "direct/QueryController.java",
      "multiline/QueryController.java",
      "qualified/QueryController.java",
      "supplier/QueryController.java",
    ]);
    expect(
      records.map(
        (record) =>
          record.frameworkModel?.propagators.find(
            ({ kind }) => kind === "r2dbc-databaseclient-execution-stage",
          )?.symbol,
      ),
    ).toEqual(["then", "fetch", "flatMap", "mapValue"]);
  });

  test("rejects binding-only flow, inert specifications, lookalikes, and reassignment", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-negative-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "bound",
        'return client.sql("SELECT * FROM accounts WHERE username = :username").bind("username", username).fetch().one();',
      ],
      ["inert", "return client.sql(username);"],
      [
        "bind-no-execution",
        'return client.sql("SELECT 1").bind("p", username);',
      ],
      ["after-semicolon", "client.sql(username); return client.fetch();"],
      ["fixed", 'return client.sql("SELECT 1").fetch().one();'],
      ["malformed", "return client.sql(username, username).fetch().one();"],
    ] as const;
    for (const [id, body] of cases) {
      await writeDirectCase(repository, id, body);
    }
    await writeDirectCase(
      repository,
      "reassigned",
      "client = replacement; return client.sql(username).fetch().one();",
      "private DatabaseClient client; private final DatabaseClient replacement = null;",
    );
    await writeDirectCase(
      repository,
      "local-lookalike",
      "return client.sql(username).fetch();",
      "private final DatabaseClient client = new DatabaseClient();",
      "final class DatabaseClient { DatabaseClient sql(String value) { return this; } DatabaseClient fetch() { return this; } }",
    );

    expect(r2dbcRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("retains the execution stage after two typed service boundaries", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-relay-"),
    );
    temporaryPaths.push(repository);
    await writeRepositoryFile(
      repository,
      "src/AccountController.java",
      `import org.springframework.web.bind.annotation.RequestParam;
public final class AccountController {
  private final AccountService service;
  public Object lookup(@RequestParam String username) { return service.lookup(username); }
}`,
    );
    await writeRepositoryFile(
      repository,
      "src/AccountService.java",
      `public final class AccountService {
  private final AccountQueries queries;
  public Object lookup(String username) { return queries.lookup(username); }
}`,
    );
    await writeRepositoryFile(
      repository,
      "src/AccountQueries.java",
      `import org.springframework.r2dbc.core.DatabaseClient;
public final class AccountQueries {
  private final DatabaseClient client;
  public Object lookup(String username) { return client.sql(username).fetch().one(); }
}`,
    );

    const records = r2dbcRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.propagators.at(-1)).toEqual({
      kind: "r2dbc-databaseclient-execution-stage",
      path: "src/AccountQueries.java",
      line: 4,
      symbol: "fetch",
    });
  });

  test("separates identical Java type names in sibling Maven projects", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-r2dbc-project-scope-"),
    );
    temporaryPaths.push(repository);
    for (const project of ["vulnerable", "control"]) {
      await writeRepositoryFile(
        repository,
        `${project}/pom.xml`,
        "<project />",
      );
      await writeRepositoryFile(
        repository,
        `${project}/src/main/java/example/AccountController.java`,
        `package example;
import org.springframework.web.bind.annotation.RequestParam;
public final class AccountController {
  private final AccountService service;
  public Object lookup(@RequestParam String username) { return service.lookup(username); }
}`,
      );
      await writeRepositoryFile(
        repository,
        `${project}/src/main/java/example/AccountService.java`,
        `package example;
public final class AccountService {
  private final AccountQueries queries;
  public Object lookup(String username) { return queries.lookup(username); }
}`,
      );
      await writeRepositoryFile(
        repository,
        `${project}/src/main/java/example/AccountQueries.java`,
        `package example;
import org.springframework.r2dbc.core.DatabaseClient;
public final class AccountQueries {
  private final DatabaseClient client;
  public Object lookup(String username) { return ${
    project === "vulnerable"
      ? "client.sql(username).fetch().one()"
      : 'client.sql("SELECT * FROM accounts WHERE username = :username").bind("username", username).fetch().one()'
  }; }
}`,
      );
    }

    const records = r2dbcRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      path: "vulnerable/src/main/java/example/AccountQueries.java",
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: {
          path: "vulnerable/src/main/java/example/AccountController.java",
        },
      },
    });
  });

  test("retains the vulnerable fixture under whole-repository saturation", async () => {
    const records = r2dbcRecords(
      await buildResidualRiskInventory(resolve(benchmarkRoot, "..")),
    );

    expect(records.map(({ path }) => path)).toEqual([
      "benchmarks/fixtures/java-r2dbc-databaseclient-sql-injection/src/main/java/example/AccountQueries.java",
    ]);
    expect(
      records.some(({ path }) =>
        path.includes("java-r2dbc-databaseclient-bound-parameter"),
      ),
    ).toBeFalse();
  }, 120_000);

  test("requires grammar, reactive-consumption, dialect, and impact validation", () => {
    const prompt = scanQualityGatePrompt("spring-r2dbc-sql");
    expect(prompt).toContain(
      "value occupying DatabaseClient.sql's SQL-grammar argument",
    );
    expect(prompt).toContain(
      "fixed server-owned SQL statement with the same request value passed only through bind or bindNull",
    );
    expect(prompt).toContain(
      "verify that the returned Publisher is consumed or returned into an active reactive chain",
    );
    expect(prompt).toContain("deployed R2DBC driver and database dialect");
    expect(prompt).toContain(
      "concrete unauthorized read, write, or availability effect",
    );
  });
});
