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
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function kyselyRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-kysely-mysql-ddl-sql-injection",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "0.28.13",
  dependencySection = "dependencies",
  dependencyName = "kysely",
): Promise<void> {
  const root = join(repository, id);
  await mkdir(root, { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [dependencySection]: { [dependencyName]: version },
      },
      null,
      2,
    ),
  );
  await mkdir(dirname(join(root, "handler.mjs")), { recursive: true });
  await writeFile(join(root, "handler.mjs"), source);
}

async function writeNpmLock(
  repository: string,
  id: string,
  declaration: string,
  resolved: string,
  lockfileVersion = 3,
  rootDeclaration = declaration,
): Promise<void> {
  await writeFile(
    join(repository, id, "package-lock.json"),
    JSON.stringify(
      lockfileVersion === 1
        ? {
            name: id,
            lockfileVersion,
            dependencies: { kysely: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { kysely: rootDeclaration } },
              "node_modules/kysely": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const direct = (
  binding: string,
  construction = "const db = new Kysely({ dialect: new MysqlDialect({ pool: {} }) });",
  value = "request.query.status",
  terminal = ".compile()",
) =>
  `${binding}\n${construction}\nexport function handler(request) {\n  return db.schema.createIndex("idx").on("orders").column("status").where("status", "=", ${value})${terminal};\n}\n`;

describe("Kysely MySQL DDL literal SQL injection framework benchmark", () => {
  test("keeps a strict affected and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-kysely-mysql-ddl-sql-injection-manifest.json",
        ),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 1 || value === 0,
      ),
    ).toBe(true);
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-kysely-mysql-ddl-sql-injection",
      "node-multi-hop-patched-kysely-mysql-ddl-literal",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-89"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, compile sink, dialect, and dependency proof", async () => {
    const vulnerable = kyselyRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-kysely-mysql-ddl-sql-injection",
        ),
      ),
    );
    const repaired = kyselyRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-patched-kysely-mysql-ddl-literal",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(repaired).toHaveLength(0);
    expect(vulnerable[0]).toMatchObject({
      path: "src/storage.js",
      line: 17,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: { path: "src/server.js", line: 4 },
        sink: {
          kind: "vulnerable-kysely-mysql-ddl-literal-escape",
          cweIds: ["CWE-89"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "kysely-runtime-dependency",
      path: "package.json",
      line: 10,
      symbol: "kysely@0.28.13:manifest-exact:mysql-ddl-literal-escape:compile",
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "kysely-mysql-dialect",
      path: "src/storage.js",
      line: 9,
      symbol: "MysqlDialect",
    });
  });

  test("recognizes official bindings, schema aliases, and both execution terminals", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-kysely-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", direct('import { Kysely, MysqlDialect } from "kysely";')],
      [
        "aliased",
        direct(
          'import { Kysely as Database, MysqlDialect as Mysql } from "kysely";',
          "const db = new Database({ dialect: new Mysql({ pool: {} }) });",
          "request.query.status",
          ".execute()",
        ),
      ],
      [
        "namespace",
        direct(
          'import * as K from "kysely";',
          "const db = new K.Kysely({ dialect: new K.MysqlDialect({ pool: {} }) });",
        ),
      ],
      [
        "import-equals",
        direct(
          'import K = require("kysely");',
          "const db = new K.Kysely({ dialect: new K.MysqlDialect({ pool: {} }) });",
        ),
      ],
      [
        "commonjs",
        direct(
          'const { Kysely, MysqlDialect } = require("kysely");',
          "const db = new Kysely({ dialect: new MysqlDialect({ pool: {} }) });\nconst schema = db.schema;",
        ).replace("db.schema.createIndex", "schema.createIndex"),
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    expect(
      kyselyRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(cases.map(([id]) => `${id}/handler.mjs`).sort());
  });

  test("accepts only declaration-consistent modern lock evidence", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-kysely-locks-"),
    );
    temporaryPaths.push(repository);
    const source = direct('import { Kysely, MysqlDialect } from "kysely";');
    for (const id of ["vulnerable-lock", "patched-lock", "stale-lock", "v1"]) {
      await writeCase(repository, id, source, "^0.28.0");
    }
    await writeNpmLock(repository, "vulnerable-lock", "^0.28.0", "0.28.13");
    await writeNpmLock(repository, "patched-lock", "^0.28.0", "0.28.14");
    await writeNpmLock(
      repository,
      "stale-lock",
      "^0.28.0",
      "0.28.13",
      3,
      "0.27.0",
    );
    await writeNpmLock(repository, "v1", "^0.28.0", "0.28.13", 1);
    const records = kyselyRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.path).toBe("vulnerable-lock/handler.mjs");
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-kysely-mysql-ddl-literal-escape",
    );
  });

  test("fails closed across dialect, lifecycle, argument, provenance, identity, and mutation boundaries", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-kysely-negatives-"),
    );
    temporaryPaths.push(repository);
    const binding = 'import { Kysely, MysqlDialect } from "kysely";';
    const cases = [
      ["patched", direct(binding), "0.28.14", "dependencies", "kysely"],
      [
        "prerelease",
        direct(binding),
        "0.28.13-beta.1",
        "dependencies",
        "kysely",
      ],
      ["dev-only", direct(binding), "0.28.13", "devDependencies", "kysely"],
      [
        "wrong-package",
        direct(binding),
        "0.28.13",
        "dependencies",
        "not-kysely",
      ],
      [
        "fixed-value",
        direct(binding, undefined, '"active"'),
        "0.28.13",
        "dependencies",
        "kysely",
      ],
      [
        "no-execution",
        direct(binding, undefined, "request.query.status", ""),
        "0.28.13",
        "dependencies",
        "kysely",
      ],
      [
        "request-operator",
        direct(binding).replace(
          '.where("status", "=", request.query.status)',
          '.where("status", request.query.operator, "active")',
        ),
        "0.28.13",
        "dependencies",
        "kysely",
      ],
      [
        "ordinary-dml",
        direct(binding).replace(
          'db.schema.createIndex("idx").on("orders").column("status")',
          'db.selectFrom("orders").selectAll()',
        ),
        "0.28.13",
        "dependencies",
        "kysely",
      ],
      [
        "reassigned-instance",
        direct(binding).replace(
          "export function handler",
          "db = replacement;\nexport function handler",
        ),
        "0.28.13",
        "dependencies",
        "kysely",
      ],
      [
        "local-lookalike",
        direct(
          "class Kysely {}\nclass MysqlDialect {}",
          "const db = new Kysely({ dialect: new MysqlDialect({}) });",
        ),
        "0.28.13",
        "dependencies",
        "kysely",
      ],
    ] as const;
    for (const [id, source, version, section, name] of cases) {
      await writeCase(repository, id, source, version, section, name);
    }
    expect(kyselyRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("adds field-local validation guidance without overstating compiled SQL", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({
        frameworkModel: { id: "node-http-kysely-mysql-ddl-sql-injection" },
      }),
    );
    expect(prompt).toContain("GHSA-8cpq-38p9-67gx");
    expect(prompt).toContain("CreateIndexBuilder.where");
    expect(prompt).toContain("NO_BACKSLASH_ESCAPES");
    expect(prompt).toContain("compile() or execute()");
    expect(prompt).toContain("not database reachability");
  });
});
