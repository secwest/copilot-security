import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
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

function sequelizeOracleRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-sequelize-oracle-sql-injection",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "6.37.3",
  dependencySection = "dependencies",
  dependencyName = "sequelize",
  filename = "handler.mjs",
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
  await writeFile(join(root, filename), source);
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
            dependencies: { sequelize: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { sequelize: rootDeclaration } },
              "node_modules/sequelize": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const source = (
  constructorBinding = 'import { Sequelize } from "sequelize";',
  constructorExpression = "Sequelize",
  operation = "findOne",
  arguments_ = "{ where: { firstName: request.query.firstName } }",
  configuration = '{ dialect: "oracle" }',
) =>
  `${constructorBinding}\nconst database = new ${constructorExpression}("students", "app", "password", ${configuration});\nconst Student = database.define("Student", {});\nexport function handler(request) { return Student.${operation}(${arguments_}); }\n`;

describe("Sequelize Oracle SQL injection framework benchmark", () => {
  test("keeps a strict vulnerable and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-sequelize-oracle-sql-injection-manifest.json",
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
      "node-multi-hop-sequelize-oracle-sql-injection",
      "node-multi-hop-repaired-sequelize-oracle-query",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-89"],
      acceptableSeverities: ["critical", "high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, ORM sink, dialect, and dependency proof", async () => {
    const vulnerable = sequelizeOracleRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-sequelize-oracle-sql-injection",
        ),
      ),
    );
    const repaired = sequelizeOracleRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-repaired-sequelize-oracle-query",
        ),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/storage.js",
      line: 14,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: { path: "src/server.js", line: 7, kind: "http-request-field" },
        sink: {
          path: "src/storage.js",
          line: 14,
          kind: "vulnerable-sequelize-oracle-string-escape",
          cweIds: ["CWE-89"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "sequelize-runtime-dependency",
          path: "package.json",
          symbol:
            "sequelize@6.37.3:manifest-exact:oracle-string-escape-sql-injection",
        }),
        expect.objectContaining({
          kind: "sequelize-oracle-dialect",
          path: "src/storage.js",
          line: 4,
          symbol: "dialect:oracle",
        }),
        expect.objectContaining({ kind: "relative-module-import" }),
        expect.objectContaining({ kind: "wrapper-parameter" }),
      ]),
    );
  });

  test("accepts official constructor forms, static Oracle configuration, and modeled ORM operations", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-sequelize-oracle-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", source()],
      [
        "named-alias",
        source(
          'import { Sequelize as OracleOrm } from "sequelize";',
          "OracleOrm",
        ),
      ],
      ["default", source('import Sequelize from "sequelize";')],
      [
        "namespace",
        source('import * as orm from "sequelize";', "orm.Sequelize"),
      ],
      [
        "import-equals",
        source('import Sequelize = require("sequelize");'),
        "handler.ts",
      ],
      [
        "commonjs-destructure",
        source('const { Sequelize } = require("sequelize");'),
      ],
      ["commonjs-direct", source('const Sequelize = require("sequelize");')],
      [
        "static-uri",
        'import { Sequelize } from "sequelize";\nconst database = new Sequelize("oracle://app:password@database/students");\nconst Student = database.define("Student", {});\nexport function handler(request) { return Student.findOne({ where: { firstName: request.query.firstName } }); }\n',
      ],
      [
        "resolved-config",
        'import { Sequelize } from "sequelize";\nconst dialect = "oracle";\nconst options = { dialect };\nconst database = new Sequelize("students", "app", "password", options);\nconst Student = database.define("Student", {});\nexport function handler(request) { return Student.findOne({ where: { firstName: request.query.firstName } }); }\n',
      ],
      ["count", source(undefined, undefined, "count")],
      ["destroy", source(undefined, undefined, "destroy")],
      ["find-all", source(undefined, undefined, "findAll")],
      ["find-and-count", source(undefined, undefined, "findAndCountAll")],
      [
        "update",
        source(
          undefined,
          undefined,
          "update",
          '{ status: "active" }, { where: { firstName: request.query.firstName } }',
        ),
      ],
    ] as const;
    for (const [id, code, filename = "handler.mjs"] of cases) {
      await writeCase(
        repository,
        id,
        code,
        "6.37.3",
        "dependencies",
        "sequelize",
        filename,
      );
    }

    expect(
      sequelizeOracleRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(
      cases
        .map(([id, , filename = "handler.mjs"]) => `${id}/${filename}`)
        .sort(),
    );
  });

  test("enforces the repaired boundary and stable versions", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-sequelize-oracle-versions-"),
    );
    temporaryPaths.push(repository);
    const vulnerable = ["5.22.5", "6.0.0", "6.37.2", "6.37.3"];
    const safe = ["6.37.4", "6.37.5", "7.0.0", "6.37.3-beta.1"];
    for (const version of [...vulnerable, ...safe]) {
      await writeCase(
        repository,
        `v-${version.replaceAll(".", "-")}`,
        source(),
        version,
      );
    }
    expect(
      sequelizeOracleRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    ).toEqual(
      vulnerable.map((version) => `v-${version.replaceAll(".", "-")}`).sort(),
    );
  });

  test("rejects non-Oracle, non-predicate, lookalike, replaced, and inert shapes", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-sequelize-oracle-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "mysql",
        source(
          undefined,
          undefined,
          undefined,
          undefined,
          '{ dialect: "mysql" }',
        ),
      ],
      [
        "dynamic-dialect",
        source(
          undefined,
          undefined,
          undefined,
          undefined,
          "{ dialect: process.env.DIALECT }",
        ),
      ],
      [
        "fixed-where",
        source(
          undefined,
          undefined,
          undefined,
          '{ where: { firstName: "Alice" } }',
        ),
      ],
      [
        "request-outside-where",
        source(
          undefined,
          undefined,
          undefined,
          '{ where: { firstName: "Alice" }, logging: request.query.logging }',
        ),
      ],
      [
        "missing-where",
        source(
          undefined,
          undefined,
          undefined,
          "{ limit: request.query.limit }",
        ),
      ],
      [
        "package-only",
        'import { Sequelize } from "sequelize";\nexport function handler(request) { return request.query.firstName; }\n',
      ],
      [
        "local-lookalike",
        source('import { Sequelize } from "./sequelize.js";'),
      ],
      [
        "constructor-shadow",
        'import { Sequelize } from "sequelize";\nexport function handler(Sequelize, request) { const database = new Sequelize("db", "u", "p", { dialect: "oracle" }); const Student = database.define("Student", {}); return Student.findOne({ where: { firstName: request.query.firstName } }); }\n',
      ],
      [
        "instance-reassigned",
        'import { Sequelize } from "sequelize";\nlet database = new Sequelize("db", "u", "p", { dialect: "oracle" });\ndatabase = safeDatabase;\nconst Student = database.define("Student", {});\nexport function handler(request) { return Student.findOne({ where: { firstName: request.query.firstName } }); }\n',
      ],
      [
        "model-reassigned",
        'import { Sequelize } from "sequelize";\nconst database = new Sequelize("db", "u", "p", { dialect: "oracle" });\nlet Student = database.define("Student", {});\nStudent = SafeStudent;\nexport function handler(request) { return Student.findOne({ where: { firstName: request.query.firstName } }); }\n',
      ],
      [
        "define-replaced",
        'import { Sequelize } from "sequelize";\nconst database = new Sequelize("db", "u", "p", { dialect: "oracle" });\ndatabase.define = safeDefine;\nconst Student = database.define("Student", {});\nexport function handler(request) { return Student.findOne({ where: { firstName: request.query.firstName } }); }\n',
      ],
      [
        "orm-member-replaced",
        'import { Sequelize } from "sequelize";\nconst database = new Sequelize("db", "u", "p", { dialect: "oracle" });\nconst Student = database.define("Student", {});\nStudent.findOne = safeFindOne;\nexport function handler(request) { return Student.findOne({ where: { firstName: request.query.firstName } }); }\n',
      ],
    ] as const;
    for (const [id, code] of cases) await writeCase(repository, id, code);
    expect(
      sequelizeOracleRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exact production provenance or a declaration-consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-sequelize-oracle-dependencies-"),
    );
    temporaryPaths.push(repository);
    await writeCase(repository, "locked-range", source(), "^6.30.0");
    await writeNpmLock(repository, "locked-range", "^6.30.0", "6.37.3");
    await writeCase(repository, "unlocked-range", source(), "^6.30.0");
    await writeCase(repository, "v1-lock", source(), "^6.30.0");
    await writeNpmLock(repository, "v1-lock", "^6.30.0", "6.37.3", 1);
    await writeCase(repository, "inconsistent-lock", source(), "^6.37.4");
    await writeNpmLock(
      repository,
      "inconsistent-lock",
      "^6.37.4",
      "6.37.3",
      3,
      "^6.30.0",
    );
    await writeCase(
      repository,
      "dev-only",
      source(),
      "6.37.3",
      "devDependencies",
    );
    await writeCase(
      repository,
      "wrong-package",
      source(),
      "6.37.3",
      "dependencies",
      "sequelize-clone",
    );

    const records = sequelizeOracleRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "locked-range/handler.mjs",
    ]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-sequelize-oracle-string-escape",
    );
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "sequelize-runtime-dependency",
          symbol:
            "sequelize@6.37.3:npm-lockfile:oracle-string-escape-sql-injection",
        }),
      ]),
    );
  });

  test("keeps application sources identical and excludes test/example trees", async () => {
    for (const relative of [
      "src/server.js",
      "src/gateway.js",
      "src/service.js",
      "src/storage.js",
      "witness.mjs",
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-sequelize-oracle-sql-injection",
            relative,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-repaired-sequelize-oracle-query",
            relative,
          ),
          "utf8",
        ),
      );
    }
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-sequelize-oracle-exclusions-"),
    );
    temporaryPaths.push(repository);
    for (const directory of [
      "test",
      "tests",
      "__tests__",
      "example",
      "examples",
    ]) {
      await writeCase(repository, directory, source());
    }
    expect(
      sequelizeOracleRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exploit-specific SQL-generation validation", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-sequelize-oracle-sql-injection");
    expect(prompt).toContain("GHSA-v8fg-2rw7-q452");
    expect(prompt).toContain("CVE-2026-69240");
    expect(prompt).toContain("query generator without contacting a database");
    expect(prompt).toContain("6.37.4 rejects the identical payload");
    expect(prompt).toContain("Report CWE-89 only");
  });
});
