import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface LogtapeRecord {
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

interface CaseOptions {
  declaration?: string;
  dependencySection?: "dependencies" | "devDependencies";
  lock?: boolean;
  lockedVersion?: string;
  packageName?: string;
  source?: string;
}

const temporaryPaths: string[] = [];

const defaultSource = `import { configure, getLogger } from "@logtape/logtape";
import { getSyslogSink } from "@logtape/syslog";
await configure({
  sinks: { security: getSyslogSink({ includeStructuredData: true }) },
  loggers: [{ category: ["audit"], sinks: ["security"] }],
});
const auditLogger = getLogger(["audit"]);
export function auditRequest(request) {
  auditLogger.info("request audited", { audit: request.body.audit });
}
`;

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function logtapeRecords(inventory: string): LogtapeRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as LogtapeRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-logtape-syslog-structured-data-injection",
    );
}

async function temporaryRepository(label: string): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), `copilot-security-logtape-${label}-`),
  );
  temporaryPaths.push(repository);
  return repository;
}

async function writeCase(
  repository: string,
  id: string,
  options: CaseOptions = {},
): Promise<void> {
  const root = join(repository, id);
  const declaration = options.declaration ?? "2.1.4";
  const dependencySection = options.dependencySection ?? "dependencies";
  const packageName = options.packageName ?? "@logtape/syslog";
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [dependencySection]: {
          "@logtape/logtape": "2.1.4",
          [packageName]: declaration,
        },
      },
      null,
      2,
    ),
  );
  if (options.lock === true) {
    await writeFile(
      join(root, "package-lock.json"),
      JSON.stringify(
        {
          name: id,
          lockfileVersion: 3,
          packages: {
            "": {
              [dependencySection]: {
                "@logtape/logtape": "2.1.4",
                [packageName]: declaration,
              },
            },
            "node_modules/@logtape/syslog": {
              version: options.lockedVersion ?? "2.1.4",
            },
          },
        },
        null,
        2,
      ),
    );
  }
  await writeFile(
    join(root, "src", "audit.js"),
    options.source ?? defaultSource,
  );
}

describe("LogTape syslog structured-data injection model", () => {
  test("requires the affected dependency and complete connected topology", async () => {
    const repository = await temporaryRepository("topology");
    await writeCase(repository, "affected");
    const records = logtapeRecords(
      await buildResidualRiskInventory(join(repository, "affected")),
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      path: "src/audit.js",
      line: 9,
      frameworkModel: {
        id: "node-logtape-syslog-structured-data-injection",
        scope: "same-file",
        source: {
          kind: "remote-request-body",
          path: "src/audit.js",
          line: 9,
        },
        sink: {
          kind: "vulnerable-logtape-syslog-structured-data-value",
          path: "src/audit.js",
          line: 9,
          cweIds: ["CWE-93", "CWE-117"],
        },
      },
    });
    expect(
      records[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "remote-log-record-property",
      "official-logtape-logger-binding",
      "connected-logtape-syslog-sink",
      "official-logtape-configure-binding",
      "enabled-logtape-structured-data",
      "official-logtape-syslog-binding",
      "logtape-syslog-runtime-dependency",
    ]);
    expect(records[0]?.frameworkModel?.propagators[0]?.symbol).toBe(
      "structured-data-value:request.body.audit",
    );
  });

  test("accepts every reviewed affected release line and exact lock provenance", async () => {
    const repository = await temporaryRepository("versions");
    const versions = ["0.9.0", "1.3.10", "2.0.0", "2.0.13", "2.1.0", "2.1.4"];
    for (const version of versions) {
      await writeCase(repository, `affected-${version}`, {
        declaration: version,
      });
      expect(
        logtapeRecords(
          await buildResidualRiskInventory(
            join(repository, `affected-${version}`),
          ),
        ),
        version,
      ).toHaveLength(1);
    }
    await writeCase(repository, "affected-lock", {
      declaration: "^2.1.0",
      lock: true,
      lockedVersion: "2.1.4",
    });
    const lockRecords = logtapeRecords(
      await buildResidualRiskInventory(join(repository, "affected-lock")),
    );
    expect(lockRecords).toHaveLength(1);
    expect(lockRecords[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-logtape-syslog-structured-data-value",
    );
    expect(lockRecords[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "@logtape/syslog@2.1.4:npm-lockfile:unescaped-structured-data",
    );
  });

  test("recognizes remote values, computed names, spreads, and root categories", async () => {
    const repository = await temporaryRepository("sources");
    const variants = [
      {
        id: "computed-key",
        source: defaultSource.replace(
          `{ audit: request.body.audit }`,
          `{ [request.body.field]: "fixed" }`,
        ),
        boundary: "structured-data-key",
      },
      {
        id: "spread-body",
        source: defaultSource.replace(
          `{ audit: request.body.audit }`,
          `{ ...request.body }`,
        ),
        boundary: "structured-data-key",
      },
      {
        id: "query-string",
        source: defaultSource.replace(
          `request.body.audit`,
          `String(request.query.audit)`,
        ),
        boundary: "structured-data-value",
      },
      {
        id: "root-category",
        source: defaultSource
          .replace(`category: ["audit"]`, `category: []`)
          .replace(`getLogger(["audit"])`, `getLogger(["audit", "http"])`),
        boundary: "structured-data-value",
      },
    ];
    for (const variant of variants) {
      await writeCase(repository, variant.id, { source: variant.source });
      const records = logtapeRecords(
        await buildResidualRiskInventory(join(repository, variant.id)),
      );
      expect(records, variant.id).toHaveLength(1);
      expect(records[0]?.frameworkModel?.sink.kind).toContain(variant.boundary);
    }
  });

  test("recognizes official aliases, receivers, and resolved topology objects", async () => {
    const repository = await temporaryRepository("bindings");
    const application = (
      imports: string,
      configureCall: string,
      loggerCall: string,
      sinkCall: string,
    ) => `${imports}
const syslogOptions = { includeStructuredData: true };
const securitySink = ${sinkCall}(syslogOptions);
const sinkMap = { security: securitySink };
const loggerRules = [{ category: ["audit"], sinks: ["security"] }];
const logtapeOptions = { sinks: sinkMap, loggers: loggerRules };
await ${configureCall}(logtapeOptions);
const auditLogger = ${loggerCall}(["audit"]);
export function auditRequest(request) {
  auditLogger.warning("request audited", { audit: request.headers["x-audit"] });
}
`;
    const variants = [
      {
        id: "named-aliases",
        source: application(
          `import { configure as setup, getLogger as loggerFor } from "@logtape/logtape";\nimport { getSyslogSink as syslog } from "@logtape/syslog";`,
          "setup",
          "loggerFor",
          "syslog",
        ),
      },
      {
        id: "namespaces",
        source: application(
          `import * as Tape from "@logtape/logtape";\nimport * as Syslog from "@logtape/syslog";`,
          "Tape.configure",
          "Tape.getLogger",
          "Syslog.getSyslogSink",
        ),
      },
      {
        id: "typescript-import-equals",
        source: application(
          `import Tape = require("@logtape/logtape");\nimport Syslog = require("@logtape/syslog");`,
          "Tape.configure",
          "Tape.getLogger",
          "Syslog.getSyslogSink",
        ),
      },
      {
        id: "commonjs-receivers",
        source: application(
          `const Tape = require("@logtape/logtape");\nconst Syslog = require("@logtape/syslog");`,
          "Tape.configure",
          "Tape.getLogger",
          "Syslog.getSyslogSink",
        ),
      },
      {
        id: "commonjs-direct-members",
        source: application(
          `const setup = require("@logtape/logtape").configure;\nconst loggerFor = require("@logtape/logtape").getLogger;\nconst syslog = require("@logtape/syslog").getSyslogSink;`,
          "setup",
          "loggerFor",
          "syslog",
        ),
      },
      {
        id: "commonjs-destructured",
        source: application(
          `const { configure: setup, getLogger: loggerFor } = require("@logtape/logtape");\nconst { getSyslogSink: syslog } = require("@logtape/syslog");`,
          "setup",
          "loggerFor",
          "syslog",
        ),
      },
    ];
    for (const variant of variants) {
      await writeCase(repository, variant.id, { source: variant.source });
      expect(
        logtapeRecords(
          await buildResidualRiskInventory(join(repository, variant.id)),
        ),
        variant.id,
      ).toHaveLength(1);
    }
  });

  test("rejects repaired, unproved, wrong, and development-only dependencies", async () => {
    const repository = await temporaryRepository("provenance-negatives");
    const cases: Array<[string, CaseOptions]> = [
      ["fixed-1311", { declaration: "1.3.11" }],
      ["fixed-2014", { declaration: "2.0.14" }],
      ["fixed-215", { declaration: "2.1.5" }],
      ["later-major", { declaration: "3.0.0" }],
      ["prerelease", { declaration: "2.1.4-beta.1" }],
      ["wrong-package", { packageName: "@example/syslog" }],
      ["development-only", { dependencySection: "devDependencies" }],
      ["unproved-range", { declaration: "^2.1.0" }],
      [
        "fixed-lock",
        { declaration: "^2.1.0", lock: true, lockedVersion: "2.1.5" },
      ],
    ];
    for (const [id, options] of cases) await writeCase(repository, id, options);
    for (const [id] of cases) {
      expect(
        logtapeRecords(await buildResidualRiskInventory(join(repository, id))),
        id,
      ).toEqual([]);
    }
  });

  test("rejects disabled, disconnected, message-only, trusted, and sanitized flows", async () => {
    const repository = await temporaryRepository("flow-negatives");
    const cases: Array<[string, string]> = [
      [
        "default-structured-data",
        defaultSource.replace(`{ includeStructuredData: true }`, `{}`),
      ],
      [
        "disabled-structured-data",
        defaultSource.replace(
          `includeStructuredData: true`,
          `includeStructuredData: false`,
        ),
      ],
      [
        "dynamic-structured-data",
        defaultSource.replace(
          `includeStructuredData: true`,
          `includeStructuredData: enabled`,
        ),
      ],
      [
        "disconnected-sink",
        defaultSource.replace(`sinks: ["security"]`, `sinks: ["console"]`),
      ],
      [
        "category-mismatch",
        defaultSource.replace(`getLogger(["audit"])`, `getLogger(["billing"])`),
      ],
      [
        "message-only",
        defaultSource.replace(
          `auditLogger.info("request audited", { audit: request.body.audit });`,
          `auditLogger.info(request.body.audit);`,
        ),
      ],
      [
        "trusted-property",
        defaultSource.replace(`request.body.audit`, `"trusted"`),
      ],
      [
        "json-escaped-property",
        defaultSource.replace(
          `request.body.audit`,
          `JSON.stringify(request.body.audit)`,
        ),
      ],
      [
        "c0-sanitized-property",
        defaultSource.replace(
          `request.body.audit`,
          `request.body.audit.replace(/[\\x00-\\x1f]/g, "")`,
        ),
      ],
      [
        "unexported-route",
        defaultSource.replace(
          `export function auditRequest`,
          `function auditRequest`,
        ),
      ],
      [
        "logger-reassigned",
        defaultSource.replace(
          `export function auditRequest`,
          `auditLogger = trustedLogger;\nexport function auditRequest`,
        ),
      ],
      [
        "sink-binding-reassigned",
        defaultSource.replace(
          `await configure({`,
          `getSyslogSink = trustedSinkFactory;\nawait configure({`,
        ),
      ],
      [
        "configure-binding-reassigned",
        defaultSource.replace(
          `await configure({`,
          `configure = trustedConfigure;\nawait configure({`,
        ),
      ],
    ];
    for (const [id, source] of cases)
      await writeCase(repository, id, { source });
    for (const [id] of cases) {
      expect(
        logtapeRecords(await buildResidualRiskInventory(join(repository, id))),
        id,
      ).toEqual([]);
    }
  });
});
