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

function shellQuoteRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-shell-quote-object-token-command-injection",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "1.8.3",
  dependencySection = "dependencies",
  dependencyName = "shell-quote",
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
            dependencies: { "shell-quote": { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { "shell-quote": rootDeclaration } },
              "node_modules/shell-quote": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const source = ({
  quoteImport = 'import { quote } from "shell-quote";',
  quoteCallee = "quote",
  processImport = 'import { execSync } from "node:child_process";',
  tokenExpression = "[{ op: request.query.operator }]",
  beforeQuote = "",
  dispatch = "execSync(command)",
}: {
  quoteImport?: string;
  quoteCallee?: string;
  processImport?: string;
  tokenExpression?: string;
  beforeQuote?: string;
  dispatch?: string;
} = {}) => `${processImport}
${quoteImport}
export function handler(request) {
  ${beforeQuote}
  const command = ${quoteCallee}(${tokenExpression});
  return ${dispatch};
}
`;

describe("shell-quote object-token command-injection framework benchmark", () => {
  test("keeps a strict multi-hop vulnerable and repaired pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-shell-quote-object-token-command-injection-manifest.json",
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
      "node-multi-hop-shell-quote-object-token-command-injection",
      "node-multi-hop-repaired-shell-quote-object-token",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-77", "CWE-78"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const vulnerable = shellQuoteRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-shell-quote-object-token-command-injection",
        ),
      ),
    );
    const repaired = shellQuoteRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-repaired-shell-quote-object-token",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/runner.js",
      line: 6,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: { path: "src/server.js", line: 7, kind: "http-request-field" },
        sink: {
          path: "src/runner.js",
          line: 6,
          kind: "vulnerable-shell-quote-object-token-line-terminator-command-injection",
          cweIds: ["CWE-77", "CWE-78"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "shell-quote-runtime-dependency",
          path: "package.json",
          symbol: "shell-quote@1.8.3:manifest-exact:direct-object-token",
        }),
        expect.objectContaining({
          kind: "relative-module-import",
          path: "src/server.js",
          line: 2,
        }),
        expect.objectContaining({
          kind: "wrapper-parameter",
          path: "src/runner.js",
          line: 4,
        }),
      ]),
    );
  });

  test("accepts official quote bindings and real shell dispatch forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shell-quote-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", source()],
      [
        "named-alias",
        source({
          quoteImport: 'import { quote as shellQuote } from "shell-quote";',
          quoteCallee: "shellQuote",
        }),
      ],
      [
        "namespace",
        source({
          quoteImport: 'import * as shellQuote from "shell-quote";',
          quoteCallee: "shellQuote.quote",
        }),
      ],
      [
        "default-receiver",
        source({
          quoteImport: 'import shellQuote from "shell-quote";',
          quoteCallee: "shellQuote.quote",
        }),
      ],
      [
        "import-equals",
        source({
          quoteImport: 'import shellQuote = require("shell-quote");',
          quoteCallee: "shellQuote.quote",
        }),
        "handler.ts",
      ],
      [
        "commonjs-destructure",
        source({ quoteImport: 'const { quote } = require("shell-quote");' }),
      ],
      [
        "commonjs-receiver",
        source({
          quoteImport: 'const shellQuote = require("shell-quote");',
          quoteCallee: "shellQuote.quote",
        }),
      ],
      [
        "direct-require",
        source({
          quoteImport: "",
          quoteCallee: 'require("shell-quote").quote',
        }),
      ],
      [
        "exec",
        source({
          processImport: 'import { exec } from "node:child_process";',
          dispatch: "exec(command)",
        }),
      ],
      [
        "explicit-shell",
        source({
          processImport: 'import { execFile } from "node:child_process";',
          dispatch: 'execFile("/bin/sh", ["-c", command])',
        }),
      ],
      [
        "spawn-shell",
        source({
          processImport: 'import { spawn } from "node:child_process";',
          dispatch: 'spawn("bash", ["-lc", command])',
        }),
      ],
      [
        "shell-option",
        source({
          processImport: 'import { spawnSync } from "node:child_process";',
          dispatch: 'spawnSync(command, [], { shell: "/bin/sh" })',
        }),
      ],
    ] as const;
    for (const [id, code, filename = "handler.mjs"] of cases) {
      await writeCase(
        repository,
        id,
        code,
        "1.8.3",
        "dependencies",
        "shell-quote",
        filename,
      );
    }
    expect(
      shellQuoteRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(
      cases
        .map(([id, , filename = "handler.mjs"]) => `${id}/${filename}`)
        .sort(),
    );
  });

  test("supports direct aliases and the documented parse envFn object route", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shell-quote-routes-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "object-alias",
        source({
          beforeQuote:
            "const token = { op: request.query.operator };\n  const tokens = [token];",
          tokenExpression: "tokens",
        }),
      ],
      [
        "env-arrow",
        source({
          quoteImport: 'import { parse, quote } from "shell-quote";',
          beforeQuote:
            'const tokens = parse("echo $X", () => ({ op: request.query.operator }));',
          tokenExpression: "tokens",
        }),
      ],
      [
        "env-classic",
        source({
          quoteImport: 'import * as shellQuote from "shell-quote";',
          quoteCallee: "shellQuote.quote",
          beforeQuote:
            'const tokens = shellQuote.parse("echo $X", function env() { return { op: request.query.operator }; });',
          tokenExpression: "tokens",
        }),
      ],
    ] as const;
    for (const [id, code] of cases) await writeCase(repository, id, code);
    const records = shellQuoteRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual(
      cases.map(([id]) => `${id}/handler.mjs`).sort(),
    );
    expect(
      records.map(
        ({ frameworkModel }) => frameworkModel?.propagators[0]?.symbol,
      ),
    ).toEqual(
      expect.arrayContaining([
        "shell-quote@1.8.3:manifest-exact:direct-object-token",
        "shell-quote@1.8.3:manifest-exact:env-function-object-token",
      ]),
    );
  });

  test("enforces the stable affected version boundary", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shell-quote-versions-"),
    );
    temporaryPaths.push(repository);
    const vulnerable = ["1.1.0", "1.7.3", "1.8.2", "1.8.3"];
    const safe = ["0.9.0", "1.0.0", "1.8.4", "1.9.0", "2.0.0", "1.8.3-beta.1"];
    for (const version of [...vulnerable, ...safe]) {
      await writeCase(
        repository,
        `v-${version.replaceAll(".", "-")}`,
        source(),
        version,
      );
    }
    expect(
      shellQuoteRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    ).toEqual(
      vulnerable.map((version) => `v-${version.replaceAll(".", "-")}`).sort(),
    );
  });

  test("rejects safe token shapes, unused quoting, and shell-free dispatch", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shell-quote-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "ordinary-string",
        source({ tokenExpression: "[request.query.operator]" }),
      ],
      ["fixed-operator", source({ tokenExpression: '[{ op: ";" }]' })],
      [
        "glob-pattern",
        source({
          tokenExpression: '[{ op: "glob", pattern: request.query.pattern }]',
        }),
      ],
      [
        "comment",
        source({ tokenExpression: "[{ comment: request.query.comment }]" }),
      ],
      [
        "parser-only",
        source({
          quoteImport: 'import { parse, quote } from "shell-quote";',
          tokenExpression: "parse(request.query.command)",
        }),
      ],
      ["unused", source({ dispatch: 'execSync("echo fixed")' })],
      [
        "shell-free",
        source({
          processImport: 'import { execFile } from "node:child_process";',
          dispatch: 'execFile("printf", [command])',
        }),
      ],
      [
        "wrong-shell-flag",
        source({
          processImport: 'import { execFile } from "node:child_process";',
          dispatch: 'execFile("/bin/sh", ["-s", command])',
        }),
      ],
      [
        "local-lookalike",
        source({ quoteImport: 'import { quote } from "./shell-quote.js";' }),
      ],
      ["quote-reassigned", source({ beforeQuote: "quote = safeQuote;" })],
      [
        "member-replaced",
        source({
          quoteImport: 'import * as shellQuote from "shell-quote";',
          quoteCallee: "shellQuote.quote",
          beforeQuote: "shellQuote.quote = safeQuote;",
        }),
      ],
      [
        "command-reassigned",
        source({ dispatch: "(command = safeCommand, execSync(command))" }),
      ],
    ] as const;
    for (const [id, code] of cases) await writeCase(repository, id, code);
    expect(
      shellQuoteRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exact production provenance or a consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shell-quote-dependencies-"),
    );
    temporaryPaths.push(repository);
    await writeCase(repository, "locked-range", source(), "^1.8.0");
    await writeNpmLock(repository, "locked-range", "^1.8.0", "1.8.3");
    await writeCase(repository, "unlocked-range", source(), "^1.8.0");
    await writeCase(repository, "v1-lock", source(), "^1.8.0");
    await writeNpmLock(repository, "v1-lock", "^1.8.0", "1.8.3", 1);
    await writeCase(repository, "inconsistent-lock", source(), "^1.8.4");
    await writeNpmLock(
      repository,
      "inconsistent-lock",
      "^1.8.4",
      "1.8.3",
      3,
      "^1.8.0",
    );
    await writeCase(
      repository,
      "dev-only",
      source(),
      "1.8.3",
      "devDependencies",
    );
    await writeCase(
      repository,
      "wrong-package",
      source(),
      "1.8.3",
      "dependencies",
      "shell-quote-clone",
    );
    const records = shellQuoteRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "locked-range/handler.mjs",
    ]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-shell-quote-object-token-line-terminator-command-injection",
    );
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "shell-quote-runtime-dependency",
          symbol: "shell-quote@1.8.3:npm-lockfile:direct-object-token",
        }),
      ]),
    );
  });

  test("keeps application sources identical and excludes test/example paths", async () => {
    for (const relative of [
      "src/server.js",
      "src/gateway.js",
      "src/service.js",
      "src/runner.js",
      "witness.mjs",
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-shell-quote-object-token-command-injection",
            relative,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-repaired-shell-quote-object-token",
            relative,
          ),
          "utf8",
        ),
      );
    }
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shell-quote-paths-"),
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
      shellQuoteRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exploit-specific validation guidance", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain(
      "node-http-shell-quote-object-token-command-injection",
    );
    expect(prompt).toContain("GHSA-w7jw-789q-3m8p");
    expect(prompt).toContain("CVE-2026-9277");
    expect(prompt).toContain("object token");
    expect(prompt).toContain("1.8.4 rejects the identical token");
    expect(prompt).toContain("Report CWE-77 and CWE-78 only");
  });
});
