import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
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
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function shescapeRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-shescape-cmd-injection",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "3.0.0",
  dependencySection = "dependencies",
  dependencyName = "shescape",
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
            dependencies: { shescape: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { shescape: rootDeclaration } },
              "node_modules/shescape": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const direct = (
  shescapeImport = 'import { Shescape } from "shescape";',
  processImport = 'import { execSync } from "node:child_process";',
  construction = "const escaper = new Shescape(options);",
  escapeCall = "escaper.escape(request.query.value)",
  dispatch = "execSync(command, options)",
) => `${processImport}
${shescapeImport}
const options = { shell: "cmd.exe", windowsHide: true };
${construction}
export function handler(request) {
  const escaped = ${escapeCall};
  const command = \`if defined FALSY (echo \${escaped})\`;
  return ${dispatch};
}
`;

describe("Shescape CMD parenthesis-injection framework benchmark", () => {
  test("keeps a strict multi-hop vulnerable and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-shescape-cmd-injection-manifest.json"),
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
      "node-multi-hop-shescape-cmd-injection",
      "node-multi-hop-repaired-shescape-cmd",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-116"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const vulnerable = shescapeRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-shescape-cmd-injection",
        ),
      ),
    );
    const repaired = shescapeRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-repaired-shescape-cmd"),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/runner.js",
      line: 10,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: { path: "src/server.js", line: 7, kind: "http-request-field" },
        sink: {
          path: "src/runner.js",
          line: 10,
          kind: "vulnerable-shescape-cmd-parenthesis-injection",
          cweIds: ["CWE-78", "CWE-116"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "shescape-runtime-dependency",
          path: "package.json",
          symbol: "shescape@3.0.0:manifest-exact:cmd-parenthesis-injection",
        }),
        expect.objectContaining({
          kind: "relative-module-import",
          path: "src/server.js",
          line: 2,
        }),
        expect.objectContaining({
          kind: "wrapper-parameter",
          path: "src/runner.js",
          line: 7,
        }),
      ]),
    );
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
            "node-multi-hop-shescape-cmd-injection",
            relative,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-repaired-shescape-cmd",
            relative,
          ),
          "utf8",
        ),
      );
    }
  });

  test("keeps both affected release lines and rejects their repairs", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shescape-versions-"),
    );
    temporaryPaths.push(repository);
    const vulnerable = ["0.9.0", "1.7.1", "2.0.0", "2.1.13", "3.0.0"];
    const safe = ["2.1.14", "2.2.0", "3.0.1", "4.0.0", "3.0.0-beta.1"];
    for (const version of [...vulnerable, ...safe]) {
      await writeCase(
        repository,
        `v-${version.replaceAll(".", "-")}`,
        direct(),
        version,
      );
    }
    expect(
      shescapeRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    ).toEqual(
      vulnerable.map((version) => `v-${version.replaceAll(".", "-")}`).sort(),
    );
  });

  test("accepts official class, stateless, process, alias, and multiline forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shescape-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", direct()],
      [
        "named-alias",
        direct(
          'import { Shescape as CmdEscaper } from "shescape";',
          'import { execSync as run } from "node:child_process";',
          "const escaper = new CmdEscaper(options);",
          "escaper.escape(request.query.value)",
          "run(command, options)",
        ),
      ],
      [
        "constructor-alias",
        direct(
          'import { Shescape as OfficialShescape } from "shescape";',
          'import { execSync } from "node:child_process";',
          "const CmdEscaper = OfficialShescape;\nconst escaper = new CmdEscaper(options);",
        ),
      ],
      [
        "namespace",
        direct(
          'import * as shescape from "shescape";',
          'import * as childProcess from "node:child_process";',
          "const escaper = new shescape.Shescape(options);",
          "escaper.escape(request.query.value)",
          "childProcess.execSync(command, options)",
        ),
      ],
      [
        "commonjs",
        direct(
          'const shescape = require("shescape");',
          'const childProcess = require("child_process");',
          "const escaper = new shescape.Shescape(options);",
          "escaper.escape(request.query.value)",
          "childProcess.execSync(command, options)",
        ),
        "handler.cjs",
      ],
      [
        "commonjs-destructure",
        direct(
          'const { Shescape: CmdEscaper } = require("shescape");',
          'const { execSync: run } = require("child_process");',
          "const escaper = new CmdEscaper(options);",
          "escaper.escape(request.query.value)",
          "run(command, options)",
        ),
        "handler.cjs",
      ],
      [
        "commonjs-direct-members",
        direct(
          'const CmdEscaper = require("shescape").Shescape;',
          'const run = require("child_process").execSync;',
          "const escaper = new CmdEscaper(options);",
          "escaper.escape(request.query.value)",
          "run(command, options)",
        ),
        "handler.cjs",
      ],
      [
        "typescript-import-equals",
        direct(
          'import shescape = require("shescape");',
          'import childProcess = require("node:child_process");',
          "const escaper = new shescape.Shescape(options);",
          "escaper.escape(request.query.value)",
          "childProcess.execSync(command, options)",
        ),
        "handler.ts",
      ],
      [
        "instance-alias",
        direct(
          undefined,
          undefined,
          "const official = new Shescape(options);\nconst escaper = official;",
        ),
      ],
      [
        "stateless",
        direct(
          'import { escape } from "shescape/stateless";',
          undefined,
          "",
          "escape(request.query.value, options)",
        ),
      ],
      [
        "stateless-namespace",
        direct(
          'import * as shescape from "shescape/stateless";',
          undefined,
          "",
          "shescape.escape(request.query.value, options)",
        ),
      ],
      ["shell-true", direct().replace('shell: "cmd.exe"', "shell: true")],
      [
        "escaped-alias",
        direct()
          .replace(
            "const command =",
            "const escapedAlias = escaped;\n  const command =",
          )
          .replace("${escaped})", "${escapedAlias})"),
      ],
      [
        "nested-dispatch",
        `import { execSync } from "node:child_process";
import { Shescape } from "shescape";
const options = { shell: "cmd.exe" };
const escaper = new Shescape(options);
export function handler(request) {
  return execSync(\`echo \${escaper.escape(request.query.value)}\`, options);
}
`,
      ],
      [
        "multiline",
        `import { execSync } from "node:child_process";
import { Shescape } from "shescape";
const options = {
  shell: "cmd.exe",
};
const escaper = new Shescape(
  options,
);
export function handler(request) {
  const escaped = escaper.escape(
    request.query.value,
  );
  return execSync(
    \`echo \${escaped}\`,
    options,
  );
}
`,
      ],
      [
        "escape-all-spawn",
        direct(
          undefined,
          'import { spawnSync } from "node:child_process";',
          undefined,
          "escaper.escapeAll([request.query.value])",
          'spawnSync("echo", escaped, options)',
        ),
      ],
      [
        "exec-file-shell",
        direct(
          undefined,
          'import { execFileSync } from "node:child_process";',
          undefined,
          undefined,
          'execFileSync("cmd.exe", ["/c", command], options)',
        ),
      ],
    ] as const;
    for (const [id, source, filename = "handler.mjs"] of cases) {
      await writeCase(
        repository,
        id,
        source,
        "3.0.0",
        "dependencies",
        "shescape",
        filename,
      );
    }
    expect(
      shescapeRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(
      cases
        .map(([id, , filename = "handler.mjs"]) => `${id}/${filename}`)
        .sort(),
    );
  });

  test("rejects non-CMD, no-dispatch, fixed input, lookalike, shadowed, and replaced flows", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shescape-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "powershell",
        direct().replace('shell: "cmd.exe"', 'shell: "powershell.exe"'),
      ],
      ["bash", direct().replace('shell: "cmd.exe"', 'shell: "/bin/bash"')],
      [
        "no-dispatch",
        direct().replace(
          "return execSync(command, options);",
          "return escaped;",
        ),
      ],
      ["fixed-input", direct().replace("request.query.value", '"trusted"')],
      [
        "local-lookalike",
        direct().replace('from "shescape"', 'from "./shescape.js"'),
      ],
      [
        "constructor-reassigned",
        direct().replace(
          "const escaper",
          "Shescape = SafeShescape;\nconst escaper",
        ),
      ],
      [
        "instance-reassigned",
        direct().replace(
          "export function",
          "escaper = safeEscaper;\nexport function",
        ),
      ],
      [
        "escape-replaced",
        direct().replace(
          "export function",
          "escaper.escape = safeEscape;\nexport function",
        ),
      ],
      [
        "process-replaced",
        direct().replace(
          "export function",
          "execSync = safeExec;\nexport function",
        ),
      ],
      [
        "process-lookalike",
        direct(undefined, 'import { execSync } from "./child_process.js";'),
      ],
      [
        "no-process-options",
        direct().replace("execSync(command, options)", "execSync(command)"),
      ],
      [
        "construction-options-mutated",
        direct().replace(
          "export function",
          'options.shell = "/bin/bash";\nexport function',
        ),
      ],
      [
        "dispatch-options-mutated",
        direct().replace(
          "return execSync",
          'options.shell = "/bin/bash";\n  return execSync',
        ),
      ],
      [
        "dispatch-options-defined",
        direct().replace(
          "return execSync",
          'Object.defineProperty(options, "shell", { value: "/bin/bash" });\n  return execSync',
        ),
      ],
      [
        "safe-argv",
        direct()
          .replace(
            "execSync(command, options)",
            'execFileSync("echo", [escaped])',
          )
          .replace("import { execSync }", "import { execFileSync }"),
      ],
    ] as const;
    for (const [id, source] of cases) await writeCase(repository, id, source);
    expect(
      shescapeRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("requires exact production provenance or a declaration-consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shescape-dependencies-"),
    );
    temporaryPaths.push(repository);
    const source = direct();
    await writeCase(repository, "locked-range", source, "^3.0.0");
    await writeNpmLock(repository, "locked-range", "^3.0.0", "3.0.0");
    await writeCase(repository, "unlocked-range", source, "^3.0.0");
    await writeCase(repository, "v1-lock", source, "^3.0.0");
    await writeNpmLock(repository, "v1-lock", "^3.0.0", "3.0.0", 1);
    await writeCase(repository, "inconsistent-lock", source, "^3.0.1");
    await writeNpmLock(
      repository,
      "inconsistent-lock",
      "^3.0.1",
      "3.0.0",
      3,
      "^3.0.0",
    );
    await writeCase(repository, "dev-only", source, "3.0.0", "devDependencies");
    await writeCase(
      repository,
      "wrong-package",
      source,
      "3.0.0",
      "dependencies",
      "shescape-clone",
    );

    const records = shescapeRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records.map(({ path }) => path)).toEqual([
      "locked-range/handler.mjs",
    ]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-shescape-cmd-parenthesis-injection",
    );
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "shescape-runtime-dependency",
          path: "locked-range/package.json",
          symbol: "shescape@3.0.0:npm-lockfile:cmd-parenthesis-injection",
        }),
      ]),
    );
  });

  test("excludes test/example trees and retains the canonical row under the repository cap", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-shescape-exclusions-"),
    );
    temporaryPaths.push(repository);
    for (const directory of [
      "test",
      "tests",
      "__tests__",
      "example",
      "examples",
    ] as const) {
      const root = join(repository, directory);
      await mkdir(root, { recursive: true });
      await writeFile(
        join(root, "package.json"),
        JSON.stringify({ dependencies: { shescape: "3.0.0" } }),
      );
      await writeFile(join(root, "handler.mjs"), direct());
    }
    expect(
      shescapeRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);

    const repositoryInventory = await buildResidualRiskInventory(
      resolve(process.cwd(), "..", ".."),
    );
    const repositoryRecords = repositoryInventory
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as FrameworkRecord);
    expect(
      repositoryRecords.filter(({ frameworkModel }) => frameworkModel).length,
    ).toBeGreaterThanOrEqual(166);
    const paths = shescapeRecords(repositoryInventory).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-shescape-cmd-injection/src/runner.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-repaired-shescape-cmd/src/runner.js",
    );
  }, 60_000);

  test("requires exploit-specific validation before reporting command injection", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-shescape-cmd-injection");
    expect(prompt).toContain("GHSA-w4hw-qcx7-56pr");
    expect(prompt).toContain("CVE-2026-73414");
    expect(prompt).toContain("cmd.exe");
    expect(prompt).toContain("parentheses");
    expect(prompt).toContain("Do not report command injection");
  });
});
