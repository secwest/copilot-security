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

function vm2Records(
  inventory: string,
  id = "node-http-vm2-host-proto-sandbox-escape",
): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter((record) => record.frameworkModel?.id === id);
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "3.11.5",
  dependencySection = "dependencies",
  dependencyName = "vm2",
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
            dependencies: { vm2: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { vm2: rootDeclaration } },
              "node_modules/vm2": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const assigned = (
  binding: string,
  constructor = "VM",
  options = "",
  expression = "request.body.code",
) =>
  `${binding}\nconst sandbox = new ${constructor}(${options});\nexport function handler(request) {\n  return sandbox.run(${expression});\n}\n`;

describe("vm2 application-reachable sandbox escape framework benchmark", () => {
  test("keeps a strict vulnerable and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-vm2-sandbox-escape-manifest.json"),
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
      "node-multi-hop-vm2-sandbox-escape",
      "node-multi-hop-repaired-vm2-sandbox",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-94", "CWE-693"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, VM.run sink, and dependency proof", async () => {
    const vulnerable = vm2Records(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-vm2-sandbox-escape"),
      ),
    );
    const repaired = vm2Records(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-multi-hop-repaired-vm2-sandbox"),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(vulnerable[0]).toMatchObject({
      path: "src/sandbox.js",
      line: 5,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: {
          path: "src/server.js",
          line: 8,
          kind: "http-request-field",
        },
        sink: {
          path: "src/sandbox.js",
          line: 5,
          kind: "vulnerable-vm2-host-proto-mutator-sandbox-escape",
          cweIds: ["CWE-94", "CWE-693"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "vm2-runtime-dependency",
          path: "package.json",
          symbol: "vm2@3.11.5:manifest-exact:host-proto-mutator-sandbox-escape",
        }),
        expect.objectContaining({
          kind: "relative-module-import",
          path: "src/server.js",
          line: 2,
        }),
        expect.objectContaining({
          kind: "wrapper-parameter",
          path: "src/sandbox.js",
          line: 4,
        }),
      ]),
    );
    for (const relative of [
      "src/server.js",
      "src/gateway.js",
      "src/service.js",
      "src/sandbox.js",
      "witness.mjs",
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-vm2-sandbox-escape",
            relative,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-repaired-vm2-sandbox",
            relative,
          ),
          "utf8",
        ),
      );
    }
  });

  test("accepts official constructor forms, VMScript, and immediate runs", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-vm2-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", assigned('import { VM } from "vm2";')],
      [
        "named-alias",
        assigned('import { VM as Sandbox } from "vm2";', "Sandbox"),
      ],
      ["namespace", assigned('import * as vm2 from "vm2";', "vm2.VM")],
      ["default", assigned('import vm2 from "vm2";', "vm2.VM")],
      [
        "import-equals",
        assigned('import vm2 = require("vm2");', "vm2.VM"),
        "handler.ts",
      ],
      ["commonjs-receiver", assigned('const vm2 = require("vm2");', "vm2.VM")],
      [
        "commonjs-named",
        assigned('const { VM: Sandbox } = require("vm2");', "Sandbox"),
      ],
      [
        "direct-class-require",
        assigned('const Sandbox = require("vm2").VM;', "Sandbox"),
      ],
      [
        "stable-constructor-alias",
        'import { VM } from "vm2";\nconst Sandbox = VM;\nconst sandbox = new Sandbox();\nexport function handler(request) { return sandbox.run(request.body.code); }\n',
      ],
      [
        "vmscript",
        'import { VM, VMScript } from "vm2";\nconst sandbox = new VM();\nexport function handler(request) {\n  const script = new VMScript(request.body.code);\n  return sandbox.run(script);\n}\n',
      ],
      [
        "immediate",
        'import { VM } from "vm2";\nexport function handler(request) { return new VM().run(request.body.code); }\n',
      ],
    ] as const;
    for (const [id, source, filename = "handler.mjs"] of cases) {
      await writeCase(
        repository,
        id,
        source,
        "3.11.5",
        "dependencies",
        "vm2",
        filename,
      );
    }

    const paths = vm2Records(await buildResidualRiskInventory(repository)).map(
      ({ path }) => path,
    );
    expect(paths).toEqual(
      cases
        .map(([id, , filename = "handler.mjs"]) => `${id}/${filename}`)
        .sort(),
    );
  });

  test("models wildcard NodeVM exposure and honors complete builtin cutouts", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-vm2-wildcard-"),
    );
    temporaryPaths.push(repository);
    const source = (options: string) =>
      assigned(
        'import { NodeVM } from "vm2";',
        "NodeVM",
        options,
        "request.body.code",
      );
    await writeCase(
      repository,
      "wildcard",
      source('{ require: { builtin: ["*"] } }'),
    );
    await writeCase(
      repository,
      "dns-still-open",
      source('{ require: { builtin: ["*", "-os"] } }'),
    );
    await writeCase(repository, "no-wildcard", source("{}"));
    await writeCase(
      repository,
      "both-excluded",
      source('{ require: { builtin: ["*", "-os", "-dns"] } }'),
    );
    await writeCase(
      repository,
      "both-replaced",
      source(
        '{ require: { builtin: ["*"], mock: { os: {} }, override: { dns: { servers: "disabled" } } } }',
      ),
    );
    await writeCase(
      repository,
      "unknown-replacements",
      source(
        '{ require: { builtin: ["*"], mock: { os: safeOs }, override: { dns: safeDns } } }',
      ),
    );

    const paths = vm2Records(
      await buildResidualRiskInventory(repository),
      "node-http-vm2-wildcard-builtin-host-exposure",
    ).map(({ path }) => path);
    expect(paths).toEqual([
      "dns-still-open/handler.mjs",
      "unknown-replacements/handler.mjs",
      "wildcard/handler.mjs",
    ]);
  });

  test("enforces the 3.11.6 repair boundary and rejects prereleases", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-vm2-versions-"),
    );
    temporaryPaths.push(repository);
    const vulnerable = ["1.0.0", "2.0.0", "3.9.19", "3.11.4", "3.11.5"];
    const safe = ["3.11.6", "3.11.7", "4.0.0", "3.11.5-beta.1"];
    for (const version of [...vulnerable, ...safe]) {
      await writeCase(
        repository,
        `v-${version.replaceAll(".", "-")}`,
        assigned('import { VM } from "vm2";'),
        version,
      );
    }
    const paths = vm2Records(await buildResidualRiskInventory(repository)).map(
      ({ path }) => path.split("/")[0],
    );
    expect(paths).toEqual(
      vulnerable.map((version) => `v-${version.replaceAll(".", "-")}`).sort(),
    );
  });

  test("rejects package presence, trusted code, local lookalikes, and replaced capabilities", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-vm2-negatives-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      [
        "package-only",
        'import { VM } from "vm2";\nexport function handler(request) { return request.body.code; }\n',
      ],
      [
        "trusted-code",
        'import { VM } from "vm2";\nconst sandbox = new VM();\nexport function handler(request) { return sandbox.run("2 + 2"); }\n',
      ],
      [
        "local-lookalike",
        'import { VM } from "./vm2.js";\nconst sandbox = new VM();\nexport function handler(request) { return sandbox.run(request.body.code); }\n',
      ],
      [
        "wrong-package",
        'import { VM } from "vm2-clone";\nconst sandbox = new VM();\nexport function handler(request) { return sandbox.run(request.body.code); }\n',
      ],
      [
        "constructor-reassigned",
        'import { VM } from "vm2";\nVM = SafeVM;\nconst sandbox = new VM();\nexport function handler(request) { return sandbox.run(request.body.code); }\n',
      ],
      [
        "instance-reassigned",
        'import { VM } from "vm2";\nlet sandbox = new VM();\nsandbox = safeSandbox;\nexport function handler(request) { return sandbox.run(request.body.code); }\n',
      ],
      [
        "run-replaced",
        'import { VM } from "vm2";\nconst sandbox = new VM();\nsandbox.run = safeRun;\nexport function handler(request) { return sandbox.run(request.body.code); }\n',
      ],
      [
        "run-defined",
        'import { VM } from "vm2";\nconst sandbox = new VM();\nObject.defineProperty(sandbox, "run", { value: safeRun });\nexport function handler(request) { return sandbox.run(request.body.code); }\n',
      ],
      [
        "binding-shadowed",
        'import { VM } from "vm2";\nexport function handler(VM, request) { const sandbox = new VM(); return sandbox.run(request.body.code); }\n',
      ],
      [
        "receiver-member-replaced",
        'import * as vm2 from "vm2";\nvm2.VM = SafeVM;\nconst sandbox = new vm2.VM();\nexport function handler(request) { return sandbox.run(request.body.code); }\n',
      ],
    ] as const;
    for (const [id, source] of cases) {
      await writeCase(repository, id, source);
    }
    expect(vm2Records(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("requires exact production provenance or a declaration-consistent modern lock", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-vm2-dependencies-"),
    );
    temporaryPaths.push(repository);
    const source = assigned('import { VM } from "vm2";');
    await writeCase(repository, "locked-range", source, "^3.11.0");
    await writeNpmLock(repository, "locked-range", "^3.11.0", "3.11.5");
    await writeCase(repository, "unlocked-range", source, "^3.11.0");
    await writeCase(repository, "v1-lock", source, "^3.11.0");
    await writeNpmLock(repository, "v1-lock", "^3.11.0", "3.11.5", 1);
    await writeCase(repository, "inconsistent-lock", source, "^3.11.6");
    await writeNpmLock(
      repository,
      "inconsistent-lock",
      "^3.11.6",
      "3.11.5",
      3,
      "^3.11.0",
    );
    await writeCase(
      repository,
      "dev-only",
      source,
      "3.11.5",
      "devDependencies",
    );
    await writeCase(
      repository,
      "wrong-package-name",
      source,
      "3.11.5",
      "dependencies",
      "vm2-clone",
    );

    const records = vm2Records(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "locked-range/handler.mjs",
    ]);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-vm2-host-proto-mutator-sandbox-escape",
    );
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "vm2-runtime-dependency",
          path: "locked-range/package.json",
          symbol: "vm2@3.11.5:npm-lockfile:host-proto-mutator-sandbox-escape",
        }),
      ]),
    );
  });

  test("excludes tests/examples and retains only the vulnerable canonical row", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-vm2-exclusions-"),
    );
    temporaryPaths.push(repository);
    const source = assigned('import { VM } from "vm2";');
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
        JSON.stringify({ dependencies: { vm2: "3.11.5" } }),
      );
      await writeFile(join(root, "handler.mjs"), source);
    }
    expect(vm2Records(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );

    const paths = vm2Records(
      await buildResidualRiskInventory(resolve(process.cwd(), "..", "..")),
    ).map(({ path }) => path);
    expect(paths).toContain(
      "benchmarks/fixtures/node-multi-hop-vm2-sandbox-escape/src/sandbox.js",
    );
    expect(paths).not.toContain(
      "benchmarks/fixtures/node-multi-hop-repaired-vm2-sandbox/src/sandbox.js",
    );
  }, 60_000);

  test("requires exploit-specific validation before reporting host impact", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("vm2");
    expect(prompt).toContain("GHSA-cfcw-xp6x-25gj");
    expect(prompt).toContain("GHSA-m5w8-4gq2-6f8x");
    expect(prompt).toContain("3.11.6");
    expect(prompt).toContain("VM.run");
    expect(prompt).toContain("NodeVM.run");
    expect(prompt).toContain("Do not report remote code execution");
  });
});
