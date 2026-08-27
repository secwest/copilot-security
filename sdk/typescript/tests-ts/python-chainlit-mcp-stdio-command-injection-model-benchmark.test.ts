import { afterEach, describe, expect, test } from "bun:test";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
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
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const affectedId = "python-chainlit-mcp-stdio-command-injection";

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function chainlitRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter((record) => record.frameworkModel?.id === affectedId);
}

function normalizeLineEndings(text: string): string {
  return text.replaceAll("\r\n", "\n");
}

async function writeRepository(
  options: {
    app?: string;
    config?: string | null;
    requirements?: string | null;
    extra?: Readonly<Record<string, string>>;
  } = {},
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-chainlit-"),
  );
  temporaryPaths.push(repository);
  const files: Record<string, string> = {
    "src/app.py": options.app ?? "import chainlit as cl\n",
    ...(options.extra ?? {}),
  };
  if (options.requirements !== null) {
    files["requirements.txt"] = options.requirements ?? "chainlit==2.11.1\n";
  }
  if (options.config !== null) {
    files[".chainlit/config.toml"] =
      options.config ??
      [
        "[features.mcp]",
        "enabled = true",
        "",
        "[features.mcp.stdio]",
        "enabled = true",
        'allowed_executables = ["npx", "uvx"]',
        "",
      ].join("\n");
  }
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

describe("Python Chainlit MCP stdio command injection model", () => {
  test("keeps a strict affected and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "python-chainlit-mcp-stdio-command-injection-manifest.json",
        ),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        expected: Array<{
          cwe?: string[];
          acceptableSeverities?: string[];
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
      affectedId,
      "python-chainlit-mcp-stdio-repaired-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-78"]);
    expect(manifest.cases[0]?.expected[0]?.acceptableSeverities).toEqual([
      "critical",
    ]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(14);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(14);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(manifest.cases[1]?.expected).toEqual([]);

    const roots = [
      join(
        benchmarkRoot,
        "fixtures",
        "python-chainlit-mcp-stdio-command-injection",
      ),
      join(
        benchmarkRoot,
        "fixtures",
        "python-chainlit-mcp-stdio-repaired-control",
      ),
    ];
    for (const relativePath of [
      ".python-version",
      join(".chainlit", "config.toml"),
      "README.md",
      "RUNTIME.md",
      join("examples", "witness.py"),
      join("src", "__init__.py"),
      join("src", "app.py"),
    ]) {
      expect(await readFile(join(roots[0]!, relativePath), "utf8")).toBe(
        await readFile(join(roots[1]!, relativePath), "utf8"),
      );
    }
    expect(
      normalizeLineEndings(
        await readFile(join(roots[0]!, "requirements.txt"), "utf8"),
      ),
    ).toBe("chainlit==2.11.1\n");
    expect(
      normalizeLineEndings(
        await readFile(join(roots[1]!, "requirements.txt"), "utf8"),
      ),
    ).toBe("chainlit==2.12.0\n");
  });

  test("emits the exact configuration-to-process topology", async () => {
    const affected = chainlitRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-chainlit-mcp-stdio-command-injection",
        ),
      ),
    );
    const repaired = chainlitRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-chainlit-mcp-stdio-repaired-control",
        ),
      ),
    );

    expect(repaired).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/app.py");
    expect(affected[0]?.line).toBe(1);
    expect(affected[0]?.frameworkModel?.scope).toBe("cross-file");
    expect(affected[0]?.frameworkModel?.source).toEqual({
      kind: "remote-chainlit-mcp-fullcommand-request",
      path: ".chainlit/config.toml",
      line: 2,
    });
    expect(affected[0]?.frameworkModel?.sink).toEqual({
      kind: "chainlit-affected-mcp-stdio-client-command-spawn",
      path: "src/app.py",
      line: 1,
      cweIds: ["CWE-78"],
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "chainlit-application-import",
      "chainlit-runtime-dependency",
      "chainlit-mcp-enabled-configuration",
      "chainlit-mcp-stdio-command-capability",
      "intrinsic-chainlit-mcp-request-command-source",
      "intrinsic-chainlit-executable-only-validation",
      "intrinsic-chainlit-stdio-process-spawn",
    ]);
    expect(
      affected[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "chainlit-runtime-dependency",
      )?.symbol,
    ).toBe("chainlit@2.11.1:requirements-exact:mcp-fullcommand");
  });

  test("supports official import forms and command-capable stdio policies", async () => {
    const repositories = await Promise.all([
      writeRepository(),
      writeRepository({ app: "from chainlit import on_message\n" }),
      writeRepository({
        config: "[features.mcp]\nenabled = true\n",
      }),
      writeRepository({
        config:
          'features.mcp.enabled = true\nfeatures.mcp.stdio.enabled = true\nfeatures.mcp.stdio.allowed_executables = ["python3"]\n',
      }),
      writeRepository({ requirements: "chainlit==2.4.0\n" }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        chainlitRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1, 1, 1]);
    expect(
      records[2]?.[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "chainlit-mcp-stdio-command-capability",
      )?.symbol,
    ).toContain("all executables allowed");
  });

  test("rejects repaired, ambiguous, disabled, shadowed, nonproduction, and text-only candidates", async () => {
    const exactConfig =
      '[features.mcp]\nenabled = true\n[features.mcp.stdio]\nenabled = true\nallowed_executables = ["npx"]\n';
    const repositories = await Promise.all([
      writeRepository({ requirements: "chainlit==2.12.0\n" }),
      writeRepository({ requirements: "chainlit==2.3.9\n" }),
      writeRepository({ requirements: "chainlit>=2.4.0\n" }),
      writeRepository({ requirements: null }),
      writeRepository({ requirements: "chainlit==2.11.1\nchainlit==2.10.0\n" }),
      writeRepository({ requirements: "chainlit==2.11.1rc1\n" }),
      writeRepository({ config: "[features.mcp]\nenabled = false\n" }),
      writeRepository({
        config:
          "[features.mcp]\nenabled = true\n[features.mcp.stdio]\nenabled = false\n",
      }),
      writeRepository({
        config:
          "[features.mcp]\nenabled = true\n[features.mcp.stdio]\nallowed_executables = []\n",
      }),
      writeRepository({
        config:
          '[features.mcp]\nenabled = true\n[features.mcp.stdio]\nallowed_executables = ["git"]\n',
      }),
      writeRepository({ config: "[features.mcp\nenabled = true\n" }),
      writeRepository({ config: null }),
      writeRepository({
        extra: { "chainlit.py": "def on_message(fn): return fn\n" },
      }),
      writeRepository({ app: "def load():\n    import chainlit\n" }),
      writeRepository({ app: 'TEXT = "import chainlit"\n' }),
      writeRepository({
        app: "print('application')\n",
        extra: { "tests/test_app.py": "import chainlit\n" },
      }),
      writeRepository({
        app: "print('application')\n",
        extra: { "examples/app.py": "import chainlit\n" },
      }),
      writeRepository({ app: "print('application')\n", config: exactConfig }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        chainlitRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual(
      Array.from({ length: repositories.length }, () => 0),
    );
  });

  test.skipIf(process.platform === "win32")(
    "does not follow symlinked dependency or MCP configuration evidence",
    async () => {
      const dependencyRepository = await writeRepository({
        requirements: null,
        extra: { "actual-requirements.txt": "chainlit==2.11.1\n" },
      });
      await symlink(
        "actual-requirements.txt",
        join(dependencyRepository, "requirements.txt"),
      );
      const configRepository = await writeRepository({ config: null });
      await writeFile(
        join(configRepository, "actual-config.toml"),
        "[features.mcp]\nenabled = true\n",
      );
      await mkdir(join(configRepository, ".chainlit"));
      await symlink(
        "../actual-config.toml",
        join(configRepository, ".chainlit", "config.toml"),
      );

      expect(
        chainlitRecords(await buildResidualRiskInventory(dependencyRepository)),
      ).toEqual([]);
      expect(
        chainlitRecords(await buildResidualRiskInventory(configRepository)),
      ).toEqual([]);
    },
  );

  test("retains the official import amid dense unrelated calls and imports", async () => {
    const decoys = Array.from(
      { length: 100 },
      (_, index) => `import service_${index}`,
    );
    const repository = await writeRepository({
      app: [...decoys, "import chainlit as cl"].join("\n"),
    });

    const records = chainlitRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(101);
  });

  test("host re-audit requires the complete command boundary in both report fields", async () => {
    const repository = await writeRepository();
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-chainlit-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_chainlit_quality",
      taxonomy: { cwe: ["CWE-78"] },
      locations: [{ path: "src/app.py", startLine: 1, role: "sink" }],
      codeEvidence: [
        {
          id: "chainlit-import",
          path: "src/app.py",
          startLine: 1,
          code: "import chainlit as cl",
          explanation: "Official Chainlit application import.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms an affected application import.",
        method: "static topology and non-executing package witness",
        exploitWitness:
          "The bounded validator returns a parsed executable and inert arguments without execution.",
        negativeControl:
          "The repaired request schema rejects the removed client-command fields.",
        evidence: ["chainlit-import"],
        counterEvidence:
          "No deployment, authentication, reachability, or process effect is assumed.",
        remainingUncertainty: "Deployment reachability is unknown.",
      },
      attackPath: {
        summary: "A client command may reach the stdio process path.",
        dataflow: {
          source: "chainlit-import",
          sink: "chainlit-import",
          outcome: "argument injection",
        },
        reachability: {
          attacker: "MCP client",
          entrypoint: "POST /mcp",
          outcome: "process launch parameters",
        },
        brokenControls: ["Executable-only validation"],
        evidenceRefs: ["chainlit-import"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const inventory = await buildResidualRiskInventory(repository);
    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    const rows = incomplete.split("\n").map((line) => JSON.parse(line));
    expect(rows[1]).toMatchObject({
      findingId: "occ_chainlit_quality",
      frameworkModelId: affectedId,
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "validate_mcp_command",
      "shlex.split",
      "executable-only allowlist",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "chainlit 2.12.0",
      "client command removed",
      "repaired control",
    ]);

    const semanticContract = [
      "GHSA-w3fx-mc44-mf6j and CVE-2026-45018 affect this official Chainlit application import chainlit launch.",
      ".chainlit/config.toml has features.mcp.enabled = true with features.mcp.stdio stdio enabled and allowed_executables npx and uvx.",
      "The exact chainlit==2.11.1 affected release accepts POST /mcp fullCommand as a client-controlled command.",
      "validate_mcp_command uses shlex.split with an executable-only allowlist before StdioServerParameters reaches stdio_client subprocess spawn.",
      "An authentication callback, anonymous session policy, and network reachability remain deployment uncertainties.",
      "On Python 3.12.3 the non-executing witness records parsed argv without launching anything.",
      "The chainlit 2.12.0 repaired control has client command removed.",
      "Configured stdio process and concurrent MCP sessions remain residual risk.",
      "This is CWE-78 OS command injection through command argument injection.",
    ].join(" ");
    finding.validation.summary = semanticContract;
    finding.attackPath.summary = semanticContract;
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );

    expect(
      await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      ),
    ).toBe("");
  });

  test("requires exact topology, non-executing validation, repair, and calibrated impact in the prompt", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain(
      "For python-chainlit-mcp-stdio-command-injection rows",
    );
    expect(prompt).toContain("GHSA-w3fx-mc44-mf6j / CVE-2026-45018");
    expect(prompt).toContain("validate_mcp_command used shlex.split");
    expect(prompt).toContain("never pass that output to a subprocess");
    expect(prompt).toContain("Chainlit 2.12.0 removes client fullCommand");
    expect(prompt).toContain("before claiming remote code execution");
    expect(prompt).toContain("Report CWE-78");
  });
});
