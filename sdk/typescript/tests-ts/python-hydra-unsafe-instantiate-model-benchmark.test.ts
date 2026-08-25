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

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function hydraRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "python-web-hydra-unsafe-instantiate",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
  requirements: string | null = "hydra-core==1.3.3\n",
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-hydra-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  if (requirements !== null) {
    await writeFile(join(repository, "requirements.txt"), requirements, "utf8");
  }
  return repository;
}

const directRoute = (binding: string, call: string) =>
  [binding, "def route(request):", `    return ${call}`].join("\n");

describe("Python Hydra untrusted target instantiation model", () => {
  test("keeps a strict affected and advisory-control benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-hydra-unsafe-instantiate-manifest.json"),
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
      "python-hydra-unsafe-instantiate",
      "python-hydra-blocklist-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-94", "CWE-470"]);
    expect(manifest.cases[0]?.expected[0]?.acceptableSeverities).toEqual([
      "critical",
      "high",
    ]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(10);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(10);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(manifest.cases[1]?.expected).toEqual([]);

    for (const relativePath of [
      ".python-version",
      join("examples", "witness.py"),
      join("src", "factory.py"),
      join("src", "server.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-hydra-unsafe-instantiate",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-hydra-blocklist-control",
            relativePath,
          ),
          "utf8",
        ),
      );
    }
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-hydra-unsafe-instantiate",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toContain("hydra-core==1.3.3");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-hydra-blocklist-control",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toContain("hydra-core==1.3.4");
  });

  test("emits the exact cross-file request-config-to-Hydra path", async () => {
    const affected = hydraRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-hydra-unsafe-instantiate"),
      ),
    );
    const control = hydraRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-hydra-blocklist-control"),
      ),
    );

    expect(control).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/factory.py");
    expect(affected[0]?.line).toBe(7);
    expect(affected[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(affected[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-config",
      path: "src/server.py",
      line: 15,
    });
    expect(affected[0]?.frameworkModel?.sink).toMatchObject({
      kind: "hydra-affected-untrusted-target-instantiation",
      path: "src/factory.py",
      line: 7,
      cweIds: ["CWE-94", "CWE-470"],
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "hydra-instantiate-binding",
        "hydra-core-runtime-dependency",
        "hydra-untrusted-config-or-target-edge",
        "intrinsic-hydra-dynamic-target-resolution",
        "intrinsic-hydra-configured-callable-invocation",
      ]),
    );
    expect(
      affected[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "hydra-core-runtime-dependency",
      )?.symbol,
    ).toBe("hydra-core@1.3.3:requirements-exact");
  });

  test("supports exact module, utility, direct, aliased, and parenthesized bindings", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": directRoute(
          "import hydra",
          "hydra.utils.instantiate(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "import hydra as framework",
          "framework.utils.call(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "import hydra.utils as factory",
          "factory.instantiate(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "from hydra import utils as factory",
          "factory.call(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": directRoute(
          "from hydra.utils import instantiate as build",
          "build(config=request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": [
          "from hydra.utils import (",
          "    call as build,",
          ")",
          "def route(request):",
          "    return build(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from hydra.utils import instantiate",
          "build = instantiate",
          "def route(request):",
          "    return build(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import hydra",
          "def route(request):",
          "    return hydra.utils.instantiate(",
          "        config=request.get_json(),",
          "    )",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        hydraRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([
      1, 1, 1, 1, 1, 1, 1, 1,
    ]);
    expect(
      records[6]?.[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("hydra-callable-alias");
  });

  test("tracks an explicit remote _target_ override but not another option", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          "from hydra.utils import instantiate",
          "TRUSTED = {'_target_': 'my_app.Model'}",
          "def route(request):",
          "    return instantiate(TRUSTED, _target_=request.json['target'])",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from hydra.utils import instantiate",
          "TRUSTED = {'_target_': 'my_app.Model'}",
          "def route(request):",
          "    return instantiate(TRUSTED, _recursive_=request.json['recursive'])",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from hydra.utils import instantiate",
          "def route(request):",
          "    config = {",
          "        '_target_': 'my_app.Container',",
          "        'plugin': {'_target_': request.json['target']},",
          "    }",
          "    return instantiate(config)",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        hydraRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 0, 1]);
    expect(
      records[0]?.[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "hydra-untrusted-config-or-target-edge",
      )?.symbol,
    ).toBe("_target_ override");
  });

  test("enforces the stable exact 1.3.3 advisory ceiling", async () => {
    const source = {
      "app.py": directRoute(
        "from hydra.utils import instantiate",
        "instantiate(request.get_json())",
      ),
    };
    const repositories = await Promise.all([
      writeRepository(source, "hydra-core==1.3.3\n"),
      writeRepository(source, "hydra-core==1.3.4\n"),
      writeRepository(source, "hydra-core==1.4.0\n"),
      writeRepository(source, "hydra-core==1.3.3.dev0\n"),
      writeRepository(source, "hydra-core>=1.3.0\n"),
      writeRepository(source, "hydra-core==1.3.2\nhydra-core==1.3.3\n"),
      writeRepository(source, ""),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        hydraRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([1, 0, 0, 0, 0, 0, 0]);
  });

  test("rejects fixed targets, fixed configs, wrong roles, and star expansion", async () => {
    const repository = await writeRepository({
      "app.py": [
        "from hydra.utils import instantiate",
        "TRUSTED = {'_target_': 'my_app.Model'}",
        "def route(request):",
        "    inline = {'_target_': 'my_app.Model', 'name': request.json['name']}",
        "    instantiate(inline)",
        "    instantiate(TRUSTED, name=request.json['name'])",
        "    instantiate(config={'_target_': 'my_app.Model'}, name=request.json['name'])",
        "    instantiate(*request.json)",
        "    instantiate(TRUSTED, **request.json)",
        "    return None",
      ].join("\n"),
    });

    expect(hydraRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("rejects local shadows, replacements, parameter shadows, and text", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "hydra.py":
          "class utils:\n    instantiate = staticmethod(lambda value: value)\n",
        "app.py": directRoute(
          "import hydra",
          "hydra.utils.instantiate(request.get_json())",
        ),
      }),
      writeRepository({
        "hydra/__init__.py":
          "class utils:\n    instantiate = staticmethod(lambda value: value)\n",
        "app.py": directRoute(
          "import hydra",
          "hydra.utils.instantiate(request.get_json())",
        ),
      }),
      writeRepository({
        "app.py": [
          "import hydra",
          "def route(request):",
          "    hydra = request.factory",
          "    return hydra.utils.instantiate(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import hydra",
          "def safe(value): return value",
          "def route(request):",
          "    hydra.utils.instantiate = safe",
          "    return hydra.utils.instantiate(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from hydra.utils import instantiate",
          "def route(request, instantiate):",
          "    return instantiate(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "text = 'from hydra.utils import instantiate; instantiate(request.get_json())'",
          "# from hydra.utils import instantiate",
          "# instantiate(request.get_json())",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from hydra.utils import instantiate",
          "def helper():",
          "    build = instantiate",
          "    return build",
          "def route(request):",
          "    return build(request.get_json())",
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        hydraRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0, 0, 0, 0]);
  });

  test("does not follow a symlinked requirements file for version evidence", async () => {
    if (process.platform === "win32") return;
    const repository = await writeRepository(
      {
        "app.py": directRoute(
          "from hydra.utils import instantiate",
          "instantiate(request.get_json())",
        ),
        "pinned-requirements.txt": "hydra-core==1.3.3\n",
      },
      null,
    );
    await symlink(
      "pinned-requirements.txt",
      join(repository, "requirements.txt"),
    );

    expect(hydraRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("preserves a two-relay path to the terminal Hydra binding", async () => {
    const repository = await writeRepository({
      "server.py": [
        "from .relay import decode",
        "def route(request):",
        "    return decode(request.get_json())",
      ].join("\n"),
      "relay.py": [
        "from .service import construct",
        "def decode(config):",
        "    return construct(config)",
      ].join("\n"),
      "service.py": [
        "from .factory import build_component",
        "def construct(config):",
        "    return build_component(config)",
      ].join("\n"),
      "factory.py": [
        "from hydra.utils import instantiate",
        "def build_component(config):",
        "    return instantiate(config)",
      ].join("\n"),
    });

    const records = hydraRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("factory.py");
  });

  test("binding-derived candidates survive dense unrelated call sites", async () => {
    const decoys = Array.from(
      { length: 40 },
      (_, index) => `    service${index}.instantiate(value${index})`,
    );
    const repository = await writeRepository({
      "app.py": [
        "from hydra.utils import instantiate",
        "def route(request):",
        ...decoys,
        "    return instantiate(request.get_json())",
      ].join("\n"),
    });

    const records = hydraRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(43);
  });

  test("host re-audit requires Hydra evidence in both report fields", async () => {
    const repository = await writeRepository({
      "src/server.py": [
        "from .factory import build_component",
        "def route(request):",
        "    return build_component(request.get_json())",
      ].join("\n"),
      "src/factory.py": [
        "from hydra.utils import instantiate",
        "def build_component(config):",
        "    return instantiate(config)",
      ].join("\n"),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-hydra-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_hydra_quality",
      taxonomy: { cwe: ["CWE-94", "CWE-470"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/factory.py", startLine: 3, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "config-source",
          path: "src/server.py",
          startLine: 3,
          code: "    return build_component(request.get_json())",
          explanation: "Request JSON enters the component wrapper.",
          role: "source",
        },
        {
          id: "hydra-sink",
          path: "src/factory.py",
          startLine: 3,
          code: "    return instantiate(config)",
          explanation: "The same configuration reaches Hydra instantiation.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms attacker-selected target resolution.",
        method: "static source trace and bounded installed-package witness",
        exploitWitness:
          "A fixed arithmetic expression returns 42 through builtins.eval.",
        negativeControl: "The repaired package rejects that target.",
        evidence: ["config-source", "hydra-sink"],
        counterEvidence:
          "A JSON type check does not constrain callable identity.",
        remainingUncertainty: "Deployment privileges determine final impact.",
      },
      attackPath: {
        summary: "Remote configuration reaches dynamic callable selection.",
        dataflow: {
          source: "config-source",
          sink: "hydra-sink",
          outcome: "attacker-selected callable invocation",
        },
        reachability: {
          attacker: "Remote component API caller",
          entrypoint: "JSON component endpoint",
          outcome: "Service-process integrity can be affected",
        },
        brokenControls: ["No trusted target allowlist"],
        evidenceRefs: ["config-source", "hydra-sink"],
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
      findingId: "occ_hydra_quality",
      frameworkModelId: "python-web-hydra-unsafe-instantiate",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "build_component",
      "wrapper",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "hydra-core 1.3.4",
      "InstantiationException",
      "target blocklist",
    ]);

    const semanticContract = [
      "A configuration upload from request.get_json supplies request JSON config.",
      "The build_component wrapper calls the official hydra.utils.instantiate Hydra binding.",
      "The config argument is argument zero under hydra-core==1.3.3.",
      "The attacker controls _target_ callable selection and configured target arguments.",
      "On Python 3.12.3 the builtins.eval arithmetic sentinel evaluates 6 * 7.",
      "The hydra-core 1.3.4 target blocklist negative control raises InstantiationException.",
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

  test("requires versioned callable validation and false-positive controls", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain("For python-web-hydra-unsafe-instantiate rows");
    expect(prompt).toContain("GHSA-2cp2-2r3c-7p7r / CVE-2026-68508");
    expect(prompt).toContain("configuration argument zero or config= edge");
    expect(prompt).toContain("a literal application-owned _target_");
    expect(prompt).toContain(
      "builtins.eval evaluating the fixed arithmetic expression 6 * 7",
    );
    expect(prompt).toContain("hydra-core 1.3.3 to 1.3.4");
    expect(prompt).toContain("Report CWE-94 and CWE-470");
    expect(prompt).toContain("missingValidationTextAnyOf");
  });
});
