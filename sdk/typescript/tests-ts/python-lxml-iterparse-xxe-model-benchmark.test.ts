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

function lxmlRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "python-web-lxml-iterparse-xxe",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-lxml-"));
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
  }
  return repository;
}

async function scanRepositories(
  repositories: readonly string[],
): Promise<FrameworkRecord[][]> {
  return Promise.all(
    repositories.map(async (repository) =>
      lxmlRecords(await buildResidualRiskInventory(repository)),
    ),
  );
}

describe("Python lxml iterparse XXE model", () => {
  test("keeps a strict affected-version benchmark and source-identical patched control", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-lxml-iterparse-xxe-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        findingsPaths: string[];
        expected: Array<{
          cwe?: string[];
          acceptableSeverities?: string[];
          requiredValidationTextAnyOf?: string[][];
          requiredAttackPathTextAnyOf?: string[][];
          forbiddenText?: string[];
        }>;
      }>;
    };
    const canonicalManifest = JSON.parse(
      await readFile(join(benchmarkRoot, "manifest.json"), "utf8"),
    ) as typeof manifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "python-lxml-iterparse-xxe",
      "python-lxml-iterparse-patched-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-611"]);
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

    const canonicalCases = canonicalManifest.cases.filter(({ id }) =>
      id.startsWith("python-lxml-iterparse-"),
    );
    expect(canonicalCases.map(({ id }) => id)).toEqual(
      manifest.cases.map(({ id }) => id),
    );
    expect(
      canonicalCases.map(({ findingsPaths }) => findingsPaths.length),
    ).toEqual([3, 3]);
    expect(canonicalCases.map(({ expected }) => expected)).toEqual(
      manifest.cases.map(({ expected }) => expected),
    );

    for (const relativePath of [
      join("examples", "entity-marker.txt"),
      join("examples", "witness.py"),
      join("src", "parser.py"),
      join("src", "server.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-lxml-iterparse-xxe",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-lxml-iterparse-patched-control",
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
          "python-lxml-iterparse-xxe",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toContain("lxml==6.0.2");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-lxml-iterparse-patched-control",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toContain("lxml==6.1.1");
  });

  test("emits the exact upload-to-consumed-iterator path and suppresses the patched control", async () => {
    const affected = lxmlRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-lxml-iterparse-xxe"),
      ),
    );
    const control = lxmlRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-lxml-iterparse-patched-control",
        ),
      ),
    );

    expect(control).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/parser.py");
    expect(affected[0]?.line).toBe(5);
    expect(affected[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(affected[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-body",
      path: "src/server.py",
      line: 11,
    });
    expect(affected[0]?.frameworkModel?.sink).toMatchObject({
      kind: "lxml-iterparse-untrusted-xml",
      path: "src/parser.py",
      line: 5,
      cweIds: ["CWE-611"],
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "lxml-iterparse-binding",
        "lxml-iterparse-consumption",
        "affected-lxml-iterparse-default",
        "intrinsic-lxml-external-entity-resolution",
      ]),
    );
  });

  test("supports documented module, receiver, direct, parenthesized, and source-keyword forms", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "import lxml.etree",
          "def route(request):",
          "    return list(lxml.etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "import lxml.etree as ET",
          "def route(request):",
          "    return tuple(ET.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "from lxml import etree as ET",
          "def route(request):",
          "    return list(ET.iterparse(source=request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "from lxml.etree import iterparse as parse_xml",
          "def route(request):",
          "    return list(parse_xml(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "from lxml.etree import (",
          "    iterparse as parse_xml,",
          ")",
          "def route(request):",
          "    return list(parse_xml(request.stream))",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1, 1, 1]);
  });

  test("retains a late direct alias after dense unrelated calls", async () => {
    const unrelatedCalls = Array.from(
      { length: 80 },
      (_, index) => `    helper_${index}()`,
    );
    const repository = await writeRepository({
      "requirements.txt": "lxml==6.0.2\n",
      "app.py": [
        "from lxml.etree import iterparse as parse_xml",
        "def route(request):",
        ...unrelatedCalls,
        "    return list(parse_xml(request.stream))",
      ].join("\n"),
    });

    const records = lxmlRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(83);
  });

  test("accepts explicit external entities without a version pin and at the patched boundary", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream, resolve_entities=True))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.1.1\n",
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(source=request.stream, resolve_entities=True))",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([1, 1]);
    for (const rows of records) {
      expect(
        rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
      ).toContain("explicit-lxml-external-entity-resolution");
    }
  });

  test("gates the omitted default on one exact nearest pre-6.1 pin", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "requirements.txt": "lxml==6.0.4\n",
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.1.0\n",
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml>=6.0\n",
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\nlxml==6.1.1\n",
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "src/requirements.txt": "Flask==3.1.2\n",
        "src/app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([1, 0, 0, 0, 0, 0]);
  });

  test("requires iterator consumption and rejects safe or dynamic entity modes", async () => {
    const repository = await writeRepository({
      "requirements.txt": "lxml==6.0.2\n",
      "app.py": [
        "from lxml import etree",
        "def route(request):",
        "    iterator = etree.iterparse(request.stream)",
        "    return iterator",
        "def safe_false(request):",
        "    return list(etree.iterparse(request.stream, resolve_entities=False))",
        "def safe_internal(request):",
        "    return list(etree.iterparse(request.stream, resolve_entities='internal'))",
        "def dynamic(request):",
        "    return list(etree.iterparse(request.stream, resolve_entities=request.args['entities']))",
      ].join("\n"),
    });

    expect(lxmlRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );

    const loopRepository = await writeRepository({
      "requirements.txt": "lxml==6.0.2\n",
      "app.py": [
        "from lxml import etree",
        "def route(request):",
        "    for _, element in etree.iterparse(request.stream):",
        "        return element.text",
      ].join("\n"),
    });
    expect(
      lxmlRecords(await buildResidualRiskInventory(loopRepository)),
    ).toHaveLength(1);
  });

  test("rejects fixed and wrong-role values plus star expansion", async () => {
    const repository = await writeRepository({
      "requirements.txt": "lxml==6.0.2\n",
      "app.py": [
        "from lxml import etree",
        "def route(request):",
        "    list(etree.iterparse('reviewed.xml'))",
        "    list(etree.iterparse('reviewed.xml', events=request.args['events']))",
        "    list(etree.iterparse(*request.stream))",
        "    list(etree.iterparse(request.stream, *request.options))",
      ].join("\n"),
    });

    expect(lxmlRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("rejects local shadows, reassignment, member replacement, and text", async () => {
    const repositories = await Promise.all([
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "lxml.py": "class etree: pass\n",
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    etree = request.parser",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "from lxml import etree",
          "def safe(value): return []",
          "def route(request):",
          "    etree.iterparse = safe",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "text = 'from lxml import etree; list(etree.iterparse(request.stream))'",
          "# from lxml import etree; list(etree.iterparse(request.stream))",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0]);
  });

  test("preserves a two-relay path to the terminal consumed iterator", async () => {
    const repository = await writeRepository({
      "requirements.txt": "lxml==6.0.2\n",
      "server.py": [
        "from .relay import decode",
        "def route(request):",
        "    return decode(request.stream)",
      ].join("\n"),
      "relay.py": [
        "from .service import parse",
        "def decode(value):",
        "    return parse(value)",
      ].join("\n"),
      "service.py": [
        "from .parser import parse_events",
        "def parse(value):",
        "    return parse_events(value)",
      ].join("\n"),
      "parser.py": [
        "from lxml.etree import iterparse",
        "def parse_events(document):",
        "    return list(iterparse(document))",
      ].join("\n"),
    });

    const records = lxmlRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("parser.py");
  });

  test.skipIf(process.platform === "win32")(
    "does not follow a symlinked requirements file for version evidence",
    async () => {
      const repository = await writeRepository({
        "real-requirements.txt": "lxml==6.0.2\n",
        "app.py": [
          "from lxml import etree",
          "def route(request):",
          "    return list(etree.iterparse(request.stream))",
        ].join("\n"),
      });
      await symlink(
        "real-requirements.txt",
        join(repository, "requirements.txt"),
      );

      expect(lxmlRecords(await buildResidualRiskInventory(repository))).toEqual(
        [],
      );
    },
  );

  test("host re-audit requires complete lxml evidence in both report fields", async () => {
    const repository = await writeRepository({
      "requirements.txt": "lxml==6.0.2\n",
      "src/server.py": [
        "from .parser import parse_events",
        "def route(request):",
        "    return parse_events(request.files['document'].stream)",
      ].join("\n"),
      "src/parser.py": [
        "from lxml import etree",
        "def parse_events(document):",
        "    return list(etree.iterparse(document))",
      ].join("\n"),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-lxml-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_lxml_quality",
      taxonomy: { cwe: ["CWE-611"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/parser.py", startLine: 3, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "xml-source",
          path: "src/server.py",
          startLine: 3,
          code: "    return parse_events(request.files['document'].stream)",
          explanation: "The uploaded XML stream enters the parser wrapper.",
          role: "source",
        },
        {
          id: "iterparse-sink",
          path: "src/parser.py",
          startLine: 3,
          code: "    return list(etree.iterparse(document))",
          explanation:
            "The iterator is eagerly consumed under the affected default.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms a reachable XML parser.",
        method: "static source trace",
        exploitWitness: "A bounded XML document refers to a local marker.",
        negativeControl: "The patched dependency rejects the external entity.",
        evidence: ["xml-source", "iterparse-sink"],
        counterEvidence: "The byte limit does not disable entity expansion.",
        remainingUncertainty: "Deployment versions determine final exposure.",
      },
      attackPath: {
        summary: "A remote caller reaches XML parsing.",
        dataflow: {
          source: "xml-source",
          sink: "iterparse-sink",
          outcome: "local file disclosure",
        },
        reachability: {
          attacker: "Unauthenticated remote caller",
          entrypoint: "XML upload endpoint",
          outcome: "Fixture marker confidentiality is lost",
        },
        brokenControls: ["Affected entity-resolution default"],
        evidenceRefs: ["xml-source", "iterparse-sink"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const residualRiskInventory = await buildResidualRiskInventory(repository);

    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      residualRiskInventory,
    );
    const rows = incomplete.split("\n").map((line) => JSON.parse(line));
    expect(rows[1]).toMatchObject({
      findingId: "occ_lxml_quality",
      frameworkModelId: "python-web-lxml-iterparse-xxe",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "parse_events",
      "wrapper",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "Python 3.12.3",
    ]);

    const semanticContract = [
      "A request.files XML upload supplies the uploaded XML stream.",
      "The parse_events wrapper passes it as source argument zero to the lxml.etree.iterparse binding.",
      "Eager list( iterator consumption drives parsing under the pre-6.1 default resolve_entities=True affected by CVE-2026-41066.",
      "A DOCTYPE external SYSTEM entity reads a local file URI and discloses the fixture marker.",
      "The fixture was tested on Python 3.12.3 with lxml 6.0.2; this does not prove deployment versions.",
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
        residualRiskInventory,
      ),
    ).toBe("");
  });

  test("requires version-aware entity evidence and precise false-positive controls", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain("For python-web-lxml-iterparse-xxe rows");
    expect(prompt).toContain("source argument zero or source keyword");
    expect(prompt).toContain(
      "iterator-consumption and unsafe-mode propagators",
    );
    expect(prompt).toContain("explicit resolve_entities=True");
    expect(prompt).toContain("one exact lxml<6.1.0 requirements.txt pin");
    expect(prompt).toContain("CVE-2026-41066/GHSA-vfmq-68hx-4jfw");
    expect(prompt).toContain(
      "lxml 6.1.0 changed iterparse's default from True to 'internal'",
    );
    expect(prompt).toContain("no_network=True does not prevent local file");
    expect(prompt).toContain("Python 3.12.3");
    expect(prompt).toContain("lxml==6.0.2");
    expect(prompt).toContain("lxml==6.1.1");
    expect(prompt).toContain("Report CWE-611");
  });
});
