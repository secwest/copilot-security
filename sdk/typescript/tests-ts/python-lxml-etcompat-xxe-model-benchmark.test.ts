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

function etcompatRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "python-web-lxml-etcompat-xxe",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-lxml-etcompat-"),
  );
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
      etcompatRecords(await buildResidualRiskInventory(repository)),
    ),
  );
}

const exactRequirement = { "requirements.txt": "lxml==6.0.2\n" };

describe("Python lxml ET-compatible parser XXE model", () => {
  test("keeps a strict affected-version benchmark and source-identical patched control", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-lxml-etcompat-xxe-manifest.json"),
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
      "python-lxml-etcompat-xxe",
      "python-lxml-etcompat-patched-control",
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
      id.startsWith("python-lxml-etcompat-"),
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
      join("src", "__init__.py"),
      join("src", "parser.py"),
      join("src", "server.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-lxml-etcompat-xxe",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-lxml-etcompat-patched-control",
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
          "python-lxml-etcompat-xxe",
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
          "python-lxml-etcompat-patched-control",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toContain("lxml==6.1.1");
  });

  test("emits the exact upload-parser-use path and suppresses the patched control", async () => {
    const affected = etcompatRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-lxml-etcompat-xxe"),
      ),
    );
    const control = etcompatRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-lxml-etcompat-patched-control"),
      ),
    );

    expect(control).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/parser.py");
    expect(affected[0]?.line).toBe(6);
    expect(affected[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(affected[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-body",
      path: "src/server.py",
      line: 11,
    });
    expect(affected[0]?.frameworkModel?.sink).toMatchObject({
      kind: "lxml-etcompat-untrusted-xml",
      path: "src/parser.py",
      line: 6,
      cweIds: ["CWE-611"],
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "lxml-parse-binding",
        "lxml-etcompat-binding",
        "lxml-etcompat-construction",
        "affected-lxml-etcompat-default",
        "lxml-etcompat-parser-use",
        "intrinsic-lxml-external-entity-resolution",
      ]),
    );
  });

  test("supports module, receiver, direct, parenthesized, and official alias bindings", async () => {
    const repositories = await Promise.all([
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "import lxml.etree",
          "def route():",
          "    parser = lxml.etree.ETCompatXMLParser()",
          "    return lxml.etree.fromstring(request.data, parser=parser)",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "import lxml.etree as ET",
          "def route():",
          "    return ET.fromstring(request.data, ET.ETCompatXMLParser())",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml import etree as ET",
          "def route():",
          "    parser = ET.XMLTreeBuilder()",
          "    return ET.XML(request.data, parser=parser)",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml.etree import ETCompatXMLParser as Parser, fromstring as decode",
          "def route():",
          "    return decode(request.data, parser=Parser())",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml.etree import (",
          "    XML as decode,",
          "    XMLTreeBuilder as Builder,",
          ")",
          "def route():",
          "    return decode(text=request.data, parser=Builder())",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1, 1, 1]);
  });

  test("supports all bounded official parse operations and parser argument forms", async () => {
    const sources = [
      "return etree.parse(source=request.stream, parser=parser)",
      "return etree.XML(text=request.data, parser=parser)",
      "return etree.fromstringlist(strings=[request.data], parser=parser)",
      "return etree.fromstring(request.data, parser)",
    ];
    const repositories = await Promise.all(
      sources.map((source) =>
        writeRepository({
          ...exactRequirement,
          "app.py": [
            "from flask import request",
            "from lxml import etree",
            "def route():",
            "    parser = etree.ETCompatXMLParser()",
            `    ${source}`,
          ].join("\n"),
        }),
      ),
    );

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1, 1]);
  });

  test("supports bounded multiline construction and parser use", async () => {
    const repository = await writeRepository({
      ...exactRequirement,
      "app.py": [
        "from flask import request",
        "from lxml.etree import ETCompatXMLParser as Parser, fromstring as decode",
        "def route():",
        "    parser = Parser(",
        "        no_network=True,",
        "    )",
        "    return decode(",
        "        request.data,",
        "        parser=parser,",
        "    )",
      ].join("\n"),
    });

    expect(
      etcompatRecords(await buildResidualRiskInventory(repository)),
    ).toHaveLength(1);
  });

  test("accepts explicit unsafe mode but rejects safe, dynamic, and unproved defaults", async () => {
    const make = (
      requirement: string | undefined,
      constructor: string,
    ): Promise<string> =>
      writeRepository({
        ...(requirement === undefined
          ? {}
          : { "requirements.txt": requirement }),
        "app.py": [
          "from flask import request",
          "from lxml import etree",
          "def route():",
          `    parser = etree.ETCompatXMLParser(${constructor})`,
          "    return etree.fromstring(request.data, parser=parser)",
        ].join("\n"),
      });
    const repositories = await Promise.all([
      make(undefined, "resolve_entities=True"),
      make("lxml==6.1.1\n", "resolve_entities=True"),
      make("lxml==6.0.2\n", "resolve_entities=False"),
      make("lxml==6.0.2\n", "resolve_entities='internal'"),
      make("lxml==6.0.2\n", "resolve_entities=unsafe"),
      make(undefined, ""),
      make("lxml>=5,<7\n", ""),
      make("lxml==6.0.2\nlxml==6.0.3\n", ""),
      make("lxml==6.1.0\n", ""),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([
      1, 1, 0, 0, 0, 0, 0, 0, 0,
    ]);
  });

  test("uses only the nearest exact requirements boundary", async () => {
    const app = [
      "from flask import request",
      "from lxml import etree",
      "def route():",
      "    return etree.fromstring(request.data, parser=etree.ETCompatXMLParser())",
    ].join("\n");
    const repositories = await Promise.all([
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "src/app.py": app,
      }),
      writeRepository({
        "requirements.txt": "lxml==6.0.2\n",
        "src/requirements.txt": "Flask==3.1.2\n",
        "src/app.py": app,
      }),
      writeRepository({
        "requirements.txt": "lxml==6.1.1\n",
        "src/requirements.txt": "lxml==6.0.2\n",
        "src/app.py": app,
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([1, 0, 1]);
  });

  test("requires the exact constructed parser to reach the exact parse call", async () => {
    const bodies = [
      [
        "parser = etree.ETCompatXMLParser()",
        "return etree.fromstring(request.data)",
      ],
      [
        "parser = etree.ETCompatXMLParser()",
        "return etree.fromstring(request.data, parser=other)",
      ],
      [
        "parser = etree.ETCompatXMLParser()",
        "parser = None",
        "return etree.fromstring(request.data, parser=parser)",
      ],
      [
        "parser = etree.XMLParser(resolve_entities=False)",
        "return etree.fromstring(request.data, parser=parser)",
      ],
      [
        "parser = etree.ETCompatXMLParser()",
        "active = parser",
        "return etree.fromstring(request.data, parser=active)",
      ],
      [
        "return etree.fromstring(request.data, parser=etree.ETCompatXMLParser())",
      ],
    ];
    const repositories = await Promise.all(
      bodies.map((body) =>
        writeRepository({
          ...exactRequirement,
          "app.py": [
            "from flask import request",
            "from lxml import etree",
            "def route():",
            ...body.map((line) => `    ${line}`),
          ].join("\n"),
        }),
      ),
    );

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0, 1, 1]);
  });

  test("does not resolve a same-named parser object out of another function scope", async () => {
    const repository = await writeRepository({
      ...exactRequirement,
      "app.py": [
        "from flask import request",
        "from lxml import etree",
        "def build_for_other_route():",
        "    parser = etree.ETCompatXMLParser()",
        "    return parser",
        "def route():",
        "    return etree.fromstring(request.data, parser=parser)",
      ].join("\n"),
    });

    expect(
      etcompatRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("rejects package shadows, binding replacement, parameter shadows, and lookalikes", async () => {
    const repositories = await Promise.all([
      writeRepository({
        ...exactRequirement,
        "lxml.py": "class etree: pass\n",
        "app.py": [
          "from flask import request",
          "from lxml import etree",
          "def route():",
          "    return etree.fromstring(request.data, parser=etree.ETCompatXMLParser())",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml import etree",
          "etree.ETCompatXMLParser = factory",
          "def route():",
          "    return etree.fromstring(request.data, parser=etree.ETCompatXMLParser())",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml import etree",
          "etree.fromstring = decode",
          "def route():",
          "    return etree.fromstring(request.data, parser=etree.ETCompatXMLParser())",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml import etree",
          "def route(etree):",
          "    return etree.fromstring(request.data, parser=etree.ETCompatXMLParser())",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml import etree",
          "def route():",
          "    text = 'etree.fromstring(request.data, parser=etree.ETCompatXMLParser())'",
          "    return text",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0, 0]);
  });

  test("does not conflate ordinary XMLParser or local lookalike constructors", async () => {
    const repositories = await Promise.all([
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml import etree",
          "def route():",
          "    parser = etree.XMLParser()",
          "    return etree.fromstring(request.data, parser=parser)",
        ].join("\n"),
      }),
      writeRepository({
        ...exactRequirement,
        "app.py": [
          "from flask import request",
          "from lxml import etree",
          "class ETCompatXMLParser:",
          "    pass",
          "def route():",
          "    return etree.fromstring(request.data, parser=ETCompatXMLParser())",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([0, 0]);
  });

  test("rejects fixed or wrong-role XML, star calls, and constructor positional arguments", async () => {
    const bodies = [
      "return etree.fromstring(b'<root/>', parser=etree.ETCompatXMLParser())",
      "return etree.fromstring(request.headers['X-XML'], parser=etree.ETCompatXMLParser())",
      "return etree.fromstring(*args, parser=etree.ETCompatXMLParser())",
      "return etree.fromstring(request.data, parser=etree.ETCompatXMLParser(*options))",
      "return etree.fromstring(request.data, parser=etree.ETCompatXMLParser('utf8'))",
    ];
    const repositories = await Promise.all(
      bodies.map((body) =>
        writeRepository({
          ...exactRequirement,
          "app.py": [
            "from flask import request",
            "from lxml import etree",
            "def route():",
            `    ${body}`,
          ].join("\n"),
        }),
      ),
    );

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0, 0]);
  });

  test("finds a late arbitrary direct alias after dense unrelated calls", async () => {
    const decoys = Array.from(
      { length: 80 },
      (_, index) => `value_${index} = unrelated_${index}()`,
    );
    const repository = await writeRepository({
      ...exactRequirement,
      "app.py": [
        "from flask import request",
        "from lxml.etree import ETCompatXMLParser as Parser, fromstring as decode",
        ...decoys,
        "result = decode(request.data, parser=Parser())",
      ].join("\n"),
    });

    const records = etcompatRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(83);
  });

  test("preserves arbitrary direct aliases through a two-relay relative wrapper path", async () => {
    const repository = await writeRepository({
      ...exactRequirement,
      "server.py": [
        "from flask import request",
        "from .service import decode_document",
        "def route():",
        "    return decode_document(request.data)",
      ].join("\n"),
      "service.py": [
        "from .parser import parse_document",
        "def decode_document(value):",
        "    return parse_document(value)",
      ].join("\n"),
      "parser.py": [
        "from lxml.etree import ETCompatXMLParser as Parser, fromstring as decode",
        "def parse_document(document):",
        "    return decode(document, parser=Parser())",
      ].join("\n"),
    });

    const records = etcompatRecords(
      await buildResidualRiskInventory(repository),
    );
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
          "from flask import request",
          "from lxml import etree",
          "def route():",
          "    return etree.fromstring(request.data, parser=etree.ETCompatXMLParser())",
        ].join("\n"),
      });
      await symlink(
        "real-requirements.txt",
        join(repository, "requirements.txt"),
      );

      expect(
        etcompatRecords(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    },
  );

  test("host re-audit requires complete ET-compatible evidence in both report fields", async () => {
    const repository = await writeRepository({
      ...exactRequirement,
      "src/server.py": [
        "from .parser import parse_document",
        "def route(request):",
        "    return parse_document(request.files['document'].read())",
      ].join("\n"),
      "src/parser.py": [
        "from lxml import etree",
        "def parse_document(document):",
        "    parser = etree.ETCompatXMLParser()",
        "    return etree.fromstring(document, parser=parser)",
      ].join("\n"),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-lxml-etcompat-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_lxml_etcompat_quality",
      taxonomy: { cwe: ["CWE-611"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/parser.py", startLine: 4, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "xml-source",
          path: "src/server.py",
          startLine: 3,
          code: "    return parse_document(request.files['document'].read())",
          explanation: "The uploaded XML enters the parser wrapper.",
          role: "source",
        },
        {
          id: "etcompat-sink",
          path: "src/parser.py",
          startLine: 4,
          code: "    return etree.fromstring(document, parser=parser)",
          explanation:
            "The exact ET-compatible parser is supplied under the affected default.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms a reachable XML parser.",
        method: "static source trace",
        exploitWitness: "A bounded XML document refers to a local marker.",
        negativeControl: "The patched dependency rejects the external entity.",
        evidence: ["xml-source", "etcompat-sink"],
        counterEvidence: "The byte limit does not disable entity expansion.",
        remainingUncertainty: "Deployment versions determine final exposure.",
      },
      attackPath: {
        summary: "A remote caller reaches XML parsing.",
        dataflow: {
          source: "xml-source",
          sink: "etcompat-sink",
          outcome: "local file disclosure",
        },
        reachability: {
          attacker: "Unauthenticated remote caller",
          entrypoint: "XML upload endpoint",
          outcome: "Fixture marker confidentiality is lost",
        },
        brokenControls: ["Affected entity-resolution default"],
        evidenceRefs: ["xml-source", "etcompat-sink"],
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
      findingId: "occ_lxml_etcompat_quality",
      frameworkModelId: "python-web-lxml-etcompat-xxe",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "ETCompatXMLParser",
      "XMLTreeBuilder",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "Python 3.12.3",
    ]);

    const semanticContract = [
      "A request.files XML upload supplies the uploaded XML to the parse_document wrapper.",
      "The live ETCompatXMLParser is constructed and passed as the parser= argument to the lxml.etree.fromstring parse binding.",
      "The pre-6.1 default resolve_entities=True affected by CVE-2026-41066 resolves a DOCTYPE external SYSTEM entity.",
      "A local file URI discloses the fixture marker.",
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

  test("requires exact parser identity, parser use, and version-aware evidence", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain("For python-web-lxml-etcompat-xxe rows");
    expect(prompt).toContain("ETCompatXMLParser or official XMLTreeBuilder");
    expect(prompt).toContain("argument one or parser=");
    expect(prompt).toContain("explicit resolve_entities=True");
    expect(prompt).toContain(
      "one exact nearest lxml<6.1.0 requirements.txt pin",
    );
    expect(prompt).toContain("CVE-2026-41066/GHSA-vfmq-68hx-4jfw");
    expect(prompt).toContain("Ordinary XMLParser defaults changed in lxml 5.0");
    expect(prompt).toContain("no_network=True does not prevent local file");
    expect(prompt).toContain("Python 3.12.3");
    expect(prompt).toContain("lxml==6.0.2");
    expect(prompt).toContain("lxml==6.1.1");
    expect(prompt).toContain("Report CWE-611");
  });
});
