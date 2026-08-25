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

function tarfileRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "python-web-tarfile-unsafe-extraction",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-python-tarfile-"),
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
      tarfileRecords(await buildResidualRiskInventory(repository)),
    ),
  );
}

const runtime312 = { ".python-version": "3.12.3\n" };

function moduleRoute(
  extraction: string,
  creation = 'with tarfile.open(fileobj=request.files["archive"].stream, mode="r:*") as archive:',
): string {
  return [
    "from flask import request",
    "import tarfile",
    "def route():",
    `    ${creation}`,
    `        ${extraction}`,
  ].join("\n");
}

describe("Python standard-library tarfile unsafe extraction model", () => {
  test("keeps a strict TarSlip benchmark and topology-matched data-filter control", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-tarfile-unsafe-extraction-manifest.json"),
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
    const canonical = JSON.parse(
      await readFile(join(benchmarkRoot, "manifest.json"), "utf8"),
    ) as typeof manifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "python-tarfile-unsafe-extraction",
      "python-tarfile-data-filter-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-22"]);
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

    const canonicalCases = canonical.cases.filter(({ id }) =>
      id.startsWith("python-tarfile-"),
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
      ".python-version",
      join("examples", "escaped-marker.txt"),
      join("examples", "witness.py"),
      join("src", "__init__.py"),
      join("src", "server.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-tarfile-unsafe-extraction",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-tarfile-data-filter-control",
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
          "python-tarfile-unsafe-extraction",
          "src",
          "extractor.py",
        ),
        "utf8",
      ),
    ).toContain("archive.extractall(path=destination)");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-tarfile-data-filter-control",
          "src",
          "extractor.py",
        ),
        "utf8",
      ),
    ).toContain('filter="data"');
  });

  test("emits the exact upload-wrapper-open-extraction path and suppresses the control", async () => {
    const affected = tarfileRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-tarfile-unsafe-extraction"),
      ),
    );
    const control = tarfileRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-tarfile-data-filter-control"),
      ),
    );

    expect(control).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/extractor.py");
    expect(affected[0]?.line).toBe(8);
    expect(affected[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(affected[0]?.frameworkModel?.source).toMatchObject({
      kind: "framework-request-body",
      path: "src/server.py",
      line: 14,
    });
    expect(affected[0]?.frameworkModel?.sink).toMatchObject({
      kind: "tarfile-untrusted-archive-extraction",
      path: "src/extractor.py",
      line: 8,
      cweIds: ["CWE-22"],
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "tarfile-creator-binding",
        "tarfile-untrusted-archive-open",
        "python-runtime-version",
        "pre-3.14-fully-trusted-tar-default",
        "tarfile-extraction-operation",
        "intrinsic-tar-member-path-write",
      ]),
    );
  });

  test("supports module, module alias, direct, constructor, and parenthesized bindings", async () => {
    const repositories = await Promise.all([
      writeRepository({
        ...runtime312,
        "app.py": moduleRoute("archive.extractall()"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile as tf",
          "def route():",
          "    with tf.open(fileobj=request.stream, mode='r:*') as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "from tarfile import open as open_archive",
          "def route():",
          "    archive = open_archive(fileobj=request.stream, mode='r')",
          "    archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "from tarfile import TarFile as Archive",
          "def route():",
          "    archive = Archive(name=None, mode='r', fileobj=request.stream)",
          "    archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "from tarfile import (",
          "    open as open_archive,",
          ")",
          "def route():",
          "    with open_archive(fileobj=request.stream) as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1, 1, 1]);
  });

  test("supports extract and extractall, assignment receivers, aliases, and multiline calls", async () => {
    const repositories = await Promise.all([
      writeRepository({
        ...runtime312,
        "app.py": moduleRoute("archive.extract(member)"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def route():",
          "    archive = tarfile.open(",
          "        fileobj=request.stream,",
          "        mode='r:*',",
          "    )",
          "    active = archive",
          "    active.extractall(",
          "        path='/srv/imports',",
          "    )",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def route():",
          "    with tarfile.open(request.path, 'r', request.stream) as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([1, 1, 1]);
  });

  test("applies the Python 3.14 default transition and exact nearest runtime boundary", async () => {
    const make = (
      runtimePath: string | undefined,
      version: string | undefined,
    ): Promise<string> =>
      writeRepository({
        ...(runtimePath === undefined || version === undefined
          ? {}
          : { [runtimePath]: version }),
        "app.py": moduleRoute("archive.extractall()"),
      });
    const repositories = await Promise.all([
      make(".python-version", "3.11.9\n"),
      make(".python-version", "3.12.3\n"),
      make(".python-version", "3.13.9\n"),
      make(".python-version", "3.14.0\n"),
      make("runtime.txt", "python-3.12.3\n"),
      make(undefined, undefined),
      make(".python-version", ">=3.12,<3.14\n"),
      writeRepository({
        ".python-version": "3.12.3\n",
        "runtime.txt": "python-3.12.3\n",
        "app.py": moduleRoute("archive.extractall()"),
      }),
      writeRepository({
        ".python-version": "3.14.0\n",
        "src/.python-version": "3.12.3\n",
        "src/app.py": moduleRoute("archive.extractall()"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([
      1, 1, 1, 0, 1, 0, 0, 0, 1,
    ]);
  });

  test("accepts only exact unsafe filters and rejects exact safe or ambiguous filters", async () => {
    const make = (version: string, imports: string, filter: string) =>
      writeRepository({
        ".python-version": `${version}\n`,
        "app.py": [
          "from flask import request",
          imports,
          "def route():",
          "    with tarfile.open(fileobj=request.stream) as archive:",
          `        archive.extractall(filter=${filter})`,
        ].join("\n"),
      });
    const repositories = await Promise.all([
      make("3.12.3", "import tarfile", "'fully_trusted'"),
      make("3.14.0", "import tarfile", "'fully_trusted'"),
      make(
        "3.12.3",
        "import tarfile\nfrom tarfile import fully_trusted_filter as trusted",
        "trusted",
      ),
      make("3.12.3", "import tarfile", "'data'"),
      make("3.12.3", "import tarfile", "'tar'"),
      make(
        "3.12.3",
        "import tarfile\nfrom tarfile import data_filter",
        "data_filter",
      ),
      make(
        "3.12.3",
        "import tarfile\nfrom tarfile import tar_filter as bounded",
        "bounded",
      ),
      make("3.12.3", "import tarfile", "policy"),
      make("3.11.9", "import tarfile", "'fully_trusted'"),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([
      1, 1, 1, 0, 0, 0, 0, 0, 0,
    ]);
  });

  test("honors exact instance and class extraction_filter overrides", async () => {
    const make = (assignment: string) =>
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def route():",
          "    archive = tarfile.open(fileobj=request.stream)",
          `    ${assignment}`,
          "    archive.extractall()",
        ].join("\n"),
      });
    const repositories = await Promise.all([
      make("archive.extraction_filter = tarfile.data_filter"),
      make("archive.extraction_filter = staticmethod(tarfile.tar_filter)"),
      make("archive.extraction_filter = tarfile.fully_trusted_filter"),
      make("archive.extraction_filter = policy"),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "tarfile.TarFile.extraction_filter = staticmethod(tarfile.data_filter)",
          "def route():",
          "    with tarfile.open(fileobj=request.stream) as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "tarfile.TarFile.extraction_filter = staticmethod(tarfile.fully_trusted_filter)",
          "def route():",
          "    with tarfile.open(fileobj=request.stream) as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 1, 0, 0, 1]);
  });

  test("rejects write modes, wrong fileobj roles, fixed inputs, and star expansion", async () => {
    const repositories = await Promise.all([
      writeRepository({
        ...runtime312,
        "app.py": moduleRoute(
          "archive.extractall()",
          'with tarfile.open(fileobj=request.stream, mode="w:gz") as archive:',
        ),
      }),
      writeRepository({
        ...runtime312,
        "app.py": moduleRoute(
          "archive.extractall(path=request.form['destination'])",
          "with tarfile.open(fileobj=trusted_stream) as archive:",
        ),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def route():",
          "    with tarfile.open(name=request.form['path']) as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": moduleRoute("archive.extractall(*options)"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def route():",
          "    with tarfile.open(*options, fileobj=request.stream) as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0, 0]);
  });

  test("rejects shadows, replaced bindings, receiver reassignment, other scopes, and lookalikes", async () => {
    const repositories = await Promise.all([
      writeRepository({
        ...runtime312,
        "tarfile.py": "def open(*args, **kwargs): pass\n",
        "app.py": moduleRoute("archive.extractall()"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "tarfile.open = factory",
          "def route():",
          "    with tarfile.open(fileobj=request.stream) as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def route(tarfile):",
          "    with tarfile.open(fileobj=request.stream) as archive:",
          "        archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def route():",
          "    archive = tarfile.open(fileobj=request.stream)",
          "    archive = safe_archive",
          "    archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def build():",
          "    archive = tarfile.open(fileobj=request.stream)",
          "def route():",
          "    archive.extractall()",
        ].join("\n"),
      }),
      writeRepository({
        ...runtime312,
        "app.py": [
          "from flask import request",
          "import tarfile",
          "def route():",
          "    text = 'archive.extractall()'",
          "    return text",
        ].join("\n"),
      }),
    ]);

    const records = await scanRepositories(repositories);
    expect(records.map((rows) => rows.length)).toEqual([0, 0, 0, 0, 0, 0]);
  });

  test("does not let dense unrelated extraction calls consume the exact receiver candidate budget", async () => {
    const decoys = Array.from(
      { length: 80 },
      (_, index) => `other_${index}.extractall()`,
    );
    const repository = await writeRepository({
      ...runtime312,
      "app.py": [
        "from flask import request",
        "import tarfile",
        ...decoys,
        "archive = tarfile.open(fileobj=request.stream)",
        "active = archive",
        "active.extractall()",
      ].join("\n"),
    });

    const records = tarfileRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(85);
  });

  test("preserves the fileobj flow through a two-relay relative wrapper path", async () => {
    const repository = await writeRepository({
      ...runtime312,
      "server.py": [
        "from flask import request",
        "from .service import import_archive",
        "def route():",
        "    return import_archive(request.files['archive'].stream)",
      ].join("\n"),
      "service.py": [
        "from .extractor import extract_archive",
        "def import_archive(stream):",
        "    return extract_archive(stream)",
      ].join("\n"),
      "extractor.py": [
        "import tarfile as tf",
        "def extract_archive(stream):",
        "    with tf.open(fileobj=stream, mode='r:*') as archive:",
        "        archive.extractall()",
      ].join("\n"),
    });

    const records = tarfileRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(records[0]?.frameworkModel?.source.path).toBe("server.py");
    expect(records[0]?.frameworkModel?.sink.path).toBe("extractor.py");
  });

  test.skipIf(process.platform === "win32")(
    "does not follow symlinked runtime metadata",
    async () => {
      const repository = await writeRepository({
        "real-version": "3.12.3\n",
        "app.py": moduleRoute("archive.extractall()"),
      });
      await symlink("real-version", join(repository, ".python-version"));

      expect(
        tarfileRecords(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    },
  );

  test("host re-audit requires complete tarfile evidence in both report fields", async () => {
    const repository = await writeRepository({
      ...runtime312,
      "src/server.py": [
        "from .extractor import extract_archive",
        "def route(request):",
        "    return extract_archive(request.files['archive'].stream)",
      ].join("\n"),
      "src/extractor.py": [
        "import tarfile",
        "def extract_archive(stream):",
        "    with tarfile.open(fileobj=stream) as archive:",
        "        archive.extractall()",
      ].join("\n"),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-python-tarfile-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_python_tarfile_quality",
      taxonomy: { cwe: ["CWE-22"] },
      locations: [
        { path: "src/server.py", startLine: 3, role: "source" },
        { path: "src/extractor.py", startLine: 4, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "archive-source",
          path: "src/server.py",
          startLine: 3,
          code: "    return extract_archive(request.files['archive'].stream)",
          explanation: "The uploaded archive stream enters the wrapper.",
          role: "source",
        },
        {
          id: "tarfile-sink",
          path: "src/extractor.py",
          startLine: 4,
          code: "        archive.extractall()",
          explanation: "The opened TarFile extracts all members.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms a reachable archive extraction.",
        method: "static source trace",
        exploitWitness: "A bounded archive contains an escaped marker.",
        negativeControl: "A data filter rejects traversal.",
        evidence: ["archive-source", "tarfile-sink"],
        counterEvidence:
          "The upload byte limit does not constrain member paths.",
        remainingUncertainty:
          "Deployment runtime and privileges determine impact.",
      },
      attackPath: {
        summary: "A remote caller reaches archive extraction.",
        dataflow: {
          source: "archive-source",
          sink: "tarfile-sink",
          outcome: "outside-destination write",
        },
        reachability: {
          attacker: "Unauthenticated remote caller",
          entrypoint: "archive upload endpoint",
          outcome: "fixture marker integrity is lost",
        },
        brokenControls: ["Unsafe extraction-filter default"],
        evidenceRefs: ["archive-source", "tarfile-sink"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const residual = await buildResidualRiskInventory(repository);
    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      residual,
    );
    const rows = incomplete.split("\n").map((line) => JSON.parse(line));
    expect(rows[1]).toMatchObject({
      findingId: "occ_python_tarfile_quality",
      frameworkModelId: "python-web-tarfile-unsafe-extraction",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "fully_trusted",
      "pre-3.14 default",
      "unsafe extraction filter",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "Python 3.12.3",
    ]);

    const contract = [
      "A request.files archive upload supplies the uploaded tar stream to the extract_archive wrapper.",
      "The official tarfile.open TarFile binding consumes the archive through its fileobj open argument before extractall.",
      "On Python 3.12.3 the pre-3.14 default filter=None uses fully_trusted extraction.",
      "A ../ traversal member path writes the escaped marker outside destination as an arbitrary file write.",
      'The negative control passes filter="data" and raises OutsideDestinationError.',
    ].join(" ");
    finding.validation.summary = contract;
    finding.attackPath.summary = contract;
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );

    expect(
      await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        residual,
      ),
    ).toBe("");
  });

  test("quality-gate prompt preserves runtime, filter, receiver, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain("For python-web-tarfile-unsafe-extraction rows");
    expect(prompt).toContain("tarfile.open or TarFile binding");
    expect(prompt).toContain("fileobj edge");
    expect(prompt).toContain("Python below 3.14");
    expect(prompt).toContain("Python 3.14 changes the default to data");
    expect(prompt).toContain("fully_trusted_filter");
    expect(prompt).toContain("OutsideDestinationError");
    expect(prompt).toContain("Python 3.12.3");
    expect(prompt).toContain("Report CWE-22");
  });
});
