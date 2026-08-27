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

function asyncSshRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "python-asyncssh-scp-download-path-traversal",
    );
}

async function writeRepository(
  files: Readonly<Record<string, string>>,
  requirements: string | null = "asyncssh==2.23.0\n",
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-asyncssh-"),
  );
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

function moduleDownload(
  moduleImport = "import asyncssh",
  call = 'asyncssh.scp((conn, "release.tar"), Path("downloads"))',
): string {
  return [
    "from pathlib import Path",
    moduleImport,
    "async def fetch(conn):",
    `    return await ${call}`,
  ].join("\n");
}

describe("Python AsyncSSH SCP download traversal model", () => {
  test("keeps a strict affected and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "python-asyncssh-scp-download-path-traversal-manifest.json",
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
      "python-asyncssh-scp-download-path-traversal",
      "python-asyncssh-scp-repaired-control",
    ]);
    expect(manifest.cases[0]?.expected[0]?.cwe).toEqual(["CWE-22"]);
    expect(manifest.cases[0]?.expected[0]?.acceptableSeverities).toEqual([
      "high",
    ]);
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(12);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(12);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(manifest.cases[1]?.expected).toEqual([]);

    for (const relativePath of [
      ".python-version",
      "README.md",
      "RUNTIME.md",
      join("examples", "witness.py"),
      join("src", "__init__.py"),
      join("src", "downloader.py"),
    ]) {
      expect(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-asyncssh-scp-download-path-traversal",
            relativePath,
          ),
          "utf8",
        ),
      ).toBe(
        await readFile(
          join(
            benchmarkRoot,
            "fixtures",
            "python-asyncssh-scp-repaired-control",
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
          "python-asyncssh-scp-download-path-traversal",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toBe("asyncssh==2.23.0\n");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "python-asyncssh-scp-repaired-control",
          "requirements.txt",
        ),
        "utf8",
      ),
    ).toBe("asyncssh==2.23.1\n");
  });

  test("emits the exact remote-source-to-local-write topology", async () => {
    const affected = asyncSshRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "python-asyncssh-scp-download-path-traversal",
        ),
      ),
    );
    const repaired = asyncSshRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "python-asyncssh-scp-repaired-control"),
      ),
    );

    expect(repaired).toEqual([]);
    expect(affected).toHaveLength(1);
    expect(affected[0]?.path.replaceAll("\\", "/")).toBe("src/downloader.py");
    expect(affected[0]?.line).toBe(9);
    expect(affected[0]?.frameworkModel?.scope).toBe("same-file");
    expect(affected[0]?.frameworkModel?.source).toMatchObject({
      kind: "malicious-scp-server-protocol-filename",
      path: "src/downloader.py",
      line: 9,
    });
    expect(affected[0]?.frameworkModel?.sink).toMatchObject({
      kind: "asyncssh-affected-scp-download-path-traversal",
      path: "src/downloader.py",
      line: 9,
      cweIds: ["CWE-22"],
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "asyncssh-scp-binding",
        "asyncssh-runtime-dependency",
        "asyncssh-remote-scp-source",
        "asyncssh-local-download-destination",
        "intrinsic-scp-server-filename-control",
        "intrinsic-asyncssh-traversal-write",
      ]),
    );
    expect(
      affected[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "asyncssh-runtime-dependency",
      )?.symbol,
    ).toBe("asyncssh@2.23.0:requirements-exact");
  });

  test("supports official module, direct, alias, callable-alias, keyword, tuple-host, and host-path forms", async () => {
    const repositories = await Promise.all([
      writeRepository({ "app.py": moduleDownload() }),
      writeRepository({
        "app.py": moduleDownload(
          "import asyncssh as ssh",
          'ssh.scp((conn, "release.tar"), "downloads")',
        ),
      }),
      writeRepository({
        "app.py": moduleDownload(
          "from asyncssh import scp",
          'scp((conn, "release.tar"), "downloads")',
        ),
      }),
      writeRepository({
        "app.py": moduleDownload(
          "from asyncssh import scp as copy_remote",
          'copy_remote((conn, "release.tar"), "downloads")',
        ),
      }),
      writeRepository({
        "app.py": moduleDownload(
          ["from asyncssh import (", "    scp as copy_remote,", ")"].join("\n"),
          'copy_remote((conn, "release.tar"), "downloads")',
        ),
      }),
      writeRepository({
        "app.py": [
          "import asyncssh",
          "copy_remote = asyncssh.scp",
          "async def fetch(conn):",
          '    return await copy_remote((conn, "release.tar"), "downloads")',
        ].join("\n"),
      }),
      writeRepository({
        "app.py": moduleDownload(
          "import asyncssh",
          'asyncssh.scp(srcpaths=(("files.example", 8022), "release.tar"), dstpath="downloads")',
        ),
      }),
      writeRepository({
        "app.py": [
          "import asyncssh",
          "async def fetch():",
          '    return await asyncssh.scp("files.example:release.tar", "downloads")',
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        asyncSshRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual([
      1, 1, 1, 1, 1, 1, 1, 1,
    ]);
    expect(
      records[5]?.[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("asyncssh-scp-callable-alias");
    expect(
      records[7]?.[0]?.frameworkModel?.propagators.find(
        ({ kind }) => kind === "asyncssh-remote-scp-source",
      )?.symbol,
    ).toContain("host-path");
  });

  test("rejects repaired or ambiguous metadata, uploads, remote destinations, shadows, replacements, tests, expansion, and lookalikes", async () => {
    const exact = moduleDownload();
    const repositories = await Promise.all([
      writeRepository({ "app.py": exact }, "asyncssh==2.23.1\n"),
      writeRepository({ "app.py": exact }, "asyncssh>=2.20.0\n"),
      writeRepository({ "app.py": exact }, null),
      writeRepository(
        { "app.py": exact },
        "asyncssh==2.23.0\nasyncssh==2.22.0\n",
      ),
      writeRepository({ "app.py": exact }, "asyncssh==2.23.0rc1\n"),
      writeRepository({
        "asyncssh.py": "async def scp(*args): pass\n",
        "app.py": exact,
      }),
      writeRepository({
        "app.py": [
          "import asyncssh",
          "asyncssh = service.fake_ssh",
          "async def fetch(conn):",
          '    return await asyncssh.scp((conn, "release.tar"), "downloads")',
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import asyncssh",
          "asyncssh.scp = safe_copy",
          "async def fetch(conn):",
          '    return await asyncssh.scp((conn, "release.tar"), "downloads")',
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "from asyncssh import scp",
          "scp = safe_copy",
          "async def fetch(conn):",
          '    return await scp((conn, "release.tar"), "downloads")',
        ].join("\n"),
      }),
      writeRepository({
        "app.py": [
          "import asyncssh",
          "async def fetch(conn, asyncssh):",
          '    return await asyncssh.scp((conn, "release.tar"), "downloads")',
        ].join("\n"),
      }),
      writeRepository({
        "app.py": moduleDownload(
          "import asyncssh",
          'asyncssh.scp("release.tar", (conn, "uploads"))',
        ),
      }),
      writeRepository({
        "app.py": moduleDownload(
          "import asyncssh",
          'asyncssh.scp((conn, "release.tar"), (backup, "copies"))',
        ),
      }),
      writeRepository({
        "app.py": moduleDownload(
          "import asyncssh",
          'asyncssh.scp("release.tar", "downloads")',
        ),
      }),
      writeRepository({
        "app.py": moduleDownload(
          "import asyncssh",
          'asyncssh.scp((conn, "release.tar"))',
        ),
      }),
      writeRepository({
        "app.py": moduleDownload(
          "import asyncssh",
          "asyncssh.scp(*request.args)",
        ),
      }),
      writeRepository({ "tests/test_download.py": exact }),
      writeRepository({ "examples/download.py": exact }),
      writeRepository({
        "app.py": [
          "text = 'import asyncssh'",
          '# await asyncssh.scp((conn, "release.tar"), "downloads")',
        ].join("\n"),
      }),
      writeRepository({ "app.py": "import asyncssh\n" }),
      writeRepository({
        "app.py": moduleDownload(
          "from asyncssh.scp import scp",
          'scp((conn, "release.tar"), "downloads")',
        ),
      }),
      writeRepository({
        "app.py": [
          "import asyncssh",
          "async def fetch(conn, destination):",
          '    return await asyncssh.scp((conn, "release.tar"), destination)',
        ].join("\n"),
      }),
    ]);

    const records = await Promise.all(
      repositories.map(async (repository) =>
        asyncSshRecords(await buildResidualRiskInventory(repository)),
      ),
    );
    expect(records.map((rows) => rows.length)).toEqual(
      Array.from({ length: repositories.length }, () => 0),
    );
  });

  test.skipIf(process.platform === "win32")(
    "does not follow a symlinked requirements file for version evidence",
    async () => {
      const repository = await writeRepository(
        {
          "app.py": moduleDownload(),
          "actual-requirements.txt": "asyncssh==2.23.0\n",
        },
        null,
      );
      await symlink(
        "actual-requirements.txt",
        join(repository, "requirements.txt"),
      );

      expect(
        asyncSshRecords(await buildResidualRiskInventory(repository)),
      ).toEqual([]);
    },
  );

  test("binding-derived candidates survive dense unrelated scp calls", async () => {
    const decoys = Array.from(
      { length: 80 },
      (_, index) => `    worker${index}.scp(source, destination)`,
    );
    const repository = await writeRepository({
      "app.py": [
        "import asyncssh",
        "async def fetch(conn, source, destination):",
        ...decoys,
        '    return await asyncssh.scp((conn, "release.tar"), "downloads")',
      ].join("\n"),
    });

    const records = asyncSshRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.line).toBe(83);
  });

  test("host re-audit requires the complete SCP traversal boundary in both report fields", async () => {
    const repository = await writeRepository({
      "src/downloader.py": moduleDownload(),
    });
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-asyncssh-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding = {
      occurrenceId: "occ_asyncssh_quality",
      taxonomy: { cwe: ["CWE-22"] },
      locations: [{ path: "src/downloader.py", startLine: 4, role: "sink" }],
      codeEvidence: [
        {
          id: "scp-sink",
          path: "src/downloader.py",
          startLine: 4,
          code: '    return await asyncssh.scp((conn, "release.tar"), Path("downloads"))',
          explanation:
            "A remote SCP source is downloaded to a local directory.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Static review confirms an SCP download.",
        method: "static topology trace and bounded loopback witness",
        exploitWitness: "A fixed inert marker stays inside a disposable root.",
        negativeControl: "The repaired package rejects the filename.",
        evidence: ["scp-sink"],
        counterEvidence: "No persistent target is used.",
        remainingUncertainty:
          "Deployment target and privileges remain unknown.",
      },
      attackPath: {
        summary: "A remote SCP response reaches a local file write.",
        dataflow: {
          source: "scp-sink",
          sink: "scp-sink",
          outcome: "outside-target marker write",
        },
        reachability: {
          attacker: "Malicious or compromised SSH server",
          entrypoint: "SCP download",
          outcome: "Local file integrity can be affected",
        },
        brokenControls: ["Affected filename parsing"],
        evidenceRefs: ["scp-sink"],
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
      findingId: "occ_asyncssh_quality",
      frameworkModelId: "python-asyncssh-scp-download-path-traversal",
      reasons: [
        "missing_model_specific_validation_evidence",
        "missing_model_specific_attack_path_evidence",
      ],
    });
    expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
      "_parse_cd_args",
      "unsanitized filename",
    ]);
    expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
      "asyncssh 2.23.1",
      "Invalid filename",
      "repaired control",
    ]);

    const semanticContract = [
      "GHSA-2wxc-x7rj-hg8f and CVE-2026-54591 affect the official asyncssh.scp binding.",
      "An SSHClientConnection remote source tuple supplies a remote SCP source to a local destination download directory and destination root.",
      "The exact asyncssh==2.23.0 pin sends scp -f and lets the server-controlled C filename or D directory select a name.",
      "_parse_cd_args accepts the unsanitized filename before posixpath.join reaches _recv_file and open wb for the local file write.",
      "On Python 3.12.3 a temporary directory witness creates an escaped marker outside target but inside the disposable root.",
      "The asyncssh 2.23.1 repaired control raises Invalid filename.",
      "SFTP is preferred because residual SCP overwrite risk remains within the target directory.",
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

  test("requires exact topology, safe witness, repaired control, and residual-risk evidence in the quality prompt", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "gap-row");

    expect(prompt).toContain(
      "For python-asyncssh-scp-download-path-traversal rows",
    );
    expect(prompt).toContain("GHSA-2wxc-x7rj-hg8f / CVE-2026-54591");
    expect(prompt).toContain(
      "_parse_cd_args accepted those names verbatim, _recv_files used posixpath.join",
    );
    expect(prompt).toContain("automatically removed temporary root");
    expect(prompt).toContain("Recommend SFTP");
    expect(prompt).toContain("Report CWE-22");
  });
});
