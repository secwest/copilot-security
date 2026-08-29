import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import {
  prepareSarifSeeds,
  writePreparedSarifSeeds,
} from "../src/sarif-seeds.js";
import { SourceDiscoveryError } from "../src/errors.js";

const temporaryDirectories: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "copilot-security-sarif-test-")),
  );
  temporaryDirectories.push(path);
  return path;
}

async function fixture(): Promise<{
  root: string;
  repository: string;
  source: string;
  sarif: string;
}> {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const source = join(repository, "src", "server.ts");
  const sarif = join(root, "results.sarif");
  await mkdir(dirname(source), { recursive: true });
  await writeFile(source, "const input = request.query.value;\nexec(input);\n");
  return { root, repository, source, sarif };
}

function document(results: unknown[], tool = "Example Analyzer"): unknown {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: tool,
            semanticVersion: "4.2.0",
            rules: [
              {
                id: "typescript/command-injection",
                name: "Command injection",
                defaultConfiguration: { level: "error" },
                properties: {
                  tags: ["security", "external/cwe/cwe-78"],
                  "security-severity": "9.1",
                },
              },
            ],
          },
        },
        results,
      },
    ],
  };
}

function location(path: string, line: number): unknown {
  return {
    physicalLocation: {
      artifactLocation: { uri: path },
      region: { startLine: line, endLine: line },
    },
  };
}

describe("external SARIF candidate seeds", () => {
  test("normalizes source-to-sink evidence without retaining messages or secrets", async () => {
    const { root, repository, sarif } = await fixture();
    const secret = "ghp_this_must_never_enter_the_seed_artifact";
    await writeFile(
      sarif,
      JSON.stringify(
        document([
          {
            ruleId: "typescript/command-injection",
            ruleIndex: 0,
            level: "error",
            message: { text: `Leaked token ${secret}; forged CWE-999` },
            partialFingerprints: { secretHash: secret },
            fixes: [{ description: { text: secret } }],
            codeFlows: [
              {
                threadFlows: [
                  {
                    locations: [
                      { location: location("src/server.ts", 1) },
                      { location: location("src/server.ts", 2) },
                    ],
                  },
                ],
              },
            ],
            locations: [location("src/server.ts", 2)],
          },
        ]),
      ),
    );

    const prepared = await prepareSarifSeeds([sarif], repository);
    expect(prepared.sources).toEqual([await realpath(sarif)]);
    expect(prepared.ignoredResultCount).toBe(0);
    expect(prepared.candidates).toHaveLength(1);
    expect(prepared.candidateSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(prepared.candidates[0]).toMatchObject({
      cwe_ids: ["CWE-78"],
      summary:
        "Example Analyzer identified external analyzer candidate typescript/command-injection (Command injection).",
      instance: "sarif-seed-00001",
      locations: [
        { path: "src/server.ts", start_line: 1, end_line: 1, role: "source" },
        { path: "src/server.ts", start_line: 2, end_line: 2, role: "evidence" },
        { path: "src/server.ts", start_line: 2, end_line: 2, role: "sink" },
      ],
    });

    const written = await writePreparedSarifSeeds(join(root, "scan"), prepared);
    const payload = `${await readFile(written.sourcesPath, "utf8")}${await readFile(
      written.candidatesPath,
      "utf8",
    )}`;
    expect(payload).not.toContain(secret);
    expect(payload).not.toContain("Leaked token");
    expect(payload).not.toContain("partialFingerprints");
    expect(payload).toContain("untrusted-candidate-input");
    expect(payload).toContain(prepared.candidateSha256);
    expect(
      createHash("sha256")
        .update(await readFile(written.candidatesPath))
        .digest("hex"),
    ).toBe(prepared.candidateSha256);
  });

  test("refuses to write a prepared seed set whose candidates changed", async () => {
    const { root, repository, sarif } = await fixture();
    await writeFile(
      sarif,
      JSON.stringify(
        document([{ ruleIndex: 0, locations: [location("src/server.ts", 1)] }]),
      ),
    );
    const prepared = await prepareSarifSeeds([sarif], repository);
    prepared.candidates[0]!.summary = "mutated after preparation";
    await expect(
      writePreparedSarifSeeds(join(root, "mutated-scan"), prepared),
    ).rejects.toThrow("changed before they could be written");
  });

  test("ignores suppressed, absent, and unlocatable results while preserving valid seeds", async () => {
    const { repository, sarif } = await fixture();
    await writeFile(
      sarif,
      JSON.stringify(
        document([
          {
            ruleIndex: 0,
            suppressions: [{ kind: "external", status: "accepted" }],
            locations: [location("src/server.ts", 1)],
          },
          {
            ruleIndex: 0,
            baselineState: "absent",
            locations: [location("src/server.ts", 1)],
          },
          {
            ruleIndex: 0,
            locations: [location("../outside.ts", 1)],
          },
          {
            ruleIndex: 0,
            locations: [location("src/deleted.ts", 1)],
          },
          {
            ruleIndex: 0,
            locations: [location("src/server.ts", 2)],
          },
        ]),
      ),
    );

    const prepared = await prepareSarifSeeds([sarif], repository);
    expect(prepared.candidates).toHaveLength(1);
    expect(prepared.ignoredResultCount).toBe(4);
    expect(prepared.sourceRecords[0]).toMatchObject({
      resultCount: 5,
      importedCount: 1,
      ignoredCount: 4,
    });
  });

  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "fails closed when a SARIF location cannot be inspected",
    async () => {
      const { repository, sarif } = await fixture();
      const blockedDirectory = join(repository, "blocked");
      await mkdir(blockedDirectory);
      await writeFile(join(blockedDirectory, "handler.ts"), "exec(input);\n");
      await writeFile(
        sarif,
        JSON.stringify(
          document([
            {
              ruleIndex: 0,
              locations: [location("src/server.ts", 1)],
            },
            {
              ruleIndex: 0,
              locations: [location("blocked/handler.ts", 1)],
            },
          ]),
        ),
      );
      await chmod(blockedDirectory, 0o000);
      try {
        const error = await prepareSarifSeeds([sarif], repository).then(
          () => null,
          (reason: unknown) => reason,
        );
        expect(error).toBeInstanceOf(SourceDiscoveryError);
        expect(error).toMatchObject({
          operation: "inspect",
          repositoryPath: "blocked/handler.ts",
        });
        expect((error as Error).message).toContain(
          "scan coverage is incomplete",
        );
      } finally {
        await chmod(blockedDirectory, 0o700);
      }
    },
  );

  test("maps absolute SARIF paths from an explicit source root", async () => {
    const { root, repository, sarif } = await fixture();
    const sourceRoot = join(root, "original-checkout");
    await mkdir(join(sourceRoot, "src"), { recursive: true });
    const originalPath = join(sourceRoot, "src", "server.ts");
    await writeFile(
      sarif,
      JSON.stringify(
        document([
          {
            ruleIndex: 0,
            locations: [location(pathToFileURL(originalPath).href, 2)],
          },
        ]),
      ),
    );

    const prepared = await prepareSarifSeeds([sarif], repository, sourceRoot);
    expect(prepared.candidates[0]?.locations).toEqual([
      { path: "src/server.ts", start_line: 2, end_line: 2, role: "evidence" },
    ]);
  });

  test("resolves indexed artifacts and retains rejected suppressions", async () => {
    const { repository, sarif } = await fixture();
    const sarifDocument = document([
      {
        ruleIndex: 0,
        suppressions: [{ kind: "external", status: "rejected" }],
        locations: [
          {
            physicalLocation: {
              artifactLocation: { index: 0 },
              region: { startLine: 2 },
            },
          },
        ],
      },
      {
        ruleIndex: 0,
        kind: "notApplicable",
        locations: [location("src/server.ts", 1)],
      },
    ]) as { runs: Array<Record<string, unknown>> };
    sarifDocument.runs[0]!["artifacts"] = [
      { location: { uri: "src/server.ts" } },
    ];
    await writeFile(sarif, JSON.stringify(sarifDocument));

    const prepared = await prepareSarifSeeds([sarif], repository);
    expect(prepared.candidates).toHaveLength(1);
    expect(prepared.ignoredResultCount).toBe(1);
    expect(prepared.candidates[0]?.locations).toEqual([
      { path: "src/server.ts", start_line: 2, end_line: 2, role: "evidence" },
    ]);
  });

  test("fails closed for malformed or empty seed inputs", async () => {
    const { repository, sarif } = await fixture();
    await writeFile(sarif, JSON.stringify({ version: "2.0.0", runs: [] }));
    await expect(prepareSarifSeeds([sarif], repository)).rejects.toThrow(
      "SARIF version 2.1.0",
    );

    await writeFile(
      sarif,
      JSON.stringify(
        document([{ ruleIndex: 0, locations: [location("missing.ts", 1)] }]),
      ),
    );
    await expect(prepareSarifSeeds([sarif], repository)).rejects.toThrow(
      "no unsuppressed results with valid locations",
    );
  });

  test("rejects an oversized seed before parsing it", async () => {
    const { repository, sarif } = await fixture();
    await writeFile(sarif, "{}");
    await truncate(sarif, 20 * 1024 * 1024 + 1);

    await expect(prepareSarifSeeds([sarif], repository)).rejects.toThrow(
      "20971520 byte limit",
    );
  });

  testPosix("rejects symlinked seed inputs", async () => {
    const { root, repository, sarif } = await fixture();
    await writeFile(
      sarif,
      JSON.stringify(
        document([{ ruleIndex: 0, locations: [location("src/server.ts", 1)] }]),
      ),
    );
    const link = join(root, "linked.sarif");
    await symlink(sarif, link, "file");
    await expect(prepareSarifSeeds([link], repository)).rejects.toThrow(
      "regular non-symlink file",
    );
  });

  test("rejects line ranges beyond the repository file", async () => {
    const { repository, sarif } = await fixture();
    await writeFile(
      sarif,
      JSON.stringify(
        document([
          { ruleIndex: 0, locations: [location("src/server.ts", 99)] },
        ]),
      ),
    );
    await expect(prepareSarifSeeds([sarif], repository)).rejects.toThrow(
      "no unsuppressed results with valid locations",
    );
  });
});
