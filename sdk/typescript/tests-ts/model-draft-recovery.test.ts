import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { normalizeMalformedScanDrafts } from "../src/model-draft-recovery.js";

const validDrafts = {
  "scan-manifest.json": { documentType: "copilot-security.scan-manifest" },
  "findings.json": { documentType: "copilot-security.findings", findings: [] },
  "coverage.json": { documentType: "copilot-security.coverage", surfaces: [] },
} as const;

describe("model draft notation recovery", () => {
  test("does not rewrite already-valid JSON", async () => {
    const directory = await draftDirectory();
    const before = await Promise.all(
      Object.keys(validDrafts).map((name) =>
        readFile(join(directory, name), "utf8"),
      ),
    );

    expect(await normalizeMalformedScanDrafts(directory)).toEqual([]);
    const after = await Promise.all(
      Object.keys(validDrafts).map((name) =>
        readFile(join(directory, name), "utf8"),
      ),
    );
    expect(after).toEqual(before);
  });

  test("recovers bounded flow-style drafts without evaluating their data", async () => {
    const directory = await draftDirectory();
    await writeFile(
      join(directory, "scan-manifest.json"),
      "{ documentType: copilot-security.scan-manifest, scan: { status: completed } }\n",
    );
    await writeFile(
      join(directory, "findings.json"),
      [
        "{ documentType: copilot-security.findings, findings: [",
        "{ title: Untrusted URL reaches HttpClient, codeEvidence: [",
        "{ id: ev-sink, code: [HttpGet] public async Task<IActionResult> Get([FromQuery] string target, CancellationToken cancellationToken) { return Ok(await FetchAsync(target, cancellationToken)); }, explanation: Complete source and sink trace. }",
        "] } ] }",
      ].join("\n"),
    );
    await writeFile(
      join(directory, "coverage.json"),
      "{ documentType: copilot-security.coverage, completeness: complete, surfaces: [Controllers/PreviewController.cs, Services/PreviewClient.cs] }\n",
    );

    expect(await normalizeMalformedScanDrafts(directory)).toEqual([
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
    ]);
    const findings = JSON.parse(
      await readFile(join(directory, "findings.json"), "utf8"),
    ) as { findings: Array<{ codeEvidence: Array<{ code: string }> }> };
    expect(findings.findings[0]!.codeEvidence[0]!.code).toContain(
      "[HttpGet] public async Task<IActionResult>",
    );
    expect(
      JSON.parse(await readFile(join(directory, "coverage.json"), "utf8")),
    ).toMatchObject({ completeness: "complete" });
  });

  test("recovers compact keys and comma-bearing prose without inventing fields", async () => {
    const directory = await draftDirectory();
    await writeFile(
      join(directory, "scan-manifest.json"),
      [
        "{documentType:copilot-security.scan-manifest, schemaVersion:1.0, scan:{",
        "status:completed, threatModel:{summary:Prevent SSRF, redirects, and response disclosure., assets:[Internal network]},",
        "coverageRef:coverage.json, findingsRef:findings.json}}",
      ].join("\n"),
    );

    expect(await normalizeMalformedScanDrafts(directory)).toEqual([
      "scan-manifest.json",
    ]);
    const manifest = JSON.parse(
      await readFile(join(directory, "scan-manifest.json"), "utf8"),
    ) as {
      documentType: string;
      scan: { threatModel: Record<string, unknown> };
    };
    expect(manifest.documentType).toBe("copilot-security.scan-manifest");
    expect(manifest.scan.threatModel).toEqual({
      summary: "Prevent SSRF, redirects, and response disclosure.",
      assets: ["Internal network"],
    });
  });

  test("fails closed and leaves every draft untouched when one draft is ambiguous", async () => {
    const directory = await draftDirectory();
    const manifestPath = join(directory, "scan-manifest.json");
    const findingsPath = join(directory, "findings.json");
    await writeFile(
      manifestPath,
      "{ documentType: copilot-security.scan-manifest }\n",
    );
    await writeFile(findingsPath, "{ duplicate: first, duplicate: second }\n");
    const beforeManifest = await readFile(manifestPath, "utf8");

    await expect(normalizeMalformedScanDrafts(directory)).rejects.toThrow(
      "bounded host normalization could not parse",
    );
    expect(await readFile(manifestPath, "utf8")).toBe(beforeManifest);
  });

  test("rejects aliases, non-object roots, empty files, and symlinks", async () => {
    const aliasDirectory = await draftDirectory();
    await writeFile(
      join(aliasDirectory, "coverage.json"),
      "{ first: &shared [one], second: *shared }\n",
    );
    await expect(
      normalizeMalformedScanDrafts(aliasDirectory),
    ).rejects.toThrow();

    const arrayDirectory = await draftDirectory();
    await writeFile(join(arrayDirectory, "coverage.json"), "[one, two]\n");
    await expect(normalizeMalformedScanDrafts(arrayDirectory)).rejects.toThrow(
      "non-object document root",
    );

    const emptyDirectory = await draftDirectory();
    await writeFile(join(emptyDirectory, "coverage.json"), "");
    await expect(normalizeMalformedScanDrafts(emptyDirectory)).rejects.toThrow(
      "regular, non-empty coverage.json",
    );

    if (process.platform !== "win32") {
      const symlinkDirectory = await draftDirectory();
      const external = join(await temporaryDirectory(), "external.json");
      await writeFile(external, "{}\n");
      const coveragePath = join(symlinkDirectory, "coverage.json");
      await writeFile(coveragePath, "unused");
      await lstat(coveragePath);
      await rm(coveragePath);
      await symlink(external, coveragePath);
      await expect(
        normalizeMalformedScanDrafts(symlinkDirectory),
      ).rejects.toThrow("regular, non-empty coverage.json");
    }
  });
});

async function draftDirectory(): Promise<string> {
  const directory = join(await temporaryDirectory(), "scan");
  await mkdir(directory);
  for (const [name, document] of Object.entries(validDrafts)) {
    await writeFile(join(directory, name), `${JSON.stringify(document)}\n`);
  }
  return directory;
}

async function temporaryDirectory(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "copilot-security-model-draft-"));
}
