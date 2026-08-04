import { afterEach, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  buildSecretCandidateInventory,
  prepareSecretScanning,
  type SecretCandidateRecord,
} from "../src/secret-candidates.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";

interface HistoryManifestCase {
  id: string;
  path: string;
  expected: "candidate" | "no_candidate";
  ruleId?: string;
  prefix: string;
  fragments: string[];
  suffix: string;
  minimumHistoryObjects?: number;
}

interface HistoryManifest {
  schemaVersion: "1.0";
  thresholds: {
    precision: number;
    recall: number;
    falsePositives: number;
    falseNegatives: number;
  };
  cases: HistoryManifestCase[];
}

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function git(repository: string, ...args: string[]): string {
  return execFileSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
    timeout: 15_000,
  }).trim();
}

function rows(inventory: string): SecretCandidateRecord[] {
  return inventory
    .split("\n")
    .slice(1)
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as SecretCandidateRecord);
}

describe("reachable Git secret-history benchmark", () => {
  test("finds deleted credentials, rejects controls, and deduplicates revisions without leaking values", async () => {
    const manifest = JSON.parse(
      await readFile(
        resolve("../../benchmarks/secret-history-manifest.json"),
        "utf8",
      ),
    ) as HistoryManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    const root = await mkdtemp(join(tmpdir(), "copilot-security-history-"));
    temporaryPaths.push(root);
    const repository = join(root, "repository");
    const credentialHome = join(root, "copilot-security-home");
    await mkdir(repository);
    await mkdir(credentialHome);
    git(repository, "init", "-q");
    git(repository, "config", "user.name", "History Benchmark");
    git(repository, "config", "user.email", "history@example.invalid");

    const materialized = new Map<string, string>();
    for (const fixture of manifest.cases) {
      const value = fixture.fragments.join("");
      materialized.set(fixture.id, value);
      const path = join(repository, fixture.path);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, `${fixture.prefix}${value}${fixture.suffix}`);
    }
    git(repository, "add", "--all");
    git(repository, "commit", "-q", "-m", "materialize history corpus");

    const duplicate = manifest.cases.find(
      (fixture) => fixture.minimumHistoryObjects !== undefined,
    );
    if (duplicate === undefined) throw new Error("Missing deduplication case.");
    await writeFile(
      join(repository, duplicate.path),
      `${duplicate.prefix}${materialized.get(duplicate.id)}${duplicate.suffix}# same credential in a new blob\n`,
    );
    git(repository, "add", "--all");
    git(repository, "commit", "-q", "-m", "retain credential in new blob");

    for (const fixture of manifest.cases) {
      await unlink(join(repository, fixture.path));
    }
    await writeFile(join(repository, "README.md"), "History corpus cleaned.\n");
    git(repository, "add", "--all");
    git(repository, "commit", "-q", "-m", "remove historical credentials");

    const trustedGit = await resolveTrustedExecutable(
      "git",
      process.env,
      repository,
    );
    expect(trustedGit).not.toBeNull();
    const prepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
    });
    const result = await buildSecretCandidateInventory(
      repository,
      prepared,
      "history-benchmark",
      new Date("2026-08-03T12:00:00.000Z"),
      undefined,
      { depth: 16, git: trustedGit },
    );
    const candidates = rows(result.inventory);
    const positives = manifest.cases.filter(
      (fixture) => fixture.expected === "candidate",
    );
    const negatives = manifest.cases.filter(
      (fixture) => fixture.expected === "no_candidate",
    );
    const truePositives = positives.filter((fixture) =>
      candidates.some(
        (candidate) =>
          candidate.path === fixture.path &&
          candidate.ruleId === fixture.ruleId &&
          candidate.source === "git_history",
      ),
    ).length;
    const falseNegatives = positives.length - truePositives;
    const falsePositives = negatives.filter((fixture) =>
      candidates.some((candidate) => candidate.path === fixture.path),
    ).length;
    const precision =
      truePositives / Math.max(1, truePositives + falsePositives);
    const recall = truePositives / Math.max(1, positives.length);

    expect(precision).toBeGreaterThanOrEqual(manifest.thresholds.precision);
    expect(recall).toBeGreaterThanOrEqual(manifest.thresholds.recall);
    expect(falsePositives).toBe(manifest.thresholds.falsePositives);
    expect(falseNegatives).toBe(manifest.thresholds.falseNegatives);
    expect(result.history.status).toBe("complete");
    expect(result.history.truncated).toBe(false);
    expect(result.history.requestedDepth).toBe(16);
    expect(result.scannedFileCount).toBe(1);
    expect(candidates).toHaveLength(positives.length);
    for (const candidate of candidates) {
      expect(candidate.history?.objectIds.length).toBeGreaterThan(0);
      expect(candidate.history?.objectIdsTruncated).toBe(false);
    }
    const deduplicated = candidates.find(
      (candidate) => candidate.path === duplicate.path,
    );
    expect(deduplicated?.history?.objectCount).toBeGreaterThanOrEqual(
      duplicate.minimumHistoryObjects ?? 2,
    );
    expect(
      [...materialized.values()].some((value) =>
        result.inventory.includes(value),
      ),
    ).toBe(false);
    const report = await readFile(result.reportPath, "utf8");
    expect(
      [...materialized.values()].some((value) => report.includes(value)),
    ).toBe(false);
  }, 45_000);
});
