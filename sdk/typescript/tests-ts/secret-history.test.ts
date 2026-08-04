import { afterEach, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  buildSecretCandidateInventory,
  MAX_SECRET_HISTORY_DEPTH,
  prepareSecretScanning,
  SecretScanningError,
  secretHistoryDepth,
  type SecretCandidateRecord,
} from "../src/secret-candidates.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function git(repository: string, ...args: string[]): void {
  execFileSync("git", ["-C", repository, ...args], {
    stdio: "ignore",
    timeout: 15_000,
  });
}

function inventoryRows(inventory: string): SecretCandidateRecord[] {
  return inventory
    .split("\n")
    .slice(1)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as SecretCandidateRecord);
}

async function historyRepository(): Promise<{
  repository: string;
  credentialHome: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-history-test-"));
  temporaryPaths.push(root);
  const repository = join(root, "repository");
  const credentialHome = join(root, "copilot-security-home");
  await mkdir(repository);
  await mkdir(credentialHome);
  git(repository, "init", "-q");
  git(repository, "config", "user.name", "History Test");
  git(repository, "config", "user.email", "history@example.invalid");
  return { repository, credentialHome };
}

describe("local reachable Git secret history", () => {
  test("honors the commit horizon and immutable path scope", async () => {
    const { repository, credentialHome } = await historyRepository();
    const selected = ["ghp_", "N7qR2mV9xK4sD8fH3jL6cB5wT1yU0aP2eZ7Q"].join("");
    const excluded = ["glpat-", "C8vB3nM6qW2rT9yK5dF7sP4x"].join("");
    for (const [path, value] of [
      ["selected/retired.env", selected],
      ["excluded/retired.env", excluded],
    ] as const) {
      const absolute = join(repository, path);
      await mkdir(dirname(absolute), { recursive: true });
      await writeFile(absolute, `token="${value}"\n`);
    }
    git(repository, "add", "--all");
    git(repository, "commit", "-q", "-m", "add credentials");
    await unlink(join(repository, "selected/retired.env"));
    await unlink(join(repository, "excluded/retired.env"));
    await writeFile(join(repository, "README.md"), "Current tree is clean.\n");
    git(repository, "add", "--all");
    git(repository, "commit", "-q", "-m", "remove credentials");

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
    const shallow = await buildSecretCandidateInventory(
      repository,
      prepared,
      "history-depth-one",
      new Date(),
      undefined,
      { depth: 1, git: trustedGit },
    );
    expect(inventoryRows(shallow.inventory)).toHaveLength(0);
    expect(shallow.history.requestedDepth).toBe(1);
    expect(shallow.history.status).toBe("complete");

    const scoped = await buildSecretCandidateInventory(
      repository,
      prepared,
      "history-scoped",
      new Date(),
      ["selected/retired.env"],
      { depth: 8, git: trustedGit },
    );
    const candidates = inventoryRows(scoped.inventory);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.path).toBe("selected/retired.env");
    expect(candidates[0]?.source).toBe("git_history");
    expect(scoped.inventory).not.toContain(selected);
    expect(scoped.inventory).not.toContain(excluded);
  });

  test("distinguishes disabled, non-Git, and unavailable history without guessing completion", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-security-no-history-"));
    temporaryPaths.push(root);
    const repository = join(root, "repository");
    const credentialHome = join(root, "copilot-security-home");
    await mkdir(repository);
    await mkdir(credentialHome);
    await writeFile(join(repository, "README.md"), "No Git metadata.\n");
    const prepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
    });

    const disabled = await buildSecretCandidateInventory(
      repository,
      prepared,
      "history-disabled",
      new Date(),
      undefined,
      { depth: 0, git: null },
    );
    expect(disabled.history.status).toBe("disabled");
    expect(disabled.truncated).toBe(false);

    const noRepository = await buildSecretCandidateInventory(
      repository,
      prepared,
      "history-not-git",
      new Date(),
      undefined,
      { depth: 8, git: null },
    );
    expect(noRepository.history.status).toBe("not_git_repository");
    expect(noRepository.truncated).toBe(false);

    git(repository, "init", "-q");
    const unavailable = await buildSecretCandidateInventory(
      repository,
      prepared,
      "history-unavailable",
      new Date(),
      undefined,
      { depth: 8, git: null },
    );
    expect(unavailable.history.status).toBe("unavailable");
    expect(unavailable.history.truncated).toBe(true);
    expect(unavailable.truncated).toBe(true);
  });

  test("rejects invalid history bounds before running Git", () => {
    expect(secretHistoryDepth(undefined)).toBe(128);
    expect(secretHistoryDepth(0)).toBe(0);
    expect(secretHistoryDepth(MAX_SECRET_HISTORY_DEPTH)).toBe(
      MAX_SECRET_HISTORY_DEPTH,
    );
    expect(() => secretHistoryDepth(-1)).toThrow(SecretScanningError);
    expect(() => secretHistoryDepth(MAX_SECRET_HISTORY_DEPTH + 1)).toThrow(
      SecretScanningError,
    );
    expect(() => secretHistoryDepth(1.5)).toThrow(SecretScanningError);
  });
});
