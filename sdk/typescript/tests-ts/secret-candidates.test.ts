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
import { join } from "node:path";
import { ConfigurationError } from "../src/errors.js";
import {
  buildSecretCandidateInventory,
  prepareSecretScanning,
  readSecretBaseline,
  SecretScanningError,
  type SecretCandidateRecord,
} from "../src/secret-candidates.js";

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryScanner(): Promise<{
  repository: string;
  credentialHome: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-secrets-"));
  temporaryPaths.push(root);
  const repository = join(root, "repository");
  const credentialHome = join(root, "copilot-security-home");
  await mkdir(repository, { recursive: true });
  await mkdir(credentialHome, { recursive: true });
  return { repository, credentialHome };
}

function candidateRows(inventory: string): SecretCandidateRecord[] {
  return inventory
    .split("\n")
    .slice(1)
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as SecretCandidateRecord);
}

describe("local secret candidates", () => {
  test("detects typed and generic credentials without persisting or prompting secret bytes", async () => {
    const { repository, credentialHome } = await temporaryScanner();
    const values = {
      github: `ghp_${"A1b2".repeat(9)}`,
      gitlab: `glpat-${"C3d4".repeat(6)}`,
      stripe: `sk_live_${"E5f6".repeat(6)}`,
      generic: ["v9Px7Qm2", "Lk8Nz4Rt", "6Wy1Bc5D"].join(""),
    };
    await writeFile(
      join(repository, ".env.production"),
      [
        `GITHUB_TOKEN=${values.github}`,
        `GITLAB_TOKEN=${values.gitlab}`,
        `STRIPE_SECRET=${values.stripe}`,
        `CLIENT_SECRET=${values.generic}`,
        "",
      ].join("\n"),
    );
    const prepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
    });

    const result = await buildSecretCandidateInventory(
      repository,
      prepared,
      "scan-typed",
      new Date("2026-08-03T12:00:00.000Z"),
    );
    const rows = candidateRows(result.inventory);

    expect(result.truncated).toBe(false);
    expect(rows.map((row) => row.ruleId)).toEqual([
      "github-token",
      "gitlab-token",
      "stripe-live-secret-key",
      "generic-high-entropy-secret",
    ]);
    expect({ line: rows[0]?.line, column: rows[0]?.column }).toEqual({
      line: 1,
      column: 14,
    });
    expect(rows.every((row) => row.path === ".env.production")).toBe(true);
    expect(
      rows.every((row) => row.shape.redacted.startsWith("[redacted:")),
    ).toBe(true);
    expect(
      rows.every((row) => row.fingerprint.startsWith("hmac-sha256:")),
    ).toBe(true);
    const report = await readFile(result.reportPath, "utf8");
    for (const value of Object.values(values)) {
      expect(result.inventory).not.toContain(value);
      expect(report).not.toContain(value);
    }
  });

  test("uses stable line-independent fingerprints scoped to repository and local key", async () => {
    const { repository, credentialHome } = await temporaryScanner();
    const secret = ["P7yQ9mR2", "vK4nT6xW", "8zB3cD5f"].join("");
    await writeFile(join(repository, "config.ini"), `password="${secret}"\n`);
    const prepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
    });
    const first = candidateRows(
      (await buildSecretCandidateInventory(repository, prepared, "scan-first"))
        .inventory,
    )[0];
    await writeFile(
      join(repository, "config.ini"),
      `# line moved\n\npassword="${secret}"\n`,
    );
    const moved = candidateRows(
      (await buildSecretCandidateInventory(repository, prepared, "scan-moved"))
        .inventory,
    )[0];
    const other = await temporaryScanner();
    await writeFile(
      join(other.repository, "config.ini"),
      `password="${secret}"\n`,
    );
    const otherPrepared = await prepareSecretScanning({
      credentialHome: other.credentialHome,
      repositoryScope: other.repository,
    });
    const differentlyScoped = candidateRows(
      (
        await buildSecretCandidateInventory(
          other.repository,
          otherPrepared,
          "scan-other",
        )
      ).inventory,
    )[0];

    expect(first?.line).toBe(1);
    expect(moved?.line).toBe(3);
    expect(moved?.fingerprint).toBe(first?.fingerprint);
    expect(differentlyScoped?.fingerprint).not.toBe(first?.fingerprint);
  });

  test("suppresses only exact justified unexpired baseline entries and reactivates expiry", async () => {
    const { repository, credentialHome } = await temporaryScanner();
    const value = ["M8rT2vW7", "xY4zB9cD", "5fG6hJ3k"].join("");
    await writeFile(
      join(repository, "settings.yaml"),
      `client_secret: "${value}"\n`,
    );
    const initial = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
    });
    const first = candidateRows(
      (
        await buildSecretCandidateInventory(
          repository,
          initial,
          "scan-before-baseline",
        )
      ).inventory,
    )[0];
    expect(first).toBeDefined();
    const baselinePath = join(credentialHome, "approved-baseline.json");
    const justification =
      "Synthetic integration credential used by an isolated fixture.";
    await writeFile(
      baselinePath,
      `${JSON.stringify(
        {
          schemaVersion: "1.0",
          entries: [
            {
              fingerprint: first?.fingerprint,
              ruleId: first?.ruleId,
              path: first?.path,
              justification,
              expiresAt: "2026-09-01T00:00:00.000Z",
            },
          ],
        },
        null,
        2,
      )}\n`,
    );
    const prepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
      baselinePath,
    });
    const suppressed = await buildSecretCandidateInventory(
      repository,
      prepared,
      "scan-suppressed",
      new Date("2026-08-03T00:00:00.000Z"),
    );
    const expired = await buildSecretCandidateInventory(
      repository,
      prepared,
      "scan-expired",
      new Date("2026-10-01T00:00:00.000Z"),
    );

    expect(suppressed.activeCount).toBe(0);
    expect(suppressed.suppressedCount).toBe(1);
    expect(candidateRows(suppressed.inventory)).toEqual([]);
    expect(await readFile(suppressed.reportPath, "utf8")).not.toContain(
      justification,
    );
    expect(expired.activeCount).toBe(1);
    expect(expired.expiredBaselineCount).toBe(1);
    expect(candidateRows(expired.inventory)[0]?.disposition).toBe("active");

    const unsafeBaselinePath = join(credentialHome, "unsafe-baseline.json");
    await writeFile(
      unsafeBaselinePath,
      JSON.stringify({
        schemaVersion: "1.0",
        entries: [
          {
            fingerprint: first?.fingerprint,
            ruleId: first?.ruleId,
            path: first?.path,
            justification: `Never copy candidate bytes ${value}`,
            expiresAt: "2026-09-01T00:00:00.000Z",
          },
        ],
      }),
    );
    const unsafePrepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
      baselinePath: unsafeBaselinePath,
    });
    await expect(
      buildSecretCandidateInventory(
        repository,
        unsafePrepared,
        "scan-unsafe-baseline",
        new Date("2026-08-03T00:00:00.000Z"),
      ),
    ).rejects.toThrow("justification contains candidate bytes");
  });

  test("rejects malformed and linked baselines before scanning", async () => {
    const { repository, credentialHome } = await temporaryScanner();
    const malformed = join(credentialHome, "malformed.json");
    await writeFile(
      malformed,
      JSON.stringify({
        schemaVersion: "1.0",
        entries: [
          {
            fingerprint: `hmac-sha256:${"a".repeat(64)}`,
            ruleId: "generic-high-entropy-secret",
            path: "config.json",
            justification: "short",
            expiresAt: "tomorrow",
          },
        ],
      }),
    );
    await expect(readSecretBaseline(malformed)).rejects.toBeInstanceOf(
      ConfigurationError,
    );

    const excessive = join(credentialHome, "excessive.json");
    await writeFile(
      excessive,
      JSON.stringify({
        schemaVersion: "1.0",
        entries: Array.from({ length: 10_001 }, () => ({})),
      }),
    );
    await expect(readSecretBaseline(excessive)).rejects.toThrow(
      "more than 10000 entries",
    );

    const valid = join(credentialHome, "valid.json");
    const linked = join(credentialHome, "linked.json");
    await writeFile(valid, '{"schemaVersion":"1.0","entries":[]}\n');
    try {
      await symlink(valid, linked, "file");
      await expect(readSecretBaseline(linked)).rejects.toBeInstanceOf(
        ConfigurationError,
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EPERM") throw error;
    }
    expect(repository).not.toBe(credentialHome);
  });

  test("rejects traversal baselines, invalid key state, and linked scanner state", async () => {
    const { repository, credentialHome } = await temporaryScanner();
    const traversal = join(credentialHome, "traversal.json");
    await writeFile(
      traversal,
      JSON.stringify({
        schemaVersion: "1.0",
        entries: [
          {
            fingerprint: `hmac-sha256:${"b".repeat(64)}`,
            ruleId: "github-token",
            path: "src/../outside.env",
            justification: "This deliberately invalid path must fail closed.",
            expiresAt: "2026-09-01T00:00:00.000Z",
          },
        ],
      }),
    );
    await expect(readSecretBaseline(traversal)).rejects.toBeInstanceOf(
      ConfigurationError,
    );

    const prepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
    });
    await writeFile(
      join(credentialHome, "secret-scanner", "fingerprint.key"),
      "too-short",
    );
    await expect(
      prepareSecretScanning({ credentialHome, repositoryScope: repository }),
    ).rejects.toThrow("fingerprint key is unsafe or invalid");
    expect(prepared.fingerprintKey.byteLength).toBe(32);

    const linkedHome = join(
      await mkdtemp(join(tmpdir(), "copilot-security-linked-home-")),
      "copilot-security-home",
    );
    temporaryPaths.push(join(linkedHome, ".."));
    await mkdir(linkedHome, { recursive: true });
    const outside = await mkdtemp(join(tmpdir(), "copilot-security-outside-"));
    temporaryPaths.push(outside);
    try {
      await symlink(outside, join(linkedHome, "secret-scanner"), "dir");
      await expect(
        prepareSecretScanning({
          credentialHome: linkedHome,
          repositoryScope: repository,
        }),
      ).rejects.toBeInstanceOf(SecretScanningError);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EPERM") throw error;
    }
  });

  test("honors immutable target paths and ignores placeholders, generated trees, and binary files", async () => {
    const { repository, credentialHome } = await temporaryScanner();
    await mkdir(join(repository, "node_modules", "package"), {
      recursive: true,
    });
    const includedValue = ["Q8wE2rT7", "yU4iO9pA", "5sD6fG3h"].join("");
    const excludedValue = ["Z9xC3vB8", "nM5aS1dF", "7gH4jK6l"].join("");
    await writeFile(
      join(repository, "included.env"),
      `token="${includedValue}"\n`,
    );
    await writeFile(
      join(repository, "excluded.env"),
      `token="${excludedValue}"\n`,
    );
    await writeFile(
      join(repository, "placeholder.env"),
      'token="example-placeholder-token"\n',
    );
    await writeFile(
      join(repository, "environment-reference.env"),
      [
        'token="COPILOT_GITHUB_TOKEN"',
        'client_secret="AZURE_CLIENT_SECRET"',
        'api_key="SERVICE_SIGNING_KEY"',
      ].join("\n"),
    );
    await writeFile(
      join(repository, "node_modules", "package", "secret.env"),
      `token="${["R4tY8uI2", "oP6aS9dF", "3gH7jK5l"].join("")}"\n`,
    );
    await writeFile(
      join(repository, "binary.dat"),
      Buffer.from(`token="${["V5bN9mQ3", "wE7rT2yU", "6iO4pA8s"].join("")}"\0`),
    );
    await writeFile(
      join(repository, "runtime.ts"),
      "const token = runtimeCredentialValue;\n",
    );
    const prepared = await prepareSecretScanning({
      credentialHome,
      repositoryScope: repository,
    });
    const scoped = await buildSecretCandidateInventory(
      repository,
      prepared,
      "scan-scoped",
      new Date(),
      ["included.env", "../escape.env", "missing.env"],
    );
    const broad = await buildSecretCandidateInventory(
      repository,
      prepared,
      "scan-broad",
    );

    expect(candidateRows(scoped.inventory).map((row) => row.path)).toEqual([
      "included.env",
    ]);
    expect(candidateRows(broad.inventory).map((row) => row.path)).toEqual([
      "excluded.env",
      "included.env",
    ]);
  });
});
