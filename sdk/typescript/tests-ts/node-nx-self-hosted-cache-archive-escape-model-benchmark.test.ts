import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface NxCacheRecord {
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

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    expected: Array<{
      cwe?: string[];
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
      locations?: Array<{ startLine: number; endLine: number }>;
    }>;
  }>;
}

interface CaseOptions {
  activation?: string;
  additionalDevDependencies?: Record<string, string>;
  command?: string;
  declaration?: string;
  dependencySection?: "dependencies" | "devDependencies";
  lock?: boolean;
  lockedVersion?: string;
  lockfileVersion?: number;
  nxJson?: Record<string, unknown>;
  packageName?: string;
  rootLockDeclaration?: string;
  workflowPath?: string;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function nxCacheRecords(inventory: string): NxCacheRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as NxCacheRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-nx-self-hosted-cache-archive-escape",
    );
}

async function temporaryRepository(label: string): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), `copilot-security-nx-cache-${label}-`),
  );
  temporaryPaths.push(repository);
  return repository;
}

async function writeCase(
  repository: string,
  id: string,
  options: CaseOptions = {},
): Promise<string> {
  const root = join(repository, id);
  const packageName = options.packageName ?? "nx";
  const declaration = options.declaration ?? "22.7.6";
  const section = options.dependencySection ?? "devDependencies";
  const workflowPath =
    options.workflowPath ?? join(".github", "workflows", "ci.yml");
  const workflow = `name: cache build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ${options.activation ?? "NX_SELF_HOSTED_REMOTE_CACHE_SERVER: http://127.0.0.1:48721"}
    steps:
      - name: Build cached target
        run: ${options.command ?? "npx nx run app:build"}
`;
  await mkdir(join(root, workflowPath, ".."), { recursive: true });
  await writeFile(join(root, workflowPath), workflow);
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [section]: {
          [packageName]: declaration,
          ...(section === "devDependencies"
            ? options.additionalDevDependencies
            : {}),
        },
      },
      null,
      2,
    ),
  );
  if (options.nxJson !== undefined) {
    await writeFile(
      join(root, "nx.json"),
      JSON.stringify(options.nxJson, null, 2),
    );
  }
  if (options.lock === true) {
    const lockfileVersion = options.lockfileVersion ?? 3;
    await writeFile(
      join(root, "package-lock.json"),
      JSON.stringify(
        lockfileVersion === 1
          ? {
              name: id,
              lockfileVersion,
              dependencies: {
                [packageName]: {
                  version: options.lockedVersion ?? "22.7.6",
                },
              },
            }
          : {
              name: id,
              lockfileVersion,
              packages: {
                "": {
                  [section]: {
                    [packageName]: options.rootLockDeclaration ?? declaration,
                  },
                },
                [`node_modules/${packageName}`]: {
                  version: options.lockedVersion ?? "22.7.6",
                },
              },
            },
        null,
        2,
      ),
    );
  }
  return root;
}

describe("Nx self-hosted remote-cache archive escape model", () => {
  test("keeps a strict affected and repaired executable benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-nx-self-hosted-cache-archive-escape-manifest.json",
        ),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 1 || value === 0,
      ),
    ).toBe(true);
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-nx-self-hosted-cache-archive-escape",
      "node-nx-self-hosted-cache-archive-contained",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-22", "CWE-59"],
      acceptableSeverities: ["high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
      locations: [{ startLine: 10, endLine: 10 }],
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const affected = nxCacheRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-nx-self-hosted-cache-archive-escape",
        ),
      ),
    );
    const repaired = nxCacheRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-nx-self-hosted-cache-archive-contained",
        ),
      ),
    );
    expect(affected).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(affected[0]).toMatchObject({
      path: ".github/workflows/ci.yml",
      line: 10,
      frameworkModel: {
        id: "node-nx-self-hosted-cache-archive-escape",
        scope: "same-file",
        source: {
          kind: "nx-self-hosted-http-cache-configuration",
          path: ".github/workflows/ci.yml",
          line: 7,
        },
        sink: {
          kind: "vulnerable-nx-http-remote-cache-restore",
          path: ".github/workflows/ci.yml",
          line: 10,
          cweIds: ["CWE-22", "CWE-59"],
        },
      },
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "nx-self-hosted-http-cache-configuration",
      "nx-cache-consuming-task-execution",
      "nx-runtime-dependency",
    ]);
    expect(affected[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "nx@22.7.6:manifest-exact:unconfined-http-cache-tar-extraction",
    );
  });

  test("accepts build-time declarations and declaration-consistent modern locks", async () => {
    const repository = await temporaryRepository("provenance");
    const exact = await writeCase(repository, "exact-dev");
    const locked = await writeCase(repository, "locked-dev", {
      declaration: "^22.7.0",
      lock: true,
      lockedVersion: "22.7.6",
    });
    expect(
      nxCacheRecords(await buildResidualRiskInventory(exact)),
    ).toHaveLength(1);
    const lockedRecords = nxCacheRecords(
      await buildResidualRiskInventory(locked),
    );
    expect(lockedRecords).toHaveLength(1);
    expect(lockedRecords[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-nx-http-remote-cache-restore",
    );
    expect(lockedRecords[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "nx@22.7.6:npm-lockfile:unconfined-http-cache-tar-extraction",
    );
  });

  test("covers every affected stable built-in release window and common task commands", async () => {
    const repository = await temporaryRepository("versions-commands");
    const cases: Array<[string, string, string]> = [
      ["introduced", "20.8.0", "nx run app:build"],
      ["major-21", "21.6.5", "pnpm exec nx run-many -t build"],
      ["last-22", "22.7.6", "yarn nx affected -t test"],
      ["first-23", "23.0.0", "bunx nx build app"],
      ["last-23", "23.0.1", "npm exec nx run app:build"],
    ];
    for (const [id, declaration, command] of cases) {
      const root = await writeCase(repository, id, { declaration, command });
      expect(
        nxCacheRecords(await buildResidualRiskInventory(root)),
        id,
      ).toHaveLength(1);
    }
  });

  test("rejects fixed, pre-introduction, prerelease, wrong, stale, and unproved releases", async () => {
    const repository = await temporaryRepository("version-negatives");
    const cases: Array<[string, CaseOptions]> = [
      ["before-introduction", { declaration: "20.7.9" }],
      ["fixed-22", { declaration: "22.7.7" }],
      ["later-22", { declaration: "22.8.0" }],
      ["fixed-23", { declaration: "23.0.2" }],
      ["later-major", { declaration: "24.0.0" }],
      ["prerelease", { declaration: "22.7.6-beta.1" }],
      ["wrong-package", { packageName: "nx-fork" }],
      ["unproved-range", { declaration: "^22.7.0" }],
      [
        "fixed-lock",
        {
          declaration: "^22.7.0",
          lock: true,
          lockedVersion: "22.7.7",
        },
      ],
      [
        "inconsistent-lock",
        {
          declaration: "^22.7.0",
          lock: true,
          lockedVersion: "22.7.6",
          rootLockDeclaration: "~21.6.0",
        },
      ],
      [
        "v1-lock",
        {
          declaration: "^22.7.0",
          lock: true,
          lockfileVersion: 1,
          lockedVersion: "22.7.6",
        },
      ],
    ];
    for (const [id, options] of cases) {
      const root = await writeCase(repository, id, options);
      expect(
        nxCacheRecords(await buildResidualRiskInventory(root)),
        id,
      ).toEqual([]);
    }
  });

  test("requires an enabled self-hosted cache and a cache-consuming task", async () => {
    const repository = await temporaryRepository("topology-negatives");
    const cases: Array<[string, CaseOptions]> = [
      ["empty-cache", { activation: 'NX_SELF_HOSTED_REMOTE_CACHE_SERVER: ""' }],
      ["cloud-only", { activation: "NX_CLOUD_ACCESS_TOKEN: a-token" }],
      ["local-only", { activation: "NX_CACHE_DIRECTORY: .nx/cache" }],
      ["skip-flag", { command: "npx nx run app:build --skip-nx-cache" }],
      [
        "skip-environment",
        {
          activation: "NX_SKIP_NX_CACHE: true",
          command:
            "NX_SELF_HOSTED_REMOTE_CACHE_SERVER=http://127.0.0.1:48721 npx nx run app:build",
        },
      ],
      ["administrative-graph", { command: "npx nx graph" }],
      ["administrative-migrate", { command: "npx nx migrate latest" }],
      ["administrative-reset", { command: "npx nx reset" }],
    ];
    for (const [id, options] of cases) {
      const root = await writeCase(repository, id, options);
      expect(
        nxCacheRecords(await buildResidualRiskInventory(root)),
        id,
      ).toEqual([]);
    }
  });

  test("models configured unpatched provider packages even with fixed core Nx", async () => {
    const repository = await temporaryRepository("providers");
    const providers: Array<[string, string, Record<string, unknown>]> = [
      ["s3", "@nx/s3-cache", { s3: { region: "us-east-1", bucket: "cache" } }],
      ["gcs", "@nx/gcs-cache", { gcs: { bucket: "cache" } }],
      ["azure", "@nx/azure-cache", { azure: { container: "cache" } }],
      [
        "powerpack-s3",
        "@nx/powerpack-s3-cache",
        { s3: { region: "us-east-1", bucket: "cache" } },
      ],
    ];
    for (const [id, packageName, nxJson] of providers) {
      const root = await writeCase(repository, id, {
        activation: "CI: true",
        additionalDevDependencies: { nx: "22.7.7" },
        declaration: "5.0.7",
        nxJson,
        packageName,
      });
      const records = nxCacheRecords(await buildResidualRiskInventory(root));
      expect(records, id).toHaveLength(1);
      expect(records[0]?.frameworkModel?.scope).toBe("cross-file");
      expect(records[0]?.frameworkModel?.sink.kind).toBe(
        "unpatched-nx-provider-cache-restore",
      );
      expect(records[0]?.frameworkModel?.propagators.at(-1)?.symbol).toContain(
        `${packageName}@5.0.7:manifest-exact:`,
      );
    }

    const shared = await writeCase(repository, "shared-fs", {
      activation: "CI: true",
      additionalDevDependencies: { nx: "22.7.7" },
      declaration: "5.0.7",
      packageName: "@nx/shared-fs-cache",
    });
    const sharedRecords = nxCacheRecords(
      await buildResidualRiskInventory(shared),
    );
    expect(sharedRecords).toHaveLength(1);
    expect(sharedRecords[0]?.frameworkModel?.source.kind).toBe(
      "nx-shared-filesystem-cache-ci-activation",
    );
  });

  test("rejects provider membership without an active read path", async () => {
    const repository = await temporaryRepository("provider-negatives");
    const noConfig = await writeCase(repository, "no-config", {
      activation: "CI: true",
      declaration: "5.0.7",
      packageName: "@nx/s3-cache",
    });
    const disabled = await writeCase(repository, "disabled", {
      activation: "CI: true",
      declaration: "5.0.7",
      nxJson: {
        s3: {
          region: "us-east-1",
          bucket: "cache",
          ciMode: "no-cache",
        },
      },
      packageName: "@nx/s3-cache",
    });
    const prerelease = await writeCase(repository, "provider-prerelease", {
      activation: "CI: true",
      declaration: "5.0.7-beta.1",
      nxJson: { s3: { region: "us-east-1", bucket: "cache" } },
      packageName: "@nx/s3-cache",
    });
    const sharedLocal = await writeCase(repository, "shared-local", {
      activation: "NX_CACHE_DIRECTORY: /mnt/cache",
      command: "npx nx run app:build",
      declaration: "5.0.7",
      packageName: "@nx/shared-fs-cache",
      workflowPath: "build.sh",
    });
    for (const [id, root] of [
      ["no-config", noConfig],
      ["disabled", disabled],
      ["provider-prerelease", prerelease],
      ["shared-local", sharedLocal],
    ] as const) {
      expect(
        nxCacheRecords(await buildResidualRiskInventory(root)),
        id,
      ).toEqual([]);
    }
  });

  test("keeps application and bounded witness bytes identical across the pair", async () => {
    const affectedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-nx-self-hosted-cache-archive-escape",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-nx-self-hosted-cache-archive-contained",
    );
    for (const path of [
      join(".github", "workflows", "ci.yml"),
      "nx.json",
      "project.json",
      join("src", "workspace.mjs"),
      join("tools", "build.mjs"),
      "witness.test.mjs",
    ]) {
      expect(await readFile(join(affectedRoot, path), "utf8"), path).toBe(
        await readFile(join(repairedRoot, path), "utf8"),
      );
    }
    const affectedPackage = JSON.parse(
      await readFile(join(affectedRoot, "package.json"), "utf8"),
    ) as { devDependencies: Record<string, string> };
    const repairedPackage = JSON.parse(
      await readFile(join(repairedRoot, "package.json"), "utf8"),
    ) as { devDependencies: Record<string, string> };
    expect(affectedPackage.devDependencies["nx"]).toBe("22.7.6");
    expect(repairedPackage.devDependencies["nx"]).toBe("22.7.7");
  });

  test("requires bounded validation and disciplined impact claims", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-nx-self-hosted-cache-archive-escape");
    expect(prompt).toContain("GHSA-vp3h-ghgh-jr7g");
    expect(prompt).toContain("20.8.0 through 22.7.6");
    expect(prompt).toContain("deprecated packages are unpatched");
    expect(prompt).toContain("loopback-only cache server");
    expect(prompt).toContain("never write or execute a payload");
    expect(prompt).toContain("CWE-22 and CWE-59");
  });
});
