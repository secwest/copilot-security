import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface KubernetesRecord {
  path: string;
  line: number;
  categories: string[];
  frameworkModel?: {
    schemaVersion: string;
    id: string;
    language: string;
    scope: string;
    source: { kind: string; path: string; line: number; symbol: string };
    sink: {
      kind: string;
      path: string;
      line: number;
      symbol: string;
      cweIds: string[];
    };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
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
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "kubernetes-cluster-admin-broad-subject",
  "kubernetes-cluster-admin-specific-group",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): KubernetesRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as KubernetesRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "kubernetes-cluster-admin-broad-subject",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<KubernetesRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-kubernetes-rbac-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function binding(
  options: {
    apiVersion?: string;
    kind?: string;
    name?: string;
    metadataExtra?: string;
    roleApiGroup?: string;
    roleKind?: string;
    roleName?: string;
    subjectApiGroup?: string;
    subjectKind?: string;
    subjectName?: string;
    subjectExtra?: string;
  } = {},
): string {
  return `apiVersion: ${options.apiVersion ?? "rbac.authorization.k8s.io/v1"}
kind: ${options.kind ?? "ClusterRoleBinding"}
metadata:
  name: ${options.name ?? "broad-cluster-admin"}
${options.metadataExtra === undefined ? "" : `  ${options.metadataExtra}\n`}roleRef:
  apiGroup: ${options.roleApiGroup ?? "rbac.authorization.k8s.io"}
  kind: ${options.roleKind ?? "ClusterRole"}
  name: ${options.roleName ?? "cluster-admin"}
subjects:
  - apiGroup: ${options.subjectApiGroup ?? "rbac.authorization.k8s.io"}
    kind: ${options.subjectKind ?? "Group"}
    name: ${options.subjectName ?? "system:serviceaccounts"}
${options.subjectExtra === undefined ? "" : `    ${options.subjectExtra}\n`}`;
}

describe("Kubernetes cluster-admin broad-subject model benchmark", () => {
  test("keeps the broad binding and specific-group control under perfect gates", async () => {
    const benchmark = JSON.parse(
      await readFile(
        join(benchmarkRoot, "kubernetes-cluster-admin-binding-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(benchmark.schemaVersion).toBe("1.0");
    expect(
      Object.values(benchmark.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(benchmark.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(benchmark.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-269", "CWE-284"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(benchmark.cases[1]?.expected).toEqual([]);
  });

  test("preserves exact broad principal, binding, role reference, and lines", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "src/rbac.yaml",
      line: 8,
      categories: ["kubernetes-cluster-admin-broad-subject"],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "kubernetes-yaml",
        scope: "same-file",
        source: {
          kind: "broad-kubernetes-principal",
          path: "src/rbac.yaml",
          line: 12,
          symbol: "kind=Group;name=system:serviceaccounts",
        },
        sink: {
          kind: "cluster-admin-clusterrolebinding",
          path: "src/rbac.yaml",
          line: 8,
          symbol:
            "apiGroup=rbac.authorization.k8s.io;kind=ClusterRole;name=cluster-admin;scope=cluster",
          cweIds: ["CWE-269", "CWE-284"],
        },
        propagators: [
          {
            kind: "kubernetes-clusterrolebinding",
            path: "src/rbac.yaml",
            line: 2,
            symbol:
              "kind=ClusterRoleBinding;apiVersion=rbac.authorization.k8s.io/v1;name=all-serviceaccounts-cluster-admin",
          },
        ],
        candidateControls: [],
      },
    });
    expect(safe).toEqual([]);
  });

  test("recognizes only the documented intrinsically broad principals", async () => {
    for (const [subjectKind, subjectName] of [
      ["Group", "system:serviceaccounts"],
      ["Group", "system:authenticated"],
      ["Group", "system:unauthenticated"],
      ["User", "system:anonymous"],
    ] as const) {
      const rows = await repositoryInventory({
        "binding.yaml": binding({ subjectKind, subjectName }),
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.source.symbol).toBe(
        `kind=${subjectKind};name=${subjectName}`,
      );
    }
  });

  test("supports multi-document YAML and Kubernetes List objects", async () => {
    const multi = await repositoryInventory({
      "multi.yaml": `${binding({ name: "first" })}---\n${binding({ name: "second", subjectName: "system:authenticated" })}`,
    });
    expect(multi).toHaveLength(2);
    const item = binding({ name: "listed" })
      .split("\n")
      .map((line) => (line === "" ? line : `    ${line}`))
      .join("\n");
    const listed = await repositoryInventory({
      "list.yaml": `apiVersion: v1\nkind: List\nitems:\n  - ${item.trimStart()}`,
    });
    expect(listed).toHaveLength(1);
    expect(listed[0]?.frameworkModel?.propagators[0]?.symbol).toContain(
      "name=listed",
    );
  });

  test("rejects narrower subjects, scope, roles, and schema lookalikes", async () => {
    const controls = [
      binding({ subjectName: "platform-admins" }),
      binding({ subjectName: "system:serviceaccounts:operations" }),
      binding({ subjectKind: "ServiceAccount", subjectName: "default" }),
      binding({ kind: "RoleBinding" }),
      binding({ roleName: "admin" }),
      binding({ roleKind: "Role" }),
      binding({ roleApiGroup: "example.invalid" }),
      binding({ subjectApiGroup: "example.invalid" }),
      binding({ apiVersion: "rbac.authorization.k8s.io/v1beta1" }),
      binding({ metadataExtra: "namespace: operations" }),
      binding({ subjectExtra: "namespace: operations" }),
    ];
    for (const [index, source] of controls.entries()) {
      expect(
        await repositoryInventory({ [`control-${index}.yaml`]: source }),
      ).toEqual([]);
    }
  });

  test("fails closed on duplicate identities, aliases, malformed YAML, and non-YAML files", async () => {
    const base = binding();
    const controls: Record<string, string> = {
      "duplicate-subject.yaml": `${base}  - apiGroup: rbac.authorization.k8s.io\n    kind: Group\n    name: system:serviceaccounts\n`,
      "duplicate-key.yaml": base.replace(
        "  name: cluster-admin\n",
        "  name: cluster-admin\n  name: cluster-admin\n",
      ),
      "alias.yaml": `${base}copy: &copy\n  value: one\nother: *copy\n`,
      "malformed.yaml": `${base}broken: [\n`,
      "missing-name.yaml": binding({ name: "" }),
      "binding.json": base,
    };
    expect(await repositoryInventory(controls)).toEqual([]);
  });

  test("gives the correction turn exact RBAC reachability boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"kubernetes-cluster-admin-broad-subject"}}',
    );
    expect(prompt).toContain("For kubernetes-cluster-admin-broad-subject rows");
    expect(prompt).toContain("system:serviceaccounts");
    expect(prompt).toContain("RBAC permissions are additive");
    expect(prompt).toContain("Do not infer an internet-reachable API");
    expect(prompt).toContain("CWE-269/CWE-284");
  });
});
