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
  "kubernetes-privileged-sensitive-hostpath",
  "kubernetes-safe-isolated-volume",
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
        record.frameworkModel?.id ===
        "kubernetes-privileged-sensitive-hostpath",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<KubernetesRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-kubernetes-hostpath-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function manifest(
  options: {
    apiVersion?: string;
    kind?: string;
    name?: string;
    podSpecPrefix?: string;
    containerSection?: string;
    privileged?: string;
    volumeName?: string;
    mountName?: string;
    mountPath?: string;
    mountExtra?: string;
    hostPath?: string;
    volumeBody?: string;
  } = {},
): string {
  const kind = options.kind ?? "Pod";
  const podSpecPrefix =
    options.podSpecPrefix ??
    (kind === "Pod"
      ? "spec:"
      : kind === "CronJob"
        ? "spec:\n  jobTemplate:\n    spec:\n      template:\n        spec:"
        : "spec:\n  template:\n    spec:");
  const indent =
    kind === "Pod" ? "  " : kind === "CronJob" ? "          " : "      ";
  const section = options.containerSection ?? "containers";
  const volumeName = options.volumeName ?? "host";
  const mountName = options.mountName ?? volumeName;
  const volumeBody =
    options.volumeBody ??
    `hostPath:\n${indent}      path: ${options.hostPath ?? "/etc"}`;
  return `apiVersion: ${options.apiVersion ?? (kind === "Pod" ? "v1" : kind === "Job" || kind === "CronJob" ? "batch/v1" : "apps/v1")}
kind: ${kind}
metadata:
  name: ${options.name ?? "host-agent"}
${podSpecPrefix}
${indent}${section}:
${indent}  - name: agent
${indent}    image: example.invalid/agent@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
${indent}    securityContext:
${indent}      privileged: ${options.privileged ?? "true"}
${indent}    volumeMounts:
${indent}      - name: ${mountName}
${indent}        mountPath: ${options.mountPath ?? "/host"}
${options.mountExtra === undefined ? "" : `${indent}        ${options.mountExtra}\n`}${indent}volumes:
${indent}  - name: ${volumeName}
${indent}    ${volumeBody}
`;
}

describe("Kubernetes privileged sensitive hostPath model benchmark", () => {
  test("keeps the host-compromise chain and isolated-volume control under perfect gates", async () => {
    const benchmark = JSON.parse(
      await readFile(
        join(benchmarkRoot, "kubernetes-privileged-hostpath-manifest.json"),
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
      cwe: ["CWE-250", "CWE-732"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(benchmark.cases[1]?.expected).toEqual([]);
  });

  test("preserves workload, privilege, volume, mount, and exact line provenance", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "src/deploy.yaml",
      line: 22,
      categories: ["kubernetes-privileged-sensitive-hostpath"],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "kubernetes-yaml",
        scope: "same-file",
        source: {
          kind: "privileged-container-execution",
          path: "src/deploy.yaml",
          line: 19,
          symbol: "section=containers;container=maintenance",
        },
        sink: {
          kind: "writable-sensitive-hostpath-mount",
          path: "src/deploy.yaml",
          line: 22,
          symbol: "volume=host-root;hostPath=/;mountPath=/host;readOnly=false",
          cweIds: ["CWE-250", "CWE-732"],
        },
        propagators: [
          {
            kind: "kubernetes-workload-pod-template",
            path: "src/deploy.yaml",
            line: 2,
            symbol:
              "kind=Deployment;apiVersion=apps/v1;namespace=operations;name=host-maintenance",
          },
          {
            kind: "sensitive-hostpath-volume",
            path: "src/deploy.yaml",
            line: 27,
            symbol: "volume=host-root;hostPath=/",
          },
          {
            kind: "named-read-write-volume-mount",
            path: "src/deploy.yaml",
            line: 22,
            symbol: "volume=host-root;container=maintenance;section=containers",
          },
        ],
        candidateControls: [],
      },
    });
    expect(safe).toEqual([]);
  });

  test("supports current Linux workload and container-section shapes", async () => {
    for (const [kind, apiVersion, podSpecPrefix] of [
      ["Pod", "v1", undefined],
      ["ReplicationController", "v1", undefined],
      ["Deployment", "apps/v1", undefined],
      ["DaemonSet", "apps/v1", undefined],
      ["ReplicaSet", "apps/v1", undefined],
      ["StatefulSet", "apps/v1", undefined],
      ["Job", "batch/v1", undefined],
      ["CronJob", "batch/v1", undefined],
    ] as const) {
      expect(
        await repositoryInventory({
          "workload.yaml": manifest({ kind, apiVersion, podSpecPrefix }),
        }),
      ).toHaveLength(1);
    }
    for (const containerSection of [
      "containers",
      "initContainers",
      "ephemeralContainers",
    ]) {
      const rows = await repositoryInventory({
        "pod.yml": manifest({ containerSection }),
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.source.symbol).toContain(
        `section=${containerSection}`,
      );
    }
  });

  test("supports multi-document files and Kubernetes List objects", async () => {
    const multi = await repositoryInventory({
      "multi.yaml": `${manifest({ name: "first" })}---\n${manifest({ name: "second", hostPath: "/var/lib/kubelet" })}`,
    });
    expect(multi).toHaveLength(2);
    const item = manifest({ name: "listed" })
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

  test("requires the same exact privileged container and named read-write sensitive mount", async () => {
    const controls = [
      manifest({ privileged: "false" }),
      manifest({ privileged: '"true"' }),
      manifest({ mountExtra: "readOnly: true" }),
      manifest({ mountExtra: 'readOnly: "false"' }),
      manifest({ mountName: "other" }),
      manifest({ mountPath: "relative/host" }),
      manifest({ hostPath: "/var/log/agent" }),
      manifest({ volumeBody: "emptyDir: {}" }),
      manifest({ mountExtra: "subPathExpr: $(HOST_SUBPATH)" }),
      manifest({ hostPath: "/", mountExtra: "subPath: var/log/agent" }),
    ];
    for (const [index, source] of controls.entries()) {
      expect(
        await repositoryInventory({ [`control-${index}.yaml`]: source }),
      ).toEqual([]);
    }
    expect(
      await repositoryInventory({
        "sensitive-subpath.yaml": manifest({
          hostPath: "/",
          mountExtra: "subPath: etc/kubernetes",
        }),
      }),
    ).toHaveLength(1);
  });

  test("rejects user-namespace, Windows, schema, identity, ambiguity, and parser lookalikes", async () => {
    const base = manifest();
    const controls: Record<string, string> = {
      "userns.yaml": base.replace("spec:\n", "spec:\n  hostUsers: false\n"),
      "windows-os.yaml": base.replace(
        "spec:\n",
        "spec:\n  os:\n    name: windows\n",
      ),
      "windows-selector.yaml": base.replace(
        "spec:\n",
        "spec:\n  nodeSelector:\n    kubernetes.io/os: windows\n",
      ),
      "wrong-api.yaml": manifest({ apiVersion: "apps/v1", kind: "Pod" }),
      "invalid-host-users.yaml": base.replace(
        "spec:\n",
        'spec:\n  hostUsers: "false"\n',
      ),
      "missing-name.yaml": manifest({ name: "" }),
      "duplicate-volume.yaml": base.replace(
        "  volumes:\n",
        "  volumes:\n    - name: host\n      emptyDir: {}\n",
      ),
      "duplicate-container.yaml": base.replace(
        "  containers:\n",
        "  containers:\n    - name: agent\n      image: example.invalid/other:1\n",
      ),
      "alias.yaml": `${base}\nmetadataCopy: &copy\n  key: value\nother: *copy\n`,
      "duplicate-key.yaml": base.replace(
        "    securityContext:\n",
        "    securityContext:\n      privileged: true\n",
      ),
      "not-kubernetes.yaml":
        "kind: Deployment\nmetadata:\n  name: fake\nspec:\n  privileged: true\n  hostPath: /\n",
      "config.json": base,
    };
    expect(await repositoryInventory(controls)).toEqual([]);
  });

  test("gives the correction turn Kubernetes-specific validation boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"kubernetes-privileged-sensitive-hostpath"}}',
    );
    expect(prompt).toContain(
      "For kubernetes-privileged-sensitive-hostpath rows",
    );
    expect(prompt).toContain("hostUsers: false");
    expect(prompt).toContain("Pod Security admission");
    expect(prompt).toContain("readOnly: true");
    expect(prompt).toContain("do not infer an attacker-controlled container");
  });
});
