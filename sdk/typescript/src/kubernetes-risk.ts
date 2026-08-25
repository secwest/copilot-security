import { posix } from "node:path";
import {
  isAlias,
  isMap,
  isNode,
  isScalar,
  isSeq,
  LineCounter,
  parseAllDocuments,
  type Pair,
} from "yaml";

const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;

const WORKLOAD_APIS = new Map<string, string>([
  ["Pod", "v1"],
  ["ReplicationController", "v1"],
  ["Deployment", "apps/v1"],
  ["DaemonSet", "apps/v1"],
  ["ReplicaSet", "apps/v1"],
  ["StatefulSet", "apps/v1"],
  ["Job", "batch/v1"],
  ["CronJob", "batch/v1"],
]);

const SENSITIVE_HOST_PATHS = [
  "/boot",
  "/dev",
  "/etc",
  "/proc",
  "/root",
  "/run",
  "/sys",
  "/usr",
  "/opt/cni/bin",
  "/etc/cni/net.d",
  "/var/lib/containerd",
  "/var/lib/docker",
  "/var/lib/kubelet",
  "/var/run",
] as const;

interface CandidateControl {
  kind: string;
  path: string;
  line: number;
}

export interface KubernetesPrivilegedHostPathRecord {
  path: string;
  line: number;
  categories: ["kubernetes-privileged-sensitive-hostpath"];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "kubernetes-privileged-sensitive-hostpath";
    language: "kubernetes-yaml";
    scope: "same-file";
    source: {
      kind: "privileged-container-execution";
      path: string;
      line: number;
      symbol: string;
    };
    sink: {
      kind: "writable-sensitive-hostpath-mount";
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-250", "CWE-732"];
    };
    propagators: Array<{
      kind:
        | "kubernetes-workload-pod-template"
        | "sensitive-hostpath-volume"
        | "named-read-write-volume-mount";
      path: string;
      line: number;
      symbol: string;
    }>;
    candidateControls: CandidateControl[];
  };
}

interface ParsedDocuments {
  roots: unknown[];
  counter: LineCounter;
}

interface WorkloadSpec {
  apiVersion: string;
  kind: string;
  kindLine: number;
  name: string;
  namespace: string;
  podSpec: unknown;
}

interface SensitiveVolume {
  name: string;
  hostPath: string;
  line: number;
}

function mapPair(node: unknown, key: string): Pair | undefined {
  if (!isMap(node)) return undefined;
  return node.items.find(
    (pair) => isScalar(pair.key) && pair.key.value === key,
  );
}

function scalarText(node: unknown): string | undefined {
  if (!isScalar(node)) return undefined;
  return typeof node.value === "string" ? node.value : undefined;
}

function scalarBoolean(node: unknown): boolean | undefined {
  if (!isScalar(node)) return undefined;
  return typeof node.value === "boolean" ? node.value : undefined;
}

function containsAlias(node: unknown): boolean {
  if (isAlias(node)) return true;
  if (isMap(node)) {
    return node.items.some(
      (pair) => containsAlias(pair.key) || containsAlias(pair.value),
    );
  }
  return isSeq(node) && node.items.some((item) => containsAlias(item));
}

function parseDocuments(source: string): ParsedDocuments | undefined {
  const counter = new LineCounter();
  const documents = parseAllDocuments(source, {
    lineCounter: counter,
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
    version: "1.2",
  });
  if (
    documents.some(
      (document) =>
        document.errors.length > 0 || containsAlias(document.contents),
    )
  ) {
    return undefined;
  }
  return {
    roots: documents
      .map((document) => document.contents)
      .filter((contents) => contents !== null),
    counter,
  };
}

function nodeLine(node: unknown, counter: LineCounter): number | undefined {
  if (!isNode(node) || node.range === null || node.range === undefined) {
    return undefined;
  }
  return counter.linePos(node.range[0]).line;
}

function pairLine(pair: Pair | undefined, counter: LineCounter): number {
  return nodeLine(pair?.key, counter) ?? nodeLine(pair?.value, counter) ?? 1;
}

function nestedValue(root: unknown, keys: readonly string[]): unknown {
  let value = root;
  for (const key of keys) {
    const pair = mapPair(value, key);
    if (pair === undefined) return undefined;
    value = pair.value;
  }
  return value;
}

function workloadSpec(
  root: unknown,
  counter: LineCounter,
): WorkloadSpec | undefined {
  if (!isMap(root)) return undefined;
  const apiVersion = scalarText(mapPair(root, "apiVersion")?.value);
  const kindPair = mapPair(root, "kind");
  const kind = scalarText(kindPair?.value);
  if (
    apiVersion === undefined ||
    kind === undefined ||
    WORKLOAD_APIS.get(kind) !== apiVersion
  ) {
    return undefined;
  }
  const metadata = mapPair(root, "metadata")?.value;
  const name = scalarText(mapPair(metadata, "name")?.value)?.trim();
  if (name === undefined || name === "") return undefined;
  const namespace =
    scalarText(mapPair(metadata, "namespace")?.value)?.trim() || "default";
  const podSpec =
    kind === "Pod"
      ? nestedValue(root, ["spec"])
      : kind === "CronJob"
        ? nestedValue(root, ["spec", "jobTemplate", "spec", "template", "spec"])
        : nestedValue(root, ["spec", "template", "spec"]);
  if (!isMap(podSpec)) return undefined;
  return {
    apiVersion,
    kind,
    kindLine: pairLine(kindPair, counter),
    name,
    namespace,
    podSpec,
  };
}

function rootDocuments(root: unknown): unknown[] {
  if (!isMap(root)) return [];
  if (
    scalarText(mapPair(root, "apiVersion")?.value) === "v1" &&
    scalarText(mapPair(root, "kind")?.value) === "List"
  ) {
    const items = mapPair(root, "items")?.value;
    return isSeq(items) ? items.items : [];
  }
  return [root];
}

function isWindowsPodSpec(podSpec: unknown): boolean {
  const osName = scalarText(nestedValue(podSpec, ["os", "name"]));
  if (osName?.toLowerCase() === "windows") return true;
  const selectedOs = scalarText(
    mapPair(mapPair(podSpec, "nodeSelector")?.value, "kubernetes.io/os")?.value,
  );
  return selectedOs?.toLowerCase() === "windows";
}

function normalizedAbsoluteHostPath(value: string): string | undefined {
  if (!value.startsWith("/") || value.includes("\\") || value.includes("\0")) {
    return undefined;
  }
  return posix.normalize(value);
}

function isSensitiveHostPath(value: string): boolean {
  if (value === "/") return true;
  return SENSITIVE_HOST_PATHS.some(
    (root) => value === root || value.startsWith(`${root}/`),
  );
}

function sensitiveVolumes(
  podSpec: unknown,
  counter: LineCounter,
): Map<string, SensitiveVolume> | undefined {
  const volumes = mapPair(podSpec, "volumes")?.value;
  if (!isSeq(volumes)) return new Map();
  const allNames = volumes.items.map((item) =>
    scalarText(mapPair(item, "name")?.value),
  );
  const duplicateNames = new Set(
    allNames.filter(
      (name): name is string =>
        name !== undefined &&
        allNames.filter((candidate) => candidate === name).length > 1,
    ),
  );
  if (duplicateNames.size > 0) return undefined;
  const result = new Map<string, SensitiveVolume>();
  for (const volume of volumes.items) {
    if (!isMap(volume)) continue;
    const name = scalarText(mapPair(volume, "name")?.value);
    const hostPath = mapPair(volume, "hostPath")?.value;
    const pathPair = mapPair(hostPath, "path");
    const rawPath = scalarText(pathPair?.value);
    if (
      name === undefined ||
      name.trim() === "" ||
      duplicateNames.has(name) ||
      rawPath === undefined
    ) {
      continue;
    }
    const normalized = normalizedAbsoluteHostPath(rawPath);
    if (normalized === undefined || !isSensitiveHostPath(normalized)) continue;
    result.set(name, {
      name,
      hostPath: normalized,
      line: pairLine(pathPair, counter),
    });
  }
  return result;
}

function effectiveHostPath(
  hostPath: string,
  mount: unknown,
): string | undefined {
  const subPathExpr = mapPair(mount, "subPathExpr");
  if (subPathExpr !== undefined) return undefined;
  const subPath = scalarText(mapPair(mount, "subPath")?.value);
  if (subPath === undefined || subPath === "") return hostPath;
  if (subPath.startsWith("/") || subPath.includes("\\")) return undefined;
  const normalized = posix.normalize(posix.join(hostPath, subPath));
  if (
    normalized !== hostPath &&
    !normalized.startsWith(hostPath === "/" ? "/" : `${hostPath}/`)
  ) {
    return undefined;
  }
  return normalized;
}

function sourceExcerpt(
  lines: readonly string[],
  startLine: number,
  endLine: number,
): string {
  return lines
    .slice(startLine - 1, endLine)
    .map((line, offset) => `${startLine + offset}: ${line}`)
    .join("\n");
}

function contextExcerpt(
  lines: readonly string[],
  line: number,
): { startLine: number; endLine: number; excerpt: string } {
  const startLine = Math.max(1, line - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(lines.length, line + CONTEXT_LINES_AFTER);
  return {
    startLine,
    endLine,
    excerpt: sourceExcerpt(lines, startLine, endLine),
  };
}

function workloadRecords(
  path: string,
  lines: readonly string[],
  workload: WorkloadSpec,
  counter: LineCounter,
): KubernetesPrivilegedHostPathRecord[] {
  const hostUsersPair = mapPair(workload.podSpec, "hostUsers");
  const hostUsers = scalarBoolean(hostUsersPair?.value);
  if (
    isWindowsPodSpec(workload.podSpec) ||
    (hostUsersPair !== undefined && hostUsers === undefined) ||
    hostUsers === false
  ) {
    return [];
  }
  const volumes = sensitiveVolumes(workload.podSpec, counter);
  if (volumes === undefined || volumes.size === 0) return [];
  const records: KubernetesPrivilegedHostPathRecord[] = [];
  const workloadSymbol = `kind=${workload.kind};apiVersion=${workload.apiVersion};namespace=${workload.namespace};name=${workload.name}`;
  for (const section of [
    "containers",
    "initContainers",
    "ephemeralContainers",
  ] as const) {
    const containers = mapPair(workload.podSpec, section)?.value;
    if (!isSeq(containers)) continue;
    const containerNames = containers.items.map((container) =>
      scalarText(mapPair(container, "name")?.value),
    );
    if (
      containerNames.some(
        (name, index) =>
          name !== undefined && containerNames.indexOf(name) !== index,
      )
    ) {
      continue;
    }
    for (const container of containers.items) {
      if (!isMap(container)) continue;
      const containerName = scalarText(mapPair(container, "name")?.value);
      if (containerName === undefined || containerName.trim() === "") continue;
      const privilegedPair = mapPair(
        mapPair(container, "securityContext")?.value,
        "privileged",
      );
      if (scalarBoolean(privilegedPair?.value) !== true) continue;
      const privilegedLine = pairLine(privilegedPair, counter);
      const mounts = mapPair(container, "volumeMounts")?.value;
      if (!isSeq(mounts)) continue;
      for (const mount of mounts.items) {
        if (!isMap(mount)) continue;
        const volumeName = scalarText(mapPair(mount, "name")?.value);
        const volume =
          volumeName === undefined ? undefined : volumes.get(volumeName);
        if (volume === undefined) continue;
        const readOnlyPair = mapPair(mount, "readOnly");
        const readOnly = scalarBoolean(readOnlyPair?.value);
        if (readOnlyPair !== undefined && readOnly === undefined) continue;
        if (readOnly === true) continue;
        const mountPathPair = mapPair(mount, "mountPath");
        const mountPath = scalarText(mountPathPair?.value);
        if (mountPath === undefined || !mountPath.startsWith("/")) continue;
        const hostPath = effectiveHostPath(volume.hostPath, mount);
        if (hostPath === undefined || !isSensitiveHostPath(hostPath)) continue;
        const sinkLine = pairLine(mountPathPair, counter);
        const sinkContext = contextExcerpt(lines, sinkLine);
        const sourceContext = contextExcerpt(lines, privilegedLine);
        records.push({
          path,
          line: sinkLine,
          categories: ["kubernetes-privileged-sensitive-hostpath"],
          priority: 100,
          startLine: sinkContext.startLine,
          endLine: sinkContext.endLine,
          excerpt: sinkContext.excerpt,
          sourceExcerpt: sourceContext.excerpt,
          frameworkModel: {
            schemaVersion: "1.2",
            id: "kubernetes-privileged-sensitive-hostpath",
            language: "kubernetes-yaml",
            scope: "same-file",
            source: {
              kind: "privileged-container-execution",
              path,
              line: privilegedLine,
              symbol: `section=${section};container=${containerName}`,
            },
            sink: {
              kind: "writable-sensitive-hostpath-mount",
              path,
              line: sinkLine,
              symbol: `volume=${volume.name};hostPath=${hostPath};mountPath=${posix.normalize(mountPath)};readOnly=false`,
              cweIds: ["CWE-250", "CWE-732"],
            },
            propagators: [
              {
                kind: "kubernetes-workload-pod-template",
                path,
                line: workload.kindLine,
                symbol: workloadSymbol,
              },
              {
                kind: "sensitive-hostpath-volume",
                path,
                line: volume.line,
                symbol: `volume=${volume.name};hostPath=${volume.hostPath}`,
              },
              {
                kind: "named-read-write-volume-mount",
                path,
                line: sinkLine,
                symbol: `volume=${volume.name};container=${containerName};section=${section}`,
              },
            ],
            candidateControls: [],
          },
        });
      }
    }
  }
  return records;
}

export function kubernetesPrivilegedHostPathRecords(
  path: string,
  lines: readonly string[],
  source: string,
): KubernetesPrivilegedHostPathRecord[] {
  if (!/\.ya?ml$/iu.test(path)) return [];
  const parsed = parseDocuments(source);
  if (parsed === undefined) return [];
  const records: KubernetesPrivilegedHostPathRecord[] = [];
  for (const parsedRoot of parsed.roots) {
    for (const root of rootDocuments(parsedRoot)) {
      const workload = workloadSpec(root, parsed.counter);
      if (workload === undefined) continue;
      records.push(...workloadRecords(path, lines, workload, parsed.counter));
    }
  }
  return records;
}
