import { createHash } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_SARIF_BYTES = 20 * 1024 * 1024;
const MAX_SARIF_FILES = 32;
const MAX_RUNS_PER_FILE = 20;
const MAX_RESULTS = 5_000;
const MAX_LOCATIONS_PER_RESULT = 128;
const MAX_TEXT_LENGTH = 512;
const CWE_PATTERN = /\bCWE(?:[-_: ]+)?(\d{1,7})\b/giu;

export interface SarifSeedLocation {
  path: string;
  start_line: number;
  end_line: number;
  role: "source" | "sink" | "evidence";
}

export interface SarifSeedCandidate {
  cwe_ids: string[];
  locations: SarifSeedLocation[];
  summary: string;
  evidence: string;
  context: string;
  instance: string;
}

export interface SarifSeedSource {
  id: string;
  fileName: string;
  sha256: string;
  runCount: number;
  resultCount: number;
  importedCount: number;
  ignoredCount: number;
  tools: string[];
}

export interface PreparedSarifSeeds {
  sourceRoot: string;
  sources: string[];
  sourceRecords: SarifSeedSource[];
  candidates: SarifSeedCandidate[];
  candidateSha256: string;
  ignoredResultCount: number;
}

interface SarifLocationContext {
  repository: string;
  sourceRoot: string;
  lineCounts: Map<string, number>;
  signal?: AbortSignal;
}

export async function prepareSarifSeeds(
  paths: readonly string[],
  repository: string,
  sourceRoot?: string,
  signal?: AbortSignal,
): Promise<PreparedSarifSeeds> {
  const canonicalRepository = await canonicalDirectory(
    repository,
    "Repository",
  );
  const canonicalSourceRoot = await canonicalDirectory(
    sourceRoot ?? canonicalRepository,
    "SARIF source root",
  );
  if (paths.length === 0) {
    return {
      sourceRoot: canonicalSourceRoot,
      sources: [],
      sourceRecords: [],
      candidates: [],
      candidateSha256: createHash("sha256").update("").digest("hex"),
      ignoredResultCount: 0,
    };
  }
  if (paths.length > MAX_SARIF_FILES) {
    throw new Error(
      `At most ${MAX_SARIF_FILES} SARIF seed files are supported.`,
    );
  }

  const uniqueSources = new Set<string>();
  for (const requested of paths) {
    signal?.throwIfAborted();
    if (!requested.trim()) throw new Error("SARIF seed paths cannot be empty.");
    const path = resolve(requested);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new Error(`SARIF seed must be a regular non-symlink file: ${path}`);
    }
    if (metadata.size > MAX_SARIF_BYTES) {
      throw new Error(
        `SARIF seed exceeds the ${MAX_SARIF_BYTES} byte limit: ${path}`,
      );
    }
    uniqueSources.add(await realpath(path));
  }

  const context: SarifLocationContext = {
    repository: canonicalRepository,
    sourceRoot: canonicalSourceRoot,
    lineCounts: new Map(),
    signal,
  };
  const sourceRecords: SarifSeedSource[] = [];
  const candidates: SarifSeedCandidate[] = [];
  let ignoredResultCount = 0;
  let totalResultCount = 0;

  for (const [sourceIndex, path] of [...uniqueSources].sort().entries()) {
    signal?.throwIfAborted();
    const bytes = await readBoundedSarifFile(path, signal);
    let document: unknown;
    try {
      document = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
    } catch (error) {
      throw new Error(`SARIF seed is not valid UTF-8 JSON: ${path}`, {
        cause: error,
      });
    }
    if (!isRecord(document) || document["version"] !== "2.1.0") {
      throw new Error(`SARIF seed must use SARIF version 2.1.0: ${path}`);
    }
    const runs = document["runs"];
    if (
      !Array.isArray(runs) ||
      runs.length === 0 ||
      runs.length > MAX_RUNS_PER_FILE
    ) {
      throw new Error(
        `SARIF seed must contain 1 through ${MAX_RUNS_PER_FILE} runs: ${path}`,
      );
    }

    const sourceId = `sarif-source-${String(sourceIndex + 1).padStart(3, "0")}`;
    const sourceDigest = createHash("sha256").update(bytes).digest("hex");
    const tools = new Set<string>();
    let sourceResultCount = 0;
    let importedCount = 0;
    let sourceIgnoredCount = 0;

    for (const [runIndex, run] of runs.entries()) {
      if (!isRecord(run))
        throw new Error(`SARIF run ${runIndex + 1} is invalid: ${path}`);
      const driver = driverFromRun(run, path, runIndex);
      const toolName = boundedText(driver["name"], "SARIF tool name");
      const toolVersion = optionalBoundedText(
        driver["semanticVersion"] ?? driver["version"],
      );
      const toolLabel =
        toolVersion === undefined ? toolName : `${toolName} ${toolVersion}`;
      tools.add(toolLabel);
      const rules = Array.isArray(driver["rules"]) ? driver["rules"] : [];
      const artifacts = Array.isArray(run["artifacts"]) ? run["artifacts"] : [];
      const results = run["results"] ?? [];
      if (!Array.isArray(results)) {
        throw new Error(
          `SARIF run ${runIndex + 1} results must be an array: ${path}`,
        );
      }
      sourceResultCount += results.length;
      totalResultCount += results.length;
      if (totalResultCount > MAX_RESULTS) {
        throw new Error(
          `SARIF seeds contain more than ${MAX_RESULTS} results.`,
        );
      }

      for (const [resultIndex, result] of results.entries()) {
        signal?.throwIfAborted();
        if (!isRecord(result)) {
          throw new Error(
            `SARIF result ${runIndex + 1}:${resultIndex + 1} is invalid: ${path}`,
          );
        }
        if (isSuppressedOrAbsent(result)) {
          sourceIgnoredCount++;
          ignoredResultCount++;
          continue;
        }
        const rule = ruleForResult(result, rules);
        const ruleId =
          optionalBoundedText(result["ruleId"] ?? rule?.["id"]) ??
          "unidentified-rule";
        const ruleName = optionalBoundedText(rule?.["name"]);
        const locations = await locationsForResult(result, context, artifacts);
        if (locations.length === 0) {
          sourceIgnoredCount++;
          ignoredResultCount++;
          continue;
        }
        const cweIds = cwesFromResult(result, rule);
        const severity = sarifSeverity(result, rule);
        const seedId = `sarif-seed-${String(candidates.length + 1).padStart(5, "0")}`;
        const displayRule =
          ruleName === undefined ? ruleId : `${ruleId} (${ruleName})`;
        candidates.push({
          cwe_ids: cweIds,
          locations,
          summary: `${toolName} identified external analyzer candidate ${displayRule}.`,
          evidence:
            "This is an untrusted SARIF seed, not a confirmed finding. Inspect the referenced repository code and independently establish source, control, sink, reachability, exploitability, impact, and counterevidence.",
          context: [
            `seed_id=${seedId}`,
            `source_id=${sourceId}`,
            `source_sha256=${sourceDigest}`,
            `run=${runIndex + 1}`,
            `result=${resultIndex + 1}`,
            `tool=${toolLabel}`,
            `rule=${ruleId}`,
            `severity=${severity}`,
          ].join("; "),
          instance: seedId,
        });
        importedCount++;
      }
    }

    sourceRecords.push({
      id: sourceId,
      fileName: basename(path),
      sha256: sourceDigest,
      runCount: runs.length,
      resultCount: sourceResultCount,
      importedCount,
      ignoredCount: sourceIgnoredCount,
      tools: [...tools].sort(),
    });
  }

  if (candidates.length === 0) {
    throw new Error(
      "SARIF seeds contained no unsuppressed results with valid locations inside the repository.",
    );
  }
  return {
    sourceRoot: canonicalSourceRoot,
    sources: [...uniqueSources].sort(),
    sourceRecords,
    candidates,
    candidateSha256: createHash("sha256")
      .update(serializedSarifCandidates(candidates))
      .digest("hex"),
    ignoredResultCount,
  };
}

async function readBoundedSarifFile(
  path: string,
  signal?: AbortSignal,
): Promise<Buffer> {
  signal?.throwIfAborted();
  const initial = await lstat(path);
  if (initial.isSymbolicLink() || !initial.isFile()) {
    throw new Error(`SARIF seed must be a regular non-symlink file: ${path}`);
  }
  if (initial.size > MAX_SARIF_BYTES) {
    throw new Error(
      `SARIF seed exceeds the ${MAX_SARIF_BYTES} byte limit: ${path}`,
    );
  }

  const handle = await open(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.dev !== initial.dev ||
      opened.ino !== initial.ino
    ) {
      throw new Error(`SARIF seed changed before it could be read: ${path}`);
    }
    if (opened.size > MAX_SARIF_BYTES) {
      throw new Error(
        `SARIF seed exceeds the ${MAX_SARIF_BYTES} byte limit: ${path}`,
      );
    }

    const buffer = Buffer.allocUnsafe(MAX_SARIF_BYTES + 1);
    let offset = 0;
    while (offset < buffer.byteLength) {
      signal?.throwIfAborted();
      const { bytesRead } = await handle.read(
        buffer,
        offset,
        buffer.byteLength - offset,
        null,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_SARIF_BYTES) {
      throw new Error(
        `SARIF seed exceeds the ${MAX_SARIF_BYTES} byte limit: ${path}`,
      );
    }
    const completed = await handle.stat();
    if (
      !completed.isFile() ||
      completed.dev !== opened.dev ||
      completed.ino !== opened.ino ||
      completed.size > MAX_SARIF_BYTES
    ) {
      throw new Error(`SARIF seed changed while it was being read: ${path}`);
    }
    return Buffer.from(buffer.subarray(0, offset));
  } finally {
    await handle.close();
  }
}

export async function writePreparedSarifSeeds(
  scanDir: string,
  prepared: Readonly<PreparedSarifSeeds>,
  signal?: AbortSignal,
): Promise<{ candidatesPath: string; sourcesPath: string }> {
  if (prepared.candidates.length === 0) {
    throw new Error("Cannot write an empty SARIF seed set.");
  }
  const contextDirectory = join(scanDir, "artifacts", "01_context");
  const discoveryDirectory = join(scanDir, "artifacts", "02_discovery");
  await Promise.all([
    mkdir(contextDirectory, { recursive: true, mode: 0o700 }),
    mkdir(discoveryDirectory, { recursive: true, mode: 0o700 }),
  ]);
  const sourcesPath = join(contextDirectory, "external_sarif_sources.json");
  const candidatesPath = join(
    discoveryDirectory,
    "external_sarif_candidates.jsonl",
  );
  const candidateRows = serializedSarifCandidates(prepared.candidates);
  const candidateSha256 = createHash("sha256")
    .update(candidateRows)
    .digest("hex");
  if (candidateSha256 !== prepared.candidateSha256) {
    throw new Error(
      "Prepared SARIF candidates changed before they could be written.",
    );
  }
  const sourceDocument = {
    schemaVersion: "1.0",
    trust: "untrusted-candidate-input",
    secretHandling:
      "Result messages, snippets, fixes, properties, fingerprints, and embedded content were intentionally omitted.",
    candidateCount: prepared.candidates.length,
    candidateSha256,
    ignoredResultCount: prepared.ignoredResultCount,
    sources: prepared.sourceRecords,
  };
  await writeFile(sourcesPath, `${JSON.stringify(sourceDocument)}\n`, {
    flag: "wx",
    mode: 0o600,
    signal,
  });
  await writeFile(candidatesPath, candidateRows, {
    flag: "wx",
    mode: 0o600,
    signal,
  });
  return { candidatesPath, sourcesPath };
}

function serializedSarifCandidates(
  candidates: readonly SarifSeedCandidate[],
): string {
  return candidates.length === 0
    ? ""
    : `${candidates.map((candidate) => JSON.stringify(candidate)).join("\n")}\n`;
}

async function canonicalDirectory(
  path: string,
  label: string,
): Promise<string> {
  const requested = resolve(path);
  const metadata = await lstat(requested);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} must be a non-symlink directory: ${requested}`);
  }
  return await realpath(requested);
}

function driverFromRun(
  run: Record<string, unknown>,
  path: string,
  runIndex: number,
): Record<string, unknown> {
  const tool = run["tool"];
  const driver = isRecord(tool) ? tool["driver"] : undefined;
  if (!isRecord(driver)) {
    throw new Error(`SARIF run ${runIndex + 1} has no tool driver: ${path}`);
  }
  return driver;
}

function ruleForResult(
  result: Record<string, unknown>,
  rules: unknown[],
): Record<string, unknown> | undefined {
  const index = result["ruleIndex"];
  if (Number.isInteger(index) && (index as number) >= 0) {
    const rule = rules[index as number];
    if (isRecord(rule)) return rule;
  }
  const ruleId = result["ruleId"];
  if (typeof ruleId !== "string") return undefined;
  return rules.find(
    (rule): rule is Record<string, unknown> =>
      isRecord(rule) && rule["id"] === ruleId,
  );
}

function isSuppressedOrAbsent(result: Record<string, unknown>): boolean {
  if (
    result["baselineState"] === "absent" ||
    result["kind"] === "pass" ||
    result["kind"] === "notApplicable"
  ) {
    return true;
  }
  const suppressions = result["suppressions"];
  return (
    Array.isArray(suppressions) &&
    suppressions.some(
      (suppression) =>
        !isRecord(suppression) || suppression["status"] !== "rejected",
    )
  );
}

async function locationsForResult(
  result: Record<string, unknown>,
  context: SarifLocationContext,
  artifacts: unknown[],
): Promise<SarifSeedLocation[]> {
  const rawLocations: Array<{
    value: unknown;
    role: SarifSeedLocation["role"];
  }> = [];
  const codeFlowLocations: unknown[] = [];
  const codeFlows = result["codeFlows"];
  if (Array.isArray(codeFlows)) {
    for (const codeFlow of codeFlows) {
      if (!isRecord(codeFlow) || !Array.isArray(codeFlow["threadFlows"]))
        continue;
      for (const threadFlow of codeFlow["threadFlows"]) {
        if (!isRecord(threadFlow) || !Array.isArray(threadFlow["locations"]))
          continue;
        for (const location of threadFlow["locations"]) {
          if (isRecord(location)) codeFlowLocations.push(location["location"]);
        }
      }
    }
  }
  if (codeFlowLocations.length > MAX_LOCATIONS_PER_RESULT) {
    throw new Error(
      `A SARIF result contains more than ${MAX_LOCATIONS_PER_RESULT} code-flow locations.`,
    );
  }
  for (const [index, location] of codeFlowLocations.entries()) {
    rawLocations.push({
      value: location,
      role:
        codeFlowLocations.length === 1
          ? "evidence"
          : index === 0
            ? "source"
            : index === codeFlowLocations.length - 1
              ? "sink"
              : "evidence",
    });
  }
  const primaryLocations = result["locations"];
  if (Array.isArray(primaryLocations)) {
    if (primaryLocations.length > MAX_LOCATIONS_PER_RESULT) {
      throw new Error(
        `A SARIF result contains more than ${MAX_LOCATIONS_PER_RESULT} primary locations.`,
      );
    }
    rawLocations.push(
      ...primaryLocations.map((value) => ({
        value,
        role: "evidence" as const,
      })),
    );
  }

  const normalized = new Map<string, SarifSeedLocation>();
  for (const raw of rawLocations) {
    const location = await normalizeLocation(
      raw.value,
      raw.role,
      context,
      artifacts,
    );
    if (location === null) continue;
    const key = `${location.path}\0${location.start_line}\0${location.end_line}\0${location.role}`;
    normalized.set(key, location);
  }
  return [...normalized.values()].sort(
    (left, right) =>
      left.path.localeCompare(right.path) ||
      left.start_line - right.start_line ||
      left.end_line - right.end_line ||
      left.role.localeCompare(right.role),
  );
}

async function normalizeLocation(
  value: unknown,
  role: SarifSeedLocation["role"],
  context: SarifLocationContext,
  artifacts: unknown[],
): Promise<SarifSeedLocation | null> {
  if (!isRecord(value)) return null;
  const physical = value["physicalLocation"];
  if (!isRecord(physical)) return null;
  const artifact = physical["artifactLocation"];
  let uri = isRecord(artifact) ? artifact["uri"] : undefined;
  if (typeof uri !== "string" && isRecord(artifact)) {
    const index = artifact["index"];
    if (Number.isInteger(index) && (index as number) >= 0) {
      const referencedArtifact = artifacts[index as number];
      const referencedLocation = isRecord(referencedArtifact)
        ? referencedArtifact["location"]
        : undefined;
      if (isRecord(referencedLocation)) uri = referencedLocation["uri"];
    }
  }
  if (typeof uri !== "string" || uri.length === 0 || uri.includes("\0"))
    return null;
  const repositoryPath = sarifUriToRepositoryPath(uri, context);
  if (repositoryPath === null) return null;
  const metadata = await lstat(repositoryPath).catch(() => null);
  if (metadata === null || metadata.isSymbolicLink() || !metadata.isFile())
    return null;
  const canonical = await realpath(repositoryPath);
  if (!isInside(context.repository, canonical)) return null;
  const relativePath = relative(context.repository, canonical)
    .split(sep)
    .join("/");
  if (
    !relativePath ||
    relativePath.split("/").some((part) => part.includes(":"))
  ) {
    return null;
  }
  const region = physical["region"];
  const startLine =
    positiveInteger(isRecord(region) ? region["startLine"] : undefined) ?? 1;
  const endLine =
    positiveInteger(isRecord(region) ? region["endLine"] : undefined) ??
    startLine;
  if (endLine < startLine) return null;
  let lineCount = context.lineCounts.get(canonical);
  if (lineCount === undefined) {
    lineCount = await countLines(canonical, context.signal);
    context.lineCounts.set(canonical, lineCount);
  }
  if (startLine > lineCount || endLine > lineCount) return null;
  return { path: relativePath, start_line: startLine, end_line: endLine, role };
}

function sarifUriToRepositoryPath(
  uri: string,
  context: Pick<SarifLocationContext, "repository" | "sourceRoot">,
): string | null {
  let decoded: string;
  try {
    decoded = uri.startsWith("file:")
      ? fileURLToPath(uri)
      : decodeURIComponent(uri.split(/[?#]/u, 1)[0]!);
  } catch {
    return null;
  }
  if (decoded.includes("\0")) return null;
  if (isAbsolute(decoded)) {
    const canonicalRelative = relative(context.sourceRoot, resolve(decoded));
    if (
      canonicalRelative === "" ||
      canonicalRelative === ".." ||
      canonicalRelative.startsWith(`..${sep}`) ||
      isAbsolute(canonicalRelative)
    ) {
      return null;
    }
    return resolve(context.repository, canonicalRelative);
  }
  const portable = decoded.replaceAll("\\", "/");
  if (
    portable.startsWith("/") ||
    /^[A-Za-z]:/u.test(portable) ||
    portable.split("/").some((part) => part === "..")
  ) {
    return null;
  }
  return resolve(context.repository, portable);
}

async function countLines(path: string, signal?: AbortSignal): Promise<number> {
  const metadata = await stat(path);
  if (metadata.size === 0) return 1;
  let lines = 0;
  let finalByte = -1;
  const stream = createReadStream(path);
  try {
    for await (const chunk of stream) {
      signal?.throwIfAborted();
      const bytes = chunk as Buffer;
      for (const byte of bytes) if (byte === 0x0a) lines++;
      finalByte = bytes.at(-1) ?? finalByte;
    }
  } finally {
    stream.destroy();
  }
  return lines + (finalByte === 0x0a ? 0 : 1);
}

function cwesFromResult(
  result: Record<string, unknown>,
  rule: Record<string, unknown> | undefined,
): string[] {
  const values: string[] = [];
  for (const value of [result["ruleId"], rule?.["id"], rule?.["name"]]) {
    if (typeof value === "string") values.push(value);
  }
  const ruleProperties = isRecord(rule?.["properties"])
    ? rule["properties"]
    : undefined;
  for (const value of [ruleProperties?.["tags"], ruleProperties?.["cwe"]]) {
    collectCweMetadataStrings(value, values);
  }
  const taxa = result["taxa"];
  if (Array.isArray(taxa)) {
    for (const taxon of taxa.slice(0, 64)) {
      if (!isRecord(taxon)) continue;
      for (const value of [taxon["id"], taxon["name"]]) {
        if (typeof value === "string") values.push(value);
      }
    }
  }
  const cwes = new Set<number>();
  for (const value of values) {
    for (const match of value.matchAll(CWE_PATTERN)) {
      const number = Number(match[1]);
      if (Number.isSafeInteger(number) && number > 0) cwes.add(number);
    }
  }
  return [...cwes]
    .sort((left, right) => left - right)
    .map((number) => `CWE-${number}`);
}

function collectCweMetadataStrings(value: unknown, output: string[]): void {
  if (typeof value === "string") {
    if (value.length <= 4_096) output.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 64)) {
      if (typeof item === "string" && item.length <= 4_096) output.push(item);
    }
  }
}

function sarifSeverity(
  result: Record<string, unknown>,
  rule: Record<string, unknown> | undefined,
): string {
  const properties = isRecord(rule?.["properties"])
    ? rule["properties"]
    : undefined;
  const score = properties?.["security-severity"];
  const numericScore = typeof score === "string" ? Number(score) : score;
  if (typeof numericScore === "number" && Number.isFinite(numericScore)) {
    if (numericScore > 9) return "critical";
    if (numericScore >= 7) return "high";
    if (numericScore >= 4) return "medium";
    if (numericScore > 0) return "low";
  }
  const configuration = isRecord(rule?.["defaultConfiguration"])
    ? rule["defaultConfiguration"]
    : undefined;
  const level = result["level"] ?? configuration?.["level"];
  return level === "error"
    ? "high"
    : level === "warning"
      ? "medium"
      : level === "note"
        ? "low"
        : "unknown";
}

function boundedText(value: unknown, label: string): string {
  const text = optionalBoundedText(value);
  if (text === undefined) throw new Error(`${label} must be non-empty text.`);
  return text;
}

function optionalBoundedText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/gu, " ").trim();
  if (!normalized) return undefined;
  return normalized.slice(0, MAX_TEXT_LENGTH);
}

function positiveInteger(value: unknown): number | undefined {
  return Number.isInteger(value) && (value as number) > 0
    ? (value as number)
    : undefined;
}

function isInside(root: string, path: string): boolean {
  const child = relative(root, path);
  return (
    child !== "" &&
    child !== ".." &&
    !child.startsWith(`..${sep}`) &&
    !isAbsolute(child)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
