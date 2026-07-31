import { createHash, randomBytes } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { CopilotSecurityError } from "./errors.js";

const MAX_CAMPAIGN_BYTES = 1024 * 1024;
const MAX_RECEIPT_BYTES = 256 * 1024;
const MAX_FIXTURE_FILES = 10_000;
const MAX_FIXTURE_BYTES = 256 * 1024 * 1024;

export const BENCHMARK_CAMPAIGN_FILENAME = "benchmark-campaign.json";

export interface BenchmarkCampaignScanner {
  cliPath: string;
  cliSha256: string;
  packageSha256: string;
  label: string;
}

export interface BenchmarkCampaignScanPolicy {
  mode: "standard" | "deep";
  model?: string;
  effort?: "low" | "medium" | "high" | "xhigh";
  maxAiCredits?: number;
}

export interface BenchmarkCampaignSelection {
  caseIds: string[];
  findingsPathsByCase: Record<string, string[]>;
  fixtureSha256ByCase: Record<string, string>;
}

export interface BenchmarkCampaignDocument {
  documentType: "copilot-security.benchmark-campaign";
  schemaVersion: "1.0";
  campaignId: string;
  corpusId: string;
  scanPolicyId: string;
  createdAt: string;
  manifest: {
    path: string;
    sha256: string;
  };
  scanner: BenchmarkCampaignScanner;
  source: {
    repositoryRevision: string | null;
    runnerSha256: string;
    runtime: {
      node: string;
      platform: string;
      arch: string;
    };
  };
  selection: BenchmarkCampaignSelection;
  scan: BenchmarkCampaignScanPolicy & {
    auth: "auto" | "github" | "token" | "chatgpt" | "api-key";
  };
}

export interface BenchmarkCampaignIdentityInput {
  createdAt?: string;
  manifestPath: string;
  manifestSha256: string;
  repositoryRevision: string | null;
  runnerSha256: string;
  runtime: BenchmarkCampaignDocument["source"]["runtime"];
  scanner: BenchmarkCampaignScanner;
  selection: BenchmarkCampaignSelection;
  scan: BenchmarkCampaignDocument["scan"];
}

export interface BenchmarkRunReceipt {
  documentType: "copilot-security.benchmark-run";
  schemaVersion: "1.0";
  campaignId: string;
  caseId: string;
  run: number;
  attempt: number;
  status: number;
  signal: string | null;
  timedOut: boolean;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  scanner: BenchmarkCampaignScanner;
  scan: BenchmarkCampaignDocument["scan"];
  fixture: {
    sha256: string;
    repositoryRevision: string;
  };
  artifacts?: {
    scanId: string;
    findingsSha256: string;
    coverageSha256: string;
    manifestSha256: string;
  };
  error?: string;
}

export function createBenchmarkCampaign(
  input: BenchmarkCampaignIdentityInput,
): BenchmarkCampaignDocument {
  if (
    !isSha256(input.manifestSha256) ||
    !isSha256(input.runnerSha256) ||
    !isValidScanner(input.scanner) ||
    !isValidRuntime(input.runtime) ||
    !isValidScan(input.scan)
  ) {
    throw new CopilotSecurityError(
      "Benchmark campaign identity input is invalid.",
    );
  }
  const selection = normalizeSelection(input.selection);
  const scanPolicy: BenchmarkCampaignScanPolicy = {
    mode: input.scan.mode,
    ...(input.scan.model === undefined ? {} : { model: input.scan.model }),
    ...(input.scan.effort === undefined ? {} : { effort: input.scan.effort }),
    ...(input.scan.maxAiCredits === undefined
      ? {}
      : { maxAiCredits: input.scan.maxAiCredits }),
  };
  const corpusId = identityDigest({
    schemaVersion: "1.0",
    manifestSha256: input.manifestSha256,
    selection,
  });
  const scanPolicyId = identityDigest({
    schemaVersion: "1.0",
    ...scanPolicy,
  });
  const campaignId = identityDigest({
    schemaVersion: "1.0",
    corpusId,
    scanPolicyId,
    scanner: {
      cliSha256: input.scanner.cliSha256,
      packageSha256: input.scanner.packageSha256,
      label: input.scanner.label,
    },
    auth: input.scan.auth,
    repositoryRevision: input.repositoryRevision,
    runnerSha256: input.runnerSha256,
    runtime: input.runtime,
  });
  return {
    documentType: "copilot-security.benchmark-campaign",
    schemaVersion: "1.0",
    campaignId,
    corpusId,
    scanPolicyId,
    createdAt: input.createdAt ?? new Date().toISOString(),
    manifest: {
      path: resolve(input.manifestPath),
      sha256: input.manifestSha256,
    },
    scanner: {
      cliPath: resolve(input.scanner.cliPath),
      cliSha256: input.scanner.cliSha256,
      packageSha256: input.scanner.packageSha256,
      label: input.scanner.label,
    },
    source: {
      repositoryRevision: input.repositoryRevision,
      runnerSha256: input.runnerSha256,
      runtime: { ...input.runtime },
    },
    selection,
    scan: {
      ...scanPolicy,
      auth: input.scan.auth,
    },
  };
}

export async function ensureBenchmarkCampaign(
  resultsDirectory: string,
  expected: BenchmarkCampaignDocument,
): Promise<BenchmarkCampaignDocument> {
  const root = resolve(resultsDirectory);
  await mkdir(root, { recursive: true });
  const path = join(root, BENCHMARK_CAMPAIGN_FILENAME);
  let existing: BenchmarkCampaignDocument;
  try {
    existing = parseCampaign(
      await readBounded(path, MAX_CAMPAIGN_BYTES, "benchmark campaign"),
      path,
    );
  } catch (error) {
    if (!isMissing(error)) throw error;
    const entries = await readdir(root);
    if (entries.length > 0) {
      throw new CopilotSecurityError(
        `Benchmark results already exist without ${BENCHMARK_CAMPAIGN_FILENAME}: ${root}. Use a new results directory so scanner revisions and policies cannot be mixed.`,
      );
    }
    await writeJsonAtomic(path, expected);
    return expected;
  }
  if (existing.campaignId !== expected.campaignId) {
    throw new CopilotSecurityError(
      `Benchmark campaign mismatch in ${path}. Existing ${existing.campaignId} uses a different scanner revision, corpus, authentication source, or scan policy; use a new results directory.`,
    );
  }
  if (
    existing.corpusId !== expected.corpusId ||
    existing.scanPolicyId !== expected.scanPolicyId
  ) {
    throw new CopilotSecurityError(
      `Benchmark campaign identity fields are inconsistent in ${path}.`,
    );
  }
  return existing;
}

export async function readBenchmarkCampaign(
  resultsDirectory: string,
): Promise<BenchmarkCampaignDocument | null> {
  const path = join(resolve(resultsDirectory), BENCHMARK_CAMPAIGN_FILENAME);
  try {
    return parseCampaign(
      await readBounded(path, MAX_CAMPAIGN_BYTES, "benchmark campaign"),
      path,
    );
  } catch (error) {
    if (isMissing(error)) return null;
    throw error;
  }
}

export async function readSuccessfulBenchmarkReceipt(
  path: string,
  expected: { campaignId: string; caseId: string; run: number },
): Promise<BenchmarkRunReceipt> {
  const receipt = parseReceipt(
    await readBounded(path, MAX_RECEIPT_BYTES, "benchmark run receipt"),
    path,
  );
  if (
    receipt.campaignId !== expected.campaignId ||
    receipt.caseId !== expected.caseId ||
    receipt.run !== expected.run
  ) {
    throw new CopilotSecurityError(
      `Benchmark run receipt does not match ${expected.caseId} run ${expected.run}: ${path}.`,
    );
  }
  if (
    receipt.status !== 0 ||
    receipt.timedOut ||
    receipt.artifacts === undefined
  ) {
    throw new CopilotSecurityError(
      `Benchmark run receipt is not a completed sealed scan for ${expected.caseId} run ${expected.run}: ${path}.`,
    );
  }
  return receipt;
}

export async function readBenchmarkReceiptAttempt(
  path: string,
): Promise<number | null> {
  try {
    return parseReceipt(
      await readBounded(path, MAX_RECEIPT_BYTES, "benchmark run receipt"),
      path,
    ).attempt;
  } catch (error) {
    if (isMissing(error)) return null;
    return null;
  }
}

export async function writeBenchmarkReceipt(
  path: string,
  receipt: BenchmarkRunReceipt,
): Promise<void> {
  validateReceipt(receipt, path);
  await writeJsonAtomic(path, receipt);
}

export async function preserveBenchmarkAttempt(options: {
  resultsDirectory: string;
  caseId: string;
  run: number;
  attempt: number;
  outputDirectory: string;
  statusPath: string;
}): Promise<string | null> {
  const outputExists = await lstat(options.outputDirectory).catch(() => null);
  const statusExists = await lstat(options.statusPath).catch(() => null);
  if (outputExists === null && statusExists === null) return null;
  const root = resolve(options.resultsDirectory);
  requireContained(root, resolve(options.outputDirectory), "benchmark output");
  requireContained(root, resolve(options.statusPath), "benchmark status");
  const segment = safeCaseSegment(options.caseId);
  const destination = join(
    root,
    ".benchmark-attempts",
    segment,
    `run-${options.run}`,
    `attempt-${options.attempt}`,
  );
  if ((await lstat(destination).catch(() => null)) !== null) {
    throw new CopilotSecurityError(
      `Benchmark attempt archive already exists: ${destination}.`,
    );
  }
  await mkdir(destination, { recursive: true });
  if (outputExists !== null) {
    if (!outputExists.isDirectory() || outputExists.isSymbolicLink()) {
      throw new CopilotSecurityError(
        `Benchmark output is not a regular directory: ${options.outputDirectory}.`,
      );
    }
    await rename(options.outputDirectory, join(destination, "output"));
  }
  if (statusExists !== null) {
    if (!statusExists.isFile() || statusExists.isSymbolicLink()) {
      throw new CopilotSecurityError(
        `Benchmark status is not a regular file: ${options.statusPath}.`,
      );
    }
    await rename(options.statusPath, join(destination, "status.json"));
  }
  return destination;
}

export async function createBenchmarkAttemptOutput(options: {
  resultsDirectory: string;
  outputDirectory: string;
  attempt: number;
}): Promise<string> {
  if (!Number.isSafeInteger(options.attempt) || options.attempt < 1) {
    throw new CopilotSecurityError(
      "Benchmark attempt must be a positive integer.",
    );
  }
  const root = resolve(options.resultsDirectory);
  const output = resolve(options.outputDirectory);
  requireContained(root, output, "benchmark output");
  const parent = dirname(output);
  await mkdir(parent, { recursive: true });
  const staging = await mkdtemp(
    join(parent, `.${basename(output)}.scanner-attempt-${options.attempt}-`),
  );
  requireContained(root, staging, "benchmark attempt output");
  return staging;
}

export async function promoteBenchmarkAttemptOutput(options: {
  resultsDirectory: string;
  attemptOutputDirectory: string;
  outputDirectory: string;
}): Promise<void> {
  const root = resolve(options.resultsDirectory);
  const staging = resolve(options.attemptOutputDirectory);
  const output = resolve(options.outputDirectory);
  requireContained(root, staging, "benchmark attempt output");
  requireContained(root, output, "benchmark output");
  const stagingMetadata = await lstat(staging);
  if (!stagingMetadata.isDirectory() || stagingMetadata.isSymbolicLink()) {
    throw new CopilotSecurityError(
      `Benchmark attempt output is not a regular directory: ${staging}.`,
    );
  }
  if ((await lstat(output).catch(() => null)) !== null) {
    throw new CopilotSecurityError(
      `Benchmark output already exists and cannot be replaced: ${output}.`,
    );
  }
  await rename(staging, output);
}

export async function sha256File(path: string): Promise<string> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new CopilotSecurityError(`Expected a regular file to hash: ${path}.`);
  }
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

export async function sha256Directory(root: string): Promise<string> {
  const canonicalRoot = resolve(root);
  const rootMetadata = await lstat(canonicalRoot);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new CopilotSecurityError(
      `Benchmark fixture is not a regular directory: ${canonicalRoot}.`,
    );
  }
  const files: Array<{ path: string; bytes: Buffer }> = [];
  let totalBytes = 0;
  const pending = [canonicalRoot];
  while (pending.length > 0) {
    const directory = pending.pop()!;
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) {
        throw new CopilotSecurityError(
          `Benchmark fixture contains a symbolic link: ${path}.`,
        );
      }
      if (metadata.isDirectory()) {
        pending.push(path);
        continue;
      }
      if (!metadata.isFile()) {
        throw new CopilotSecurityError(
          `Benchmark fixture contains a non-file entry: ${path}.`,
        );
      }
      const bytes = await readFile(path);
      totalBytes += bytes.byteLength;
      if (files.length >= MAX_FIXTURE_FILES || totalBytes > MAX_FIXTURE_BYTES) {
        throw new CopilotSecurityError(
          `Benchmark fixture exceeds the campaign hashing limit: ${canonicalRoot}.`,
        );
      }
      files.push({
        path: relative(canonicalRoot, path).split(sep).join("/"),
        bytes,
      });
    }
  }
  files.sort((left, right) => left.path.localeCompare(right.path, "en"));
  const digest = createHash("sha256");
  for (const file of files) {
    const pathBytes = Buffer.from(file.path, "utf8");
    const header = Buffer.alloc(16);
    header.writeBigUInt64BE(BigInt(pathBytes.byteLength), 0);
    header.writeBigUInt64BE(BigInt(file.bytes.byteLength), 8);
    digest.update(header).update(pathBytes).update(file.bytes);
  }
  return digest.digest("hex");
}

export async function sha256ScannerPackage(
  packageRoot: string,
): Promise<string> {
  const root = resolve(packageRoot);
  const components: Array<{ path: string; sha256: string }> = [];
  for (const path of ["bin", "dist", "_bundled_plugin"]) {
    components.push({ path, sha256: await sha256Directory(join(root, path)) });
  }
  for (const path of ["package.json", "pnpm-lock.yaml"]) {
    const absolute = join(root, path);
    const metadata = await lstat(absolute).catch(() => null);
    if (metadata === null) {
      if (path === "pnpm-lock.yaml") continue;
      throw new CopilotSecurityError(
        `Scanner package component is missing: ${absolute}.`,
      );
    }
    components.push({ path, sha256: await sha256File(absolute) });
  }
  return identityDigest({ schemaVersion: "1.0", components });
}

function normalizeSelection(
  selection: BenchmarkCampaignSelection,
): BenchmarkCampaignSelection {
  const caseIds = [...selection.caseIds];
  if (
    caseIds.length === 0 ||
    new Set(caseIds).size !== caseIds.length ||
    caseIds.some((id) => typeof id !== "string" || id.length === 0)
  ) {
    throw new CopilotSecurityError(
      "Benchmark campaign selection must contain unique nonempty case IDs.",
    );
  }
  const findingsPathsByCase: Record<string, string[]> = {};
  const fixtureSha256ByCase: Record<string, string> = {};
  for (const caseId of caseIds) {
    const paths = selection.findingsPathsByCase[caseId];
    if (
      !Array.isArray(paths) ||
      paths.length === 0 ||
      paths.some((path) => typeof path !== "string" || path.length === 0)
    ) {
      throw new CopilotSecurityError(
        `Benchmark campaign case has no result paths: ${caseId}.`,
      );
    }
    findingsPathsByCase[caseId] = [...paths];
    const fixtureSha256 = selection.fixtureSha256ByCase[caseId];
    if (!isSha256(fixtureSha256)) {
      throw new CopilotSecurityError(
        `Benchmark campaign case has no fixture digest: ${caseId}.`,
      );
    }
    fixtureSha256ByCase[caseId] = fixtureSha256;
  }
  return { caseIds, findingsPathsByCase, fixtureSha256ByCase };
}

function identityDigest(value: unknown): string {
  return createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right, "en"))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function parseCampaign(bytes: Buffer, path: string): BenchmarkCampaignDocument {
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new CopilotSecurityError(
      `Invalid benchmark campaign JSON: ${path}.`,
      {
        cause: error,
      },
    );
  }
  if (!isRecord(value)) {
    throw new CopilotSecurityError(`Invalid benchmark campaign: ${path}.`);
  }
  const campaign = value as unknown as BenchmarkCampaignDocument;
  if (
    campaign.documentType !== "copilot-security.benchmark-campaign" ||
    campaign.schemaVersion !== "1.0" ||
    !isSha256(campaign.campaignId) ||
    !isSha256(campaign.corpusId) ||
    !isSha256(campaign.scanPolicyId) ||
    typeof campaign.createdAt !== "string" ||
    !isRecord(campaign.manifest) ||
    typeof campaign.manifest.path !== "string" ||
    !isSha256(campaign.manifest.sha256) ||
    !isRecord(campaign.scanner) ||
    typeof campaign.scanner.cliPath !== "string" ||
    !isSha256(campaign.scanner.cliSha256) ||
    !isSha256(campaign.scanner.packageSha256) ||
    typeof campaign.scanner.label !== "string" ||
    !isRecord(campaign.source) ||
    !(
      campaign.source.repositoryRevision === null ||
      typeof campaign.source.repositoryRevision === "string"
    ) ||
    !isSha256(campaign.source.runnerSha256) ||
    !isRecord(campaign.source.runtime) ||
    typeof campaign.source.runtime.node !== "string" ||
    typeof campaign.source.runtime.platform !== "string" ||
    typeof campaign.source.runtime.arch !== "string" ||
    !isRecord(campaign.selection) ||
    !isRecord(campaign.scan)
  ) {
    throw new CopilotSecurityError(`Invalid benchmark campaign: ${path}.`);
  }
  normalizeSelection(campaign.selection);
  const recreated = createBenchmarkCampaign({
    createdAt: campaign.createdAt,
    manifestPath: campaign.manifest.path,
    manifestSha256: campaign.manifest.sha256,
    repositoryRevision: campaign.source.repositoryRevision,
    runnerSha256: campaign.source.runnerSha256,
    runtime: campaign.source.runtime,
    scanner: campaign.scanner,
    selection: campaign.selection,
    scan: campaign.scan,
  });
  if (
    recreated.campaignId !== campaign.campaignId ||
    recreated.corpusId !== campaign.corpusId ||
    recreated.scanPolicyId !== campaign.scanPolicyId ||
    canonicalJson(recreated) !== canonicalJson(campaign)
  ) {
    throw new CopilotSecurityError(
      `Benchmark campaign identity does not match its contents: ${path}.`,
    );
  }
  return campaign;
}

function parseReceipt(bytes: Buffer, path: string): BenchmarkRunReceipt {
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new CopilotSecurityError(`Invalid benchmark run receipt: ${path}.`, {
      cause: error,
    });
  }
  validateReceipt(value, path);
  return value;
}

function validateReceipt(
  value: unknown,
  path: string,
): asserts value is BenchmarkRunReceipt {
  if (!isRecord(value)) {
    throw new CopilotSecurityError(`Invalid benchmark run receipt: ${path}.`);
  }
  const artifacts = value["artifacts"];
  const scanner = value["scanner"];
  const scan = value["scan"];
  const fixture = value["fixture"];
  if (
    value["documentType"] !== "copilot-security.benchmark-run" ||
    value["schemaVersion"] !== "1.0" ||
    !isSha256(value["campaignId"]) ||
    typeof value["caseId"] !== "string" ||
    !Number.isSafeInteger(value["run"]) ||
    (value["run"] as number) <= 0 ||
    !Number.isSafeInteger(value["attempt"]) ||
    (value["attempt"] as number) <= 0 ||
    !Number.isSafeInteger(value["status"]) ||
    !(value["signal"] === null || typeof value["signal"] === "string") ||
    typeof value["timedOut"] !== "boolean" ||
    typeof value["startedAt"] !== "string" ||
    typeof value["completedAt"] !== "string" ||
    !Number.isSafeInteger(value["durationMs"]) ||
    (value["durationMs"] as number) < 0 ||
    !isValidScanner(scanner) ||
    !isValidScan(scan) ||
    !isRecord(fixture) ||
    !isSha256(fixture["sha256"]) ||
    typeof fixture["repositoryRevision"] !== "string" ||
    fixture["repositoryRevision"].length === 0 ||
    !(value["error"] === undefined || typeof value["error"] === "string") ||
    !(
      artifacts === undefined ||
      (isRecord(artifacts) &&
        typeof artifacts["scanId"] === "string" &&
        isSha256(artifacts["findingsSha256"]) &&
        isSha256(artifacts["coverageSha256"]) &&
        isSha256(artifacts["manifestSha256"]))
    ) ||
    (value["status"] === 0 &&
      (value["timedOut"] ||
        artifacts === undefined ||
        value["error"] !== undefined)) ||
    (value["status"] !== 0 && artifacts !== undefined)
  ) {
    throw new CopilotSecurityError(`Invalid benchmark run receipt: ${path}.`);
  }
}

async function readBounded(
  path: string,
  maximum: number,
  label: string,
): Promise<Buffer> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new CopilotSecurityError(`${label} is not a regular file: ${path}.`);
  }
  if (metadata.size > maximum) {
    throw new CopilotSecurityError(
      `${label} exceeds the ${maximum}-byte limit: ${path}.`,
    );
  }
  return readFile(path);
}

async function writeJsonAtomic(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, path);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

function safeCaseSegment(caseId: string): string {
  const slug = caseId
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/gu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, 80);
  const suffix = createHash("sha256")
    .update(caseId, "utf8")
    .digest("hex")
    .slice(0, 12);
  return `${slug || "case"}-${suffix}`;
}

function requireContained(root: string, path: string, label: string): void {
  const child = relative(root, path);
  if (
    child === ".." ||
    child.startsWith(`..${sep}`) ||
    child === "" ||
    child.startsWith(sep)
  ) {
    throw new CopilotSecurityError(
      `${label} escapes its campaign directory: ${path}.`,
    );
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isValidScanner(value: unknown): value is BenchmarkCampaignScanner {
  return (
    isRecord(value) &&
    typeof value["cliPath"] === "string" &&
    value["cliPath"].length > 0 &&
    isSha256(value["cliSha256"]) &&
    isSha256(value["packageSha256"]) &&
    typeof value["label"] === "string" &&
    value["label"].trim().length > 0 &&
    value["label"].length <= 120
  );
}

function isValidRuntime(
  value: unknown,
): value is BenchmarkCampaignDocument["source"]["runtime"] {
  return (
    isRecord(value) &&
    typeof value["node"] === "string" &&
    value["node"].length > 0 &&
    typeof value["platform"] === "string" &&
    value["platform"].length > 0 &&
    typeof value["arch"] === "string" &&
    value["arch"].length > 0
  );
}

function isValidScan(
  value: unknown,
): value is BenchmarkCampaignDocument["scan"] {
  return (
    isRecord(value) &&
    ["auto", "github", "token", "chatgpt", "api-key"].includes(
      String(value["auth"]),
    ) &&
    (value["mode"] === "standard" || value["mode"] === "deep") &&
    (value["model"] === undefined ||
      (typeof value["model"] === "string" && value["model"].length > 0)) &&
    (value["effort"] === undefined ||
      ["low", "medium", "high", "xhigh"].includes(String(value["effort"]))) &&
    (value["maxAiCredits"] === undefined ||
      (typeof value["maxAiCredits"] === "number" &&
        Number.isFinite(value["maxAiCredits"]) &&
        value["maxAiCredits"] >= 30))
  );
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}
