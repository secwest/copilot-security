import { createHash, createHmac, randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";
import { ConfigurationError, CopilotSecurityError } from "./errors.js";

const FINGERPRINT_KEY_BYTES = 32;
const MAX_BASELINE_BYTES = 4 * 1024 * 1024;
const MAX_BASELINE_ENTRIES = 10_000;
const MAX_FILES = 4_000;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_CANDIDATES = 2_000;
const BASELINE_SCHEMA_VERSION = "1.0";
const CANDIDATE_SCHEMA_VERSION = "1.0";

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".cache",
  ".gradle",
  ".pnpm-store",
  ".svn",
  ".tox",
  ".venv",
  ".yarn",
  "__pycache__",
  "bin",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "obj",
  "target",
  "vendor",
]);

const BINARY_EXTENSIONS = new Set([
  ".7z",
  ".a",
  ".avi",
  ".bmp",
  ".class",
  ".dll",
  ".dylib",
  ".eot",
  ".exe",
  ".gif",
  ".gz",
  ".ico",
  ".jar",
  ".jpeg",
  ".jpg",
  ".mov",
  ".mp3",
  ".mp4",
  ".o",
  ".obj",
  ".otf",
  ".pdf",
  ".png",
  ".so",
  ".tar",
  ".tgz",
  ".ttf",
  ".webm",
  ".webp",
  ".woff",
  ".woff2",
  ".zip",
]);

interface SecretRule {
  id: string;
  title: string;
  category: string;
  severity: "high" | "critical";
  expression: RegExp;
}

const SECRET_RULES: readonly SecretRule[] = [
  {
    id: "github-token",
    title: "GitHub access token",
    category: "source-control-token",
    severity: "critical",
    expression:
      /\b(?:github_pat_[A-Za-z0-9_]{70,255}|gh[opusr]_[A-Za-z0-9]{36,255})\b/gu,
  },
  {
    id: "gitlab-token",
    title: "GitLab access token",
    category: "source-control-token",
    severity: "critical",
    expression: /\bglpat-[A-Za-z0-9_-]{20,255}\b/gu,
  },
  {
    id: "slack-token",
    title: "Slack token",
    category: "collaboration-token",
    severity: "critical",
    expression: /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/gu,
  },
  {
    id: "stripe-live-secret-key",
    title: "Stripe live secret key",
    category: "payment-token",
    severity: "critical",
    expression: /\bsk_live_[A-Za-z0-9]{16,255}\b/gu,
  },
  {
    id: "npm-access-token",
    title: "npm access token",
    category: "package-registry-token",
    severity: "critical",
    expression: /\bnpm_[A-Za-z0-9]{36,255}\b/gu,
  },
  {
    id: "pypi-upload-token",
    title: "PyPI upload token",
    category: "package-registry-token",
    severity: "critical",
    expression: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{35,255}\b/gu,
  },
  {
    id: "sendgrid-api-key",
    title: "SendGrid API key",
    category: "service-api-key",
    severity: "critical",
    expression: /\bSG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{32,128}\b/gu,
  },
  {
    id: "google-api-key",
    title: "Google API key",
    category: "service-api-key",
    severity: "high",
    expression: /\bAIza[A-Za-z0-9_-]{35}\b/gu,
  },
  {
    id: "aws-access-key-id",
    title: "AWS access key identifier",
    category: "cloud-credential",
    severity: "high",
    expression: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu,
  },
  {
    id: "private-key-material",
    title: "Private key material",
    category: "private-key",
    severity: "critical",
    expression:
      /-----BEGIN (?:DSA |EC |ENCRYPTED |OPENSSH |PGP |RSA )?PRIVATE KEY-----/gu,
  },
];

const GENERIC_ASSIGNMENT =
  /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|client[_-]?secret|consumer[_-]?secret|encryption[_-]?key|password|passwd|private[_-]?key|refresh[_-]?token|secret|signing[_-]?key|token|webhook[_-]?secret)\b\s*(?:=|:|=>)\s*(?:["'`]([^"'`\s]{12,512})["'`]|([A-Za-z0-9_+./=-]{12,512}))/giu;

const PLACEHOLDER_EXPRESSION =
  /(?:attacker|benchmark|changeme|dummy|example|fake|fixture|must[-_]?(?:never|not)|not[-_]?a[-_]?secret|placeholder|redacted|sample|should[-_]?not|synthetic|test(?:ing)?|victim|your[-_]|xxx)/iu;

export interface SecretBaselineEntry {
  fingerprint: string;
  ruleId: string;
  path: string;
  justification: string;
  expiresAt: string;
}

export interface PreparedSecretScanning {
  readonly fingerprintKey: Buffer;
  readonly fingerprintScope: string;
  readonly baselinePath: string;
  readonly baselineEntries: readonly SecretBaselineEntry[];
  readonly baselineIndex: ReadonlyMap<string, SecretBaselineEntry>;
  readonly reportDirectory: string;
}

export interface SecretCandidateShape {
  length: number;
  characterClasses: string[];
  entropyBand: "low" | "medium" | "high";
  redacted: string;
}

export interface SecretCandidateRecord {
  type: "secret_candidate";
  schemaVersion: "1.0";
  ruleId: string;
  title: string;
  category: string;
  severity: "high" | "critical";
  path: string;
  line: number;
  column: number;
  fingerprint: string;
  shape: SecretCandidateShape;
  disposition: "active" | "suppressed";
  baseline?: {
    expiresAt: string;
  };
}

export interface SecretCandidateInventoryResult {
  inventory: string;
  reportPath: string;
  candidateCount: number;
  activeCount: number;
  suppressedCount: number;
  expiredBaselineCount: number;
  scannedFileCount: number;
  truncated: boolean;
}

export class SecretScanningError extends CopilotSecurityError {}

export async function prepareSecretScanning(options: {
  credentialHome: string;
  repositoryScope: string;
  baselinePath?: string;
}): Promise<PreparedSecretScanning> {
  const credentialMetadata = await lstat(options.credentialHome).catch(
    () => null,
  );
  if (
    credentialMetadata === null ||
    !credentialMetadata.isDirectory() ||
    credentialMetadata.isSymbolicLink()
  ) {
    throw new SecretScanningError(
      `Secret scanner credential home is unsafe or unavailable: ${options.credentialHome}`,
    );
  }
  const canonicalCredentialHome = await realpath(options.credentialHome);
  const root = await preparePrivateDirectory(
    join(canonicalCredentialHome, "secret-scanner"),
    canonicalCredentialHome,
  );
  const fingerprintKey = await prepareFingerprintKey(
    join(root, "fingerprint.key"),
  );
  const baselineDirectory = await preparePrivateDirectory(
    join(root, "baselines"),
    root,
  );
  const reportDirectory = await preparePrivateDirectory(
    join(root, "reports"),
    root,
  );
  const fingerprintScope = await realpath(options.repositoryScope);
  const defaultBaselinePath = join(
    baselineDirectory,
    `${createHmac("sha256", fingerprintKey)
      .update("baseline-scope\0")
      .update(fingerprintScope)
      .digest("hex")}.json`,
  );
  const baselinePath =
    options.baselinePath === undefined
      ? defaultBaselinePath
      : resolve(options.baselinePath);
  if (options.baselinePath === undefined) {
    await createDefaultBaseline(baselinePath);
  }
  const baselineEntries = await readSecretBaseline(baselinePath);
  const baselineIndex = new Map(
    baselineEntries.map((entry) => [baselineIdentity(entry), entry]),
  );
  return {
    fingerprintKey,
    fingerprintScope,
    baselinePath,
    baselineEntries,
    baselineIndex,
    reportDirectory,
  };
}

export async function buildSecretCandidateInventory(
  repository: string,
  prepared: PreparedSecretScanning,
  scanId: string,
  now = new Date(),
  includePaths?: readonly string[],
): Promise<SecretCandidateInventoryResult> {
  const canonicalRepository = await realpath(repository);
  const candidates: SecretCandidateRecord[] = [];
  const uniqueIncludedPaths =
    includePaths === undefined ? undefined : [...new Set(includePaths)];
  const paths =
    uniqueIncludedPaths === undefined
      ? await discoverCandidatePaths(canonicalRepository)
      : uniqueIncludedPaths
          .filter(isContainedRelativePath)
          .slice(0, MAX_FILES)
          .sort((left, right) => left.localeCompare(right));
  let truncated =
    paths.length >= MAX_FILES ||
    (uniqueIncludedPaths !== undefined &&
      uniqueIncludedPaths.length > MAX_FILES);
  let totalBytes = 0;
  let scannedFileCount = 0;
  for (const path of paths) {
    if (candidates.length >= MAX_CANDIDATES) break;
    const absolutePath = resolve(canonicalRepository, path);
    const metadata = await lstat(absolutePath).catch(() => null);
    if (
      metadata === null ||
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.size > MAX_FILE_BYTES
    ) {
      continue;
    }
    totalBytes += metadata.size;
    if (totalBytes > MAX_TOTAL_BYTES) {
      truncated = true;
      break;
    }
    const canonicalPath = await realpath(absolutePath).catch(() => null);
    if (
      canonicalPath === null ||
      !isContainedPath(canonicalRepository, canonicalPath)
    ) {
      continue;
    }
    const bytes = await readFile(canonicalPath).catch(() => null);
    if (bytes === null || bytes.includes(0)) continue;
    const text = bytes.toString("utf8");
    if (replacementCharacterRatio(text) > 0.01) continue;
    scannedFileCount += 1;
    candidates.push(
      ...candidateRecordsForText(
        text,
        path.replaceAll("\\", "/"),
        prepared,
        now,
        MAX_CANDIDATES - candidates.length,
      ),
    );
    if (candidates.length >= MAX_CANDIDATES) truncated = true;
  }

  candidates.sort(compareCandidateRecords);
  const active = candidates.filter(
    (candidate) => candidate.disposition === "active",
  );
  const suppressed = candidates.length - active.length;
  const activeFingerprints = new Set(
    candidates.map((candidate) => candidate.fingerprint),
  );
  const expiredBaselineCount = prepared.baselineEntries.filter(
    (entry) =>
      activeFingerprints.has(entry.fingerprint) &&
      Date.parse(entry.expiresAt) <= now.getTime(),
  ).length;
  const reportPath = join(
    prepared.reportDirectory,
    `${safeStateComponent(scanId)}.jsonl`,
  );
  const summary = {
    type: "secret_candidate_summary",
    schemaVersion: CANDIDATE_SCHEMA_VERSION,
    scannedFileCount,
    candidateCount: candidates.length,
    activeCount: active.length,
    suppressedCount: suppressed,
    expiredBaselineCount,
    truncated,
    limits: {
      maxFiles: MAX_FILES,
      maxFileBytes: MAX_FILE_BYTES,
      maxTotalBytes: MAX_TOTAL_BYTES,
      maxCandidates: MAX_CANDIDATES,
    },
    baselinePath: prepared.baselinePath,
  };
  await writePrivateJsonLines(reportPath, [summary, ...candidates]);
  const inventory = [
    JSON.stringify({
      ...summary,
      baselinePath: undefined,
    }),
    ...active.map((candidate) => JSON.stringify(candidate)),
  ].join("\n");
  return {
    inventory,
    reportPath,
    candidateCount: candidates.length,
    activeCount: active.length,
    suppressedCount: suppressed,
    expiredBaselineCount,
    scannedFileCount,
    truncated,
  };
}

export async function readSecretBaseline(
  baselinePath: string,
): Promise<SecretBaselineEntry[]> {
  const metadata = await lstat(baselinePath).catch(() => null);
  if (metadata === null) {
    throw new ConfigurationError(
      `Secret baseline does not exist: ${baselinePath}`,
    );
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > MAX_BASELINE_BYTES
  ) {
    throw new ConfigurationError(
      `Secret baseline must be a regular file no larger than ${MAX_BASELINE_BYTES} bytes: ${baselinePath}`,
    );
  }
  const bytes = await readFile(baselinePath);
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new ConfigurationError(
      `Secret baseline is not valid JSON: ${baselinePath}`,
      {
        cause: error,
      },
    );
  }
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["entries", "schemaVersion"]) ||
    value["schemaVersion"] !== BASELINE_SCHEMA_VERSION
  ) {
    throw new ConfigurationError(
      `Secret baseline must use schemaVersion ${BASELINE_SCHEMA_VERSION}: ${baselinePath}`,
    );
  }
  const entries = value["entries"];
  if (!Array.isArray(entries)) {
    throw new ConfigurationError(
      `Secret baseline entries must be an array: ${baselinePath}`,
    );
  }
  if (entries.length > MAX_BASELINE_ENTRIES) {
    throw new ConfigurationError(
      `Secret baseline contains more than ${MAX_BASELINE_ENTRIES} entries: ${baselinePath}`,
    );
  }
  const seen = new Set<string>();
  return entries.map((entry, index) => {
    if (
      !isRecord(entry) ||
      !hasExactKeys(entry, [
        "expiresAt",
        "fingerprint",
        "justification",
        "path",
        "ruleId",
      ])
    ) {
      throw invalidBaselineEntry(baselinePath, index);
    }
    const fingerprint = entry["fingerprint"];
    const ruleId = entry["ruleId"];
    const path = entry["path"];
    const justification = entry["justification"];
    const expiresAt = entry["expiresAt"];
    if (
      typeof fingerprint !== "string" ||
      !/^hmac-sha256:[a-f0-9]{64}$/u.test(fingerprint) ||
      typeof ruleId !== "string" ||
      !/^[a-z0-9][a-z0-9-]{0,63}$/u.test(ruleId) ||
      typeof path !== "string" ||
      !isContainedRelativePath(path) ||
      typeof justification !== "string" ||
      justification.trim().length < 8 ||
      typeof expiresAt !== "string" ||
      !isCanonicalUtcTimestamp(expiresAt)
    ) {
      throw invalidBaselineEntry(baselinePath, index);
    }
    const normalizedPath = path.replaceAll("\\", "/");
    const identity = baselineIdentity({
      fingerprint,
      ruleId,
      path: normalizedPath,
    });
    if (seen.has(identity)) {
      throw new ConfigurationError(
        `Secret baseline contains a duplicate entry at index ${index}: ${baselinePath}`,
      );
    }
    seen.add(identity);
    return {
      fingerprint,
      ruleId,
      path: normalizedPath,
      justification: justification.trim(),
      expiresAt,
    };
  });
}

function candidateRecordsForText(
  text: string,
  path: string,
  prepared: PreparedSecretScanning,
  now: Date,
  limit: number,
): SecretCandidateRecord[] {
  const matches: Array<{
    rule: SecretRule;
    secret: string;
    index: number;
    end: number;
  }> = [];
  for (const rule of SECRET_RULES) {
    const expression = new RegExp(
      rule.expression.source,
      rule.expression.flags,
    );
    for (const match of text.matchAll(expression)) {
      if (match.index === undefined || match[0] === "") continue;
      matches.push({
        rule,
        secret: match[0],
        index: match.index,
        end: match.index + match[0].length,
      });
    }
  }
  const genericRule: SecretRule = {
    id: "generic-high-entropy-secret",
    title: "High-entropy assigned secret",
    category: "generic-credential",
    severity: "high",
    expression: GENERIC_ASSIGNMENT,
  };
  const genericExpression = new RegExp(
    GENERIC_ASSIGNMENT.source,
    GENERIC_ASSIGNMENT.flags,
  );
  for (const match of text.matchAll(genericExpression)) {
    const secret = match[1] ?? match[2];
    if (match.index === undefined || secret === undefined) continue;
    if (match[2] !== undefined && !allowsUnquotedSecret(path)) continue;
    const relativeIndex = match[0].indexOf(secret);
    const index = match.index + relativeIndex;
    const end = index + secret.length;
    if (
      PLACEHOLDER_EXPRESSION.test(secret) ||
      /^\$\{[^}\r\n]+\}$/u.test(secret) ||
      shannonEntropy(secret) < 3.5 ||
      matches.some(
        (candidate) => index < candidate.end && end > candidate.index,
      )
    ) {
      continue;
    }
    matches.push({ rule: genericRule, secret, index, end });
  }
  matches.sort(
    (left, right) =>
      left.index - right.index || left.rule.id.localeCompare(right.rule.id),
  );
  const seen = new Set<string>();
  const records: SecretCandidateRecord[] = [];
  const lineStarts = sourceLineStarts(text);
  for (const match of matches) {
    if (records.length >= limit) break;
    const fingerprint = secretFingerprint(
      prepared.fingerprintKey,
      prepared.fingerprintScope,
      match.rule.id,
      path,
      match.secret,
    );
    const identity = `${match.rule.id}\0${path}\0${match.index}\0${fingerprint}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    const indexedBaseline = prepared.baselineIndex.get(
      baselineIdentity({ fingerprint, ruleId: match.rule.id, path }),
    );
    if (
      indexedBaseline !== undefined &&
      indexedBaseline.justification.includes(match.secret)
    ) {
      throw new SecretScanningError(
        `Secret baseline justification contains candidate bytes: ${prepared.baselinePath}`,
      );
    }
    const baseline =
      indexedBaseline !== undefined &&
      Date.parse(indexedBaseline.expiresAt) > now.getTime()
        ? indexedBaseline
        : undefined;
    const location = lineAndColumn(lineStarts, match.index);
    records.push({
      type: "secret_candidate",
      schemaVersion: CANDIDATE_SCHEMA_VERSION,
      ruleId: match.rule.id,
      title: match.rule.title,
      category: match.rule.category,
      severity: match.rule.severity,
      path,
      line: location.line,
      column: location.column,
      fingerprint,
      shape: secretShape(match.secret),
      disposition: baseline === undefined ? "active" : "suppressed",
      ...(baseline === undefined
        ? {}
        : {
            baseline: {
              expiresAt: baseline.expiresAt,
            },
          }),
    });
  }
  return records;
}

function allowsUnquotedSecret(path: string): boolean {
  const name = path.replaceAll("\\", "/").split("/").at(-1) ?? "";
  return (
    name === ".env" ||
    name.startsWith(".env.") ||
    /\.(?:cfg|conf|env|ini|properties|toml|ya?ml)$/iu.test(name)
  );
}

function secretFingerprint(
  key: Buffer,
  scope: string,
  ruleId: string,
  path: string,
  secret: string,
): string {
  const digest = createHmac("sha256", key)
    .update(JSON.stringify([scope, ruleId, path, secret]))
    .digest("hex");
  return `hmac-sha256:${digest}`;
}

function secretShape(secret: string): SecretCandidateShape {
  const classes: string[] = [];
  if (/[a-z]/u.test(secret)) classes.push("lower");
  if (/[A-Z]/u.test(secret)) classes.push("upper");
  if (/[0-9]/u.test(secret)) classes.push("digit");
  if (/[^A-Za-z0-9]/u.test(secret)) classes.push("symbol");
  const entropy = shannonEntropy(secret);
  return {
    length: secret.length,
    characterClasses: classes,
    entropyBand: entropy >= 4.5 ? "high" : entropy >= 3.5 ? "medium" : "low",
    redacted: `[redacted:${secret.length}]`,
  };
}

function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

async function discoverCandidatePaths(repository: string): Promise<string[]> {
  const paths: string[] = [];
  const pending = [repository];
  while (pending.length > 0 && paths.length < MAX_FILES) {
    const directory = pending.pop();
    if (directory === undefined) break;
    const entries = await readdir(directory, { withFileTypes: true }).catch(
      () => [],
    );
    entries.sort((left, right) => right.name.localeCompare(left.name));
    for (const entry of entries) {
      if (paths.length >= MAX_FILES) break;
      const absolutePath = join(directory, entry.name);
      if (
        entry.isDirectory() &&
        !entry.isSymbolicLink() &&
        !IGNORED_DIRECTORIES.has(entry.name.toLowerCase())
      ) {
        pending.push(absolutePath);
      } else if (
        entry.isFile() &&
        !entry.isSymbolicLink() &&
        !BINARY_EXTENSIONS.has(extension(entry.name))
      ) {
        paths.push(relative(repository, absolutePath));
      }
    }
  }
  return paths.sort((left, right) => left.localeCompare(right));
}

async function preparePrivateDirectory(
  path: string,
  protectedRoot: string,
): Promise<string> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new SecretScanningError(
      `Secret scanner state is not a directory: ${path}`,
    );
  }
  if (process.platform !== "win32") await chmod(path, 0o700);
  const canonical = await realpath(path);
  if (!isContainedPath(protectedRoot, canonical)) {
    throw new SecretScanningError(
      `Secret scanner state escaped its private home: ${path}`,
    );
  }
  return canonical;
}

async function prepareFingerprintKey(path: string): Promise<Buffer> {
  try {
    const handle = await open(path, "wx", 0o600);
    try {
      await handle.writeFile(randomBytes(FINGERPRINT_KEY_BYTES));
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (nodeErrorCode(error) !== "EEXIST") {
      throw new SecretScanningError(
        `Unable to create the secret fingerprint key: ${path}`,
        {
          cause: error,
        },
      );
    }
  }
  const metadata = await lstat(path).catch(() => null);
  if (
    metadata === null ||
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size !== FINGERPRINT_KEY_BYTES
  ) {
    throw new SecretScanningError(
      `Secret fingerprint key is unsafe or invalid: ${path}`,
    );
  }
  if (process.platform !== "win32") await chmod(path, 0o600);
  const key = await readFile(path);
  if (key.byteLength !== FINGERPRINT_KEY_BYTES) {
    throw new SecretScanningError(
      `Secret fingerprint key has an invalid length: ${path}`,
    );
  }
  return key;
}

async function createDefaultBaseline(path: string): Promise<void> {
  try {
    const handle = await open(path, "wx", 0o600);
    try {
      await handle.writeFile(
        `${JSON.stringify({ schemaVersion: BASELINE_SCHEMA_VERSION, entries: [] }, null, 2)}\n`,
      );
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (nodeErrorCode(error) !== "EEXIST") {
      throw new SecretScanningError(
        `Unable to create the secret baseline: ${path}`,
        {
          cause: error,
        },
      );
    }
  }
}

async function writePrivateJsonLines(
  path: string,
  values: readonly unknown[],
): Promise<void> {
  const temporaryPath = join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  const handle = await open(temporaryPath, "wx", 0o600);
  try {
    await handle.writeFile(
      `${values.map((value) => JSON.stringify(value)).join("\n")}\n`,
    );
    await handle.sync();
  } catch (error) {
    throw new SecretScanningError(
      `Unable to write the redacted secret report: ${path}`,
      {
        cause: error,
      },
    );
  } finally {
    await handle.close();
  }
  await rename(temporaryPath, path).catch((error) => {
    throw new SecretScanningError(
      `Unable to publish the redacted secret report: ${path}`,
      {
        cause: error,
      },
    );
  });
}

function sourceLineStarts(text: string): number[] {
  const starts = [0];
  for (
    let index = text.indexOf("\n");
    index >= 0;
    index = text.indexOf("\n", index + 1)
  ) {
    starts.push(index + 1);
  }
  return starts;
}

function lineAndColumn(
  lineStarts: readonly number[],
  index: number,
): { line: number; column: number } {
  let low = 0;
  let high = lineStarts.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if ((lineStarts[middle] ?? 0) <= index) low = middle + 1;
    else high = middle;
  }
  const lineIndex = Math.max(0, low - 1);
  return {
    line: lineIndex + 1,
    column: index - (lineStarts[lineIndex] ?? 0) + 1,
  };
}

function compareCandidateRecords(
  left: SecretCandidateRecord,
  right: SecretCandidateRecord,
): number {
  return (
    left.path.localeCompare(right.path) ||
    left.line - right.line ||
    left.column - right.column ||
    left.ruleId.localeCompare(right.ruleId)
  );
}

function replacementCharacterRatio(text: string): number {
  if (text.length === 0) return 0;
  let replacements = 0;
  for (const character of text) {
    if (character === "\uFFFD") replacements += 1;
  }
  return replacements / text.length;
}

function isContainedPath(root: string, candidate: string): boolean {
  return isContainedRelativePath(relative(root, candidate));
}

function isContainedRelativePath(path: string): boolean {
  const normalized = path.replaceAll("\\", "/");
  const segments = normalized.split("/");
  return (
    path.length > 0 &&
    path !== "." &&
    !path.includes("\0") &&
    !isAbsolute(path) &&
    !/^[A-Za-z]:/u.test(path) &&
    segments.every(
      (segment) => segment.length > 0 && segment !== "." && segment !== "..",
    )
  );
}

function safeStateComponent(value: string): string {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value)
    ? value
    : createHash("sha256").update(value).digest("hex");
}

function extension(path: string): string {
  const index = path.lastIndexOf(".");
  return index < 0 ? "" : path.slice(index).toLowerCase();
}

function baselineIdentity(
  entry: Pick<SecretBaselineEntry, "fingerprint" | "ruleId" | "path">,
): string {
  return `${entry.fingerprint}\0${entry.ruleId}\0${entry.path}`;
}

function isCanonicalUtcTimestamp(value: string): boolean {
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}

function invalidBaselineEntry(path: string, index: number): ConfigurationError {
  return new ConfigurationError(
    `Secret baseline entry ${index} is invalid; exact fingerprint, ruleId, relative path, justification, and canonical UTC expiresAt are required: ${path}`,
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort((left, right) =>
    left.localeCompare(right),
  );
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function nodeErrorCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error["code"] === "string"
    ? error["code"]
    : undefined;
}
