import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { extname, isAbsolute, join, relative, resolve } from "node:path";

const MAX_FILES = 2_000;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_CANDIDATES = 4_096;
const MAX_SIGNALS = 96;

const SOURCE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".clj",
  ".cljs",
  ".cjs",
  ".coffee",
  ".cpp",
  ".cs",
  ".dart",
  ".ex",
  ".exs",
  ".erl",
  ".fs",
  ".fsx",
  ".go",
  ".groovy",
  ".gvy",
  ".h",
  ".hpp",
  ".hrl",
  ".java",
  ".js",
  ".jsx",
  ".kt",
  ".kts",
  ".lua",
  ".m",
  ".mjs",
  ".mm",
  ".php",
  ".pl",
  ".pm",
  ".ps1",
  ".py",
  ".rb",
  ".rego",
  ".rs",
  ".scala",
  ".sh",
  ".sol",
  ".sql",
  ".svelte",
  ".swift",
  ".tf",
  ".ts",
  ".tsx",
  ".vb",
  ".vue",
  ".xml",
  ".yaml",
  ".yml",
]);

const RISK_SIGNALS: ReadonlyArray<
  readonly [category: string, priority: number, expression: RegExp]
> = [
  [
    "archive-or-attacker-path",
    90,
    /\b(?:arcname|entry|filename|member|tarinfo|zipentry)\b|\.(?:filename|getName|name)\b/iu,
  ],
  [
    "filesystem-write",
    80,
    /\b(?:copyfile|createWriteStream|extract|extractall|makedirs|mkdir|move|open|rename|sendFile|write_bytes|write_text|writeFile|writeFileSync)\b/iu,
  ],
  [
    "process-or-shell",
    100,
    /\b(?:child_process|exec|execFile|execSync|popen|ProcessBuilder|Runtime\.getRuntime|shell\s*[:=]\s*true|spawn|spawnSync|subprocess|system)\b/iu,
  ],
  [
    "dynamic-code-or-template",
    95,
    /\b(?:compile|eval|execScript|Function|render|renderString|template)\s*\(/iu,
  ],
  [
    "query-or-object-lookup",
    85,
    /\b(?:execute|findById|findOne|getById|query|raw|select|where)\s*\(/iu,
  ],
  [
    "authorization-boundary",
    85,
    /\b(?:accountId|customerId|objectId|ownerId|req\.params|request\.params|tenantId|userId)\b/iu,
  ],
  [
    "network-request",
    80,
    /\b(?:axios|fetch|http\.get|http\.request|requests\.(?:get|post|put|delete)|urlopen)\s*\(/iu,
  ],
  [
    "parser-or-deserializer",
    90,
    /\b(?:deserialize|load|loads|ObjectInputStream|parse|pickle|readObject|unmarshal|yaml\.load)\s*\(/iu,
  ],
  [
    "cryptographic-verification",
    75,
    /\b(?:crypto|decrypt|encrypt|hash|hmac|jwt|signature|verify)\b/iu,
  ],
  [
    "unsafe-memory-operation",
    95,
    /\b(?:gets|memcpy|scanf|sprintf|strcat|strcpy|vsprintf)\s*\(/iu,
  ],
  [
    "browser-or-response-injection",
    85,
    /\b(?:dangerouslySetInnerHTML|document\.write|innerHTML|mark_safe|redirect|Response\.Write)\b/iu,
  ],
  [
    "disabled-security-control",
    95,
    /\b(?:rejectUnauthorized|verify|verify_mode)\s*[:=]\s*(?:false|0|none)\b/iu,
  ],
];

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".venv",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
]);

interface ResidualRiskRecord {
  path: string;
  line: number;
  categories: string[];
  priority: number;
  excerpt: string;
}

export async function buildResidualRiskInventory(
  repository: string,
  scanDirectory?: string,
): Promise<string> {
  const canonicalRepository = await realpath(repository);
  const inventoryPaths =
    scanDirectory === undefined
      ? []
      : await readModelInventoryPaths(scanDirectory, canonicalRepository);
  const paths =
    inventoryPaths.length > 0
      ? inventoryPaths
      : await discoverSourcePaths(canonicalRepository);
  const records: ResidualRiskRecord[] = [];
  let totalBytes = 0;

  for (const candidatePath of paths.slice(0, MAX_FILES)) {
    if (records.length >= MAX_CANDIDATES) break;
    const source = await readBoundedRepositoryFile(
      canonicalRepository,
      candidatePath,
    );
    if (source === null) continue;
    totalBytes += source.byteLength;
    if (totalBytes > MAX_TOTAL_BYTES) break;
    const text = source.toString("utf8");
    if (text.includes("\0")) continue;
    const lines = text.split(/\r?\n/u);
    for (let index = 0; index < lines.length; index += 1) {
      const matchingSignals = RISK_SIGNALS.filter(([, , expression]) =>
        expression.test(lines[index] ?? ""),
      );
      const categories = matchingSignals.map(([category]) => category);
      if (categories.length === 0) continue;
      const start = Math.max(0, index - 2);
      const end = Math.min(lines.length, index + 3);
      records.push({
        path: candidatePath.replaceAll("\\", "/"),
        line: index + 1,
        categories,
        priority: Math.max(...matchingSignals.map(([, priority]) => priority)),
        excerpt: lines
          .slice(start, end)
          .map((line, offset) => `${start + offset + 1}: ${line}`)
          .join("\n"),
      });
      if (records.length >= MAX_CANDIDATES) break;
    }
  }

  return records
    .sort(
      (left, right) =>
        right.priority - left.priority ||
        left.path.localeCompare(right.path) ||
        left.line - right.line,
    )
    .slice(0, MAX_SIGNALS)
    .map(({ priority: _priority, ...record }) => JSON.stringify(record))
    .join("\n");
}

async function readModelInventoryPaths(
  scanDirectory: string,
  repository: string,
): Promise<string[]> {
  const inventory = await readFile(
    join(scanDirectory, "artifacts", "02_discovery", "in_scope_files.txt"),
    "utf8",
  ).catch(() => "");
  const seen = new Set<string>();
  for (const line of inventory.split(/\r?\n/u)) {
    const candidate = line.trim();
    if (candidate === "" || isAbsolute(candidate) || !isSourcePath(candidate)) {
      continue;
    }
    const relativePath = relative(repository, resolve(repository, candidate));
    if (!isContainedRelativePath(relativePath)) continue;
    seen.add(relativePath);
  }
  return [...seen].sort((left, right) => left.localeCompare(right));
}

async function discoverSourcePaths(repository: string): Promise<string[]> {
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
        !IGNORED_DIRECTORIES.has(entry.name)
      ) {
        pending.push(absolutePath);
      } else if (
        entry.isFile() &&
        !entry.isSymbolicLink() &&
        isSourcePath(entry.name)
      ) {
        paths.push(relative(repository, absolutePath));
      }
    }
  }
  return paths.sort((left, right) => left.localeCompare(right));
}

function isSourcePath(path: string): boolean {
  const baseName = path.replaceAll("\\", "/").split("/").at(-1) ?? "";
  return (
    SOURCE_EXTENSIONS.has(extname(baseName).toLowerCase()) ||
    /^(?:Dockerfile|Gemfile|Jenkinsfile|Makefile|Rakefile)$/u.test(baseName)
  );
}

async function readBoundedRepositoryFile(
  repository: string,
  relativePath: string,
): Promise<Buffer | null> {
  const candidate = resolve(repository, relativePath);
  if (!isContainedRelativePath(relative(repository, candidate))) return null;
  const metadata = await lstat(candidate).catch(() => null);
  if (
    metadata === null ||
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > MAX_FILE_BYTES
  ) {
    return null;
  }
  const canonicalCandidate = await realpath(candidate).catch(() => null);
  if (
    canonicalCandidate === null ||
    !isContainedRelativePath(relative(repository, canonicalCandidate))
  ) {
    return null;
  }
  return await readFile(canonicalCandidate);
}

function isContainedRelativePath(path: string): boolean {
  return (
    path !== "" &&
    path !== ".." &&
    !path.startsWith("..\\") &&
    !path.startsWith("../") &&
    !isAbsolute(path)
  );
}
