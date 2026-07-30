import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { extname, isAbsolute, join, relative, resolve } from "node:path";

const MAX_FILES = 2_000;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_CANDIDATES = 4_096;
const MAX_SIGNALS = 96;
const MAX_SIGNALS_PER_FILE = MAX_SIGNALS;
const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const MAX_EXCERPT_LINES = 16;
const SOFT_SIGNALS_PER_FILE = 4;

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
    "untrusted-input",
    92,
    /\b(?:req|request)\.(?:body|cookies|data|files|form|headers|params|query|values)\b|\b(?:process|sys)\.argv\b|\b(?:environ|getenv|stdin)\b|\bgetParameter\s*\(/iu,
  ],
  [
    "authentication-or-session",
    94,
    /\b(?:authorization|bearer|cookie|jwt|login|oauth|oidc|session|token)\b|\b(?:authenticate|decode|verify)\s*\(/iu,
  ],
  [
    "filesystem-write",
    80,
    /\b(?:copyfile|createWriteStream|extract|extractall|makedirs|mkdir|move|open|rename|sendFile|write_bytes|write_text|writeFile|writeFileSync)\b/iu,
  ],
  [
    "process-or-shell",
    100,
    /\b(?:child_process|execFile|execSync|popen|ProcessBuilder|Runtime\.getRuntime|spawn|spawnSync|subprocess)\b|\b(?:exec|system)\s*\(|\bshell\s*[:=]\s*true\b/iu,
  ],
  [
    "dynamic-code-or-template",
    95,
    /\b(?:compile|eval|execScript|Function|render|renderString|template)\s*\(/iu,
  ],
  [
    "dynamic-property-or-prototype",
    96,
    /\b(?:__proto__|Object\.assign|Object\.setPrototypeOf|prototype)\b|\[[A-Za-z_$][\w$]*\]\s*(?:=|\?\?=|\|\|=)/iu,
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
    "xml-or-entity-parser",
    93,
    /\b(?:DocumentBuilderFactory|fromstring|lxml|SAXParserFactory|XMLParser)\b|\b(?:disallow-doctype-decl|external-general-entities|load_dtd|no_network|resolve_entities)\b/iu,
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
    /\b(?:dangerouslySetInnerHTML|document\.write|innerHTML|mark_safe|redirect|Response\.Write)\b|\.(?:send|write)\s*\(/iu,
  ],
  [
    "disabled-security-control",
    95,
    /\b(?:check_hostname|rejectUnauthorized|verify|verify_mode)\s*[:=]\s*(?:false|0|none|ssl\.CERT_NONE)\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b/iu,
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
  startLine: number;
  endLine: number;
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
    let fileRecords: ResidualRiskRecord[] = [];
    const retainedFileRecords: ResidualRiskRecord[] = [];
    for (let index = 0; index < lines.length; index += 1) {
      const matchingSignals = RISK_SIGNALS.filter(([, , expression]) =>
        expression.test(lines[index] ?? ""),
      );
      const categories = matchingSignals.map(([category]) => category);
      if (categories.length === 0) continue;
      const startLine = Math.max(1, index + 1 - CONTEXT_LINES_BEFORE);
      const endLine = Math.min(lines.length, index + 1 + CONTEXT_LINES_AFTER);
      mergeResidualRiskRecord(fileRecords, lines, {
        path: candidatePath.replaceAll("\\", "/"),
        line: index + 1,
        categories,
        priority: Math.max(...matchingSignals.map(([, priority]) => priority)),
        startLine,
        endLine,
        excerpt: "",
      });
      if (fileRecords.length >= MAX_CANDIDATES) {
        retainedFileRecords.push(
          ...selectResidualRiskRecords(fileRecords, MAX_SIGNALS_PER_FILE),
        );
        fileRecords = [];
      }
    }
    records.push(
      ...selectResidualRiskRecords(
        [...retainedFileRecords, ...fileRecords],
        MAX_SIGNALS_PER_FILE,
      ),
    );
  }

  return selectResidualRiskRecords(records, MAX_SIGNALS)
    .map(
      ({
        priority: _priority,
        startLine: _startLine,
        endLine: _endLine,
        ...record
      }) => JSON.stringify(record),
    )
    .join("\n");
}

function mergeResidualRiskRecord(
  records: ResidualRiskRecord[],
  lines: readonly string[],
  next: ResidualRiskRecord,
): void {
  const previous = records.at(-1);
  if (
    previous !== undefined &&
    next.startLine <= previous.endLine + 1 &&
    Math.max(previous.endLine, next.endLine) -
      Math.min(previous.startLine, next.startLine) +
      1 <=
      MAX_EXCERPT_LINES
  ) {
    previous.categories = [
      ...new Set([...previous.categories, ...next.categories]),
    ];
    if (next.priority > previous.priority) {
      previous.line = next.line;
    }
    previous.priority = Math.max(previous.priority, next.priority);
    previous.startLine = Math.min(previous.startLine, next.startLine);
    previous.endLine = Math.max(previous.endLine, next.endLine);
    previous.excerpt = sourceExcerpt(
      lines,
      previous.startLine,
      previous.endLine,
    );
    return;
  }
  next.excerpt = sourceExcerpt(lines, next.startLine, next.endLine);
  records.push(next);
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

function selectResidualRiskRecords(
  records: readonly ResidualRiskRecord[],
  limit: number,
): ResidualRiskRecord[] {
  const ranked = [...records].sort(compareResidualRiskRecords);
  const selected: ResidualRiskRecord[] = [];
  const selectedRecords = new Set<ResidualRiskRecord>();
  const add = (record: ResidualRiskRecord): void => {
    if (selected.length >= limit || selectedRecords.has(record)) {
      return;
    }
    selected.push(record);
    selectedRecords.add(record);
  };

  const representedCategories = new Set<string>();
  for (const record of ranked) {
    if (
      record.categories.some((category) => !representedCategories.has(category))
    ) {
      add(record);
      record.categories.forEach((category) =>
        representedCategories.add(category),
      );
    }
  }

  const representedPaths = new Set(selected.map((record) => record.path));
  const pathSeedLimit = Math.floor(limit / 2);
  for (const record of ranked) {
    if (selected.length >= pathSeedLimit || representedPaths.has(record.path)) {
      continue;
    }
    add(record);
    representedPaths.add(record.path);
  }

  const selectedPerPath = new Map<string, number>();
  for (const record of selected) {
    selectedPerPath.set(
      record.path,
      (selectedPerPath.get(record.path) ?? 0) + 1,
    );
  }
  for (const record of ranked) {
    if ((selectedPerPath.get(record.path) ?? 0) >= SOFT_SIGNALS_PER_FILE) {
      continue;
    }
    const before = selected.length;
    add(record);
    if (selected.length > before) {
      selectedPerPath.set(
        record.path,
        (selectedPerPath.get(record.path) ?? 0) + 1,
      );
    }
  }

  for (const record of ranked) add(record);
  return selected.sort(compareResidualRiskRecords);
}

function compareResidualRiskRecords(
  left: ResidualRiskRecord,
  right: ResidualRiskRecord,
): number {
  return (
    right.priority - left.priority ||
    left.path.localeCompare(right.path) ||
    left.line - right.line
  );
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
