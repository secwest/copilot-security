const CONTEXT_LINES_BEFORE = 5;
const CONTEXT_LINES_AFTER = 7;
const MAX_RECORDS = 64;
const MAX_SOURCE_CHARACTERS = 512 * 1024;

const MCP_MODULES = new Set([
  "@modelcontextprotocol/server",
  "@modelcontextprotocol/sdk/server/mcp.js",
]);
const CHILD_PROCESS_MODULES = new Set(["child_process", "node:child_process"]);
const VM_MODULES = new Set(["vm", "node:vm"]);
const WORKER_THREAD_MODULES = new Set([
  "worker_threads",
  "node:worker_threads",
]);
const SQLITE_MODULES = new Set(["node:sqlite"]);
const FS_MODULES = new Set([
  "fs",
  "fs/promises",
  "node:fs",
  "node:fs/promises",
]);
const FETCH_MODULES = new Set(["node-fetch", "undici"]);
const HTTP_MODULES = new Set(["http", "https", "node:http", "node:https"]);
const SOURCE_EXTENSIONS = new Set(["cjs", "js", "jsx", "mjs", "ts", "tsx"]);
const EXCLUDED_PATH_PARTS = new Set([
  "__fixtures__",
  "__mocks__",
  "__tests__",
  "coverage",
  "dist",
  "fixtures",
  "generated",
  "mocks",
  "node_modules",
  "test",
  "tests",
]);
const COMMAND_METHODS = new Set([
  "exec",
  "execFile",
  "execFileSync",
  "execSync",
  "fork",
  "spawn",
  "spawnSync",
]);
const SHELL_METHODS = new Set(["exec", "execSync"]);
const SPAWN_METHODS = new Set(["spawn", "spawnSync"]);
const ARRAY_ARGUMENT_METHODS = new Set([
  "execFile",
  "execFileSync",
  "spawn",
  "spawnSync",
]);
const FILESYSTEM_PATH_ARGUMENTS = new Map<string, readonly number[]>([
  ["access", [0]],
  ["accessSync", [0]],
  ["appendFile", [0]],
  ["appendFileSync", [0]],
  ["chmod", [0]],
  ["chmodSync", [0]],
  ["chown", [0]],
  ["chownSync", [0]],
  ["copyFile", [0, 1]],
  ["copyFileSync", [0, 1]],
  ["cp", [0, 1]],
  ["cpSync", [0, 1]],
  ["createReadStream", [0]],
  ["createWriteStream", [0]],
  ["existsSync", [0]],
  ["lchmod", [0]],
  ["lchmodSync", [0]],
  ["lchown", [0]],
  ["lchownSync", [0]],
  ["link", [0, 1]],
  ["linkSync", [0, 1]],
  ["lstat", [0]],
  ["lstatSync", [0]],
  ["lutimes", [0]],
  ["lutimesSync", [0]],
  ["mkdir", [0]],
  ["mkdirSync", [0]],
  ["mkdtemp", [0]],
  ["mkdtempSync", [0]],
  ["open", [0]],
  ["openAsBlob", [0]],
  ["openSync", [0]],
  ["opendir", [0]],
  ["opendirSync", [0]],
  ["readdir", [0]],
  ["readdirSync", [0]],
  ["readFile", [0]],
  ["readFileSync", [0]],
  ["readlink", [0]],
  ["readlinkSync", [0]],
  ["realpath", [0]],
  ["realpathSync", [0]],
  ["rename", [0, 1]],
  ["renameSync", [0, 1]],
  ["rm", [0]],
  ["rmSync", [0]],
  ["rmdir", [0]],
  ["rmdirSync", [0]],
  ["stat", [0]],
  ["statSync", [0]],
  ["statfs", [0]],
  ["statfsSync", [0]],
  ["symlink", [0, 1]],
  ["symlinkSync", [0, 1]],
  ["truncate", [0]],
  ["truncateSync", [0]],
  ["unlink", [0]],
  ["unlinkSync", [0]],
  ["unwatchFile", [0]],
  ["utimes", [0]],
  ["utimesSync", [0]],
  ["watch", [0]],
  ["watchFile", [0]],
  ["writeFile", [0]],
  ["writeFileSync", [0]],
]);
const NETWORK_METHODS = new Set([
  "delete",
  "fetch",
  "get",
  "head",
  "options",
  "patch",
  "post",
  "put",
  "request",
]);
const IMMEDIATE_VM_EVALUATORS = new Set([
  "runInContext",
  "runInNewContext",
  "runInThisContext",
]);
const VM_CODE_CONSTRUCTORS = new Set([
  "compileFunction",
  "Script",
  "SourceTextModule",
]);
const POSIX_SHELLS = new Set(["ash", "bash", "dash", "ksh", "sh", "zsh"]);
const POWERSHELLS = new Set([
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
]);

type McpModelId =
  | "node-mcp-tool-argument-injection"
  | "node-mcp-tool-code-injection"
  | "node-mcp-tool-command-injection"
  | "node-mcp-tool-path-traversal"
  | "node-mcp-tool-regex-injection"
  | "node-mcp-tool-sql-injection"
  | "node-mcp-tool-ssrf";
type McpSinkKind =
  | "mcp-tool-code-evaluation"
  | "mcp-tool-worker-code-evaluation"
  | "mcp-tool-executable-selection"
  | "mcp-tool-filesystem-path"
  | "mcp-tool-interpreter-option"
  | "mcp-tool-network-destination"
  | "mcp-tool-regular-expression"
  | "mcp-tool-sql-query"
  | "mcp-tool-shell-command"
  | "mcp-tool-shell-enabled-spawn";

interface BindingSet {
  direct: Map<string, string>;
  namespaces: Map<string, string>;
}

interface Range {
  start: number;
  end: number;
}

interface SourceBinding {
  name: string;
  line: number;
  expression: RegExp;
}

interface TaintBinding extends SourceBinding {
  definedAt: number;
  propagators: Array<{ kind: string; line: number; symbol?: string }>;
}

interface Registration {
  method: "registerTool" | "tool";
  server: string;
  toolName: string;
  line: number;
  body: Range;
  sources: SourceBinding[];
}

interface Sink {
  kind: McpSinkKind;
  line: number;
  symbol: string;
  source: TaintBinding;
  viaHelper?: boolean;
}

export interface NodeMcpToolRiskRecord {
  path: string;
  line: number;
  categories: string[];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: McpModelId;
    language: "javascript-typescript";
    scope: "same-file";
    source: {
      kind: "mcp-tool-input";
      path: string;
      line: number;
      symbol: string;
    };
    sink: {
      kind: McpSinkKind;
      path: string;
      line: number;
      symbol: string;
      cweIds:
        | readonly ["CWE-22", "CWE-73"]
        | readonly ["CWE-78", "CWE-88"]
        | readonly ["CWE-88", "CWE-94"]
        | readonly ["CWE-89"]
        | readonly ["CWE-94", "CWE-95"]
        | readonly ["CWE-400", "CWE-730"]
        | readonly ["CWE-918"];
    };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

/**
 * Finds exact MCP SDK tool-input flows to Node process, code-evaluation,
 * regular-expression, SQL, filesystem, and network sinks. The pass is
 * intentionally bounded and ownership-sensitive: unresolved imports, schema-less v2
 * callbacks, unsupported callback forms, and shadowed globals produce no
 * framework row for later stages to over-trust.
 */
export function nodeMcpToolRiskRecords(
  path: string,
  lines: readonly string[],
  source: string,
): NodeMcpToolRiskRecord[] {
  const normalizedPath = path.replaceAll("\\", "/");
  if (!ownsPath(normalizedPath) || source.length > MAX_SOURCE_CHARACTERS)
    return [];
  const structural = maskJavascript(source);
  const imports = importBindings(source, structural);
  const mcpClasses = importedNames(imports, MCP_MODULES, "McpServer");
  if (mcpClasses.size === 0) return [];
  const servers = constructedServers(structural, mcpClasses);
  if (servers.size === 0) return [];
  const registrations = toolRegistrations(source, structural, servers);
  if (registrations.length === 0) return [];

  const commandBindings = bindingsForModules(imports, CHILD_PROCESS_MODULES);
  const evaluationBindings = bindingsForModules(imports, VM_MODULES);
  for (const [local, imported] of evaluationBindings.direct) {
    if (imported === "default") {
      evaluationBindings.namespaces.set(local, "node:vm");
    }
  }
  const workerBindings = bindingsForModules(imports, WORKER_THREAD_MODULES);
  const sqliteBindings = bindingsForModules(imports, SQLITE_MODULES);
  for (const [local, imported] of sqliteBindings.direct) {
    if (imported === "default") {
      sqliteBindings.namespaces.set(local, "node:sqlite");
    }
  }
  const sqliteDatabases = constructedSqliteDatabases(
    source,
    structural,
    sqliteBindings,
  );
  const filesystemBindings = bindingsForModules(imports, FS_MODULES);
  for (const [local, imported] of filesystemBindings.direct) {
    if (imported === "default" || imported === "promises") {
      filesystemBindings.namespaces.set(
        local,
        imported === "promises" ? "node:fs/promises" : "node:fs",
      );
    }
  }
  const fetchBindings = bindingsForModules(imports, FETCH_MODULES);
  const httpBindings = bindingsForModules(imports, HTTP_MODULES);
  const axiosBindings = bindingsForModules(imports, new Set(["axios"]));
  for (const [local, imported] of axiosBindings.direct) {
    if (imported === "default") axiosBindings.namespaces.set(local, "axios");
  }
  if (!hasLocalDeclaration(structural, "fetch")) {
    fetchBindings.direct.set("fetch", "fetch");
  }
  const helpers = helperSummaries(
    source,
    structural,
    commandBindings,
    evaluationBindings,
    workerBindings,
    sqliteDatabases,
    filesystemBindings,
    fetchBindings,
    httpBindings,
    axiosBindings,
  );

  const records: NodeMcpToolRiskRecord[] = [];
  for (const registration of registrations) {
    const taint = propagatedBindings(source, structural, registration);
    const sinks = [
      ...commandSinks(source, structural, registration, taint, commandBindings),
      ...evaluationSinks(
        source,
        structural,
        registration,
        taint,
        evaluationBindings,
        workerBindings,
      ),
      ...regexSinks(source, structural, registration, taint),
      ...sqliteSinks(source, structural, registration, taint, sqliteDatabases),
      ...filesystemSinks(
        source,
        structural,
        registration,
        taint,
        filesystemBindings,
      ),
      ...networkSinks(
        source,
        structural,
        registration,
        taint,
        fetchBindings,
        httpBindings,
        axiosBindings,
      ),
      ...helperSinks(source, structural, registration, taint, helpers),
    ];
    for (const sink of sinks) {
      const modelId: McpModelId =
        sink.kind === "mcp-tool-network-destination"
          ? "node-mcp-tool-ssrf"
          : sink.kind === "mcp-tool-code-evaluation" ||
              sink.kind === "mcp-tool-worker-code-evaluation"
            ? "node-mcp-tool-code-injection"
            : sink.kind === "mcp-tool-regular-expression"
              ? "node-mcp-tool-regex-injection"
              : sink.kind === "mcp-tool-sql-query"
                ? "node-mcp-tool-sql-injection"
                : sink.kind === "mcp-tool-filesystem-path"
                  ? "node-mcp-tool-path-traversal"
                  : sink.kind === "mcp-tool-interpreter-option"
                    ? "node-mcp-tool-argument-injection"
                    : "node-mcp-tool-command-injection";
      const startLine = Math.max(1, sink.line - CONTEXT_LINES_BEFORE);
      const endLine = Math.min(lines.length, sink.line + CONTEXT_LINES_AFTER);
      const sourceStart = Math.max(1, registration.line - 2);
      const sourceEnd = Math.min(lines.length, registration.line + 5);
      records.push({
        path: normalizedPath,
        line: sink.line,
        categories: [
          `framework-dataflow:${modelId}`,
          "modeled-source:mcp-tool-input",
          `modeled-sink:${sink.kind}`,
          modelId === "node-mcp-tool-ssrf"
            ? "broken-control:mcp-tool-network-destination-not-pinned"
            : modelId === "node-mcp-tool-code-injection"
              ? "broken-control:mcp-tool-code-data-boundary"
              : modelId === "node-mcp-tool-regex-injection"
                ? "broken-control:mcp-tool-regex-pattern-boundary"
                : modelId === "node-mcp-tool-sql-injection"
                  ? "broken-control:mcp-tool-sql-data-boundary"
                  : modelId === "node-mcp-tool-path-traversal"
                    ? "broken-control:mcp-tool-filesystem-path-not-confined"
                    : modelId === "node-mcp-tool-argument-injection"
                      ? "broken-control:mcp-tool-interpreter-end-of-options-missing"
                      : "broken-control:mcp-tool-command-data-boundary",
        ],
        priority:
          modelId === "node-mcp-tool-code-injection"
            ? 129
            : modelId === "node-mcp-tool-regex-injection"
              ? 125
              : modelId === "node-mcp-tool-sql-injection"
                ? 126
                : modelId === "node-mcp-tool-ssrf"
                  ? 122
                  : modelId === "node-mcp-tool-path-traversal"
                    ? 124
                    : modelId === "node-mcp-tool-argument-injection"
                      ? 126
                      : 127,
        startLine,
        endLine,
        excerpt: sourceExcerpt(lines, startLine, endLine),
        sourceExcerpt: sourceExcerpt(lines, sourceStart, sourceEnd),
        frameworkModel: {
          schemaVersion: "1.2",
          id: modelId,
          language: "javascript-typescript",
          scope: "same-file",
          source: {
            kind: "mcp-tool-input",
            path: normalizedPath,
            line: sink.source.line,
            symbol: sink.source.name,
          },
          sink: {
            kind: sink.kind,
            path: normalizedPath,
            line: sink.line,
            symbol: sink.symbol,
            cweIds:
              modelId === "node-mcp-tool-ssrf"
                ? (["CWE-918"] as const)
                : modelId === "node-mcp-tool-code-injection"
                  ? (["CWE-94", "CWE-95"] as const)
                  : modelId === "node-mcp-tool-regex-injection"
                    ? (["CWE-400", "CWE-730"] as const)
                    : modelId === "node-mcp-tool-sql-injection"
                      ? (["CWE-89"] as const)
                      : modelId === "node-mcp-tool-path-traversal"
                        ? (["CWE-22", "CWE-73"] as const)
                        : modelId === "node-mcp-tool-argument-injection"
                          ? (["CWE-88", "CWE-94"] as const)
                          : (["CWE-78", "CWE-88"] as const),
          },
          propagators: [
            {
              kind: "mcp-tool-registration",
              path: normalizedPath,
              line: registration.line,
              symbol: `${registration.server}.${registration.method}:${registration.toolName}`,
            },
            ...sink.source.propagators.map((item) => ({
              ...item,
              path: normalizedPath,
            })),
          ],
          candidateControls: [
            {
              kind: "mcp-input-schema-validation",
              path: normalizedPath,
              line: registration.line,
            },
          ],
        },
      });
      if (records.length >= MAX_RECORDS) return records;
    }
  }
  return records;
}

function ownsPath(path: string): boolean {
  const parts = path.toLowerCase().split("/");
  const extension = parts.at(-1)?.split(".").at(-1) ?? "";
  if (!SOURCE_EXTENSIONS.has(extension)) return false;
  if (parts.some((part) => EXCLUDED_PATH_PARTS.has(part))) return false;
  const basename = parts.at(-1) ?? "";
  return !/(?:^|[._-])(?:spec|test)(?:[._-]|$)/u.test(basename);
}

function sourceExcerpt(
  lines: readonly string[],
  start: number,
  end: number,
): string {
  return lines
    .slice(start - 1, end)
    .map((line, index) => `${start + index}: ${line}`)
    .join("\n");
}

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset; index += 1) {
    if (source.charCodeAt(index) === 10) line += 1;
  }
  return line;
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function maskJavascript(source: string): string {
  const output = [...source];
  const blank = (index: number): void => {
    if (output[index] !== "\n" && output[index] !== "\r") output[index] = " ";
  };
  let index = 0;
  while (index < source.length) {
    const current = source[index];
    const next = source[index + 1];
    if (current === "/" && next === "/") {
      blank(index++);
      blank(index++);
      while (index < source.length && source[index] !== "\n") blank(index++);
      continue;
    }
    if (current === "/" && next === "*") {
      blank(index++);
      blank(index++);
      while (index < source.length) {
        if (source[index] === "*" && source[index + 1] === "/") {
          blank(index++);
          blank(index++);
          break;
        }
        blank(index++);
      }
      continue;
    }
    if (current === '"' || current === "'") {
      const quote = current;
      blank(index++);
      while (index < source.length) {
        if (source[index] === "\\") {
          blank(index++);
          if (index < source.length) blank(index++);
          continue;
        }
        const done = source[index] === quote;
        blank(index++);
        if (done) break;
      }
      continue;
    }
    if (current === "`") {
      blank(index++);
      while (index < source.length) {
        if (source[index] === "\\") {
          blank(index++);
          if (index < source.length) blank(index++);
          continue;
        }
        if (source[index] === "`") {
          blank(index++);
          break;
        }
        if (source[index] === "$" && source[index + 1] === "{") {
          index += 2;
          const close = matchingDelimiterInSource(source, index - 1, "{", "}");
          if (close < 0) {
            while (index < source.length) blank(index++);
            break;
          }
          const expression = maskJavascript(source.slice(index, close));
          for (let inner = 0; inner < expression.length; inner += 1) {
            output[index + inner] = expression[inner]!;
          }
          index = close + 1;
          continue;
        }
        blank(index++);
      }
      continue;
    }
    index += 1;
  }
  return output.join("");
}

function matchingDelimiterInSource(
  source: string,
  open: number,
  opening: string,
  closing: string,
): number {
  let depth = 0;
  let quote: string | undefined;
  for (let index = open; index < source.length; index += 1) {
    const current = source[index];
    if (quote !== undefined) {
      if (current === "\\") index += 1;
      else if (current === quote) quote = undefined;
      continue;
    }
    if (current === '"' || current === "'" || current === "`") {
      quote = current;
      continue;
    }
    if (current === opening) depth += 1;
    else if (current === closing) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function matchingOpeningStructuralDelimiter(
  structural: string,
  close: number,
  opening: string,
  closing: string,
): number {
  let depth = 0;
  for (let index = close; index >= 0; index -= 1) {
    if (structural[index] === closing) depth += 1;
    else if (structural[index] === opening) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

interface ImportBindings {
  named: Array<{ module: string; imported: string; local: string }>;
  namespaces: Array<{ module: string; local: string }>;
}

function importBindings(source: string, structural: string): ImportBindings {
  const result: ImportBindings = { named: [], namespaces: [] };
  const namedImport =
    /\bimport\s*\{([^}]{0,8192})\}\s*from\s*["']([^"'\r\n]+)["']/gu;
  for (const statement of source.matchAll(namedImport)) {
    if (!visibleKeywordAt(structural, statement.index!, "import")) continue;
    for (const binding of maskJavascript(statement[1]!).split(",")) {
      const match = binding
        .trim()
        .replace(/^type\s+/u, "")
        .match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/u);
      if (match !== null) {
        result.named.push({
          module: statement[2]!,
          imported: match[1]!,
          local: match[2] ?? match[1]!,
        });
      }
    }
  }

  const namespaceImport =
    /\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*["']([^"'\r\n]+)["']/gu;
  for (const statement of source.matchAll(namespaceImport)) {
    if (!visibleKeywordAt(structural, statement.index!, "import")) continue;
    result.namespaces.push({
      module: statement[2]!,
      local: statement[1]!,
    });
  }

  const defaultImport =
    /\bimport\s+([A-Za-z_$][\w$]*)\s+from\s*["']([^"'\r\n]+)["']/gu;
  for (const statement of source.matchAll(defaultImport)) {
    if (!visibleKeywordAt(structural, statement.index!, "import")) continue;
    result.named.push({
      module: statement[2]!,
      imported: "default",
      local: statement[1]!,
    });
  }

  const destructuredRequire =
    /\b(?:const|let|var)\s*\{([^}]{0,8192})\}\s*=\s*require\s*\(\s*["']([^"'\r\n]+)["']\s*\)/gu;
  for (const statement of source.matchAll(destructuredRequire)) {
    if (!visibleDeclarationAt(structural, statement.index!)) continue;
    for (const binding of maskJavascript(statement[1]!).split(",")) {
      const match = binding
        .trim()
        .match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/u);
      if (match !== null) {
        result.named.push({
          module: statement[2]!,
          imported: match[1]!,
          local: match[2] ?? match[1]!,
        });
      }
    }
  }

  const namespaceRequire =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']([^"'\r\n]+)["']\s*\)/gu;
  for (const statement of source.matchAll(namespaceRequire)) {
    if (!visibleDeclarationAt(structural, statement.index!)) continue;
    result.namespaces.push({
      module: statement[2]!,
      local: statement[1]!,
    });
  }

  const importEquals =
    /\bimport\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']([^"'\r\n]+)["']\s*\)/gu;
  for (const statement of source.matchAll(importEquals)) {
    if (!visibleKeywordAt(structural, statement.index!, "import")) continue;
    result.namespaces.push({
      module: statement[2]!,
      local: statement[1]!,
    });
  }
  return result;
}

function visibleKeywordAt(
  structural: string,
  offset: number,
  keyword: string,
): boolean {
  return structural.slice(offset, offset + keyword.length) === keyword;
}

function visibleDeclarationAt(structural: string, offset: number): boolean {
  return /^(?:const|let|var)\b/u.test(structural.slice(offset, offset + 6));
}

function importedNames(
  imports: ImportBindings,
  modules: ReadonlySet<string>,
  imported: string,
): Set<string> {
  const names = new Set(
    imports.named
      .filter(
        (binding) =>
          modules.has(binding.module) && binding.imported === imported,
      )
      .map((binding) => binding.local),
  );
  for (const binding of imports.namespaces) {
    if (modules.has(binding.module)) names.add(`${binding.local}.${imported}`);
  }
  return names;
}

function bindingsForModules(
  imports: ImportBindings,
  modules: ReadonlySet<string>,
): BindingSet {
  return {
    direct: new Map(
      imports.named
        .filter((binding) => modules.has(binding.module))
        .map((binding) => [binding.local, binding.imported]),
    ),
    namespaces: new Map(
      imports.namespaces
        .filter((binding) => modules.has(binding.module))
        .map((binding) => [binding.local, binding.module]),
    ),
  };
}

function constructedServers(
  structural: string,
  classes: ReadonlySet<string>,
): Set<string> {
  const servers = new Set<string>();
  for (const className of classes) {
    const expression = new RegExp(
      String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+${escapeRegularExpression(className)}\s*\(`,
      "gu",
    );
    for (const match of structural.matchAll(expression)) servers.add(match[1]!);
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const server of [...servers]) {
      const alias = new RegExp(
        String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*${escapeRegularExpression(server)}\b`,
        "gu",
      );
      for (const match of structural.matchAll(alias)) {
        if (!servers.has(match[1]!)) {
          servers.add(match[1]!);
          changed = true;
        }
      }
    }
  }
  return servers;
}

function matchingStructuralDelimiter(
  structural: string,
  open: number,
  opening: string,
  closing: string,
): number {
  let depth = 0;
  for (let index = open; index < structural.length; index += 1) {
    if (structural[index] === opening) depth += 1;
    else if (structural[index] === closing) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function splitArgumentRanges(
  structural: string,
  start: number,
  end: number,
): Range[] {
  const ranges: Range[] = [];
  let partStart = start;
  let round = 0;
  let square = 0;
  let curly = 0;
  for (let index = start; index < end; index += 1) {
    const token = structural[index];
    if (token === "(") round += 1;
    else if (token === ")") round -= 1;
    else if (token === "[") square += 1;
    else if (token === "]") square -= 1;
    else if (token === "{") curly += 1;
    else if (token === "}") curly -= 1;
    else if (token === "," && round === 0 && square === 0 && curly === 0) {
      ranges.push({ start: partStart, end: index });
      partStart = index + 1;
    }
  }
  if (structural.slice(partStart, end).trim() !== "")
    ranges.push({ start: partStart, end });
  return ranges;
}

function trimRange(structural: string, range: Range): Range {
  let { start, end } = range;
  while (start < end && /\s/u.test(structural[start]!)) start += 1;
  while (end > start && /\s/u.test(structural[end - 1]!)) end -= 1;
  return { start, end };
}

function trimSourceRange(source: string, range: Range): Range {
  let { start, end } = range;
  while (start < end && /\s/u.test(source[start]!)) start += 1;
  while (end > start && /\s/u.test(source[end - 1]!)) end -= 1;
  return { start, end };
}

function toolRegistrations(
  source: string,
  structural: string,
  servers: ReadonlySet<string>,
): Registration[] {
  const registrations: Registration[] = [];
  for (const server of servers) {
    const call = new RegExp(
      String.raw`\b${escapeRegularExpression(server)}\s*\.\s*(registerTool|tool)\s*\(`,
      "gu",
    );
    for (const match of structural.matchAll(call)) {
      const method = match[1] as Registration["method"];
      const open = match.index! + match[0].lastIndexOf("(");
      const close = matchingStructuralDelimiter(structural, open, "(", ")");
      if (close < 0) continue;
      const arguments_ = splitArgumentRanges(structural, open + 1, close).map(
        (range) => trimSourceRange(source, range),
      );
      if (arguments_.length < 3) continue;
      const callback = callbackRange(structural, arguments_.at(-1)!);
      if (callback === undefined) continue;
      if (method === "registerTool") {
        const config = arguments_[1]!;
        if (
          !/\binputSchema\b\s*(?::|[,}])/u.test(
            structural.slice(config.start, config.end),
          )
        )
          continue;
      } else {
        const schema = arguments_.at(-2)!;
        if (structural.slice(schema.start, schema.end).trim() === "") continue;
      }
      const sources = callbackSources(structural, callback.parameters);
      if (sources.length === 0) continue;
      const nameRange = arguments_[0]!;
      const rawName = source.slice(nameRange.start, nameRange.end).trim();
      const toolName =
        /^(["'])([^"']+)\1$/u.exec(rawName)?.[2] ?? "dynamic-tool";
      registrations.push({
        method,
        server,
        toolName,
        line: lineAt(source, match.index!),
        body: callback.body,
        sources,
      });
    }
  }
  return registrations;
}

function callbackRange(
  structural: string,
  range: Range,
): { parameters: Range; body: Range } | undefined {
  const value = structural.slice(range.start, range.end);
  const functionMatch =
    /^(?:async\s+)?function\s*(?:[A-Za-z_$][\w$]*)?\s*\(/u.exec(value);
  if (functionMatch !== null) {
    const open = range.start + functionMatch[0].lastIndexOf("(");
    const close = matchingStructuralDelimiter(structural, open, "(", ")");
    if (close < 0 || close >= range.end) return undefined;
    const bodyOpen = structural.indexOf("{", close + 1);
    if (bodyOpen < 0 || bodyOpen >= range.end) return undefined;
    const bodyClose = matchingStructuralDelimiter(
      structural,
      bodyOpen,
      "{",
      "}",
    );
    if (bodyClose < 0 || bodyClose > range.end) return undefined;
    return {
      parameters: { start: open + 1, end: close },
      body: { start: bodyOpen + 1, end: bodyClose },
    };
  }
  let arrow = -1;
  let round = 0;
  let square = 0;
  let curly = 0;
  for (let index = range.start; index < range.end - 1; index += 1) {
    const token = structural[index];
    if (token === "(") round += 1;
    else if (token === ")") round -= 1;
    else if (token === "[") square += 1;
    else if (token === "]") square -= 1;
    else if (token === "{") curly += 1;
    else if (token === "}") curly -= 1;
    else if (
      token === "=" &&
      structural[index + 1] === ">" &&
      round === 0 &&
      square === 0 &&
      curly === 0
    ) {
      arrow = index;
      break;
    }
  }
  if (arrow < 0) return undefined;
  let parameterStart = range.start;
  const asyncMatch = /^\s*async\s+/u.exec(
    structural.slice(parameterStart, arrow),
  );
  if (asyncMatch !== null) parameterStart += asyncMatch[0].length;
  let parameters = trimRange(structural, { start: parameterStart, end: arrow });
  if (
    structural[parameters.start] === "(" &&
    structural[parameters.end - 1] === ")"
  ) {
    parameters = { start: parameters.start + 1, end: parameters.end - 1 };
  }
  let bodyStart = arrow + 2;
  while (bodyStart < range.end && /\s/u.test(structural[bodyStart]!))
    bodyStart += 1;
  if (structural[bodyStart] === "{") {
    const bodyClose = matchingStructuralDelimiter(
      structural,
      bodyStart,
      "{",
      "}",
    );
    if (bodyClose < 0 || bodyClose > range.end) return undefined;
    return { parameters, body: { start: bodyStart + 1, end: bodyClose } };
  }
  return { parameters, body: { start: bodyStart, end: range.end } };
}

function callbackSources(structural: string, range: Range): SourceBinding[] {
  const parameters = splitArgumentRanges(structural, range.start, range.end);
  if (parameters.length === 0) return [];
  let first = structural.slice(parameters[0]!.start, parameters[0]!.end).trim();
  const line = lineAt(structural, parameters[0]!.start);
  if (first.startsWith("{")) {
    const close = matchingStructuralDelimiter(first, 0, "{", "}");
    if (close < 0) return [];
    first = first.slice(0, close + 1);
  }
  if (first.startsWith("{") && first.endsWith("}")) {
    const bindings: SourceBinding[] = [];
    for (const raw of splitArgumentRanges(first, 1, first.length - 1)) {
      const entry = first.slice(raw.start, raw.end).trim().replace(/\?$/u, "");
      const match = entry.match(
        /^(?:\.\.\.)?([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?(?:\s*=.*)?$/u,
      );
      if (match === null) continue;
      const local = match[2] ?? match[1]!;
      bindings.push({
        name: local,
        line,
        expression: new RegExp(
          String.raw`(?<![.\w$])${escapeRegularExpression(local)}\b(?!\s*:)`,
          "u",
        ),
      });
    }
    return bindings;
  }
  const identifier = first.match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*[^=]+)?$/u)?.[1];
  if (identifier === undefined) return [];
  return [
    {
      name: `${identifier}.*`,
      line,
      expression: new RegExp(
        String.raw`\b${escapeRegularExpression(identifier)}\s*(?:\.|\?\.)\s*[A-Za-z_$][\w$]*`,
        "u",
      ),
    },
  ];
}

function propagatedBindings(
  source: string,
  structural: string,
  registration: Registration,
): TaintBinding[] {
  const bindings: TaintBinding[] = registration.sources.map((item) => ({
    ...item,
    definedAt: registration.body.start,
    propagators: [],
  }));
  const bodyShape = structural.slice(
    registration.body.start,
    registration.body.end,
  );
  const declaration =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\n]+)?\s*=\s*([^;\n]+)/gu;
  let changed = true;
  while (changed) {
    changed = false;
    for (const match of bodyShape.matchAll(declaration)) {
      const local = match[1]!;
      if (bindings.some((binding) => binding.name === local)) continue;
      const expressionStart =
        registration.body.start + match.index! + match[0].indexOf(match[2]!);
      const expressionEnd = expressionStart + match[2]!.length;
      const parent = taintForRange(
        structural,
        { start: expressionStart, end: expressionEnd },
        bindings,
      );
      if (parent === undefined) continue;
      bindings.push({
        name: local,
        line: lineAt(source, registration.body.start + match.index!),
        expression: new RegExp(
          String.raw`(?<![.\w$])${escapeRegularExpression(local)}\b(?!\s*:)`,
          "u",
        ),
        definedAt: registration.body.start + match.index!,
        propagators: [
          ...parent.propagators,
          {
            kind: "mcp-tool-local-assignment",
            line: lineAt(source, registration.body.start + match.index!),
            symbol: local,
          },
        ],
      });
      changed = true;
    }
  }
  return bindings;
}

function taintForRange(
  structural: string,
  range: Range,
  bindings: readonly TaintBinding[],
): TaintBinding | undefined {
  const shape = structural.slice(range.start, range.end);
  return bindings.find((binding) => binding.expression.test(shape));
}

function liveTaintForRange(
  structural: string,
  range: Range,
  body: Range,
  bindings: readonly TaintBinding[],
): TaintBinding | undefined {
  for (const binding of bindings) {
    if (!binding.expression.test(structural.slice(range.start, range.end)))
      continue;
    const assignedName = binding.name.endsWith(".*")
      ? binding.name.slice(0, -2)
      : binding.name;
    const assignment = new RegExp(
      String.raw`\b${escapeRegularExpression(assignedName)}\s*=(?!=|>)\s*([^;\n]+)`,
      "gu",
    );
    let last: RegExpMatchArray | undefined;
    const prefix = structural.slice(
      Math.max(body.start, binding.definedAt + 1),
      range.start,
    );
    for (const match of prefix.matchAll(assignment)) last = match;
    if (last === undefined) return binding;
    if (
      bindings.some(
        (candidate) =>
          candidate !== binding && candidate.expression.test(last?.[1] ?? ""),
      )
    ) {
      return binding;
    }
  }
  return undefined;
}

interface HelperSummary {
  name: string;
  parameterIndex: number;
  sink: Sink;
}

interface SqliteDatabaseBinding {
  constructionLine: number;
  constructionOffset: number;
  constructorSymbol: string;
  rootReceiver: string;
}

function constructedSqliteDatabases(
  source: string,
  structural: string,
  bindings: BindingSet,
): ReadonlyMap<string, SqliteDatabaseBinding> {
  const constructors: Array<{
    expression: string;
    symbol: string;
    bindingRoot: string;
    member?: string;
  }> = [];
  for (const [local, imported] of bindings.direct) {
    if (imported === "DatabaseSync") {
      constructors.push({
        expression: escapeRegularExpression(local),
        symbol: local,
        bindingRoot: local,
      });
    }
  }
  for (const [namespace] of bindings.namespaces) {
    constructors.push({
      expression: `${escapeRegularExpression(namespace)}\\s*\\.\\s*DatabaseSync`,
      symbol: `${namespace}.DatabaseSync`,
      bindingRoot: namespace,
      member: "DatabaseSync",
    });
  }

  const databases = new Map<string, SqliteDatabaseBinding>();
  for (const constructor of constructors) {
    const declaration = new RegExp(
      String.raw`(?:^|[;}\n])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\n]+)?\s*=\s*new\s+${constructor.expression}\s*\(`,
      "gu",
    );
    for (const match of structural.matchAll(declaration)) {
      const offset = match.index! + match[0].lastIndexOf("new");
      if (!isModuleScopeOffset(structural, offset)) continue;
      if (
        identifierWasReassigned(structural, constructor.bindingRoot, offset) ||
        (constructor.member !== undefined &&
          memberWasReassigned(
            structural,
            constructor.bindingRoot,
            constructor.member,
            offset,
          ))
      ) {
        continue;
      }
      const open = structural.indexOf("(", offset);
      const close = matchingStructuralDelimiter(structural, open, "(", ")");
      if (open < 0 || close < 0) continue;
      if (callArgumentCount(source, structural, open + 1, close) !== 1)
        continue;
      const receiver = match[1]!;
      databases.set(receiver, {
        constructionLine: lineAt(source, offset),
        constructionOffset: offset,
        constructorSymbol: constructor.symbol,
        rootReceiver: receiver,
      });
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const [receiver, database] of [...databases]) {
      const alias = new RegExp(
        String.raw`(?:^|[;}\n])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\n]+)?\s*=\s*${escapeRegularExpression(receiver)}\s*(?:;|\n|$)`,
        "gu",
      );
      for (const match of structural.matchAll(alias)) {
        const offset = match.index! + match[0].indexOf(match[1]!);
        if (
          databases.has(match[1]!) ||
          !isModuleScopeOffset(structural, offset) ||
          identifierWasReassigned(structural, receiver, offset)
        ) {
          continue;
        }
        databases.set(match[1]!, database);
        changed = true;
      }
    }
  }
  return databases;
}

function callArgumentCount(
  source: string,
  structural: string,
  start: number,
  end: number,
): number {
  if (source.slice(start, end).trim() === "") return 0;
  let count = 1;
  let round = 0;
  let square = 0;
  let curly = 0;
  for (let index = start; index < end; index += 1) {
    const token = structural[index];
    if (token === "(") round += 1;
    else if (token === ")") round -= 1;
    else if (token === "[") square += 1;
    else if (token === "]") square -= 1;
    else if (token === "{") curly += 1;
    else if (token === "}") curly -= 1;
    else if (token === "," && round === 0 && square === 0 && curly === 0)
      count += 1;
  }
  return count;
}

function isModuleScopeOffset(structural: string, offset: number): boolean {
  let depth = 0;
  for (let index = 0; index < offset; index += 1) {
    if (structural[index] === "{") depth += 1;
    else if (structural[index] === "}") depth = Math.max(0, depth - 1);
  }
  return depth === 0;
}

function helperSummaries(
  source: string,
  structural: string,
  commandBindings: BindingSet,
  evaluationBindings: BindingSet,
  workerBindings: BindingSet,
  sqliteDatabases: ReadonlyMap<string, SqliteDatabaseBinding>,
  filesystemBindings: BindingSet,
  fetchBindings: BindingSet,
  httpBindings: BindingSet,
  axiosBindings: BindingSet,
): HelperSummary[] {
  const summaries: HelperSummary[] = [];
  const declaration = /\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/gu;
  for (const match of structural.matchAll(declaration)) {
    const open = match.index! + match[0].lastIndexOf("(");
    const close = matchingStructuralDelimiter(structural, open, "(", ")");
    if (close < 0) continue;
    const bodyOpen = structural.indexOf("{", close + 1);
    if (bodyOpen < 0) continue;
    const bodyClose = matchingStructuralDelimiter(
      structural,
      bodyOpen,
      "{",
      "}",
    );
    if (bodyClose < 0) continue;
    summaries.push(
      ...summarizeHelperBody(
        source,
        structural,
        match[1]!,
        match.index!,
        splitArgumentRanges(structural, open + 1, close),
        { start: bodyOpen + 1, end: bodyClose },
        commandBindings,
        evaluationBindings,
        workerBindings,
        sqliteDatabases,
        filesystemBindings,
        fetchBindings,
        httpBindings,
        axiosBindings,
      ),
    );
  }

  const assigned =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*)?\(/gu;
  for (const match of structural.matchAll(assigned)) {
    const open = match.index! + match[0].lastIndexOf("(");
    const close = matchingStructuralDelimiter(structural, open, "(", ")");
    if (close < 0) continue;
    const suffix = structural.slice(close + 1, close + 32);
    const isArrow = /^\s*=>/u.test(suffix);
    const isFunctionExpression = /function\s*\($/u.test(match[0]);
    if (!isArrow && !isFunctionExpression) continue;
    const bodyOpen = structural.indexOf("{", close + 1);
    if (
      bodyOpen < 0 ||
      (!isArrow && !/^\s*\{/u.test(structural.slice(close + 1, bodyOpen + 1)))
    )
      continue;
    if (
      isArrow &&
      !/^\s*=>\s*\{/u.test(structural.slice(close + 1, bodyOpen + 1))
    )
      continue;
    const bodyClose = matchingStructuralDelimiter(
      structural,
      bodyOpen,
      "{",
      "}",
    );
    if (bodyClose < 0) continue;
    summaries.push(
      ...summarizeHelperBody(
        source,
        structural,
        match[1]!,
        match.index!,
        splitArgumentRanges(structural, open + 1, close),
        { start: bodyOpen + 1, end: bodyClose },
        commandBindings,
        evaluationBindings,
        workerBindings,
        sqliteDatabases,
        filesystemBindings,
        fetchBindings,
        httpBindings,
        axiosBindings,
      ),
    );
  }
  return summaries;
}

function summarizeHelperBody(
  source: string,
  structural: string,
  name: string,
  declarationOffset: number,
  parameterRanges: readonly Range[],
  body: Range,
  commandBindings: BindingSet,
  evaluationBindings: BindingSet,
  workerBindings: BindingSet,
  sqliteDatabases: ReadonlyMap<string, SqliteDatabaseBinding>,
  filesystemBindings: BindingSet,
  fetchBindings: BindingSet,
  httpBindings: BindingSet,
  axiosBindings: BindingSet,
): HelperSummary[] {
  const summaries: HelperSummary[] = [];
  const helperRegistration: Registration = {
    method: "registerTool",
    server: "local-helper",
    toolName: name,
    line: lineAt(source, declarationOffset),
    body,
    sources: [],
  };
  for (
    let parameterIndex = 0;
    parameterIndex < parameterRanges.length;
    parameterIndex += 1
  ) {
    const parameter = structural
      .slice(
        parameterRanges[parameterIndex]!.start,
        parameterRanges[parameterIndex]!.end,
      )
      .trim();
    const parameterName = parameter.match(
      /^([A-Za-z_$][\w$]*)(?:\s*:\s*.+)?$/u,
    )?.[1];
    if (parameterName === undefined) continue;
    const parameterSource: SourceBinding = {
      name: parameterName,
      line: lineAt(source, parameterRanges[parameterIndex]!.start),
      expression: new RegExp(
        String.raw`(?<![.\w$])${escapeRegularExpression(parameterName)}\b(?!\s*:)`,
        "u",
      ),
    };
    const taint = propagatedBindings(source, structural, {
      ...helperRegistration,
      sources: [parameterSource],
    });
    const sinks = [
      ...commandSinks(
        source,
        structural,
        helperRegistration,
        taint,
        commandBindings,
      ),
      ...evaluationSinks(
        source,
        structural,
        helperRegistration,
        taint,
        evaluationBindings,
        workerBindings,
      ),
      ...regexSinks(source, structural, helperRegistration, taint),
      ...sqliteSinks(
        source,
        structural,
        helperRegistration,
        taint,
        sqliteDatabases,
      ),
      ...filesystemSinks(
        source,
        structural,
        helperRegistration,
        taint,
        filesystemBindings,
      ),
      ...networkSinks(
        source,
        structural,
        helperRegistration,
        taint,
        fetchBindings,
        httpBindings,
        axiosBindings,
      ),
    ];
    for (const sink of sinks) summaries.push({ name, parameterIndex, sink });
  }
  return summaries;
}

function helperSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
  helpers: readonly HelperSummary[],
): Sink[] {
  const sinks: Sink[] = [];
  for (const helper of helpers) {
    const expression = new RegExp(
      String.raw`\b${escapeRegularExpression(helper.name)}\s*\(`,
      "gu",
    );
    for (const match of structural
      .slice(registration.body.start, registration.body.end)
      .matchAll(expression)) {
      const offset = registration.body.start + match.index!;
      const open = offset + match[0].lastIndexOf("(");
      const close = matchingStructuralDelimiter(structural, open, "(", ")");
      if (close < 0 || close > registration.body.end) continue;
      const arguments_ = splitArgumentRanges(structural, open + 1, close).map(
        (range) => trimSourceRange(source, range),
      );
      const argument = arguments_[helper.parameterIndex];
      if (argument === undefined) continue;
      const sourceBinding = liveTaintForRange(
        structural,
        argument,
        registration.body,
        taint,
      );
      if (sourceBinding === undefined) continue;
      sinks.push({
        ...helper.sink,
        source: {
          ...sourceBinding,
          propagators: [
            ...sourceBinding.propagators,
            ...helper.sink.source.propagators,
            {
              kind: "mcp-tool-helper-call",
              line: lineAt(source, offset),
              symbol: helper.name,
            },
          ],
        },
        viaHelper: true,
      });
    }
  }
  return sinks;
}

interface CallSite {
  method: string;
  symbol: string;
  line: number;
  offset: number;
  close: number;
  arguments: Range[];
}

function boundCalls(
  source: string,
  structural: string,
  body: Range,
  bindings: BindingSet,
  accepted: ReadonlySet<string>,
): CallSite[] {
  const calls: CallSite[] = [];
  for (const [local, imported] of bindings.direct) {
    if (!accepted.has(imported)) continue;
    const expression = new RegExp(
      String.raw`(?<![.\w$])${escapeRegularExpression(local)}\s*\(`,
      "gu",
    );
    for (const match of structural
      .slice(body.start, body.end)
      .matchAll(expression)) {
      const offset = body.start + match.index!;
      const open = offset + match[0].lastIndexOf("(");
      const close = matchingStructuralDelimiter(structural, open, "(", ")");
      if (close < 0 || close > body.end) continue;
      calls.push({
        method: imported,
        symbol: local,
        line: lineAt(source, offset),
        offset,
        close,
        arguments: splitArgumentRanges(structural, open + 1, close).map(
          (range) => trimSourceRange(source, range),
        ),
      });
    }
  }
  for (const [namespace] of bindings.namespaces) {
    const methods = [...accepted].map(escapeRegularExpression).join("|");
    const expression = new RegExp(
      String.raw`(?<![.\w$])${escapeRegularExpression(namespace)}\s*\.\s*(${methods})\s*\(`,
      "gu",
    );
    for (const match of structural
      .slice(body.start, body.end)
      .matchAll(expression)) {
      const offset = body.start + match.index!;
      const open = offset + match[0].lastIndexOf("(");
      const close = matchingStructuralDelimiter(structural, open, "(", ")");
      if (close < 0 || close > body.end) continue;
      calls.push({
        method: match[1]!,
        symbol: `${namespace}.${match[1]}`,
        line: lineAt(source, offset),
        offset,
        close,
        arguments: splitArgumentRanges(structural, open + 1, close).map(
          (range) => trimSourceRange(source, range),
        ),
      });
    }
  }
  return calls;
}

function filesystemCalls(
  source: string,
  structural: string,
  body: Range,
  bindings: BindingSet,
): CallSite[] {
  const accepted = new Set(FILESYSTEM_PATH_ARGUMENTS.keys());
  const calls = boundCalls(source, structural, body, bindings, accepted);
  const methods = [...accepted].map(escapeRegularExpression).join("|");
  for (const [namespace, module] of bindings.namespaces) {
    if (module === "fs/promises" || module === "node:fs/promises") continue;
    const expression = new RegExp(
      String.raw`\b${escapeRegularExpression(namespace)}\s*\.\s*promises\s*\.\s*(${methods})\s*\(`,
      "gu",
    );
    for (const match of structural
      .slice(body.start, body.end)
      .matchAll(expression)) {
      const offset = body.start + match.index!;
      const open = offset + match[0].lastIndexOf("(");
      const close = matchingStructuralDelimiter(structural, open, "(", ")");
      if (close < 0 || close > body.end) continue;
      calls.push({
        method: match[1]!,
        symbol: `${namespace}.promises.${match[1]}`,
        line: lineAt(source, offset),
        offset,
        close,
        arguments: splitArgumentRanges(structural, open + 1, close).map(
          (range) => trimSourceRange(source, range),
        ),
      });
    }
  }
  return calls;
}

function filesystemSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
  bindings: BindingSet,
): Sink[] {
  const sinks: Sink[] = [];
  for (const call of filesystemCalls(
    source,
    structural,
    registration.body,
    bindings,
  )) {
    for (const argumentIndex of FILESYSTEM_PATH_ARGUMENTS.get(call.method) ??
      []) {
      const argument = call.arguments[argumentIndex];
      if (argument === undefined) continue;
      const sourceBinding = liveTaintForRange(
        structural,
        argument,
        registration.body,
        taint,
      );
      if (sourceBinding === undefined) continue;
      sinks.push({
        kind: "mcp-tool-filesystem-path",
        line: call.line,
        symbol: `${call.symbol}:path[${argumentIndex}]`,
        source: sourceBinding,
      });
      break;
    }
  }
  return sinks;
}

function commandSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
  bindings: BindingSet,
): Sink[] {
  const sinks: Sink[] = [];
  for (const call of boundCalls(
    source,
    structural,
    registration.body,
    bindings,
    COMMAND_METHODS,
  )) {
    const first = call.arguments[0];
    if (first === undefined) continue;
    const firstTaint = liveTaintForRange(
      structural,
      first,
      registration.body,
      taint,
    );
    if (SHELL_METHODS.has(call.method) && firstTaint !== undefined) {
      sinks.push({
        kind: "mcp-tool-shell-command",
        line: call.line,
        symbol: call.symbol,
        source: firstTaint,
      });
      continue;
    }
    if (firstTaint !== undefined) {
      sinks.push({
        kind: "mcp-tool-executable-selection",
        line: call.line,
        symbol: call.symbol,
        source: firstTaint,
      });
      continue;
    }
    if (!ARRAY_ARGUMENT_METHODS.has(call.method)) continue;
    const second = call.arguments[1];
    const secondTaint =
      second === undefined
        ? undefined
        : liveTaintForRange(structural, second, registration.body, taint);
    const options = call.arguments[2];
    const shellEnabled =
      options !== undefined &&
      /\bshell\s*:\s*true\b/u.test(
        structural.slice(options.start, options.end),
      );
    if (shellEnabled && secondTaint !== undefined) {
      sinks.push({
        kind: SPAWN_METHODS.has(call.method)
          ? "mcp-tool-shell-enabled-spawn"
          : "mcp-tool-shell-command",
        line: call.line,
        symbol: call.symbol,
        source: secondTaint,
      });
      continue;
    }
    const interpreterOption =
      second === undefined || !isNodeRuntimeExecutable(source, first)
        ? undefined
        : taintedNodeOptionArgument(
            source,
            structural,
            second,
            registration,
            taint,
          );
    if (interpreterOption !== undefined) {
      sinks.push({
        kind: "mcp-tool-interpreter-option",
        line: call.line,
        symbol: `${call.symbol}:argv[${interpreterOption.index}]`,
        source: interpreterOption.source,
      });
      continue;
    }
    const executable = literalValue(source.slice(first.start, first.end));
    if (
      secondTaint !== undefined &&
      executable !== undefined &&
      isShell(executable)
    ) {
      sinks.push({
        kind: "mcp-tool-shell-command",
        line: call.line,
        symbol: call.symbol,
        source: secondTaint,
      });
    }
  }
  return sinks;
}

function evaluationSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
  bindings: BindingSet,
  workerBindings: BindingSet,
): Sink[] {
  const sinks: Sink[] = [];
  const calls = [
    ...boundCalls(
      source,
      structural,
      registration.body,
      bindings,
      IMMEDIATE_VM_EVALUATORS,
    ).filter((call) =>
      exactBindingCallIsLive(structural, registration.body, call),
    ),
    ...globalEvalCalls(source, structural, registration.body),
  ];
  for (const call of calls) {
    const code = call.arguments[0];
    if (code === undefined) continue;
    const sourceBinding = liveTaintForRange(
      structural,
      code,
      registration.body,
      taint,
    );
    if (sourceBinding === undefined) continue;
    sinks.push({
      kind: "mcp-tool-code-evaluation",
      line: call.line,
      symbol: `${call.symbol}:code[0]`,
      source: sourceBinding,
    });
  }
  sinks.push(
    ...compiledEvaluationSinks(
      source,
      structural,
      registration,
      taint,
      bindings,
    ),
  );
  sinks.push(
    ...workerEvaluationSinks(
      source,
      structural,
      registration,
      taint,
      workerBindings,
    ),
  );
  return sinks;
}

function workerEvaluationSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
  bindings: BindingSet,
): Sink[] {
  const sinks: Sink[] = [];
  for (const call of boundCalls(
    source,
    structural,
    registration.body,
    bindings,
    new Set(["Worker"]),
  )) {
    if (!exactBindingCallIsLive(structural, registration.body, call)) continue;
    if (!hasNewPrefix(structural, registration.body, call.offset)) continue;
    const code = call.arguments[0];
    const options = call.arguments[1];
    if (
      code === undefined ||
      options === undefined ||
      !hasExactLiteralTrueProperty(source, structural, options, "eval")
    ) {
      continue;
    }
    const sourceBinding = liveTaintForRange(
      structural,
      code,
      registration.body,
      taint,
    );
    if (sourceBinding === undefined) continue;
    sinks.push({
      kind: "mcp-tool-worker-code-evaluation",
      line: call.line,
      symbol: `${call.symbol}:code[0]`,
      source: {
        ...sourceBinding,
        propagators: [
          ...sourceBinding.propagators,
          {
            kind: "mcp-tool-code-construction",
            line: call.line,
            symbol: `new ${call.symbol}:code[0]`,
          },
          {
            kind: "mcp-tool-worker-startup",
            line: call.line,
            symbol: `${call.symbol}:eval:true`,
          },
        ],
      },
    });
  }
  return sinks;
}

function hasExactLiteralTrueProperty(
  source: string,
  structural: string,
  range: Range,
  property: string,
): boolean {
  const object = trimRange(structural, range);
  if (structural[object.start] !== "{") return false;
  const close = matchingStructuralDelimiter(structural, object.start, "{", "}");
  if (close !== object.end - 1) return false;
  let matched = false;
  for (const entry of splitArgumentRanges(
    structural,
    object.start + 1,
    close,
  )) {
    const shape = structural.slice(entry.start, entry.end).trim();
    if (shape.startsWith("...") || shape.startsWith("[")) return false;
    const colon = structural.indexOf(":", entry.start);
    if (colon < 0 || colon >= entry.end) continue;
    const key = source.slice(entry.start, colon).trim();
    if (
      key !== property &&
      key !== `"${property}"` &&
      key !== `'${property}'`
    ) {
      continue;
    }
    if (matched || structural.slice(colon + 1, entry.end).trim() !== "true")
      return false;
    matched = true;
  }
  return matched;
}

interface CodeExecutionSite {
  line: number;
  offset: number;
  symbol: string;
  method?: string;
  propagators?: Array<{ kind: string; line: number; symbol?: string }>;
}

function compiledEvaluationSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
  bindings: BindingSet,
): Sink[] {
  const sinks: Sink[] = [];
  for (const call of globalFunctionConstructorCalls(
    source,
    structural,
    registration.body,
  )) {
    const execution = callableExecutionAfterConstruction(
      source,
      structural,
      registration.body,
      call.offset,
      call.close,
      "Function",
    );
    if (execution === undefined) continue;
    for (const [argumentIndex, argument] of call.arguments.entries()) {
      const sourceBinding = liveTaintForRange(
        structural,
        argument,
        registration.body,
        taint,
      );
      if (sourceBinding === undefined) continue;
      sinks.push(
        compiledEvaluationSink(
          sourceBinding,
          execution,
          call.line,
          `Function:code[${argumentIndex}]`,
          argumentIndex,
        ),
      );
    }
  }

  for (const call of boundCalls(
    source,
    structural,
    registration.body,
    bindings,
    VM_CODE_CONSTRUCTORS,
  )) {
    if (!exactBindingCallIsLive(structural, registration.body, call)) continue;
    const code = call.arguments[0];
    if (code === undefined) continue;
    const sourceBinding = liveTaintForRange(
      structural,
      code,
      registration.body,
      taint,
    );
    if (sourceBinding === undefined) continue;

    let execution: CodeExecutionSite | undefined;
    if (call.method === "compileFunction") {
      if (hasNewPrefix(structural, registration.body, call.offset)) continue;
      execution = callableExecutionAfterConstruction(
        source,
        structural,
        registration.body,
        call.offset,
        call.close,
        call.symbol,
      );
    } else if (call.method === "Script") {
      if (!hasNewPrefix(structural, registration.body, call.offset)) continue;
      execution = methodExecutionAfterConstruction(
        source,
        structural,
        registration.body,
        call.offset,
        call.close,
        IMMEDIATE_VM_EVALUATORS,
      );
    } else if (call.method === "SourceTextModule") {
      if (!hasNewPrefix(structural, registration.body, call.offset)) continue;
      execution = moduleEvaluationAfterConstruction(
        source,
        structural,
        registration.body,
        call.offset,
        call.close,
        call.symbol,
      );
    }
    if (execution === undefined) continue;
    if (
      execution.method !== undefined &&
      constructorPrototypeMethodWasReplaced(
        structural,
        call.symbol,
        execution.method,
        execution.offset,
      )
    ) {
      continue;
    }
    sinks.push(
      compiledEvaluationSink(
        sourceBinding,
        execution,
        call.line,
        `${call.symbol}:code[0]`,
        0,
      ),
    );
  }
  return sinks;
}

function compiledEvaluationSink(
  sourceBinding: TaintBinding,
  execution: CodeExecutionSite,
  constructionLine: number,
  constructionSymbol: string,
  codeArgumentIndex: number,
): Sink {
  return {
    kind: "mcp-tool-code-evaluation",
    line: execution.line,
    symbol: `${execution.symbol}:code[${codeArgumentIndex}]`,
    source: {
      ...sourceBinding,
      propagators: [
        ...sourceBinding.propagators,
        {
          kind: "mcp-tool-code-construction",
          line: constructionLine,
          symbol: constructionSymbol,
        },
        ...(execution.propagators ?? []),
      ],
    },
  };
}

function globalFunctionConstructorCalls(
  source: string,
  structural: string,
  body: Range,
): CallSite[] {
  if (
    hasLocalDeclaration(structural, "Function") ||
    bodyHasNamedParameter(structural, body, "Function")
  ) {
    return [];
  }
  const calls: CallSite[] = [];
  const expression =
    /(?<![.\w$])(?:new\s+)?(?:Function|(?:globalThis|global|window)\s*\.\s*Function)\s*\(/gu;
  for (const match of structural
    .slice(body.start, body.end)
    .matchAll(expression)) {
    const offset = body.start + match.index!;
    if (globalFunctionWasReplaced(structural, offset)) continue;
    const open = offset + match[0].lastIndexOf("(");
    const close = matchingStructuralDelimiter(structural, open, "(", ")");
    if (close < 0 || close > body.end) continue;
    calls.push({
      method: "Function",
      symbol: "Function",
      line: lineAt(source, offset),
      offset,
      close,
      arguments: splitArgumentRanges(structural, open + 1, close).map((range) =>
        trimSourceRange(source, range),
      ),
    });
  }
  return calls;
}

function callableExecutionAfterConstruction(
  source: string,
  structural: string,
  body: Range,
  constructorOffset: number,
  constructorClose: number,
  constructorSymbol: string,
): CodeExecutionSite | undefined {
  const directSuffix = structural.slice(
    constructorClose + 1,
    Math.min(body.end, constructorClose + 257),
  );
  const direct = /^\s*(?:\.\s*(call|apply))?\s*\(/u.exec(directSuffix);
  if (direct !== null) {
    const method = direct[1];
    const offset = constructorClose + 1 + direct.index;
    if (
      method !== undefined &&
      functionPrototypeMethodWasReplaced(structural, method, offset)
    ) {
      return undefined;
    }
    return {
      line: lineAt(source, offset),
      offset,
      symbol:
        method === undefined
          ? `${constructorSymbol}()`
          : `${constructorSymbol}.${method}`,
      ...(method === undefined ? {} : { method }),
    };
  }

  const variable = assignedConstructionVariable(
    structural,
    body,
    constructorOffset,
  );
  if (variable === undefined) return undefined;
  const escaped = escapeRegularExpression(variable);
  const execution = new RegExp(
    String.raw`(?<![.\w$])${escaped}\s*(?:\.\s*(call|apply))?\s*\(`,
    "gu",
  );
  for (const match of structural
    .slice(constructorClose + 1, body.end)
    .matchAll(execution)) {
    const offset = constructorClose + 1 + match.index!;
    const method = match[1];
    if (
      constructedValueWasReplaced(
        structural,
        variable,
        constructorClose + 1,
        offset,
        new Set(["call", "apply"]),
      ) ||
      (method !== undefined &&
        functionPrototypeMethodWasReplaced(structural, method, offset))
    ) {
      return undefined;
    }
    return {
      line: lineAt(source, offset),
      offset,
      symbol: method === undefined ? `${variable}()` : `${variable}.${method}`,
      ...(method === undefined ? {} : { method }),
    };
  }
  return undefined;
}

function methodExecutionAfterConstruction(
  source: string,
  structural: string,
  body: Range,
  constructorOffset: number,
  constructorClose: number,
  methods: ReadonlySet<string>,
): CodeExecutionSite | undefined {
  const alternatives = [...methods].map(escapeRegularExpression).join("|");
  const directSuffix = structural.slice(
    constructorClose + 1,
    Math.min(body.end, constructorClose + 257),
  );
  const direct = new RegExp(
    String.raw`^\s*\.\s*(${alternatives})\s*\(`,
    "u",
  ).exec(directSuffix);
  if (direct !== null) {
    const offset = constructorClose + 1 + direct.index;
    return {
      line: lineAt(source, offset),
      offset,
      symbol: direct[1]!,
      method: direct[1]!,
    };
  }
  const variable = assignedConstructionVariable(
    structural,
    body,
    constructorOffset,
  );
  if (variable === undefined) return undefined;
  const escaped = escapeRegularExpression(variable);
  const execution = new RegExp(
    String.raw`(?<![.\w$])${escaped}\s*\.\s*(${alternatives})\s*\(`,
    "gu",
  );
  for (const match of structural
    .slice(constructorClose + 1, body.end)
    .matchAll(execution)) {
    const offset = constructorClose + 1 + match.index!;
    if (
      constructedValueWasReplaced(
        structural,
        variable,
        constructorClose + 1,
        offset,
        methods,
      )
    ) {
      return undefined;
    }
    return {
      line: lineAt(source, offset),
      offset,
      symbol: `${variable}.${match[1]}`,
      method: match[1]!,
    };
  }
  return undefined;
}

function moduleEvaluationAfterConstruction(
  source: string,
  structural: string,
  body: Range,
  constructorOffset: number,
  constructorClose: number,
  constructorSymbol: string,
): CodeExecutionSite | undefined {
  const variable = assignedConstructionVariable(
    structural,
    body,
    constructorOffset,
  );
  if (variable === undefined) return undefined;
  const escaped = escapeRegularExpression(variable);
  const eventPattern = new RegExp(
    String.raw`(?<![.\w$])${escaped}\s*\.\s*(linkRequests|instantiate|link|evaluate)\s*\(`,
    "gu",
  );
  let legacyLinked = false;
  let requestsLinked = false;
  let instantiated = false;
  const lifecycle: Array<{ kind: string; line: number; symbol?: string }> = [];
  const scanStart = constructorClose + 1;
  let cursor = scanStart;
  for (const match of structural
    .slice(scanStart, body.end)
    .matchAll(eventPattern)) {
    const offset = scanStart + match.index!;
    const method = match[1]!;
    if (
      constructedValueWasReplaced(
        structural,
        variable,
        cursor,
        offset,
        new Set(["link", "linkRequests", "instantiate", "evaluate"]),
      ) ||
      constructorPrototypeMethodWasReplaced(
        structural,
        constructorSymbol,
        method,
        offset,
      )
    ) {
      return undefined;
    }
    if (method === "link") {
      if (!callIsDirectlyAwaited(structural, offset)) return undefined;
      legacyLinked = true;
      lifecycle.push({
        kind: "mcp-tool-code-linking",
        line: lineAt(source, offset),
        symbol: `${variable}.link`,
      });
    } else if (method === "linkRequests") {
      requestsLinked = true;
      lifecycle.push({
        kind: "mcp-tool-code-linking",
        line: lineAt(source, offset),
        symbol: `${variable}.linkRequests`,
      });
    } else if (method === "instantiate") {
      if (!requestsLinked) return undefined;
      instantiated = true;
      lifecycle.push({
        kind: "mcp-tool-code-instantiation",
        line: lineAt(source, offset),
        symbol: `${variable}.instantiate`,
      });
    } else if (method === "evaluate") {
      if (!legacyLinked && !(requestsLinked && instantiated)) return undefined;
      return {
        line: lineAt(source, offset),
        offset,
        symbol: `${variable}.evaluate`,
        method,
        propagators: lifecycle,
      };
    }
    cursor = offset + match[0].length;
  }
  return undefined;
}

function assignedConstructionVariable(
  structural: string,
  body: Range,
  constructorOffset: number,
): string | undefined {
  const prefix = structural.slice(
    Math.max(body.start, constructorOffset - 512),
    constructorOffset,
  );
  return /(?:^|[;{}\n])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\n]+)?\s*=\s*(?:new\s+)?$/u.exec(
    prefix,
  )?.[1];
}

function exactBindingCallIsLive(
  structural: string,
  body: Range,
  call: CallSite,
): boolean {
  const [root, member] = call.symbol.split(".");
  if (root === undefined) return false;
  if (
    bodyHasNamedParameter(structural, body, root) ||
    localDeclarationBefore(structural, body, root, call.offset) ||
    identifierWasReassigned(structural, root, call.offset)
  ) {
    return false;
  }
  return (
    member === undefined ||
    !memberWasReassigned(structural, root, member, call.offset)
  );
}

function localDeclarationBefore(
  structural: string,
  body: Range,
  name: string,
  offset: number,
): boolean {
  const escaped = escapeRegularExpression(name);
  return new RegExp(
    String.raw`\b(?:class|function|const|let|var)\s+${escaped}\b`,
    "u",
  ).test(structural.slice(body.start, offset));
}

function identifierWasReassigned(
  structural: string,
  name: string,
  offset: number,
): boolean {
  const escaped = escapeRegularExpression(name);
  const expression = new RegExp(
    String.raw`(?<![.\w$])${escaped}\s*(?:=(?!=|>)|\+\+|--)`,
    "gu",
  );
  for (const match of structural.slice(0, offset).matchAll(expression)) {
    const prefix = structural.slice(
      Math.max(0, match.index! - 32),
      match.index!,
    );
    if (/\b(?:const|let|var|import)\s*$/u.test(prefix)) continue;
    return true;
  }
  return false;
}

function memberWasReassigned(
  structural: string,
  root: string,
  member: string,
  offset: number,
): boolean {
  const expression = new RegExp(
    String.raw`(?<![.\w$])${escapeRegularExpression(root)}\s*\.\s*${escapeRegularExpression(member)}\s*(?:=(?!=|>)|\+\+|--)`,
    "u",
  );
  return expression.test(structural.slice(0, offset));
}

function constructedValueWasReplaced(
  structural: string,
  variable: string,
  start: number,
  end: number,
  methods: ReadonlySet<string>,
): boolean {
  const escaped = escapeRegularExpression(variable);
  const alternatives = [...methods].map(escapeRegularExpression).join("|");
  return new RegExp(
    String.raw`(?<![.\w$])${escaped}\s*(?:=(?!=|>)|\+\+|--)|(?<![.\w$])${escaped}\s*\.\s*(?:${alternatives})\s*(?:=(?!=|>)|\+\+|--)`,
    "u",
  ).test(structural.slice(start, end));
}

function constructorPrototypeMethodWasReplaced(
  structural: string,
  constructorSymbol: string,
  method: string,
  offset: number,
): boolean {
  const parts = constructorSymbol.split(".");
  const constructorExpression = parts
    .map(escapeRegularExpression)
    .join(String.raw`\s*\.\s*`);
  return new RegExp(
    String.raw`(?<![.\w$])${constructorExpression}\s*\.\s*prototype\s*\.\s*${escapeRegularExpression(method)}\s*(?:=(?!=|>)|\+\+|--)`,
    "u",
  ).test(structural.slice(0, offset));
}

function functionPrototypeMethodWasReplaced(
  structural: string,
  method: string,
  offset: number,
): boolean {
  return new RegExp(
    String.raw`(?:(?<![.\w$])Function|(?<![\w$])(?:globalThis|global|window)\s*\.\s*Function)\s*\.\s*prototype\s*\.\s*${escapeRegularExpression(method)}\s*(?:=(?!=|>)|\+\+|--)`,
    "u",
  ).test(structural.slice(0, offset));
}

function globalFunctionWasReplaced(
  structural: string,
  offset: number,
): boolean {
  return (
    identifierWasReassigned(structural, "Function", offset) ||
    /(?<![\w$])(?:globalThis|global|window)\s*\.\s*Function\s*(?:=(?!=|>)|\+\+|--)/u.test(
      structural.slice(0, offset),
    )
  );
}

function hasNewPrefix(
  structural: string,
  body: Range,
  offset: number,
): boolean {
  return /\bnew\s*$/u.test(
    structural.slice(Math.max(body.start, offset - 32), offset),
  );
}

function callIsDirectlyAwaited(structural: string, offset: number): boolean {
  return /\bawait\s*$/u.test(
    structural.slice(Math.max(0, offset - 32), offset),
  );
}

function sqliteSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
  databases: ReadonlyMap<string, SqliteDatabaseBinding>,
): Sink[] {
  if (databases.size === 0) return [];
  const databaseBindings: BindingSet = {
    direct: new Map(),
    namespaces: new Map(
      [...databases.keys()].map((receiver) => [receiver, "node:sqlite"]),
    ),
  };
  const sinks: Sink[] = [];
  for (const call of boundCalls(
    source,
    structural,
    registration.body,
    databaseBindings,
    new Set(["exec"]),
  )) {
    const receiver = call.symbol.split(".")[0];
    const database =
      receiver === undefined ? undefined : databases.get(receiver);
    const sql = call.arguments[0];
    if (
      database === undefined ||
      sql === undefined ||
      !exactBindingCallIsLive(structural, registration.body, call) ||
      sqliteDatabaseWasClosed(
        source,
        structural,
        registration,
        databaseBindings,
        database,
        call.offset,
      ) ||
      constructorPrototypeMethodWasReplaced(
        structural,
        database.constructorSymbol,
        "exec",
        call.offset,
      )
    ) {
      continue;
    }
    const sourceBinding = liveTaintForRange(
      structural,
      sql,
      registration.body,
      taint,
    );
    if (sourceBinding === undefined) continue;
    sinks.push({
      kind: "mcp-tool-sql-query",
      line: call.line,
      symbol: `${call.symbol}:sql[0]`,
      source: {
        ...sourceBinding,
        propagators: [
          ...sourceBinding.propagators,
          {
            kind: "mcp-tool-sqlite-database",
            line: database.constructionLine,
            symbol: `${database.rootReceiver}=new ${database.constructorSymbol}`,
          },
          {
            kind: "mcp-tool-sql-execution",
            line: call.line,
            symbol: `${call.symbol}:sql[0]`,
          },
        ],
      },
    });
  }
  return sinks;
}

function sqliteDatabaseWasClosed(
  source: string,
  structural: string,
  registration: Registration,
  bindings: BindingSet,
  database: SqliteDatabaseBinding,
  executionOffset: number,
): boolean {
  const handlerClose = boundCalls(
    source,
    structural,
    registration.body,
    bindings,
    new Set(["close"]),
  ).some(
    (call) =>
      call.offset < executionOffset &&
      exactBindingCallIsLive(structural, registration.body, call),
  );
  if (handlerClose) return true;

  for (const receiver of bindings.namespaces.keys()) {
    const close = new RegExp(
      String.raw`(?<![.\w$])${escapeRegularExpression(receiver)}\s*\.\s*close\s*\(`,
      "gu",
    );
    for (const match of structural
      .slice(database.constructionOffset)
      .matchAll(close)) {
      const offset = database.constructionOffset + match.index!;
      if (isModuleScopeOffset(structural, offset)) return true;
    }
  }
  return false;
}

function regexSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
): Sink[] {
  if (
    hasLocalDeclaration(structural, "RegExp") ||
    bodyHasNamedParameter(structural, registration.body, "RegExp")
  ) {
    return [];
  }
  const sinks: Sink[] = [];
  const constructor = /(?<![.\w$])(?:new\s+)?RegExp\s*\(/gu;
  for (const match of structural
    .slice(registration.body.start, registration.body.end)
    .matchAll(constructor)) {
    const offset = registration.body.start + match.index!;
    if (
      /(?<![.\w$])RegExp\s*(?:=(?!=|>)|\+\+|--)/u.test(
        structural.slice(0, offset),
      ) ||
      /(?<![\w$])(?:globalThis|global|window)\s*\.\s*RegExp\s*(?:=(?!=|>)|\+\+|--)/u.test(
        structural.slice(0, offset),
      )
    ) {
      continue;
    }
    const open = offset + match[0].lastIndexOf("(");
    const close = matchingStructuralDelimiter(structural, open, "(", ")");
    if (close < 0 || close > registration.body.end) continue;
    const pattern = splitArgumentRanges(structural, open + 1, close)[0];
    if (pattern === undefined) continue;
    const sourceBinding = liveTaintForRange(
      structural,
      trimSourceRange(source, pattern),
      registration.body,
      taint,
    );
    if (sourceBinding === undefined) continue;
    const execution = regexExecutionAfterConstruction(
      source,
      structural,
      registration.body,
      offset,
      close,
    );
    if (execution === undefined) continue;
    const escapedMethod = escapeRegularExpression(execution.method);
    if (
      new RegExp(
        String.raw`(?:(?<![.\w$])RegExp|(?<![\w$])(?:globalThis|global|window)\s*\.\s*RegExp)\s*\.\s*prototype\s*\.\s*${escapedMethod}\s*(?:=(?!=|>)|\+\+|--)`,
        "u",
      ).test(structural.slice(0, execution.offset))
    ) {
      continue;
    }
    sinks.push({
      kind: "mcp-tool-regular-expression",
      line: execution.line,
      symbol: `RegExp.${execution.method}:pattern[0]`,
      source: {
        ...sourceBinding,
        propagators: [
          ...sourceBinding.propagators,
          {
            kind: "mcp-tool-regex-construction",
            line: lineAt(source, offset),
            symbol: "RegExp:pattern[0]",
          },
        ],
      },
    });
  }
  return sinks;
}

function regexExecutionAfterConstruction(
  source: string,
  structural: string,
  body: Range,
  constructorOffset: number,
  constructorClose: number,
): { line: number; method: "exec" | "test"; offset: number } | undefined {
  const directSuffix = structural.slice(
    constructorClose + 1,
    Math.min(body.end, constructorClose + 257),
  );
  const direct = /^\s*\.\s*(exec|test)\s*\(/u.exec(directSuffix);
  if (direct !== null) {
    return {
      line: lineAt(source, constructorClose + 1 + direct.index),
      method: direct[1] as "exec" | "test",
      offset: constructorClose + 1 + direct.index,
    };
  }

  const declarationPrefix = structural.slice(
    Math.max(body.start, constructorOffset - 512),
    constructorOffset,
  );
  const assignment =
    /(?:^|[;{}\n])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$/u.exec(
      declarationPrefix,
    );
  const variable = assignment?.[1];
  if (variable === undefined) return undefined;
  const escaped = escapeRegularExpression(variable);
  const execution = new RegExp(
    String.raw`(?<![.\w$])${escaped}\s*\.\s*(exec|test)\s*\(`,
    "gu",
  );
  for (const match of structural
    .slice(constructorClose + 1, body.end)
    .matchAll(execution)) {
    const offset = constructorClose + 1 + match.index!;
    const between = structural.slice(constructorClose + 1, offset);
    if (
      new RegExp(
        String.raw`(?<![.\w$])${escaped}\s*(?:=(?!=|>)|\+\+|--)|(?<![.\w$])${escaped}\s*\.\s*(?:exec|test)\s*=(?!=|>)`,
        "u",
      ).test(between)
    ) {
      return undefined;
    }
    return {
      line: lineAt(source, offset),
      method: match[1] as "exec" | "test",
      offset,
    };
  }
  return undefined;
}

function globalEvalCalls(
  source: string,
  structural: string,
  body: Range,
): CallSite[] {
  if (
    hasLocalDeclaration(structural, "eval") ||
    bodyHasNamedParameter(structural, body, "eval")
  ) {
    return [];
  }
  const calls: CallSite[] = [];
  const expression = /(?<![.\w$])eval\s*\(/gu;
  for (const match of structural
    .slice(body.start, body.end)
    .matchAll(expression)) {
    const offset = body.start + match.index!;
    const prefix = structural.slice(body.start, offset);
    if (/(?<![.\w$])eval\s*(?:=(?!=|>)|\+\+|--)/u.test(prefix)) continue;
    const open = offset + match[0].lastIndexOf("(");
    const close = matchingStructuralDelimiter(structural, open, "(", ")");
    if (close < 0 || close > body.end) continue;
    calls.push({
      method: "eval",
      symbol: "eval",
      line: lineAt(source, offset),
      offset,
      close,
      arguments: splitArgumentRanges(structural, open + 1, close).map((range) =>
        trimSourceRange(source, range),
      ),
    });
  }
  return calls;
}

function bodyHasNamedParameter(
  structural: string,
  body: Range,
  name: string,
): boolean {
  const close = structural.lastIndexOf(")", body.start - 1);
  if (close < Math.max(0, body.start - 8192)) return false;
  const open = matchingOpeningStructuralDelimiter(structural, close, "(", ")");
  if (open < 0) return false;
  const exact = new RegExp(
    String.raw`^(?:\.\.\.\s*)?${escapeRegularExpression(name)}(?:\s*[?:=].*)?$`,
    "u",
  );
  return splitArgumentRanges(structural, open + 1, close).some((range) =>
    exact.test(structural.slice(range.start, range.end).trim()),
  );
}

function isNodeRuntimeExecutable(source: string, range: Range): boolean {
  return (
    source.slice(range.start, range.end).replaceAll(/\s/gu, "") ===
    "process.execPath"
  );
}

function taintedNodeOptionArgument(
  source: string,
  structural: string,
  argumentArray: Range,
  registration: Registration,
  taint: readonly TaintBinding[],
): { index: number; source: TaintBinding } | undefined {
  const array = trimRange(structural, argumentArray);
  if (structural[array.start] !== "[") return undefined;
  const close = matchingStructuralDelimiter(structural, array.start, "[", "]");
  if (close !== array.end - 1) return undefined;
  const elements = splitArgumentRanges(structural, array.start + 1, close).map(
    (range) => trimSourceRange(source, range),
  );
  let optionsEnded = false;
  for (const [index, element] of elements.entries()) {
    if (literalValue(source.slice(element.start, element.end)) === "--") {
      optionsEnded = true;
      continue;
    }
    const sourceBinding = liveTaintForRange(
      structural,
      element,
      registration.body,
      taint,
    );
    if (sourceBinding !== undefined && !optionsEnded)
      return { index, source: sourceBinding };
  }
  return undefined;
}

function isShell(executable: string): boolean {
  const basename =
    executable.replaceAll("\\", "/").split("/").at(-1)?.toLowerCase() ?? "";
  return (
    POSIX_SHELLS.has(basename) ||
    POWERSHELLS.has(basename) ||
    basename === "cmd" ||
    basename === "cmd.exe"
  );
}

function literalValue(value: string): string | undefined {
  const trimmed = value.trim();
  const match = trimmed.match(/^(["'])([^"']*)\1$/u);
  return match?.[2];
}

function networkSinks(
  source: string,
  structural: string,
  registration: Registration,
  taint: readonly TaintBinding[],
  fetchBindings: BindingSet,
  httpBindings: BindingSet,
  axiosBindings: BindingSet,
): Sink[] {
  const sinks: Sink[] = [];
  const append = (call: CallSite, destination: Range | undefined): void => {
    if (destination === undefined) return;
    const sourceBinding = liveTaintForRange(
      structural,
      destination,
      registration.body,
      taint,
    );
    if (sourceBinding === undefined) return;
    sinks.push({
      kind: "mcp-tool-network-destination",
      line: call.line,
      symbol: call.symbol,
      source: sourceBinding,
    });
  };
  for (const call of boundCalls(
    source,
    structural,
    registration.body,
    fetchBindings,
    new Set(["default", "fetch"]),
  )) {
    append(call, call.arguments[0]);
  }
  for (const call of boundCalls(
    source,
    structural,
    registration.body,
    httpBindings,
    new Set(["get", "request"]),
  )) {
    const first = call.arguments[0];
    append(
      call,
      first === undefined
        ? undefined
        : objectDestinationRange(
            source,
            structural,
            first,
            new Set(["host", "hostname", "href", "protocol"]),
          ),
    );
  }
  for (const call of boundCalls(
    source,
    structural,
    registration.body,
    axiosBindings,
    new Set([...NETWORK_METHODS, "default"]),
  )) {
    const first = call.arguments[0];
    if (first === undefined) continue;
    append(
      call,
      call.method === "default" || call.method === "request"
        ? objectDestinationRange(
            source,
            structural,
            first,
            new Set(["baseURL", "url"]),
          )
        : first,
    );
  }
  return sinks;
}

function objectDestinationRange(
  source: string,
  structural: string,
  range: Range,
  properties: ReadonlySet<string>,
): Range | undefined {
  const shape = structural.slice(range.start, range.end).trim();
  if (!shape.startsWith("{")) return range;
  const open = structural.indexOf("{", range.start);
  const close = matchingStructuralDelimiter(structural, open, "{", "}");
  if (close < 0 || close >= range.end) return undefined;
  for (const entry of splitArgumentRanges(structural, open + 1, close)) {
    const entryShape = structural.slice(entry.start, entry.end).trim();
    const property = entryShape.match(/^([A-Za-z_$][\w$]*)\s*(?::|$)/u)?.[1];
    if (property === undefined || !properties.has(property)) continue;
    const colon = structural.indexOf(":", entry.start);
    if (colon >= 0 && colon < entry.end) {
      return trimSourceRange(source, { start: colon + 1, end: entry.end });
    }
    return trimSourceRange(source, entry);
  }
  return undefined;
}

function hasLocalDeclaration(structural: string, name: string): boolean {
  const escaped = escapeRegularExpression(name);
  return new RegExp(
    String.raw`\b(?:class|function|const|let|var)\s+${escaped}\b|\bimport\s+(?:\{[^}]*\b${escaped}\b[^}]*\}|${escaped}\b|\*\s+as\s+${escaped}\b)`,
    "u",
  ).test(structural);
}
