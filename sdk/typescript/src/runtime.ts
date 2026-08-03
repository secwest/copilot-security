import { execFile as execFileCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants, type Stats } from "node:fs";
import {
  chmod,
  cp,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readlink,
  readdir,
  realpath,
  rename,
  rm,
  rmdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  sep,
  win32,
} from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { crc32 } from "node:zlib";
import { setTimeout as delay } from "node:timers/promises";
import extractZip from "extract-zip";
import { parse } from "smol-toml";
import {
  CopilotSecurityError,
  OutputDirectoryError,
  PluginBootstrapError,
  PluginPythonUnavailableError,
} from "./errors.js";
import type { JsonObject } from "./config.js";
import {
  resolveTrustedExecutable,
  resolveTrustedWindowsCommandWrapper,
} from "./trusted-executable.js";

const execFile = promisify(execFileCallback);

export const MARKETPLACE_NAME = "copilot-security-sdk";
export const PLUGIN_NAME = "copilot-security";

const MAX_ZIP_ENTRIES = 4_096;
const MAX_ZIP_CENTRAL_DIRECTORY = 16 * 1024 * 1024;
const MAX_ZIP_ENTRY_SIZE = 128 * 1024 * 1024;
const MAX_ZIP_EXPANDED_SIZE = 512 * 1024 * 1024;
const MAX_PLUGIN_MANIFEST_SIZE = 1024 * 1024;
const MAX_PLUGIN_COPY_ENTRIES = 4_096;
const MAX_PLUGIN_COPY_FILE_SIZE = 128 * 1024 * 1024;
const MAX_PLUGIN_COPY_SIZE = 512 * 1024 * 1024;
const MAX_COPILOT_ACCOUNT_CONFIG_SIZE = 1024 * 1024;
const MODEL_UNSAFE_PATH = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const CREDENTIAL_LOCK_NAME = ".copilot-security-scan.lock";
const CREDENTIAL_LOGOUT_MARKER = ".copilot-security-logged-out";
const CREDENTIAL_LOCK_POLL_MILLISECONDS = 25;
const INCOMPLETE_CREDENTIAL_LOCK_MILLISECONDS = 30_000;
const SETTINGS_REPLACE_ATTEMPTS = 20;
const SETTINGS_REPLACE_INITIAL_DELAY_MILLISECONDS = 10;
const SETTINGS_REPLACE_MAX_DELAY_MILLISECONDS = 250;
const SDK_DIRECTORY_CLEANUP_MAX_RETRIES = 10;
const SDK_DIRECTORY_CLEANUP_RETRY_DELAY_MILLISECONDS = 100;

export interface PluginInstall {
  pluginRoot: string;
  marketplaceRoot: string;
  installedRoot: string;
  marketplaceName: typeof MARKETPLACE_NAME;
  name: typeof PLUGIN_NAME;
  version: string;
}

export interface CopilotCommand {
  command: string;
  prefixArgs: readonly string[];
}

export type ProcessEnvironment = Record<string, string | undefined>;

export interface PluginPythonOptions {
  configuredPath?: string;
  environment?: ProcessEnvironment;
  homeDirectory?: string;
  managedRuntimeRoots?: readonly string[];
  protectedRoot?: string;
  signal?: AbortSignal;
}

export interface WorkbenchCommandOptions {
  python: string;
  pluginRoot: string;
  environment: ProcessEnvironment;
  signal?: AbortSignal;
  failureMessage?: string;
}

export interface CopilotScannerSandboxOptions {
  repository: string;
  scanDirectory: string;
  pluginRoot: string;
  analysisWorkspace?: string;
}

export interface CopilotAnalysisWorkspace {
  root: string;
  repository: string;
  pluginRoot: string;
  linkManifest: string;
}

export interface CopilotInventoryTarget {
  kind: "repository" | "paths" | "refs" | "working_tree";
  paths: readonly string[];
  base?: string;
  head?: string;
}

export interface CopilotScanInventorySnapshot {
  fileCount: number;
  repositoryPaths: readonly string[];
  files: ReadonlyArray<{ path: string; sha256: string }>;
}

export interface CopilotScannerSandboxConfig {
  enabled: true;
  addCurrentWorkingDirectory: false;
  userPolicy: {
    filesystem: {
      readwritePaths: string[];
      readonlyPaths: string[];
      deniedPaths: string[];
      clearPolicyOnExit: true;
    };
    network: {
      allowOutbound: false;
      allowLocalNetwork: false;
    };
  };
}

const COPILOT_SCANNER_INHERITED_ENVIRONMENT = new Set([
  "ALLUSERSPROFILE",
  "APPDATA",
  "COLORTERM",
  "COMSPEC",
  "FORCE_COLOR",
  "GH_HOST",
  "GITHUB_HOST",
  "HOMEDRIVE",
  "HOMEPATH",
  "HOME",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "LANG",
  "LC_ALL",
  "LOCALAPPDATA",
  "NO_COLOR",
  "NO_PROXY",
  "NUMBER_OF_PROCESSORS",
  "OS",
  "PATHEXT",
  "PROCESSOR_ARCHITECTURE",
  "PROCESSOR_IDENTIFIER",
  "PROCESSOR_LEVEL",
  "PROCESSOR_REVISION",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "PROGRAMW6432",
  "REQUESTS_CA_BUNDLE",
  "SHELL",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TERM",
  "TMP",
  "TMPDIR",
  "USERDOMAIN",
  "USERNAME",
  "USERPROFILE",
  "WINDIR",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
]);

/**
 * Build the environment inherited by the Copilot process and its shell tools.
 * Scanner paths and authentication are retained, but unrelated ambient secrets,
 * executable-injection variables, and arbitrary PATH entries are not.
 */
export function copilotScannerExecutionEnvironment(
  environment: ProcessEnvironment,
  executables: {
    copilot: string;
    python: string;
    git?: string;
    tools?: readonly string[];
  },
  platform: NodeJS.Platform = process.platform,
): ProcessEnvironment {
  const pathImplementation = platform === "win32" ? win32 : posix;
  const selected = Object.fromEntries(
    Object.entries(environment).filter(([name, value]) => {
      if (value === undefined) return false;
      const upper = name.toUpperCase();
      return (
        COPILOT_SCANNER_INHERITED_ENVIRONMENT.has(upper) ||
        upper === "COPILOT_HOME" ||
        upper === "COPILOT_CACHE_HOME" ||
        upper === "PYTHON" ||
        upper.startsWith("COPILOT_SECURITY_")
      );
    }),
  );
  for (const name of Object.keys(selected)) {
    if (name.toUpperCase() === "PATH") delete selected[name];
  }

  const systemRoot =
    environmentEntry(environment, "SYSTEMROOT") ?? "C:\\Windows";
  const candidates = [
    pathImplementation.dirname(executables.copilot),
    pathImplementation.dirname(executables.python),
    ...(executables.git === undefined
      ? []
      : [pathImplementation.dirname(executables.git)]),
    ...(executables.tools ?? []).map((path) =>
      pathImplementation.dirname(path),
    ),
    ...(platform === "win32"
      ? [
          pathImplementation.join(systemRoot, "System32"),
          systemRoot,
          pathImplementation.join(systemRoot, "System32", "Wbem"),
          pathImplementation.join(
            systemRoot,
            "System32",
            "WindowsPowerShell",
            "v1.0",
          ),
        ]
      : ["/usr/local/bin", "/usr/bin", "/bin"]),
  ];
  const seen = new Set<string>();
  selected["PATH"] = candidates
    .filter((path) => {
      const key = platform === "win32" ? path.toLowerCase() : path;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .join(pathImplementation.delimiter);
  selected["PYTHON"] = executables.python;
  return selected;
}

function environmentEntry(
  environment: ProcessEnvironment,
  requested: string,
): string | undefined {
  const upper = requested.toUpperCase();
  return Object.entries(environment).find(
    ([name, value]) => name.toUpperCase() === upper && value?.trim(),
  )?.[1];
}

export function copilotScannerSandboxConfig(
  copilotHome: string,
  options: CopilotScannerSandboxOptions,
): CopilotScannerSandboxConfig {
  const sensitivePaths = [
    join(homedir(), ".aws"),
    join(homedir(), ".azure"),
    join(homedir(), ".copilot"),
    join(homedir(), ".gnupg"),
    join(homedir(), ".kube"),
    join(homedir(), ".ssh"),
    join(copilotHome, "auth.json"),
    join(copilotHome, "config.json"),
    join(copilotHome, "mcp-oauth-config"),
    join(copilotHome, "mcp-secrets"),
    join(copilotHome, "permissions-config.json"),
    join(copilotHome, "session-state"),
    join(copilotHome, "session-store.db"),
    join(copilotHome, "session-store.db-shm"),
    join(copilotHome, "session-store.db-wal"),
  ];
  return {
    enabled: true,
    addCurrentWorkingDirectory: false,
    userPolicy: {
      filesystem: {
        readwritePaths: [
          options.scanDirectory,
          ...(options.analysisWorkspace === undefined
            ? []
            : [options.analysisWorkspace]),
        ],
        readonlyPaths:
          options.analysisWorkspace === undefined
            ? [options.repository, options.pluginRoot]
            : [],
        deniedPaths: sensitivePaths,
        clearPolicyOnExit: true,
      },
      network: {
        allowOutbound: false,
        allowLocalNetwork: false,
      },
    },
  };
}

/**
 * Copy model-visible inputs into an expendable workspace. Symbolic links and
 * other special entries are recorded instead of recreated, so no staged path
 * can traverse back into the source repository or another host location.
 */
export async function prepareCopilotAnalysisWorkspace(
  repository: string,
  pluginRoot: string,
  signal?: AbortSignal,
  repositoryScopes?: readonly string[],
): Promise<CopilotAnalysisWorkspace> {
  signal?.throwIfAborted();
  const root = await mkdtemp(join(tmpdir(), "copilot-security-analysis-"));
  const stagedRepository = join(root, "repository");
  const stagedPlugin = join(root, "plugin");
  const runtimeMetadataRoot = join(stagedPlugin, ".copilot-security-runtime");
  const linkManifest = join(runtimeMetadataRoot, "links.json");
  const links: Array<{
    tree: "repository" | "plugin";
    path: string;
    target?: string;
    kind: "symbolic_link" | "special";
  }> = [];
  const normalizedRepositoryScopes = repositoryScopes
    ?.map((path) =>
      path.replaceAll("\\", "/").replace(/^\.\//u, "").replace(/\/$/u, ""),
    )
    .filter((path) => path !== "" && path !== ".");

  const repositoryPathIsInScope = (path: string): boolean =>
    normalizedRepositoryScopes === undefined ||
    normalizedRepositoryScopes.length === 0 ||
    path === "" ||
    normalizedRepositoryScopes.some(
      (scope) =>
        path === scope ||
        path.startsWith(`${scope}/`) ||
        scope.startsWith(`${path}/`),
    );

  const repositoryPathIsExcluded = (path: string): boolean => {
    const parts = path.split("/");
    if (parts.includes(".git")) return true;
    for (const excluded of ["node_modules", ".pnpm-store"]) {
      const index = parts.indexOf(excluded);
      if (index < 0) continue;
      const excludedRoot = parts.slice(0, index + 1).join("/");
      const explicitlySelected = normalizedRepositoryScopes?.some(
        (scope) =>
          scope === excludedRoot || scope.startsWith(`${excludedRoot}/`),
      );
      if (explicitlySelected !== true) return true;
    }
    return false;
  };

  const stage = async (
    source: string,
    destination: string,
    tree: "repository" | "plugin",
  ): Promise<void> => {
    const canonicalSource = await realpath(source);
    await cp(canonicalSource, destination, {
      recursive: true,
      force: false,
      errorOnExist: true,
      dereference: false,
      verbatimSymlinks: true,
      filter: async (current) => {
        signal?.throwIfAborted();
        const repositoryPath = relative(canonicalSource, current)
          .split(sep)
          .join("/");
        if (
          tree === "repository" &&
          (!repositoryPathIsInScope(repositoryPath) ||
            repositoryPathIsExcluded(repositoryPath))
        ) {
          return false;
        }
        const metadata = await lstat(current);
        if (metadata.isSymbolicLink()) {
          links.push({
            tree,
            path: repositoryPath,
            target: await readlink(current),
            kind: "symbolic_link",
          });
          return false;
        }
        if (!metadata.isDirectory() && !metadata.isFile()) {
          links.push({
            tree,
            path: repositoryPath,
            kind: "special",
          });
          return false;
        }
        return true;
      },
    });
  };

  let complete = false;
  try {
    await stage(repository, stagedRepository, "repository");
    await stage(pluginRoot, stagedPlugin, "plugin");
    signal?.throwIfAborted();
    await mkdir(runtimeMetadataRoot, { mode: 0o700 });
    await writeFile(
      linkManifest,
      `${JSON.stringify({ schemaVersion: "1.0", entries: links }, null, 2)}\n`,
      { flag: "wx", mode: 0o400 },
    );
    complete = true;
    return {
      root: await realpath(root),
      repository: await realpath(stagedRepository),
      pluginRoot: await realpath(stagedPlugin),
      linkManifest: await realpath(linkManifest),
    };
  } finally {
    if (!complete) await rm(root, { recursive: true, force: true });
  }
}

/**
 * Generate the model's immutable file inventory in the trusted host process.
 * The model consumes this worklist but cannot select or silently narrow scope.
 */
export async function prepareCopilotScanInventory(options: {
  python: string;
  pluginRoot: string;
  repository: string;
  diffRepository?: string;
  scanDirectory: string;
  target: CopilotInventoryTarget;
  scopesFile?: string;
  environment: ProcessEnvironment;
  signal?: AbortSignal;
}): Promise<CopilotScanInventorySnapshot> {
  options.signal?.throwIfAborted();
  const discoveryDirectory = join(
    options.scanDirectory,
    "artifacts",
    "02_discovery",
  );
  await mkdir(discoveryDirectory, { recursive: true, mode: 0o700 });
  const rankInput = join(discoveryDirectory, "host_rank_input.jsonl");
  const inventory = join(discoveryDirectory, "in_scope_files.txt");
  const deepReviewInput = join(discoveryDirectory, "deep_review_input.jsonl");
  const securityGuidancePaths = join(
    discoveryDirectory,
    "security_guidance_paths.json",
  );
  const script = join(options.pluginRoot, "scripts", "generate_rank_input.py");
  const target = options.target;
  const rankRepository =
    target.kind === "refs" || target.kind === "working_tree"
      ? options.diffRepository ?? options.repository
      : options.repository;
  const args =
    target.kind === "refs" || target.kind === "working_tree"
      ? [
          "make-diff-rank-input",
          "--repo",
          rankRepository,
          "--base",
          target.base ?? "HEAD",
          "--mode",
          target.kind === "refs" ? "revisions" : "local-patch",
          ...(target.kind === "refs" ? ["--head", target.head ?? "HEAD"] : []),
          "--preview-bytes",
          "0",
          "--out",
          rankInput,
        ]
      : [
          "make-repo-rank-input",
          "--repo",
          options.repository,
          ...(target.kind === "paths"
            ? ["--scopes-file", requireScopesFile(options.scopesFile)]
            : []),
          "--preview-bytes",
          "0",
          "--out",
          rankInput,
        ];
  try {
    await execFile(options.python, ["-I", "-B", script, ...args], {
      env: options.environment,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      windowsHide: true,
      signal: options.signal,
    });
    await execFile(
      options.python,
      [
        "-I",
        "-B",
        join(options.pluginRoot, "scripts", "resolve_security_md.py"),
        "--repo",
        options.repository,
        "--list",
        "--out",
        securityGuidancePaths,
      ],
      {
        env: options.environment,
        encoding: "utf8",
        maxBuffer: 1024 * 1024,
        windowsHide: true,
        signal: options.signal,
      },
    );
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new CopilotSecurityError(
      `Could not generate the immutable scan inventory: ${processErrorDetail(error)}`,
      { cause: error },
    );
  }

  const metadata = await lstat(rankInput);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > 32 * 1024 * 1024
  ) {
    throw new CopilotSecurityError(
      "The generated scan worklist is not a bounded regular file.",
    );
  }
  const rankBytes = await readFile(rankInput);
  const guidanceMetadata = await lstat(securityGuidancePaths);
  if (
    !guidanceMetadata.isFile() ||
    guidanceMetadata.isSymbolicLink() ||
    guidanceMetadata.size > 1024 * 1024
  ) {
    throw new CopilotSecurityError(
      "The generated security-guidance inventory is not a bounded regular file.",
    );
  }
  let guidancePaths: unknown;
  try {
    guidancePaths = JSON.parse(await readFile(securityGuidancePaths, "utf8"));
  } catch (error) {
    throw new CopilotSecurityError(
      "The generated security-guidance inventory is invalid JSON.",
      { cause: error },
    );
  }
  if (
    !Array.isArray(guidancePaths) ||
    guidancePaths.some(
      (path) => typeof path !== "string" || !safeInventoryPath(path),
    )
  ) {
    throw new CopilotSecurityError(
      "The generated security-guidance inventory contains an invalid path.",
    );
  }
  const rows: Array<{ path: string; area: string }> = [];
  const seen = new Set<string>();
  for (const [index, line] of rankBytes
    .toString("utf8")
    .split(/\r?\n/u)
    .entries()) {
    if (line === "") continue;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch (error) {
      throw new CopilotSecurityError(
        `The generated scan worklist has invalid JSON at line ${index + 1}.`,
        { cause: error },
      );
    }
    if (
      !isRecord(value) ||
      typeof value["path"] !== "string" ||
      typeof value["area"] !== "string" ||
      !safeInventoryPath(value["path"]) ||
      seen.has(value["path"])
    ) {
      throw new CopilotSecurityError(
        `The generated scan worklist has an invalid path at line ${index + 1}.`,
      );
    }
    seen.add(value["path"]);
    rows.push({ path: value["path"], area: value["area"] });
  }
  const inventoryBytes = Buffer.from(
    rows.length === 0 ? "" : `${rows.map((row) => row.path).join("\n")}\n`,
    "utf8",
  );
  if (inventoryBytes.length > 8 * 1024 * 1024) {
    throw new CopilotSecurityError(
      "The generated scan inventory exceeds the deterministic size limit.",
    );
  }
  const deepReviewBytes = Buffer.from(
    rows
      .map((row) => JSON.stringify({ path: row.path, area: row.area }))
      .join("\n") + (rows.length === 0 ? "" : "\n"),
    "utf8",
  );
  await Promise.all([
    writeFile(inventory, inventoryBytes, { flag: "wx", mode: 0o400 }),
    writeFile(deepReviewInput, deepReviewBytes, { flag: "wx", mode: 0o400 }),
  ]);
  await Promise.all([
    chmod(rankInput, 0o400),
    chmod(inventory, 0o400),
    chmod(deepReviewInput, 0o400),
    chmod(securityGuidancePaths, 0o400),
  ]);
  const files = await Promise.all(
    [rankInput, inventory, deepReviewInput, securityGuidancePaths].map(
      async (path) => ({
        path,
        sha256: createHash("sha256")
          .update(await readFile(path))
          .digest("hex"),
      }),
    ),
  );
  return {
    fileCount: rows.length,
    repositoryPaths: rows.map((row) => row.path),
    files,
  };
}

/** Fail closed if a model or tool altered the host-owned worklist. */
export async function verifyCopilotScanInventory(
  snapshot: CopilotScanInventorySnapshot,
): Promise<void> {
  for (const file of snapshot.files) {
    const metadata = await lstat(file.path).catch(() => null);
    if (
      metadata === null ||
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      createHash("sha256")
        .update(await readFile(file.path))
        .digest("hex") !== file.sha256
    ) {
      throw new CopilotSecurityError(
        "The immutable host-generated scan inventory was modified during model execution.",
      );
    }
  }
}

/**
 * Bind every model-visible file to the authoritative target bytes. Callers
 * sandwich this comparison between workbench target-snapshot checks so a
 * mutable worktree cannot be attested as a different model input.
 */
export async function verifyCopilotAnalysisWorkspaceSnapshot(
  repository: string,
  stagedRepository: string,
  repositoryPaths: readonly string[],
): Promise<void> {
  const [sourceRoot, stagedRoot] = await Promise.all([
    realpath(repository),
    realpath(stagedRepository),
  ]);
  for (const path of repositoryPaths) {
    if (!safeInventoryPath(path)) {
      throw new CopilotSecurityError(
        "The model-visible repository inventory contains an unsafe path.",
      );
    }
    const source = join(sourceRoot, ...path.split("/"));
    const staged = join(stagedRoot, ...path.split("/"));
    const [sourceMetadata, stagedMetadata] = await Promise.all([
      lstat(source).catch(() => null),
      lstat(staged).catch(() => null),
    ]);
    if (
      sourceMetadata === null ||
      stagedMetadata === null ||
      !sourceMetadata.isFile() ||
      !stagedMetadata.isFile() ||
      sourceMetadata.isSymbolicLink() ||
      stagedMetadata.isSymbolicLink() ||
      sourceMetadata.size !== stagedMetadata.size
    ) {
      throw new CopilotSecurityError(
        "The disposable analysis workspace does not match the registered scan target.",
      );
    }
    const [sourceBytes, stagedBytes] = await Promise.all([
      readFile(source),
      readFile(staged),
    ]);
    if (
      !createHash("sha256")
        .update(sourceBytes)
        .digest()
        .equals(createHash("sha256").update(stagedBytes).digest())
    ) {
      throw new CopilotSecurityError(
        "The disposable analysis workspace does not match the registered scan target.",
      );
    }
  }
}

function requireScopesFile(path: string | undefined): string {
  if (path === undefined) {
    throw new CopilotSecurityError(
      "Scoped scans require a host-generated target-paths file.",
    );
  }
  return path;
}

function safeInventoryPath(path: string): boolean {
  if (
    path.length === 0 ||
    path.length > 4096 ||
    path.startsWith("/") ||
    path.includes("\\") ||
    MODEL_UNSAFE_PATH.test(path) ||
    /^[A-Za-z]:/u.test(path)
  ) {
    return false;
  }
  const parts = path.split("/");
  return parts.every(
    (part) => part.length > 0 && part !== "." && part !== "..",
  );
}

/**
 * Install a scanner-owned native Copilot CLI sandbox policy. The SDK runtime
 * reads this file through COPILOT_HOME before it creates the session.
 */
export async function writeCopilotScannerSandboxSettings(
  copilotHome: string,
  options: CopilotScannerSandboxOptions,
): Promise<void> {
  const [
    canonicalHome,
    repository,
    scanDirectory,
    pluginRoot,
    analysisWorkspace,
  ] = await Promise.all([
    realpath(copilotHome),
    realpath(options.repository),
    realpath(options.scanDirectory),
    realpath(options.pluginRoot),
    options.analysisWorkspace === undefined
      ? Promise.resolve(undefined)
      : realpath(options.analysisWorkspace),
  ]);
  const settingsPath = join(canonicalHome, "settings.json");
  const existing = await lstat(settingsPath).catch((error) => {
    if (nodeErrorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (existing !== null && (!existing.isFile() || existing.isSymbolicLink())) {
    throw new OutputDirectoryError(
      `Copilot Security sandbox settings are not a regular file: ${settingsPath}`,
    );
  }

  const sandbox = copilotScannerSandboxConfig(canonicalHome, {
    repository,
    scanDirectory,
    pluginRoot,
    ...(analysisWorkspace === undefined ? {} : { analysisWorkspace }),
  });
  const settings = {
    askUser: false,
    autoUpdate: false,
    experimental: true,
    includeCoAuthoredBy: false,
    remote: "off",
    remoteExport: false,
    permissions: { disableBypassPermissionsMode: "disable" },
    sandbox: {
      ...sandbox,
      allowBypass: false,
      gitAuth: false,
      ghAuth: false,
      sandboxMcpServers: true,
      sandboxLspServers: true,
    },
  };
  const temporary = join(
    canonicalHome,
    `.copilot-security-settings-${randomUUID()}.tmp`,
  );
  let created = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    created = true;
    try {
      await handle.chmod(0o600);
      await handle.writeFile(`${JSON.stringify(settings, null, 2)}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await replaceScannerSettings(temporary, settingsPath);
    created = false;
  } finally {
    if (created) await rm(temporary, { force: true }).catch(() => undefined);
  }
}

async function replaceScannerSettings(
  temporary: string,
  destination: string,
): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await rename(temporary, destination);
      return;
    } catch (error) {
      const code = nodeErrorCode(error);
      const retryable =
        process.platform === "win32" &&
        (code === "EACCES" || code === "EBUSY" || code === "EPERM");
      if (!retryable || attempt >= SETTINGS_REPLACE_ATTEMPTS) throw error;
      await delay(
        Math.min(
          SETTINGS_REPLACE_INITIAL_DELAY_MILLISECONDS * 2 ** (attempt - 1),
          SETTINGS_REPLACE_MAX_DELAY_MILLISECONDS,
        ),
      );
    }
  }
}

export function copilotSecurityStateDirectory(
  environment: ProcessEnvironment = process.env,
): string {
  const environmentValue = (requested: string): string | undefined => {
    const exact = environment[requested]?.trim();
    if (exact) return exact;
    return Object.entries(environment)
      .find(
        ([name, value]) => name.toUpperCase() === requested && value?.trim(),
      )?.[1]
      ?.trim();
  };
  const configured =
    environmentValue("COPILOT_SECURITY_HOME") ??
    environmentValue("COPILOT_SECURITY_STATE_DIR");
  if (configured !== undefined) return resolve(expandHome(configured));
  return resolve(homedir(), ".copilot-security");
}

export function copilotSecurityCredentialHome(
  environment: ProcessEnvironment = process.env,
): string {
  return join(
    copilotSecurityStateDirectory(environment),
    "copilot-security-home",
  );
}

export async function prepareCopilotSecurityCredentialHome(
  environment: ProcessEnvironment = process.env,
  validateLocation?: (path: string) => void,
): Promise<string> {
  const path = copilotSecurityCredentialHome(environment);
  try {
    try {
      await mkdir(path, { recursive: true, mode: 0o700 });
    } catch (error) {
      if (nodeErrorCode(error) === "EEXIST") {
        const existing = await lstat(path).catch(() => null);
        if (
          existing !== null &&
          (!existing.isDirectory() || existing.isSymbolicLink())
        ) {
          throw new OutputDirectoryError(
            `Copilot Security home is not a directory: ${path}`,
            { cause: error },
          );
        }
      }
      throw error;
    }
    if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    const metadata = await lstat(path);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new OutputDirectoryError(
        `Copilot Security home is not a directory: ${path}`,
      );
    }
    const canonical = await realpath(path);
    requireModelSafeOutputDir(canonical);
    validateLocation?.(canonical);
    await requirePrivateCredentialHome(metadata, canonical);
    return canonical;
  } catch (error) {
    if (error instanceof OutputDirectoryError) throw error;
    throw new OutputDirectoryError(
      `Unable to prepare the Copilot Security home: ${path}`,
      { cause: error },
    );
  }
}

export async function requirePrivateCredentialHome(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  options: {
    platform?: NodeJS.Platform;
    secureWindowsHome?: (path: string) => Promise<void>;
  } = {},
): Promise<void> {
  if ((options.platform ?? process.platform) !== "win32") {
    requirePrivateOutputDirectory(metadata, path);
    return;
  }

  try {
    await (options.secureWindowsHome ?? secureWindowsCredentialHome)(path);
  } catch (error) {
    throw new OutputDirectoryError(
      `Unable to create a private Windows credential home: ${path}`,
      { cause: error },
    );
  }
}

async function secureWindowsCredentialHome(path: string): Promise<void> {
  const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
  const powershell = join(
    systemRoot,
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$path = [Environment]::GetEnvironmentVariable('COPILOT_SECURITY_HOME_ACL_PATH', 'Process')",
    "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()",
    "if ($null -eq $identity.User) { throw 'Unable to identify the current Windows user' }",
    "$acl = New-Object System.Security.AccessControl.DirectorySecurity",
    "$acl.SetAccessRuleProtection($true, $false)",
    "$inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit",
    "$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity.User, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)",
    "$acl.SetOwner($identity.User)",
    "$acl.SetAccessRule($rule)",
    "[System.IO.Directory]::SetAccessControl($path, $acl)",
    "$verified = [System.IO.Directory]::GetAccessControl($path)",
    "if (-not $verified.AreAccessRulesProtected) { throw 'Credential ACL still inherits access rules' }",
    "$unexpected = @($verified.Access | Where-Object { $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -ne $identity.User.Value })",
    "if ($unexpected.Count -ne 0) { throw 'Credential ACL grants access to another identity' }",
  ].join("; ");
  await execFile(
    powershell,
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
    {
      env: {
        ...process.env,
        COPILOT_SECURITY_HOME_ACL_PATH: path,
      },
      encoding: "utf8",
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    },
  );
}

export async function acquireCopilotSecurityCredentialHomeLock(
  copilotHome: string,
  signal?: AbortSignal,
): Promise<() => Promise<void>> {
  const lock = join(copilotHome, CREDENTIAL_LOCK_NAME);
  const ownerPath = join(lock, "owner.json");
  const token = randomUUID();

  while (true) {
    throwIfSignalAborted(signal);
    try {
      await mkdir(lock, { mode: 0o700 });
    } catch (error) {
      if (nodeErrorCode(error) !== "EEXIST") throw error;
      if (await recoverStaleCredentialHomeLock(lock)) continue;
      await delay(CREDENTIAL_LOCK_POLL_MILLISECONDS, undefined, { signal });
      continue;
    }

    try {
      await writeFile(
        ownerPath,
        `${JSON.stringify({ pid: process.pid, token })}\n`,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      );
    } catch (error) {
      await rm(lock, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }

    let released = false;
    return async () => {
      if (released) return;
      const owner = JSON.parse(await readFile(ownerPath, "utf8")) as {
        token?: unknown;
      };
      if (owner.token !== token) {
        throw new PluginBootstrapError(
          "The Copilot Security home lock is no longer owned by this scan.",
        );
      }
      await rm(lock, { recursive: true, force: true });
      released = true;
    };
  }
}

async function recoverStaleCredentialHomeLock(lock: string): Promise<boolean> {
  const metadata = await lstat(lock).catch((error: unknown) => {
    if (nodeErrorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (metadata === null) return true;
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new OutputDirectoryError(
      `Copilot Security home lock is not a directory: ${lock}`,
    );
  }

  let owner: unknown;
  try {
    owner = JSON.parse(await readFile(join(lock, "owner.json"), "utf8"));
  } catch (error) {
    if (nodeErrorCode(error) !== "ENOENT" && !(error instanceof SyntaxError)) {
      throw error;
    }
    if (
      Date.now() - metadata.mtimeMs <
      INCOMPLETE_CREDENTIAL_LOCK_MILLISECONDS
    ) {
      return false;
    }
  }

  if (isRecord(owner) && typeof owner["pid"] === "number") {
    try {
      process.kill(owner["pid"], 0);
      return false;
    } catch (error) {
      if (nodeErrorCode(error) !== "ESRCH") {
        if (nodeErrorCode(error) === "EPERM") return false;
        throw error;
      }
    }
  } else if (
    Date.now() - metadata.mtimeMs <
    INCOMPLETE_CREDENTIAL_LOCK_MILLISECONDS
  ) {
    return false;
  }

  const quarantine = `${lock}.stale-${randomUUID()}`;
  try {
    await rename(lock, quarantine);
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return true;
    throw error;
  }
  await rm(quarantine, { recursive: true, force: true });
  return true;
}

export async function setCopilotSecurityCredentialLogout(
  copilotHome: string,
  loggedOut: boolean,
): Promise<void> {
  const marker = join(copilotHome, CREDENTIAL_LOGOUT_MARKER);
  if (!loggedOut) {
    await rm(marker, { force: true });
    return;
  }

  const temporary = join(
    copilotHome,
    `.copilot-security-logout-${randomUUID()}.tmp`,
  );
  try {
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.chmod(0o600);
      await handle.writeFile("logged out\n", "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, marker);
  } finally {
    await rm(temporary, { force: true });
  }
}

export async function copilotSecurityCredentialAllowsAmbientImport(
  copilotHome: string,
): Promise<boolean> {
  try {
    const marker = await lstat(join(copilotHome, CREDENTIAL_LOGOUT_MARKER));
    if (!marker.isFile() || marker.isSymbolicLink()) {
      throw new OutputDirectoryError(
        `Copilot Security logout marker is not a regular file: ${copilotHome}`,
      );
    }
    return false;
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return true;
    throw error;
  }
}

export async function copilotSecurityHasStoredFileCredentials(
  copilotHome: string,
): Promise<boolean> {
  const path = join(copilotHome, "auth.json");
  let metadata: Stats;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return false;
    throw error;
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new OutputDirectoryError(
      `Copilot Security stored authentication is not a regular file: ${path}`,
    );
  }
  return true;
}

export async function preserveCopilotSecurityPluginRegistration(
  copilotHome: string,
  config: JsonObject,
): Promise<JsonObject> {
  let existing: unknown;
  try {
    existing = parse(await readFile(join(copilotHome, "config.toml"), "utf8"));
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return config;
    throw new PluginBootstrapError(
      "Unable to read the existing Copilot Security plugin registration.",
      { cause: error },
    );
  }

  const marketplaces = isRecord(existing)
    ? existing["marketplaces"]
    : undefined;
  const plugins = isRecord(existing) ? existing["plugins"] : undefined;
  const marketplace = isRecord(marketplaces)
    ? marketplaces[MARKETPLACE_NAME]
    : undefined;
  const plugin = isRecord(plugins)
    ? plugins[`${PLUGIN_NAME}@${MARKETPLACE_NAME}`]
    : undefined;
  const source = isRecord(marketplace) ? marketplace["source"] : undefined;
  if (
    !isRecord(marketplace) ||
    marketplace["source_type"] !== "local" ||
    typeof source !== "string" ||
    !(await sameFile(source, join(copilotHome, "sdk-marketplace"))) ||
    !isRecord(plugin) ||
    plugin["enabled"] !== true
  ) {
    return config;
  }

  return {
    ...config,
    marketplaces: {
      [MARKETPLACE_NAME]: { source_type: "local", source },
    },
    plugins: {
      [`${PLUGIN_NAME}@${MARKETPLACE_NAME}`]: { enabled: true },
    },
  };
}

export async function preparePersistentScanRoot(
  stateDirectory: string,
  repositoryName: string,
): Promise<string> {
  const root = join(stateDirectory, "scans", safePrefix(repositoryName));
  await mkdir(root, { recursive: true, mode: 0o700 });
  return await realpath(root);
}

export async function runWorkbench(
  options: WorkbenchCommandOptions,
  args: readonly string[],
): Promise<JsonObject> {
  let stdout: string;
  try {
    ({ stdout } = await execFile(
      options.python,
      [
        "-I",
        "-B",
        join(options.pluginRoot, "scripts", "workbench_db.py"),
        ...args,
      ],
      {
        env: options.environment,
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
        signal: options.signal,
      },
    ));
  } catch (error) {
    if (options.signal?.aborted) throw error;
    const detail = processErrorDetail(error);
    const databaseFailure =
      /\b(?:unable to open database file|attempt to write a readonly database|readonly database|disk i\/o error)\b/iu.test(
        detail,
      );
    const failure =
      options.failureMessage ?? "Could not run the Copilot Security workbench";
    throw new CopilotSecurityError(
      databaseFailure
        ? `${failure}: cannot open the workbench database at ${join(
            copilotSecurityStateDirectory(options.environment),
            "workbench.sqlite3",
          )}. Ensure the state directory and SQLite journal files are writable, or set COPILOT_SECURITY_HOME to a writable directory outside the scanned repository.`
        : `${failure}: ${detail}`,
      { cause: error },
    );
  }
  let result: unknown;
  try {
    result = JSON.parse(stdout);
  } catch (error) {
    throw new CopilotSecurityError(
      "The Copilot Security workbench returned invalid JSON.",
      { cause: error },
    );
  }
  if (!isRecord(result)) {
    throw new CopilotSecurityError(
      "The Copilot Security workbench returned an invalid response.",
    );
  }
  return result as JsonObject;
}

export function bundledPluginCandidates(moduleDirectory: string): string[] {
  const packageCandidates = [
    resolve(moduleDirectory, "_bundled_plugin"),
    resolve(moduleDirectory, "../_bundled_plugin"),
  ];
  return basename(moduleDirectory) === "src"
    ? [
        resolve(moduleDirectory, "../../../plugins/copilot-security"),
        ...packageCandidates,
      ]
    : packageCandidates;
}

export async function bundledPluginRoot(): Promise<string> {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  for (const candidate of bundledPluginCandidates(moduleDirectory)) {
    if (await hasPluginManifest(candidate)) {
      return await realpath(candidate);
    }
  }
  throw new PluginBootstrapError(
    "The bundled Copilot Security plugin is missing.",
  );
}

export async function validateOutputDir(
  outputDirectory?: string,
  archiveExisting = false,
): Promise<string | null> {
  if (outputDirectory === undefined) {
    return null;
  }
  requireModelSafeOutputDir(outputDirectory);
  const path = resolve(expandHome(outputDirectory));
  try {
    const metadata = await lstat(path).catch((error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (metadata !== null) {
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        throw new OutputDirectoryError(
          `Scan output is not a directory: ${path}`,
        );
      }
      if (!archiveExisting && (await readdir(path)).length !== 0) {
        throw new OutputDirectoryError(
          `Scan output directory is not empty: ${path}. To keep the existing results and start a new scan, add --archive-existing.`,
        );
      }
      requirePrivateOutputDirectory(metadata, path);
      const canonical = await realpath(path);
      requireModelSafeOutputDir(canonical);
      return canonical;
    }

    let parent = dirname(path);
    while (true) {
      try {
        if ((await stat(parent)).isDirectory()) {
          const canonical = resolve(
            await realpath(parent),
            relative(parent, path),
          );
          requireModelSafeOutputDir(canonical);
          return canonical;
        }
        break;
      } catch (error) {
        if (nodeErrorCode(error) !== "ENOENT") throw error;
        const next = dirname(parent);
        if (next === parent) break;
        parent = next;
      }
    }
    throw new OutputDirectoryError(
      `Unable to create scan output directory: ${path}`,
    );
  } catch (error) {
    if (error instanceof OutputDirectoryError) throw error;
    throw new OutputDirectoryError(
      `Unable to inspect scan output directory: ${outputDirectory}`,
      { cause: error },
    );
  }
}

export async function planOutputArchive(
  outputDirectory: string | null,
): Promise<string | null> {
  if (outputDirectory === null) return null;
  const entries = await readdir(outputDirectory).catch((error: unknown) => {
    if (nodeErrorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (entries === null || entries.length === 0) return null;
  const timestamp = new Date()
    .toISOString()
    .replaceAll(/[-:]/g, "")
    .replace(/\.\d{3}Z$/, "");
  return `${outputDirectory}.previous-${timestamp}-${randomUUID().slice(0, 8)}`;
}

export function requireModelSafeOutputDir(path: string): void {
  if (MODEL_UNSAFE_PATH.test(path)) {
    throw new OutputDirectoryError(
      "Scan output directory must not contain control or line-separator characters.",
    );
  }
}

export async function prepareOutputDir(
  outputDirectory: string | undefined,
  repositoryName: string,
  temporaryRoot: string = tmpdir(),
  validateLocation?: (path: string) => void,
  archiveExisting = false,
  onOutputArchived?: (archiveDir: string) => void,
): Promise<string> {
  if (outputDirectory === undefined) {
    requireModelSafeOutputDir(temporaryRoot);
    requireModelSafeOutputDir(await realpath(temporaryRoot));
  }
  const path = await validateOutputDir(outputDirectory, archiveExisting);
  validateLocation?.(path ?? (await realpath(temporaryRoot)));
  if (path === null) {
    const created = await mkdtemp(
      join(temporaryRoot, `copilot-security-${safePrefix(repositoryName)}-`),
    );
    if ((process.umask() & 0o700) !== 0) await chmod(created, 0o700);
    try {
      return await validatePreparedOutputDir(created, validateLocation);
    } catch (error) {
      await rmdir(created).catch(() => undefined);
      throw error;
    }
  }
  let createdRoot: string | undefined;
  try {
    let existing = await lstat(path).catch((error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (existing !== null && archiveExisting) {
      const archiveDir = await planOutputArchive(path);
      if (archiveDir !== null) {
        await rename(path, archiveDir);
        onOutputArchived?.(archiveDir);
        existing = null;
      }
    }
    if (existing === null) {
      createdRoot = await mkdir(path, { recursive: true, mode: 0o700 });
      if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    }
    return await validatePreparedOutputDir(path, validateLocation);
  } catch (error) {
    if (createdRoot !== undefined) {
      await removeEmptyDirectories(path, createdRoot);
    }
    if (error instanceof OutputDirectoryError) throw error;
    throw new OutputDirectoryError(
      `Unable to create scan output directory: ${path}`,
      {
        cause: error,
      },
    );
  }
}

export async function validatePreparedOutputDir(
  path: string,
  validateLocation?: (path: string) => void,
): Promise<string> {
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new OutputDirectoryError(`Scan output is not a directory: ${path}`);
  }
  const canonical = await realpath(path);
  requireModelSafeOutputDir(canonical);
  validateLocation?.(canonical);
  const entries = await readdir(canonical);
  if (entries.length !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must be empty: ${path}`,
    );
  }
  requirePrivateOutputDirectory(metadata, path);
  return canonical;
}

export function requirePrivateOutputDirectory(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  effectiveUid = process.geteuid?.(),
): void {
  if (process.platform === "win32") return;
  if ((metadata.mode & 0o077) !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must not be accessible to other users (chmod 700): ${path}`,
    );
  }
  if (effectiveUid !== undefined && metadata.uid !== effectiveUid) {
    throw new OutputDirectoryError(
      `Scan output directory must be owned by the current user: ${path}`,
    );
  }
}

async function removeEmptyDirectories(
  path: string,
  root: string,
): Promise<void> {
  let current = path;
  while (true) {
    try {
      await rmdir(current);
    } catch {
      return;
    }
    if (current === root) return;
    current = dirname(current);
  }
}

export async function createIsolatedHome(
  temporaryRoot: string = tmpdir(),
  validateLocation?: (path: string) => void,
): Promise<string> {
  const path = await mkdtemp(
    join(temporaryRoot, "secwest-copilot-security-home-"),
  );
  try {
    if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    return await validatePreparedOutputDir(path, validateLocation);
  } catch (error) {
    await rmdir(path).catch(() => undefined);
    throw error;
  }
}

export async function importAmbientAuth(
  ambientHome: string,
  isolatedHome: string,
): Promise<boolean> {
  const importedFileCredentials = await importAmbientFileCredentials(
    ambientHome,
    isolatedHome,
  );
  const importedAccountSelection = await importAmbientAccountSelection(
    ambientHome,
    isolatedHome,
  );
  return importedFileCredentials || importedAccountSelection;
}

async function importAmbientFileCredentials(
  ambientHome: string,
  isolatedHome: string,
): Promise<boolean> {
  const source = join(expandHome(ambientHome), "auth.json");
  let metadata;
  try {
    metadata = await stat(source);
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return false;
    throw new PluginBootstrapError(
      `Unable to inspect ambient Copilot authentication: ${source}`,
      {
        cause: error,
      },
    );
  }
  if (!metadata.isFile()) {
    return false;
  }
  await mkdir(isolatedHome, { recursive: true, mode: 0o700 });
  if (await copilotSecurityHasStoredFileCredentials(isolatedHome)) return true;
  const destination = join(isolatedHome, "auth.json");
  const temporary = join(isolatedHome, `.auth-${randomUUID()}.tmp`);
  try {
    await copyFile(source, temporary, constants.COPYFILE_EXCL);
    await chmod(temporary, 0o600);
    try {
      await copyFile(temporary, destination, constants.COPYFILE_EXCL);
    } catch (error) {
      if (
        nodeErrorCode(error) === "EEXIST" &&
        (await copilotSecurityHasStoredFileCredentials(isolatedHome))
      ) {
        return true;
      }
      throw error;
    }
    await chmod(destination, 0o600);
    return true;
  } catch (error) {
    throw new PluginBootstrapError(
      "Unable to copy ambient Copilot authentication.",
      {
        cause: error,
      },
    );
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

/**
 * Copilot CLI's OS credential-store entries are selected by the non-secret
 * loggedInUsers/lastLoggedInUser metadata in config.json. A fresh isolated
 * COPILOT_HOME otherwise silently falls back to gh auth, which may be a
 * different account with different model entitlements. Import only the active
 * account selector—not settings, experiments, trust state, sessions, or
 * tokens—and never replace an account explicitly selected in the scanner home.
 */
async function importAmbientAccountSelection(
  ambientHome: string,
  isolatedHome: string,
): Promise<boolean> {
  const source = join(expandHome(ambientHome), "config.json");
  const ambient = await readCopilotAccountConfig(source, true);
  const selected = copilotAccountSelection(ambient);
  if (selected === null) return false;

  await mkdir(isolatedHome, { recursive: true, mode: 0o700 });
  const destination = join(isolatedHome, "config.json");
  const isolated = await readCopilotAccountConfig(destination, false);
  if (copilotAccountSelection(isolated) !== null) return true;

  const updated: JsonObject = {
    ...(isRecord(isolated) ? (isolated as JsonObject) : {}),
    loggedInUsers: [selected],
    lastLoggedInUser: selected,
  };
  const temporary = join(isolatedHome, `.copilot-account-${randomUUID()}.tmp`);
  try {
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.chmod(0o600);
      await handle.writeFile(
        `// User settings belong in settings.json.\n// This file is managed automatically.\n${JSON.stringify(updated, null, 2)}\n`,
        "utf8",
      );
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, destination);
    return true;
  } catch (error) {
    throw new PluginBootstrapError(
      "Unable to import the ambient Copilot account selection.",
      { cause: error },
    );
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

async function readCopilotAccountConfig(
  path: string,
  ambient: boolean,
): Promise<unknown> {
  let metadata: Stats;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return {};
    throw new PluginBootstrapError(
      `Unable to inspect ${ambient ? "ambient" : "isolated"} Copilot account metadata.`,
      { cause: error },
    );
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > MAX_COPILOT_ACCOUNT_CONFIG_SIZE
  ) {
    throw new PluginBootstrapError(
      `${ambient ? "Ambient" : "Isolated"} Copilot account metadata is not a bounded regular file.`,
    );
  }
  try {
    const contents = await readFile(path, "utf8");
    const objectStart = contents.indexOf("{");
    if (objectStart < 0) return {};
    return JSON.parse(contents.slice(objectStart));
  } catch (error) {
    throw new PluginBootstrapError(
      `Unable to read ${ambient ? "ambient" : "isolated"} Copilot account metadata.`,
      { cause: error },
    );
  }
}

function copilotAccountSelection(value: unknown): JsonObject | null {
  if (!isRecord(value) || !isRecord(value["lastLoggedInUser"])) return null;
  const host = value["lastLoggedInUser"]["host"];
  const login = value["lastLoggedInUser"]["login"];
  if (
    typeof host !== "string" ||
    typeof login !== "string" ||
    login.length < 1 ||
    login.length > 256 ||
    MODEL_UNSAFE_PATH.test(login)
  ) {
    return null;
  }
  try {
    const parsed = new URL(host);
    if (
      parsed.protocol !== "https:" ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.search !== "" ||
      parsed.hash !== "" ||
      (parsed.pathname !== "" && parsed.pathname !== "/")
    ) {
      return null;
    }
    return { host: parsed.origin, login };
  } catch {
    return null;
  }
}

export async function extractPluginZip(
  archive: string,
  destination: string,
  signal?: AbortSignal,
): Promise<string> {
  const archivePath = resolve(expandHome(archive));
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const staging = await realpath(
    await mkdtemp(join(dirname(destination), ".copilot-security-plugin-")),
  );
  try {
    throwIfSignalAborted(signal);
    await rejectBackslashZipNames(archivePath, signal);
    let expandedSize = 0;
    const paths = new Set<string>();
    const checksums: Array<{ path: string; checksum: number }> = [];
    await extractZip(archivePath, {
      dir: staging,
      defaultDirMode: 0o700,
      defaultFileMode: 0o600,
      onEntry(entry, archive) {
        throwIfSignalAborted(signal);
        if (archive.entryCount > MAX_ZIP_ENTRIES) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains too many entries: ${archive.entryCount}.`,
          );
        }
        const path = safeArchivePath(entry.fileName);
        const collisionKey = path.toLowerCase();
        if (paths.has(collisionKey)) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains a duplicate path: ${entry.fileName}`,
          );
        }
        paths.add(collisionKey);
        if (((entry.externalFileAttributes >>> 16) & 0o170000) === 0o120000) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains an unsafe path: ${entry.fileName}`,
          );
        }
        if (entry.uncompressedSize > MAX_ZIP_ENTRY_SIZE) {
          throw new PluginBootstrapError(
            `Plugin ZIP entry exceeds the safety limit: ${entry.fileName}`,
          );
        }
        expandedSize += entry.uncompressedSize;
        if (expandedSize > MAX_ZIP_EXPANDED_SIZE) {
          throw new PluginBootstrapError(
            "Plugin ZIP expanded size exceeds the safety limit.",
          );
        }
        const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
        const directory =
          entry.fileName.endsWith("/") ||
          mode === 0o040000 ||
          (entry.versionMadeBy >>> 8 === 0 &&
            entry.externalFileAttributes === 16);
        if (!directory) {
          checksums.push({ path, checksum: entry.crc32 >>> 0 });
        }
      },
    });
    for (const { path, checksum } of checksums) {
      throwIfSignalAborted(signal);
      const bytes = await readFile(join(staging, ...path.split("/")));
      if (crc32(bytes) !== checksum) {
        throw new PluginBootstrapError(
          `Plugin ZIP entry failed CRC-32 validation: ${path}`,
        );
      }
    }
    const pluginRoot = await discoverPluginRoot(staging);
    throwIfSignalAborted(signal);
    const relativeRoot = relative(staging, pluginRoot);
    await rename(staging, destination);
    return await validatePluginRoot(join(destination, relativeRoot));
  } catch (error) {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    throwIfSignalAborted(signal);
    if (error instanceof PluginBootstrapError) throw error;
    throw new PluginBootstrapError(`Invalid plugin ZIP: ${archivePath}`, {
      cause: error,
    });
  }
}

async function rejectBackslashZipNames(
  path: string,
  signal?: AbortSignal,
): Promise<void> {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size < 22) {
      throw new Error("missing end of central directory");
    }
    const tailSize = Math.min(metadata.size, 65_557);
    const tail = await readExactly(
      handle,
      tailSize,
      metadata.size - tailSize,
      signal,
    );
    let end = tail.byteLength - 22;
    while (
      end >= 0 &&
      (tail.readUInt32LE(end) !== 0x06054b50 ||
        end + 22 + tail.readUInt16LE(end + 20) !== tail.byteLength)
    ) {
      end -= 1;
    }
    if (end < 0) throw new Error("missing end of central directory");
    const entries = tail.readUInt16LE(end + 10);
    const centralSize = tail.readUInt32LE(end + 12);
    const centralOffset = tail.readUInt32LE(end + 16);
    if (
      entries === 0xffff ||
      centralSize === 0xffffffff ||
      centralOffset === 0xffffffff
    ) {
      throw new Error("unsupported ZIP64 archive");
    }
    if (entries > MAX_ZIP_ENTRIES) {
      throw new PluginBootstrapError(
        `Plugin ZIP contains too many entries: ${entries}.`,
      );
    }
    if (centralSize > MAX_ZIP_CENTRAL_DIRECTORY) {
      throw new PluginBootstrapError(
        "Plugin ZIP central directory exceeds the safety limit.",
      );
    }
    const endOffset = metadata.size - tailSize + end;
    if (centralOffset + centralSize > endOffset) {
      throw new Error("invalid central directory bounds");
    }
    const central = await readExactly(
      handle,
      centralSize,
      centralOffset,
      signal,
    );
    let offset = 0;
    for (let index = 0; index < entries; index += 1) {
      if (
        offset + 46 > central.byteLength ||
        central.readUInt32LE(offset) !== 0x02014b50
      ) {
        throw new Error("invalid central directory");
      }
      const nameLength = central.readUInt16LE(offset + 28);
      const extraLength = central.readUInt16LE(offset + 30);
      const commentLength = central.readUInt16LE(offset + 32);
      const nameStart = offset + 46;
      const nameEnd = nameStart + nameLength;
      if (nameEnd > central.byteLength) {
        throw new Error("invalid central directory name");
      }
      if (central.subarray(nameStart, nameEnd).includes(0x5c)) {
        throw new PluginBootstrapError(
          "Plugin ZIP contains a backslash-qualified path.",
        );
      }
      offset = nameEnd + extraLength + commentLength;
    }
    if (offset !== central.byteLength) {
      throw new Error("invalid central directory size");
    }
  } finally {
    await handle.close();
  }
}

export async function resolvePluginPath(
  pluginPath: string | undefined,
  workspace: string,
  signal?: AbortSignal,
): Promise<string> {
  if (pluginPath === undefined) {
    return await bundledPluginRoot();
  }

  const path = resolve(expandHome(pluginPath));
  const metadata = await lstat(path).catch(() => null);
  if (metadata?.isFile() && extname(path).toLowerCase() === ".zip") {
    return await extractPluginZip(
      path,
      join(workspace, "extracted-plugin"),
      signal,
    );
  }
  if (metadata?.isDirectory() && !metadata.isSymbolicLink()) {
    throwIfSignalAborted(signal);
    return await validatePluginRoot(path);
  }
  throw new PluginBootstrapError(
    `Plugin path must be a directory or ZIP: ${path}`,
  );
}

export async function createMarketplace(
  copilotHome: string,
  pluginRoot: string,
  signal?: AbortSignal,
): Promise<string> {
  throwIfSignalAborted(signal);
  const root = await realpath(pluginRoot);
  const marketplace = join(copilotHome, "sdk-marketplace");
  const pluginDestination = join(marketplace, "plugins", PLUGIN_NAME);
  const projectionContract = join(
    root,
    ".internal",
    "external-promotion",
    "external-projection-contract.json",
  );
  if (
    root === (await bundledPluginRoot()) &&
    (await isRegularFile(projectionContract))
  ) {
    await copyExternalPayload(root, pluginDestination);
  } else {
    await copyPluginTree(root, pluginDestination, signal);
  }
  throwIfSignalAborted(signal);
  const manifest = {
    name: MARKETPLACE_NAME,
    interface: { displayName: "Copilot Security SDK" },
    plugins: [
      {
        name: PLUGIN_NAME,
        source: { source: "local", path: `./plugins/${PLUGIN_NAME}` },
        policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
        category: "Security",
      },
    ],
  };
  const manifestPath = join(
    marketplace,
    ".agents",
    "plugins",
    "marketplace.json",
  );
  await mkdir(dirname(manifestPath), { recursive: true, mode: 0o700 });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
    signal,
  });
  throwIfSignalAborted(signal);
  return marketplace;
}

async function pluginProjectionFingerprint(
  root: string,
  signal?: AbortSignal,
): Promise<string> {
  throwIfSignalAborted(signal);
  const canonical = await realpath(root);
  const contractPath = join(
    canonical,
    ".internal",
    "external-promotion",
    "external-projection-contract.json",
  );
  let paths: string[];

  if (
    canonical === (await bundledPluginRoot()) &&
    (await isRegularFile(contractPath))
  ) {
    let contract: unknown;
    try {
      contract = JSON.parse(await readFile(contractPath, "utf8"));
    } catch (error) {
      throw new PluginBootstrapError(
        `Invalid plugin projection contract: ${contractPath}`,
        { cause: error },
      );
    }
    const shipped = isRecord(contract) ? contract["shippedExact"] : undefined;
    if (
      !Array.isArray(shipped) ||
      !shipped.every((path) => typeof path === "string")
    ) {
      throw new PluginBootstrapError(
        "Plugin projection contract must contain shippedExact paths.",
      );
    }
    paths = [
      ...new Set(
        ["plugin.json", ...shipped]
          .filter((path) => !path.startsWith("sdk/"))
          .map((path) => safeArchivePath(path)),
      ),
    ];
  } else {
    paths = [];
    const pending = [canonical];
    let entries = 0;
    while (pending.length > 0) {
      throwIfSignalAborted(signal);
      const path = pending.pop()!;
      const metadata = await lstat(path);
      if (++entries > MAX_PLUGIN_COPY_ENTRIES) {
        throw new PluginBootstrapError(
          `Plugin source exceeds the copy entry limit: ${path}`,
        );
      }
      if (metadata.isSymbolicLink()) {
        throw new PluginBootstrapError(
          `Plugin contains an unsafe source path: ${path}`,
        );
      }
      if (metadata.isDirectory()) {
        for (const entry of await readdir(path)) {
          pending.push(join(path, entry));
        }
      } else if (metadata.isFile()) {
        paths.push(relative(canonical, path).split(sep).join("/"));
      } else {
        throw new PluginBootstrapError(
          `Plugin contains a non-regular file: ${path}`,
        );
      }
    }
  }

  paths.sort();
  const fingerprint = createHash("sha256");
  let totalSize = 0;
  for (const relativePath of paths) {
    throwIfSignalAborted(signal);
    const path = join(canonical, ...relativePath.split("/"));
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new PluginBootstrapError(
        `Plugin projection contains an unsafe source path: ${path}`,
      );
    }
    if (metadata.size > MAX_PLUGIN_COPY_FILE_SIZE) {
      throw new PluginBootstrapError(
        `Plugin source exceeds the per-file safety limit: ${path}`,
      );
    }
    totalSize += metadata.size;
    if (totalSize > MAX_PLUGIN_COPY_SIZE) {
      throw new PluginBootstrapError(
        "Plugin source exceeds the copy safety limit.",
      );
    }
    const handle = await open(
      path,
      constants.O_RDONLY |
        (process.platform === "win32"
          ? 0
          : constants.O_NOFOLLOW | constants.O_NONBLOCK),
    );
    try {
      if (!samePluginFile(metadata, await handle.stat())) {
        throw new PluginBootstrapError(
          `Plugin source changed before its integrity could be verified: ${path}`,
        );
      }
      const contents = await readExactly(handle, metadata.size, 0, signal);
      if (!samePluginFile(metadata, await handle.stat())) {
        throw new PluginBootstrapError(
          `Plugin source changed while its integrity was being verified: ${path}`,
        );
      }
      fingerprint.update(relativePath);
      fingerprint.update("\0");
      fingerprint.update(String(metadata.size));
      fingerprint.update("\0");
      fingerprint.update(contents);
      fingerprint.update("\0");
    } finally {
      await handle.close();
    }
  }
  return fingerprint.digest("hex");
}

async function copilotSecurityPluginRegistration(
  copilotHome: string,
): Promise<{ marketplace: boolean; plugin: boolean }> {
  let config: unknown;
  try {
    config = parse(await readFile(join(copilotHome, "config.toml"), "utf8"));
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") {
      return { marketplace: false, plugin: false };
    }
    throw new PluginBootstrapError(
      "Unable to inspect the existing Copilot Security plugin registration.",
      { cause: error },
    );
  }
  const marketplaces = isRecord(config) ? config["marketplaces"] : undefined;
  const plugins = isRecord(config) ? config["plugins"] : undefined;
  return {
    marketplace:
      isRecord(marketplaces) && isRecord(marketplaces[MARKETPLACE_NAME]),
    plugin:
      isRecord(plugins) &&
      isRecord(plugins[`${PLUGIN_NAME}@${MARKETPLACE_NAME}`]),
  };
}

export function resolveCopilotCommand(): CopilotCommand {
  return {
    command: process.env["COPILOT_CLI_PATH"]?.trim() || "copilot",
    prefixArgs: [],
  };
}

export async function bootstrapPlugin(
  copilotHome: string,
  pluginRoot: string,
  options: {
    copilotCommand?: CopilotCommand;
    runCopilot?: (
      command: CopilotCommand,
      args: readonly string[],
      environment: ProcessEnvironment,
      signal?: AbortSignal,
    ) => Promise<string>;
    environment?: ProcessEnvironment;
    signal?: AbortSignal;
  } = {},
): Promise<PluginInstall> {
  const root = await realpath(pluginRoot);
  const { name, version } = await pluginMetadata(root);
  const existingMarketplace = join(copilotHome, "sdk-marketplace");
  let upgradeExistingPlugin = false;
  let repairIncompletePlugin = false;
  let installedRoot: string | null = null;
  try {
    await verifyPluginRegistration(copilotHome, existingMarketplace);
    installedRoot = await findInstalledPlugin(copilotHome);
  } catch (error) {
    throwIfSignalAborted(options.signal);
    if (
      !(error instanceof PluginBootstrapError) &&
      nodeErrorCode(error) !== "ENOENT"
    ) {
      throw error;
    }
    const marketplace = await lstat(existingMarketplace).catch(
      (failure: unknown) => {
        if (nodeErrorCode(failure) === "ENOENT") return null;
        throw failure;
      },
    );
    if (
      marketplace !== null &&
      (!marketplace.isDirectory() || marketplace.isSymbolicLink())
    ) {
      throw new PluginBootstrapError(
        `Copilot Security marketplace is not a safe directory: ${existingMarketplace}`,
      );
    }
    const registration = await copilotSecurityPluginRegistration(copilotHome);
    repairIncompletePlugin =
      marketplace !== null || registration.marketplace || registration.plugin;
  }

  if (installedRoot !== null) {
    const installed = await pluginMetadata(installedRoot);
    if (installed.name === name && installed.version === version) {
      const [selectedFingerprint, marketplaceFingerprint] = await Promise.all([
        pluginProjectionFingerprint(root, options.signal),
        pluginProjectionFingerprint(
          join(existingMarketplace, "plugins", PLUGIN_NAME),
          options.signal,
        ),
      ]);
      if (selectedFingerprint === marketplaceFingerprint) {
        return {
          pluginRoot: root,
          marketplaceRoot: existingMarketplace,
          installedRoot,
          marketplaceName: MARKETPLACE_NAME,
          name,
          version,
        };
      }
    }
    upgradeExistingPlugin = true;
  }

  throwIfSignalAborted(options.signal);
  const baseEnvironment = options.environment ?? process.env;
  const configuredCommand = Object.entries(baseEnvironment).find(
    ([name]) => name.toUpperCase() === "COPILOT_CLI_PATH",
  )?.[1];
  const unresolvedCommand =
    options.copilotCommand ??
    (configuredCommand?.trim()
      ? { command: configuredCommand.trim(), prefixArgs: [] }
      : resolveCopilotCommand());
  const directTrustedCommand =
    options.copilotCommand === undefined
      ? await resolveTrustedExecutable(
          unresolvedCommand.command,
          baseEnvironment,
          process.cwd(),
        )
      : null;
  const trustedCommand =
    options.copilotCommand === undefined && directTrustedCommand === null
      ? await resolveTrustedWindowsCommandWrapper(
          unresolvedCommand.command,
          baseEnvironment,
          process.cwd(),
        )
      : directTrustedCommand;
  if (options.copilotCommand === undefined && trustedCommand === null) {
    throw new PluginBootstrapError(
      "A trusted GitHub Copilot CLI executable was not found for plugin bootstrap.",
    );
  }
  const command =
    trustedCommand === null
      ? unresolvedCommand
      : { command: trustedCommand.executable, prefixArgs: [] };
  const environment = {
    ...(trustedCommand?.environment ?? baseEnvironment),
    COPILOT_HOME: copilotHome,
  };
  const run = options.runCopilot ?? runCopilot;
  if (upgradeExistingPlugin || repairIncompletePlugin) {
    const registration = await copilotSecurityPluginRegistration(copilotHome);
    if (registration.plugin) {
      await run(
        command,
        ["plugin", "remove", `${PLUGIN_NAME}@${MARKETPLACE_NAME}`],
        environment,
        options.signal,
      );
      throwIfSignalAborted(options.signal);
    }
    if (registration.marketplace) {
      await run(
        command,
        ["plugin", "marketplace", "remove", MARKETPLACE_NAME],
        environment,
        options.signal,
      );
      throwIfSignalAborted(options.signal);
    }
    throwIfSignalAborted(options.signal);
    await rm(existingMarketplace, { recursive: true, force: true });
    throwIfSignalAborted(options.signal);
  }

  const marketplace = await createMarketplace(
    copilotHome,
    root,
    options.signal,
  );
  await run(
    command,
    ["plugin", "marketplace", "add", marketplace],
    environment,
    options.signal,
  );
  await run(
    command,
    ["plugin", "add", `${PLUGIN_NAME}@${MARKETPLACE_NAME}`],
    environment,
    options.signal,
  );
  await verifyPluginRegistration(copilotHome, marketplace);
  const verifiedInstalledRoot = await findInstalledPlugin(copilotHome);
  const installed = await pluginMetadata(verifiedInstalledRoot);
  if (installed.name !== name || installed.version !== version) {
    throw new PluginBootstrapError(
      "Installed Copilot Security plugin metadata does not match the selected plugin.",
    );
  }
  return {
    pluginRoot: root,
    marketplaceRoot: marketplace,
    installedRoot: verifiedInstalledRoot,
    marketplaceName: MARKETPLACE_NAME,
    name,
    version,
  };
}

export async function pluginMetadata(
  root: string,
): Promise<{ name: typeof PLUGIN_NAME; version: string }> {
  const manifestPath = join(root, "plugin.json");
  let manifest: unknown;
  try {
    const expected = await lstat(manifestPath);
    if (
      !expected.isFile() ||
      expected.isSymbolicLink() ||
      expected.size > MAX_PLUGIN_MANIFEST_SIZE
    ) {
      throw new Error("plugin manifest is not a bounded regular file");
    }
    const input = await open(
      manifestPath,
      constants.O_RDONLY |
        (process.platform === "win32"
          ? 0
          : constants.O_NOFOLLOW | constants.O_NONBLOCK),
    );
    try {
      const opened = await input.stat();
      if (!samePluginFile(expected, opened)) {
        throw new Error("plugin manifest changed before reading");
      }
      const bytes = await readExactly(input, expected.size, 0);
      if (!samePluginFile(expected, await input.stat())) {
        throw new Error("plugin manifest changed while reading");
      }
      manifest = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
    } finally {
      await input.close();
    }
  } catch (error) {
    throw new PluginBootstrapError(
      `Invalid Copilot plugin directory: ${root}`,
      {
        cause: error,
      },
    );
  }
  if (!isRecord(manifest) || manifest["name"] !== PLUGIN_NAME) {
    throw new PluginBootstrapError(
      "Plugin manifest must have name 'copilot-security'.",
    );
  }
  const version = manifest["version"];
  if (typeof version !== "string" || version.trim().length === 0) {
    throw new PluginBootstrapError(
      "Plugin manifest must have a non-empty version.",
    );
  }
  return { name: PLUGIN_NAME, version };
}

export async function resolvePluginPython(
  options: PluginPythonOptions = {},
): Promise<string> {
  const environment = options.environment ?? process.env;
  const protectedRoot = options.protectedRoot ?? process.cwd();
  if (options.configuredPath !== undefined) {
    return await requirePython(
      options.configuredPath,
      "configured plugin Python",
      environment,
      protectedRoot,
      options.signal,
    );
  }
  const inherited = environment["PYTHON"]?.trim();
  if (inherited) {
    return await requirePython(
      inherited,
      "PYTHON",
      environment,
      protectedRoot,
      options.signal,
    );
  }

  const home = options.homeDirectory ?? homedir();
  const managedRoots = options.managedRuntimeRoots ?? [
    join(home, ".cache", "copilot-runtimes", "copilot-primary-runtime"),
  ];
  const relativeCandidates =
    process.platform === "win32"
      ? [
          join("dependencies", "python", "python.exe"),
          join("dependencies", "python", "python", "python.exe"),
          join("dependencies", "python", "bin", "python.exe"),
        ]
      : [
          join("dependencies", "python", "bin", "python3"),
          join("dependencies", "python", "bin", "python"),
        ];
  for (const root of managedRoots) {
    for (const relativeCandidate of relativeCandidates) {
      const candidate = join(root, relativeCandidate);
      const resolved = await usablePython(
        candidate,
        environment,
        protectedRoot,
        options.signal,
      );
      if (resolved !== null) return resolved;
    }
  }

  for (const candidate of process.platform === "win32"
    ? ["python", "python3"]
    : ["python3", "python"]) {
    const resolved = await usablePython(
      candidate,
      environment,
      protectedRoot,
      options.signal,
    );
    if (resolved !== null) return resolved;
  }
  throw new PluginPythonUnavailableError(
    "The bundled Copilot Security plugin requires Python 3.10 or later (Python 3.10 also requires tomli), but no usable interpreter was found. " +
      "Set pythonPath, --python, or PYTHON, install the Copilot managed runtime, or add python3/python to PATH.",
  );
}

export function pluginExecutionEnvironment(
  python: string,
  environment: ProcessEnvironment = process.env,
): ProcessEnvironment {
  return { ...environment, PYTHON: python };
}

export async function cleanupSdkDirectory(path: string): Promise<void> {
  await rm(path, {
    recursive: true,
    force: true,
    // Windows scanners, indexers, and antivirus can retain a handle briefly
    // after Copilot exits. Node retries EBUSY, EPERM, and ENOTEMPTY for us.
    maxRetries: SDK_DIRECTORY_CLEANUP_MAX_RETRIES,
    retryDelay: SDK_DIRECTORY_CLEANUP_RETRY_DELAY_MILLISECONDS,
  });
}

async function runCopilot(
  command: CopilotCommand,
  args: readonly string[],
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<string> {
  try {
    const { stdout } = await execFile(
      command.command,
      [...command.prefixArgs, ...args],
      {
        env: environment,
        encoding: "utf8",
        signal,
      },
    );
    return stdout;
  } catch (error) {
    const detail = processErrorDetail(error);
    throw new PluginBootstrapError(
      `Copilot plugin bootstrap failed: ${detail}`,
      {
        cause: error,
      },
    );
  }
}

async function findInstalledPlugin(copilotHome: string): Promise<string> {
  const root = join(
    copilotHome,
    "plugins",
    "cache",
    MARKETPLACE_NAME,
    PLUGIN_NAME,
  );
  const candidates: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true }).catch(
    () => [],
  )) {
    if (entry.isDirectory()) {
      const candidate = join(root, entry.name);
      if (await hasPluginManifest(candidate)) candidates.push(candidate);
    }
  }
  if (candidates.length !== 1) {
    throw new PluginBootstrapError(
      "Copilot plugin install did not produce one installed Copilot Security plugin.",
    );
  }
  return await realpath(candidates[0]!);
}

async function discoverPluginRoot(root: string): Promise<string> {
  if (await hasPluginManifest(root)) return await validatePluginRoot(root);
  const children = (await readdir(root, { withFileTypes: true })).filter(
    (entry) => entry.isDirectory(),
  );
  if (children.length === 1) {
    const candidate = join(root, children[0]!.name);
    if (await hasPluginManifest(candidate))
      return await validatePluginRoot(candidate);
  }
  throw new PluginBootstrapError(
    "Plugin ZIP must contain Copilot Security at its root or in one top-level directory.",
  );
}

async function validatePluginRoot(root: string): Promise<string> {
  await pluginMetadata(root);
  return await realpath(root);
}

async function verifyPluginRegistration(
  copilotHome: string,
  marketplace: string,
): Promise<void> {
  const configPath = join(copilotHome, "config.toml");
  let config: unknown;
  try {
    config = parse(await readFile(configPath, "utf8"));
  } catch (error) {
    throw new PluginBootstrapError(
      "Copilot plugin bootstrap produced an unreadable config.toml.",
      {
        cause: error,
      },
    );
  }
  const marketplaces = isRecord(config) ? config["marketplaces"] : undefined;
  const plugins = isRecord(config) ? config["plugins"] : undefined;
  const marketplaceConfig = isRecord(marketplaces)
    ? marketplaces[MARKETPLACE_NAME]
    : undefined;
  const pluginConfig = isRecord(plugins)
    ? plugins[`${PLUGIN_NAME}@${MARKETPLACE_NAME}`]
    : undefined;
  if (!isRecord(marketplaceConfig) || !isRecord(pluginConfig)) {
    throw new PluginBootstrapError(
      "Copilot plugin bootstrap did not preserve plugin registration.",
    );
  }
  const registeredSource = String(marketplaceConfig["source"] ?? "");
  if (!(await sameFile(registeredSource, marketplace))) {
    throw new PluginBootstrapError(
      "Copilot plugin marketplace registration has the wrong source.",
    );
  }
  if (pluginConfig["enabled"] !== true) {
    throw new PluginBootstrapError(
      "Copilot Security plugin is not enabled after bootstrap.",
    );
  }
}

async function copyPluginTree(
  source: string,
  destination: string,
  signal?: AbortSignal,
): Promise<void> {
  const pending: Array<{ source: string; destination: string }> = [
    { source, destination },
  ];
  const directories = new Map<string, Stats>();
  let entries = 0;
  let size = 0;
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  try {
    while (pending.length > 0) {
      throwIfSignalAborted(signal);
      const current = pending.pop()!;
      await requirePluginAncestors(source, current.source, directories, signal);
      const metadata = await lstat(current.source);
      if (++entries > MAX_PLUGIN_COPY_ENTRIES) {
        throw new PluginBootstrapError(
          `Plugin source exceeds the copy entry limit: ${current.source}`,
        );
      }
      if (metadata.isSymbolicLink()) {
        throw new PluginBootstrapError(
          `Plugin contains an unsafe source path: ${current.source}`,
        );
      }
      if (metadata.isDirectory()) {
        const children = await readdir(current.source);
        const afterRead = await lstat(current.source);
        if (!samePluginFile(metadata, afterRead)) {
          throw new PluginBootstrapError(
            `Plugin directory changed while it was being copied: ${current.source}`,
          );
        }
        directories.set(current.source, afterRead);
        await mkdir(current.destination, { mode: 0o700 });
        for (const child of children) {
          pending.push({
            source: join(current.source, child),
            destination: join(current.destination, child),
          });
        }
        continue;
      }
      if (!metadata.isFile()) {
        throw new PluginBootstrapError(
          `Plugin contains a non-regular file: ${current.source}`,
        );
      }
      if (metadata.size > MAX_PLUGIN_COPY_FILE_SIZE) {
        throw new PluginBootstrapError(
          `Plugin source exceeds the per-file safety limit: ${current.source}`,
        );
      }
      size += metadata.size;
      if (size > MAX_PLUGIN_COPY_SIZE) {
        throw new PluginBootstrapError(
          "Plugin source exceeds the copy safety limit.",
        );
      }
      const input = await open(
        current.source,
        constants.O_RDONLY |
          (process.platform === "win32"
            ? 0
            : constants.O_NOFOLLOW | constants.O_NONBLOCK),
      );
      let output: Awaited<ReturnType<typeof open>> | undefined;
      try {
        if (!samePluginFile(metadata, await input.stat())) {
          throw new PluginBootstrapError(
            `Plugin source changed before it could be copied: ${current.source}`,
          );
        }
        await requirePluginAncestors(
          source,
          current.source,
          directories,
          signal,
        );
        const bytes = await readExactly(input, metadata.size, 0, signal);
        if (!samePluginFile(metadata, await input.stat())) {
          throw new PluginBootstrapError(
            `Plugin source changed while it was being copied: ${current.source}`,
          );
        }
        await requirePluginAncestors(
          source,
          current.source,
          directories,
          signal,
        );
        output = await open(
          current.destination,
          constants.O_WRONLY |
            constants.O_CREAT |
            constants.O_EXCL |
            (process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
          0o600,
        );
        await output.writeFile(bytes);
        await output.chmod(metadata.mode & 0o777);
      } finally {
        await output?.close();
        await input.close();
      }
    }
  } catch (error) {
    await rm(destination, { recursive: true, force: true });
    throw error;
  }
}

async function requirePluginAncestors(
  root: string,
  path: string,
  directories: ReadonlyMap<string, Stats>,
  signal?: AbortSignal,
): Promise<void> {
  const relativePath = relative(root, path);
  if (
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    isAbsolute(relativePath)
  ) {
    throw new PluginBootstrapError(
      `Plugin source path escapes its root: ${path}`,
    );
  }
  if (relativePath === "") return;

  let ancestor = root;
  const parents = ["", ...relativePath.split(sep).slice(0, -1)];
  for (const component of parents) {
    throwIfSignalAborted(signal);
    if (component !== "") ancestor = join(ancestor, component);
    const expected = directories.get(ancestor);
    const actual = await lstat(ancestor);
    if (
      expected === undefined ||
      actual.isSymbolicLink() ||
      !actual.isDirectory() ||
      !samePluginFile(expected, actual)
    ) {
      throw new PluginBootstrapError(
        `Plugin source directory changed while it was being copied: ${ancestor}`,
      );
    }
  }
}

function samePluginFile(first: Stats, second: Stats): boolean {
  return (
    first.dev === second.dev &&
    first.ino === second.ino &&
    first.size === second.size &&
    first.mtimeMs === second.mtimeMs &&
    first.mode === second.mode &&
    first.isFile() === second.isFile() &&
    first.isDirectory() === second.isDirectory()
  );
}

async function readExactly(
  handle: Awaited<ReturnType<typeof open>>,
  length: number,
  position: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    throwIfSignalAborted(signal);
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      length - offset,
      position + offset,
    );
    if (bytesRead === 0) throw new Error("unexpected end of plugin file");
    offset += bytesRead;
  }
  return buffer;
}

async function copyExternalPayload(
  source: string,
  destination: string,
): Promise<void> {
  const contractPath = join(
    source,
    ".internal",
    "external-promotion",
    "external-projection-contract.json",
  );
  let contract: unknown;
  try {
    contract = JSON.parse(await readFile(contractPath, "utf8"));
  } catch (error) {
    throw new PluginBootstrapError(
      `Invalid plugin projection contract: ${contractPath}`,
      {
        cause: error,
      },
    );
  }
  const shippedExact = isRecord(contract)
    ? contract["shippedExact"]
    : undefined;
  if (
    !Array.isArray(shippedExact) ||
    !shippedExact.every((value) => typeof value === "string")
  ) {
    throw new PluginBootstrapError(
      "Plugin projection contract must contain shippedExact paths.",
    );
  }
  const paths = ["plugin.json", ...shippedExact].filter(
    (value) => !value.startsWith("sdk/"),
  );
  for (const path of paths) {
    const normalized = safeArchivePath(path);
    const sourcePath = join(source, ...normalized.split("/"));
    const destinationPath = join(destination, ...normalized.split("/"));
    const metadata = await lstat(sourcePath).catch(() => null);
    if (metadata === null || !metadata.isFile() || metadata.isSymbolicLink()) {
      throw new PluginBootstrapError(
        `Bundled plugin file is missing or unsafe: ${sourcePath}`,
      );
    }
    await mkdir(dirname(destinationPath), { recursive: true, mode: 0o700 });
    await copyFile(sourcePath, destinationPath, constants.COPYFILE_EXCL);
  }
}

function safeArchivePath(value: string): string {
  const parts = value.split("/");
  const normalized = parts
    .filter((part) => part !== "" && part !== ".")
    .join("/");
  if (
    value.length === 0 ||
    value.startsWith("/") ||
    value.startsWith("//") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    value.includes("\0") ||
    parts.some((part) => part.includes(":")) ||
    normalized.length === 0
  ) {
    throw new PluginBootstrapError(
      `Plugin ZIP contains an unsafe path: ${value}`,
    );
  }
  return normalized;
}

async function requirePython(
  candidate: string,
  source: string,
  environment: ProcessEnvironment,
  protectedRoot: string,
  signal?: AbortSignal,
): Promise<string> {
  const resolved = await usablePython(
    candidate,
    environment,
    protectedRoot,
    signal,
  );
  if (resolved !== null) return resolved;
  throw new PluginPythonUnavailableError(
    `The ${source} interpreter is unavailable or unusable: ${candidate}. ` +
      "The bundled Copilot Security plugin requires Python 3.10 or later for scan execution; Python 3.10 also requires tomli.",
  );
}

async function usablePython(
  candidate: string,
  environment: ProcessEnvironment = process.env,
  protectedRoot: string = process.cwd(),
  signal?: AbortSignal,
): Promise<string | null> {
  const command = await resolveTrustedExecutable(
    isPythonPathCandidate(candidate) ? expandHome(candidate) : candidate,
    environment,
    protectedRoot,
  );
  if (command === null) return null;
  try {
    const { stdout } = await execFile(
      command.executable,
      [
        "-I",
        "-c",
        "import importlib.util,sys\nif sys.version_info < (3, 10): raise SystemExit(1)\nif sys.version_info < (3, 11) and importlib.util.find_spec('tomli') is None: raise SystemExit(1)\nprint('copilot-security-python-ok')",
      ],
      {
        env: command.environment,
        encoding: "utf8",
        timeout: 5_000,
        windowsHide: true,
        signal,
      },
    );
    return stdout.trim() === "copilot-security-python-ok"
      ? command.executable
      : null;
  } catch (error) {
    if (signal?.aborted) throw error;
    return null;
  }
}

export function isPythonPathCandidate(candidate: string): boolean {
  return (
    candidate.includes("/") ||
    candidate.includes("\\") ||
    candidate.startsWith(".")
  );
}

async function hasPluginManifest(root: string): Promise<boolean> {
  return await isRegularFile(join(root, "plugin.json"));
}

async function isRegularFile(path: string): Promise<boolean> {
  try {
    const metadata = await lstat(path);
    return metadata.isFile() && !metadata.isSymbolicLink();
  } catch {
    return false;
  }
}

async function sameFile(left: string, right: string): Promise<boolean> {
  try {
    const [leftMetadata, rightMetadata] = await Promise.all([
      stat(left),
      stat(right),
    ]);
    return (
      leftMetadata.dev === rightMetadata.dev &&
      leftMetadata.ino === rightMetadata.ino
    );
  } catch {
    return false;
  }
}

export function expandHome(value: string): string {
  if (value === "~") return homedir();
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    return join(homedir(), value.slice(2));
  }
  return value;
}

function safePrefix(value: string): string {
  return basename(value).replace(/[^A-Za-z0-9._-]/g, "-") || "repository";
}

function processErrorDetail(error: unknown): string {
  if (isRecord(error)) {
    for (const key of ["stderr", "stdout", "message"] as const) {
      const value = error[key];
      if (typeof value === "string" && value.trim()) return value.trim();
      if (value instanceof Uint8Array) {
        const decoded = new TextDecoder().decode(value).trim();
        if (decoded) return decoded;
      }
    }
  }
  return String(error) || "unknown error";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nodeErrorCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error["code"] === "string"
    ? error["code"]
    : undefined;
}

function abortReason(signal: AbortSignal): unknown {
  return (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

function throwIfSignalAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortReason(signal);
}
