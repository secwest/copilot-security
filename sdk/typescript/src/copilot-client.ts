import { lstat, mkdtemp, readFile, realpath } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import {
  approveAll,
  CopilotClient,
  RuntimeConnection,
  type AssistantUsageData,
  type SessionEvent,
} from "@github/copilot-sdk";
import type { JsonObject } from "./config.js";
import { ConfigurationError, CopilotSecurityError } from "./errors.js";
import {
  importAmbientAuth,
  MARKETPLACE_NAME,
  pluginMetadata,
  prepareCopilotSecurityCredentialHome,
  resolvePluginPath,
  type PluginInstall,
  type ProcessEnvironment,
} from "./runtime.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const MAX_WRAPPER_BYTES = 16 * 1024;
const MAX_SCAN_MILLISECONDS = 24 * 60 * 60 * 1_000;
type CopilotReasoningEffort = "low" | "medium" | "high" | "xhigh";

export interface CopilotScannerOptions {
  cliPath: string;
  environment: Record<string, string>;
  model: string;
  reasoningEffort: string;
  pluginRoot: string;
  maxAiCredits?: number;
}

interface ScannerEvent {
  readonly type: string;
  readonly [key: string]: unknown;
}

export interface CopilotScannerThread {
  readonly id: string | null;
  runStreamed(
    input: string,
    options: { signal: AbortSignal },
  ): Promise<{ events: AsyncGenerator<ScannerEvent> }>;
}

export interface PreparedCopilotRuntime {
  copilotHome: string;
  persistentCredentialHome: true;
  bootstrapWorkspace: string;
  plugin: PluginInstall;
  environment: Record<string, string>;
  credentialsAvailable: boolean;
  effectiveConfig: JsonObject;
}

export async function copilotAuthStatus(
  cliPath: string,
  environment: Record<string, string>,
): Promise<{
  authenticated: boolean;
  details: string;
}> {
  const client = new CopilotClient({
    connection: RuntimeConnection.forStdio({
      path: cliPath,
      args: ["--no-auto-update", "--no-remote", "--no-remote-export"],
      env: environment,
    }),
    mode: "copilot-cli",
    workingDirectory: process.cwd(),
    useLoggedInUser: true,
    logLevel: "error",
  });
  try {
    await client.start();
    const status = await client.getAuthStatus();
    return {
      authenticated: status.isAuthenticated,
      details:
        status.statusMessage ??
        [status.authType, status.login, status.host]
          .filter((value): value is string => typeof value === "string")
          .join(" "),
    };
  } finally {
    const stopErrors = await client
      .stop()
      .catch((error: unknown) => [
        error instanceof Error ? error : new Error(errorMessage(error)),
      ]);
    if (stopErrors.length > 0) {
      await client.forceStop().catch(() => undefined);
    }
  }
}

/**
 * Adapts the official Copilot SDK event stream to the small event surface used
 * by the inherited scanner harness. The model, tools, skills, subagents, and
 * filesystem operations still execute in the installed Copilot CLI process.
 */
export class CopilotScannerClient {
  readonly #options: CopilotScannerOptions;

  public constructor(options: CopilotScannerOptions) {
    this.#options = options;
  }

  public startThread(options: {
    workingDirectory: string;
    skipGitRepoCheck: boolean;
    approvalPolicy: "never";
  }): CopilotScannerThread {
    return new CopilotThread(this.#options, options.workingDirectory);
  }
}

class CopilotThread implements CopilotScannerThread {
  public id: string | null = null;
  readonly #options: CopilotScannerOptions;
  readonly #workingDirectory: string;

  public constructor(options: CopilotScannerOptions, workingDirectory: string) {
    this.#options = options;
    this.#workingDirectory = workingDirectory;
  }

  public async runStreamed(
    input: string,
    options: { signal: AbortSignal },
  ): Promise<{ events: AsyncGenerator<ScannerEvent> }> {
    const queue = new AsyncEventQueue<ScannerEvent>();
    const usage = emptyUsage();
    const client = new CopilotClient({
      connection: RuntimeConnection.forStdio({
        path: this.#options.cliPath,
        args: ["--no-auto-update", "--no-remote", "--no-remote-export"],
        env: this.#options.environment,
      }),
      mode: "copilot-cli",
      workingDirectory: this.#workingDirectory,
      useLoggedInUser: true,
      logLevel: "error",
    });

    await client.start();
    const session = await client.createSession({
      clientName: "copilot-security",
      model: this.#options.model,
      reasoningEffort: requireReasoningEffort(this.#options.reasoningEffort),
      workingDirectory: this.#workingDirectory,
      streaming: true,
      includeSubAgentStreamingEvents: true,
      pluginDirectories: [this.#options.pluginRoot],
      enableSkills: true,
      enableConfigDiscovery: false,
      skipCustomInstructions: true,
      customAgentsLocalOnly: true,
      coauthorEnabled: false,
      remoteSession: "off",
      enableSessionStore: false,
      skipEmbeddingRetrieval: true,
      embeddingCacheStorage: "in-memory",
      ...(this.#options.maxAiCredits === undefined
        ? {}
        : { sessionLimits: { maxAiCredits: this.#options.maxAiCredits } }),
      onPermissionRequest: approveAll,
      onEvent: (event) => translateEvent(event, queue, usage),
    });
    this.id = session.sessionId;
    queue.push({ type: "thread.started", thread_id: session.sessionId });

    const abort = (): void => {
      void session.abort().catch(() => undefined);
    };
    options.signal.addEventListener("abort", abort, { once: true });

    // The Copilot SDK intentionally unrefs its child transport. A pending
    // Promise or async-generator waiter does not keep Node alive by itself, so
    // hold one referenced timer until the streamed turn and cleanup settle.
    const completionGuard = setInterval(() => undefined, 60_000);
    void (async () => {
      try {
        await session.sendAndWait({ prompt: input }, MAX_SCAN_MILLISECONDS);
        if (!options.signal.aborted) {
          try {
            await session.sendAndWait(
              { prompt: scanQualityGatePrompt() },
              MAX_SCAN_MILLISECONDS,
            );
          } catch (error) {
            if (!(await hasDraftArtifacts(this.#options.environment))) {
              throw error;
            }
            queue.push({
              type: "copilot.quality_gate_incomplete",
              message:
                "The correction turn ended after the first turn wrote all draft artifacts.",
            });
          }
        }
        if (!options.signal.aborted) {
          queue.push({ type: "turn.completed", usage });
        }
      } catch (error) {
        if (!options.signal.aborted) {
          queue.push({
            type: "turn.failed",
            error: { message: errorMessage(error) },
            usage,
          });
        }
      } finally {
        clearInterval(completionGuard);
        options.signal.removeEventListener("abort", abort);
        await session.disconnect().catch(() => undefined);
        const stopErrors = await client
          .stop()
          .catch((error: unknown) => [
            error instanceof Error ? error : new Error(errorMessage(error)),
          ]);
        if (stopErrors.length > 0) {
          await client.forceStop().catch(() => undefined);
        }
        queue.close();
      }
    })();

    return { events: queue.events() };
  }
}

function scanQualityGatePrompt(): string {
  return [
    "Mandatory Copilot Security quality gate. Continue the same scan; do not summarize or stop early.",
    "Reopen the repository source and all three draft artifacts.",
    "Run an independent residual search for dangerous APIs and missing controls, including process/shell execution, query construction, path/archive/file writes, URL fetches, parsers/deserializers, templates, authentication, object/tenant authorization, cryptographic verification, state transitions, races, replay, and resource bounds.",
    "Trace every high-risk hit from attacker-controlled source through controls to impact. Challenge every reviewed-safe conclusion against the actual code and compare it with the nearest safe sibling or negative control.",
    "Validate each candidate, record the exploit witness and strongest counterevidence, and complete attack-path analysis. Do not suppress a candidate merely because the first pass missed it. Findings are only reachable, exploitable security defects with concrete adverse impact: remove mitigated flows, rejected candidates, safe controls, documentation notes, hardening suggestions, and defense-in-depth observations from findings.json. Zero findings is valid.",
    "Then repair scan-manifest.json, findings.json, and coverage.json using COPILOT_SECURITY_PLUGIN_ROOT/references/draft-contract.md and the schemas. Each top level must be an object; manifest.scan and manifest.scan.scope must be objects; every finding needs explicit CWE, codeEvidence, nonempty validation, and nonempty attackPath; coverage needs canonical surfaces and complete per-file closure.",
    "Write the corrected files beneath COPILOT_SECURITY_SCAN_DIR. Do not seal them. Return only after reopening and checking the corrected JSON.",
  ].join("\n");
}

async function hasDraftArtifacts(
  environment: Record<string, string>,
): Promise<boolean> {
  const scanDirectory = environment["COPILOT_SECURITY_SCAN_DIR"];
  if (scanDirectory === undefined) return false;
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    const metadata = await lstat(join(scanDirectory, name)).catch(() => null);
    if (metadata === null || !metadata.isFile() || metadata.isSymbolicLink()) {
      return false;
    }
  }
  return true;
}

function translateEvent(
  event: SessionEvent,
  queue: AsyncEventQueue<ScannerEvent>,
  usage: ReturnType<typeof emptyUsage>,
): void {
  if (event.type === "assistant.usage") {
    addUsage(usage, event.data);
    queue.push({ type: "copilot.usage", event });
    return;
  }
  if (event.type === "assistant.message" && event.agentId === undefined) {
    queue.push({
      type: "item.completed",
      item: { type: "agent_message", text: event.data.content },
    });
    return;
  }
  if (event.type === "session.error") {
    queue.push({ type: "error", message: event.data.message });
    return;
  }
  if (
    event.type === "subagent.started" ||
    event.type === "subagent.completed" ||
    event.type === "subagent.failed"
  ) {
    queue.push({ type: event.type, event });
  }
}

function emptyUsage(): {
  input_tokens: number;
  cached_input_tokens: number;
  cache_write_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
  copilot_premium_requests: number;
  copilot_nano_aiu: number;
} {
  return {
    input_tokens: 0,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 0,
    reasoning_output_tokens: 0,
    copilot_premium_requests: 0,
    copilot_nano_aiu: 0,
  };
}

function addUsage(
  target: ReturnType<typeof emptyUsage>,
  source: AssistantUsageData,
): void {
  target.input_tokens += source.inputTokens ?? 0;
  target.cached_input_tokens += source.cacheReadTokens ?? 0;
  target.cache_write_input_tokens += source.cacheWriteTokens ?? 0;
  target.output_tokens += source.outputTokens ?? 0;
  target.reasoning_output_tokens += source.reasoningTokens ?? 0;
  target.copilot_premium_requests += source.cost ?? 0;
  target.copilot_nano_aiu += source.copilotUsage?.totalNanoAiu ?? 0;
}

function requireReasoningEffort(value: string): CopilotReasoningEffort {
  if (["low", "medium", "high", "xhigh"].includes(value)) {
    return value as CopilotReasoningEffort;
  }
  throw new ConfigurationError(
    "Copilot reasoning effort must be low, medium, high, or xhigh.",
  );
}

class AsyncEventQueue<T> {
  readonly #values: T[] = [];
  readonly #waiters: Array<(value: IteratorResult<T>) => void> = [];
  #closed = false;

  public push(value: T): void {
    if (this.#closed) return;
    const waiter = this.#waiters.shift();
    if (waiter === undefined) {
      this.#values.push(value);
    } else {
      waiter({ done: false, value });
    }
  }

  public close(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const waiter of this.#waiters.splice(0)) {
      waiter({ done: true, value: undefined });
    }
  }

  public async *events(): AsyncGenerator<T> {
    while (true) {
      const next = await this.#next();
      if (next.done) return;
      yield next.value;
    }
  }

  async #next(): Promise<IteratorResult<T>> {
    const value = this.#values.shift();
    if (value !== undefined) return { done: false, value };
    if (this.#closed) return { done: true, value: undefined };
    return await new Promise<IteratorResult<T>>((resolveNext) => {
      this.#waiters.push(resolveNext);
    });
  }
}

export async function prepareCopilotRuntime(
  config: {
    pluginPath?: string;
    copilotPath?: string;
    copilotOverrides?: JsonObject;
  },
  environment: ProcessEnvironment = process.env,
  signal?: AbortSignal,
): Promise<PreparedCopilotRuntime> {
  signal?.throwIfAborted();
  const ambientHome =
    environmentValue(environment, "COPILOT_HOME") ??
    join(homedir(), ".copilot");
  const copilotHome = await prepareCopilotSecurityCredentialHome(environment);
  const importedFileCredentials = await importAmbientAuth(
    ambientHome,
    copilotHome,
  );
  const bootstrapWorkspace = await mkdtemp(
    join(tmpdir(), "copilot-security-runtime-"),
  );
  const pluginRoot = await resolvePluginPath(
    config.pluginPath,
    bootstrapWorkspace,
    signal,
  );
  const metadata = await pluginMetadata(pluginRoot);
  const cli = await resolveCopilotCli(
    config.copilotPath ??
      environmentValue(environment, "COPILOT_CLI_PATH") ??
      "copilot",
    environment,
    process.cwd(),
  );
  const effectiveConfig = copilotConfiguration(config);
  const cleanEnvironment = definedEnvironment(cli.environment);
  return {
    copilotHome: copilotHome,
    persistentCredentialHome: true,
    bootstrapWorkspace,
    plugin: {
      pluginRoot,
      marketplaceRoot: pluginRoot,
      installedRoot: pluginRoot,
      marketplaceName: MARKETPLACE_NAME,
      name: metadata.name,
      version: metadata.version,
    },
    environment: {
      ...cleanEnvironment,
      COPILOT_HOME: copilotHome,
      COPILOT_CLI_PATH: cli.executable,
    },
    credentialsAvailable:
      importedFileCredentials ||
      ["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"].some(
        (name) => environmentValue(environment, name) !== undefined,
      ),
    effectiveConfig,
  };
}

function copilotConfiguration(config: {
  copilotOverrides?: JsonObject;
}): JsonObject {
  const overrides = config.copilotOverrides ?? {};
  const model = overrides["model"];
  const effort =
    overrides["reasoning_effort"] ?? overrides["model_reasoning_effort"];
  return {
    model:
      typeof model === "string" && model.trim().length > 0
        ? model
        : "gpt-5.6-sol",
    model_reasoning_effort:
      typeof effort === "string" && effort.trim().length > 0 ? effort : "xhigh",
  };
}

export async function resolveCopilotCli(
  candidate: string,
  environment: ProcessEnvironment,
  protectedRoot: string,
): Promise<{ executable: string; environment: ProcessEnvironment }> {
  const direct = await resolveTrustedExecutable(
    candidate,
    environment,
    protectedRoot,
  );
  if (direct !== null) return direct;

  if (process.platform === "win32" && !/[\\/]/u.test(candidate)) {
    const wrapper = await resolveWindowsCommandWrapper(
      candidate,
      environment,
      protectedRoot,
    );
    if (wrapper !== null) return wrapper;
  }
  throw new CopilotSecurityError(
    `GitHub Copilot CLI was not found: ${candidate}. Install it or set COPILOT_CLI_PATH.`,
  );
}

async function resolveWindowsCommandWrapper(
  candidate: string,
  environment: ProcessEnvironment,
  protectedRoot: string,
): Promise<{ executable: string; environment: ProcessEnvironment } | null> {
  const path = environmentValue(environment, "PATH");
  for (const entry of path?.split(delimiter) ?? []) {
    if (!isAbsolute(entry)) continue;
    const wrapper = join(entry, `${candidate}.cmd`);
    const metadata = await lstat(wrapper).catch(() => null);
    if (
      metadata === null ||
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.size > MAX_WRAPPER_BYTES
    ) {
      continue;
    }
    const contents = await readFile(wrapper, "utf8");
    const invocation = contents
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .find((line) => line.length > 0 && !/^@?echo off$/iu.test(line));
    const match = /^"([^"]+\\copilot\.exe)"\s+%\*$/iu.exec(invocation ?? "");
    if (match?.[1] === undefined) continue;
    const executable = await realpath(resolve(match[1])).catch(() => null);
    if (executable === null) continue;
    const trusted = await resolveTrustedExecutable(
      executable,
      environment,
      protectedRoot,
    );
    if (trusted !== null) return trusted;
  }
  return null;
}

function environmentValue(
  environment: ProcessEnvironment,
  requested: string,
): string | undefined {
  const exact = environment[requested]?.trim();
  if (exact) return exact;
  return Object.entries(environment).find(
    ([name, value]) => name.toUpperCase() === requested && value?.trim(),
  )?.[1];
}

function definedEnvironment(
  environment: ProcessEnvironment,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
