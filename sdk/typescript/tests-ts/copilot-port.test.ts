import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  addCopilotUsage,
  closureGapCounts,
  copilotModelTurnTimeoutMilliseconds,
  copilotModelErrorRecovery,
  copilotShellSandboxViolation,
  COPILOT_SCANNER_SESSION_HOOKS,
  createCopilotScannerSessionHooks,
  createScopedScannerPermissionHandler,
  DEFAULT_MODEL_TURN_TIMEOUT_MILLISECONDS,
  emptyCopilotUsage,
  isSafetyClassifierRefusal,
  prepareCopilotRuntime,
  resolveCopilotCli,
  runScanQualityCorrection,
  safetyClassifierRetryPrompt,
  sendCopilotPromptWithSafetyRecovery,
  sendCopilotTurnWithDeadline,
  startManagedCopilotSession,
  stopManagedCopilotClient,
  type CopilotScannerOptions,
} from "../src/copilot-client.js";
import {
  CopilotSecurity,
  scanAuthentication,
  type ScanAuthentication,
} from "../src/index.js";
import {
  copilotSecurityCredentialHome,
  copilotSecurityStateDirectory,
} from "../src/runtime.js";

const temporaryPaths: string[] = [];

async function createCopilotStub(root: string): Promise<string> {
  await mkdir(root, { recursive: true });
  const executable = join(
    root,
    process.platform === "win32" ? "copilot.exe" : "copilot",
  );
  await writeFile(executable, "", { mode: 0o700 });
  await chmod(executable, 0o700);
  return executable;
}

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map(async (path) => {
      await rm(path, { recursive: true, force: true });
    }),
  );
});

describe("Copilot port", () => {
  test("restricts noninteractive permission approval to isolated scan writes", async () => {
    const root = join(tmpdir(), `copilot-permissions-${randomUUID()}`);
    const repository = join(root, "repository");
    const scanDirectory = join(root, "scan");
    const outsideDirectory = join(root, "outside");
    temporaryPaths.push(root);
    await mkdir(repository, { recursive: true });
    await mkdir(scanDirectory, { recursive: true });
    await mkdir(outsideDirectory, { recursive: true });
    const redirectedDirectory = join(scanDirectory, "redirected");
    await symlink(
      outsideDirectory,
      redirectedDirectory,
      process.platform === "win32" ? "junction" : "dir",
    );
    const handler = createScopedScannerPermissionHandler(
      scanDirectory,
      repository,
      scanDirectory,
    );

    expect(
      await handler(
        {
          kind: "write",
          fileName: join(scanDirectory, "findings.json"),
          diff: "",
          intention: "correct draft findings",
          canOfferSessionApproval: true,
        },
        { sessionId: "session" },
      ),
    ).toEqual({ kind: "approve-once" });
    const tokenHandler = createScopedScannerPermissionHandler(
      scanDirectory,
      repository,
      scanDirectory,
      false,
    );
    expect(
      await tokenHandler(
        {
          kind: "shell",
          fullCommandText: "git status --short",
          intention: "inspect repository state",
          commands: [{ identifier: "git status", readOnly: true }],
          possiblePaths: [],
          possibleUrls: [],
          hasWriteFileRedirection: false,
          canOfferSessionApproval: false,
        },
        { sessionId: "session" },
      ),
    ).toMatchObject({ kind: "reject" });
    expect(
      await handler(
        {
          kind: "read",
          path: join(repository, "source.ts"),
          intention: "inspect repository source",
        },
        { sessionId: "session" },
      ),
    ).toEqual({ kind: "approve-once" });
    expect(
      await handler(
        {
          kind: "shell",
          fullCommandText: "git status --short",
          intention: "inspect repository state",
          commands: [{ identifier: "git status", readOnly: true }],
          possiblePaths: [],
          possibleUrls: [],
          hasWriteFileRedirection: false,
          canOfferSessionApproval: false,
        },
        { sessionId: "session" },
      ),
    ).toEqual({ kind: "approve-once" });
    expect(
      await handler(
        {
          kind: "url",
          url: "https://example.invalid",
          intention: "test denial",
        },
        { sessionId: "session" },
      ),
    ).toEqual({
      kind: "reject",
      feedback:
        "Copilot Security permits only sandboxed, offline repository reads and scan-directory artifact operations; this request is outside that profile.",
    });
    expect(
      await handler(
        {
          kind: "write",
          fileName: join(repository, "source.ts"),
          diff: "",
          intention: "unexpected repository mutation",
          canOfferSessionApproval: true,
        },
        { sessionId: "session" },
      ),
    ).toEqual({
      kind: "reject",
      feedback:
        "Copilot Security permits only sandboxed, offline repository reads and scan-directory artifact operations; this request is outside that profile.",
    });
    expect(
      await handler(
        {
          kind: "write",
          fileName: join(redirectedDirectory, "escaped.json"),
          diff: "",
          intention: "follow a redirected scan path",
          canOfferSessionApproval: true,
        },
        { sessionId: "session" },
      ),
    ).toMatchObject({ kind: "reject" });
    expect(
      await handler(
        {
          kind: "shell",
          fullCommandText: "curl https://example.invalid",
          intention: "attempt network access",
          commands: [{ identifier: "curl", readOnly: false }],
          possiblePaths: [],
          possibleUrls: [{ url: "https://example.invalid" }],
          hasWriteFileRedirection: false,
          canOfferSessionApproval: false,
        },
        { sessionId: "session" },
      ),
    ).toMatchObject({ kind: "reject" });
    expect(
      await handler(
        {
          kind: "write",
          fileName: join(scanDirectory, "coverage.json"),
          diff: "",
          intention: "request an unnecessary sandbox bypass",
          canOfferSessionApproval: true,
          requestSandboxBypass: true,
        },
        { sessionId: "session" },
      ),
    ).toMatchObject({ kind: "reject" });
  });

  test("exports the Copilot product surface and metadata", () => {
    const scanner = new CopilotSecurity();
    expect(scanner.metadata).toMatchObject({
      sdk: "@github/copilot-sdk",
      executable: "github/copilot-cli",
      executableVersion: "system",
    });
  });

  test("selects GitHub token variables in documented precedence order", () => {
    const authentication: ScanAuthentication = scanAuthentication({
      GITHUB_TOKEN: "third",
      GH_TOKEN: "second",
      COPILOT_GITHUB_TOKEN: "first",
    });
    expect(authentication).toEqual({
      method: "github_token",
      source: "COPILOT_GITHUB_TOKEN",
      verified: false,
    });
    expect(scanAuthentication({}, "github")).toEqual({
      method: "stored_credentials",
      verified: false,
    });
    expect(() => scanAuthentication({}, "token")).toThrow(
      "COPILOT_GITHUB_TOKEN",
    );
  });

  test("resolves a configured system Copilot executable", async () => {
    const root = join(tmpdir(), `copilot-port-${randomUUID()}`);
    temporaryPaths.push(root);
    const executable = await createCopilotStub(root);
    const resolved = await resolveCopilotCli(
      executable,
      { PATH: process.env["PATH"] },
      process.cwd(),
    );
    expect(resolved.executable.toLowerCase()).toBe(executable.toLowerCase());
  });

  test.skipIf(process.platform !== "win32")(
    "unwraps the standard Windows copilot.cmd launcher without invoking a shell",
    async () => {
      const root = join(tmpdir(), `copilot-port-${randomUUID()}`);
      const bin = join(root, "bin");
      const install = join(root, "install");
      temporaryPaths.push(root);
      await mkdir(bin, { recursive: true });
      await mkdir(install, { recursive: true });
      const executable = join(install, "copilot.exe");
      await writeFile(executable, "");
      await writeFile(
        join(bin, "copilot.cmd"),
        `@echo off\r\n"${executable}" %*\r\n`,
      );

      const resolved = await resolveCopilotCli(
        "copilot",
        { PATH: [bin, process.env["PATH"] ?? ""].join(delimiter) },
        process.cwd(),
      );
      expect(resolved.executable.toLowerCase()).toBe(executable.toLowerCase());
    },
  );

  test("keeps the scanner adapter options strongly typed", () => {
    const options: CopilotScannerOptions = {
      cliPath: "copilot",
      environment: {},
      gitHubToken: "synthetic-token",
      model: "gpt-5.6-sol",
      reasoningEffort: "xhigh",
      pluginRoot: "plugin",
    };
    expect(options).toMatchObject({
      gitHubToken: "synthetic-token",
      model: "gpt-5.6-sol",
    });
  });

  test("separates request cost units from AI-credit consumption", () => {
    const usage = emptyCopilotUsage();
    addCopilotUsage(usage, {
      model: "gpt-5.6-terra",
      inputTokens: 100,
      outputTokens: 20,
      cost: 2,
      copilotUsage: { totalNanoAiu: 1_500_000_000 },
    });
    addCopilotUsage(usage, {
      model: "gpt-5.6-terra",
      inputTokens: 50,
      cacheReadTokens: 25,
      outputTokens: 10,
      cost: 3,
      copilotUsage: { totalNanoAiu: 250_000_000 },
    });

    expect(usage).toEqual({
      input_tokens: 150,
      cached_input_tokens: 25,
      cache_write_input_tokens: 0,
      output_tokens: 30,
      reasoning_output_tokens: 0,
      copilot_request_cost_units: 5,
      copilot_nano_aiu: 1_750_000_000,
      copilot_ai_credits: 1.75,
    });
    expect(usage).not.toHaveProperty("copilot_premium_requests");
  });

  test("bounds each Copilot model turn with a scanner-owned timeout", () => {
    expect(copilotModelTurnTimeoutMilliseconds({})).toBe(
      DEFAULT_MODEL_TURN_TIMEOUT_MILLISECONDS,
    );
    expect(
      copilotModelTurnTimeoutMilliseconds({
        COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS: "720000",
      }),
    ).toBe(720_000);
    for (const configured of [
      "",
      "0",
      "59999",
      "1.5",
      "not-a-timeout",
      "86400001",
    ]) {
      expect(() =>
        copilotModelTurnTimeoutMilliseconds({
          COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS: configured,
        }),
      ).toThrow("COPILOT_SECURITY_MODEL_TURN_TIMEOUT_MS");
    }
  });

  test("aborts the Copilot session at the hard model-turn deadline", async () => {
    let aborts = 0;
    await expect(
      sendCopilotTurnWithDeadline(
        {
          async abort(): Promise<void> {
            aborts += 1;
          },
          async sendAndWait(): Promise<never> {
            return await new Promise<never>(() => {});
          },
        },
        "scan",
        5,
      ),
    ).rejects.toThrow("exceeded the 5 millisecond scanner deadline");
    expect(aborts).toBe(1);

    const completed = await sendCopilotTurnWithDeadline(
      {
        async abort(): Promise<void> {
          aborts += 1;
        },
        async sendAndWait(
          input: { prompt: string },
          timeoutMilliseconds: number,
        ): Promise<unknown> {
          return { ...input, timeoutMilliseconds };
        },
      },
      "scan",
      100,
    );
    expect(completed).toEqual({
      prompt: "scan",
      timeoutMilliseconds: 100,
    });
    expect(aborts).toBe(1);
  });

  test("requests bounded native retries only for recoverable model calls", () => {
    expect(COPILOT_SCANNER_SESSION_HOOKS.onErrorOccurred).toBe(
      copilotModelErrorRecovery,
    );
    expect(
      copilotModelErrorRecovery({
        recoverable: true,
        errorContext: "model_call",
        error: "provider detail must not affect recovery",
      }),
    ).toEqual({
      errorHandling: "retry",
      retryCount: 2,
    });
    expect(
      copilotModelErrorRecovery({
        recoverable: false,
        errorContext: "model_call",
        error: "Response blocked by content filtering policy",
      }),
    ).toEqual({
      errorHandling: "retry",
      retryCount: 6,
    });
    for (const input of [
      {
        recoverable: false,
        errorContext: "model_call" as const,
        error: "terminal model failure",
      },
      {
        recoverable: true,
        errorContext: "tool_execution" as const,
        error: "do not replay a tool",
      },
      {
        recoverable: true,
        errorContext: "system" as const,
        error: "do not guess about system recovery",
      },
      {
        recoverable: true,
        errorContext: "user_input" as const,
        error: "noninteractive scanner",
      },
    ]) {
      expect(copilotModelErrorRecovery(input)).toBeUndefined();
    }
  });

  test("requires positive native-sandbox telemetry for every shell tool", async () => {
    const base = {
      sessionId: "session-1",
      timestamp: new Date(),
      workingDirectory: "C:\\repository",
      toolName: "powershell",
      toolArgs: {},
    };
    const result = {
      textResultForLlm: "ok",
      resultType: "success" as const,
    };

    expect(
      copilotShellSandboxViolation({
        ...base,
        toolResult: {
          ...result,
          toolTelemetry: { properties: { sandboxApplied: "true" } },
        },
      }),
    ).toBeNull();
    expect(
      copilotShellSandboxViolation({ ...base, toolResult: result }),
    ).toBeInstanceOf(Error);
    expect(
      copilotShellSandboxViolation({
        ...base,
        toolName: "view",
        toolResult: result,
      }),
    ).toBeNull();

    const violations: Error[] = [];
    const hooks = createCopilotScannerSessionHooks((error) =>
      violations.push(error),
    );
    await hooks.onPostToolUse?.(
      { ...base, toolResult: result },
      { sessionId: "session-1" },
    );
    await hooks.onPostToolUseFailure?.(
      { ...base, error: "sandbox backend failed" },
      { sessionId: "session-1" },
    );
    expect(violations).toHaveLength(2);
    expect(violations[0]?.message).toContain("did not report");
    expect(violations[1]?.message).toContain("without verifiable");
  });

  test("retries only explicit safety-classifier refusals", async () => {
    for (const refusal of [
      "Safety classifier rejected the response.",
      "Response blocked by content filtering policy.",
      "Request was filtered by the Responsible AI Service.",
      "This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. To get authorized for security work, join the Trusted Access for Cyber program.",
      "policy_violation",
      "I can't assist with harmful cyber activity.",
    ]) {
      expect(isSafetyClassifierRefusal(refusal)).toBeTrue();
    }
    for (const ordinaryFailure of [
      "The severity policy blocked this release.",
      "Plugin ZIP entry exceeds the safety limit.",
      "Authentication failed.",
      "The scanner found unsafe deserialization.",
      "Request timed out.",
    ]) {
      expect(isSafetyClassifierRefusal(ordinaryFailure)).toBeFalse();
    }

    const prompts: string[] = [];
    let sends = 0;
    await sendCopilotPromptWithSafetyRecovery(
      "scan the repository",
      async (prompt) => {
        prompts.push(prompt);
        sends += 1;
        if (sends === 1) {
          throw new Error("Response blocked by content filtering policy.");
        }
        if (sends === 2) {
          return {
            data: {
              content: "I can't assist with harmful cyber activity.",
            },
          };
        }
        return { data: { content: "Defensive scan completed." } };
      },
    );

    expect(prompts).toHaveLength(3);
    expect(prompts[0]).toBe("scan the repository");
    expect(prompts[1]).toContain("safety-refusal recovery 1/5");
    expect(prompts[2]).toContain("safety-refusal recovery 2/5");
    expect(prompts[1]).not.toContain("scan the repository");
    expect(safetyClassifierRetryPrompt("original", 5)).toContain(
      "Complete only the scanner's structured defensive contract",
    );
  });

  test("fails transparently after bounded safety retries without replaying other errors", async () => {
    let refusalAttempts = 0;
    await expect(
      sendCopilotPromptWithSafetyRecovery("scan", async () => {
        refusalAttempts += 1;
        throw new Error("Safety classifier refused the response.");
      }),
    ).rejects.toThrow(
      "safety filtering rejected the authorized defensive scan after 6 prompt attempts",
    );
    expect(refusalAttempts).toBe(6);

    const terminal = new Error("network stopped");
    let terminalAttempts = 0;
    await expect(
      sendCopilotPromptWithSafetyRecovery("scan", async () => {
        terminalAttempts += 1;
        throw terminal;
      }),
    ).rejects.toBe(terminal);
    expect(terminalAttempts).toBe(1);
  });

  test("completes after the correction turn only when the host re-audit closes", async () => {
    const prompts: string[] = [];
    let reads = 0;

    await runScanQualityCorrection({
      residualRiskInventory: "",
      coverageGapInventory: "",
      findingQualityGapInventory: "",
      sendPrompt: async (prompt) => {
        prompts.push(prompt);
      },
      readClosureInventories: async () => {
        reads += 1;
        return {
          coverageGapInventory: '{"type":"coverage-gap-summary","gapCount":0}',
          findingQualityGapInventory: "",
        };
      },
    });

    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("Mandatory Copilot Security quality gate");
    expect(reads).toBe(1);
  });

  test("uses one bounded repair turn when corrected artifacts retain gaps", async () => {
    const prompts: string[] = [];
    const closureStates = [
      {
        coverageGapInventory:
          '{"type":"coverage-gap-summary","gapCount":2}\n{"path":"src/a.ts"}',
        findingQualityGapInventory:
          '{"type":"finding-quality-gap-summary","gapCount":1}\n{"findingId":"occ_1"}',
      },
      {
        coverageGapInventory: '{"type":"coverage-gap-summary","gapCount":0}',
        findingQualityGapInventory: "",
      },
    ];

    await runScanQualityCorrection({
      residualRiskInventory: "",
      coverageGapInventory: "",
      findingQualityGapInventory: "",
      sendPrompt: async (prompt) => {
        prompts.push(prompt);
      },
      readClosureInventories: async () => closureStates.shift()!,
    });

    expect(prompts).toHaveLength(2);
    expect(prompts[1]).toContain(
      "Final bounded Copilot Security closure repair",
    );
    expect(prompts[1]).toContain("<coverage-gap-inventory>");
    expect(prompts[1]).toContain("<finding-quality-gap-inventory>");
    expect(closureStates).toHaveLength(0);
  });

  test("preserves first-turn transport recovery without re-auditing stale drafts", async () => {
    const expected = new Error("correction transport stopped");
    let reads = 0;

    const correction = runScanQualityCorrection({
      residualRiskInventory: "",
      coverageGapInventory: "",
      findingQualityGapInventory: "",
      sendPrompt: async () => {
        throw expected;
      },
      readClosureInventories: async () => {
        reads += 1;
        return {
          coverageGapInventory: "",
          findingQualityGapInventory: "",
        };
      },
    });

    await expect(correction).rejects.toBe(expected);
    expect(reads).toBe(0);
  });

  test("fails closed after the bounded repair when deterministic gaps persist", async () => {
    const prompts: string[] = [];
    let reads = 0;
    const coverageGapInventory = '{"type":"coverage-gap-summary","gapCount":0}';
    const findingQualityGapInventory =
      '{"type":"finding-quality-gap-summary","gapCount":3}';

    const correction = runScanQualityCorrection({
      residualRiskInventory: "",
      coverageGapInventory: "",
      findingQualityGapInventory: "",
      sendPrompt: async (prompt) => {
        prompts.push(prompt);
      },
      readClosureInventories: async () => {
        reads += 1;
        return { coverageGapInventory, findingQualityGapInventory };
      },
    });

    await expect(correction).rejects.toMatchObject({
      name: "ScanClosureIncompleteError",
      findingQualityGapCount: 3,
      coverageGapCount: 0,
    });
    expect(prompts).toHaveLength(2);
    expect(prompts[1]).not.toContain("<coverage-gap-inventory>");
    expect(prompts[1]).toContain("<finding-quality-gap-inventory>");
    expect(reads).toBe(2);
  });

  test("fails closed when the targeted repair transport stops", async () => {
    let sends = 0;
    const expected = new Error("repair transport stopped");
    const correction = runScanQualityCorrection({
      residualRiskInventory: "",
      coverageGapInventory: "",
      findingQualityGapInventory: "",
      sendPrompt: async () => {
        sends += 1;
        if (sends === 2) throw expected;
      },
      readClosureInventories: async () => ({
        coverageGapInventory: '{"type":"coverage-gap-summary","gapCount":1}',
        findingQualityGapInventory: "",
      }),
    });

    await expect(correction).rejects.toMatchObject({
      name: "ScanClosureIncompleteError",
      coverageGapCount: 1,
      findingQualityGapCount: 0,
      cause: expected,
    });
    expect(sends).toBe(2);
  });

  test("treats malformed nonempty closure inventories as unresolved", () => {
    expect(
      closureGapCounts("not-json", '{"type":"wrong-summary","gapCount":0}'),
    ).toEqual({
      coverage: 1,
      findingQuality: 1,
    });
    expect(
      closureGapCounts(
        '{"type":"coverage-gap-summary","gapCount":-1}',
        '{"type":"finding-quality-gap-summary","gapCount":0}',
      ),
    ).toEqual({
      coverage: 1,
      findingQuality: 0,
    });
  });

  test("cleans up a partially started runtime without retrying session creation", async () => {
    const events: string[] = [];
    const expected = new Error("session creation failed");
    const client = {
      async start(): Promise<void> {
        events.push("start");
      },
      async stop(): Promise<Error[]> {
        events.push("stop");
        return [];
      },
      async forceStop(): Promise<void> {
        events.push("force-stop");
      },
    };
    let createAttempts = 0;

    await expect(
      startManagedCopilotSession(
        client,
        new AbortController().signal,
        async () => {
          createAttempts += 1;
          events.push("create");
          throw expected;
        },
      ),
    ).rejects.toBe(expected);

    expect(createAttempts).toBe(1);
    expect(events).toEqual(["start", "create", "stop"]);
  });

  test("force-stops failed graceful cleanup while preserving the startup error", async () => {
    const events: string[] = [];
    const expected = new Error("startup failed");
    const client = {
      async start(): Promise<void> {
        events.push("start");
        throw expected;
      },
      async stop(): Promise<Error[]> {
        events.push("stop");
        return [new Error("cleanup failed")];
      },
      async forceStop(): Promise<void> {
        events.push("force-stop");
      },
    };

    await expect(
      startManagedCopilotSession(
        client,
        new AbortController().signal,
        async () => {
          events.push("create");
          return {};
        },
      ),
    ).rejects.toBe(expected);

    expect(events).toEqual(["start", "stop", "force-stop"]);
  });

  test("bounds a hung graceful shutdown before forcing the runtime to stop", async () => {
    const events: string[] = [];
    const client = {
      async start(): Promise<void> {},
      async stop(): Promise<Error[]> {
        events.push("stop");
        return await new Promise<Error[]>(() => {});
      },
      async forceStop(): Promise<void> {
        events.push("force-stop");
      },
    };

    await stopManagedCopilotClient(client, 5);

    expect(events).toEqual(["stop", "force-stop"]);
  });

  test("honors cancellation before and during session initialization", async () => {
    const beforeStart = new AbortController();
    const beforeReason = new Error("cancelled before start");
    beforeStart.abort(beforeReason);
    const beforeEvents: string[] = [];
    const beforeClient = {
      async start(): Promise<void> {
        beforeEvents.push("start");
      },
      async stop(): Promise<Error[]> {
        beforeEvents.push("stop");
        return [];
      },
      async forceStop(): Promise<void> {
        beforeEvents.push("force-stop");
      },
    };
    await expect(
      startManagedCopilotSession(beforeClient, beforeStart.signal, async () => {
        beforeEvents.push("create");
        return {};
      }),
    ).rejects.toBe(beforeReason);
    expect(beforeEvents).toEqual([]);

    const duringCreate = new AbortController();
    const duringReason = new Error("cancelled during create");
    const duringEvents: string[] = [];
    const duringClient = {
      async start(): Promise<void> {
        duringEvents.push("start");
      },
      async stop(): Promise<Error[]> {
        duringEvents.push("stop");
        return [];
      },
      async forceStop(): Promise<void> {
        duringEvents.push("force-stop");
      },
    };
    await expect(
      startManagedCopilotSession(
        duringClient,
        duringCreate.signal,
        async () => {
          duringEvents.push("create");
          duringCreate.abort(duringReason);
          return {};
        },
      ),
    ).rejects.toBe(duringReason);
    expect(duringEvents).toEqual(["start", "create", "stop"]);
  });

  test("keeps scanner state inside its dedicated Copilot namespace", () => {
    const copilotHome = join(tmpdir(), "copilot-owned");
    const dedicatedHome = join(tmpdir(), "copilot-security-owned");

    expect(
      copilotSecurityStateDirectory({
        COPILOT_HOME: copilotHome,
      }),
    ).toEndWith(".copilot-security");
    expect(
      copilotSecurityCredentialHome({
        COPILOT_SECURITY_HOME: dedicatedHome,
        COPILOT_HOME: copilotHome,
      }),
    ).toBe(join(dedicatedHome, "copilot-security-home"));
  });

  test("runs the SDK transport from copilot-security-home", async () => {
    const root = join(tmpdir(), `copilot-security-runtime-${randomUUID()}`);
    const scannerHome = join(root, "scanner");
    const ambientHome = join(root, "ambient");
    const executable = await createCopilotStub(join(root, "bin"));
    temporaryPaths.push(root);
    await mkdir(ambientHome, { recursive: true });

    const runtime = await prepareCopilotRuntime(
      {},
      {
        ...process.env,
        COPILOT_SECURITY_HOME: scannerHome,
        COPILOT_HOME: ambientHome,
        COPILOT_CLI_PATH: executable,
      },
    );
    temporaryPaths.push(runtime.bootstrapWorkspace);

    expect(runtime.copilotHome).toBe(
      join(scannerHome, "copilot-security-home"),
    );
    expect(runtime.environment["COPILOT_HOME"]).toBe(runtime.copilotHome);
    expect(runtime.copilotHome).not.toContain(ambientHome);
  });
});
