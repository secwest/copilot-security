import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  addCopilotUsage,
  closureGapCounts,
  completeDraftQualityRecoveryPrompt,
  coverageClosureRecoveryPrompt,
  CopilotFileReviewTracker,
  copilotModelTurnTimeoutMilliseconds,
  copilotModelErrorRecovery,
  copilotShellSandboxViolation,
  COPILOT_SCANNER_SESSION_HOOKS,
  createCopilotScannerSessionHooks,
  createScopedScannerPermissionHandler,
  DEFAULT_FRESH_SESSION_ATTEMPTS,
  DEFAULT_MODEL_TURN_TIMEOUT_MILLISECONDS,
  disconnectManagedCopilotSession,
  emptyCopilotUsage,
  freshSessionRecoveryPrompt,
  freshSessionRetryReason,
  isSafetyClassifierRefusal,
  MAX_FRESH_SESSION_ATTEMPTS,
  modelFailureAfterCompleteDraftArtifacts,
  prepareCopilotRuntime,
  resolveCopilotCli,
  runWithFreshCopilotSessions,
  runScanQualityCorrection,
  safetyClassifierFreshSessionRecoveryPrompt,
  safetyClassifierRetryPrompt,
  sendCopilotPromptWithSafetyRecovery,
  sendCopilotTurnWithDeadline,
  startManagedCopilotSession,
  stopManagedCopilotClient,
  type CopilotScannerOptions,
} from "../src/copilot-client.js";
import {
  CompleteDraftArtifactsError,
  CopilotSecurity,
  CopilotSecurityError,
  ModelTransportInterruptedError,
  ModelTurnDeadlineExceededError,
  SafetyClassifierRetriesExhaustedError,
  ScanClosureIncompleteError,
  scanAuthentication,
  type ScanAuthentication,
} from "../src/index.js";
import {
  copilotSecurityCredentialHome,
  copilotSecurityStateDirectory,
} from "../src/runtime.js";
import { buildCoverageGapInventory } from "../src/residual-risk.js";

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
  test("records only successful built-in views beneath the staged repository", () => {
    const repository = join(tmpdir(), "copilot-review-tracker");
    const tracker = new CopilotFileReviewTracker(repository);
    const start = (
      toolCallId: string,
      toolName: string,
      path: string,
      mcpServerName?: string,
    ): void => {
      tracker.record({
        type: "tool.execution_start",
        data: {
          toolCallId,
          toolName,
          arguments: { path },
          ...(mcpServerName === undefined ? {} : { mcpServerName }),
        },
      } as never);
    };
    const complete = (toolCallId: string, success: boolean): void => {
      tracker.record({
        type: "tool.execution_complete",
        data: { toolCallId, success },
      } as never);
    };

    start("accepted", "view", join(repository, "src", "accepted.ts"));
    complete("accepted", true);
    start("failed", "view", join(repository, "src", "failed.ts"));
    complete("failed", false);
    start("outside", "view", join(repository, "..", "outside.ts"));
    complete("outside", true);
    start("shell", "bash", join(repository, "src", "shell.ts"));
    complete("shell", true);
    start("mcp", "view", join(repository, "src", "mcp.ts"), "untrusted-server");
    complete("mcp", true);

    expect([...tracker.reviewedInventoryPaths]).toEqual(["src/accepted.ts"]);
  });

  test("preserves successful views but clears unfinished calls across fresh sessions", () => {
    const repository = join(tmpdir(), "copilot-review-session-boundary");
    const tracker = new CopilotFileReviewTracker(repository);
    const start = (toolCallId: string, path: string): void => {
      tracker.record({
        type: "tool.execution_start",
        data: {
          toolCallId,
          toolName: "view",
          arguments: { path },
        },
      } as never);
    };
    const complete = (toolCallId: string): void => {
      tracker.record({
        type: "tool.execution_complete",
        data: { toolCallId, success: true },
      } as never);
    };

    start("completed", join(repository, "src", "first.ts"));
    complete("completed");
    start("reused", join(repository, "src", "interrupted.ts"));

    tracker.startSession();
    complete("reused");
    expect([...tracker.reviewedInventoryPaths]).toEqual(["src/first.ts"]);

    start("reused", join(repository, "src", "second.ts"));
    complete("reused");
    expect([...tracker.reviewedInventoryPaths]).toEqual([
      "src/first.ts",
      "src/second.ts",
    ]);
  });

  test("benchmarks exact coverage closure across an interrupted replacement session", async () => {
    const root = join(tmpdir(), `copilot-review-recovery-${randomUUID()}`);
    const repository = join(root, "repository");
    const scanDirectory = join(root, "scan");
    const discoveryDirectory = join(scanDirectory, "artifacts", "02_discovery");
    temporaryPaths.push(root);
    await mkdir(repository, { recursive: true });
    await mkdir(discoveryDirectory, { recursive: true });
    await writeFile(
      join(discoveryDirectory, "in_scope_files.txt"),
      "src/first.ts\nsrc/interrupted.ts\nsrc/replacement.ts\n",
    );
    await writeFile(
      join(scanDirectory, "coverage.json"),
      JSON.stringify({
        surfaces: [
          { label: "src/first.ts", disposition: "no_issue_found" },
          { label: "src/interrupted.ts", disposition: "no_issue_found" },
          { label: "src/replacement.ts", disposition: "no_issue_found" },
        ],
      }),
    );

    const tracker = new CopilotFileReviewTracker(repository);
    const start = (toolCallId: string, path: string): void => {
      tracker.record({
        type: "tool.execution_start",
        data: {
          toolCallId,
          toolName: "view",
          arguments: { path: join(repository, path) },
        },
      } as never);
    };
    const complete = (toolCallId: string): void => {
      tracker.record({
        type: "tool.execution_complete",
        data: { toolCallId, success: true },
      } as never);
    };
    const gapCount = async (): Promise<number> =>
      closureGapCounts(
        await buildCoverageGapInventory(
          scanDirectory,
          tracker.reviewedInventoryPaths,
        ),
        "",
      ).coverage;

    start("first", "src/first.ts");
    complete("first");
    start("reused", "src/interrupted.ts");
    expect(await gapCount()).toBe(2);

    tracker.startSession();
    complete("reused");
    expect(await gapCount()).toBe(2);

    start("reused", "src/interrupted.ts");
    complete("reused");
    start("replacement", "src/replacement.ts");
    complete("replacement");
    expect(await gapCount()).toBe(0);
    expect([...tracker.reviewedInventoryPaths]).toEqual([
      "src/first.ts",
      "src/interrupted.ts",
      "src/replacement.ts",
    ]);
  });

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
    expect(
      await handler(
        {
          kind: "write",
          fileName: join(
            scanDirectory,
            "artifacts",
            "02_discovery",
            "in_scope_files.txt",
          ),
          diff: "",
          intention: "replace the host inventory",
          canOfferSessionApproval: true,
        },
        { sessionId: "session" },
      ),
    ).toEqual({
      kind: "reject",
      feedback:
        "Copilot Security permits only sandboxed, offline repository reads and scan-directory artifact operations; this request is outside that profile.",
    });
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

  test("retries deadline failures in isolated sessions with idempotent recovery prompts", async () => {
    const attempts: Array<{ attempt: number; prompt: string }> = [];
    const retries: Array<[number, number, string]> = [];
    const result = await runWithFreshCopilotSessions({
      maxAttempts: DEFAULT_FRESH_SESSION_ATTEMPTS,
      prompt: "run the immutable scanner contract",
      runAttempt: async (attempt, prompt) => {
        attempts.push({ attempt, prompt });
        if (attempt < 3) throw new ModelTurnDeadlineExceededError(60_000);
        return "completed";
      },
      onRetry: (attempt, maximum, reason) => {
        retries.push([attempt, maximum, reason]);
      },
    });

    expect(result).toBe("completed");
    expect(attempts.map(({ attempt }) => attempt)).toEqual([1, 2, 3]);
    expect(attempts[0]?.prompt).toBe("run the immutable scanner contract");
    expect(attempts[1]?.prompt).toContain("Fresh-session recovery attempt 2/3");
    expect(attempts[1]?.prompt).toContain(
      "existing scan artifact as an untrusted, possibly partial draft",
    );
    expect(attempts[1]?.prompt).toContain(
      "trusted host will independently verify target identity",
    );
    expect(retries).toEqual([
      [2, 3, "model_timeout"],
      [3, 3, "model_timeout"],
    ]);
  });

  test("hands complete timed-out drafts to deterministic host recovery", async () => {
    const root = join(tmpdir(), `copilot-draft-recovery-${randomUUID()}`);
    const scanDirectory = join(root, "scan");
    temporaryPaths.push(root);
    await mkdir(scanDirectory, { recursive: true });
    const environment = { COPILOT_SECURITY_SCAN_DIR: scanDirectory };
    const timeout = new ModelTurnDeadlineExceededError(60_000);

    expect(
      await modelFailureAfterCompleteDraftArtifacts(timeout, environment),
    ).toBeNull();
    for (const name of ["scan-manifest.json", "findings.json"]) {
      await writeFile(join(scanDirectory, name), "{ draft: true }\n");
    }
    expect(
      await modelFailureAfterCompleteDraftArtifacts(timeout, environment),
    ).toBeNull();
    await writeFile(join(scanDirectory, "coverage.json"), "{ draft: true }\n");

    const recoverable = await modelFailureAfterCompleteDraftArtifacts(
      timeout,
      environment,
    );
    expect(recoverable).toBeInstanceOf(CopilotSecurityError);
    expect(recoverable?.message).toBe(
      "Copilot's model turn ended after producing all scan drafts; deterministic host validation will decide whether the scan can be recovered.",
    );
    expect(recoverable?.cause).toBe(timeout);
    expect(freshSessionRetryReason(recoverable)).toBeNull();

    expect(
      await modelFailureAfterCompleteDraftArtifacts(
        new Error("Safety classifier rejected the response"),
        environment,
      ),
    ).toBeNull();

    const missingResource = new Error(
      "400 The resource you requested was not found. (Request ID: redacted)",
    );
    const missingResourceRecovery =
      await modelFailureAfterCompleteDraftArtifacts(
        missingResource,
        environment,
      );
    expect(missingResourceRecovery).toBeInstanceOf(CompleteDraftArtifactsError);
    expect(missingResourceRecovery?.cause).toBe(missingResource);
  });

  test("moves complete timed-out drafts into bounded fresh-session quality correction", async () => {
    const root = join(tmpdir(), `copilot-draft-correction-${randomUUID()}`);
    const scanDirectory = join(root, "scan");
    temporaryPaths.push(root);
    await mkdir(scanDirectory, { recursive: true });
    for (const name of [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
    ]) {
      await writeFile(join(scanDirectory, name), "{}\n");
    }
    const failure = await modelFailureAfterCompleteDraftArtifacts(
      new ModelTurnDeadlineExceededError(60_000),
      { COPILOT_SECURITY_SCAN_DIR: scanDirectory },
    );
    if (failure === null) throw new Error("expected complete-draft failure");

    const attempts: Array<{
      attempt: number;
      prompt: string;
      phase: string;
      reason?: string;
    }> = [];
    const retries: Array<[number, number, string, string]> = [];
    const result = await runWithFreshCopilotSessions({
      maxAttempts: 3,
      prompt: "perform the complete repository scan",
      runAttempt: async (attempt, prompt, context) => {
        attempts.push({ attempt, prompt, ...context });
        if (attempt === 1) throw failure;
        return "corrected";
      },
      onRetry: (attempt, maximum, reason, phase) => {
        retries.push([attempt, maximum, reason, phase]);
      },
    });

    expect(result).toBe("corrected");
    expect(attempts).toHaveLength(2);
    expect(attempts[0]).toMatchObject({ attempt: 1, phase: "scan" });
    expect(attempts[1]).toMatchObject({
      attempt: 2,
      phase: "draft_quality_correction",
      reason: "model_timeout",
    });
    expect(attempts[1]?.prompt).toContain(
      "Fresh-session draft-quality recovery 2/3",
    );
    expect(attempts[1]?.prompt).toContain("missing_direct_file_review");
    expect(attempts[1]?.prompt).not.toContain(
      "perform the complete repository scan",
    );
    expect(retries).toEqual([
      [2, 3, "model_timeout", "draft_quality_correction"],
    ]);
    expect(completeDraftQualityRecoveryPrompt(3, 5)).toContain(
      "preserve successful direct-file views",
    );
  });

  test("keeps repeated draft correction transport failures inside the session budget", async () => {
    const phases: string[] = [];
    const prompts: string[] = [];
    const retries: Array<[string, string]> = [];
    const result = await runWithFreshCopilotSessions({
      maxAttempts: 3,
      prompt: "initial scan",
      runAttempt: async (attempt, prompt, context) => {
        phases.push(context.phase);
        prompts.push(prompt);
        if (attempt === 1) {
          throw new CompleteDraftArtifactsError("draft timeout", {
            cause: new ModelTurnDeadlineExceededError(60_000),
          });
        }
        if (attempt === 2) {
          throw new CompleteDraftArtifactsError("draft transport", {
            cause: new ModelTransportInterruptedError(),
          });
        }
        return "closed";
      },
      onRetry: (_attempt, _maximum, reason, phase) => {
        retries.push([reason, phase]);
      },
    });

    expect(result).toBe("closed");
    expect(phases).toEqual([
      "scan",
      "draft_quality_correction",
      "draft_quality_correction",
    ]);
    expect(prompts[0]).toBe("initial scan");
    expect(prompts[1]).toContain("draft-quality recovery 2/3");
    expect(prompts[2]).toContain("draft-quality recovery 3/3");
    expect(retries).toEqual([
      ["model_timeout", "draft_quality_correction"],
      ["transport_interrupted", "draft_quality_correction"],
    ]);
  });

  test("spends the remaining isolated-session budget on host-proven coverage closure", async () => {
    const attempts: Array<{
      attempt: number;
      phase: string;
      reason?: string;
      prompt: string;
    }> = [];
    const retries: Array<[number, number, string, string]> = [];
    const remainingCoverage = [474, 73, 0];

    const result = await runWithFreshCopilotSessions({
      maxAttempts: 5,
      prompt: "perform the complete repository scan",
      runAttempt: async (attempt, prompt, context) => {
        attempts.push({ attempt, prompt, ...context });
        const gaps = remainingCoverage.shift();
        if (gaps === undefined) throw new Error("missing benchmark state");
        if (gaps > 0) throw new ScanClosureIncompleteError(0, gaps);
        return "closed";
      },
      onRetry: (attempt, maximum, reason, phase) => {
        retries.push([attempt, maximum, reason, phase]);
      },
    });

    expect(result).toBe("closed");
    expect(remainingCoverage).toHaveLength(0);
    expect(attempts.map(({ attempt }) => attempt)).toEqual([1, 2, 3]);
    expect(attempts[0]).toMatchObject({ attempt: 1, phase: "scan" });
    for (const attempt of attempts.slice(1)) {
      expect(attempt).toMatchObject({
        phase: "coverage_closure",
        reason: "closure_incomplete",
      });
      expect(attempt.prompt).toContain("Fresh-session coverage closure");
      expect(attempt.prompt).toContain("missing_direct_file_review");
      expect(attempt.prompt).toContain(
        "inspect only the exact repository paths",
      );
      expect(attempt.prompt).not.toContain(
        "perform the complete repository scan",
      );
    }
    expect(retries).toEqual([
      [2, 5, "closure_incomplete", "coverage_closure"],
      [3, 5, "closure_incomplete", "coverage_closure"],
    ]);
    expect(coverageClosureRecoveryPrompt(5, 5)).toContain(
      "leave coverage partial if the total isolated-session budget is exhausted",
    );
  });

  test("fails closed when host-proven gaps exhaust the total isolated-session budget", async () => {
    const attempts: Array<{ attempt: number; phase: string }> = [];
    const gapCounts: number[] = [];
    const terminal = new ScanClosureIncompleteError(2, 11);

    await expect(
      runWithFreshCopilotSessions({
        maxAttempts: 3,
        prompt: "scan",
        runAttempt: async (attempt, _prompt, context) => {
          attempts.push({ attempt, phase: context.phase });
          gapCounts.push(terminal.coverageGapCount);
          throw terminal;
        },
      }),
    ).rejects.toBe(terminal);

    expect(attempts).toEqual([
      { attempt: 1, phase: "scan" },
      { attempt: 2, phase: "coverage_closure" },
      { attempt: 3, phase: "coverage_closure" },
    ]);
    expect(gapCounts).toEqual([11, 11, 11]);
  });

  test("preserves transport classification inside closure and does not replay terminal causes", async () => {
    const phases: string[] = [];
    const reasons: string[] = [];
    const recovered = await runWithFreshCopilotSessions({
      maxAttempts: 2,
      prompt: "scan",
      runAttempt: async (attempt, _prompt, context) => {
        phases.push(context.phase);
        if (attempt === 1) {
          throw new ScanClosureIncompleteError(0, 4, {
            cause: new ModelTransportInterruptedError(),
          });
        }
        return "closed";
      },
      onRetry: (_attempt, _maximum, reason) => reasons.push(reason),
    });
    expect(recovered).toBe("closed");
    expect(phases).toEqual(["scan", "draft_quality_correction"]);
    expect(reasons).toEqual(["transport_interrupted"]);

    let attempts = 0;
    const terminal = new ScanClosureIncompleteError(0, 4, {
      cause: new CopilotSecurityError(
        "safety filtering rejected the authorized defensive scan after bounded retries",
      ),
    });
    await expect(
      runWithFreshCopilotSessions({
        maxAttempts: 5,
        prompt: "scan",
        runAttempt: async () => {
          attempts += 1;
          throw terminal;
        },
      }),
    ).rejects.toBe(terminal);
    expect(attempts).toBe(1);
  });

  test("fails closed after the configured fresh-session budget", async () => {
    const terminal = new ModelTurnDeadlineExceededError(60_000);
    const attempts: number[] = [];

    await expect(
      runWithFreshCopilotSessions({
        maxAttempts: MAX_FRESH_SESSION_ATTEMPTS,
        prompt: "scan",
        runAttempt: async (attempt) => {
          attempts.push(attempt);
          throw terminal;
        },
      }),
    ).rejects.toBe(terminal);
    expect(attempts).toEqual([1, 2, 3, 4, 5]);
  });

  test("never retries authentication, raw classifier, contract, or cancellation failures", async () => {
    for (const terminal of [
      new Error("401 unauthorized token"),
      new Error("Safety classifier rejected the response"),
      new Error("coverage contract validation failed"),
      new CompleteDraftArtifactsError("unretryable complete drafts", {
        cause: new CopilotSecurityError("401 authentication failed"),
      }),
    ]) {
      let attempts = 0;
      await expect(
        runWithFreshCopilotSessions({
          maxAttempts: 3,
          prompt: "scan",
          runAttempt: async () => {
            attempts += 1;
            throw terminal;
          },
        }),
      ).rejects.toBe(terminal);
      expect(attempts).toBe(1);
    }

    const cancellation = new AbortController();
    const reason = new Error("user cancelled");
    let attempts = 0;
    await expect(
      runWithFreshCopilotSessions({
        maxAttempts: 3,
        signal: cancellation.signal,
        prompt: "scan",
        runAttempt: async () => {
          attempts += 1;
          cancellation.abort(reason);
          throw new ModelTurnDeadlineExceededError(60_000);
        },
      }),
    ).rejects.toBe(reason);
    expect(attempts).toBe(1);
  });

  test("classifies only bounded timeout and transport failures for fresh sessions", () => {
    expect(
      freshSessionRetryReason(new ModelTurnDeadlineExceededError(60_000)),
    ).toBe("model_timeout");
    expect(freshSessionRetryReason(new ModelTransportInterruptedError())).toBe(
      "transport_interrupted",
    );
    expect(
      freshSessionRetryReason(new SafetyClassifierRetriesExhaustedError(6)),
    ).toBe("safety_filter_refusal");
    for (const message of [
      "Responses stream ended without a completed response",
      "read ECONNRESET while waiting for model transport",
      "socket hang up",
    ]) {
      expect(freshSessionRetryReason(new Error(message))).toBe(
        "transport_interrupted",
      );
    }
    for (const message of [
      "403 model access forbidden",
      "Safety filtering rejected the request",
      "sandbox telemetry missing",
      "scan contract is incomplete",
    ]) {
      expect(freshSessionRetryReason(new Error(message))).toBeNull();
    }
    expect(
      freshSessionRetryReason(
        new CopilotSecurityError(
          "Scanner contract failed after a transport closed.",
        ),
      ),
    ).toBeNull();
    expect(() => freshSessionRecoveryPrompt("scan", 2, 3)).not.toThrow();
  });

  test("uses the fresh-session budget after bounded safety refusals", async () => {
    const attempts: Array<{
      attempt: number;
      phase: string;
      reason?: string;
      prompt: string;
    }> = [];
    const retries: Array<[number, number, string, string]> = [];
    const refusal = new SafetyClassifierRetriesExhaustedError(6);
    const result = await runWithFreshCopilotSessions({
      maxAttempts: 3,
      prompt: "perform the complete defensive repository scan",
      runAttempt: async (attempt, prompt, context) => {
        attempts.push({ attempt, prompt, ...context });
        if (attempt < 3) throw refusal;
        return "completed";
      },
      onRetry: (attempt, maximum, reason, phase) => {
        retries.push([attempt, maximum, reason, phase]);
      },
    });

    expect(result).toBe("completed");
    expect(attempts.map(({ attempt }) => attempt)).toEqual([1, 2, 3]);
    expect(attempts[1]).toMatchObject({
      phase: "scan",
      reason: "safety_filter_refusal",
    });
    expect(attempts[1]?.prompt).toContain(
      "Fresh-session safety-filter recovery 2/3",
    );
    expect(attempts[1]?.prompt).toContain(
      "authorized defensive software-assurance scan",
    );
    expect(attempts[1]?.prompt).toContain(
      "perform the complete defensive repository scan",
    );
    expect(retries).toEqual([
      [2, 3, "safety_filter_refusal", "scan"],
      [3, 3, "safety_filter_refusal", "scan"],
    ]);
    expect(safetyClassifierFreshSessionRecoveryPrompt("scan", 2, 3)).toContain(
      "do not target external systems",
    );
  });

  test("retries a sanitized model-transport interruption", async () => {
    const attempts: number[] = [];
    const result = await runWithFreshCopilotSessions({
      maxAttempts: 2,
      prompt: "scan",
      runAttempt: async (attempt) => {
        attempts.push(attempt);
        if (attempt === 1) throw new ModelTransportInterruptedError();
        return "completed";
      },
    });

    expect(result).toBe("completed");
    expect(attempts).toEqual([1, 2]);
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
    ).rejects.toBeInstanceOf(SafetyClassifierRetriesExhaustedError);
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

  test("uses the first bounded repair when corrected artifacts retain gaps", async () => {
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
    expect(prompts[1]).toContain("Bounded Copilot Security closure repair 1/3");
    expect(prompts[1]).toContain("Coverage serialization invariant");
    expect(prompts[1]).toContain("Never repair JSON with regular-expression");
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

  test("closes on a later repair only after every intermediate host re-audit", async () => {
    const prompts: string[] = [];
    const closureStates = [
      {
        coverageGapInventory:
          '{"type":"coverage-gap-summary","gapCount":2}\n{"path":"src/first.ts"}',
        findingQualityGapInventory: "",
      },
      {
        coverageGapInventory:
          '{"type":"coverage-gap-summary","gapCount":1}\n{"path":"src/second.ts"}',
        findingQualityGapInventory: "",
      },
      {
        coverageGapInventory:
          '{"type":"coverage-gap-summary","gapCount":1}\n{"path":"src/third.ts"}',
        findingQualityGapInventory: "",
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

    expect(prompts).toHaveLength(4);
    expect(prompts[1]).toContain("closure repair 1/3");
    expect(prompts[1]).toContain("src/first.ts");
    expect(prompts[2]).toContain("closure repair 2/3");
    expect(prompts[2]).toContain("src/second.ts");
    expect(prompts[2]).not.toContain("src/first.ts");
    expect(prompts[3]).toContain("closure repair 3/3");
    expect(prompts[3]).toContain("src/third.ts");
    expect(closureStates).toHaveLength(0);
  });

  test("fails closed after all bounded repairs when deterministic gaps persist", async () => {
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
    expect(prompts).toHaveLength(4);
    for (const prompt of prompts.slice(1)) {
      expect(prompt).not.toContain("<coverage-gap-inventory>");
      expect(prompt).toContain("<finding-quality-gap-inventory>");
    }
    expect(prompts[3]).toContain("closure repair 3/3");
    expect(reads).toBe(4);
  });

  test("rejects an invalid closure repair bound before sending a repair", async () => {
    let sends = 0;
    const correction = runScanQualityCorrection({
      residualRiskInventory: "",
      coverageGapInventory: "",
      findingQualityGapInventory: "",
      maxRepairAttempts: 0,
      sendPrompt: async () => {
        sends += 1;
      },
      readClosureInventories: async () => ({
        coverageGapInventory: '{"type":"coverage-gap-summary","gapCount":1}',
        findingQualityGapInventory: "",
      }),
    });

    await expect(correction).rejects.toThrow(
      "Scan closure repair attempts must be a positive whole number.",
    );
    expect(sends).toBe(1);
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

  test("bounds a hung session disconnect before opening a fresh session", async () => {
    let disconnects = 0;
    await disconnectManagedCopilotSession(
      {
        async disconnect(): Promise<never> {
          disconnects += 1;
          return await new Promise<never>(() => {});
        },
      },
      5,
    );
    expect(disconnects).toBe(1);
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
  }, 180_000);
});
