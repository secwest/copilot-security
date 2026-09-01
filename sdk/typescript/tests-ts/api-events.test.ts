import { mkdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
type ThreadEvent = { type: string; [key: string]: unknown };
import { afterEach, describe, expect, test } from "bun:test";
import { runScanEvents } from "../src/api.js";
import {
  CompleteDraftArtifactsError,
  CopilotSecurityError,
  IncompleteScanError,
  ScanClosureIncompleteError,
  ScanInterruptedError,
  type ScanReconnectDetails,
  type ScanWorkerStatus,
} from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  completedEvents,
  createApiTestFixtures,
  runEvents,
  type ScanObserverName,
} from "./support/api-events.js";

const { cleanup, copyCompletedScan, temporaryDirectory } =
  createApiTestFixtures();

afterEach(cleanup);

describe("one-shot scan events", () => {
  test("surfaces cumulative streamed usage before turn completion", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const observed: unknown[] = [];
    async function* events(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield {
        type: "copilot.usage",
        usage: { input_tokens: 20, output_tokens: 4 },
      };
      yield* completedEvents();
    }

    await runScanEvents({
      thread: {
        id: null,
        async runStreamed() {
          return { events: events() };
        },
      },
      events: events(),
      signal: new AbortController().signal,
      scanDir,
      pluginRoot: PLUGIN_ROOT,
      expectation: {
        repository: "/repository",
        repositoryRevision: "deadbeef",
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      onUsage: (usage) => observed.push(usage),
    });

    expect(observed).toEqual([{ input_tokens: 20, output_tokens: 4 }]);
  });

  test("validates completed scan artifacts", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const result = await runEvents(scanDir, completedEvents());

    expect(result.threadId).toBe("thread-1");
    expect(result.turnResult).toMatchObject({
      status: "completed",
      model: "gpt-5.6-sol",
      finalResponse: "scan complete",
    });
    expect(result.cost).toEqual({
      model: "gpt-5.6-sol",
      inputTokens: 10,
      cachedInputTokens: 2,
      cacheWriteInputTokens: 0,
      outputTokens: 3,
      estimatedUsd: 0.000131,
    });
  });

  test("accepts target identity validated by the workbench", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const events = completedEvents();

    const result = await runScanEvents({
      thread: {
        id: null,
        async runStreamed() {
          return { events };
        },
      },
      events,
      signal: new AbortController().signal,
      scanDir,
      pluginRoot: PLUGIN_ROOT,
      expectation: {
        repository: "/repository",
        repositoryRevision: "different-revision",
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      workbenchValidated: true,
    });

    expect(result.threadId).toBe("thread-1");
    expect(result.turnResult.status).toBe("completed");
  });

  test("lets the workbench seal artifacts before validating completed scans", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "scan");
    const events = completedEvents();
    let finalized = false;

    const result = await runScanEvents({
      thread: {
        id: null,
        async runStreamed() {
          return { events };
        },
      },
      events,
      signal: new AbortController().signal,
      scanDir,
      pluginRoot: PLUGIN_ROOT,
      expectation: {
        repository: "/repository",
        repositoryRevision: "deadbeef",
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      onFinalize: async (usage) => {
        expect(usage).toMatchObject({
          input_tokens: 10,
          cached_input_tokens: 2,
          output_tokens: 3,
        });
        expect(existsSync(join(scanDir, "scan-manifest.json"))).toBe(false);
        await copyCompletedScan(root);
        finalized = true;
      },
    });

    expect(finalized).toBe(true);
    expect(result.threadId).toBe("thread-1");
    expect(result.turnResult.status).toBe("completed");
  });

  test("reports a scan as started only after the thread starts", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const milestones: string[] = [];

    async function* events(): AsyncGenerator<ThreadEvent> {
      milestones.push("stream opened");
      yield { type: "turn.started" };
      milestones.push("thread starting");
      yield* completedEvents();
    }

    await runEvents(scanDir, events(), undefined, undefined, undefined, () =>
      milestones.push("scan started"),
    );

    expect(milestones).toEqual([
      "stream opened",
      "thread starting",
      "scan started",
    ]);
  });

  test("does not report a scan as started when its stream fails first", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    let scanStarted = false;

    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "error", message: "stream failed to start" };
    }

    await expect(
      runEvents(
        scanDir,
        failedEvents(),
        undefined,
        undefined,
        undefined,
        () => {
          scanStarted = true;
        },
      ),
    ).rejects.toThrow("stream failed to start");
    expect(scanStarted).toBe(false);
  });

  test("reports a scan as started only once if thread events are replayed", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    let starts = 0;
    const observerErrors: Array<[ScanObserverName, string]> = [];

    async function* replayedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield* completedEvents();
    }

    await runEvents(
      scanDir,
      replayedEvents(),
      undefined,
      undefined,
      undefined,
      () => {
        starts += 1;
        throw new Error("start observer exploded");
      },
      (observer, error) => {
        observerErrors.push([observer, (error as Error).message]);
      },
    );

    expect(starts).toBe(1);
    expect(observerErrors).toEqual([
      ["onScanStarted", "start observer exploded"],
    ]);
  });

  test("retains partial output and reports interruption", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    const abortController = new AbortController();
    const reconnects: Array<[number, number]> = [];
    let notifyReconnect!: () => void;
    const reconnectSeen = new Promise<void>((resolve) => {
      notifyReconnect = resolve;
    });
    async function* interruptedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-2" };
      yield { type: "error", message: "Reconnecting... 2/5" };
      await new Promise<void>((resolve) => {
        abortController.signal.addEventListener("abort", () => resolve(), {
          once: true,
        });
      });
      throw new DOMException("aborted", "AbortError");
    }
    const result = runEvents(
      scanDir,
      interruptedEvents(),
      abortController,
      (attempt, maxAttempts) => {
        reconnects.push([attempt, maxAttempts]);
        notifyReconnect();
      },
    );

    await reconnectSeen;
    abortController.abort();
    await expect(result).rejects.toMatchObject({
      name: ScanInterruptedError.name,
      scanDir,
    });
    expect(reconnects).toEqual([[2, 5]]);
    await expect(stat(scanDir)).resolves.toBeDefined();
  });

  test("isolates synchronous and asynchronous progress-observer failures", async () => {
    for (const asynchronous of [false, true]) {
      const scanDir = await copyCompletedScan(await temporaryDirectory());
      const observerErrors: Array<[ScanObserverName, string]> = [];
      async function* reconnectingEvents(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "error", message: "Reconnecting... 2/5" };
        yield {
          type: "turn.completed",
          usage: {
            input_tokens: 1,
            cached_input_tokens: 0,
            output_tokens: 1,
            reasoning_output_tokens: 0,
          },
        };
      }

      await expect(
        runEvents(
          scanDir,
          reconnectingEvents(),
          new AbortController(),
          () => {
            const error = new Error("observer exploded");
            if (asynchronous) return Promise.reject(error);
            throw error;
          },
          undefined,
          undefined,
          (observer, error) => {
            observerErrors.push([observer, (error as Error).message]);
            if (asynchronous) return Promise.reject(new Error("report failed"));
          },
        ),
      ).resolves.toBeDefined();
      expect(observerErrors).toEqual([["onReconnect", "observer exploded"]]);
    }
  });

  test("keeps the Copilot stream alive through reconnect notifications", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const reconnects: Array<[number, number]> = [];
    let release!: () => void;
    const paused = new Promise<void>((resolve) => {
      release = resolve;
    });
    let notifyReconnect!: () => void;
    const reconnectSeen = new Promise<void>((resolve) => {
      notifyReconnect = resolve;
    });
    let closed = false;
    async function* reconnectingEvents(): AsyncGenerator<ThreadEvent> {
      try {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "turn.started" };
        yield {
          type: "error",
          message:
            "Reconnecting... 2/5 (Rate limit reached for org-private. Please try again in 1.2s.)",
        };
        notifyReconnect();
        await paused;
        yield { type: "error", message: "Reconnecting… 3/5" };
        yield {
          type: "item.completed",
          item: {
            id: "message-1",
            type: "agent_message",
            text: "scan complete",
          },
        };
        yield {
          type: "turn.completed",
          usage: {
            input_tokens: 10,
            cached_input_tokens: 2,
            output_tokens: 3,
            reasoning_output_tokens: 1,
          },
        };
      } finally {
        closed = true;
      }
    }
    const result = runEvents(
      scanDir,
      reconnectingEvents(),
      new AbortController(),
      (attempt, maxAttempts) => reconnects.push([attempt, maxAttempts]),
    );

    await reconnectSeen;
    expect(closed).toBe(false);
    expect(reconnects).toEqual([[2, 5]]);
    release();

    await expect(result).resolves.toBeDefined();
    expect(closed).toBe(true);
    expect(reconnects).toEqual([
      [2, 5],
      [3, 5],
    ]);
  });

  test("preserves terminal failures after reconnect notifications", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield { type: "error", message: "Reconnecting... 2/5" };
      yield {
        type: "turn.failed",
        error: { message: "retry budget exhausted" },
      };
    }

    await expect(runEvents(scanDir, failedEvents())).rejects.toMatchObject({
      name: CopilotSecurityError.name,
      message: "retry budget exhausted",
    });
  });

  test("recovers a terminal model-stream failure when deterministic finalization accepts the artifacts", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "scan");
    let recovered: Error | null = null;
    let finalized = 0;
    const usage = {
      input_tokens: 50,
      cached_input_tokens: 10,
      output_tokens: 20,
      reasoning_output_tokens: 5,
    };
    async function* failedAfterArtifacts(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-recovered" };
      yield {
        type: "turn.failed",
        error: {
          message: "Responses stream ended without a completed response",
        },
        usage,
      } as ThreadEvent;
    }

    const result = await runScanEvents({
      thread: {
        id: null,
        async runStreamed() {
          return { events: failedAfterArtifacts() };
        },
      },
      events: failedAfterArtifacts(),
      signal: new AbortController().signal,
      scanDir,
      pluginRoot: PLUGIN_ROOT,
      expectation: {
        repository: "/repository",
        repositoryRevision: "deadbeef",
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      recoverIncompleteWithFinalize: true,
      onFinalize: async (observedUsage) => {
        finalized += 1;
        expect(observedUsage).toEqual(usage);
        await copyCompletedScan(root);
        return observedUsage;
      },
      onRecovered: (failure) => {
        recovered = failure;
      },
    });

    expect(finalized).toBe(1);
    expect(recovered).toMatchObject({
      message: "Responses stream ended without a completed response",
    });
    expect(result.threadId).toBe("thread-recovered");
    expect(result.turnResult).toMatchObject({
      status: "completed",
      usage,
    });
  });

  test("preserves partial artifacts but rejects an exhausted closure", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "scan");
    let recovered: Error | null = null;
    let finalized = 0;
    async function* exhaustedClosure(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-partial-closure" };
      yield {
        type: "turn.failed",
        error: { message: "private model text must not be forwarded" },
        failure_kind: "closure_incomplete",
        finding_quality_gap_count: 2,
        coverage_gap_count: 474,
        usage: { input_tokens: 100, output_tokens: 10 },
      };
    }

    let rejection: unknown = null;
    try {
      await runScanEvents({
        thread: {
          id: null,
          async runStreamed() {
            return { events: exhaustedClosure() };
          },
        },
        events: exhaustedClosure(),
        signal: new AbortController().signal,
        scanDir,
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          repository: "/repository",
          repositoryRevision: "deadbeef",
          target: { kind: "repository", paths: [] },
          mode: "standard",
          pluginVersion: "0.1.0",
        },
        recoverIncompleteWithFinalize: true,
        onFinalize: async (usage) => {
          finalized += 1;
          await copyCompletedScan(root);
          return usage;
        },
        onRecovered: (failure) => {
          recovered = failure;
        },
      });
    } catch (error) {
      rejection = error;
    }

    expect(finalized).toBe(1);
    expect(recovered).toBeNull();
    expect(rejection).toBeInstanceOf(ScanClosureIncompleteError);
    expect(rejection).toMatchObject({
      findingQualityGapCount: 2,
      coverageGapCount: 474,
    });
    expect((rejection as Error).message).not.toContain("private model text");
  });

  test("recovers a thrown complete-draft signal when deterministic finalization accepts the artifacts", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "scan");
    let recovered: Error | null = null;
    let finalized = 0;
    const failure = new CompleteDraftArtifactsError(
      "complete drafts await host validation",
    );
    async function* throwsAfterDrafts(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-thrown-drafts" };
      throw failure;
    }

    const result = await runScanEvents({
      thread: {
        id: null,
        async runStreamed() {
          return { events: throwsAfterDrafts() };
        },
      },
      events: throwsAfterDrafts(),
      signal: new AbortController().signal,
      scanDir,
      pluginRoot: PLUGIN_ROOT,
      expectation: {
        repository: "/repository",
        repositoryRevision: "deadbeef",
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      recoverIncompleteWithFinalize: true,
      onFinalize: async (observedUsage) => {
        finalized += 1;
        expect(observedUsage).toBeNull();
        await copyCompletedScan(root);
        return observedUsage;
      },
      onRecovered: (observedFailure) => {
        recovered = observedFailure;
      },
    });

    expect(finalized).toBe(1);
    expect(recovered as Error | null).toBe(failure);
    expect(result.threadId).toBe("thread-thrown-drafts");
    expect(result.turnResult).toMatchObject({
      status: "completed",
      usage: null,
    });
  });

  test("preserves the terminal stream error when deterministic recovery rejects incomplete artifacts", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield {
        type: "turn.failed",
        error: { message: "model stream exhausted its retries" },
      };
    }

    await expect(
      runScanEvents({
        thread: {
          id: null,
          async runStreamed() {
            return { events: failedEvents() };
          },
        },
        events: failedEvents(),
        signal: new AbortController().signal,
        scanDir,
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          repository: "/repository",
          repositoryRevision: "deadbeef",
          target: { kind: "repository", paths: [] },
          mode: "standard",
          pluginVersion: "0.1.0",
        },
        recoverIncompleteWithFinalize: true,
        onFinalize: async () => {
          throw new Error("artifacts are incomplete");
        },
      }),
    ).rejects.toMatchObject({
      name: CopilotSecurityError.name,
      message: "model stream exhausted its retries",
    });
  });

  test("reports deterministic rejection of a thrown complete-draft signal", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "scan");
    async function* throwsAfterDrafts(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-rejected-drafts" };
      throw new CompleteDraftArtifactsError(
        "complete drafts await host validation",
      );
    }

    await expect(
      runScanEvents({
        thread: {
          id: null,
          async runStreamed() {
            return { events: throwsAfterDrafts() };
          },
        },
        events: throwsAfterDrafts(),
        signal: new AbortController().signal,
        scanDir,
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          repository: "/repository",
          repositoryRevision: "deadbeef",
          target: { kind: "repository", paths: [] },
          mode: "standard",
          pluginVersion: "0.1.0",
        },
        recoverIncompleteWithFinalize: true,
        onFinalize: async () => {
          throw new Error("malformed manifest");
        },
      }),
    ).rejects.toMatchObject({
      name: CompleteDraftArtifactsError.name,
      message:
        "Copilot produced all scan drafts, but deterministic host validation rejected them.",
    });
  });

  test("extracts bounded rate-limit context from reconnect notifications", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const reconnects: Array<{
      attempt: number;
      maxAttempts: number;
      details?: ScanReconnectDetails;
    }> = [];

    async function* events(): AsyncGenerator<ThreadEvent> {
      yield {
        type: "error",
        message:
          "Reconnecting... 2/5 (Rate limit reached for org-private. Please try again in 1.2s.)",
      };
      yield {
        type: "error",
        message:
          "Reconnecting... 3/5 (Rate limit reached. Please try again in 999999s.)",
      };
      yield { type: "error", message: "Reconnecting... 4/5" };
      yield* completedEvents();
    }

    await runEvents(
      scanDir,
      events(),
      new AbortController(),
      (attempt, maxAttempts, details) => {
        reconnects.push({
          attempt,
          maxAttempts,
          ...(details ? { details } : {}),
        });
      },
    );

    expect(reconnects).toEqual([
      {
        attempt: 2,
        maxAttempts: 5,
        details: { reason: "rate_limit", retryAfterSeconds: 1.2 },
      },
      { attempt: 3, maxAttempts: 5, details: { reason: "rate_limit" } },
      { attempt: 4, maxAttempts: 5 },
    ]);
    expect(JSON.stringify(reconnects)).not.toContain("org-private");
  });

  test("reports bounded fresh-session recovery without provider error text", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const reconnects: Array<{
      attempt: number;
      maximum: number;
      details?: ScanReconnectDetails;
    }> = [];
    let starts = 0;
    async function* events(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-attempt-1" };
      yield {
        type: "copilot.fresh_session_retry",
        attempt: 2,
        max_attempts: 3,
        reason: "model_timeout",
        recovery_phase: "draft_quality_correction",
        provider_error: "private provider detail",
      };
      yield {
        type: "copilot.fresh_session_retry",
        attempt: 3,
        max_attempts: 3,
        reason: "closure_incomplete",
        recovery_phase: "coverage_closure",
        coverage_gap_count: 474,
      };
      yield {
        type: "copilot.fresh_session_retry",
        attempt: 2,
        max_attempts: 5,
        reason: "safety_filter_refusal",
        recovery_phase: "scan",
        provider_error: "private classifier detail",
      };
      yield {
        type: "copilot.fresh_session_retry",
        attempt: 3,
        max_attempts: 5,
        reason: "model_resource_not_found",
        recovery_phase: "draft_quality_correction",
        provider_error: "private resource identifier",
      };
      yield {
        type: "copilot.fresh_session_retry",
        attempt: 999,
        max_attempts: 999,
        reason: "model_timeout",
      };
      yield { type: "thread.started", thread_id: "thread-attempt-2" };
      yield {
        type: "turn.completed",
        usage: { input_tokens: 30, output_tokens: 5 },
      };
    }

    const result = await runEvents(
      scanDir,
      events(),
      new AbortController(),
      (attempt, maximum, details) => {
        reconnects.push({ attempt, maximum, details });
      },
      undefined,
      () => {
        starts += 1;
      },
    );

    expect(result.threadId).toBe("thread-attempt-2");
    expect(starts).toBe(1);
    expect(reconnects).toEqual([
      {
        attempt: 2,
        maximum: 3,
        details: {
          reason: "model_timeout",
          phase: "draft_quality_correction",
        },
      },
      {
        attempt: 3,
        maximum: 3,
        details: {
          reason: "closure_incomplete",
          phase: "coverage_closure",
        },
      },
      {
        attempt: 2,
        maximum: 5,
        details: {
          reason: "safety_filter_refusal",
          phase: "scan",
        },
      },
      {
        attempt: 3,
        maximum: 5,
        details: {
          reason: "model_resource_not_found",
          phase: "draft_quality_correction",
        },
      },
    ]);
    expect(JSON.stringify(reconnects)).not.toContain("private provider detail");
    expect(JSON.stringify(reconnects)).not.toContain(
      "private classifier detail",
    );
    expect(JSON.stringify(reconnects)).not.toContain(
      "private resource identifier",
    );
    expect(JSON.stringify(reconnects)).not.toContain("474");
  });

  test("classifies retryable reconnect causes without exposing provider details", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const reconnects: ScanReconnectDetails[] = [];

    async function* events(): AsyncGenerator<ThreadEvent> {
      yield {
        type: "error",
        message: "Reconnecting... 1/5 (ECONNRESET org-private)",
      };
      yield {
        type: "error",
        message: "Reconnecting... 2/5 (429 rate limit reached org-private)",
      };
      yield* completedEvents();
    }

    await runEvents(
      scanDir,
      events(),
      new AbortController(),
      (_a, _m, detail) => {
        if (detail !== undefined) reconnects.push(detail);
      },
    );

    expect(reconnects).toEqual([
      { reason: "network" },
      { reason: "rate_limit" },
    ]);
    expect(JSON.stringify(reconnects)).not.toContain("org-private");
  });

  test("fails immediately on definitive authentication and authorization errors", async () => {
    for (const message of [
      "Reconnecting... 1/5 (401 invalid API key org-private)",
      "Reconnecting... 1/5 (403 model access denied org-private)",
    ]) {
      const scanDir = join(await temporaryDirectory(), "partial-scan");
      await mkdir(scanDir, { mode: 0o700 });
      const reconnects: Array<[number, number]> = [];
      let advancedPastFailure = false;

      async function* events(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "error", message };
        advancedPastFailure = true;
        yield { type: "error", message: "Reconnecting... 2/5" };
      }

      await expect(
        runEvents(
          scanDir,
          events(),
          new AbortController(),
          (attempt, maxAttempts) => {
            reconnects.push([attempt, maxAttempts]);
          },
        ),
      ).rejects.toMatchObject({ name: CopilotSecurityError.name, message });
      expect(reconnects).toEqual([]);
      expect(advancedPastFailure).toBe(false);
    }
  });

  test("uses the last reconnect error when Copilot ends without a terminal event", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    async function* incompleteEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield { type: "error", message: "Reconnecting... 2/5" };
    }

    await expect(runEvents(scanDir, incompleteEvents())).rejects.toMatchObject({
      name: IncompleteScanError.name,
      message: "Reconnecting... 2/5",
    });
  });

  test("keeps non-reconnect stream errors terminal", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    for (const message of ["stream disconnected", "Reconnecting... 6/5"]) {
      async function* failedEvents(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "turn.started" };
        yield { type: "error", message: "Reconnecting... 2/5" };
        yield { type: "error", message };
      }

      await expect(runEvents(scanDir, failedEvents())).rejects.toMatchObject({
        name: CopilotSecurityError.name,
        message,
      });
    }
  });

  test("preserves subprocess failures after reconnect notifications", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield { type: "error", message: "Reconnecting... 2/5" };
      throw new Error("Copilot Exec exited with code 1");
    }

    await expect(runEvents(scanDir, failedEvents())).rejects.toThrow(
      "Copilot Exec exited with code 1",
    );
  });

  test("forwards bounded worker-capacity updates while the scan runs", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const statuses: ScanWorkerStatus[] = [];
    async function* workerEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield {
        type: "item.completed",
        item: {
          id: "command-1",
          type: "command_execution",
          command:
            "python3 /plugin/scripts/config_preflight.py --profile security_scan",
          aggregated_output: JSON.stringify({
            profile: "security_scan",
            status: "ready",
            results: [
              { capability: "delegated_workers", status: "pass" },
              {
                capability: "usable_worker_slots_6",
                status: "pass",
                actual: 8,
              },
            ],
          }),
          exit_code: 0,
          status: "completed",
        },
      };
      yield {
        type: "item.completed",
        item: {
          id: "message-1",
          type: "agent_message",
          text: 'COPILOT_SECURITY_WORKER_STATUS {"phase":"ranking","planned":6,"started":3}',
        },
      };
      yield {
        type: "turn.completed",
        usage: {
          input_tokens: 10,
          cached_input_tokens: 2,
          output_tokens: 3,
          reasoning_output_tokens: 1,
        },
      };
    }

    await expect(
      runEvents(
        scanDir,
        workerEvents(),
        new AbortController(),
        undefined,
        (status) => statuses.push(status),
      ),
    ).resolves.toBeDefined();
    expect(statuses).toEqual([
      { kind: "preflight", delegation: "available", configuredSlots: 8 },
      { kind: "dispatch", phase: "ranking", planned: 6, started: 3 },
    ]);
  });
});
