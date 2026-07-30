import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  copilotModelErrorRecovery,
  COPILOT_SCANNER_SESSION_HOOKS,
  prepareCopilotRuntime,
  resolveCopilotCli,
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
      model: "gpt-5.6-sol",
      reasoningEffort: "xhigh",
      pluginRoot: "plugin",
    };
    expect(options.model).toBe("gpt-5.6-sol");
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
