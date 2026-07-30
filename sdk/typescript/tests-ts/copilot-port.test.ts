import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  resolveCopilotCli,
  type CopilotScannerOptions,
} from "../src/copilot-client.js";
import {
  CopilotSecurity,
  scanAuthentication,
  type ScanAuthentication,
} from "../src/index.js";

const temporaryPaths: string[] = [];

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
    await mkdir(root, { recursive: true });
    const executable = join(root, "copilot.exe");
    await writeFile(executable, "");
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
});
