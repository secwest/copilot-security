import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  bundledPluginRoot,
  copilotSecurityCredentialHome,
  copilotSecurityStateDirectory,
  importAmbientAuth,
  pluginMetadata,
} from "../src/runtime.js";

describe("standalone Copilot runtime", () => {
  test("uses a scanner-owned state and runtime namespace", () => {
    const state = copilotSecurityStateDirectory({
      COPILOT_HOME: join("C:\\", "users", "scanner", ".copilot"),
    });
    expect(state).toEndWith(".copilot-security");
    expect(state).not.toContain(join(".copilot", "state", "plugins"));
    expect(
      copilotSecurityCredentialHome({ COPILOT_SECURITY_HOME: state }),
    ).toBe(join(state, "copilot-security-home"));
  });

  test("loads the root Copilot plugin manifest", async () => {
    const root = await bundledPluginRoot();
    expect(await pluginMetadata(root)).toMatchObject({
      name: "copilot-security",
      version: "0.1.14",
    });
  });

  test("imports only ambient Copilot account selection into an isolated home", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-account-import-"));
    const ambient = join(root, "ambient");
    const isolated = join(root, "isolated");
    try {
      await mkdir(ambient, { recursive: true });
      await mkdir(isolated, { recursive: true });
      await writeFile(
        join(ambient, "config.json"),
        [
          "// managed",
          JSON.stringify({
            loggedInUsers: [
              {
                host: "https://github.com",
                login: "dragosruiu_microsoft",
              },
            ],
            lastLoggedInUser: {
              host: "https://github.com",
              login: "dragosruiu_microsoft",
            },
            staff: true,
            trustedFolders: ["C:\\private"],
            expAssignmentsCache: { secretState: true },
          }),
        ].join("\n"),
      );
      await writeFile(
        join(isolated, "config.json"),
        JSON.stringify({ firstLaunchAt: "2026-07-30T00:00:00.000Z" }),
      );

      expect(await importAmbientAuth(ambient, isolated)).toBeTrue();
      const importedText = await readFile(
        join(isolated, "config.json"),
        "utf8",
      );
      const imported = JSON.parse(
        importedText.slice(importedText.indexOf("{")),
      );
      expect(imported).toEqual({
        firstLaunchAt: "2026-07-30T00:00:00.000Z",
        loggedInUsers: [
          {
            host: "https://github.com",
            login: "dragosruiu_microsoft",
          },
        ],
        lastLoggedInUser: {
          host: "https://github.com",
          login: "dragosruiu_microsoft",
        },
      });
      expect(importedText).not.toContain("private");
      expect(importedText).not.toContain("secretState");
      expect(importedText).not.toContain('"staff"');
      expect(importedText).not.toContain("token");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("preserves an account explicitly selected in the scanner home", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-account-preserve-"));
    const ambient = join(root, "ambient");
    const isolated = join(root, "isolated");
    try {
      await mkdir(ambient, { recursive: true });
      await mkdir(isolated, { recursive: true });
      await writeFile(
        join(ambient, "config.json"),
        JSON.stringify({
          lastLoggedInUser: {
            host: "https://github.com",
            login: "ambient-account",
          },
        }),
      );
      const selected = {
        loggedInUsers: [
          { host: "https://github.example.test", login: "scanner-account" },
        ],
        lastLoggedInUser: {
          host: "https://github.example.test",
          login: "scanner-account",
        },
      };
      await writeFile(join(isolated, "config.json"), JSON.stringify(selected));

      expect(await importAmbientAuth(ambient, isolated)).toBeTrue();
      const preserved = JSON.parse(
        await readFile(join(isolated, "config.json"), "utf8"),
      );
      expect(preserved).toEqual(selected);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
