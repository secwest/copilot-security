import { describe, expect, test } from "bun:test";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  bundledPluginRoot,
  copilotScannerExecutionEnvironment,
  copilotSecurityCredentialHome,
  copilotSecurityStateDirectory,
  importAmbientAuth,
  prepareCopilotAnalysisWorkspace,
  prepareCopilotScanInventory,
  pluginMetadata,
  resolvePluginPython,
  verifyCopilotScanInventory,
  verifyCopilotAnalysisWorkspaceSnapshot,
  writeCopilotScannerSandboxSettings,
} from "../src/runtime.js";

describe("standalone Copilot runtime", () => {
  test("stages expendable repository and plugin copies without link escapes", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-analysis-input-"));
    const repository = join(root, "repository");
    const plugin = join(root, "plugin");
    const external = join(root, "external");
    let workspace: Awaited<
      ReturnType<typeof prepareCopilotAnalysisWorkspace>
    > | null = null;
    try {
      await Promise.all([
        mkdir(join(repository, "src"), { recursive: true }),
        mkdir(plugin, { recursive: true }),
        mkdir(external, { recursive: true }),
      ]);
      await Promise.all([
        writeFile(join(repository, "src", "app.js"), "export {};\n"),
        writeFile(join(plugin, "plugin.json"), "{}\n"),
        writeFile(join(external, "host-only.txt"), "host-only\n"),
      ]);
      const sourceLink = join(repository, "external-link");
      await symlink(
        external,
        sourceLink,
        process.platform === "win32" ? "junction" : "dir",
      );
      const recordedTarget = await readlink(sourceLink);

      workspace = await prepareCopilotAnalysisWorkspace(repository, plugin);

      expect(
        await readFile(join(workspace.repository, "src", "app.js"), "utf8"),
      ).toBe("export {};\n");
      expect(
        await readFile(join(workspace.pluginRoot, "plugin.json"), "utf8"),
      ).toBe("{}\n");
      expect(
        await lstat(join(workspace.repository, "external-link")).catch(
          () => null,
        ),
      ).toBeNull();
      expect(
        JSON.parse(await readFile(workspace.linkManifest, "utf8")),
      ).toEqual({
        schemaVersion: "1.0",
        entries: [
          {
            tree: "repository",
            path: "external-link",
            target: recordedTarget,
            kind: "symbolic_link",
          },
        ],
      });
    } finally {
      if (workspace !== null) {
        await rm(workspace.root, { recursive: true, force: true });
      }
      await rm(root, { recursive: true, force: true });
    }
  });

  test("stages only explicit repository scopes and omits dependency trees", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-analysis-scopes-"));
    const repository = join(root, "repository");
    const plugin = join(root, "plugin");
    let workspace: Awaited<
      ReturnType<typeof prepareCopilotAnalysisWorkspace>
    > | null = null;
    try {
      await Promise.all([
        mkdir(join(repository, "src"), { recursive: true }),
        mkdir(join(repository, "sdk", "node_modules", "dependency"), {
          recursive: true,
        }),
        mkdir(plugin, { recursive: true }),
      ]);
      await Promise.all([
        writeFile(join(repository, "src", "app.js"), "export {};\n"),
        writeFile(join(repository, "sdk", "index.ts"), "export {};\n"),
        writeFile(
          join(repository, "sdk", "node_modules", "dependency", "index.js"),
          "module.exports = {};\n",
        ),
        writeFile(join(repository, "unrelated.bin"), Buffer.from([0, 1, 2])),
        writeFile(join(plugin, "plugin.json"), "{}\n"),
      ]);

      workspace = await prepareCopilotAnalysisWorkspace(
        repository,
        plugin,
        undefined,
        ["src", "sdk"],
      );

      expect(
        await readFile(join(workspace.repository, "src", "app.js"), "utf8"),
      ).toBe("export {};\n");
      expect(
        await readFile(join(workspace.repository, "sdk", "index.ts"), "utf8"),
      ).toBe("export {};\n");
      expect(
        await lstat(join(workspace.repository, "sdk", "node_modules")).catch(
          () => null,
        ),
      ).toBeNull();
      expect(
        await lstat(join(workspace.repository, "unrelated.bin")).catch(
          () => null,
        ),
      ).toBeNull();
      await expect(
        verifyCopilotAnalysisWorkspaceSnapshot(
          repository,
          workspace.repository,
          ["src/app.js", "sdk/index.ts"],
        ),
      ).resolves.toBeUndefined();
      await writeFile(
        join(repository, "sdk", "index.ts"),
        "export const changed = true;\n",
      );
      await expect(
        verifyCopilotAnalysisWorkspaceSnapshot(
          repository,
          workspace.repository,
          ["src/app.js", "sdk/index.ts"],
        ),
      ).rejects.toThrow(
        "disposable analysis workspace does not match the registered scan target",
      );
    } finally {
      if (workspace !== null) {
        await rm(workspace.root, { recursive: true, force: true });
      }
      await rm(root, { recursive: true, force: true });
    }
  });

  test("generates and seals a host-owned immutable scan inventory", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-host-inventory-"));
    const repository = join(root, "repository");
    const scanDirectory = join(root, "scan");
    try {
      await Promise.all([
        mkdir(join(repository, "src"), { recursive: true }),
        mkdir(join(repository, "node_modules", "dependency"), {
          recursive: true,
        }),
        mkdir(scanDirectory, { recursive: true }),
      ]);
      await Promise.all([
        writeFile(join(repository, "src", "app.js"), "export {}\n"),
        writeFile(
          join(repository, "src", "ignored.bin"),
          Buffer.from([0, 1, 2]),
        ),
        writeFile(join(repository, "SECURITY.md"), "# Test policy\n"),
        writeFile(
          join(repository, "node_modules", "dependency", "SECURITY.md"),
          "# Dependency policy\n",
        ),
      ]);
      const pluginRoot = await bundledPluginRoot();
      const python = await resolvePluginPython({ environment: process.env });
      const snapshot = await prepareCopilotScanInventory({
        python,
        pluginRoot,
        repository,
        scanDirectory,
        target: { kind: "repository", paths: [] },
        environment: process.env,
      });

      expect(snapshot.fileCount).toBe(1);
      const discovery = join(scanDirectory, "artifacts", "02_discovery");
      expect(
        await readFile(join(discovery, "in_scope_files.txt"), "utf8"),
      ).toBe("src/app.js\n");
      expect(
        await readFile(join(discovery, "deep_review_input.jsonl"), "utf8"),
      ).toBe('{"path":"src/app.js","area":"."}\n');
      expect(
        JSON.parse(
          await readFile(
            join(discovery, "security_guidance_paths.json"),
            "utf8",
          ),
        ),
      ).toEqual(["SECURITY.md"]);
      await expect(
        verifyCopilotScanInventory(snapshot),
      ).resolves.toBeUndefined();

      const inventory = join(discovery, "in_scope_files.txt");
      await chmod(inventory, 0o600);
      await writeFile(inventory, "src/other.js\n");
      await expect(verifyCopilotScanInventory(snapshot)).rejects.toThrow(
        "immutable host-generated scan inventory was modified",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("passes only scanner-required state and a constrained tool path", () => {
    const copilot = "C:\\tools\\copilot\\copilot.exe";
    const python = "C:\\tools\\python\\python.exe";
    const git = "C:\\tools\\git\\git.exe";
    const environment = copilotScannerExecutionEnvironment(
      {
        APPDATA: "C:\\Users\\scanner\\AppData\\Roaming",
        COPILOT_HOME: "C:\\scanner-home",
        COPILOT_SECURITY_SCAN_DIR: "C:\\scan",
        GH_TOKEN: "token",
        NODE_OPTIONS: "--require=C:\\untrusted\\inject.js",
        PATH: "C:\\Strawberry\\c\\bin;C:\\untrusted",
        SECRET_FROM_UNRELATED_TOOL: "do-not-inherit",
        SystemRoot: "C:\\Windows",
      },
      { copilot, python, git },
      "win32",
    );

    expect(environment).toMatchObject({
      APPDATA: "C:\\Users\\scanner\\AppData\\Roaming",
      COPILOT_HOME: "C:\\scanner-home",
      COPILOT_SECURITY_SCAN_DIR: "C:\\scan",
      GH_TOKEN: "token",
      PYTHON: python,
      SystemRoot: "C:\\Windows",
    });
    expect(environment["NODE_OPTIONS"]).toBeUndefined();
    expect(environment["SECRET_FROM_UNRELATED_TOOL"]).toBeUndefined();
    expect(environment["PATH"]?.split(";")).toEqual([
      "C:\\tools\\copilot",
      "C:\\tools\\python",
      "C:\\tools\\git",
      "C:\\Windows\\System32",
      "C:\\Windows",
      "C:\\Windows\\System32\\Wbem",
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    ]);
  });

  test("uses target-platform path rules for a constrained POSIX tool path", () => {
    const environment = copilotScannerExecutionEnvironment(
      {
        HOME: "/home/scanner",
        LD_PRELOAD: "/tmp/untrusted.so",
        PATH: "/tmp/untrusted:/usr/bin",
        SECRET_FROM_UNRELATED_TOOL: "do-not-inherit",
      },
      {
        copilot: "/opt/copilot/bin/copilot",
        python: "/opt/python/bin/python3",
        git: "/usr/bin/git",
        tools: ["/opt/tools/bin/rg"],
      },
      "linux",
    );

    expect(environment).toMatchObject({
      HOME: "/home/scanner",
      PYTHON: "/opt/python/bin/python3",
    });
    expect(environment["LD_PRELOAD"]).toBeUndefined();
    expect(environment["SECRET_FROM_UNRELATED_TOOL"]).toBeUndefined();
    expect(environment["PATH"]?.split(":")).toEqual([
      "/opt/copilot/bin",
      "/opt/python/bin",
      "/usr/bin",
      "/opt/tools/bin",
      "/usr/local/bin",
      "/bin",
    ]);
  });

  test("writes a native fail-closed Copilot sandbox policy", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-sandbox-settings-"));
    const home = join(root, "home");
    const repository = join(root, "repository");
    const scanDirectory = join(root, "scan");
    const pluginRoot = join(root, "plugin");
    try {
      await Promise.all(
        [home, repository, scanDirectory, pluginRoot].map(
          async (path) => await mkdir(path, { recursive: true }),
        ),
      );
      await writeFile(
        join(home, "settings.json"),
        JSON.stringify({ logLevel: "all", sandbox: { enabled: false } }),
      );

      await writeCopilotScannerSandboxSettings(home, {
        repository,
        scanDirectory,
        pluginRoot,
      });

      const settings = JSON.parse(
        await readFile(join(home, "settings.json"), "utf8"),
      );
      expect(settings).toMatchObject({
        askUser: false,
        autoUpdate: false,
        includeCoAuthoredBy: false,
        remote: "off",
        remoteExport: false,
        permissions: { disableBypassPermissionsMode: "disable" },
        sandbox: {
          enabled: true,
          addCurrentWorkingDirectory: false,
          allowBypass: false,
          gitAuth: false,
          ghAuth: false,
          userPolicy: {
            filesystem: {
              readwritePaths: [scanDirectory],
              readonlyPaths: [repository, pluginRoot],
              clearPolicyOnExit: true,
            },
            network: {
              allowOutbound: false,
              allowLocalNetwork: false,
            },
          },
        },
      });
      expect(settings).not.toHaveProperty("logLevel");
      expect(settings.sandbox.userPolicy.filesystem.deniedPaths).toContain(
        join(home, "config.json"),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

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
