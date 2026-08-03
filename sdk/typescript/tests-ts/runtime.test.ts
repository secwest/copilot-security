import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import {
  bundledPluginRoot,
  cleanupSdkDirectory,
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

function git(repository: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: repository,
    encoding: "utf8",
  }).trim();
}

describe("standalone Copilot runtime", () => {
  test("removes nested SDK temporary directories idempotently", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-sdk-cleanup-"));
    await mkdir(join(root, "nested"), { recursive: true });
    await writeFile(join(root, "nested", "artifact.json"), "{}\n");

    await cleanupSdkDirectory(root);
    expect(await lstat(root).catch(() => null)).toBeNull();
    await expect(cleanupSdkDirectory(root)).resolves.toBeUndefined();
  });

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
      expect(workspace.linkManifest).toBe(
        join(workspace.pluginRoot, ".copilot-security-runtime", "links.json"),
      );
      expect(
        relative(workspace.repository, workspace.linkManifest).startsWith(".."),
      ).toBe(true);
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
        mkdir(join(repository, "src", "main", "java", "example"), {
          recursive: true,
        }),
        mkdir(join(repository, "examples"), { recursive: true }),
        mkdir(join(repository, "bin", "Release", "net8.0"), {
          recursive: true,
        }),
        mkdir(join(repository, "node_modules", "dependency"), {
          recursive: true,
        }),
        mkdir(join(repository, "obj", "Release", "net8.0"), {
          recursive: true,
        }),
        mkdir(scanDirectory, { recursive: true }),
      ]);
      await Promise.all([
        writeFile(join(repository, "src", "app.js"), "export {}\n"),
        writeFile(
          join(
            repository,
            "src",
            "main",
            "java",
            "example",
            "Application.java",
          ),
          "package example; public final class Application {}\n",
        ),
        writeFile(
          join(repository, "examples", "excluded.js"),
          "throw new Error('example-only');\n",
        ),
        writeFile(
          join(repository, "bin", "Release", "net8.0", "generated.cs"),
          'Process.Start(request.Query["command"]);\n',
        ),
        writeFile(
          join(repository, "obj", "Release", "net8.0", "generated.cs"),
          'client.GetAsync(request.Query["target"]);\n',
        ),
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

      expect(snapshot.fileCount).toBe(2);
      const discovery = join(scanDirectory, "artifacts", "02_discovery");
      expect(
        await readFile(join(discovery, "in_scope_files.txt"), "utf8"),
      ).toBe("src/app.js\nsrc/main/java/example/Application.java\n");
      expect(
        await readFile(join(discovery, "deep_review_input.jsonl"), "utf8"),
      ).toBe(
        '{"path":"src/app.js","area":"."}\n' +
          '{"path":"src/main/java/example/Application.java","area":"."}\n',
      );
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

  test("generates working-tree inventory from the authoritative Git repository", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-diff-inventory-"));
    const repository = join(root, "repository");
    const plugin = join(root, "plugin");
    const scanDirectory = join(root, "scan");
    let workspace: Awaited<
      ReturnType<typeof prepareCopilotAnalysisWorkspace>
    > | null = null;
    try {
      await Promise.all([
        mkdir(join(repository, "src"), { recursive: true }),
        mkdir(plugin, { recursive: true }),
        mkdir(scanDirectory, { recursive: true }),
      ]);
      await Promise.all([
        writeFile(join(repository, "src", "app.ts"), "export const v = 1;\n"),
        writeFile(join(plugin, "plugin.json"), "{}\n"),
      ]);
      git(repository, "init");
      git(repository, "config", "user.name", "Scanner Test");
      git(repository, "config", "user.email", "scanner-test@example.invalid");
      git(repository, "add", "src/app.ts");
      git(repository, "commit", "-m", "base");
      const base = git(repository, "rev-parse", "HEAD");
      await Promise.all([
        writeFile(join(repository, "src", "app.ts"), "export const v = 2;\n"),
        writeFile(
          join(repository, "src", "new.ts"),
          "export const added = true;\n",
        ),
      ]);
      git(repository, "add", "src/new.ts");

      workspace = await prepareCopilotAnalysisWorkspace(repository, plugin);
      const snapshot = await prepareCopilotScanInventory({
        python: await resolvePluginPython({ environment: process.env }),
        pluginRoot: await bundledPluginRoot(),
        repository: workspace.repository,
        diffRepository: repository,
        scanDirectory,
        target: { kind: "working_tree", paths: [], base, head: base },
        environment: process.env,
      });

      expect(snapshot.repositoryPaths).toEqual(["src/app.ts", "src/new.ts"]);
      await expect(
        verifyCopilotAnalysisWorkspaceSnapshot(
          repository,
          workspace.repository,
          snapshot.repositoryPaths,
        ),
      ).resolves.toBeUndefined();
    } finally {
      if (workspace !== null) {
        await rm(workspace.root, { recursive: true, force: true });
      }
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
      PYTHON: python,
      SystemRoot: "C:\\Windows",
    });
    expect(environment["GH_TOKEN"]).toBeUndefined();
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

  test("keeps concurrent native sandbox policy replacement valid", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-sandbox-concurrent-"));
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

      await Promise.all(
        Array.from(
          { length: 16 },
          async () =>
            await writeCopilotScannerSandboxSettings(home, {
              repository,
              scanDirectory,
              pluginRoot,
            }),
        ),
      );

      const settings = JSON.parse(
        await readFile(join(home, "settings.json"), "utf8"),
      );
      expect(settings.sandbox.userPolicy.filesystem).toMatchObject({
        readwritePaths: [scanDirectory],
        readonlyPaths: [repository, pluginRoot],
      });
      expect(
        (await readdir(home)).filter((name) => name.endsWith(".tmp")),
      ).toEqual([]);
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
