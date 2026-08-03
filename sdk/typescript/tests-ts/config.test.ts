import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { parse } from "smol-toml";
import { scanRuntimeCopilotConfig } from "../src/api.js";
import {
  ConfigurationError,
  DEFAULT_COPILOT_CONFIG,
  type JsonObject,
  mergedCopilotConfig,
  writeCopilotConfig,
} from "../src/index.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "copilot-security-config-"));
  temporaryDirectories.push(path);
  return path;
}

describe("Copilot configuration", () => {
  test("lets Copilot honor native and managed credential storage", async () => {
    expect(DEFAULT_COPILOT_CONFIG["cli_auth_credentials_store"]).toBe("auto");
    expect((await mergedCopilotConfig({}))["cli_auth_credentials_store"]).toBe(
      "auto",
    );
  });

  test("deep-merges native multi-agent v2 defaults", async () => {
    const merged = await mergedCopilotConfig({
      copilotOverrides: {
        features: { multi_agent_v2: { max_concurrent_threads_per_session: 4 } },
        model_reasoning_effort: "high",
        windows: { sandbox: "elevated" },
      },
    });
    expect(merged["features"]).toEqual({
      plugins: true,
      goals: true,
      multi_agent_v2: {
        enabled: true,
        max_concurrent_threads_per_session: 4,
      },
    });
    expect(merged["agents"]).toBeUndefined();
    expect(merged["model"]).toBe("auto");
    expect(merged["model_reasoning_effort"]).toBe("high");
    expect(merged["windows"]).toEqual({ sandbox: "elevated" });
  });

  test("preserves legacy elevated Windows sandbox overrides", async () => {
    const merged = await mergedCopilotConfig({
      copilotOverrides: {
        features: { elevated_windows_sandbox: true },
      },
    });

    expect(merged).toMatchObject({
      features: { elevated_windows_sandbox: true },
      windows: { sandbox: "elevated" },
    });
  });

  test("projects legacy elevated Windows overrides into selected profiles", async () => {
    const merged = await mergedCopilotConfig({
      copilotOverrides: {
        profile: "elevated",
        profiles: {
          elevated: {
            features: { elevated_windows_sandbox: true },
          },
        },
      },
    });

    expect(merged).toMatchObject({
      windows: { sandbox: "unelevated" },
      profiles: {
        elevated: {
          features: { elevated_windows_sandbox: true },
          windows: { sandbox: "elevated" },
        },
      },
    });
  });

  test("allows selected profiles to override root elevated sandbox defaults", async () => {
    const merged = await mergedCopilotConfig({
      copilotOverrides: {
        features: { elevated_windows_sandbox: true },
        profile: "restricted",
        profiles: {
          restricted: {
            features: { elevated_windows_sandbox: false },
          },
        },
      },
    });

    expect(merged).toMatchObject({
      windows: { sandbox: "elevated" },
      profiles: {
        restricted: {
          features: { elevated_windows_sandbox: false },
          windows: { sandbox: "unelevated" },
        },
      },
    });
  });

  test("gives profile-local Windows sandbox overrides precedence", async () => {
    const merged = await mergedCopilotConfig({
      copilotOverrides: {
        profile: "restricted",
        profiles: {
          restricted: {
            features: { elevated_windows_sandbox: true },
            windows: { sandbox: "unelevated" },
          },
        },
      },
    });

    expect(merged).toMatchObject({
      profiles: {
        restricted: {
          features: { elevated_windows_sandbox: true },
          windows: { sandbox: "unelevated" },
        },
      },
    });
  });

  test("gives explicit Windows sandbox overrides precedence", async () => {
    const merged = await mergedCopilotConfig({
      copilotOverrides: {
        features: { elevated_windows_sandbox: true },
        windows: { sandbox: "unelevated" },
      },
    });

    expect(merged).toMatchObject({
      features: { elevated_windows_sandbox: true },
      windows: { sandbox: "unelevated" },
    });
  });

  test("retains the Windows sandbox in the hardened scan profile", async () => {
    const stateDirectory = join(tmpdir(), "copilot-security-windows-state");
    const merged = await mergedCopilotConfig({});

    expect(scanRuntimeCopilotConfig(merged, stateDirectory)).toMatchObject({
      windows: { sandbox: "unelevated" },
      default_permissions: "copilot_security_scan",
      permissions: {
        copilot_security_scan: {
          filesystem: {
            ":root": "read",
            ":workspace_roots": "write",
            [stateDirectory]: "write",
          },
        },
      },
    });
  });

  test("writes deterministic scanner sandbox settings", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    await writeCopilotConfig(path, await mergedCopilotConfig({}));

    expect(parse(await readFile(path, "utf8"))).toMatchObject({
      windows: { sandbox: "unelevated" },
    });
  });

  test("writes selected scanner profile settings", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    const config = await mergedCopilotConfig({
      copilotOverrides: {
        profile: "elevated",
        profiles: {
          elevated: {
            features: { elevated_windows_sandbox: true },
          },
        },
      },
    });
    const nativeConfig = structuredClone(config);
    delete nativeConfig["profile"];
    delete nativeConfig["profiles"];
    const profileConfig = (config["profiles"] as JsonObject)[
      "elevated"
    ] as JsonObject;
    const profilePath = join(root, "elevated.config.toml");
    await writeCopilotConfig(path, nativeConfig);
    await writeCopilotConfig(profilePath, profileConfig);

    expect(parse(await readFile(path, "utf8"))).toMatchObject({
      windows: { sandbox: "unelevated" },
    });
    expect(parse(await readFile(profilePath, "utf8"))).toMatchObject({
      features: { elevated_windows_sandbox: true },
      windows: { sandbox: "elevated" },
    });
  });

  test("rejects prototype-bearing override keys", async () => {
    for (const key of ["__proto__", "constructor", "prototype"]) {
      await expect(
        mergedCopilotConfig({
          copilotOverrides: JSON.parse(
            `{"features":{"custom":[{"${key}":{"polluted":true}}]}}`,
          ),
        }),
      ).rejects.toThrow(`Invalid Copilot override key: ${key}`);
    }
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  test("rejects non-object overrides with a configuration error", async () => {
    for (const copilotOverrides of [null, [], false, 1, "invalid"]) {
      await expect(
        mergedCopilotConfig({ copilotOverrides } as never),
      ).rejects.toThrow("copilotOverrides must be an object");
    }
  });

  test("keeps exported default configuration deeply immutable", async () => {
    expect(Object.isFrozen(DEFAULT_COPILOT_CONFIG)).toBe(true);
    expect(Object.isFrozen(DEFAULT_COPILOT_CONFIG["features"])).toBe(true);
    expect(Object.isFrozen(DEFAULT_COPILOT_CONFIG["windows"])).toBe(true);
    expect(
      Object.isFrozen(
        (DEFAULT_COPILOT_CONFIG["features"] as Record<string, unknown>)[
          "multi_agent_v2"
        ],
      ),
    ).toBe(true);
    expect(() => {
      (DEFAULT_COPILOT_CONFIG["features"] as Record<string, unknown>)["goals"] =
        false;
    }).toThrow();
    expect((await mergedCopilotConfig({}))["features"]).toMatchObject({
      goals: true,
      multi_agent_v2: {
        enabled: true,
        max_concurrent_threads_per_session: 9,
      },
    });
    expect(await mergedCopilotConfig({})).toMatchObject({
      model: "auto",
      model_reasoning_effort: "xhigh",
      windows: {
        sandbox: "unelevated",
      },
    });
  });

  test("rejects owned plugin keys and incompatible v2 overrides", async () => {
    await expect(
      mergedCopilotConfig({ copilotOverrides: { features: false } }),
    ).rejects.toThrow("features must be a TOML table");
    await expect(
      mergedCopilotConfig({
        copilotOverrides: { features: { plugins: false } },
      }),
    ).rejects.toThrow(ConfigurationError);
    await expect(
      mergedCopilotConfig({ copilotOverrides: { agents: { max_threads: 2 } } }),
    ).rejects.toThrow("legacy v1");
    await expect(
      mergedCopilotConfig({
        copilotOverrides: { features: { multi_agent_v2: { enabled: false } } },
      }),
    ).rejects.toThrow("cannot be disabled");

    await expect(
      mergedCopilotConfig({
        copilotOverrides: {
          profile: "disabled",
          profiles: { disabled: { features: { plugins: false } } },
        },
      }),
    ).rejects.toThrow("owns plugin loading configuration");
    await expect(
      mergedCopilotConfig({
        copilotOverrides: {
          profile: "disabled",
          profiles: {
            disabled: {
              features: { multi_agent_v2: { enabled: false } },
            },
          },
        },
      }),
    ).rejects.toThrow("cannot be disabled");
    await expect(
      mergedCopilotConfig({
        copilotOverrides: {
          profiles: { legacy: { agents: { max_threads: 2 } } },
        },
      }),
    ).rejects.toThrow("legacy v1");
    await expect(
      mergedCopilotConfig({
        copilotOverrides: {
          profiles: {
            deep: {
              features: {
                multi_agent_v2: {
                  max_concurrent_threads_per_session: 5,
                },
              },
            },
          },
        },
      }),
    ).resolves.toBeDefined();
  });

  test("writes deterministic TOML atomically with restrictive permissions", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "home", "config.toml");
    await writeCopilotConfig(path, {
      features: { plugins: true, goals: true },
      agents: { max_threads: 12 },
      model_reasoning_effort: "high",
    });
    const text = await readFile(path, "utf8");
    expect(parse(text)).toEqual({
      features: { plugins: true, goals: true },
      agents: { max_threads: 12 },
      model_reasoning_effort: "high",
    });
    if (process.platform !== "win32") {
      expect((await stat(path)).mode & 0o777).toBe(0o600);
    }
  });

  test("serializes numeric TOML overrides", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    await writeCopilotConfig(path, {
      max_safe: Number.MAX_SAFE_INTEGER,
      fractional: 1.5,
      exponent: 1e-7,
    });
    expect(parse(await readFile(path, "utf8"))).toEqual({
      max_safe: Number.MAX_SAFE_INTEGER,
      fractional: 1.5,
      exponent: 1e-7,
    });
  });

  test.skipIf(process.platform === "win32")(
    "keeps atomic TOML output readable under a restrictive umask",
    async () => {
      const root = await temporaryDirectory();
      const path = join(root, "config.toml");
      const previous = process.umask(0o777);
      try {
        await writeCopilotConfig(path, { model: "test" });
      } finally {
        process.umask(previous);
      }
      expect((await stat(path)).mode & 0o777).toBe(0o600);
      expect(await readFile(path, "utf8")).toContain('model = "test"');
    },
  );

  test("serializes nested inline tables in TOML arrays", async () => {
    const root = await temporaryDirectory();
    const path = join(root, "config.toml");
    const hooks = {
      SessionStart: [
        {
          matcher: "*",
          hooks: [{ type: "command", command: "echo hi" }],
        },
      ],
    };
    await writeCopilotConfig(path, { hooks });
    expect(parse(await readFile(path, "utf8"))).toEqual({ hooks });
  });
});
