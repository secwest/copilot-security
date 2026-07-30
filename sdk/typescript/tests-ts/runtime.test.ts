import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  bundledPluginRoot,
  copilotSecurityCredentialHome,
  copilotSecurityStateDirectory,
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
});
