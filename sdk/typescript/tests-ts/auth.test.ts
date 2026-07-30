import { describe, expect, test } from "bun:test";
import { resolveCopilotCommand } from "../src/runtime.js";

describe("Copilot authentication boundary", () => {
  test("uses the installed Copilot CLI without an embedded model-runtime package", () => {
    const previous = process.env["COPILOT_CLI_PATH"];
    try {
      process.env["COPILOT_CLI_PATH"] = "C:\\tools\\copilot.exe";
      expect(resolveCopilotCommand()).toEqual({
        command: "C:\\tools\\copilot.exe",
        prefixArgs: [],
      });
    } finally {
      if (previous === undefined) {
        delete process.env["COPILOT_CLI_PATH"];
      } else {
        process.env["COPILOT_CLI_PATH"] = previous;
      }
    }
  });
});
