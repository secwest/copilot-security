import { describe, expect, test } from "bun:test";
import {
  CopilotSecurity,
  AuthenticationRequiredError,
  scanAuthentication,
} from "../src/index.js";

describe("Copilot Security API", () => {
  test("exports only the Copilot runtime identity", () => {
    const scanner = new CopilotSecurity();
    expect(scanner.metadata).toEqual({
      sdk: "@github/copilot-sdk",
      sdkVersion: "1.0.7",
      executable: "github/copilot-cli",
      executableVersion: "system",
    });
  });

  test("selects tokens in Copilot CLI precedence order", () => {
    expect(
      scanAuthentication({
        GITHUB_TOKEN: "third",
        GH_TOKEN: "second",
        COPILOT_GITHUB_TOKEN: "first",
      }),
    ).toEqual({
      method: "github_token",
      source: "COPILOT_GITHUB_TOKEN",
      verified: false,
    });
    expect(scanAuthentication({}, "github")).toEqual({
      method: "stored_credentials",
      verified: false,
    });
    expect(() => scanAuthentication({}, "token")).toThrow(
      AuthenticationRequiredError,
    );
  });

  test("does not accept authentication modes owned by another scanner", () => {
    expect(() => scanAuthentication({}, "unsupported" as never)).toThrow(
      "Authentication mode must be auto, github, or token",
    );
  });
});
