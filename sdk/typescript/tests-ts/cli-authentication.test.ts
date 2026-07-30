import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

describe("CLI authentication", () => {
  test("forwards Copilot's native OAuth login and optional host", async () => {
    let invocation: readonly string[] = [];
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies({
      onCopilot: (args) => {
        invocation = args;
        return 0;
      },
    });

    expect(
      await main(
        ["login", "--host", "https://example.ghe.com"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(invocation).toEqual(["login", "--host", "https://example.ghe.com"]);
  });

  test("warns when an environment token remains authoritative", async () => {
    const stderr = capture();
    const deps = dependencies({
      environment: { GH_TOKEN: "synthetic-token" },
      onCopilot: () => 0,
    });

    expect(await main(["login"], capture().stream, stderr.stream, deps)).toBe(
      0,
    );
    expect(stderr.text()).toContain(
      "scans will continue to use GH_TOKEN until that environment variable is unset",
    );
  });
});
