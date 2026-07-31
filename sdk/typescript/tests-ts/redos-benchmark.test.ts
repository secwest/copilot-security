import { runInNewContext } from "node:vm";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface Registry {
  aliases: string[];
  reserve(alias: string): void;
}

interface Fixture {
  registerAlias(
    request: { body: { alias: unknown } },
    registry: Registry,
  ): {
    status: number;
    body: { alias?: string; error?: string };
  };
}

const VM_TIMEOUT_MS = 100;
const attackAlias = `${"a".repeat(30)}!`;

test("catastrophic alias regex blocks while the bounded linear validator preserves behavior", async () => {
  const vulnerable = await loadFixture("javascript-redos-alias-validation");
  const safe = await loadFixture("javascript-safe-linear-alias-validation");

  expect(() =>
    invokeWithDeadline(vulnerable, attackAlias, createRegistry()),
  ).toThrow("Script execution timed out");

  const safeRegistry = createRegistry();
  expect(invokeWithDeadline(safe, attackAlias, safeRegistry)).toEqual({
    status: 400,
    body: { error: "invalid_alias" },
  });
  expect(safeRegistry.aliases).toEqual([]);

  for (const fixture of [vulnerable, safe]) {
    const registry = createRegistry();
    expect(invokeWithDeadline(fixture, "aaaa", registry)).toEqual({
      status: 201,
      body: { alias: "aaaa" },
    });
    expect(registry.aliases).toEqual(["aaaa"]);
    expect(invokeWithDeadline(fixture, "aa!a", registry)).toEqual({
      status: 400,
      body: { error: "invalid_alias" },
    });
    expect(invokeWithDeadline(fixture, 42, registry)).toEqual({
      status: 400,
      body: { error: "invalid_alias" },
    });
  }

  expect(invokeWithDeadline(safe, "a".repeat(65), createRegistry())).toEqual({
    status: 400,
    body: { error: "invalid_alias" },
  });
});

function createRegistry(): Registry {
  const aliases: string[] = [];
  return {
    aliases,
    reserve(alias) {
      aliases.push(alias);
    },
  };
}

function invokeWithDeadline(
  fixture: Fixture,
  alias: unknown,
  registry: Registry,
) {
  return runInNewContext(
    "registerAlias(request, registry)",
    {
      registerAlias: fixture.registerAlias,
      registry,
      request: { body: { alias } },
    },
    { timeout: VM_TIMEOUT_MS },
  );
}

async function loadFixture(fixture: string): Promise<Fixture> {
  const source = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
    "alias.js",
  );
  return (await import(pathToFileURL(source).href)) as Fixture;
}
