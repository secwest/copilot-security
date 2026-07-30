import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface TestDirectory {
  queries: Array<{
    expression: string;
    variables: Record<string, string>;
  }>;
  selectOne(
    expression: string,
    variables?: Record<string, string>,
  ): Record<string, string> | null;
}

test("XPath benchmark proves boolean-predicate authentication bypass and variable binding", async () => {
  const vulnerable = await loadFixture(
    "javascript-xpath-authentication-injection",
  );
  const safe = await loadFixture("javascript-safe-xpath-authentication");
  const vulnerableDirectory = vulnerable.createDirectory();
  const safeDirectory = safe.createDirectory();
  const injectedVerifier = "' or role/text()='administrator";
  const attacker = {
    username: "nobody",
    passwordVerifier: injectedVerifier,
  };

  expect(vulnerable.createSession(vulnerableDirectory, attacker)).toEqual({
    subject: "administrator",
    role: "administrator",
  });
  expect(vulnerableDirectory.queries.at(-1)).toEqual({
    expression:
      "/users/user[username/text()='nobody' and passwordVerifier/text()='' or role/text()='administrator']",
    variables: {},
  });
  const vulnerableQueryCount = vulnerableDirectory.queries.length;
  expect(
    vulnerable.createSession(vulnerableDirectory, {
      username: "viewer' or role/text()='administrator",
      passwordVerifier: "wrong-proof",
    }),
  ).toBeNull();
  expect(vulnerableDirectory.queries).toHaveLength(vulnerableQueryCount);

  expect(safe.createSession(safeDirectory, attacker)).toBeNull();
  expect(safeDirectory.queries.at(-1)).toEqual({
    expression:
      "/users/user[username/text()=$username and passwordVerifier/text()=$passwordVerifier]",
    variables: {
      username: "nobody",
      passwordVerifier: injectedVerifier,
    },
  });

  expect(
    safe.createSession(safeDirectory, {
      username: "viewer",
      passwordVerifier: "wrong-proof",
    }),
  ).toBeNull();
  expect(
    safe.createSession(safeDirectory, {
      username: "viewer",
      passwordVerifier: "viewer-proof",
    }),
  ).toEqual({
    subject: "viewer",
    role: "viewer",
  });
  expect(
    safe.createSession(safeDirectory, {
      username: "administrator",
      passwordVerifier: "admin-proof",
    }),
  ).toEqual({
    subject: "administrator",
    role: "administrator",
  });

  const syntaxPayload = `" or username/text()=$username or 'x'='x`;
  expect(
    safe.createSession(safeDirectory, {
      username: "viewer",
      passwordVerifier: syntaxPayload,
    }),
  ).toBeNull();
  expect(safeDirectory.queries.at(-1)?.variables["passwordVerifier"]).toBe(
    syntaxPayload,
  );
});

async function loadFixture(fixture: string): Promise<{
  createDirectory: () => TestDirectory;
  createSession: (
    directory: TestDirectory,
    credentials: { passwordVerifier: string; username: string },
  ) => unknown;
}> {
  const sourceRoot = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
  );
  const session = (await import(
    pathToFileURL(resolve(sourceRoot, "session.js")).href
  )) as Record<string, unknown>;
  const directory = (await import(
    pathToFileURL(resolve(sourceRoot, "directory.js")).href
  )) as Record<string, unknown>;
  expect(typeof session["createSession"]).toBe("function");
  expect(typeof directory["createXmlAccountDirectory"]).toBe("function");
  return {
    createDirectory: directory[
      "createXmlAccountDirectory"
    ] as () => TestDirectory,
    createSession: session["createSession"] as (
      directory: TestDirectory,
      credentials: { passwordVerifier: string; username: string },
    ) => unknown,
  };
}
