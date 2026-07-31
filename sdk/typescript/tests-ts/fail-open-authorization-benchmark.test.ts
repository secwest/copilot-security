import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface AccessRequest {
  action: string;
  resourceId: string;
  subjectId: string;
}

interface Authorizer {
  checkAccess(request: AccessRequest): Promise<unknown>;
}

interface Vault {
  exports: string[];
  exportSigningKeys(resourceId: string): Promise<string[]>;
}

interface Fixture {
  exportSigningKeys(
    request: {
      params: { keyringId: string };
      session: { accountId: string };
      log: { warn(details: unknown, message: string): void };
    },
    authorizer: Authorizer,
    vault: Vault,
  ): Promise<{
    status: number;
    body: { error?: string; keys?: string[] };
  }>;
}

test("policy exceptions fail open only in the vulnerable signing-key export", async () => {
  const vulnerable = await loadFixture(
    "javascript-fail-open-policy-authorization",
  );
  const safe = await loadFixture(
    "javascript-safe-fail-closed-policy-authorization",
  );
  const checks: AccessRequest[] = [];
  const authorizer: Authorizer = {
    async checkAccess(request) {
      checks.push({ ...request });
      if (request.resourceId === "root-signing") {
        throw new Error("policy service unavailable");
      }
      if (request.resourceId === "malformed-decision") return "allow";
      return (
        request.subjectId === "release-maintainer" &&
        request.resourceId === "release-signing"
      );
    },
  };

  const vulnerableVault = createVault();
  expect(
    await invoke(
      vulnerable,
      authorizer,
      vulnerableVault,
      "ordinary-developer",
      "root-signing",
    ),
  ).toEqual({
    status: 200,
    body: { keys: ["root-signing-private-key"] },
  });
  expect(vulnerableVault.exports).toEqual(["root-signing"]);

  const safeVault = createVault();
  expect(
    await invoke(
      safe,
      authorizer,
      safeVault,
      "ordinary-developer",
      "root-signing",
    ),
  ).toEqual({
    status: 503,
    body: { error: "authorization_unavailable" },
  });
  expect(safeVault.exports).toEqual([]);

  for (const fixture of [vulnerable, safe]) {
    const deniedVault = createVault();
    expect(
      await invoke(
        fixture,
        authorizer,
        deniedVault,
        "ordinary-developer",
        "release-signing",
      ),
    ).toEqual({
      status: 403,
      body: { error: "forbidden" },
    });
    expect(deniedVault.exports).toEqual([]);

    const allowedVault = createVault();
    expect(
      await invoke(
        fixture,
        authorizer,
        allowedVault,
        "release-maintainer",
        "release-signing",
      ),
    ).toEqual({
      status: 200,
      body: { keys: ["release-signing-private-key"] },
    });
    expect(allowedVault.exports).toEqual(["release-signing"]);
  }

  const vulnerableMalformedVault = createVault();
  expect(
    await invoke(
      vulnerable,
      authorizer,
      vulnerableMalformedVault,
      "ordinary-developer",
      "malformed-decision",
    ),
  ).toEqual({
    status: 200,
    body: { keys: ["malformed-decision-private-key"] },
  });

  const safeMalformedVault = createVault();
  expect(
    await invoke(
      safe,
      authorizer,
      safeMalformedVault,
      "ordinary-developer",
      "malformed-decision",
    ),
  ).toEqual({
    status: 403,
    body: { error: "forbidden" },
  });
  expect(safeMalformedVault.exports).toEqual([]);

  expect(checks).toContainEqual({
    action: "export-signing-keys",
    resourceId: "root-signing",
    subjectId: "ordinary-developer",
  });
});

function createVault(): Vault {
  const exports: string[] = [];
  return {
    exports,
    async exportSigningKeys(resourceId) {
      exports.push(resourceId);
      return [`${resourceId}-private-key`];
    },
  };
}

async function invoke(
  fixture: Fixture,
  authorizer: Authorizer,
  vault: Vault,
  subjectId: string,
  resourceId: string,
) {
  return fixture.exportSigningKeys(
    {
      params: { keyringId: resourceId },
      session: { accountId: subjectId },
      log: { warn() {} },
    },
    authorizer,
    vault,
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
    "export.js",
  );
  return (await import(pathToFileURL(source).href)) as Fixture;
}
