import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface Fixture {
  createApiKeyStore(
    records: Array<{ accountId: string; keys: string[] }>,
  ): ApiKeyStore;
  createSessionStore(
    records: Array<{ accountId: string; id: string; role: string }>,
  ): SessionStore;
  getApiKeys(
    request: {
      cookies: Record<string, string | undefined>;
      headers: Record<string, string | undefined>;
    },
    response: ResponseRecorder,
    sessions: SessionStore,
    apiKeys: ApiKeyStore,
  ): ResponseRecorder;
  sessionCookie: {
    httpOnly: boolean;
    sameSite: string;
    secure: boolean;
  };
}

interface ApiKeyStore {
  forAccount(accountId: string): string[];
}

interface SessionStore {
  get(
    sessionId: string,
  ): { accountId: string; id: string; role: string } | null;
}

interface ResponseRecorder {
  body: unknown;
  headers: Map<string, string>;
  statusCode: number | null;
  json(body: unknown): ResponseRecorder;
  setHeader(name: string, value: string): ResponseRecorder;
  status(code: number): ResponseRecorder;
}

const apiOrigin = "https://api.example.test";
const trustedPortalOrigin = "https://portal.example.test";
const attackerOrigin = "https://capture.example.test";
const victimSessionId = "victim-session";
const victimAccountId = "victim-account";
const victimApiKey = "fixture-victim-control-plane-key";

test("credentialed CORS reflection exposes victim keys while an exact origin allowlist prevents reads", async () => {
  const vulnerable = await loadFixture(
    "javascript-credentialed-cors-exfiltration",
  );
  const safe = await loadFixture("javascript-safe-cors-allowlist");

  expect(vulnerable.sessionCookie).toEqual({
    httpOnly: true,
    sameSite: "lax",
    secure: true,
  });
  expect(siteFor(attackerOrigin)).toBe(siteFor(apiOrigin));

  const vulnerableResult = credentialedBrowserFetch(
    vulnerable,
    attackerOrigin,
    victimSessionId,
  );
  expect(vulnerableResult.response.statusCode).toBe(200);
  expect(
    vulnerableResult.response.headers.get("access-control-allow-origin"),
  ).toBe(attackerOrigin);
  expect(
    vulnerableResult.response.headers.get("access-control-allow-credentials"),
  ).toBe("true");
  expect(vulnerableResult.browserCanRead).toBe(true);
  expect(vulnerableResult.exposedBody).toEqual({
    accountId: victimAccountId,
    keys: [victimApiKey],
  });
  expect(attackerCanUseKey(vulnerableResult.exposedBody)).toBe(true);

  const safeAttackerResult = credentialedBrowserFetch(
    safe,
    attackerOrigin,
    victimSessionId,
  );
  expect(safeAttackerResult.response.statusCode).toBe(403);
  expect(
    safeAttackerResult.response.headers.has("access-control-allow-origin"),
  ).toBe(false);
  expect(safeAttackerResult.browserCanRead).toBe(false);
  expect(safeAttackerResult.exposedBody).toBeNull();
  expect(attackerCanUseKey(safeAttackerResult.exposedBody)).toBe(false);

  for (const rejectedOrigin of [
    "null",
    "https://portal.example.test.attacker.test",
    "http://portal.example.test",
    "https://portal.example.test:444",
  ]) {
    const rejected = credentialedBrowserFetch(
      safe,
      rejectedOrigin,
      victimSessionId,
      true,
    );
    expect(rejected.response.statusCode).toBe(403);
    expect(rejected.response.headers.has("access-control-allow-origin")).toBe(
      false,
    );
  }

  const safeTrustedResult = credentialedBrowserFetch(
    safe,
    trustedPortalOrigin,
    victimSessionId,
  );
  expect(safeTrustedResult.response.statusCode).toBe(200);
  expect(
    safeTrustedResult.response.headers.get("access-control-allow-origin"),
  ).toBe(trustedPortalOrigin);
  expect(
    safeTrustedResult.response.headers.get("access-control-allow-credentials"),
  ).toBe("true");
  expect(safeTrustedResult.browserCanRead).toBe(true);
  expect(safeTrustedResult.exposedBody).toEqual({
    accountId: victimAccountId,
    keys: [victimApiKey],
  });

  const unauthenticated = credentialedBrowserFetch(
    vulnerable,
    attackerOrigin,
    "unknown-session",
  );
  expect(unauthenticated.response.statusCode).toBe(401);
  expect(unauthenticated.exposedBody).toEqual({ error: "unauthorized" });
  expect(attackerCanUseKey(unauthenticated.exposedBody)).toBe(false);
});

function attackerCanUseKey(body: unknown): boolean {
  if (typeof body !== "object" || body === null || !("keys" in body)) {
    return false;
  }
  return (
    Array.isArray(body.keys) && body.keys.some((key) => key === victimApiKey)
  );
}

function credentialedBrowserFetch(
  fixture: Fixture,
  origin: string,
  sessionId: string,
  forceCookie = false,
): {
  browserCanRead: boolean;
  exposedBody: unknown | null;
  response: ResponseRecorder;
} {
  const requestCarriesCookie =
    forceCookie ||
    (fixture.sessionCookie.secure &&
      fixture.sessionCookie.sameSite === "lax" &&
      siteFor(origin) === siteFor(apiOrigin));
  const response = responseRecorder();
  fixture.getApiKeys(
    {
      cookies: { sid: requestCarriesCookie ? sessionId : undefined },
      headers: { origin },
    },
    response,
    fixture.createSessionStore([
      {
        accountId: victimAccountId,
        id: victimSessionId,
        role: "administrator",
      },
    ]),
    fixture.createApiKeyStore([
      { accountId: victimAccountId, keys: [victimApiKey] },
    ]),
  );
  const browserCanRead =
    response.headers.get("access-control-allow-origin") === origin &&
    response.headers.get("access-control-allow-credentials") === "true";
  return {
    browserCanRead,
    exposedBody: browserCanRead ? response.body : null,
    response,
  };
}

function responseRecorder(): ResponseRecorder {
  return {
    body: null,
    headers: new Map<string, string>(),
    statusCode: null,
    json(body) {
      this.body = body;
      return this;
    },
    setHeader(name, value) {
      this.headers.set(name.toLowerCase(), value);
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
  };
}

function siteFor(origin: string): string {
  if (origin === "null") return "opaque";
  const url = new URL(origin);
  const registrableDomain = url.hostname.split(".").slice(-2).join(".");
  return `${url.protocol}//${registrableDomain}`;
}

async function loadFixture(fixture: string): Promise<Fixture> {
  const sourceRoot = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
  );
  const apiKeys = (await import(
    pathToFileURL(resolve(sourceRoot, "api-keys.js")).href
  )) as Record<string, unknown>;
  const keysRoute = (await import(
    pathToFileURL(resolve(sourceRoot, "keys-route.js")).href
  )) as Record<string, unknown>;
  const sessions = (await import(
    pathToFileURL(resolve(sourceRoot, "sessions.js")).href
  )) as Record<string, unknown>;
  return {
    createApiKeyStore: apiKeys[
      "createApiKeyStore"
    ] as Fixture["createApiKeyStore"],
    createSessionStore: sessions[
      "createSessionStore"
    ] as Fixture["createSessionStore"],
    getApiKeys: keysRoute["getApiKeys"] as Fixture["getApiKeys"],
    sessionCookie: sessions["sessionCookie"] as Fixture["sessionCookie"],
  };
}
