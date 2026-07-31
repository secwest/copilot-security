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
  openAccountSocket(
    request: {
      cookies: Record<string, string | undefined>;
      headers: Record<string, string | undefined>;
    },
    socket: SocketRecorder,
    sessions: SessionStore,
    apiKeys: ApiKeyStore,
  ): boolean;
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

interface SocketRecorder {
  close(code: number, reason: string): void;
  on(event: "message", handler: (raw: string) => void): void;
  receive(raw: string): void;
  send(raw: string): void;
  state: {
    closeCode: number | null;
    closeReason: string | null;
    messages: string[];
  };
}

const apiOrigin = "https://api.example.test";
const trustedPortalOrigin = "https://portal.example.test";
const attackerOrigin = "https://attacker.test";
const victimSessionId = "victim-session";
const victimAccountId = "victim-account";
const victimApiKey = "fixture-victim-control-plane-key";

test("cross-site WebSocket hijacking exposes victim keys while exact Origin authorization prevents the upgrade", async () => {
  const vulnerable = await loadFixture(
    "javascript-cross-site-websocket-hijacking",
  );
  const safe = await loadFixture("javascript-safe-websocket-origin");

  expect(vulnerable.sessionCookie).toEqual({
    httpOnly: true,
    sameSite: "none",
    secure: true,
  });
  expect(siteFor(attackerOrigin)).not.toBe(siteFor(apiOrigin));

  const vulnerableResult = browserWebSocket(
    vulnerable,
    attackerOrigin,
    victimSessionId,
  );
  expect(vulnerableResult.cookieAttached).toBe(true);
  expect(vulnerableResult.accepted).toBe(true);
  expect(vulnerableResult.socket.state.closeCode).toBeNull();
  expect(vulnerableResult.sessionReads).toBe(1);
  expect(vulnerableResult.apiKeyReads).toBe(1);
  expect(vulnerableResult.messages).toContainEqual({
    accountId: victimAccountId,
    keys: [victimApiKey],
  });
  expect(attackerCanUseKey(vulnerableResult.messages)).toBe(true);

  const safeAttackerResult = browserWebSocket(
    safe,
    attackerOrigin,
    victimSessionId,
  );
  expect(safeAttackerResult.cookieAttached).toBe(true);
  expect(safeAttackerResult.accepted).toBe(false);
  expect(safeAttackerResult.socket.state.closeCode).toBe(4403);
  expect(safeAttackerResult.socket.state.closeReason).toBe(
    "origin_not_allowed",
  );
  expect(safeAttackerResult.sessionReads).toBe(0);
  expect(safeAttackerResult.apiKeyReads).toBe(0);
  expect(safeAttackerResult.messages).toEqual([]);
  expect(attackerCanUseKey(safeAttackerResult.messages)).toBe(false);

  for (const rejectedOrigin of [
    "null",
    "https://capture.example.test",
    "https://portal.example.test.attacker.test",
    "http://portal.example.test",
    "https://portal.example.test:444",
  ]) {
    const rejected = browserWebSocket(safe, rejectedOrigin, victimSessionId);
    expect(rejected.accepted).toBe(false);
    expect(rejected.socket.state.closeCode).toBe(4403);
    expect(rejected.sessionReads).toBe(0);
    expect(rejected.apiKeyReads).toBe(0);
  }

  const safeTrustedResult = browserWebSocket(
    safe,
    trustedPortalOrigin,
    victimSessionId,
  );
  expect(safeTrustedResult.accepted).toBe(true);
  expect(safeTrustedResult.socket.state.closeCode).toBeNull();
  expect(safeTrustedResult.sessionReads).toBe(1);
  expect(safeTrustedResult.apiKeyReads).toBe(1);
  expect(safeTrustedResult.messages).toContainEqual({
    accountId: victimAccountId,
    keys: [victimApiKey],
  });

  const unauthenticated = browserWebSocket(
    vulnerable,
    attackerOrigin,
    "unknown-session",
  );
  expect(unauthenticated.cookieAttached).toBe(true);
  expect(unauthenticated.accepted).toBe(false);
  expect(unauthenticated.socket.state.closeCode).toBe(4401);
  expect(unauthenticated.apiKeyReads).toBe(0);
  expect(attackerCanUseKey(unauthenticated.messages)).toBe(false);
});

function attackerCanUseKey(messages: unknown[]): boolean {
  return messages.some(
    (message) =>
      typeof message === "object" &&
      message !== null &&
      "keys" in message &&
      Array.isArray(message.keys) &&
      message.keys.includes(victimApiKey),
  );
}

function browserWebSocket(
  fixture: Fixture,
  origin: string,
  sessionId: string,
): {
  accepted: boolean;
  apiKeyReads: number;
  cookieAttached: boolean;
  messages: unknown[];
  sessionReads: number;
  socket: SocketRecorder;
} {
  const cookieAttached =
    fixture.sessionCookie.secure &&
    fixture.sessionCookie.sameSite === "none" &&
    origin.startsWith("https://");
  const sessions = fixture.createSessionStore([
    {
      accountId: victimAccountId,
      id: victimSessionId,
      role: "administrator",
    },
  ]);
  const apiKeys = fixture.createApiKeyStore([
    { accountId: victimAccountId, keys: [victimApiKey] },
  ]);
  let sessionReads = 0;
  let apiKeyReads = 0;
  const monitoredSessions: SessionStore = {
    get(id) {
      sessionReads += 1;
      return sessions.get(id);
    },
  };
  const monitoredApiKeys: ApiKeyStore = {
    forAccount(accountId) {
      apiKeyReads += 1;
      return apiKeys.forAccount(accountId);
    },
  };
  const socket = socketRecorder();
  const accepted = fixture.openAccountSocket(
    {
      cookies: { sid: cookieAttached ? sessionId : undefined },
      headers: { origin },
    },
    socket,
    monitoredSessions,
    monitoredApiKeys,
  );
  if (accepted) {
    socket.receive(JSON.stringify({ action: "list-api-keys" }));
  }
  return {
    accepted,
    apiKeyReads,
    cookieAttached,
    messages: socket.state.messages.map((message) => JSON.parse(message)),
    sessionReads,
    socket,
  };
}

function socketRecorder(): SocketRecorder {
  let messageHandler: ((raw: string) => void) | undefined;
  const state: SocketRecorder["state"] = {
    closeCode: null,
    closeReason: null,
    messages: [],
  };
  return {
    close(code, reason) {
      state.closeCode = code;
      state.closeReason = reason;
    },
    on(event, handler) {
      if (event === "message") messageHandler = handler;
    },
    receive(raw) {
      if (state.closeCode === null) messageHandler?.(raw);
    },
    send(raw) {
      if (state.closeCode === null) state.messages.push(raw);
    },
    state,
  };
}

function siteFor(origin: string): string {
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
  const route = (await import(
    pathToFileURL(resolve(sourceRoot, "websocket-route.js")).href
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
    openAccountSocket: route[
      "openAccountSocket"
    ] as Fixture["openAccountSocket"],
    sessionCookie: sessions["sessionCookie"] as Fixture["sessionCookie"],
  };
}
