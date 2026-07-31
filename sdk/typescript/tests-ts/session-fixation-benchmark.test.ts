import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface Account {
  id: string;
  role: string;
  username: string;
}

interface AccountStore {
  authenticate(username: string, password: string): Promise<Account | null>;
  findById(accountId: string): Account | null;
}

interface CookieOptions {
  httpOnly: boolean;
  sameSite: string;
  secure: boolean;
}

interface Response {
  cookies: Array<{ name: string; options: CookieOptions; value: string }>;
  cookie(name: string, value: string, options: CookieOptions): void;
}

interface Session {
  accountId: string | null;
  id: string;
}

interface SessionStore {
  find(sessionId: string): Session | null;
  startAnonymousSession(): Session;
}

interface Fixture {
  begin(
    request: { query: { sessionId?: string } },
    response: Response,
    sessions: SessionStore,
  ): Session;
  complete(
    request: {
      body: { password?: string; username?: string };
      cookies: { sid?: string };
    },
    response: Response,
    accounts: AccountStore,
    sessions: SessionStore,
  ): Promise<Account | null>;
  createAccounts(
    records: Array<{
      id: string;
      passwordHash: string;
      role: string;
      username: string;
    }>,
    verifyPassword: (
      password: string,
      passwordHash: string,
    ) => Promise<boolean>,
  ): AccountStore;
  createSessions(): SessionStore;
  sessionCookie: CookieOptions;
  view(
    request: { cookies: { sid?: string } },
    accounts: AccountStore,
    sessions: SessionStore,
  ): Account | null;
}

const victim = Object.freeze({
  id: "victim-account",
  passwordHash: "stored-password-hash",
  role: "administrator",
  username: "victim",
});

test("session fixation benchmark proves attacker reuse and authenticated-session rotation", async () => {
  const vulnerable = await loadFixture("javascript-session-fixation");
  const safe = await loadFixture("javascript-safe-session-rotation");
  const verifyPassword = async (
    password: string,
    passwordHash: string,
  ): Promise<boolean> =>
    password === "victim-password" && passwordHash === victim.passwordHash;

  const vulnerableAccounts = vulnerable.createAccounts(
    [victim],
    verifyPassword,
  );
  const vulnerableSessions = vulnerable.createSessions();
  const attackerKnownSession = vulnerableSessions.startAnonymousSession();
  const vulnerableBootstrapResponse = responseRecorder();
  const victimAnonymousSession = vulnerable.begin(
    { query: { sessionId: attackerKnownSession.id } },
    vulnerableBootstrapResponse,
    vulnerableSessions,
  );

  expect(victimAnonymousSession.id).toBe(attackerKnownSession.id);
  expect(vulnerableBootstrapResponse.cookies.at(-1)).toEqual({
    name: "sid",
    options: vulnerable.sessionCookie,
    value: attackerKnownSession.id,
  });

  const vulnerableLoginResponse = responseRecorder();
  expect(
    await vulnerable.complete(
      {
        body: { password: "victim-password", username: victim.username },
        cookies: { sid: victimAnonymousSession.id },
      },
      vulnerableLoginResponse,
      vulnerableAccounts,
      vulnerableSessions,
    ),
  ).toEqual({
    id: victim.id,
    role: victim.role,
    username: victim.username,
  });
  expect(vulnerableLoginResponse.cookies.at(-1)?.value).toBe(
    attackerKnownSession.id,
  );
  expect(
    vulnerable.view(
      { cookies: { sid: attackerKnownSession.id } },
      vulnerableAccounts,
      vulnerableSessions,
    ),
  ).toEqual({
    id: victim.id,
    role: victim.role,
    username: victim.username,
  });

  const safeAccounts = safe.createAccounts([victim], verifyPassword);
  const safeSessions = safe.createSessions();
  const safeAttackerSession = safeSessions.startAnonymousSession();
  const safeBootstrapResponse = responseRecorder();
  const safeVictimAnonymousSession = safe.begin(
    { query: { sessionId: safeAttackerSession.id } },
    safeBootstrapResponse,
    safeSessions,
  );

  expect(safeVictimAnonymousSession.id).not.toBe(safeAttackerSession.id);
  expect(safeBootstrapResponse.cookies.at(-1)?.value).toBe(
    safeVictimAnonymousSession.id,
  );
  expect(safe.sessionCookie).toEqual({
    httpOnly: true,
    sameSite: "lax",
    secure: true,
  });

  const safeLoginResponse = responseRecorder();
  expect(
    await safe.complete(
      {
        body: { password: "victim-password", username: victim.username },
        cookies: { sid: safeVictimAnonymousSession.id },
      },
      safeLoginResponse,
      safeAccounts,
      safeSessions,
    ),
  ).toEqual({
    id: victim.id,
    role: victim.role,
    username: victim.username,
  });
  const authenticatedSessionId = safeLoginResponse.cookies.at(-1)?.value;
  expect(authenticatedSessionId).toBeString();
  expect(authenticatedSessionId).not.toBe(safeVictimAnonymousSession.id);
  expect(authenticatedSessionId).not.toBe(safeAttackerSession.id);
  expect(safeSessions.find(safeVictimAnonymousSession.id)).toBeNull();
  expect(
    safe.view(
      { cookies: { sid: safeAttackerSession.id } },
      safeAccounts,
      safeSessions,
    ),
  ).toBeNull();
  expect(
    safe.view(
      { cookies: { sid: safeVictimAnonymousSession.id } },
      safeAccounts,
      safeSessions,
    ),
  ).toBeNull();
  expect(
    safe.view(
      { cookies: { sid: authenticatedSessionId } },
      safeAccounts,
      safeSessions,
    ),
  ).toEqual({
    id: victim.id,
    role: victim.role,
    username: victim.username,
  });

  const failedLoginSession = safeSessions.startAnonymousSession();
  const failedLoginResponse = responseRecorder();
  expect(
    await safe.complete(
      {
        body: { password: "wrong-password", username: victim.username },
        cookies: { sid: failedLoginSession.id },
      },
      failedLoginResponse,
      safeAccounts,
      safeSessions,
    ),
  ).toBeNull();
  expect(failedLoginResponse.cookies).toHaveLength(0);
  expect(safeSessions.find(failedLoginSession.id)?.accountId).toBeNull();
});

function responseRecorder(): Response {
  const cookies: Response["cookies"] = [];
  return {
    cookies,
    cookie(name, value, options) {
      cookies.push({ name, options, value });
    },
  };
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
  const accounts = (await import(
    pathToFileURL(resolve(sourceRoot, "accounts.js")).href
  )) as Record<string, unknown>;
  const login = (await import(
    pathToFileURL(resolve(sourceRoot, "login.js")).href
  )) as Record<string, unknown>;
  const sessions = (await import(
    pathToFileURL(resolve(sourceRoot, "sessions.js")).href
  )) as Record<string, unknown>;
  return {
    begin: login["beginLogin"] as Fixture["begin"],
    complete: login["completeLogin"] as Fixture["complete"],
    createAccounts: accounts["createAccountStore"] as Fixture["createAccounts"],
    createSessions: sessions["createSessionStore"] as Fixture["createSessions"],
    sessionCookie: login["sessionCookie"] as CookieOptions,
    view: login["viewAccount"] as Fixture["view"],
  };
}
