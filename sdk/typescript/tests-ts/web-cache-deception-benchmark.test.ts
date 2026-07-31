import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface Request {
  method: string;
  path: string;
  cookies: Record<string, string | undefined>;
}

interface Response {
  status: number;
  body: Record<string, unknown>;
  headers: Record<string, string>;
}

interface Fixture {
  createAccountOrigin(dependencies: {
    sessions: {
      get(id: string): { accountId: string; id: string } | null;
    };
    apiKeys: { forAccount(accountId: string): string[] };
  }): (request: Request) => Response;
  createApiKeyStore(records: Array<{ accountId: string; keys: string[] }>): {
    forAccount(accountId: string): string[];
  };
  createEdgeCache(origin: (request: Request) => Response): {
    handle(request: Request): Response;
    size(): number;
  };
  createSessionStore(records: Array<{ accountId: string; id: string }>): {
    get(id: string): { accountId: string; id: string } | null;
  };
}

const deceptivePath = "/account/profile.css";
const victimSessionId = "victim-session";
const victimAccountId = "victim-account";
const victimApiKey = "fixture-victim-control-plane-key";

test("shared-cache and origin routing disagreement leaks a victim key while exact routing and public-only caching prevent it", async () => {
  const vulnerable = await loadFixture("javascript-web-cache-deception");
  const safe = await loadFixture("javascript-safe-private-cache");

  const exposed = exercise(vulnerable);
  expect(exposed.attackerBeforeVictim.status).toBe(401);
  expect(exposed.attackerBeforeVictim.headers["x-cache"]).toBe("MISS");
  expect(exposed.victimDeceptive.status).toBe(200);
  expect(exposed.victimDeceptive.headers["x-cache"]).toBe("MISS");
  expect(exposed.victimDeceptive.headers["cache-control"]).toBe(
    "private, no-store",
  );
  expect(exposed.attackerAfterVictim.status).toBe(200);
  expect(exposed.attackerAfterVictim.headers["x-cache"]).toBe("HIT");
  expect(exposed.attackerAfterVictim.body).toEqual(
    exposed.victimDeceptive.body,
  );
  expect(exposed.originCallsAfterVictim).toBe(exposed.originCallsAfterAttack);
  expect(exposed.cacheEntries).toBe(1);
  expect(attackerCanUseKey(exposed.attackerAfterVictim)).toBe(true);

  const protectedResult = exercise(safe);
  expect(protectedResult.attackerBeforeVictim.status).toBe(404);
  expect(protectedResult.victimDeceptive.status).toBe(404);
  expect(protectedResult.attackerAfterVictim.status).toBe(404);
  expect(protectedResult.attackerAfterVictim.headers["x-cache"]).toBe("MISS");
  expect(attackerCanUseKey(protectedResult.attackerAfterVictim)).toBe(false);
  expect(protectedResult.cacheEntries).toBe(0);

  const direct = exerciseDirectAccount(safe);
  expect(direct.victim.status).toBe(200);
  expect(direct.victim.headers["cache-control"]).toBe("private, no-store");
  expect(direct.attacker.status).toBe(401);
  expect(direct.attacker.headers["x-cache"]).toBe("MISS");
  expect(attackerCanUseKey(direct.attacker)).toBe(false);
  expect(direct.cacheEntries).toBe(0);

  const publicAsset = exercisePublicAsset(safe);
  expect(publicAsset.first.status).toBe(200);
  expect(publicAsset.first.headers["x-cache"]).toBe("MISS");
  expect(publicAsset.second.headers["x-cache"]).toBe("HIT");
  expect(publicAsset.originCalls).toBe(1);
  expect(publicAsset.cacheEntries).toBe(1);
});

function exercise(fixture: Fixture) {
  const { edge, originCalls } = buildEdge(fixture);
  const attackerBeforeVictim = edge.handle(request(deceptivePath));
  const victimDeceptive = edge.handle(request(deceptivePath, victimSessionId));
  const originCallsAfterVictim = originCalls();
  const attackerAfterVictim = edge.handle(request(deceptivePath));
  return {
    attackerBeforeVictim,
    victimDeceptive,
    attackerAfterVictim,
    originCallsAfterVictim,
    originCallsAfterAttack: originCalls(),
    cacheEntries: edge.size(),
  };
}

function exerciseDirectAccount(fixture: Fixture) {
  const { edge } = buildEdge(fixture);
  const victim = edge.handle(request("/account", victimSessionId));
  const attacker = edge.handle(request("/account"));
  return { victim, attacker, cacheEntries: edge.size() };
}

function exercisePublicAsset(fixture: Fixture) {
  const { edge, originCalls } = buildEdge(fixture);
  const first = edge.handle(request("/assets/app.css"));
  const second = edge.handle(request("/assets/app.css"));
  return {
    first,
    second,
    originCalls: originCalls(),
    cacheEntries: edge.size(),
  };
}

function buildEdge(fixture: Fixture) {
  const sessions = fixture.createSessionStore([
    { accountId: victimAccountId, id: victimSessionId },
  ]);
  const apiKeys = fixture.createApiKeyStore([
    { accountId: victimAccountId, keys: [victimApiKey] },
  ]);
  const origin = fixture.createAccountOrigin({ sessions, apiKeys });
  let calls = 0;
  const edge = fixture.createEdgeCache((incoming) => {
    calls += 1;
    return origin(incoming);
  });
  return { edge, originCalls: () => calls };
}

function request(path: string, sessionId?: string): Request {
  return {
    method: "GET",
    path,
    cookies: { sid: sessionId },
  };
}

function attackerCanUseKey(response: Response): boolean {
  return (
    Array.isArray(response.body["apiKeys"]) &&
    response.body["apiKeys"].includes(victimApiKey)
  );
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
  const edge = (await import(
    pathToFileURL(resolve(sourceRoot, "edge-cache.js")).href
  )) as Record<string, unknown>;
  const origin = (await import(
    pathToFileURL(resolve(sourceRoot, "origin.js")).href
  )) as Record<string, unknown>;
  return {
    createAccountOrigin: origin[
      "createAccountOrigin"
    ] as Fixture["createAccountOrigin"],
    createApiKeyStore: origin[
      "createApiKeyStore"
    ] as Fixture["createApiKeyStore"],
    createEdgeCache: edge["createEdgeCache"] as Fixture["createEdgeCache"],
    createSessionStore: origin[
      "createSessionStore"
    ] as Fixture["createSessionStore"],
  };
}
