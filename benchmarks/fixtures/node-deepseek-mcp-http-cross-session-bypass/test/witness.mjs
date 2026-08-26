import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const expected = process.argv[2];
assert.ok(
  expected === undefined || expected === "vulnerable" || expected === "patched",
);

process.env.DEEPSEEK_API_KEY = "sk-copilot-security-bounded-witness";
process.env.SKIP_CONNECTION_TEST = "true";
process.env.SESSION_TTL_MINUTES = "30";
process.env.MAX_SESSIONS = "8";

const packageRoot = join(
  process.cwd(),
  "node_modules",
  "@arikusi",
  "deepseek-mcp-server",
);
const packageJson = JSON.parse(
  await readFile(join(packageRoot, "package.json"), "utf8"),
);
const { loadConfig, resetConfig } = await import(
  pathToFileURL(join(packageRoot, "dist", "config.js"))
);
const { SessionStore } = await import(
  pathToFileURL(join(packageRoot, "dist", "session.js"))
);

loadConfig();
const vulnerable = typeof SessionStore.getInstance === "function";
if (expected !== undefined) assert.equal(vulnerable, expected === "vulnerable");

const victimStore = vulnerable
  ? SessionStore.getInstance()
  : new SessionStore();
const attackerStore = vulnerable
  ? SessionStore.getInstance()
  : new SessionStore();
const sessionId = "bounded-colliding-session-id";
const marker = "bounded-victim-conversation-marker";

try {
  victimStore.create(sessionId);
  victimStore.addMessages(sessionId, [{ role: "user", content: marker }]);
  const observed = attackerStore.getMessages(sessionId);
  if (vulnerable) {
    assert.equal(attackerStore, victimStore);
    assert.equal(
      attackerStore.list().some(({ id }) => id === sessionId),
      true,
    );
    assert.equal(observed[0]?.content, marker);
  } else {
    assert.notEqual(attackerStore, victimStore);
    assert.deepEqual(attackerStore.list(), []);
    assert.deepEqual(observed, []);
  }
  console.log(
    JSON.stringify({
      version: packageJson.version,
      storeIdentityShared: attackerStore === victimStore,
      attackerEnumeratedVictim: attackerStore
        .list()
        .some(({ id }) => id === sessionId),
      attackerReadMarker: observed[0]?.content === marker,
    }),
  );
} finally {
  victimStore.clear();
  if (attackerStore !== victimStore) attackerStore.clear();
  if (vulnerable) SessionStore.resetInstance();
  resetConfig();
}
