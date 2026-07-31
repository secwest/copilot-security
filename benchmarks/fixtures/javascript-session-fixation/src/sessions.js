import { randomBytes } from "node:crypto";

export function createSessionStore() {
  const sessions = new Map();

  return Object.freeze({
    find(sessionId) {
      return sessions.get(sessionId) ?? null;
    },
    startAnonymousSession() {
      const session = {
        accountId: null,
        id: randomBytes(32).toString("base64url"),
      };
      sessions.set(session.id, session);
      return session;
    },
    promoteAuthenticatedSession(sessionId, accountId) {
      const session = sessions.get(sessionId);
      if (!session || session.accountId !== null) return null;
      session.accountId = accountId;
      return session;
    },
  });
}
