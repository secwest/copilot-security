import { randomBytes } from "node:crypto";

function newSessionId() {
  return randomBytes(32).toString("base64url");
}

export function createSessionStore() {
  const sessions = new Map();

  return Object.freeze({
    find(sessionId) {
      return sessions.get(sessionId) ?? null;
    },
    startAnonymousSession() {
      const session = { accountId: null, id: newSessionId() };
      sessions.set(session.id, session);
      return session;
    },
    rotateAuthenticatedSession(sessionId, accountId) {
      const anonymousSession = sessions.get(sessionId);
      if (!anonymousSession || anonymousSession.accountId !== null) return null;
      sessions.delete(sessionId);
      const authenticatedSession = {
        accountId,
        id: newSessionId(),
      };
      sessions.set(authenticatedSession.id, authenticatedSession);
      return authenticatedSession;
    },
  });
}
