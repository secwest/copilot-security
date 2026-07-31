import { randomBytes } from "node:crypto";
import { challengeFor } from "./identity-provider.js";

export function createLinkTransactionStore() {
  const pending = new Map();

  return Object.freeze({
    begin({ accountId, sessionId }) {
      if (
        typeof accountId !== "string" ||
        typeof sessionId !== "string" ||
        accountId.length === 0 ||
        sessionId.length === 0
      ) {
        throw new TypeError("invalid identity-link transaction owner");
      }
      const state = randomBytes(32).toString("base64url");
      const codeVerifier = randomBytes(32).toString("base64url");
      const transaction = Object.freeze({
        accountId,
        codeChallenge: challengeFor(codeVerifier),
        codeVerifier,
        sessionId,
        state,
      });
      pending.set(state, transaction);
      return transaction;
    },
    consume({ sessionId, state }) {
      const transaction = pending.get(state);
      if (!transaction || transaction.sessionId !== sessionId) return null;
      pending.delete(state);
      return transaction;
    },
  });
}
