import { createHash, randomBytes } from "node:crypto";

function digest(token) {
  return createHash("sha256").update(token, "ascii").digest("hex");
}

export function createResetTokenStore(now = () => Date.now()) {
  const pending = new Map();
  const activeByAccount = new Map();

  return Object.freeze({
    consume(token) {
      const tokenDigest = digest(String(token));
      const record = pending.get(tokenDigest);
      if (!record) return null;
      pending.delete(tokenDigest);
      if (activeByAccount.get(record.accountId) === tokenDigest) {
        activeByAccount.delete(record.accountId);
      }
      return record.expiresAt > now() ? record.accountId : null;
    },
    issue(accountId) {
      const previousDigest = activeByAccount.get(accountId);
      if (previousDigest) pending.delete(previousDigest);
      const token = randomBytes(32).toString("base64url");
      const tokenDigest = digest(token);
      pending.set(
        tokenDigest,
        Object.freeze({
          accountId,
          expiresAt: now() + 15 * 60_000,
        }),
      );
      activeByAccount.set(accountId, tokenDigest);
      return token;
    },
  });
}
