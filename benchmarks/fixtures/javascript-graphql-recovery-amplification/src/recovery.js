import { randomBytes } from "node:crypto";

export function createRecoveryService(records) {
  const accounts = new Map(
    records.map((record) => [record.accountId, { ...record }]),
  );
  const resetTokens = new Map();
  return {
    verifyRecoveryCode({ accountId, code }) {
      const account = accounts.get(String(accountId));
      if (!account || account.recoveryCode !== String(code)) {
        return { accepted: false, error: "invalid_code" };
      }
      const resetToken = randomBytes(32).toString("hex");
      resetTokens.set(resetToken, account.accountId);
      return { accepted: true, resetToken };
    },
    resetPassword({ accountId, resetToken, newPassword }) {
      const normalizedAccountId = String(accountId);
      if (resetTokens.get(String(resetToken)) !== normalizedAccountId) {
        return { changed: false, error: "invalid_reset_token" };
      }
      resetTokens.delete(String(resetToken));
      accounts.get(normalizedAccountId).password = String(newPassword);
      return { changed: true };
    },
    passwordFor(accountId) {
      return accounts.get(String(accountId))?.password ?? null;
    },
  };
}
