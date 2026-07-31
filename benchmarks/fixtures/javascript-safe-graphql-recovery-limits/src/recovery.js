import { randomBytes, timingSafeEqual } from "node:crypto";

const MAX_FAILED_ATTEMPTS = 3;

export function createRecoveryService(records) {
  const accounts = new Map(
    records.map((record) => [record.accountId, { ...record }]),
  );
  const failedAttempts = new Map();
  const resetTokens = new Map();
  return {
    verifyRecoveryCode({ accountId, code }) {
      const normalizedAccountId = String(accountId);
      const attempts = failedAttempts.get(normalizedAccountId) ?? 0;
      if (attempts >= MAX_FAILED_ATTEMPTS) {
        return { accepted: false, error: "too_many_attempts" };
      }

      const account = accounts.get(normalizedAccountId);
      if (!account || !codesEqual(account.recoveryCode, String(code))) {
        failedAttempts.set(normalizedAccountId, attempts + 1);
        return { accepted: false, error: "invalid_code" };
      }

      failedAttempts.delete(normalizedAccountId);
      const resetToken = randomBytes(32).toString("hex");
      resetTokens.set(resetToken, normalizedAccountId);
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
    failedAttemptsFor(accountId) {
      return failedAttempts.get(String(accountId)) ?? 0;
    },
    passwordFor(accountId) {
      return accounts.get(String(accountId))?.password ?? null;
    },
  };
}

function codesEqual(expected, supplied) {
  const expectedBytes = Buffer.from(String(expected), "utf8");
  const suppliedBytes = Buffer.from(String(supplied), "utf8");
  return (
    expectedBytes.length === suppliedBytes.length &&
    timingSafeEqual(expectedBytes, suppliedBytes)
  );
}
