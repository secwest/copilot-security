export function createAccountStore(records, hashPassword) {
  const byEmail = new Map(
    records.map((record) => [record.email, { ...record }]),
  );
  const byId = new Map(
    [...byEmail.values()].map((record) => [record.id, record]),
  );

  return Object.freeze({
    async changePassword(accountId, password) {
      const account = byId.get(accountId);
      if (!account) return false;
      account.passwordHash = await hashPassword(password);
      return true;
    },
    findByEmail(email) {
      const account = byEmail.get(email);
      return account ? publicAccount(account) : null;
    },
    passwordHashFor(accountId) {
      return byId.get(accountId)?.passwordHash ?? null;
    },
  });
}

function publicAccount(account) {
  return Object.freeze({
    email: account.email,
    id: account.id,
    role: account.role,
  });
}
