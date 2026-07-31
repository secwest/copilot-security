export function createAccountStore(records, verifyPassword) {
  const byUsername = new Map(
    records.map((record) => [record.username, record]),
  );
  const byId = new Map(records.map((record) => [record.id, record]));

  return Object.freeze({
    async authenticate(username, password) {
      const record = byUsername.get(username);
      if (!record || !(await verifyPassword(password, record.passwordHash))) {
        return null;
      }
      return publicAccount(record);
    },
    findById(accountId) {
      const record = byId.get(accountId);
      return record ? publicAccount(record) : null;
    },
  });
}

function publicAccount(record) {
  return Object.freeze({
    id: record.id,
    role: record.role,
    username: record.username,
  });
}
