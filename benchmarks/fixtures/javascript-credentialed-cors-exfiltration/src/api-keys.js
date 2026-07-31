export function createApiKeyStore(records) {
  const byAccount = new Map(
    records.map((record) => [
      record.accountId,
      Object.freeze([...record.keys]),
    ]),
  );

  return Object.freeze({
    forAccount(accountId) {
      return [...(byAccount.get(accountId) ?? [])];
    },
  });
}
