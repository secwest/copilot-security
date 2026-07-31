const TRUSTED_ISSUER = "https://identity.example.test";

export function createAccountStore(accountIds) {
  const accounts = new Map(
    accountIds.map((id) => [id, Object.freeze({ id, plan: "standard" })]),
  );
  const externalLinks = new Map();

  return Object.freeze({
    externalLinks,
    linkExternalIdentity(accountId, identity) {
      const account = accounts.get(accountId);
      if (!account) throw new TypeError("unknown local account");
      const externalKey = trustedExternalKey(identity);
      const existing = externalLinks.get(externalKey);
      if (existing && existing !== accountId) {
        throw new Error("external identity already linked");
      }
      externalLinks.set(externalKey, accountId);
      return account;
    },
    loginExternal(identity) {
      const accountId = externalLinks.get(trustedExternalKey(identity));
      return accountId ? accounts.get(accountId) ?? null : null;
    },
  });
}

function trustedExternalKey(identity) {
  if (
    identity?.issuer !== TRUSTED_ISSUER ||
    typeof identity.subject !== "string" ||
    identity.subject.length === 0 ||
    identity.subject.length > 256
  ) {
    throw new TypeError("untrusted external identity");
  }
  return `${identity.issuer}|${identity.subject}`;
}
