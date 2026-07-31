import { randomBytes, verify } from "node:crypto";

export const expectedOrigin = "https://login.example.test";
export const expectedRpId = "example.test";
const transactionLifetimeMs = 5 * 60 * 1000;

function assertionBytes(challenge, origin, rpId) {
  return Buffer.from(
    [challenge, origin, rpId]
      .map((value) => `${Buffer.byteLength(value, "utf8")}:${value}`)
      .join("|"),
    "utf8",
  );
}

export function createServerState(users, registrations) {
  return {
    usersByName: new Map(users.map((user) => [user.username, user])),
    credentials: new Map(
      registrations.map((credential) => [credential.credentialId, credential]),
    ),
    transactions: new Map(),
    sessions: new Map(),
  };
}

export function beginLogin(state, username, now = Date.now()) {
  const user = state.usersByName.get(username);
  if (!user) throw new Error("unknown account");
  const allowedCredentialIds = [...state.credentials.values()]
    .filter((credential) => credential.ownerId === user.id)
    .map((credential) => credential.credentialId);
  if (allowedCredentialIds.length === 0) throw new Error("no passkey");

  const transactionId = randomBytes(24).toString("base64url");
  const challenge = randomBytes(32).toString("base64url");
  state.transactions.set(transactionId, {
    challenge,
    userId: user.id,
    allowedCredentialIds: new Set(allowedCredentialIds),
    expiresAt: now + transactionLifetimeMs,
  });
  return {
    transactionId,
    challenge,
    allowedCredentialIds,
    origin: expectedOrigin,
    rpId: expectedRpId,
  };
}

export function finishLogin(state, assertion, now = Date.now()) {
  const transaction = state.transactions.get(assertion.transactionId);
  const credential = state.credentials.get(assertion.credentialId);
  if (!transaction || !credential || transaction.expiresAt < now) {
    throw new Error("invalid transaction");
  }
  if (
    !transaction.allowedCredentialIds.has(credential.credentialId) ||
    credential.ownerId !== transaction.userId
  ) {
    throw new Error("credential is not bound to this account");
  }
  if (assertion.origin !== expectedOrigin || assertion.rpId !== expectedRpId) {
    throw new Error("invalid relying party");
  }
  const valid = verify(
    "sha256",
    assertionBytes(transaction.challenge, assertion.origin, assertion.rpId),
    credential.publicKey,
    Buffer.from(assertion.signature, "base64url"),
  );
  if (!valid) throw new Error("invalid signature");
  if (!state.transactions.delete(assertion.transactionId)) {
    throw new Error("transaction already consumed");
  }

  const sessionId = randomBytes(24).toString("base64url");
  state.sessions.set(sessionId, { userId: credential.ownerId });
  return { sessionId, userId: credential.ownerId };
}
