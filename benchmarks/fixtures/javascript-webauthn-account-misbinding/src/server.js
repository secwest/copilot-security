import { randomBytes, verify } from "node:crypto";

export const expectedOrigin = "https://login.example.test";
export const expectedRpId = "example.test";

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
    activeChallenges: new Set(),
    sessions: new Map(),
  };
}

export function beginLogin(state, username) {
  const user = state.usersByName.get(username);
  if (!user) throw new Error("unknown account");
  const challenge = randomBytes(32).toString("base64url");
  state.activeChallenges.add(challenge);
  return { challenge, rpId: expectedRpId, origin: expectedOrigin };
}

export function finishLogin(state, assertion) {
  const requestedUser = state.usersByName.get(assertion.username);
  const credential = state.credentials.get(assertion.credentialId);
  if (!requestedUser || !credential) throw new Error("invalid assertion");
  if (!state.activeChallenges.has(assertion.challenge)) {
    throw new Error("invalid challenge");
  }
  if (assertion.origin !== expectedOrigin || assertion.rpId !== expectedRpId) {
    throw new Error("invalid relying party");
  }
  const valid = verify(
    "sha256",
    assertionBytes(assertion.challenge, assertion.origin, assertion.rpId),
    credential.publicKey,
    Buffer.from(assertion.signature, "base64url"),
  );
  if (!valid) throw new Error("invalid signature");

  state.activeChallenges.delete(assertion.challenge);
  const sessionId = randomBytes(24).toString("base64url");
  state.sessions.set(sessionId, { userId: requestedUser.id });
  return { sessionId, userId: requestedUser.id };
}
