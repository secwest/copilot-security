import { randomBytes, verify } from "node:crypto";
import { assertionBytes } from "./identity-provider.js";
import { createSession } from "./session.js";

export const serviceProviderEntityId =
  "https://portal.example.test/saml/metadata";
export const assertionConsumerUrl = "https://portal.example.test/saml/acs";
export const trustedIssuer = "https://idp.example.test/metadata";

export function createServiceProvider(identityProviderPublicKey) {
  return {
    identityProviderPublicKey,
    requests: new Map(),
    sessions: new Map(),
  };
}

export function beginLogin(state, now = Date.now()) {
  const requestId = `request-${randomBytes(24).toString("base64url")}`;
  state.requests.set(requestId, { expiresAt: now + 5 * 60 * 1_000 });
  return {
    requestId,
    destination: assertionConsumerUrl,
    audience: serviceProviderEntityId,
  };
}

export function consumeResponse(state, response, now = Date.now()) {
  const request = state.requests.get(response.inResponseTo);
  if (!request || request.expiresAt < now) {
    throw new Error("invalid authentication request");
  }
  if (
    response.issuer !== trustedIssuer ||
    response.destination !== assertionConsumerUrl
  ) {
    throw new Error("invalid SAML response context");
  }
  if (!Array.isArray(response.assertions) || response.assertions.length !== 1) {
    throw new Error("SAML response must contain exactly one assertion");
  }
  const assertionIds = new Set();
  for (const assertion of response.assertions) {
    if (
      typeof assertion.id !== "string" ||
      assertion.id.length === 0 ||
      assertionIds.has(assertion.id)
    ) {
      throw new Error("invalid or duplicate assertion ID");
    }
    assertionIds.add(assertion.id);
  }
  if (
    response.signature?.algorithm !== "RSA-SHA256" ||
    typeof response.signature.referenceId !== "string"
  ) {
    throw new Error("invalid SAML signature");
  }
  const signedAssertion = response.assertions[0];
  if (response.signature.referenceId !== signedAssertion.id) {
    throw new Error("signature does not bind the consumed assertion");
  }
  const signatureValid = verify(
    "RSA-SHA256",
    assertionBytes(signedAssertion),
    state.identityProviderPublicKey,
    Buffer.from(response.signature.value, "base64url"),
  );
  if (!signatureValid) throw new Error("invalid SAML signature");
  if (
    signedAssertion.issuer !== trustedIssuer ||
    signedAssertion.audience !== serviceProviderEntityId ||
    signedAssertion.recipient !== assertionConsumerUrl ||
    signedAssertion.issuedAt > now ||
    signedAssertion.expiresAt < now
  ) {
    throw new Error("invalid signed assertion context");
  }

  state.requests.delete(response.inResponseTo);
  const sessionId = randomBytes(24).toString("base64url");
  const session = createSession(signedAssertion);
  state.sessions.set(sessionId, session);
  return { sessionId, userId: session.userId, roles: [...session.roles] };
}
