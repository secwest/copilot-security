import { generateKeyPairSync, randomUUID, sign } from "node:crypto";

export function assertionBytes(assertion) {
  return Buffer.from(
    JSON.stringify({
      id: assertion.id,
      issuer: assertion.issuer,
      subject: assertion.subject,
      audience: assertion.audience,
      recipient: assertion.recipient,
      issuedAt: assertion.issuedAt,
      expiresAt: assertion.expiresAt,
      roles: assertion.roles,
    }),
    "utf8",
  );
}

export function createIdentityProvider(issuer) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  return Object.freeze({
    issuer,
    publicKey,
    issueResponse({
      requestId,
      destination,
      audience,
      recipient = destination,
      subject,
      roles,
      now,
    }) {
      const assertion = Object.freeze({
        id: `assertion-${randomUUID()}`,
        issuer,
        subject,
        audience,
        recipient,
        issuedAt: now,
        expiresAt: now + 5 * 60 * 1_000,
        roles: Object.freeze([...roles]),
      });
      return {
        issuer,
        destination,
        inResponseTo: requestId,
        assertions: [assertion],
        signature: {
          referenceId: assertion.id,
          algorithm: "RSA-SHA256",
          value: sign(
            "RSA-SHA256",
            assertionBytes(assertion),
            privateKey,
          ).toString("base64url"),
        },
      };
    },
  });
}
