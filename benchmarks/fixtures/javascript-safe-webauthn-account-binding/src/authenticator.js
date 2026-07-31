import { generateKeyPairSync, sign } from "node:crypto";

function assertionBytes(challenge, origin, rpId) {
  return Buffer.from(
    [challenge, origin, rpId]
      .map((value) => `${Buffer.byteLength(value, "utf8")}:${value}`)
      .join("|"),
    "utf8",
  );
}

export function createAuthenticator(credentialId, ownerId) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });

  return Object.freeze({
    registration: Object.freeze({ credentialId, ownerId, publicKey }),
    signAssertion(challenge, origin, rpId) {
      return sign(
        "sha256",
        assertionBytes(challenge, origin, rpId),
        privateKey,
      ).toString("base64url");
    },
  });
}
