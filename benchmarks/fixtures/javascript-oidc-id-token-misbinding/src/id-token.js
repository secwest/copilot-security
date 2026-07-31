import { verify } from "node:crypto";

function decodeJson(segment) {
  const value = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid ID token JSON");
  }
  return value;
}

export function verifySignedIdToken(token, publicKey) {
  if (typeof token !== "string") throw new Error("invalid ID token");
  if (token.length > 8192) throw new Error("ID token exceeds size limit");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid compact ID token");

  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const header = decodeJson(encodedHeader);
  if (header.alg !== "EdDSA" || header.typ !== "JWT") {
    throw new Error("invalid ID token algorithm");
  }

  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = Buffer.from(encodedSignature, "base64url");
  if (!verify(null, Buffer.from(signingInput), publicKey, signature)) {
    throw new Error("invalid ID token signature");
  }
  return decodeJson(encodedClaims);
}
