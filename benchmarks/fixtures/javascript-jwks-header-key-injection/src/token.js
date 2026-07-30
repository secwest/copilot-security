import { createPublicKey, verify } from "node:crypto";

export async function verifyIdToken(token, policy) {
  const segments = token.split(".");
  if (segments.length !== 3) throw new Error("invalid JWT structure");
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = decodeSegment(encodedHeader);
  if (
    header.alg !== "EdDSA" ||
    typeof header.kid !== "string" ||
    typeof header.jku !== "string"
  ) {
    throw new Error("invalid JWT header");
  }
  const keyUrl = new URL(header.jku);
  if (
    keyUrl.protocol !== "https:" ||
    keyUrl.origin !== policy.allowedJwksOrigin ||
    keyUrl.username !== "" ||
    keyUrl.password !== ""
  ) {
    throw new Error("untrusted JWKS service origin");
  }
  const jwks = await policy.fetchJwks(keyUrl.href);
  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk) throw new Error("JWT signing key not found");
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  if (
    !verify(
      null,
      Buffer.from(signingInput, "ascii"),
      createPublicKey({ key: jwk, format: "jwk" }),
      Buffer.from(encodedSignature, "base64url"),
    )
  ) {
    throw new Error("invalid JWT signature");
  }
  const claims = decodeSegment(encodedPayload);
  validateClaims(claims, policy);
  return claims;
}

function validateClaims(claims, policy) {
  if (
    claims.iss !== policy.expectedIssuer ||
    claims.aud !== policy.expectedAudience ||
    typeof claims.exp !== "number" ||
    typeof claims.iat !== "number" ||
    claims.exp <= policy.now ||
    claims.iat > policy.now ||
    policy.now - claims.iat > policy.maxTokenAgeSeconds
  ) {
    throw new Error("invalid ID token trust binding or lifetime");
  }
  if (
    typeof claims.nonce !== "string" ||
    !policy.pendingNonces.delete(claims.nonce)
  ) {
    throw new Error("invalid or replayed ID token nonce");
  }
}

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}
