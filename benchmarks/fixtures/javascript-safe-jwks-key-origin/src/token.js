import { createPublicKey, verify } from "node:crypto";

const CLAIM_KEYS = ["aud", "exp", "iat", "iss", "nonce", "role", "sub"];

export async function verifyIdToken(token, policy) {
  const segments = token.split(".");
  if (segments.length !== 3) throw new Error("invalid JWT structure");
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = decodeSegment(encodedHeader);
  if (
    !header ||
    typeof header !== "object" ||
    Array.isArray(header) ||
    header.alg !== "EdDSA" ||
    header.typ !== "JWT" ||
    typeof header.kid !== "string"
  ) {
    throw new Error("invalid JWT header");
  }
  if ("jku" in header || "x5u" in header) {
    throw new Error("untrusted remote key URL");
  }
  const jwks = await policy.fetchJwks(policy.expectedJwksUri);
  const matchingKeys = jwks.keys.filter(
    (candidate) =>
      candidate.kid === header.kid &&
      candidate.alg === "EdDSA" &&
      candidate.kty === "OKP" &&
      candidate.crv === "Ed25519" &&
      candidate.use === "sig",
  );
  if (matchingKeys.length !== 1) {
    throw new Error("JWT key identifier must select one trusted signing key");
  }
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  if (
    !verify(
      null,
      Buffer.from(signingInput, "ascii"),
      createPublicKey({ key: matchingKeys[0], format: "jwk" }),
      Buffer.from(encodedSignature, "base64url"),
    )
  ) {
    throw new Error("invalid JWT signature");
  }
  const claims = decodeSegment(encodedPayload);
  if (
    !claims ||
    typeof claims !== "object" ||
    Array.isArray(claims) ||
    Object.keys(claims).sort().join("\0") !== CLAIM_KEYS.join("\0")
  ) {
    throw new Error("invalid ID token claims");
  }
  if (
    claims.iss !== policy.expectedIssuer ||
    claims.aud !== policy.expectedAudience ||
    typeof claims.sub !== "string" ||
    typeof claims.role !== "string" ||
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
  return Object.freeze(claims);
}

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}
