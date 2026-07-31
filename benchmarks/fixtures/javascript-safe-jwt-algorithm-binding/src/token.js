import { createPublicKey, verify } from "node:crypto";

const EXPECTED_ALGORITHM = "RS256";
const CLAIM_KEYS = ["aud", "exp", "iss", "role", "sub"];

export function verifyAccessToken(token, policy) {
  const segments = token.split(".");
  if (segments.length !== 3) throw new Error("invalid JWT structure");
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = decodeSegment(encodedHeader);
  if (
    !header ||
    typeof header !== "object" ||
    Array.isArray(header) ||
    header.alg !== EXPECTED_ALGORITHM ||
    header.typ !== "JWT" ||
    typeof header.kid !== "string"
  ) {
    throw new Error("invalid JWT header");
  }
  const keyMaterial = policy.trustedKeys.get(header.kid);
  if (!keyMaterial) throw new Error("JWT signing key not found");
  let verificationKey;
  try {
    verificationKey = createPublicKey(keyMaterial);
  } catch {
    throw new Error("trusted JWT key must be an RSA public key");
  }
  if (verificationKey.asymmetricKeyType !== "rsa") {
    throw new Error("trusted JWT key must be an RSA public key");
  }

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  if (
    !verify(
      "RSA-SHA256",
      Buffer.from(signingInput, "ascii"),
      verificationKey,
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
    Object.keys(claims).sort().join("\0") !== CLAIM_KEYS.join("\0") ||
    claims.iss !== policy.expectedIssuer ||
    claims.aud !== policy.expectedAudience ||
    typeof claims.sub !== "string" ||
    typeof claims.role !== "string" ||
    typeof claims.exp !== "number" ||
    claims.exp <= policy.now
  ) {
    throw new Error("invalid JWT claims");
  }
  return Object.freeze(claims);
}

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}
