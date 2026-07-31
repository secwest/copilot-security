import { createHmac, timingSafeEqual, verify } from "node:crypto";

export function verifyAccessToken(token, policy) {
  const segments = token.split(".");
  if (segments.length !== 3) throw new Error("invalid JWT structure");
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = decodeSegment(encodedHeader);
  if (
    !header ||
    typeof header !== "object" ||
    typeof header.alg !== "string" ||
    typeof header.kid !== "string"
  ) {
    throw new Error("invalid JWT header");
  }
  const verificationKey = policy.trustedKeys.get(header.kid);
  if (!verificationKey) throw new Error("JWT signing key not found");

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = Buffer.from(encodedSignature, "base64url");
  let signatureValid;
  if (header.alg === "RS256") {
    signatureValid = verify(
      "RSA-SHA256",
      Buffer.from(signingInput, "ascii"),
      verificationKey,
      signature,
    );
  } else if (header.alg === "HS256") {
    const expected = createHmac("sha256", verificationKey)
      .update(signingInput, "ascii")
      .digest();
    signatureValid =
      signature.length === expected.length &&
      timingSafeEqual(signature, expected);
  } else {
    throw new Error("unsupported JWT algorithm");
  }
  if (!signatureValid) throw new Error("invalid JWT signature");

  const claims = decodeSegment(encodedPayload);
  validateClaims(claims, policy);
  return claims;
}

function validateClaims(claims, policy) {
  if (
    !claims ||
    typeof claims !== "object" ||
    claims.iss !== policy.expectedIssuer ||
    claims.aud !== policy.expectedAudience ||
    typeof claims.sub !== "string" ||
    typeof claims.role !== "string" ||
    typeof claims.exp !== "number" ||
    claims.exp <= policy.now
  ) {
    throw new Error("invalid JWT claims");
  }
}

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}
