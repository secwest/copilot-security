const CLAIM_KEYS = [
  "audience",
  "id",
  "issuer",
  "notBefore",
  "notOnOrAfter",
  "recipient",
  "role",
  "subject",
];

export function validateSamlResponse(response, policy) {
  const matchingAssertions = response.assertions.filter(
    (assertion) => assertion.id === response.signature.referenceId,
  );
  if (matchingAssertions.length !== 1) {
    throw new Error("signature reference must select exactly one assertion");
  }
  const signedAssertion = matchingAssertions[0];
  if (
    !policy.verifySignature(
      signedAssertion.signedPayload,
      response.signature.signatureValue,
    )
  ) {
    throw new Error("invalid SAML assertion signature");
  }
  const claims = JSON.parse(signedAssertion.signedPayload);
  if (
    !claims ||
    typeof claims !== "object" ||
    Array.isArray(claims) ||
    Object.keys(claims).sort().join("\0") !== CLAIM_KEYS.join("\0")
  ) {
    throw new Error("invalid signed assertion shape");
  }
  if (
    typeof claims.id !== "string" ||
    claims.id !== signedAssertion.id ||
    claims.id !== response.signature.referenceId
  ) {
    throw new Error("signed assertion identifier mismatch");
  }
  if (
    claims.issuer !== policy.expectedIssuer ||
    claims.audience !== policy.expectedAudience ||
    claims.recipient !== policy.expectedRecipient
  ) {
    throw new Error("signed assertion trust binding mismatch");
  }
  if (
    typeof claims.subject !== "string" ||
    typeof claims.role !== "string" ||
    typeof claims.notBefore !== "number" ||
    typeof claims.notOnOrAfter !== "number" ||
    policy.now < claims.notBefore ||
    policy.now >= claims.notOnOrAfter
  ) {
    throw new Error("invalid signed assertion claims or lifetime");
  }
  if (policy.replayCache.has(claims.id)) {
    throw new Error("signed assertion replay rejected");
  }
  policy.replayCache.add(claims.id);
  return Object.freeze(claims);
}
