export function validateSamlResponse(response, verifySignature) {
  const signedAssertion = response.assertions.find(
    (assertion) => assertion.id === response.signature.referenceId,
  );
  if (!signedAssertion) throw new Error("signed assertion not found");
  if (
    !verifySignature(
      signedAssertion.signedPayload,
      response.signature.signatureValue,
    )
  ) {
    throw new Error("invalid SAML assertion signature");
  }
  return response.assertions[0].claims;
}
