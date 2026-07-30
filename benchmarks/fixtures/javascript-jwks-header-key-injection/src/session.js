export function createSession(idTokenClaims) {
  return {
    subject: idTokenClaims.sub,
    role: idTokenClaims.role,
    issuer: idTokenClaims.iss,
  };
}
