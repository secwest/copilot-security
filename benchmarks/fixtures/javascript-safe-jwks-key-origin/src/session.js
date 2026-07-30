export function createSession(idTokenClaims) {
  return Object.freeze({
    subject: idTokenClaims.sub,
    role: idTokenClaims.role,
    issuer: idTokenClaims.iss,
  });
}
