export function createSession(assertionClaims) {
  return Object.freeze({
    subject: assertionClaims.subject,
    role: assertionClaims.role,
    issuer: assertionClaims.issuer,
  });
}
