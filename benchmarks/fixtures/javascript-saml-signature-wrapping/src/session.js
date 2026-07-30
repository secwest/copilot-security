export function createSession(assertionClaims) {
  return {
    subject: assertionClaims.subject,
    role: assertionClaims.role,
    issuer: assertionClaims.issuer,
  };
}
