export function createSession(assertion) {
  return Object.freeze({
    userId: assertion.subject,
    roles: Object.freeze([...assertion.roles]),
  });
}
