export function createSession(assertion) {
  return {
    userId: assertion.subject,
    roles: [...assertion.roles],
  };
}
