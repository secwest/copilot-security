import { authenticateDirectoryUser } from "./authentication.js";

export function createSession(directory, credentials) {
  const user = authenticateDirectoryUser(directory, credentials);
  if (!user) return null;

  return Object.freeze({
    subject: user.username,
    role: user.role,
  });
}
