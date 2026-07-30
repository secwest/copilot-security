import { requireDirectoryAdministrator } from "./authorization.js";

export function createAdministrativeSession(directory, identity) {
  const group = requireDirectoryAdministrator(directory, identity);
  if (!group) return null;

  return Object.freeze({
    subject: identity.subject,
    role: "administrator",
    directoryGroup: group.dn,
  });
}
