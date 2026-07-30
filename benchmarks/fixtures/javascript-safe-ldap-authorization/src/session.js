import { requireDirectoryAdministrator } from "./authorization.js";

export function createAdministrativeSession(directory, accounts, identity) {
  const group = requireDirectoryAdministrator(directory, accounts, identity);
  if (!group) return null;

  return Object.freeze({
    subject: identity.subject,
    role: "administrator",
    directoryGroup: group.dn,
  });
}
