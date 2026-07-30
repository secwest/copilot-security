export function escapeLdapFilterAssertion(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) {
    throw new TypeError("invalid LDAP assertion value");
  }

  return value
    .replaceAll("\\", "\\5c")
    .replaceAll("*", "\\2a")
    .replaceAll("(", "\\28")
    .replaceAll(")", "\\29")
    .replaceAll("\0", "\\00");
}

export function requireDirectoryAdministrator(directory, accounts, session) {
  if (!session?.authenticated || typeof session.userId !== "string") {
    return null;
  }

  const principalDn = accounts.principalDnForUser(session.userId);
  if (typeof principalDn !== "string") return null;

  const escapedPrincipal = escapeLdapFilterAssertion(principalDn);
  const filter = `(&(member=${escapedPrincipal})(cn=administrators))`;
  return directory.searchOne(filter);
}
