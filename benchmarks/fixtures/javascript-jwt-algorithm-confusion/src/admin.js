export function exportSigningAudit(accessTokenClaims, database) {
  if (accessTokenClaims.role !== "administrator") {
    throw new Error("administrator role required");
  }
  return database.exportSigningAudit();
}
