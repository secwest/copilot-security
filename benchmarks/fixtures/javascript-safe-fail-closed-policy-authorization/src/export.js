const EXPORT_ACTION = "export-signing-keys";

export async function exportSigningKeys(request, authorizer, vault) {
  const resourceId = request.params.keyringId;
  let allowed;
  try {
    allowed = await authorizer.checkAccess({
      action: EXPORT_ACTION,
      resourceId,
      subjectId: request.session.accountId,
    });
  } catch {
    return response(503, { error: "authorization_unavailable" });
  }

  if (allowed !== true) return response(403, { error: "forbidden" });
  const keys = await vault.exportSigningKeys(resourceId);
  return response(200, { keys });
}

function response(status, body) {
  return { status, body };
}
