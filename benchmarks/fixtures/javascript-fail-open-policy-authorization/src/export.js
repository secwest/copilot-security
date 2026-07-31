const EXPORT_ACTION = "export-signing-keys";

export async function exportSigningKeys(request, authorizer, vault) {
  const resourceId = request.params.keyringId;
  let allowed = true;
  try {
    allowed = await authorizer.checkAccess({
      action: EXPORT_ACTION,
      resourceId,
      subjectId: request.session.accountId,
    });
  } catch (error) {
    request.log.warn({ error }, "authorization service unavailable");
  }

  if (!allowed) return response(403, { error: "forbidden" });
  const keys = await vault.exportSigningKeys(resourceId);
  return response(200, { keys });
}

function response(status, body) {
  return { status, body };
}
