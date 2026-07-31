export function authorizeAndForward(
  rawQuery,
  principal,
  executeBackend,
  state,
) {
  const gatewayParameters = new URLSearchParams(rawQuery);
  const authorizedAction = gatewayParameters.get("action");
  if (authorizedAction !== "view" && principal.role !== "administrator") {
    return { status: 403, authorizedAction };
  }

  return executeBackend(rawQuery, principal, state);
}
