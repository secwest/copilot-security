export function executeBackend(rawQuery, principal, state) {
  const parameters = Object.fromEntries(new URLSearchParams(rawQuery));
  const recordId = parameters.recordId;

  if (parameters.action === "delete") {
    const deleted = state.records.delete(recordId);
    state.audit.push({ action: "delete", principalId: principal.id, recordId });
    return { status: deleted ? 200 : 404, executedAction: "delete" };
  }
  if (parameters.action === "view") {
    return {
      status: state.records.has(recordId) ? 200 : 404,
      executedAction: "view",
    };
  }
  return { status: 400, executedAction: "invalid" };
}
