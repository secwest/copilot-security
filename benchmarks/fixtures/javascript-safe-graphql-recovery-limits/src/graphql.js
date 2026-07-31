const MAX_SELECTIONS = 10;
const RECOVERY_FIELD = "verifyRecoveryCode";
const PUBLIC_FIELD = "viewerStatus";

export function createGraphqlGateway({
  recovery,
  maxResolverCostPerClient = 10,
}) {
  const chargedCost = new Map();
  return {
    execute(request) {
      const plan = validateExecutionPlan(request.document);
      if (!plan.ok) return response(400, { error: plan.error });

      const clientId = String(request.clientId);
      const nextCost = (chargedCost.get(clientId) ?? 0) + plan.cost;
      if (nextCost > maxResolverCostPerClient) {
        return response(429, { error: "resolver_cost_exceeded" });
      }
      chargedCost.set(clientId, nextCost);

      const data = {};
      for (const selection of plan.selections) {
        data[selection.alias] =
          selection.field === RECOVERY_FIELD
            ? recovery.verifyRecoveryCode(selection.arguments)
            : { available: true };
      }
      return response(200, { data });
    },
    chargedCost(clientId) {
      return chargedCost.get(String(clientId)) ?? 0;
    },
  };
}

function validateExecutionPlan(document) {
  if (!Array.isArray(document?.selections)) {
    return { ok: false, error: "invalid_document" };
  }
  if (
    document.selections.length === 0 ||
    document.selections.length > MAX_SELECTIONS
  ) {
    return { ok: false, error: "selection_limit_exceeded" };
  }

  const aliases = new Set();
  let recoveryOperations = 0;
  for (const selection of document.selections) {
    if (
      typeof selection?.alias !== "string" ||
      aliases.has(selection.alias) ||
      ![RECOVERY_FIELD, PUBLIC_FIELD].includes(selection.field)
    ) {
      return { ok: false, error: "invalid_selection" };
    }
    aliases.add(selection.alias);
    if (selection.field === RECOVERY_FIELD) recoveryOperations += 1;
  }
  if (recoveryOperations > 1) {
    return { ok: false, error: "one_recovery_operation_per_request" };
  }
  return {
    ok: true,
    cost: document.selections.length,
    selections: document.selections,
  };
}

function response(status, body) {
  return { status, body };
}
