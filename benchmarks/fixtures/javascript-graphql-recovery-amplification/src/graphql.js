export function createGraphqlGateway({ recovery, maxRequestsPerClient = 3 }) {
  const requestCounts = new Map();
  return {
    execute(request) {
      const clientId = String(request.clientId);
      const nextCount = (requestCounts.get(clientId) ?? 0) + 1;
      if (nextCount > maxRequestsPerClient) {
        return response(429, { error: "too_many_requests" });
      }
      requestCounts.set(clientId, nextCount);

      const data = {};
      for (const selection of request.document.selections) {
        if (selection.field !== "verifyRecoveryCode") {
          data[selection.alias] = { error: "unsupported_field" };
          continue;
        }
        data[selection.alias] = recovery.verifyRecoveryCode(
          selection.arguments,
        );
      }
      return response(200, { data });
    },
    requestCount(clientId) {
      return requestCounts.get(String(clientId)) ?? 0;
    },
  };
}

function response(status, body) {
  return { status, body };
}
