export function createAccountOrigin({ sessions, apiKeys }) {
  return function handleOrigin(request) {
    if (request.path === "/assets/app.css") {
      return response(
        200,
        { content: "body { color: #123; }" },
        { "cache-control": "public, max-age=300" },
      );
    }

    const routedPath = request.path.replace(/\/[^/]+\.(?:css|js|png)$/iu, "");
    if (routedPath !== "/account") {
      return response(404, { error: "not_found" });
    }

    const session = sessions.get(String(request.cookies.sid ?? ""));
    if (!session) return response(401, { error: "unauthorized" });
    return response(
      200,
      {
        accountId: session.accountId,
        apiKeys: apiKeys.forAccount(session.accountId),
      },
      { "cache-control": "private, no-store" },
    );
  };
}

export function createSessionStore(records) {
  const sessions = new Map(records.map((record) => [record.id, { ...record }]));
  return {
    get(id) {
      const session = sessions.get(id);
      return session ? { ...session } : null;
    },
  };
}

export function createApiKeyStore(records) {
  const keys = new Map(
    records.map((record) => [record.accountId, [...record.keys]]),
  );
  return {
    forAccount(accountId) {
      return [...(keys.get(accountId) ?? [])];
    },
  };
}

function response(status, body, headers = {}) {
  return { status, body, headers };
}
