import { applyCredentialedCors } from "./cors.js";

export function getApiKeys(request, response, sessions, apiKeys) {
  if (!applyCredentialedCors(request, response)) {
    return response.status(403).json({ error: "origin_not_allowed" });
  }
  const session = sessions.get(String(request.cookies.sid ?? ""));
  if (!session) return response.status(401).json({ error: "unauthorized" });
  return response.status(200).json({
    accountId: session.accountId,
    keys: apiKeys.forAccount(session.accountId),
  });
}
