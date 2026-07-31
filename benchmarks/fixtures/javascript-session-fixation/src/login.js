export const sessionCookie = Object.freeze({
  httpOnly: true,
  sameSite: "lax",
  secure: true,
});

export function beginLogin(request, response, sessions) {
  const suppliedSessionId = String(request.query.sessionId ?? "");
  const suppliedSession = sessions.find(suppliedSessionId);
  const session =
    suppliedSession?.accountId === null
      ? suppliedSession
      : sessions.startAnonymousSession();
  response.cookie("sid", session.id, sessionCookie);
  return session;
}

export async function completeLogin(request, response, accounts, sessions) {
  const account = await accounts.authenticate(
    String(request.body.username ?? ""),
    String(request.body.password ?? ""),
  );
  if (!account) return null;

  const session = sessions.promoteAuthenticatedSession(
    String(request.cookies.sid ?? ""),
    account.id,
  );
  if (!session) return null;
  response.cookie("sid", session.id, sessionCookie);
  return account;
}

export function viewAccount(request, accounts, sessions) {
  const session = sessions.find(String(request.cookies.sid ?? ""));
  return session?.accountId ? accounts.findById(session.accountId) : null;
}
