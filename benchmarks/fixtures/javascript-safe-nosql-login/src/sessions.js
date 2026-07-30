const USERNAME = /^[a-z0-9._-]{3,64}$/iu;
const LOGIN_VERIFIER = /^[a-z0-9_-]{32,128}$/iu;

export function registerSessionRoutes(router, database) {
  router.post("/session", (request, response) =>
    createSession(request, response, database),
  );
}

export async function createSession(request, response, database) {
  const username = request.body.username;
  const loginVerifier = request.body.loginVerifier;
  if (typeof username !== "string" || !USERNAME.test(username)) {
    return response.status(400).end();
  }
  if (
    typeof loginVerifier !== "string" ||
    !LOGIN_VERIFIER.test(loginVerifier)
  ) {
    return response.status(400).end();
  }

  const account = await database.accounts.findOne({
    username,
    loginVerifier,
  });
  if (!account) return response.status(401).end();

  request.session.userId = account.id;
  request.session.role = account.role;
  return response.status(204).end();
}
