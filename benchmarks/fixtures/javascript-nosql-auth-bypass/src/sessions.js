export function registerSessionRoutes(router, database) {
  router.post("/session", (request, response) =>
    createSession(request, response, database),
  );
}

export async function createSession(request, response, database) {
  const account = await database.accounts.findOne({
    username: request.body.username,
    loginVerifier: request.body.loginVerifier,
  });
  if (!account) return response.status(401).end();

  request.session.userId = account.id;
  request.session.role = account.role;
  return response.status(204).end();
}
