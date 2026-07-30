export async function updateAccount(request, response, database) {
  const account = await database.accounts.findById(request.params.accountId);
  if (!account) return response.status(404).end();
  if (account.ownerId !== request.session.userId) {
    return response.status(404).end();
  }
  account.displayName = String(request.body.displayName ?? account.displayName);
  account.timeZone = String(request.body.timeZone ?? account.timeZone);
  await database.accounts.save(account);
  return response.json(account);
}

export async function requireAdministrator(request, response, next, database) {
  const account = await database.accounts.findById(request.session.userId);
  if (!account?.isAdmin) return response.status(403).end();
  return next();
}
