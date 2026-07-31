const PUBLIC_ORIGIN = new URL("https://accounts.example.test");

export async function startPasswordReset(
  request,
  response,
  accounts,
  resetTokens,
  mailer,
) {
  const account = accounts.findByEmail(String(request.body.email ?? ""));
  if (account) {
    const token = resetTokens.issue(account.id);
    const resetUrl = new URL("/password-reset/complete", PUBLIC_ORIGIN);
    resetUrl.searchParams.set("token", token);
    await mailer.sendPasswordReset(account.email, resetUrl.href);
  }
  return response.status(202).end();
}

export async function completePasswordReset(
  request,
  response,
  accounts,
  resetTokens,
) {
  const accountId = resetTokens.consume(String(request.body.token ?? ""));
  if (!accountId) return response.status(400).end();
  await accounts.changePassword(
    accountId,
    String(request.body.newPassword ?? ""),
  );
  return response.status(204).end();
}
