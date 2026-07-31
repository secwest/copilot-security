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
    const authority = String(
      request.headers["x-forwarded-host"] ?? request.headers.host ?? "",
    );
    const resetUrl = new URL(
      "/password-reset/complete",
      `https://${authority}`,
    );
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
