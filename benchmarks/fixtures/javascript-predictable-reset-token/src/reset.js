export async function startPasswordReset(request, response, accounts) {
  const account = await accounts.findByEmail(request.body.email);
  if (account) {
    const token = Math.floor(Math.random() * 1_000_000)
      .toString()
      .padStart(6, "0");
    await accounts.saveResetToken(account.id, token, Date.now() + 15 * 60_000);
    await accounts.sendResetToken(account.email, token);
  }
  return response.status(202).end();
}
