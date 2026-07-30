import { createHash, randomBytes } from "node:crypto";

export async function startPasswordReset(request, response, accounts) {
  const account = await accounts.findByEmail(request.body.email);
  if (account) {
    const token = randomBytes(32).toString("base64url");
    const tokenDigest = createHash("sha256").update(token).digest("hex");
    await accounts.saveResetTokenDigest(
      account.id,
      tokenDigest,
      Date.now() + 15 * 60_000,
    );
    await accounts.sendResetToken(account.email, token);
  }
  return response.status(202).end();
}
