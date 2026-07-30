import { randomBytes, timingSafeEqual } from "node:crypto";

export const sessionCookie = Object.freeze({
  httpOnly: true,
  secure: true,
  sameSite: "none",
});

export function beginSession(session) {
  session.csrfToken = randomBytes(32).toString("hex");
}

export function registerAccountRoutes(router, formParser, database, mailer) {
  router.post(
    "/account/recovery-email",
    formParser.urlencoded({ extended: false }),
    changeRecoveryEmail(database),
  );
  router.post("/password-reset", startPasswordReset(database, mailer));
}

function hasValidCsrfToken(request) {
  const submitted = String(request.body.csrfToken ?? "");
  const expected = String(request.session.csrfToken ?? "");
  if (!/^[a-f0-9]{64}$/.test(submitted)) return false;
  if (!/^[a-f0-9]{64}$/.test(expected)) return false;
  return timingSafeEqual(
    Buffer.from(submitted, "hex"),
    Buffer.from(expected, "hex"),
  );
}

function changeRecoveryEmail(database) {
  return async function handleRecoveryEmail(request, response) {
    if (!hasValidCsrfToken(request)) return response.status(403).end();
    const account = await database.accounts.findById(request.session.userId);
    if (!account) return response.status(404).end();
    account.recoveryEmail = String(request.body.recoveryEmail);
    await database.accounts.save(account);
    return response.status(204).end();
  };
}

function startPasswordReset(database, mailer) {
  return async function handlePasswordReset(request, response) {
    const account = await database.accounts.findByRecoveryEmail(
      request.body.email,
    );
    if (account) await mailer.sendPasswordReset(account.recoveryEmail);
    return response.status(202).end();
  };
}
