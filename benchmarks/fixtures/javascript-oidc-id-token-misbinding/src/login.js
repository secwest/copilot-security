import { verifySignedIdToken } from "./id-token.js";
import { randomBytes } from "node:crypto";

export const OIDC_ISSUER = "https://identity.example";
export const OIDC_CLIENT_ID = "payroll-client";

export function beginLogin(session) {
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  session.pendingState = state;
  return { clientId: OIDC_CLIENT_ID, state, nonce };
}

export async function finishLogin({
  session,
  response,
  publicKey,
  accounts,
  nowSeconds,
}) {
  if (
    typeof response.state !== "string" ||
    response.state !== session.pendingState
  ) {
    throw new Error("invalid OIDC callback state");
  }
  delete session.pendingState;

  const claims = verifySignedIdToken(response.idToken, publicKey);
  if (
    claims.iss !== OIDC_ISSUER ||
    typeof claims.sub !== "string" ||
    claims.sub.length === 0 ||
    typeof claims.exp !== "number" ||
    claims.exp <= nowSeconds
  ) {
    throw new Error("invalid ID token issuer, subject, or lifetime");
  }

  const account = await accounts.findByFederatedIdentity(
    claims.iss,
    claims.sub,
  );
  if (!account) throw new Error("unknown federated account");
  session.accountId = account.id;
  return { accountId: account.id };
}
