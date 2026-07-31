import { randomBytes, timingSafeEqual } from "node:crypto";
import { verifySignedIdToken } from "./id-token.js";

export const OIDC_ISSUER = "https://identity.example";
export const OIDC_CLIENT_ID = "payroll-client";
const MAX_LOGIN_AGE_SECONDS = 300;

export function beginLogin(session, nowSeconds) {
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  session.pendingOidc = {
    clientId: OIDC_CLIENT_ID,
    createdAt: nowSeconds,
    nonce,
    state,
  };
  return { clientId: OIDC_CLIENT_ID, state, nonce };
}

function sameSecret(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function intendedForClient(claims, clientId) {
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (
    audiences.length === 0 ||
    !audiences.every((audience) => typeof audience === "string") ||
    !audiences.includes(clientId)
  ) {
    return false;
  }
  if (audiences.length > 1 && claims.azp !== clientId) return false;
  return claims.azp === undefined || claims.azp === clientId;
}

export async function finishLogin({
  session,
  response,
  publicKey,
  accounts,
  nowSeconds,
}) {
  const pending = session.pendingOidc;
  delete session.pendingOidc;
  if (
    !pending ||
    pending.clientId !== OIDC_CLIENT_ID ||
    !sameSecret(response.state, pending.state) ||
    nowSeconds - pending.createdAt > MAX_LOGIN_AGE_SECONDS
  ) {
    throw new Error("invalid or expired OIDC login transaction");
  }

  const claims = verifySignedIdToken(response.idToken, publicKey);
  if (
    claims.iss !== OIDC_ISSUER ||
    typeof claims.sub !== "string" ||
    claims.sub.length === 0 ||
    typeof claims.exp !== "number" ||
    claims.exp <= nowSeconds ||
    !intendedForClient(claims, pending.clientId) ||
    !sameSecret(claims.nonce, pending.nonce)
  ) {
    throw new Error("invalid ID token trust or transaction binding");
  }

  const account = await accounts.findByFederatedIdentity(
    claims.iss,
    claims.sub,
  );
  if (!account) throw new Error("unknown federated account");
  session.accountId = account.id;
  return { accountId: account.id };
}
