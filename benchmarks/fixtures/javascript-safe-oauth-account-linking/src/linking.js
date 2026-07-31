const CLIENT_ID = "secwest-control-plane";
const REDIRECT_URI = "https://app.example.test/oauth/link/callback";

export function beginExternalIdentityLink(
  identityProvider,
  linkTransactions,
  session,
) {
  if (
    typeof session?.accountId !== "string" ||
    typeof session?.id !== "string"
  ) {
    return null;
  }
  const transaction = linkTransactions.begin({
    accountId: session.accountId,
    sessionId: session.id,
  });
  return identityProvider.authorizationUrl({
    clientId: CLIENT_ID,
    codeChallenge: transaction.codeChallenge,
    codeChallengeMethod: "S256",
    redirectUri: REDIRECT_URI,
    responseType: "code",
    state: transaction.state,
  });
}

export function completeExternalIdentityLink(
  identityProvider,
  accounts,
  linkTransactions,
  session,
  request,
) {
  if (
    typeof session?.accountId !== "string" ||
    typeof session?.id !== "string" ||
    typeof request?.code !== "string" ||
    typeof request?.state !== "string"
  ) {
    return null;
  }
  const transaction = linkTransactions.consume({
    sessionId: session.id,
    state: request.state,
  });
  if (!transaction || transaction.accountId !== session.accountId) return null;

  const identity = identityProvider.exchangeCode({
    code: request.code,
    codeVerifier: transaction.codeVerifier,
    redirectUri: REDIRECT_URI,
  });
  return accounts.linkExternalIdentity(transaction.accountId, identity);
}
