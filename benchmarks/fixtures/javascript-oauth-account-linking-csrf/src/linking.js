const CLIENT_ID = "secwest-control-plane";
const REDIRECT_URI = "https://app.example.test/oauth/link/callback";

export function beginExternalIdentityLink(identityProvider, session) {
  if (typeof session?.accountId !== "string") return null;

  return identityProvider.authorizationUrl({
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    responseType: "code",
  });
}

export function completeExternalIdentityLink(
  identityProvider,
  accounts,
  session,
  request,
) {
  if (
    typeof session?.accountId !== "string" ||
    typeof request?.code !== "string"
  ) {
    return null;
  }

  const identity = identityProvider.exchangeCode({
    code: request.code,
    redirectUri: REDIRECT_URI,
  });
  return accounts.linkExternalIdentity(session.accountId, identity);
}
