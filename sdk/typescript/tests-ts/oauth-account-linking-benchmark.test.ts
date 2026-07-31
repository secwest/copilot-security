import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface Account {
  id: string;
  plan: string;
}

interface AccountStore {
  externalLinks: Map<string, string>;
  linkExternalIdentity(accountId: string, identity: ExternalIdentity): Account;
  loginExternal(identity: ExternalIdentity): Account | null;
}

interface AuthorizationRequest {
  clientId: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  redirectUri: string;
  responseType: string;
  state?: string;
}

interface ExternalIdentity {
  issuer: string;
  subject: string;
}

interface IdentityProvider {
  authorizationRequests: AuthorizationRequest[];
  exchanges: Array<{
    code: string;
    codeVerifier?: string;
    redirectUri: string;
  }>;
  authorizationUrl(request: AuthorizationRequest): AuthorizationRequest;
  exchangeCode(request: {
    code: string;
    codeVerifier?: string;
    redirectUri: string;
  }): ExternalIdentity;
  issueAuthorizationCode(input: {
    authorizationRequest: AuthorizationRequest;
    subject: string;
  }): string;
}

interface LinkTransactionStore {
  begin(input: { accountId: string; sessionId: string }): {
    accountId: string;
    codeChallenge: string;
    codeVerifier: string;
    sessionId: string;
    state: string;
  };
  consume(input: { sessionId: string; state: string }): {
    accountId: string;
    codeChallenge: string;
    codeVerifier: string;
    sessionId: string;
    state: string;
  } | null;
}

interface Session {
  accountId: string;
  id: string;
}

test("OAuth account-linking benchmark proves login CSRF takeover and session-bound PKCE defense", async () => {
  const vulnerable = await loadFixture("javascript-oauth-account-linking-csrf");
  const safe = await loadFixture("javascript-safe-oauth-account-linking");
  const attackerSession = {
    accountId: "attacker-local",
    id: "attacker-browser-session",
  };
  const victimSession = {
    accountId: "victim-local",
    id: "victim-browser-session",
  };

  const vulnerableProvider = vulnerable.createIdentityProvider();
  const vulnerableAccounts = vulnerable.createAccountStore([
    attackerSession.accountId,
    victimSession.accountId,
  ]);
  const attackerAuthorization = vulnerable.begin(
    vulnerableProvider,
    attackerSession,
  );
  expect(attackerAuthorization).toEqual({
    clientId: "secwest-control-plane",
    redirectUri: "https://app.example.test/oauth/link/callback",
    responseType: "code",
  });
  expect(attackerAuthorization.state).toBeUndefined();
  expect(attackerAuthorization.codeChallenge).toBeUndefined();
  const attackerCode = vulnerableProvider.issueAuthorizationCode({
    authorizationRequest: attackerAuthorization,
    subject: "attacker-idp-subject",
  });

  expect(
    vulnerable.complete(vulnerableProvider, vulnerableAccounts, victimSession, {
      code: attackerCode,
    }),
  ).toEqual({ id: "victim-local", plan: "standard" });
  expect(vulnerableProvider.exchanges.at(-1)).toEqual({
    code: attackerCode,
    redirectUri: "https://app.example.test/oauth/link/callback",
  });
  expect(
    vulnerableAccounts.loginExternal({
      issuer: vulnerable.issuer,
      subject: "attacker-idp-subject",
    }),
  ).toEqual({ id: "victim-local", plan: "standard" });

  const safeProvider = safe.createIdentityProvider();
  const safeAccounts = safe.createAccountStore([
    attackerSession.accountId,
    victimSession.accountId,
  ]);
  const safeTransactions = safe.createTransactions();
  const safeAttackerAuthorization = safe.begin(
    safeProvider,
    safeTransactions,
    attackerSession,
  );
  expect(safeAttackerAuthorization.state?.length).toBeGreaterThanOrEqual(32);
  expect(
    safeAttackerAuthorization.codeChallenge?.length,
  ).toBeGreaterThanOrEqual(32);
  expect(safeAttackerAuthorization.codeChallengeMethod).toBe("S256");
  const safeAttackerCode = safeProvider.issueAuthorizationCode({
    authorizationRequest: safeAttackerAuthorization,
    subject: "attacker-idp-subject",
  });

  expect(
    safe.complete(safeProvider, safeAccounts, safeTransactions, victimSession, {
      code: safeAttackerCode,
      state: safeAttackerAuthorization.state,
    }),
  ).toBeNull();
  expect(safeProvider.exchanges).toHaveLength(0);
  expect(
    safeAccounts.loginExternal({
      issuer: safe.issuer,
      subject: "attacker-idp-subject",
    }),
  ).toBeNull();
  expect(
    safe.complete(safeProvider, safeAccounts, safeTransactions, victimSession, {
      code: safeAttackerCode,
    }),
  ).toBeNull();

  const victimAuthorization = safe.begin(
    safeProvider,
    safeTransactions,
    victimSession,
  );
  const victimCode = safeProvider.issueAuthorizationCode({
    authorizationRequest: victimAuthorization,
    subject: "victim-idp-subject",
  });
  expect(
    safe.complete(safeProvider, safeAccounts, safeTransactions, victimSession, {
      code: victimCode,
      state: victimAuthorization.state,
    }),
  ).toEqual({ id: "victim-local", plan: "standard" });
  expect(
    safeProvider.exchanges.at(-1)?.codeVerifier?.length,
  ).toBeGreaterThanOrEqual(32);
  expect(
    safe.challengeFor(safeProvider.exchanges.at(-1)?.codeVerifier ?? ""),
  ).toBe(victimAuthorization.codeChallenge ?? "");
  expect(
    safeAccounts.loginExternal({
      issuer: safe.issuer,
      subject: "victim-idp-subject",
    }),
  ).toEqual({ id: "victim-local", plan: "standard" });

  const exchangeCount = safeProvider.exchanges.length;
  expect(
    safe.complete(safeProvider, safeAccounts, safeTransactions, victimSession, {
      code: victimCode,
      state: victimAuthorization.state,
    }),
  ).toBeNull();
  expect(safeProvider.exchanges).toHaveLength(exchangeCount);
});

async function loadFixture(fixture: string): Promise<{
  begin: (
    identityProvider: IdentityProvider,
    transactionsOrSession: LinkTransactionStore | Session,
    session?: Session,
  ) => AuthorizationRequest;
  challengeFor: (verifier: string) => string;
  complete: (
    identityProvider: IdentityProvider,
    accounts: AccountStore,
    transactionsOrSession: LinkTransactionStore | Session,
    sessionOrRequest: Session | { code: string; state?: string },
    request?: { code: string; state?: string },
  ) => Account | null;
  createAccountStore: (accountIds: string[]) => AccountStore;
  createIdentityProvider: () => IdentityProvider;
  createTransactions: () => LinkTransactionStore;
  issuer: string;
}> {
  const sourceRoot = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
  );
  const linking = (await import(
    pathToFileURL(resolve(sourceRoot, "linking.js")).href
  )) as Record<string, unknown>;
  const accounts = (await import(
    pathToFileURL(resolve(sourceRoot, "accounts.js")).href
  )) as Record<string, unknown>;
  const identityProvider = (await import(
    pathToFileURL(resolve(sourceRoot, "identity-provider.js")).href
  )) as Record<string, unknown>;
  let createTransactions: () => LinkTransactionStore = () => {
    throw new Error("fixture does not provide link transactions");
  };
  if (fixture.includes("safe-")) {
    const transactions = (await import(
      pathToFileURL(resolve(sourceRoot, "transactions.js")).href
    )) as Record<string, unknown>;
    createTransactions = transactions[
      "createLinkTransactionStore"
    ] as () => LinkTransactionStore;
  }
  return {
    begin: linking["beginExternalIdentityLink"] as (
      identityProvider: IdentityProvider,
      transactionsOrSession: LinkTransactionStore | Session,
      session?: Session,
    ) => AuthorizationRequest,
    challengeFor: identityProvider["challengeFor"] as (
      verifier: string,
    ) => string,
    complete: linking["completeExternalIdentityLink"] as (
      identityProvider: IdentityProvider,
      accounts: AccountStore,
      transactionsOrSession: LinkTransactionStore | Session,
      sessionOrRequest: Session | { code: string; state?: string },
      request?: { code: string; state?: string },
    ) => Account | null,
    createAccountStore: accounts["createAccountStore"] as (
      accountIds: string[],
    ) => AccountStore,
    createIdentityProvider: identityProvider[
      "createIdentityProvider"
    ] as () => IdentityProvider,
    createTransactions,
    issuer: identityProvider["IDENTITY_ISSUER"] as string,
  };
}
