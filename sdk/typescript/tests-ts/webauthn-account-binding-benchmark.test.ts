import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const repositoryRoot = join(PLUGIN_ROOT, "..", "..", "..");

type User = { id: string; username: string };
type Registration = {
  credentialId: string;
  ownerId: string;
  publicKey: object;
};
type Authenticator = {
  registration: Registration;
  signAssertion(challenge: string, origin: string, rpId: string): string;
};
type State = {
  sessions: Map<string, { userId: string }>;
  transactions?: Map<string, unknown>;
};
type BeginResult = {
  transactionId?: string;
  challenge: string;
  allowedCredentialIds?: string[];
  origin: string;
  rpId: string;
};
type FinishResult = { sessionId: string; userId: string };
type ServerModule = {
  expectedOrigin: string;
  expectedRpId: string;
  createServerState(users: User[], registrations: Registration[]): State;
  beginLogin(state: State, username: string, now?: number): BeginResult;
  finishLogin(
    state: State,
    assertion: Record<string, unknown>,
    now?: number,
  ): FinishResult;
};

const victim: User = { id: "user-victim", username: "victim@example.test" };
const attacker: User = {
  id: "user-attacker",
  username: "attacker@example.test",
};

async function fixture(name: string): Promise<{
  server: ServerModule;
  victimAuthenticator: Authenticator;
  attackerAuthenticator: Authenticator;
  state: State;
}> {
  const sourceRoot = join(
    repositoryRoot,
    "benchmarks",
    "fixtures",
    name,
    "src",
  );
  const server = (await import(
    pathToFileURL(join(sourceRoot, "server.js")).href
  )) as ServerModule;
  const authenticatorModule = (await import(
    pathToFileURL(join(sourceRoot, "authenticator.js")).href
  )) as {
    createAuthenticator(credentialId: string, ownerId: string): Authenticator;
  };
  const victimAuthenticator = authenticatorModule.createAuthenticator(
    "credential-victim",
    victim.id,
  );
  const attackerAuthenticator = authenticatorModule.createAuthenticator(
    "credential-attacker",
    attacker.id,
  );
  return {
    server,
    victimAuthenticator,
    attackerAuthenticator,
    state: server.createServerState(
      [victim, attacker],
      [victimAuthenticator.registration, attackerAuthenticator.registration],
    ),
  };
}

describe("WebAuthn credential-to-account binding benchmark", () => {
  test("a valid attacker credential creates a victim session when identity is not bound", async () => {
    const vulnerable = await fixture("javascript-webauthn-account-misbinding");
    const options = vulnerable.server.beginLogin(
      vulnerable.state,
      victim.username,
    );
    const signature = vulnerable.attackerAuthenticator.signAssertion(
      options.challenge,
      options.origin,
      options.rpId,
    );

    const result = vulnerable.server.finishLogin(vulnerable.state, {
      username: victim.username,
      credentialId: vulnerable.attackerAuthenticator.registration.credentialId,
      challenge: options.challenge,
      origin: options.origin,
      rpId: options.rpId,
      signature,
    });

    expect(result.userId).toBe(victim.id);
    expect(vulnerable.state.sessions.get(result.sessionId)).toEqual({
      userId: victim.id,
    });
  });

  test("the vulnerable server really enforces RP context and the signature", async () => {
    const vulnerable = await fixture("javascript-webauthn-account-misbinding");
    const wrongOriginOptions = vulnerable.server.beginLogin(
      vulnerable.state,
      victim.username,
    );
    expect(() =>
      vulnerable.server.finishLogin(vulnerable.state, {
        username: victim.username,
        credentialId:
          vulnerable.attackerAuthenticator.registration.credentialId,
        challenge: wrongOriginOptions.challenge,
        origin: "https://attacker.example",
        rpId: wrongOriginOptions.rpId,
        signature: vulnerable.attackerAuthenticator.signAssertion(
          wrongOriginOptions.challenge,
          "https://attacker.example",
          wrongOriginOptions.rpId,
        ),
      }),
    ).toThrow("invalid relying party");

    const invalidSignatureOptions = vulnerable.server.beginLogin(
      vulnerable.state,
      victim.username,
    );
    expect(() =>
      vulnerable.server.finishLogin(vulnerable.state, {
        username: victim.username,
        credentialId:
          vulnerable.attackerAuthenticator.registration.credentialId,
        challenge: invalidSignatureOptions.challenge,
        origin: invalidSignatureOptions.origin,
        rpId: invalidSignatureOptions.rpId,
        signature: vulnerable.attackerAuthenticator.signAssertion(
          invalidSignatureOptions.challenge + "-different",
          invalidSignatureOptions.origin,
          invalidSignatureOptions.rpId,
        ),
      }),
    ).toThrow("invalid signature");
  });

  test("the safe transaction rejects substitution and still accepts the bound credential", async () => {
    const safe = await fixture("javascript-safe-webauthn-account-binding");
    const options = safe.server.beginLogin(safe.state, victim.username, 1_000);

    expect(options.allowedCredentialIds).toEqual([
      safe.victimAuthenticator.registration.credentialId,
    ]);
    expect(() =>
      safe.server.finishLogin(
        safe.state,
        {
          transactionId: options.transactionId,
          credentialId: safe.attackerAuthenticator.registration.credentialId,
          origin: options.origin,
          rpId: options.rpId,
          signature: safe.attackerAuthenticator.signAssertion(
            options.challenge,
            options.origin,
            options.rpId,
          ),
        },
        2_000,
      ),
    ).toThrow("credential is not bound to this account");

    const result = safe.server.finishLogin(
      safe.state,
      {
        transactionId: options.transactionId,
        credentialId: safe.victimAuthenticator.registration.credentialId,
        origin: options.origin,
        rpId: options.rpId,
        signature: safe.victimAuthenticator.signAssertion(
          options.challenge,
          options.origin,
          options.rpId,
        ),
      },
      2_000,
    );
    expect(result.userId).toBe(victim.id);
  });

  test("the safe server derives an attacker session only from the attacker's bound transaction", async () => {
    const safe = await fixture("javascript-safe-webauthn-account-binding");
    const options = safe.server.beginLogin(safe.state, attacker.username);
    const assertion = {
      transactionId: options.transactionId,
      credentialId: safe.attackerAuthenticator.registration.credentialId,
      origin: options.origin,
      rpId: options.rpId,
      signature: safe.attackerAuthenticator.signAssertion(
        options.challenge,
        options.origin,
        options.rpId,
      ),
    };

    const result = safe.server.finishLogin(safe.state, assertion);
    expect(result.userId).toBe(attacker.id);
    expect(safe.state.sessions.get(result.sessionId)).toEqual({
      userId: attacker.id,
    });
    expect(() => safe.server.finishLogin(safe.state, assertion)).toThrow(
      "invalid transaction",
    );
  });

  test("the safe server rejects expired transactions and wrong relying-party context", async () => {
    const safe = await fixture("javascript-safe-webauthn-account-binding");
    const expired = safe.server.beginLogin(safe.state, victim.username, 1_000);
    expect(() =>
      safe.server.finishLogin(
        safe.state,
        {
          transactionId: expired.transactionId,
          credentialId: safe.victimAuthenticator.registration.credentialId,
          origin: expired.origin,
          rpId: expired.rpId,
          signature: safe.victimAuthenticator.signAssertion(
            expired.challenge,
            expired.origin,
            expired.rpId,
          ),
        },
        1_000 + 5 * 60 * 1_000 + 1,
      ),
    ).toThrow("invalid transaction");

    const wrongRp = safe.server.beginLogin(safe.state, victim.username, 1_000);
    expect(() =>
      safe.server.finishLogin(
        safe.state,
        {
          transactionId: wrongRp.transactionId,
          credentialId: safe.victimAuthenticator.registration.credentialId,
          origin: wrongRp.origin,
          rpId: "attacker.example",
          signature: safe.victimAuthenticator.signAssertion(
            wrongRp.challenge,
            wrongRp.origin,
            "attacker.example",
          ),
        },
        2_000,
      ),
    ).toThrow("invalid relying party");
  });
});
