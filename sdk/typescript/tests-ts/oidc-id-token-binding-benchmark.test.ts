import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { PLUGIN_ROOT } from "./plugin-root.js";

const repositoryRoot = join(PLUGIN_ROOT, "..", "..", "..");
const vulnerableRoot = join(
  repositoryRoot,
  "benchmarks",
  "fixtures",
  "javascript-oidc-id-token-misbinding",
  "src",
);
const safeRoot = join(
  repositoryRoot,
  "benchmarks",
  "fixtures",
  "javascript-safe-oidc-id-token-binding",
  "src",
);

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signIdToken(
  claims: Record<string, unknown>,
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"],
): string {
  const header = encodeJson({ alg: "EdDSA", typ: "JWT" });
  const payload = encodeJson(claims);
  const input = `${header}.${payload}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString("base64url")}`;
}

function accounts() {
  return {
    async findByFederatedIdentity(issuer: string, subject: string) {
      return issuer === "https://identity.example" && subject === "victim-sub"
        ? { id: "victim-account" }
        : null;
    },
  };
}

describe("OIDC ID-token binding benchmark", () => {
  test("a signed sibling-client token takes over the vulnerable session while the bound verifier rejects it", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const vulnerable = await import(
      pathToFileURL(join(vulnerableRoot, "login.js")).href
    );
    const safe = await import(pathToFileURL(join(safeRoot, "login.js")).href);
    const nowSeconds = 2_000_000_000;

    const siblingToken = signIdToken(
      {
        iss: "https://identity.example",
        sub: "victim-sub",
        aud: "expenses-client",
        azp: "expenses-client",
        nonce: "sibling-client-nonce",
        exp: nowSeconds + 300,
        iat: nowSeconds,
      },
      privateKey,
    );

    const vulnerableSession: Record<string, unknown> = {
      id: "attacker-browser",
    };
    const vulnerableRequest = vulnerable.beginLogin(vulnerableSession);
    await expect(
      vulnerable.finishLogin({
        session: vulnerableSession,
        response: {
          state: vulnerableRequest.state,
          idToken: siblingToken,
        },
        publicKey,
        accounts: accounts(),
        nowSeconds,
      }),
    ).resolves.toEqual({ accountId: "victim-account" });
    expect(vulnerableSession["accountId"]).toBe("victim-account");

    const safeSession: Record<string, unknown> = { id: "attacker-browser" };
    const safeRequest = safe.beginLogin(safeSession, nowSeconds);
    await expect(
      safe.finishLogin({
        session: safeSession,
        response: { state: safeRequest.state, idToken: siblingToken },
        publicKey,
        accounts: accounts(),
        nowSeconds,
      }),
    ).rejects.toThrow("invalid ID token trust or transaction binding");
    expect(safeSession["accountId"]).toBeUndefined();
  });

  test("the safe verifier binds audience, azp, nonce, state, lifetime, issuer, signature, and replay", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const safe = await import(pathToFileURL(join(safeRoot, "login.js")).href);
    const nowSeconds = 2_000_000_000;

    const attempt = async (
      claims: Record<string, unknown>,
      overrides: Record<string, unknown> = {},
    ) => {
      const session: Record<string, unknown> = { id: "browser-session" };
      const request = safe.beginLogin(session, nowSeconds);
      const token = signIdToken(
        {
          iss: "https://identity.example",
          sub: "victim-sub",
          aud: "payroll-client",
          azp: "payroll-client",
          nonce: request.nonce,
          exp: nowSeconds + 300,
          iat: nowSeconds,
          ...claims,
        },
        privateKey,
      );
      return {
        request,
        session,
        finish: () =>
          safe.finishLogin({
            session,
            response: { state: request.state, idToken: token, ...overrides },
            publicKey,
            accounts: accounts(),
            nowSeconds,
          }),
      };
    };

    for (const claims of [
      { aud: "expenses-client", azp: "expenses-client" },
      { aud: ["payroll-client", "expenses-client"], azp: "expenses-client" },
      { aud: ["payroll-client", "expenses-client"], azp: undefined },
      { nonce: "another-browser-nonce" },
      { nonce: undefined },
      { iss: "https://attacker.example" },
      { exp: nowSeconds },
    ]) {
      const rejected = await attempt(claims);
      await expect(rejected.finish()).rejects.toThrow();
      expect(rejected.session["accountId"]).toBeUndefined();
    }

    const badState = await attempt({}, { state: "attacker-state" });
    await expect(badState.finish()).rejects.toThrow(
      "invalid or expired OIDC login transaction",
    );

    const valid = await attempt({});
    await expect(valid.finish()).resolves.toEqual({
      accountId: "victim-account",
    });
    await expect(valid.finish()).rejects.toThrow(
      "invalid or expired OIDC login transaction",
    );

    const wrongSignature = await attempt({});
    const anotherKey = generateKeyPairSync("ed25519").privateKey;
    const wrongSignatureToken = signIdToken(
      {
        iss: "https://identity.example",
        sub: "victim-sub",
        aud: "payroll-client",
        nonce: wrongSignature.request.nonce,
        exp: nowSeconds + 300,
      },
      anotherKey,
    );
    await expect(
      safe.finishLogin({
        session: wrongSignature.session,
        response: {
          state: wrongSignature.request.state,
          idToken: wrongSignatureToken,
        },
        publicKey,
        accounts: accounts(),
        nowSeconds,
      }),
    ).rejects.toThrow("invalid ID token signature");
  });
});
