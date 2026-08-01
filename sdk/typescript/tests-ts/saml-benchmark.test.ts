import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const repositoryRoot = join(PLUGIN_ROOT, "..", "..", "..");
const now = 1_800_000_000_000;

type Assertion = {
  id: string;
  issuer: string;
  subject: string;
  audience: string;
  recipient: string;
  issuedAt: number;
  expiresAt: number;
  roles: string[];
};
type SamlResponse = {
  issuer: string;
  destination: string;
  inResponseTo: string;
  assertions: Assertion[];
  signature: {
    referenceId: string;
    algorithm: string;
    value: string;
  };
};
type IdentityProvider = {
  publicKey: object;
  issueResponse(input: {
    requestId: string;
    destination: string;
    audience: string;
    recipient?: string;
    subject: string;
    roles: string[];
    now: number;
  }): SamlResponse;
};
type SamlModule = {
  assertionConsumerUrl: string;
  serviceProviderEntityId: string;
  trustedIssuer: string;
  createServiceProvider(publicKey: object): {
    requests: Map<string, unknown>;
    sessions: Map<string, { userId: string; roles: string[] }>;
  };
  beginLogin(
    state: { requests: Map<string, unknown> },
    now?: number,
  ): { requestId: string; destination: string; audience: string };
  consumeResponse(
    state: {
      requests: Map<string, unknown>;
      sessions: Map<string, { userId: string; roles: string[] }>;
    },
    response: SamlResponse,
    now?: number,
  ): { sessionId: string; userId: string; roles: string[] };
};

async function fixture(name: string): Promise<{
  identityProvider: IdentityProvider;
  saml: SamlModule;
  state: ReturnType<SamlModule["createServiceProvider"]>;
}> {
  const sourceRoot = join(
    repositoryRoot,
    "benchmarks",
    "fixtures",
    name,
    "src",
  );
  const identityProviderModule = (await import(
    pathToFileURL(join(sourceRoot, "identity-provider.js")).href
  )) as {
    createIdentityProvider(issuer: string): IdentityProvider;
  };
  const saml = (await import(
    pathToFileURL(join(sourceRoot, "saml.js")).href
  )) as SamlModule;
  const identityProvider = identityProviderModule.createIdentityProvider(
    saml.trustedIssuer,
  );
  return {
    identityProvider,
    saml,
    state: saml.createServiceProvider(identityProvider.publicKey),
  };
}

function legitimateResponse(
  current: Awaited<ReturnType<typeof fixture>>,
  options: {
    subject?: string;
    roles?: string[];
    audience?: string;
    recipient?: string;
    issuedAt?: number;
  } = {},
): SamlResponse {
  const request = current.saml.beginLogin(current.state, now);
  return current.identityProvider.issueResponse({
    requestId: request.requestId,
    destination: request.destination,
    audience: options.audience ?? request.audience,
    recipient: options.recipient,
    subject: options.subject ?? "user-attacker",
    roles: options.roles ?? ["viewer"],
    now: options.issuedAt ?? now,
  });
}

function wrapped(response: SamlResponse): SamlResponse {
  const signed = response.assertions[0]!;
  const unsignedAdministrator: Assertion = {
    ...signed,
    id: "unsigned-administrator-assertion",
    subject: "user-victim-administrator",
    roles: ["administrator"],
  };
  return { ...response, assertions: [unsignedAdministrator, signed] };
}

describe("SAML signed-assertion identity binding benchmark", () => {
  test("a real attacker signature authorizes an unsigned wrapped administrator assertion", async () => {
    const vulnerable = await fixture("javascript-saml-signature-wrapping");
    const response = wrapped(legitimateResponse(vulnerable));

    const result = vulnerable.saml.consumeResponse(
      vulnerable.state,
      response,
      now + 1_000,
    );

    expect(result.userId).toBe("user-victim-administrator");
    expect(result.roles).toEqual(["administrator"]);
    expect(vulnerable.state.sessions.get(result.sessionId)).toEqual({
      userId: "user-victim-administrator",
      roles: ["administrator"],
    });
  });

  test("the vulnerable service provider still enforces signatures and relying-party context", async () => {
    const vulnerable = await fixture("javascript-saml-signature-wrapping");
    const tampered = legitimateResponse(vulnerable);
    tampered.assertions = [
      { ...tampered.assertions[0]!, subject: "tampered-subject" },
    ];
    expect(() =>
      vulnerable.saml.consumeResponse(vulnerable.state, tampered, now + 1_000),
    ).toThrow("invalid SAML signature");

    const wrongAudience = legitimateResponse(vulnerable, {
      audience: "https://attacker.example/saml/metadata",
    });
    expect(() =>
      vulnerable.saml.consumeResponse(
        vulnerable.state,
        wrongAudience,
        now + 1_000,
      ),
    ).toThrow("invalid signed assertion context");

    const wrongRecipient = legitimateResponse(vulnerable, {
      recipient: "https://attacker.example/saml/acs",
    });
    expect(() =>
      vulnerable.saml.consumeResponse(
        vulnerable.state,
        wrongRecipient,
        now + 1_000,
      ),
    ).toThrow("invalid signed assertion context");
  });

  test("the safe service provider rejects wrapping and accepts the signed account", async () => {
    const safe = await fixture("javascript-safe-saml-assertion-binding");
    const response = legitimateResponse(safe);
    expect(() =>
      safe.saml.consumeResponse(safe.state, wrapped(response), now + 1_000),
    ).toThrow("exactly one assertion");

    const valid = legitimateResponse(safe);
    const result = safe.saml.consumeResponse(safe.state, valid, now + 1_000);
    expect(result.userId).toBe("user-attacker");
    expect(result.roles).toEqual(["viewer"]);
  });

  test("the safe service provider rejects reference confusion, modification, expiry, and replay", async () => {
    const safe = await fixture("javascript-safe-saml-assertion-binding");
    const wrongReference = legitimateResponse(safe);
    wrongReference.signature = {
      ...wrongReference.signature,
      referenceId: "different-assertion",
    };
    expect(() =>
      safe.saml.consumeResponse(safe.state, wrongReference, now + 1_000),
    ).toThrow("does not bind");

    const modified = legitimateResponse(safe);
    modified.assertions[0] = {
      ...modified.assertions[0]!,
      roles: ["administrator"],
    };
    expect(() =>
      safe.saml.consumeResponse(safe.state, modified, now + 1_000),
    ).toThrow("invalid SAML signature");

    const expired = legitimateResponse(safe, {
      issuedAt: now - 10 * 60 * 1_000,
    });
    expect(() =>
      safe.saml.consumeResponse(safe.state, expired, now + 1_000),
    ).toThrow("invalid signed assertion context");

    const replayed = legitimateResponse(safe);
    safe.saml.consumeResponse(safe.state, replayed, now + 1_000);
    expect(() =>
      safe.saml.consumeResponse(safe.state, replayed, now + 2_000),
    ).toThrow("invalid authentication request");
  });
});
