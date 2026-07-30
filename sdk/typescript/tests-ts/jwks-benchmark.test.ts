import {
  generateKeyPairSync,
  sign as signBytes,
  type KeyObject,
} from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface IdTokenClaims {
  aud: string;
  exp: number;
  iat: number;
  iss: string;
  nonce: string;
  role: string;
  sub: string;
}

interface SigningJwk {
  alg: string;
  crv: string;
  kid: string;
  kty: string;
  use: string;
  x: string;
}

interface TokenPolicy {
  allowedJwksOrigin: string;
  expectedAudience: string;
  expectedIssuer: string;
  expectedJwksUri: string;
  fetchJwks: (uri: string) => Promise<{ keys: SigningJwk[] }>;
  maxTokenAgeSeconds: number;
  now: number;
  pendingNonces: Set<string>;
}

type TokenValidator = (
  token: string,
  policy: TokenPolicy,
) => Promise<IdTokenClaims>;

type SessionCreator = (claims: IdTokenClaims) => {
  subject: string;
  role: string;
  issuer: string;
};

const NOW = 1_800_100_000;
const ISSUER = "https://identity.example.test";
const AUDIENCE = "secwest-control-plane";
const JWKS_SERVICE_ORIGIN = "https://keys.example.test";
const TRUSTED_JWKS = `${JWKS_SERVICE_ORIGIN}/issuers/secwest/jwks.json`;
const ATTACKER_JWKS = `${JWKS_SERVICE_ORIGIN}/tenants/attacker/jwks.json`;

test("JWKS benchmark proves attacker-controlled key origin and pinned issuer keys", async () => {
  const vulnerable = await loadFixture("javascript-jwks-header-key-injection");
  const safe = await loadFixture("javascript-safe-jwks-key-origin");
  const trustedKeys = generateKeyPairSync("ed25519");
  const attackerKeys = generateKeyPairSync("ed25519");
  const trustedJwk = signingJwk(trustedKeys.publicKey, "trusted-key");
  const attackerJwk = signingJwk(attackerKeys.publicKey, "attacker-key");

  const forgedAdministrator = claims({
    nonce: "attacker-login",
    role: "administrator",
    sub: "attacker@example.test",
  });
  const attackerToken = signedToken(
    attackerKeys.privateKey,
    forgedAdministrator,
    {
      jku: ATTACKER_JWKS,
      kid: attackerJwk.kid,
    },
  );
  const vulnerableRequests: string[] = [];
  const vulnerableClaims = await vulnerable.validate(
    attackerToken,
    policy(
      keyServer(
        new Map([
          [ATTACKER_JWKS, [attackerJwk]],
          [TRUSTED_JWKS, [trustedJwk]],
        ]),
        vulnerableRequests,
      ),
      new Set([forgedAdministrator.nonce]),
    ),
  );
  expect(vulnerableRequests).toEqual([ATTACKER_JWKS]);
  expect(vulnerable.createSession(vulnerableClaims)).toEqual({
    subject: "attacker@example.test",
    role: "administrator",
    issuer: ISSUER,
  });

  const offOriginClaims = claims({ nonce: "off-origin" });
  const offOriginToken = signedToken(attackerKeys.privateKey, offOriginClaims, {
    jku: "https://internal.example.test/jwks.json",
    kid: attackerJwk.kid,
  });
  const offOriginRequests: string[] = [];
  await expect(
    vulnerable.validate(
      offOriginToken,
      policy(
        keyServer(
          new Map([["https://internal.example.test/jwks.json", [attackerJwk]]]),
          offOriginRequests,
        ),
        new Set([offOriginClaims.nonce]),
      ),
    ),
  ).rejects.toThrow("untrusted JWKS service origin");
  expect(offOriginRequests).toEqual([]);

  const rejectedRemoteRequests: string[] = [];
  await expect(
    safe.validate(
      attackerToken,
      policy(
        keyServer(
          new Map([
            [ATTACKER_JWKS, [attackerJwk]],
            [TRUSTED_JWKS, [trustedJwk]],
          ]),
          rejectedRemoteRequests,
        ),
        new Set([forgedAdministrator.nonce]),
      ),
    ),
  ).rejects.toThrow("untrusted remote key URL");
  expect(rejectedRemoteRequests).toEqual([]);

  const trustedViewer = claims({
    nonce: "trusted-login",
    role: "viewer",
    sub: "viewer@example.test",
  });
  const trustedToken = signedToken(trustedKeys.privateKey, trustedViewer, {
    kid: trustedJwk.kid,
  });
  const trustedRequests: string[] = [];
  const trustedPolicy = policy(
    keyServer(new Map([[TRUSTED_JWKS, [trustedJwk]]]), trustedRequests),
    new Set([trustedViewer.nonce]),
  );
  const trustedClaims = await safe.validate(trustedToken, trustedPolicy);
  expect(trustedRequests).toEqual([TRUSTED_JWKS]);
  expect(safe.createSession(trustedClaims)).toEqual({
    subject: "viewer@example.test",
    role: "viewer",
    issuer: ISSUER,
  });

  await expect(safe.validate(trustedToken, trustedPolicy)).rejects.toThrow(
    "invalid or replayed ID token nonce",
  );

  const wrongIssuer = claims({
    iss: "https://attacker.example.test",
    nonce: "wrong-issuer",
  });
  await expect(
    safe.validate(
      signedToken(trustedKeys.privateKey, wrongIssuer, {
        kid: trustedJwk.kid,
      }),
      policy(
        keyServer(new Map([[TRUSTED_JWKS, [trustedJwk]]]), []),
        new Set([wrongIssuer.nonce]),
      ),
    ),
  ).rejects.toThrow("invalid ID token trust binding or lifetime");

  const wrongAudience = claims({
    aud: "attacker-service",
    nonce: "wrong-audience",
  });
  await expect(
    safe.validate(
      signedToken(trustedKeys.privateKey, wrongAudience, {
        kid: trustedJwk.kid,
      }),
      policy(
        keyServer(new Map([[TRUSTED_JWKS, [trustedJwk]]]), []),
        new Set([wrongAudience.nonce]),
      ),
    ),
  ).rejects.toThrow("invalid ID token trust binding or lifetime");

  const expired = claims({
    exp: NOW,
    iat: NOW - 600,
    nonce: "expired",
  });
  await expect(
    safe.validate(
      signedToken(trustedKeys.privateKey, expired, {
        kid: trustedJwk.kid,
      }),
      policy(
        keyServer(new Map([[TRUSTED_JWKS, [trustedJwk]]]), []),
        new Set([expired.nonce]),
      ),
    ),
  ).rejects.toThrow("invalid ID token trust binding or lifetime");

  const tamperedClaims = claims({
    nonce: trustedViewer.nonce,
    role: "administrator",
    sub: "attacker@example.test",
  });
  const [trustedHeader, , trustedSignature] = trustedToken.split(".");
  const tamperedToken = `${trustedHeader}.${encode(tamperedClaims)}.${trustedSignature}`;
  await expect(
    safe.validate(
      tamperedToken,
      policy(
        keyServer(new Map([[TRUSTED_JWKS, [trustedJwk]]]), []),
        new Set([tamperedClaims.nonce]),
      ),
    ),
  ).rejects.toThrow("invalid JWT signature");

  await expect(
    safe.validate(
      trustedToken,
      policy(
        keyServer(
          new Map([[TRUSTED_JWKS, [trustedJwk, { ...trustedJwk }]]]),
          [],
        ),
        new Set([trustedViewer.nonce]),
      ),
    ),
  ).rejects.toThrow("JWT key identifier must select one trusted signing key");

  await expect(
    safe.validate(
      signedToken(trustedKeys.privateKey, claims({ nonce: "wrong-alg" }), {
        alg: "HS256",
        kid: trustedJwk.kid,
      }),
      policy(
        keyServer(new Map([[TRUSTED_JWKS, [trustedJwk]]]), []),
        new Set(["wrong-alg"]),
      ),
    ),
  ).rejects.toThrow("invalid JWT header");
});

async function loadFixture(fixture: string): Promise<{
  validate: TokenValidator;
  createSession: SessionCreator;
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
  const token = (await import(
    pathToFileURL(resolve(sourceRoot, "token.js")).href
  )) as Record<string, unknown>;
  const session = (await import(
    pathToFileURL(resolve(sourceRoot, "session.js")).href
  )) as Record<string, unknown>;
  expect(typeof token["verifyIdToken"]).toBe("function");
  expect(typeof session["createSession"]).toBe("function");
  return {
    validate: token["verifyIdToken"] as TokenValidator,
    createSession: session["createSession"] as SessionCreator,
  };
}

function signingJwk(publicKey: KeyObject, kid: string): SigningJwk {
  const exported = publicKey.export({ format: "jwk" });
  if (
    exported.kty !== "OKP" ||
    exported.crv !== "Ed25519" ||
    typeof exported.x !== "string"
  ) {
    throw new Error("expected an Ed25519 public JWK");
  }
  return {
    alg: "EdDSA",
    crv: exported.crv,
    kid,
    kty: exported.kty,
    use: "sig",
    x: exported.x,
  };
}

function signedToken(
  privateKey: KeyObject,
  tokenClaims: IdTokenClaims,
  headerOverrides: Record<string, unknown>,
): string {
  const encodedHeader = encode({
    alg: "EdDSA",
    typ: "JWT",
    ...headerOverrides,
  });
  const encodedPayload = encode(tokenClaims);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signBytes(
    null,
    Buffer.from(signingInput, "ascii"),
    privateKey,
  ).toString("base64url");
  return `${signingInput}.${signature}`;
}

function keyServer(
  routes: ReadonlyMap<string, SigningJwk[]>,
  requests: string[],
): TokenPolicy["fetchJwks"] {
  return async (uri) => {
    requests.push(uri);
    const keys = routes.get(uri);
    if (!keys) throw new Error("unrecognized JWKS endpoint");
    return { keys };
  };
}

function policy(
  fetchJwks: TokenPolicy["fetchJwks"],
  pendingNonces: Set<string>,
): TokenPolicy {
  return {
    allowedJwksOrigin: JWKS_SERVICE_ORIGIN,
    expectedAudience: AUDIENCE,
    expectedIssuer: ISSUER,
    expectedJwksUri: TRUSTED_JWKS,
    fetchJwks,
    maxTokenAgeSeconds: 300,
    now: NOW,
    pendingNonces,
  };
}

function claims(overrides: Partial<IdTokenClaims> = {}): IdTokenClaims {
  return {
    aud: AUDIENCE,
    exp: NOW + 300,
    iat: NOW - 30,
    iss: ISSUER,
    nonce: "login-nonce",
    role: "viewer",
    sub: "viewer@example.test",
    ...overrides,
  };
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
