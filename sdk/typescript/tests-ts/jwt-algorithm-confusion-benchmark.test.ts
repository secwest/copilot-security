import {
  createHmac,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface AccessTokenClaims {
  aud: string;
  exp: number;
  iss: string;
  role: string;
  sub: string;
}

interface TokenPolicy {
  expectedAudience: string;
  expectedIssuer: string;
  now: number;
  trustedKeys: Map<string, string>;
}

type TokenVerifier = (token: string, policy: TokenPolicy) => AccessTokenClaims;

type AuditExporter = (
  claims: AccessTokenClaims,
  database: { exportSigningAudit: () => string[] },
) => string[];

const NOW = 1_800_200_000;
const ISSUER = "https://identity.example.test";
const AUDIENCE = "secwest-control-plane";
const KEY_ID = "production-rsa-key";

test("token-selected HS256 reinterprets a public RSA key while algorithm and key-type binding stop the forgery", async () => {
  const vulnerable = await loadFixture("javascript-jwt-algorithm-confusion");
  const safe = await loadFixture("javascript-safe-jwt-algorithm-binding");
  const trusted = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicKey = publicKeyPem(trusted.publicKey);
  const policy = tokenPolicy(publicKey);
  const database = {
    exportSigningAudit: () => [
      "root-signing-key-rotation",
      "customer-token-revocations",
    ],
  };

  const forgedClaims = claims({
    role: "administrator",
    sub: "attacker@example.test",
  });
  const forgedToken = hs256Token(publicKey, forgedClaims);
  const acceptedForgery = vulnerable.verify(forgedToken, policy);
  expect(acceptedForgery).toEqual(forgedClaims);
  expect(vulnerable.exportAudit(acceptedForgery, database)).toEqual([
    "root-signing-key-rotation",
    "customer-token-revocations",
  ]);

  expect(() => safe.verify(forgedToken, policy)).toThrow("invalid JWT header");

  const viewerClaims = claims();
  const legitimateViewer = rs256Token(trusted.privateKey, viewerClaims);
  expect(safe.verify(legitimateViewer, policy)).toEqual(viewerClaims);
  expect(() =>
    safe.exportAudit(safe.verify(legitimateViewer, policy), database),
  ).toThrow("administrator role required");

  const administratorClaims = claims({
    role: "administrator",
    sub: "operator@example.test",
  });
  const legitimateAdministrator = rs256Token(
    trusted.privateKey,
    administratorClaims,
  );
  expect(
    safe.exportAudit(safe.verify(legitimateAdministrator, policy), database),
  ).toEqual(["root-signing-key-rotation", "customer-token-revocations"]);

  const [header, , signature] = legitimateViewer.split(".");
  const tamperedToken = `${header}.${encode(forgedClaims)}.${signature}`;
  expect(() => safe.verify(tamperedToken, policy)).toThrow(
    "invalid JWT signature",
  );

  const unknownKeyToken = rs256Token(trusted.privateKey, viewerClaims, {
    kid: "attacker-key",
  });
  expect(() => safe.verify(unknownKeyToken, policy)).toThrow(
    "JWT signing key not found",
  );

  const elliptic = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const ellipticPublicKey = publicKeyPem(elliptic.publicKey);
  expect(() =>
    safe.verify(
      rs256Token(trusted.privateKey, viewerClaims),
      tokenPolicy(ellipticPublicKey),
    ),
  ).toThrow("trusted JWT key must be an RSA public key");
});

async function loadFixture(fixture: string): Promise<{
  exportAudit: AuditExporter;
  verify: TokenVerifier;
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
  const admin = (await import(
    pathToFileURL(resolve(sourceRoot, "admin.js")).href
  )) as Record<string, unknown>;
  expect(typeof token["verifyAccessToken"]).toBe("function");
  expect(typeof admin["exportSigningAudit"]).toBe("function");
  return {
    exportAudit: admin["exportSigningAudit"] as AuditExporter,
    verify: token["verifyAccessToken"] as TokenVerifier,
  };
}

function tokenPolicy(publicKey: string): TokenPolicy {
  return {
    expectedAudience: AUDIENCE,
    expectedIssuer: ISSUER,
    now: NOW,
    trustedKeys: new Map([[KEY_ID, publicKey]]),
  };
}

function publicKeyPem(key: KeyObject): string {
  const pem = key.export({ format: "pem", type: "spki" });
  return typeof pem === "string" ? pem : pem.toString("utf8");
}

function claims(overrides: Partial<AccessTokenClaims> = {}): AccessTokenClaims {
  return {
    aud: AUDIENCE,
    exp: NOW + 300,
    iss: ISSUER,
    role: "viewer",
    sub: "viewer@example.test",
    ...overrides,
  };
}

function hs256Token(publicKey: string, tokenClaims: AccessTokenClaims): string {
  const signingInput = `${encode({
    alg: "HS256",
    kid: KEY_ID,
    typ: "JWT",
  })}.${encode(tokenClaims)}`;
  const signature = createHmac("sha256", publicKey)
    .update(signingInput, "ascii")
    .digest("base64url");
  return `${signingInput}.${signature}`;
}

function rs256Token(
  privateKey: KeyObject,
  tokenClaims: AccessTokenClaims,
  headerOverrides: Record<string, unknown> = {},
): string {
  const signingInput = `${encode({
    alg: "RS256",
    kid: KEY_ID,
    typ: "JWT",
    ...headerOverrides,
  })}.${encode(tokenClaims)}`;
  const signature = sign(
    "RSA-SHA256",
    Buffer.from(signingInput, "ascii"),
    privateKey,
  ).toString("base64url");
  return `${signingInput}.${signature}`;
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
