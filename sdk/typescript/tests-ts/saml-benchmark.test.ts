import {
  generateKeyPairSync,
  sign as signBytes,
  verify as verifyBytes,
  type KeyObject,
} from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface AssertionClaims {
  audience: string;
  id: string;
  issuer: string;
  notBefore: number;
  notOnOrAfter: number;
  recipient: string;
  role: string;
  subject: string;
}

interface SamlAssertion {
  id: string;
  signedPayload: string;
  claims: AssertionClaims;
}

interface SamlResponse {
  assertions: SamlAssertion[];
  signature: {
    referenceId: string;
    signatureValue: string;
  };
}

type SignatureVerifier = (
  signedPayload: string,
  signatureValue: string,
) => boolean;

type VulnerableValidator = (
  response: SamlResponse,
  verifySignature: SignatureVerifier,
) => AssertionClaims;

interface SamlPolicy {
  verifySignature: SignatureVerifier;
  expectedIssuer: string;
  expectedAudience: string;
  expectedRecipient: string;
  now: number;
  replayCache: Set<string>;
}

type SafeValidator = (
  response: SamlResponse,
  policy: SamlPolicy,
) => AssertionClaims;

type SessionCreator = (claims: AssertionClaims) => {
  subject: string;
  role: string;
  issuer: string;
};

const NOW = 1_800_000_000;
const ISSUER = "https://identity.example.test";
const AUDIENCE = "urn:secwest:control-plane";
const RECIPIENT = "https://control.example.test/saml/acs";

test("SAML benchmark proves signed-versus-consumed assertion confusion and exact binding", async () => {
  const vulnerable = await loadFixture<VulnerableValidator>(
    "javascript-saml-signature-wrapping",
  );
  const safe = await loadFixture<SafeValidator>(
    "javascript-safe-saml-assertion-binding",
  );
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const verifySignature = signatureVerifier(publicKey);
  const signedUser = claims({
    id: "_signed-user",
    subject: "viewer@example.test",
    role: "viewer",
  });
  const unsignedAdministrator = claims({
    id: "_unsigned-administrator",
    subject: "attacker@example.test",
    role: "administrator",
  });
  const response = signedResponse(
    privateKey,
    signedUser,
    unsignedAdministrator,
  );

  const vulnerableClaims = vulnerable.validate(response, verifySignature);
  expect(vulnerable.createSession(vulnerableClaims)).toEqual({
    subject: "attacker@example.test",
    role: "administrator",
    issuer: ISSUER,
  });

  const replayCache = new Set<string>();
  const safeClaims = safe.validate(
    response,
    policy(verifySignature, replayCache),
  );
  expect(safe.createSession(safeClaims)).toEqual({
    subject: "viewer@example.test",
    role: "viewer",
    issuer: ISSUER,
  });
  expect(safeClaims).not.toBe(response.assertions[0]?.claims);
  expect(safeClaims).not.toBe(response.assertions[1]?.claims);

  expect(() =>
    safe.validate(response, policy(verifySignature, replayCache)),
  ).toThrow("signed assertion replay rejected");

  const wrongAudience = signedResponse(
    privateKey,
    claims({
      id: "_wrong-audience",
      audience: "urn:attacker:service",
    }),
    unsignedAdministrator,
  );
  expect(() =>
    safe.validate(wrongAudience, policy(verifySignature, new Set())),
  ).toThrow("signed assertion trust binding mismatch");

  const wrongRecipient = signedResponse(
    privateKey,
    claims({
      id: "_wrong-recipient",
      recipient: "https://attacker.example.test/saml/acs",
    }),
    unsignedAdministrator,
  );
  expect(() =>
    safe.validate(wrongRecipient, policy(verifySignature, new Set())),
  ).toThrow("signed assertion trust binding mismatch");

  const wrongIssuer = signedResponse(
    privateKey,
    claims({
      id: "_wrong-issuer",
      issuer: "https://attacker.example.test",
    }),
    unsignedAdministrator,
  );
  expect(() =>
    safe.validate(wrongIssuer, policy(verifySignature, new Set())),
  ).toThrow("signed assertion trust binding mismatch");

  const expired = signedResponse(
    privateKey,
    claims({
      id: "_expired",
      notBefore: NOW - 600,
      notOnOrAfter: NOW,
    }),
    unsignedAdministrator,
  );
  expect(() =>
    safe.validate(expired, policy(verifySignature, new Set())),
  ).toThrow("invalid signed assertion claims or lifetime");

  const tampered = signedResponse(
    privateKey,
    claims({ id: "_tampered" }),
    unsignedAdministrator,
  );
  tampered.assertions[1]!.signedPayload = JSON.stringify(
    claims({
      id: "_tampered",
      subject: "attacker@example.test",
      role: "administrator",
    }),
  );
  expect(() =>
    safe.validate(tampered, policy(verifySignature, new Set())),
  ).toThrow("invalid SAML assertion signature");

  const duplicateReference = signedResponse(
    privateKey,
    claims({ id: "_duplicate-reference" }),
    unsignedAdministrator,
  );
  duplicateReference.assertions.push({
    ...duplicateReference.assertions[1]!,
  });
  expect(() =>
    safe.validate(duplicateReference, policy(verifySignature, new Set())),
  ).toThrow("signature reference must select exactly one assertion");
});

async function loadFixture<
  Validator extends VulnerableValidator | SafeValidator,
>(
  fixture: string,
): Promise<{
  validate: Validator;
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
  const saml = (await import(
    pathToFileURL(resolve(sourceRoot, "saml.js")).href
  )) as Record<string, unknown>;
  const session = (await import(
    pathToFileURL(resolve(sourceRoot, "session.js")).href
  )) as Record<string, unknown>;
  expect(typeof saml["validateSamlResponse"]).toBe("function");
  expect(typeof session["createSession"]).toBe("function");
  return {
    validate: saml["validateSamlResponse"] as Validator,
    createSession: session["createSession"] as SessionCreator,
  };
}

function signedResponse(
  privateKey: KeyObject,
  signedClaims: AssertionClaims,
  unsignedClaims: AssertionClaims,
): SamlResponse {
  const signedPayload = JSON.stringify(signedClaims);
  return {
    assertions: [
      {
        id: unsignedClaims.id,
        signedPayload: JSON.stringify(unsignedClaims),
        claims: unsignedClaims,
      },
      {
        id: signedClaims.id,
        signedPayload,
        claims: unsignedClaims,
      },
    ],
    signature: {
      referenceId: signedClaims.id,
      signatureValue: signBytes(
        null,
        Buffer.from(signedPayload, "utf8"),
        privateKey,
      ).toString("base64"),
    },
  };
}

function signatureVerifier(publicKey: KeyObject): SignatureVerifier {
  return (signedPayload, signatureValue) =>
    verifyBytes(
      null,
      Buffer.from(signedPayload, "utf8"),
      publicKey,
      Buffer.from(signatureValue, "base64"),
    );
}

function policy(
  verifySignature: SignatureVerifier,
  replayCache: Set<string>,
): SamlPolicy {
  return {
    verifySignature,
    expectedIssuer: ISSUER,
    expectedAudience: AUDIENCE,
    expectedRecipient: RECIPIENT,
    now: NOW,
    replayCache,
  };
}

function claims(overrides: Partial<AssertionClaims> = {}): AssertionClaims {
  return {
    audience: AUDIENCE,
    id: "_assertion",
    issuer: ISSUER,
    notBefore: NOW - 60,
    notOnOrAfter: NOW + 300,
    recipient: RECIPIENT,
    role: "viewer",
    subject: "viewer@example.test",
    ...overrides,
  };
}
