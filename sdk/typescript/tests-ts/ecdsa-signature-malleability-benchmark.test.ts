import { generateKeyPairSync, sign } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const repositoryRoot = join(PLUGIN_ROOT, "..", "..", "..");
const vulnerablePath = join(
  repositoryRoot,
  "benchmarks",
  "fixtures",
  "javascript-ecdsa-signature-malleability-replay",
  "src",
  "webhook.js",
);
const safePath = join(
  repositoryRoot,
  "benchmarks",
  "fixtures",
  "javascript-safe-ecdsa-event-idempotency",
  "src",
  "webhook.js",
);

const P256_ORDER = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);
const nowSeconds = 2_000_000_000;

function settlement(id = "evt_settlement_ecdsa_001", issuedAt = nowSeconds) {
  return JSON.stringify({
    id,
    type: "payment.settled",
    issuedAt,
    data: {
      accountId: "acct_merchant_wallet",
      amountCents: 50_000,
      currency: "USD",
    },
  });
}

function request(rawBody: string, signature: Buffer) {
  return { rawBody, signatureBase64: signature.toString("base64") };
}

function malleateP256Der(signature: Buffer): Buffer {
  if (
    signature[0] !== 0x30 ||
    signature[1] !== signature.length - 2 ||
    signature[2] !== 0x02
  ) {
    throw new Error("unexpected ECDSA signature encoding");
  }
  const rLength = signature[3]!;
  const rStart = 4;
  const sTag = rStart + rLength;
  if (signature[sTag] !== 0x02) {
    throw new Error("unexpected ECDSA signature encoding");
  }
  const sLength = signature[sTag + 1]!;
  const sStart = sTag + 2;
  if (sStart + sLength !== signature.length) {
    throw new Error("unexpected ECDSA signature encoding");
  }

  const r = decodeInteger(signature.subarray(rStart, sTag));
  const s = decodeInteger(signature.subarray(sStart));
  if (r <= 0n || r >= P256_ORDER || s <= 0n || s >= P256_ORDER) {
    throw new Error("invalid ECDSA scalar");
  }
  return encodeDerSignature(r, P256_ORDER - s);
}

function decodeInteger(bytes: Buffer): bigint {
  if (bytes.length === 0) throw new Error("empty DER integer");
  return BigInt(`0x${bytes.toString("hex")}`);
}

function encodeDerSignature(r: bigint, s: bigint): Buffer {
  const encodedR = encodeInteger(r);
  const encodedS = encodeInteger(s);
  const body = Buffer.concat([
    Buffer.from([0x02, encodedR.length]),
    encodedR,
    Buffer.from([0x02, encodedS.length]),
    encodedS,
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function encodeInteger(value: bigint): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = `0${hex}`;
  let bytes = Buffer.from(hex, "hex");
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
  if ((bytes[0]! & 0x80) !== 0)
    bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return bytes;
}

describe("ECDSA signature-malleability replay benchmark", () => {
  test("a valid twin signature bypasses signature-byte replay identity", async () => {
    const vulnerable = await import(pathToFileURL(vulnerablePath).href);
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const rawBody = settlement();
    const signature = sign("sha256", Buffer.from(rawBody), privateKey);
    const twin = malleateP256Der(signature);
    const ledger = new vulnerable.SettlementLedger();

    expect(twin.equals(signature)).toBeFalse();
    expect(
      vulnerable.handleSettlementWebhook(request(rawBody, signature), {
        publicKey,
        ledger,
        nowSeconds,
      }),
    ).toEqual({ applied: true, balance: 50_000 });
    expect(
      vulnerable.handleSettlementWebhook(request(rawBody, twin), {
        publicKey,
        ledger,
        nowSeconds,
      }),
    ).toEqual({ applied: true, balance: 100_000 });
    expect(
      vulnerable.handleSettlementWebhook(request(rawBody, signature), {
        publicKey,
        ledger,
        nowSeconds,
      }),
    ).toEqual({ applied: false, balance: 100_000 });
    expect(ledger.balance("acct_merchant_wallet")).toBe(100_000);
  });

  test("signed event identity rejects both valid encodings as one operation", async () => {
    const safe = await import(pathToFileURL(safePath).href);
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const rawBody = settlement();
    const signature = sign("sha256", Buffer.from(rawBody), privateKey);
    const twin = malleateP256Der(signature);
    const ledger = new safe.SettlementLedger();

    expect(
      safe.handleSettlementWebhook(request(rawBody, signature), {
        publicKey,
        ledger,
        nowSeconds,
      }),
    ).toEqual({ applied: true, balance: 50_000 });
    expect(
      safe.handleSettlementWebhook(request(rawBody, twin), {
        publicKey,
        ledger,
        nowSeconds,
      }),
    ).toEqual({ applied: false, balance: 50_000 });
    expect(ledger.balance("acct_merchant_wallet")).toBe(50_000);
  });

  test("the safe boundary rejects stale, tampered, and wrongly signed events", async () => {
    const safe = await import(pathToFileURL(safePath).href);
    const trusted = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const attacker = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const ledger = new safe.SettlementLedger();
    const rawBody = settlement();
    const signature = sign("sha256", Buffer.from(rawBody), trusted.privateKey);

    for (const rejected of [
      request(
        settlement("evt_stale", nowSeconds - 301),
        sign(
          "sha256",
          Buffer.from(settlement("evt_stale", nowSeconds - 301)),
          trusted.privateKey,
        ),
      ),
      request(settlement("evt_tampered"), signature),
      request(
        rawBody,
        sign("sha256", Buffer.from(rawBody), attacker.privateKey),
      ),
      { rawBody, signatureBase64: `${signature.toString("base64")}=junk` },
      request(
        "x".repeat(64 * 1024 + 1),
        sign(
          "sha256",
          Buffer.from("x".repeat(64 * 1024 + 1)),
          trusted.privateKey,
        ),
      ),
    ]) {
      expect(() =>
        safe.handleSettlementWebhook(rejected, {
          publicKey: trusted.publicKey,
          ledger,
          nowSeconds,
        }),
      ).toThrow();
    }
    expect(ledger.balance("acct_merchant_wallet")).toBe(0);
  });

  test("the safe event key permits a distinct signed settlement", async () => {
    const safe = await import(pathToFileURL(safePath).href);
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const ledger = new safe.SettlementLedger();

    for (const [id, balance] of [
      ["evt_settlement_ecdsa_001", 50_000],
      ["evt_settlement_ecdsa_002", 100_000],
    ] as const) {
      const rawBody = settlement(id);
      expect(
        safe.handleSettlementWebhook(
          request(rawBody, sign("sha256", Buffer.from(rawBody), privateKey)),
          { publicKey, ledger, nowSeconds },
        ),
      ).toEqual({ applied: true, balance });
    }
  });
});
