import { createHash, verify } from "node:crypto";

const MAX_BODY_BYTES = 64 * 1024;
const MAX_CLOCK_SKEW_SECONDS = 300;

function decodeSignature(signatureBase64) {
  if (
    typeof signatureBase64 !== "string" ||
    signatureBase64.length < 8 ||
    signatureBase64.length > 120 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64)
  ) {
    throw new Error("invalid webhook signature encoding");
  }
  const signature = Buffer.from(signatureBase64, "base64");
  if (
    signature.length < 8 ||
    signature.length > 80 ||
    signature.toString("base64") !== signatureBase64
  ) {
    throw new Error("invalid webhook signature encoding");
  }
  return signature;
}

function parseSettlement(rawBody, nowSeconds) {
  if (
    typeof rawBody !== "string" ||
    Buffer.byteLength(rawBody) > MAX_BODY_BYTES ||
    !Number.isSafeInteger(nowSeconds)
  ) {
    throw new Error("invalid webhook request");
  }
  const event = JSON.parse(rawBody);
  if (
    event === null ||
    typeof event !== "object" ||
    typeof event.id !== "string" ||
    !/^evt_[A-Za-z0-9_-]{1,120}$/.test(event.id) ||
    event.type !== "payment.settled" ||
    !Number.isSafeInteger(event.issuedAt) ||
    Math.abs(nowSeconds - event.issuedAt) > MAX_CLOCK_SKEW_SECONDS ||
    event.data === null ||
    typeof event.data !== "object" ||
    typeof event.data.accountId !== "string" ||
    !/^acct_[A-Za-z0-9_-]{1,120}$/.test(event.data.accountId) ||
    !Number.isSafeInteger(event.data.amountCents) ||
    event.data.amountCents <= 0 ||
    event.data.amountCents > 10_000_000 ||
    event.data.currency !== "USD"
  ) {
    throw new Error("invalid settlement event");
  }
  return event;
}

export class SettlementLedger {
  #balances = new Map();
  #consumedSignatureDigests = new Set();

  applySignatureOnce(signature, accountId, amountCents) {
    const replayKey = createHash("sha256").update(signature).digest("hex");
    if (this.#consumedSignatureDigests.has(replayKey)) {
      return { applied: false, balance: this.balance(accountId) };
    }
    this.#consumedSignatureDigests.add(replayKey);
    const balance = this.balance(accountId) + amountCents;
    this.#balances.set(accountId, balance);
    return { applied: true, balance };
  }

  balance(accountId) {
    return this.#balances.get(accountId) ?? 0;
  }
}

export function handleSettlementWebhook(
  { rawBody, signatureBase64 },
  { publicKey, ledger, nowSeconds },
) {
  const signature = decodeSignature(signatureBase64);
  if (!verify("sha256", rawBody, publicKey, signature)) {
    throw new Error("invalid webhook signature");
  }
  const event = parseSettlement(rawBody, nowSeconds);
  return ledger.applySignatureOnce(
    signature,
    event.data.accountId,
    event.data.amountCents,
  );
}
