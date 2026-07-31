import { createHmac, timingSafeEqual } from "node:crypto";

const MAX_BODY_BYTES = 64 * 1024;
const MAX_CLOCK_SKEW_SECONDS = 300;

function parseSignatureHeader(header) {
  if (typeof header !== "string" || header.length > 512) {
    throw new Error("invalid webhook signature header");
  }
  const fields = new Map();
  for (const part of header.split(",")) {
    const separator = part.indexOf("=");
    if (separator <= 0) throw new Error("invalid webhook signature header");
    const name = part.slice(0, separator);
    const value = part.slice(separator + 1);
    if (fields.has(name)) throw new Error("duplicate webhook signature field");
    fields.set(name, value);
  }
  const timestampText = fields.get("t");
  const signature = fields.get("v1");
  if (
    fields.size !== 2 ||
    !/^[0-9]{1,12}$/.test(timestampText ?? "") ||
    !/^[a-f0-9]{64}$/.test(signature ?? "")
  ) {
    throw new Error("invalid webhook signature header");
  }
  return { timestamp: Number(timestampText), signature };
}

function sameHex(left, right) {
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return (
    leftBytes.length === rightBytes.length &&
    leftBytes.length === 32 &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function verifyFreshSignedPayload(
  rawBody,
  signatureHeader,
  secret,
  nowSeconds,
) {
  if (
    typeof rawBody !== "string" ||
    Buffer.byteLength(rawBody) > MAX_BODY_BYTES
  ) {
    throw new Error("invalid webhook body");
  }
  const { timestamp, signature } = parseSignatureHeader(signatureHeader);
  if (
    !Number.isSafeInteger(nowSeconds) ||
    !Number.isSafeInteger(timestamp) ||
    Math.abs(nowSeconds - timestamp) > MAX_CLOCK_SKEW_SECONDS
  ) {
    throw new Error("stale webhook signature");
  }
  const expected = createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");
  if (!sameHex(signature, expected)) {
    throw new Error("invalid webhook signature");
  }
}

function parseSettlement(rawBody) {
  const event = JSON.parse(rawBody);
  if (
    event === null ||
    typeof event !== "object" ||
    typeof event.id !== "string" ||
    !/^evt_[A-Za-z0-9_-]{1,120}$/.test(event.id) ||
    event.type !== "payment.settled" ||
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

export class PaymentLedger {
  #balances = new Map();
  #processedEventIds = new Set();

  applyCreditOnce(eventId, accountId, amountCents) {
    if (this.#processedEventIds.has(eventId)) {
      return { applied: false, balance: this.balance(accountId) };
    }
    this.#processedEventIds.add(eventId);
    const balance = this.balance(accountId) + amountCents;
    this.#balances.set(accountId, balance);
    return { applied: true, balance };
  }

  balance(accountId) {
    return this.#balances.get(accountId) ?? 0;
  }
}

export function handlePaymentWebhook(
  { rawBody, signatureHeader },
  { secret, ledger, nowSeconds },
) {
  verifyFreshSignedPayload(rawBody, signatureHeader, secret, nowSeconds);
  const event = parseSettlement(rawBody);
  return ledger.applyCreditOnce(
    event.id,
    event.data.accountId,
    event.data.amountCents,
  );
}
