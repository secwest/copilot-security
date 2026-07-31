import { createHmac } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const repositoryRoot = join(PLUGIN_ROOT, "..", "..", "..");
const vulnerablePath = join(
  repositoryRoot,
  "benchmarks",
  "fixtures",
  "javascript-signed-webhook-replay",
  "src",
  "webhook.js",
);
const safePath = join(
  repositoryRoot,
  "benchmarks",
  "fixtures",
  "javascript-safe-signed-webhook",
  "src",
  "webhook.js",
);

const secret = "benchmark-webhook-secret-with-32-bytes";
const nowSeconds = 2_000_000_000;

function signedRequest(rawBody: string, timestamp = nowSeconds, key = secret) {
  const signature = createHmac("sha256", key)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");
  return {
    rawBody,
    signatureHeader: `t=${timestamp},v1=${signature}`,
  };
}

function settlement(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    id: "evt_settlement_001",
    type: "payment.settled",
    data: {
      accountId: "acct_attacker_wallet",
      amountCents: 50_000,
      currency: "USD",
    },
    ...overrides,
  });
}

describe("signed webhook replay benchmark", () => {
  test("a captured valid settlement credits the vulnerable ledger repeatedly", async () => {
    const vulnerable = await import(pathToFileURL(vulnerablePath).href);
    const ledger = new vulnerable.PaymentLedger();
    const request = signedRequest(settlement(), nowSeconds - 86_400);

    expect(
      vulnerable.handlePaymentWebhook(request, { secret, ledger }),
    ).toEqual({ balance: 50_000 });
    expect(
      vulnerable.handlePaymentWebhook(request, { secret, ledger }),
    ).toEqual({ balance: 100_000 });
    expect(ledger.balance("acct_attacker_wallet")).toBe(100_000);

    const tampered = { ...request, rawBody: settlement({ id: "evt_other" }) };
    expect(() =>
      vulnerable.handlePaymentWebhook(tampered, { secret, ledger }),
    ).toThrow("invalid webhook signature");
  });

  test("the safe handler binds freshness and atomically consumes the event ID", async () => {
    const safe = await import(pathToFileURL(safePath).href);
    const ledger = new safe.PaymentLedger();
    const request = signedRequest(settlement());

    expect(
      safe.handlePaymentWebhook(request, { secret, ledger, nowSeconds }),
    ).toEqual({ applied: true, balance: 50_000 });
    expect(
      safe.handlePaymentWebhook(request, { secret, ledger, nowSeconds }),
    ).toEqual({ applied: false, balance: 50_000 });
    expect(ledger.balance("acct_attacker_wallet")).toBe(50_000);

    for (const rejected of [
      signedRequest(settlement(), nowSeconds - 301),
      signedRequest(settlement(), nowSeconds + 301),
      signedRequest(settlement(), nowSeconds, "wrong-signing-secret"),
      { ...request, rawBody: settlement({ id: "evt_tampered" }) },
      { ...request, signatureHeader: `${request.signatureHeader},v1=00` },
      signedRequest(settlement({ id: "" })),
      signedRequest(
        settlement({
          data: {
            accountId: "acct_attacker_wallet",
            amountCents: -1,
            currency: "USD",
          },
        }),
      ),
      signedRequest("x".repeat(64 * 1024 + 1)),
    ]) {
      expect(() =>
        safe.handlePaymentWebhook(rejected, { secret, ledger, nowSeconds }),
      ).toThrow();
    }

    expect(ledger.balance("acct_attacker_wallet")).toBe(50_000);
  });
});
