import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const repositoryRoot = join(PLUGIN_ROOT, "..", "..", "..");
const vulnerablePath = join(
  repositoryRoot,
  "benchmarks",
  "fixtures",
  "javascript-forwarded-client-rate-limit-bypass",
  "src",
  "recovery.js",
);
const safePath = join(
  repositoryRoot,
  "benchmarks",
  "fixtures",
  "javascript-safe-forwarded-client-budget",
  "src",
  "recovery.js",
);

type RecoveryRequest = {
  peerAddress: string;
  headers: Record<string, string>;
  accountId: string;
  recoveryCode: string;
  newPassword: string;
};

type Gateway = {
  recover(request: RecoveryRequest): { status: number };
  passwordFor(accountId: string): string | undefined;
  attemptsFor?(clientAddress: string): number;
  attemptsForAccount?(accountId: string): number;
  attemptsForClient?(clientAddress: string): number;
};

type GatewayConstructor = new (options: {
  recoveryCodes: Map<string, string>;
  trustedProxies?: Set<string>;
}) => Gateway;

const victim = "victim@example.test";
const actualClient = "203.0.113.44";
const trustedIngress = "10.0.0.8";

function recoveryRequest(
  spoofedFirstHop: string,
  recoveryCode: string,
  peerAddress = trustedIngress,
): RecoveryRequest {
  return {
    peerAddress,
    headers: {
      "x-forwarded-for": `${spoofedFirstHop}, ${actualClient}`,
    },
    accountId: victim,
    recoveryCode,
    newPassword: "attacker-selected-password",
  };
}

async function gatewayConstructor(path: string): Promise<GatewayConstructor> {
  const module = (await import(pathToFileURL(path).href)) as {
    RecoveryGateway: GatewayConstructor;
  };
  return module.RecoveryGateway;
}

describe("forwarded client identity benchmark fixtures", () => {
  test("attacker-controlled leftmost forwarding hops bypass the vulnerable client budget", async () => {
    const RecoveryGateway = await gatewayConstructor(vulnerablePath);
    const gateway = new RecoveryGateway({
      recoveryCodes: new Map([[victim, "correct-code"]]),
    });

    for (let attempt = 1; attempt <= 3; attempt += 1) {
      expect(
        gateway.recover(
          recoveryRequest(`198.51.100.${attempt}`, `wrong-${attempt}`),
        ).status,
      ).toBe(401);
    }
    expect(
      gateway.recover(recoveryRequest("198.51.100.4", "correct-code")).status,
    ).toBe(200);
    expect(gateway.passwordFor(victim)).toBe("attacker-selected-password");
    expect(gateway.attemptsFor?.("198.51.100.1")).toBe(1);
    expect(gateway.attemptsFor?.("198.51.100.4")).toBe(1);
  });

  test("safe right-to-left proxy peeling binds spoof variants to one client and account", async () => {
    const RecoveryGateway = await gatewayConstructor(safePath);
    const gateway = new RecoveryGateway({
      recoveryCodes: new Map([[victim, "correct-code"]]),
      trustedProxies: new Set([trustedIngress]),
    });

    for (let attempt = 1; attempt <= 3; attempt += 1) {
      expect(
        gateway.recover(
          recoveryRequest(`198.51.100.${attempt}`, `wrong-${attempt}`),
        ).status,
      ).toBe(401);
    }
    expect(
      gateway.recover(recoveryRequest("198.51.100.4", "correct-code")).status,
    ).toBe(429);
    expect(gateway.passwordFor(victim)).toBeUndefined();
    expect(gateway.attemptsForClient?.(actualClient)).toBe(3);
    expect(gateway.attemptsForAccount?.(victim)).toBe(3);
  });

  test("safe gateway ignores forwarding metadata from an untrusted direct peer", async () => {
    const RecoveryGateway = await gatewayConstructor(safePath);
    const gateway = new RecoveryGateway({
      recoveryCodes: new Map([[victim, "correct-code"]]),
      trustedProxies: new Set([trustedIngress]),
    });
    const directPeer = "192.0.2.90";

    for (let attempt = 1; attempt <= 3; attempt += 1) {
      expect(
        gateway.recover(
          recoveryRequest(
            `198.51.100.${attempt}`,
            `wrong-${attempt}`,
            directPeer,
          ),
        ).status,
      ).toBe(401);
    }
    expect(
      gateway.recover(
        recoveryRequest("198.51.100.4", "correct-code", directPeer),
      ).status,
    ).toBe(429);
    expect(gateway.attemptsForClient?.(directPeer)).toBe(3);
    expect(gateway.passwordFor(victim)).toBeUndefined();
  });

  test("safe gateway rejects malformed forwarding chains without spending a guess", async () => {
    const RecoveryGateway = await gatewayConstructor(safePath);
    const gateway = new RecoveryGateway({
      recoveryCodes: new Map([[victim, "correct-code"]]),
      trustedProxies: new Set([trustedIngress]),
    });
    const malformed = recoveryRequest("198.51.100.1", "correct-code");
    malformed.headers["x-forwarded-for"] = "198.51.100.01, 203.0.113.44";
    const oversized = recoveryRequest("198.51.100.1", "correct-code");
    oversized.headers["x-forwarded-for"] = "1".repeat(513);

    expect(gateway.recover(malformed).status).toBe(400);
    expect(gateway.recover(oversized).status).toBe(400);
    expect(gateway.attemptsForAccount?.(victim)).toBe(0);
    expect(gateway.passwordFor(victim)).toBeUndefined();
  });

  test("safe gateway peels multiple exact trusted proxy hops from the right", async () => {
    const RecoveryGateway = await gatewayConstructor(safePath);
    const secondProxy = "10.0.0.7";
    const gateway = new RecoveryGateway({
      recoveryCodes: new Map([[victim, "correct-code"]]),
      trustedProxies: new Set([trustedIngress, secondProxy]),
    });
    const request = recoveryRequest("198.51.100.200", "correct-code");
    request.headers["x-forwarded-for"] =
      `198.51.100.200, ${actualClient}, ${secondProxy}`;

    expect(gateway.recover(request).status).toBe(200);
    expect(gateway.attemptsForClient?.(actualClient)).toBe(1);
    expect(gateway.passwordFor(victim)).toBe("attacker-selected-password");
  });
});
