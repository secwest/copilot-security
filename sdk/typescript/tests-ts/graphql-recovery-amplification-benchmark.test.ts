import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface Selection {
  alias: string;
  field: string;
  arguments?: { accountId: string; code: string };
}

interface Response {
  status: number;
  body: {
    error?: string;
    data?: Record<
      string,
      {
        accepted?: boolean;
        available?: boolean;
        error?: string;
        resetToken?: string;
      }
    >;
  };
}

interface Recovery {
  verifyRecoveryCode(input: { accountId: string; code: string }): {
    accepted: boolean;
    error?: string;
    resetToken?: string;
  };
  resetPassword(input: {
    accountId: string;
    resetToken: string;
    newPassword: string;
  }): { changed: boolean; error?: string };
  failedAttemptsFor?(accountId: string): number;
  passwordFor(accountId: string): string | null;
}

interface Gateway {
  execute(request: {
    clientId: string;
    document: { selections: Selection[] };
  }): Response;
  chargedCost?(clientId: string): number;
  requestCount?(clientId: string): number;
}

interface Fixture {
  createGraphqlGateway(options: { recovery: Recovery }): Gateway;
  createRecoveryService(
    records: Array<{
      accountId: string;
      password: string;
      recoveryCode: string;
    }>,
  ): Recovery;
}

const accountId = "victim-account";
const originalPassword = "victim-original-password";
const attackerPassword = "attacker-selected-password";
const correctCode = "1404";
const guesses = ["1401", "1402", "1403", correctCode] as const;

test("GraphQL aliases bypass request-level recovery throttling while execution-plan and account limits stop the same attack", async () => {
  const vulnerable = await loadFixture(
    "javascript-graphql-recovery-amplification",
  );
  const vulnerableOrdinary = build(vulnerable);

  for (const code of guesses.slice(0, 3)) {
    expect(
      singleGuess(vulnerableOrdinary.gateway, "ordinary-client", code).status,
    ).toBe(200);
  }
  const blockedFourth = singleGuess(
    vulnerableOrdinary.gateway,
    "ordinary-client",
    guesses[3],
  );
  expect(blockedFourth.status).toBe(429);
  expect(vulnerableOrdinary.recovery.passwordFor(accountId)).toBe(
    originalPassword,
  );

  const vulnerableAliased = build(vulnerable);
  const amplified = vulnerableAliased.gateway.execute({
    clientId: "alias-attacker",
    document: {
      selections: guesses.map((code, index) => recoverySelection(index, code)),
    },
  });
  expect(amplified.status).toBe(200);
  expect(vulnerableAliased.gateway.requestCount?.("alias-attacker")).toBe(1);
  expect(amplified.body.data?.["guess4"]?.accepted).toBe(true);
  const stolenResetToken = amplified.body.data?.["guess4"]?.resetToken;
  expect(stolenResetToken).toBeString();
  expect(
    vulnerableAliased.recovery.resetPassword({
      accountId,
      resetToken: stolenResetToken!,
      newPassword: attackerPassword,
    }),
  ).toEqual({ changed: true });
  expect(vulnerableAliased.recovery.passwordFor(accountId)).toBe(
    attackerPassword,
  );

  const safe = await loadFixture("javascript-safe-graphql-recovery-limits");
  const safeAliased = build(safe);
  const rejectedBatch = safeAliased.gateway.execute({
    clientId: "alias-attacker",
    document: {
      selections: guesses.map((code, index) => recoverySelection(index, code)),
    },
  });
  expect(rejectedBatch).toEqual({
    status: 400,
    body: { error: "one_recovery_operation_per_request" },
  });
  expect(safeAliased.gateway.chargedCost?.("alias-attacker")).toBe(0);
  expect(safeAliased.recovery.failedAttemptsFor?.(accountId)).toBe(0);
  expect(safeAliased.recovery.passwordFor(accountId)).toBe(originalPassword);

  const distributed = build(safe);
  for (const [index, code] of guesses.slice(0, 3).entries()) {
    const result = singleGuess(
      distributed.gateway,
      `distributed-client-${index}`,
      code,
    );
    expect(result.body.data?.["guess1"]?.error).toBe("invalid_code");
  }
  const accountLimited = singleGuess(
    distributed.gateway,
    "distributed-client-4",
    guesses[3],
  );
  expect(accountLimited.body.data?.["guess1"]).toEqual({
    accepted: false,
    error: "too_many_attempts",
  });
  expect(distributed.recovery.failedAttemptsFor?.(accountId)).toBe(3);
  expect(distributed.recovery.passwordFor(accountId)).toBe(originalPassword);

  const legitimate = build(safe);
  const legitimateResponse = singleGuess(
    legitimate.gateway,
    "victim-client",
    guesses[3],
  );
  const legitimateToken = legitimateResponse.body.data?.["guess1"]?.resetToken;
  expect(legitimateToken).toBeString();
  expect(
    legitimate.recovery.resetPassword({
      accountId,
      resetToken: legitimateToken!,
      newPassword: "victim-new-password",
    }),
  ).toEqual({ changed: true });

  const safePublicBatch = legitimate.gateway.execute({
    clientId: "public-client",
    document: {
      selections: [
        { alias: "primary", field: "viewerStatus" },
        { alias: "secondary", field: "viewerStatus" },
      ],
    },
  });
  expect(safePublicBatch).toEqual({
    status: 200,
    body: {
      data: {
        primary: { available: true },
        secondary: { available: true },
      },
    },
  });
});

function build(fixture: Fixture) {
  const recovery = fixture.createRecoveryService([
    {
      accountId,
      password: originalPassword,
      recoveryCode: guesses[3],
    },
  ]);
  return {
    gateway: fixture.createGraphqlGateway({ recovery }),
    recovery,
  };
}

function singleGuess(gateway: Gateway, clientId: string, code: string) {
  return gateway.execute({
    clientId,
    document: { selections: [recoverySelection(0, code)] },
  });
}

function recoverySelection(index: number, code: string): Selection {
  return {
    alias: `guess${index + 1}`,
    field: "verifyRecoveryCode",
    arguments: { accountId, code },
  };
}

async function loadFixture(fixture: string): Promise<Fixture> {
  const sourceRoot = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
  );
  const graphql = (await import(
    pathToFileURL(resolve(sourceRoot, "graphql.js")).href
  )) as Record<string, unknown>;
  const recovery = (await import(
    pathToFileURL(resolve(sourceRoot, "recovery.js")).href
  )) as Record<string, unknown>;
  return {
    createGraphqlGateway: graphql[
      "createGraphqlGateway"
    ] as Fixture["createGraphqlGateway"],
    createRecoveryService: recovery[
      "createRecoveryService"
    ] as Fixture["createRecoveryService"],
  };
}
