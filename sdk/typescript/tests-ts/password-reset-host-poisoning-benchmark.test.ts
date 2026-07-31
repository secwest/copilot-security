import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface AccountStore {
  changePassword(accountId: string, password: string): Promise<boolean>;
  findByEmail(
    email: string,
  ): { email: string; id: string; role: string } | null;
  passwordHashFor(accountId: string): string | null;
}

interface Fixture {
  complete(
    request: { body: { newPassword?: string; token?: string | null } },
    response: ResponseRecorder,
    accounts: AccountStore,
    resetTokens: ResetTokenStore,
  ): Promise<ResponseRecorder>;
  createAccounts(
    records: Array<{
      email: string;
      id: string;
      passwordHash: string;
      role: string;
    }>,
    hashPassword: (password: string) => Promise<string>,
  ): AccountStore;
  createResetTokens(now?: () => number): ResetTokenStore;
  start(
    request: {
      body: { email?: string };
      headers: Record<string, string | undefined>;
    },
    response: ResponseRecorder,
    accounts: AccountStore,
    resetTokens: ResetTokenStore,
    mailer: Mailer,
  ): Promise<ResponseRecorder>;
}

interface Mailer {
  messages: Array<{ email: string; resetUrl: string }>;
  sendPasswordReset(email: string, resetUrl: string): Promise<void>;
}

interface ResetTokenStore {
  consume(token: string): string | null;
  issue(accountId: string): string;
}

interface ResponseRecorder {
  ended: boolean;
  statusCode: number | null;
  end(): ResponseRecorder;
  status(code: number): ResponseRecorder;
}

const victim = Object.freeze({
  email: "victim@example.test",
  id: "victim-account",
  passwordHash: "hash:old-password",
  role: "administrator",
});
const canonicalOrigin = "https://accounts.example.test";
const attackerOrigin = "https://capture.attacker.test";

test("password-reset host poisoning captures a strong token while fixed origin prevents disclosure", async () => {
  const vulnerable = await loadFixture(
    "javascript-password-reset-host-poisoning",
  );
  const safe = await loadFixture("javascript-safe-password-reset-origin");
  const hashPassword = async (password: string): Promise<string> =>
    `hash:${password}`;

  const vulnerableAccounts = vulnerable.createAccounts([victim], hashPassword);
  const vulnerableTokens = vulnerable.createResetTokens(() => 1_000_000);
  const vulnerableMailer = mailerRecorder();
  const vulnerableStartResponse = responseRecorder();
  expect(
    await vulnerable.start(
      {
        body: { email: victim.email },
        headers: {
          host: "accounts.example.test",
          "x-forwarded-host": "capture.attacker.test",
        },
      },
      vulnerableStartResponse,
      vulnerableAccounts,
      vulnerableTokens,
      vulnerableMailer,
    ),
  ).toBe(vulnerableStartResponse);
  expect(vulnerableStartResponse.statusCode).toBe(202);
  expect(vulnerableStartResponse.ended).toBe(true);
  expect(vulnerableMailer.messages).toHaveLength(1);
  expect(vulnerableMailer.messages[0]?.email).toBe(victim.email);

  const poisonedUrl = new URL(vulnerableMailer.messages[0]?.resetUrl ?? "");
  expect(poisonedUrl.origin).toBe(attackerOrigin);
  expect(poisonedUrl.pathname).toBe("/password-reset/complete");
  const capturedToken = attackerCapturedToken(poisonedUrl);
  expect(capturedToken?.length).toBeGreaterThanOrEqual(32);

  const vulnerableCompleteResponse = responseRecorder();
  await vulnerable.complete(
    {
      body: {
        newPassword: "attacker-password",
        token: capturedToken,
      },
    },
    vulnerableCompleteResponse,
    vulnerableAccounts,
    vulnerableTokens,
  );
  expect(vulnerableCompleteResponse.statusCode).toBe(204);
  expect(vulnerableAccounts.passwordHashFor(victim.id)).toBe(
    "hash:attacker-password",
  );

  const vulnerableReplayResponse = responseRecorder();
  await vulnerable.complete(
    {
      body: {
        newPassword: "replayed-password",
        token: capturedToken,
      },
    },
    vulnerableReplayResponse,
    vulnerableAccounts,
    vulnerableTokens,
  );
  expect(vulnerableReplayResponse.statusCode).toBe(400);
  expect(vulnerableAccounts.passwordHashFor(victim.id)).toBe(
    "hash:attacker-password",
  );

  const safeAccounts = safe.createAccounts([victim], hashPassword);
  const safeTokens = safe.createResetTokens(() => 1_000_000);
  const safeMailer = mailerRecorder();
  const safeStartResponse = responseRecorder();
  await safe.start(
    {
      body: { email: victim.email },
      headers: {
        host: "capture.attacker.test",
        "x-forwarded-host": "capture.attacker.test",
        "x-forwarded-proto": "http",
      },
    },
    safeStartResponse,
    safeAccounts,
    safeTokens,
    safeMailer,
  );
  expect(safeStartResponse.statusCode).toBe(202);
  expect(safeMailer.messages).toHaveLength(1);
  const safeUrl = new URL(safeMailer.messages[0]?.resetUrl ?? "");
  expect(safeUrl.origin).toBe(canonicalOrigin);
  expect(safeUrl.href).not.toContain("capture.attacker.test");
  expect(attackerCapturedToken(safeUrl)).toBeNull();

  const safeAttackerResponse = responseRecorder();
  await safe.complete(
    {
      body: {
        newPassword: "attacker-password",
        token: attackerCapturedToken(safeUrl),
      },
    },
    safeAttackerResponse,
    safeAccounts,
    safeTokens,
  );
  expect(safeAttackerResponse.statusCode).toBe(400);
  expect(safeAccounts.passwordHashFor(victim.id)).toBe(victim.passwordHash);

  const legitimateToken = safeUrl.searchParams.get("token");
  expect(legitimateToken?.length).toBeGreaterThanOrEqual(32);
  const safeVictimResponse = responseRecorder();
  await safe.complete(
    {
      body: {
        newPassword: "victim-new-password",
        token: legitimateToken,
      },
    },
    safeVictimResponse,
    safeAccounts,
    safeTokens,
  );
  expect(safeVictimResponse.statusCode).toBe(204);
  expect(safeAccounts.passwordHashFor(victim.id)).toBe(
    "hash:victim-new-password",
  );

  const boundedTokens = safe.createResetTokens(() => 1_000_000);
  const replacedToken = boundedTokens.issue(victim.id);
  const currentToken = boundedTokens.issue(victim.id);
  expect(currentToken).not.toBe(replacedToken);
  expect(boundedTokens.consume(replacedToken)).toBeNull();
  expect(boundedTokens.consume(currentToken)).toBe(victim.id);
  expect(boundedTokens.consume(currentToken)).toBeNull();
});

function attackerCapturedToken(url: URL): string | null {
  return url.origin === attackerOrigin ? url.searchParams.get("token") : null;
}

function mailerRecorder(): Mailer {
  const messages: Mailer["messages"] = [];
  return {
    messages,
    async sendPasswordReset(email, resetUrl) {
      messages.push({ email, resetUrl });
    },
  };
}

function responseRecorder(): ResponseRecorder {
  return {
    ended: false,
    statusCode: null,
    end() {
      this.ended = true;
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
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
  const accounts = (await import(
    pathToFileURL(resolve(sourceRoot, "accounts.js")).href
  )) as Record<string, unknown>;
  const passwordReset = (await import(
    pathToFileURL(resolve(sourceRoot, "password-reset.js")).href
  )) as Record<string, unknown>;
  const resetTokens = (await import(
    pathToFileURL(resolve(sourceRoot, "reset-tokens.js")).href
  )) as Record<string, unknown>;
  return {
    complete: passwordReset["completePasswordReset"] as Fixture["complete"],
    createAccounts: accounts["createAccountStore"] as Fixture["createAccounts"],
    createResetTokens: resetTokens[
      "createResetTokenStore"
    ] as Fixture["createResetTokens"],
    start: passwordReset["startPasswordReset"] as Fixture["start"],
  };
}
