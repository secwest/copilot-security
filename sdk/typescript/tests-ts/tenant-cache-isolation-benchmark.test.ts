import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";

interface Request {
  cookies: { sid?: string };
  params: { invoiceId?: string };
}

interface Response {
  status: number;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

interface Fixture {
  createSessionStore(records: Session[]): {
    get(id: string | undefined): Session | null;
  };
  createInvoiceRepository(records: Invoice[]): {
    findForTenant(tenantId: string, invoiceId: string): Invoice | null;
    lookupCount(): number;
  };
  createInvoiceApi(dependencies: {
    sessions: ReturnType<Fixture["createSessionStore"]>;
    invoices: ReturnType<Fixture["createInvoiceRepository"]>;
  }): {
    handle(request: Request): Response;
    cacheSize(): number;
  };
}

interface Session {
  id: string;
  tenantId: string;
  userId: string;
}

interface Invoice extends Record<string, unknown> {
  id: string;
  tenantId: string;
  amountCents: number;
  downloadToken: string;
}

const sessions: Session[] = [
  { id: "session-alpine", tenantId: "tenant-alpine", userId: "user-a" },
  { id: "session-boreal", tenantId: "tenant-boreal", userId: "user-b" },
];

const invoices: [Invoice, Invoice] = [
  {
    id: "invoice-100",
    tenantId: "tenant-alpine",
    amountCents: 125_000,
    downloadToken: "alpine-confidential-download-token",
  },
  {
    id: "invoice-100",
    tenantId: "tenant-boreal",
    amountCents: 8_500,
    downloadToken: "boreal-confidential-download-token",
  },
];

describe("tenant-scoped application-cache benchmark", () => {
  test("an authenticated tenant receives another tenant's cached invoice", async () => {
    const fixture = await loadFixture("javascript-tenant-cache-key-confusion");

    const direct = buildApi(fixture);
    expect(direct.api.handle(request("session-boreal")).body).toEqual(
      invoices[1],
    );

    const exposed = buildApi(fixture);
    const victim = exposed.api.handle(request("session-alpine"));
    expect(victim.status).toBe(200);
    expect(victim.headers["x-application-cache"]).toBe("MISS");
    expect(victim.body).toEqual(invoices[0]);
    expect(exposed.repository.lookupCount()).toBe(1);

    const attacker = exposed.api.handle(request("session-boreal"));
    expect(attacker.status).toBe(200);
    expect(attacker.headers["x-application-cache"]).toBe("HIT");
    expect(attacker.body).toEqual(invoices[0]);
    expect(attacker.body["downloadToken"]).toBe(
      "alpine-confidential-download-token",
    );
    expect(exposed.repository.lookupCount()).toBe(1);
    expect(exposed.api.cacheSize()).toBe(1);
  });

  test("tenant-derived cache namespaces preserve both tenants' records", async () => {
    const fixture = await loadFixture("javascript-safe-tenant-cache-isolation");
    const isolated = buildApi(fixture);

    const alpine = isolated.api.handle(request("session-alpine"));
    const boreal = isolated.api.handle(request("session-boreal"));
    const borealAgain = isolated.api.handle(request("session-boreal"));

    expect(alpine.body).toEqual(invoices[0]);
    expect(boreal.body).toEqual(invoices[1]);
    expect(borealAgain.body).toEqual(invoices[1]);
    expect(borealAgain.headers["x-application-cache"]).toBe("HIT");
    expect(isolated.repository.lookupCount()).toBe(2);
    expect(isolated.api.cacheSize()).toBe(2);

    expect(isolated.api.handle(request(undefined)).status).toBe(401);
    expect(
      isolated.api.handle(request("session-alpine", "../invoice")).status,
    ).toBe(400);
  });
});

function buildApi(fixture: Fixture) {
  const sessionStore = fixture.createSessionStore(sessions);
  const repository = fixture.createInvoiceRepository(invoices);
  return {
    repository,
    api: fixture.createInvoiceApi({
      sessions: sessionStore,
      invoices: repository,
    }),
  };
}

function request(
  sessionId: string | undefined,
  invoiceId = "invoice-100",
): Request {
  return { cookies: { sid: sessionId }, params: { invoiceId } };
}

async function loadFixture(name: string): Promise<Fixture> {
  const source = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    name,
    "src",
    "invoices.js",
  );
  return (await import(pathToFileURL(source).href)) as Fixture;
}
