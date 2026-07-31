const IDENTIFIER = /^[a-z][a-z0-9-]{2,63}$/u;

export function createSessionStore(records) {
  const sessions = new Map(
    records.map((record) => [
      record.id,
      { id: record.id, tenantId: record.tenantId, userId: record.userId },
    ]),
  );
  return {
    get(sessionId) {
      const session = sessions.get(sessionId);
      return session === undefined ? null : { ...session };
    },
  };
}

export function createInvoiceRepository(records) {
  const invoices = new Map(
    records.map((record) => [
      `${record.tenantId}:${record.id}`,
      structuredClone(record),
    ]),
  );
  let lookups = 0;
  return {
    findForTenant(tenantId, invoiceId) {
      lookups += 1;
      const invoice = invoices.get(`${tenantId}:${invoiceId}`);
      return invoice === undefined ? null : structuredClone(invoice);
    },
    lookupCount() {
      return lookups;
    },
  };
}

export function createInvoiceApi({ sessions, invoices }) {
  const invoiceCache = new Map();

  return {
    handle(request) {
      const session = sessions.get(request.cookies.sid);
      if (session === null)
        return response(401, { error: "authentication required" });

      const invoiceId = String(request.params.invoiceId ?? "");
      if (!IDENTIFIER.test(invoiceId)) {
        return response(400, { error: "invalid invoice ID" });
      }

      const cacheKey = `invoice:${invoiceId}`;
      const cached = invoiceCache.get(cacheKey);
      if (cached !== undefined) {
        return response(200, structuredClone(cached), "HIT");
      }

      const invoice = invoices.findForTenant(session.tenantId, invoiceId);
      if (invoice === null)
        return response(404, { error: "invoice not found" });

      invoiceCache.set(cacheKey, structuredClone(invoice));
      return response(200, invoice, "MISS");
    },
    cacheSize() {
      return invoiceCache.size;
    },
  };
}

function response(status, body, cacheStatus = "BYPASS") {
  return {
    status,
    headers: { "x-application-cache": cacheStatus },
    body,
  };
}
