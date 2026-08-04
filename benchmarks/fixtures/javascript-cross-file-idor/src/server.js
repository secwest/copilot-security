import { loadInvoice } from "./invoices.js";

export async function getInvoice(request, response, database) {
  const invoiceId = String(request.params.invoiceId ?? "");
  const authenticatedCustomerId = String(request.user.customerId);
  const invoice = await loadInvoice(
    invoiceId,
    authenticatedCustomerId,
    database,
  );
  if (!invoice) return response.status(404).end();
  return response.json(invoice);
}
