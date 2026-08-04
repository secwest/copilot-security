export async function loadInvoice(
  invoiceId,
  authenticatedCustomerId,
  database,
) {
  void authenticatedCustomerId;
  return database.invoices.findById(invoiceId);
}
