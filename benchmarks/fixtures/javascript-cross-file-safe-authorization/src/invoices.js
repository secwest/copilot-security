export async function loadInvoice(
  invoiceId,
  authenticatedCustomerId,
  database,
) {
  return database.invoices.findOne({
    id: invoiceId,
    ownerId: authenticatedCustomerId,
  });
}
