export async function getInvoice(request, response, database) {
  const invoice = await database.invoices.findOne({
    id: request.params.invoiceId,
    ownerId: request.user.customerId,
  });
  if (!invoice) return response.status(404).end();
  return response.json(invoice);
}
