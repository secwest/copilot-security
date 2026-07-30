export async function getInvoice(request, response, database) {
  const invoice = await database.invoices.findById(request.params.invoiceId);
  if (!invoice) return response.status(404).end();
  return response.json(invoice);
}
