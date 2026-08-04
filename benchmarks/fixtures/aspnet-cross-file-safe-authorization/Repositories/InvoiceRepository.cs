using Microsoft.EntityFrameworkCore;
using Secwest.Benchmarks.AspnetAuthorization.Data;
using Secwest.Benchmarks.AspnetAuthorization.Models;

namespace Secwest.Benchmarks.AspnetAuthorization.Repositories;

public sealed class InvoiceRepository
{
    private readonly DbSet<Invoice> _invoices;

    public InvoiceRepository(InvoicesDbContext database)
    {
        _invoices = database.Invoices;
    }

    public async Task<Invoice?> LoadInvoiceAsync(
        int invoiceId,
        int authenticatedCustomerId)
    {
        return await _invoices.SingleOrDefaultAsync(invoice =>
            invoice.Id == invoiceId &&
            invoice.CustomerId == authenticatedCustomerId);
    }
}
