using Microsoft.EntityFrameworkCore;
using Secwest.Benchmarks.AspnetIdor.Data;
using Secwest.Benchmarks.AspnetIdor.Models;

namespace Secwest.Benchmarks.AspnetIdor.Repositories;

public sealed class InvoiceRepository
{
    private readonly DbSet<Invoice> _invoices;

    public InvoiceRepository(InvoicesDbContext database)
    {
        _invoices = database.Invoices;
    }

    public async Task<Invoice?> LoadInvoiceAsync(int invoiceId)
    {
        return await _invoices.FindAsync(invoiceId);
    }
}
