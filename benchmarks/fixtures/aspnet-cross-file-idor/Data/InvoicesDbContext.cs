using Microsoft.EntityFrameworkCore;
using Secwest.Benchmarks.AspnetIdor.Models;

namespace Secwest.Benchmarks.AspnetIdor.Data;

public sealed class InvoicesDbContext(DbContextOptions<InvoicesDbContext> options)
    : DbContext(options)
{
    public DbSet<Invoice> Invoices => Set<Invoice>();
}
