using Microsoft.EntityFrameworkCore;
using Secwest.Benchmarks.AspnetAuthorization.Models;

namespace Secwest.Benchmarks.AspnetAuthorization.Data;

public sealed class InvoicesDbContext(DbContextOptions<InvoicesDbContext> options)
    : DbContext(options)
{
    public DbSet<Invoice> Invoices => Set<Invoice>();
}
