using Microsoft.EntityFrameworkCore;
using Secwest.Benchmarks.AspnetAuthorization.Data;
using Secwest.Benchmarks.AspnetAuthorization.Models;
using Secwest.Benchmarks.AspnetAuthorization.Repositories;

var options = new DbContextOptionsBuilder<InvoicesDbContext>()
    .UseInMemoryDatabase($"authorization-{Guid.NewGuid()}")
    .Options;
await using var database = new InvoicesDbContext(options);
database.Invoices.AddRange(
    new Invoice { Id = 1, CustomerId = 100, Description = "attacker" },
    new Invoice { Id = 2, CustomerId = 200, Description = "victim" });
await database.SaveChangesAsync();

var repository = new InvoiceRepository(database);
var crossCustomer = await repository.LoadInvoiceAsync(2, 100);
var ownInvoice = await repository.LoadInvoiceAsync(1, 100);
if (crossCustomer is not null || ownInvoice?.CustomerId != 100)
{
    throw new InvalidOperationException("The principal-bound lookup did not preserve tenant isolation.");
}

Console.WriteLine("ASP.NET authorization control: cross-customer selection was rejected.");
