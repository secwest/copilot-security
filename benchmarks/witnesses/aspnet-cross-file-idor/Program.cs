using Microsoft.EntityFrameworkCore;
using Secwest.Benchmarks.AspnetIdor.Data;
using Secwest.Benchmarks.AspnetIdor.Models;
using Secwest.Benchmarks.AspnetIdor.Repositories;

var options = new DbContextOptionsBuilder<InvoicesDbContext>()
    .UseInMemoryDatabase($"idor-{Guid.NewGuid()}")
    .Options;
await using var database = new InvoicesDbContext(options);
database.Invoices.AddRange(
    new Invoice { Id = 1, CustomerId = 100, Description = "attacker" },
    new Invoice { Id = 2, CustomerId = 200, Description = "victim" });
await database.SaveChangesAsync();

var repository = new InvoiceRepository(database);
var selected = await repository.LoadInvoiceAsync(2);
if (selected?.CustomerId != 200)
{
    throw new InvalidOperationException("The vulnerable lookup did not expose the victim invoice.");
}

Console.WriteLine("ASP.NET BOLA witness: attacker-selected key returned the victim invoice.");
