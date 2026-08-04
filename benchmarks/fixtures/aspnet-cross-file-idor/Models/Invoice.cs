namespace Secwest.Benchmarks.AspnetIdor.Models;

public sealed class Invoice
{
    public int Id { get; set; }
    public int CustomerId { get; set; }
    public string Description { get; set; } = string.Empty;
}
