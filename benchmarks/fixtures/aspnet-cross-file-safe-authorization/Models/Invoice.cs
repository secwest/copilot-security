namespace Secwest.Benchmarks.AspnetAuthorization.Models;

public sealed class Invoice
{
    public int Id { get; set; }
    public int CustomerId { get; set; }
    public string Description { get; set; } = string.Empty;
}
