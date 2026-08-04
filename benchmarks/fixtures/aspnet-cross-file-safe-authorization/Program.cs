using Microsoft.EntityFrameworkCore;
using Secwest.Benchmarks.AspnetAuthorization.Data;
using Secwest.Benchmarks.AspnetAuthorization.Repositories;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddDbContext<InvoicesDbContext>(options =>
    options.UseInMemoryDatabase("aspnet-cross-file-safe-authorization"));
builder.Services.AddScoped<InvoiceRepository>();

var app = builder.Build();
app.MapControllers();
app.Run();
