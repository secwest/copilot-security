using Microsoft.EntityFrameworkCore;
using Secwest.Benchmarks.AspnetIdor.Data;
using Secwest.Benchmarks.AspnetIdor.Repositories;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddDbContext<InvoicesDbContext>(options =>
    options.UseInMemoryDatabase("aspnet-cross-file-idor"));
builder.Services.AddScoped<InvoiceRepository>();

var app = builder.Build();
app.MapControllers();
app.Run();
