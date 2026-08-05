using Secwest.Benchmarks.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration["ConnectionStrings:App"] = "benchmark-in-memory";
builder.Services.AddRazorPages();
builder.Services.AddScoped<UserQueries>();

var app = builder.Build();
app.MapRazorPages();
app.Run();
