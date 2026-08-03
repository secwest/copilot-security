using Secwest.Benchmarks.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration["ConnectionStrings:App"] = "benchmark-in-memory";
builder.Services.AddControllers();
builder.Services.AddSingleton<UserQueries>();
var app = builder.Build();
app.MapControllers();
app.Run();
