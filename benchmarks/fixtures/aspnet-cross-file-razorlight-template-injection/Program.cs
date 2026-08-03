using Secwest.Benchmarks.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddSingleton<RazorTemplateRenderer>();
var app = builder.Build();
app.MapControllers();
app.Run();
