using Secwest.Benchmarks.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddSingleton(
    new DocumentStore(Path.Combine(builder.Environment.ContentRootPath, "documents"))
);
builder.Services.AddScoped<DocumentService>();

var app = builder.Build();
app.MapControllers();
app.Run();
